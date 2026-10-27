// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Phase 4 RED test suite based on .gemini audit reports and Go / uWebSockets issue trackers.
// Verifies protocol flaws, RFC non-conformances, and security vulnerabilities that are CURRENTLY UNFIXED in goose-wing.
//
// Issues covered:
// 1. RFC 9110 §6.5.1 & Go #81143: Disallow Content-Type and Content-Encoding in Chunked Trailers
// 2. RFC 9110 §14.1.2 & Go #81858 (CVE-2026-78667): Range Requests Exceeding Max Ranges Must Return 200 OK (Not 416)
// 3. RFC 9112 §6.1 & RFC 7230 §3.3.3: Invalid Response Transfer-Encoding Must Reject (Not Fall Through to Content-Length)
// 4. RFC 3986 §3.2.2 & Go #75678 (CVE-2025-47912): parse_url_view Must Reject Non-IPv6 Bracketed Hosts ([google.com], [127.0.0.1])
// 5. RFC 3986 §2 / RFC 9112 §3.2 & CVE-2023-26159: parse_url_view Must Reject Unencoded CRLF in Host and Path
// 6. RFC 6455 §5.5 & uWS #1407: WebSocket Control Frame Encoding with Payload > 125 Must Never Emit Extended Length (126/127)

import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. RFC 9110 §6.5.1 & Go #81143: Disallow Content-Type and Content-Encoding in Trailers
// ----------------------------------------------------------------------------
fn test_forbidden_trailer_fields(t: core::T&) {
    t.run("Content-Type in chunked trailer must be rejected as DisallowedTrailer") { sub =>
        // RFC 9110 Section 6.5.1:
        // "A sender MUST NOT generate a trailer that contains any of the following fields:
        // ... Content-Encoding, Content-Type, Content-Range."
        // A recipient MUST NOT process forbidden fields as metadata of the payload.
        var out_body: u8[>..] = [];
        var out_trailers: wing::HeaderItem[..16] = [];
        let chunk_wire: const u8[:] = "5\r\nHello\r\n0\r\nContent-Type: text/html\r\n\r\n";

        let err, _ = wing::decode_chunked_body_with_trailers(chunk_wire, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.DisallowedTrailer, "Content-Type trailer must be rejected with DisallowedTrailer (RFC 9110 §6.5.1)");
    };

    t.run("Content-Encoding in chunked trailer must be rejected as DisallowedTrailer") { sub =>
        var out_body: u8[>..] = [];
        var out_trailers: wing::HeaderItem[..16] = [];
        let chunk_wire: const u8[:] = "5\r\nHello\r\n0\r\nContent-Encoding: gzip\r\n\r\n";

        let err, _ = wing::decode_chunked_body_with_trailers(chunk_wire, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.DisallowedTrailer, "Content-Encoding trailer must be rejected with DisallowedTrailer (RFC 9110 §6.5.1)");
    };
}

// ----------------------------------------------------------------------------
// 2. RFC 9110 §14.1.2 & Go #81858 (CVE-2026-78667): Exceeded Ranges Must Return 200 OK
// ----------------------------------------------------------------------------
fn test_exceeded_max_ranges_returns_200(t: core::T&) {
    t.run("Range request with > 16 ranges must be ignored and served with 200 OK") { sub =>
        // RFC 9110 Section 14.1.2 & Go #81858 (CVE-2026-78667):
        // "An origin server MAY ignore a Range header field containing more than one range,
        // or containing ranges with excessive overhead... and return the entire selected
        // representation with a 200 (OK) status code."
        // In http/multipart.goose:668, serve_range_request returns 416 for ExceededMaxRanges!
        var out_status: i32 = 0;
        var out_headers = wing::new_header_map();
        var out_body: u8[>..] = [];

        let payload: const u8[:] = "0123456789abcdefghijklmnopqrstuvwxyz";
        let mod_time = core::unix(1700000000);

        // 17 small ranges exceeds max_ranges=16
        let excessive_range = "bytes=0-1,2-3,4-5,6-7,8-9,10-11,12-13,14-15,16-17,18-19,20-21,22-23,24-25,26-27,28-29,30-31,32-33";

        wing::serve_range_request(
            excessive_range,
            "",
            "\"etag123\"",
            mod_time,
            payload.len,
            "text/plain",
            out_status,
            out_headers,
            out_body,
        ) { start, len, buf =>
            buf.append(payload[start..(start + len)]);
        };

        sub.assert_eq(out_status, 200, "Excessive range count must be ignored and return 200 OK (Go #81858 / CVE-2026-78667)");
        sub.assert_bytes_eq(out_body[..], payload, "Must return complete representation when excessive ranges are ignored");
    };
}

// ----------------------------------------------------------------------------
// 3. RFC 9112 §6.1 & RFC 7230 §3.3.3: Invalid Response Transfer-Encoding Rejection
// ----------------------------------------------------------------------------
fn test_response_invalid_transfer_encoding_rejected(t: core::T&) {
    t.run("Response with invalid Transfer-Encoding and Content-Length must NOT fall through") { sub =>
        // RFC 9112 Section 6.1:
        // "If a Transfer-Encoding header field is present in a response and the chunked transfer
        // coding is not the final transfer coding, the recipient MUST treat the response as an
        // error or close the connection without reading the body."
        // Currently, parse_http1_wire_response falls through to Content-Length!
        var res = wing::new_response();
        let wire: const u8[:] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, identity\r\nContent-Length: 5\r\n\r\nhello";
        let ok, _ = wing::parse_http1_wire_response(wire, res);

        sub.assert_false(ok, "parse_http1_wire_response MUST reject response with invalid Transfer-Encoding (RFC 9112 §6.1)");
    };

    t.run("Response with unknown Transfer-Encoding must be rejected") { sub =>
        var res = wing::new_response();
        let wire_unknown: const u8[:] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: bogus\r\nContent-Length: 4\r\n\r\ntest";
        let ok_unk, _ = wing::parse_http1_wire_response(wire_unknown, res);

        sub.assert_false(ok_unk, "parse_http1_wire_response MUST reject response with unknown Transfer-Encoding 'bogus'");
    };
}

// ----------------------------------------------------------------------------
// 4. RFC 3986 §3.2.2 & Go #75678 (CVE-2025-47912): parse_url_view Non-IPv6 Bracket Rejection
// ----------------------------------------------------------------------------
fn test_parse_url_view_non_ipv6_bracketed_host(t: core::T&) {
    t.run("parse_url_view must reject bracketed domain name [google.com]") { sub =>
        // RFC 3986 Section 3.2.2:
        // IP-literal = "[" ( IPv6address / IPvFuture ) "]"
        // Hostnames and IPv4 addresses MUST NOT be enclosed in square brackets.
        // Currently, parse_url_view accepts 'http://[google.com]/path' with view.valid == true!
        let view, err = core::parse_url_view("http://[google.com]/path");
        sub.assert_false(view.valid, "parse_url_view MUST reject hostname in square brackets [google.com] (Go #75678 / CVE-2025-47912)");
        sub.assert_true(err != core::UrlParseError.None, "Must return parse error for bracketed hostname");
    };

    t.run("parse_url_view must reject bracketed IPv4 address [127.0.0.1]") { sub =>
        let view_ip, err_ip = core::parse_url_view("http://[127.0.0.1]/path");
        sub.assert_false(view_ip.valid, "parse_url_view MUST reject IPv4 address in square brackets [127.0.0.1]");
        sub.assert_true(err_ip != core::UrlParseError.None, "Must return parse error for bracketed IPv4 address");
    };
}

// ----------------------------------------------------------------------------
// 5. RFC 3986 §2 / RFC 9112 §3.2 & CVE-2023-26159: CRLF in URL View Host and Path
// ----------------------------------------------------------------------------
fn test_parse_url_view_crlf_rejection(t: core::T&) {
    t.run("parse_url_view must reject unencoded CRLF in host") { sub =>
        // Unencoded CRLF in URL host enables HTTP request smuggling and host header injection.
        let view, err = core::parse_url_view("http://evil\r\n.com/path");
        sub.assert_false(view.valid, "parse_url_view MUST reject CRLF in host (CVE-2023-26159)");
        sub.assert_true(err != core::UrlParseError.None, "Must return parse error for CRLF in host");
    };

    t.run("parse_url_view must reject unencoded CRLF in path") { sub =>
        // Unencoded CRLF in URL path enables HTTP request line splitting and header injection.
        let view, err = core::parse_url_view("http://example.com/path\r\nInjected-Header: 1");
        sub.assert_false(view.valid, "parse_url_view MUST reject CRLF in path (CVE-2023-26159)");
        sub.assert_true(err != core::UrlParseError.None, "Must return parse error for CRLF in path");
    };
}

// ----------------------------------------------------------------------------
// 6. RFC 6455 §5.5 & uWS #1407: WebSocket Control Frame Encoding Clamps to <= 125
// ----------------------------------------------------------------------------
fn test_ws_control_frame_encoding_size_limit(t: core::T&) {
    t.run("send_ping with payload > 125 must NEVER serialize extended length (126/127)") { sub =>
        // RFC 6455 Section 5.5:
        // "All control frames MUST have a payload length of 125 bytes or less and MUST NOT be fragmented."
        // An implementation MUST NOT encode a control frame with payload length > 125.
        // Currently, encode_ws_frame emits 0x7E (126) or 0x7F (127), which is wire-invalid!
        var ws = wing::new_websocket_session(true);
        var big_ping: u8[..256] = [];
        for i in 130 { big_ping.push('x' as u8); }

        var wire_out: u8[..512] = [];
        wing::send_ping(ws, big_ping[..], wire_out);

        guard wire_out.len >= 2 else {
            sub.assert_true(false, "send_ping produced empty wire output");
            return;
        }

        // Byte 1 has mask bit and 7-bit length
        let raw_len = wire_out[1] & 0x7F;
        sub.assert_true(raw_len <= 125, "Control frame payload length on wire MUST be <= 125 (RFC 6455 §5.5)");
        sub.assert_true(raw_len != 126 && raw_len != 127, "Control frame MUST NEVER use extended length 126 or 127");
    };
}

fn main() {
    let _ = wing::tcp_init();
    var dummy: u8[4] = [0, 0, 0, 0];
    wing::swar_to_lower(dummy[..]);

    var runner = core::new_runner("RED Suite Phase 4: CVE & Issue Tracker Flaws", core::Verbosity.Verbose);

    core::run_case(runner, "1. RFC 9110 §6.5.1 & Go #81143: Disallow Content-Type and Content-Encoding in Trailers", test_forbidden_trailer_fields);
    core::run_case(runner, "2. RFC 9110 §14.1.2 & Go #81858: Range Requests Exceeding Max Ranges Return 200 OK", test_exceeded_max_ranges_returns_200);
    core::run_case(runner, "3. RFC 9112 §6.1 & RFC 7230 §3.3.3: Invalid Response Transfer-Encoding Rejection", test_response_invalid_transfer_encoding_rejected);
    core::run_case(runner, "4. RFC 3986 §3.2.2 & Go #75678: parse_url_view Non-IPv6 Bracket Rejection", test_parse_url_view_non_ipv6_bracketed_host);
    core::run_case(runner, "5. RFC 3986 §2 / RFC 9112 §3.2 & CVE-2023-26159: CRLF in URL View Host and Path", test_parse_url_view_crlf_rejection);
    core::run_case(runner, "6. RFC 6455 §5.5 & uWS #1407: WebSocket Control Frame Encoding Clamps to <= 125", test_ws_control_frame_encoding_size_limit);

    let ok = core::finish(runner);
    print("\n[RED PHASE 4 TEST SUITE STATUS] Finished execution. Result ok=", ok);
    if !ok {
        print(">>> CONFIRMED RED PHASE 4: Target vulnerabilities/flaws reproduce successfully against the current codebase! <<<\n");
    }
}
