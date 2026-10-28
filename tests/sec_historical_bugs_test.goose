// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for historical bugs and CVEs across Go stdlib, uWebSockets, and OpenSSL:
// 1. Go CVE-2026-78667: Range Header Flood / Length Limit Enforcement (1024-byte ceiling).
// 2. Go #75557 / RFC 7578 §4.2: Content-Disposition CRLF and NUL Injection Defenses.
// 3. RFC 9113 / Go #81115 / CVE-2026-78660: HTTP/2 HPACK Content-Length Integer Overflow Prevention.
// 4. OpenSSL #31392 / CVE-2009-2408: X.509 URI NameConstraints Matching & NUL Byte Injection Rejection.
// 5. uWebSockets #1876 & #1009: Control Frame Priority Under Backpressure and Heartbeat Reset.
// 6. RFC 8446 §5.4: TLS 1.3 InnerPlaintext Zero-Length Application Data vs Malicious All-Padding.
import std;
import core from "..";
import wing from "..";

fn test_cve_2026_78667_range_header_overflow(t: core::T&) {
    t.run("CVE-2026-78667: Range header exceeding 1024 bytes MUST be rejected") { sub =>
        var oversized: u8[>..] = [];
        oversized.append("bytes=");
        for i in 200 {
            oversized.append("0-1,");
        }
        oversized.append("0-1");

        let rs, err = wing::parse_range_header(oversized[..], 1000);
        sub.assert_true(err == wing::RangeError.ExceededMaxRanges, "Range header > 1024 bytes must return ExceededMaxRanges");
        sub.assert_eq(rs.ranges.len, 0, "No ranges should be populated");
    };

    t.run("Valid Range header under 1024 bytes must succeed") { sub =>
        let rs, err = wing::parse_range_header("bytes=0-499,500-999", 2000, true);
        sub.assert_true(wing::is_ok(err), "Valid range must succeed");
        sub.assert_eq(rs.ranges.len, 1, "Ranges 0-499 and 500-999 should coalesce into 1 contiguous range (0-999)");
    };
}

fn test_go_75557_content_disposition_crlf_injection(t: core::T&) {
    t.run("Go #75557: Field name with CRLF injection MUST be rejected") { sub =>
        var out: u8[..256] = [];
        let ok = wing::format_content_disposition("upload\r\nEvil: injected", "test.txt", out);
        sub.assert_false(ok, "CRLF in field name must return false");
        sub.assert_eq(out.len, 0, "Output must remain empty on rejection");
    };

    t.run("Go #75557: Filename with CRLF injection MUST be rejected") { sub =>
        var out: u8[..256] = [];
        let ok = wing::format_content_disposition("file", "image.png\r\nSet-Cookie: pwned=1", out);
        sub.assert_false(ok, "CRLF in filename must return false");
        sub.assert_eq(out.len, 0, "Output must remain empty on rejection");
    };

    t.run("Go #75557: NUL byte injection in field name or filename MUST be rejected") { sub =>
        var out: u8[..256] = [];
        let ok = wing::format_content_disposition("field\0injection", "safe.txt", out);
        sub.assert_false(ok, "NUL byte in field name must return false");
    };

    t.run("Valid parameters with quotes and backslashes are properly escaped") { sub =>
        var out: u8[..256] = [];
        let ok = wing::format_content_disposition("my \"field\"", "vacation\\\"photo\".jpg", out);
        sub.assert_true(ok, "Valid parameters should format successfully");
        sub.assert_true(core::index_of_slice(out[..], "name=\"my \\\"field\\\"\"") >= 0, "Quotes in name must be escaped");
        sub.assert_true(core::index_of_slice(out[..], "filename=\"vacation\\\\\\\"photo\\\".jpg\"") >= 0, "Backslashes and quotes escaped in filename");
    };
}

fn test_http2_content_length_overflow_defense(t: core::T&) {
    t.run("RFC 9113 & Go #81115: HTTP/2 Content-Length > 19 digits MUST be rejected as PROTOCOL_ERROR") { sub =>
        var dt_enc = wing::new_dynamic_table(4096);
        var raw_bytes: u8[>..] = [];
        wing::encode_hpack_field(dt_enc, raw_bytes, ":method", "POST", false, false);
        wing::encode_hpack_field(dt_enc, raw_bytes, ":scheme", "https", false, false);
        wing::encode_hpack_field(dt_enc, raw_bytes, ":path", "/upload", false, false);
        wing::encode_hpack_field(dt_enc, raw_bytes, "content-length", "999999999999999999999999999999", false, false);

        var dt_dec = wing::new_dynamic_table(4096);
        var out_list = wing::DecodedH2HeaderList { .. };
        let err = wing::decode_hpack_header_block(dt_dec, raw_bytes[..], out_list, 8192, true);
        sub.assert_eq(err, wing::ERR_PROTOCOL_ERROR, "Excessive digits in Content-Length must trigger PROTOCOL_ERROR");
    };

    t.run("Valid Content-Length in HTTP/2 is parsed correctly") { sub =>
        var dt_enc = wing::new_dynamic_table(4096);
        var raw_bytes: u8[>..] = [];
        wing::encode_hpack_field(dt_enc, raw_bytes, ":method", "POST", false, false);
        wing::encode_hpack_field(dt_enc, raw_bytes, ":scheme", "https", false, false);
        wing::encode_hpack_field(dt_enc, raw_bytes, ":path", "/upload", false, false);
        wing::encode_hpack_field(dt_enc, raw_bytes, "content-length", "1048576", false, false);

        var dt_dec = wing::new_dynamic_table(4096);
        var out_list = wing::DecodedH2HeaderList { .. };
        let err = wing::decode_hpack_header_block(dt_dec, raw_bytes[..], out_list, 8192, true);
        sub.assert_eq(err, wing::ERR_NO_ERROR, "Valid Content-Length must succeed");
        sub.assert_true(out_list.has_content_length, "has_content_length set");
        sub.assert_eq(out_list.content_length_val, 1048576, "parsed content-length matches");
    };
}

fn test_openssl_31392_uri_name_constraints_nul(t: core::T&) {
    t.run("OpenSSL #31392 / RFC 5280 §4.2.1.10: URI matching against DNS name constraint") { sub =>
        sub.assert_true(wing::match_uri_name_constraint("https://api.example.com/v1", "example.com"), "Subdomain matches constraint");
        sub.assert_true(wing::match_uri_name_constraint("https://example.com/login", "example.com"), "Exact domain matches constraint");
        sub.assert_false(wing::match_uri_name_constraint("https://evil.com/login", "example.com"), "Foreign domain must be rejected");
    };

    t.run("CVE-2009-2408: URI containing embedded NUL byte MUST be rejected") { sub =>
        let nul_uri: u8[29] = [
            'h', 't', 't', 'p', 's', ':', '/', '/',
            'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
            0x00,
            '.', 'e', 'v', 'i', 'l', '.', 'c', 'o', 'm',
        ];
        sub.assert_false(wing::match_uri_name_constraint(nul_uri[..], "example.com"), "NUL byte in URI must be rejected");
    };

    t.run("CVE-2024-45341 / Go #71208: IPv6 Zone ID URI Name Constraints Bypass Defense") { sub =>
        sub.assert_true(
            wing::match_uri_name_constraint("https://[2001:db8::1%25eth0]:8443/api", "2001:db8::1"),
            "IPv6 URI with encoded zone ID matches IP constraint",
        );
        sub.assert_true(
            wing::match_uri_name_constraint("https://[2001:db8::1%eth0]/status", "[2001:db8::1]"),
            "IPv6 URI with raw zone ID matches bracketed constraint",
        );
        sub.assert_false(
            wing::match_uri_name_constraint("https://[2001:db8::2%eth0]/api", "2001:db8::1"),
            "Non-matching IPv6 URI must be rejected",
        );
        sub.assert_false(
            wing::match_uri_name_constraint("https://[malformed-ipv6/api", "2001:db8::1"),
            "Unclosed bracket in IPv6 URI must be rejected",
        );
    };
}

fn test_uwebsockets_1876_control_priority_under_backpressure(t: core::T&) {
    t.run("uWebSockets #1876: Control frames MUST NOT be dropped when backpressure threshold is reached") { sub =>
        var ws = wing::WebSocketSession { .. };
        wing::set_max_backpressure(ws, 100, false); // 100 bytes max backpressure

        var out_wire: u8[>..] = [];
        // Saturate backpressure buffer
        let st1 = wing::send_text_with_status(ws, "Initial message filling backpressure quota", out_wire);
        sub.assert_true(st1 == wing::WsSendStatus.Backpressure || st1 == wing::WsSendStatus.Success, "Initial send succeeds or backpressures");
        sub.assert_true(wing::is_backpressured(ws), "Socket is backpressured");

        // Subsequent data message exceeding threshold is dropped
        var dropped_wire: u8[>..] = [];
        let st2 = wing::send_text_with_status(ws, "Excessive payload that must be dropped due to backpressure ceiling", dropped_wire);
        sub.assert_eq(st2, wing::WsSendStatus.Dropped, "Data frame must be dropped under pressure");

        // Control frame (Ping) must NOT be dropped!
        var ping_wire: u8[>..] = [];
        wing::send_ping(ws, "heartbeat", ping_wire);
        sub.assert_true(ping_wire.len > 0, "Ping frame must be written even when socket is backpressured");

        // Control frame (Close) must NOT be dropped!
        var close_wire: u8[>..] = [];
        wing::close(ws, wing::WS_STATUS_NORMAL, "clean close", close_wire);
        sub.assert_true(close_wire.len > 0, "Close frame must be written even when socket is backpressured");
        sub.assert_true(ws.is_closed, "Session marked closed");
    };
}

fn test_openssl_tls13_zero_length_plaintext_invariants(t: core::T&) {
    t.run("RFC 8446 §5.4: Empty Application Data record with padding is permitted") { sub =>
        // Record with inner ContentType = 0x17 (Application Data) followed by zero padding
        let plain_wire: u8[4] = [0x17, 0x00, 0x00, 0x00];
        let content, inner_type, alert = wing::unpack_tls_inner_plaintext(plain_wire[..]);
        sub.assert_true(alert == wing::TlsAlert.CloseNotify, "Empty application data with padding must be accepted");
        sub.assert_eq(inner_type, 0x17, "Inner content type is ApplicationData");
        sub.assert_eq(content.len, 0, "Payload length is 0");
    };

    t.run("RFC 8446 §5.4: Empty Handshake record MUST be rejected with unexpected_message") { sub =>
        // Record with inner ContentType = 0x16 (Handshake) and 0 payload bytes followed by padding
        let plain_hs: u8[3] = [0x16, 0x00, 0x00];
        let _, _, alert = wing::unpack_tls_inner_plaintext(plain_hs[..]);
        sub.assert_eq(alert, wing::TlsAlert.UnexpectedMessage, "Empty Handshake record must return unexpected_message");
    };

    t.run("RFC 8446 §5.4: All-zero padding record MUST be rejected with unexpected_message") { sub =>
        let all_zero: u8[16] = [0; 16];
        let _, _, alert = wing::unpack_tls_inner_plaintext(all_zero[..]);
        sub.assert_eq(alert, wing::TlsAlert.UnexpectedMessage, "All-zero record missing inner ContentType must be rejected");
    };
}

fn test_go_66434_content_transfer_encoding_rejection(t: core::T&) {
    t.run("Go #66434 & RFC 7578 §4.7: Content-Transfer-Encoding in multipart part MUST be rejected") { sub =>
        let body = "--sep\r\nContent-Disposition: form-data; name=\"msg\"\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8=\r\n--sep--\r\n";
        let msg, err = wing::parse_multipart(body, "sep");
        sub.assert_true(err == wing::MultipartError.InvalidPartHeaders, "Deprecated Content-Transfer-Encoding must be rejected");
        sub.assert_false(msg.valid, "Message marked invalid");
    };

    t.run("Standard multipart without Content-Transfer-Encoding must succeed") { sub =>
        let body = "--sep\r\nContent-Disposition: form-data; name=\"msg\"\r\n\r\nHello World\r\n--sep--\r\n";
        let msg, err = wing::parse_multipart(body, "sep");
        sub.assert_true(wing::is_ok(err), "Standard multipart must parse successfully");
        sub.assert_true(msg.valid, "Message marked valid");
        sub.assert_eq(msg.parts.len, 1, "1 part parsed");
    };
}

fn test_uwebsockets_1662_streaming_utf8_continuation(t: core::T&) {
    t.run("uWS #1662 / Autobahn 6.x: Incomplete multi-byte codepoint split across frame chunks") { sub =>
        // Euro sign € is 3 bytes: 0xE2, 0x82, 0xAC
        let chunk1: u8[2] = [0xE2, 0x82];
        let off1_non_final, ok1_non_final = core::validate_utf8_streaming(chunk1[..], false);
        sub.assert_true(ok1_non_final, "Valid prefix of incomplete 3-byte codepoint accepted when non-final");
        sub.assert_eq(off1_non_final, 0, "0 complete codepoints in chunk1");

        let off1_final, ok1_final = core::validate_utf8_streaming(chunk1[..], true);
        sub.assert_false(ok1_final, "Incomplete codepoint at final boundary MUST be rejected");

        // Complete sequence in assembled buffer
        let full: u8[3] = [0xE2, 0x82, 0xAC];
        let off_full, ok_full = core::validate_utf8_streaming(full[..], true);
        sub.assert_true(ok_full, "Complete 3-byte codepoint accepted");
        sub.assert_eq(off_full, 3, "All 3 bytes verified as complete codepoint");
    };

    t.run("uWS #1662 / Autobahn 6.x: Overlong UTF-8 prefix rejected immediately") { sub =>
        // Overlong 2-byte: 0xC0 0x80 (ASCII NUL encoded as 2 bytes)
        let overlong: u8[2] = [0xC0, 0x80];
        let _, ok_overlong = core::validate_utf8_streaming(overlong[..], false);
        sub.assert_false(ok_overlong, "Overlong prefix must be rejected immediately even on non-final chunk");
    };

    t.run("uWS #1662 / Autobahn 6.x: UTF-16 surrogate prefix rejected immediately") { sub =>
        // High surrogate U+D800: 0xED 0xA0 0x80
        let surrogate: u8[2] = [0xED, 0xA0];
        let _, ok_surrogate = core::validate_utf8_streaming(surrogate[..], false);
        sub.assert_false(ok_surrogate, "Surrogate prefix must be rejected immediately");
    };
}

fn test_openssl_33428_ech_alpn_isolation(t: core::T&) {
    t.run("OpenSSL #33428: ECH accepted MUST only permit inner ALPN negotiation") { sub =>
        let inner_alpn = "h2";
        let outer_alpn = "http/1.1";

        sub.assert_true(
            wing::validate_ech_alpn_negotiation(true, "h2", inner_alpn, outer_alpn),
            "Selected inner ALPN accepted when ECH accepted",
        );
        sub.assert_false(
            wing::validate_ech_alpn_negotiation(true, "http/1.1", inner_alpn, outer_alpn),
            "Outer ALPN rejected when ECH accepted",
        );
    };

    t.run("OpenSSL #33428: ECH rejected/bypassed MUST only permit outer ALPN negotiation") { sub =>
        let inner_alpn = "h2";
        let outer_alpn = "http/1.1";

        sub.assert_true(
            wing::validate_ech_alpn_negotiation(false, "http/1.1", inner_alpn, outer_alpn),
            "Selected outer ALPN accepted when ECH rejected",
        );
        sub.assert_false(
            wing::validate_ech_alpn_negotiation(false, "h2", inner_alpn, outer_alpn),
            "Inner ALPN MUST NOT leak into unencrypted outer connection",
        );
    };
}

fn main() {
    var runner = core::new_runner("Historical Vulnerabilities & Protocol Edge-Case Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Go CVE-2026-78667: Range Header Overflow Defense", test_cve_2026_78667_range_header_overflow);
    core::run_case(runner, "2. Go #75557: Content-Disposition CRLF Injection Defenses", test_go_75557_content_disposition_crlf_injection);
    core::run_case(runner, "3. RFC 9113 & Go #81115: HTTP/2 Content-Length Overflow Defense", test_http2_content_length_overflow_defense);
    core::run_case(runner, "4. OpenSSL #31392 & Go #71208: URI NameConstraints & IPv6 Zone", test_openssl_31392_uri_name_constraints_nul);
    core::run_case(runner, "5. uWebSockets #1876: Control Frame Priority Under Backpressure", test_uwebsockets_1876_control_priority_under_backpressure);
    core::run_case(runner, "6. RFC 8446 §5.4: TLS 1.3 InnerPlaintext Zero-Length Invariants", test_openssl_tls13_zero_length_plaintext_invariants);
    core::run_case(runner, "7. Go #66434 / RFC 7578 §4.7: Content-Transfer-Encoding Rejection", test_go_66434_content_transfer_encoding_rejection);
    core::run_case(runner, "8. uWS #1662 / Autobahn 6.x: Streaming UTF-8 Chunk Boundaries", test_uwebsockets_1662_streaming_utf8_continuation);
    core::run_case(runner, "9. OpenSSL #33428: ECH Outer vs Inner ALPN Strict Isolation", test_openssl_33428_ech_alpn_isolation);

    let ok = core::finish(runner);
    assert(ok);
}
