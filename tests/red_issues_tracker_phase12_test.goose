// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Phase 12 RED test suite: Fixed-Capacity Truncation Smuggling, Protocol Errors & Boundary Hardening
// Covers 12 target groups from the audit:
//
// 1. NoVarySearch 2D array capacity, key truncation smuggling, and trailing query bounds (http/novarysearch.goose)
// 2. Chunked FSM trailing split CRLF infinite loop and chunk extension syntax (http/headers/chunked_fsm.goose, chunked.goose)
// 3. HTTP/1.x Content-Length invalid-first smuggling bypass, Host delimiters, and Set-Cookie bounds (http/headers/lexical.goose, headers.goose)
// 4. MIME & SFV key collision/truncation smuggling, token/binary bounds, and content disposition type length (http/mime.goose)
// 5. Cache-Control unqualified private override and Vary multi-header & truncation poisoning (http/cache/*)
// 6. URL origin 128B host bounds, path resolution bounds, Punycode DNS limits, and view validation (core/url/*)
// 7. HTTP signatures label binding, HSTS quoted max-age & duplicates, and W3C tracestate syntax (http/signatures.goose, hsts.goose, trace.goose)
// 8. HTTP/2 multiplexer invalid settings rejection, zero-increment flow control, and stream association (server/h2_multiplexer.goose, http/h2_framer.goose)
// 9. HTTP/3 informational 100/103 multi-HEADERS handling, 101 status rejection, and QPACK field syntax (http3/connection.goose, qpack.goose)
// 10. gRPC stream reader 32-message truncation smuggling, non-numeric status code handling, and unary framing (grpc/*)
// 11. DPoP method substring verification bypass, Digest unclosed quotes & algorithm overflow, and PrivateToken bounds (auth/*, security/*)
// 12. X.509 critical extension enforcement & validity order, HTTP/1 CONNECT tunnel pipelining hygiene, and Akamai capacity bounds (tls/*, server/*, fingerprint/*)

import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. NoVarySearch (http/novarysearch.goose)
// ----------------------------------------------------------------------------
fn test_novarysearch_truncation_and_bounds(t: core::T&) {
    t.run("No-Vary-Search must reject > 16 parameters rather than silently dropping 17th") { sub =>
        // Construct header with 17 except parameters: except=("p1" "p2" ... "p17")
        var raw_hdr: u8[..1024] = [];
        raw_hdr.append("params, except=(");
        for i in 17 {
            if i > 0 { raw_hdr.append(" "); }
            raw_hdr.push('"');
            raw_hdr.append("p");
            format(raw_hdr, i);
            raw_hdr.push('"');
        }
        raw_hdr.push(')');

        let nvs, ok = wing::parse_no_vary_search(raw_hdr[..]);
        sub.assert_false(ok, "No-Vary-Search with > 16 except params MUST return false to prevent cache poisoning");
        sub.assert_false(nvs.is_valid, "nvs.is_valid MUST be false on capacity overflow");
    };

    t.run("No-Vary-Search unclosed quotes in params must return false") { sub =>
        let nvs, ok = wing::parse_no_vary_search("params=(\"unclosed");
        sub.assert_false(ok, "Unclosed quote in No-Vary-Search MUST fail parsing");
        sub.assert_false(nvs.is_valid, "nvs.is_valid MUST be false on unclosed quote");
    };

    t.run("No-Vary-Search trailing question mark at end of header must not abort") { sub =>
        let nvs, ok = wing::parse_no_vary_search("params=?");
        sub.assert_false(ok, "Trailing '?' at EOF MUST return false safely");
    };

    t.run("No-Vary-Search 2D array parameter length > 16B must succeed without abort") { sub =>
        // 22-byte parameter name
        let nvs, ok = wing::parse_no_vary_search("params=(\"utm_campaign_source\")");
        sub.assert_true(ok, "22-byte parameter name must parse successfully");
        sub.assert_true(nvs.is_valid, "nvs must be valid");
        sub.assert_true(wing::is_param_ignored(nvs, "utm_campaign_source"), "utm_campaign_source is ignored");
    };
}

// ----------------------------------------------------------------------------
// 2. Chunked FSM & Extensions (http/headers/chunked_fsm.goose, chunked.goose)
// ----------------------------------------------------------------------------
fn test_chunked_fsm_and_extensions_rfc9112(t: core::T&) {
    t.run("Chunk extension with empty value (ext=) must return Error") { sub =>
        var dec = internal::new_chunk_fsm_decoder();
        let status, _, _ = internal::chunk_fsm_feed(dec, "5;ext=\r\nhello\r\n0\r\n\r\n");
        sub.assert_true(status == internal::ChunkFsmStatus.Error, "ext= with empty value MUST return Error");
    };

    t.run("Chunk extension with unclosed quote must return Error") { sub =>
        var dec = internal::new_chunk_fsm_decoder();
        let status, _, _ = internal::chunk_fsm_feed(dec, "5;ext=\"unclosed\r\nhello\r\n0\r\n\r\n");
        sub.assert_true(status == internal::ChunkFsmStatus.Error, "Unclosed quote in chunk extension MUST return Error");
    };

    t.run("parse_chunk_size_hex rejects DEL (0x7F)") { sub =>
        var sz: u64 = 0;
        let err = wing::parse_chunk_size_hex("5;ext=foo\x7F", sz);
        sub.assert_true(err == wing::ChunkedDecodeError.InvalidChunkExtension, "DEL in chunk extension must be rejected");
    };

    t.run("parse_chunk_size_hex rejects invalid quoted-pair control escape") { sub =>
        var sz: u64 = 0;
        let err = wing::parse_chunk_size_hex("5;ext=\"a\\\x01b\"", sz);
        sub.assert_true(err == wing::ChunkedDecodeError.InvalidChunkExtension, "Control char escape in quoted-pair must be rejected");
    };

    t.run("Chunk FSM handles split trailing CRLF without infinite loop") { sub =>
        var dec = internal::new_chunk_fsm_decoder();
        // Feed chunk body + '\r'
        let st1, off1, slice1 = internal::chunk_fsm_feed(dec, "5\r\nhello\r");
        sub.assert_true(st1 == internal::ChunkFsmStatus.YieldChunk, "First feed yields chunk slice");
        sub.assert_eq(slice1, "hello", "Body payload emitted");

        // Feed remaining '\n'
        let st2, off2, slice2 = internal::chunk_fsm_feed(dec, "\n");
        sub.assert_true(st2 == internal::ChunkFsmStatus.NeedMore, "Second feed consumes trailing LF and expects next chunk");

        // Feed final chunk
        let st3, off3, _ = internal::chunk_fsm_feed(dec, "0\r\n\r\n");
        sub.assert_true(st3 == internal::ChunkFsmStatus.Complete, "Zero chunk terminates stream");
    };
}

// ----------------------------------------------------------------------------
// 3. HTTP/1.x Headers & Smuggling (http/headers/lexical.goose, headers.goose)
// ----------------------------------------------------------------------------
fn test_http1_headers_cl_host_and_cookie_bounds(t: core::T&) {
    t.run("track_header_presence MUST reject invalid first Content-Length value") { sub =>
        var tracker = wing::new_header_presence_tracker();
        let ok = wing::track_header_presence(tracker, "Content-Length", "invalid", 0);
        sub.assert_false(ok, "Invalid first Content-Length MUST return false immediately");
    };

    t.run("validate_header_framing_conflicts rejects Host with interior comma") { sub =>
        var map = wing::new_header_map();
        let err = wing::parse_headers("Host: a.com, b.com\r\n\r\n", map);
        sub.assert_true(err == wing::HeaderParseError.InvalidHeaderValue, "Host with comma MUST be rejected");
    };

    t.run("validate_header_framing_conflicts rejects Host with interior space") { sub =>
        var map = wing::new_header_map();
        let err = wing::parse_headers("Host: a .com\r\n\r\n", map);
        sub.assert_true(err == wing::HeaderParseError.InvalidHeaderValue, "Host with space MUST be rejected");
    };

    t.run("get_set_cookie with Set-Cookie > 1024B must not abort") { sub =>
        var raw_hdr: u8[>..] = [];
        raw_hdr.append("Host: example.com\r\nSet-Cookie: session=");
        for i in 1500 { raw_hdr.push('x'); }
        raw_hdr.append("\r\n\r\n");

        var map = wing::new_header_map();
        let err = wing::parse_headers(raw_hdr[..], map);
        sub.assert_true(err == wing::HeaderParseError.None, "Headers parsed successfully");

        var cookies: u8[..1024][>..] = [];
        wing::get_set_cookie(map, cookies);
        sub.assert_eq(cookies.len, 1, "Exactly one Set-Cookie retrieved without abort");
    };
}

// ----------------------------------------------------------------------------
// 4. MIME & Structured Field Values (http/mime.goose)
// ----------------------------------------------------------------------------
fn test_mime_and_sfv_truncation_smuggling(t: core::T&) {
    t.run("parse_sfv_key rejects keys exceeding 64 bytes to prevent collision smuggling") { sub =>
        // 65-byte key: 64 'a's + 'b'
        var long_key_entry: u8[..128] = [];
        for i in 64 { long_key_entry.push('a'); }
        long_key_entry.append("b=1");

        var dict = wing::SfvDict { .. };
        let ok = wing::parse_sfv_dict(long_key_entry[..], dict);
        sub.assert_false(ok, "SFV key > 64B MUST return false and not truncate to 64B");
    };

    t.run("parse_sfv_token rejects tokens exceeding 1088 bytes") { sub =>
        var raw_tok: u8[>..] = [];
        for i in 1100 { raw_tok.push('a'); }

        var item = wing::SfvItem { .. };
        let ok = wing::parse_sfv_item(raw_tok[..], item);
        sub.assert_false(ok, "SFV token > 1088 bytes MUST return false");
    };

    t.run("parse_sfv_binary rejects byte sequences exceeding 1088 bytes") { sub =>
        var raw_bin: u8[>..] = [];
        raw_bin.push(':');
        for i in 1100 { raw_bin.push('A'); }
        raw_bin.push(':');

        var item = wing::SfvItem { .. };
        let ok = wing::parse_sfv_item(raw_bin[..], item);
        sub.assert_false(ok, "SFV binary > 1088 bytes MUST return false");
    };

    t.run("parse_content_disposition rejects type name > 32 bytes without abort") { sub =>
        var raw_disp: u8[..128] = [];
        for i in 40 { raw_disp.push('x'); }
        raw_disp.append("; filename=\"test.txt\"");

        let mt, ok = wing::parse_content_disposition(raw_disp[..]);
        sub.assert_false(ok, "Disposition type > 32 bytes MUST return false safely");
    };
}

// ----------------------------------------------------------------------------
// 5. Cache-Control & Vary (http/cache/*)
// ----------------------------------------------------------------------------
fn test_cache_control_and_vary_poisoning_rfc9111(t: core::T&) {
    t.run("Unqualified private directive following qualified private must make response uncacheable in shared cache") { sub =>
        var req_map = wing::new_header_map();
        wing::append_header(req_map, ":method", "GET");

        var resp_map = wing::new_header_map();
        // Qualified private followed by unqualified private
        wing::append_header(resp_map, "Cache-Control", "private=\"X-Custom\", private");

        let resp_cc = wing::parse_cache_control_headers(resp_map, false, false);
        sub.assert_true(resp_cc.is_private(), "Response has private flag");
        sub.assert_true(resp_cc.private_overflow || resp_cc.private_fields.len == 0, "Unqualified private must flag full privacy");
    };

    t.run("Empty private=\"\" directive must not leave response cacheable in shared cache") { sub =>
        var resp_map = wing::new_header_map();
        wing::append_header(resp_map, "Cache-Control", "private=\"\"");

        let resp_cc = wing::parse_cache_control_headers(resp_map, false, false);
        sub.assert_true(resp_cc.is_private(), "private=\"\" sets private flag");
        sub.assert_true(resp_cc.private_overflow || resp_cc.private_fields.len == 0, "Empty private=\"\" must flag full privacy");
    };

    t.run("Vary snapshot with header value > 256 bytes must invalidate snapshot") { sub =>
        var req_headers = wing::new_header_map();
        var long_val: u8[>..] = [];
        for i in 300 { long_val.push('k'); }
        wing::append_header(req_headers, "X-Auth-Token", long_val[..]);

        let snap = wing::record_vary_snapshot("X-Auth-Token", req_headers);
        sub.assert_false(snap.valid, "Varied request header > 256B MUST invalidate snapshot to prevent truncated cache hits");
    };
}

// ----------------------------------------------------------------------------
// 6. URL & Origin (core/url/*)
// ----------------------------------------------------------------------------
fn test_url_origin_punycode_and_view_validation(t: core::T&) {
    t.run("DNS label > 63 bytes in URL must return InvalidHost (CVE-2026-97044)") { sub =>
        var long_url: u8[..256] = [];
        long_url.append("http://");
        for i in 64 { long_url.push('a'); }
        long_url.append(".com/");

        let parsed, err = core::parse_url(long_url[..]);
        sub.assert_false(parsed.valid, "URL with host label > 63B MUST be rejected");
        sub.assert_true(err == core::UrlParseError.InvalidHost, "Error must be InvalidHost");
    };

    t.run("parse_url_view rejects empty host on special http scheme") { sub =>
        let view, err = core::parse_url_view("http:///path");
        sub.assert_false(view.valid, "Empty host for http scheme MUST return valid == false");
    };

    t.run("parse_url_view rejects forbidden space in host") { sub =>
        let view, err = core::parse_url_view("http://exa mple.com/path");
        sub.assert_false(view.valid, "Space in host MUST return valid == false");
    };

    t.run("compute_public_suffix and extract_etld_plus_one with 180B domain must not abort") { sub =>
        var long_domain: u8[..256] = [];
        for i in 10 {
            long_domain.append("subdomain.");
        }
        long_domain.append("example.co.uk");

        var suffix: u8[..256] = [];
        let is_icann = core::public_suffix_with_icann(long_domain[..], suffix);
        sub.assert_eq(suffix[..], "co.uk", "Suffix correctly extracted for 180B host");

        var etld: u8[..256] = [];
        core::extract_etld_plus_one(long_domain[..], etld);
        sub.assert_eq(etld[..], "example.co.uk", "eTLD+1 correctly extracted for 180B host");
    };

    t.run("parse_endpoint returns InputTooLong on path overflow without abort") { sub =>
        var base_url_str: u8[>..] = [];
        base_url_str.append("http://example.com/");
        for i in 1500 { base_url_str.push('a'); }

        let base_url, _ = core::parse_url(base_url_str[..]);
        sub.assert_true(base_url.valid, "Base URL valid");

        var ep: u8[>..] = [];
        for i in 700 { ep.push('b'); }

        let res_url, err = core::parse_endpoint(base_url, ep[..]);
        sub.assert_false(res_url.valid, "Oversized combined path must return valid == false");
        sub.assert_true(err == core::UrlParseError.InputTooLong, "Error must be InputTooLong");
    };
}

// ----------------------------------------------------------------------------
// 7. Signatures, HSTS, and Trace Context (http/*)
// ----------------------------------------------------------------------------
fn test_http_extensions_signatures_hsts_trace(t: core::T&) {
    t.run("verify_http_signature must enforce signature label match") { sub =>
        var req = wing::new_request("GET", "https://example.com/data");
        var params = wing::HttpSignatureParams { label: "sig1", .. };
        params.components.push("@method");
        params.components.push("@target-uri");

        let key = "secret-key-1234";
        sub.assert_true(wing::sign_http_request(req, params, key), "Request signed successfully");

        // Verify with matching label
        sub.assert_true(wing::verify_http_signature(req, "sig1", params, key), "Verification with sig1 succeeds");

        // Verify with mismatched label MUST fail
        sub.assert_false(wing::verify_http_signature(req, "sig2", params, key), "Verification with sig2 MUST fail");
    };

    t.run("parse_hsts_header supports quoted max-age") { sub =>
        let dir, ok = wing::parse_hsts_header("max-age=\"31536000\"; includeSubDomains");
        sub.assert_true(ok, "Quoted max-age must parse successfully per RFC 6797 §6.1");
        sub.assert_eq(dir.max_age_sec, 31536000, "max-age value matches 31536000");
        sub.assert_true(dir.include_subdomains, "includeSubDomains matches");
    };

    t.run("parse_hsts_header rejects duplicate max-age directives") { sub =>
        let dir, ok = wing::parse_hsts_header("max-age=100; max-age=200");
        sub.assert_false(ok, "Duplicate max-age directive MUST be rejected per RFC 6797 §6.1");
    };

    t.run("tracestate parser rejects empty value") { sub =>
        let ts, ok = wing::parse_tracestate("foo=");
        sub.assert_false(ok, "Empty tracestate value MUST be rejected per W3C Section 3.3.1.2");
    };

    t.run("tracestate parser rejects key starting with non-alpha") { sub =>
        let ts, ok = wing::parse_tracestate("_bad=1");
        sub.assert_false(ok, "Tracestate key starting with '_' MUST be rejected per W3C Section 3.3.1.1");
    };
}

// ----------------------------------------------------------------------------
// 8. HTTP/2 Server Multiplexer & HPACK (server/*, http2/*, http/*)
// ----------------------------------------------------------------------------
fn test_h2_multiplexer_and_hpack_rfc9113(t: core::T&) {
    t.run("H2 server ingress rejects invalid SETTINGS_MAX_FRAME_SIZE < 16384") { sub =>
        var sess = wing::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        // Client preface + SETTINGS frame with MAX_FRAME_SIZE = 0
        var wire_in: u8[..64] = [];
        wire_in.append(wing::H2_CLIENT_PREFACE[..]);

        // Frame header: len=6, type=4 (SETTINGS), flags=0, stream_id=0
        wire_in.push(0x00); wire_in.push(0x00); wire_in.push(0x06);
        wire_in.push(0x04);
        wire_in.push(0x00);
        wire_in.push(0x00); wire_in.push(0x00); wire_in.push(0x00); wire_in.push(0x00);
        // Setting ID 0x05 (MAX_FRAME_SIZE), val 0x00000000
        wire_in.push(0x00); wire_in.push(0x05);
        wire_in.push(0x00); wire_in.push(0x00); wire_in.push(0x00); wire_in.push(0x00);

        var out_wire: u8[..512] = [];
        let consumed, ok = wing::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_in[..], 1000, out_wire);
        sub.assert_false(ok, "Invalid SETTINGS_MAX_FRAME_SIZE MUST return ok == false and emit GOAWAY");
    };

    t.run("validate_h2_stream_association rejects Priority and PushPromise on stream 0") { sub =>
        let hdr_prio = wing::H2FrameHeader {
            frame_type: wing::H2FrameType.Priority,
            flags: 0,
            stream_id: 0,
            payload_len: 5,
        };
        sub.assert_true(wing::validate_h2_stream_association(hdr_prio) == wing::H2ErrorCode.ProtocolError, "Priority on stream 0 is ProtocolError");

        let hdr_push = wing::H2FrameHeader {
            frame_type: wing::H2FrameType.PushPromise,
            flags: 0,
            stream_id: 0,
            payload_len: 4,
        };
        sub.assert_true(wing::validate_h2_stream_association(hdr_push) == wing::H2ErrorCode.ProtocolError, "PushPromise on stream 0 is ProtocolError");

        let hdr_ga = wing::H2FrameHeader {
            frame_type: wing::H2FrameType.GoAway,
            flags: 0,
            stream_id: 1,
            payload_len: 8,
        };
        sub.assert_true(wing::validate_h2_stream_association(hdr_ga) == wing::H2ErrorCode.ProtocolError, "GoAway on stream 1 is ProtocolError");
    };
}

// ----------------------------------------------------------------------------
// 9. HTTP/3 & QPACK (http3/*)
// ----------------------------------------------------------------------------
fn test_h3_and_qpack_rfc9114_rfc9204(t: core::T&) {
    t.run("H3 request stream accepts 103 Early Hints followed by 200 final response (Go #80687)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);
        let sid, _ = wing::open_request_stream(conn);

        // 1. Ingest 103 Early Hints HEADERS frame
        var qpack_103: u8[..64] = [];
        qpack_103.push(0x00); qpack_103.push(0x00);
        wing::encode_qpack_field(qpack_103, ":status", "103", true);

        var frame_103: u8[..128] = [];
        wing::encode_h3_headers_frame(frame_103, qpack_103[..]);
        let err1 = wing::handle_stream_data(conn, sid, true, frame_103[..], false);
        sub.assert_eq(err1, wing::H3_ERR_NO_ERROR, "103 Early Hints HEADERS accepted");

        // 2. Ingest 200 OK final response HEADERS frame
        var qpack_200: u8[..64] = [];
        qpack_200.push(0x00); qpack_200.push(0x00);
        wing::encode_qpack_field(qpack_200, ":status", "200", true);

        var frame_200: u8[..128] = [];
        wing::encode_h3_headers_frame(frame_200, qpack_200[..]);
        let err2 = wing::handle_stream_data(conn, sid, true, frame_200[..], true);
        sub.assert_eq(err2, wing::H3_ERR_NO_ERROR, "200 OK HEADERS after 103 Early Hints accepted");

        let status, ok_s = wing::get_status_code(conn, sid);
        sub.assert_true(ok_s, "Status code available");
        sub.assert_eq(status, 200, "Final status code is 200");
    };

    t.run("H3 rejects :status 101 Switching Protocols (RFC 9114 §4.3.2)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);
        let sid, _ = wing::open_request_stream(conn);

        var qpack_101: u8[..64] = [];
        qpack_101.push(0x00); qpack_101.push(0x00);
        wing::encode_qpack_field(qpack_101, ":status", "101", true);

        var frame_101: u8[..128] = [];
        wing::encode_h3_headers_frame(frame_101, qpack_101[..]);
        let err = wing::handle_stream_data(conn, sid, true, frame_101[..], false);
        sub.assert_eq(err, wing::H3_ERR_GENERAL_PROTOCOL, ":status 101 MUST return H3_ERR_GENERAL_PROTOCOL");
    };

    t.run("QPACK emit_field_checked rejects field names with invalid token chars") { sub =>
        var fields: wing::HeaderField[>..] = [];
        var budget: u64 = 4096;
        let err = wing::emit_field_checked(fields, budget, "bad name", "value", false);
        sub.assert_true(err == wing::QpackError.DecompressionFailed, "QPACK field name with space MUST fail");
    };
}

// ----------------------------------------------------------------------------
// 10. gRPC Stream & Status Codecs (grpc/*)
// ----------------------------------------------------------------------------
fn test_grpc_stream_truncation_and_status(t: core::T&) {
    t.run("parse_client_stream rejects > 32 messages rather than silently dropping 33rd") { sub =>
        var body: u8[>..] = [];
        for i in 33 {
            var msg_buf: u8[..32] = [];
            msg_buf.append("msg");
            format(msg_buf, i);
            wing::encode_grpc_lpm(msg_buf[..], body, false);
        }

        var reader = wing::new_grpc_client_stream_reader();
        let ok = wing::parse_client_stream(body[..], false, reader);
        sub.assert_false(ok, "parse_client_stream with > 32 messages MUST return false to prevent message loss");
    };

    t.run("extract_grpc_status with non-numeric grpc-status sets Unknown") { sub =>
        var hdrs = wing::new_header_map();
        var trls = wing::new_header_map();
        wing::append_header(trls, "grpc-status", "invalid-code");

        var status = wing::GrpcStatusCode.Ok;
        var msg: u8[..256] = [];
        wing::extract_grpc_status(hdrs, trls, status, msg);
        sub.assert_true(status == wing::GrpcStatusCode.Unknown, "Non-numeric grpc-status MUST map to GrpcStatusCode.Unknown");
    };

    t.run("parse_grpc_unary_response with truncated 3-byte body returns false") { sub =>
        var hdrs = wing::new_header_map();
        var trls = wing::new_header_map();
        let trunc_body: u8[3] = [0x00, 0x00, 0x05]; // Needs 5 bytes LPM header

        var resp = wing::new_grpc_response();
        let ok = wing::parse_grpc_unary_response(hdrs, trls, trunc_body[..], false, resp);
        sub.assert_false(ok, "Truncated gRPC body < 5 bytes MUST return false");
    };
}

// ----------------------------------------------------------------------------
// 11. Auth DPoP, Digest & PrivacyPass (auth/*, security/*)
// ----------------------------------------------------------------------------
fn test_auth_dpop_digest_privacypass(t: core::T&) {
    t.run("verify_dpop_method requires exact method claim match, preventing substring bypass") { sub =>
        // Claims JSON has DELETE method, but URL contains 'GET'
        let claims = "{\"htm\":\"DELETE\",\"htu\":\"https://example.com/GET_resource\",\"iat\":1700000000}";
        let matches_get = wing::verify_dpop_method(claims, "GET");
        sub.assert_false(matches_get, "DPoP verification for GET MUST NOT pass when claim is DELETE");
    };

    t.run("parse_digest_challenge rejects unclosed quotes") { sub =>
        let chal, ok = wing::parse_digest_challenge("Digest realm=\"unclosed, nonce=\"12345\"");
        sub.assert_false(ok, "Digest challenge with unclosed quote MUST return false");
    };

    t.run("parse_digest_challenge rejects parameter values > 128 bytes") { sub =>
        var raw_chal: u8[>..] = [];
        raw_chal.append("Digest realm=\"test\", nonce=\"");
        for i in 150 { raw_chal.push('a'); }
        raw_chal.append("\"");

        let chal, ok = wing::parse_digest_challenge(raw_chal[..]);
        sub.assert_false(ok, "Digest challenge parameter > 128B MUST return false");
    };
}

// ----------------------------------------------------------------------------
// 12. X.509, Server CONNECT Hygiene & Akamai (tls/*, server/*, fingerprint/*)
// ----------------------------------------------------------------------------
fn test_x509_critical_ext_server_connect_and_akamai(t: core::T&) {
    t.run("verify_signature_scheme_curve_binding rejects generic EC OID without curve match") { sub =>
        let ok = wing::verify_signature_scheme_curve_binding(
            wing::SIG_SCHEME_ECDSA_SECP256R1_SHA256,
            wing::OID_EC_PUBLIC_KEY[..],
        );
        sub.assert_false(ok, "Generic id-ecPublicKey without curve binding MUST be rejected");
    };

    t.run("HTTP/1 CONNECT fast-path sets Connection: close and consumes all bytes (CVE-2026-94439)") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        server.fast_path = true;

        var wire_in: u8[..256] = [];
        wire_in.append("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: example.com\r\n\r\n");

        var wire_out: u8[..1024] = [];
        let count, total_consumed, ok = wing::handle_connection_wire_pipelined_stream(server, "127.0.0.1", wire_in[..], 1000, wire_out);
        sub.assert_true(ok, "CONNECT request handled");
        sub.assert_eq(count, 1, "Only the CONNECT request was processed");
        sub.assert_eq(total_consumed, wire_in.len, "All post-CONNECT tunnel bytes consumed to prevent HTTP/1 pipelining smuggling");
        sub.assert_true(core::contains(wire_out[..], "connection: close") || core::contains(wire_out[..], "Connection: close"), "CONNECT response must contain Connection: close");
    };

    t.run("parse_akamai_fingerprint rejects > 16 settings") { sub =>
        var raw_fp: u8[..512] = [];
        for i in 17 {
            if i > 0 { raw_fp.push(';'); }
            format(raw_fp, i + 1);
            raw_fp.push(':');
            raw_fp.append("100");
        }
        raw_fp.append("|15663105|0|m,a,s,p");

        let fp, ok = wing::parse_akamai_fingerprint(raw_fp[..]);
        sub.assert_false(ok, "Akamai fingerprint with > 16 settings MUST return false rather than dropping settings");
    };

    t.run("order_pseudo_headers handles pseudo_headers > 4 chars without abort") { sub =>
        var fp = wing::AkamaiFingerprint { .. };
        fp.pseudo_headers.push('m');
        fp.pseudo_headers.push('a');
        fp.pseudo_headers.push('s');
        fp.pseudo_headers.push('p');
        fp.pseudo_headers.push('x'); // 5th pseudo header

        var out_hdrs: wing::HeaderItem[..4] = [];
        wing::order_pseudo_headers(fp, "GET", "example.com", "https", "/", out_hdrs);
        sub.assert_eq(out_hdrs.len, 4, "Bounded to 4 pseudo headers without abort");
    };
}

// ----------------------------------------------------------------------------
// Main Runner
// ----------------------------------------------------------------------------
fn main() {
    var runner = core::new_runner("RED Suite Phase 12: Fixed Buffer Limits & Security Hardening", core::Verbosity.Verbose);

    core::run_case(runner, "1. NoVarySearch truncation and bounds (http/novarysearch.goose)", test_novarysearch_truncation_and_bounds);
    core::run_case(runner, "2. Chunked FSM & extensions RFC 9112 (http/headers/*)", test_chunked_fsm_and_extensions_rfc9112);
    core::run_case(runner, "3. HTTP/1.x headers CL, host, cookie bounds (http/headers/*)", test_http1_headers_cl_host_and_cookie_bounds);
    core::run_case(runner, "4. MIME & SFV truncation smuggling (http/mime.goose)", test_mime_and_sfv_truncation_smuggling);
    core::run_case(runner, "5. Cache-Control & Vary RFC 9111 (http/cache/*)", test_cache_control_and_vary_poisoning_rfc9111);
    core::run_case(runner, "6. URL & Origin validation & bounds (core/url/*)", test_url_origin_punycode_and_view_validation);
    core::run_case(runner, "7. Signatures, HSTS, Trace Context (http/*)", test_http_extensions_signatures_hsts_trace);
    core::run_case(runner, "8. H2 multiplexer & HPACK RFC 9113 (server/*, http2/*, http/*)", test_h2_multiplexer_and_hpack_rfc9113);
    core::run_case(runner, "9. HTTP/3 & QPACK RFC 9114 / RFC 9204 (http3/*)", test_h3_and_qpack_rfc9114_rfc9204);
    core::run_case(runner, "10. gRPC stream & status codecs (grpc/*)", test_grpc_stream_truncation_and_status);
    core::run_case(runner, "11. Auth DPoP, Digest & PrivacyPass (auth/*, security/*)", test_auth_dpop_digest_privacypass);
    core::run_case(runner, "12. X.509, Server CONNECT hygiene & Akamai (tls/*, server/*, fingerprint/*)", test_x509_critical_ext_server_connect_and_akamai);

    let ok = core::finish(runner);
    assert(ok);
}
