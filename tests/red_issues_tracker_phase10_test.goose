// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Phase 10 RED test suite: Heapless Fixed-Capacity Buffer Safety & RFC Invariants
// Tests capacity truncation smuggling, bounds aborts, and RFC protocol non-conformances:
//
// 1. Path dot-segment desync when segments exceed buffer capacity (core/url/parser.goose)
// 2. URL oversized input & scheme handling without runtime abort (core/url/parser.goose)
// 3. Query parameter smuggling & key truncation false match (core/url/query.goose)
// 4. MediaType parameter truncation smuggling & duplicate boundary (http/mime.goose)
// 5. Multipart oversized Content-Type header on part without abort (http/multipart.goose)
// 6. HPACK literal header with indexed name value > 16B abort (http2/hpack.goose)
// 7. HTTP/2 :authority whitespace and comma rejection (http2/hpack.goose)
// 8. HTTP/3 unknown pseudo-header (:custom) & CTL character rejection (http3/connection.goose)
// 9. Router path capacity truncation smuggling (server/router.goose)
// 10. Alt-Svc oversized proto/host/endpoint capacity safety (http/altsvc.goose)

import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. Path dot-segment desync on segment capacity overflow (core/url/parser.goose)
// ----------------------------------------------------------------------------
fn test_path_dot_segment_capacity_desync(t: core::T&) {
    t.run("Path dot-segment normalization MUST NOT desync when segments exceed 256") { sub =>
        // Construct a URL with 256 's' segments, followed by 'target' and '/..'
        // E.g.: http://example.com/s/s/.../s/target/..
        // Total segments before '..': 257.
        // If segment 257 ('target') is omitted from seg_starts, '/..' pops segment 256 ('s'),
        // leaving 'target' in the path and deleting an innocent earlier segment!
        var raw_url: u8[..2048] = [];
        raw_url.append("http://example.com");
        for i in 256 {
            raw_url.append("/s");
        }
        raw_url.append("/target/..");

        let parsed = core::new_url(raw_url[..]);
        sub.assert_true(parsed.valid, "URL with 257 segments should parse or fail safely");

        let path = core::pathname(parsed);
        // 'target' should have been canceled out by '..'
        let has_target = core::index_of_slice(path, "target") >= 0;
        sub.assert_false(has_target, "Path segment 'target' MUST be canceled by '/..' and not leak into normalized path");

        // Count how many '/s' segments remain: must be exactly 256!
        var s_count = 0;
        var cur: i64 = 0;
        while cur < path.len {
            let idx = core::index_of_slice(path[cur..], "/s");
            if idx >= 0 {
                s_count++;
                cur += idx + 2;
            } else {
                break;
            }
        }
        sub.assert_eq(s_count, 256, "Exactly 256 '/s' segments must remain; segment 256 MUST NOT be popped by target/..");
    };

    t.run("Fixed-capacity try_push and try_append return false on capacity boundary") { sub =>
        var arr: i32[..4] = [];
        sub.assert_true(arr.try_push(10), "try_push 1 should succeed");
        sub.assert_true(arr.try_push(20), "try_push 2 should succeed");
        sub.assert_true(arr.try_push(30), "try_push 3 should succeed");
        sub.assert_true(arr.try_push(40), "try_push 4 should succeed");
        sub.assert_false(arr.try_push(50), "try_push 5 MUST fail on full buffer");
        sub.assert_eq(arr.len, 4, "arr.len must remain 4 without truncation corruption");

        var str: u8[..6] = [];
        sub.assert_true(str.try_append("abc"), "try_append abc should succeed");
        sub.assert_false(str.try_append("defg"), "try_append defg MUST fail because 3 + 4 > 6");
        sub.assert_eq(str.len, 3, "str.len must remain 3 after failed try_append");
        sub.assert_true(str.try_append("def"), "try_append def should succeed exactly filling capacity");
        sub.assert_eq(str.len, 6, "str.len must be 6");
    };

    t.run("URL path depth exceeding 1024 segments returns UrlParseError.PathTooDeep") { sub =>
        var deep_path: u8[..2048] = [];
        deep_path.append("http://example.com");
        for i in 1025 {
            deep_path.push('/');
        }

        let parsed, err = core::parse_url(deep_path[..]);
        sub.assert_false(parsed.valid, "URL with > 1024 segments must be invalid");
        sub.assert_true(err == core::UrlParseError.PathTooDeep, "Error code MUST be UrlParseError.PathTooDeep");
    };
}

// ----------------------------------------------------------------------------
// 2. URL oversized input & scheme handling without runtime abort (core/url/parser.goose)
// ----------------------------------------------------------------------------
fn test_url_oversized_input_no_abort(t: core::T&) {
    t.run("URL with scheme > 64 bytes MUST be rejected gracefully without abort") { sub =>
        var long_scheme: u8[..128] = [];
        for i in 70 { long_scheme.push('a'); }
        long_scheme.append("://example.com/");

        let parsed = core::new_url(long_scheme[..]);
        sub.assert_false(parsed.valid, "Scheme > 64 bytes MUST be marked invalid without abort");
    };

    t.run("URL input > 2048 bytes MUST be rejected gracefully without abort") { sub =>
        var giant_url: u8[>..] = [];
        giant_url.append("http://example.com/");
        for i in 2100 { giant_url.push('x'); }

        let parsed = core::new_url(giant_url[..]);
        sub.assert_false(parsed.valid, "URL input > 2048 bytes MUST be rejected without bounds abort");
    };
}

// ----------------------------------------------------------------------------
// 3. Query parameter smuggling & key truncation false match (core/url/query.goose)
// ----------------------------------------------------------------------------
fn test_query_parameter_smuggling_and_truncation(t: core::T&) {
    t.run("Fast query param lookup MUST NOT falsely match when key exceeds 64 bytes") { sub =>
        // Construct query: ?aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_evil=1
        // (64 'a's followed by '_evil')
        var raw_query: u8[..256] = [];
        raw_query.append("?");
        for i in 64 { raw_query.push('a'); }
        raw_query.append("_evil=1");

        // Search for 64 'a's: it MUST NOT match!
        var search_key: u8[..64] = [];
        for i in 64 { search_key.push('a'); }

        var out_val: u8[..64] = [];
        let found, _ = core::get_query_param_fast(raw_query[..], search_key[..], out_val);
        sub.assert_false(found, "Fast query param lookup MUST NOT falsely match truncated 64-byte key");
    };

    t.run("Query param parser MUST NOT silently drop parameter 129 (smuggling)") { sub =>
        // Construct query with 128 benign params followed by '&admin=true'
        var raw_query: u8[>..] = [];
        for i in 128 {
            if i > 0 { raw_query.push('&'); }
            raw_query.append("p");
            core::format_u64_dec(i as u64, raw_query);
            raw_query.append("=val");
        }
        raw_query.append("&admin=true");

        // Fixed-capacity protocol decoders must treat buffer overflow as an explicit error
        let count_valid = core::validate_query_param_count(raw_query[..]);
        sub.assert_false(count_valid, "validate_query_param_count MUST reject query when parameters exceed capacity 128");

        let list = core::parse_query_params(raw_query[..]);
        sub.assert_true(list.overflow, "parse_query_params MUST flag overflow when parameters exceed capacity 128");
    };
}

// ----------------------------------------------------------------------------
// 4. MediaType parameter truncation smuggling & duplicate boundary (http/mime.goose)
// ----------------------------------------------------------------------------
fn test_mime_parameter_truncation_and_boundary(t: core::T&) {
    t.run("MediaType parameter count > 16 MUST fail parsing (no silent drop)") { sub =>
        // 16 dummy parameters followed by '; boundary=evil_boundary'
        var raw_mt: u8[..1024] = [];
        raw_mt.append("multipart/form-data");
        for i in 16 {
            raw_mt.append("; p");
            core::format_u64_dec(i as u64, raw_mt);
            raw_mt.append("=val");
        }
        raw_mt.append("; boundary=evil_boundary");

        let mt, ok = wing::parse_media_type(raw_mt[..]);
        sub.assert_false(ok, "MediaType with > 16 parameters MUST fail parsing instead of silently dropping boundary");
    };

    t.run("Duplicate boundary parameter MUST be rejected (RFC 2046 / Go #82343)") { sub =>
        let raw = "multipart/form-data; boundary=first; boundary=second";
        let mt, ok = wing::parse_media_type(raw);
        sub.assert_false(ok, "Duplicate boundary parameter MUST be rejected");
    };

    t.run("MediaType parameter value > 256 bytes MUST fail safely without abort") { sub =>
        var raw_long_val: u8[..512] = [];
        raw_long_val.append("text/plain; charset=\"");
        for i in 300 { raw_long_val.push('u'); }
        raw_long_val.append("\"");

        let mt, ok = wing::parse_media_type(raw_long_val[..]);
        sub.assert_false(ok, "Parameter value > 256 bytes MUST fail parsing safely without abort");
    };
}

// ----------------------------------------------------------------------------
// 5. Multipart oversized Content-Type header on part without abort (http/multipart.goose)
// ----------------------------------------------------------------------------
fn test_multipart_oversized_content_type_no_abort(t: core::T&) {
    t.run("Multipart part with Content-Type > 64 bytes MUST NOT abort") { sub =>
        var body: u8[..1024] = [];
        body.append("--myboundary\r\n");
        body.append("Content-Disposition: form-data; name=\"upload\"; filename=\"test.docx\"\r\n");
        // 71-byte Content-Type (exceeds part.content_type: u8[..64] capacity)
        body.append("Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document\r\n\r\n");
        body.append("payload content\r\n");
        body.append("--myboundary--\r\n");

        let msg, err = wing::parse_multipart(body[..], "myboundary");
        sub.assert_true(wing::is_ok(err), "Part with long Content-Type header MUST parse without bounds abort");
        sub.assert_eq(msg.parts.len, 1, "Parsed 1 part");
        sub.assert_true(msg.parts[0].content_type.len > 0, "Part content_type must be captured");
    };
}

// ----------------------------------------------------------------------------
// 6. HPACK literal header with indexed name value > 16B abort (http2/hpack.goose)
// ----------------------------------------------------------------------------
fn test_hpack_literal_indexed_name_dynamic_value_overflow(t: core::T&) {
    t.run("Literal header with indexed name pointing to dynamic table value > 16B MUST NOT abort") { sub =>
        var dt = wing::new_dynamic_table(4096);
        // Insert entry into dynamic table with name 'custom-header' and value '01234567890123456789' (20 bytes > 16)
        wing::insert_header(dt, "custom-header", "01234567890123456789");

        // Encode a Literal Header Field with Incremental Indexing - Indexed Name
        // Dynamic table index 62 is the newly added entry (static table has 61 entries)
        var wire: u8[..64] = [];
        // Bit pattern: 01xxxxxx (0x40 | index 62) -> 0x40 | 62 = 0x7E
        wire.push(0x7E);
        // New value as 7-bit string literal: 'newval' (len 6)
        wire.push(0x06);
        wire.append("newval");

        var out_headers = wing::DecodedH2HeaderList { .. };
        let err_code = wing::decode_hpack_header_block(dt, wire[..], out_headers);
        sub.assert_eq(err_code, wing::ERR_NO_ERROR, "Literal header with indexed name from dynamic table MUST decode without bounds abort");
        sub.assert_eq(out_headers.fields.len, 1, "Decoded 1 header");
        sub.assert_eq(out_headers.fields[0].name[..], "custom-header", "Header name matches dynamic table entry");
        sub.assert_eq(out_headers.fields[0].value[..], "newval", "Header value matches literal value");
    };
}

// ----------------------------------------------------------------------------
// 7. HTTP/2 :authority whitespace and comma rejection (http2/hpack.goose)
// ----------------------------------------------------------------------------
fn test_h2_authority_whitespace_rejection(t: core::T&) {
    t.run(":authority with interior space MUST return ERR_PROTOCOL_ERROR") { sub =>
        var headers = wing::DecodedH2HeaderList { .. };
        let ok_meth = wing::validate_header_ordering_and_rules(headers, ":method", "GET");
        headers.fields.push(wing::DecodedH2Header { name: ":method", value: "GET", .. });

        let code = wing::validate_header_ordering_and_rules(headers, ":authority", "example.com :80");
        sub.assert_eq(code, wing::ERR_PROTOCOL_ERROR, ":authority with space MUST be rejected with ERR_PROTOCOL_ERROR");
    };

    t.run(":authority with comma MUST return ERR_PROTOCOL_ERROR") { sub =>
        var headers = wing::DecodedH2HeaderList { .. };
        let ok_meth = wing::validate_header_ordering_and_rules(headers, ":method", "GET");
        headers.fields.push(wing::DecodedH2Header { name: ":method", value: "GET", .. });

        let code = wing::validate_header_ordering_and_rules(headers, ":authority", "example.com,evil.com");
        sub.assert_eq(code, wing::ERR_PROTOCOL_ERROR, ":authority with comma MUST be rejected with ERR_PROTOCOL_ERROR");
    };
}

// ----------------------------------------------------------------------------
// 8. HTTP/3 unknown pseudo-header (:custom) & CTL character rejection (http3/connection.goose)
// ----------------------------------------------------------------------------
fn test_h3_pseudo_header_unknown_and_ctl(t: core::T&) {
    t.run("HTTP/3 request with unknown pseudo-header :custom MUST return error") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        let s_id, ok_open = conn.open_request_stream();
        sub.assert_true(ok_open, "Stream opened");

        // Encode QPACK headers with unknown pseudo-header :custom
        var qpack_buf: u8[>..] = [0x00, 0x00];
        wing::encode_qpack_field(qpack_buf, ":method", "GET");
        wing::encode_qpack_field(qpack_buf, ":scheme", "https");
        wing::encode_qpack_field(qpack_buf, ":path", "/");
        wing::encode_qpack_field(qpack_buf, ":custom", "invalid");

        var wire_buf: u8[>..] = [];
        wing::encode_h3_headers_frame(wire_buf, qpack_buf[..]);

        let res = conn.handle_stream_data(s_id, true, wire_buf[..], false);
        sub.assert_true(res != wing::H3_ERR_NO_ERROR, "HTTP/3 unknown pseudo-header :custom MUST be rejected with error (RFC 9114 §4.3)");
    };

    t.run("HTTP/3 header with CTL character MUST return error") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        let s_id, ok_open = conn.open_request_stream();
        sub.assert_true(ok_open, "Stream opened");

        // Encode QPACK headers with CTL char 0x01 in header value
        var qpack_buf: u8[>..] = [0x00, 0x00];
        wing::encode_qpack_field(qpack_buf, ":method", "GET");
        wing::encode_qpack_field(qpack_buf, ":scheme", "https");
        wing::encode_qpack_field(qpack_buf, ":path", "/");
        wing::encode_qpack_field(qpack_buf, "custom", "bad\x01value");

        var wire_buf: u8[>..] = [];
        wing::encode_h3_headers_frame(wire_buf, qpack_buf[..]);

        let res = conn.handle_stream_data(s_id, true, wire_buf[..], false);
        sub.assert_true(res != wing::H3_ERR_NO_ERROR, "HTTP/3 header value with CTL MUST be rejected with error (RFC 9114 §4.2)");
    };
}

// ----------------------------------------------------------------------------
// 9. Router path capacity truncation smuggling (server/router.goose)
// ----------------------------------------------------------------------------
fn test_router_path_capacity_truncation_smuggling(t: core::T&) {
    t.run("Router MUST NOT truncate oversized path to match parent route") { sub =>
        var router = wing::new_radix_router();
        wing::add_route(router, "GET", "/admin", 1);

        // Path is /admin/ + 520 'x's (exceeds 512 bytes)
        var long_path: u8[..600] = [];
        long_path.append("/admin/");
        for i in 520 { long_path.push('x'); }

        var params = wing::ZeroAllocParams { .. };
        let match_res = wing::match_route(router, "GET", long_path[..], params);
        let is_found = match match_res {
            Found _ => true,
            _ => false,
        };
        sub.assert_false(is_found, "Oversized non-matching subpath MUST NOT be truncated to match /admin");
    };
}

// ----------------------------------------------------------------------------
// 10. Alt-Svc oversized proto/host/endpoint capacity safety (http/altsvc.goose)
// ----------------------------------------------------------------------------
fn test_altsvc_oversized_capacity_safety(t: core::T&) {
    t.run("Alt-Svc with > 4 endpoints MUST NOT abort on fixed array overflow") { sub =>
        var endpoints: wing::AltSvcEndpoint[..4] = [];
        // Header with 5 endpoints
        let raw = "h3=\":443\", h2=\":443\", h3-29=\":443\", h3-Q050=\":443\", h3-Q046=\":443\"";
        let ok, is_clear = wing::parse_altsvc_header(raw, endpoints);
        sub.assert_true(ok, "Alt-Svc with 5 endpoints parsed without aborting");
        sub.assert_eq(endpoints.len, 4, "Capacity clamped cleanly at 4 without crash");
    };

    t.run("Alt-Svc with proto > 16 bytes MUST NOT abort") { sub =>
        var endpoints: wing::AltSvcEndpoint[..4] = [];
        let raw = "superlongprotonamethatexceeds16bytes=\":443\"";
        let ok, is_clear = wing::parse_altsvc_header(raw, endpoints);
        sub.assert_true(ok, "Alt-Svc with long proto parsed without aborting");
    };
}

fn main() {
    var runner = core::new_runner("RED Suite Phase 10: Fixed-Capacity Smuggling & RFC Flaws", core::Verbosity.Verbose);
    core::run_case(runner, "1. Path dot-segment capacity desync (core/url/parser.goose)", test_path_dot_segment_capacity_desync);
    core::run_case(runner, "2. URL oversized input handling without abort (core/url/parser.goose)", test_url_oversized_input_no_abort);
    core::run_case(runner, "3. Query parameter smuggling & key truncation (core/url/query.goose)", test_query_parameter_smuggling_and_truncation);
    core::run_case(runner, "4. MediaType parameter truncation & duplicate boundary (http/mime.goose)", test_mime_parameter_truncation_and_boundary);
    core::run_case(runner, "5. Multipart oversized Content-Type header on part (http/multipart.goose)", test_multipart_oversized_content_type_no_abort);
    core::run_case(runner, "6. HPACK literal header indexed name dynamic value overflow (http2/hpack.goose)", test_hpack_literal_indexed_name_dynamic_value_overflow);
    core::run_case(runner, "7. HTTP/2 :authority whitespace and comma rejection (http2/hpack.goose)", test_h2_authority_whitespace_rejection);
    core::run_case(runner, "8. HTTP/3 unknown pseudo-header & CTL character rejection (http3/connection.goose)", test_h3_pseudo_header_unknown_and_ctl);
    core::run_case(runner, "9. Router path capacity truncation smuggling (server/router.goose)", test_router_path_capacity_truncation_smuggling);
    core::run_case(runner, "10. Alt-Svc oversized proto/host/endpoints capacity safety (http/altsvc.goose)", test_altsvc_oversized_capacity_safety);
    let ok = core::finish(runner);
    assert(ok);
}
