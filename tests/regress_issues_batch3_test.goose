// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Issue Regression Suite Batch 3 (Phases 11-15)
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// Issues covered:
// 1. SFV string & display string truncation vs syntax rejection (http/mime.goose)
// 2. SFV parameter & list/dict capacity smuggling (http/mime.goose)
// 3. RFC 9111 Vary header > 16 fields cache poisoning defense (http/cache/validators.goose)
// 4. No-Vary-Search parameter capacity & key overflow safety (http/novarysearch.goose)
// 5. Digest challenge parameter value > 128B rejection without corruption (auth/digest.goose)
// 6. JWT claims & header oversized field safety without runtime abort (auth/jwt.goose)
// 7. W3C Trace Context 256-byte key specification compliance (http/trace.goose)
// 8. HTTP/1.x obs-fold buffer capacity overflow safety (http/headers.goose)

// ----------------------------------------------------------------------------
// 1. SFV string & display string overflow rejection (http/mime.goose)
// ----------------------------------------------------------------------------
fn test_sfv_string_overflow_rejection(t: lit::T&) {
    t.run("SFV string > 1088 bytes must be rejected as syntax error") { sub =>
        var raw_str: u8[>..] = [];
        raw_str.push('"');
        for i in 1090 {
            raw_str.push('a');
        }
        raw_str.push('"');

        var item = wing::SfvItem { .. };
        let ok = wing::parse_sfv_item(raw_str[..], item);
        sub.assert_false(ok, "SFV string > 1088 bytes MUST return false and not silently truncate");
    };

    t.run("SFV display string > 1088 bytes must be rejected as syntax error") { sub =>
        var raw_dstr: u8[>..] = [];
        raw_dstr.append("%\"");
        for i in 1090 {
            raw_dstr.push('b');
        }
        raw_dstr.push('"');

        var item = wing::SfvItem { .. };
        let ok = wing::parse_sfv_item(raw_dstr[..], item);
        sub.assert_false(ok, "SFV display string > 1088 bytes MUST return false and not silently truncate");
    };
}

// ----------------------------------------------------------------------------
// 2. SFV parameter & list/dict capacity smuggling (http/mime.goose)
// ----------------------------------------------------------------------------
fn test_sfv_capacity_smuggling_rejection(t: lit::T&) {
    t.run("SFV item with > 16 parameters must be rejected rather than dropping 17th") { sub =>
        var raw_params: u8[..1024] = [];
        raw_params.append("token");
        for i in 17 {
            raw_params.append(";p");
            format(raw_params, i);
            raw_params.append("=1");
        }

        var item = wing::SfvItem { .. };
        let ok = wing::parse_sfv_item(raw_params[..], item);
        sub.assert_false(ok, "SFV parameters > 16 MUST be rejected rather than dropping security parameters");
    };

    t.run("SFV dictionary with > 64 keys must be rejected") { sub =>
        var raw_dict: u8[>..] = [];
        for i in 65 {
            if i > 0 { raw_dict.append(", "); }
            raw_dict.append("k");
            format(raw_dict, i);
            raw_dict.append("=1");
        }

        var dict = wing::SfvDict { .. };
        let ok = wing::parse_sfv_dict(raw_dict[..], dict);
        sub.assert_false(ok, "SFV dict > 64 entries MUST return false and not drop keys");
    };
}

// ----------------------------------------------------------------------------
// 3. RFC 9111 Vary header > 16 fields cache poisoning defense (http/cache/validators.goose)
// ----------------------------------------------------------------------------
fn test_vary_snapshot_capacity_poisoning_defense(t: lit::T&) {
    t.run("Vary header with > 16 fields MUST invalidate snapshot to prevent cache poisoning") { sub =>
        var vary_val: u8[..512] = [];
        for i in 17 {
            if i > 0 { vary_val.append(", "); }
            vary_val.append("X-Vary-");
            format(vary_val, i);
        }

        var req_headers = wing::HeaderMap { .. };
        wing::append_header(req_headers, "X-Vary-16", "secret-value");

        let snap = wing::record_vary_snapshot(vary_val[..], req_headers);
        sub.assert_false(snap.valid, "Vary snapshot with > 16 fields MUST have valid == false (RFC 9111 §4.1)");

        let matches = wing::matches_vary(snap, req_headers);
        sub.assert_false(matches, "matches_vary MUST return false when snapshot is invalid to prevent poisoning");
    };
}

// ----------------------------------------------------------------------------
// 4. No-Vary-Search parameter capacity & key overflow safety (http/novarysearch.goose)
// ----------------------------------------------------------------------------
fn test_novarysearch_capacity_safety(t: lit::T&) {
    t.run("normalize_query_for_cache MUST fail safely on key > 64B without truncating") { sub =>
        var raw_q: u8[..512] = [];
        for i in 70 { raw_q.push('x'); }
        raw_q.append("=val");

        var nvs = wing::NoVarySearch { .. };
        var out_norm: u8[..512] = [];
        wing::normalize_query_for_cache(raw_q[..], nvs, out_norm);
        // Truncation smuggling check: key must not be silently truncated into 64 bytes
        let has_truncated = out_norm.len >= 64 && out_norm[..64] == raw_q[..64];
        sub.assert_false(has_truncated, "normalize_query_for_cache MUST NOT silently truncate key > 64B");
    };
}

// ----------------------------------------------------------------------------
// 5. Digest challenge parameter value > 128B rejection without corruption (auth/digest.goose)
// ----------------------------------------------------------------------------
fn test_digest_param_overflow_safety(t: lit::T&) {
    t.run("Digest challenge with nonce > 128 bytes MUST NOT be silently truncated") { sub =>
        var long_chal: u8[>..] = [];
        long_chal.append("Digest realm=\"test\", nonce=\"");
        for i in 150 { long_chal.push('a'); }
        long_chal.append("\", qop=\"auth\"");

        let chal, ok = wing::parse_digest_challenge(long_chal[..]);
        sub.assert_false(ok, "Digest challenge with nonce > 128B MUST return false and not truncate nonce");
    };
}

// ----------------------------------------------------------------------------
// 6. JWT claims & header oversized field safety without runtime abort (auth/jwt.goose)
// ----------------------------------------------------------------------------
fn test_jwt_oversized_fields_no_abort(t: lit::T&) {
    t.run("JWT claims with iss > 128 bytes MUST return InvalidClaimsJson without abort") { sub =>
        var long_iss: u8[>..] = [];
        long_iss.append("{\"iss\":\"https://accounts.example.com/");
        for i in 150 { long_iss.push('y'); }
        long_iss.append("\",\"sub\":\"user1\"}");

        var b64_claims: u8[>..] = [];
        core::base64url_encode(long_iss[..], b64_claims);

        var claims = wing::JwtClaims { .. };
        let err = wing::decode_jwt_claims(b64_claims[..], claims);
        sub.assert_true(err == wing::JwtError.InvalidClaimsJson, "JWT claims with iss > 128B must return InvalidClaimsJson");
    };
}

// ----------------------------------------------------------------------------
// 7. W3C Trace Context 256-byte key specification compliance (http/trace.goose)
// ----------------------------------------------------------------------------
fn test_trace_context_spec_key_length(t: lit::T&) {
    t.run("tracestate parser MUST accept valid 100-byte multi-tenant key without abort") { sub =>
        // Construct valid W3C key: 90 chars tenant + '@' + 9 chars system = 100 chars
        var header_val: u8[..256] = [];
        for i in 90 { header_val.push('a'); }
        header_val.push('@');
        for i in 9 { header_val.push('b'); }
        header_val.append("=congo");

        let ts, ok = wing::parse_tracestate(header_val[..]);
        sub.assert_true(ok, "W3C tracestate with 100-byte valid key MUST parse successfully");
        sub.assert_eq(ts.members.len, 1, "Exactly one member parsed");
    };
}

// ----------------------------------------------------------------------------
// 8. HTTP/1.x obs-fold buffer capacity overflow safety (http/headers.goose)
// ----------------------------------------------------------------------------
fn test_http_headers_obs_fold_capacity_safety(t: lit::T&) {
    t.run("Oversized obs-fold continuation MUST return CapacityExceeded without abort") { sub =>
        var headers_raw: u8[>..] = [];
        headers_raw.append("Host: example.com\r\nX-Fold: start\r\n");
        // Pad with continuations exceeding 8192 bytes
        for i in 100 {
            headers_raw.append(" ");
            for j in 90 { headers_raw.push('z'); }
            headers_raw.append("\r\n");
        }
        headers_raw.append("\r\n");

        var map = wing::HeaderMap { .. };
        let err = wing::parse_headers(headers_raw[..], map, true);
        sub.assert_true(err == wing::HeaderParseError.CapacityExceeded, "Oversized obs-fold MUST return CapacityExceeded");
    };
}

// --- Component: regress_issues_batch12 ---
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

// ----------------------------------------------------------------------------
// 1. NoVarySearch (http/novarysearch.goose)
// ----------------------------------------------------------------------------
fn test_novarysearch_truncation_and_bounds(t: lit::T&) {
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

    t.run("No-Vary-Search key-order defaults to true per W3C Section 2.1") { sub =>
        let nvs, ok = wing::parse_no_vary_search("params=(\"utm_source\")");
        sub.assert_true(ok, "Parse without key-order directive");
        sub.assert_true(nvs.key_order_matters, "key_order_matters MUST default to true");

        var out_norm: u8[..256] = [];
        wing::normalize_query_for_cache("b=2&a=1&c=3", nvs, out_norm);
        sub.assert_bytes_eq(out_norm[..], "b=2&a=1&c=3", "Order preserved when key-order directive is absent");

        let nvs_order, ok_order = wing::parse_no_vary_search("key-order");
        sub.assert_true(ok_order, "Parse key-order directive");
        sub.assert_false(nvs_order.key_order_matters, "key-order sets key_order_matters to false");

        var out_sorted: u8[..256] = [];
        wing::normalize_query_for_cache("b=2&a=1&c=3", nvs_order, out_sorted);
        sub.assert_bytes_eq(out_sorted[..], "a=1&b=2&c=3", "Order sorted when key-order is present");

        let nvs_q0, ok_q0 = wing::parse_no_vary_search("key-order=?0");
        sub.assert_true(ok_q0, "Parse key-order=?0");
        sub.assert_true(nvs_q0.key_order_matters, "key-order=?0 sets key_order_matters to true");
    };
}

// ----------------------------------------------------------------------------
// 2. Chunked FSM & Extensions (http/headers/chunked_fsm.goose, chunked.goose)
// ----------------------------------------------------------------------------
fn test_chunked_fsm_and_extensions_rfc9112(t: lit::T&) {
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
fn test_http1_headers_cl_host_and_cookie_bounds(t: lit::T&) {
    t.run("track_header_presence MUST reject invalid first Content-Length value") { sub =>
        var tracker = wing::HeaderPresenceTracker { .. };
        let ok = wing::track_header_presence(tracker, "Content-Length", "invalid", 0);
        sub.assert_false(ok, "Invalid first Content-Length MUST return false immediately");
    };

    t.run("validate_header_framing_conflicts rejects Host with interior comma") { sub =>
        var map = wing::HeaderMap { .. };
        let err = wing::parse_headers("Host: a.com, b.com\r\n\r\n", map);
        sub.assert_true(err == wing::HeaderParseError.InvalidHeaderValue, "Host with comma MUST be rejected");
    };

    t.run("validate_header_framing_conflicts rejects Host with interior space") { sub =>
        var map = wing::HeaderMap { .. };
        let err = wing::parse_headers("Host: a .com\r\n\r\n", map);
        sub.assert_true(err == wing::HeaderParseError.InvalidHeaderValue, "Host with space MUST be rejected");
    };

    t.run("get_set_cookie with Set-Cookie > 1024B must not abort") { sub =>
        var raw_hdr: u8[>..] = [];
        raw_hdr.append("Host: example.com\r\nSet-Cookie: session=");
        for i in 1500 { raw_hdr.push('x'); }
        raw_hdr.append("\r\n\r\n");

        var map = wing::HeaderMap { .. };
        let err = wing::parse_headers(raw_hdr[..], map);
        sub.assert_true(err == wing::HeaderParseError.None, "Headers parsed successfully");

        var cookies: u8[..1024][>..] = [];
        wing::get_set_cookie(map, cookies);
        sub.assert_eq(cookies.len, 1, "Exactly one Set-Cookie retrieved without abort");
    };

    t.run("classify_well_known_header recognises CORS access-control headers") { sub =>
        var map = wing::HeaderMap { .. };
        let raw = "Access-Control-Max-Age: 600\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: X-Custom, Authorization\r\n\r\n";
        let err = wing::parse_headers(raw, map);
        sub.assert_true(err == wing::HeaderParseError.None, "Headers parsed successfully");
        sub.assert_bytes_eq(wing::get_inline(map, wing::WellKnownHeader.AccessControlMaxAge), "600", "AccessControlMaxAge inline match");
        sub.assert_bytes_eq(wing::get_inline(map, wing::WellKnownHeader.AccessControlRequestMethod), "POST", "AccessControlRequestMethod inline match");
        sub.assert_bytes_eq(wing::get_inline(map, wing::WellKnownHeader.AccessControlRequestHeaders), "X-Custom, Authorization", "AccessControlRequestHeaders inline match");
    };
}

// ----------------------------------------------------------------------------
// 4. MIME & Structured Field Values (http/mime.goose)
// ----------------------------------------------------------------------------
fn test_mime_and_sfv_truncation_smuggling(t: lit::T&) {
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

    t.run("decompress_dcz_payload and decompress_dcb_payload reject corrupted payloads") { sub =>
        let corrupt = "corrupted non-compressed payload bytes";
        var out_dcz: u8[>..] = [];
        let ok_dcz = wing::decompress_dcz_payload(corrupt, "dictionary", out_dcz);
        sub.assert_false(ok_dcz, "decompress_dcz_payload MUST return false on corrupted data");
        sub.assert_eq(out_dcz.len, 0, "No raw bytes emitted to out_buf on DCZ error");

        var out_dcb: u8[>..] = [];
        let ok_dcb = wing::decompress_dcb_payload(corrupt, "dictionary", out_dcb);
        sub.assert_false(ok_dcb, "decompress_dcb_payload MUST return false on corrupted data");
        sub.assert_eq(out_dcb.len, 0, "No raw bytes emitted to out_buf on DCB error");
    };
}

// ----------------------------------------------------------------------------
// 5. Cache-Control & Vary (http/cache/*)
// ----------------------------------------------------------------------------
fn test_cache_control_and_vary_poisoning_rfc9111(t: lit::T&) {
    t.run("Unqualified private directive following qualified private must make response uncacheable in shared cache") { sub =>
        var req_map = wing::HeaderMap { .. };
        wing::append_header(req_map, ":method", "GET");

        var resp_map = wing::HeaderMap { .. };
        // Qualified private followed by unqualified private
        wing::append_header(resp_map, "Cache-Control", "private=\"X-Custom\", private");

        let resp_cc = wing::parse_cache_control_headers(
            resp_map,
            wing::CacheControlParseOptions { is_request: false, ignore_cargo_cult: false },
        );
        sub.assert_true(resp_cc.is_private(), "Response has private flag");
        sub.assert_true(resp_cc.private_overflow || resp_cc.private_fields.len == 0, "Unqualified private must flag full privacy");
    };

    t.run("Empty private=\"\" directive must not leave response cacheable in shared cache") { sub =>
        var resp_map = wing::HeaderMap { .. };
        wing::append_header(resp_map, "Cache-Control", "private=\"\"");

        let resp_cc = wing::parse_cache_control_headers(
            resp_map,
            wing::CacheControlParseOptions { is_request: false, ignore_cargo_cult: false },
        );
        sub.assert_true(resp_cc.is_private(), "private=\"\" sets private flag");
        sub.assert_true(resp_cc.private_overflow || resp_cc.private_fields.len == 0, "Empty private=\"\" must flag full privacy");
    };

    t.run("Vary snapshot with header value > 256 bytes must invalidate snapshot") { sub =>
        var req_headers = wing::HeaderMap { .. };
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
fn test_url_origin_punycode_and_view_validation(t: lit::T&) {
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
fn test_http_extensions_signatures_hsts_trace(t: lit::T&) {
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

    t.run("hsts rejects IP address literal and trims trailing dot") { sub =>
        var cache = wing::HstsCache { .. };
        // RFC 6797 §8.1.1: Rejection of IP address literals
        sub.assert_false(wing::hsts_cache_update(cache, "192.168.1.1", "max-age=31536000", 1000), "HSTS must reject IPv4 literal");
        sub.assert_false(wing::hsts_cache_update(cache, "::1", "max-age=31536000", 1000), "HSTS must reject IPv6 literal");
        sub.assert_false(wing::is_hsts_host(cache, "192.168.1.1", 1000), "IPv4 is not HSTS host");
        sub.assert_false(wing::is_hsts_host(cache, "127.0.0.1", 1000), "127.0.0.1 is not HSTS host");

        // FQDN trailing dot normalization
        sub.assert_true(wing::hsts_cache_update(cache, "example.com.", "max-age=31536000", 1000), "HSTS ingests FQDN with trailing dot");
        sub.assert_true(wing::is_hsts_host(cache, "example.com", 1000), "Matches without trailing dot");
        sub.assert_true(wing::is_hsts_host(cache, "example.com.", 1000), "Matches with trailing dot");
        sub.assert_true(wing::is_hsts_host(cache, "app.dev.", 1000), "Preloaded TLD matches with trailing dot");
    };
}

// ----------------------------------------------------------------------------
// 8. HTTP/2 Server Multiplexer & HPACK (server/*, http2/*, http/*)
// ----------------------------------------------------------------------------
fn test_h2_multiplexer_and_hpack_rfc9113(t: lit::T&) {
    t.run("H2 server ingress rejects invalid SETTINGS_MAX_FRAME_SIZE < 16384") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        // Client preface + SETTINGS frame with MAX_FRAME_SIZE = 0
        var wire_in: u8[..64] = [];
        wire_in.append(rfc::H2_CLIENT_PREFACE[..]);

        // Frame header: len=6, type=4 (SETTINGS), flags=0, stream_id=0
        wire_in.push(0x00); wire_in.push(0x00); wire_in.push(0x06);
        wire_in.push(0x04);
        wire_in.push(0x00);
        wire_in.push(0x00); wire_in.push(0x00); wire_in.push(0x00); wire_in.push(0x00);
        // Setting ID 0x05 (MAX_FRAME_SIZE), val 0x00000000
        wire_in.push(0x00); wire_in.push(0x05);
        wire_in.push(0x00); wire_in.push(0x00); wire_in.push(0x00); wire_in.push(0x00);

        var out_wire: u8[..512] = [];
        let consumed, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_in[..], 1000, out_wire);
        sub.assert_false(ok, "Invalid SETTINGS_MAX_FRAME_SIZE MUST return ok == false and emit GOAWAY");
    };

    t.run("validate_stream_id_association rejects Priority and PushPromise on stream 0") { sub =>
        sub.assert_eq(rfc::validate_stream_id_association(0, rfc::H2_FRAME_PRIORITY), rfc::H2_ERR_PROTOCOL_ERROR, "Priority on stream 0 is ProtocolError");
        sub.assert_eq(rfc::validate_stream_id_association(0, rfc::H2_FRAME_PUSH_PROMISE), rfc::H2_ERR_PROTOCOL_ERROR, "PushPromise on stream 0 is ProtocolError");
        sub.assert_eq(rfc::validate_stream_id_association(1, rfc::H2_FRAME_GOAWAY), rfc::H2_ERR_PROTOCOL_ERROR, "GoAway on stream 1 is ProtocolError");
    };

    t.run("H2Connection enforces settings flood and single headers frame bounds") { sub =>
        var conn = internal::new_h2_connection(0);

        // 1. Single HEADERS frame exceeding max_header_list_size (8192) must trigger EnhanceYourCalm
        let big_hdr = internal::FrameHeader {
            length:     12000,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  1,
        };
        let err_big = internal::on_ingress_frame_header(conn, big_hdr, 0);
        sub.assert_eq(err_big, rfc::H2_ERR_ENHANCE_YOUR_CALM, "Single HEADERS > 8KB triggers EnhanceYourCalm");

        // 2. SETTINGS flood defense (CVE-2019-9515)
        var conn_set = internal::new_h2_connection(0);
        for _ in 64 {
            let sf = internal::FrameHeader {
                length:     6,
                frame_type: rfc::H2_FRAME_SETTINGS,
                flags:      0x0,
                stream_id:  0,
            };
            sub.assert_eq(internal::on_ingress_frame_header(conn_set, sf, 0), rfc::H2_ERR_NO_ERROR);
        }
        let sf_65 = internal::FrameHeader {
            length:     6,
            frame_type: rfc::H2_FRAME_SETTINGS,
            flags:      0x0,
            stream_id:  0,
        };
        sub.assert_eq(internal::on_ingress_frame_header(conn_set, sf_65, 0), rfc::H2_ERR_ENHANCE_YOUR_CALM, "65th SETTINGS triggers EnhanceYourCalm");
    };
}

// ----------------------------------------------------------------------------
// 9. HTTP/3 & QPACK (http3/*)
// ----------------------------------------------------------------------------
fn test_h3_and_qpack_rfc9114_rfc9204(t: lit::T&) {
    t.run("H3 request stream accepts 103 Early Hints followed by 200 final response (Go #80687)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);
        let sid, _ = internal::open_request_stream(conn);

        // 1. Ingest 103 Early Hints HEADERS frame
        var qpack_103: u8[..64] = [];
        qpack_103.push(0x00); qpack_103.push(0x00);
        internal::encode_qpack_field(qpack_103, ":status", "103", true);

        var frame_103: u8[..128] = [];
        internal::encode_h3_headers_frame(frame_103, qpack_103[..]);
        let err1 = internal::handle_stream_data(conn, sid, true, frame_103[..], false);
        sub.assert_eq(err1, rfc::H3_ERR_NO_ERROR, "103 Early Hints HEADERS accepted");

        // 2. Ingest 200 OK final response HEADERS frame
        var qpack_200: u8[..64] = [];
        qpack_200.push(0x00); qpack_200.push(0x00);
        internal::encode_qpack_field(qpack_200, ":status", "200", true);

        var frame_200: u8[..128] = [];
        internal::encode_h3_headers_frame(frame_200, qpack_200[..]);
        let err2 = internal::handle_stream_data(conn, sid, true, frame_200[..], true);
        sub.assert_eq(err2, rfc::H3_ERR_NO_ERROR, "200 OK HEADERS after 103 Early Hints accepted");

        let status, ok_s = internal::get_status_code(conn, sid);
        sub.assert_true(ok_s, "Status code available");
        sub.assert_eq(status, 200, "Final status code is 200");
    };

    t.run("H3 rejects :status 101 Switching Protocols (RFC 9114 §4.3.2)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);
        let sid, _ = internal::open_request_stream(conn);

        var qpack_101: u8[..64] = [];
        qpack_101.push(0x00); qpack_101.push(0x00);
        internal::encode_qpack_field(qpack_101, ":status", "101", true);

        var frame_101: u8[..128] = [];
        internal::encode_h3_headers_frame(frame_101, qpack_101[..]);
        let err = internal::handle_stream_data(conn, sid, true, frame_101[..], false);
        sub.assert_eq(err, rfc::H3_ERR_GENERAL_PROTOCOL, ":status 101 MUST return H3_ERR_GENERAL_PROTOCOL");
    };

    t.run("QPACK emit_field_checked rejects field names with invalid token chars") { sub =>
        var fields: internal::HeaderField[>..] = [];
        var budget: u64                        = 4096;
        let err = internal::emit_field_checked(fields, budget, "bad name", "value", false);
        sub.assert_true(err == internal::QpackError.DecompressionFailed, "QPACK field name with space MUST fail");
    };
}

// ----------------------------------------------------------------------------
// 10. gRPC Stream & Status Codecs (grpc/*)
// ----------------------------------------------------------------------------
fn test_grpc_stream_truncation_and_status(t: lit::T&) {
    t.run("parse_client_stream rejects > 32 messages rather than silently dropping 33rd") { sub =>
        var body: u8[>..] = [];
        for i in 33 {
            var msg_buf: u8[..32] = [];
            msg_buf.append("msg");
            format(msg_buf, i);
            wing::encode_grpc_lpm(msg_buf[..], body, false);
        }

        var reader = wing::GrpcClientStreamReader { .. };
        let ok = wing::parse_client_stream(body[..], false, reader);
        sub.assert_false(ok, "parse_client_stream with > 32 messages MUST return false to prevent message loss");
    };

    t.run("extract_grpc_status with non-numeric grpc-status sets Unknown") { sub =>
        var hdrs = wing::HeaderMap { .. };
        var trls = wing::HeaderMap { .. };
        wing::append_header(trls, "grpc-status", "invalid-code");

        var status = wing::GrpcStatusCode.Ok;
        var msg: u8[..256] = [];
        wing::extract_grpc_status(hdrs, trls, status, msg);
        sub.assert_true(status == wing::GrpcStatusCode.Unknown, "Non-numeric grpc-status MUST map to GrpcStatusCode.Unknown");
    };

    t.run("parse_grpc_unary_response with truncated 3-byte body returns false") { sub =>
        var hdrs = wing::HeaderMap { .. };
        var trls = wing::HeaderMap { .. };
        let trunc_body: u8[3] = [0x00, 0x00, 0x05]; // Needs 5 bytes LPM header

        var resp = wing::GrpcResponse { .. };
        let ok = wing::parse_grpc_unary_response(hdrs, trls, trunc_body[..], false, resp);
        sub.assert_false(ok, "Truncated gRPC body < 5 bytes MUST return false");
    };
}

// ----------------------------------------------------------------------------
// 11. Auth DPoP, Digest & PrivacyPass (auth/*, security/*)
// ----------------------------------------------------------------------------
fn test_auth_dpop_digest_privacypass(t: lit::T&) {
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
fn test_x509_critical_ext_server_connect_and_akamai(t: lit::T&) {
    t.run("verify_signature_scheme_curve_binding rejects generic EC OID without curve match") { sub =>
        let ok = wing::verify_signature_scheme_curve_binding(
            rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256,
            rfc::OID_EC_PUBLIC_KEY[..],
        );
        sub.assert_false(ok, "Generic id-ecPublicKey without curve binding MUST be rejected");
    };

    t.run("HTTP/1 CONNECT sets Connection: close and consumes all bytes (CVE-2026-94439)") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);

        var wire_in: u8[..256] = [];
        wire_in.append("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: example.com\r\n\r\n");

        var wire_out: u8[..1024] = [];
        let count, total_consumed, ok, wants_close = wing::handle_connection_wire_pipelined_stream(server, "127.0.0.1", wire_in[..], 1000, wire_out);
        sub.assert_true(ok, "CONNECT request handled");
        sub.assert_true(wants_close, "CONNECT request must set wants_close");
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

        var out_hdrs = wing::HeaderMap { .. };
        wing::order_pseudo_headers(fp, "GET", "example.com", "https", "/", out_hdrs);
        sub.assert_eq(out_hdrs.entries.len, 4, "Bounded to 4 pseudo headers without abort");
    };
}

// ----------------------------------------------------------------------------
// Main Runner
// ----------------------------------------------------------------------------

// --- Component: regress_issues_batch13 ---
// Phase 13 RED test suite: RFC Protocol Invariants, Payload Truncation Smuggling,
// Boundary Validations, and Safe Resource Limits.
//
// 1. HTTP/2 Content-Length desync, padding bounds & mandatory pseudo-headers (server/h2_multiplexer.goose)
// 2. WebSocket Connection header token parsing & unfragmented frame capacity (realtime/websocket.goose)
// 3. Client Redirect cross-origin Origin leak on 307/308 & fragment capacity (client/redirect.goose)
// 4. Server-Sent Events empty data dispatch & retry integer overflow (realtime/sse.goose)
// 5. Multipart boundary trailing space & parameter truncation smuggling (http/multipart.goose)
// 6. Connection pool TLD wildcard SAN defense & CONNECT response parser desync (net/pool.goose, net/proxy.goose)

// ----------------------------------------------------------------------------
// 1. HTTP/2 Server Multiplexer (server/h2_multiplexer.goose, http2/*)
// ----------------------------------------------------------------------------
fn has_rst_stream_for(wire: const u8[:], stream_id: u32) -> bool {
    var p: i64 = 0;
    while p + 9 <= wire.len {
        let f_len = ((wire[p] as u32) << 16) | ((wire[p + 1] as u32) << 8) | wire[p + 2];
        let f_type = wire[p + 3];
        let f_sid = ((wire[p + 5] as u32) << 24) | ((wire[p + 6] as u32) << 16) | ((wire[p + 7] as u32) << 8) | wire[p + 8];
        if f_type == rfc::H2_FRAME_RST_STREAM && f_sid == stream_id {
            return true;
        }
        p += 9 + (f_len as i64);
    }
    return false;
}

fn test_h2_multiplexer_rfc9113_invariants(t: lit::T&) {
    var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
    var timer = internal::new_connection_timer(30000000000, 1000000000);

    t.run("H2 ingress rejects Content-Length > 0 on HEADERS frame with END_STREAM") { sub =>
        sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var wire_in: u8[>..] = [];
        wire_in.append(rfc::H2_CLIENT_PREFACE[..]);

        // HEADERS frame on stream 1 with END_STREAM set, but Content-Length: 10!
        var hpack_block: u8[>..] = [];
        var dt = internal::new_dynamic_table(4096);
        internal::encode_hpack_field(dt, hpack_block, ":method", "POST", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, hpack_block, ":scheme", "https", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, hpack_block, ":path", "/api", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, hpack_block, "content-length", "10", internal::HpackIndexing.Incremental, false);

        let flags = rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM;
        let hdr = internal::FrameHeader {
            length:     hpack_block.len as u32,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      flags,
            stream_id:  1,
        };
        internal::encode_frame_header_to(hdr, wire_in);
        wire_in.append(hpack_block[..]);

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_in[..], 1000, out_wire);

        // Under RFC 9113 §8.1.1, Content-Length mismatch on END_STREAM MUST be rejected with stream error RST_STREAM
        sub.assert_true(ok, "Connection MUST remain alive on stream error per RFC 9113 §5.4.2");
        sub.assert_true(has_rst_stream_for(out_wire[..], 1), "Content-Length: 10 with 0 DATA bytes must emit RST_STREAM(PROTOCOL_ERROR)");
    };

    t.run("H2 ingress rejects PADDED frame when pad_len >= frame_payload.len") { sub =>
        sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var wire_in: u8[>..] = [];
        wire_in.append(rfc::H2_CLIENT_PREFACE[..]);

        // PADDED frame with payload length 5, but pad_len byte = 10 (pad_len >= payload_len)
        let hdr = internal::FrameHeader {
            length:     5,
            frame_type: rfc::H2_FRAME_DATA,
            flags:      rfc::H2_FLAG_PADDED,
            stream_id:  1,
        };
        internal::encode_frame_header_to(hdr, wire_in);
        wire_in.push(10); // pad_len byte = 10
        wire_in.push(0); wire_in.push(0); wire_in.push(0); wire_in.push(0);

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_in[..], 1000, out_wire);
        sub.assert_false(ok, "Padding length >= frame payload length MUST emit GOAWAY(PROTOCOL_ERROR)");
    };

    t.run("H2 ingress rejects request missing mandatory pseudo-headers") { sub =>
        sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var wire_in: u8[>..] = [];
        wire_in.append(rfc::H2_CLIENT_PREFACE[..]);

        // HEADERS frame missing :path and :scheme
        var hpack_block: u8[>..] = [];
        var dt = internal::new_dynamic_table(4096);
        internal::encode_hpack_field(dt, hpack_block, ":method", "GET", internal::HpackIndexing.Incremental, false);

        let flags = rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM;
        let hdr = internal::FrameHeader {
            length:     hpack_block.len as u32,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      flags,
            stream_id:  1,
        };
        internal::encode_frame_header_to(hdr, wire_in);
        wire_in.append(hpack_block[..]);

        var out_wire: u8[>..] = [];
        let _, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_in[..], 1000, out_wire);
        sub.assert_true(ok, "Connection MUST remain alive on stream error per RFC 9113 §5.4.2");
        sub.assert_true(has_rst_stream_for(out_wire[..], 1), "Request missing :scheme and :path MUST emit RST_STREAM(PROTOCOL_ERROR)");
    };
}

// ----------------------------------------------------------------------------
// 2. WebSocket Protocol Invariants (realtime/websocket.goose)
// ----------------------------------------------------------------------------
fn test_websocket_token_and_capacity_invariants(t: lit::T&) {
    t.run("ws_upgrade_request rejects Connection header with non-token substring") { sub =>
        var req = wing::new_request("GET", "https://example.com/ws");
        req.set_header("Upgrade", "websocket");
        req.set_header("Connection", "not-an-upgrade");
        req.set_header("Sec-WebSocket-Version", "13");
        req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");

        var resp = wing::Response { .. };
        let _, ok = wing::ws_upgrade_request(req, resp);
        sub.assert_false(ok, "Connection: not-an-upgrade MUST NOT match 'Upgrade' token");
        sub.assert_eq(resp.status_code, 400, "Response status 400 Bad Request");
    };

    t.run("ws_upgrade_request accepts Upgrade token when multiple Connection headers exist") { sub =>
        var req = wing::new_request("GET", "https://example.com/ws");
        req.set_header("Upgrade", "websocket");
        req.set_header("Connection", "keep-alive");
        wing::append_header(req.headers, "Connection", "Upgrade");
        req.set_header("Sec-WebSocket-Version", "13");
        req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");

        var resp = wing::Response { .. };
        let _, ok = wing::ws_upgrade_request(req, resp);
        sub.assert_true(ok, "Upgrade token in second Connection header MUST be recognized");
        sub.assert_eq(resp.status_code, 101, "Response status 101 Switching Protocols");
    };

    t.run("receive rejects unfragmented message exceeding 16KB with MessageTooBig (1009)") { sub =>
        var ws = wing::new_websocket_session(true);
        let no_mask: u8[4] = [0, 0, 0, 0];

        // 20000-byte unfragmented text frame
        var big_payload: u8[>..] = [];
        for i in 20000 { big_payload.push('a'); }

        var wire: u8[>..] = [];
        wing::encode_ws_frame(wire, rfc::WS_OPCODE_TEXT, big_payload[..], false, no_mask, true);

        var msg = wing::WsMessage { .. };
        var reply: u8[>..] = [];
        wing::receive(ws, wire[..], msg, reply);

        sub.assert_false(msg.is_valid, "Message exceeding 16KB capacity MUST NOT be marked valid");
        sub.assert_true(ws.is_closed, "WebSocket session MUST be closed on capacity overflow");
        sub.assert_eq(ws.close_code, rfc::WS_STATUS_MESSAGE_TOO_BIG, "Close code MUST be 1009 Message Too Big");
    };
}

// ----------------------------------------------------------------------------
// 3. Client Redirect Engine (client/redirect.goose)
// ----------------------------------------------------------------------------
fn test_client_redirect_origin_and_fragment_safety(t: lit::T&) {
    t.run("Cross-origin 307 redirect MUST set Origin to null to prevent leaking internal origin") { sub =>
        var headers = wing::HeaderMap { .. };
        wing::append_header(headers, "Origin", "https://internal.corp.example.com");
        wing::append_header(headers, "Content-Type", "application/json");

        var redir = wing::RedirectInfo {
            status_code:     307,
            is_cross_origin: true,
            clear_body:      false, // 307 retains POST body!
            ..
        };

        wing::sanitize_headers_on_redirect(headers, redir, wing::RedirectSanitizeOptions { .. });

        let origin_idx = wing::find_header_index(headers, "Origin");
        sub.assert_ge(origin_idx, 0, "Origin header present");
        sub.assert_bytes_eq(wing::get_header(headers, "Origin"), "null", "Origin on cross-origin 307 MUST be 'null'");
    };

    t.run("inherit_target_fragment does not crash when combined length exceeds 2048") { sub =>
        var long_target: u8[>..] = [];
        long_target.append("https://target.com/");
        for i in 2040 { long_target.push('x'); }

        // Must not crash or panic with capacity exceeded
        let info = wing::compute_redirect_info(
            "GET",
            302,
            "https://example.com/base#very-long-fragment",
            long_target[..],
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin,
            "",
            wing::RedirectOptions { is_main_frame: true },
        );
        sub.assert_true(info.error == wing::RedirectError.None || info.error == wing::RedirectError.InvalidLocationUrl, "Handled safely without crash");
    };
}

// ----------------------------------------------------------------------------
// 4. Server-Sent Events (realtime/sse.goose)
// ----------------------------------------------------------------------------
fn test_sse_w3c_spec_invariants(t: lit::T&) {
    t.run("W3C EventSource §9.2.6: Event without data field MUST NOT dispatch") { sub =>
        var parser = wing::SseParser { .. };
        var events: wing::SseEvent[..16] = [];

        // Stream with event: ping but NO data: line, followed by empty line
        wing::sse_feed(parser, "event: ping\n\n", events);

        sub.assert_eq(events.len, 0, "Event without data line MUST NOT be dispatched per W3C Section 9.2.6");
    };

    t.run("SSE retry integer parsing must not overflow into tight reconnect loop") { sub =>
        var parser = wing::SseParser { .. };
        var events: wing::SseEvent[..16] = [];

        // 20-digit number exceeding u32::MAX
        wing::sse_feed(parser, "retry: 99999999999999999999\ndata: ok\n\n", events);

        sub.assert_gt(parser.retry_ms, 0, "retry_ms must remain positive and saturated");
        sub.assert_eq(parser.retry_ms, 0xFFFFFFFF, "retry_ms saturated to u32::MAX on overflow");
    };

    t.run("sse_format_event rejects or strips CRLF injection in event_type and id") { sub =>
        var out: u8[>..] = [];
        wing::sse_format_event(out, "custom\r\ndata: injected", "hello", "id1\r\nevil: true");

        sub.assert_false(core::contains(out[..], "\r"), "CRLF injection in event_type/id must not produce raw CR");
        sub.assert_false(core::contains(out[..], "data: injected"), "Injected data line in event_type must not appear");
    };
}

// ----------------------------------------------------------------------------
// 5. Multipart Form-Data (http/multipart.goose)
// ----------------------------------------------------------------------------
fn test_multipart_boundary_and_smuggling_invariants(t: lit::T&) {
    t.run("RFC 2046 §5.1.1: Boundary ending in space is strictly invalid") { sub =>
        let valid_space = wing::validate_boundary_string("valid-boundary ");
        sub.assert_false(valid_space, "Boundary with trailing space MUST be rejected per RFC 2046 §5.1.1");
    };

    t.run("Multipart part with field name > 64B MUST NOT be silently truncated") { sub =>
        var long_name: u8[>..] = [];
        for i in 65 { long_name.push('a'); }

        var body: u8[>..] = [];
        body.append("--myboundary\r\nContent-Disposition: form-data; name=\"");
        body.append(long_name[..]);
        body.append("\"\r\n\r\nvalue\r\n--myboundary--\r\n");

        let msg, err = wing::parse_multipart(body[..], "myboundary");
        // Parameter name > 64B must return InvalidPartHeaders and not truncate to 64 'a's
        sub.assert_false(wing::is_ok(err), "Field name > 64B must be rejected rather than silently truncated");
        sub.assert_false(msg.valid, "Message valid flag must be false");
    };
}

// ----------------------------------------------------------------------------
// 6. Connection Pool & Proxies (net/pool.goose, net/proxy.goose)
// ----------------------------------------------------------------------------
fn test_pool_and_proxy_san_invariants(t: lit::T&) {
    t.run("matches_san_pattern rejects TLD wildcard *.com") { sub =>
        let matches_tld = wing::matches_san_pattern("*.com", "example.com");
        sub.assert_false(matches_tld, "*.com wildcard MUST NOT match apex domain (RFC 6125 §6.4.3)");
    };

    t.run("matches_san_pattern rejects candidate hostname with literal wildcard") { sub =>
        let matches_wild = wing::matches_san_pattern("*.example.com", "*.example.com");
        sub.assert_false(matches_wild, "Candidate hostname containing literal '*' MUST NOT match");
    };

    t.run("verify_connect_tunnel_response rejects non-HTTP or 4-digit status codes") { sub =>
        let err1 = wing::verify_connect_tunnel_response("HTTP/1.1 2000 OK\r\n\r\n");
        sub.assert_true(err1 == wing::ConnectTunnelError.InvalidStatusLine, "Status code '2000' must be InvalidStatusLine");

        let err2 = wing::verify_connect_tunnel_response("UNKNOWN 200 OK\r\n\r\n");
        sub.assert_true(err2 == wing::ConnectTunnelError.InvalidStatusLine, "Non-HTTP protocol must be InvalidStatusLine");
    };
}

// ----------------------------------------------------------------------------
// Main Runner
// ----------------------------------------------------------------------------

// --- Component: regress_issues_batch14 ---
// Phase 14 RED test suite: RFC Protocol Invariants, Trailer Filtering,
// UTF-8 Truncation Boundaries, Sticky FSM Error States, and Codec Quota Guards.
//
// 1. HTTP/2 Response Trailers Filtering & HPACK Encoding (server/h2_multiplexer.goose)
// 2. WebSocket Close UTF-8 Boundary Truncation & Subprotocol Lists (realtime/websocket.goose)
// 3. HTTP Chunked 64-bit FSM Error Stickiness, Bare CR & Trailer Invariants (http/headers/chunked_fsm.goose)
// 4. Zstandard RFC 8878 RLE Block, SizeMismatch & 0-Sequence Bomb Guards (core/compress/zstd.goose)
// 5. Deflate RFC 1951 Dynamic Huffman Missing EOB 256 Rejection (core/compress/deflate.goose)

// ----------------------------------------------------------------------------
// 1. HTTP/2 Response Trailers Filtering & HPACK Encoding
// ----------------------------------------------------------------------------
fn test_h2_multiplexer_trailers(t: lit::T&) {
    t.run("emit_response_trailers filters pseudo-headers, hop-by-hop, and disallowed fields") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var trailers = wing::HeaderMap { .. };

        // Valid trailers
        wing::append_header(trailers, "x-checksum", "sha256-abc");
        wing::append_header(trailers, "x-duration", "15ms");

        // Forbidden pseudo-headers and connection headers per RFC 9113 §8.1 / §8.2.2
        wing::append_header(trailers, ":status", "200");
        wing::append_header(trailers, "connection", "close");
        wing::append_header(trailers, "transfer-encoding", "chunked");
        wing::append_header(trailers, "content-length", "42");
        wing::append_header(trailers, "host", "example.com");

        var out_wire: u8[>..] = [];
        internal::emit_response_trailers(sess, 1, trailers, out_wire);

        sub.assert_gt(out_wire.len, 9, "Trailers frame emitted");

        // Parse frame header
        let hdr, ok_hdr = internal::parse_frame_header(out_wire[..9], 16384);
        sub.assert_eq(ok_hdr, rfc::H2_ERR_NO_ERROR, "Frame header valid");
        sub.assert_eq(hdr.frame_type, rfc::H2_FRAME_HEADERS, "Type is HEADERS");
        sub.assert_eq(hdr.stream_id, 1, "Stream ID is 1");
        sub.assert_true((hdr.flags & rfc::H2_FLAG_END_HEADERS) != 0, "FLAG_END_HEADERS set");
        sub.assert_true((hdr.flags & rfc::H2_FLAG_END_STREAM) != 0, "FLAG_END_STREAM set");

        // Decode HPACK payload
        var dec_pseudo = internal::H2PseudoHeaders { is_trailer: true, .. };
        var dec_list = wing::HeaderMap { .. };
        let dec_err = internal::decode_hpack_to_map(sess.conn.hpack_dec, out_wire[9..9 + (hdr.length as i64)], dec_pseudo, dec_list);
        sub.assert_eq(dec_err, rfc::H2_ERR_NO_ERROR, "HPACK block decoded");

        // Exactly 2 valid trailer headers should survive
        sub.assert_eq(dec_list.entries.len, 2, "Only 2 valid trailers encoded");
        sub.assert_bytes_eq(wing::entry_name(dec_list, dec_list.entries[0]), "x-checksum", "First trailer name");
        sub.assert_bytes_eq(wing::entry_value(dec_list, dec_list.entries[0]), "sha256-abc", "First trailer value");
        sub.assert_bytes_eq(wing::entry_name(dec_list, dec_list.entries[1]), "x-duration", "Second trailer name");
        sub.assert_bytes_eq(wing::entry_value(dec_list, dec_list.entries[1]), "15ms", "Second trailer value");
    };

    t.run("handle_h2_server_ingress emits response with body and trailers") { sub =>
        var sess = internal::new_h2_server_session("goose-wing/1.0", 1000);
        var pipeline = wing::new_server_pipeline_config("127.0.0.1", wing::new_gcra_quota(1000, core::secs(1), 100));
        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var wire_in: u8[>..] = [];
        wire_in.append(rfc::H2_CLIENT_PREFACE[..]);

        // Client request on stream 1
        var hpack_block: u8[>..] = [];
        var dt = internal::new_dynamic_table(4096);
        internal::encode_hpack_field(dt, hpack_block, ":method", "GET", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, hpack_block, ":scheme", "https", internal::HpackIndexing.Incremental, false);
        internal::encode_hpack_field(dt, hpack_block, ":path", "/test", internal::HpackIndexing.Incremental, false);

        let req_hdr = internal::FrameHeader {
            length:     hpack_block.len as u32,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
            stream_id:  1,
        };
        internal::encode_frame_header_to(req_hdr, wire_in);
        wire_in.append(hpack_block[..]);

        var out_wire: u8[>..] = [];
        let consumed, ok = internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", wire_in[..], 1000, out_wire);
        sub.assert_true(ok, "Ingress handled cleanly");
        sub.assert_gt(consumed, 0, "Ingress bytes consumed");
        sub.assert_gt(out_wire.len, 0, "Server produced response");
    };
}

// ----------------------------------------------------------------------------
// 2. WebSocket Close UTF-8 Boundary Truncation & Subprotocol Lists
// ----------------------------------------------------------------------------
fn test_websocket_close_and_subprotocol(t: lit::T&) {
    t.run("encode_close_payload preserves UTF-8 integrity on 123-byte boundary") { sub =>
        // Build reason string of 122 ASCII 'A's + 3-byte Euro sign '€' (0xE2, 0x82, 0xAC)
        var reason: u8[>..] = [];
        for i in 122 {
            reason.push('A');
        }
        reason.push(0xE2);
        reason.push(0x82);
        reason.push(0xAC); // Total 125 bytes

        var out: u8[>..] = [];
        wing::encode_close_payload(out, rfc::WS_STATUS_NORMAL, reason[..]);

        sub.assert_eq(out.len, 2 + 122, "Status code (2B) + truncated reason (122B)");
        let code, reason_slice, ok_parse = wing::parse_close_payload(out[..]);
        sub.assert_true(ok_parse, "Parse close payload succeeds");
        sub.assert_eq(code, rfc::WS_STATUS_NORMAL, "Code matches 1000");
        sub.assert_true(core::validate_utf8(reason_slice), "Truncated reason must be strictly valid UTF-8");
        sub.assert_eq(reason_slice.len, 122, "Euro symbol split across 123B was peeled back cleanly");
    };

    t.run("encode_close_payload keeps 3-byte UTF-8 char when ending exactly at 123") { sub =>
        // 120 ASCII + 3-byte '€' at indices 120..122 -> fits exactly in 123 bytes!
        var reason: u8[>..] = [];
        for i in 120 {
            reason.push('A');
        }
        reason.push(0xE2);
        reason.push(0x82);
        reason.push(0xAC);
        reason.push('Z'); // byte 123 (would be 124th byte)

        var out: u8[>..] = [];
        wing::encode_close_payload(out, rfc::WS_STATUS_NORMAL, reason[..]);

        sub.assert_eq(out.len, 2 + 123, "Status code (2B) + 123B reason");
        let _, reason_slice, ok_parse = wing::parse_close_payload(out[..]);
        sub.assert_true(ok_parse, "Parse succeeds");
        sub.assert_true(core::validate_utf8(reason_slice), "Valid UTF-8");
        sub.assert_eq(reason_slice[120], 0xE2, "Euro byte 0");
        sub.assert_eq(reason_slice[121], 0x82, "Euro byte 1");
        sub.assert_eq(reason_slice[122], 0xAC, "Euro byte 2");
    };

    t.run("has_subprotocol_token parses comma-separated lists with whitespace") { sub =>
        let list = "graphql-ws,  chat.v2 , json-rpc";
        sub.assert_true(wing::has_subprotocol_token(list, "graphql-ws"), "Matches first token");
        sub.assert_true(wing::has_subprotocol_token(list, "chat.v2"), "Matches trimmed token");
        sub.assert_true(wing::has_subprotocol_token(list, "json-rpc"), "Matches last token");
        sub.assert_false(wing::has_subprotocol_token(list, "chat"), "Rejects partial prefix");
        sub.assert_false(wing::has_subprotocol_token(list, "graphql"), "Rejects partial prefix");
    };

    t.run("ws_upgrade_request checks multiple Sec-WebSocket-Protocol headers") { sub =>
        var req = wing::new_request("GET", "https://example.com/ws");
        req.set_header("Host", "example.com");
        req.set_header("Upgrade", "websocket");
        req.set_header("Connection", "Upgrade");
        req.set_header("Sec-WebSocket-Version", "13");
        req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        wing::append_header(req.headers, "Sec-WebSocket-Protocol", "wamp.2.json");
        wing::append_header(req.headers, "Sec-WebSocket-Protocol", "chat.v1");

        var resp = wing::Response { .. };
        let ws_sess, ok = wing::ws_upgrade_request(req, resp, "chat.v1");
        sub.assert_true(ok, "Upgrade accepted with subprotocol from second header");
        sub.assert_eq(resp.status_code, 101, "Switching Protocols 101");
        sub.assert_bytes_eq(resp.header("sec-websocket-protocol"), "chat.v1", "Subprotocol header set");
        sub.assert_bytes_eq(ws_sess.subprotocol[..], "chat.v1", "Session subprotocol populated");
    };

    t.run("is_websocket_upgrade_request handles comma-separated Connection tokens") { sub =>
        var req = wing::new_request("GET", "https://example.com/ws");
        req.set_header("Host", "example.com");
        req.set_header("Upgrade", "websocket");
        req.set_header("Connection", "keep-alive, Upgrade");
        req.set_header("Sec-WebSocket-Version", "13");
        req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");

        sub.assert_true(wing::is_websocket_upgrade_request(req), "Recognized as WebSocket upgrade request");
    };

    t.run("SharedWsCompressor deflate and inflate round-trip with RFC 7692 tail stripping") { sub =>
        var comp = wing::SharedWsCompressor { .. };
        let original = "Hello, WebSocket PerMessageDeflate with zero-heap shared reactor context!";

        var wire: u8[>..] = [];
        let ok_c = wing::ws_deflate_message(comp, original, wire, true);
        sub.assert_true(ok_c, "Deflate succeeds");
        sub.assert_gt(wire.len, 0, "Compressed bytes produced");

        var restored: u8[>..] = [];
        let ok_d = wing::ws_inflate_message(comp, wire[..], restored, 65536, true);
        sub.assert_true(ok_d, "Inflate succeeds");
        sub.assert_bytes_eq(restored[..], original, "Restored text matches verbatim");
    };
}

// ----------------------------------------------------------------------------
// 3. HTTP Chunked 64-bit FSM Error Stickiness, Bare CR & Trailer Invariants
// ----------------------------------------------------------------------------
fn test_chunked_fsm_invariants(t: lit::T&) {
    t.run("chunk_fsm_feed error state is sticky and idempotent") { sub =>
        var dec = internal::new_chunk_fsm_decoder();
        // Malformed chunk size: '1', '2' consumed, 'Z' triggers Error
        let st1, cons1, _ = internal::chunk_fsm_feed(dec, "12Z\r\n");
        sub.assert_eq(st1, internal::ChunkFsmStatus.Error, "First feed returns Error");
        sub.assert_eq(cons1, 2, "2 valid hex bytes consumed before error at byte 2");

        // Subsequent feed on poisoned decoder MUST immediately return Error with 0 bytes consumed
        let st2, cons2, _ = internal::chunk_fsm_feed(dec, "4\r\nWiki\r\n0\r\n\r\n");
        sub.assert_eq(st2, internal::ChunkFsmStatus.Error, "Poisoned decoder remains in Error");
        sub.assert_eq(cons2, 0, "Poisoned decoder consumes 0 bytes");

        // Reset restores usability
        internal::chunk_fsm_reset(dec);
        let st3, _, _ = internal::chunk_fsm_feed(dec, "4\r\nWiki\r\n0\r\n\r\n");
        sub.assert_eq(st3, internal::ChunkFsmStatus.YieldChunk, "Reset decoder functions again");
    };

    t.run("chunk_fsm_feed rejects bare CR in trailer lines (RFC 9112 §2.2)") { sub =>
        var dec = internal::new_chunk_fsm_decoder();
        // Trailer line has \r followed by 'X' instead of \n
        let raw = "0\r\nX-Trailer: val\rX-Next: 1\r\n\r\n";
        let st, _, _ = internal::chunk_fsm_feed(dec, raw);
        sub.assert_eq(st, internal::ChunkFsmStatus.Error, "Bare CR in trailer line rejected");
    };

    t.run("chunk_fsm_feed rejects bare LF and obs-fold in trailer mode") { sub =>
        var dec1 = internal::new_chunk_fsm_decoder();
        let st1, _, _ = internal::chunk_fsm_feed(dec1, "0\r\n\n");
        sub.assert_eq(st1, internal::ChunkFsmStatus.Error, "Bare LF in trailer mode rejected");

        var dec2 = internal::new_chunk_fsm_decoder();
        // obs-fold (space at start of trailer line)
        let st2, _, _ = internal::chunk_fsm_feed(dec2, "0\r\n X-Fold: bad\r\n\r\n");
        sub.assert_eq(st2, internal::ChunkFsmStatus.Error, "Obs-fold at start of trailer line rejected");
    };

    t.run("chunk_fsm_feed rejects NUL and CTL bytes in trailer line") { sub =>
        var dec = internal::new_chunk_fsm_decoder();
        var raw: u8[..32] = "0\r\nX-Bad: \0val\r\n\r\n";
        let st, _, _ = internal::chunk_fsm_feed(dec, raw[..]);
        sub.assert_eq(st, internal::ChunkFsmStatus.Error, "NUL byte in trailer rejected");
    };
}

// ----------------------------------------------------------------------------
// 4. Zstandard RFC 8878 RLE Block, SizeMismatch & 0-Sequence Bomb Guards
// ----------------------------------------------------------------------------
fn test_zstandard_rfc8878_invariants(t: lit::T&) {
    t.run("Zstandard RLE_Block decompression repeats 1 byte block_size times") { sub =>
        // Construct valid Zstandard frame containing an RLE_Block (Block_Type = 1)
        var frame: u8[>..] = [];
        // Magic
        frame.push(0x28); frame.push(0xB5); frame.push(0x2F); frame.push(0xFD);
        // Frame Header Descriptor: single segment, no checksum, FCS = 2B
        frame.push(0x20 | 0x40);
        // Frame_Content_Size = 256 + 100 = 356 bytes
        core::write_le_u16(frame, 100);

        // Block Header: last_block=1, block_type=RLE(1), block_size=356
        let last_bit: u32 = 1;
        let btype:    u32 = 1; // RLE
        let bsize:    u32 = 356;
        let b_hdr = last_bit | (btype << 1) | (bsize << 3);
        frame.push((b_hdr & 0xFF) as u8);
        frame.push(((b_hdr >> 8) & 0xFF) as u8);
        frame.push(((b_hdr >> 16) & 0xFF) as u8);
        // RLE content: exactly 1 byte 'Z' (0x5A)
        frame.push(0x5A);

        var decomp: u8[>..] = [];
        let ok, err = core::zstd_decompress(frame[..], decomp);
        sub.assert_true(ok, "RLE block decompression succeeds");
        sub.assert_eq(err, core::CompressError.None, "Error is None");
        sub.assert_eq(decomp.len, 356, "Decompressed size is exactly 356 bytes");
        var all_z = true;
        for b in decomp {
            if b != 0x5A { all_z = false; }
        }
        sub.assert_true(all_z, "All 356 bytes are 'Z'");
    };

    t.run("Zstandard Frame_Content_Size mismatch triggers SizeMismatch") { sub =>
        // Construct frame with declared Frame_Content_Size = 20, but block only decompresses 10 bytes
        var frame: u8[>..] = [];
        frame.push(0x28); frame.push(0xB5); frame.push(0x2F); frame.push(0xFD);
        frame.push(0x20); // single segment, FCS = 1B (flag 0)
        frame.push(20);   // Declared FCS = 20

        // Raw block with 10 bytes
        let b_hdr = 1 | (0 << 1) | (10 << 3);
        frame.push((b_hdr & 0xFF) as u8);
        frame.push(((b_hdr >> 8) & 0xFF) as u8);
        frame.push(((b_hdr >> 16) & 0xFF) as u8);
        for i in 10 { frame.push('A'); }

        var decomp: u8[>..] = [];
        let ok, err = core::zstd_decompress(frame[..], decomp);
        sub.assert_false(ok, "FCS mismatch must fail");
        sub.assert_eq(err, core::CompressError.SizeMismatch, "Error is SizeMismatch");
    };

    t.run("Zstandard 0-sequences block respects max_output_bytes quota") { sub =>
        // Frame with raw block of 50 bytes tested against quota of 20 bytes
        var frame: u8[>..] = [];
        frame.push(0x28); frame.push(0xB5); frame.push(0x2F); frame.push(0xFD);
        frame.push(0x20);
        frame.push(50);

        let b_hdr = 1 | (0 << 1) | (50 << 3);
        frame.push((b_hdr & 0xFF) as u8);
        frame.push(((b_hdr >> 8) & 0xFF) as u8);
        frame.push(((b_hdr >> 16) & 0xFF) as u8);
        for i in 50 { frame.push('B'); }

        var decomp: u8[>..] = [];
        let ok, err = core::zstd_decompress_with_limit(frame[..], decomp, 20);
        sub.assert_false(ok, "Exceeding quota fails");
        sub.assert_eq(err, core::CompressError.OutputBufferOverflow, "Error is OutputBufferOverflow");
    };
}

// ----------------------------------------------------------------------------
// 5. Deflate RFC 1951 Dynamic Huffman Missing EOB 256 Rejection
// ----------------------------------------------------------------------------
fn test_deflate_rfc1951_invariants(t: lit::T&) {
    t.run("inflate rejects Dynamic Huffman block missing EOB symbol 256 (RFC 1951 §3.2.7)") { sub =>
        // Construct minimal corrupt Dynamic Huffman bitstream where symbol 256 has code length 0.
        // Bit 0: BFINAL=1, Bits 1-2: BTYPE=10 (Dynamic)
        // HLIT = 0 (257 codes: 0..256), HDIST = 0 (1 dist code), HCLEN = 1 (5 code length codes: 16,17,18,0,8)
        var w = core::BitWriter { bit_buf: 0, bit_count: 0 };
        var wire: u8[>..] = [];

        core::write_bits(w, 1 | (2 << 1), 3, wire); // BFINAL=1, BTYPE=10
        core::write_bits(w, 0, 5, wire);             // HLIT: 257 codes (0..256)
        core::write_bits(w, 0, 5, wire);             // HDIST: 1 code
        core::write_bits(w, 1, 4, wire);             // HCLEN: 4+1 = 5 code length codes (16, 17, 18, 0, 8)

        // Code length code lengths: for 16, 17, 18, 0, 8
        // Let code 18 (repeat 11..138 zeros) have length 1 (code 0)
        core::write_bits(w, 0, 3, wire); // 16: len 0
        core::write_bits(w, 0, 3, wire); // 17: len 0
        core::write_bits(w, 1, 3, wire); // 18: len 1 (code 0)
        core::write_bits(w, 0, 3, wire); // 0: len 0
        core::write_bits(w, 0, 3, wire); // 8: len 0

        // Now encode HLIT+HDIST = 257 + 1 = 258 code lengths.
        // Use code 18 twice with 7 extra bits each (repeat zeros):
        // 1st: code 0 (1 bit) + 127 extra bits -> 138 zeros (codes 0..137)
        core::write_bits(w, 0, 1, wire);
        core::write_bits(w, 127, 7, wire);
        // 2nd: code 0 (1 bit) + 109 extra bits -> 120 zeros (codes 138..257)
        // Thus ALL symbols 0..256 have length 0, including EOB 256!
        core::write_bits(w, 0, 1, wire);
        core::write_bits(w, 109, 7, wire);

        core::flush_bits(w, wire);

        var decomp: u8[>..] = [];
        let ok, err = core::inflate(wire[..], decomp);
        sub.assert_false(ok, "Dynamic Huffman missing EOB 256 MUST fail");
        sub.assert_eq(err, core::CompressError.CodeLengthsIncomplete, "Error is CodeLengthsIncomplete");
    };

    t.run("get_deflate_config returns valid tuning across all levels 0..9") { sub =>
        for lvl in 10 {
            let cfg = core::get_deflate_config(lvl as i32);
            sub.assert_gt(cfg.max_chain, 0, "max_chain positive");
            sub.assert_gt(cfg.good_len, 0, "good_len positive");
            sub.assert_gt(cfg.nice_len, 0, "nice_len positive");
        }
    };
}

// ----------------------------------------------------------------------------
// Main Runner
// ----------------------------------------------------------------------------

// --- Component: regress_issues_batch15 ---
// Phase 15 RED test suite: HTTP/3 & QUIC Transport Engine RFC Invariants,
// QPACK Dynamic Table Ring Decoders, Header Protection & Stream Multiplexer Defenses.
//
// 1. QUIC Packet Headers, Header Protection & Interval Reassembly (quic/packet.goose)
// 2. QPACK Modular RIC, Post-Base Bounds & Bare-Colon Token Sanitization (http3/qpack.goose)
// 3. HTTP/3 Framing, Reserved 0x00 Setting & Malformed Payloads (http3/framing.goose)
// 4. HTTP/3 Multiplexer, Unidirectional Encoder/Decoder Dispatch & Trailer Defenses (http3/connection.goose)

// ----------------------------------------------------------------------------
// 1. QUIC Packet Headers, Header Protection & Interval Reassembly
// ----------------------------------------------------------------------------
fn test_quic_packet_and_reassembly(t: lit::T&) {
    t.run("parse_quic_header enforces fixed bit, CID lengths, and plen >= pn_len") { sub =>
        // 1. Short header with fixed bit cleared (bit 6 = 0) MUST fail per RFC 9000 §17.3
        let bad_short: u8[16] = [
            0x00, // Fixed bit (0x40) is not set!
            0x01, 0x02, 0x03, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let _, ok_s = internal::parse_quic_header(bad_short[..], 4);
        sub.assert_false(ok_s, "Short header with fixed bit 0 rejected");

        // 2. Short header with dcid_len_short > 20 MUST fail
        let valid_short: u8[16] = [
            0x40, // Short header, fixed bit 1, pn_len 1
            0x01, 0x02, 0x03, 0x04,
            0x2A, // packet number
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let _, ok_dcid_lg = internal::parse_quic_header(valid_short[..], 21);
        sub.assert_false(ok_dcid_lg, "Short header with dcid > 20 rejected");

        let hdr_s, ok_s_valid = internal::parse_quic_header(valid_short[..], 4);
        sub.assert_true(ok_s_valid, "Valid short header accepted");
        sub.assert_eq(hdr_s.header_type, internal::QuicHeaderType.OneRtt, "Header type is OneRtt");
        sub.assert_eq(hdr_s.pn_length, 1, "PN length is 1");

        // 3. Long header with fixed bit cleared MUST fail per RFC 9000 §17.2
        var bad_long: u8[..64] = [];
        bad_long.push(0x80); // Long header, but fixed bit 0x40 NOT set!
        core::append_u32_be(bad_long, rfc::QUIC_VERSION_1);
        bad_long.push(4); // DCID len
        bad_long.append([1, 2, 3, 4]);
        bad_long.push(4); // SCID len
        bad_long.append([5, 6, 7, 8]);
        internal::quic_encode_varint(bad_long, 10); // plen
        bad_long.push(1); // pn
        let _, ok_l_fix = internal::parse_quic_header(bad_long[..], 0);
        sub.assert_false(ok_l_fix, "Long header with fixed bit 0 rejected");

        // 4. Long header with plen < pn_len MUST fail per RFC 9000 §17.2
        var bad_plen: u8[..64] = [];
        bad_plen.push(0xC1); // Long header, Initial, pn_len = 2 (bits 0..1 = 1)
        core::append_u32_be(bad_plen, rfc::QUIC_VERSION_1);
        bad_plen.push(0); // DCID len 0
        bad_plen.push(0); // SCID len 0
        internal::quic_encode_varint(bad_plen, 0); // token len 0
        internal::quic_encode_varint(bad_plen, 1); // plen = 1, but pn_len = 2!
        bad_plen.append([0x00, 0x2A]); // 2 bytes PN
        let _, ok_plen = internal::parse_quic_header(bad_plen[..], 0);
        sub.assert_false(ok_plen, "Long header with plen < pn_len rejected");
    };

    t.run("encode_quic_header enforces pn_len bounds and 20-byte CID") { sub =>
        var hdr = internal::QuicHeader {
            header_type:    internal::QuicHeaderType.Initial,
            version:        rfc::QUIC_VERSION_1,
            payload_length: 64,
            packet_number:  1,
            ..
        };
        // Valid 20-byte DCID (matches QUIC_MAX_CID_LEN = 20)
        for i in 20 { hdr.dcid.push(i as u8); }

        var out: u8[..128] = [];
        let ok_valid = internal::encode_quic_header(out, hdr, 1);
        sub.assert_true(ok_valid, "encode with DCID == 20 accepted");

        // Invalid pn_len 0 or 5
        out.clear();
        sub.assert_false(internal::encode_quic_header(out, hdr, 0), "pn_len 0 rejected");
        sub.assert_false(internal::encode_quic_header(out, hdr, 5), "pn_len 5 rejected");
    };

    t.run("apply and remove header protection with truncated buffers") { sub =>
        let hp_mask: u8[5] = [0x5A, 0x11, 0x22, 0x33, 0x44];

        // Empty buffer
        var empty_buf: u8[..4] = [];
        internal::apply_header_protection(empty_buf[..], 0, 1, hp_mask);
        let pn_len_e, pn_e = internal::remove_header_protection(empty_buf[..], 0, hp_mask);
        sub.assert_eq(pn_len_e, 0, "remove on empty returns 0");
        sub.assert_eq(pn_e, 0, "pn on empty returns 0");

        // Truncated buffer where pn_offset + pn_len > pkt.len
        var trunc_buf: u8[4] = [0xC0, 0x00, 0x00, 0x00];
        internal::apply_header_protection(trunc_buf[..], 10, 2, hp_mask); // offset 10 > len 4: safe no-op
        sub.assert_eq(trunc_buf[0], 0xC0, "first byte untouched when out of bounds");

        let pn_len_tr, _ = internal::remove_header_protection(trunc_buf[..], 10, hp_mask);
        sub.assert_eq(pn_len_tr, 0, "remove out of bounds returns 0");
        sub.assert_eq(trunc_buf[0], 0xC0, "first byte restored on out-of-bounds");

        // Valid round-trip
        var valid_pkt: u8[8] = [0xC0, 0x01, 0x02, 0x03, 0x12, 0x34, 0xAA, 0xBB];
        let orig_first = valid_pkt[0];
        let orig_pn0 = valid_pkt[4];
        let orig_pn1 = valid_pkt[5];

        internal::apply_header_protection(valid_pkt[..], 4, 2, hp_mask);
        sub.assert_ne(valid_pkt[0], orig_first, "first byte masked");

        let dec_pn_len, dec_pn = internal::remove_header_protection(valid_pkt[..], 4, hp_mask);
        sub.assert_eq(dec_pn_len, 1, "pn_len unmasked is (first & 3) + 1");
        sub.assert_eq(valid_pkt[0], orig_first, "first byte restored");
    };

    t.run("decode_packet_number bounds checking and epoch shifts") { sub =>
        // Out of bounds pn_len
        let pn_raw = internal::decode_packet_number(100, 42, 0);
        sub.assert_eq(pn_raw, 42, "pn_len 0 returns truncated");
        let pn_lg = internal::decode_packet_number(100, 42, 5);
        sub.assert_eq(pn_lg, 42, "pn_len 5 returns truncated");

        // 1-byte PN decoding near wrap-around
        let pn1 = internal::decode_packet_number(0xA8252, 0x9B, 1);
        sub.assert_eq(pn1, 0xA829B, "RFC 9000 Appendix A.3 1-byte decode vector");

        // 2-byte PN decoding
        let pn2 = internal::decode_packet_number(0xA8252, 0x9B3F, 2);
        sub.assert_eq(pn2, 0xA9B3F, "RFC 9000 Appendix A.3 2-byte decode vector");
    };

    t.run("can_send_on_path anti-amplification overflow protection") { sub =>
        let ip: u8[16] = [0; 16];
        var path = internal::new_path_state(ip, 443, false);

        // Path received 1000 bytes -> can send up to 3000 bytes
        internal::on_path_bytes_received(path, 1000);
        sub.assert_true(internal::can_send_on_path(path, 3000), "3000 <= 3 * 1000 allowed");
        sub.assert_false(internal::can_send_on_path(path, 3001), "3001 > 3 * 1000 blocked");

        // Test with massive numbers that would overflow 3 * received or sent + packet
        var path_huge = internal::new_path_state(ip, 443, false);
        path_huge.bytes_received = 0x7FFFFFFFFFFFFFFF; // 3 * bytes_received overflows u64
        path_huge.bytes_sent = 0xFFFFFFFFFFFFFFF0;
        sub.assert_false(internal::can_send_on_path(path_huge, 32), "sent + packet overflow safely blocked");

        // Validated path ignores limit
        internal::validate_path(path);
        sub.assert_true(internal::can_send_on_path(path, 1000000), "validated path allows send");
    };

    t.run("decode_quic_datagram_frame respects packet_end boundary") { sub =>
        var wire: u8[..32] = [];
        // DATAGRAM with Length (0x31)
        sub.assert_true(internal::encode_quic_datagram_frame(wire, "hello", true), "encode datagram len");

        // Normal decode without packet_end
        let payload1, end1, ok1 = internal::decode_quic_datagram_frame(wire[..], 0, 0);
        sub.assert_true(ok1, "decode ok without packet_end");
        sub.assert_bytes_eq(payload1, "hello", "payload matches");

        // Decode with packet_end cutting into datagram length
        let _, _, ok_trunc = internal::decode_quic_datagram_frame(wire[..], 0, end1 - 1);
        sub.assert_false(ok_trunc, "datagram exceeding packet_end rejected");
    };

    t.run("merge_reassembly_interval enforces 64 intervals capacity") { sub =>
        var r_buf = internal::new_reassembly_buffer(65536);

        // Insert 64 disjunct intervals [0, 1), [2, 3), [4, 5), ...
        for i in 64 {
            let s = (i as u64) * 2;
            let ok = internal::insert_fragment(r_buf, s, "X", false);
            sub.assert_true(ok, "insert interval");
        }
        sub.assert_eq(r_buf.intervals.len, 64, "intervals array full at cap 64");

        // 65th disjunct interval cannot be added
        let ok_65 = internal::insert_fragment(r_buf, 200, "Y", false);
        sub.assert_false(ok_65, "65th disjunct interval safely rejected on capacity exhaustion");
    };
}

// ----------------------------------------------------------------------------
// 2. QPACK Modular RIC, Post-Base Bounds & Bare-Colon Token Sanitization
// ----------------------------------------------------------------------------
fn test_qpack_invariants_and_token_defenses(t: lit::T&) {
    t.run("decode_base integer overflow and underflow protection") { sub =>
        // Sign bit 0: Base = ric + delta_base. Test overflow on ric + delta_base
        let _, err_ov = internal::decode_base(0, 10, 0xFFFFFFFFFFFFFFFF);
        sub.assert_eq(err_ov, internal::QpackError.DecompressionFailed, "overflow in base addition rejected");

        // Sign bit 1: Base = ric - delta_base - 1. Test underflow when ric <= delta_base
        let _, err_un = internal::decode_base(1, 5, 5);
        sub.assert_eq(err_un, internal::QpackError.DecompressionFailed, "underflow in base subtraction rejected");

        let base_ok, err_ok = internal::decode_base(0, 5, 10);
        sub.assert_eq(err_ok, internal::QpackError.None, "valid base decoded");
        sub.assert_eq(base_ok, 15, "base is 15");
    };

    t.run("emit_field_checked rejects bare colon and non-token characters") { sub =>
        var fields: internal::HeaderField[>..] = [];
        var budget: u64                        = 4096;

        // Bare colon ":" must be rejected
        let err_colon = internal::emit_field_checked(fields, budget, ":", "val", false);
        sub.assert_eq(err_colon, internal::QpackError.DecompressionFailed, "bare colon rejected");

        // Empty field name
        let err_empty = internal::emit_field_checked(fields, budget, "", "val", false);
        sub.assert_eq(err_empty, internal::QpackError.DecompressionFailed, "empty name rejected");

        // Disallowed control char in name
        let err_ctl = internal::emit_field_checked(fields, budget, "bad\nheader", "val", false);
        sub.assert_eq(err_ctl, internal::QpackError.DecompressionFailed, "newline in name rejected");

        // Valid pseudo header
        let err_valid = internal::emit_field_checked(fields, budget, ":status", "200", false);
        sub.assert_eq(err_valid, internal::QpackError.None, "valid :status accepted");
        sub.assert_eq(fields.len, 1, "field emitted");
    };

    t.run("decode_qpack_section enforces RFC 9204 Post-Base index bounds abs_idx < ric") { sub =>
        var tbl = internal::new_qpack_table(4096, 16);
        // Insert one dynamic entry: "x-foo" = "bar" -> abs_idx = 0
        internal::qpack_insert_literal(tbl, "x-foo", "bar");
        sub.assert_eq(tbl.insert_count, 1, "dynamic table insert_count is 1");

        // Construct section with RIC = 1, Base = 0 (S=1, DeltaBase=0 -> Base = 1 - 0 - 1 = 0)
        // Then attempt Post-Base index 1 -> abs_idx = Base + 1 = 1 >= RIC (1)
        // Per RFC 9204 §4.5.3, abs_idx >= ric MUST be treated as decompression error!
        var sec: u8[..32] = [];
        // 1. EncodedInsertCount = 1 (enc_ric for ric=1 is 2 when max_entries = 4096/32 = 128)
        let enc_ric = internal::encode_ric(1, 4096);
        internal::hpack_encode_int(sec, enc_ric, 8, 0x00);
        // 2. Sign=1, DeltaBase=0 -> 0x80 | 0 = 0x80
        sec.push(0x80);
        // 3. Post-Base Indexed Field Line: 0001xxxx with post_idx = 1 -> 0x11
        sec.push(0x11);

        var out_fields: internal::HeaderField[>..] = [];
        let err = internal::decode_qpack_section(tbl, sec[..], out_fields, 4096);
        sub.assert_eq(err, internal::QpackError.DecompressionFailed, "post_idx resulting in abs_idx >= ric rejected");
    };

    t.run("decode_qpack_section accepts valid RIC >= max_dyn_abs_used + 1 per RFC 9204 §4.5.1") { sub =>
        var tbl = internal::new_qpack_table(4096, 16);
        // Insert two entries: abs_idx 0 ("x-first"), abs_idx 1 ("x-second")
        internal::qpack_insert_literal(tbl, "x-first", "v1");
        internal::qpack_insert_literal(tbl, "x-second", "v2");
        sub.assert_eq(tbl.insert_count, 2, "dynamic table insert_count is 2");

        // Section references ONLY static :status 200 (index 0)
        // Encoder signals RIC = 2 (TotalNumberOfInserts), Base = 2 (S=0, DeltaBase=0)
        // Per RFC 9204 §4.5.1, encoder MAY set RIC > 0 even if no dynamic entries referenced
        var sec: u8[..32] = [];
        let enc_ric = internal::encode_ric(2, 4096);
        internal::hpack_encode_int(sec, enc_ric, 8, 0x00);
        sec.push(0x00); // S=0, DeltaBase=0 -> Base = 2
        sec.push(0xD9); // Static index 25 (:status 200)

        var out_fields: internal::HeaderField[>..] = [];
        let err = internal::decode_qpack_section(tbl, sec[..], out_fields, 4096);
        sub.assert_eq(err, internal::QpackError.None, "RIC > 0 with static-only fields accepted per RFC 9204 §4.5.1");
        sub.assert_eq(out_fields.len, 1, "1 field decoded");
        sub.assert_bytes_eq(out_fields[0].name[..], ":status", "name is :status");
        sub.assert_bytes_eq(out_fields[0].value[..], "200", "value is 200");
    };
}

// ----------------------------------------------------------------------------
// 3. HTTP/3 Framing, Reserved 0x00 Setting & Malformed Payloads
// ----------------------------------------------------------------------------
fn test_h3_framing_and_settings_invariants(t: lit::T&) {
    t.run("parse_h3_settings_frame rejects reserved setting 0x00 and duplicates") { sub =>
        // 1. Reserved setting 0x00 (from HTTP/2) MUST cause H3_SETTINGS_ERROR (RFC 9114 §7.2.4.1)
        var payload_00: u8[..16] = [];
        internal::quic_encode_varint(payload_00, 0x00); // Reserved identifier 0x00
        internal::quic_encode_varint(payload_00, 100);

        var st1 = wing::H3Settings { .. };
        let err_00 = internal::parse_h3_settings_frame(payload_00[..], st1);
        sub.assert_eq(err_00, rfc::H3_ERR_SETTINGS_ERROR, "Reserved setting 0x00 rejected with H3_SETTINGS_ERROR");

        // 2. Duplicate QPACK_MAX_TABLE_CAPACITY setting MUST cause H3_SETTINGS_ERROR
        var payload_dup: u8[..32] = [];
        internal::quic_encode_varint(payload_dup, rfc::H3_SETTING_QPACK_MAX_TABLE_CAPACITY);
        internal::quic_encode_varint(payload_dup, 4096);
        internal::quic_encode_varint(payload_dup, rfc::H3_SETTING_QPACK_MAX_TABLE_CAPACITY);
        internal::quic_encode_varint(payload_dup, 8192);

        var st2 = wing::H3Settings { .. };
        let err_dup = internal::parse_h3_settings_frame(payload_dup[..], st2);
        sub.assert_eq(err_dup, rfc::H3_ERR_SETTINGS_ERROR, "Duplicate setting rejected with H3_SETTINGS_ERROR");

        // 3. Invalid ENABLE_CONNECT_PROTOCOL value (must be 0 or 1)
        var payload_conn: u8[..16] = [];
        internal::quic_encode_varint(payload_conn, rfc::H3_SETTING_ENABLE_CONNECT_PROTOCOL);
        internal::quic_encode_varint(payload_conn, 2); // Invalid: only 0 or 1 allowed

        var st3 = wing::H3Settings { .. };
        let err_conn = internal::parse_h3_settings_frame(payload_conn[..], st3);
        sub.assert_eq(err_conn, rfc::H3_ERR_SETTINGS_ERROR, "Invalid connect protocol val rejected with H3_SETTINGS_ERROR");
    };
}

// ----------------------------------------------------------------------------
// 4. HTTP/3 Multiplexer, Unidirectional Dispatch & Trailer Defenses
// ----------------------------------------------------------------------------
fn test_h3_multiplexer_and_stream_defenses(t: lit::T&) {
    t.run("handle_stream_data dispatches QPACK encoder stream instructions and catches errors") { sub =>
        let settings = wing::H3Settings { qpack_max_table_capacity: 4096, .. };
        var conn = internal::new_h3_client_connection(settings);

        // 1. Establish control stream first (Stream 2)
        var ctrl_wire: u8[..64] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        let err_c = conn.handle_stream_data(2, false, ctrl_wire[..], false);
        sub.assert_eq(err_c, rfc::H3_ERR_NO_ERROR, "control stream established");

        // 2. Open QPACK encoder stream (Stream 6) with valid Set Dynamic Table Capacity instruction (0x20 | 5-bit cap)
        var enc_wire: u8[..64] = [];
        internal::quic_encode_varint(enc_wire, rfc::H3_STREAM_QPACK_ENCODER);
        internal::hpack_encode_int(enc_wire, 2048, 5, 0x20); // Capacity 2048
        let err_enc = conn.handle_stream_data(6, false, enc_wire[..], false);
        sub.assert_eq(err_enc, rfc::H3_ERR_NO_ERROR, "encoder stream capacity instruction processed");
        sub.assert_eq(conn.qpack_table.capacity_bytes, 2048, "dynamic table capacity updated to 2048");

        // 3. Send malformed instruction on encoder stream -> returns H3_ERR_QPACK_ENCODER_STREAM_ERROR
        var bad_enc_wire: u8[..16] = [];
        // Capacity larger than max_capacity_bytes (4096)
        internal::hpack_encode_int(bad_enc_wire, 999999, 5, 0x20);
        let err_bad_enc = conn.handle_stream_data(6, false, bad_enc_wire[..], false);
        sub.assert_eq(err_bad_enc, rfc::H3_ERR_QPACK_ENCODER_STREAM_ERROR, "invalid encoder instruction closed connection");
        sub.assert_eq(conn.state, internal::H3ConnState.Closed, "conn state is Closed");
    };

    t.run("handle_stream_data rejects second trailer section and DATA after trailers") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);

        // Setup control stream
        var ctrl_wire: u8[..64] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        // Stream 0: Initial response headers (200 OK)
        var resp_hdrs: u8[..64] = [];
        var sec1:      u8[..16] = [0x00, 0x00, 0xD9]; // RIC 0, Base 0, :status 200
        internal::encode_h3_headers_frame(resp_hdrs, sec1[..]);
        let err_h1 = conn.handle_stream_data(0, true, resp_hdrs[..], false);
        sub.assert_eq(err_h1, rfc::H3_ERR_NO_ERROR, "initial 200 OK headers accepted");

        // Stream 0: DATA frame
        var data_frame: u8[..32] = [];
        internal::encode_h3_data_frame(data_frame, "hello");
        let err_d1 = conn.handle_stream_data(0, true, data_frame[..], false);
        sub.assert_eq(err_d1, rfc::H3_ERR_NO_ERROR, "data frame accepted");

        // Stream 0: First trailer section (x-checksum: abc)
        var trailer1_frame: u8[..64] = [];
        var sec_tr1:        u8[..32] = [0x00, 0x00];
        // Literal with literal name: name "x-chk", val "1"
        sec_tr1.push(0x25);
        sec_tr1.append("x-chk");
        sec_tr1.push(0x01);
        sec_tr1.append("1");
        internal::encode_h3_headers_frame(trailer1_frame, sec_tr1[..]);
        let err_tr1 = conn.handle_stream_data(0, true, trailer1_frame[..], false);
        sub.assert_eq(err_tr1, rfc::H3_ERR_NO_ERROR, "first trailer section accepted");

        // 1. DATA frame AFTER trailers MUST cause H3_FRAME_UNEXPECTED (RFC 9114 §4.1)
        var post_tr_data: u8[..32] = [];
        internal::encode_h3_data_frame(post_tr_data, "illegal");
        let err_post_d = conn.handle_stream_data(0, true, post_tr_data[..], false);
        sub.assert_eq(err_post_d, rfc::H3_ERR_FRAME_UNEXPECTED, "DATA after trailers rejected with H3_FRAME_UNEXPECTED");

        // Reset and test second trailer section rejection
        var conn2 = internal::new_h3_client_connection(settings);
        conn2.handle_stream_data(2, false, ctrl_wire[..], false);
        conn2.handle_stream_data(0, true, resp_hdrs[..], false);
        conn2.handle_stream_data(0, true, data_frame[..], false);
        conn2.handle_stream_data(0, true, trailer1_frame[..], false);

        // 2. Second trailer section MUST cause H3_FRAME_UNEXPECTED (RFC 9114 §4.1)
        let err_tr2 = conn2.handle_stream_data(0, true, trailer1_frame[..], false);
        sub.assert_eq(err_tr2, rfc::H3_ERR_FRAME_UNEXPECTED, "second trailer section rejected with H3_FRAME_UNEXPECTED");
    };

    t.run("handle_stream_data validates 3-digit status code and trailer disallowed headers") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = internal::new_h3_client_connection(settings);

        // Setup control stream
        var ctrl_wire: u8[..64] = [];
        internal::quic_encode_varint(ctrl_wire, rfc::H3_STREAM_CONTROL);
        internal::encode_h3_settings_frame(ctrl_wire, settings);
        conn.handle_stream_data(2, false, ctrl_wire[..], false);

        // 1. Status code with 4 digits e.g. "0200" MUST fail
        var sec_bad_st: u8[..32] = [0x00, 0x00];
        // Literal with static name index 24 (:status) encoded with 4-bit prefix
        internal::hpack_encode_int(sec_bad_st, 24, 4, 0x50);
        sec_bad_st.push(4); // len 4
        sec_bad_st.append("0200");

        var bad_st_frame: u8[..64] = [];
        internal::encode_h3_headers_frame(bad_st_frame, sec_bad_st[..]);
        let err_st = conn.handle_stream_data(0, true, bad_st_frame[..], false);
        sub.assert_eq(err_st, rfc::H3_ERR_GENERAL_PROTOCOL, "4-digit status code rejected");

        // 2. Disallowed content-length in trailer section MUST fail
        var conn3 = internal::new_h3_client_connection(settings);
        conn3.handle_stream_data(2, false, ctrl_wire[..], false);
        var sec_ok:  u8[..16] = [0x00, 0x00, 0xD9]; // :status 200
        var ok_hdrs: u8[..32] = [];
        internal::encode_h3_headers_frame(ok_hdrs, sec_ok[..]);
        conn3.handle_stream_data(0, true, ok_hdrs[..], false);

        var sec_cl_tr: u8[..32] = [0x00, 0x00];
        // Literal with static name index 4 (content-length)
        sec_cl_tr.push(0x50 | 4);
        sec_cl_tr.push(2);
        sec_cl_tr.append("10");

        var cl_tr_frame: u8[..64] = [];
        internal::encode_h3_headers_frame(cl_tr_frame, sec_cl_tr[..]);
        let err_cl_tr = conn3.handle_stream_data(0, true, cl_tr_frame[..], false);
        sub.assert_eq(err_cl_tr, rfc::H3_ERR_GENERAL_PROTOCOL, "content-length in trailer rejected");
    };
}

// Main Runner

fn main() {
    var runner = lit::new_runner("Issue Regression Suite Batch 3 (Phases 11-15)", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. SFV string overflow rejection (http/mime.goose)", test_sfv_string_overflow_rejection);
    lit::run_case(runner, "2. SFV capacity smuggling rejection (http/mime.goose)", test_sfv_capacity_smuggling_rejection);
    lit::run_case(runner, "3. RFC 9111 Vary cache poisoning defense (http/cache/validators.goose)", test_vary_snapshot_capacity_poisoning_defense);
    lit::run_case(runner, "4. No-Vary-Search capacity safety (http/novarysearch.goose)", test_novarysearch_capacity_safety);
    lit::run_case(runner, "5. Digest challenge parameter overflow safety (auth/digest.goose)", test_digest_param_overflow_safety);
    lit::run_case(runner, "6. JWT oversized fields safety (auth/jwt.goose)", test_jwt_oversized_fields_no_abort);
    lit::run_case(runner, "7. W3C Trace Context 256-byte key support (http/trace.goose)", test_trace_context_spec_key_length);
    lit::run_case(runner, "8. HTTP/1.x obs-fold capacity safety (http/headers.goose)", test_http_headers_obs_fold_capacity_safety);
    lit::run_case(runner, "9. NoVarySearch truncation and bounds (http/novarysearch.goose)", test_novarysearch_truncation_and_bounds);
    lit::run_case(runner, "10. Chunked FSM & extensions RFC 9112 (http/headers/*)", test_chunked_fsm_and_extensions_rfc9112);
    lit::run_case(runner, "11. HTTP/1.x headers CL, host, cookie bounds (http/headers/*)", test_http1_headers_cl_host_and_cookie_bounds);
    lit::run_case(runner, "12. MIME & SFV truncation smuggling (http/mime.goose)", test_mime_and_sfv_truncation_smuggling);
    lit::run_case(runner, "13. Cache-Control & Vary RFC 9111 (http/cache/*)", test_cache_control_and_vary_poisoning_rfc9111);
    lit::run_case(runner, "14. URL & Origin validation & bounds (core/url/*)", test_url_origin_punycode_and_view_validation);
    lit::run_case(runner, "15. Signatures, HSTS, Trace Context (http/*)", test_http_extensions_signatures_hsts_trace);
    lit::run_case(runner, "16. H2 multiplexer & HPACK RFC 9113 (server/*, http2/*, http/*)", test_h2_multiplexer_and_hpack_rfc9113);
    lit::run_case(runner, "17. HTTP/3 & QPACK RFC 9114 / RFC 9204 (http3/*)", test_h3_and_qpack_rfc9114_rfc9204);
    lit::run_case(runner, "18. gRPC stream & status codecs (grpc/*)", test_grpc_stream_truncation_and_status);
    lit::run_case(runner, "19. Auth DPoP, Digest & PrivacyPass (auth/*, security/*)", test_auth_dpop_digest_privacypass);
    lit::run_case(runner, "20. X.509, Server CONNECT hygiene & Akamai (tls/*, server/*, fingerprint/*)", test_x509_critical_ext_server_connect_and_akamai);
    lit::run_case(runner, "21. H2 multiplexer RFC 9113 invariants (server/h2_multiplexer.goose)", test_h2_multiplexer_rfc9113_invariants);
    lit::run_case(runner, "22. WebSocket token & capacity invariants (realtime/websocket.goose)", test_websocket_token_and_capacity_invariants);
    lit::run_case(runner, "23. Client Redirect origin & fragment safety (client/redirect.goose)", test_client_redirect_origin_and_fragment_safety);
    lit::run_case(runner, "24. Server-Sent Events W3C spec invariants (realtime/sse.goose)", test_sse_w3c_spec_invariants);
    lit::run_case(runner, "25. Multipart boundary & smuggling invariants (http/multipart.goose)", test_multipart_boundary_and_smuggling_invariants);
    lit::run_case(runner, "26. Pool & Proxy SAN invariants (net/pool.goose, net/proxy.goose)", test_pool_and_proxy_san_invariants);
    lit::run_case(runner, "27. H2 multiplexer trailer encoding (server/h2_multiplexer.goose)", test_h2_multiplexer_trailers);
    lit::run_case(runner, "28. WebSocket Close UTF-8 & Subprotocols (realtime/websocket.goose)", test_websocket_close_and_subprotocol);
    lit::run_case(runner, "29. HTTP Chunked FSM invariants (http/headers/chunked_fsm.goose)", test_chunked_fsm_invariants);
    lit::run_case(runner, "30. Zstandard RFC 8878 invariants (core/compress/zstd.goose)", test_zstandard_rfc8878_invariants);
    lit::run_case(runner, "31. Deflate RFC 1951 invariants (core/compress/deflate.goose)", test_deflate_rfc1951_invariants);
    lit::run_case(runner, "32. QUIC Packet Headers, Header Protection & Interval Reassembly", test_quic_packet_and_reassembly);
    lit::run_case(runner, "33. QPACK Modular RIC, Post-Base Bounds & Bare-Colon Token Sanitization", test_qpack_invariants_and_token_defenses);
    lit::run_case(runner, "34. HTTP/3 Framing, Reserved 0x00 Setting & Malformed Payloads", test_h3_framing_and_settings_invariants);
    lit::run_case(runner, "35. HTTP/3 Multiplexer, Unidirectional Dispatch & Trailer Defenses", test_h3_multiplexer_and_stream_defenses);

    let ok = lit::finish(runner);
    assert(ok);
}
