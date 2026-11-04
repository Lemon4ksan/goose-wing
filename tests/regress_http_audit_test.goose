// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: HTTP Audit Regression Suite
// Covers confirmed findings F001 - F008 from goose-bug-hunter audit.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// ----------------------------------------------------------------------------
// F001: Compression Dictionary Bounds and Overflow Rejection
// ----------------------------------------------------------------------------
fn test_f001_compression_dict_bounds(t: lit::T&) {
    t.run("dictionary_cache_insert rejects match_pattern > 128 bytes") { sub =>
        var cache = wing::DictionaryCache { .. };
        var long_pat: u8[..200] = [];
        long_pat.append("/");
        for i in 150 { long_pat.push('a'); }

        let ok = wing::dictionary_cache_insert(
            cache,
            "https://example.com",
            long_pat[..],
            "dict1",
            "dictionary payload content",
            86400,
            1700000000,
        );
        sub.assert_false(ok, "match_pattern > 128B MUST be rejected rather than aborting on DictionaryEntry.match_pattern append");
    };

    t.run("dictionary_cache_insert rejects id > 64 bytes") { sub =>
        var cache = wing::DictionaryCache { .. };
        var long_id: u8[..100] = [];
        for i in 80 { long_id.push('b'); }

        let ok = wing::dictionary_cache_insert(
            cache,
            "https://example.com",
            "/assets/*",
            long_id[..],
            "dictionary payload content",
            86400,
            1700000000,
        );
        sub.assert_false(ok, "id > 64B MUST be rejected rather than aborting on DictionaryEntry.id append");
    };

    t.run("parse_use_as_dictionary_header rejects match_pattern > 128 bytes") { sub =>
        var raw: u8[..256] = [];
        raw.append("match=\"/");
        for i in 150 { raw.push('a'); }
        raw.append("\", id=\"v1\"");

        let p, ok = wing::parse_use_as_dictionary_header(raw[..]);
        sub.assert_false(ok, "match_pattern > 128B MUST return ok == false and not overflow DictionaryParams.match_pattern");
    };
}

// ----------------------------------------------------------------------------
// F002: Status Diagnostics Bounds and Safety
// ----------------------------------------------------------------------------
fn test_f002_status_diagnostics_bounds_and_safety(t: lit::T&) {
    t.run("parse_cache_status_header rejects unclosed quoted string") { sub =>
        var entries: wing::CacheStatusEntry[..8] = [];
        let count = wing::parse_cache_status_header("OriginCache; key=\"unclosed", entries);
        sub.assert_eq(count, 0, "Unclosed quote in Cache-Status MUST fail parsing rather than consuming to EOF");
    };

    t.run("parse_cache_status_header rejects fwd > 32 bytes without abort") { sub =>
        var raw: u8[..128] = [];
        raw.append("OriginCache; fwd=");
        for i in 50 { raw.push('x'); }

        var entries: wing::CacheStatusEntry[..8] = [];
        let count = wing::parse_cache_status_header(raw[..], entries);
        sub.assert_eq(count, 0, "fwd > 32B MUST be rejected and not abort on entry.fwd.append");
    };

    t.run("parse_cache_status_header rejects non-numeric fwd-status without wrapping") { sub =>
        var entries: wing::CacheStatusEntry[..8] = [];
        let count = wing::parse_cache_status_header("OriginCache; fwd-status=invalid", entries);
        sub.assert_eq(count, 0, "Invalid fwd-status MUST fail rather than setting fwd_status=0 via discarded tuple error");
    };

    t.run("parse_proxy_status_header rejects error > 64 bytes without abort") { sub =>
        var raw: u8[..128] = [];
        raw.append("edge1; error=");
        for i in 80 { raw.push('e'); }

        var entries: wing::ProxyStatusEntry[..8] = [];
        let count = wing::parse_proxy_status_header(raw[..], entries);
        sub.assert_eq(count, 0, "error > 64B MUST be rejected and not abort on entry.error_type.append");
    };
}

// ----------------------------------------------------------------------------
// F003: Signature-Input Label Enforcement & Key ID Bounds
// ----------------------------------------------------------------------------
fn test_f003_signature_input_verification(t: lit::T&) {
    t.run("verify_http_signature rejects when label missing from Signature-Input header") { sub =>
        var req = wing::new_request("GET", "https://example.com/data");
        var params = wing::HttpSignatureParams { label: "sig1", .. };
        params.components.push("@method");
        params.components.push("@target-uri");

        let key = "secret-key-12345678901234567890";
        sub.assert_true(wing::sign_http_request(req, params, key), "Request signed successfully");

        // Tamper Signature-Input to define a different label "sig_other"
        wing::set_header(req, "Signature-Input", "sig_other=(\"@method\" \"@target-uri\")");

        // Verification for "sig1" MUST fail because sig1 is not declared in Signature-Input!
        let ok_ver = wing::verify_http_signature(req, "sig1", params, key);
        sub.assert_false(ok_ver, "verify_http_signature MUST fail when label does not match Signature-Input");
    };

    t.run("sign_request_ed25519 rejects key_id > 64 bytes without abort") { sub =>
        var req = wing::new_request("POST", "https://example.com/api");
        var long_key_id: u8[..128] = [];
        for i in 80 { long_key_id.push('k'); }

        let seed: u8[32] = [0x01; 32];
        let ok = wing::sign_request_ed25519(req, long_key_id[..], seed[..]);
        sub.assert_false(ok, "key_id > 64B MUST return false and not abort on params.key_id.append");
    };
}

// ----------------------------------------------------------------------------
// F004: OHTTP Key Configs Vector Safety & Discard
// ----------------------------------------------------------------------------
fn ohttp_test_key_config_bytes() -> u8[45] {
    return [
        0x01, 0x00, 0x20,
        0x31, 0xe1, 0xf0, 0x5a, 0x74, 0x01, 0x02, 0x11, 0x52, 0x20, 0xe9, 0xaf, 0x91,
        0x8f, 0x73, 0x86, 0x74, 0xae, 0xc9, 0x5f, 0x54, 0xdb, 0x6e, 0x04, 0xeb, 0x70,
        0x5a, 0xae, 0x8e, 0x79, 0x81, 0x55,
        0x00, 0x08,
        0x00, 0x01, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x03,
    ];
}

fn test_f004_ohttp_key_configs_discard_and_out(t: lit::T&) {
    t.run("parse_ohttp_key_configs populates empty bounded vector without panic") { sub =>
        var cfg_bytes = ohttp_test_key_config_bytes();

        var wire: u8[..128] = [];
        wire.push(0x00);
        wire.push(45);
        wire.append(cfg_bytes[..]);

        var out:       wing::OhttpKeyConfig[..4] = [];
        var out_count: i32                       = 0;
        let ok = wing::parse_ohttp_key_configs(wire[..], out, out_count);
        sub.assert_true(ok, "parse_ohttp_key_configs succeeds with empty vector out");
        sub.assert_eq(out_count, 1, "out_count is 1");
        sub.assert_eq(out.len, 1, "out bounded array length updated to 1");
    };

    t.run("parse_ohttp_key_configs clears out on partial failure") { sub =>
        var cfg_bytes = ohttp_test_key_config_bytes();

        // 1st config valid, 2nd config truncated
        var wire: u8[..128] = [];
        wire.push(0x00);
        wire.push(45);
        wire.append(cfg_bytes[..]);
        wire.push(0x00);
        wire.push(10);
        wire.append(cfg_bytes[..10]);

        var out:       wing::OhttpKeyConfig[..4] = [];
        var out_count: i32                       = 0;
        let ok = wing::parse_ohttp_key_configs(wire[..], out, out_count);
        sub.assert_false(ok, "parse_ohttp_key_configs fails on corrupt 2nd config");
        sub.assert_eq(out_count, 0, "out_count reset to 0");
        sub.assert_eq(out.len, 0, "out array cleared to 0 elements (all-or-nothing discard)");
    };
}

// ----------------------------------------------------------------------------
// F005: SFV Zero Silent Drops (Invariant 13)
// ----------------------------------------------------------------------------
fn test_f005_sfv_no_silent_dropping(t: lit::T&) {
    t.run("parse_sf_dict rejects dictionaries with > 16 entries") { sub =>
        var raw: u8[..512] = [];
        for i in 17 {
            if i > 0 { raw.append(", "); }
            raw.append("k");
            format(raw, i);
            raw.append("=1");
        }

        var entries: wing::SfDictEntry[..16] = [];
        let ok = wing::parse_sf_dict(raw[..], entries);
        sub.assert_false(ok, "parse_sf_dict MUST return false on > 16 entries rather than silently dropping 17th");
    };

    t.run("parse_sf_list rejects lists with > 16 items") { sub =>
        var raw: u8[..512] = [];
        for i in 17 {
            if i > 0 { raw.append(", "); }
            raw.append("item");
            format(raw, i);
        }

        var items: wing::SfParameterizedItem[..16] = [];
        let ok = wing::parse_sf_list(raw[..], items);
        sub.assert_false(ok, "parse_sf_list MUST return false on > 16 items rather than silently dropping 17th");
    };

    t.run("sf_parse_inner_list rejects inner lists with > 8 items") { sub =>
        var raw: u8[..512] = "endpoints=(";
        for i in 9 {
            if i > 0 { raw.push(' '); }
            raw.append("srv");
            format(raw, i);
        }
        raw.push(')');

        var entries: wing::SfDictEntry[..16] = [];
        let ok = wing::parse_sf_dict(raw[..], entries);
        sub.assert_false(ok, "Inner list > 8 items MUST return false rather than silently dropping 9th");
    };
}

// ----------------------------------------------------------------------------
// F006: W3C Trace Context Hex & Key Specification Compliance
// ----------------------------------------------------------------------------
fn test_f006_trace_w3c_conformance(t: lit::T&) {
    t.run("parse_traceparent rejects uppercase hex in trace-id per W3C Section 3.2.2.1") { sub =>
        // Uppercase hex '4BF9...' MUST be rejected
        let raw = "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01";
        let tp, ok = wing::parse_traceparent(raw);
        sub.assert_false(ok, "Uppercase hex in traceparent MUST be rejected per W3C §3.2.2.1");
    };

    t.run("parse_tracestate rejects multi-tenant key whose system-id starts with digit") { sub =>
        // System-id starts with digit '1' -> forbidden by W3C §3.3.1.2 (system-id must start with [a-z])
        let ts, ok = wing::parse_tracestate("tenant@1sys=val");
        sub.assert_false(ok, "System-id starting with digit MUST be rejected per W3C §3.3.1.2");
    };

    t.run("parse_tracestate rejects multi-tenant key whose tenant-id starts with non-alnum") { sub =>
        // Tenant-id starts with '_' -> forbidden by W3C §3.3.1.2 (tenant-id must start with [a-z0-9])
        let ts, ok = wing::parse_tracestate("_bad@sys=val");
        sub.assert_false(ok, "Tenant-id starting with non-alnum MUST be rejected per W3C §3.3.1.2");
    };

    t.run("parse_tracestate rejects > 32 members rather than silent drop") { sub =>
        var raw: u8[..1024] = [];
        for i in 33 {
            if i > 0 { raw.push(','); }
            raw.append("m");
            format(raw, i);
            raw.append("=1");
        }

        let ts, ok = wing::parse_tracestate(raw[..]);
        sub.assert_false(ok, "Tracestate > 32 members MUST return ok == false rather than dropping 33rd");
    };
}

// ----------------------------------------------------------------------------
// F007: RFC 6797 HSTS Duplicate Directives & Valueless Invariants
// ----------------------------------------------------------------------------
fn test_f007_hsts_rfc6797_invariants(t: lit::T&) {
    t.run("parse_hsts_header rejects duplicate includeSubDomains directive") { sub =>
        let dir, ok = wing::parse_hsts_header("max-age=31536000; includeSubDomains; includeSubDomains");
        sub.assert_false(ok, "Duplicate includeSubDomains MUST be rejected per RFC 6797 §6.1");
    };

    t.run("parse_hsts_header rejects duplicate preload directive") { sub =>
        let dir, ok = wing::parse_hsts_header("max-age=31536000; preload; preload");
        sub.assert_false(ok, "Duplicate preload MUST be rejected per RFC 6797 §6.1");
    };

    t.run("parse_hsts_header rejects includeSubDomains with value") { sub =>
        let dir, ok = wing::parse_hsts_header("max-age=31536000; includeSubDomains=true");
        sub.assert_false(ok, "includeSubDomains directive with value MUST be rejected per RFC 6797 §6.1.2");
    };

    t.run("hsts_cache_update updates is_preload on existing cache entry") { sub =>
        var cache = wing::HstsCache { .. };
        let ok1 = wing::hsts_cache_update(cache, "example.com", "max-age=31536000", 1000);
        sub.assert_true(ok1, "Initial HSTS entry stored without preload");

        // Now update same host with preload directive
        let ok2 = wing::hsts_cache_update(cache, "example.com", "max-age=31536000; preload", 2000);
        sub.assert_true(ok2, "Update HSTS entry with preload succeeds");
        sub.assert_true(cache.entries[0].is_preload, "Existing cache entry is_preload must be updated to true");
    };
}

// ----------------------------------------------------------------------------
// F008: HTTP Cache Engine Response Body Overflow Protection
// ----------------------------------------------------------------------------
fn test_f008_cache_engine_oversized_response(t: lit::T&) {
    t.run("on_response does not cache body exceeding CachedEntry body capacity") { sub =>
        var cache = wing::HttpCache { .. };
        cache.options.max_entry_size = 8192; // Configured higher than CachedEntry.body.cap (4096)

        var req = wing::new_request("GET", "https://example.com/large-image");
        var res = wing::Response { status_code: 200, .. };
        wing::set_header(res, "Cache-Control", "public, max-age=3600");
        for i in 5000 {
            res.body.push('x');
        }

        var ts = wing::CacheTimestamps { .. };
        let dec = wing::on_response(cache, req, res, ts, -1);
        sub.assert_true(
            dec.kind == wing::ResponseDecisionKind.PassThrough,
            "Response with body > 4096B MUST pass through without aborting on CachedEntry.body append",
        );
    };
}

// ----------------------------------------------------------------------------
// F009: Alt-Svc Slot Prioritization for h3 & failed_attempts Saturation
// ----------------------------------------------------------------------------
fn test_f009_altsvc_slot_prioritization_and_backoff_saturation(t: lit::T&) {
    t.run("parse_altsvc_header retains h3 when preceded by 4 draft/legacy protocols") { sub =>
        var cache = wing::AltSvcCache { .. };
        let origin = "example.com:443";
        let raw = "h3-Q050=\":443\", h3-Q046=\":443\", h3-27=\":443\", h3-29=\":443\", h3=\":8443\"; ma=3600";
        wing::update(cache, origin, raw, 1000);

        var ep = wing::AltSvcEndpoint { .. };
        let found = wing::lookup_h3(cache, origin, 1050, ep);
        sub.assert_true(found, "5th h3 endpoint MUST NOT be dropped by 4 preceding draft protocols");
        sub.assert_eq(ep.port as i64, 8443, "Promoted h3 port must be 8443");
    };

    t.run("record_failure saturates failed_attempts without wrapping u8 to 0") { sub =>
        var cache = wing::AltSvcCache { .. };
        let origin = "backoff.example.com:443";
        wing::update(cache, origin, "h3=\":443\"; ma=86400", 1000);

        for i in 256 {
            wing::record_failure(cache, origin, 1000);
        }
        let attempts = wing::failed_attempts(cache, origin);
        sub.assert_true(attempts > 0, "failed_attempts MUST saturate (> 0) after 256 failures instead of wrapping to 0");
        sub.assert_true(wing::is_broken(cache, origin, 1150), "Origin must remain in 160s max backoff at t=1150");
    };

    t.run("lookup_h3 rejects negative elapsed time on backward clock jump") { sub =>
        var cache = wing::AltSvcCache { .. };
        let origin = "clock.example.com:443";
        wing::update(cache, origin, "h3=\":443\"; ma=60", 1000);

        var ep = wing::AltSvcEndpoint { .. };
        let found = wing::lookup_h3(cache, origin, 900, ep);
        sub.assert_false(found, "Negative elapsed time (now_sec < inserted_at_sec) MUST NOT match as fresh");
    };
}

// ----------------------------------------------------------------------------
// F010: HeaderMap Overflow Spill Smuggling, Obs-Fold & get_combined Bounds
// ----------------------------------------------------------------------------
fn test_f010_headermap_overflow_and_bounds(t: lit::T&) {
    t.run("parse_headers_with_overflow detects conflicting Content-Length after 128 headers") { sub =>
        var raw: u8[>..] = [];
        raw.append("Host: example.com\r\n");
        for i in 128 {
            raw.append("X-Pad: 1\r\n");
        }
        raw.append("Transfer-Encoding: chunked\r\n");
        raw.append("Content-Length: 50\r\n\r\n");

        var map = wing::HeaderMap { .. };
        var arena = wing::OverflowArena { .. };
        let err = wing::parse_headers_with_overflow(raw[..], map, arena, false);
        sub.assert_false(wing::is_ok(err), "Conflicting TE + CL past 128th header MUST be rejected");
    };

    t.run("parse_headers_with_overflow handles duplicate Content-Length when raw > 8192B without OOB") { sub =>
        var raw: u8[>..] = [];
        raw.append("Host: example.com\r\n");
        raw.append("Content-Length: 10\r\n");
        raw.append("Content-Length: 10\r\n");
        for i in 100 {
            raw.append("X-Large-Padding-Header: 012345678901234567890123456789012345678901234567890123456789\r\n");
        }
        raw.append("\r\n");

        var map = wing::HeaderMap { .. };
        var arena = wing::OverflowArena { .. };
        let err = wing::parse_headers_with_overflow(raw[..], map, arena, false);
        sub.assert_true(wing::is_ok(err), "Identical duplicate Content-Length in >8KB arena buffer must succeed without OOB");
    };

    t.run("parse_headers_with_overflow handles obs-fold on 129th header when raw <= 8192B") { sub =>
        var raw: u8[>..] = [];
        for i in 129 {
            raw.append("X-H: v\r\n");
        }
        raw.append(" folded\r\n\r\n");

        var map = wing::HeaderMap { .. };
        var arena = wing::OverflowArena { .. };
        let err = wing::parse_headers_with_overflow(raw[..], map, arena, true);
        sub.assert_true(wing::is_ok(err), "Obs-fold on 129th header with stack raw_buf must not slice empty spill_raw");
    };

    t.run("get_combined rejects overflow when combined header value exceeds out buffer capacity") { sub =>
        var map = wing::HeaderMap { .. };
        var v1: u8[..400] = [];
        for i in 300 { v1.push('a'); }
        var v2: u8[..400] = [];
        for i in 300 { v2.push('b'); }
        wing::append_header(map, "Vary", v1[..]);
        wing::append_header(map, "Vary", v2[..]);

        var small_out: u8[..512] = [];
        let ok = wing::get_combined(map, "Vary", small_out, 512);
        sub.assert_false(ok, "get_combined MUST return false and clear out when combined length > max_out_len");
        sub.assert_eq(small_out.len, 0, "small_out must be cleared on capacity failure");
    };

    t.run("merge_with_headers_304 preserves multiple headers of same name in 304 response") { sub =>
        var cached = wing::HeaderMap { .. };
        wing::append_header(cached, "Cache-Control", "max-age=10");

        var resp_304 = wing::HeaderMap { .. };
        wing::append_header(resp_304, "Cache-Control", "public");
        wing::append_header(resp_304, "Cache-Control", "max-age=3600");

        wing::merge_with_headers_304(cached, resp_304);
        var combined: u8[..256] = [];
        let ok = wing::get_combined(cached, "Cache-Control", combined);
        sub.assert_true(ok, "Combined Cache-Control exists");
        sub.assert_bytes_eq(combined[..], "public, max-age=3600", "Both 304 Cache-Control lines must be preserved");
    };
}

// ----------------------------------------------------------------------------
// F011: Perfect Hash Non-Alpha Collision & Chunked Trailer Validation
// ----------------------------------------------------------------------------
fn test_f011_perfect_hash_and_chunked_trailers(t: lit::T&) {
    t.run("identify_known_header rejects non-alpha control char collision on user\\ragent") { sub =>
        let id = wing::identify_known_header("user\ragent");
        sub.assert_true(id == wing::KnownHeaderId.Unknown, "user\\ragent MUST NOT match KnownHeaderId.UserAgent");
    };

    t.run("chunk_fsm_feed rejects forbidden framing trailer Content-Length") { sub =>
        var dec = internal::ChunkFsmDecoder { .. };
        let wire = "0\r\nContent-Length: 100\r\n\r\n";
        let st, consumed, chunk = internal::chunk_fsm_feed(dec, wire);
        sub.assert_true(st == internal::ChunkFsmStatus.Error, "Forbidden Content-Length trailer in ChunkFsmDecoder MUST be rejected");
    };

    t.run("decode_chunked_body_with_trailers clears out_body and out_trailers on mid-stream error") { sub =>
        let wire = "4\r\nWiki\r\n4\r\nBad!\r\n0\r\nContent-Length: 5\r\n\r\n";
        var out_body:     u8[>..]                = [];
        var out_trailers: wing::HeaderItem[..16] = [];
        let err, consumed = wing::decode_chunked_body_with_trailers(wire, out_body, out_trailers);
        sub.assert_false(err == wing::ChunkedDecodeError.None, "Disallowed trailer fails chunked decode");
        sub.assert_eq(out_body.len, 0, "out_body MUST be cleared on chunked decode failure");
    };
}

// ----------------------------------------------------------------------------
// F012: Binary HTTP (RFC 9292) Varint Bounds, Trailer Validation & Cursor Hygiene
// ----------------------------------------------------------------------------
fn test_f012_bhttp_bounds_and_validation(t: lit::T&) {
    t.run("bhttp_decode_request rejects 8-byte max varint section length without signed overflow") { sub =>
        // Framing 0x00, GET, empty scheme, empty authority, "/", then 8-byte varint 0xFFFFFFFFFFFFFFFF (len = 0x3FFFFFFFFFFFFFFF)
        let raw: u8[17] = [
            0x00,
            0x03, 'G', 'E', 'T',
            0x00,
            0x00,
            0x01, '/',
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        var req = wing::BhttpRequest { .. };
        let ok = wing::bhttp_decode_request(raw[..], req);
        sub.assert_false(ok, "Max 62-bit varint section length MUST return false without signed i64 overflow");
        sub.assert_eq(req.method.len, 0, "out request MUST be reset on failure");
    };

    t.run("bhttp_decode_trailer_line rejects control characters in trailer value") { sub =>
        let sec: u8[9] = [0x04, 'x', '-', 'o', 'k', 0x03, 'a', 0x00, 'b'];
        var idx: i64 = 0;
        let ok = wing::bhttp_decode_trailer_line(sec[..], idx);
        sub.assert_false(ok, "Trailer value containing NUL byte MUST be rejected");
        sub.assert_eq(idx, 0, "idx MUST remain unchanged on failure");
    };

    t.run("bhttp_read_len_bytes leaves idx unchanged when length exceeds remaining bytes") { sub =>
        let raw: u8[3] = [0x0A, 'a', 'b'];
        var idx: i64 = 0;
        let slice, ok = wing::bhttp_read_len_bytes(raw[..], idx);
        sub.assert_false(ok, "Length 10 on 3-byte buffer fails");
        sub.assert_eq(idx, 0, "idx MUST remain 0 on failure");
    };
}

// ----------------------------------------------------------------------------
// F013: HTTP Cache Control, Freshness Overflow, ETag & Engine Invariants
// ----------------------------------------------------------------------------
fn test_f013_http_cache_invariants(t: lit::T&) {
    t.run("Cache-Control max-stale=invalid is rejected instead of granting infinite staleness") { sub =>
        var cc = wing::CacheControl { .. };
        wing::parse_cache_control_str("max-stale=invalid", cc, true);
        sub.assert_false(wing::has_max_stale(cc), "Malformed max-stale=invalid MUST NOT set CC_HAS_MAX_STALE with -1");
    };

    t.run("is_max_stale_blocked ignores s-maxage in private cache") { sub =>
        var resp_cc = wing::CacheControl { .. };
        wing::parse_cache_control_str("max-age=10, s-maxage=10", resp_cc, true);
        let policy = wing::FreshnessPolicy { shared: false, .. };
        sub.assert_false(wing::is_max_stale_blocked(resp_cc, policy), "s-maxage MUST NOT block max-stale in a private cache");
    };

    t.run("parse_etag rejects interior double quotes and control characters") { sub =>
        let etag1 = wing::parse_etag("\"a\", \"b\"");
        sub.assert_false(etag1.valid, "Interior quotes in ETag MUST be rejected per RFC 9110 §8.8.3");

        let etag2 = wing::parse_etag("\"bad\x7ftag\"");
        sub.assert_false(etag2.valid, "DEL (0x7F) in ETag MUST be rejected per RFC 9110 §8.8.3");
    };

    t.run("HEAD response does not overwrite cached GET body in HttpCache") { sub =>
        var cache = wing::HttpCache { .. };
        var get_req = wing::new_request("GET", "https://example.com/item");
        var get_res = wing::Response { status_code: 200, .. };
        wing::set_header(get_res, "Cache-Control", "max-age=3600");
        get_res.body.append("cached-get-body");

        var ts = wing::CacheTimestamps { .. };
        let dec1 = wing::on_response(cache, get_req, get_res, ts, -1);
        sub.assert_true(dec1.kind == wing::ResponseDecisionKind.StoreAndReturn, "GET stored");

        var head_req = wing::new_request("HEAD", "https://example.com/item");
        var head_res = wing::Response { status_code: 200, .. };
        wing::set_header(head_res, "Cache-Control", "max-age=3600");
        let dec2 = wing::on_response(cache, head_req, head_res, ts, -1);

        let look = wing::lookup(cache, get_req, ts.response_time);
        sub.assert_true(look.kind == wing::LookupResultKind.Hit, "Subsequent GET must still hit cached GET entry");
        sub.assert_bytes_eq(look.cached_response.body[..], "cached-get-body", "Cached GET body must remain intact after HEAD");
    };
}

// ----------------------------------------------------------------------------
// F014: MIME SFV Unclosed Inner List, SFV Grammar & HTTP Signatures Verification
// ----------------------------------------------------------------------------
fn test_f014_sfv_and_signatures(t: lit::T&) {
    t.run("parse_sfv_list and parse_sfv_dict reject unclosed '(' at EOF") { sub =>
        var list = wing::SfvList { .. };
        let ok_l = wing::parse_sfv_list("(", list);
        sub.assert_false(ok_l, "Unclosed '(' in parse_sfv_list MUST return false");

        var dict = wing::SfvDict { .. };
        let ok_d = wing::parse_sfv_dict("k=(", dict);
        sub.assert_false(ok_d, "Unclosed 'k=(' in parse_sfv_dict MUST return false");
    };

    t.run("parse_sf_dict and parse_sf_list reject leading/consecutive commas and invalid base64 binary") { sub =>
        var entries: wing::SfDictEntry[..16] = [];
        sub.assert_false(wing::parse_sf_dict(", a=1", entries), "Leading comma in SF dict MUST fail");
        sub.assert_false(wing::parse_sf_dict("a=1, , b=2", entries), "Empty member in SF dict MUST fail");

        var items: wing::SfParameterizedItem[..16] = [];
        sub.assert_false(wing::parse_sf_list(":not valid base64!:", items), "Invalid base64 chars in sf-binary MUST fail");
    };

    t.run("verify_http_signature rejects when Signature-Input component list does not match params") { sub =>
        var req = wing::new_request("GET", "https://example.com/pay");
        var params = wing::HttpSignatureParams { label: "sig1", .. };
        params.components.push("@method");
        params.components.push("@target-uri");

        let key = "secret-key-12345678901234567890";
        sub.assert_true(wing::sign_http_request(req, params, key), "Signed request");

        // Tamper Signature-Input to omit @target-uri (empty inner list)
        wing::set_header(req, "Signature-Input", "sig1=();alg=\"hmac-sha256\"");
        let ok_ver = wing::verify_http_signature(req, "sig1", params, key);
        sub.assert_false(ok_ver, "Mismatched component list in Signature-Input MUST fail verification");
    };
}

// ----------------------------------------------------------------------------
// F015: H2 ExpectContinuation, Compression Dict, Forwarded, HSTS IPv6 & Trace
// ----------------------------------------------------------------------------
fn test_f015_h2_dict_forwarded_hsts_trace(t: lit::T&) {
    t.run("H2 process_incoming_frame returns ProtocolError and closes connection on bad frame during ExpectContinuation") { sub =>
        var framer = internal::H2SecurityFramer { .. };
        let hdr_open = internal::H2FrameHeader {
            payload_len: 10,
            frame_type:  internal::H2FrameType.Headers,
            flags:       0, // END_HEADERS not set -> ExpectContinuation
            stream_id:   1,
            valid:       true,
        };
        let err1 = internal::process_incoming_frame(framer, hdr_open);
        sub.assert_true(err1 == internal::H2ErrorCode.NoError, "HEADERS opens continuation state");

        // Send a PING with invalid length 4 while ExpectContinuation is active
        let bad_ping = internal::H2FrameHeader {
            payload_len: 4,
            frame_type:  internal::H2FrameType.Ping,
            flags:       0,
            stream_id:   0,
            valid:       true,
        };
        let err2 = internal::process_incoming_frame(framer, bad_ping);
        sub.assert_true(err2 == internal::H2ErrorCode.ProtocolError, "Non-CONTINUATION frame during ExpectContinuation MUST return ProtocolError per RFC 9113 §6.10");
        sub.assert_true(framer.state == internal::H2ConnState.Closed, "Framer state MUST transition to Closed");
    };

    t.run("parse_use_as_dictionary_header rejects oversized id even when followed by valid match") { sub =>
        var raw: u8[..256] = [];
        raw.append("id=\"");
        for i in 80 { raw.push('x'); }
        raw.append("\", match=\"/assets/*\"");

        let p, ok = wing::parse_use_as_dictionary_header(raw[..]);
        sub.assert_false(ok, "Oversized id followed by valid match MUST fail parsing");
    };

    t.run("parse_forwarded_element rejects oversized parameter value") { sub =>
        var raw: u8[..300] = [];
        raw.append("for=\"");
        for i in 200 { raw.push('1'); }
        raw.append("\";proto=https");

        var elem = wing::ForwardedElement { .. };
        let ok = wing::parse_forwarded_element(raw[..], elem);
        sub.assert_false(ok, "Forwarded element with oversized for parameter MUST fail instead of ignoring error");
    };

    t.run("parse_tracestate rejects duplicate keys per W3C Section 3.3.1") { sub =>
        let ts, ok = wing::parse_tracestate("rojo=1,rojo=2");
        sub.assert_false(ok, "Duplicate key in tracestate MUST be rejected per W3C §3.3.1");
    };
}

// ----------------------------------------------------------------------------
// Main Suite Runner
// ----------------------------------------------------------------------------
fn main() {
    var runner = lit::new_runner("HTTP Bug Hunter Regression Suite (F001 - F015)", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. F001 Compression Dictionary Bounds & Safety", test_f001_compression_dict_bounds);
    lit::run_case(runner, "2. F002 Status Diagnostics Bounds & Safety", test_f002_status_diagnostics_bounds_and_safety);
    lit::run_case(runner, "3. F003 Signature-Input Label Enforcement", test_f003_signature_input_verification);
    lit::run_case(runner, "4. F004 OHTTP Key Configs Safety & Discard", test_f004_ohttp_key_configs_discard_and_out);
    lit::run_case(runner, "5. F005 SFV Zero Silent Drops (Invariant 13)", test_f005_sfv_no_silent_dropping);
    lit::run_case(runner, "6. F006 W3C Trace Context Conformance", test_f006_trace_w3c_conformance);
    lit::run_case(runner, "7. F007 RFC 6797 HSTS Invariants", test_f007_hsts_rfc6797_invariants);
    lit::run_case(runner, "8. F008 HTTP Cache Engine Response Body Overflow", test_f008_cache_engine_oversized_response);
    lit::run_case(runner, "9. F009 Alt-Svc Slot Prioritization & Backoff Saturation", test_f009_altsvc_slot_prioritization_and_backoff_saturation);
    lit::run_case(runner, "10. F010 HeaderMap Overflow Spill Smuggling & Bounds", test_f010_headermap_overflow_and_bounds);
    lit::run_case(runner, "11. F011 Perfect Hash Collision & Chunked Trailers", test_f011_perfect_hash_and_chunked_trailers);
    lit::run_case(runner, "12. F012 Binary HTTP (RFC 9292) Varint & Trailer Safety", test_f012_bhttp_bounds_and_validation);
    lit::run_case(runner, "13. F013 HTTP Cache Invariants & ETag Validation", test_f013_http_cache_invariants);
    lit::run_case(runner, "14. F014 SFV Unclosed Inner List & HTTP Signatures", test_f014_sfv_and_signatures);
    lit::run_case(runner, "15. F015 H2 Continuation, Dict, Forwarded & Tracestate", test_f015_h2_dict_forwarded_hsts_trace);

    let ok = lit::finish(runner);
    assert(ok);
}
