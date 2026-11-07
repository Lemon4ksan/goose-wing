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
        var out_body: u8[>..] = [];
        var out_trailers = wing::HeaderMap { .. };
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
    t.run("H2 on_ingress_frame_header returns ProtocolError on bad frame during continuation") { sub =>
        var conn = internal::new_h2_connection(0);
        let hdr_open = internal::FrameHeader {
            length:     10,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      0, // END_HEADERS not set -> ExpectContinuation
            stream_id:  1,
        };
        let err1 = internal::on_ingress_frame_header(conn, hdr_open, 0);
        sub.assert_true(err1 == rfc::H2_ERR_NO_ERROR, "HEADERS opens continuation state");

        // Send a PING with invalid length 4 while ExpectContinuation is active
        let bad_ping = internal::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_PING,
            flags:      0,
            stream_id:  0,
        };
        let err2 = internal::on_ingress_frame_header(conn, bad_ping, 0);
        sub.assert_true(err2 == rfc::H2_ERR_PROTOCOL_ERROR, "Non-CONTINUATION frame during ExpectContinuation MUST return ProtocolError per RFC 9113 §6.10");
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
// F016: Diagnostics Escapes, NVS Quotes/Parens, Hints Semicolons & Cert Chain
// ----------------------------------------------------------------------------
fn test_f016_diagnostics_nvs_hints_cert(t: lit::T&) {
    t.run("parse_proxy_status_header handles escaped quotes in details") { sub =>
        var entries: wing::ProxyStatusEntry[..8] = [];
        let raw = "edge1; error=connection_refused; details=\"upstream \\\"backend-1\\\" rst\"";
        let count = wing::parse_proxy_status_header(raw, entries);
        sub.assert_eq(count, 1, "Proxy-Status with escaped quotes in details must parse 1 entry");
        sub.assert_bytes_eq(entries[0].details[..], "upstream \\\"backend-1\\\" rst", "Details must preserve escaped quotes");
    };

    t.run("parse_no_vary_search handles parens and escaped quotes inside inner list") { sub =>
        let nvs1, ok1 = wing::parse_no_vary_search("params=(\"user(id)\" \"session\")");
        sub.assert_true(ok1, "NVS with parens inside quoted string must parse successfully");
        sub.assert_eq(nvs1.params.len, 2, "NVS params must contain 2 items");

        let nvs2, ok2 = wing::parse_no_vary_search("params=(\"foo\\\"bar\")");
        sub.assert_true(ok2, "NVS with escaped quote inside string must parse successfully");
        sub.assert_eq(nvs2.params.len, 1, "NVS params must contain 1 item");
    };

    t.run("parse_link_header preserves semicolons inside quoted parameter values") { sub =>
        var links: wing::EarlyHintLink[..8] = [];
        let raw = "</style.css>; rel=preload; as=style; extra=\"foo;rel=tampered\"";
        let ok = wing::parse_link_header(raw, links);
        sub.assert_true(ok, "Link header with quoted semicolon parameter must parse successfully");
        sub.assert_eq(links.len, 1, "One link element parsed");
        sub.assert_bytes_eq(links[0].rel[..], "preload", "rel attribute MUST not be overwritten by quoted param containing semicolon");
    };

    t.run("parse_client_cert_chain rejects empty or whitespace-only inputs") { sub =>
        var certs: u8[..4096][..4] = [];
        var lens:  i32[..4]        = [];
        var count: i32             = 0;
        let ok_empty = wing::parse_client_cert_chain("", certs, lens, count);
        sub.assert_false(ok_empty, "Empty client cert chain must be rejected per RFC 9440 / RFC 8941");

        let ok_ws = wing::parse_client_cert_chain("   ", certs, lens, count);
        sub.assert_false(ok_ws, "Whitespace client cert chain must be rejected");
    };

    t.run("decompress_dcz_payload and dcb preserve caller buffer on failure") { sub =>
        var buf: u8[..64] = [];
        buf.append("prefix");
        let ok_z = wing::decompress_dcz_payload("corrupted-zstd", "dict", buf);
        sub.assert_false(ok_z, "Invalid zstd payload MUST fail");
        sub.assert_bytes_eq(buf[..], "prefix", "Existing caller data in buf MUST NOT be cleared on zstd failure");

        let ok_b = wing::decompress_dcb_payload("corrupted-brotli", "dict", buf);
        sub.assert_false(ok_b, "Invalid brotli payload MUST fail");
        sub.assert_bytes_eq(buf[..], "prefix", "Existing caller data in buf MUST NOT be cleared on brotli failure");
    };
}

// ----------------------------------------------------------------------------
// F017-F023: HeaderMap Overflow Obs-Fold, Empty Host Smuggling, Shift & Chunked
// ----------------------------------------------------------------------------
fn test_f017_f023_headers_chunked_forwarded(t: lit::T&) {
    t.run("F017: handle_obs_fold_arena migrates name to spill_raw so resolve_entry_name does not panic") { sub =>
        var raw: u8[>..] = [];
        for i in 128 {
            raw.append("X-P: 1\r\n");
        }
        raw.append("X-Fold: val1\r\n val2\r\nHost: example.com\r\n\r\n");

        var map = wing::HeaderMap { .. };
        var arena = wing::OverflowArena { .. };
        let err = wing::parse_headers_with_overflow(raw[..], map, arena, true);
        sub.assert_true(wing::is_ok(err), "Obs-fold on 129th header followed by Host must succeed without OOB");
        sub.assert_bytes_eq(wing::get_header_spill(map, arena, "X-Fold"), "val1 val2", "Folded 129th header value resolved");
    };

    t.run("F018: duplicate Host header rejected even when first Host value is empty") { sub =>
        var map = wing::HeaderMap { .. };
        let err = wing::parse_headers("Host: \r\nHost: evil.com\r\n\r\n", map, false);
        sub.assert_false(wing::is_ok(err), "Duplicate Host after empty Host MUST be rejected per RFC 9112 §3.2");
    };

    t.run("F019: shift_raw_buf_left updates obs-folded values_begin when earlier header folded at tail") { sub =>
        var map = wing::HeaderMap { .. };
        let err = wing::parse_headers("X-Fold: a\r\n b\r\nX-Next: longvalue\r\n\r\n", map, true);
        sub.assert_true(wing::is_ok(err), "Initial obs-fold parse succeeds");
        wing::set_header(map, "X-Next", "v");
        sub.assert_bytes_eq(wing::get_header(map, "X-Fold"), "a b", "Obs-folded header value remains valid after in-place shrink");
    };

    t.run("F020: remove_sensitive_headers does not panic on HEADER_SRC_ARENA entries when raw > 8KB") { sub =>
        var raw: u8[>..] = [];
        raw.append("Authorization: Bearer secret\r\nX-Custom: 1\r\nX-Custom: 2\r\n");
        for i in 100 {
            raw.append("X-Pad: 01234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n");
        }
        raw.append("\r\n");
        var map = wing::HeaderMap { .. };
        var arena = wing::OverflowArena { .. };
        let err = wing::parse_headers_with_overflow(raw[..], map, arena, false);
        sub.assert_true(wing::is_ok(err), "Large >8KB header block parsed");
        wing::remove_sensitive_headers(map);
        sub.assert_false(wing::has_header_spill(map, arena, "Authorization"), "Sensitive Authorization removed without OOB");
    };

    t.run("F021: Host obs-fold smuggling, status-line SP/range, Proxy-Authenticate non-cacheable & 304 capacity") { sub =>
        var map1 = wing::HeaderMap { .. };
        let err1 = wing::parse_headers("Host: example.com\r\n , evil.com\r\n\r\n", map1, true);
        sub.assert_false(wing::is_ok(err1), "Obs-fold injecting space/comma into Host MUST be rejected");

        var map2 = wing::HeaderMap { .. };
        sub.assert_false(wing::is_ok(wing::parse_response_headers("HTTP/1.1200 OK\r\n\r\n", map2)), "Missing SP after HTTP/1.1 must fail");
        sub.assert_false(wing::is_ok(wing::parse_response_headers("HTTP/1.1 2000 OK\r\n\r\n", map2)), "4-digit status code must fail");
        sub.assert_false(wing::is_ok(wing::parse_response_headers("HTTP/1.1 000 OK\r\n\r\n", map2)), "Status code < 100 must fail");

        var src = wing::HeaderMap { .. };
        wing::append_header(src, "Proxy-Authenticate", "Basic realm=\"p\"");
        var dst = wing::HeaderMap { .. };
        wing::persist_headers(src, dst, wing::PERSIST_SANS_NON_CACHEABLE);
        sub.assert_false(wing::has_header(dst, "Proxy-Authenticate"), "Proxy-Authenticate MUST be stripped as non-cacheable");
    };

    t.run("F022-F023: Forwarded duplicate param & malformed element rejection, ChunkFsm BWS before = & TE params") { sub =>
        var elems: wing::ForwardedElement[..8] = [];
        sub.assert_eq(wing::parse_forwarded_header("for=1.2.3.4;for=5.6.7.8", elems), 0, "Duplicate for= in Forwarded element MUST fail per RFC 7239 §4");
        sub.assert_eq(wing::parse_forwarded_header("bad_elem, for=1.2.3.4", elems), 0, "Malformed Forwarded element MUST reject header");

        var dec = internal::ChunkFsmDecoder { .. };
        let st, consumed, chunk = internal::chunk_fsm_feed(dec, "4;ext =val\r\nWiki\r\n0\r\n\r\n");
        sub.assert_false(st == internal::ChunkFsmStatus.Error, "BWS before '=' in chunk-ext MUST be accepted per RFC 9112 §7.1.1");

        sub.assert_false(wing::validate_transfer_encoding_value("gzip;===, chunked"), "Malformed transfer-parameter gzip;=== MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// F024-F028: HSTS, Alt-Svc, Early Hints, Incremental, BHTTP, Dict & Digest
// ----------------------------------------------------------------------------
fn test_f024_f028_hsts_altsvc_bhttp_dict_digest(t: lit::T&) {
    t.run("F024: HSTS quoted semicolon extension, uppercase HTTP:// upgrade, and CRLF cache line") { sub =>
        let dir, ok = wing::parse_hsts_header("ext=\"x; includeSubDomains\"; max-age=31536000");
        sub.assert_true(ok, "Quoted semicolon in HSTS extension directive must parse");
        sub.assert_false(dir.include_subdomains, "Quoted '; includeSubDomains' inside ext MUST NOT set include_subdomains");

        var cache = wing::HstsCache { .. };
        sub.assert_true(wing::load_hsts_cache(cache, "example.com\t9999999999\t1\t1\r\n", 1000) == 1, "Load CRLF HSTS line");
        sub.assert_true(cache.entries[0].is_preload, "CRLF line must preserve is_preload == true");

        var up_url: u8[..128] = [];
        let upgraded = wing::hsts_upgrade_url(cache, "HTTP://example.com/login", 1000, up_url);
        sub.assert_true(upgraded, "Uppercase HTTP:// scheme MUST be upgraded by HSTS per RFC 6797 §8.3");
        sub.assert_bytes_eq(up_url[..], "https://example.com/login", "Upgraded URL normalized to https://");
    };

    t.run("F025: Alt-Svc quoted ';', Link first-rel & escaped quote comma, Incremental trailing/multi-line") { sub =>
        var cache = wing::AltSvcCache { .. };
        wing::update(cache, "example.com:443", "h3=\":443\"; ext=\"a;ma=0\"; ma=3600", 1000);
        var ep = wing::AltSvcEndpoint { .. };
        sub.assert_true(wing::lookup_h3(cache, "example.com:443", 1500, ep), "Quoted ';ma=0' inside ext must not zero ma=3600");

        var links: wing::EarlyHintLink[..8] = [];
        sub.assert_true(wing::parse_link_header("</a.js>; rel=preload; rel=nofollow", links), "Parse Link with duplicate rel");
        sub.assert_bytes_eq(links[0].rel[..], "preload", "First rel parameter MUST win per RFC 8288 §3.3");

        let inc_val, inc_ok = wing::parse_incremental_header("?1 ?0");
        sub.assert_false(inc_ok, "Incremental header with trailing '?0' MUST be rejected");
    };

    t.run("F026: BHTTP lowercase field names, Known-Length 1xx informational response, and method reset") { sub =>
        let raw_1xx: u8[9] = [
            0x01,       // Known-Length Response
            0x40, 0x67, // 103 Early Hints (2-byte varint = 103)
            0x00,       // empty 1xx field section
            0x40, 0xC8, // 200 OK
            0x00,       // empty final field section
            0x00,       // empty body
            0x00,       // empty trailer section
        ];
        var resp = wing::BhttpResponse { .. };
        sub.assert_true(wing::bhttp_decode_response(raw_1xx[..], resp), "Known-length BHTTP response with 103 before 200 MUST succeed per RFC 9292 §3.5.1");
        sub.assert_eq(resp.status, 200, "Final status code is 200");

        let bad_req: u8[7] = [0x00, 0x03, 'G', 'E', 'T', 0x05, 'h'];
        var req = wing::BhttpRequest { .. };
        sub.assert_false(wing::bhttp_decode_request(bad_req[..], req), "Truncated scheme fails");
        sub.assert_eq(req.method.len, 0, "req.method MUST be cleared on partial failure");
    };

    t.run("F027-F028: Compression dict empty-id collision & longest match, Digest multi-line verification") { sub =>
        var dcache = wing::DictionaryCache { .. };
        sub.assert_true(wing::dictionary_cache_insert(dcache, "https://ex.com", "/a/*", "", "dict-short", 3600, 100), "Insert short dict");
        sub.assert_true(wing::dictionary_cache_insert(dcache, "https://ex.com", "/a/b/*", "", "dict-long", 3600, 101), "Insert long dict without id");
        sub.assert_eq(dcache.entries.len, 2, "Second nameless dictionary with distinct match_pattern MUST NOT overwrite first");

        var matched_hash: u8[..64] = [];
        sub.assert_true(wing::dictionary_lookup_for_request(dcache, "https://ex.com", "/a/b/app.js", 110, matched_hash), "Lookup dict");
        sub.assert_bytes_eq(matched_hash[..], dcache.entries[1].sha256_base64[..], "Longest match_pattern MUST take precedence per RFC 9842 §2.2.3");

        let p_bad, ok_bad = wing::parse_use_as_dictionary_header("match=\"/a/*\", type=unknown");
        sub.assert_false(ok_bad, "Unknown dictionary type MUST be rejected per RFC 9842 §2.1.4");

        var req = wing::new_request("POST", "https://ex.com/upload");
        req.body.append("hello");
        var valid_dig: u8[..128] = [];
        sub.assert_true(wing::format_digest_field_value("sha-256", "hello", valid_dig), "Format valid digest");
        wing::append_header(req.headers, "Content-Digest", valid_dig[..]);
        wing::append_header(req.headers, "Content-Digest", "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:");
        sub.assert_false(wing::verify_request_content_digest(req), "Bad sha-256 on second Content-Digest header line MUST fail verification");
    };
}

// ----------------------------------------------------------------------------
// F029-F031: HTTP Cache Freshness, Validators, Cache Groups & Targeted Cache
// ----------------------------------------------------------------------------
fn test_f029_f031_http_cache_and_targeted_cache(t: lit::T&) {
    t.run("F029: SWR must not override client max-age or min-fresh when response is still fresh") { sub =>
        var resp_cc = wing::CacheControl { .. };
        wing::parse_cache_control_str("max-age=3600, stale-while-revalidate=60", resp_cc);
        var req_cc = wing::CacheControl { .. };
        wing::parse_cache_control_str("max-age=10", req_cc);
        let hdrs = wing::HeaderMap { .. };
        let ts = wing::CacheTimestamps {
            request_time:  core::Time { wall_sec: 1000, .. },
            response_time: core::Time { wall_sec: 1000, .. },
            now:           core::Time { wall_sec: 1100, .. },
            ..
        };
        let metrics = wing::evaluate_freshness(resp_cc, req_cc, hdrs, ts);
        sub.assert_false(metrics.is_fresh, "Age 100s > client max-age=10s is not fresh");
        sub.assert_false(metrics.stale_allowed, "Server SWR MUST NOT override client max-age when response is not yet stale (age 100 < lifetime 3600)");
        sub.assert_true(metrics.requires_revalidation, "Must require revalidation when client max-age is exceeded");
    };

    t.run("F030: Sanitize no-cache=\"X-Foo\", no-cache and multi-line 304 header merge") { sub =>
        var src = wing::HeaderMap { .. };
        wing::append_header(src, "Content-Type", "text/plain");
        wing::append_header(src, "X-Foo", "secret");
        var cc = wing::CacheControl { .. };
        wing::parse_cache_control_str("no-cache=\"X-Foo\", no-cache", cc);
        var dst = wing::HeaderMap { .. };
        wing::sanitize_for_storage(src, dst, false, cc);
        sub.assert_bytes_eq(wing::get_header(dst, "Content-Type"), "text/plain", "Unqualified no-cache after no-cache=\"X-Foo\" MUST NOT strip Content-Type from storage");
        sub.assert_bytes_eq(wing::get_header(dst, "X-Foo"), "", "Qualified X-Foo is stripped");

        var cached = wing::HeaderMap { .. };
        wing::append_header(cached, "X-Custom", "old");
        var resp_304 = wing::HeaderMap { .. };
        wing::append_header(resp_304, "X-Custom", "v1");
        wing::append_header(resp_304, "X-Custom", "v2");
        wing::merge_cached_headers_304(cached, resp_304);
        var comb: u8[..128] = [];
        sub.assert_true(wing::get_combined(cached, "X-Custom", comb), "Combined 304 X-Custom");
        sub.assert_bytes_eq(comb[..], "v1, v2", "Multi-line 304 headers of same name MUST both be preserved");
    };

    t.run("F031: Cross-origin Cache-Group-Invalidation isolation & invalid Targeted Cache-Control fallback") { sub =>
        var cache = wing::new_http_cache();
        let ts = wing::CacheTimestamps {
            request_time:  core::Time { wall_sec: 1000, .. },
            response_time: core::Time { wall_sec: 1000, .. },
            now:           core::Time { wall_sec: 1000, .. },
            ..
        };
        var req_a = wing::new_request("GET", "https://victim.example/asset.js");
        var resp_a = wing::Response { status_code: 200, .. };
        resp_a.set_header("Cache-Control", "max-age=3600");
        resp_a.set_header("Cache-Groups", "\"shared-tag\"");
        resp_a.body.append("victim");
        let dec_a = wing::on_response(cache, req_a, resp_a, ts);
        sub.assert_true(dec_a.kind == wing::ResponseDecisionKind.StoreAndReturn, "Stored victim entry");

        var req_evil = wing::new_request("POST", "https://attacker.example/purge");
        var resp_evil = wing::Response { status_code: 200, .. };
        resp_evil.set_header("Cache-Group-Invalidation", "\"shared-tag\"");
        let _ = wing::on_response(cache, req_evil, resp_evil, ts);
        sub.assert_true(cache.entries[dec_a.entry_idx].is_valid, "Cross-origin Cache-Group-Invalidation MUST NOT evict victim.example entry per RFC 9875 §3");

        var tmap = wing::HeaderMap { .. };
        wing::append_header(tmap, "Cache-Control", "no-store");
        wing::append_header(tmap, "CDN-Cache-Control", "@invalid");
        let tcc = wing::parse_targeted_cache_control_headers(tmap, "fastly");
        sub.assert_true(wing::is_no_store(tcc), "Unrecognized/empty CDN-Cache-Control MUST fall back to Cache-Control: no-store per RFC 9213 §2.1");
    };
}

// ----------------------------------------------------------------------------
// F032-F037: OHTTP, NVS, MIME, Problem, Multipart, SFV, Signatures & Status
// ----------------------------------------------------------------------------
fn test_f032_f037_ohttp_nvs_mime_problem_sfv_signatures(t: lit::T&) {
    t.run("F032-F034: NVS oversized ignored param & params=?1, MIME interior quote & duplicate param") { sub =>
        let nvs1, ok_nvs1 = wing::parse_no_vary_search("params=?1");
        sub.assert_true(ok_nvs1 && nvs1.ignore_all_params, "No-Vary-Search params=?1 MUST be accepted as boolean true");

        let _, ok_nvs_bad = wing::parse_no_vary_search("except=(\"id\")");
        sub.assert_false(ok_nvs_bad, "No-Vary-Search except without params MUST be rejected");

        var big_q: u8[..400] = [];
        big_q.append("utm_source=");
        for i in 300 { big_q.push('x'); }
        big_q.append("&id=42");
        var norm_q: u8[..128] = [];
        wing::normalize_query_for_cache(big_q[..], nvs1, norm_q);
        sub.assert_bytes_eq(norm_q[..], "", "All params ignored");

        let nvs_exc, ok_exc = wing::parse_no_vary_search("params, except=(\"id\")");
        sub.assert_true(ok_exc, "Parse params, except=(\"id\")");
        wing::normalize_query_for_cache(big_q[..], nvs_exc, norm_q);
        sub.assert_bytes_eq(norm_q[..], "id=42", "Oversized ignored param MUST NOT abort normalization of retained id=42");

        var unq_out: u8[..32] = [];
        sub.assert_false(wing::strict_unquote("\"a\"b\"", unq_out), "Unescaped interior quote MUST fail strict_unquote per RFC 9110 §5.6.4");

        let _, ok_mt = wing::parse_media_type("text/plain; charset=utf-8; charset=iso-8859-1");
        sub.assert_false(ok_mt, "Duplicate media type parameter charset MUST be rejected per RFC 9110 §5.6.6");
    };

    t.run("F035-F037: Problem oversized field & control escape, SFV inner list SP, Signatures & Cache-Status") { sub =>
        var big_json: u8[..400] = [];
        big_json.append("{\"title\":\"");
        for i in 200 { big_json.push('A'); }
        big_json.append("\",\"status\":400}");
        var prob = wing::ProblemDetails { .. };
        sub.assert_false(wing::parse_problem_details(big_json[..], prob), "Oversized ProblemDetails title (>128B) MUST fail closed instead of corrupting JSON reader");

        var entries: wing::SfDictEntry[..16] = [];
        sub.assert_false(wing::parse_sf_dict("sig1=(\"a\"\"b\")", entries), "Adjacent inner-list items without SP MUST be rejected per RFC 8941 §4.2.1.2");
        sub.assert_true(wing::parse_sf_dict("sig1=(\"@authority\";req)", entries), "Inner-list item with ;req parameter MUST be accepted per RFC 9421 §2.2.8");

        var c_entries: wing::CacheStatusEntry[..8] = [];
        let n_cs = wing::parse_cache_status_header("OriginCache; hit=?0", c_entries);
        sub.assert_eq(n_cs, 1, "Parsed Cache-Status with hit=?0");
        sub.assert_false(c_entries[0].hit, "hit=?0 MUST set hit=false per RFC 9211 §2.1");

        sub.assert_false(wing::is_valid_tracestate_val("abc "), "Trailing space in tracestate value MUST be rejected per W3C §3.3.1.2");
    };
}

// ----------------------------------------------------------------------------
// Main Suite Runner
// ----------------------------------------------------------------------------
fn main() {
    var runner = lit::new_runner("HTTP Bug Hunter Regression Suite (F001 - F037)", lit::Verbosity.Verbose);

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
    lit::run_case(runner, "16. F016 Diagnostics Escapes, NVS Quotes, Hints Semicolons & Certs", test_f016_diagnostics_nvs_hints_cert);
    lit::run_case(runner, "17. F017-F023 HeaderMap Arena Obs-Fold, Host Smuggling & Chunked", test_f017_f023_headers_chunked_forwarded);
    lit::run_case(runner, "18. F024-F028 HSTS, Alt-Svc, Early Hints, BHTTP, Dict & Digest", test_f024_f028_hsts_altsvc_bhttp_dict_digest);
    lit::run_case(runner, "19. F029-F031 HTTP Cache Freshness, Validators, Groups & Targeted", test_f029_f031_http_cache_and_targeted_cache);
    lit::run_case(runner, "20. F032-F037 OHTTP, NVS, MIME, Problem, SFV, Signatures & Status", test_f032_f037_ohttp_nvs_mime_problem_sfv_signatures);

    let ok = lit::finish(runner);
    assert(ok);
}
