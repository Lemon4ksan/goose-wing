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
// Main Suite Runner
// ----------------------------------------------------------------------------
fn main() {
    var runner = lit::new_runner("HTTP Bug Hunter Regression Suite (F001 - F008)", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. F001 Compression Dictionary Bounds & Safety", test_f001_compression_dict_bounds);
    lit::run_case(runner, "2. F002 Status Diagnostics Bounds & Safety", test_f002_status_diagnostics_bounds_and_safety);
    lit::run_case(runner, "3. F003 Signature-Input Label Enforcement", test_f003_signature_input_verification);
    lit::run_case(runner, "4. F004 OHTTP Key Configs Safety & Discard", test_f004_ohttp_key_configs_discard_and_out);
    lit::run_case(runner, "5. F005 SFV Zero Silent Drops (Invariant 13)", test_f005_sfv_no_silent_dropping);
    lit::run_case(runner, "6. F006 W3C Trace Context Conformance", test_f006_trace_w3c_conformance);
    lit::run_case(runner, "7. F007 RFC 6797 HSTS Invariants", test_f007_hsts_rfc6797_invariants);
    lit::run_case(runner, "8. F008 HTTP Cache Engine Response Body Overflow", test_f008_cache_engine_oversized_response);

    let ok = lit::finish(runner);
    assert(ok);
}
