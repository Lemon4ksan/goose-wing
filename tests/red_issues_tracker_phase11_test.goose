// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Phase 11 RED test suite: Fixed-Capacity Truncation Smuggling, Protocol Limits & Defer Lifecycle
// Tests bounds aborts, silent drops, and RFC protocol non-conformances:
//
// 1. SFV string & display string truncation vs syntax rejection (http/mime.goose)
// 2. SFV parameter & list/dict capacity smuggling (http/mime.goose)
// 3. RFC 9111 Vary header > 16 fields cache poisoning defense (http/cache/validators.goose)
// 4. No-Vary-Search parameter capacity & key overflow safety (http/novarysearch.goose)
// 5. Digest challenge parameter value > 128B rejection without corruption (auth/digest.goose)
// 6. JWT claims & header oversized field safety without runtime abort (auth/jwt.goose)
// 7. W3C Trace Context 256-byte key specification compliance (http/trace.goose)
// 8. HTTP/1.x obs-fold buffer capacity overflow safety (http/headers.goose)

import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. SFV string & display string overflow rejection (http/mime.goose)
// ----------------------------------------------------------------------------
fn test_sfv_string_overflow_rejection(t: core::T&) {
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
fn test_sfv_capacity_smuggling_rejection(t: core::T&) {
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
fn test_vary_snapshot_capacity_poisoning_defense(t: core::T&) {
    t.run("Vary header with > 16 fields MUST invalidate snapshot to prevent cache poisoning") { sub =>
        var vary_val: u8[..512] = [];
        for i in 17 {
            if i > 0 { vary_val.append(", "); }
            vary_val.append("X-Vary-");
            format(vary_val, i);
        }

        var req_headers = wing::new_header_map();
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
fn test_novarysearch_capacity_safety(t: core::T&) {
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
fn test_digest_param_overflow_safety(t: core::T&) {
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
fn test_jwt_oversized_fields_no_abort(t: core::T&) {
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
fn test_trace_context_spec_key_length(t: core::T&) {
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
fn test_http_headers_obs_fold_capacity_safety(t: core::T&) {
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

        var map = wing::new_header_map();
        let err = wing::parse_headers(headers_raw[..], map, true);
        sub.assert_true(err == wing::HeaderParseError.CapacityExceeded, "Oversized obs-fold MUST return CapacityExceeded");
    };
}

fn main() {
    var runner = core::new_runner("RED Suite Phase 11: Fixed Buffer Limits & Safety", core::Verbosity.Verbose);
    core::run_case(runner, "1. SFV string overflow rejection (http/mime.goose)", test_sfv_string_overflow_rejection);
    core::run_case(runner, "2. SFV capacity smuggling rejection (http/mime.goose)", test_sfv_capacity_smuggling_rejection);
    core::run_case(runner, "3. RFC 9111 Vary cache poisoning defense (http/cache/validators.goose)", test_vary_snapshot_capacity_poisoning_defense);
    core::run_case(runner, "4. No-Vary-Search capacity safety (http/novarysearch.goose)", test_novarysearch_capacity_safety);
    core::run_case(runner, "5. Digest challenge parameter overflow safety (auth/digest.goose)", test_digest_param_overflow_safety);
    core::run_case(runner, "6. JWT oversized fields safety (auth/jwt.goose)", test_jwt_oversized_fields_no_abort);
    core::run_case(runner, "7. W3C Trace Context 256-byte key support (http/trace.goose)", test_trace_context_spec_key_length);
    core::run_case(runner, "8. HTTP/1.x obs-fold capacity safety (http/headers.goose)", test_http_headers_obs_fold_capacity_safety);
    let ok = core::finish(runner);
    assert(ok);
}
