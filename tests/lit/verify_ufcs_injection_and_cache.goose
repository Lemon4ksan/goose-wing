// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

// Mock PKCS#11 / CloudKMS hardware signer holding zero key material in struct fields.
struct Pkcs11HsmSigner {
    slot_id:    u32 = 1,
    sign_count: u32 = 0,
}

fn wing::sign_message(
    hsm:     Pkcs11HsmSigner&,
    alg:     const u8[:],
    tbs:     const u8[:],
    out_sig: u8[..512]&,
) -> bool {
    guard hsm.slot_id == 7 else {
        out_sig.clear();
        return false;
    }
    let enclave_secret = "pkcs11-enclave-slot-7-master-hmac-key";
    guard wing::compute_raw_signature(alg, enclave_secret, tbs, out_sig) else {
        return false;
    }
    hsm.sign_count += 1;
    return true;
}

fn wing::verify_message(
    hsm:          const Pkcs11HsmSigner&,
    alg:          const u8[:],
    tbs:          const u8[:],
    received_sig: const u8[:],
) -> bool {
    guard hsm.slot_id == 7 else { return false; }
    let enclave_secret = "pkcs11-enclave-slot-7-master-hmac-key";
    return wing::verify_crypto_signature(alg, enclave_secret, tbs, received_sig);
}

fn make_request_sig_params() -> wing::HttpSignatureParams {
    var params = wing::HttpSignatureParams {
        created: 1700000000,
        expires: 1700000300,
        ..
    };
    let _ = params.label.try_set("sig1");
    let _ = params.key_id.try_set("kms-key-01");
    let _ = params.alg.try_set("hmac-sha256");
    params.components.push("@method");
    params.components.push("@authority");
    params.components.push("@path");
    return params;
}

fn make_response_sig_params() -> wing::HttpSignatureParams {
    var params = wing::HttpSignatureParams {
        created: 1700000000,
        expires: 1700000300,
        ..
    };
    let _ = params.label.try_set("sig1");
    let _ = params.key_id.try_set("kms-key-01");
    let _ = params.alg.try_set("hmac-sha256");
    params.components.push("@status");
    params.components.push("content-type");
    params.components.push("@method;req");
    return params;
}

fn test_ufcs_crypto_signer_injection() {
    var mem_signer, ok_init = wing::new_memory_key_signer("in-memory-secret-hmac-key-2026-test");
    assert(ok_init);

    let req_params = make_request_sig_params();
    var req = wing::new_request("POST", "https://api.example.com/v1/orders");
    assert(wing::sign_http_request_with(req, req_params, mem_signer));
    assert(wing::verify_http_signature_with(req, "sig1", req_params, mem_signer, 1700000050));

    let res_params = make_response_sig_params();
    var res = wing::Response { status_code: 201, .. };
    res.set_header("Content-Type", "application/json");
    assert(wing::sign_http_response_with(res, req, res_params, mem_signer));
    assert(wing::verify_http_response_signature_with(res, req, "sig1", res_params, mem_signer, 1700000050));

    wing::clear_memory_key_signer(mem_signer);
    assert(mem_signer.key.len == 0);
    var req_after_clear = wing::new_request("GET", "https://api.example.com/v1/orders");
    assert(!wing::sign_http_request_with(req_after_clear, req_params, mem_signer));

    var hsm = Pkcs11HsmSigner { slot_id: 7, sign_count: 0 };
    var hsm_req = wing::new_request("POST", "https://api.example.com/v1/payments");
    assert(wing::sign_http_request_with(hsm_req, req_params, hsm));
    assert(wing::verify_http_signature_with(hsm_req, "sig1", req_params, hsm, 1700000050));

    var hsm_res = wing::Response { status_code: 200, .. };
    hsm_res.set_header("Content-Type", "application/json");
    assert(wing::sign_http_response_with(hsm_res, hsm_req, res_params, hsm));
    assert(wing::verify_http_response_signature_with(hsm_res, hsm_req, "sig1", res_params, hsm, 1700000050));
    assert(hsm.sign_count == 2);

    print("UFCS_SIGNER_INJECTION: OK hsm_calls=", hsm.sign_count);
}

fn make_item_url(idx: i64, out: u8[..256]&) {
    out.clear();
    out.append("https://cdn.example.com/assets/item-");
    idx.format_i64_dec(out);
}

fn make_cacheable_item_response(idx: i64) -> wing::Response {
    var resp = wing::Response { status_code: 200, .. };
    resp.set_header("Cache-Control", "public, max-age=3600");
    var etag_val: u8[..64] = "\"etag-";
    idx.format_i64_dec(etag_val);
    etag_val.push('"');
    resp.set_header("ETag", etag_val[..]);
    resp.body.append("payload-");
    idx.format_i64_dec(resp.body);
    return resp;
}

fn test_scalable_http_cache_and_stage_polymorphism() {
    var cache = wing::ScalableHttpCache { .. };
    wing::init_scalable_http_cache(cache, 128, 4096);
    let now_ts: i64 = 1700000000;

    // Populate 48 entries (> 32 and > old static 16-entry limit)
    for i in 48 {
        var url_buf: u8[..256] = [];
        make_item_url(i, url_buf);
        let req = wing::new_request("GET", url_buf[..]);
        let resp = make_cacheable_item_response(i);
        assert(cache.store_response(req, resp, now_ts));
    }
    assert(cache.entries.len == 48);

    // Fill remaining capacity up to 128 entries
    for i in 48..128 {
        var url_buf: u8[..256] = [];
        make_item_url(i, url_buf);
        let req = wing::new_request("GET", url_buf[..]);
        let resp = make_cacheable_item_response(i);
        assert(cache.store_response(req, resp, now_ts));
    }
    assert(cache.entries.len == 128);
    assert(cache.lru_head == 127);
    assert(cache.lru_tail == 0);

    // Touch entry 0 via lookup so entry 0 becomes MRU head and entry 1 becomes LRU tail
    var url0: u8[..256] = [];
    make_item_url(0, url0);
    let req0 = wing::new_request("GET", url0[..]);
    let hit0 = cache.lookup(req0, now_ts);
    assert(hit0.kind == wing::LookupResultKind.Hit);
    assert(cache.lru_head == 0);
    assert(cache.lru_tail == 1);

    // Store entry 128 when at capacity (128); must evict LRU tail (entry 1) in O(1)
    var url128: u8[..256] = [];
    make_item_url(128, url128);
    let req128 = wing::new_request("GET", url128[..]);
    let resp128 = make_cacheable_item_response(128);
    assert(cache.store_response(req128, resp128, now_ts));
    assert(cache.entries.len == 128);

    // Entry 1 was evicted -> Miss; Entry 0 and Entry 128 remain -> Hit
    var url1: u8[..256] = [];
    make_item_url(1, url1);
    let req1 = wing::new_request("GET", url1[..]);
    let miss1 = cache.lookup(req1, now_ts);
    assert(miss1.kind == wing::LookupResultKind.Miss);

    let hit0_again = cache.lookup(req0, now_ts);
    assert(hit0_again.kind == wing::LookupResultKind.Hit);

    // Pass ScalableHttpCache directly into stage_client_cache_lookup<Cache> via UFCS polymorphism
    var stage_hdrs = wing::HeaderMap { .. };
    var stage_resp = wing::Response { .. };
    var reval_idx: i64 = -1;
    let verdict = wing::stage_client_cache_lookup(
        req128,
        url128[..],
        now_ts,
        stage_hdrs,
        stage_resp,
        reval_idx,
        cache,
        true,
    );
    match verdict {
        ShortCircuit sc => assert(sc.status_code == 200),
        _ => assert(false),
    };
    assert(stage_resp.body[..] == "payload-128");

    print("SCALABLE_CACHE_UFCS: OK entries=", cache.entries.len, " body=", stage_resp.body[..]);
}

fn main() {
    test_ufcs_crypto_signer_injection();
    // CHECK: UFCS_SIGNER_INJECTION: OK hsm_calls=2
    test_scalable_http_cache_and_stage_polymorphism();
    // CHECK: SCALABLE_CACHE_UFCS: OK entries=128 body=payload-128
}
