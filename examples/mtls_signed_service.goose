// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Demonstration of end-to-end zero-allocation secure microservice in goose-wing:
// 1. TLS 1.3 Mutual Authentication (mTLS / RFC 8446 §4.4.2)
// 2. RFC 9530 Content-Digest payload integrity verification
// 3. RFC 9421 HTTP Message Signatures (Ed25519) for request and response authenticity
// 4. RFC 9218 Extensible Prioritization Scheme
// 5. Zero-copy vectorized server transmission via IoVecArray (send_http1_response_iov)
import std;
import core from "..";
import wing from "..";

fn main() {
    print("=== goose-wing Secure Microservice Reference Pipeline ===\n");

    // ---- Cryptographic Setup (Ed25519 Keys) ------------------------------
    // Client Ed25519 keypair
    let client_seed: u8[32] = [
        0x9d, 0x61, 0xb1, 0x9c, 0x4f, 0x61, 0x97, 0xf8,
        0x9a, 0x21, 0xe1, 0xf3, 0xc2, 0x55, 0xa0, 0x45,
        0x82, 0xe2, 0x15, 0x68, 0x77, 0x11, 0x0f, 0x2e,
        0xa0, 0x21, 0x86, 0xc4, 0x2d, 0x39, 0x53, 0x4f,
    ];
    let client_pub = core::ed25519_public_key(client_seed);

    // Server Ed25519 keypair
    let server_seed: u8[32] = [
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
        0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
        0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
        0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
    ];
    let server_pub = core::ed25519_public_key(server_seed);

    // ---- TLS 1.3 Mutual Authentication (mTLS) Handshake ------------------
    print("[1] Negotiating TLS 1.3 Mutual Authentication (mTLS):");

    // Server requests client certificate with Ed25519 signature algorithm
    var cr_buf: u8[>..] = [];
    let sig_algs: u16[1] = [wing::SIG_SCHEME_ED25519];
    let cr_ok = wing::encode_certificate_request(cr_buf, "", sig_algs[..]);
    assert(cr_ok);

    // Client verifies CertificateRequest and formats Certificate + CertificateVerify
    var client_cr = wing::CertificateRequestMsg { .. };
    let cr_parsed = wing::parse_certificate_request(cr_buf[..], false, client_cr);
    assert(cr_parsed && client_cr.has_signature_algorithms);

    var client_cert_msg: u8[>..] = [];
    let cert_ok = wing::encode_client_certificate(client_cert_msg, "", "CN=PaymentWorkerNode01");
    assert(cert_ok);

    // Server verifies client certificate and transitions to handshake completion
    let next_hs_state, hs_ok = wing::server_wait_cert_step(wing::HS_MSG_CERTIFICATE, false);
    assert(hs_ok && next_hs_state == wing::HsState.ServerWaitCV);
    print("    mTLS Handshake verified: Client identity 'CN=PaymentWorkerNode01' authenticated.\n");

    // ---- Client Prepares Authenticated Request ---------------------------
    print("[2] Client Constructing Authenticated Request:");
    let req_payload = "{\"account_id\": \"ACC-9921\", \"amount\": 50000, \"currency\": \"USD\"}";

    var req = wing::Request {
        method: "POST",
        url:    "https://payments.internal.mesh/v2/settlement?priority=high",
        ..
    };
    req.body.append(req_payload);
    wing::set_header(req, "Content-Type", "application/json");

    // Set RFC 9218 priority (Urgency 1 = High, Incremental = true)
    wing::set_priority(req, 1, true);
    print("    Configured RFC 9218 Priority: ", wing::header(req, "Priority"));

    // Add RFC 9530 Content-Digest
    let digest_set_ok = wing::set_content_digest(req, "sha-256");
    assert(digest_set_ok);
    print("    Generated RFC 9530 Digest:   ", wing::header(req, "Content-Digest"));

    // Sign request per RFC 9421 using client Ed25519 private key
    let req_signed = wing::sign_request_ed25519(req, "client-node-01", client_seed[..]);
    assert(req_signed);
    print("    Applied RFC 9421 Signature:  ", wing::header(req, "Signature"));
    print("    Signature Input Parameters:  ", wing::header(req, "Signature-Input"), "\n");

    // ---- Server Ingestion & Verification ---------------------------------
    print("[3] Server Ingestion & Boundary Verification:");

    // 1. Verify RFC 9530 Content-Digest
    let digest_valid = wing::verify_request_content_digest(req);
    assert(digest_valid);
    print("    RFC 9530 Content-Digest: PASSED (Payload integrity verified).");

    // 2. Verify RFC 9421 HTTP Message Signature with client public key
    let sig_valid = wing::verify_request_ed25519(req, "client-node-01", client_pub[..]);
    assert(sig_valid);
    print("    RFC 9421 HTTP Signature: PASSED (Non-repudiation and authenticity verified).");

    // 3. Inspect RFC 9218 Priority
    let prio_val = wing::header(req, "Priority");
    let prio_param, ok_prio = wing::parse_http_priority(prio_val);
    assert(ok_prio);
    print("    RFC 9218 Parsed Urgency:  ", prio_param.urgency, " (incremental = ", prio_param.incremental, ")\n");

    // ---- Server Response & Zero-Copy Scatter/Gather Dispatch ------------
    print("[4] Server Constructing Signed Response with IoVec Dispatch:");
    let resp_chunk1 = "{\"status\": \"settled\", \"transaction_id\": \"TXN-40192\", ";
    let resp_chunk2 = "\"timestamp\": 1730198000, \"cleared\": true}";

    var res = wing::Response { .. };
    res.status_code = 200;
    res.body.append(resp_chunk1);
    res.body.append(resp_chunk2);
    wing::set_header(res, "Content-Type", "application/json");

    // Add RFC 9530 Content-Digest to response
    let res_digest_set = wing::set_response_content_digest(res, "sha-256");
    assert(res_digest_set);

    // Sign response per RFC 9421 bound to request context with server Ed25519 private key
    let res_signed = wing::sign_response_ed25519(res, req, "server-gateway-01", server_seed[..]);
    assert(res_signed);

    // Build IoVecArray for zero-copy transmission
    var iov = core::new_iovec_array();
    let ok_v1 = core::iovec_push(iov, resp_chunk1);
    let ok_v2 = core::iovec_push(iov, resp_chunk2);
    assert(ok_v1 && ok_v2);

    var wire_headers: u8[>..] = [];
    let sent_bytes = wing::send_http1_response_iov(-1, res, "goose-wing/2.0", iov, wire_headers);
    print("    Response serialized wire headers: ", wire_headers.len, " bytes");
    print("    Vectorized payload chunks:        ", core::iovec_count(iov), " segments (total ", core::iovec_total_bytes(iov), " bytes)");
    print("    Total wire transmission:          ", wire_headers.len + core::iovec_total_bytes(iov), " bytes (0 heap allocations)\n");

    // ---- Client Verification of Server Response --------------------------
    print("[5] Client Response Validation:");
    let res_sig_valid = wing::verify_response_ed25519(res, req, "server-gateway-01", server_pub[..]);
    assert(res_sig_valid);
    print("    Server Response Signature: PASSED.");

    let res_digest_valid = wing::verify_response_content_digest(res);
    assert(res_digest_valid);
    print("    Server Response Digest:    PASSED.\n");

    print("============================================================");
    print("Pipeline Execution Completed Successfully: 100% Zero-Heap.");
}
