// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Binary HTTP (RFC 9292) and Oblivious HTTP (RFC 9458) verification suite.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: bhttp --------------------------------------------------------

fn test_bhttp_request_roundtrip(t: lit::T&) {
    t.run("RFC 9292 Section 3.1/3.4 Known-Length Request Encode and Decode") { sub =>
        var req = wing::BhttpRequest { .. };
        req.method.clear();
        req.method.append("GET");
        req.target.clear();
        req.target.append("/index.html");
        let ok_h = req.headers.append_header("accept", "*/*");
        sub.assert_true(ok_h, "header appended");
        req.body.clear();
        req.body.append("hi");
        req.body_len = 2;

        var out: u8[..8192] = [];
        let n = wing::bhttp_encode_request(req, out);
        sub.assert_true(n > 0, "encode succeeds");
        sub.assert_eq(out[0], rfc::BHTTP_FRAME_KNOWN_LEN_REQUEST, "framing indicator is 0 (RFC 9292 Section 3.3)");

        var decoded = wing::BhttpRequest { .. };
        let ok = wing::bhttp_decode_request(out[..n], decoded);
        sub.assert_true(ok, "decode succeeds");
        sub.assert_bytes_eq(decoded.method[..], "GET", "method round-trips");
        sub.assert_bytes_eq(decoded.target[..], "/index.html", "target round-trips");
        sub.assert_bytes_eq(decoded.headers.get_header("accept"), "*/*", "header round-trips");
        sub.assert_eq(decoded.body_len, 2, "body length round-trips");
        sub.assert_bytes_eq(decoded.body[..decoded.body_len], "hi", "body bytes round-trip");

        // Re-encode the decoded message: byte-identical to the first encoding.
        var out2: u8[..8192] = [];
        let n2 = wing::bhttp_encode_request(decoded, out2);
        sub.assert_eq(n2, n, "re-encode length matches");
        sub.assert_bytes_eq(out2[..n2], out[..n], "re-encode is byte-identical");
    };
}

fn test_bhttp_response_roundtrip(t: lit::T&) {
    t.run("RFC 9292 Section 3.1/3.5 Known-Length Response Encode and Decode") { sub =>
        var res = wing::BhttpResponse { .. };
        let ok_h = res.headers.append_header("content-type", "text/plain");
        sub.assert_true(ok_h, "header appended");
        res.body.clear();
        res.body.append("ok");
        res.body_len = 2;

        var out: u8[..8192] = [];
        let n = wing::bhttp_encode_response(res, out);
        sub.assert_true(n > 0, "encode succeeds");
        sub.assert_eq(out[0], rfc::BHTTP_FRAME_KNOWN_LEN_RESPONSE, "framing indicator is 1 (RFC 9292 Section 3.3)");

        var decoded = wing::BhttpResponse { .. };
        let ok = wing::bhttp_decode_response(out[..n], decoded);
        sub.assert_true(ok, "decode succeeds");
        sub.assert_eq(decoded.status, 200, "status round-trips");
        sub.assert_bytes_eq(decoded.headers.get_header("content-type"), "text/plain", "header round-trips");
        sub.assert_eq(decoded.body_len, 2, "body length round-trips");
        sub.assert_bytes_eq(decoded.body[..decoded.body_len], "ok", "body bytes round-trip");
    };
}

fn test_bhttp_invalid_framing(t: lit::T&) {
    t.run("RFC 9292 Section 3.3/4 Invalid Framing Indicator Rejection") { sub =>
        // 0x04 is outside the four permitted values (0..3) -> invalid per Section 4.
        let bad04: u8[2] = [0x04, 0x03];
        var req_out = wing::BhttpRequest { .. };
        sub.assert_false(wing::bhttp_decode_request(bad04[..], req_out), "framing 0x04 rejected for requests");
        var res_out = wing::BhttpResponse { .. };
        sub.assert_false(wing::bhttp_decode_response(bad04[..], res_out), "framing 0x04 rejected for responses");

        // Indeterminate-length framing (2/3) is out of scope: decoder accepts only 0/1.
        let bad02: u8[1] = [0x02];
        sub.assert_false(
            wing::bhttp_decode_request(bad02[..], req_out),
            "framing 0x02 rejected (indeterminate out of scope)",
        );
        let bad03: u8[1] = [0x03];
        sub.assert_false(
            wing::bhttp_decode_response(bad03[..], res_out),
            "framing 0x03 rejected (indeterminate out of scope)",
        );
    };
}

// --- Component: ohttp key configs --------------------------------------------

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

fn test_ohttp_key_config(t: lit::T&) {
    t.run("RFC 9458 Section 3.1 Single Key Configuration Layout") { sub =>
        let cfg_bytes = ohttp_test_key_config_bytes();
        var cfg = wing::OhttpKeyConfig { .. };
        let ok = wing::parse_ohttp_key_config(cfg_bytes[..], cfg);
        sub.assert_true(ok, "Appendix A key configuration parses");
        sub.assert_eq(cfg.key_id, 0x01, "key identifier is 1");
        sub.assert_eq(cfg.kem_id, rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256, "KEM ID is X25519 (0x0020)");
        sub.assert_eq(cfg.kdf_id, rfc::HPKE_KDF_HKDF_SHA256, "first pair KDF ID is HKDF-SHA256 (0x0001)");
        sub.assert_eq(cfg.aead_id, rfc::HPKE_AEAD_AES_128_GCM, "first pair AEAD ID is AES-128-GCM (0x0001)");
        sub.assert_eq(cfg.public_key_len, 32, "public key is Npk = 32 bytes");
        let pk_expect: u8[32] = [
            0x31, 0xe1, 0xf0, 0x5a, 0x74, 0x01, 0x02, 0x11, 0x52, 0x20, 0xe9, 0xaf, 0x91,
            0x8f, 0x73, 0x86, 0x74, 0xae, 0xc9, 0x5f, 0x54, 0xdb, 0x6e, 0x04, 0xeb, 0x70,
            0x5a, 0xae, 0x8e, 0x79, 0x81, 0x55,
        ];
        for i in 32 {
            sub.assert_eq(cfg.public_key[i], pk_expect[i], "public key bytes match");
        }

        // Unsupported suite (AES-256-GCM is outside the restricted OHTTP suite
        // set) in the first — and only selected — KDF/AEAD pair is rejected.
        var bad = cfg_bytes;
        bad[39] = 0x00;
        bad[40] = 0x02;
        var bad_cfg = wing::OhttpKeyConfig { .. };
        sub.assert_false(wing::parse_ohttp_key_config(bad[..], bad_cfg), "unsupported AEAD pair rejected");
    };

    t.run("RFC 9458 Section 3.2 Collection Parse and All-or-Nothing Discard") { sub =>
        let cfg_bytes = ohttp_test_key_config_bytes();

        // Valid two-config collection: u16be length prefix per element, concatenated.
        var good: u8[..128] = [];
        good.push(0x00);
        good.push(45);
        good.append(cfg_bytes[..]);
        var cfg2 = cfg_bytes;
        cfg2[0] = 0x07;
        good.push(0x00);
        good.push(45);
        good.append(cfg2[..]);

        var out:       wing::OhttpKeyConfig[..4] = [wing::OhttpKeyConfig { .. }; 4];
        var out_count: i32                       = 0;
        let ok = wing::parse_ohttp_key_configs(good[..], out, out_count);
        sub.assert_true(ok, "valid two-config collection parses");
        sub.assert_eq(out_count, 2, "two configurations recovered");
        sub.assert_eq(out[0].key_id, 0x01, "first key id is 1");
        sub.assert_eq(out[1].key_id, 0x07, "second key id is 7");

        // Second element's length prefix lies (claims 100 bytes, only 45 present):
        // Clients MUST discard incorrectly encoded collections (RFC 9458 Section 3.2).
        var lying: u8[..128] = [];
        lying.push(0x00);
        lying.push(45);
        lying.append(cfg_bytes[..]);
        lying.push(0x00);
        lying.push(100);
        lying.append(cfg_bytes[..]);
        var out2:       wing::OhttpKeyConfig[..4] = [wing::OhttpKeyConfig { .. }; 4];
        var out_count2: i32                       = 99;
        let ok2 = wing::parse_ohttp_key_configs(lying[..], out2, out_count2);
        sub.assert_false(ok2, "lying length prefix discards whole collection");
        sub.assert_eq(out_count2, 0, "out_count is 0 after discard");

        // Malformed element content (element shorter than a valid config) also discards the collection.
        var truncated: u8[..128] = [];
        truncated.push(0x00);
        truncated.push(10);
        truncated.push(0x01);
        truncated.push(0x00);
        truncated.push(0x20);
        truncated.append(cfg_bytes[3..10]);
        var out3:       wing::OhttpKeyConfig[..4] = [wing::OhttpKeyConfig { .. }; 4];
        var out_count3: i32                       = 99;
        let ok3 = wing::parse_ohttp_key_configs(truncated[..], out3, out_count3);
        sub.assert_false(ok3, "truncated element discards whole collection");
        sub.assert_eq(out_count3, 0, "out_count is 0 after truncated discard");
    };
}

// --- Component: ohttp request/response ---------------------------------------

fn ohttp_test_keypair() -> u8[32] {
    return [
        0x3c, 0x16, 0x89, 0x75, 0x67, 0x4b, 0x2f, 0xa8, 0xe4, 0x65, 0x97, 0x0b, 0x79,
        0xc8, 0xdc, 0xf0, 0x9f, 0x1c, 0x74, 0x16, 0x26, 0x48, 0x0b, 0xd4, 0xc6, 0x16,
        0x2f, 0xc5, 0xb6, 0xa9, 0x8e, 0x1a,
    ];
}

fn ohttp_test_ephemeral_sk() -> u8[32] {
    return [
        0xbc, 0x51, 0xd5, 0xe9, 0x30, 0xbd, 0xa2, 0x65, 0x89, 0x89, 0x0a, 0xc7, 0x03,
        0x2f, 0x70, 0xad, 0x12, 0xe4, 0xec, 0xb3, 0x7a, 0xbb, 0x1b, 0x65, 0xb1, 0x25,
        0x6c, 0x9c, 0x48, 0x99, 0x9c, 0x73,
    ];
}

fn test_ohttp_request_roundtrip(t: lit::T&) {
    t.run("RFC 9458 Section 4.1/4.3 Request Seal and Open Round-Trip") { sub =>
        let skR = ohttp_test_keypair();
        let pkR = core::x25519_base_scalarmult(skR);

        var cfg = wing::OhttpKeyConfig { .. };
        cfg.key_id = 1;
        cfg.public_key.append(pkR[..]);
        cfg.public_key_len = 32;

        var inner = wing::BhttpRequest { .. };
        inner.target.clear();
        inner.target.append("/ohttp");
        var inner_buf: u8[..8192] = [];
        let inner_len = wing::bhttp_encode_request(inner, inner_buf);
        sub.assert_true(inner_len > 0, "inner bhttp request encodes");

        let eph = ohttp_test_ephemeral_sk();
        var session = wing::OhttpSession { .. };
        var sealed:     u8[..8192] = [];
        var sealed_len: i32        = 0;
        let ok_seal = wing::ohttp_seal_request(cfg, eph, inner_buf[..inner_len], sealed, sealed_len, session);
        sub.assert_true(ok_seal, "ohttp_seal_request succeeds");
        sub.assert_true(sealed_len > 39, "sealed output has hdr + enc + ct");

        // 7-byte hdr: key_id, kem_id, kdf_id, aead_id in network order (RFC 9458 Section 4.1).
        sub.assert_eq(sealed[0], 0x01, "hdr key_id is 1");
        sub.assert_eq(sealed[1], 0x00, "hdr kem_id high byte");
        sub.assert_eq(sealed[2], 0x20, "hdr kem_id low byte (0x0020)");
        sub.assert_eq(sealed[3], 0x00, "hdr kdf_id high byte");
        sub.assert_eq(sealed[4], 0x01, "hdr kdf_id low byte (0x0001)");
        sub.assert_eq(sealed[5], 0x00, "hdr aead_id high byte");
        sub.assert_eq(sealed[6], 0x01, "hdr aead_id low byte (0x0001)");
        sub.assert_eq(session.enc_len, 32, "session retains 32-byte enc");

        var gw_session = wing::OhttpSession { .. };
        var opened:     u8[..8192] = [];
        var opened_len: i32        = 0;
        let ok_open = wing::ohttp_open_request(skR, sealed[..sealed_len], opened, opened_len, gw_session);
        sub.assert_true(ok_open, "ohttp_open_request succeeds");
        sub.assert_eq(opened_len, inner_len, "opened plaintext length matches");
        sub.assert_bytes_eq(opened[..opened_len], inner_buf[..inner_len], "opened plaintext equals original bhttp");
        sub.assert_eq(gw_session.enc_len, 32, "gateway session retains enc for response salt");

        // Tamper one ciphertext byte (first ct byte is at offset 7 + 32 = 39).
        var tampered: u8[..8192] = [];
        tampered.append(sealed[..sealed_len]);
        tampered[39] = tampered[39] ^ 0x01;
        var opened2:     u8[..8192] = [];
        var opened_len2: i32        = 0;
        var gw_session2 = wing::OhttpSession { .. };
        let ok_tamper = wing::ohttp_open_request(skR, tampered[..sealed_len], opened2, opened_len2, gw_session2);
        sub.assert_false(ok_tamper, "tampered ciphertext fails to open");
    };
}

fn test_ohttp_response_roundtrip(t: lit::T&) {
    t.run("RFC 9458 Section 4.4 Response Seal and Open Round-Trip") { sub =>
        let skR = ohttp_test_keypair();
        let pkR = core::x25519_base_scalarmult(skR);

        var cfg = wing::OhttpKeyConfig { .. };
        cfg.key_id = 1;
        cfg.public_key.append(pkR[..]);
        cfg.public_key_len = 32;

        var inner = wing::BhttpRequest { .. };
        var inner_buf: u8[..8192] = [];
        let inner_len = wing::bhttp_encode_request(inner, inner_buf);

        let eph = ohttp_test_ephemeral_sk();
        var client_session = wing::OhttpSession { .. };
        var sealed:     u8[..8192] = [];
        var sealed_len: i32        = 0;
        sub.assert_true(
            wing::ohttp_seal_request(cfg, eph, inner_buf[..inner_len], sealed, sealed_len, client_session),
            "request sealed",
        );

        var gw_session = wing::OhttpSession { .. };
        var opened:     u8[..8192] = [];
        var opened_len: i32        = 0;
        sub.assert_true(
            wing::ohttp_open_request(skR, sealed[..sealed_len], opened, opened_len, gw_session),
            "request opened by gateway",
        );

        // Gateway seals a response with a caller-supplied 16-byte response_nonce.
        var resp = wing::BhttpResponse { .. };
        resp.body.clear();
        resp.body.append("ok");
        resp.body_len = 2;
        var resp_buf: u8[..8192] = [];
        let resp_len = wing::bhttp_encode_response(resp, resp_buf);
        sub.assert_true(resp_len > 0, "response bhttp encodes");

        let response_nonce: u8[16] = [
            0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
            0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        ];
        var enc_res:     u8[..8192] = [];
        var enc_res_len: i32        = 0;
        let ok_seal_res = wing::ohttp_seal_response(
            gw_session, response_nonce[..], resp_buf[..resp_len], enc_res, enc_res_len,
        );
        sub.assert_true(ok_seal_res, "ohttp_seal_response succeeds");
        sub.assert_eq(enc_res_len, 16 + resp_len + 16, "enc_response = nonce || ct (with 16B tag)");
        sub.assert_bytes_eq(enc_res[..16], response_nonce[..], "enc_response starts with response_nonce");

        var client_out:     u8[..8192] = [];
        var client_out_len: i32        = 0;
        let ok_open_res = wing::ohttp_open_response(client_session, enc_res[..enc_res_len], client_out, client_out_len);
        sub.assert_true(ok_open_res, "ohttp_open_response succeeds");
        sub.assert_eq(client_out_len, resp_len, "response length matches");
        sub.assert_bytes_eq(client_out[..client_out_len], resp_buf[..resp_len], "response bhttp round-trips");

        // Tamper one byte of the AEAD-protected response (past the 16-byte nonce).
        var tampered: u8[..8192] = [];
        tampered.append(enc_res[..enc_res_len]);
        tampered[16] = tampered[16] ^ 0x01;
        var client_out2:     u8[..8192] = [];
        var client_out_len2: i32        = 0;
        sub.assert_false(
            wing::ohttp_open_response(client_session, tampered[..enc_res_len], client_out2, client_out_len2),
            "tampered enc_response fails to open",
        );
    };
}

fn test_hpke_export(t: lit::T&) {
    t.run("RFC 9180 Section 5.3 Secret Export Determinism") { sub =>
        let skR = ohttp_test_keypair();
        let pkR = core::x25519_base_scalarmult(skR);
        let eph = ohttp_test_ephemeral_sk();
        let info: const u8[:] = "message/bhttp request";

        var enc: u8[32] = [0; 32];
        var ctx = wing::HpkeContext { .. };
        let ok = wing::hpke_setup_base_s(
            pkR,
            info,
            rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256,
            rfc::HPKE_KDF_HKDF_SHA256,
            rfc::HPKE_AEAD_AES_128_GCM,
            eph,
            enc,
            ctx,
        );
        sub.assert_true(ok, "hpke_setup_base_s succeeds");

        var out1: u8[16] = [0; 16];
        var out2: u8[16] = [0; 16];
        var out3: u8[16] = [0; 16];
        sub.assert_true(wing::hpke_export(ctx, "message/bhttp response", out1[..]), "export with response context");
        sub.assert_true(wing::hpke_export(ctx, "message/bhttp response", out2[..]), "export repeated");
        sub.assert_true(wing::hpke_export(ctx, "message/bhttp request", out3[..]), "export with different context");
        for i in 16 {
            sub.assert_eq(out1[i], out2[i], "export is deterministic for fixed inputs");
        }
        var differs = false;
        for i in 16 {
            if out1[i] != out3[i] {
                differs = true;
            }
        }
        sub.assert_true(differs, "export differs when exporter_context differs");
    };
}

// --- Component: RFC 9458 Appendix A ------------------------------------------

fn test_ohttp_rfc9458_appendix_a(t: lit::T&) {
    t.run("RFC 9458 Appendix A Complete Request and Response Example (byte-for-byte)") { sub =>
        // Appendix A vectors; the corpus contains a complete example, so the
        // seal outputs are verified byte-for-byte per AGENTS.md vector policy.
        let skR = ohttp_test_keypair();
        let pkR = core::x25519_base_scalarmult(skR);
        let pk_expect: u8[32] = [
            0x31, 0xe1, 0xf0, 0x5a, 0x74, 0x01, 0x02, 0x11, 0x52, 0x20, 0xe9, 0xaf, 0x91,
            0x8f, 0x73, 0x86, 0x74, 0xae, 0xc9, 0x5f, 0x54, 0xdb, 0x6e, 0x04, 0xeb, 0x70,
            0x5a, 0xae, 0x8e, 0x79, 0x81, 0x55,
        ];
        for i in 32 {
            sub.assert_eq(pkR[i], pk_expect[i], "derived public key matches Appendix A");
        }

        var cfg = wing::OhttpKeyConfig { .. };
        let cfg_bytes = ohttp_test_key_config_bytes();
        sub.assert_true(wing::parse_ohttp_key_config(cfg_bytes[..], cfg), "Appendix A config parses");

        // Binary HTTP request from Appendix A: GET https://example.com/ (truncated after control data).
        let bhttp_req: u8[25] = [
            0x00, 0x03, 0x47, 0x45, 0x54, 0x05, 0x68, 0x74, 0x74, 0x70, 0x73, 0x0b,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x01, 0x2f,
        ];
        var decoded_req = wing::BhttpRequest { .. };
        sub.assert_true(wing::bhttp_decode_request(bhttp_req[..], decoded_req), "Appendix A bhttp request decodes");
        sub.assert_bytes_eq(decoded_req.method[..], "GET", "method is GET");
        sub.assert_bytes_eq(decoded_req.target[..], "/", "path is /");

        // Encapsulated Request (80 bytes): hdr || enc || ct.
        let eph = ohttp_test_ephemeral_sk();
        let enc_request: u8[80] = [
            0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01,
            0x4b, 0x28, 0xf8, 0x81, 0x33, 0x3e, 0x7c, 0x16, 0x4f, 0xfc, 0x49, 0x9a, 0xd9,
            0x79, 0x6f, 0x87, 0x7f, 0x4e, 0x10, 0x51, 0xee, 0x6d, 0x31, 0xba, 0xd1, 0x9d,
            0xec, 0x96, 0xc2, 0x08, 0xb4, 0x72,
            0x63, 0x74, 0xe4, 0x69, 0x13, 0x59, 0x06, 0x99, 0x2e, 0x12, 0x68, 0xc5, 0x94,
            0xd2, 0xa1, 0x0c, 0x69, 0x5d, 0x85, 0x8c, 0x40, 0xa0, 0x26, 0xe7, 0x96, 0x5e,
            0x7d, 0x86, 0xb8, 0x3d, 0xd4, 0x40, 0xb2, 0xc0, 0x18, 0x52, 0x04, 0xb4, 0xd6,
            0x35, 0x25,
        ];
        var sealed:     u8[..8192] = [];
        var sealed_len: i32        = 0;
        var client_session = wing::OhttpSession { .. };
        let ok_seal = wing::ohttp_seal_request(cfg, eph, bhttp_req[..], sealed, sealed_len, client_session);
        sub.assert_true(ok_seal, "Appendix A request seals");
        sub.assert_eq(sealed_len, 80, "enc_request is 80 bytes");
        for i in 80 {
            sub.assert_eq(sealed[i], enc_request[i], "enc_request matches Appendix A byte-for-byte");
        }

        var opened:     u8[..8192] = [];
        var opened_len: i32        = 0;
        var gw_session = wing::OhttpSession { .. };
        sub.assert_true(
            wing::ohttp_open_request(skR, enc_request[..], opened, opened_len, gw_session),
            "Appendix A request opens at gateway",
        );
        sub.assert_bytes_eq(opened[..opened_len], bhttp_req[..], "opened request equals Appendix A bhttp");

        // Exported secret from the gateway's receiver context (RFC 9458 Section 4.4 step 1).
        var secret: u8[16] = [0; 16];
        sub.assert_true(wing::hpke_export(gw_session.ctx, "message/bhttp response", secret[..]), "export succeeds");
        let secret_expect: u8[16] = [
            0x62, 0xd8, 0x7a, 0x6b, 0xa5, 0x69, 0xee, 0x81, 0x01, 0x4c, 0x26, 0x41,
            0xf5, 0x2b, 0xea, 0x36,
        ];
        for i in 16 {
            sub.assert_eq(secret[i], secret_expect[i], "exported secret matches Appendix A");
        }

        // Plaintext response: known-length 200, truncated after control data.
        let resp_plain: u8[3] = [0x01, 0x40, 0xc8];
        let response_nonce: u8[16] = [
            0xc7, 0x89, 0xe7, 0x15, 0x1f, 0xcb, 0xa4, 0x61, 0x58, 0xca, 0x84, 0xb0,
            0x44, 0x64, 0x91, 0x0d,
        ];
        let enc_response: u8[35] = [
            0xc7, 0x89, 0xe7, 0x15, 0x1f, 0xcb, 0xa4, 0x61, 0x58, 0xca, 0x84, 0xb0,
            0x44, 0x64, 0x91, 0x0d,
            0x86, 0xf9, 0x01, 0x3e, 0x40, 0x4f, 0xee, 0xa0, 0x14, 0xe7, 0xbe, 0x4a,
            0x44, 0x1f, 0x23, 0x4f, 0x85, 0x7f, 0xbd,
        ];
        var sealed_res:     u8[..8192] = [];
        var sealed_res_len: i32        = 0;
        let ok_seal_res = wing::ohttp_seal_response(
            gw_session, response_nonce[..], resp_plain[..], sealed_res, sealed_res_len,
        );
        sub.assert_true(ok_seal_res, "Appendix A response seals");
        sub.assert_eq(sealed_res_len, 35, "enc_response is 35 bytes");
        for i in 35 {
            sub.assert_eq(sealed_res[i], enc_response[i], "enc_response matches Appendix A byte-for-byte");
        }

        var client_out:     u8[..8192] = [];
        var client_out_len: i32        = 0;
        sub.assert_true(
            wing::ohttp_open_response(client_session, enc_response[..], client_out, client_out_len),
            "client opens Appendix A enc_response",
        );
        sub.assert_bytes_eq(client_out[..client_out_len], resp_plain[..], "client recovers Appendix A response");
    };
}

fn main() {
    var runner = lit::new_runner("Binary HTTP (RFC 9292) and Oblivious HTTP (RFC 9458) Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. RFC 9292 Section 3.1/3.3 Known-Length Request Round-Trip", test_bhttp_request_roundtrip);
    lit::run_case(runner, "2. RFC 9292 Known-Length Response Round-Trip", test_bhttp_response_roundtrip);
    lit::run_case(runner, "3. RFC 9292 Section 3.3/4 Invalid Framing Indicator Rejection", test_bhttp_invalid_framing);
    lit::run_case(
        runner, "4. RFC 9458 Section 3.1/3.2 Key Config Parsing and Collection Discard", test_ohttp_key_config,
    );
    lit::run_case(
        runner, "5. RFC 9458 Section 4.1/4.3 Request Seal/Open Round-Trip and Tamper", test_ohttp_request_roundtrip,
    );
    lit::run_case(
        runner, "6. RFC 9458 Section 4.4 Response Seal/Open Round-Trip and Tamper", test_ohttp_response_roundtrip,
    );
    lit::run_case(runner, "7. RFC 9180 Section 5.3 Secret Export Determinism", test_hpke_export);
    lit::run_case(runner, "8. RFC 9458 Appendix A Complete Request/Response Example", test_ohttp_rfc9458_appendix_a);

    let ok = lit::finish(runner);
    assert(ok);
}
