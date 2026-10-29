// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for TLS 1.3 Mutual Authentication (mTLS / RFC 8446 Section 4.4.2):
// - CertificateRequest message encoding & parsing (RFC 8446 §4.3.2)
// - Empty client Certificate handling and CertificateVerify omission (RFC 8446 §4.4.2)
// - Client certificate formatting & digital signature generation (RFC 8446 §4.4.3)
// - Cryptographic signature verification via Ed25519 against transcript hash
// - Strict rejection on signature tampering, wrong public key, or context tampering
import std;
import core from "..";
import wing from "..";

fn test_certificate_request_codec(t: core::T&) {
    t.run("CertificateRequest Encoding & Parsing (RFC 8446 §4.3.2)") { sub =>
        var req_buf: u8[>..] = [];
        let sig_algs: u16[3] = [
            wing::SIG_SCHEME_ED25519,
            wing::SIG_SCHEME_ECDSA_SECP256R1_SHA256,
            wing::SIG_SCHEME_RSA_PSS_RSAE_SHA256,
        ];
        let enc_ok = wing::encode_certificate_request(req_buf, "", sig_algs[..]);
        sub.assert_true(enc_ok, "Encoded CertificateRequest");
        sub.assert_gt(req_buf.len, 8, "Message has length");

        var parsed_req = wing::CertificateRequestMsg { .. };
        let parse_ok = wing::parse_certificate_request(req_buf[..], false, parsed_req);
        sub.assert_true(parse_ok, "Parsed CertificateRequest");
        sub.assert_eq(parsed_req.context.len, 0, "Initial handshake context is 0 bytes");
        sub.assert_true(parsed_req.has_signature_algorithms, "Has signature algorithms extension");
        sub.assert_eq(parsed_req.sig_algorithms.len, 3, "Contains 3 signature schemes");
        sub.assert_eq(parsed_req.sig_algorithms[0], wing::SIG_SCHEME_ED25519, "First scheme is Ed25519");
        sub.assert_eq(parsed_req.sig_algorithms[1], wing::SIG_SCHEME_ECDSA_SECP256R1_SHA256, "Second is P-256");
        sub.assert_eq(parsed_req.sig_algorithms[2], wing::SIG_SCHEME_RSA_PSS_RSAE_SHA256, "Third is RSA-PSS");
    };
}

fn test_empty_client_certificate(t: core::T&) {
    t.run("Empty Client Certificate Handling (RFC 8446 §4.4.2)") { sub =>
        // Client without certificate must send empty Certificate message
        var cert_buf: u8[>..] = [];
        let enc_ok = wing::encode_client_certificate(cert_buf, "", "");
        sub.assert_true(enc_ok, "Encoded empty client Certificate");

        let is_empty, ok_p = wing::parse_certificate_header_is_empty(cert_buf[..]);
        sub.assert_true(ok_p, "Parsed certificate header");
        sub.assert_true(is_empty, "Certificate list is empty");

        // FSM verification: empty client cert transitions directly to ServerWaitFinished (CV omitted)
        let next_state, ok_trans = wing::server_wait_cert_step(wing::HS_MSG_CERTIFICATE, true);
        sub.assert_true(ok_trans, "Empty cert valid in ServerWaitCert");
        sub.assert_eq(next_state, wing::HsState.ServerWaitFinished, "Transitions directly to ServerWaitFinished");

        // Negative: if client mistakenly sends CertificateVerify after empty cert, server must reject
        let _, bad_cv = wing::server_wait_cv_step(wing::HS_MSG_CERTIFICATE_VERIFY, true);
        sub.assert_false(bad_cv, "CertificateVerify after empty cert strictly rejected");
    };
}

fn test_client_certificate_verify_ed25519(t: core::T&) {
    t.run("Client CertificateVerify Generation & Verification (Ed25519)") { sub =>
        // 1. Generate Ed25519 client keypair
        var seed: u8[32] = [0; 32];
        for i in 32 { seed[i] = (i + 1) as u8; }
        let client_pub = core::ed25519_public_key(seed);

        // Simulated transcript hash (SHA-256 of ClientHello..Certificate)
        var transcript_hash: u8[32] = [0x5A; 32];

        // 2. Client side: construct signed message and sign
        var sign_input: u8[160] = [0; 160];
        let input_len, ok_in = wing::build_certificate_verify_message(false, transcript_hash[..], sign_input[..]);
        sub.assert_true(ok_in, "Built client CertificateVerify input");

        let sig = core::ed25519_sign(seed, sign_input[..input_len]);

        // Encode CertificateVerify message
        var cv_buf: u8[>..] = [];
        let enc_cv = wing::encode_client_certificate_verify(cv_buf, wing::SIG_SCHEME_ED25519, sig[..]);
        sub.assert_true(enc_cv, "Encoded CertificateVerify message");

        // 3. Server side: parse and cryptographically verify
        let scheme, parsed_sig, ok_parse_cv = wing::parse_certificate_verify(cv_buf[..]);
        sub.assert_true(ok_parse_cv, "Parsed CertificateVerify");
        sub.assert_eq(scheme, wing::SIG_SCHEME_ED25519, "Scheme is Ed25519");
        sub.assert_eq(parsed_sig.len, 64, "Signature length is 64 bytes");

        let verify_ok = wing::verify_client_certificate_verify(
            scheme,
            parsed_sig,
            client_pub[..],
            transcript_hash[..],
        );
        sub.assert_true(verify_ok, "Cryptographic signature verifies successfully");

        // 4. Security checks: Tampered signature rejected
        var tampered_sig: u8[64] = [0; 64];
        for i in 64 { tampered_sig[i] = parsed_sig[i]; }
        tampered_sig[10] = tampered_sig[10] ^ 0xFF;
        let tampered_ok = wing::verify_client_certificate_verify(
            scheme,
            tampered_sig[..],
            client_pub[..],
            transcript_hash[..],
        );
        sub.assert_false(tampered_ok, "Tampered signature rejected");

        // Wrong public key rejected
        var wrong_pub: u8[32] = [0xFF; 32];
        let wrong_pub_ok = wing::verify_client_certificate_verify(
            scheme,
            parsed_sig,
            wrong_pub[..],
            transcript_hash[..],
        );
        sub.assert_false(wrong_pub_ok, "Wrong public key rejected");

        // Wrong transcript hash rejected
        var wrong_hash: u8[32] = [0x00; 32];
        let wrong_hash_ok = wing::verify_client_certificate_verify(
            scheme,
            parsed_sig,
            client_pub[..],
            wrong_hash[..],
        );
        sub.assert_false(wrong_hash_ok, "Mismatched transcript hash rejected");
    };
}

fn main() {
    var runner = core::new_runner("TLS 1.3 Mutual Authentication (mTLS) Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. CertificateRequest Codec", test_certificate_request_codec);
    core::run_case(runner, "2. Empty Client Certificate", test_empty_client_certificate);
    core::run_case(runner, "3. Client CertificateVerify Ed25519", test_client_certificate_verify_ed25519);
    let ok = core::finish(runner);
    assert(ok);
}
