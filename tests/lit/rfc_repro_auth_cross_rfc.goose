// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s
// RUN: goose check %s

import std;
import wing from "../..";
import core from "../..";

fn test_digest_cross_rfc() {
    // 1. RFC 9110 §11.2: Duplicate challenge parameter injection / algorithm downgrade
    let chal_dup_alg, ok1 = wing::parse_digest_challenge(
        "Digest realm=\"api\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", algorithm=SHA-256, algorithm=MD5",
    );
    let r1 = !ok1 && !chal_dup_alg.valid;

    let chal_dup_nonce, ok2 = wing::parse_digest_challenge(
        "Digest realm=\"api\", nonce=\"nonce_one_123456\", nonce=\"nonce_two_654321\"",
    );
    let r2 = !ok2 && !chal_dup_nonce.valid;

    // 2. RFC 7616 §3.3 & §4: Unsupported charset and invalid userhash
    let chal_bad_charset, ok3 = wing::parse_digest_challenge(
        "Digest realm=\"api\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", charset=ISO-8859-1",
    );
    let r3 = !ok3 && !chal_bad_charset.valid;

    let chal_good_charset, ok4 = wing::parse_digest_challenge(
        "Digest realm=\"api\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", charset=utf-8, userhash=false",
    );
    let r4 = ok4 && chal_good_charset.valid && !chal_good_charset.userhash;

    let chal_bad_userhash, ok5 = wing::parse_digest_challenge(
        "Digest realm=\"api\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", userhash=invalid",
    );
    let r5 = !ok5 && !chal_bad_userhash.valid;

    // 3. RFC 7616 §3.3: Malformed qop token list & empty qop="" downgrade
    let qop_bad_tail = !wing::qop_list_has_token("auth, bad;token", "auth");
    let chal_empty_qop, ok6 = wing::parse_digest_challenge(
        "Digest realm=\"api\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"\"",
    );
    let r6 = qop_bad_tail && !ok6 && !chal_empty_qop.valid;

    // 4. Stale challenge refresh must not silently downgrade SHA-256 to MD5 when algorithm omitted
    var stored, _ = wing::parse_digest_challenge(
        "Digest realm=\"api\", nonce=\"initial_nonce_12345\", algorithm=SHA-256, qop=\"auth\"",
    );
    let creds = wing::DigestCredentials { username: "alice", password: "secret", .. };
    var nc: u32 = 5;
    let ok_refresh = wing::refresh_digest_stale_nonce(
        stored,
        "Digest realm=\"api\", nonce=\"fresh_nonce_67890\", stale=true, qop=\"auth\"",
        creds,
        nc,
    );
    let bad_downgrade = !wing::refresh_digest_stale_nonce(
        stored,
        "Digest realm=\"api\", nonce=\"downgrade_nonce_111\", algorithm=MD5, stale=true, qop=\"auth\"",
        creds,
        nc,
    );
    let r7 = ok_refresh && stored.algorithm[..] == "SHA-256" && bad_downgrade && stored.algorithm[..] == "SHA-256";

    // 5. Control char in quoted realm rejected
    let chal_ctl, ok8 = wing::parse_digest_challenge(
        "Digest realm=\"api\x07\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"",
    );
    let r8 = !ok8 && !chal_ctl.valid;

    assert(r1);
    assert(r2);
    assert(r3);
    assert(r4);
    assert(r5);
    assert(r6);
    assert(r7);
    assert(r8);
    print("DIGEST_CROSS_RFC: true\n");
}
fn test_jwks_dpop_jwt_cross_rfc() {
    // 6. JWKS: Off-curve P-256 EC coordinates rejected in add_es256_key and parse_jwks_json
    var jwks_ec = wing::Jwks { .. };
    var zero_coord: u8[32] = [0; 32];
    let r9 = !wing::add_es256_key(jwks_ec, "ec-zero", zero_coord[..], zero_coord[..]);

    var jwks_json_ec = wing::Jwks { .. };
    let bad_ec_json = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"y\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}]}";
    let r10 = !wing::parse_jwks_json(bad_ec_json, jwks_json_ec);

    // 7. JWKS: Secondary key with private field "d" or invalid key in "keys" array must fail entire JWKS parse
    var jwks_mixed = wing::Jwks { .. };
    let mixed_json = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"},{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\"}]}";
    let r11 = !wing::parse_jwks_json(mixed_json, jwks_mixed);

    // 8. JWKS: compute_jwk_thumbprint rejects invalidated key & verify() preserves out_header on KeyNotFound
    var invalid_key = wing::JwksKey { kty: wing::JwkKeyType.OKP, crv: "Ed25519", valid: false, .. };
    var tp_out: u8[..64] = [];
    let r12 = !wing::compute_jwk_thumbprint(invalid_key, tp_out);

    var jwks_v = wing::Jwks { .. };
    let pub_ed: u8[32] = [1; 32];
    let _ = wing::add_ed25519_key(jwks_v, "real-kid", pub_ed);
    var sentinel_hdr = wing::JwtHeader { alg: wing::JwtAlg.EdDSA, kid: "sentinel-kid", .. };
    var sentinel_clm = wing::JwtClaims { .. };
    let opts = wing::default_jwt_validation_options(wing::JwtAlg.EdDSA);
    let verr = wing::verify(
        "eyJhbGciOiJFZERTQSIsImtpZCI6Im1pc3Npbmcta2lkIn0.eyJzdWIiOiJ1MSIsImV4cCI6OTk5OTk5OTk5OX0.c2ln",
        jwks_v, opts, 1700000000, sentinel_hdr, sentinel_clm,
    );
    let r13 = verr == wing::JwtError.KeyNotFound && sentinel_hdr.kid[..] == "sentinel-kid";

    // 9. DPoP: Header alg <-> jwk.kty mismatch, embedded jwk use="enc" / off-curve EC rejected
    let dpop_mismatch_hdr = "{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}}";
    let dpop_enc_hdr = "{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"use\":\"enc\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}}";
    let dpop_offcurve_hdr = "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"y\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}}";
    let r14 = !wing::verify_dpop_header(dpop_mismatch_hdr, "EdDSA") &&
              !wing::verify_dpop_header(dpop_enc_hdr, "EdDSA") &&
              !wing::verify_dpop_header(dpop_offcurve_hdr, "ES256");

    // 10. DPoP URI normalization: reject empty host, invalid port, and spaces in query
    var norm_u: u8[..256] = [];
    let r15 = !wing::normalize_dpop_target_uri("http://:80/resource", norm_u) &&
              !wing::normalize_dpop_target_uri("http://example.com:abc/resource", norm_u) &&
              !wing::normalize_dpop_target_uri("https://example.com/resource?q=a b", norm_u);

    // 11. JWT typ case-insensitive "APPLICATION/" prefix & RFC 7515 §4.1.9 slash check, plus empty aud rejection
    let r16 = wing::is_matching_jwt_typ("APPLICATION/at+jwt", "at+jwt") &&
              !wing::is_matching_jwt_typ("application/application/jwt", "application/jwt");
    var bad_aud_claims = wing::JwtClaims { .. };
    let r17 = !wing::parse_jwt_claims_json("{\"aud\":\"\"}", bad_aud_claims) &&
              !wing::parse_jwt_claims_json("{\"aud\":[\"\",\"api\"]}", bad_aud_claims);

    assert(r9);
    assert(r10);
    assert(r11);
    assert(r12);
    assert(r13);
    assert(r14);
    assert(r15);
    assert(r16);
    assert(r17);
    print("JWKS_DPOP_JWT_CROSS_RFC: true\n");
}

fn test_acme_pkce_dpop_jwks_seams() {
    // 12. ACME (RFC 8555 §8.1 & §8.3): acme_find_challenge rejects mismatched/corrupt key_auth slot
    // and clears out buffers on acme_key_authorization / acme_http01_path failure
    var acme_table: wing::AcmeChallenge[..8] = [];
    acme_table.push(wing::AcmeChallenge { token: "tok1", key_auth: "other.TP", key_auth_len: 8 });
    acme_table.push(wing::AcmeChallenge { token: "tok1", key_auth: "tok1.bad/tp", key_auth_len: 11 });
    acme_table.push(wing::AcmeChallenge { token: "tok1", key_auth: "tok1.TP", key_auth_len: 4 });
    acme_table.push(wing::AcmeChallenge { token: "tok1", key_auth: "tok1.ValidTP", key_auth_len: 12 });
    var acme_body: u8[..256] = [];
    var acme_len:  i32       = 0;
    let found_acme = wing::acme_find_challenge(acme_table, "/.well-known/acme-challenge/tok1", acme_body, acme_len);
    var acme_out: u8[..256] = "stale_key_auth";
    let bad_ka = wing::acme_key_authorization("bad/tok", "TP", acme_out);
    var acme_path: u8[..128] = "stale_path";
    let bad_hp = wing::acme_http01_path("bad/tok", acme_path);
    let r18 = found_acme && acme_len == 12 && acme_body[..] == "tok1.ValidTP" &&
              bad_ka == -1 && acme_out.len == 0 && bad_hp == -1 && acme_path.len == 0;

    // 13. PKCE (RFC 7636 §4.2): compute_code_challenge clears out on failure & create_pkce_pair clears method on error
    var pkce_out: u8[..128] = "stale_challenge";
    let ok_pkce = wing::compute_code_challenge("short", "S256", pkce_out);
    let bad_pair, ok_pair = wing::create_pkce_pair("0123456789abcdef0123456789abcdef", "invalid_method");
    let r19 = !ok_pkce && pkce_out.len == 0 && !ok_pair && bad_pair.verifier.len == 0 && bad_pair.method.len == 0;

    // 14. DPoP (RFC 9449 §4.2 / §6.1 / §8): parse_dpop_claims rejects empty ath/nonce/jkt & control chars in nonce
    var dpop_clm = wing::DPoPClaims { .. };
    let r20 = !wing::parse_dpop_claims("{\"jti\":\"j1\",\"htm\":\"GET\",\"htu\":\"https://example.com/\",\"iat\":1700000000,\"ath\":\"\"}", dpop_clm) &&
              !wing::parse_dpop_claims("{\"jti\":\"j1\",\"htm\":\"GET\",\"htu\":\"https://example.com/\",\"iat\":1700000000,\"nonce\":\"bad\\r\\nnonce\"}", dpop_clm) &&
              !wing::parse_dpop_claims("{\"jti\":\"j1\",\"htm\":\"GET\",\"htu\":\"https://example.com/\",\"iat\":1700000000,\"jkt\":\"\"}", dpop_clm);

    // 15. JWT/JWKS (RFC 7515 §4.1.4 & RFC 6598): Empty "kid":"" or "typ":"" rejected; CGNAT 100.64.0.0/10 exact bounds
    var empty_kid_hdr = wing::JwtHeader { .. };
    var empty_typ_hdr = wing::JwtHeader { .. };
    var jwks_empty_kid = wing::Jwks { .. };
    let r21 = !wing::parse_jwt_header_json("{\"alg\":\"EdDSA\",\"kid\":\"\"}", empty_kid_hdr) &&
              !wing::parse_jwt_header_json("{\"alg\":\"HS256\",\"typ\":\"\"}", empty_typ_hdr) &&
              !wing::parse_jwks_json("{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}]}", jwks_empty_kid) &&
              !wing::is_safe_remote_jwks_url("https://100.108.0.1/jwks") &&
              wing::is_safe_remote_jwks_url("https://100.60.0.1/jwks");

    // 16. JWKS zeroize_jwks_key wipes EC and RSA key material completely
    var rsa_key = wing::JwksKey { kty: wing::JwkKeyType.RSA, valid: true, .. };
    rsa_key.ec_x.append("ec_x_bytes");
    rsa_key.rsa_n.append("rsa_n_bytes");
    rsa_key.rsa_e.append("e_bytes");
    wing::zeroize_jwks_key(rsa_key);
    let r22 = !rsa_key.valid && rsa_key.ec_x.len == 0 && rsa_key.rsa_n.len == 0 && rsa_key.rsa_e.len == 0;

    assert(r18);
    assert(r19);
    assert(r20);
    assert(r21);
    assert(r22);
    print("ACME_PKCE_DPOP_JWKS_SEAMS: true\n");
}

// CHECK: DIGEST_CROSS_RFC: true
// CHECK: JWKS_DPOP_JWT_CROSS_RFC: true
// CHECK: ACME_PKCE_DPOP_JWKS_SEAMS: true
fn main() {
    test_digest_cross_rfc();
    test_jwks_dpop_jwt_cross_rfc();
    test_acme_pkce_dpop_jwks_seams();
}
