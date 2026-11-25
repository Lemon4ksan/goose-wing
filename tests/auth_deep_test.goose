// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn make_b64url_jws_raw<B>(hdr_json: const u8[:], clm_json: const u8[:], sig: const u8[:], out: B&) {
    out.clear();
    core::base64url_encode(hdr_json, out);
    out.push('.');
    core::base64url_encode(clm_json, out);
    out.push('.');
    if sig.len > 0 {
        core::base64url_encode(sig, out);
    }
}

fn sign_raw_dpop_ed25519<B>(
    seed:     const u8[32]&,
    hdr_json: const u8[:],
    clm_json: const u8[:],
    out:      B&,
) {
    var signing: u8[..4096] = [];
    core::base64url_encode(hdr_json, signing);
    signing.push('.');
    core::base64url_encode(clm_json, signing);
    let sig = core::ed25519_sign(seed, signing[..]);
    out.clear();
    out.append(signing[..]);
    out.push('.');
    core::base64url_encode(sig[..], out);
}

fn test_jwt_core_and_verify(t: lit::T&) {
    t.run("JWT algorithms, headers, claims, and RFC 7797 unencoded") { sub =>
        sub.assert_true(auth::parse_jwt_alg("none") == auth::JwtAlg.None, "alg none");
        sub.assert_true(auth::parse_jwt_alg("HS256") == auth::JwtAlg.HS256, "alg HS256");
        sub.assert_true(auth::parse_jwt_alg("HS384") == auth::JwtAlg.HS384, "alg HS384");
        sub.assert_true(auth::parse_jwt_alg("HS512") == auth::JwtAlg.HS512, "alg HS512");
        sub.assert_true(auth::parse_jwt_alg("EdDSA") == auth::JwtAlg.EdDSA, "alg EdDSA");
        sub.assert_true(auth::parse_jwt_alg("ES256") == auth::JwtAlg.ES256, "alg ES256");
        sub.assert_true(auth::parse_jwt_alg("RS256") == auth::JwtAlg.RS256, "alg RS256");
        sub.assert_true(auth::parse_jwt_alg("PS256") == auth::JwtAlg.PS256, "alg PS256");
        sub.assert_true(auth::parse_jwt_alg("RS512") == auth::JwtAlg.Unknown, "alg unknown");

        var hdr = auth::new_jwt_header(auth::JwtAlg.HS256, "k1");
        let _ = hdr.cty.try_set("JWT");
        sub.assert_true(auth::add_header_crit(hdr, "b64"), "add crit b64");
        sub.assert_false(auth::add_header_crit(hdr, "b64"), "duplicate crit fails");
        hdr.has_b64 = true;
        hdr.b64 = false;

        var hdr_json: u8[..512] = [];
        sub.assert_true(auth::serialize_jwt_header(hdr, hdr_json), "serialize header with b64:false");
        var parsed_hdr = auth::JwtHeader { .. };
        sub.assert_true(auth::parse_jwt_header_json(hdr_json[..], parsed_hdr), "crit b64 with b64 present parses");

        var hdr2 = auth::new_jwt_header(auth::JwtAlg.HS256, "k1");
        hdr2.has_b64 = true;
        hdr2.b64 = true;
        let _ = auth::add_header_crit(hdr2, "exp");
        var hdr2_json: u8[..512] = [];
        sub.assert_true(auth::serialize_jwt_header(hdr2, hdr2_json), "serialize hdr2");
        sub.assert_false(auth::parse_jwt_header_json(hdr2_json[..], parsed_hdr), "crit param missing in header fails");
        sub.assert_false(auth::parse_jwt_header_json("[1,2]", parsed_hdr), "non-object header fails");
        sub.assert_false(auth::parse_jwt_header_json("{\"alg\":\"HS256\"\xFF}", parsed_hdr), "invalid utf8 header fails");

        var claims = auth::JwtClaims { exp: 2000, nbf: 1000, iat: 1000, .. };
        let _ = claims.iss.try_set("https://issuer.example");
        let _ = claims.sub.try_set("user-42");
        let _ = claims.jti.try_set("jti-1");
        sub.assert_true(auth::set_audience(claims, "api-1"), "set_audience");
        sub.assert_true(auth::add_audience(claims, "api-2"), "add_audience");
        sub.assert_false(auth::set_audience(claims, ""), "empty audience rejected");
        sub.assert_true(auth::set_claim(claims, "role", "admin"), "set custom str");
        sub.assert_true(auth::set_claim(claims, "role", "super"), "replace custom str");
        sub.assert_true(auth::set_claim_int(claims, "lvl", 7), "set custom int");
        sub.assert_true(auth::set_claim_int(claims, "lvl", 9), "replace custom int");
        sub.assert_true(auth::set_claim_bool(claims, "mfa", true), "set custom bool");
        sub.assert_true(auth::set_claim_bool(claims, "mfa", false), "replace custom bool");
        sub.assert_false(auth::set_claim(claims, "sub", "x"), "cannot set std claim via set_claim");
        sub.assert_false(auth::set_claim_int(claims, "exp", 1), "cannot set std claim via set_claim_int");
        sub.assert_false(auth::set_claim_bool(claims, "iss", true), "cannot set std claim via set_claim_bool");

        sub.assert_bytes_eq(auth::claim_str(claims, "iss"), "https://issuer.example", "claim_str iss");
        sub.assert_bytes_eq(auth::claim_str(claims, "sub"), "user-42", "claim_str sub");
        sub.assert_bytes_eq(auth::claim_str(claims, "aud"), "api-1", "claim_str aud");
        sub.assert_bytes_eq(auth::claim_str(claims, "jti"), "jti-1", "claim_str jti");
        sub.assert_bytes_eq(auth::claim_str(claims, "role"), "super", "claim_str custom");
        sub.assert_bytes_eq(auth::claim_str(claims, "missing"), "", "claim_str missing");
        let lvl_v, ok_lvl = auth::claim_int(claims, "lvl");
        sub.assert_true(ok_lvl && lvl_v == 9, "claim_int matched");
        let _, bad_lvl = auth::claim_int(claims, "role");
        sub.assert_false(bad_lvl, "claim_int wrong type false");
        let mfa_v, ok_mfa = auth::claim_bool(claims, "mfa");
        sub.assert_true(ok_mfa && !mfa_v, "claim_bool matched");
        let _, bad_mfa = auth::claim_bool(claims, "lvl");
        sub.assert_false(bad_mfa, "claim_bool wrong type false");

        var clm_json: u8[..1024] = [];
        sub.assert_true(auth::serialize_jwt_claims(claims, clm_json), "serialize claims");
        var parsed_clm = auth::JwtClaims { .. };
        sub.assert_true(auth::parse_jwt_claims_json(clm_json[..], parsed_clm), "roundtrip parse claims");
        sub.assert_false(auth::parse_jwt_claims_json("{\"a\\b\":1}", parsed_clm), "escaped key rejected");
        sub.assert_false(auth::parse_jwt_claims_json("[]", parsed_clm), "non-object claims rejected");

        let hmac_key = "0123456789abcdef0123456789abcdef";
        var tok_hs256: u8[..2048] = [];
        let std_hdr = auth::new_jwt_header(auth::JwtAlg.HS256, "k1");
        sub.assert_true(auth::sign_jwt_hmac(std_hdr, claims, hmac_key, tok_hs256), "sign HS256");

        var opts = auth::default_jwt_validation_options(auth::JwtAlg.HS256);
        let _ = opts.expected_issuer.try_set("https://issuer.example");
        let _ = opts.expected_audience.try_set("api-2");
        let _ = opts.expected_subject.try_set("user-42");
        let _ = opts.expected_typ.try_set("JWT");
        opts.require_nbf = true;
        opts.min_remaining_ttl_seconds = 100;

        var out_hdr = auth::JwtHeader { .. };
        var out_clm = auth::JwtClaims { .. };
        sub.assert_true(auth::verify_jwt_hmac(tok_hs256[..], hmac_key, opts, 1500, out_hdr, out_clm) == auth::JwtError.None, "verify_jwt_hmac ok");

        // Remaining TTL guard and identity mismatches
        sub.assert_true(auth::verify_jwt_hmac(tok_hs256[..], hmac_key, opts, 1950, out_hdr, out_clm) == auth::JwtError.TokenExpired, "min_remaining_ttl triggers TokenExpired");
        opts.min_remaining_ttl_seconds = 0;
        sub.assert_true(auth::verify_jwt_hmac(tok_hs256[..], hmac_key, opts, 900, out_hdr, out_clm) == auth::JwtError.TokenNotYetValid, "nbf check");

        var bad_opts = opts;
        let _ = bad_opts.expected_issuer.try_set("https://wrong");
        sub.assert_true(auth::verify_jwt_hmac(tok_hs256[..], hmac_key, bad_opts, 1500, out_hdr, out_clm) == auth::JwtError.IssuerMismatch, "IssuerMismatch");
        bad_opts = opts;
        let _ = bad_opts.expected_subject.try_set("other");
        sub.assert_true(auth::verify_jwt_hmac(tok_hs256[..], hmac_key, bad_opts, 1500, out_hdr, out_clm) == auth::JwtError.SubjectMismatch, "SubjectMismatch");
        bad_opts = opts;
        bad_opts.expected_audience.clear();
        sub.assert_true(auth::verify_jwt_hmac(tok_hs256[..], hmac_key, bad_opts, 1500, out_hdr, out_clm) == auth::JwtError.AudienceMismatch, "AudienceMismatch when unconfigured");

        // Header-only & unverified parsing including b64:false error
        sub.assert_true(auth::parse_jwt_header_only(tok_hs256[..], out_hdr) == auth::JwtError.None, "header only");
        sub.assert_true(auth::parse_jwt_unverified(tok_hs256[..], out_hdr, out_clm) == auth::JwtError.None, "unverified");
        sub.assert_true(auth::parse_jwt_header_only("bad", out_hdr) == auth::JwtError.MalformedToken, "bad token");
        var bad_unenc: u8[..256] = [];
        make_b64url_jws_raw("{\"alg\":\"HS256\",\"crit\":[\"b64\"],\"b64\":false}", "{\"sub\":\"1\"}", hmac_key, bad_unenc);
        sub.assert_true(auth::parse_jwt_unverified(bad_unenc[..], out_hdr, out_clm) == auth::JwtError.CriticalHeaderUnsupported, "unverified rejects b64:false");

        // RFC 7797 unencoded HS256 positive & negative (single unencoded payload without '.')
        var unenc_prefix: u8[..256] = [];
        core::base64url_encode("{\"alg\":\"HS256\",\"crit\":[\"b64\"],\"b64\":false}", unenc_prefix);
        unenc_prefix.append(".raw-payload");
        var unenc_hmac = core::hmac_sha256(hmac_key, unenc_prefix[..]);
        var unenc_tok: u8[..512] = [];
        unenc_tok.append(unenc_prefix[..]);
        unenc_tok.push('.');
        core::base64url_encode(unenc_hmac[..], unenc_tok);
        sub.assert_true(auth::verify_jws_unencoded_hs256(unenc_tok[..], hmac_key), "RFC 7797 unencoded JWS verifies");
        sub.assert_false(auth::verify_jws_unencoded_hs256(unenc_tok[..], "short"), "RFC 7797 rejects short key");
        unenc_tok[unenc_tok.len - 1] = if unenc_tok[unenc_tok.len - 1] == 'A' { 'B' } else { 'A' };
        sub.assert_false(auth::verify_jws_unencoded_hs256(unenc_tok[..], hmac_key), "RFC 7797 rejects tampered sig");
    };

    t.run("EdDSA & ES256 JWT + JWKS management and verify_jwt") { sub =>
        let ed_seed: u8[32] = [0x11; 32];
        let ed_pub = core::ed25519_public_key(ed_seed);
        let ec_priv: u8[32] = [0x22; 32];
        let ec_pub = core::ecdsa_p256_public_key(ec_priv);

        var jwks = auth::Jwks { .. };
        sub.assert_true(auth::add_ed25519_key(jwks, "ed-1", ed_pub), "add ed25519");
        sub.assert_true(auth::add_es256_key(jwks, "ec-1", ec_pub[1..33], ec_pub[33..65]), "add es256");
        let hmac64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        sub.assert_true(auth::add_symmetric_key(jwks, "hs-1", auth::JwtAlg.HS256, hmac64), "add symmetric");
        let idx_f, ok_f = auth::find_key(jwks, "ec-1");
        sub.assert_true(ok_f && idx_f == 1, "find_key ec-1");

        // Canonical JWK & thumbprint & compatibility
        var canon: u8[..512] = [];
        var thumb: u8[..64]  = [];
        sub.assert_true(auth::compute_canonical_jwk(jwks.keys[0], canon), "canonical OKP JWK");
        sub.assert_true(auth::compute_jwk_thumbprint(jwks.keys[0], thumb) && thumb.len == 43, "thumbprint OKP 43 chars");
        sub.assert_true(auth::compute_canonical_jwk(jwks.keys[1], canon), "canonical EC JWK");
        sub.assert_true(auth::compute_jwk_thumbprint(jwks.keys[1], thumb) && thumb.len == 43, "thumbprint EC 43 chars");
        sub.assert_true(auth::validate_jwks_key_compatibility(jwks.keys[0], auth::JwtAlg.EdDSA) == auth::JwtError.None, "compat OKP/EdDSA");
        sub.assert_true(auth::validate_jwks_key_compatibility(jwks.keys[0], auth::JwtAlg.HS256) == auth::JwtError.AlgorithmMismatch, "alg confusion rejected");

        var jwks_json: u8[..2048] = [];
        sub.assert_true(auth::serialize_jwks(jwks, jwks_json), "serialize jwks");
        var parsed_jwks = auth::Jwks { .. };
        sub.assert_true(auth::parse_jwks_json(jwks_json[..], parsed_jwks), "parse_jwks_json");
        sub.assert_true(parsed_jwks.keys.len == 3, "parsed 3 keys");
        var bad_jwks = auth::Jwks { .. };
        sub.assert_false(auth::parse_jwks_json("{\"keys\":[]}", bad_jwks), "empty keys rejected");
        sub.assert_false(auth::parse_jwks_json("{\"keys\":[{\"kty\":\"oct\",\"k\":\"YWI\"}],\"keys\":[]}", bad_jwks), "duplicate keys rejected");
        sub.assert_false(auth::parse_jwks_json("{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"alg\":\"none\",\"x\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}]}", bad_jwks), "alg=none in JWKS rejected");
        sub.assert_false(auth::parse_jwks_json("{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"d\":\"secret\"}]}", bad_jwks), "private key d in JWKS rejected");
        sub.assert_false(auth::parse_jwks_json("{\"keys\":[{\"kty\":\"oct\",\"use\":\"enc\",\"key_ops\":[\"verify\"],\"k\":\"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY\"}]}", bad_jwks), "conflicting use/key_ops rejected");
        sub.assert_false(auth::parse_jwks_json("{\"keys\":[{\"kty\":\"oct\",\"key_ops\":[\"bogus\"],\"k\":\"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY\"}]}", bad_jwks), "unknown key_ops rejected");

        let claims = auth::JwtClaims { exp: 5000, sub: "alice", .. };
        let ed_hdr = auth::new_jwt_header(auth::JwtAlg.EdDSA, "ed-1");
        let ec_hdr = auth::new_jwt_header(auth::JwtAlg.ES256, "ec-1");
        var ed_tok: u8[..1024] = [];
        var ec_tok: u8[..1024] = [];
        sub.assert_true(auth::sign_jwt_eddsa(ed_hdr, claims, ed_seed, ed_tok), "sign EdDSA");
        sub.assert_true(auth::sign_jwt_es256(ec_hdr, claims, ec_priv, ec_tok), "sign ES256");

        var out_hdr = auth::JwtHeader { .. };
        var out_clm = auth::JwtClaims { .. };
        let opts_ed = auth::default_jwt_validation_options(auth::JwtAlg.EdDSA);
        let opts_ec = auth::default_jwt_validation_options(auth::JwtAlg.ES256);
        sub.assert_true(auth::verify_jwt(parsed_jwks, ed_tok[..], opts_ed, 1000, out_hdr, out_clm) == auth::JwtError.None, "verify_jwt EdDSA");
        sub.assert_true(auth::verify_jwt(parsed_jwks, ec_tok[..], opts_ec, 1000, out_hdr, out_clm) == auth::JwtError.None, "verify_jwt ES256");

        // HS384 and HS512 sign + verify
        var tok_hs384: u8[..1024] = [];
        var tok_hs512: u8[..1024] = [];
        let hdr384 = auth::new_jwt_header(auth::JwtAlg.HS384, "h384");
        let hdr512 = auth::new_jwt_header(auth::JwtAlg.HS512, "h512");
        sub.assert_true(auth::sign_jwt_hmac(hdr384, claims, hmac64, tok_hs384), "sign HS384");
        sub.assert_true(auth::sign_jwt_hmac(hdr512, claims, hmac64, tok_hs512), "sign HS512");
        let opts384 = auth::default_jwt_validation_options(auth::JwtAlg.HS384);
        let opts512 = auth::default_jwt_validation_options(auth::JwtAlg.HS512);
        sub.assert_true(auth::verify_jwt_hmac(tok_hs384[..], hmac64, opts384, 1000, out_hdr, out_clm) == auth::JwtError.None, "verify HS384");
        sub.assert_true(auth::verify_jwt_hmac(tok_hs512[..], hmac64, opts512, 1000, out_hdr, out_clm) == auth::JwtError.None, "verify HS512");

        // add_rsa_key check (valid shape with high bit set, e=65537)
        var rsa_n: u8[256] = [0; 256];
        rsa_n[0] = 0x80;
        rsa_n[255] = 0x01;
        let rsa_e: u8[3] = [0x01, 0x00, 0x01];
        sub.assert_true(auth::add_rsa_key(jwks, "rsa-1", auth::JwtAlg.RS256, rsa_n[..], rsa_e[..]), "add_rsa_key RS256");
        sub.assert_false(auth::add_rsa_key(jwks, "rsa-bad", auth::JwtAlg.ES256, rsa_n[..], rsa_e[..]), "add_rsa_key rejects ES256");
        sub.assert_true(auth::verify_jwt(parsed_jwks, ed_tok[..], opts_ec, 1000, out_hdr, out_clm) == auth::JwtError.AlgorithmMismatch, "alg mismatch rejected");

        // Tamper EC signature & check invalid base64 / KeyNotFound
        var bad_ec = copy(ec_tok);
        bad_ec[bad_ec.len - 2] = if bad_ec[bad_ec.len - 2] == 'A' { 'B' } else { 'A' };
        sub.assert_true(auth::verify_jwt_es256(bad_ec[..], ec_pub[..], opts_ec, 1000, out_hdr, out_clm) == auth::JwtError.SignatureInvalid, "tampered ES256 rejected");
        let missing_kid_hdr = auth::new_jwt_header(auth::JwtAlg.EdDSA, "no-such-kid");
        var miss_tok: u8[..1024] = [];
        sub.assert_true(auth::sign_jwt_eddsa(missing_kid_hdr, claims, ed_seed, miss_tok), "sign unknown kid");
        sub.assert_true(auth::verify_jwt(parsed_jwks, miss_tok[..], opts_ed, 1000, out_hdr, out_clm) == auth::JwtError.KeyNotFound, "unknown kid rejected");

        sub.assert_true(auth::is_safe_remote_jwks_url("https://auth.example.com/.well-known/jwks.json"), "safe https jwks url");
        sub.assert_false(auth::is_safe_remote_jwks_url("http://auth.example.com/jwks.json"), "http jwks url blocked");
        sub.assert_false(auth::is_safe_remote_jwks_url("https://127.0.0.1/jwks.json"), "loopback SSRF blocked");
        sub.assert_false(auth::is_safe_remote_jwks_url("https://user:pass@auth.example.com/jwks.json"), "credentials blocked");

        auth::zeroize_jwks(parsed_jwks);
        sub.assert_true(parsed_jwks.keys.len == 0, "zeroize_jwks cleared");
    };
}

fn test_jwe_introspection_and_device(t: lit::T&) {
    t.run("JWE dir A256GCM seal/open + Concat KDF") { sub =>
        let z: u8[32] = [0x33; 32];
        let derived, ok_kdf = auth::concat_kdf_sha256(z, "A256GCM", "alice", "bob", 256);
        sub.assert_true(ok_kdf, "concat_kdf_sha256 256-bit");
        let _, bad_bits = auth::concat_kdf_sha256(z, "A256GCM", "alice", "bob", 128);
        sub.assert_false(bad_bits, "concat_kdf rejects unsupported key_bits");

        let iv: u8[12] = [0x04; 12];
        let prot_b64 = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0";
        var tok: u8[..512] = [];
        sub.assert_true(auth::jwe_seal_dir_a256gcm(prot_b64, derived, iv, "top-secret-payload", tok), "jwe seal");
        var opened: u8[..256] = [];
        sub.assert_true(auth::jwe_open_dir_a256gcm(tok[..], derived, opened), "jwe open");
        sub.assert_bytes_eq(opened[..], "top-secret-payload", "jwe roundtrip");

        // Random IV seal + negative tamper
        var tok2: u8[..512] = [];
        sub.assert_true(auth::jwe_seal_dir_a256gcm_random_iv(prot_b64, derived, "hello", tok2), "jwe random iv seal");
        sub.assert_true(auth::jwe_open_dir_a256gcm(tok2[..], derived, opened), "jwe random iv open");
        sub.assert_bytes_eq(opened[..], "hello", "jwe random iv plaintext");
        tok2[tok2.len - 1] = if tok2[tok2.len - 1] == 'A' { 'B' } else { 'A' };
        sub.assert_false(auth::jwe_open_dir_a256gcm(tok2[..], derived, opened), "tampered JWE tag rejected");
        sub.assert_true(opened.len == 0, "opened wiped on error");
        sub.assert_false(auth::jwe_open_dir_a256gcm("not.a.jwe", derived, opened), "malformed JWE rejected");
    };

    t.run("OAuth2 Introspection & Device Grant RFC 7662 / 7617 / 8628") { sub =>
        var form: u8[..256] = [];
        sub.assert_true(auth::encode_token_endpoint_form("tok+1/2=3", auth::TokenTypeHint.AccessToken, form), "encode access_token form");
        sub.assert_true(core::contains(form[..], "token_type_hint=access_token"), "hint=access_token");
        sub.assert_true(auth::encode_token_endpoint_form("ref1", auth::TokenTypeHint.RefreshToken, form), "encode refresh_token form");
        sub.assert_true(auth::encode_token_endpoint_form("t2", auth::TokenTypeHint.None, form), "encode hint None");
        sub.assert_false(auth::encode_token_endpoint_form("", auth::TokenTypeHint.None, form), "empty token rejected");

        let active_json = "{\"active\":true,\"scope\":\"read write\",\"client_id\":\"c1\",\"sub\":\"s1\",\"aud\":[\"a1\",\"a2\"],\"exp\":2000000000,\"iat\":1700000000,\"nbf\":1700000000}";
        let resp_a, ok_a = auth::parse_introspection_response(active_json);
        sub.assert_true(ok_a && resp_a.active && resp_a.aud.len == 2, "active introspection parsed");
        let inactive_json = "{\"active\":false,\"scope\":\"secret\",\"sub\":\"alice\",\"exp\":999}";
        let resp_i, ok_i = auth::parse_introspection_response(inactive_json);
        sub.assert_true(ok_i && !resp_i.active && resp_i.sub.len == 0 && resp_i.scope.len == 0 && resp_i.exp == -1, "inactive introspection scrubbed all fields");
        let _, bad_intro = auth::parse_introspection_response("{\"scope\":\"read\"}");
        sub.assert_false(bad_intro, "missing active rejected");

        var auth_hdr: u8[..256] = [];
        sub.assert_true(auth::encode_oauth2_basic_auth("id+1", "p@ss:word", auth_hdr), "encode basic auth");
        var out_id:  u8[..128] = [];
        var out_sec: u8[..128] = [];
        sub.assert_true(auth::decode_oauth2_basic_auth(auth_hdr[..], out_id, out_sec), "decode basic auth");
        sub.assert_bytes_eq(out_id[..], "id+1", "client_id decoded");
        sub.assert_bytes_eq(out_sec[..], "p@ss:word", "client_secret decoded");
        sub.assert_false(auth::decode_oauth2_basic_auth("Bearer abc", out_id, out_sec), "non-Basic rejected");

        let dev_json = "{\"device_code\":\"dc1\",\"user_code\":\"ABCD-EFGH\",\"verification_uri\":\"https://ex.com/dev\",\"verification_uri_complete\":\"https://ex.com/dev?c=ABCD\",\"expires_in\":1800,\"interval\":5}";
        let dev, ok_dev = auth::parse_device_auth_response(dev_json);
        sub.assert_true(ok_dev && dev.expires_in_sec == 1800 && dev.interval_sec == 5, "device auth parsed");
        let _, bad_dev_uri = auth::parse_device_auth_response("{\"device_code\":\"dc\",\"user_code\":\"uc\",\"verification_uri\":\"http://insecure.example/dev\",\"expires_in\":600}");
        sub.assert_false(bad_dev_uri, "http verification_uri blocked per RFC 8628");

        let next_pend, cont_p = auth::step_device_poll_interval(auth::DevicePollStatus.AuthorizationPending, 5, 60);
        sub.assert_true(cont_p && next_pend == 5, "pending preserves interval");
        let next_slow, cont_s = auth::step_device_poll_interval(auth::DevicePollStatus.SlowDown, 5, 60);
        sub.assert_true(cont_s && next_slow == 10, "slow_down adds 5s");
        let _, stop_d = auth::step_device_poll_interval(auth::DevicePollStatus.AccessDenied, 5, 60);
        sub.assert_false(stop_d, "access_denied stops polling");
    };
}

fn test_dpop_and_acme(t: lit::T&) {
    t.run("DPoP EdDSA & ES256 proofs, replay cache, headers, and attack paths") { sub =>
        let seed: u8[32] = [0x55; 32];
        let pub_ed = core::ed25519_public_key(seed);
        let ec_priv: u8[32] = [0x66; 32];
        let ec_pub = core::ecdsa_p256_public_key(ec_priv);

        var proof_ed: u8[..2048] = [];
        var proof_ec: u8[..2048] = [];
        sub.assert_true(auth::create_dpop_proof(seed[..], "POST", "https://api.example.com:443/token?x=1#f", "tok123", "srv-nonce", 1000, "jti-ed-1", proof_ed), "create DPoP EdDSA");
        sub.assert_true(auth::create_dpop_proof_es256(ec_priv, "GET", "https://api.example.com/res", "", "", 1000, "jti-ec-1", proof_ec), "create DPoP ES256");

        sub.assert_true(auth::verify_dpop_proof(proof_ed[..], pub_ed[..], "POST", "https://api.example.com/token", "tok123", "srv-nonce", 1010), "verify DPoP EdDSA");
        sub.assert_true(auth::verify_dpop_proof(proof_ec[..], ec_pub[..], "GET", "https://api.example.com/res", "", "", 1010, 300, 60, "", "ES256"), "verify DPoP ES256");

        // Replay cache test
        var cache = auth::DPoPReplayCache { .. };
        sub.assert_true(auth::verify_dpop_proof_with_replay_cache(cache, proof_ed[..], pub_ed[..], "POST", "https://api.example.com/token", 1010, "tok123", "srv-nonce"), "first DPoP accepted");
        sub.assert_false(auth::verify_dpop_proof_with_replay_cache(cache, proof_ed[..], pub_ed[..], "POST", "https://api.example.com/token", 1015, "tok123", "srv-nonce"), "replayed DPoP rejected");

        // Header attachment + nonce extraction
        var hdrs = http::HeaderMap { .. };
        auth::attach_dpop(hdrs, proof_ed[..], "tok123");
        http::set_header(hdrs, "DPoP-Nonce", "next_nonce_789");
        var nonce_out: u8[..64] = [];
        sub.assert_true(auth::extract_dpop_nonce(hdrs, nonce_out), "extract_dpop_nonce");
        sub.assert_bytes_eq(nonce_out[..], "next_nonce_789", "nonce value");

        // Attack: embedded private key parameter 'd' in DPoP JWK must be rejected
        var x_b64: u8[..64] = [];
        core::base64url_encode(pub_ed[..], x_b64);
        var bad_hdr_priv: u8[..256] = [];
        bad_hdr_priv.append("{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"");
        bad_hdr_priv.append(x_b64[..]);
        bad_hdr_priv.append("\",\"d\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}}");
        let clm_ok = "{\"jti\":\"j1\",\"htm\":\"POST\",\"htu\":\"https://api.example.com/token\",\"iat\":1000}";
        var evil_proof: u8[..1024] = [];
        sign_raw_dpop_ed25519(seed, bad_hdr_priv[..], clm_ok, evil_proof);
        sub.assert_false(auth::verify_dpop_proof(evil_proof[..], pub_ed[..], "POST", "https://api.example.com/token", "", "", 1000), "DPoP JWK containing private key rejected");

        // Claims & header validators
        sub.assert_false(auth::verify_dpop_header("{\"typ\":\"jwt\",\"alg\":\"EdDSA\"}"), "wrong typ rejected");
        sub.assert_false(auth::verify_dpop_header("{\"typ\":\"dpop+jwt\",\"alg\":\"HS256\",\"jwk\":{\"kty\":\"oct\",\"k\":\"AA\"}}", ""), "symmetric alg rejected");
        sub.assert_true(auth::verify_dpop_jti(clm_ok), "verify_dpop_jti");
        sub.assert_true(auth::verify_dpop_method(clm_ok, "POST"), "verify_dpop_method");
        sub.assert_false(auth::verify_dpop_method(clm_ok, "post"), "method is case sensitive");
        sub.assert_true(auth::verify_dpop_uri(clm_ok, "https://API.EXAMPLE.COM:443/token"), "verify_dpop_uri");
        sub.assert_false(auth::verify_dpop_uri("{\"jti\":\"j1\",\"htm\":\"GET\",\"htu\":\"https://ex.com/?q=1\",\"iat\":1000}", "https://ex.com/"), "query in htu rejected");
        sub.assert_true(auth::verify_dpop_iat(clm_ok, 1050, 300, 60), "verify_dpop_iat");

        var canonical_jwk: u8[..256] = [];
        canonical_jwk.append("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"");
        canonical_jwk.append(x_b64[..]);
        canonical_jwk.append("\"}");
        let jkt_hash = core::sha256(canonical_jwk[..]);
        var jkt_b64: u8[..64] = [];
        core::base64url_encode(jkt_hash[..], jkt_b64);
        sub.assert_true(auth::matches_dpop_jkt_thumbprint(pub_ed, jkt_b64[..], jkt_b64[..]), "jkt thumbprint matches");

        // DPoP claims, jkt, URI normalization, and JTI entropy branches
        let clm_with_jkt = "{\"jti\":\"j1\",\"htm\":\"POST\",\"htu\":\"https://api.example.com/token\",\"iat\":1000,\"jkt\":\"abc\"}";
        sub.assert_true(auth::verify_dpop_jkt(clm_with_jkt, "abc"), "verify_dpop_jkt match");
        sub.assert_false(auth::verify_dpop_jkt(clm_with_jkt, "xyz"), "verify_dpop_jkt mismatch");

        var parsed_dpop = auth::DPoPClaims { .. };
        sub.assert_true(auth::parse_dpop_claims("{\"jti\":\"j1\",\"htm\":\"POST\",\"htu\":\"https://api.example.com/token\",\"iat\":1000,\"nonce\":\"n1\"}", parsed_dpop), "parse_dpop_claims");
        sub.assert_false(auth::verify_dpop_claims(parsed_dpop, "POST", "https://api.example.com/token", "missing_tok", "n1", 1010), "verify_dpop_claims missing ath fails");
        sub.assert_false(auth::verify_dpop_claims(parsed_dpop, "POST", "https://api.example.com/token", "", "wrong_nonce", 1010), "verify_dpop_claims wrong nonce fails");
        sub.assert_false(auth::verify_dpop_claims(parsed_dpop, "POST", "https://api.example.com/token", "", "n1", 2000, 300, 60), "verify_dpop_claims expired iat fails");
        sub.assert_false(auth::verify_dpop_claims(parsed_dpop, "POST", "https://api.example.com/token", "", "n1", 500, 300, 60), "verify_dpop_claims future iat fails");

        var uri_norm: u8[..256] = [];
        sub.assert_false(auth::normalize_dpop_target_uri("https://ex.com/\"bad", uri_norm), "quote in target uri rejected");
        sub.assert_false(auth::normalize_dpop_target_uri("https://ex.com/\\bad", uri_norm), "backslash in target uri rejected");
        var jti_buf: u8[..128] = [];
        sub.assert_false(auth::generate_dpop_jti(jti_buf, "short"), "short entropy rejected");
        sub.assert_true(auth::generate_dpop_jti(jti_buf, "0123456789abcdef") && jti_buf.len > 0, "16B entropy JTI");
        sub.assert_true(auth::generate_dpop_jti(jti_buf) && jti_buf.len == 22, "auto CSPRNG JTI 22 chars");
    };

    t.run("ACME v2 Directory, Order, Authz HTTP-01 & Flattened JWS") { sub =>
        let priv_key: u8[32] = [0x77; 32];
        var thumb: u8[..64] = [];
        sub.assert_true(auth::acme_jwk_thumbprint_p256(priv_key, thumb), "acme thumbprint");
        sub.assert_true(thumb.len == 43, "43-char thumbprint");

        var jws: u8[>..] = [];
        sub.assert_true(auth::acme_sign_jws_es256(priv_key, "https://acme.example/new-order", "nonce-1", "", "{\"identifiers\":[]}", jws), "acme_sign_jws_es256 with jwk");
        sub.assert_true(auth::acme_sign_jws_es256(priv_key, "https://acme.example/order/1", "nonce-2", "https://acme.example/acct/1", "", jws), "acme POST-as-GET with kid");

        var dir = auth::AcmeDirectory { .. };
        let dir_json = "{\"newNonce\":\"https://acme.example/n\",\"newAccount\":\"https://acme.example/a\",\"newOrder\":\"https://acme.example/o\",\"meta\":{\"terms\":\"x\"}}";
        sub.assert_true(auth::acme_parse_directory(dir_json, dir), "acme_parse_directory");
        sub.assert_bytes_eq(dir.new_order[..], "https://acme.example/o", "newOrder matched");
        sub.assert_false(auth::acme_parse_directory("{\"newNonce\":\"ftp://bad\"}", dir), "bad scheme directory rejected");

        var ord = auth::AcmeOrder { .. };
        let ord_json = "{\"status\":\"valid\",\"authorizations\":[\"https://acme.example/az/1\"],\"finalize\":\"https://acme.example/fin\",\"certificate\":\"https://acme.example/cert\"}";
        sub.assert_true(auth::acme_parse_order(ord_json, ord), "acme_parse_order");
        sub.assert_true(ord.status == auth::AcmeOrderStatus.Valid && ord.authz_urls.len == 1, "order valid");

        var ch = auth::AcmeHttp01Challenge { .. };
        let authz_json = "{\"status\":\"pending\",\"challenges\":[{\"type\":\"dns-01\",\"url\":\"https://acme.example/d\",\"status\":\"pending\",\"token\":\"aaaaaaaaaaaaaaaaaaaaaaaa\"},{\"type\":\"http-01\",\"url\":\"https://acme.example/h\",\"status\":\"pending\",\"token\":\"EvaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA\"}]}";
        sub.assert_true(auth::acme_parse_authz_http01(authz_json, thumb[..], ch), "acme_parse_authz_http01 skips sibling dns-01");
        sub.assert_true(ch.authz_status == auth::AcmeAuthzStatus.Pending && ch.status == auth::AcmeOrderStatus.Pending, "authz pending");
        sub.assert_false(auth::acme_parse_authz_http01("{\"status\":\"bogus\",\"challenges\":[]}", thumb[..], ch), "unknown authz status fails");
    };
}

fn main() {
    let runner = lit::new_runner("Auth Deep Verification Suite");
    lit::run_case(runner, "1. JWT Core, Signatures & JWKS", test_jwt_core_and_verify);
    lit::run_case(runner, "2. JWE, Introspection & Device Grant", test_jwe_introspection_and_device);
    lit::run_case(runner, "3. DPoP & ACME v2", test_dpop_and_acme);
    assert(lit::finish(runner));
}
