// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 7520 (JOSE Cookbook), RFC 7797 (JWS Unencoded Payload), and RFC 8037 (EdDSA JWS)
// known-answer vector verification.
//
// RUN: goose %s | %FileCheck %s

import wing from "../..";

fn decode_b64u_fixed(src: const u8[:], dst: u8[>..]&) -> bool {
    dst.clear();
    return core::base64url_decode(src, dst);
}

fn verify_rfc7520_rsa_and_pss() {
    var b64_n: u8[>..] = [];
    b64_n.append("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRoj");
    b64_n.append("dNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2l");
    b64_n.append("bzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6c");
    b64_n.append("S6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3");
    b64_n.append("-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwU");
    b64_n.append("kRz5iaiQkqgc5gHdrNP5zw");

    var n_bytes: u8[>..] = [];
    var e_bytes: u8[>..] = [];
    assert(decode_b64u_fixed(b64_n[..], n_bytes));
    assert(decode_b64u_fixed("AQAB", e_bytes));

    // Section 4.1: RS256 over protected_b64u || "." || payload_b64u
    var rs_input: u8[>..] = [];
    rs_input.append("eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhh");
    rs_input.append("bXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcg");
    rs_input.append("b3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlv");
    rs_input.append("dSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hl");
    rs_input.append("cmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4");

    var rs_sig_b64: u8[>..] = [];
    rs_sig_b64.append("MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZo");
    rs_sig_b64.append("pdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmD");
    rs_sig_b64.append("LJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9e");
    rs_sig_b64.append("Ro4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2");
    rs_sig_b64.append("aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH8");
    rs_sig_b64.append("4ogoree7vjbU5y18kDquDg");

    var rs_sig: u8[>..] = [];
    assert(decode_b64u_fixed(rs_sig_b64[..], rs_sig));
    assert(
        auth::verify_jwt_rsa_signature(
            auth::JwtAlg.RS256,
            n_bytes[..],
            e_bytes[..],
            rs_input[..],
            rs_sig[..],
        ),
    );
    rs_sig[0] ^= 0x01;
    assert(
        !auth::verify_jwt_rsa_signature(
            auth::JwtAlg.RS256,
            n_bytes[..],
            e_bytes[..],
            rs_input[..],
            rs_sig[..],
        ),
    );

    // Section 4.2: PS384 RSA-PSS signature
    var ps_input: u8[>..] = [];
    ps_input.append("eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhh");
    ps_input.append("bXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcg");
    ps_input.append("b3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlv");
    ps_input.append("dSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hl");
    ps_input.append("cmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4");

    var ps_sig_b64: u8[>..] = [];
    ps_sig_b64.append("cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2IpN");
    ps_sig_b64.append("6-tPid6VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXUvdvW");
    ps_sig_b64.append("Xzg-UD8biiReQFlfz28zGWVsdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRXe8P_ij");
    ps_sig_b64.append("Q7p8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2Xez2Mlp8cBE5awDzT0qI0n6ui");
    ps_sig_b64.append("P1aCN_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a6GYmJUAfmW");
    ps_sig_b64.append("jwZ6oD4ifKo8DYM-X72Eaw");

    var ps_sig: u8[>..] = [];
    assert(decode_b64u_fixed(ps_sig_b64[..], ps_sig));
    assert(core::rsa_pss_sha384_verify(n_bytes[..], e_bytes[..], ps_input[..], ps_sig[..]));
    ps_sig[0] ^= 0x01;
    assert(!core::rsa_pss_sha384_verify(n_bytes[..], e_bytes[..], ps_input[..], ps_sig[..]));
    print("RFC7520_RSA_OK");
}

fn verify_hmac_unencoded_and_eddsa() {
    // RFC 7520 Section 4.4: HMAC-SHA256 JWS
    var k_hs: u8[>..] = [];
    assert(decode_b64u_fixed("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg", k_hs));
    var hs_in: u8[>..] = [];
    hs_in.append("eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVl");
    hs_in.append("ZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywg");
    hs_in.append("Z29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5k");
    hs_in.append("IGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dp");
    hs_in.append("bmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4");
    var hs_sig: u8[>..] = [];
    assert(decode_b64u_fixed("s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0", hs_sig));
    assert(
        auth::verify_jwt_hmac_signature(
            auth::JwtAlg.HS256,
            k_hs[..],
            hs_in[..],
            hs_sig[..],
        ),
    );
    hs_sig[0] ^= 0x80;
    assert(
        !auth::verify_jwt_hmac_signature(
            auth::JwtAlg.HS256,
            k_hs[..],
            hs_in[..],
            hs_sig[..],
        ),
    );

    // RFC 7797 Section 4.2: Unencoded payload JWS ("b64": false)
    var k_7797:    u8[>..] = [];
    var b64_k7797: u8[>..] = [];
    b64_k7797.append("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0i");
    b64_k7797.append("PS4hcgUuTwjAzZr1Z9CAow");
    assert(decode_b64u_fixed(b64_k7797[..], k_7797));

    // Vector omitting "crit":["b64"] passes raw HMAC but is rejected by strict RFC 7797 check
    var sig_7797_nocrit: u8[>..] = [];
    assert(decode_b64u_fixed("GsyM6AQJbQHY8aQKCbZSPJHzMRWo3HKIlcDuXof7nqs", sig_7797_nocrit));
    assert(
        auth::verify_jwt_hmac_signature(
            auth::JwtAlg.HS256,
            k_7797[..],
            "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2V9.$.02",
            sig_7797_nocrit[..],
        ),
    );
    var tok_nocrit: u8[>..] = [];
    tok_nocrit.append("eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2V9.$.02.");
    tok_nocrit.append("GsyM6AQJbQHY8aQKCbZSPJHzMRWo3HKIlcDuXof7nqs");
    assert(!auth::verify_jws_unencoded_hs256(tok_nocrit[..], k_7797[..]));

    // Compact RFC 7797 token with "crit":["b64"] must pass verify_jws_unencoded_hs256
    var tok_7797: u8[>..] = [];
    tok_7797.append("eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19.");
    tok_7797.append("This is the payload string!.");
    tok_7797.append("ciks0B6Hs-amhOqxI5_iG6mPKnMDlWCb7J2Wu7mtIcg");
    assert(auth::verify_jws_unencoded_hs256(tok_7797[..], k_7797[..]));
    tok_7797[tok_7797.len - 1] = 'A';
    assert(!auth::verify_jws_unencoded_hs256(tok_7797[..], k_7797[..]));

    // RFC 8037 Appendix A.4: Ed25519 JWS
    var ed_pk_vec: u8[>..] = [];
    assert(decode_b64u_fixed("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", ed_pk_vec));
    assert(ed_pk_vec.len == 32);
    var ed_pk: u8[32] = [0; 32];
    for i in 32 {
        ed_pk[i] = ed_pk_vec[i];
    }
    var ed_sig_b64: u8[>..] = [];
    ed_sig_b64.append("hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5B");
    ed_sig_b64.append("hVsPt9g7sVvpAr_MuM0KAg");
    var ed_sig: u8[>..] = [];
    assert(decode_b64u_fixed(ed_sig_b64[..], ed_sig));
    let ed_input = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
    assert(auth::verify_jwt_eddsa_signature(ed_pk, ed_input, ed_sig[..]));
    ed_sig[0] ^= 0x01;
    assert(!auth::verify_jwt_eddsa_signature(ed_pk, ed_input, ed_sig[..]));
    print("RFC7797_EDDSA_OK");
}

fn verify_rfc7520_jwe_dir_gcm() {
    // RFC 7520 Section 5.6: Direct Encryption using AES-128-GCM
    var k_vec:   u8[>..] = [];
    var iv_vec:  u8[>..] = [];
    var tag_vec: u8[>..] = [];
    assert(decode_b64u_fixed("XctOhJAkA-pD9Lh7ZgW_2A", k_vec));
    assert(decode_b64u_fixed("refa467QzzKx6QAB", iv_vec));
    assert(decode_b64u_fixed("vbb32Xvllea2OtmHAdccRQ", tag_vec));
    assert(k_vec.len == 16 && iv_vec.len == 12 && tag_vec.len == 16);

    var key16: u8[16] = [0; 16];
    var iv12:  u8[12] = [0; 12];
    var tag16: u8[16] = [0; 16];
    for i in 16 { key16[i] = k_vec[i]; }
    for i in 12 { iv12[i] = iv_vec[i]; }
    for i in 16 { tag16[i] = tag_vec[i]; }

    var aad: u8[>..] = [];
    aad.append("eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MTdi");
    aad.append("NWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0");

    var ct_b64: u8[>..] = [];
    ct_b64.append("JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7YhL");
    ct_b64.append("pT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zMDB2n");
    ct_b64.append("0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_BIwCPT");
    ct_b64.append("jb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5g-NJsUPb");
    ct_b64.append("jk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSInZI-wjsY0yu");
    ct_b64.append("3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp");
    var ct: u8[>..] = [];
    assert(decode_b64u_fixed(ct_b64[..], ct));

    var pt: u8[512] = [0; 512];
    let pt_len, ok_open = core::aes128_gcm_open_into(
        key16,
        iv12,
        ct[..],
        aad[..],
        tag16,
        pt[..],
    );
    assert(ok_open && pt_len == ct.len);
    let pt_slice = pt[..pt_len];
    assert(core::starts_with(pt_slice, "You can trust us to stick with you"));
    assert(core::ends_with(pt_slice, "We are your friends, Frodo."));

    // Negative auth tag flip
    tag16[0] ^= 0x01;
    let _, fail_open = core::aes128_gcm_open_into(key16, iv12, ct[..], aad[..], tag16, pt[..]);
    assert(!fail_open);

    // Wing JWE dir + A256GCM roundtrip check
    let cek256:  u8[32] = [0x42; 32];
    let iv_a256: u8[12] = [0x24; 12];
    let hdr_b64 = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0";
    var sealed: u8[>..] = [];
    assert(
        auth::jwe_seal_dir_a256gcm(hdr_b64, cek256, iv_a256, pt_slice, sealed),
    );
    var opened: u8[>..] = [];
    assert(auth::jwe_open_dir_a256gcm(sealed[..], cek256, opened));
    assert(opened[..] == pt_slice);
    print("RFC7520_JWE_OK");
}

fn main() {
    // CHECK: RFC7520_RSA_OK
    verify_rfc7520_rsa_and_pss();
    // CHECK-NEXT: RFC7797_EDDSA_OK
    verify_hmac_unencoded_and_eddsa();
    // CHECK-NEXT: RFC7520_JWE_OK
    verify_rfc7520_jwe_dir_gcm();
}
