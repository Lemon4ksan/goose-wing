// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// C-callable cryptographic entry points for the ctgrind / TIMECOP taint harness.
// Build C library via:
//   goose --standalone --header .lit/cache/ctgrind/ctgrind_target.h \
//     -o .lit/cache/ctgrind/ctgrind_target.c tools/ctgrind/ctgrind_target.goose
import std;
import wing from "../..";

fn copy_12(src: const u8[:], dst: u8[12]&) -> bool {
    guard src.len == 12 else { return false; }
    for i in 12 { dst[i] = src[i]; }
    return true;
}

fn copy_16(src: const u8[:], dst: u8[16]&) -> bool {
    guard src.len == 16 else { return false; }
    for i in 16 { dst[i] = src[i]; }
    return true;
}

fn copy_32(src: const u8[:], dst: u8[32]&) -> bool {
    guard src.len == 32 else { return false; }
    for i in 32 { dst[i] = src[i]; }
    return true;
}

export fn wing_ctgrind_ct_eq_bytes(a: const u8[:], b: const u8[:]) -> u8 {
    guard a.len > 0 && a.len == b.len else { return 0; }
    return if core::ct_eq_bytes(a, b) { 1 } else { 0 };
}

export fn wing_ctgrind_aes128_block(key: const u8[:], pt: const u8[:], out: u8[:]) -> u8 {
    var k: u8[16] = [0; 16];
    var p: u8[16] = [0; 16];
    guard copy_16(key, k) && copy_16(pt, p) && out.len >= 16 else { return 0; }
    var ks = core::aes128_key_schedule(k);
    let ct = core::aes128_encrypt_block(ks, p);
    core::zeroize_aes128_ks(ks);
    for i in 16 { out[i] = ct[i]; }
    return 1;
}

export fn wing_ctgrind_aes256_block(key: const u8[:], pt: const u8[:], out: u8[:]) -> u8 {
    var k: u8[32] = [0; 32];
    var p: u8[16] = [0; 16];
    guard copy_32(key, k) && copy_16(pt, p) && out.len >= 16 else { return 0; }
    var ks = core::aes256_key_schedule(k);
    let ct = core::aes_encrypt_block(ks, p);
    core::zeroize_aes256_ks(ks);
    for i in 16 { out[i] = ct[i]; }
    return 1;
}

export fn wing_ctgrind_chacha20_poly1305(
    key: const u8[:],
    iv:  const u8[:],
    pt:  const u8[:],
    out: u8[:],
) -> u8 {
    var k: u8[32] = [0; 32];
    var n: u8[12] = [0; 12];
    let need = core::add_sat_i64(pt.len, 16);
    guard copy_32(key, k) && copy_12(iv, n) && out.len >= need else { return 0; }
    let tag, written, ok = core::chacha20_poly1305_seal(k, n, pt, "", out[..pt.len]);
    guard ok && written == pt.len else { return 0; }
    let tag_dst = out[pt.len..need];
    for i in 16 { tag_dst[i] = tag[i]; }
    return 1;
}

export fn wing_ctgrind_x25519_scalarmult(
    scalar: const u8[:],
    point:  const u8[:],
    out:    u8[:],
) -> u8 {
    var s: u8[32] = [0; 32];
    var p: u8[32] = [0; 32];
    guard copy_32(scalar, s) && copy_32(point, p) && out.len >= 32 else { return 0; }
    let res = core::x25519_scalarmult(s, p);
    for i in 32 { out[i] = res[i]; }
    return 1;
}

export fn wing_ctgrind_ecdsa_p256_sign(
    priv: const u8[:],
    msg:  const u8[:],
    out:  u8[:],
) -> u8 {
    var k: u8[32] = [0; 32];
    guard copy_32(priv, k) && out.len >= 64 else { return 0; }
    let sig = core::ecdsa_p256_sign(k, msg);
    for i in 64 { out[i] = sig[i]; }
    return 1;
}

export fn wing_ctgrind_ed25519_sign(
    seed: const u8[:],
    msg:  const u8[:],
    out:  u8[:],
) -> u8 {
    var s: u8[32] = [0; 32];
    guard copy_32(seed, s) && out.len >= 64 else { return 0; }
    let sig = core::ed25519_sign(s, msg);
    for i in 64 { out[i] = sig[i]; }
    return 1;
}

export fn wing_ctgrind_rsa_mod_exp(
    base:   const u8[:],
    exp:    const u8[:],
    mod_be: const u8[:],
    out:    u8[:],
) -> u8 {
    guard mod_be.len >= 64 && mod_be.len <= 512 && out.len >= mod_be.len else { return 0; }
    var res: u8[..512] = [];
    guard core::rsa_mod_exp(base, exp, mod_be, res) && res.len == mod_be.len else { return 0; }
    for i in res.len { out[i] = res[i]; }
    return 1;
}

export fn wing_ctgrind_mlkem768_keygen(
    d_seed: const u8[:],
    z_seed: const u8[:],
    ek_out: u8[:],
    dk_out: u8[:],
) -> u8 {
    var d: u8[32] = [0; 32];
    var z: u8[32] = [0; 32];
    guard copy_32(d_seed, d) && copy_32(z_seed, z) else { return 0; }
    guard ek_out.len >= 1184 && dk_out.len >= 2400 else { return 0; }
    let ek, dk = tls_internal::mlkem768_keygen(d, z);
    for i in 1184 { ek_out[i] = ek[i]; }
    for i in 2400 { dk_out[i] = dk[i]; }
    return 1;
}

export fn wing_ctgrind_mlkem768_encaps(
    ek_in:  const u8[:],
    m_seed: const u8[:],
    ct_out: u8[:],
    ss_out: u8[:],
) -> u8 {
    var m: u8[32] = [0; 32];
    guard ek_in.len == 1184 && copy_32(m_seed, m) else { return 0; }
    guard ct_out.len >= 1088 && ss_out.len >= 32 else { return 0; }
    var ek: u8[1184] = [0; 1184];
    for i in 1184 { ek[i] = ek_in[i]; }
    let ct, ss, ok = tls_internal::mlkem768_encapsulate(ek, m);
    guard ok else { return 0; }
    for i in 1088 { ct_out[i] = ct[i]; }
    for i in 32 { ss_out[i] = ss[i]; }
    return 1;
}

export fn wing_ctgrind_mlkem768_decapsulate(
    ct:     const u8[:],
    dk:     const u8[:],
    ss_out: u8[:],
) -> u8 {
    guard ct.len == 1088 && dk.len == 2400 && ss_out.len >= 32 else { return 0; }
    guard tls_internal::mlkem768_decapsulate(ct, dk, ss_out) else { return 0; }
    return 1;
}

fn main() {}
