// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation RSA signature verification and generation (RFC 8017).
// Supports RSASSA-PKCS1-v1_5 and RSASSA-PSS with SHA-256, SHA-384, and SHA-512 up to 4096-bit keys.
namespace core;

import std;
import core.crypto.ct;
import core.crypto.sha;

// ---- Big-Endian Multi-Precision Modular Arithmetic (up to 4096 bits) -----

// Compares two equal-length big-endian byte slices `a` and `b`.
// crap:ignore
inline fn rsa_be_cmp(a: const u8[:], b: const u8[:]) -> i32 {
    for i in a.len {
        if a[i] > b[i] { return 1; }
        if a[i] < b[i] { return -1; }
    }
    return 0;
}

// Computes `acc = (acc + addend) mod m` on equal-length big-endian slices `acc[0..k]`.
// crap:ignore
fn rsa_be_add_mod(acc: u8[:], addend: const u8[:], m: const u8[:]) {
    let k = m.len;
    var carry: u32 = 0;
    var idx:   i64 = k - 1;
    while idx >= 0 {
        let s = (acc[idx] as u32) + addend[idx] + carry;
        acc[idx] = (s & 0xFF) as u8;
        carry = s >> 8;
        idx -= 1;
    }
    if carry != 0 || rsa_be_cmp(acc, m) >= 0 {
        var borrow: i32 = 0;
        var j:      i64 = k - 1;
        while j >= 0 {
            let d = (acc[j] as i32) - m[j] - borrow;
            acc[j] = (d & 0xFF) as u8;
            borrow = if d < 0 { 1 } else { 0 };
            j -= 1;
        }
    }
}

// Computes `out = (a * b) mod m` on equal-length big-endian buffers of length `k <= 512`.
// crap:ignore
fn rsa_be_mul_mod(a: const u8[:], b: const u8[:], m: const u8[:], out: u8[..512]&) {
    let k = m.len;
    var res: u8[512] = [0; 512];
    for i in k {
        let byte_a = a[i];
        var bit: i32 = 7;
        while bit >= 0 {
            rsa_be_add_mod(res[0..k], res[0..k], m);
            if ((byte_a >> bit) & 1) == 1 {
                rsa_be_add_mod(res[0..k], b, m);
            }
            bit -= 1;
        }
    }
    out.clear();
    out.append(res[0..k]);
}

// Advances one exponent bit during left-to-right binary modular exponentiation.
// crap:ignore
fn rsa_mod_exp_step(acc: u8[..512]&, base: const u8[:], m: const u8[:], b_val: u8, started: bool&) {
    var tmp: u8[..512] = [];
    if started {
        rsa_be_mul_mod(acc[..], acc[..], m, tmp);
        acc.clear();
        acc.append(tmp[..]);
    }
    guard b_val == 1 else { return; }
    if !started {
        acc.clear();
        acc.append(base);
        started = true;
        return;
    }
    rsa_be_mul_mod(acc[..], base, m, tmp);
    acc.clear();
    acc.append(tmp[..]);
}

// Computes `out = base^exp mod m` where `m` is big-endian modulus of length `64 <= k <= 512`.
// crap:ignore
fn rsa_mod_exp(base: const u8[:], exp: const u8[:], m: const u8[:], out: u8[..512]&) -> bool {
    let k = m.len;
    guard k >= 64 && k <= 512 else { return false; }
    guard base.len == k && exp.len > 0 && exp.len <= 512 else { return false; }
    guard (m[k - 1] & 1) == 1 && (m[0] & 0x80) != 0 else { return false; }
    guard rsa_be_cmp(base, m) < 0 else { return false; }

    var acc: u8[..512] = [];
    for z in k - 1 {
        acc.push(0);
    }
    acc.push(1);

    var started = false;
    for i in exp.len {
        let eb = exp[i];
        var bit: i32 = 7;
        while bit >= 0 {
            let b_val = (eb >> bit) & 1;
            rsa_mod_exp_step(acc, base, m, b_val, started);
            bit -= 1;
        }
    }
    guard started else { return false; }
    out.clear();
    out.append(acc[..]);
    return true;
}

// Validates that an RSA public exponent `e_be` is an odd integer in `3 <= e < n` (RFC 8017 §3.1).
// crap:ignore
fn is_valid_rsa_public_exponent(e_be: const u8[:], n_be: const u8[:]) -> bool {
    guard e_be.len > 0 && n_be.len >= 64 else { return false; }
    var start: i64 = 0;
    while start < e_be.len && e_be[start] == 0 {
        start += 1;
    }
    let e_trim = e_be[start..e_be.len];
    guard e_trim.len >= 1 && e_trim.len <= n_be.len else { return false; }
    guard (e_trim[e_trim.len - 1] & 1) == 1 else { return false; }
    guard e_trim.len > 1 || e_trim[0] >= 3 else { return false; }
    if e_trim.len == n_be.len {
        guard rsa_be_cmp(e_trim, n_be) < 0 else { return false; }
    }
    return true;
}

// ---- ASN.1 DER RSAPublicKey Parser (RFC 8017 Appendix A.1.1) -------------

// Reads an ASN.1 DER tag and length at `idx`, advancing `idx` to the value payload.
// Leaves `idx` unchanged on error.
//
// Example:
//   der = [0x02, 0x81, 0x80, ...], idx = 0
//   returns: tag = 0x02, len = 128, ok = true, idx = 3
// crap:ignore
fn parse_der_tlv_header(der: const u8[:], idx: i64&) -> u8, i64, bool {
    guard idx + 2 <= der.len else { return 0, 0, false; }
    let tag = der[idx];
    let b1 = der[idx + 1];
    var next_idx = idx + 2;
    if (b1 & 0x80) == 0 {
        let len = b1 as i64;
        guard next_idx + len <= der.len else { return 0, 0, false; }
        idx = next_idx;
        return tag, len, true;
    }
    let num_bytes = (b1 & 0x7F) as i64;
    guard num_bytes >= 1 && num_bytes <= 2 && next_idx + num_bytes <= der.len else { return 0, 0, false; }
    var len: i64 = 0;
    for i in num_bytes {
        len = (len << 8) | der[next_idx + i];
    }
    guard (num_bytes == 1 && len >= 128) || (num_bytes == 2 && len >= 256) else { return 0, 0, false; }
    next_idx += num_bytes;
    guard next_idx + len <= der.len else { return 0, 0, false; }
    idx = next_idx;
    return tag, len, true;
}

// Parses an ASN.1 DER `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
// Strips a single leading `0x00` sign-padding byte from positive DER integers.
//
// Example:
//   der = [0x30, ..., 0x02, ..., 0x00, N..., 0x02, 0x03, 0x01, 0x00, 0x01]
//   returns: n_be = N, e_be = [0x01, 0x00, 0x01], ok = true
// crap:ignore
fn parse_rsa_public_key_der(der: const u8[:]) -> const u8[:], const u8[:], bool {
    var idx: i64 = 0;
    let seq_tag, seq_len, seq_ok = parse_der_tlv_header(der, idx);
    guard seq_ok && seq_tag == 0x30 && idx + seq_len == der.len else { return "", "", false; }

    let n_tag, n_len, n_ok = parse_der_tlv_header(der, idx);
    guard n_ok && n_tag == 0x02 && n_len >= 64 else { return "", "", false; }
    var n_slice = der[idx..idx + n_len];
    idx += n_len;
    guard (n_slice[0] & 0x80) == 0 else { return "", "", false; }
    if n_slice[0] == 0x00 {
        guard n_slice.len > 1 && (n_slice[1] & 0x80) != 0 else { return "", "", false; }
        n_slice = n_slice[1..n_slice.len];
    }

    let e_tag, e_len, e_ok = parse_der_tlv_header(der, idx);
    guard e_ok && e_tag == 0x02 && e_len >= 1 && idx + e_len == der.len else { return "", "", false; }
    var e_slice = der[idx..idx + e_len];
    guard (e_slice[0] & 0x80) == 0 else { return "", "", false; }
    if e_slice[0] == 0x00 {
        guard e_slice.len > 1 && (e_slice[1] & 0x80) != 0 else { return "", "", false; }
        e_slice = e_slice[1..e_slice.len];
    }
    guard is_valid_rsa_public_exponent(e_slice, n_slice) else { return "", "", false; }
    return n_slice, e_slice, true;
}

// ---- EMSA-PKCS1-v1_5 Encoding & Verification (RFC 8017 Section 9.2) ------

// DigestInfo DER prefix for SHA-256 (19 bytes)
const PKCS1_DIGESTINFO_SHA256: const u8[19] = [
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
];

// DigestInfo DER prefix for SHA-384 (19 bytes)
const PKCS1_DIGESTINFO_SHA384: const u8[19] = [
    0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
];

// Builds an EMSA-PKCS1-v1_5 encoded message block of length `em_len`.
// crap:ignore
fn build_emsa_pkcs1_v15(
    digest_info_prefix: const u8[:],
    hash:               const u8[:],
    em_len:             i64,
    out_em:             u8[..512]&,
) -> bool {
    let t_len = digest_info_prefix.len + hash.len;
    guard em_len >= t_len + 11 && em_len <= 512 else { return false; }
    out_em.clear();
    out_em.push(0x00);
    out_em.push(0x01);
    let ps_len = em_len - t_len - 3;
    for i in ps_len {
        out_em.push(0xFF);
    }
    out_em.push(0x00);
    out_em.append(digest_info_prefix);
    out_em.append(hash);
    return true;
}

// Verifies an RSASSA-PKCS1-v1_5 SHA-256 signature using big-endian modulus `n_be` and exponent `e_be`.
// crap:ignore
fn rsa_pkcs1_sha256_verify(n_be: const u8[:], e_be: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    guard sig.len == n_be.len && is_valid_rsa_public_exponent(e_be, n_be) else { return false; }
    var em: u8[..512] = [];
    guard rsa_mod_exp(sig, e_be, n_be, em) else { return false; }
    let digest = sha256(message);
    var expected_em: u8[..512] = [];
    guard build_emsa_pkcs1_v15(PKCS1_DIGESTINFO_SHA256[..], digest[..], n_be.len, expected_em) else { return false; }
    return ct_eq_bytes(em[..], expected_em[..]);
}

// Verifies an RSASSA-PKCS1-v1_5 SHA-384 signature using big-endian modulus `n_be` and exponent `e_be`.
// crap:ignore
fn rsa_pkcs1_sha384_verify(n_be: const u8[:], e_be: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    guard sig.len == n_be.len && is_valid_rsa_public_exponent(e_be, n_be) else { return false; }
    var em: u8[..512] = [];
    guard rsa_mod_exp(sig, e_be, n_be, em) else { return false; }
    let digest = sha384(message);
    var expected_em: u8[..512] = [];
    guard build_emsa_pkcs1_v15(PKCS1_DIGESTINFO_SHA384[..], digest[..], n_be.len, expected_em) else { return false; }
    return ct_eq_bytes(em[..], expected_em[..]);
}

// Verifies an RSASSA-PKCS1-v1_5 SHA-256 signature against an ASN.1 DER `RSAPublicKey`.
fn rsa_pkcs1_sha256_verify_der(spki_pubkey_der: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    let n_be, e_be, ok = parse_rsa_public_key_der(spki_pubkey_der);
    guard ok else { return false; }
    return rsa_pkcs1_sha256_verify(n_be, e_be, message, sig);
}

// Verifies an RSASSA-PKCS1-v1_5 SHA-384 signature against an ASN.1 DER `RSAPublicKey`.
fn rsa_pkcs1_sha384_verify_der(spki_pubkey_der: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    let n_be, e_be, ok = parse_rsa_public_key_der(spki_pubkey_der);
    guard ok else { return false; }
    return rsa_pkcs1_sha384_verify(n_be, e_be, message, sig);
}

// Generates an RSASSA-PKCS1-v1_5 SHA-256 signature using big-endian modulus `n_be` and private exponent `d_be`.
// crap:ignore
fn rsa_pkcs1_sha256_sign(
    n_be:    const u8[:],
    d_be:    const u8[:],
    message: const u8[:],
    out_sig: u8[..512]&,
) -> bool {
    let digest = sha256(message);
    var em: u8[..512] = [];
    guard build_emsa_pkcs1_v15(PKCS1_DIGESTINFO_SHA256[..], digest[..], n_be.len, em) else { return false; }
    return rsa_mod_exp(em[..], d_be, n_be, out_sig);
}

// ---- MGF1 & RSASSA-PSS Encoding / Verification (RFC 8017 Section 9.1) ----

// XORs a block of MGF1 mask bytes into `dst` starting at `offset`.
// crap:ignore
fn rsa_mgf1_xor_block(blk: const u8[:], dst: u8[:], offset: i64) {
    let limit = min(blk.len, dst.len - offset);
    for i in limit {
        dst[offset + i] ^= blk[i];
    }
}

// Mask Generation Function MGF1 (RFC 8017 Appendix B.2.1) supporting SHA-256 (32), SHA-384 (48), and SHA-512 (64).
// crap:ignore
fn rsa_mgf1_xor(seed: const u8[:], hash_len: i64, dst: u8[:]) {
    guard seed.len <= 64 && (hash_len == 32 || hash_len == 48 || hash_len == 64) else { return; }
    var counter: u32      = 0;
    var offset:  i64      = 0;
    var hash_in: u8[..68] = [];
    while offset < dst.len {
        hash_in.clear();
        hash_in.append(seed);
        hash_in.push((counter >> 24) as u8);
        hash_in.push((counter >> 16) as u8);
        hash_in.push((counter >> 8) as u8);
        hash_in.push(counter as u8);
        if hash_len == 32 {
            let blk = sha256(hash_in[..]);
            rsa_mgf1_xor_block(blk[..], dst, offset);
            offset += 32;
        } else if hash_len == 48 {
            let blk = sha384(hash_in[..]);
            rsa_mgf1_xor_block(blk[..], dst, offset);
            offset += 48;
        } else {
            let blk = sha512(hash_in[..]);
            rsa_mgf1_xor_block(blk[..], dst, offset);
            offset += 64;
        }
        counter += 1;
    }
}

// Verifies an EMSA-PSS encoded block `em` against `m_hash` with salt length equal to `m_hash.len`.
// crap:ignore
fn verify_emsa_pss(em: const u8[:], m_hash: const u8[:], mod_first_byte: u8) -> bool {
    let h_len = m_hash.len;
    let em_len = em.len;
    guard (h_len == 32 || h_len == 48 || h_len == 64) && mod_first_byte > 1 else { return false; }
    guard em_len >= h_len + h_len + 2 && em_len <= 512 else { return false; }
    guard em[em_len - 1] == 0xBC else { return false; }

    var top_mask: u8 = 0xFF;
    var b = mod_first_byte;
    while (b & 0x80) == 0 && b != 0 {
        top_mask >>= 1;
        b <<= 1;
    }
    top_mask >>= 1;
    guard (em[0] & (~top_mask)) == 0 else { return false; }

    let db_len = em_len - h_len - 1;
    var db: u8[512] = [0; 512];
    for i in db_len {
        db[i] = em[i];
    }
    let h_slice = em[db_len..db_len + h_len];
    rsa_mgf1_xor(h_slice, h_len, db[0..db_len]);
    db[0] &= top_mask;

    let zero_pad_len = db_len - h_len - 1;
    for i in zero_pad_len {
        guard db[i] == 0x00 else { return false; }
    }
    guard db[zero_pad_len] == 0x01 else { return false; }

    let salt = db[zero_pad_len + 1..db_len];
    var m_prime: u8[..136] = [];
    for z in 8 {
        m_prime.push(0x00);
    }
    m_prime.append(m_hash);
    m_prime.append(salt);

    if h_len == 32 {
        let h_calc = sha256(m_prime[..]);
        return ct_eq_bytes(h_calc[..], h_slice);
    }
    if h_len == 48 {
        let h_calc = sha384(m_prime[..]);
        return ct_eq_bytes(h_calc[..], h_slice);
    }
    let h_calc = sha512(m_prime[..]);
    return ct_eq_bytes(h_calc[..], h_slice);
}

// Verifies an RSASSA-PSS SHA-256 signature using big-endian modulus `n_be` and exponent `e_be`.
// crap:ignore
fn rsa_pss_sha256_verify(n_be: const u8[:], e_be: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    guard sig.len == n_be.len && is_valid_rsa_public_exponent(e_be, n_be) else { return false; }
    var em: u8[..512] = [];
    guard rsa_mod_exp(sig, e_be, n_be, em) else { return false; }
    let m_hash = sha256(message);
    return verify_emsa_pss(em[..], m_hash[..], n_be[0]);
}

// Verifies an RSASSA-PSS SHA-384 signature using big-endian modulus `n_be` and exponent `e_be`.
// crap:ignore
fn rsa_pss_sha384_verify(n_be: const u8[:], e_be: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    guard sig.len == n_be.len && is_valid_rsa_public_exponent(e_be, n_be) else { return false; }
    var em: u8[..512] = [];
    guard rsa_mod_exp(sig, e_be, n_be, em) else { return false; }
    let m_hash = sha384(message);
    return verify_emsa_pss(em[..], m_hash[..], n_be[0]);
}

// Verifies an RSASSA-PSS SHA-512 signature using big-endian modulus `n_be` and exponent `e_be`.
// crap:ignore
fn rsa_pss_sha512_verify(n_be: const u8[:], e_be: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    guard sig.len == n_be.len && is_valid_rsa_public_exponent(e_be, n_be) else { return false; }
    var em: u8[..512] = [];
    guard rsa_mod_exp(sig, e_be, n_be, em) else { return false; }
    let m_hash = sha512(message);
    return verify_emsa_pss(em[..], m_hash[..], n_be[0]);
}

// Verifies an RSASSA-PSS SHA-256 signature against an ASN.1 DER `RSAPublicKey`.
fn rsa_pss_sha256_verify_der(spki_pubkey_der: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    let n_be, e_be, ok = parse_rsa_public_key_der(spki_pubkey_der);
    guard ok else { return false; }
    return rsa_pss_sha256_verify(n_be, e_be, message, sig);
}

// Verifies an RSASSA-PSS SHA-384 signature against an ASN.1 DER `RSAPublicKey`.
fn rsa_pss_sha384_verify_der(spki_pubkey_der: const u8[:], message: const u8[:], sig: const u8[:]) -> bool {
    let n_be, e_be, ok = parse_rsa_public_key_der(spki_pubkey_der);
    guard ok else { return false; }
    return rsa_pss_sha384_verify(n_be, e_be, message, sig);
}

// Encodes an EMSA-PSS message block of length `em_len` using `m_hash` and `salt`.
// crap:ignore
fn encode_emsa_pss(
    m_hash:         const u8[:],
    salt:           const u8[:],
    em_len:         i64,
    mod_first_byte: u8,
    out_em:         u8[..512]&,
) -> bool {
    let h_len = m_hash.len;
    let s_len = salt.len;
    guard (h_len == 32 || h_len == 48 || h_len == 64) && mod_first_byte > 1 else { return false; }
    guard s_len == h_len && em_len >= h_len + s_len + 2 && em_len <= 512 else { return false; }

    var m_prime: u8[..136] = [];
    for z in 8 {
        m_prime.push(0x00);
    }
    m_prime.append(m_hash);
    m_prime.append(salt);

    var h_buf: u8[..64] = [];
    if h_len == 32 {
        let d = sha256(m_prime[..]);
        h_buf.append(d[..]);
    } else if h_len == 48 {
        let d = sha384(m_prime[..]);
        h_buf.append(d[..]);
    } else {
        let d = sha512(m_prime[..]);
        h_buf.append(d[..]);
    }

    let db_len = em_len - h_len - 1;
    let zero_pad_len = db_len - s_len - 1;
    var db: u8[512] = [0; 512];
    db[zero_pad_len] = 0x01;
    for i in s_len {
        db[zero_pad_len + 1 + i] = salt[i];
    }
    rsa_mgf1_xor(h_buf[..], h_len, db[0..db_len]);

    var top_mask: u8 = 0xFF;
    var b = mod_first_byte;
    while (b & 0x80) == 0 && b != 0 {
        top_mask >>= 1;
        b <<= 1;
    }
    top_mask >>= 1;
    db[0] &= top_mask;

    out_em.clear();
    out_em.append(db[0..db_len]);
    out_em.append(h_buf[..]);
    out_em.push(0xBC);
    return true;
}

// Generates an RSASSA-PSS SHA-256 signature using big-endian modulus `n_be`, exponent `d_be`, and 32-byte `salt`.
// crap:ignore
fn rsa_pss_sha256_sign(
    n_be:    const u8[:],
    d_be:    const u8[:],
    salt:    const u8[:],
    message: const u8[:],
    out_sig: u8[..512]&,
) -> bool {
    guard n_be.len >= 64 && salt.len == 32 else { return false; }
    let m_hash = sha256(message);
    var em: u8[..512] = [];
    guard encode_emsa_pss(m_hash[..], salt, n_be.len, n_be[0], em) else { return false; }
    return rsa_mod_exp(em[..], d_be, n_be, out_sig);
}

// Generates an RSASSA-PSS SHA-512 signature using big-endian modulus `n_be`, exponent `d_be`, and 64-byte `salt`.
// crap:ignore
fn rsa_pss_sha512_sign(
    n_be:    const u8[:],
    d_be:    const u8[:],
    salt:    const u8[:],
    message: const u8[:],
    out_sig: u8[..512]&,
) -> bool {
    guard n_be.len >= 130 && salt.len == 64 else { return false; }
    let m_hash = sha512(message);
    var em: u8[..512] = [];
    guard encode_emsa_pss(m_hash[..], salt, n_be.len, n_be[0], em) else { return false; }
    return rsa_mod_exp(em[..], d_be, n_be, out_sig);
}
