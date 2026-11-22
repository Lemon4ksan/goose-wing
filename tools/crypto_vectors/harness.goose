// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Line-based stdin/stdout cryptographic test vector oracle for goose-wing.
// Invokes real core::crypto and tls_internal ML-KEM-768 primitives for
// Wycheproof, C2SP CCTV, and NIST ACVP conformance suites.
import std;
import wing from "../..";

root struct HarnessScratch {
    f0:   u8[>..] = [],
    f1:   u8[>..] = [],
    f2:   u8[>..] = [],
    f3:   u8[>..] = [],
    f4:   u8[>..] = [],
    out:  u8[>..] = [],
    hex1: u8[>..] = [],
    hex2: u8[>..] = [],
}

// Decodes an even-length hexadecimal ASCII string (or "-" for empty) into `out`.
// Clears `out` and returns false on odd length or invalid hex digit.
//
// Example:
//   hex_str = "6f6b"
//   returns: true, out = "ok"
fn decode_hex_field(hex_str: const u8[:], out: u8[>..]&) -> bool {
    out.clear();
    guard hex_str.len > 0 && hex_str != "-" else { return true; }
    guard (hex_str.len & 1) == 0 else { return false; }
    var i: i64 = 0;
    while i < hex_str.len {
        let next_i = core::add_sat_i64(i, 2);
        let b, ok = core::parse_u8_hex(hex_str[i..next_i]);
        guard ok else {
            out.clear();
            return false;
        }
        out.push(b);
        i = next_i;
    }
    return true;
}

fn encode_hex_field(data: const u8[:], out: u8[>..]&) {
    out.clear();
    if data.len == 0 {
        out.push('-');
        return;
    }
    for i in data.len {
        core::format_u64_hex_fixed(data[i], 2, out, false);
    }
}

fn copy_exact_12(src: const u8[:], dst: u8[12]&) -> bool {
    guard src.len == 12 else { return false; }
    for i in 12 { dst[i] = src[i]; }
    return true;
}

fn copy_exact_16(src: const u8[:], dst: u8[16]&) -> bool {
    guard src.len == 16 else { return false; }
    for i in 16 { dst[i] = src[i]; }
    return true;
}

fn copy_exact_32(src: const u8[:], dst: u8[32]&) -> bool {
    guard src.len == 32 else { return false; }
    for i in 32 { dst[i] = src[i]; }
    return true;
}

fn copy_exact_64(src: const u8[:], dst: u8[64]&) -> bool {
    guard src.len == 64 else { return false; }
    for i in 64 { dst[i] = src[i]; }
    return true;
}

// Decodes 2 tab-separated hex fields from `rest` into `s.f0` and `s.f1`.
//
// Example:
//   rest = "aa\tbb"
//   returns: true, s.f0 = [0xaa], s.f1 = [0xbb]
fn decode_2_hex_fields(rest: const u8[:], s: HarnessScratch&) -> bool {
    let c0, c1, ok0 = rest.split_once_byte('\t');
    guard ok0 else { return false; }
    return decode_hex_field(c0, s.f0) && decode_hex_field(c1, s.f1);
}

// Decodes 3 tab-separated hex fields from `rest` into `s.f0..s.f2`.
//
// Example:
//   rest = "aa\tbb\tcc"
//   returns: true, s.f0 = [0xaa], s.f1 = [0xbb], s.f2 = [0xcc]
fn decode_3_hex_fields(rest: const u8[:], s: HarnessScratch&) -> bool {
    let c0, r0, ok0 = rest.split_once_byte('\t');
    let c1, c2, ok1 = r0.split_once_byte('\t');
    guard ok0 && ok1 else { return false; }
    return decode_hex_field(c0, s.f0) &&
        decode_hex_field(c1, s.f1) &&
        decode_hex_field(c2, s.f2);
}

// Decodes 4 tab-separated hex fields from `rest` into `s.f0..s.f3`.
//
// Example:
//   rest = "aa\tbb\t-\tcc"
//   returns: true, s.f0 = [0xaa], s.f1 = [0xbb], s.f2 = [], s.f3 = [0xcc]
fn decode_4_hex_fields(rest: const u8[:], s: HarnessScratch&) -> bool {
    let c0, r0, ok0 = rest.split_once_byte('\t');
    let c1, r1, ok1 = r0.split_once_byte('\t');
    let c2, c3, ok2 = r1.split_once_byte('\t');
    guard ok0 && ok1 && ok2 else { return false; }
    return decode_hex_field(c0, s.f0) &&
        decode_hex_field(c1, s.f1) &&
        decode_hex_field(c2, s.f2) &&
        decode_hex_field(c3, s.f3);
}

// Decodes 5 tab-separated hex fields from `rest` into `s.f0..s.f4`.
//
// Example:
//   rest = "aa\tbb\t-\tcc\tdd"
//   returns: true, s.f0..s.f4 populated
fn decode_5_hex_fields(rest: const u8[:], s: HarnessScratch&) -> bool {
    let c0, r0, ok0 = rest.split_once_byte('\t');
    let c1, r1, ok1 = r0.split_once_byte('\t');
    let c2, r2, ok2 = r1.split_once_byte('\t');
    let c3, c4, ok3 = r2.split_once_byte('\t');
    guard ok0 && ok1 && ok2 && ok3 else { return false; }
    return decode_hex_field(c0, s.f0) &&
        decode_hex_field(c1, s.f1) &&
        decode_hex_field(c2, s.f2) &&
        decode_hex_field(c3, s.f3) &&
        decode_hex_field(c4, s.f4);
}

fn emit_aead_seal(tag: const u8[16]&, ct: const u8[:], ok: bool, s: HarnessScratch&) {
    guard ok else {
        print("FAIL");
        return;
    }
    encode_hex_field(ct, s.hex1);
    encode_hex_field(tag[..], s.hex2);
    print("OK\t", s.hex1[..], "\t", s.hex2[..]);
}

fn handle_aes128_gcm(is_seal: bool, rest: const u8[:], s: HarnessScratch&) {
    var key: u8[16] = [0; 16];
    var iv:  u8[12] = [0; 12];
    if is_seal {
        guard decode_4_hex_fields(rest, s) &&
            copy_exact_16(s.f0[..], key) &&
            copy_exact_12(s.f1[..], iv) else {
            print("FAIL");
            return;
        }
        s.out.clear();
        push_n(s.out, 0 as u8, s.f3.len);
        let tag, n, ok = core::aes128_gcm_seal(key, iv, s.f3[..], s.f2[..], s.out[..]);
        emit_aead_seal(tag, s.out[..n], ok, s);
        return;
    }
    var tag: u8[16] = [0; 16];
    guard decode_5_hex_fields(rest, s) &&
        copy_exact_16(s.f0[..], key) &&
        copy_exact_12(s.f1[..], iv) &&
        copy_exact_16(s.f4[..], tag) else {
        print("FAIL");
        return;
    }
    s.out.clear();
    guard core::aes128_gcm_open(key, iv, s.f3[..], s.f2[..], tag, s.out) else {
        print("FAIL");
        return;
    }
    encode_hex_field(s.out[..], s.hex1);
    print("OK\t", s.hex1[..]);
}

fn handle_aes256_gcm(is_seal: bool, rest: const u8[:], s: HarnessScratch&) {
    var key: u8[32] = [0; 32];
    var iv:  u8[12] = [0; 12];
    if is_seal {
        guard decode_4_hex_fields(rest, s) &&
            copy_exact_32(s.f0[..], key) &&
            copy_exact_12(s.f1[..], iv) else {
            print("FAIL");
            return;
        }
        s.out.clear();
        push_n(s.out, 0 as u8, s.f3.len);
        let tag, n, ok = core::aes256_gcm_seal(key, iv, s.f3[..], s.f2[..], s.out[..]);
        emit_aead_seal(tag, s.out[..n], ok, s);
        return;
    }
    var tag: u8[16] = [0; 16];
    guard decode_5_hex_fields(rest, s) &&
        copy_exact_32(s.f0[..], key) &&
        copy_exact_12(s.f1[..], iv) &&
        copy_exact_16(s.f4[..], tag) else {
        print("FAIL");
        return;
    }
    s.out.clear();
    guard core::aes256_gcm_open(key, iv, s.f3[..], s.f2[..], tag, s.out) else {
        print("FAIL");
        return;
    }
    encode_hex_field(s.out[..], s.hex1);
    print("OK\t", s.hex1[..]);
}

fn handle_chacha_poly(is_seal: bool, rest: const u8[:], s: HarnessScratch&) {
    var key: u8[32] = [0; 32];
    var iv:  u8[12] = [0; 12];
    if is_seal {
        guard decode_4_hex_fields(rest, s) &&
            copy_exact_32(s.f0[..], key) &&
            copy_exact_12(s.f1[..], iv) else {
            print("FAIL");
            return;
        }
        s.out.clear();
        push_n(s.out, 0 as u8, s.f3.len);
        let tag, n, ok = core::chacha20_poly1305_seal(key, iv, s.f3[..], s.f2[..], s.out[..]);
        emit_aead_seal(tag, s.out[..n], ok, s);
        return;
    }
    var tag: u8[16] = [0; 16];
    guard decode_5_hex_fields(rest, s) &&
        copy_exact_32(s.f0[..], key) &&
        copy_exact_12(s.f1[..], iv) &&
        copy_exact_16(s.f4[..], tag) else {
        print("FAIL");
        return;
    }
    s.out.clear();
    guard core::chacha20_poly1305_open(key, iv, s.f3[..], s.f2[..], tag, s.out) else {
        print("FAIL");
        return;
    }
    encode_hex_field(s.out[..], s.hex1);
    print("OK\t", s.hex1[..]);
}

fn handle_x25519(rest: const u8[:], s: HarnessScratch&) {
    var priv: u8[32] = [0; 32];
    var pub:  u8[32] = [0; 32];
    guard decode_2_hex_fields(rest, s) &&
        copy_exact_32(s.f0[..], priv) &&
        copy_exact_32(s.f1[..], pub) else {
        print("FAIL");
        return;
    }
    let shared, ok = core::x25519_shared_secret(priv, pub);
    guard ok else {
        print("FAIL");
        return;
    }
    encode_hex_field(shared[..], s.hex1);
    print("OK\t", s.hex1[..]);
}

fn handle_ecdsa_verify(is_p384: bool, rest: const u8[:], s: HarnessScratch&) {
    guard decode_3_hex_fields(rest, s) else {
        print("FAIL");
        return;
    }
    let ok = if is_p384 {
        core::ecdsa_p384_verify_der(s.f0[..], s.f1[..], s.f2[..])
    } else {
        core::ecdsa_p256_verify_der(s.f0[..], s.f1[..], s.f2[..])
    };
    print(if ok { "OK" } else { "FAIL" });
}

fn handle_ed25519_verify(rest: const u8[:], s: HarnessScratch&) {
    var pub: u8[32] = [0; 32];
    var sig: u8[64] = [0; 64];
    guard decode_3_hex_fields(rest, s) &&
        copy_exact_32(s.f0[..], pub) &&
        copy_exact_64(s.f2[..], sig) else {
        print("FAIL");
        return;
    }
    let ok = core::ed25519_verify(pub, s.f1[..], sig);
    print(if ok { "OK" } else { "FAIL" });
}

fn handle_rsa_verify(is_pss: bool, rest: const u8[:], s: HarnessScratch&) {
    guard decode_3_hex_fields(rest, s) else {
        print("FAIL");
        return;
    }
    let ok = if is_pss {
        core::rsa_pss_sha256_verify_der(s.f0[..], s.f1[..], s.f2[..])
    } else {
        core::rsa_pkcs1_sha256_verify_der(s.f0[..], s.f1[..], s.f2[..])
    };
    print(if ok { "OK" } else { "FAIL" });
}

fn handle_hkdf(is_sha384: bool, rest: const u8[:], s: HarnessScratch&) {
    let c0, r0, ok0 = rest.split_once_byte('\t');
    let c1, r1, ok1 = r0.split_once_byte('\t');
    let c2, c3, ok2 = r1.split_once_byte('\t');
    guard ok0 && ok1 && ok2 else {
        print("FAIL");
        return;
    }
    let out_len_u, ok_len = c3.parse_u64_dec();
    guard ok_len && out_len_u <= 65535 &&
        decode_hex_field(c0, s.f0) &&
        decode_hex_field(c1, s.f1) &&
        decode_hex_field(c2, s.f2) else {
        print("FAIL");
        return;
    }
    let out_len = out_len_u as i64;
    s.out.clear();
    push_n(s.out, 0 as u8, out_len);
    let ok = if is_sha384 {
        let prk = core::hkdf_extract_384(s.f0[..], s.f1[..]);
        core::hkdf_expand_bytes_384(prk[..], s.f2[..], out_len_u as u16, s.out[..])
    } else {
        let prk = core::hkdf_extract(s.f0[..], s.f1[..]);
        core::hkdf_expand_bytes_256(prk[..], s.f2[..], out_len_u as u16, s.out[..])
    };
    guard ok else {
        print("FAIL");
        return;
    }
    encode_hex_field(s.out[..], s.hex1);
    print("OK\t", s.hex1[..]);
}

fn handle_sha(bits: i32, rest: const u8[:], s: HarnessScratch&) {
    guard decode_hex_field(rest, s.f0) else {
        print("FAIL");
        return;
    }
    if bits == 256 {
        let d = core::sha256(s.f0[..]);
        encode_hex_field(d[..], s.hex1);
        print("OK\t", s.hex1[..]);
        return;
    }
    if bits == 384 {
        let d = core::sha384(s.f0[..]);
        encode_hex_field(d[..], s.hex1);
        print("OK\t", s.hex1[..]);
        return;
    }
    let d = core::sha512(s.f0[..]);
    encode_hex_field(d[..], s.hex1);
    print("OK\t", s.hex1[..]);
}

fn handle_hmac(is_sha384: bool, rest: const u8[:], s: HarnessScratch&) {
    guard decode_2_hex_fields(rest, s) else {
        print("FAIL");
        return;
    }
    if is_sha384 {
        let mac = core::hmac_sha384(s.f0[..], s.f1[..]);
        encode_hex_field(mac[..], s.hex1);
        print("OK\t", s.hex1[..]);
        return;
    }
    let mac = core::hmac_sha256(s.f0[..], s.f1[..]);
    encode_hex_field(mac[..], s.hex1);
    print("OK\t", s.hex1[..]);
}

fn handle_mlkem768_keygen(rest: const u8[:], s: HarnessScratch&) {
    var d_seed: u8[32] = [0; 32];
    var z_seed: u8[32] = [0; 32];
    guard decode_2_hex_fields(rest, s) &&
        copy_exact_32(s.f0[..], d_seed) &&
        copy_exact_32(s.f1[..], z_seed) else {
        print("FAIL");
        return;
    }
    let ek, dk = tls_internal::mlkem768_keygen(d_seed, z_seed);
    encode_hex_field(ek[..], s.hex1);
    encode_hex_field(dk[..], s.hex2);
    print("OK\t", s.hex1[..], "\t", s.hex2[..]);
}

fn handle_mlkem768_encaps(rest: const u8[:], s: HarnessScratch&) {
    var m_rand: u8[32] = [0; 32];
    guard decode_2_hex_fields(rest, s) &&
        s.f0.len == 1184 &&
        copy_exact_32(s.f1[..], m_rand) else {
        print("FAIL");
        return;
    }
    var ek: u8[1184] = [0; 1184];
    for i in 1184 { ek[i] = s.f0[i]; }
    let ct, ss, ok = tls_internal::mlkem768_encapsulate(ek, m_rand);
    guard ok else {
        print("FAIL");
        return;
    }
    encode_hex_field(ct[..], s.hex1);
    encode_hex_field(ss[..], s.hex2);
    print("OK\t", s.hex1[..], "\t", s.hex2[..]);
}

fn handle_mlkem768_decaps(rest: const u8[:], s: HarnessScratch&) {
    guard decode_2_hex_fields(rest, s) else {
        print("FAIL");
        return;
    }
    var ss: u8[32] = [0; 32];
    guard tls_internal::mlkem768_decapsulate(s.f0[..], s.f1[..], ss[..]) else {
        print("FAIL");
        return;
    }
    encode_hex_field(ss[..], s.hex1);
    print("OK\t", s.hex1[..]);
}

fn dispatch_symmetric(cmd: const u8[:], rest: const u8[:], s: HarnessScratch&) -> bool {
    if cmd == "AES128_GCM_SEAL" { handle_aes128_gcm(true, rest, s); return true; }
    if cmd == "AES128_GCM_OPEN" { handle_aes128_gcm(false, rest, s); return true; }
    if cmd == "AES256_GCM_SEAL" { handle_aes256_gcm(true, rest, s); return true; }
    if cmd == "AES256_GCM_OPEN" { handle_aes256_gcm(false, rest, s); return true; }
    if cmd == "CHACHA20_POLY1305_SEAL" { handle_chacha_poly(true, rest, s); return true; }
    if cmd == "CHACHA20_POLY1305_OPEN" { handle_chacha_poly(false, rest, s); return true; }
    if cmd == "HKDF_SHA256" { handle_hkdf(false, rest, s); return true; }
    if cmd == "HKDF_SHA384" { handle_hkdf(true, rest, s); return true; }
    if cmd == "SHA256" { handle_sha(256, rest, s); return true; }
    if cmd == "SHA384" { handle_sha(384, rest, s); return true; }
    if cmd == "SHA512" { handle_sha(512, rest, s); return true; }
    if cmd == "HMAC_SHA256" { handle_hmac(false, rest, s); return true; }
    if cmd == "HMAC_SHA384" { handle_hmac(true, rest, s); return true; }
    return false;
}

fn dispatch_asymmetric(cmd: const u8[:], rest: const u8[:], s: HarnessScratch&) -> bool {
    if cmd == "X25519" { handle_x25519(rest, s); return true; }
    if cmd == "ECDSA_P256_VERIFY_DER" { handle_ecdsa_verify(false, rest, s); return true; }
    if cmd == "ECDSA_P384_VERIFY_DER" { handle_ecdsa_verify(true, rest, s); return true; }
    if cmd == "ED25519_VERIFY" { handle_ed25519_verify(rest, s); return true; }
    if cmd == "RSA_PKCS1_SHA256_VERIFY_DER" { handle_rsa_verify(false, rest, s); return true; }
    if cmd == "RSA_PSS_SHA256_VERIFY_DER" { handle_rsa_verify(true, rest, s); return true; }
    if cmd == "MLKEM768_KEYGEN" { handle_mlkem768_keygen(rest, s); return true; }
    if cmd == "MLKEM768_ENCAPS" { handle_mlkem768_encaps(rest, s); return true; }
    if cmd == "MLKEM768_DECAPS" { handle_mlkem768_decaps(rest, s); return true; }
    return false;
}

fn process_command_line(raw_line: const u8[:], s: HarnessScratch&) {
    let line = raw_line.trim_end_byte('\n').trim_end_byte('\r');
    guard line.len > 0 else { return; }
    let cmd, rest, ok = line.split_once_byte('\t');
    guard ok else {
        print("ERR\tBAD_SYNTAX");
        flush_stdout();
        return;
    }
    if !dispatch_symmetric(cmd, rest, s) && !dispatch_asymmetric(cmd, rest, s) {
        print("ERR\tUNKNOWN_CMD");
    }
    flush_stdout();
}

fn main() {
    var scratch = HarnessScratch { .. };
    var line_buf: u8[>..] = [];
    while true {
        line_buf.clear();
        guard read_line(line_buf) else { break; }
        process_command_line(line_buf[..], scratch);
    }
}
