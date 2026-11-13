// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Differential Verification Oracle for goose-wing.
// Evaluates cryptographic digests, MACs, HKDF, AEAD ciphers, X25519, Ed25519,
// RFC 1951 Deflate, RFC 1950 Zlib, RFC 1952 Gzip, RFC 4648 Base64/Base64URL,
// and RFC 9112 HTTP/1.1 framing against external reference implementations
// and official Google Wycheproof test vectors in batch mode.

import std;
import os;
import core from "../..";
import wing from "../..";

// Decodes an even-length ASCII hex string into `out`.
//
// Example:
//   hex = "48656c6c6f", out = []
//   returns: true, out = "Hello"
fn decode_hex_input<B>(hex: const u8[:], out: B&) -> bool {
    out.clear();
    guard (hex.len & 1) == 0 else { return false; }
    var i: i64 = 0;
    while core::add_sat_i64(i, 2) <= hex.len {
        let end = core::add_sat_i64(i, 2);
        let packed, ok = core::parse_u8_hex(hex[i..end]);
        guard ok && out.try_push(packed) else {
            out.clear();
            return false;
        }
        i = end;
    }
    return true;
}

fn append_hex_bytes<B>(src: const u8[:], out: B&) {
    for b in src {
        guard core::add_sat_i64(out.len, 2) <= out.cap else { return; }
        core::format_u8_hex(b, out, false);
    }
}

fn eval_hash_op<B>(op: const u8[:], payload: const u8[:], out_line: B&) -> bool {
    if op == "sha256" {
        let d = core::sha256(payload);
        out_line.append("OK ");
        append_hex_bytes(d[..], out_line);
        return true;
    }
    if op == "sha384" {
        let d = core::sha384(payload);
        out_line.append("OK ");
        append_hex_bytes(d[..], out_line);
        return true;
    }
    if op == "sha512" {
        let d = core::sha512(payload);
        out_line.append("OK ");
        append_hex_bytes(d[..], out_line);
        return true;
    }
    return false;
}

fn eval_mac_and_x25519_op<B>(op: const u8[:], key: const u8[:], msg: const u8[:], out_line: B&) -> bool {
    if op == "hmac_sha256" {
        let tag = core::hmac_sha256(key, msg);
        out_line.append("OK ");
        append_hex_bytes(tag[..], out_line);
        return true;
    }
    if op == "hmac_sha384" {
        let tag = core::hmac_sha384(key, msg);
        out_line.append("OK ");
        append_hex_bytes(tag[..], out_line);
        return true;
    }
    if op == "hmac_sha512" {
        let tag = core::hmac_sha512(key, msg);
        out_line.append("OK ");
        append_hex_bytes(tag[..], out_line);
        return true;
    }
    if op == "x25519" {
        guard key.len == 32 && msg.len == 32 else {
            out_line.append("ERR");
            return true;
        }
        var scalar: u8[32] = [0; 32];
        var point:  u8[32] = [0; 32];
        for i in 32 {
            scalar[i] = key[i];
            point[i] = msg[i];
        }
        let shared = core::x25519_scalarmult(scalar, point);
        out_line.append("OK ");
        append_hex_bytes(shared[..], out_line);
        return true;
    }
    if op == "mlkem768_keygen_decaps" {
        guard key.len == 64 && msg.len == 1088 else {
            out_line.append("ERR");
            return true;
        }
        var d_seed: u8[32] = [0; 32];
        var z_seed: u8[32] = [0; 32];
        for i in 32 {
            d_seed[i] = key[i];
            z_seed[i] = key[32 + i];
        }
        let ek, dk = internal::mlkem768_keygen(d_seed, z_seed);
        var ss: u8[32] = [0; 32];
        guard internal::mlkem768_decapsulate(msg, dk[..], ss[..]) else {
            out_line.append("ERR");
            return true;
        }
        out_line.append("OK ");
        append_hex_bytes(ek[..], out_line);
        append_hex_bytes(ss[..], out_line);
        return true;
    }
    if op == "mlkem768_encaps" {
        guard key.len == 1184 && msg.len == 32 else {
            out_line.append("ERR");
            return true;
        }
        var ek:     u8[1184] = [0; 1184];
        var m_rand: u8[32]   = [0; 32];
        for i in 1184 { ek[i] = key[i]; }
        for i in 32 { m_rand[i] = msg[i]; }
        let ct, ss, ok = internal::mlkem768_encapsulate(ek, m_rand);
        guard ok else {
            out_line.append("ERR");
            return true;
        }
        out_line.append("OK ");
        append_hex_bytes(ct[..], out_line);
        append_hex_bytes(ss[..], out_line);
        return true;
    }
    return false;
}

fn eval_ecdsa_op<B>(is_p384: bool, pub_key: const u8[:], msg: const u8[:], sig: const u8[:], out_line: B&) {
    let ok = if is_p384 {
        core::ecdsa_p384_verify(pub_key, msg, sig)
    } else {
        core::ecdsa_p256_verify(pub_key, msg, sig)
    };
    if ok {
        out_line.append("OK");
    } else {
        out_line.append("ERR");
    }
}

fn eval_rsa_verify_op<B>(op: const u8[:], packed_key: const u8[:], msg: const u8[:], sig: const u8[:], out_line: B&) {
    guard packed_key.len >= 3 else {
        out_line.append("ERR");
        return;
    }
    let n_len = core::read_be_u16(packed_key, 0) as i64;
    guard n_len > 0 && core::add_sat_i64(2, n_len) < packed_key.len else {
        out_line.append("ERR");
        return;
    }
    let n_be = packed_key[2..2 + n_len];
    let e_be = packed_key[2 + n_len..];
    var ok = false;
    if op == "rsa_pkcs1_sha256_verify" {
        ok = core::rsa_pkcs1_sha256_verify(n_be, e_be, msg, sig);
    } else if op == "rsa_pkcs1_sha384_verify" {
        ok = core::rsa_pkcs1_sha384_verify(n_be, e_be, msg, sig);
    } else if op == "rsa_pss_sha256_verify" {
        ok = core::rsa_pss_sha256_verify(n_be, e_be, msg, sig);
    } else if op == "rsa_pss_sha384_verify" {
        ok = core::rsa_pss_sha384_verify(n_be, e_be, msg, sig);
    } else if op == "rsa_pss_sha512_verify" {
        ok = core::rsa_pss_sha512_verify(n_be, e_be, msg, sig);
    }
    if ok {
        out_line.append("OK");
    } else {
        out_line.append("ERR");
    }
}

fn eval_ed25519_op<B>(arg1: const u8[:], arg2: const u8[:], arg3: const u8[:], out_line: B&) {
    guard arg1.len == 32 && arg3.len == 64 else {
        out_line.append("ERR");
        return;
    }
    var pk:  u8[32] = [0; 32];
    var sig: u8[64] = [0; 64];
    for i in 32 { pk[i] = arg1[i]; }
    for i in 64 { sig[i] = arg3[i]; }
    if core::ed25519_verify(pk, arg2, sig) {
        out_line.append("OK");
    } else {
        out_line.append("ERR");
    }
}

fn eval_hkdf_op<B>(
    is_384:   bool,
    ikm:      const u8[:],
    salt:     const u8[:],
    len_info: const u8[:],
    scratch:  u8[..16384]&,
    out_line: B&,
) {
    guard len_info.len >= 2 else {
        out_line.append("ERR");
        return;
    }
    let out_len = core::read_be_u16(len_info, 0);
    let len_i64: i64 = out_len;
    guard len_i64 <= scratch.cap else {
        out_line.append("ERR");
        return;
    }
    let info = len_info[2..];
    scratch.clear();
    for _ in len_i64 { scratch.push(0); }
    let ok = if !is_384 {
        let prk256 = core::hkdf_extract(salt, ikm);
        core::hkdf_expand_bytes_256(prk256[..], info, out_len, scratch[..len_i64])
    } else {
        let prk384 = core::hkdf_extract_384(salt, ikm);
        core::hkdf_expand_bytes_384(prk384[..], info, out_len, scratch[..len_i64])
    };
    if !ok {
        out_line.append("ERR");
        return;
    }
    out_line.append("OK ");
    append_hex_bytes(scratch[..len_i64], out_line);
}

fn unpack_key32_nonce12(kn: const u8[:], k: u8[32]&, n: u8[12]&) -> bool {
    guard kn.len == 44 else { return false; }
    for i in 32 { k[i] = kn[i]; }
    let tail = kn[32..44];
    for i in 12 { n[i] = tail[i]; }
    return true;
}

fn unpack_key16_nonce12(kn: const u8[:], k: u8[16]&, n: u8[12]&) -> bool {
    guard kn.len == 28 else { return false; }
    for i in 16 { k[i] = kn[i]; }
    let tail = kn[16..28];
    for i in 12 { n[i] = tail[i]; }
    return true;
}

fn unpack_ct_and_tag16(ct_tag: const u8[:], tag: u8[16]&) -> const u8[:], bool {
    guard ct_tag.len >= 16 else { return "", false; }
    let ct_len = core::sub_sat_i64(ct_tag.len, 16);
    let tag_slice = ct_tag[ct_len..];
    for i in 16 { tag[i] = tag_slice[i]; }
    return ct_tag[..ct_len], true;
}

fn eval_chacha20_open_seal<B>(
    is_seal:  bool,
    kn:       const u8[:],
    aad:      const u8[:],
    payload:  const u8[:],
    scratch:  u8[..16384]&,
    out_line: B&,
) {
    scratch.clear();
    var k: u8[32] = [0; 32];
    var n: u8[12] = [0; 12];
    guard unpack_key32_nonce12(kn, k, n) else {
        out_line.append("ERR");
        return;
    }
    if !is_seal {
        var tag: u8[16] = [0; 16];
        let ct, ok_ct = unpack_ct_and_tag16(payload, tag);
        if !ok_ct || !core::chacha20_poly1305_open(k, n, ct, aad, tag, scratch) {
            out_line.append("ERR");
            return;
        }
        out_line.append("OK ");
        append_hex_bytes(scratch[..], out_line);
        return;
    }
    guard payload.len <= scratch.cap else {
        out_line.append("ERR");
        return;
    }
    for _ in payload.len { scratch.push(0); }
    let tag, wr, ok = core::chacha20_poly1305_seal(k, n, payload, aad, scratch[..payload.len]);
    if !ok {
        out_line.append("ERR");
        return;
    }
    out_line.append("OK ");
    append_hex_bytes(scratch[..wr], out_line);
    append_hex_bytes(tag[..], out_line);
}

fn eval_xchacha20_open<B>(
    kn:       const u8[:],
    aad:      const u8[:],
    payload:  const u8[:],
    scratch:  u8[..16384]&,
    out_line: B&,
) {
    scratch.clear();
    guard kn.len == 56 else {
        out_line.append("ERR");
        return;
    }
    var k:   u8[32] = [0; 32];
    var n24: u8[24] = [0; 24];
    var tag: u8[16] = [0; 16];
    for i in 32 { k[i] = kn[i]; }
    let tail = kn[32..56];
    for i in 24 { n24[i] = tail[i]; }
    let ct, ok_ct = unpack_ct_and_tag16(payload, tag);
    if !ok_ct || !core::xchacha20_poly1305_open(k, n24, ct, aad, tag, scratch) {
        out_line.append("ERR");
        return;
    }
    out_line.append("OK ");
    append_hex_bytes(scratch[..], out_line);
}

fn eval_aes128_gcm_op<B>(
    is_seal:  bool,
    kn:       const u8[:],
    aad:      const u8[:],
    payload:  const u8[:],
    scratch:  u8[..16384]&,
    out_line: B&,
) {
    scratch.clear();
    var k16: u8[16] = [0; 16];
    var n12: u8[12] = [0; 12];
    guard unpack_key16_nonce12(kn, k16, n12) else {
        out_line.append("ERR");
        return;
    }
    if !is_seal {
        var tag: u8[16] = [0; 16];
        let ct, ok_ct = unpack_ct_and_tag16(payload, tag);
        if !ok_ct || !core::aes128_gcm_open(k16, n12, ct, aad, tag, scratch) {
            out_line.append("ERR");
            return;
        }
        out_line.append("OK ");
        append_hex_bytes(scratch[..], out_line);
        return;
    }
    guard payload.len <= scratch.cap else {
        out_line.append("ERR");
        return;
    }
    for _ in payload.len { scratch.push(0); }
    let tag, wr, ok = core::aes128_gcm_seal(k16, n12, payload, aad, scratch[..payload.len]);
    if !ok {
        out_line.append("ERR");
        return;
    }
    out_line.append("OK ");
    append_hex_bytes(scratch[..wr], out_line);
    append_hex_bytes(tag[..], out_line);
}

fn eval_aes256_gcm_op<B>(
    is_seal:  bool,
    kn:       const u8[:],
    aad:      const u8[:],
    payload:  const u8[:],
    scratch:  u8[..16384]&,
    out_line: B&,
) {
    scratch.clear();
    var k32: u8[32] = [0; 32];
    var n12: u8[12] = [0; 12];
    guard unpack_key32_nonce12(kn, k32, n12) else {
        out_line.append("ERR");
        return;
    }
    if !is_seal {
        var tag: u8[16] = [0; 16];
        let ct, ok_ct = unpack_ct_and_tag16(payload, tag);
        if !ok_ct || !core::aes256_gcm_open(k32, n12, ct, aad, tag, scratch) {
            out_line.append("ERR");
            return;
        }
        out_line.append("OK ");
        append_hex_bytes(scratch[..], out_line);
        return;
    }
    guard payload.len <= scratch.cap else {
        out_line.append("ERR");
        return;
    }
    for _ in payload.len { scratch.push(0); }
    let tag, wr, ok = core::aes256_gcm_seal(k32, n12, payload, aad, scratch[..payload.len]);
    if !ok {
        out_line.append("ERR");
        return;
    }
    out_line.append("OK ");
    append_hex_bytes(scratch[..wr], out_line);
    append_hex_bytes(tag[..], out_line);
}

fn dispatch_three_arg_op<B>(
    op:       const u8[:],
    arg1:     const u8[:],
    arg2:     const u8[:],
    arg3:     const u8[:],
    scratch:  u8[..16384]&,
    out_line: B&,
) -> bool {
    if op == "ed25519_verify" {
        eval_ed25519_op(arg1, arg2, arg3, out_line);
        return true;
    }
    if op == "hkdf_sha256" || op == "hkdf_sha384" {
        eval_hkdf_op(op == "hkdf_sha384", arg1, arg2, arg3, scratch, out_line);
        return true;
    }
    if op == "chacha20_open" || op == "chacha20_seal" {
        eval_chacha20_open_seal(op == "chacha20_seal", arg1, arg2, arg3, scratch, out_line);
        return true;
    }
    if op == "xchacha20_open" {
        eval_xchacha20_open(arg1, arg2, arg3, scratch, out_line);
        return true;
    }
    if op == "aes128_gcm_open" || op == "aes128_gcm_seal" {
        eval_aes128_gcm_op(op == "aes128_gcm_seal", arg1, arg2, arg3, scratch, out_line);
        return true;
    }
    if op == "aes256_gcm_open" || op == "aes256_gcm_seal" {
        eval_aes256_gcm_op(op == "aes256_gcm_seal", arg1, arg2, arg3, scratch, out_line);
        return true;
    }
    if op == "ecdsa_p256_verify" || op == "ecdsa_p384_verify" {
        eval_ecdsa_op(op == "ecdsa_p384_verify", arg1, arg2, arg3, out_line);
        return true;
    }
    if op == "rsa_pkcs1_sha256_verify" || op == "rsa_pkcs1_sha384_verify" ||
        op == "rsa_pss_sha256_verify" || op == "rsa_pss_sha384_verify" ||
        op == "rsa_pss_sha512_verify" {
        eval_rsa_verify_op(op, arg1, arg2, arg3, out_line);
        return true;
    }
    return false;
}

fn emit_compress_result<B>(ok: bool, scratch: const u8[..16384]&, out_line: B&) {
    if !ok {
        out_line.append("ERR");
        return;
    }
    out_line.append("OK ");
    append_hex_bytes(scratch[..], out_line);
}

fn eval_compress_op<B>(op: const u8[:], payload: const u8[:], scratch: u8[..16384]&, out_line: B&) -> bool {
    scratch.clear();
    if op == "zlib_decompress" {
        let ok, _ = core::zlib_decompress_with_dict(payload, scratch, "");
        emit_compress_result(ok, scratch, out_line);
        return true;
    }
    if op == "zlib_compress" {
        emit_compress_result(core::zlib_compress(payload, scratch, 6), scratch, out_line);
        return true;
    }
    if op == "gzip_decompress" {
        let _, err_gz = core::gzip_decompress(payload, scratch);
        emit_compress_result(err_gz == core::CompressError.None, scratch, out_line);
        return true;
    }
    if op == "gzip_compress" {
        emit_compress_result(core::gzip_compress(payload, scratch, 6), scratch, out_line);
        return true;
    }
    if op == "deflate_decompress" {
        let _, err_def = core::inflate(payload, scratch);
        emit_compress_result(err_def == core::CompressError.None, scratch, out_line);
        return true;
    }
    if op == "deflate_compress" {
        emit_compress_result(core::deflate(payload, scratch, 6), scratch, out_line);
        return true;
    }
    return false;
}

fn eval_base64_op<B>(op: const u8[:], payload: const u8[:], scratch: u8[..16384]&, out_line: B&) -> bool {
    scratch.clear();
    if op == "b64_encode" {
        core::base64_encode(payload, scratch);
        emit_compress_result(true, scratch, out_line);
        return true;
    }
    if op == "b64_decode" {
        emit_compress_result(core::base64_decode(payload, scratch), scratch, out_line);
        return true;
    }
    if op == "b64url_encode" {
        core::base64url_encode(payload, scratch);
        emit_compress_result(true, scratch, out_line);
        return true;
    }
    if op == "b64url_decode" {
        emit_compress_result(core::base64url_decode(payload, scratch), scratch, out_line);
        return true;
    }
    return false;
}

fn eval_http1_op<B>(op: const u8[:], payload: const u8[:], out_line: B&) -> bool {
    if op == "http1_verdict" {
        var req = wing::Request { .. };
        let ok, consumed = wing::parse_http1_wire_request(payload, req);
        if !ok || consumed <= 0 {
            out_line.append("ERR");
            return true;
        }
        out_line.append("ok ");
        if (req.presence_mask & wing::HDR_PRESENCE_TRANSFER_ENCODING) != 0 {
            out_line.append("chunked");
        } else if req.body.len > 0 {
            out_line.append("length");
        } else {
            out_line.append("none");
        }
        out_line.push(' ');
        core::format_i64_dec(req.body.len, out_line);
        out_line.push(' ');
        append_hex_bytes(req.body[..], out_line);
        return true;
    }
    guard op == "http1_req" else { return false; }
    var req = wing::Request { .. };
    let ok, consumed = wing::parse_http1_wire_request(payload, req);
    if !ok || consumed <= 0 {
        out_line.append("ERR");
        return true;
    }
    out_line.append("OK ");
    out_line.append(req.method[..]);
    out_line.push(' ');
    append_hex_bytes(req.url[..], out_line);
    out_line.push(' ');
    let ver_minor: i64 = if req.is_http10 { 0 } else { 1 };
    core::format_i64_dec(ver_minor, out_line);
    out_line.push(' ');
    core::format_i64_dec(req.body.len, out_line);
    out_line.push(' ');
    let is_chunked: i64 = if (req.presence_mask & wing::HDR_PRESENCE_TRANSFER_ENCODING) != 0 { 1 } else { 0 };
    core::format_i64_dec(is_chunked, out_line);
    return true;
}

fn process_multi_arg_line<B>(
    op:       const u8[:],
    hex1:     const u8[:],
    after1:   const u8[:],
    arg1_buf: u8[..8192]&,
    arg2_buf: u8[..8192]&,
    arg3_buf: u8[..8192]&,
    scratch:  u8[..16384]&,
    out_line: B&,
) {
    let hex2, hex3, has_arg3 = core::split_once_byte(after1, ':');
    if has_arg3 {
        let ok1 = decode_hex_input(hex1, arg1_buf);
        let ok2 = decode_hex_input(hex2, arg2_buf);
        let ok3 = decode_hex_input(hex3, arg3_buf);
        guard ok1 && ok2 && ok3 else {
            out_line.append("ERR:HEX3");
            return;
        }
        if !dispatch_three_arg_op(op, arg1_buf[..], arg2_buf[..], arg3_buf[..], scratch, out_line) {
            out_line.append("ERR:UNKNOWN_OP3");
        }
        return;
    }
    let ok1 = decode_hex_input(hex1, arg1_buf);
    let ok2 = decode_hex_input(hex2, arg2_buf);
    guard ok1 && ok2 else {
        out_line.append("ERR:HEX2");
        return;
    }
    if !eval_mac_and_x25519_op(op, arg1_buf[..], arg2_buf[..], out_line) {
        out_line.append("ERR:UNKNOWN_OP2");
    }
}

fn process_oracle_line<B>(
    line:     const u8[:],
    arg1_buf: u8[..8192]&,
    arg2_buf: u8[..8192]&,
    arg3_buf: u8[..8192]&,
    scratch:  u8[..16384]&,
    out_line: B&,
) {
    out_line.clear();
    let trimmed = core::trim_ascii_space(line);
    guard trimmed.len > 0 else { return; }

    let op_raw, rest_raw, has_sep = core::split_once_byte(trimmed, ' ');
    let op = if has_sep { op_raw } else { trimmed };
    let rest = if has_sep { core::trim_ascii_space(rest_raw) } else { "" };

    let hex1, after1, has_arg2 = core::split_once_byte(rest, ':');
    if has_arg2 {
        process_multi_arg_line(op, hex1, after1, arg1_buf, arg2_buf, arg3_buf, scratch, out_line);
        return;
    }

    guard decode_hex_input(rest, arg1_buf) else {
        out_line.append("ERR:HEX1");
        return;
    }

    if eval_hash_op(op, arg1_buf[..], out_line) { return; }
    if eval_compress_op(op, arg1_buf[..], scratch, out_line) { return; }
    if eval_base64_op(op, arg1_buf[..], scratch, out_line) { return; }
    if eval_http1_op(op, arg1_buf[..], out_line) { return; }

    out_line.append("ERR:UNKNOWN_OP");
}

fn scan_line_end(buf: const u8[:], start: i64) -> i64 {
    var cur = start;
    while cur < buf.len && buf[cur] != '\n' {
        cur = core::add_sat_i64(cur, 1);
    }
    return cur;
}

fn main() {
    let a = args();
    guard a.len >= 2 else {
        print("usage: diff_oracle <batch_file>");
        exit(2);
    }

    var raw_batch: u8[>..]     = [];
    var arg1_buf:  u8[..8192]  = [];
    var arg2_buf:  u8[..8192]  = [];
    var arg3_buf:  u8[..8192]  = [];
    var scratch:   u8[..16384] = [];
    var out_line:  u8[..32768] = [];

    guard read_file(a[1], raw_batch) else {
        print("ERR:READ_FILE");
        exit(1);
    }

    var pos: i64 = 0;
    let total = raw_batch.len;
    while pos < total {
        let line_end = scan_line_end(raw_batch[..], pos);
        let line = raw_batch[pos..line_end];
        pos = core::add_sat_i64(line_end, 1);
        process_oracle_line(line, arg1_buf, arg2_buf, arg3_buf, scratch, out_line);
        if out_line.len > 0 {
            print(out_line[..]);
        }
    }
}
