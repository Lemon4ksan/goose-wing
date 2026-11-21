// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal prepared-key AES-GCM record helpers and QUIC level dispatch for `tls`.
namespace tls_internal;

import std;
import core;
import .internal;
import .record;

// Seals a TLS 1.3 record using pre-expanded `aes_ctx`, writing header, ciphertext, and 16-byte tag in-place.
fn record_seal_aes_gcm_prepared_into(
    aes_ctx:        const core::AesGcmKey&,
    iv:             const u8[12]&,
    seq_num:        u64,
    inner_type:     u8,
    plaintext:      const u8[:],
    out_ciphertext: u8[:],
) -> i64, tls::Alert, bool {
    let inner_len = core::add_sat_i64(plaintext.len, 1);
    let enc_len = core::add_sat_i64(inner_len, rfc::TLS_AEAD_TAG_LEN);
    let enc_u16 = (enc_len & 0xFFFF) as u16;
    let total_len = core::add_sat_i64(rfc::TLS_RECORD_HEADER_LEN, enc_len);
    let plain_end = core::add_sat_i64(rfc::TLS_RECORD_HEADER_LEN, plaintext.len);
    guard aes_ctx.valid && plaintext.len >= 0 && plaintext.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN &&
          enc_len <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN && out_ciphertext.len >= total_len else {
        return 0, tls::Alert.RecordOverflow, false;
    }
    guard inner_type >= rfc::TLS_CONTENT_ALERT && inner_type <= rfc::TLS_CONTENT_APPLICATION_DATA else {
        return 0, tls::Alert.UnexpectedMessage, false;
    }
    let nonce, ok_nonce = tls::compute_record_nonce(iv, seq_num);
    guard ok_nonce else { return 0, tls::Alert.UnexpectedMessage, false; }

    var hdr_buf: u8[..5] = [];
    guard tls::encode_ciphertext_header(
        hdr_buf,
        rfc::TLS_CONTENT_APPLICATION_DATA,
        enc_u16,
    ) else {
        return 0, tls::Alert.InternalError, false;
    }

    core::ct_copy_bytes(out_ciphertext[..rfc::TLS_RECORD_HEADER_LEN], hdr_buf[..]);
    core::ct_copy_bytes(out_ciphertext[rfc::TLS_RECORD_HEADER_LEN..plain_end], plaintext);
    out_ciphertext[plain_end] = inner_type;

    var ct_payload = out_ciphertext[rfc::TLS_RECORD_HEADER_LEN..total_len];
    let tag, written, ok_seal = core::aes_gcm_seal_prepared_inplace(
        aes_ctx,
        nonce,
        ct_payload[..inner_len],
        out_ciphertext[..rfc::TLS_RECORD_HEADER_LEN],
    );
    guard ok_seal && written == inner_len else {
        core::secure_zeroize_slice(out_ciphertext[..total_len]);
        return 0, tls::Alert.InternalError, false;
    }
    core::ct_copy_bytes(ct_payload[inner_len..], tag[..]);
    return total_len, tls::Alert.CloseNotify, true;
}

// Decrypts a TLS 1.3 record using pre-expanded `aes_ctx` and unpacks TLSInnerPlaintext (RFC 8446 §5.2).
fn record_decrypt_aes_gcm_prepared_into(
    aes_ctx:        const core::AesGcmKey&,
    iv:             const u8[12]&,
    seq_num:        u64,
    record_header:  const u8[:],
    record_payload: const u8[:],
    out_plaintext:  u8[:],
) -> i64, u8, tls::Alert, bool {
    guard aes_ctx.valid && record_header.len == 5 &&
          record_payload.len >= TLS_MIN_AEAD_PAYLOAD_LEN else {
        return 0, 0, tls::Alert.DecodeError, false;
    }
    guard record_payload.len <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else {
        return 0, 0, tls::Alert.RecordOverflow, false;
    }
    let ct_len = core::sub_sat_i64(record_payload.len, rfc::TLS_AEAD_TAG_LEN);
    guard ct_len <= rfc::TLS_MAX_INNER_PLAINTEXT_LEN && out_plaintext.len >= ct_len else {
        return 0, 0, tls::Alert.RecordOverflow, false;
    }
    let nonce, ok_nonce = tls::compute_record_nonce(iv, seq_num);
    guard ok_nonce else { return 0, 0, tls::Alert.UnexpectedMessage, false; }

    var tag: u8[16] = [0; 16];
    let tag_slice = record_payload[ct_len..];
    guard tag_slice.len == 16 else { return 0, 0, tls::Alert.DecodeError, false; }
    for i in 16 { tag[i] = tag_slice[i]; }

    let dec_len, ok_open = core::aes_gcm_open_prepared_into(
        aes_ctx,
        nonce,
        record_payload[..ct_len],
        record_header,
        tag,
        out_plaintext[..ct_len],
    );
    guard ok_open && dec_len == ct_len else {
        core::secure_zeroize_slice(out_plaintext[..ct_len]);
        return 0, 0, tls::Alert.BadRecordMac, false;
    }
    let plain, inner_type, alert = tls::unpack_inner_plaintext(out_plaintext[..ct_len]);
    guard alert == tls::Alert.CloseNotify else {
        core::secure_zeroize_slice(out_plaintext[..ct_len]);
        return 0, 0, alert, false;
    }
    let plain_len = plain.len;
    core::secure_zeroize_slice(out_plaintext[plain_len..ct_len]);
    return plain_len, inner_type, tls::Alert.CloseNotify, true;
}

// Seals a TLS 1.3 record using `aes_ctx` when valid for AES-GCM, falling back to key-slice dispatch.
fn record_seal_prepared_into(
    cipher_suite:   u16,
    key:            const u8[:],
    aes_ctx:        const core::AesGcmKey&,
    iv:             const u8[12]&,
    seq_num:        u64,
    inner_type:     u8,
    plaintext:      const u8[:],
    out_ciphertext: u8[:],
) -> i64, tls::Alert, bool {
    if aes_ctx.valid && is_aes_gcm_cipher_suite(cipher_suite) {
        return record_seal_aes_gcm_prepared_into(aes_ctx, iv, seq_num, inner_type, plaintext, out_ciphertext);
    }
    return tls::record_seal_into(cipher_suite, key, iv, seq_num, inner_type, plaintext, out_ciphertext);
}

// Decrypts a TLS 1.3 record using `aes_ctx` when valid for AES-GCM, falling back to key-slice dispatch.
fn record_decrypt_prepared_into(
    cipher_suite:   u16,
    key:            const u8[:],
    aes_ctx:        const core::AesGcmKey&,
    iv:             const u8[12]&,
    seq_num:        u64,
    record_header:  const u8[:],
    record_payload: const u8[:],
    out_plaintext:  u8[:],
) -> i64, u8, tls::Alert, bool {
    if aes_ctx.valid && is_aes_gcm_cipher_suite(cipher_suite) {
        return record_decrypt_aes_gcm_prepared_into(
            aes_ctx,
            iv,
            seq_num,
            record_header,
            record_payload,
            out_plaintext,
        );
    }
    return tls::record_decrypt_into(cipher_suite, key, iv, seq_num, record_header, record_payload, out_plaintext);
}
