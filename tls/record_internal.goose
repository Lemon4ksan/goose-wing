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

checkfree inline fn tls_be_u16_head(s: const u8[:]) -> u16 {
    if s.len < 2 { return 0; }
    return ((s[0] as u16) << 8) | s[1];
}

checkfree inline fn tls_be_u24_head(s: const u8[:]) -> u32 {
    if s.len < 3 { return 0; }
    let hi = tls_be_u16_head(s) as u32;
    return (hi << 8) | s[2];
}

checkfree inline fn tls_be_u32_head(s: const u8[:]) -> u32 {
    if s.len < 4 { return 0; }
    let hi = tls_be_u16_head(s) as u32;
    let lo = tls_be_u16_head(s[2..]) as u32;
    return (hi << 16) | lo;
}

// RFC 9000 Section 19.6: CRYPTO Frames - Validates 62-bit varint offset and computes end offset.
checkfree inline fn quic_crypto_frame_end(offset: u64, data_len: i64) -> u64, bool {
    if offset > rfc::QUIC_VARINT_MAX || data_len < 0 { return 0, false; }
    let end_offset = offset + (data_len as u64);
    if end_offset < offset || end_offset > rfc::QUIC_VARINT_MAX { return 0, false; }
    return end_offset, true;
}

// Computes a validated non-negative stream offset span (`hi - lo`) for RFC 9000 Section 7.5 bounds.
checkfree inline fn quic_crypto_offset_delta(hi: u64, lo: u64) -> u64, bool {
    if hi < lo { return 0, false; }
    return hi - lo, true;
}

// Computes remaining contiguous free capacity in `QuicCryptoStream.buf`.
checkfree inline fn quic_crypto_buf_free_bytes(buf: const u8[..16384]&) -> u64 {
    if buf.len < 0 || buf.len > buf.cap { return 0; }
    return (buf.cap as u64) - (buf.len as u64);
}

checkfree inline fn quic_crypto_buf_append(buf: u8[..16384]&, src: const u8[:]) -> bool {
    guard src.len >= 0 && (src.len as u64) <= quic_crypto_buf_free_bytes(buf) else { return false; }
    buf.append(src);
    return true;
}

checkfree fn quic_ooo_ring_write(ring: u8[4096]&, stream_off: u64, src: const u8[:]) -> bool {
    guard src.len >= 0 && src.len <= tls::QUIC_CRYPTO_OOO_WINDOW_BYTES else { return false; }
    if src.len == 0 { return true; }
    let start = (stream_off & tls::QUIC_CRYPTO_OOO_MASK) as i64;
    guard start >= 0 && start < ring.len else { return false; }
    let dst1 = ring[start..];
    let first = if src.len < dst1.len { src.len } else { dst1.len };
    guard first >= 0 && first <= dst1.len && first <= src.len else { return false; }
    for i in first {
        dst1[i] = src[i];
    }
    let src2 = src[first..];
    guard src2.len <= ring.len else { return false; }
    for i in src2.len {
        ring[i] = src2[i];
    }
    return true;
}

checkfree fn quic_ooo_ring_drain_to_buf(
    ring:       const u8[4096]&,
    stream_off: u64,
    count:      i64,
    buf:        u8[..16384]&,
) -> bool {
    guard count >= 0 && count <= tls::QUIC_CRYPTO_OOO_WINDOW_BYTES else { return false; }
    if count == 0 { return true; }
    guard (count as u64) <= quic_crypto_buf_free_bytes(buf) else { return false; }
    let start = (stream_off & tls::QUIC_CRYPTO_OOO_MASK) as i64;
    guard start >= 0 && start < ring.len else { return false; }
    let part1 = ring[start..];
    let first = if count < part1.len { count } else { part1.len };
    guard first >= 0 && first <= part1.len else { return false; }
    guard quic_crypto_buf_append(buf, part1[..first]) else { return false; }
    let rest_u, ok_rest = quic_crypto_offset_delta(count as u64, first as u64);
    let rest = rest_u as i64;
    guard ok_rest && rest >= 0 && rest <= ring.len else { return false; }
    if rest > 0 {
        guard quic_crypto_buf_append(buf, ring[..rest]) else { return false; }
    }
    return true;
}

checkfree fn quic_ooo_write_subrange(
    ring:         u8[4096]&,
    frame_offset: u64,
    data:         const u8[:],
    seg_start:    u64,
    seg_end:      u64,
) -> bool {
    if seg_start >= seg_end { return true; }
    let off_u, ok_off = quic_crypto_offset_delta(seg_start, frame_offset);
    let len_u, ok_len = quic_crypto_offset_delta(seg_end, seg_start);
    let slice_off = off_u as i64;
    let slice_len = len_u as i64;
    guard ok_off && ok_len && slice_off >= 0 && slice_off <= data.len else { return false; }
    let tail = data[slice_off..];
    guard slice_len >= 0 && slice_len <= tail.len else { return false; }
    return quic_ooo_ring_write(ring, seg_start, tail[..slice_len]);
}

checkfree fn quic_ooo_write_uncovered(
    stream:     tls::QuicCryptoStream&,
    offset:     u64,
    end_offset: u64,
    data:       const u8[:],
    first:      i64,
    after:      i64,
) -> bool {
    let count = stream.ooo_ranges.len;
    guard first >= 0 && first <= after && after <= count else { return false; }
    var cur = offset;
    for idx in first..after {
        let r = stream.ooo_ranges[idx];
        guard quic_ooo_write_subrange(stream.ooo_ring, offset, data, cur, r.start) else { return false; }
        if r.end > cur { cur = r.end; }
    }
    return quic_ooo_write_subrange(stream.ooo_ring, offset, data, cur, end_offset);
}

checkfree fn quic_ooo_replace_ranges(
    ranges: tls::QuicCryptoOooRange[..16]&,
    first:  i64,
    after:  i64,
    merged: tls::QuicCryptoOooRange,
) -> bool {
    let count = ranges.len;
    guard first >= 0 && first <= after && after <= count else { return false; }
    var next: tls::QuicCryptoOooRange[..16] = [];
    for i in first {
        guard next.len < next.cap else { return false; }
        next.push(ranges[i]);
    }
    guard next.len < next.cap else { return false; }
    next.push(merged);
    for k in after..count {
        guard next.len < next.cap else { return false; }
        next.push(ranges[k]);
    }
    ranges = next;
    return true;
}

checkfree fn quic_ooo_find_merge_span(
    ranges:     const tls::QuicCryptoOooRange[..16]&,
    offset:     u64,
    end_offset: u64,
) -> i64, i64, tls::QuicCryptoOooRange {
    let count = ranges.len;
    var first: i64 = count;
    for i in count {
        if ranges[i].end >= offset {
            first = i;
            break;
        }
    }
    var after: i64 = count;
    var merged = tls::QuicCryptoOooRange { start: offset, end: end_offset };
    for i in first..count {
        let r = ranges[i];
        if r.start > end_offset {
            after = i;
            break;
        }
        if r.start < merged.start { merged.start = r.start; }
        if r.end > merged.end { merged.end = r.end; }
    }
    return first, after, merged;
}

// RFC 9000 Section 7.5: Cryptographic Message Buffering - Stages an out-of-order CRYPTO range
// into `stream.ooo_ring` and merges touching/overlapping intervals in `stream.ooo_ranges`.
checkfree fn quic_crypto_stage_ooo(
    stream:     tls::QuicCryptoStream&,
    offset:     u64,
    end_offset: u64,
    data:       const u8[:],
) -> bool {
    let rel_end, ok_rel = quic_crypto_offset_delta(end_offset, stream.consumed_offset);
    guard ok_rel && rel_end <= (tls::QUIC_CRYPTO_OOO_WINDOW_BYTES as u64) else { return false; }
    guard rel_end <= quic_crypto_buf_free_bytes(stream.buf) else { return false; }

    let first, after, merged = quic_ooo_find_merge_span(stream.ooo_ranges, offset, end_offset);
    guard stream.ooo_ranges.len < tls::QUIC_CRYPTO_OOO_MAX_RANGES || after > first else { return false; }
    guard quic_ooo_write_uncovered(stream, offset, end_offset, data, first, after) else { return false; }
    return quic_ooo_replace_ranges(stream.ooo_ranges, first, after, merged);
}

// Drains all newly contiguous or overlapped staged OOO ranges into `stream.buf`.
checkfree fn quic_crypto_drain_ooo(stream: tls::QuicCryptoStream&) -> bool {
    let count = stream.ooo_ranges.len;
    if count == 0 { return true; }

    var drop_count: i64 = count;
    for i in count {
        let r = stream.ooo_ranges[i];
        if r.start > stream.consumed_offset {
            drop_count = i;
            break;
        }
        if r.end > stream.consumed_offset {
            let take_u, ok_d = quic_crypto_offset_delta(r.end, stream.consumed_offset);
            guard ok_d else { return false; }
            let ok_drain = quic_ooo_ring_drain_to_buf(
                stream.ooo_ring, stream.consumed_offset, take_u as i64, stream.buf,
            );
            guard ok_drain else { return false; }
            stream.consumed_offset = r.end;
        }
    }
    if drop_count == 0 { return true; }

    var next: tls::QuicCryptoOooRange[..16] = [];
    for k in drop_count..count {
        guard next.len < next.cap else { return false; }
        next.push(stream.ooo_ranges[k]);
    }
    stream.ooo_ranges = next;
    return true;
}
