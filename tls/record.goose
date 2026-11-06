// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation TLS 1.3 Record Layer and RFC 9001 QUIC Crypto adapter.
// Conforms to RFC 8446 Section 5, RFC 9001 Section 5.4, and BoringSSL/BearSSL safety models.
namespace wing;

import std;
import core from "..";

// ---- TLS 1.3 Alert Codes (RFC 8446 Section 6) ---------------------------

enum TlsAlert {
    CloseNotify,
    UnexpectedMessage,
    BadRecordMac,
    RecordOverflow,
    HandshakeFailure,
    BadCertificate,
    UnsupportedCertificate,
    CertificateRevoked,
    CertificateExpired,
    CertificateUnknown,
    IllegalParameter,
    UnknownCa,
    AccessDenied,
    DecodeError,
    DecryptError,
    ProtocolVersion,
    InsufficientSecurity,
    InternalError,
    InappropriateFallback,
    UserCanceled,
    MissingExtension,
    UnsupportedExtension,
    UnrecognizedName,
    BadCertificateStatusResponse,
    UnknownPskIdentity,
    CertificateRequired,
    NoApplicationProtocol,
}

inline fn tls_alert_to_u8(alert: TlsAlert) -> u8 {
    return match alert {
        CloseNotify => rfc::TLS_ALERT_CLOSE_NOTIFY,
        UnexpectedMessage => rfc::TLS_ALERT_UNEXPECTED_MESSAGE,
        BadRecordMac => rfc::TLS_ALERT_BAD_RECORD_MAC,
        RecordOverflow => rfc::TLS_ALERT_RECORD_OVERFLOW,
        HandshakeFailure => rfc::TLS_ALERT_HANDSHAKE_FAILURE,
        BadCertificate => rfc::TLS_ALERT_BAD_CERTIFICATE,
        UnsupportedCertificate => rfc::TLS_ALERT_UNSUPPORTED_CERTIFICATE,
        CertificateRevoked => rfc::TLS_ALERT_CERTIFICATE_REVOKED,
        CertificateExpired => rfc::TLS_ALERT_CERTIFICATE_EXPIRED,
        CertificateUnknown => rfc::TLS_ALERT_CERTIFICATE_UNKNOWN,
        IllegalParameter => rfc::TLS_ALERT_ILLEGAL_PARAMETER,
        UnknownCa => rfc::TLS_ALERT_UNKNOWN_CA,
        AccessDenied => rfc::TLS_ALERT_ACCESS_DENIED,
        DecodeError => rfc::TLS_ALERT_DECODE_ERROR,
        DecryptError => rfc::TLS_ALERT_DECRYPT_ERROR,
        ProtocolVersion => rfc::TLS_ALERT_PROTOCOL_VERSION,
        InsufficientSecurity => rfc::TLS_ALERT_INSUFFICIENT_SECURITY,
        InternalError => rfc::TLS_ALERT_INTERNAL_ERROR,
        InappropriateFallback => rfc::TLS_ALERT_INAPPROPRIATE_FALLBACK,
        UserCanceled => rfc::TLS_ALERT_USER_CANCELED,
        MissingExtension => rfc::TLS_ALERT_MISSING_EXTENSION,
        UnsupportedExtension => rfc::TLS_ALERT_UNSUPPORTED_EXTENSION,
        UnrecognizedName => rfc::TLS_ALERT_UNRECOGNIZED_NAME,
        BadCertificateStatusResponse => rfc::TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE,
        UnknownPskIdentity => rfc::TLS_ALERT_UNKNOWN_PSK_IDENTITY,
        CertificateRequired => rfc::TLS_ALERT_CERTIFICATE_REQUIRED,
        NoApplicationProtocol => rfc::TLS_ALERT_NO_APPLICATION_PROTOCOL,
    };
}

inline fn u8_to_tls_alert(code: u8) -> TlsAlert, bool {
    let alert = match code {
        rfc::TLS_ALERT_CLOSE_NOTIFY => TlsAlert.CloseNotify,
        rfc::TLS_ALERT_UNEXPECTED_MESSAGE => TlsAlert.UnexpectedMessage,
        rfc::TLS_ALERT_BAD_RECORD_MAC => TlsAlert.BadRecordMac,
        rfc::TLS_ALERT_RECORD_OVERFLOW => TlsAlert.RecordOverflow,
        rfc::TLS_ALERT_HANDSHAKE_FAILURE => TlsAlert.HandshakeFailure,
        rfc::TLS_ALERT_BAD_CERTIFICATE => TlsAlert.BadCertificate,
        rfc::TLS_ALERT_UNSUPPORTED_CERTIFICATE => TlsAlert.UnsupportedCertificate,
        rfc::TLS_ALERT_CERTIFICATE_REVOKED => TlsAlert.CertificateRevoked,
        rfc::TLS_ALERT_CERTIFICATE_EXPIRED => TlsAlert.CertificateExpired,
        rfc::TLS_ALERT_CERTIFICATE_UNKNOWN => TlsAlert.CertificateUnknown,
        rfc::TLS_ALERT_ILLEGAL_PARAMETER => TlsAlert.IllegalParameter,
        rfc::TLS_ALERT_UNKNOWN_CA => TlsAlert.UnknownCa,
        rfc::TLS_ALERT_ACCESS_DENIED => TlsAlert.AccessDenied,
        rfc::TLS_ALERT_DECODE_ERROR => TlsAlert.DecodeError,
        rfc::TLS_ALERT_DECRYPT_ERROR => TlsAlert.DecryptError,
        rfc::TLS_ALERT_PROTOCOL_VERSION => TlsAlert.ProtocolVersion,
        rfc::TLS_ALERT_INSUFFICIENT_SECURITY => TlsAlert.InsufficientSecurity,
        rfc::TLS_ALERT_INTERNAL_ERROR => TlsAlert.InternalError,
        rfc::TLS_ALERT_INAPPROPRIATE_FALLBACK => TlsAlert.InappropriateFallback,
        rfc::TLS_ALERT_USER_CANCELED => TlsAlert.UserCanceled,
        rfc::TLS_ALERT_MISSING_EXTENSION => TlsAlert.MissingExtension,
        rfc::TLS_ALERT_UNSUPPORTED_EXTENSION => TlsAlert.UnsupportedExtension,
        rfc::TLS_ALERT_UNRECOGNIZED_NAME => TlsAlert.UnrecognizedName,
        rfc::TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE => TlsAlert.BadCertificateStatusResponse,
        rfc::TLS_ALERT_UNKNOWN_PSK_IDENTITY => TlsAlert.UnknownPskIdentity,
        rfc::TLS_ALERT_CERTIFICATE_REQUIRED => TlsAlert.CertificateRequired,
        rfc::TLS_ALERT_NO_APPLICATION_PROTOCOL => TlsAlert.NoApplicationProtocol,
        _ => TlsAlert.DecodeError,
    };
    if alert == TlsAlert.DecodeError && code != rfc::TLS_ALERT_DECODE_ERROR {
        return TlsAlert.DecodeError, false;
    }
    return alert, true;
}

// Parses and validates a 2-byte TLS alert message according to RFC 8446 Section 6 & 6.1.
// Returns (level, alert, is_fatal, ok).
// - Alert records MUST be exactly 2 bytes (level + description).
// - Alert level MUST be 1 (warning) or 2 (fatal).
// - In TLS 1.3, warning alerts other than close_notify (0) and user_canceled (90) MUST be treated as fatal.
//
// Example:
//   data = [0x02, 0x31] (fatal, decode_error)
//   returns: level = 2, alert = TlsAlert.DecodeError, is_fatal = true, ok = true
fn parse_tls_alert_message(data: const u8[:]) -> u8, TlsAlert, bool, bool {
    guard data.len == 2 else {
        return 0, TlsAlert.DecodeError, true, false;
    }
    let level = data[0];
    let desc = data[1];

    guard level == 1 || level == 2 else {
        return level, TlsAlert.DecodeError, true, false;
    }

    let alert, alert_ok = u8_to_tls_alert(desc);
    guard alert_ok else {
        return level, TlsAlert.DecodeError, true, false;
    }

    var is_fatal = true;
    if level == 1 {
        if desc == rfc::TLS_ALERT_CLOSE_NOTIFY || desc == rfc::TLS_ALERT_USER_CANCELED {
            is_fatal = false;
        }
    }
    return level, alert, is_fatal, true;
}

// ---- Zero-Copy Parsers (Canonical Slice + Cursor & ByteCursor) ------------

// Reads a single unsigned byte from `raw` at `cursor` and advances `cursor` by 1.
//
// Example:
//   raw = [0x17, 0x03], cursor = 0
//   returns: out = 0x17, ok = true, cursor = 1
inline fn slice_get_u8(raw: const u8[:], cursor: i64&, out: u8&) -> bool {
    guard cursor >= 0 && cursor < raw.len else {
        return false;
    }
    out = raw[cursor];
    cursor += 1;
    return true;
}

// Reads a single unsigned byte directly from `raw` at `cursor` (Rule 9 value return).
//
// Example:
//   raw = [0x17, 0x03], cursor = 0
//   returns: val = 0x17, ok = true, cursor = 1
inline fn slice_read_u8(raw: const u8[:], cursor: i64&) -> u8, bool {
    guard cursor >= 0 && cursor < raw.len else {
        return 0, false;
    }
    let val = raw[cursor];
    cursor += 1;
    return val, true;
}

// Reads a big-endian 16-bit unsigned integer from `raw` at `cursor` and advances `cursor` by 2.
//
// Example:
//   raw = [0x03, 0x03], cursor = 0
//   returns: out = 0x0303, ok = true, cursor = 2
inline fn slice_get_u16(raw: const u8[:], cursor: i64&, out: u16&) -> bool {
    guard cursor >= 0 && cursor + 2 <= raw.len else {
        return false;
    }
    out = core::read_be_u16(raw, cursor);
    cursor += 2;
    return true;
}

// Reads a big-endian 16-bit integer directly from `raw` at `cursor` (Rule 9 value return).
//
// Example:
//   raw = [0x03, 0x03], cursor = 0
//   returns: val = 0x0303, ok = true, cursor = 2
inline fn slice_read_u16(raw: const u8[:], cursor: i64&) -> u16, bool {
    guard cursor >= 0 && cursor + 2 <= raw.len else {
        return 0, false;
    }
    let val = core::read_be_u16(raw, cursor);
    cursor += 2;
    return val, true;
}

// Reads a big-endian 24-bit unsigned integer from `raw` at `cursor` and advances `cursor` by 3.
//
// Example:
//   raw = [0x00, 0x01, 0x02], cursor = 0
//   returns: out = 0x000102, ok = true, cursor = 3
inline fn slice_get_u24(raw: const u8[:], cursor: i64&, out: u32&) -> bool {
    guard cursor >= 0 && cursor + 3 <= raw.len else {
        return false;
    }
    out = core::read_be_u24(raw, cursor);
    cursor += 3;
    return true;
}

// Reads a big-endian 24-bit integer directly from `raw` at `cursor` (Rule 9 value return).
//
// Example:
//   raw = [0x00, 0x01, 0x02], cursor = 0
//   returns: val = 0x000102, ok = true, cursor = 3
inline fn slice_read_u24(raw: const u8[:], cursor: i64&) -> u32, bool {
    guard cursor >= 0 && cursor + 3 <= raw.len else {
        return 0, false;
    }
    let val = core::read_be_u24(raw, cursor);
    cursor += 3;
    return val, true;
}

// Reads a big-endian 32-bit unsigned integer from `raw` at `cursor` and advances `cursor` by 4.
//
// Example:
//   raw = [0x01, 0x02, 0x03, 0x04], cursor = 0
//   returns: out = 0x01020304, ok = true, cursor = 4
inline fn slice_get_u32(raw: const u8[:], cursor: i64&, out: u32&) -> bool {
    guard cursor >= 0 && cursor + 4 <= raw.len else {
        return false;
    }
    out = core::read_be_u32(raw, cursor);
    cursor += 4;
    return true;
}

// Reads a big-endian 32-bit integer directly from `raw` at `cursor` (Rule 9 value return).
//
// Example:
//   raw = [0x01, 0x02, 0x03, 0x04], cursor = 0
//   returns: val = 0x01020304, ok = true, cursor = 4
inline fn slice_read_u32(raw: const u8[:], cursor: i64&) -> u32, bool {
    guard cursor >= 0 && cursor + 4 <= raw.len else {
        return 0, false;
    }
    let val = core::read_be_u32(raw, cursor);
    cursor += 4;
    return val, true;
}

// Extracts a zero-copy slice of `count` bytes from `raw` at `cursor` and advances `cursor` by `count`.
//
// Example:
//   raw = "hello", cursor = 1, count = 3
//   returns: sub = "ell", ok = true, cursor = 4
inline fn slice_get_bytes(raw: const u8[:], cursor: i64&, count: i64) -> const u8[:], bool {
    guard count >= 0 && cursor >= 0 && cursor + count <= raw.len else {
        return raw[..0], false;
    }
    let sub = raw[cursor..cursor + count];
    cursor += count;
    return sub, true;
}

// Extracts a 1-byte length-prefixed slice from `raw` at `cursor`.
// Leaves `cursor` unchanged on error.
//
// Example:
//   raw = [0x02, 0xAA, 0xBB], cursor = 0
//   returns: sub = [0xAA, 0xBB], ok = true, cursor = 3
fn slice_get_u8_length_prefixed(raw: const u8[:], cursor: i64&) -> const u8[:], bool {
    let saved = cursor;
    var length: u8 = 0;
    guard slice_get_u8(raw, cursor, length) else {
        return raw[..0], false;
    }
    let sub, ok = slice_get_bytes(raw, cursor, length);
    guard ok else {
        cursor = saved;
        return raw[..0], false;
    }
    return sub, true;
}

// Extracts a big-endian 2-byte length-prefixed slice from `raw` at `cursor`.
// Leaves `cursor` unchanged on error.
//
// Example:
//   raw = [0x00, 0x02, 0xAA, 0xBB], cursor = 0
//   returns: sub = [0xAA, 0xBB], ok = true, cursor = 4
fn slice_get_u16_length_prefixed(raw: const u8[:], cursor: i64&) -> const u8[:], bool {
    let saved = cursor;
    var length: u16 = 0;
    guard slice_get_u16(raw, cursor, length) else {
        return raw[..0], false;
    }
    let sub, ok = slice_get_bytes(raw, cursor, length);
    guard ok else {
        cursor = saved;
        return raw[..0], false;
    }
    return sub, true;
}

// Extracts a big-endian 3-byte length-prefixed slice from `raw` at `cursor`.
// Leaves `cursor` unchanged on error.
//
// Example:
//   raw = [0x00, 0x00, 0x02, 0xAA, 0xBB], cursor = 0
//   returns: sub = [0xAA, 0xBB], ok = true, cursor = 5
fn slice_get_u24_length_prefixed(raw: const u8[:], cursor: i64&) -> const u8[:], bool {
    let saved = cursor;
    var length: u32 = 0;
    guard slice_get_u24(raw, cursor, length) else {
        return raw[..0], false;
    }
    let sub, ok = slice_get_bytes(raw, cursor, length);
    guard ok else {
        cursor = saved;
        return raw[..0], false;
    }
    return sub, true;
}

// Re-export core streaming cursor and builder types into wing.
type ByteCursor = core::ByteCursor;
type ByteBuilder = core::ByteBuilder;

// ---- TLS Record Layer Framing & Invariants (RFC 8446 Section 5) ---------

const RECORD_BUFSIZE_IN:  i64 = 16709; // 16384 + 325 (BearSSL BR_SSL_BUFSIZE_INPUT)
const RECORD_BUFSIZE_OUT: i64 = 16469; // 16384 + 85 (BearSSL BR_SSL_BUFSIZE_OUTPUT)

const MAX_EMPTY_RECORDS:      i32 = 32;    // BoringSSL kMaxEmptyRecords DoS defense
const MAX_EARLY_DATA_SKIPPED: i64 = 16384; // BoringSSL kMaxEarlyDataSkipped

// Computes 96-bit (12-byte) per-record nonce: N = iv ^ (0^32 || be64(seq_num))
// Rejects 2^64 - 1 to prevent counter wraparound and nonce reuse (RFC 8446 Section 5.3).
inline fn compute_record_nonce(iv: const u8[12]&, seq_num: u64) -> u8[12], bool {
    var nonce: u8[12] = [0; 12];
    if seq_num == 0xFFFFFFFFFFFFFFFF {
        return nonce, false;
    }
    for i in 12 { nonce[i] = iv[i]; }
    nonce[4] ^= ((seq_num >> 56) & 0xFF) as u8;
    nonce[5] ^= ((seq_num >> 48) & 0xFF) as u8;
    nonce[6] ^= ((seq_num >> 40) & 0xFF) as u8;
    nonce[7] ^= ((seq_num >> 32) & 0xFF) as u8;
    nonce[8] ^= ((seq_num >> 24) & 0xFF) as u8;
    nonce[9] ^= ((seq_num >> 16) & 0xFF) as u8;
    nonce[10] ^= ((seq_num >> 8) & 0xFF) as u8;
    nonce[11] ^= (seq_num & 0xFF) as u8;
    return nonce, true;
}

// Validates and increments 64-bit record sequence number; rejects 2^64 - 1 (RFC 8446 Section 5.3).
inline fn increment_record_seq_num(seq_num: u64&) -> bool {
    if seq_num >= 0xFFFFFFFFFFFFFFFF {
        return false;
    }
    seq_num++;
    return true;
}

// Unpacks TLSInnerPlaintext: strips trailing 0x00 padding bytes and extracts true ContentType (RFC 8446 §5.4).
// Enforces:
// 1. Decrypted record consisting entirely of zeros (missing inner ContentType) yields unexpected_message.
// 2. Trailing zero-padding stripping is performed without early breaks to eliminate timing side-channels.
// 3. Inner ContentType must be a valid TLS 1.3 type (0x14..0x17), otherwise unexpected_message.
// 4. Plaintext length after removing padding must not exceed 2^14 (16384) bytes, otherwise record_overflow.
// 5. Total inner plaintext cannot exceed 16624 bytes (16640 max ciphertext - 16 bytes tag), otherwise record_overflow.
// 6. Non-application_data records MUST NOT be empty (content_len == 0), otherwise unexpected_message.
// 7. Handles arbitrary zero-padding up to maximum record length without buffer underflow or overflow.
fn unpack_tls_inner_plaintext(decrypted: const u8[:]) -> const u8[:], u8, TlsAlert {
    guard decrypted.len > 0 else {
        return decrypted[..0], 0, TlsAlert.UnexpectedMessage;
    }
    guard decrypted.len <= rfc::TLS_MAX_INNER_PLAINTEXT_LEN else {
        return decrypted[..0], 0, TlsAlert.RecordOverflow;
    }

    var inner_type:  u8  = 0;
    var content_len: i64 = 0;
    var found = false;

    // Backward scan to find the last non-zero byte (inner ContentType)
    for i in decrypted.len {
        let idx = decrypted.len - 1 - i;
        let b = decrypted[idx];
        if !found && b != 0x00 {
            inner_type = b;
            content_len = idx;
            found = true;
        }
    }

    guard found else {
        return decrypted[..0], 0, TlsAlert.UnexpectedMessage;
    }
    guard inner_type >= rfc::TLS_CONTENT_ALERT && inner_type <= rfc::TLS_CONTENT_APPLICATION_DATA else {
        return decrypted[..0], 0, TlsAlert.UnexpectedMessage;
    }
    guard content_len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else {
        return decrypted[..0], 0, TlsAlert.RecordOverflow;
    }
    guard content_len > 0 || inner_type == rfc::TLS_CONTENT_APPLICATION_DATA else {
        return decrypted[..0], 0, TlsAlert.UnexpectedMessage;
    }

    return decrypted[..content_len], inner_type, TlsAlert.CloseNotify;
}

// Compares two 16-byte authentication tags in constant time (RFC 8446 §5.2).
inline fn ct_compare_tag16(a: const u8[16]&, b: const u8[16]&) -> bool {
    var diff: u8 = 0;
    for i in 16 {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

// RFC 8446 Section 5.2: Record Payload Protection - Seals plaintext and inner ContentType into a TLSCiphertext record.
// Writes 5-byte header + encrypted (plaintext || inner_type) + 16-byte AES-128-GCM tag into `out_ciphertext`.
//
// Example:
//   key = [0; 16], iv = [0; 12], seq_num = 0, inner_type = 0x17, plaintext = "ping"
//   returns: total_len = 26, alert = TlsAlert.CloseNotify, ok = true
fn tls_record_seal_aes128_gcm_into(
    key:            const u8[16]&,
    iv:             const u8[12]&,
    seq_num:        u64,
    inner_type:     u8,
    plaintext:      const u8[:],
    out_ciphertext: u8[:],
) -> i64, TlsAlert, bool {
    guard plaintext.len >= 0 && plaintext.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else {
        return 0, TlsAlert.RecordOverflow, false;
    }
    guard inner_type >= rfc::TLS_CONTENT_ALERT && inner_type <= rfc::TLS_CONTENT_APPLICATION_DATA else {
        return 0, TlsAlert.UnexpectedMessage, false;
    }
    var inner_buf: u8[..16640] = [];
    guard inner_buf.try_append(plaintext) && inner_buf.try_push(inner_type) else {
        return 0, TlsAlert.RecordOverflow, false;
    }
    var tag_dummy:       u8[16]      = [0; 16];
    var encrypted_dummy: u8[..16640] = [];
    guard encrypted_dummy.try_append(inner_buf[..]) && encrypted_dummy.try_append(tag_dummy[..]) else {
        return 0, TlsAlert.RecordOverflow, false;
    }

    let nonce, ok_nonce = compute_record_nonce(iv, seq_num);
    guard ok_nonce else {
        return 0, TlsAlert.UnexpectedMessage, false;
    }

    var hdr_buf: u8[..5] = [];
    guard encode_tls_ciphertext_header(
        hdr_buf,
        rfc::TLS_CONTENT_APPLICATION_DATA,
        encrypted_dummy.len as u16,
    ) else {
        return 0, TlsAlert.InternalError, false;
    }

    let tag, ok_seal = core::aes128_gcm_seal_inplace(key, nonce, inner_buf[..], hdr_buf[..]);
    guard ok_seal else {
        return 0, TlsAlert.InternalError, false;
    }

    var record_buf: u8[..16640] = [];
    guard record_buf.try_append(hdr_buf[..]) &&
          record_buf.try_append(inner_buf[..]) &&
          record_buf.try_append(tag[..]) else {
        return 0, TlsAlert.RecordOverflow, false;
    }
    guard out_ciphertext.len >= record_buf.len else {
        return 0, TlsAlert.RecordOverflow, false;
    }
    core::ct_copy_bytes(out_ciphertext[..record_buf.len], record_buf[..]);
    return record_buf.len, TlsAlert.CloseNotify, true;
}

// Decrypts and authenticates a TLS 1.3 record payload into a caller-provided bounded
// buffer `out_plaintext` with zero dynamic heap allocation (RFC 8446 §5.2).
// Enforces:
// - Strict capacity bound: `ct_len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN` (16384) and `out_plaintext.len >= ct_len`,
//   otherwise fails closed with `RecordOverflow` (Invariant 13).
// - Payload length < rfc::TLS_AEAD_TAG_LEN + 1 (17) -> `DecodeError`.
// - Sequence number 2^64 - 1 -> `UnexpectedMessage` (RFC 8446 §5.3).
// - Tag verification failure -> `BadRecordMac`.
//
// Example:
//   record_header = [0x17, 0x03, 0x03, 0x00, 0x15], record_payload = <21 bytes>
//   returns: plain_len = 4, inner_type = 0x17, alert = TlsAlert.CloseNotify, ok = true
fn tls_record_decrypt_aes128_gcm_into(
    key:            const u8[16]&,
    iv:             const u8[12]&,
    seq_num:        u64,
    record_header:  const u8[:],
    record_payload: const u8[:],
    out_plaintext:  u8[:],
) -> i64, u8, TlsAlert, bool {
    guard record_header.len == 5 else { return 0, 0, TlsAlert.DecodeError, false; }
    guard record_payload.len <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else {
        return 0, 0, TlsAlert.RecordOverflow, false;
    }
    guard record_payload.len >= rfc::TLS_AEAD_TAG_LEN + 1 else {
        return 0, 0, TlsAlert.DecodeError, false;
    }

    let ct_len = record_payload.len - rfc::TLS_AEAD_TAG_LEN;
    guard ct_len <= rfc::TLS_MAX_INNER_PLAINTEXT_LEN else {
        return 0, 0, TlsAlert.RecordOverflow, false;
    }

    let nonce, ok_nonce = compute_record_nonce(iv, seq_num);
    guard ok_nonce else { return 0, 0, TlsAlert.UnexpectedMessage, false; }

    let ciphertext = record_payload[..ct_len];
    let tag_slice = record_payload[ct_len..];
    var tag: u8[16] = [0; 16];
    guard tag_slice.len == 16 else { return 0, 0, TlsAlert.DecodeError, false; }
    for i in 16 { tag[i] = tag_slice[i]; }

    var temp_dec: u8[16624] = [0; 16624];
    let dec_len, ok_open = core::fused_aes_gcm_decrypt(
        key, nonce, ciphertext, record_header, tag, temp_dec[..ct_len],
    );
    guard ok_open && dec_len == ct_len else {
        core::secure_zeroize_slice(temp_dec[..ct_len]);
        return 0, 0, TlsAlert.BadRecordMac, false;
    }

    let plain, inner_type, alert = unpack_tls_inner_plaintext(temp_dec[..ct_len]);
    guard alert == TlsAlert.CloseNotify else {
        core::secure_zeroize_slice(temp_dec[..ct_len]);
        return 0, 0, alert, false;
    }

    guard out_plaintext.len >= plain.len else {
        core::secure_zeroize_slice(temp_dec[..ct_len]);
        return 0, 0, TlsAlert.RecordOverflow, false;
    }
    for i in plain.len { out_plaintext[i] = plain[i]; }
    let plain_len = plain.len;
    core::secure_zeroize_slice(temp_dec[..ct_len]);
    return plain_len, inner_type, TlsAlert.CloseNotify, true;
}

// Decrypts and authenticates a TLS 1.3 record payload with AES-128-GCM (RFC 8446 §5.2).
// Invariants enforced:
// 1. Strict alert separation:
//    - Payload length > rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN -> RecordOverflow.
//    - Payload length < rfc::TLS_AEAD_TAG_LEN + 1 (17) -> DecodeError.
//    - Sequence number 2^64 - 1 -> UnexpectedMessage (RFC 8446 §5.3).
//    - Tag verification failure -> BadRecordMac.
// 2. Absolute zero-leakage guarantee: destination buffer is completely wiped on failure.
fn tls_record_decrypt_aes128_gcm(
    key:            const u8[16]&,
    iv:             const u8[12]&,
    seq_num:        u64,
    record_header:  const u8[:],
    record_payload: const u8[:],
    out_plaintext:  u8[>..]&,
) -> u8, TlsAlert {
    out_plaintext.clear();
    guard record_header.len == 5 else {
        return 0, TlsAlert.DecodeError;
    }
    guard record_payload.len <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else {
        return 0, TlsAlert.RecordOverflow;
    }
    guard record_payload.len >= rfc::TLS_AEAD_TAG_LEN + 1 else {
        return 0, TlsAlert.DecodeError;
    }

    let nonce, ok_nonce = compute_record_nonce(iv, seq_num);
    guard ok_nonce else {
        return 0, TlsAlert.UnexpectedMessage;
    }

    let ct_len = record_payload.len - rfc::TLS_AEAD_TAG_LEN;
    guard ct_len <= rfc::TLS_MAX_INNER_PLAINTEXT_LEN else {
        return 0, TlsAlert.RecordOverflow;
    }
    let ciphertext = record_payload[..ct_len];
    let tag_slice = record_payload[ct_len..];
    var tag: u8[16] = [0; 16];
    guard tag_slice.len == 16 else { return 0, TlsAlert.DecodeError; }
    for i in 16 {
        tag[i] = tag_slice[i];
    }

    var temp_dec: u8[16624] = [0; 16624];
    let dec_len, ok_open = core::fused_aes_gcm_decrypt(
        key,
        nonce,
        ciphertext,
        record_header,
        tag,
        temp_dec[..ct_len],
    );
    guard ok_open && dec_len == ct_len else {
        return 0, TlsAlert.BadRecordMac;
    }

    let plain, inner_type, alert = unpack_tls_inner_plaintext(temp_dec[..ct_len]);
    guard alert == TlsAlert.CloseNotify else {
        core::secure_zeroize_slice(temp_dec[..ct_len]);
        return 0, alert;
    }

    out_plaintext.append(plain);
    core::secure_zeroize_slice(temp_dec[..ct_len]);
    return inner_type, TlsAlert.CloseNotify;
}

fn tls_record_seal_aes256_gcm_into(
    key:            const u8[32]&,
    iv:             const u8[12]&,
    seq_num:        u64,
    inner_type:     u8,
    plaintext:      const u8[:],
    out_ciphertext: u8[:],
) -> i64, TlsAlert, bool {
    guard plaintext.len >= 0 && plaintext.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else {
        return 0, TlsAlert.RecordOverflow, false;
    }
    guard inner_type >= rfc::TLS_CONTENT_ALERT && inner_type <= rfc::TLS_CONTENT_APPLICATION_DATA else {
        return 0, TlsAlert.UnexpectedMessage, false;
    }
    var inner_buf: u8[..16640] = [];
    guard inner_buf.try_append(plaintext) && inner_buf.try_push(inner_type) else {
        return 0, TlsAlert.RecordOverflow, false;
    }
    var tag_dummy:       u8[16]      = [0; 16];
    var encrypted_dummy: u8[..16640] = [];
    guard encrypted_dummy.try_append(inner_buf[..]) && encrypted_dummy.try_append(tag_dummy[..]) else {
        return 0, TlsAlert.RecordOverflow, false;
    }

    let nonce, ok_nonce = compute_record_nonce(iv, seq_num);
    guard ok_nonce else {
        return 0, TlsAlert.UnexpectedMessage, false;
    }

    var hdr_buf: u8[..5] = [];
    guard encode_tls_ciphertext_header(
        hdr_buf,
        rfc::TLS_CONTENT_APPLICATION_DATA,
        encrypted_dummy.len as u16,
    ) else {
        return 0, TlsAlert.InternalError, false;
    }

    let tag, ok_seal = core::aes256_gcm_seal_inplace(key, nonce, inner_buf[..], hdr_buf[..]);
    guard ok_seal else {
        return 0, TlsAlert.InternalError, false;
    }

    var record_buf: u8[..16640] = [];
    guard record_buf.try_append(hdr_buf[..]) &&
          record_buf.try_append(inner_buf[..]) &&
          record_buf.try_append(tag[..]) else {
        return 0, TlsAlert.RecordOverflow, false;
    }
    guard out_ciphertext.len >= record_buf.len else {
        return 0, TlsAlert.RecordOverflow, false;
    }
    core::ct_copy_bytes(out_ciphertext[..record_buf.len], record_buf[..]);
    return record_buf.len, TlsAlert.CloseNotify, true;
}

fn tls_record_seal_chacha20_poly1305_into(
    key:            const u8[32]&,
    iv:             const u8[12]&,
    seq_num:        u64,
    inner_type:     u8,
    plaintext:      const u8[:],
    out_ciphertext: u8[:],
) -> i64, TlsAlert, bool {
    guard plaintext.len >= 0 && plaintext.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else {
        return 0, TlsAlert.RecordOverflow, false;
    }
    guard inner_type >= rfc::TLS_CONTENT_ALERT && inner_type <= rfc::TLS_CONTENT_APPLICATION_DATA else {
        return 0, TlsAlert.UnexpectedMessage, false;
    }
    var inner_buf: u8[..16640] = [];
    guard inner_buf.try_append(plaintext) && inner_buf.try_push(inner_type) else {
        return 0, TlsAlert.RecordOverflow, false;
    }
    var tag_dummy:       u8[16]      = [0; 16];
    var encrypted_dummy: u8[..16640] = [];
    guard encrypted_dummy.try_append(inner_buf[..]) && encrypted_dummy.try_append(tag_dummy[..]) else {
        return 0, TlsAlert.RecordOverflow, false;
    }

    let nonce, ok_nonce = compute_record_nonce(iv, seq_num);
    guard ok_nonce else {
        return 0, TlsAlert.UnexpectedMessage, false;
    }

    var hdr_buf: u8[..5] = [];
    guard encode_tls_ciphertext_header(
        hdr_buf,
        rfc::TLS_CONTENT_APPLICATION_DATA,
        encrypted_dummy.len as u16,
    ) else {
        return 0, TlsAlert.InternalError, false;
    }

    let tag, ok_seal = core::chacha20_poly1305_seal_inplace(key, nonce, inner_buf[..], hdr_buf[..]);
    guard ok_seal else {
        return 0, TlsAlert.InternalError, false;
    }

    var record_buf: u8[..16640] = [];
    guard record_buf.try_append(hdr_buf[..]) &&
          record_buf.try_append(inner_buf[..]) &&
          record_buf.try_append(tag[..]) else {
        return 0, TlsAlert.RecordOverflow, false;
    }
    guard out_ciphertext.len >= record_buf.len else {
        return 0, TlsAlert.RecordOverflow, false;
    }
    core::ct_copy_bytes(out_ciphertext[..record_buf.len], record_buf[..]);
    return record_buf.len, TlsAlert.CloseNotify, true;
}

fn tls_record_decrypt_aes256_gcm_into(
    key:            const u8[32]&,
    iv:             const u8[12]&,
    seq_num:        u64,
    record_header:  const u8[:],
    record_payload: const u8[:],
    out_plaintext:  u8[:],
) -> i64, u8, TlsAlert, bool {
    guard record_header.len == 5 else { return 0, 0, TlsAlert.DecodeError, false; }
    guard record_payload.len <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else {
        return 0, 0, TlsAlert.RecordOverflow, false;
    }
    guard record_payload.len >= rfc::TLS_AEAD_TAG_LEN + 1 else {
        return 0, 0, TlsAlert.DecodeError, false;
    }

    let ct_len = record_payload.len - rfc::TLS_AEAD_TAG_LEN;
    guard ct_len <= rfc::TLS_MAX_INNER_PLAINTEXT_LEN else {
        return 0, 0, TlsAlert.RecordOverflow, false;
    }

    let nonce, ok_nonce = compute_record_nonce(iv, seq_num);
    guard ok_nonce else { return 0, 0, TlsAlert.UnexpectedMessage, false; }

    let ciphertext = record_payload[..ct_len];
    let tag_slice = record_payload[ct_len..];
    var tag: u8[16] = [0; 16];
    guard tag_slice.len == 16 else { return 0, 0, TlsAlert.DecodeError, false; }
    for i in 16 { tag[i] = tag_slice[i]; }

    var temp_dec: u8[16624] = [0; 16624];
    let dec_len, ok_open = core::aes256_gcm_open_into(
        key, nonce, ciphertext, record_header, tag, temp_dec[..ct_len],
    );
    guard ok_open && dec_len == ct_len else {
        core::secure_zeroize_slice(temp_dec[..ct_len]);
        return 0, 0, TlsAlert.BadRecordMac, false;
    }

    let plain, inner_type, alert = unpack_tls_inner_plaintext(temp_dec[..ct_len]);
    guard alert == TlsAlert.CloseNotify else {
        core::secure_zeroize_slice(temp_dec[..ct_len]);
        return 0, 0, alert, false;
    }

    guard out_plaintext.len >= plain.len else {
        core::secure_zeroize_slice(temp_dec[..ct_len]);
        return 0, 0, TlsAlert.RecordOverflow, false;
    }
    for i in plain.len { out_plaintext[i] = plain[i]; }
    let plain_len = plain.len;
    core::secure_zeroize_slice(temp_dec[..ct_len]);
    return plain_len, inner_type, TlsAlert.CloseNotify, true;
}

fn tls_record_decrypt_chacha20_poly1305_into(
    key:            const u8[32]&,
    iv:             const u8[12]&,
    seq_num:        u64,
    record_header:  const u8[:],
    record_payload: const u8[:],
    out_plaintext:  u8[:],
) -> i64, u8, TlsAlert, bool {
    guard record_header.len == 5 else { return 0, 0, TlsAlert.DecodeError, false; }
    guard record_payload.len <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else {
        return 0, 0, TlsAlert.RecordOverflow, false;
    }
    guard record_payload.len >= rfc::TLS_AEAD_TAG_LEN + 1 else {
        return 0, 0, TlsAlert.DecodeError, false;
    }

    let ct_len = record_payload.len - rfc::TLS_AEAD_TAG_LEN;
    guard ct_len <= rfc::TLS_MAX_INNER_PLAINTEXT_LEN else {
        return 0, 0, TlsAlert.RecordOverflow, false;
    }

    let nonce, ok_nonce = compute_record_nonce(iv, seq_num);
    guard ok_nonce else { return 0, 0, TlsAlert.UnexpectedMessage, false; }

    let ciphertext = record_payload[..ct_len];
    let tag_slice = record_payload[ct_len..];
    var tag: u8[16] = [0; 16];
    guard tag_slice.len == 16 else { return 0, 0, TlsAlert.DecodeError, false; }
    for i in 16 { tag[i] = tag_slice[i]; }

    var temp_dec: u8[16624] = [0; 16624];
    let dec_len, ok_open = core::chacha20_poly1305_open_into(
        key, nonce, ciphertext, record_header, tag, temp_dec[..ct_len],
    );
    guard ok_open && dec_len == ct_len else {
        core::secure_zeroize_slice(temp_dec[..ct_len]);
        return 0, 0, TlsAlert.BadRecordMac, false;
    }

    let plain, inner_type, alert = unpack_tls_inner_plaintext(temp_dec[..ct_len]);
    guard alert == TlsAlert.CloseNotify else {
        core::secure_zeroize_slice(temp_dec[..ct_len]);
        return 0, 0, alert, false;
    }

    guard out_plaintext.len >= plain.len else {
        core::secure_zeroize_slice(temp_dec[..ct_len]);
        return 0, 0, TlsAlert.RecordOverflow, false;
    }
    for i in plain.len { out_plaintext[i] = plain[i]; }
    let plain_len = plain.len;
    core::secure_zeroize_slice(temp_dec[..ct_len]);
    return plain_len, inner_type, TlsAlert.CloseNotify, true;
}

fn tls_record_seal_into(
    cipher_suite:   u16,
    key:            const u8[:],
    iv:             const u8[12]&,
    seq_num:        u64,
    inner_type:     u8,
    plaintext:      const u8[:],
    out_ciphertext: u8[:],
) -> i64, TlsAlert, bool {
    if cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 {
        guard key.len == 16 else { return 0, TlsAlert.InternalError, false; }
        var key16: u8[16] = [0; 16];
        for i in 16 { key16[i] = key[i]; }
        let n, alert, ok = tls_record_seal_aes128_gcm_into(key16, iv, seq_num, inner_type, plaintext, out_ciphertext);
        core::secure_zeroize_16(key16);
        return n, alert, ok;
    }
    if cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        guard key.len == 32 else { return 0, TlsAlert.InternalError, false; }
        var key32: u8[32] = [0; 32];
        for i in 32 { key32[i] = key[i]; }
        let n, alert, ok = tls_record_seal_aes256_gcm_into(key32, iv, seq_num, inner_type, plaintext, out_ciphertext);
        core::secure_zeroize_32(key32);
        return n, alert, ok;
    }
    if cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        guard key.len == 32 else { return 0, TlsAlert.InternalError, false; }
        var key32: u8[32] = [0; 32];
        for i in 32 { key32[i] = key[i]; }
        let n, alert, ok = tls_record_seal_chacha20_poly1305_into(
            key32, iv, seq_num, inner_type, plaintext, out_ciphertext,
        );
        core::secure_zeroize_32(key32);
        return n, alert, ok;
    }
    return 0, TlsAlert.InternalError, false;
}

fn tls_record_decrypt_into(
    cipher_suite:   u16,
    key:            const u8[:],
    iv:             const u8[12]&,
    seq_num:        u64,
    record_header:  const u8[:],
    record_payload: const u8[:],
    out_plaintext:  u8[:],
) -> i64, u8, TlsAlert, bool {
    if cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 {
        guard key.len == 16 else { return 0, 0, TlsAlert.InternalError, false; }
        var key16: u8[16] = [0; 16];
        for i in 16 { key16[i] = key[i]; }
        let n, inner, alert, ok = tls_record_decrypt_aes128_gcm_into(
            key16, iv, seq_num, record_header, record_payload, out_plaintext,
        );
        core::secure_zeroize_16(key16);
        return n, inner, alert, ok;
    }
    if cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        guard key.len == 32 else { return 0, 0, TlsAlert.InternalError, false; }
        var key32: u8[32] = [0; 32];
        for i in 32 { key32[i] = key[i]; }
        let n, inner, alert, ok = tls_record_decrypt_aes256_gcm_into(
            key32, iv, seq_num, record_header, record_payload, out_plaintext,
        );
        core::secure_zeroize_32(key32);
        return n, inner, alert, ok;
    }
    if cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        guard key.len == 32 else { return 0, 0, TlsAlert.InternalError, false; }
        var key32: u8[32] = [0; 32];
        for i in 32 { key32[i] = key[i]; }
        let n, inner, alert, ok = tls_record_decrypt_chacha20_poly1305_into(
            key32,
            iv,
            seq_num,
            record_header,
            record_payload,
            out_plaintext,
        );
        core::secure_zeroize_32(key32);
        return n, inner, alert, ok;
    }
    return 0, 0, TlsAlert.InternalError, false;
}

// DoS filter tracking consecutive empty records, early data skipped volume, and CCS records.
struct RecordFilterState {
    empty_records_count:      i32 = 0,
    early_data_skipped_bytes: i64 = 0,
    ccs_count:                i32 = 0,
}

fn check_record_payload_length(state: RecordFilterState&, payload_len: i64, is_early_data: bool) -> TlsAlert {
    guard payload_len >= 0 && payload_len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else {
        return TlsAlert.RecordOverflow;
    }

    if payload_len == 0 {
        state.empty_records_count++;
        guard state.empty_records_count <= MAX_EMPTY_RECORDS else {
            return TlsAlert.UnexpectedMessage;
        }
    } else {
        state.empty_records_count = 0;
    }

    if is_early_data {
        guard state.early_data_skipped_bytes >= 0 && state.early_data_skipped_bytes <= MAX_EARLY_DATA_SKIPPED else {
            return TlsAlert.UnexpectedMessage;
        }
        guard payload_len <= MAX_EARLY_DATA_SKIPPED - state.early_data_skipped_bytes else {
            return TlsAlert.UnexpectedMessage;
        }
        state.early_data_skipped_bytes += payload_len;
    }
    return TlsAlert.CloseNotify;
}

// Encodes the 5-byte TLSCiphertext record header (RFC 8446 §5.2).
// In TLS 1.3, TLSCiphertext outer content type MUST be application_data (0x17).
// Length MUST be at least 17 bytes (1 byte inner content type + 16 bytes AEAD tag)
// and at most rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN (16640 bytes).
inline fn encode_tls_ciphertext_header<B>(out: B&, content_type: u8, ciphertext_len: u16) -> bool {
    guard ciphertext_len >= 17 && (ciphertext_len as i64) <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else {
        return false;
    }
    guard content_type == rfc::TLS_CONTENT_APPLICATION_DATA else {
        return false;
    }
    guard core::add_sat_i64(out.len, 5) <= out.cap else {
        return false;
    }
    out.push(content_type);
    out.push(((rfc::TLS_LEGACY_VERSION_1_2 >> 8) & 0xFF) as u8);
    out.push((rfc::TLS_LEGACY_VERSION_1_2 & 0xFF) as u8);
    out.push(((ciphertext_len >> 8) & 0xFF) as u8);
    out.push((ciphertext_len & 0xFF) as u8);
    return true;
}

// Parses 5-byte record header and validates RFC 8446 length bounds and legacy version.
//
// Example:
//   hdr_bytes = [0x17, 0x03, 0x03, 0x00, 0x10]
//   returns: content_type = 23, version = 0x0303, length = 16, alert = TlsAlert.CloseNotify, ok = true
fn parse_tls_record_header(hdr_bytes: const u8[:]) -> u8, u16, u16, TlsAlert, bool {
    var cursor: i64 = 0;
    return parse_tls_record_header_at(hdr_bytes, cursor);
}

// Parses a 5-byte TLS record header from `raw` at `cursor` and advances `cursor` by 5 on success.
// Leaves `cursor` unchanged on error.
//
// Example:
//   raw = [0x17, 0x03, 0x03, 0x00, 0x10], cursor = 0
//   returns: content_type = 23, version = 0x0303, length = 16, alert = TlsAlert.CloseNotify, ok = true, cursor = 5
fn parse_tls_record_header_at(
    raw:    const u8[:],
    cursor: i64&,
) -> u8, u16, u16, TlsAlert, bool {
    let saved = cursor;
    var content_type: u8  = 0;
    var version:      u16 = 0;
    var length:       u16 = 0;
    guard slice_get_u8(raw, cursor, content_type) &&
          slice_get_u16(raw, cursor, version) &&
          slice_get_u16(raw, cursor, length) else {
        cursor = saved;
        return 0, 0, 0, TlsAlert.DecodeError, false;
    }

    if version != rfc::TLS_LEGACY_VERSION_1_2 && version != rfc::TLS_LEGACY_VERSION_1_0 {
        cursor = saved;
        return content_type, version, length, TlsAlert.ProtocolVersion, false;
    }
    if content_type < rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC || content_type > rfc::TLS_CONTENT_APPLICATION_DATA {
        cursor = saved;
        return content_type, version, length, TlsAlert.UnexpectedMessage, false;
    }
    if length > rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN {
        cursor = saved;
        return content_type, version, length, TlsAlert.RecordOverflow, false;
    }
    return content_type, version, length, TlsAlert.CloseNotify, true;
}

// Validates RFC 8446 Appendix D.4 Middlebox Compatibility Dummy ChangeCipherSpec record.
// A CCS record MUST contain exactly one single byte of value 0x01.
// Any other length or content MUST trigger DecodeError or UnexpectedMessage.
inline fn validate_change_cipher_spec_record(payload: const u8[:]) -> TlsAlert {
    if payload.len != 1 {
        return TlsAlert.DecodeError;
    }
    if !rfc::is_valid_ccs_payload(payload) {
        return TlsAlert.UnexpectedMessage;
    }
    return TlsAlert.CloseNotify;
}

// Validates RFC 8446 Appendix D.4 Middlebox Compatibility ChangeCipherSpec record with state & flood protection:
// 1. Must occur during active handshake (after ClientHello, before Finished). If not, UnexpectedMessage.
// 2. Flood protection (OpenSSL #10065 / CVE-2020-1967): at most 1 CCS record allowed during handshake.
//    Any subsequent CCS record triggers UnexpectedMessage.
// 3. Payload must be exactly 1 byte of value 0x01. If wrong length -> DecodeError; wrong value -> UnexpectedMessage.
fn check_change_cipher_spec_record(
    state:            RecordFilterState&,
    payload:          const u8[:],
    handshake_active: bool,
) -> TlsAlert {
    guard handshake_active else {
        return TlsAlert.UnexpectedMessage;
    }
    guard state.ccs_count < rfc::MAX_CCS_RECORDS else {
        return TlsAlert.UnexpectedMessage;
    }
    let alert = validate_change_cipher_spec_record(payload);
    guard alert == TlsAlert.CloseNotify else {
        return alert;
    }
    state.ccs_count++;
    return TlsAlert.CloseNotify;
}

// ---- QUIC Crypto Gateway & Header Protection (RFC 9001) ------------------

enum QuicEncryptionLevel {
    Initial,     // ssl_encryption_initial (0)
    EarlyData,   // ssl_encryption_early_data (1)
    Handshake,   // ssl_encryption_handshake (2)
    Application, // ssl_encryption_application (3)
}

inline fn quic_encryption_level_to_u8(level: QuicEncryptionLevel) -> u8 {
    return match level {
        Initial => 0,
        EarlyData => 1,
        Handshake => 2,
        Application => 3,
    };
}

enum QuicOutputEvent {
    None,
    SetReadSecret { level: QuicEncryptionLevel, cipher_id: u16, secret: u8[..48] = [], secret_len: u8 = 0 },
    SetWriteSecret { level: QuicEncryptionLevel, cipher_id: u16, secret: u8[..48] = [], secret_len: u8 = 0 },
    AddHandshakeData { level: QuicEncryptionLevel, data: const u8[:] = [] },
    FlushFlight,
    SendAlert { level: QuicEncryptionLevel, alert: TlsAlert },
}

// Extracts 16-byte Header Protection sample from QUIC packet at offset pn_offset + 4 (RFC 9001 Section 5.4.2).
inline fn quic_extract_hp_sample(pkt: const u8[:], pn_offset: u32) -> const u8[:], bool {
    guard pn_offset > 0 else {
        return pkt[..0], false;
    }
    let sample_offset = (pn_offset as i64) + 4;
    guard sample_offset + 16 <= pkt.len else {
        return pkt[..0], false;
    }
    return pkt[sample_offset..sample_offset + 16], true;
}

// Connection container for QUIC Crypto state machine isolation.
struct QuicCryptoConn {
    read_level:  QuicEncryptionLevel  = QuicEncryptionLevel.Initial,
    write_level: QuicEncryptionLevel  = QuicEncryptionLevel.Initial,
    events:      QuicOutputEvent[..8] = [],
}

fn new_quic_crypto_conn() -> QuicCryptoConn {
    return QuicCryptoConn {
        read_level:  QuicEncryptionLevel.Initial,
        write_level: QuicEncryptionLevel.Initial,
        events:      [],
    };
}

// Validates RFC 9001 invariants on incoming QUIC handshake bytes:
// 1. Encryption level must match current read_level.
// 2. CRYPTO frames cannot be empty (DecodeError) or exceed quota (RecordOverflow).
// Handshake messages (e.g. Finished with type 20 / 0x14) and payload data are valid in QUIC CRYPTO.
fn provide_quic_data(conn: QuicCryptoConn&, level: QuicEncryptionLevel, data: const u8[:]) -> TlsAlert {
    guard quic_encryption_level_to_u8(level) == quic_encryption_level_to_u8(conn.read_level) else {
        return TlsAlert.UnexpectedMessage;
    }
    guard data.len > 0 else {
        return TlsAlert.DecodeError;
    }
    guard data.len <= MAX_QUIC_CRYPTO_BUFFER_LEN else {
        return TlsAlert.RecordOverflow;
    }
    return TlsAlert.CloseNotify;
}

const MAX_QUIC_CRYPTO_BUFFER_LEN: i64 = 16384; // 16KB max handshake flight per encryption level

struct QuicCryptoStream {
    consumed_offset: u64         = 0,
    buf:             u8[..16384] = [],
}

fn new_quic_crypto_stream() -> QuicCryptoStream {
    return QuicCryptoStream {
        consumed_offset: 0,
        buf:             [],
    };
}

// Ingests a QUIC CRYPTO frame (RFC 9000 §19.6 / RFC 9001 §4).
// Handles:
// - Offset + Length 64-bit integer overflow and 2^62 - 1 varint maximum bounds protection
// - Total buffer size quota (MAX_QUIC_CRYPTO_BUFFER_LEN)
// - Out-of-order offset gap detection (returns false if offset > consumed_offset)
// - Redundant duplicate frame detection (safely dropped if offset + len <= consumed_offset)
// - Overlapping frame trimming (trims already received prefix)
fn quic_crypto_stream_ingest(
    stream: QuicCryptoStream&,
    offset: u64,
    data:   const u8[:],
) -> bool, i64 {
    // 1. Integer overflow check: offset + data.len must not wrap around u64 or exceed 2^62 - 1
    guard offset <= rfc::QUIC_VARINT_MAX else { return false, 0; }
    let end_offset = offset + (data.len as u64);
    guard end_offset >= offset && end_offset <= rfc::QUIC_VARINT_MAX else { return false, 0; }

    // 2. If end_offset <= stream.consumed_offset, entirely duplicate data; safely drop 0 new bytes
    if end_offset <= stream.consumed_offset {
        return true, 0;
    }

    // 3. Offset gap detection: we do not permit gaps (cannot skip handshake bytes)
    guard offset <= stream.consumed_offset else {
        return false, 0;
    }

    // 4. Overlapping data handling: trim already consumed prefix
    let skip = (stream.consumed_offset - offset) as i64;
    let new_data = data[skip..];

    // 5. Buffer quota check
    let new_len = stream.buf.len + new_data.len;
    guard new_len <= stream.buf.cap else {
        return false, 0;
    }

    stream.buf.append(new_data);
    stream.consumed_offset += (new_data.len as u64);
    return true, new_data.len;
}
