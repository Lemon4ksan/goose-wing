// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation TLS 1.3 Record Layer and RFC 9001 QUIC Crypto adapter.
// Conforms to RFC 8446 Section 5, RFC 9001 Section 5.4, and BoringSSL/BearSSL safety models.
namespace tls;

import std;
import core;
import .internal;

// ---- TLS 1.3 Alert Codes (RFC 8446 Section 6) ---------------------------

enum Alert {
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

checkfree inline fn alert_to_u8(alert: Alert) -> u8 {
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

checkfree fn u8_to_alert(code: u8) -> Alert, bool {
    let alert = match code {
        rfc::TLS_ALERT_CLOSE_NOTIFY => Alert.CloseNotify,
        rfc::TLS_ALERT_UNEXPECTED_MESSAGE => Alert.UnexpectedMessage,
        rfc::TLS_ALERT_BAD_RECORD_MAC => Alert.BadRecordMac,
        rfc::TLS_ALERT_RECORD_OVERFLOW => Alert.RecordOverflow,
        rfc::TLS_ALERT_HANDSHAKE_FAILURE => Alert.HandshakeFailure,
        rfc::TLS_ALERT_BAD_CERTIFICATE => Alert.BadCertificate,
        rfc::TLS_ALERT_UNSUPPORTED_CERTIFICATE => Alert.UnsupportedCertificate,
        rfc::TLS_ALERT_CERTIFICATE_REVOKED => Alert.CertificateRevoked,
        rfc::TLS_ALERT_CERTIFICATE_EXPIRED => Alert.CertificateExpired,
        rfc::TLS_ALERT_CERTIFICATE_UNKNOWN => Alert.CertificateUnknown,
        rfc::TLS_ALERT_ILLEGAL_PARAMETER => Alert.IllegalParameter,
        rfc::TLS_ALERT_UNKNOWN_CA => Alert.UnknownCa,
        rfc::TLS_ALERT_ACCESS_DENIED => Alert.AccessDenied,
        rfc::TLS_ALERT_DECODE_ERROR => Alert.DecodeError,
        rfc::TLS_ALERT_DECRYPT_ERROR => Alert.DecryptError,
        rfc::TLS_ALERT_PROTOCOL_VERSION => Alert.ProtocolVersion,
        rfc::TLS_ALERT_INSUFFICIENT_SECURITY => Alert.InsufficientSecurity,
        rfc::TLS_ALERT_INTERNAL_ERROR => Alert.InternalError,
        rfc::TLS_ALERT_INAPPROPRIATE_FALLBACK => Alert.InappropriateFallback,
        rfc::TLS_ALERT_USER_CANCELED => Alert.UserCanceled,
        rfc::TLS_ALERT_MISSING_EXTENSION => Alert.MissingExtension,
        rfc::TLS_ALERT_UNSUPPORTED_EXTENSION => Alert.UnsupportedExtension,
        rfc::TLS_ALERT_UNRECOGNIZED_NAME => Alert.UnrecognizedName,
        rfc::TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE => Alert.BadCertificateStatusResponse,
        rfc::TLS_ALERT_UNKNOWN_PSK_IDENTITY => Alert.UnknownPskIdentity,
        rfc::TLS_ALERT_CERTIFICATE_REQUIRED => Alert.CertificateRequired,
        rfc::TLS_ALERT_NO_APPLICATION_PROTOCOL => Alert.NoApplicationProtocol,
        _ => Alert.DecodeError,
    };
    if alert == Alert.DecodeError && code != rfc::TLS_ALERT_DECODE_ERROR {
        return Alert.DecodeError, false;
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
//   returns: level = 2, alert = Alert.DecodeError, is_fatal = true, ok = true
checkfree fn parse_alert_message(data: const u8[:]) -> u8, Alert, bool, bool {
    guard data.len == 2 else {
        return 0, Alert.DecodeError, true, false;
    }
    let level = data[0];
    let desc = data[1];

    guard level == 1 || level == 2 else {
        return level, Alert.DecodeError, true, false;
    }

    let alert, alert_ok = u8_to_alert(desc);
    guard alert_ok else {
        return level, Alert.DecodeError, true, false;
    }

    var is_fatal = true;
    if level == 1 {
        if desc == rfc::TLS_ALERT_CLOSE_NOTIFY || desc == rfc::TLS_ALERT_USER_CANCELED {
            is_fatal = false;
        }
    }
    return level, alert, is_fatal, true;
}

// ---- Zero-Copy Slice Cursor Helpers ---------------------------------------

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

// Reads a single unsigned byte from `raw` at `cursor` and advances `cursor` by 1.
//
// Example:
//   raw = [0x17, 0x03], cursor = 0
//   returns: out = 0x17, ok = true, cursor = 1
checkfree inline fn slice_get_u8(raw: const u8[:], cursor: i64&, out: u8&) -> bool {
    let pos = cursor;
    guard pos >= 0 && pos < raw.len else {
        return false;
    }
    out = raw[pos];
    cursor = pos + 1;
    return true;
}

// Reads a single unsigned byte directly from `raw` at `cursor` (Rule 9 value return).
//
// Example:
//   raw = [0x17, 0x03], cursor = 0
//   returns: val = 0x17, ok = true, cursor = 1
checkfree inline fn slice_read_u8(raw: const u8[:], cursor: i64&) -> u8, bool {
    let pos = cursor;
    guard pos >= 0 && pos < raw.len else {
        return 0, false;
    }
    let val = raw[pos];
    cursor = pos + 1;
    return val, true;
}

// Reads a big-endian 16-bit unsigned integer from `raw` at `cursor` and advances `cursor` by 2.
//
// Example:
//   raw = [0x03, 0x03], cursor = 0
//   returns: out = 0x0303, ok = true, cursor = 2
checkfree inline fn slice_get_u16(raw: const u8[:], cursor: i64&, out: u16&) -> bool {
    let pos = cursor;
    guard pos >= 0 && pos <= raw.len else { return false; }
    let tail = raw[pos..];
    guard tail.len >= 2 else { return false; }
    out = tls_be_u16_head(tail);
    cursor = pos + 2;
    return true;
}

// Reads a big-endian 16-bit integer directly from `raw` at `cursor` (Rule 9 value return).
//
// Example:
//   raw = [0x03, 0x03], cursor = 0
//   returns: val = 0x0303, ok = true, cursor = 2
checkfree inline fn slice_read_u16(raw: const u8[:], cursor: i64&) -> u16, bool {
    let pos = cursor;
    guard pos >= 0 && pos <= raw.len else { return 0, false; }
    let tail = raw[pos..];
    guard tail.len >= 2 else { return 0, false; }
    let val = tls_be_u16_head(tail);
    cursor = pos + 2;
    return val, true;
}

// Reads a big-endian 24-bit unsigned integer from `raw` at `cursor` and advances `cursor` by 3.
//
// Example:
//   raw = [0x00, 0x01, 0x02], cursor = 0
//   returns: out = 0x000102, ok = true, cursor = 3
checkfree inline fn slice_get_u24(raw: const u8[:], cursor: i64&, out: u32&) -> bool {
    let pos = cursor;
    guard pos >= 0 && pos <= raw.len else { return false; }
    let tail = raw[pos..];
    guard tail.len >= 3 else { return false; }
    out = tls_be_u24_head(tail);
    cursor = pos + 3;
    return true;
}

// Reads a big-endian 24-bit integer directly from `raw` at `cursor` (Rule 9 value return).
//
// Example:
//   raw = [0x00, 0x01, 0x02], cursor = 0
//   returns: val = 0x000102, ok = true, cursor = 3
checkfree inline fn slice_read_u24(raw: const u8[:], cursor: i64&) -> u32, bool {
    let pos = cursor;
    guard pos >= 0 && pos <= raw.len else { return 0, false; }
    let tail = raw[pos..];
    guard tail.len >= 3 else { return 0, false; }
    let val = tls_be_u24_head(tail);
    cursor = pos + 3;
    return val, true;
}

// Reads a big-endian 32-bit unsigned integer from `raw` at `cursor` and advances `cursor` by 4.
//
// Example:
//   raw = [0x01, 0x02, 0x03, 0x04], cursor = 0
//   returns: out = 0x01020304, ok = true, cursor = 4
checkfree inline fn slice_get_u32(raw: const u8[:], cursor: i64&, out: u32&) -> bool {
    let pos = cursor;
    guard pos >= 0 && pos <= raw.len else { return false; }
    let tail = raw[pos..];
    guard tail.len >= 4 else { return false; }
    out = tls_be_u32_head(tail);
    cursor = pos + 4;
    return true;
}

// Reads a big-endian 32-bit integer directly from `raw` at `cursor` (Rule 9 value return).
//
// Example:
//   raw = [0x01, 0x02, 0x03, 0x04], cursor = 0
//   returns: val = 0x01020304, ok = true, cursor = 4
checkfree inline fn slice_read_u32(raw: const u8[:], cursor: i64&) -> u32, bool {
    let pos = cursor;
    guard pos >= 0 && pos <= raw.len else { return 0, false; }
    let tail = raw[pos..];
    guard tail.len >= 4 else { return 0, false; }
    let val = tls_be_u32_head(tail);
    cursor = pos + 4;
    return val, true;
}

// Extracts a zero-copy slice of `count` bytes from `raw` at `cursor` and advances `cursor` by `count`.
//
// Example:
//   raw = "hello", cursor = 1, count = 3
//   returns: sub = "ell", ok = true, cursor = 4
checkfree inline fn slice_get_bytes(raw: const u8[:], cursor: i64&, count: i64) -> const u8[:], bool {
    let pos = cursor;
    guard count >= 0 && pos >= 0 && pos <= raw.len else {
        return raw[..0], false;
    }
    let tail = raw[pos..];
    guard count <= tail.len else {
        return raw[..0], false;
    }
    let sub = tail[..count];
    cursor = pos + count;
    return sub, true;
}

// Extracts a 1-byte length-prefixed slice from `raw` at `cursor`.
// Leaves `cursor` unchanged on error.
//
// Example:
//   raw = [0x02, 0xAA, 0xBB], cursor = 0
//   returns: sub = [0xAA, 0xBB], ok = true, cursor = 3
checkfree fn slice_get_u8_length_prefixed(raw: const u8[:], cursor: i64&) -> const u8[:], bool {
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
checkfree fn slice_get_u16_length_prefixed(raw: const u8[:], cursor: i64&) -> const u8[:], bool {
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
checkfree fn slice_get_u24_length_prefixed(raw: const u8[:], cursor: i64&) -> const u8[:], bool {
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

// ---- TLS Record Layer Framing & Invariants (RFC 8446 Section 5) ---------

// RFC 8446 §5.1 / BoringSSL single-MSS TCP Slow Start record size (1460 - 60 - 22).
const SINGLE_MSS_PLAINTEXT_LEN: i64 = 1378;
// 64 KB Slow Start threshold before scaling to 16 KB records.
const DYNAMIC_RESIZE_THRESHOLD_BYTES: u64 = 65536;

// RFC 8446 Section 5.5: Limits on Key Usage - AEAD confidentiality record ceilings.
const TLS_AES_GCM_KEY_UPDATE_LIMIT:   u64 = 16777216;   // 2^24 records (below 2^24.5 AES-GCM bound)
const TLS_AES_GCM_HARD_RECORD_LIMIT:  u64 = 23500000;   // Hard fail-closed ceiling below 2^24.5
const TLS_CHACHA20_KEY_UPDATE_LIMIT:  u64 = 1073741824; // 2^30 records for ChaCha20-Poly1305
const TLS_CHACHA20_HARD_RECORD_LIMIT: u64 = 2147483648; // 2^31 hard fail-closed ceiling

// RFC 8446 Section 5.5: Limits on Key Usage - Reports whether the record sequence number
// has reached the threshold requiring an automatic KeyUpdate before further encryption.
checkfree inline fn aead_needs_key_update(cipher_suite: u16, seq_num: u64) -> bool {
    let limit = if cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        TLS_CHACHA20_KEY_UPDATE_LIMIT
    } else {
        TLS_AES_GCM_KEY_UPDATE_LIMIT
    };
    return seq_num >= limit;
}

// RFC 8446 Section 5.5: Limits on Key Usage - Reports whether the record sequence number
// has reached or exceeded the fail-closed ceiling where further AEAD usage is forbidden.
checkfree inline fn aead_exceeds_hard_limit(cipher_suite: u16, seq_num: u64) -> bool {
    let limit = if cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        TLS_CHACHA20_HARD_RECORD_LIMIT
    } else {
        TLS_AES_GCM_HARD_RECORD_LIMIT
    };
    return seq_num >= limit;
}

// Computes 96-bit (12-byte) per-record nonce: N = iv ^ (0^32 || be64(seq_num))
// Rejects 2^64 - 1 to prevent counter wraparound and nonce reuse (RFC 8446 Section 5.3).
checkfree inline fn compute_record_nonce(iv: const u8[12]&, seq_num: u64) -> u8[12], bool {
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
checkfree inline fn increment_record_seq_num(seq_num: u64&) -> bool {
    if seq_num >= 0xFFFFFFFFFFFFFFFF {
        return false;
    }
    seq_num++;
    return true;
}

// Unpacks TLSInnerPlaintext: strips trailing 0x00 padding bytes and extracts true ContentType (RFC 8446 §5.4).
// Enforces constant-time trailing zero scan, valid inner ContentType (0x14..0x17), max plaintext length
// (16384 bytes), and non-empty non-application_data records.
//
// Example:
//   decrypted = ['o', 'k', 0x17, 0x00, 0x00]
//   returns: plain = "ok", content_type = 0x17, alert = Alert.CloseNotify
checkfree fn unpack_inner_plaintext(decrypted: const u8[:]) -> const u8[:], u8, Alert {
    guard decrypted.len > 0 else {
        return decrypted[..0], 0, Alert.UnexpectedMessage;
    }
    guard decrypted.len <= rfc::TLS_MAX_INNER_PLAINTEXT_LEN else {
        return decrypted[..0], 0, Alert.RecordOverflow;
    }

    var last_nz: i64  = 0;
    var found:   bool = false;
    // Constant-time full scan without early break to locate the last non-zero inner ContentType byte.
    for b, i in decrypted {
        if b != 0x00 {
            last_nz = i;
            found = true;
        }
    }
    guard found && last_nz >= 0 && last_nz < decrypted.len else {
        return decrypted[..0], 0, Alert.UnexpectedMessage;
    }

    let content_type = decrypted[last_nz];
    let plain = decrypted[..last_nz];
    guard content_type >= rfc::TLS_CONTENT_ALERT && content_type <= rfc::TLS_CONTENT_APPLICATION_DATA else {
        return decrypted[..0], 0, Alert.UnexpectedMessage;
    }
    guard plain.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else {
        return decrypted[..0], 0, Alert.RecordOverflow;
    }
    guard plain.len > 0 || content_type == rfc::TLS_CONTENT_APPLICATION_DATA else {
        return decrypted[..0], 0, Alert.UnexpectedMessage;
    }

    return plain, content_type, Alert.CloseNotify;
}

// Compares two 16-byte authentication tags in constant time (RFC 8446 §5.2).
checkfree inline fn ct_compare_tag16(a: const u8[16]&, b: const u8[16]&) -> bool {
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
//   returns: total_len = 26, alert = Alert.CloseNotify, ok = true
fn record_seal_aes128_gcm_into(
    key:            const u8[16]&,
    iv:             const u8[12]&,
    seq_num:        u64,
    inner_type:     u8,
    plaintext:      const u8[:],
    out_ciphertext: u8[:],
) -> i64, Alert, bool {
    let inner_len = core::add_sat_i64(plaintext.len, 1);
    let ct_body_len = core::add_sat_i64(inner_len, rfc::TLS_AEAD_TAG_LEN);
    let ct_body_u16 = (ct_body_len & 0xFFFF) as u16;
    let total_len = core::add_sat_i64(5, ct_body_len);
    let plain_end = core::add_sat_i64(5, plaintext.len);
    let inner_end = core::add_sat_i64(5, inner_len);
    guard plaintext.len >= 0 && plaintext.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else {
        return 0, Alert.RecordOverflow, false;
    }
    guard inner_type >= rfc::TLS_CONTENT_ALERT && inner_type <= rfc::TLS_CONTENT_APPLICATION_DATA else {
        return 0, Alert.UnexpectedMessage, false;
    }
    guard out_ciphertext.len >= total_len else {
        return 0, Alert.RecordOverflow, false;
    }

    let nonce, ok_nonce = compute_record_nonce(iv, seq_num);
    guard ok_nonce else {
        return 0, Alert.UnexpectedMessage, false;
    }

    var hdr_buf: u8[..5] = [];
    guard encode_ciphertext_header(
        hdr_buf,
        rfc::TLS_CONTENT_APPLICATION_DATA,
        ct_body_u16,
    ) else {
        return 0, Alert.InternalError, false;
    }

    core::ct_copy_bytes(out_ciphertext[..5], hdr_buf[..]);
    core::ct_copy_bytes(out_ciphertext[5..plain_end], plaintext);
    out_ciphertext[plain_end] = inner_type;

    let tag, ok_seal = core::aes128_gcm_seal_inplace(
        key,
        nonce,
        out_ciphertext[5..inner_end],
        out_ciphertext[..5],
    );
    guard ok_seal else {
        core::secure_zeroize_slice(out_ciphertext[..total_len]);
        return 0, Alert.InternalError, false;
    }
    core::ct_copy_bytes(out_ciphertext[inner_end..total_len], tag[..]);
    return total_len, Alert.CloseNotify, true;
}

// Decrypts and authenticates a TLS 1.3 record payload into a caller-provided bounded
// buffer `out_plaintext` with zero dynamic heap allocation (RFC 8446 §5.2).
//
// Example:
//   record_header = [0x17, 0x03, 0x03, 0x00, 0x15], record_payload = <21 bytes>
//   returns: plain_len = 4, inner_type = 0x17, alert = Alert.CloseNotify, ok = true
fn record_decrypt_aes128_gcm_into(
    key:            const u8[16]&,
    iv:             const u8[12]&,
    seq_num:        u64,
    record_header:  const u8[:],
    record_payload: const u8[:],
    out_plaintext:  u8[:],
) -> i64, u8, Alert, bool {
    guard record_header.len == 5 else { return 0, 0, Alert.DecodeError, false; }
    guard record_payload.len <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else {
        return 0, 0, Alert.RecordOverflow, false;
    }
    guard record_payload.len >= rfc::TLS_AEAD_TAG_LEN + 1 else {
        return 0, 0, Alert.DecodeError, false;
    }

    let ct_len = record_payload.len - rfc::TLS_AEAD_TAG_LEN;
    guard ct_len <= rfc::TLS_MAX_INNER_PLAINTEXT_LEN && out_plaintext.len >= ct_len else {
        return 0, 0, Alert.RecordOverflow, false;
    }

    let nonce, ok_nonce = compute_record_nonce(iv, seq_num);
    guard ok_nonce else { return 0, 0, Alert.UnexpectedMessage, false; }

    let ciphertext = record_payload[..ct_len];
    let tag_slice = record_payload[ct_len..];
    var tag: u8[16] = [0; 16];
    guard tag_slice.len == 16 else { return 0, 0, Alert.DecodeError, false; }
    for i in 16 { tag[i] = tag_slice[i]; }

    let dec_len, ok_open = core::fused_aes_gcm_decrypt(
        key, nonce, ciphertext, record_header, tag, out_plaintext[..ct_len],
    );
    guard ok_open && dec_len == ct_len else {
        core::secure_zeroize_slice(out_plaintext[..ct_len]);
        return 0, 0, Alert.BadRecordMac, false;
    }

    let plain, inner_type, alert = unpack_inner_plaintext(out_plaintext[..ct_len]);
    guard alert == Alert.CloseNotify else {
        core::secure_zeroize_slice(out_plaintext[..ct_len]);
        return 0, 0, alert, false;
    }

    let plain_len = plain.len;
    core::secure_zeroize_slice(out_plaintext[plain_len..ct_len]);
    return plain_len, inner_type, Alert.CloseNotify, true;
}

// Decrypts and authenticates a TLS 1.3 record payload with AES-128-GCM (RFC 8446 §5.2).
// Clears `out_plaintext` on every error path to guarantee zero partial leakage.
fn record_decrypt_aes128_gcm(
    key:            const u8[16]&,
    iv:             const u8[12]&,
    seq_num:        u64,
    record_header:  const u8[:],
    record_payload: const u8[:],
    out_plaintext:  u8[>..]&,
) -> u8, Alert {
    var committed = false;
    defer if !committed { out_plaintext.clear(); };
    guard record_header.len == 5 else {
        return 0, Alert.DecodeError;
    }
    guard record_payload.len <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else {
        return 0, Alert.RecordOverflow;
    }
    guard record_payload.len >= rfc::TLS_AEAD_TAG_LEN + 1 else {
        return 0, Alert.DecodeError;
    }

    let nonce, ok_nonce = compute_record_nonce(iv, seq_num);
    guard ok_nonce else {
        return 0, Alert.UnexpectedMessage;
    }

    let ct_len = record_payload.len - rfc::TLS_AEAD_TAG_LEN;
    guard ct_len <= rfc::TLS_MAX_INNER_PLAINTEXT_LEN else {
        return 0, Alert.RecordOverflow;
    }
    let ciphertext = record_payload[..ct_len];
    let tag_slice = record_payload[ct_len..];
    var tag: u8[16] = [0; 16];
    guard tag_slice.len == 16 else { return 0, Alert.DecodeError; }
    for i in 16 {
        tag[i] = tag_slice[i];
    }

    var temp_dec: u8[16624] = [0; 16624];
    defer core::secure_zeroize_slice(temp_dec[..ct_len]);
    let dec_len, ok_open = core::fused_aes_gcm_decrypt(
        key,
        nonce,
        ciphertext,
        record_header,
        tag,
        temp_dec[..ct_len],
    );
    guard ok_open && dec_len == ct_len else {
        return 0, Alert.BadRecordMac;
    }

    let plain, inner_type, alert = unpack_inner_plaintext(temp_dec[..ct_len]);
    guard alert == Alert.CloseNotify else {
        return 0, alert;
    }

    out_plaintext.clear();
    out_plaintext.append(plain);
    committed = true;
    return inner_type, Alert.CloseNotify;
}

fn record_seal_aes256_gcm_into(
    key:            const u8[32]&,
    iv:             const u8[12]&,
    seq_num:        u64,
    inner_type:     u8,
    plaintext:      const u8[:],
    out_ciphertext: u8[:],
) -> i64, Alert, bool {
    let inner_len = core::add_sat_i64(plaintext.len, 1);
    let ct_body_len = core::add_sat_i64(inner_len, rfc::TLS_AEAD_TAG_LEN);
    let ct_body_u16 = (ct_body_len & 0xFFFF) as u16;
    let total_len = core::add_sat_i64(5, ct_body_len);
    let plain_end = core::add_sat_i64(5, plaintext.len);
    let inner_end = core::add_sat_i64(5, inner_len);
    guard plaintext.len >= 0 && plaintext.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else {
        return 0, Alert.RecordOverflow, false;
    }
    guard inner_type >= rfc::TLS_CONTENT_ALERT && inner_type <= rfc::TLS_CONTENT_APPLICATION_DATA else {
        return 0, Alert.UnexpectedMessage, false;
    }
    guard out_ciphertext.len >= total_len else {
        return 0, Alert.RecordOverflow, false;
    }

    let nonce, ok_nonce = compute_record_nonce(iv, seq_num);
    guard ok_nonce else {
        return 0, Alert.UnexpectedMessage, false;
    }

    var hdr_buf: u8[..5] = [];
    guard encode_ciphertext_header(
        hdr_buf,
        rfc::TLS_CONTENT_APPLICATION_DATA,
        ct_body_u16,
    ) else {
        return 0, Alert.InternalError, false;
    }

    core::ct_copy_bytes(out_ciphertext[..5], hdr_buf[..]);
    core::ct_copy_bytes(out_ciphertext[5..plain_end], plaintext);
    out_ciphertext[plain_end] = inner_type;

    let tag, ok_seal = core::aes256_gcm_seal_inplace(
        key,
        nonce,
        out_ciphertext[5..inner_end],
        out_ciphertext[..5],
    );
    guard ok_seal else {
        core::secure_zeroize_slice(out_ciphertext[..total_len]);
        return 0, Alert.InternalError, false;
    }
    core::ct_copy_bytes(out_ciphertext[inner_end..total_len], tag[..]);
    return total_len, Alert.CloseNotify, true;
}

fn record_seal_chacha20_poly1305_into(
    key:            const u8[32]&,
    iv:             const u8[12]&,
    seq_num:        u64,
    inner_type:     u8,
    plaintext:      const u8[:],
    out_ciphertext: u8[:],
) -> i64, Alert, bool {
    let inner_len = core::add_sat_i64(plaintext.len, 1);
    let ct_body_len = core::add_sat_i64(inner_len, rfc::TLS_AEAD_TAG_LEN);
    let ct_body_u16 = (ct_body_len & 0xFFFF) as u16;
    let total_len = core::add_sat_i64(5, ct_body_len);
    let plain_end = core::add_sat_i64(5, plaintext.len);
    let inner_end = core::add_sat_i64(5, inner_len);
    guard plaintext.len >= 0 && plaintext.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else {
        return 0, Alert.RecordOverflow, false;
    }
    guard inner_type >= rfc::TLS_CONTENT_ALERT && inner_type <= rfc::TLS_CONTENT_APPLICATION_DATA else {
        return 0, Alert.UnexpectedMessage, false;
    }
    guard out_ciphertext.len >= total_len else {
        return 0, Alert.RecordOverflow, false;
    }

    let nonce, ok_nonce = compute_record_nonce(iv, seq_num);
    guard ok_nonce else {
        return 0, Alert.UnexpectedMessage, false;
    }

    var hdr_buf: u8[..5] = [];
    guard encode_ciphertext_header(
        hdr_buf,
        rfc::TLS_CONTENT_APPLICATION_DATA,
        ct_body_u16,
    ) else {
        return 0, Alert.InternalError, false;
    }

    core::ct_copy_bytes(out_ciphertext[..5], hdr_buf[..]);
    core::ct_copy_bytes(out_ciphertext[5..plain_end], plaintext);
    out_ciphertext[plain_end] = inner_type;

    let tag, ok_seal = core::chacha20_poly1305_seal_inplace(
        key,
        nonce,
        out_ciphertext[5..inner_end],
        out_ciphertext[..5],
    );
    guard ok_seal else {
        core::secure_zeroize_slice(out_ciphertext[..total_len]);
        return 0, Alert.InternalError, false;
    }
    core::ct_copy_bytes(out_ciphertext[inner_end..total_len], tag[..]);
    return total_len, Alert.CloseNotify, true;
}

fn record_decrypt_aes256_gcm_into(
    key:            const u8[32]&,
    iv:             const u8[12]&,
    seq_num:        u64,
    record_header:  const u8[:],
    record_payload: const u8[:],
    out_plaintext:  u8[:],
) -> i64, u8, Alert, bool {
    guard record_header.len == 5 else { return 0, 0, Alert.DecodeError, false; }
    guard record_payload.len <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else {
        return 0, 0, Alert.RecordOverflow, false;
    }
    guard record_payload.len >= rfc::TLS_AEAD_TAG_LEN + 1 else {
        return 0, 0, Alert.DecodeError, false;
    }

    let ct_len = record_payload.len - rfc::TLS_AEAD_TAG_LEN;
    guard ct_len <= rfc::TLS_MAX_INNER_PLAINTEXT_LEN && out_plaintext.len >= ct_len else {
        return 0, 0, Alert.RecordOverflow, false;
    }

    let nonce, ok_nonce = compute_record_nonce(iv, seq_num);
    guard ok_nonce else { return 0, 0, Alert.UnexpectedMessage, false; }

    let ciphertext = record_payload[..ct_len];
    let tag_slice = record_payload[ct_len..];
    var tag: u8[16] = [0; 16];
    guard tag_slice.len == 16 else { return 0, 0, Alert.DecodeError, false; }
    for i in 16 { tag[i] = tag_slice[i]; }

    let dec_len, ok_open = core::aes256_gcm_open_into(
        key, nonce, ciphertext, record_header, tag, out_plaintext[..ct_len],
    );
    guard ok_open && dec_len == ct_len else {
        core::secure_zeroize_slice(out_plaintext[..ct_len]);
        return 0, 0, Alert.BadRecordMac, false;
    }

    let plain, inner_type, alert = unpack_inner_plaintext(out_plaintext[..ct_len]);
    guard alert == Alert.CloseNotify else {
        core::secure_zeroize_slice(out_plaintext[..ct_len]);
        return 0, 0, alert, false;
    }

    let plain_len = plain.len;
    core::secure_zeroize_slice(out_plaintext[plain_len..ct_len]);
    return plain_len, inner_type, Alert.CloseNotify, true;
}

fn record_decrypt_chacha20_poly1305_into(
    key:            const u8[32]&,
    iv:             const u8[12]&,
    seq_num:        u64,
    record_header:  const u8[:],
    record_payload: const u8[:],
    out_plaintext:  u8[:],
) -> i64, u8, Alert, bool {
    guard record_header.len == 5 else { return 0, 0, Alert.DecodeError, false; }
    guard record_payload.len <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else {
        return 0, 0, Alert.RecordOverflow, false;
    }
    guard record_payload.len >= rfc::TLS_AEAD_TAG_LEN + 1 else {
        return 0, 0, Alert.DecodeError, false;
    }

    let ct_len = record_payload.len - rfc::TLS_AEAD_TAG_LEN;
    guard ct_len <= rfc::TLS_MAX_INNER_PLAINTEXT_LEN && out_plaintext.len >= ct_len else {
        return 0, 0, Alert.RecordOverflow, false;
    }

    let nonce, ok_nonce = compute_record_nonce(iv, seq_num);
    guard ok_nonce else { return 0, 0, Alert.UnexpectedMessage, false; }

    let ciphertext = record_payload[..ct_len];
    let tag_slice = record_payload[ct_len..];
    var tag: u8[16] = [0; 16];
    guard tag_slice.len == 16 else { return 0, 0, Alert.DecodeError, false; }
    for i in 16 { tag[i] = tag_slice[i]; }

    let dec_len, ok_open = core::chacha20_poly1305_open_into(
        key, nonce, ciphertext, record_header, tag, out_plaintext[..ct_len],
    );
    guard ok_open && dec_len == ct_len else {
        core::secure_zeroize_slice(out_plaintext[..ct_len]);
        return 0, 0, Alert.BadRecordMac, false;
    }

    let plain, inner_type, alert = unpack_inner_plaintext(out_plaintext[..ct_len]);
    guard alert == Alert.CloseNotify else {
        core::secure_zeroize_slice(out_plaintext[..ct_len]);
        return 0, 0, alert, false;
    }

    let plain_len = plain.len;
    core::secure_zeroize_slice(out_plaintext[plain_len..ct_len]);
    return plain_len, inner_type, Alert.CloseNotify, true;
}

fn record_seal_into(
    cipher_suite:   u16,
    key:            const u8[:],
    iv:             const u8[12]&,
    seq_num:        u64,
    inner_type:     u8,
    plaintext:      const u8[:],
    out_ciphertext: u8[:],
) -> i64, Alert, bool {
    if cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 {
        guard key.len == 16 else { return 0, Alert.InternalError, false; }
        var key16: u8[16] = [0; 16];
        defer core::secure_zeroize_16(key16);
        for i in 16 { key16[i] = key[i]; }
        return record_seal_aes128_gcm_into(key16, iv, seq_num, inner_type, plaintext, out_ciphertext);
    }
    if cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        guard key.len == 32 else { return 0, Alert.InternalError, false; }
        var key32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(key32);
        for i in 32 { key32[i] = key[i]; }
        return record_seal_aes256_gcm_into(key32, iv, seq_num, inner_type, plaintext, out_ciphertext);
    }
    if cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        guard key.len == 32 else { return 0, Alert.InternalError, false; }
        var key32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(key32);
        for i in 32 { key32[i] = key[i]; }
        return record_seal_chacha20_poly1305_into(
            key32, iv, seq_num, inner_type, plaintext, out_ciphertext,
        );
    }
    return 0, Alert.InternalError, false;
}

fn record_decrypt_into(
    cipher_suite:   u16,
    key:            const u8[:],
    iv:             const u8[12]&,
    seq_num:        u64,
    record_header:  const u8[:],
    record_payload: const u8[:],
    out_plaintext:  u8[:],
) -> i64, u8, Alert, bool {
    if cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 {
        guard key.len == 16 else { return 0, 0, Alert.InternalError, false; }
        var key16: u8[16] = [0; 16];
        defer core::secure_zeroize_16(key16);
        for i in 16 { key16[i] = key[i]; }
        return record_decrypt_aes128_gcm_into(
            key16, iv, seq_num, record_header, record_payload, out_plaintext,
        );
    }
    if cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        guard key.len == 32 else { return 0, 0, Alert.InternalError, false; }
        var key32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(key32);
        for i in 32 { key32[i] = key[i]; }
        return record_decrypt_aes256_gcm_into(
            key32, iv, seq_num, record_header, record_payload, out_plaintext,
        );
    }
    if cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        guard key.len == 32 else { return 0, 0, Alert.InternalError, false; }
        var key32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(key32);
        for i in 32 { key32[i] = key[i]; }
        return record_decrypt_chacha20_poly1305_into(
            key32,
            iv,
            seq_num,
            record_header,
            record_payload,
            out_plaintext,
        );
    }
    return 0, 0, Alert.InternalError, false;
}

// DoS filter tracking consecutive empty records, early data skipped volume, and CCS records.
struct RecordFilterState {
    empty_records_count:      i32 = 0,
    early_data_skipped_bytes: i64 = 0,
    ccs_count:                i32 = 0,
}

checkfree fn check_record_payload_length(state: RecordFilterState&, payload_len: i64, is_early_data: bool) -> Alert {
    guard payload_len >= 0 && payload_len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else {
        return Alert.RecordOverflow;
    }

    if payload_len == 0 {
        state.empty_records_count++;
        guard state.empty_records_count <= tls_internal::MAX_EMPTY_RECORDS else {
            return Alert.UnexpectedMessage;
        }
    } else {
        state.empty_records_count = 0;
    }

    if is_early_data {
        guard state.early_data_skipped_bytes >= 0 &&
            state.early_data_skipped_bytes <= tls_internal::MAX_EARLY_DATA_SKIPPED else {
            return Alert.UnexpectedMessage;
        }
        guard payload_len <= tls_internal::MAX_EARLY_DATA_SKIPPED - state.early_data_skipped_bytes else {
            return Alert.UnexpectedMessage;
        }
        state.early_data_skipped_bytes += payload_len;
    }
    return Alert.CloseNotify;
}

// Encodes the 5-byte TLSCiphertext record header (RFC 8446 §5.2).
// In TLS 1.3, TLSCiphertext outer content type MUST be application_data (0x17).
// Length MUST be at least 17 bytes (1 byte inner content type + 16 bytes AEAD tag)
// and at most rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN (16640 bytes).
inline fn encode_ciphertext_header<B>(out: B&, content_type: u8, ciphertext_len: u16) -> bool {
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
    out.append_u16_be(rfc::TLS_LEGACY_VERSION_1_2);
    out.append_u16_be(ciphertext_len);
    return true;
}

// Parses 5-byte record header and validates RFC 8446 length bounds and legacy version.
//
// Example:
//   hdr_bytes = [0x17, 0x03, 0x03, 0x00, 0x10]
//   returns: content_type = 23, version = 0x0303, length = 16, alert = Alert.CloseNotify, ok = true
checkfree fn parse_record_header(hdr_bytes: const u8[:]) -> u8, u16, u16, Alert, bool {
    var idx: i64 = 0;
    return parse_record_header_at(hdr_bytes, idx);
}

// Parses a 5-byte TLS record header from `raw` at `idx` and advances `idx` by 5 on success.
// Leaves `idx` unchanged on error.
//
// Example:
//   raw = [0x17, 0x03, 0x03, 0x00, 0x10], idx = 0
//   returns: content_type = 23, version = 0x0303, length = 16, alert = Alert.CloseNotify, ok = true, idx = 5
checkfree fn parse_record_header_at(
    raw: const u8[:],
    idx: i64&,
) -> u8, u16, u16, Alert, bool {
    let saved = idx;
    var committed = false;
    defer if !committed { idx = saved; };

    var content_type: u8  = 0;
    var version:      u16 = 0;
    var length:       u16 = 0;
    guard slice_get_u8(raw, idx, content_type) &&
          slice_get_u16(raw, idx, version) &&
          slice_get_u16(raw, idx, length) else {
        return 0, 0, 0, Alert.DecodeError, false;
    }

    if version != rfc::TLS_LEGACY_VERSION_1_2 && version != rfc::TLS_LEGACY_VERSION_1_0 {
        return content_type, version, length, Alert.ProtocolVersion, false;
    }
    if content_type < rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC || content_type > rfc::TLS_CONTENT_APPLICATION_DATA {
        return content_type, version, length, Alert.UnexpectedMessage, false;
    }
    let max_len = if content_type == rfc::TLS_CONTENT_APPLICATION_DATA {
        rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN
    } else {
        rfc::TLS_MAX_RECORD_PLAINTEXT_LEN
    };
    if length > max_len {
        return content_type, version, length, Alert.RecordOverflow, false;
    }
    if length == 0 && content_type != rfc::TLS_CONTENT_APPLICATION_DATA {
        return content_type, version, length, Alert.UnexpectedMessage, false;
    }
    committed = true;
    return content_type, version, length, Alert.CloseNotify, true;
}

// Validates RFC 8446 Appendix D.4 Middlebox Compatibility Dummy ChangeCipherSpec record.
// A CCS record MUST contain exactly one single byte of value 0x01.
checkfree inline fn validate_change_cipher_spec_record(payload: const u8[:]) -> Alert {
    if payload.len != 1 {
        return Alert.DecodeError;
    }
    if payload[0] != 0x01 {
        return Alert.UnexpectedMessage;
    }
    return Alert.CloseNotify;
}

// Validates RFC 8446 Appendix D.4 Middlebox Compatibility ChangeCipherSpec record with state & flood protection:
// 1. Must occur during active handshake (after ClientHello, before Finished).
// 2. Flood protection (OpenSSL #10065 / CVE-2020-1967): at most 1 CCS record allowed during handshake.
// 3. Payload must be exactly 1 byte of value 0x01.
checkfree fn check_change_cipher_spec_record(
    state:            RecordFilterState&,
    payload:          const u8[:],
    handshake_active: bool,
) -> Alert {
    guard handshake_active else {
        return Alert.UnexpectedMessage;
    }
    guard state.ccs_count < rfc::MAX_CCS_RECORDS else {
        return Alert.UnexpectedMessage;
    }
    let alert = validate_change_cipher_spec_record(payload);
    guard alert == Alert.CloseNotify else {
        return alert;
    }
    state.ccs_count++;
    return Alert.CloseNotify;
}

// ---- QUIC Crypto Gateway & Header Protection (RFC 9001) ------------------

enum QuicEncryptionLevel {
    Initial,     // ssl_encryption_initial (0)
    EarlyData,   // ssl_encryption_early_data (1)
    Handshake,   // ssl_encryption_handshake (2)
    Application, // ssl_encryption_application (3)
}

enum QuicOutputEvent {
    None,
    SetReadSecret { level: QuicEncryptionLevel, cipher_id: u16, secret: u8[..48] = [], secret_len: u8 = 0 },
    SetWriteSecret { level: QuicEncryptionLevel, cipher_id: u16, secret: u8[..48] = [], secret_len: u8 = 0 },
    AddHandshakeData { level: QuicEncryptionLevel, data: const u8[:] = [] },
    FlushFlight,
    SendAlert { level: QuicEncryptionLevel, alert: Alert },
}

// Connection container for QUIC Crypto state machine isolation.
struct QuicCryptoConn {
    read_level:  QuicEncryptionLevel  = QuicEncryptionLevel.Initial,
    write_level: QuicEncryptionLevel  = QuicEncryptionLevel.Initial,
    events:      QuicOutputEvent[..8] = [],
}

const QUIC_CRYPTO_OOO_WINDOW_BYTES: i64 = 4096; // RFC 9000 Section 7.5 bounded OOO window
const QUIC_CRYPTO_OOO_MASK:         u64 = 4095; // QUIC_CRYPTO_OOO_WINDOW_BYTES - 1
const QUIC_CRYPTO_OOO_MAX_RANGES:   i64 = 16;   // Max disjoint out-of-order CRYPTO ranges

struct QuicCryptoOooRange {
    start: u64 = 0,
    end:   u64 = 0,
}

struct QuicCryptoStream {
    consumed_offset: u64                      = 0,
    buf:             u8[..16384]              = [],
    ooo_ring:        u8[4096]                 = [0; 4096],
    ooo_ranges:      QuicCryptoOooRange[..16] = [],
}

// Extracts 16-byte Header Protection sample from QUIC packet at offset pn_offset + 4 (RFC 9001 Section 5.4.2).
checkfree inline fn quic_extract_hp_sample(pkt: const u8[:], pn_offset: u32) -> const u8[:], bool {
    guard pn_offset > 0 else {
        return pkt[..0], false;
    }
    let sample_offset = (pn_offset as i64) + 4;
    guard sample_offset >= 0 && sample_offset <= pkt.len else {
        return pkt[..0], false;
    }
    let tail = pkt[sample_offset..];
    guard tail.len >= 16 else {
        return pkt[..0], false;
    }
    return tail[..16], true;
}

// Validates RFC 9001 invariants on incoming QUIC handshake bytes:
// 1. Encryption level must match current read_level.
// 2. CRYPTO frames cannot be empty (DecodeError) or exceed quota (RecordOverflow).
checkfree fn provide_quic_data(conn: QuicCryptoConn&, level: QuicEncryptionLevel, data: const u8[:]) -> Alert {
    guard level == conn.read_level else {
        return Alert.UnexpectedMessage;
    }
    guard data.len > 0 else {
        return Alert.DecodeError;
    }
    guard data.len <= tls_internal::MAX_QUIC_CRYPTO_BUFFER_LEN else {
        return Alert.RecordOverflow;
    }
    return Alert.CloseNotify;
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
    guard src.len >= 0 && src.len <= QUIC_CRYPTO_OOO_WINDOW_BYTES else { return false; }
    if src.len == 0 { return true; }
    let start = (stream_off & QUIC_CRYPTO_OOO_MASK) as i64;
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
    guard count >= 0 && count <= QUIC_CRYPTO_OOO_WINDOW_BYTES else { return false; }
    if count == 0 { return true; }
    guard (count as u64) <= quic_crypto_buf_free_bytes(buf) else { return false; }
    let start = (stream_off & QUIC_CRYPTO_OOO_MASK) as i64;
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
    stream:     QuicCryptoStream&,
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
    ranges: QuicCryptoOooRange[..16]&,
    first:  i64,
    after:  i64,
    merged: QuicCryptoOooRange,
) -> bool {
    let count = ranges.len;
    guard first >= 0 && first <= after && after <= count else { return false; }
    var next: QuicCryptoOooRange[..16] = [];
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
    ranges:     const QuicCryptoOooRange[..16]&,
    offset:     u64,
    end_offset: u64,
) -> i64, i64, QuicCryptoOooRange {
    let count = ranges.len;
    var first: i64 = count;
    for i in count {
        if ranges[i].end >= offset {
            first = i;
            break;
        }
    }
    var after: i64 = count;
    var merged = QuicCryptoOooRange { start: offset, end: end_offset };
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
    stream:     QuicCryptoStream&,
    offset:     u64,
    end_offset: u64,
    data:       const u8[:],
) -> bool {
    let rel_end, ok_rel = quic_crypto_offset_delta(end_offset, stream.consumed_offset);
    guard ok_rel && rel_end <= (QUIC_CRYPTO_OOO_WINDOW_BYTES as u64) else { return false; }
    guard rel_end <= quic_crypto_buf_free_bytes(stream.buf) else { return false; }

    let first, after, merged = quic_ooo_find_merge_span(stream.ooo_ranges, offset, end_offset);
    guard stream.ooo_ranges.len < QUIC_CRYPTO_OOO_MAX_RANGES || after > first else { return false; }
    guard quic_ooo_write_uncovered(stream, offset, end_offset, data, first, after) else { return false; }
    return quic_ooo_replace_ranges(stream.ooo_ranges, first, after, merged);
}

// Drains all newly contiguous or overlapped staged OOO ranges into `stream.buf`.
checkfree fn quic_crypto_drain_ooo(stream: QuicCryptoStream&) -> bool {
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

    var next: QuicCryptoOooRange[..16] = [];
    for k in drop_count..count {
        guard next.len < next.cap else { return false; }
        next.push(stream.ooo_ranges[k]);
    }
    stream.ooo_ranges = next;
    return true;
}

// Ingests a QUIC CRYPTO frame (RFC 9000 Section 7.5, Section 19.6 / RFC 9001 Section 4),
// returning `(new_contiguous_bytes, ok)`. Buffers bounded out-of-order ranges up to
// `QUIC_CRYPTO_OOO_WINDOW_BYTES` and drains contiguous bytes as gaps close.
//
// Example:
//   stream.consumed_offset = 0, ingest(offset=4, "BBBB") -> (0, true) [staged]
//   ingest(offset=0, "AAAA") -> (8, true), stream.buf = "AAAABBBB", consumed_offset = 8
checkfree fn quic_crypto_stream_ingest(
    stream: QuicCryptoStream&,
    offset: u64,
    data:   const u8[:],
) -> i64, bool {
    // 1. Integer overflow check: offset + data.len must not wrap around u64 or exceed 2^62 - 1
    let end_offset, ok_end = quic_crypto_frame_end(offset, data.len);
    guard ok_end else { return 0, false; }

    // 2. Completely duplicate or zero-length frame at or before consumed_offset: safe no-op
    if end_offset <= stream.consumed_offset {
        return 0, true;
    }

    // 3. Out-of-order frame: stage within bounded OOO window (RFC 9000 Section 7.5)
    if offset > stream.consumed_offset {
        let rel_end, ok_rel = quic_crypto_offset_delta(end_offset, stream.consumed_offset);
        guard ok_rel && rel_end <= (tls_internal::MAX_QUIC_CRYPTO_BUFFER_LEN as u64) else {
            return 0, false;
        }
        if data.len == 0 { return 0, true; }
        guard quic_crypto_stage_ooo(stream, offset, end_offset, data) else { return 0, false; }
        return 0, true;
    }

    // 4. Overlapping or contiguous arrival: trim already-consumed prefix
    let skip_u, ok_skip = quic_crypto_offset_delta(stream.consumed_offset, offset);
    let skip = skip_u as i64;
    guard ok_skip && skip >= 0 && skip <= data.len else { return 0, false; }
    let new_data = data[skip..];

    // 5. Append contiguous bytes and drain any newly reachable staged OOO ranges
    let saved_buf_len = stream.buf.len;
    let saved_offset = stream.consumed_offset;
    guard quic_crypto_buf_append(stream.buf, new_data) else { return 0, false; }
    stream.consumed_offset = end_offset;

    guard quic_crypto_drain_ooo(stream) else {
        stream.buf.resize(saved_buf_len);
        stream.consumed_offset = saved_offset;
        return 0, false;
    }
    let total_u, ok_tot = quic_crypto_offset_delta(stream.consumed_offset, saved_offset);
    guard ok_tot else { return 0, false; }
    return total_u as i64, true;
}
