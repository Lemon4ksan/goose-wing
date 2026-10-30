// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation TLS 1.3 Record Layer and RFC 9001 QUIC Crypto adapter.
// Conforms to RFC 8446 Section 5, RFC 9001 Section 5.4, and BoringSSL/BearSSL safety models.
namespace wing;

import std;
import core from "..";

// ---- 1. TLS 1.3 Alert Codes (RFC 8446 Section 6) ---------------------------

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

fn tls_alert_to_u8(alert: TlsAlert) -> u8 {
    return match alert {
        CloseNotify => 0,
        UnexpectedMessage => 10,
        BadRecordMac => 20,
        RecordOverflow => 22,
        HandshakeFailure => 40,
        BadCertificate => 42,
        UnsupportedCertificate => 43,
        CertificateRevoked => 44,
        CertificateExpired => 45,
        CertificateUnknown => 46,
        IllegalParameter => 47,
        UnknownCa => 48,
        AccessDenied => 49,
        DecodeError => 50,
        DecryptError => 51,
        ProtocolVersion => 70,
        InsufficientSecurity => 71,
        InternalError => 80,
        InappropriateFallback => 86,
        UserCanceled => 90,
        MissingExtension => 109,
        UnsupportedExtension => 110,
        UnrecognizedName => 112,
        BadCertificateStatusResponse => 113,
        UnknownPskIdentity => 115,
        CertificateRequired => 116,
        NoApplicationProtocol => 120,
    };
}

fn u8_to_tls_alert(code: u8) -> TlsAlert, bool {
    let alert = match code {
        0 => TlsAlert.CloseNotify,
        10 => TlsAlert.UnexpectedMessage,
        20 => TlsAlert.BadRecordMac,
        22 => TlsAlert.RecordOverflow,
        40 => TlsAlert.HandshakeFailure,
        42 => TlsAlert.BadCertificate,
        43 => TlsAlert.UnsupportedCertificate,
        44 => TlsAlert.CertificateRevoked,
        45 => TlsAlert.CertificateExpired,
        46 => TlsAlert.CertificateUnknown,
        47 => TlsAlert.IllegalParameter,
        48 => TlsAlert.UnknownCa,
        49 => TlsAlert.AccessDenied,
        50 => TlsAlert.DecodeError,
        51 => TlsAlert.DecryptError,
        70 => TlsAlert.ProtocolVersion,
        71 => TlsAlert.InsufficientSecurity,
        80 => TlsAlert.InternalError,
        86 => TlsAlert.InappropriateFallback,
        90 => TlsAlert.UserCanceled,
        109 => TlsAlert.MissingExtension,
        110 => TlsAlert.UnsupportedExtension,
        112 => TlsAlert.UnrecognizedName,
        113 => TlsAlert.BadCertificateStatusResponse,
        115 => TlsAlert.UnknownPskIdentity,
        116 => TlsAlert.CertificateRequired,
        120 => TlsAlert.NoApplicationProtocol,
        _ => TlsAlert.DecodeError,
    };
    if alert == TlsAlert.DecodeError && code != 50 {
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
        if desc == 0 || desc == 90 {
            is_fatal = false;
        }
    }
    return level, alert, is_fatal, true;
}

// ---- 2. Zero-Copy Parsers (ByteCursor & ByteBuilder) -------------------------

struct ByteCursor {
    buf: const u8[:] = [],
}

inline fn cursor_from(buf: const u8[:]) -> ByteCursor {
    return ByteCursor { buf: buf };
}

inline fn cursor_len(c: const ByteCursor&) -> i64 {
    guard c.buf.len >= 0 else { return 0; }
    return c.buf.len;
}

fn get_u8(c: ByteCursor&, out: u8&) -> bool {
    if c.buf.len < 1 { return false; }
    out = c.buf[0];
    c.buf = c.buf[1..];
    return true;
}

fn get_u16(c: ByteCursor&, out: u16&) -> bool {
    if c.buf.len < 2 { return false; }
    out = ((c.buf[0] as u16) << 8) | c.buf[1];
    c.buf = c.buf[2..];
    return true;
}

fn get_u24(c: ByteCursor&, out: u32&) -> bool {
    if c.buf.len < 3 { return false; }
    out = ((c.buf[0] as u32) << 16) | ((c.buf[1] as u32) << 8) | c.buf[2];
    c.buf = c.buf[3..];
    return true;
}

fn get_u32(c: ByteCursor&, out: u32&) -> bool {
    if c.buf.len < 4 { return false; }
    out = ((c.buf[0] as u32) << 24) | ((c.buf[1] as u32) << 16) | ((c.buf[2] as u32) << 8) | c.buf[3];
    c.buf = c.buf[4..];
    return true;
}

fn get_bytes(c: ByteCursor&, out: ByteCursor&, count: i64) -> bool {
    if count < 0 || c.buf.len < count { return false; }
    out = ByteCursor { buf: c.buf[..count] };
    c.buf = c.buf[count..];
    return true;
}

fn get_u8_length_prefixed(c: ByteCursor&, out: ByteCursor&) -> bool {
    let saved = c.buf;
    var length: u8 = 0;
    if !get_u8(c, length) { return false; }
    if !get_bytes(c, out, length) {
        c.buf = saved;
        return false;
    }
    return true;
}

fn get_u16_length_prefixed(c: ByteCursor&, out: ByteCursor&) -> bool {
    let saved = c.buf;
    var length: u16 = 0;
    if !get_u16(c, length) { return false; }
    if !get_bytes(c, out, length) {
        c.buf = saved;
        return false;
    }
    return true;
}

fn get_u24_length_prefixed(c: ByteCursor&, out: ByteCursor&) -> bool {
    let saved = c.buf;
    var length: u32 = 0;
    if !get_u24(c, length) { return false; }
    if !get_bytes(c, out, length) {
        c.buf = saved;
        return false;
    }
    return true;
}

fn get_last_u8(c: ByteCursor&, out: u8&) -> bool {
    let n = c.buf.len;
    if n < 1 { return false; }
    out = c.buf[n - 1];
    c.buf = c.buf[..n - 1];
    return true;
}

struct ByteBuilder {
    offsets: i64[..8] = [],
    buf:     u8[>..]  = [],
}

fn builder_init() -> ByteBuilder {
    return ByteBuilder { offsets: [], buf: [] };
}

fn put_u8(b: ByteBuilder&, val: u8) {
    b.buf.push(val);
}

fn put_u16(b: ByteBuilder&, val: u16) {
    b.buf.push(((val >> 8) & 0xFF) as u8);
    b.buf.push((val & 0xFF) as u8);
}

fn put_u24(b: ByteBuilder&, val: u32) {
    b.buf.push(((val >> 16) & 0xFF) as u8);
    b.buf.push(((val >> 8) & 0xFF) as u8);
    b.buf.push((val & 0xFF) as u8);
}

fn put_u32(b: ByteBuilder&, val: u32) {
    b.buf.push(((val >> 24) & 0xFF) as u8);
    b.buf.push(((val >> 16) & 0xFF) as u8);
    b.buf.push(((val >> 8) & 0xFF) as u8);
    b.buf.push((val & 0xFF) as u8);
}

fn put_bytes(b: ByteBuilder&, data: const u8[:]) {
    b.buf.append(data);
}

fn start_u8_prefix(b: ByteBuilder&) -> bool {
    if b.offsets.len >= b.offsets.cap { return false; }
    b.offsets.push(b.buf.len);
    b.buf.push(0);
    return true;
}

fn finish_u8_prefix(b: ByteBuilder&) -> bool {
    guard b.offsets.len > 0 else { return false; }
    let start = b.offsets[b.offsets.len - 1];
    guard start >= 0 && start < b.buf.len else {
        b.offsets.pop();
        return false;
    }
    let body_len = b.buf.len - start - 1;
    guard body_len >= 0 && body_len <= 255 else {
        return false;
    }
    b.offsets.pop();
    b.buf[start] = body_len as u8;
    return true;
}

fn start_u16_prefix(b: ByteBuilder&) -> bool {
    if b.offsets.len >= b.offsets.cap { return false; }
    b.offsets.push(b.buf.len);
    b.buf.push(0);
    b.buf.push(0);
    return true;
}

fn finish_u16_prefix(b: ByteBuilder&) -> bool {
    guard b.offsets.len > 0 else { return false; }
    let start = b.offsets[b.offsets.len - 1];
    guard start >= 0 && start + 1 < b.buf.len else {
        b.offsets.pop();
        return false;
    }
    let body_len = b.buf.len - start - 2;
    guard body_len >= 0 && body_len <= 65535 else {
        return false;
    }
    b.offsets.pop();
    b.buf[start] = ((body_len >> 8) & 0xFF) as u8;
    b.buf[start + 1] = (body_len & 0xFF) as u8;
    return true;
}

fn start_u24_prefix(b: ByteBuilder&) -> bool {
    if b.offsets.len >= b.offsets.cap { return false; }
    b.offsets.push(b.buf.len);
    b.buf.push(0);
    b.buf.push(0);
    b.buf.push(0);
    return true;
}

fn finish_u24_prefix(b: ByteBuilder&) -> bool {
    guard b.offsets.len > 0 else { return false; }
    let start = b.offsets[b.offsets.len - 1];
    guard start >= 0 && start + 2 < b.buf.len else {
        b.offsets.pop();
        return false;
    }
    let body_len = b.buf.len - start - 3;
    guard body_len >= 0 && body_len <= 16777215 else {
        return false;
    }
    b.offsets.pop();
    b.buf[start] = ((body_len >> 16) & 0xFF) as u8;
    b.buf[start + 1] = ((body_len >> 8) & 0xFF) as u8;
    b.buf[start + 2] = (body_len & 0xFF) as u8;
    return true;
}

// ---- 3. TLS Record Layer Framing & Invariants (RFC 8446 Section 5) ---------

const RECORD_BUFSIZE_IN:         i64 = 16709; // 16384 + 325 (BearSSL BR_SSL_BUFSIZE_INPUT)
const RECORD_BUFSIZE_OUT:        i64 = 16469; // 16384 + 85 (BearSSL BR_SSL_BUFSIZE_OUTPUT)
const MAX_RECORD_PLAINTEXT_LEN:  i64 = 16384;
const MAX_RECORD_CIPHERTEXT_LEN: i64 = 16640; // 2^14 + 256
const MAX_INNER_PLAINTEXT_LEN:   i64 = 16624; // 16640 - 16 (AEAD tag) per RFC 8446 §5.1 & §5.4
const TLS_RECORD_HEADER_LEN:     i64 = 5;

const MAX_EMPTY_RECORDS:      i32 = 32; // BoringSSL kMaxEmptyRecords DoS defense
const MAX_EARLY_DATA_SKIPPED: i64 = 16384; // BoringSSL kMaxEarlyDataSkipped

const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;
const CONTENT_TYPE_ALERT:              u8 = 0x15;
const CONTENT_TYPE_HANDSHAKE:          u8 = 0x16;
const CONTENT_TYPE_APPLICATION_DATA:   u8 = 0x17;

const LEGACY_RECORD_VERSION_TLS12: u16 = 0x0303;
const TLS13_VERSION:               u16 = 0x0304;

// Computes 96-bit (12-byte) per-record nonce: N = iv ^ (0^32 || be64(seq_num))
// Rejects 2^64 - 1 to prevent counter wraparound and nonce reuse (RFC 8446 Section 5.3).
fn compute_record_nonce(iv: const u8[12]&, seq_num: u64) -> u8[12], bool {
    var nonce: u8[12] = [0; 12];
    if seq_num == 0xFFFFFFFFFFFFFFFF {
        return nonce, false;
    }
    for i in 12 { nonce[i] = iv[i]; }
    for i in 8 {
        let b = ((seq_num >> ((7 - i) * 8)) & 0xFF) as u8;
        nonce[4 + i] ^= b;
    }
    return nonce, true;
}

// Validates and increments 64-bit record sequence number; rejects 2^64 - 1 (RFC 8446 Section 5.3).
fn increment_record_seq_num(seq_num: u64&) -> bool {
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
    guard decrypted.len <= MAX_INNER_PLAINTEXT_LEN else {
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
    guard inner_type >= CONTENT_TYPE_ALERT && inner_type <= CONTENT_TYPE_APPLICATION_DATA else {
        return decrypted[..0], 0, TlsAlert.UnexpectedMessage;
    }
    guard content_len <= MAX_RECORD_PLAINTEXT_LEN else {
        return decrypted[..0], 0, TlsAlert.RecordOverflow;
    }
    guard content_len > 0 || inner_type == CONTENT_TYPE_APPLICATION_DATA else {
        return decrypted[..0], 0, TlsAlert.UnexpectedMessage;
    }

    return decrypted[..content_len], inner_type, TlsAlert.CloseNotify;
}

const AEAD_TAG_LEN: i64 = 16;

// Compares two 16-byte authentication tags in constant time (RFC 8446 §5.2).
fn ct_compare_tag16(a: const u8[16]&, b: const u8[16]&) -> bool {
    var diff: u8 = 0;
    for i in 16 {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

// Clears and zeroizes a byte slice to ensure zero leakage of unauthenticated data.
fn secure_wipe_buffer(buf: u8[:]) {
    for i in buf.len {
        buf[i] = 0;
    }
}

// Decrypts and authenticates a TLS 1.3 record payload with AES-128-GCM (RFC 8446 §5.2).
// Invariants enforced:
// 1. Strict alert separation:
//    - Payload length > MAX_RECORD_CIPHERTEXT_LEN -> RecordOverflow.
//    - Payload length < AEAD_TAG_LEN + 1 (17) -> DecodeError.
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
    guard record_payload.len <= MAX_RECORD_CIPHERTEXT_LEN else {
        return 0, TlsAlert.RecordOverflow;
    }
    guard record_payload.len >= AEAD_TAG_LEN + 1 else {
        return 0, TlsAlert.DecodeError;
    }

    let nonce, ok_nonce = compute_record_nonce(iv, seq_num);
    guard ok_nonce else {
        return 0, TlsAlert.UnexpectedMessage;
    }

    let ct_len = record_payload.len - AEAD_TAG_LEN;
    let ciphertext = record_payload[..ct_len];
    let tag_slice = record_payload[ct_len..];
    var tag: u8[16] = [0; 16];
    guard tag_slice.len == 16 else { return 0, TlsAlert.DecodeError; }
    for i in 16 {
        tag[i] = tag_slice[i];
    }

    var temp_dec: u8[>..] = [];
    let ok_open = core::aes128_gcm_open(key, nonce, ciphertext, record_header, tag, temp_dec);
    guard ok_open else {
        return 0, TlsAlert.BadRecordMac;
    }

    let plain, inner_type, alert = unpack_tls_inner_plaintext(temp_dec[..]);
    guard alert == TlsAlert.CloseNotify else {
        secure_wipe_buffer(temp_dec[..]);
        return 0, alert;
    }

    out_plaintext.append(plain);
    secure_wipe_buffer(temp_dec[..]);
    return inner_type, TlsAlert.CloseNotify;
}

// DoS filter tracking consecutive empty records, early data skipped volume, and CCS records.
struct RecordFilterState {
    empty_records_count:      i32 = 0,
    early_data_skipped_bytes: i64 = 0,
    ccs_count:                i32 = 0,
}

fn check_record_payload_length(state: RecordFilterState&, payload_len: i64, is_early_data: bool) -> TlsAlert {
    guard payload_len >= 0 && payload_len <= MAX_RECORD_PLAINTEXT_LEN else {
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
// In TLS 1.3, TLSCiphertext outer content type MUST be application_data (0x17)
// or change_cipher_spec (0x14) for middlebox compatibility.
// Length MUST be at least 17 bytes (1 byte inner content type + 16 bytes AEAD tag)
// and at most MAX_RECORD_CIPHERTEXT_LEN (16640 bytes).
fn encode_tls_ciphertext_header<B>(out: B&, content_type: u8, ciphertext_len: u16) -> bool {
    guard ciphertext_len >= 17 && (ciphertext_len as i64) <= MAX_RECORD_CIPHERTEXT_LEN else {
        return false;
    }
    guard content_type == CONTENT_TYPE_APPLICATION_DATA || content_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC else {
        return false;
    }
    out.push(content_type);
    out.push(((LEGACY_RECORD_VERSION_TLS12 >> 8) & 0xFF) as u8);
    out.push((LEGACY_RECORD_VERSION_TLS12 & 0xFF) as u8);
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
    guard hdr_bytes.len >= 5 else {
        return 0, 0, 0, TlsAlert.DecodeError, false;
    }
    let content_type = hdr_bytes[0];
    let version = ((hdr_bytes[1] as u16) << 8) | hdr_bytes[2];
    let length = ((hdr_bytes[3] as u16) << 8) | hdr_bytes[4];

    if version != LEGACY_RECORD_VERSION_TLS12 && version != 0x0301 {
        return content_type, version, length, TlsAlert.ProtocolVersion, false;
    }
    if content_type < CONTENT_TYPE_CHANGE_CIPHER_SPEC || content_type > CONTENT_TYPE_APPLICATION_DATA {
        return content_type, version, length, TlsAlert.UnexpectedMessage, false;
    }
    if length > MAX_RECORD_CIPHERTEXT_LEN {
        return content_type, version, length, TlsAlert.RecordOverflow, false;
    }
    return content_type, version, length, TlsAlert.CloseNotify, true;
}

// Validates RFC 8446 Appendix D.4 Middlebox Compatibility Dummy ChangeCipherSpec record.
// A CCS record MUST contain exactly one single byte of value 0x01.
// Any other length or content MUST trigger DecodeError or UnexpectedMessage.
fn validate_change_cipher_spec_record(payload: const u8[:]) -> TlsAlert {
    if payload.len != 1 {
        return TlsAlert.DecodeError;
    }
    if payload[0] != 0x01 {
        return TlsAlert.UnexpectedMessage;
    }
    return TlsAlert.CloseNotify;
}

const MAX_CCS_RECORDS: i32 = 1;

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
    guard state.ccs_count < MAX_CCS_RECORDS else {
        return TlsAlert.UnexpectedMessage;
    }
    let alert = validate_change_cipher_spec_record(payload);
    guard alert == TlsAlert.CloseNotify else {
        return alert;
    }
    state.ccs_count++;
    return TlsAlert.CloseNotify;
}

// ---- 4. QUIC Crypto Gateway & Header Protection (RFC 9001) ------------------

enum QuicEncryptionLevel {
    Initial,     // ssl_encryption_initial (0)
    EarlyData,   // ssl_encryption_early_data (1)
    Handshake,   // ssl_encryption_handshake (2)
    Application, // ssl_encryption_application (3)
}

fn quic_encryption_level_to_u8(level: QuicEncryptionLevel) -> u8 {
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
fn quic_extract_hp_sample(pkt: const u8[:], pn_offset: u32) -> const u8[:], bool {
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

const MAX_QUIC_VARINT: u64 = 0x3FFFFFFFFFFFFFFF; // 2^62 - 1 (RFC 9000 §16 & §19.6)

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
    guard offset <= MAX_QUIC_VARINT else { return false, 0; }
    let end_offset = offset + (data.len as u64);
    guard end_offset >= offset && end_offset <= MAX_QUIC_VARINT else { return false, 0; }

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
