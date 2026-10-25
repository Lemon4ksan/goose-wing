// Deterministic zero-allocation TLS 1.3 Record Layer and RFC 9001 QUIC Crypto adapter.
// Conforms to RFC 8446 Section 5, RFC 9001 Section 5.4, and BoringSSL/BearSSL safety models.
namespace wing;

import std;

// ---- 1. TLS 1.3 Alert Codes (RFC 8446 Section 6) ---------------------------

enum TlsAlert {
    CloseNotify,
    UnexpectedMessage,
    BadRecordMac,
    RecordOverflow,
    HandshakeFailure,
    BadCertificate,
    UnsupportedCertificate,
    CertificateExpired,
    UnknownCa,
    DecodeError,
    DecryptError,
    ProtocolVersion,
    InsufficientSecurity,
    InternalError,
    MissingExtension,
    UnsupportedExtension,
    UnrecognizedName,
    BadCertificateStatusResponse,
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
        CertificateExpired => 45,
        UnknownCa => 48,
        DecodeError => 50,
        DecryptError => 51,
        ProtocolVersion => 70,
        InsufficientSecurity => 71,
        InternalError => 80,
        MissingExtension => 109,
        UnsupportedExtension => 110,
        UnrecognizedName => 112,
        BadCertificateStatusResponse => 113,
        CertificateRequired => 116,
        NoApplicationProtocol => 120,
    };
}

fn u8_to_tls_alert(code: u8) -> TlsAlert, bool {
    if code == 0 { return TlsAlert.CloseNotify, true; }
    if code == 10 { return TlsAlert.UnexpectedMessage, true; }
    if code == 20 { return TlsAlert.BadRecordMac, true; }
    if code == 22 { return TlsAlert.RecordOverflow, true; }
    if code == 40 { return TlsAlert.HandshakeFailure, true; }
    if code == 42 { return TlsAlert.BadCertificate, true; }
    if code == 43 { return TlsAlert.UnsupportedCertificate, true; }
    if code == 45 { return TlsAlert.CertificateExpired, true; }
    if code == 48 { return TlsAlert.UnknownCa, true; }
    if code == 50 { return TlsAlert.DecodeError, true; }
    if code == 51 { return TlsAlert.DecryptError, true; }
    if code == 70 { return TlsAlert.ProtocolVersion, true; }
    if code == 71 { return TlsAlert.InsufficientSecurity, true; }
    if code == 80 { return TlsAlert.InternalError, true; }
    if code == 109 { return TlsAlert.MissingExtension, true; }
    if code == 110 { return TlsAlert.UnsupportedExtension, true; }
    if code == 112 { return TlsAlert.UnrecognizedName, true; }
    if code == 113 { return TlsAlert.BadCertificateStatusResponse, true; }
    if code == 116 { return TlsAlert.CertificateRequired, true; }
    if code == 120 { return TlsAlert.NoApplicationProtocol, true; }
    return TlsAlert.DecodeError, false;
}

// ---- 2. Zero-Copy Parsers (ByteCursor & ByteBuilder) -------------------------

struct ByteCursor {
    buf: const u8[:] = []
}

inline fn cursor_from(buf: const u8[:]) -> ByteCursor {
    return ByteCursor { buf: buf };
}

inline fn cursor_len(c: const ByteCursor&) -> i64 {
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
    var length: u8 = 0;
    if !get_u8(c, length) { return false; }
    return get_bytes(c, out, length);
}

fn get_u16_length_prefixed(c: ByteCursor&, out: ByteCursor&) -> bool {
    var length: u16 = 0;
    if !get_u16(c, length) { return false; }
    return get_bytes(c, out, length);
}

fn get_u24_length_prefixed(c: ByteCursor&, out: ByteCursor&) -> bool {
    var length: u32 = 0;
    if !get_u24(c, length) { return false; }
    return get_bytes(c, out, length);
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
    buf: u8[>..] = [],
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
    if b.offsets.len == 0 { return false; }
    let start = b.offsets.pop();
    let body_len = b.buf.len - start - 1;
    if body_len > 255 { return false; }
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
    if b.offsets.len == 0 { return false; }
    let start = b.offsets.pop();
    let body_len = b.buf.len - start - 2;
    if body_len > 65535 { return false; }
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
    if b.offsets.len == 0 { return false; }
    let start = b.offsets.pop();
    let body_len = b.buf.len - start - 3;
    if body_len > 16777215 { return false; }
    b.buf[start] = ((body_len >> 16) & 0xFF) as u8;
    b.buf[start + 1] = ((body_len >> 8) & 0xFF) as u8;
    b.buf[start + 2] = (body_len & 0xFF) as u8;
    return true;
}

// ---- 3. TLS Record Layer Framing & Invariants (RFC 8446 Section 5) ---------

const RECORD_BUFSIZE_IN: i64 = 16709; // 16384 + 325 (BearSSL BR_SSL_BUFSIZE_INPUT)
const RECORD_BUFSIZE_OUT: i64 = 16469; // 16384 + 85 (BearSSL BR_SSL_BUFSIZE_OUTPUT)
const MAX_RECORD_PLAINTEXT_LEN: i64 = 16384;
const MAX_RECORD_CIPHERTEXT_LEN: i64 = 16640; // 2^14 + 256
const TLS_RECORD_HEADER_LEN: i64 = 5;

const MAX_EMPTY_RECORDS: i32 = 32; // BoringSSL kMaxEmptyRecords DoS defense
const MAX_EARLY_DATA_SKIPPED: i64 = 16384; // BoringSSL kMaxEarlyDataSkipped

const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;
const CONTENT_TYPE_ALERT: u8 = 0x15;
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

const LEGACY_RECORD_VERSION_TLS12: u16 = 0x0303;
const TLS13_VERSION: u16 = 0x0304;

// Computes 96-bit (12-byte) per-record nonce: N = iv ^ (0^32 || be64(seq_num))
fn compute_record_nonce(iv: const u8[12]&, seq_num: u64) -> u8[12] {
    var nonce: u8[12] = [0; 12];
    for i in 12 { nonce[i] = iv[i]; }
    for i in 8 {
        let b = ((seq_num >> ((7 - i) * 8)) & 0xFF) as u8;
        nonce[4 + i] ^= b;
    }
    return nonce;
}

// Unpacks TLSInnerPlaintext: strips trailing 0x00 padding bytes and extracts true ContentType.
fn unpack_tls_inner_plaintext(decrypted: const u8[:]) -> const u8[:], u8, TlsAlert {
    var c = ByteCursor { buf: decrypted };
    var inner_type: u8 = 0;
    var last_byte: u8 = 0;
    while get_last_u8(c, last_byte) {
        if last_byte != 0x00 {
            inner_type = last_byte;
            break;
        }
    }
    if inner_type == 0 {
        return decrypted[..0], 0, TlsAlert.UnexpectedMessage;
    }
    return c.buf, inner_type, TlsAlert.CloseNotify;
}

// DoS filter tracking consecutive empty records and early data skipped volume.
struct RecordFilterState {
    empty_records_count: i32 = 0,
    early_data_skipped_bytes: i64 = 0,
}

fn check_record_payload_length(state: RecordFilterState&, payload_len: i64, is_early_data: bool) -> TlsAlert {
    if payload_len < 0 || payload_len > MAX_RECORD_PLAINTEXT_LEN {
        return TlsAlert.RecordOverflow;
    }

    if payload_len == 0 {
        state.empty_records_count++;
        if state.empty_records_count > MAX_EMPTY_RECORDS {
            return TlsAlert.UnexpectedMessage;
        }
    } else {
        state.empty_records_count = 0;
    }

    if is_early_data {
        state.early_data_skipped_bytes += payload_len;
        if state.early_data_skipped_bytes > MAX_EARLY_DATA_SKIPPED {
            return TlsAlert.UnexpectedMessage;
        }
    }
    return TlsAlert.CloseNotify;
}

// Encodes the 5-byte TLSCiphertext record header.
fn encode_tls_ciphertext_header<B>(out: B&, content_type: u8, ciphertext_len: u16) -> bool {
    out.push(content_type);
    out.push(((LEGACY_RECORD_VERSION_TLS12 >> 8) & 0xFF) as u8);
    out.push((LEGACY_RECORD_VERSION_TLS12 & 0xFF) as u8);
    out.push(((ciphertext_len >> 8) & 0xFF) as u8);
    out.push((ciphertext_len & 0xFF) as u8);
    return true;
}

// Parses 5-byte record header and validates RFC 8446 length bounds.
fn parse_tls_record_header(hdr_bytes: const u8[:]) -> u8, u16, u16, TlsAlert, bool {
    guard hdr_bytes.len >= 5 else {
        return 0, 0, 0, TlsAlert.DecodeError, false;
    }
    let content_type = hdr_bytes[0];
    let version = ((hdr_bytes[1] as u16) << 8) | hdr_bytes[2];
    let length = ((hdr_bytes[3] as u16) << 8) | hdr_bytes[4];

    if length > MAX_RECORD_CIPHERTEXT_LEN {
        return content_type, version, length, TlsAlert.RecordOverflow, false;
    }
    return content_type, version, length, TlsAlert.CloseNotify, true;
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
    let sample_offset = (pn_offset as i64) + 4;
    guard sample_offset + 16 <= pkt.len else {
        return pkt[..0], false;
    }
    return pkt[sample_offset .. sample_offset + 16], true;
}

// Connection container for QUIC Crypto state machine isolation.
struct QuicCryptoConn {
    read_level: QuicEncryptionLevel = QuicEncryptionLevel.Initial,
    write_level: QuicEncryptionLevel = QuicEncryptionLevel.Initial,
    events: QuicOutputEvent[..8] = [],
}

fn new_quic_crypto_conn() -> QuicCryptoConn {
    return QuicCryptoConn {
        read_level: QuicEncryptionLevel.Initial,
        write_level: QuicEncryptionLevel.Initial,
        events: [],
    };
}

// Validates RFC 9001 invariants on incoming QUIC handshake bytes:
// 1. Encryption level must match current read_level.
// 2. ChangeCipherSpec is strictly forbidden in QUIC streams.
fn provide_quic_data(conn: QuicCryptoConn&, level: QuicEncryptionLevel, data: const u8[:]) -> TlsAlert {
    if quic_encryption_level_to_u8(level) != quic_encryption_level_to_u8(conn.read_level) {
        return TlsAlert.UnexpectedMessage;
    }
    for b in data {
        if b == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
            return TlsAlert.UnexpectedMessage;
        }
    }
    return TlsAlert.CloseNotify;
}
