# `tls`

`tls` implements a TLS 1.3 record layer (RFC 8446), handshake state machine,
X.509 PKI certificate validator (RFC 5280), Encrypted Client Hello (ECH, RFC
9849), Hybrid Post-Quantum Key Exchange (RFC 10024 and FIPS 203 ML-KEM-768), and
certificate compression (RFC 8879).

```goose
import wing;

let slot_id = wing::tls_client_handshake(fd, "example.com", "h2", 5000);
if slot_id >= 0 {
    let _ = wing::tls_transport_send(fd, slot_id, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", 5000);
    let data, status = wing::tls_transport_recv_slice(fd, slot_id, 5000);
    wing::tls_transport_close(fd, slot_id);
}
```

## Public API

### TLS Record Layer, Alert Protocol & QUIC Crypto Streams (`tls/record.goose`, RFC 8446 §5, RFC 9001)

```goose
enum TlsAlert {
    CloseNotify, UnexpectedMessage, BadRecordMac, RecordOverflow, HandshakeFailure,
    BadCertificate, UnsupportedCertificate, CertificateRevoked, CertificateExpired,
    CertificateUnknown, IllegalParameter, UnknownCa, AccessDenied, DecodeError,
    DecryptError, ProtocolVersion, InsufficientSecurity, InternalError,
    InappropriateFallback, UserCanceled, MissingExtension, UnsupportedExtension,
    UnrecognizedName, BadCertificateStatusResponse, UnknownPskIdentity,
    CertificateRequired, NoApplicationProtocol, EchRequired,
}

struct RecordFilterState {
    empty_record_count: u32 = 0,
    ccs_count:          u32 = 0,
}

enum QuicEncryptionLevel { Initial, ZeroRtt, Handshake, OneRtt }
enum QuicOutputEvent { None, WriteData, InstallReadKeys, InstallWriteKeys, HandshakeComplete, Alert }

struct QuicCryptoStream {
    level: QuicEncryptionLevel = QuicEncryptionLevel.Initial,
    buf:   u8[..16384]         = [],
}

struct QuicCryptoConn {
    is_server: bool            = true,
    level:     QuicEncryptionLevel = QuicEncryptionLevel.Initial,
}

fn tls_alert_to_u8(alert: TlsAlert) -> u8
fn u8_to_tls_alert(code: u8) -> TlsAlert, bool
fn parse_tls_alert_message(payload: const u8[:]) -> u8, TlsAlert, TlsAlert, bool
fn compute_record_nonce(iv: const u8[12]&, seq_num: u64) -> u8[12], bool
fn increment_record_seq_num(seq_num: u64&) -> bool
fn parse_tls_record_header(buf: const u8[:]) -> u8, u16, u16, TlsAlert, bool
fn parse_tls_record_header_at(buf: const u8[:], pos: i64, is_encrypted: bool = false) -> u8, u16, u16, TlsAlert, bool
fn check_record_payload_length(payload_len: i64, is_encrypted: bool) -> TlsAlert, bool
fn check_change_cipher_spec_record(payload: const u8[:], state: RecordFilterState&) -> TlsAlert, bool
fn unpack_tls_inner_plaintext(decrypted: const u8[:]) -> i64, u8, TlsAlert, bool
fn tls_record_seal_into(cipher_suite: u16, key: const u8[:], iv: const u8[12]&, seq_num: u64, inner_type: u8, plaintext: const u8[:], dst: u8[:]) -> i64, TlsAlert, bool
fn tls_record_decrypt_into(cipher_suite: u16, key: const u8[:], iv: const u8[12]&, seq_num: u64, record_header: const u8[:], record_payload: const u8[:], out_plaintext: u8[:]) -> i64, u8, TlsAlert, bool
fn tls_record_seal_aes128_gcm_into(key: const u8[16]&, iv: const u8[12]&, seq_num: u64, inner_content_type: u8, plaintext: const u8[:], out_record: u8[:]) -> i64, TlsAlert, bool
fn tls_record_decrypt_aes128_gcm_into(key: const u8[16]&, iv: const u8[12]&, seq_num: u64, record_header: const u8[:], record_payload: const u8[:], out_plaintext: u8[:]) -> i64, u8, TlsAlert, bool
fn tls_record_decrypt_aes128_gcm(key: const u8[16]&, iv: const u8[12]&, seq_num: u64, record_header: const u8[:], record_payload: const u8[:]) -> u8[..16384], u8, TlsAlert, bool
fn tls_record_seal_aes256_gcm_into(key: const u8[32]&, iv: const u8[12]&, seq_num: u64, inner_content_type: u8, plaintext: const u8[:], out_record: u8[:]) -> i64, TlsAlert, bool
fn tls_record_decrypt_aes256_gcm_into(key: const u8[32]&, iv: const u8[12]&, seq_num: u64, record_header: const u8[:], record_payload: const u8[:], out_plaintext: u8[:]) -> i64, u8, TlsAlert, bool
fn tls_record_seal_chacha20_poly1305_into(key: const u8[32]&, iv: const u8[12]&, seq_num: u64, inner_content_type: u8, plaintext: const u8[:], out_record: u8[:]) -> i64, TlsAlert, bool
fn tls_record_decrypt_chacha20_poly1305_into(key: const u8[32]&, iv: const u8[12]&, seq_num: u64, record_header: const u8[:], record_payload: const u8[:], out_plaintext: u8[:]) -> i64, u8, TlsAlert, bool
fn new_quic_crypto_conn(is_server: bool = true) -> QuicCryptoConn
fn provide_quic_data(conn: QuicCryptoConn&, level: QuicEncryptionLevel, data: const u8[:]) -> QuicOutputEvent
fn new_quic_crypto_stream(level: QuicEncryptionLevel) -> QuicCryptoStream
fn quic_crypto_stream_ingest(stream: QuicCryptoStream&, offset: u64, data: const u8[:]) -> TlsAlert, bool
```

`check_record_payload_length` enforces RFC 8446 §5.1 plaintext (`16,384` bytes)
and §5.2 `TLSCiphertext` (`16,640` bytes) limits, returning
`TlsAlert.RecordOverflow` on violation. `compute_record_nonce` XORs the 96-bit
static IV with the 64-bit sequence number (`iv ^ seq_num`) and rejects
`0xFFFFFFFFFFFFFFFF` so sequence numbers never wrap.
`unpack_tls_inner_plaintext` scans backward past zero padding to extract the
inner `ContentType` byte. `quic_crypto_stream_ingest` reassembles out-of-order
QUIC `CRYPTO` frames per encryption epoch (`QuicEncryptionLevel`).

### Key Schedule & 0-RTT Anti-Replay (`tls/key_schedule.goose`, RFC 8446 §7, §8)

```goose
struct KeySchedule {
    hash_id:                  u8     = 1,
    hash_len:                 u8     = 32,
    stage:                    u8     = 0,
    early_secret:             u8[48] = [0; 48],
    handshake_secret:         u8[48] = [0; 48],
    master_secret:            u8[48] = [0; 48],
    client_early_traffic:     u8[48] = [0; 48],
    client_handshake_traffic: u8[48] = [0; 48],
    server_handshake_traffic: u8[48] = [0; 48],
    client_app_traffic:       u8[48] = [0; 48],
    server_app_traffic:       u8[48] = [0; 48],
    exporter_master:          u8[48] = [0; 48],
    resumption_master:        u8[48] = [0; 48],
}

struct ZeroRttStrikeRegister {
    window_ms: i64 = 10000,
    epoch_ms:  i64 = 0,
}

fn ks_init(cipher_suite: u16) -> KeySchedule, bool
fn ks_init_early_secret(ks: KeySchedule&, psk: const u8[:]) -> bool
fn ks_init_early_secret_with_mode(ks: KeySchedule&, psk: const u8[:], ke_mode: u8) -> bool
fn ks_derive_early_traffic(ks: KeySchedule&, client_hello_hash: const u8[:], is_external_psk: bool = false) -> bool
fn ks_advance_to_handshake(ks: KeySchedule&, ecdhe_shared_secret: const u8[:]) -> bool
fn ks_derive_handshake_traffic(ks: KeySchedule&, hello_transcript_hash: const u8[:]) -> bool
fn ks_advance_to_master(ks: KeySchedule&, server_finished_hash: const u8[:]) -> bool
fn ks_advance_to_resumption(ks: KeySchedule&, client_finished_hash: const u8[:]) -> bool
fn ks_export_keying_material(ks: const KeySchedule&, label: const u8[:], context: const u8[:], use_early: bool, length: u16, out: u8[:]) -> bool
fn ks_derive_resumption_psk(ks: const KeySchedule&, ticket_nonce: const u8[:], out_psk: u8[..48]&) -> bool
fn ks_derive_key_iv(ks: const KeySchedule&, traffic_secret: const u8[:], key_len: u16, out_key: u8[:], out_iv: u8[12]&) -> bool
fn ks_derive_quic_hp_key(ks: const KeySchedule&, traffic_secret: const u8[:], hp_len: u16, out_hp: u8[:]) -> bool
fn ks_compute_finished_verify_data(ks: const KeySchedule&, base_key: const u8[:], transcript_hash: const u8[:], out_verify: u8[..48]&) -> bool
fn ks_update_traffic_secret(ks: KeySchedule&, is_client: bool) -> bool
fn ks_zeroize(ks: KeySchedule&)
fn verify_psk_binder(ks: const KeySchedule&, partial_ch_hash: const u8[:], received_binder: const u8[:]) -> bool
fn hkdf_expand_label(hash_id: u8, secret: const u8[:], label: const u8[:], context: const u8[:], length: u16, out: u8[:]) -> bool
fn derive_secret(hash_id: u8, hash_len: u8, secret: const u8[:], label: const u8[:], transcript_hash: const u8[:], out: u8[:]) -> bool
fn strike_register_init(window_ms: i64, now_ms: i64) -> ZeroRttStrikeRegister
fn strike_register_rotate(sr: ZeroRttStrikeRegister&, now_ms: i64)
fn strike_register_check_and_insert(sr: ZeroRttStrikeRegister&, client_random: const u8[32]&, ticket_nonce: const u8[:], now_ms: i64) -> bool
fn validate_ticket_age(obfuscated_ticket_age: u32, ticket_age_add: u32, issued_at_ms: i64, now_ms: i64, max_lifetime_ms: i64, skew_tolerance_ms: i64) -> bool
```

`KeySchedule` enforces stage transitions (`Early` -> `Handshake` -> `Master` ->
`Resumption`) using SHA-256 (`TLS_AES_128_GCM_SHA256`,
`TLS_CHACHA20_POLY1305_SHA256`) or SHA-384 (`TLS_AES_256_GCM_SHA384`).
`verify_psk_binder` compares the `PreSharedKey` binder HMAC in constant time.
For 0-RTT early data (RFC 8446 §8), `validate_ticket_age` checks the
deobfuscated ticket age against the server clock skew window, and
`strike_register_check_and_insert` records `(client_random, ticket_nonce)` pairs
to reject replayed 0-RTT flight attempts.

### TLS 1.3 Handshake State Machine (`tls/handshake.goose`, RFC 8446 §4)

```goose
enum HandshakeMode { Full, Psk }
enum ClientAuthMode { Disabled, Requested }

enum HsState {
    ClientStart, ClientWaitSH, ClientWaitEE, ClientWaitCertCr, ClientWaitCert,
    ClientWaitCV, ClientWaitFinished, ServerWaitCH, ServerWaitEOED,
    ServerWaitCert, ServerWaitCV, ServerWaitFinished, Connected, Closed,
}

enum EarlyDataAccepted { Rejected, Accepted }
enum NegotiatedAlpn { None, H2, Http11, H3 }
enum EarlyDataState { None, Offered, Accepted, Rejected, Completed }

struct TlsExtensionEntry {
    ext_type: u16 = 0,
    offset:   u16 = 0,
    length:   u16 = 0,
}

struct CompressedCertMsg {
    algorithm:           u16 = 0,
    uncompressed_length: u32 = 0,
    compressed_len:      u32 = 0,
}

struct ParsedServerHello {
    legacy_version:        u16    = 0x0303,
    random:                u8[32] = [0; 32],
    cipher_suite:          u16    = 0,
    selected_version:      u16    = 0,
    key_share_group:       u16    = 0,
    key_share_offset:      u16    = 0,
    key_share_len:         u16    = 0,
    selected_psk_identity: u16    = 0,
    has_selected_psk:      bool   = false,
    is_hrr:                bool   = false,
}

struct NewSessionTicketMsg {
    ticket_lifetime:     u32       = 0,
    ticket_age_add:      u32       = 0,
    ticket_nonce:        u8[..255] = [],
    ticket:              u8[..512] = [],
    max_early_data_size: u32       = 0,
}

struct SessionTicketCache {
    tickets: NewSessionTicketMsg[..8] = [],
    cursor:  i64                      = 0,
}

struct KeyUpdateTracker {
    received_count: u32 = 0,
    pending_ack:    bool = false,
}

struct CertificateRequestMsg {
    context:     u8[..255] = [],
    sig_schemes: u16[..16] = [],
}

struct EarlyDataController {
    state:                  EarlyDataState = EarlyDataState.None,
    max_early_data_size:    u32            = 0,
    bytes_sent_or_received: u32            = 0,
}

fn validate_client_handshake_transition(cur: HsState, mode: HandshakeMode, msg_type: u8) -> HsState, TlsAlert, bool
fn validate_server_handshake_transition_auth(cur: HsState, mode: HandshakeMode, auth_mode: ClientAuthMode, early_data: EarlyDataAccepted, msg_type: u8) -> HsState, TlsAlert, bool
fn validate_server_handshake_transition(cur: HsState, mode: HandshakeMode, require_client_auth: bool, accept_early_data: bool, msg_type: u8) -> HsState, TlsAlert, bool
fn parse_handshake_header(buf: const u8[:]) -> u8, u32, TlsAlert, bool
fn encode_handshake_header<B>(msg_type: u8, payload_len: u32, out: B&) -> bool
fn is_hello_retry_request(server_random: const u8[32]&) -> bool
fn compress_hrr_transcript(hash_id: u8, ch1_bytes: const u8[:], out_msg_hash: u8[..52]&) -> bool
fn build_synthetic_message_hash(ch1_hash: const u8[:], hash_len: u8, out: u8[..52]&) -> i64
fn validate_server_random_downgrade(server_random: const u8[32]&, negotiated_version: u16) -> TlsAlert, bool
fn parse_sni_extension(ext_data: const u8[:]) -> const u8[:], TlsAlert, bool
fn negotiate_alpn(client_ext: const u8[:], allow_h3: bool, allow_h2: bool, allow_http11: bool) -> NegotiatedAlpn, TlsAlert, bool
fn parse_extensions_block(ext_block: const u8[:], context_msg_type: u8, out_entries: TlsExtensionEntry[..32]&) -> TlsAlert, bool
fn find_extension(entries: const TlsExtensionEntry[:], ext_block: const u8[:], target_type: u16) -> const u8[:], bool
fn parse_client_supported_versions(ext_data: const u8[:]) -> bool, TlsAlert, bool
fn parse_server_supported_versions(ext_data: const u8[:]) -> u16, TlsAlert, bool
fn parse_live_server_hello(payload: const u8[:], out: ParsedServerHello&) -> TlsAlert, bool
fn fragment_client_hello(ch_msg: const u8[:], max_frag_size: i64, out_records: u8[>..]&) -> bool
fn parse_new_session_ticket(payload: const u8[:], out: NewSessionTicketMsg&) -> TlsAlert, bool
fn cache_session_ticket(cache: SessionTicketCache&, msg: const NewSessionTicketMsg&)
fn encode_new_session_ticket<B>(lifetime: u32, age_add: u32, nonce: const u8[:], ticket: const u8[:], max_early_data: u32, out: B&) -> bool
fn track_received_key_update(tracker: KeyUpdateTracker&, request_update: u8) -> TlsAlert, bool
fn encode_key_update<B>(request_update: u8, out: B&) -> bool
fn parse_certificate_request(payload: const u8[:], out: CertificateRequestMsg&) -> TlsAlert, bool
fn encode_certificate_request<B>(context: const u8[:], sig_schemes: const u16[:], out: B&) -> bool
fn encode_client_certificate<B>(context: const u8[:], cert_der: const u8[:], out: B&) -> bool
fn encode_client_certificate_verify<B>(sig_scheme: u16, signature: const u8[:], out: B&) -> bool
fn parse_certificate_verify(payload: const u8[:]) -> u16, const u8[:], TlsAlert, bool
fn verify_tls13_certificate_verify_sig(is_server: bool, sig_scheme: u16, signature: const u8[:], transcript_hash: const u8[:], leaf_cert: const ParsedCert&, leaf_raw: const u8[:]) -> TlsAlert
fn verify_client_certificate_verify(sig_scheme: u16, signature: const u8[:], transcript_hash: const u8[:], client_cert: const ParsedCert&, client_raw: const u8[:]) -> TlsAlert
```

`validate_client_handshake_transition` and
`validate_server_handshake_transition_auth` enforce the RFC 8446 Appendix A
state machine, returning `TlsAlert.UnexpectedMessage` if `Finished` arrives
before `Certificate` / `CertificateVerify` in non-PSK handshakes.
`parse_extensions_block` indexes up to 32 extensions while rejecting duplicate
extension IDs or extensions forbidden in the current handshake message type.
`is_hello_retry_request` checks `ServerHello.random` against the RFC 8446 §4.1.3
SHA-256("HelloRetryRequest") sentinel, and `compress_hrr_transcript` replaces
`ClientHello1` with the `[254, 0, 0, hash_len, Hash(CH1)]` synthetic
`message_hash` construct.

### TLS 1.3 Live Transport & Session Tickets (`tls/session.goose`)

```goose
struct TlsTranscript {
    sha256_ctx: core::Sha256Ctx = core::Sha256Ctx { .. },
    sha384_ctx: core::Sha384Ctx = core::Sha384Ctx { .. },
}

struct TlsCipherSlot {
    in_use:       bool   = false,
    is_server:    bool   = false,
    cipher_suite: u16    = 0,
    rx_seq:       u64    = 0,
    tx_seq:       u64    = 0,
    rx_key:       u8[32] = [0; 32],
    tx_key:       u8[32] = [0; 32],
    rx_iv:        u8[12] = [0; 12],
    tx_iv:        u8[12] = [0; 12],
}

struct Tls13CachedSessionTicket {
    sni:                 u8[..128] = [],
    ticket:              u8[..512] = [],
    psk:                 u8[..48]  = [],
    cipher_suite:        u16       = 0,
    age_add:             u32       = 0,
    max_early_data_size: u32       = 0,
    alpn:                u8[..32]  = [],
}

struct TlsTicketStek {
    key_name:         u8[16] = [0; 16],
    key:              u8[32] = [0; 32],
    valid_from_unix:  i64    = 0,
    valid_until_unix: i64    = 0,
}

struct TlsTicketKeyRing {
    keys:       TlsTicketStek[..4] = [],
    active_idx: i32                = 0,
}

struct HandshakeRecordReader {
    buf: u8[..16384] = [],
}

struct TlsClientHandshakeConfig {
    sni:                    u8[..128]  = [],
    alpn:                   u8[..32]   = "h2",
    ca_cert_der:            u8[..2048] = [],
    client_cert_der:        u8[..2048] = [],
    client_private_key:     u8[32]     = [0; 32],
    skip_verify:            bool       = false,
    enable_session_tickets: bool       = true,
    prefer_pq:              bool       = false,
}

struct TlsServerHandshakeConfig {
    cert_der:            u8[..2048]       = [],
    private_key:         u8[32]           = [0; 32],
    alpn:                u8[..32]         = "h2",
    ticket_key_ring:     TlsTicketKeyRing = TlsTicketKeyRing { .. },
    require_client_cert: bool             = false,
    client_ca_der:       u8[..2048]       = [],
}

fn transcript_update(t: TlsTranscript&, data: const u8[:])
fn transcript_update_msg(t: TlsTranscript&, msg_type: u8, payload: const u8[:])
fn transcript_current_hash(t: const TlsTranscript&, out: u8[..48]&) -> u8
fn transcript_replace_with_message_hash(t: TlsTranscript&)
fn seal_stateless_tls13_ticket<B>(stek: const TlsTicketStek&, cipher_suite: u16, resumption_psk: const u8[:], alpn: const u8[:], sni: const u8[:], issued_at_sec: i64, lifetime_sec: u32, age_add: u32, max_early_data: u32, nonce_seed: u64, out: B&) -> bool
fn open_stateless_tls13_ticket(ring: const TlsTicketKeyRing&, raw_ticket: const u8[:], now_sec: i64, out_cipher_suite: u16&, out_psk: u8[..48]&, out_alpn: u8[..32]&, out_sni: u8[..128]&, out_issued_at_sec: i64&, out_age_add: u32&, out_max_early_data: u32&) -> bool
fn store_tls13_session_ticket(sni: const u8[:], ticket: const u8[:], psk: const u8[:], cipher_suite: u16, age_add: u32, max_early_data: u32, lifetime_sec: u32, alpn: const u8[:], now_ms: i64)
fn lookup_tls13_session_ticket_full(sni: const u8[:], now_ms: i64, out: Tls13CachedSessionTicket&) -> bool
fn lookup_tls13_session_ticket(sni: const u8[:], out_ticket: u8[..512]&, out_psk: u8[..48]&, out_suite: u16&, out_age_add: u32&) -> bool
fn lookup_tls13_ticket_by_identity(ticket_id: const u8[:], out_psk: u8[..48]&, out_suite: u16&) -> bool
fn clear_tls13_session_tickets()
fn alloc_tls_cipher_slot() -> i32
fn free_tls_cipher_slot(slot_id: i32)
fn tls_session_alpn(slot_id: i32, out_alpn: u8[..32]&) -> bool
fn tls_session_is_resumed(slot_id: i32) -> bool
fn tls_session_export_keying_material(slot_id: i32, label: const u8[:], context: const u8[:], length: u16, out: u8[:]) -> bool
fn tls_client_handshake(fd: i64, sni: const u8[:], alpn: const u8[:] = "h2", timeout_ms: i32 = 5000, config: const TlsClientHandshakeConfig? = null) -> i32
fn tls_server_handshake(fd: i64, cert_der: const u8[:], private_key: const u8[32]&, alpn: const u8[:] = "h2", timeout_ms: i32 = 5000) -> i32
fn tls_server_handshake_with_ch(fd: i64, ch_record: const u8[:], cert_der: const u8[:], private_key: const u8[32]&, alpn: const u8[:] = "h2", timeout_ms: i32 = 5000, server_cfg: const TlsServerHandshakeConfig? = null) -> i32
fn tls_transport_send(fd: i64, slot_id: i32, data: const u8[:], timeout_ms: i32) -> i64
fn tls_transport_recv_slice(fd: i64, slot_id: i32, timeout_ms: i32) -> const u8[:], i32
fn tls_transport_close(fd: i64, slot_id: i32)
fn tls_send_new_session_ticket(fd: i64, slot_id: i32, stek: const TlsTicketStek&, lifetime_sec: u32 = 7200, max_early_data: u32 = 16384, timeout_ms: i32 = 5000) -> bool
fn tls_send_key_update(fd: i64, slot_id: i32, request_update: u8 = 0, timeout_ms: i32 = 5000) -> bool
fn build_test_ed25519_cert_der(public_key: const u8[32]&, private_key: const u8[32]&, dns_name: const u8[:], out_der: u8[..1024]&) -> bool
```

Manages up to 64 concurrent `TlsCipherSlot` sessions (`alloc_tls_cipher_slot` /
`free_tls_cipher_slot`). `seal_stateless_tls13_ticket` and
`open_stateless_tls13_ticket` encrypt and authenticate stateless server session
tickets with `XChaCha20-Poly1305` using a 16-byte `key_name` prefix looked up in
`TlsTicketKeyRing`. `tls_transport_recv_slice` transparently processes
post-handshake `NewSessionTicket` and `KeyUpdate` messages while delivering
decrypted application data slices.

### X.509 PKI, SAN, OCSP & CRL Verification (`tls/x509.goose`, RFC 5280, RFC 6125, RFC 6960)

```goose
struct Span16 { offset: u16 = 0, length: u16 = 0 }

struct ParsedCert {
    tbs_span:        Span16 = Span16 { .. },
    serial_span:     Span16 = Span16 { .. },
    issuer_span:     Span16 = Span16 { .. },
    subject_span:    Span16 = Span16 { .. },
    spki_span:       Span16 = Span16 { .. },
    not_before_unix: i64    = 0,
    not_after_unix:  i64    = 0,
    is_ca:           bool   = false,
}

struct TrustAnchor {
    subject_der: u8[..256]  = [],
    spki_der:    u8[..512]  = [],
    raw_der:     u8[..2048] = [],
}

struct TrustAnchorStore {
    anchors: TrustAnchor[..32] = [],
}

struct ParsedSct {
    version:        u8     = 0,
    log_id:         u8[32] = [0; 32],
    timestamp_ms:   u64    = 0,
    sig_alg:        u16    = 0,
    signature_span: Span16 = Span16 { .. },
}

enum SanType { DnsName, IpAddress, Uri, Other }
struct SanEntry { san_type: SanType = SanType.DnsName, value_span: Span16 = Span16 { .. } }
struct NameConstraintEntry { is_permitted: bool = true, san_type: SanType = SanType.DnsName, subtree_span: Span16 = Span16 { .. } }

enum OcspResponseStatus { Successful, MalformedRequest, InternalError, TryLater, SigRequired, Unauthorized, Unknown }
enum OcspCertStatus { Good, Revoked, Unknown }

struct ParsedOcspResponse {
    response_status:       OcspResponseStatus = OcspResponseStatus.Unknown,
    cert_status:           OcspCertStatus     = OcspCertStatus.Unknown,
    this_update_unix:      i64                = 0,
    next_update_unix:      i64                = 0,
    has_next_update:       bool               = false,
    tbs_response_data_span: Span16            = Span16 { .. },
    sig_alg_oid_span:      Span16             = Span16 { .. },
    signature_span:        Span16             = Span16 { .. },
    serial_span:           Span16             = Span16 { .. },
}

struct ParsedCrl {
    tbs_span:         Span16   = Span16 { .. },
    issuer_span:      Span16   = Span16 { .. },
    this_update_unix: i64      = 0,
    next_update_unix: i64      = 0,
    has_next_update:  bool     = false,
    sig_alg_oid_span: Span16   = Span16 { .. },
    signature_span:   Span16   = Span16 { .. },
    revoked_hashes:   u64[128] = [0; 128],
    revoked_count:    i64      = 0,
}

fn parse_x509_certificate(raw_cert: const u8[:], out: ParsedCert&) -> bool
fn add_trust_anchor(store: TrustAnchorStore&, subject: const u8[:], spki: const u8[:]) -> bool
fn add_trust_anchor_cert_der(store: TrustAnchorStore&, raw_cert: const u8[:]) -> bool
fn matches_trust_anchor(cert: const ParsedCert&, raw_cert: const u8[:], store: const TrustAnchorStore&) -> bool
fn verify_certificate_chain(chain_certs: const ParsedCert[..8]&, raw_certs: const u8[:][..8]&, trust_store: const TrustAnchorStore&, now_unix: i64) -> TlsAlert
fn x509_verify_cert_signature(child_cert: const ParsedCert&, child_raw: const u8[:], issuer_cert: const ParsedCert&, issuer_raw: const u8[:]) -> bool
fn parse_san_extension(ext_value: const u8[:], base_offset: u16, out_entries: SanEntry[..32]&) -> bool
fn get_cert_san_extension(cert: const ParsedCert&, raw_cert: const u8[:]) -> const u8[:], u16, bool
fn match_dns_san(reference_host: const u8[:], san_dns: const u8[:]) -> bool
fn match_ip_san(reference_ip_bytes: const u8[:], san_ip_bytes: const u8[:]) -> bool
fn match_uri_san(reference_uri: const u8[:], san_uri: const u8[:]) -> bool
fn match_san(cert: const ParsedCert&, raw_cert: const u8[:], host_or_ip: const u8[:], is_ip: bool, ip_bytes: const u8[:]) -> bool
fn match_any_san(entries: const SanEntry[:], raw_buf: const u8[:], reference_dns: const u8[:], reference_ip: const u8[:]) -> bool
fn parse_name_constraints(ext_value: const u8[:], base_offset: u16, out_constraints: NameConstraintEntry[..32]&) -> bool
fn check_name_constraints(constraints: const NameConstraintEntry[:], ca_raw: const u8[:], leaf_sans: const SanEntry[:], leaf_raw: const u8[:]) -> bool
fn parse_sct_entry(buf: const u8[:], base_offset: u16, out: ParsedSct&) -> bool
fn parse_sct_list(ext_data: const u8[:], out_scts: ParsedSct[..8]&) -> bool
fn parse_ocsp_response(raw_ocsp: const u8[:], out: ParsedOcspResponse&) -> bool
fn x509_verify_ocsp_signature(ocsp: const ParsedOcspResponse&, raw_ocsp: const u8[:], issuer_cert: const ParsedCert&, issuer_raw: const u8[:]) -> bool
fn validate_ocsp_stapling(raw_ocsp: const u8[:], leaf_cert: const ParsedCert&, leaf_raw: const u8[:], now_unix: i64) -> TlsAlert
fn parse_x509_crl(raw_crl: const u8[:], out: ParsedCrl&) -> bool
fn crl_insert_serial(crl: ParsedCrl&, serial_bytes: const u8[:])
fn crl_is_revoked(crl: const ParsedCrl&, serial_bytes: const u8[:]) -> bool
fn x509_verify_crl_signature(crl: const ParsedCrl&, raw_crl: const u8[:], issuer_cert: const ParsedCert&, issuer_raw: const u8[:]) -> bool
fn verify_signature_scheme_curve_binding(sig_scheme: u16, spki_curve_id: u8) -> bool
fn build_certificate_verify_message(is_server: bool, transcript_hash: const u8[:], out_msg: u8[..146]&) -> bool
```

`parse_x509_certificate` enforces X.690 canonical DER length and integer padding
rules (forbidding BER indefinite lengths and non-minimal encodings) and records
16-bit `Span16` offsets into the caller's DER buffer without copying.
`verify_certificate_chain` validates up to 8 certificates against
`TrustAnchorStore`, checking cryptographic signatures (`Ed25519`, `ECDSA-P256`,
`RSA-PKCS1-SHA256`, `RSA-PSS-SHA256`), `BasicConstraints` `cA` and
`pathLenConstraint`, `KeyUsage`, `NameConstraints` permitted/excluded subtrees,
and validity timestamps. `match_dns_san` enforces RFC 6125 §6.4.3 single-label
leftmost wildcard rules.

### Hybrid Post-Quantum Key Exchange (`tls/post_quantum.goose`, RFC 10024 / FIPS 203)

```goose
struct PostQuantumKeyShare {
    group:           u16      = 0x11EC,
    x25519_public:   u8[32]   = [0; 32],
    mlkem768_public: u8[1184] = [0; 1184],
}

struct PostQuantumServerShare {
    group:               u16      = 0x11EC,
    x25519_public:       u8[32]   = [0; 32],
    mlkem768_ciphertext: u8[1088] = [0; 1088],
}

struct SecP256r1MLKEM768KeyShare {
    group:            u16      = 0x11EB,
    secp256r1_public: u8[65]   = [0; 65],
    mlkem768_public:  u8[1184] = [0; 1184],
}

struct SecP256r1MLKEM768ServerShare {
    group:               u16      = 0x11EB,
    secp256r1_public:    u8[65]   = [0; 65],
    mlkem768_ciphertext: u8[1088] = [0; 1088],
}

struct SecP384r1MLKEM1024KeyShare {
    group:            u16      = 0x11ED,
    secp384r1_public: u8[97]   = [0; 97],
    mlkem1024_public: u8[1568] = [0; 1568],
}

struct SecP384r1MLKEM1024ServerShare {
    group:                u16      = 0x11ED,
    secp384r1_public:     u8[97]   = [0; 97],
    mlkem1024_ciphertext: u8[1568] = [0; 1568],
}

struct MLKEM768PrivateKey {
    dk_pke: u8[1152] = [0; 1152],
    ek:     u8[1184] = [0; 1184],
    h_ek:   u8[32]   = [0; 32],
    z:      u8[32]   = [0; 32],
}

struct Poly256 { coeffs: i16[256] = [0; 256] }

fn format_hybrid_key_share<B>(share: const PostQuantumKeyShare&, out: B&)
fn parse_hybrid_key_share(share: PostQuantumKeyShare&, raw: const u8[:]) -> bool
fn format_hybrid_server_key_share<B>(share: const PostQuantumServerShare&, out: B&)
fn parse_hybrid_server_key_share(share: PostQuantumServerShare&, raw: const u8[:]) -> bool
fn format_secp256r1_mlkem768_key_share<B>(share: const SecP256r1MLKEM768KeyShare&, out: B&) -> bool
fn parse_secp256r1_mlkem768_key_share(share: SecP256r1MLKEM768KeyShare&, raw: const u8[:]) -> bool
fn format_secp256r1_mlkem768_server_share<B>(share: const SecP256r1MLKEM768ServerShare&, out: B&) -> bool
fn parse_secp256r1_mlkem768_server_share(share: SecP256r1MLKEM768ServerShare&, raw: const u8[:]) -> bool
fn format_secp384r1_mlkem1024_key_share<B>(share: const SecP384r1MLKEM1024KeyShare&, out: B&) -> bool
fn parse_secp384r1_mlkem1024_key_share(share: SecP384r1MLKEM1024KeyShare&, raw: const u8[:]) -> bool
fn format_secp384r1_mlkem1024_server_share<B>(share: const SecP384r1MLKEM1024ServerShare&, out: B&) -> bool
fn parse_secp384r1_mlkem1024_server_share(share: SecP384r1MLKEM1024ServerShare&, raw: const u8[:]) -> bool
fn mlkem768_keygen(d_seed: const u8[32]&, z_seed: const u8[32]&, out_ek: u8[1184]&, out_dk: MLKEM768PrivateKey&) -> bool
fn mlkem768_encapsulate(ek: const u8[1184]&, m_rand: const u8[32]&, out_ct: u8[1088]&, out_ss: u8[32]&) -> bool
fn mlkem768_decapsulate(dk: const MLKEM768PrivateKey&, ct: const u8[1088]&, out_ss: u8[32]&) -> bool
fn mlkem768_decapsulate_with_implicit_rejection(z: const u8[32]&, ct: const u8[1088]&, decrypted_k: const u8[32]&, ct_matches: bool, out_ss: u8[32]&)
fn mlkem768_compute_implicit_rejection(z: const u8[32]&, ct: const u8[1088]&, out_j: u8[32]&)
fn derive_x25519_mlkem768_shared_secret(mlkem_ss: const u8[32]&, x25519_ss: const u8[32]&, out_combined: u8[64]&) -> bool
fn derive_x25519_mlkem768_shared_secret_checked(z: const u8[32]&, ct: const u8[1088]&, mlkem_k: const u8[32]&, mlkem_ct_ok: bool, x25519_ss: const u8[32]&, out_combined: u8[64]&) -> bool
fn derive_secp256r1_mlkem768_shared_secret(ecdh_p256_ss: const u8[32]&, mlkem_ss: const u8[32]&, out_combined: u8[64]&) -> bool
fn derive_secp384r1_mlkem1024_shared_secret(ecdh_p384_ss: const u8[48]&, mlkem_ss: const u8[32]&, out_combined: u8[80]&) -> bool
fn derive_hybrid_shared_secret(mlkem_ss: const u8[32]&, x25519_ss: const u8[32]&, out_combined: u8[64]&) -> bool
fn derive_hybrid_shared_secret_checked(z: const u8[32]&, ct: const u8[1088]&, mlkem_k: const u8[32]&, mlkem_ct_ok: bool, x25519_ss: const u8[32]&, out_combined: u8[64]&) -> bool
```

Implements FIPS 203 ML-KEM-768 key generation, encapsulation (with §7.2
encapsulation key modulus verification over $\mathbb{Z}_{3329}$), and
Fujisaki-Okamoto decapsulation with constant-time SHAKE256 implicit rejection
(`J(z || ct)`). Supports `X25519MLKEM768` (`0x11EC`, ordered `mlkem768 ||
x25519`), `SecP256r1MLKEM768` (`0x11EB`, ordered `secp256r1 || mlkem768`), and
`SecP384r1MLKEM1024` (`0x11ED`, ordered `secp384r1 || mlkem1024`) per RFC 10024.

### Encrypted Client Hello & HPKE (`tls/ech.goose`, `tls/hpke.goose`, RFC 9849, RFC 9180)

```goose
struct EchCipherSuite { kdf_id: u16 = 0x0001, aead_id: u16 = 0x0001 }

struct EchConfig {
    version:             u16                 = 0xfe0d,
    length:              u16                 = 0,
    config_id:           u8                  = 0,
    kem_id:              u16                 = 0x0020,
    public_key:          u8[32]              = [0; 32],
    cipher_suites:       EchCipherSuite[..4] = [],
    maximum_name_length: u8                  = 0,
    public_name:         u8[..255]           = [],
    raw_bytes:           u8[..512]           = [],
}

struct EchConfigList { configs: EchConfig[..4] = [] }

struct EchClientState {
    enabled:         bool           = false,
    selected_config: EchConfig      = EchConfig { .. },
    selected_cipher: EchCipherSuite = EchCipherSuite { .. },
    inner_sni:       u8[..255]      = [],
    outer_sni:       u8[..255]      = [],
    enc:             u8[32]         = [0; 32],
    retry_configs:   u8[..512]      = [],
}

enum EchHandshakeMode { Disabled, Offered, Accepted, RejectedWithRetry, Grease }
enum EchServerHelloType { Standard, HelloRetryRequest }
enum EchClientHelloType { Outer, Inner }

struct EchFsm {
    mode:                   EchHandshakeMode = EchHandshakeMode.Disabled,
    hrr_received:           bool             = false,
    retry_configs_received: bool             = false,
    accept_confirmed:       bool             = false,
}

struct HpkeContext {
    key:             u8[32] = [0; 32],
    base_nonce:      u8[12] = [0; 12],
    seq:             u64    = 0,
    exporter_secret: u8[32] = [0; 32],
    aead_id:         u16    = 0x0001,
}

fn parse_ech_config(raw: const u8[:], out: EchConfig&) -> bool
fn parse_ech_config_list(raw: const u8[:], out_list: EchConfigList&) -> bool
fn select_ech_config(list: const EchConfigList&, out_cfg: EchConfig&, out_cs: EchCipherSuite&) -> bool
fn pad_ech_inner<B>(inner_bytes: const u8[:], max_name_len: u8, real_sni_len: i64, out_padded: B&) -> bool
fn build_ech_inner_extension<B>(out: B&)
fn encode_ech_outer_extensions<B>(ext_types: const u16[:], out: B&) -> bool
fn build_encoded_client_hello_inner<B>(inner_random: const u8[32]&, inner_sni: const u8[:], alpn: const u8[:], key_share_ext: const u8[:], outer_ext_types: const u16[:], max_name_len: u8, out_encoded: B&) -> bool
fn seal_ech_inner<B>(cfg: const EchConfig&, cs: const EchCipherSuite&, ephemeral_sk: const u8[32]&, ch_outer_aad: const u8[:], encoded_inner: const u8[:], out_enc: u8[32]&, out_ciphertext: B&, out_hpke_ctx: HpkeContext&) -> bool
fn build_ech_outer_extension<B>(config_id: u8, cs: const EchCipherSuite&, enc: const u8[32]&, ciphertext: const u8[:], out: B&) -> bool
fn compute_ech_accept_confirmation(inner_client_random: const u8[32]&, sh_transcript_hash_zeroed: const u8[:], hash_id: u8, is_hrr: bool, out_confirm: u8[8]&) -> bool
fn verify_ech_acceptance_confirmation(inner_client_random: const u8[32]&, server_hello_random: const u8[32]&, sh_transcript_hash_zeroed: const u8[:], hash_id: u8, is_hrr: bool) -> bool
fn parse_and_validate_ech_retry_configs(raw_ext: const u8[:], out_list: EchConfigList&) -> TlsAlert, bool
fn ech_fsm_on_server_hello(fsm: EchFsm&, sh_type: EchServerHelloType, accept_signal_matched: bool) -> TlsAlert, bool
fn validate_ech_alpn_negotiation(fsm: const EchFsm&, selected_alpn: const u8[:], inner_alpn_list: const u8[:][:], outer_alpn_list: const u8[:][:]) -> TlsAlert, bool
fn dhkem_x25519_encap(pk_r: const u8[32]&, sk_e: const u8[32]&, out_shared_secret: u8[32]&, out_enc: u8[32]&) -> bool
fn dhkem_x25519_decap(enc: const u8[32]&, sk_r: const u8[32]&, out_shared_secret: u8[32]&) -> bool
fn hpke_setup_base_s(pk_r: const u8[32]&, sk_e: const u8[32]&, info: const u8[:], aead_id: u16, out_enc: u8[32]&, out_ctx: HpkeContext&) -> bool
fn hpke_setup_base_r(enc: const u8[32]&, sk_r: const u8[32]&, info: const u8[:], aead_id: u16, out_ctx: HpkeContext&) -> bool
fn hpke_seal<B>(ctx: HpkeContext&, aad: const u8[:], pt: const u8[:], out_ct: B&) -> bool
fn hpke_open<B>(ctx: HpkeContext&, aad: const u8[:], ct: const u8[:], out_pt: B&) -> bool
fn hpke_export(ctx: const HpkeContext&, exporter_context: const u8[:], length: u16, out_secret: u8[:]) -> bool
fn hpke_seal_base<B>(pk_r: const u8[32]&, sk_e: const u8[32]&, info: const u8[:], aad: const u8[:], pt: const u8[:], aead_id: u16, out_enc: u8[32]&, out_ct: B&) -> bool
fn hpke_open_base<B>(enc: const u8[32]&, sk_r: const u8[32]&, info: const u8[:], aad: const u8[:], ct: const u8[:], aead_id: u16, out_pt: B&) -> bool
```

`select_ech_config` chooses the first `0xfe0d` configuration using
`DHKEM(X25519,
HKDF-SHA256)`, `HKDF-SHA256`, and `AES-128-GCM` or `ChaCha20Poly1305`.
`pad_ech_inner` pads `EncodedClientHelloInner` to a 32-byte multiple per RFC
9849 §6.1.3 before `seal_ech_inner` encrypts it with HPKE Base mode (`"tls
ech\0"` info label). `verify_ech_acceptance_confirmation` checks the trailing 8
bytes of `ServerHello.random` against the HKDF-Expand-Label confirmation signal.

### Certificate Compression (`tls/cert_compression.goose`, RFC 8879)

```goose
struct CompressedCertificate {
    algorithm:                      u16         = 0x0002,
    uncompressed_length:            u32         = 0,
    compressed_certificate_message: const u8[:] = "",
}

fn encode_compressed_certificate<B>(msg: const CompressedCertificate&, out: B&) -> bool
fn parse_compressed_certificate_msg(raw: const u8[:], out: CompressedCertificate&) -> bool
fn decompress_certificate_message<B>(msg: CompressedCertificate, max_allowed_len: u32, out_cert: B&) -> bool
fn decompress_certificate_payload<B>(algorithm: u16, uncompressed_len: u32, compressed: const u8[:], max_allowed_len: u32, out_cert: B&) -> TlsAlert, bool
fn decompress_certificate_brotli<B>(compressed: const u8[:], expected_len: u32, out: B&) -> bool
fn decompress_certificate_zlib<B>(compressed: const u8[:], expected_len: u32, out: B&) -> bool
fn decompress_certificate_zstd<B>(compressed: const u8[:], expected_len: u32, out: B&) -> bool
```

`parse_compressed_certificate_msg` validates the 24-bit `uncompressed_length`
and enforces a maximum 1024x decompression expansion ratio before
`decompress_certificate_payload` dispatches `zlib` (`0x0001`), `brotli`
(`0x0002`), or `zstd` (`0x0003`) decompression and verifies that the
decompressed output matches `uncompressed_length` to the byte.
