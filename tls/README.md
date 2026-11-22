# `tls`

`tls` implements a TLS 1.3 record layer (RFC 8446), handshake state machine,
X.509 PKI certificate validator (RFC 5280), Encrypted Client Hello (ECH, RFC
9849), Hybrid Post-Quantum Key Exchange (RFC 10024 and FIPS 203 ML-KEM-768), and
certificate compression (RFC 8879).

Public types, constants, and functions live in `namespace tls;`. Low-level
internal helpers (`key_schedule.goose`, `post_quantum.goose`,
`cert_compression.goose`, `internal.goose`, `record_internal.goose`,
`ticket_internal.goose`, `pki_internal.goose`, `x509_chain_internal.goose`,
`handshake_internal.goose`, `session_internal.goose`,
`handshake_io_internal.goose`) live in `namespace tls_internal;`.

```goose
import wing;

let cfg = tls::ClientHandshakeConfig {
    server_name: "example.com",
    alpn:        "h2",
    ..
};
let slot_idx, ok = tls::client_handshake(fd, cfg);
if ok {
    let _ = tls::transport_send(fd, slot_idx, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    var rx_buf: u8[4096] = [0; 4096];
    let n = tls::transport_recv_slice(fd, slot_idx, rx_buf[..], 5000);
    tls::transport_close(fd, slot_idx);
}
```

## Public API

### TLS Record Layer, Alert Protocol & QUIC Crypto Streams (`tls/record.goose`, RFC 8446 §5, RFC 9001)

```goose
enum Alert {
    CloseNotify, UnexpectedMessage, BadRecordMac, RecordOverflow, HandshakeFailure,
    BadCertificate, UnsupportedCertificate, CertificateRevoked, CertificateExpired,
    CertificateUnknown, IllegalParameter, UnknownCa, AccessDenied, DecodeError,
    DecryptError, ProtocolVersion, InsufficientSecurity, InternalError,
    InappropriateFallback, UserCanceled, MissingExtension, UnsupportedExtension,
    UnrecognizedName, BadCertificateStatusResponse, UnknownPskIdentity,
    CertificateRequired, NoApplicationProtocol,
}

struct RecordFilterState {
    empty_records_count:      i32 = 0,
    early_data_skipped_bytes: i64 = 0,
    ccs_count:                i32 = 0,
}

enum QuicEncryptionLevel { Initial, EarlyData, Handshake, Application }

enum QuicOutputEvent {
    None,
    SetReadSecret    { level: QuicEncryptionLevel, cipher_id: u16, secret: u8[..48] = [], secret_len: u8 = 0 },
    SetWriteSecret   { level: QuicEncryptionLevel, cipher_id: u16, secret: u8[..48] = [], secret_len: u8 = 0 },
    AddHandshakeData { level: QuicEncryptionLevel, data: const u8[:] = [] },
    FlushFlight,
    SendAlert        { level: QuicEncryptionLevel, alert: Alert },
}

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

struct QuicCryptoConn {
    read_level:  QuicEncryptionLevel  = QuicEncryptionLevel.Initial,
    write_level: QuicEncryptionLevel  = QuicEncryptionLevel.Initial,
    events:      QuicOutputEvent[..8] = [],
}

fn alert_to_u8(alert: Alert) -> u8
fn u8_to_alert(code: u8) -> Alert, bool
fn parse_alert_message(data: const u8[:]) -> u8, Alert, bool, bool
fn compute_record_nonce(iv: const u8[12]&, seq_num: u64) -> u8[12], bool
fn increment_record_seq_num(seq_num: u64&) -> bool
fn parse_record_header(hdr_bytes: const u8[:]) -> u8, u16, u16, Alert, bool
fn parse_record_header_at(raw: const u8[:], idx: i64&) -> u8, u16, u16, Alert, bool
fn check_record_payload_length(state: RecordFilterState&, payload_len: i64, is_early_data: bool) -> Alert
fn check_change_cipher_spec_record(state: RecordFilterState&, payload: const u8[:], handshake_active: bool) -> Alert
fn unpack_inner_plaintext(decrypted: const u8[:]) -> const u8[:], u8, Alert
fn record_seal_into(cipher_suite: u16, key: const u8[:], iv: const u8[12]&, seq_num: u64, inner_type: u8, plaintext: const u8[:], out_ciphertext: u8[:]) -> i64, Alert, bool
fn record_decrypt_into(cipher_suite: u16, key: const u8[:], iv: const u8[12]&, seq_num: u64, record_header: const u8[:], record_payload: const u8[:], out_plaintext: u8[:]) -> i64, u8, Alert, bool
fn record_seal_aes128_gcm_into(key: const u8[16]&, iv: const u8[12]&, seq_num: u64, inner_type: u8, plaintext: const u8[:], out_ciphertext: u8[:]) -> i64, Alert, bool
fn record_decrypt_aes128_gcm_into(key: const u8[16]&, iv: const u8[12]&, seq_num: u64, record_header: const u8[:], record_payload: const u8[:], out_plaintext: u8[:]) -> i64, u8, Alert, bool
fn record_decrypt_aes128_gcm(key: const u8[16]&, iv: const u8[12]&, seq_num: u64, record_header: const u8[:], record_payload: const u8[:], out_plaintext: u8[>..]&) -> u8, Alert
fn record_seal_aes256_gcm_into(key: const u8[32]&, iv: const u8[12]&, seq_num: u64, inner_type: u8, plaintext: const u8[:], out_ciphertext: u8[:]) -> i64, Alert, bool
fn record_decrypt_aes256_gcm_into(key: const u8[32]&, iv: const u8[12]&, seq_num: u64, record_header: const u8[:], record_payload: const u8[:], out_plaintext: u8[:]) -> i64, u8, Alert, bool
fn record_seal_chacha20_poly1305_into(key: const u8[32]&, iv: const u8[12]&, seq_num: u64, inner_type: u8, plaintext: const u8[:], out_ciphertext: u8[:]) -> i64, Alert, bool
fn record_decrypt_chacha20_poly1305_into(key: const u8[32]&, iv: const u8[12]&, seq_num: u64, record_header: const u8[:], record_payload: const u8[:], out_plaintext: u8[:]) -> i64, u8, Alert, bool
fn provide_quic_data(conn: QuicCryptoConn&, level: QuicEncryptionLevel, data: const u8[:]) -> Alert
fn quic_crypto_stream_ingest(stream: QuicCryptoStream&, offset: u64, data: const u8[:]) -> i64, bool
```

`check_record_payload_length` enforces RFC 8446 §5.1 plaintext (`16,384` bytes)
and §5.2 `TLSCiphertext` (`16,640` bytes) limits, returning
`Alert.RecordOverflow` on violation and `Alert.CloseNotify` when valid.
`compute_record_nonce` XORs the 96-bit static IV with the 64-bit sequence number
(`iv ^ seq_num`) and rejects `0xFFFFFFFFFFFFFFFF` so sequence numbers never
wrap. `unpack_inner_plaintext` scans backward past zero padding to extract the
inner `ContentType` byte. `quic_crypto_stream_ingest` reassembles QUIC `CRYPTO`
frames per encryption epoch (`QuicEncryptionLevel`) with bounded out-of-order
staging (`4,096`-byte window, up to `16` disjoint ranges per RFC 9000 §7.5),
returning `(new_bytes, ok)`.

### Key Schedule & 0-RTT Anti-Replay (`tls/key_schedule.goose`, `namespace tls_internal`, RFC 8446 §7, §8)

```goose
struct KeySchedule {
    cipher_suite:          u16      = 0,
    hash_id:               u8       = 1,
    hash_len:              u8       = 32,
    stage:                 u8       = 0,
    current_secret:        u8[48]   = [0; 48],
    client_early_traffic:  u8[48]   = [0; 48],
    early_exporter_secret: u8[..48] = [],
    client_hs_traffic:     u8[48]   = [0; 48],
    server_hs_traffic:     u8[48]   = [0; 48],
    client_ap_traffic:     u8[48]   = [0; 48],
    server_ap_traffic:     u8[48]   = [0; 48],
    exporter_secret:       u8[48]   = [0; 48],
    resumption_secret:     u8[48]   = [0; 48],
    binder_key:            u8[48]   = [0; 48],
}

struct ZeroRttStrikeRegister {
    epoch_window_ms:      i64     = 10000,
    max_age_tolerance_ms: i64     = 2000,
    current_epoch:        i64     = 0,
    bitmap_current:       u64[64] = [0; 64],
    bitmap_previous:      u64[64] = [0; 64],
}

fn ks_init(cipher_suite: u16) -> KeySchedule, bool
fn ks_init_early_secret(ks: KeySchedule&, psk: const u8[:]) -> bool
fn ks_init_early_secret_with_mode(ks: KeySchedule&, psk: const u8[:], is_external: bool) -> bool
fn ks_derive_early_traffic(ks: KeySchedule&, client_hello_hash: const u8[:]) -> bool
fn ks_advance_to_handshake(ks: KeySchedule&, ecdhe_secret: const u8[:]) -> bool
fn ks_derive_handshake_traffic(ks: KeySchedule&, ch_sh_hash: const u8[:]) -> bool
fn ks_advance_to_master(ks: KeySchedule&, transcript_through_server_finished_hash: const u8[:]) -> bool
fn ks_advance_to_resumption(ks: KeySchedule&, transcript_through_client_finished_hash: const u8[:]) -> bool
fn ks_export_keying_material(ks: const KeySchedule&, label: const u8[:], context: const u8[:], key_length: u16, out: u8[:]) -> bool
fn ks_derive_resumption_psk(ks: const KeySchedule&, ticket_nonce: const u8[:], out_psk: u8[:]) -> bool
fn ks_derive_key_iv(hash_id: u8, secret: const u8[:], key_len: u16, out_key: u8[:], out_iv: u8[12]&) -> bool
fn ks_derive_quic_hp_key(hash_id: u8, secret: const u8[:], hp_key_len: u16, out_hp_key: u8[:], version: u32 = rfc::QUIC_VERSION_1) -> bool
fn ks_compute_finished_verify_data(hash_id: u8, hash_len: u8, base_key: const u8[:], transcript_hash: const u8[:], out_verify_data: u8[:]) -> bool
fn ks_update_traffic_secret(hash_id: u8, hash_len: u8, traffic_secret: u8[:]) -> bool
fn ks_zeroize(ks: KeySchedule&)
fn verify_psk_binder(hash_id: u8, hash_len: u8, binder_key: const u8[:], truncated_ch: const u8[:], expected_binder: const u8[:]) -> bool
fn hkdf_expand_label(hash_id: u8, secret: const u8[:], label: const u8[:], context: const u8[:], length: u16, out: u8[:]) -> bool
fn derive_secret(hash_id: u8, hash_len: u8, secret: const u8[:], label: const u8[:], transcript_hash: const u8[:], out: u8[:]) -> bool
fn strike_register_init(epoch_window_ms: i64 = 10000, max_age_tolerance_ms: i64 = 2000) -> ZeroRttStrikeRegister
fn strike_register_rotate(reg: ZeroRttStrikeRegister&, now_ms: i64)
fn strike_register_check_and_insert(reg: ZeroRttStrikeRegister&, ticket_id: const u8[:], now_ms: i64) -> bool
fn validate_ticket_age(obfuscated_ticket_age: u32, ticket_age_add: u32, expected_age_ms: i64, tolerance_ms: i64) -> bool
```

`KeySchedule` (in `namespace tls_internal`) enforces stage transitions (`Early`
-> `Handshake` -> `Master` -> `Resumption`) using SHA-256
(`TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`) or SHA-384
(`TLS_AES_256_GCM_SHA384`). `verify_psk_binder` compares the `PreSharedKey`
binder HMAC in constant time. For 0-RTT early data (RFC 8446 §8),
`validate_ticket_age` checks the deobfuscated ticket age against the server
clock skew window, and `strike_register_check_and_insert` tracks ticket IDs in a
two-epoch Bloom filter to reject replayed 0-RTT flight attempts.

### TLS 1.3 Handshake State Machine (`tls/handshake.goose`, `tls/types.goose`, RFC 8446 §4)

```goose
enum HandshakeMode { Full, Psk }
enum ClientAuthMode { Disabled, Requested }

enum HsState {
    ClientStart, ClientWaitSH, ClientWaitEE, ClientWaitCertCr, ClientWaitCert,
    ClientWaitCV, ClientWaitFinished, ServerWaitCH, ServerWaitEOED,
    ServerWaitCert, ServerWaitCV, ServerWaitFinished, Connected, Closed,
}

enum EarlyDataAccepted { Rejected, Accepted }
enum NegotiatedAlpn { None, H3, H2, Http11, Other }
enum EarlyDataState { None, Offered, Accepted, Rejected }

struct ExtensionEntry {
    ext_type: u16         = 0,
    data:     const u8[:] = [],
}

struct CompressedCertMsg {
    algorithm:        u16         = rfc::CERT_COMPRESSION_ZSTD,
    uncompressed_len: u32         = 0,
    compressed_data:  const u8[:],
}

struct ParsedServerHello {
    cipher_suite:    u16        = 0,
    is_hrr:          bool       = false,
    selected_group:  u16        = 0,
    server_share:    u8[..2048] = [],
    hrr_cookie:      u8[..256]  = [],
    psk_resumed:     bool       = false,
    session_id_echo: u8[..32]   = [],
}

struct NewSessionTicketMsg {
    ticket_lifetime:     u32       = 0,
    ticket_age_add:      u32       = 0,
    ticket_nonce:        u8[..255]  = [],
    ticket:              u8[..1536] = [],
    has_early_data:      bool       = false,
    max_early_data_size: u32       = 0,
}

struct SessionTicketCache {
    tickets:        NewSessionTicketMsg[..8] = [],
    total_received: u32                      = 0,
}

struct KeyUpdateTracker {
    consecutive_updates: u32  = 0,
    pending_response:    bool = false,
    total_updates:       u32  = 0,
}

struct CertificateRequestMsg {
    context:                  u8[..255] = [],
    has_signature_algorithms: bool      = false,
    sig_algorithms:           u16[..64] = [],
}

struct EarlyDataController {
    state:                   EarlyDataState = EarlyDataState.None,
    keys_discarded:          bool           = false,
    bytes_sent:              u32            = 0,
    max_early_data_size:     u32            = 0,
    psk_cipher_suite:        u16            = 0,
    negotiated_cipher_suite: u16            = 0,
}

fn validate_client_handshake_transition(current: HsState, incoming_msg_type: u8, mode: HandshakeMode, is_hrr: bool) -> HsState, bool
fn validate_server_handshake_transition_auth(current: HsState, incoming_msg_type: u8, client_auth: ClientAuthMode, client_cert_is_empty: bool, early_data_accepted: EarlyDataAccepted = EarlyDataAccepted.Rejected) -> HsState, bool
fn validate_server_handshake_transition(current: HsState, incoming_msg_type: u8, client_auth_requested: bool, early_data_accepted: EarlyDataAccepted = EarlyDataAccepted.Rejected) -> HsState, bool
fn parse_handshake_header(data: const u8[:]) -> u8, u32, bool
fn encode_handshake_header(msg_type: u8, msg_len: u32, out: u8[4]&) -> bool
fn is_hello_retry_request(server_random: const u8[32]&) -> bool
fn compress_hrr_transcript(hash_len: u8, ch1_hash: const u8[:], out: u8[:]) -> i64, bool
fn build_synthetic_message_hash(raw_ch1: const u8[:], hash_len: u8, out: u8[:]) -> i64, bool
fn validate_server_random_downgrade(server_random: const u8[32]&, negotiated_version: u16, client_supports_tls13: bool) -> bool
fn parse_sni_extension(ext_bytes: const u8[:], out_sni: u8[..255]&) -> bool
fn negotiate_alpn(alpn_ext_bytes: const u8[:], is_quic: bool) -> NegotiatedAlpn
fn parse_cookie_extension<B>(ext_bytes: const u8[:], out_cookie: B&) -> bool
fn serialize_cookie_extension<B>(out: B&, cookie: const u8[:]) -> bool
fn parse_extensions_block(ext_block_bytes: const u8[:], entries: ExtensionEntry[..32]&) -> bool
fn find_extension(entries: const ExtensionEntry[..32]&, ext_type: u16) -> const u8[:], bool
fn parse_client_supported_versions(ext_bytes: const u8[:]) -> bool, bool
fn parse_server_supported_versions(ext_bytes: const u8[:]) -> u16, bool
fn parse_live_server_hello(payload: const u8[:], out: ParsedServerHello&) -> bool
fn fragment_client_hello<B>(raw_ch: const u8[:], first_record_len: i64, out_records: B&) -> bool
fn parse_new_session_ticket(payload: const u8[:], out: NewSessionTicketMsg&) -> bool
fn cache_session_ticket(cache: SessionTicketCache&, ticket: const NewSessionTicketMsg&) -> bool
fn encode_new_session_ticket<B>(out: B&, ticket_lifetime: u32, ticket_age_add: u32, ticket_nonce: const u8[:], ticket: const u8[:], max_early_data_size: u32) -> bool
fn track_received_key_update(tracker: KeyUpdateTracker&, state: HsState, payload: const u8[:]) -> bool, bool
fn encode_key_update<B>(out: B&, request_update: u8) -> bool
fn parse_certificate_request(payload: const u8[:], is_post_handshake: bool, out: CertificateRequestMsg&) -> bool
fn encode_certificate_request<B>(out: B&, context: const u8[:], sig_algorithms: const u16[:]) -> bool
fn encode_client_certificate<B>(out: B&, cert_context: const u8[:], cert_der: const u8[:]) -> bool
fn encode_client_certificate_verify<B>(out: B&, sig_scheme: u16, signature: const u8[:]) -> bool
fn parse_certificate_verify(payload: const u8[:]) -> u16, const u8[:], bool
fn verify_certificate_verify_sig(sig_scheme: u16, signature: const u8[:], pubkey: const u8[:], msg: const u8[:]) -> bool
fn verify_client_certificate_verify(sig_scheme: u16, signature: const u8[:], client_pubkey: const u8[:], transcript_hash: const u8[:]) -> bool
```

`validate_client_handshake_transition` and
`validate_server_handshake_transition_auth` enforce the RFC 8446 Appendix A
state machine, rejecting transitions where `Finished` arrives before
`Certificate` and `CertificateVerify` in non-PSK handshakes.
`parse_extensions_block` indexes up to 32 extensions while rejecting duplicate
extension IDs. `is_hello_retry_request` checks `ServerHello.random` against the
RFC 8446 §4.1.3 SHA-256("HelloRetryRequest") sentinel, and
`compress_hrr_transcript` replaces `ClientHello1` with the
`[254, 0, 0, hash_len, Hash(CH1)]` synthetic `message_hash` construct.

### TLS 1.3 Live Transport, Handshakes & Session Tickets (`tls/session.goose`, `tls/client_handshake.goose`, `tls/server_handshake.goose`, `tls/ticket.goose`)

```goose
const STEK_TICKET_PLAINTEXT_LEN: i64 = 63;
const STEK_TICKET_WIRE_LEN:      i64 = 95;
const MAX_CIPHER_SLOTS:          i64 = 256;

struct Transcript {
    sha256_ctx: core::Sha256Ctx = core::Sha256Ctx { .. },
    sha384_ctx: core::Sha384Ctx = core::Sha384Ctx { .. },
}

enum SliceUnsealStatus { Ok, NeedMore, Closed, ControlHandled, Error }

struct CipherSlot {
    in_use:             bool               = false,
    is_server:          bool               = false,
    ktls_tx_active:     bool               = false,
    ktls_rx_active:     bool               = false,
    cipher_suite:       u16                = 0,
    hash_id:            u8                 = 1,
    hash_len:           u8                 = 32,
    key_len:            u16                = 16,
    rx_seq:             u64                = 0,
    tx_seq:             u64                = 0,
    rx_key:             u8[32]             = [0; 32],
    tx_key:             u8[32]             = [0; 32],
    rx_aes_key:         core::AesGcmKey    = core::AesGcmKey { .. },
    tx_aes_key:         core::AesGcmKey    = core::AesGcmKey { .. },
    rx_iv:              u8[12]             = [0; 12],
    tx_iv:              u8[12]             = [0; 12],
    rx_traffic_secret:  u8[48]             = [0; 48],
    tx_traffic_secret:  u8[48]             = [0; 48],
    exporter_secret:    u8[48]             = [0; 48],
    resumption_secret:  u8[48]             = [0; 48],
    peer_closed:            bool               = false,
    resumed:                bool               = false,
    enable_session_tickets: bool               = true,
    negotiated_alpn:        u8[..255]          = [],
    server_name:            u8[..256]          = [],
    san_hosts:              u8[..128][..8]     = [],
    rx_plain_buf:           u8[..16384]        = [],
    rx_plain_pos:           i64                = 0,
    bytes_sent:             u64                = 0,
    key_update_tracker:     KeyUpdateTracker   = KeyUpdateTracker { .. },
    ticket_cache:           SessionTicketCache = SessionTicketCache { .. },
}

struct CachedSessionTicket {
    in_use:       bool       = false,
    server_name:  u8[..256]  = [],
    ticket:       u8[..1536] = [],
    psk:          u8[..48]   = [],
    age_add:      u32        = 0,
    lifetime:     u32        = 0,
    cipher_suite: u16        = 0,
    issued_at_ms: i64        = 0,
}

struct TicketStek {
    key_name:     u8[4]  = [0; 4],
    aead_key:     u8[32] = [0; 32],
    created_sec:  i64    = 0,
    lifetime_sec: u32    = 86400,
    active:       bool   = false,
}

struct TicketKeyRing {
    keys:        TicketStek[2] = [TicketStek { .. }; 2],
    current_idx: u8            = 0,
}

struct HandshakeRecordReader {
    current_record_plain: u8[..32768] = [],
    current_offset:       i64         = 0,
    seq_num:              u64         = 0,
    ccs_count:            u32         = 0,
}

struct ClientHandshakeConfig {
    server_name:            u8[..256]        = [],
    alpn:                   u8[..255]        = [],
    trust_store:            TrustAnchorStore = TrustAnchorStore { .. },
    use_system_roots:       bool             = true,
    insecure_skip_verify:   bool             = false,
    virtual_clock_sec:      i64              = 0,
    client_cert_der:        u8[..4096]       = [],
    client_chain_der:       u8[..4096][..3]  = [],
    client_priv_seed:       u8[32]           = [0; 32],
    enable_pq_hybrid:       bool             = false,
    ech_config_list:        u8[..512]        = [],
    crl_der:                u8[..4096]       = [],
    enable_session_tickets: bool             = true,
    require_ocsp_stapling:  bool             = false,
    handshake_timeout_ms:   u32              = 5000,
    keylog_file:            u8[..256]        = [],
}

struct ServerHandshakeConfig {
    cert_der:             u8[..4096]       = [],
    priv_seed:            u8[32]           = [0; 32],
    alpn:                 u8[..255]        = [],
    compressed_cert_algo: u16              = 0,
    compressed_cert_data: u8[..4096]       = [],
    handshake_timeout_ms: u32              = 5000,
    keylog_file:          u8[..256]        = [],
    require_client_cert:  bool             = false,
    client_trust_store:   TrustAnchorStore = TrustAnchorStore { .. },
}

fn transcript_update(t: Transcript&, data: const u8[:])
fn transcript_update_msg(t: Transcript&, msg_type: u8, body: const u8[:])
fn transcript_current_hash(t: const Transcript&, hash_id: u8, out_hash: u8[..48]&)
fn transcript_replace_with_message_hash(t: Transcript&, hash_id: u8, hash_len: u8) -> bool
fn seal_stateless_ticket<B>(ring: const TicketKeyRing&, psk: const u8[..48]&, cipher_suite: u16, issued_at_ms: i64, nonce_iv: const u8[12]&, out_ticket: B&) -> bool
fn open_stateless_ticket(ring: const TicketKeyRing&, raw_ticket: const u8[:], now_ms: i64) -> CachedSessionTicket, bool
fn store_session_ticket(server_name: const u8[:], ticket: const u8[:], psk: const u8[:], age_add: u32, lifetime: u32, cipher_suite: u16 = rfc::TLS_CIPHER_AES_128_GCM_SHA256, issued_at_ms: i64 = 0)
fn lookup_session_ticket_full<B>(server_name: const u8[:], out_ticket: B&, out_psk: u8[..48]&, out_age_add: u32&, out_cipher_suite: u16&, now_ms: i64 = 0) -> bool
fn lookup_session_ticket<B>(server_name: const u8[:], out_ticket: B&, out_psk: u8[32]&, out_age_add: u32&, now_ms: i64 = 0) -> bool
fn clear_session_tickets()
fn random_bytes_32() -> u8[32]
fn alloc_cipher_slot() -> u16
fn free_cipher_slot(slot_idx: u16)
fn session_alpn(slot_idx: u16) -> const u8[:]
fn session_is_resumed(slot_idx: u16) -> bool
fn session_export_keying_material(slot_idx: u16, label: const u8[:], context: const u8[:], length: u16, out: u8[..256]&) -> bool
fn client_handshake(fd: i64, config: const ClientHandshakeConfig&) -> u16, bool
fn server_handshake(fd: i64, config: const ServerHandshakeConfig&) -> u16, bool
fn server_handshake_with_ch(fd: i64, ch_msg: const u8[:], config: const ServerHandshakeConfig&) -> u16, bool
fn transport_send(fd: i64, slot_idx: u16, data: const u8[:]) -> i32
fn transport_recv_slice(fd: i64, slot_idx: u16, dst: u8[:], timeout_ms: u32 = 5000) -> i32
fn transport_close(fd: i64, slot_idx: u16)
fn send_new_session_ticket(fd: i64, slot_idx: u16, ticket_lifetime: u32, ticket_nonce: const u8[:], ticket: const u8[:], max_early_data_size: u32 = 0) -> bool
fn send_key_update(fd: i64, slot_idx: u16, request_update: u8) -> bool
fn build_test_ed25519_cert_der(seed: const u8[32]&, common_name: const u8[:], dns_san: const u8[:], ip_san: const u8[:], out_der: u8[..2048]&) -> bool
```

Manages up to 256 concurrent `CipherSlot` sessions (`alloc_cipher_slot` /
`free_cipher_slot`) via grow-on-demand lazy slot storage.
`seal_stateless_ticket` and `open_stateless_ticket` (`tls/ticket.goose`) encrypt
and authenticate 95-byte stateless server session tickets (`STEK_TICKET_WIRE_LEN
= 95`, `STEK_TICKET_PLAINTEXT_LEN = 63`) with `AES-256-GCM`
(`core::aes256_gcm_seal` / `core::aes256_gcm_open`) using a 4-byte `key_name`
(`u8[4]`) and 12-byte IV prefix looked up across active and previous slots in
`TicketKeyRing`. `transport_recv_slice` processes post-handshake
`NewSessionTicket` and `KeyUpdate` messages while delivering decrypted
application data slices.

### X.509 PKI, SAN, OCSP, CRL & PEM (`tls/x509.goose`, `tls/x509_san.goose`, `tls/asn1.goose`, `tls/ocsp.goose`, `tls/crl.goose`, `tls/sct.goose`, `tls/pem.goose`)

```goose
struct Span16 { offset: u16 = 0, length: u16 = 0 }

struct ParsedCert {
    raw_len:                          u32    = 0,
    tbs_cert:                         Span16 = Span16 { offset: 0, length: 0 },
    serial_number:                    Span16 = Span16 { offset: 0, length: 0 },
    sig_alg_oid:                      Span16 = Span16 { offset: 0, length: 0 },
    issuer_raw:                       Span16 = Span16 { offset: 0, length: 0 },
    validity_not_before:              i64    = 0,
    validity_not_after:               i64    = 0,
    subject_raw:                      Span16 = Span16 { offset: 0, length: 0 },
    spki_raw:                         Span16 = Span16 { offset: 0, length: 0 },
    spki_alg_oid:                     Span16 = Span16 { offset: 0, length: 0 },
    spki_pubkey:                      Span16 = Span16 { offset: 0, length: 0 },
    extensions_raw:                   Span16 = Span16 { offset: 0, length: 0 },
    san_raw:                          Span16 = Span16 { offset: 0, length: 0 },
    has_san:                          bool   = false,
    is_ca:                            bool   = false,
    has_basic_constraints:            bool   = false,
    path_len_constraint:              i32    = -1,
    key_usage:                        u16    = 0,
    has_key_usage:                    bool   = false,
    has_unsupported_critical:         bool   = false,
    akid_key_id:                      Span16 = Span16 { offset: 0, length: 0 },
    has_akid:                         bool   = false,
    skid_key_id:                      Span16 = Span16 { offset: 0, length: 0 },
    has_skid:                         bool   = false,
    name_constraints_raw:             Span16 = Span16 { offset: 0, length: 0 },
    has_name_constraints:             bool   = false,
    has_malformed_policy_constraints: bool   = false,
    has_must_staple:                  bool   = false,
    has_sct_list:                     bool   = false,
    sct_count:                        u8     = 0,
    has_eku:                          bool   = false,
    eku_mask:                         u8     = 0,
    signature_value:                  Span16 = Span16 { offset: 0, length: 0 },
}

struct TrustAnchor {
    subject_dn_sha256: u8[32] = [0; 32],
    spki_sha256:       u8[32] = [0; 32],
    is_valid:          bool   = false,
}

struct TrustAnchorStore {
    anchors: TrustAnchor[..16] = [],
}

struct ParsedSct {
    version:      u8     = 0,
    log_id:       u8[32] = [0; 32],
    timestamp_ms: u64    = 0,
    hash_alg:     u8     = 0,
    sig_alg:      u8     = 0,
    extensions:   Span16 = Span16 { offset: 0, length: 0 },
    signature:    Span16 = Span16 { offset: 0, length: 0 },
}

enum SanType { Dns, Ip, Uri, Email, DirName, Other }
struct SanEntry { san_type: SanType = SanType.Dns, val: const u8[:] = [] }
struct NameConstraintEntry { san_type: SanType = SanType.Dns, is_excluded: bool = false, val: const u8[:] = [] }

enum OcspResponseStatus { Successful, MalformedRequest, InternalError, TryLater, SigRequired, Unauthorized, Unknown }
enum OcspCertStatus { Good, Revoked, Unknown }

struct ParsedOcspResponse {
    status:           OcspResponseStatus = OcspResponseStatus.Unknown,
    cert_status:      OcspCertStatus     = OcspCertStatus.Unknown,
    serial_number:    Span16             = Span16 { offset: 0, length: 0 },
    issuer_name_hash: Span16             = Span16 { offset: 0, length: 0 },
    issuer_key_hash:  Span16             = Span16 { offset: 0, length: 0 },
    hash_alg_oid:     Span16             = Span16 { offset: 0, length: 0 },
    tbs_raw:          Span16             = Span16 { offset: 0, length: 0 },
    sig_alg_oid:      Span16             = Span16 { offset: 0, length: 0 },
    signature:        Span16             = Span16 { offset: 0, length: 0 },
    this_update:      i64                = 0,
    next_update:      i64                = 0,
    has_next_update:  bool               = false,
}

struct ParsedCrl {
    issuer:       const u8[:] = "",
    serials:      u64[..128]  = [],
    serial_count: i32         = 0,
    tbs_raw:      Span16      = Span16 { offset: 0, length: 0 },
    sig_alg_oid:  Span16      = Span16 { offset: 0, length: 0 },
    signature:    Span16      = Span16 { offset: 0, length: 0 },
}

enum PrivateKeyKind { Unknown, Ed25519, EcdsaP256 }

fn span_slice(raw: const u8[:], span: Span16) -> const u8[:]
fn make_span(base: const u8[:], target: const u8[:], start_hint: i64 = 0) -> Span16
fn parse_x509_certificate(raw_cert: const u8[:], out: ParsedCert&) -> bool
fn add_trust_anchor(store: TrustAnchorStore&, subject_raw: const u8[:], spki_raw: const u8[:]) -> bool
fn add_trust_anchor_cert_der(store: TrustAnchorStore&, raw_cert_der: const u8[:]) -> bool
fn matches_trust_anchor(store: const TrustAnchorStore&, cert: const ParsedCert&, raw_cert: const u8[:]) -> bool
fn verify_certificate_chain(chain_certs: const ParsedCert[..8]&, raw_certs: const u8[:][..8]&, trust_store: const TrustAnchorStore&, now_unix: i64) -> Alert
fn x509_verify_cert_signature(child_cert: const ParsedCert&, child_raw: const u8[:], parent_cert: const ParsedCert&, parent_raw: const u8[:]) -> Alert
fn parse_san_extension<S>(san_der: const u8[:], out_sans: S&) -> bool
fn get_cert_san_extension<S>(cert: const ParsedCert&, raw_cert: const u8[:], out_sans: S&) -> bool
fn match_dns_san(san_pattern: const u8[:], host: const u8[:]) -> bool
fn match_ip_san(san_ip: const u8[:], host: const u8[:]) -> bool
fn match_uri_san(san_uri_host: const u8[:], request_host: const u8[:]) -> bool
fn match_san(san: const SanEntry&, host: const u8[:]) -> bool
fn match_any_san<S>(sans: const S&, host: const u8[:]) -> bool
fn parse_name_constraints(nc_der: const u8[:], out_constraints: NameConstraintEntry[..16]&) -> bool
fn check_name_constraints(constraints: const NameConstraintEntry[..16]&, san: const SanEntry&) -> bool
fn parse_sct_entry(raw: const u8[:], out: ParsedSct&) -> bool
fn parse_sct_list(raw_list: const u8[:], out_scts: ParsedSct[..8]&) -> bool
fn parse_ocsp_response(raw_ocsp: const u8[:], out: ParsedOcspResponse&) -> bool
fn x509_verify_ocsp_signature(resp: const ParsedOcspResponse&, raw_ocsp: const u8[:], issuer_cert: const ParsedCert&, issuer_raw: const u8[:]) -> Alert
fn validate_ocsp_stapling(raw_ocsp: const u8[:], leaf_cert: const ParsedCert&, leaf_raw: const u8[:], now_unix: i64, issuer_raw_der: const u8[:] = "") -> Alert
fn unwrap_ocsp_response(ext_data: const u8[:]) -> const u8[:], bool
fn parse_asn1_serial_u64(serial_bytes: const u8[:]) -> u64, bool
fn parse_x509_crl(raw_crl: const u8[:], out: ParsedCrl&) -> bool
fn crl_insert_serial(crl: ParsedCrl&, serial: u64) -> bool
fn crl_is_revoked(crl: const ParsedCrl&, serial: u64) -> bool
fn x509_verify_crl_signature(crl: const ParsedCrl&, raw_crl: const u8[:], issuer_cert: const ParsedCert&, issuer_raw: const u8[:]) -> Alert
fn verify_signature_scheme_curve_binding(sig_scheme: u16, spki_oid: const u8[:]) -> bool
fn build_certificate_verify_message(is_server: bool, transcript_hash: const u8[:], out: u8[:]) -> i64, bool
fn pem_next_block(raw: const u8[:], idx: i64&, out_label: u8[..64]&, out_der: u8[..4096]&) -> bool
fn add_trust_anchors_pem(store: TrustAnchorStore&, pem_bundle: const u8[:]) -> i64, bool
fn load_trust_anchors_pem_file(store: TrustAnchorStore&, path: const u8[:]) -> i64, bool
fn parse_private_key_pem(pem: const u8[:], out_key: u8[32]&) -> PrivateKeyKind, bool
fn load_server_credentials_pem(cert_pem: const u8[:], key_pem: const u8[:], out_cfg: ServerHandshakeConfig&) -> bool
```

`parse_x509_certificate` enforces X.690 canonical DER length and integer padding
rules (forbidding BER indefinite lengths and non-minimal encodings) and records
16-bit `Span16` offsets into the caller's DER buffer without copying, using
`make_span` with `start_hint` so `subject_raw` resolves past `issuer_raw` on
self-signed certificates. `parse_asn1_serial_u64` maps 1..7 significant-byte DER
serials to their exact big-endian `u64` value and 8..20 byte serials (RFC 5280
§4.1.2.2) to a 64-bit FNV-1a digest with bit 63 set for O(log N) binary-search
lookup in `ParsedCrl.serials`. `verify_certificate_chain` validates up to 8
certificates against `TrustAnchorStore`, returning `Alert.CloseNotify` on valid
chains.

### Hybrid Post-Quantum Key Exchange (`tls/post_quantum.goose`, `namespace tls_internal`, RFC 10024 / FIPS 203)

```goose
struct PostQuantumKeyShare {
    group:           u16      = rfc::GROUP_X25519_MLKEM768,
    x25519_public:   u8[32]   = [0; 32],
    mlkem768_public: u8[1184] = [0; 1184],
}

struct PostQuantumServerShare {
    group:               u16      = rfc::GROUP_X25519_MLKEM768,
    x25519_public:       u8[32]   = [0; 32],
    mlkem768_ciphertext: u8[1088] = [0; 1088],
}

struct SecP256r1MLKEM768KeyShare {
    group:            u16      = rfc::GROUP_SECP256R1_MLKEM768,
    secp256r1_public: u8[65]   = [0; 65],
    mlkem768_public:  u8[1184] = [0; 1184],
}

struct SecP256r1MLKEM768ServerShare {
    group:               u16      = rfc::GROUP_SECP256R1_MLKEM768,
    secp256r1_public:    u8[65]   = [0; 65],
    mlkem768_ciphertext: u8[1088] = [0; 1088],
}

struct SecP384r1MLKEM1024KeyShare {
    group:            u16      = rfc::GROUP_SECP384R1_MLKEM1024,
    secp384r1_public: u8[97]   = [0; 97],
    mlkem1024_public: u8[1568] = [0; 1568],
}

struct SecP384r1MLKEM1024ServerShare {
    group:                u16      = rfc::GROUP_SECP384R1_MLKEM1024,
    secp384r1_public:     u8[97]   = [0; 97],
    mlkem1024_ciphertext: u8[1568] = [0; 1568],
}

struct MLKEM768PrivateKey {
    z:           u8[32]   = [0; 32],
    public_key:  u8[1152] = [0; 1152],
    private_key: u8[1152] = [0; 1152],
}

struct Poly256 { coeffs: i32[256] = [0; 256] }

fn format_hybrid_key_share<B>(share: const PostQuantumKeyShare&, out: B&)
fn parse_hybrid_key_share(share: PostQuantumKeyShare&, raw: const u8[:]) -> bool
fn format_hybrid_server_key_share<B>(share: const PostQuantumServerShare&, out: B&)
fn parse_hybrid_server_key_share(share: PostQuantumServerShare&, raw: const u8[:]) -> bool
fn format_secp256r1_mlkem768_key_share<B>(share: const SecP256r1MLKEM768KeyShare&, out: B&)
fn parse_secp256r1_mlkem768_key_share(share: SecP256r1MLKEM768KeyShare&, raw: const u8[:]) -> bool
fn format_secp256r1_mlkem768_server_share<B>(share: const SecP256r1MLKEM768ServerShare&, out: B&)
fn parse_secp256r1_mlkem768_server_share(share: SecP256r1MLKEM768ServerShare&, raw: const u8[:]) -> bool
fn format_secp384r1_mlkem1024_key_share<B>(share: const SecP384r1MLKEM1024KeyShare&, out: B&)
fn parse_secp384r1_mlkem1024_key_share(share: SecP384r1MLKEM1024KeyShare&, raw: const u8[:]) -> bool
fn format_secp384r1_mlkem1024_server_share<B>(share: const SecP384r1MLKEM1024ServerShare&, out: B&)
fn parse_secp384r1_mlkem1024_server_share(share: SecP384r1MLKEM1024ServerShare&, raw: const u8[:]) -> bool
fn mlkem768_keygen(d_seed: const u8[32]&, z_seed: const u8[32]&) -> u8[1184], u8[2400]
fn mlkem768_encapsulate(ek: const u8[1184]&, m_rand: const u8[32]&) -> u8[1088], u8[32], bool
fn mlkem768_decapsulate(ct: const u8[:], sk: const u8[:], shared_secret: u8[:]) -> bool
fn mlkem768_decapsulate_with_implicit_rejection(sk: const MLKEM768PrivateKey&, ciphertext: const u8[:], out_ss: u8[:]) -> bool, bool
fn mlkem768_compute_implicit_rejection(z: const u8[32]&, ciphertext: const u8[:], out_ss: u8[:]) -> bool
fn derive_x25519_mlkem768_shared_secret(classical_ss: const u8[32]&, pq_ss: const u8[32]&) -> u8[32]
fn derive_x25519_mlkem768_shared_secret_checked(classical_ss: const u8[:], pq_ss: const u8[:], out: u8[:]) -> bool
fn derive_secp256r1_mlkem768_shared_secret(classical_ss: const u8[32]&, pq_ss: const u8[32]&) -> u8[32]
fn derive_secp384r1_mlkem1024_shared_secret(classical_ss: const u8[48]&, pq_ss: const u8[32]&) -> u8[48]
fn derive_hybrid_shared_secret(classical_ss: const u8[32]&, pq_ss: const u8[32]&) -> u8[32]
fn derive_hybrid_shared_secret_checked(classical_ss: const u8[:], pq_ss: const u8[:], out: u8[:]) -> bool
```

Implements FIPS 203 ML-KEM-768 key generation, encapsulation (with §7.2
encapsulation key modulus verification over $\mathbb{Z}_{3329}$),
Number-Theoretic Transform (`poly_ntt`, `poly_invntt`, `poly_basemul_acc`), and
Fujisaki-Okamoto decapsulation with constant-time implicit rejection (`K_bar`).
Supports `X25519MLKEM768` (`0x11EC`, ordered `mlkem768 || x25519`),
`SecP256r1MLKEM768` (`0x11EB`, ordered `secp256r1 || mlkem768`), and
`SecP384r1MLKEM1024` (`0x11ED`, ordered `secp384r1 || mlkem1024`) per RFC 10024.

### Encrypted Client Hello (`tls/ech.goose`, RFC 9849)

```goose
struct EchCipherSuite { kdf_id: u16 = rfc::HPKE_KDF_HKDF_SHA256, aead_id: u16 = rfc::HPKE_AEAD_AES_128_GCM }

struct EchConfig {
    version:             u16                 = rfc::ECH_VERSION_RFC9849,
    length:              u16                 = 0,
    config_id:           u8                  = 0,
    kem_id:              u16                 = rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256,
    public_key:          u8[32]              = [0; 32],
    cipher_suites:       EchCipherSuite[..4] = [],
    maximum_name_length: u8                  = 0,
    public_name:         u8[..255]           = [],
    raw_bytes:           u8[..2048]          = [],
}

struct EchConfigList { configs: EchConfig[..4] = [] }

enum EchHandshakeMode { Disabled, Offered, Accepted, RejectedWithRetry, Bypassed }
enum EchServerHelloType { ServerHello, HelloRetryRequest }
enum EchClientHelloType { Outer, Inner }

struct EchFsm {
    mode:              EchHandshakeMode = EchHandshakeMode.Disabled,
    has_hrr:           bool             = false,
    offered_config_id: u8               = 0,
}

fn parse_ech_config(raw: const u8[:], out: EchConfig&) -> bool
fn parse_ech_config_list(raw: const u8[:], out: EchConfigList&) -> bool
fn select_ech_config(list: const EchConfigList&, out_cfg: EchConfig&, out_cs: EchCipherSuite&) -> bool
fn pad_ech_inner<B>(inner_bytes: const u8[:], max_name_len: u8, real_sni_len: i64, out_padded: B&) -> bool
fn build_ech_inner_extension<B>(out: B&)
fn encode_ech_outer_extensions<B>(out: B&, ext_types: const u16[:]) -> bool
fn build_encoded_client_hello_inner<B>(out: B&, inner_random: const u8[32]&, inner_sni: const u8[:], inner_alpn: const u8[:], outer_ext_types: const u16[:], max_name_len: u8) -> bool
fn seal_ech_inner<B>(config: const EchConfig&, cs: const EchCipherSuite&, outer_aad: const u8[:], inner_padded: const u8[:], ephemeral_sk: const u8[32]&, out_enc: u8[32]&, out_ct: B&) -> bool
fn build_ech_outer_extension<B>(config_id: u8, cs: const EchCipherSuite&, enc: const u8[32]&, ciphertext: const u8[:], out: B&) -> bool
fn compute_ech_accept_confirmation(inner_random: const u8[32]&, ch_inner_bytes: const u8[:], sh_msg_with_hdr: const u8[:], is_hrr: bool) -> u8[8], bool
fn verify_ech_acceptance_confirmation(ext_data: const u8[:], expected_confirmation: const u8[8]&) -> bool
fn parse_and_validate_ech_retry_configs(ext_data: const u8[:], out_config_list: EchConfigList&) -> bool
fn ech_fsm_on_server_hello(fsm: EchFsm&, sh_type: EchServerHelloType, has_ech_ext: bool, sh_confirm_or_ext: const u8[:], expected_confirm: const u8[8]&, out_retry_configs: EchConfigList&) -> bool
fn validate_ech_alpn_negotiation(is_ech_accepted: bool, selected_alpn: const u8[:], inner_alpn: const u8[:], outer_alpn: const u8[:]) -> bool
```

`select_ech_config` chooses the first `0xfe0d` configuration using
`DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, and `AES-128-GCM` or
`ChaCha20Poly1305`. `pad_ech_inner` pads `EncodedClientHelloInner` to a 32-byte
multiple per RFC 9849 §6.1.3 before `seal_ech_inner` encrypts it with HPKE Base
mode (`security/hpke.goose`, `"tls ech\0"` info label).
`verify_ech_acceptance_confirmation` checks the 8-byte confirmation signal in
constant time.

### Certificate Compression (`tls/cert_compression.goose`, `namespace tls_internal`, RFC 8879)

```goose
struct CompressedCertificate {
    algorithm:                      u16         = rfc::CERT_COMPRESSION_BROTLI,
    uncompressed_length:            u32         = 0,
    compressed_certificate_message: const u8[:] = "",
}

fn encode_compressed_certificate<B>(msg: const CompressedCertificate&, out: B&) -> bool
fn parse_compressed_certificate_msg(raw: const u8[:], out: CompressedCertificate&) -> bool
fn decompress_certificate_message<B>(msg: const CompressedCertificate&, max_allowed_len: u32, out_cert: B&) -> bool
fn decompress_certificate_payload<B>(comp_data: const u8[:], algo: u16, expected_len: u32, out_cert: B&) -> bool
fn decompress_certificate_brotli<B>(compressed_data: const u8[:], uncompressed_len: u32, out_cert: B&) -> bool
fn decompress_certificate_zlib<B>(compressed_data: const u8[:], uncompressed_len: u32, out_cert: B&) -> bool
fn decompress_certificate_zstd<B>(compressed_data: const u8[:], uncompressed_len: u32, out_cert: B&) -> bool
```

`parse_compressed_certificate_msg` validates the 24-bit `uncompressed_length`
and enforces a maximum decompression expansion ratio before
`decompress_certificate_payload` dispatches `zlib` (`0x0001`), `brotli`
(`0x0002`), or `zstd` (`0x0003`) decompression and verifies that the
decompressed output matches `uncompressed_length` to the byte.

### Pluggable TLS Backend (`tls/backend.goose`, `shim/tls_backend.c`)

```goose
enum TlsBackendKind {
    PureGoose, SystemOpenSsl, SystemSchannel, SystemSecureTransport, Auto,
}

enum TlsMinVersion { Tls13, Tls12 }

enum TlsBackendStatus {
    Ok, WantRead, WantWrite, Closed, Unavailable, HandshakeError, VerifyError, Error,
}

struct TlsBackendConfig {
    kind:                   TlsBackendKind   = TlsBackendKind.PureGoose,
    min_version:            TlsMinVersion    = TlsMinVersion.Tls13,
    is_server:              bool             = false,
    server_name:            u8[..256]        = [],
    alpn_wire:              u8[..64]         = [],
    insecure_skip_verify:   bool             = false,
    use_system_roots:       bool             = true,
    ca_file:                u8[..256]        = [],
    cert_pem_file:          u8[..256]        = [],
    key_pem_file:           u8[..256]        = [],
    cert_der:               u8[..4096]       = [],
    priv_seed:              u8[32]           = [0; 32],
    trust_store:            TrustAnchorStore = TrustAnchorStore { .. },
    enable_pq_hybrid:       bool             = false,
    enable_session_tickets: bool             = true,
    require_ocsp_stapling:  bool             = false,
    crl_der:                u8[..4096]       = [],
    keylog_file:            u8[..256]        = [],
}

struct TlsEndpoint {
    kind:        TlsBackendKind = TlsBackendKind.PureGoose,
    active_kind: TlsBackendKind = TlsBackendKind.PureGoose,
    is_server:   bool           = false,
    established: bool           = false,
    closed:      bool           = false,
    pure_slot:   i32            = -1,
    pure_gen:    u32            = 0,
    native_id:   i64            = -1,
}

fn tls_backend_available(kind: TlsBackendKind) -> bool
fn tls_endpoint_open(cfg: const TlsBackendConfig&) -> TlsEndpoint, TlsBackendStatus
fn tls_endpoint_close(ep: TlsEndpoint&)
fn tls_endpoint_feed_wire(ep: TlsEndpoint&, ciphertext: const u8[:]) -> i64, TlsBackendStatus
fn tls_endpoint_drain_wire(ep: TlsEndpoint&, dst: u8[:]) -> i64, TlsBackendStatus
fn tls_endpoint_step_handshake(ep: TlsEndpoint&) -> TlsBackendStatus
fn tls_endpoint_write_app(ep: TlsEndpoint&, plaintext: const u8[:]) -> i64, TlsBackendStatus
fn tls_endpoint_read_app(ep: TlsEndpoint&, dst: u8[:]) -> i64, TlsBackendStatus
fn tls_endpoint_selected_alpn(ep: const TlsEndpoint&) -> u8[..64]
fn tls_endpoint_is_established(ep: const TlsEndpoint&) -> bool
fn tls_endpoint_pending_wire(ep: const TlsEndpoint&) -> i64
fn tls_endpoint_shutdown(ep: TlsEndpoint&) -> TlsBackendStatus
```

`TlsEndpoint` defines a buffer-oriented, sans-IO TLS transport contract backed
by closed polymorphism across:

- `PureGoose`: native Goose TLS 1.3 handshake and record layer with zero
  external dependencies and full single-seed DST determinism. Implements **TLS
  1.3 only** (RFC 8446) and does not support TLS 1.2 even when
  `min_version = TlsMinVersion.Tls12` is configured.
- `SystemOpenSsl`: optional OpenSSL 3 / 1.1.1 / BoringSSL driver in
  `shim/tls_backend.c` using memory BIOs, strict TLS 1.3 floor by default
  (`TlsMinVersion.Tls13`) with opt-in TLS 1.2 fallback (`TlsMinVersion.Tls12`),
  `SSL_VERIFY_PEER` with `SSL_set1_host` DNS verification and
  `X509_VERIFY_PARAM_set1_ip_asc` IP-literal verification (suppressing IP SNI
  per RFC 6066 §3), optional OS root store loading (`use_system_roots: true` by
  default when `ca_file` is empty, including Windows `ROOT` store via
  `crypt32.dll`; set `use_system_roots = false` to fail closed without OS
  roots), custom `ca_file`, bidirectional mTLS (`cert_pem_file` / `key_pem_file`
  on both servers and clients, plus server `SSL_VERIFY_FAIL_IF_NO_PEER_CERT`
  when `ca_file` is configured), and server/client ALPN negotiation. Loaded
  dynamically via `dlopen` / `LoadLibraryA` with zero compile-time OpenSSL
  dependency (override paths with `WING_OPENSSL_LIB` / `WING_CRYPTO_LIB`, or
  link directly with `-DWING_TLS_LINK_OPENSSL -lssl -lcrypto`).
- `SystemSchannel`: dynamically loaded Windows `secur32.dll` Schannel client
  context with zero third-party DLLs (`SCH_CREDENTIALS` v5 TLS 1.3-only for
  default `TlsMinVersion.Tls13`; TLS 1.2 + TLS 1.3 with v4 fallback on older
  Windows 10 only when `min_version = TlsMinVersion.Tls12`).
- `SystemSecureTransport`: dynamically loaded macOS `Security.framework` client
  driver (`dlopen`, zero `-framework Security` link flag). Requires explicit
  `min_version = TlsMinVersion.Tls12` (returns `Unavailable` on default `Tls13`
  so callers never silently downgrade).
- `Auto`: selects `SystemOpenSsl` when available (Linux `libssl.so.3` /
  `libssl.so.1.1`, macOS Homebrew/MacPorts `libssl.3.dylib`, Windows
  `libssl-3-x64.dll` / `libssl-3.dll`), then `SystemSchannel` on Windows client
  endpoints or `SystemSecureTransport` on macOS client endpoints (only when no
  PEM `ca_file` / `cert_pem_file` / `key_pem_file` paths were requested), and
  falls back to `PureGoose` (TLS 1.3 only) otherwise. Fails closed when PEM
  credentials or a PEM `ca_file` without an in-memory `trust_store` cannot be
  satisfied.

`tls_endpoint_shutdown` queues a graceful RFC 8446 `close_notify` alert,
`tls_endpoint_pending_wire` reports queued outbound ciphertext bytes for reactor
`EPOLL_WRITE` arming, and `tls_endpoint_close` is idempotent and wipes handshake
and traffic keys on shutdown. Setting `enable_session_tickets = false` disables
ticket lookup and global cache storage on `PureGoose` and applies
`SSL_OP_NO_TICKET` plus zero server tickets on `SystemOpenSsl`. Setting
`keylog_file` appends NSS Key Log Format secrets on both `PureGoose` and
`SystemOpenSsl` (disabled by default when empty). `PureGoose` also enforces
`enable_pq_hybrid`, `require_ocsp_stapling`, and `crl_der` controls.

### Non-Blocking Reactor TLS Stream (`tls/stream.goose`)

```goose
struct TlsStream {
    fd:            i64         = -1,
    ep:            TlsEndpoint = TlsEndpoint { .. },
    tx_wire:       u8[..16640] = [],
    tx_wire_pos:   i64         = 0,
    rx_wire:       u8[..16640] = [],
    rx_wire_pos:   i64         = 0,
    rx_eof:        bool        = false,
    shutdown_sent: bool        = false,
}

fn tls_stream_open(fd: i64, cfg: const TlsBackendConfig&) -> TlsStream, TlsBackendStatus
fn tls_stream_flush_wire(s: TlsStream&) -> i64, TlsBackendStatus
fn tls_stream_pump_rx(s: TlsStream&) -> i64, TlsBackendStatus
fn tls_stream_step_handshake(s: TlsStream&) -> TlsBackendStatus
fn tls_stream_write(s: TlsStream&, plaintext: const u8[:]) -> i64, TlsBackendStatus
fn tls_stream_read(s: TlsStream&, dst: u8[:]) -> i64, TlsBackendStatus
fn tls_stream_poll_events(s: const TlsStream&) -> u32
fn tls_stream_shutdown(s: TlsStream&) -> TlsBackendStatus
fn tls_stream_close(s: TlsStream&)
```

`TlsStream` pairs a caller-owned non-blocking TCP socket or virtual DST pipe
descriptor with `TlsEndpoint`, preserving strict FIFO order across partial
socket writes (`WantWrite`), never dropping inbound ciphertext bytes, and
computing the exact `EPOLL_READ` / `EPOLL_WRITE` readiness bitmask via
`tls_stream_poll_events`.
