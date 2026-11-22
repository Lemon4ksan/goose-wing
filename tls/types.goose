// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Public domain types, enums, constants, and session storage for `tls`.
namespace tls;

import std;
import core;
import .asn1;
import .record;

// ---- SCT Types (RFC 6962) -------------------------------------------------

struct ParsedSct {
    version:      u8     = 0,
    log_id:       u8[32] = [0; 32],
    timestamp_ms: u64    = 0,
    hash_alg:     u8     = 0,
    sig_alg:      u8     = 0,
    extensions:   Span16 = Span16 { offset: 0, length: 0 },
    signature:    Span16 = Span16 { offset: 0, length: 0 },
}

// ---- X.509 / OCSP / CRL Types (RFC 5280, RFC 6960) ------------------------

// TLS peer validation role binding Extended Key Usage (RFC 5280 Section 4.2.1.12).
enum CertValidationRole {
    Server,
    Client,
    Any,
}

struct ParsedCert {
    raw_len:                          u32    = 0,
    tbs_cert:                         Span16 = Span16 { offset: 0, length: 0 },
    serial_number:                    Span16 = Span16 { offset: 0, length: 0 },
    sig_alg_oid:                      Span16 = Span16 { offset: 0, length: 0 },
    pss_hash_id:                      u8     = 0,
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
    subject_dn_sha256:     u8[32]    = [0; 32],
    spki_sha256:           u8[32]    = [0; 32],
    subject_raw:           u8[..384] = [],
    spki_pubkey:           u8[..600] = [],
    skid_key_id:           u8[..64]  = [],
    name_constraints_raw:  u8[..512] = [],
    key_usage:             u16       = 0,
    has_key_usage:         bool      = false,
    has_basic_constraints: bool      = false,
    is_ca:                 bool      = false,
    path_len_constraint:   i32       = -1,
    has_skid:              bool      = false,
    has_name_constraints:  bool      = false,
    has_pub_material:      bool      = false,
    validity_not_before:   i64       = 0,
    validity_not_after:    i64       = 0,
    has_validity:          bool      = false,
    is_valid:              bool      = false,
}

struct TrustAnchorStore {
    anchors: TrustAnchor[..16] = [],
}

enum SanType {
    Dns,
    Ip,
    Uri,
    Email,
    Other,
}

struct SanEntry {
    san_type: SanType     = SanType.Dns,
    val:      const u8[:] = [],
}

struct NameConstraintEntry {
    san_type:    SanType     = SanType.Dns,
    is_excluded: bool        = false,
    val:         const u8[:] = [],
}

enum OcspResponseStatus {
    Successful,
    MalformedRequest,
    InternalError,
    TryLater,
    SigRequired,
    Unauthorized,
    Unknown,
}

enum OcspCertStatus {
    Good,
    Revoked,
    Unknown,
}

struct ParsedOcspResponse {
    status:             OcspResponseStatus = OcspResponseStatus.Unknown,
    cert_status:        OcspCertStatus     = OcspCertStatus.Unknown,
    serial_number:      Span16             = Span16 { offset: 0, length: 0 },
    issuer_name_hash:   Span16             = Span16 { offset: 0, length: 0 },
    issuer_key_hash:    Span16             = Span16 { offset: 0, length: 0 },
    hash_alg_oid:       Span16             = Span16 { offset: 0, length: 0 },
    tbs_raw:            Span16             = Span16 { offset: 0, length: 0 },
    sig_alg_oid:        Span16             = Span16 { offset: 0, length: 0 },
    pss_hash_id:        u8                 = 0,
    signature:          Span16             = Span16 { offset: 0, length: 0 },
    responder_cert_der: Span16             = Span16 { offset: 0, length: 0 },
    this_update:        i64                = 0,
    next_update:        i64                = 0,
    has_next_update:    bool               = false,
}

// Parsed X.509 Certificate Revocation List (RFC 5280 Section 5.1) with sorted
// inline serial storage for O(log N) binary-search revocation lookup.
struct ParsedCrl {
    issuer:       const u8[:] = "",
    serials:      u64[..1024] = [],
    serial_count: i32         = 0,
    this_update:  i64         = 0,
    next_update:  i64         = 0,
    tbs_raw:      Span16      = Span16 { offset: 0, length: 0 },
    sig_alg_oid:  Span16      = Span16 { offset: 0, length: 0 },
    pss_hash_id:  u8          = 0,
    signature:    Span16      = Span16 { offset: 0, length: 0 },
}

enum PrivateKeyKind {
    Unknown,
    Ed25519,
    EcdsaP256,
}

// ---- Stateless Session Ticket & STEK Types (RFC 8446 §4.6.1) --------------

const STEK_TICKET_PLAINTEXT_LEN: i64 = 63; // 1B psk_len + 48B psk + 2B suite + 8B issued_ms + 4B lifetime
const STEK_TICKET_WIRE_LEN:      i64 = 95; // 4B key_name + 12B iv + 63B ciphertext + 16B tag

struct CachedSessionTicket {
    in_use:       bool       = false,
    server_name:  u8[..256]  = [],
    ticket:       u8[..1024] = [],
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

// ---- ECH Types (RFC 9849) -------------------------------------------------

struct EchCipherSuite {
    kdf_id:  u16 = rfc::HPKE_KDF_HKDF_SHA256,
    aead_id: u16 = rfc::HPKE_AEAD_AES_128_GCM,
}

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

struct EchConfigList {
    configs: EchConfig[..4] = [],
}

enum EchHandshakeMode {
    Disabled,
    Offered,
    Accepted,
    RejectedWithRetry,
    Bypassed,
}

enum EchServerHelloType {
    ServerHello,
    HelloRetryRequest,
}

enum EchClientHelloType {
    Outer,
    Inner,
}

struct EchFsm {
    mode:              EchHandshakeMode = EchHandshakeMode.Disabled,
    has_hrr:           bool             = false,
    offered_config_id: u8               = 0,
}

// ---- Handshake State Machine & Message Types (RFC 8446 §4) ----------------

enum HandshakeMode {
    Full,
    Psk,
}

enum ClientAuthMode {
    Disabled,
    Requested,
}

enum HsState {
    ClientStart,
    ClientWaitSH,
    ClientWaitEE,
    ClientWaitCertCr,
    ClientWaitCert,
    ClientWaitCV,
    ClientWaitFinished,
    ServerWaitCH,
    ServerWaitEOED,
    ServerWaitCert,
    ServerWaitCV,
    ServerWaitFinished,
    Connected,
    Closed,
}

enum EarlyDataAccepted {
    Rejected,
    Accepted,
}

enum PostHandshakeAuth {
    Disabled,
    Offered,
}

enum CertCompressionOffer {
    NotOffered,
    Offered,
}

enum NegotiatedAlpn {
    None,
    H3,
    H2,
    Http11,
    Other,
}

struct ExtensionEntry {
    ext_type: u16         = 0,
    data:     const u8[:] = [],
}

struct CompressedCertMsg {
    algorithm:        u16 = rfc::CERT_COMPRESSION_ZSTD,
    uncompressed_len: u32 = 0,
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
    ticket_nonce:        u8[..255] = [],
    ticket:              u8[..256] = [],
    has_early_data:      bool      = false,
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

enum EarlyDataState {
    None,
    Offered,
    Accepted,
    Rejected,
}

struct EarlyDataController {
    state:                   EarlyDataState = EarlyDataState.None,
    keys_discarded:          bool           = false,
    bytes_sent:              u32            = 0,
    max_early_data_size:     u32            = 0,
    psk_cipher_suite:        u16            = 0,
    negotiated_cipher_suite: u16            = 0,
}

// ---- Live Session, Transcript & Handshake Config Types --------------------

struct Transcript {
    sha256_ctx: core::Sha256Ctx = core::Sha256Ctx { .. },
    sha384_ctx: core::Sha384Ctx = core::Sha384Ctx { .. },
}

const MAX_CIPHER_SLOTS: i64 = 4096;

enum SliceUnsealStatus {
    Ok,
    NeedMore,
    Closed,
    ControlHandled,
    Error,
}

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
    peer_closed:        bool               = false,
    resumed:            bool               = false,
    negotiated_alpn:    u8[..255]          = [],
    server_name:        u8[..256]          = [],
    san_hosts:          u8[..128][..8]     = [],
    rx_plain_buf:       u8[..16384]        = [],
    rx_plain_pos:       i64                = 0,
    bytes_sent:         u64                = 0,
    key_update_tracker: KeyUpdateTracker   = KeyUpdateTracker { .. },
    ticket_cache:       SessionTicketCache = SessionTicketCache { .. },
}

struct HandshakeRecordReader {
    current_record_plain: u8[..32768] = [],
    current_offset:       i64         = 0,
    seq_num:              u64         = 0,
    ccs_count:            u32         = 0,
}

struct ClientHandshakeConfig {
    server_name:          u8[..256]        = [],
    alpn:                 u8[..255]        = [],
    trust_store:          TrustAnchorStore = TrustAnchorStore { .. },
    use_system_roots:     bool             = true,
    insecure_skip_verify: bool             = false,
    virtual_clock_sec:    i64              = 0,
    client_cert_der:      u8[..4096]       = [],
    client_chain_der:     u8[..4096][..3]  = [],
    client_priv_seed:     u8[32]           = [0; 32],
    enable_pq_hybrid:     bool             = false,
    ech_config_list:      u8[..512]        = [],
    crl_der:              u8[..4096]       = [],
}

struct ServerHandshakeConfig {
    cert_der:             u8[..4096] = [],
    priv_seed:            u8[32]     = [0; 32],
    alpn:                 u8[..255]  = [],
    compressed_cert_algo: u16        = 0,
    compressed_cert_data: u8[..4096] = [],
}

enum SniOfferState {
    Omitted,
    Offered,
}

// ---- Global Lazy Cipher Slot Table & CSPRNG Pool --------------------------

var g_tls_entropy_pool:    u8[32]          = [0; 32];
var g_tls_entropy_counter: u64             = 0;
var g_tls_cipher_slots:    CipherSlot[>..] = [];
