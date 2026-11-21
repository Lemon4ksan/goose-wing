// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Public data structures and enums for client fingerprinting (JA4/JA4H, Akamai HTTP/2, p0f v3)
// and coordinated client persona profiles.
namespace fingerprint;

import std;
import http.headers;

// ---- JA4H Types ------------------------------------------------------------

// Presence flags for HTTP headers excluded from the JA4H header count.
struct Ja4hFlags {
    has_cookie:  bool = false,
    has_referer: bool = false,
}

// ---- Akamai HTTP/2 Types ---------------------------------------------------

// Single HTTP/2 parameter within the initial SETTINGS frame.
struct AkamaiSetting {
    id:  u16 = 0,
    val: u32 = 0,
}

// Stream priority dependency declared during HTTP/2 connection setup.
struct AkamaiPriorityFrame {
    stream_id:     u32 = 0,
    exclusive:     u8  = 0, // 0 or 1
    dep_stream_id: u32 = 0,
    weight:        u16 = 0, // 1 to 256
}

// Complete Akamai HTTP/2 Client Fingerprint specification.
struct AkamaiFingerprint {
    settings:        AkamaiSetting[..16]      = [],
    window_update:   u32                      = 0, // Stream 0 window increment (0 if omitted)
    priority_frames: AkamaiPriorityFrame[..8] = [],
    pseudo_headers:  u8[..8]                  = [], // Initial chars: e.g. ['m', 'a', 's', 'p']
}

// Classification of fingerprint anomalies detected against an expected HTTP/2 profile.
enum AkamaiAnomaly {
    None,
    MissingPseudoHeaders,
    PseudoHeaderOrderMismatch,
    WindowUpdateAnomaly,
    SettingsMismatch,
}

// ---- p0f v3 TCP SYN Types --------------------------------------------------

// Window size calculation type in p0f v3 SYN fingerprint.
enum P0fWindowType {
    Normal, // Exact window size (e.g. 65535, 8192)
    Mss,    // Window is a multiple of MSS (e.g. mss*20, mss*10)
    Mtu,    // Window is a multiple of MTU (e.g. mtu*4)
    Mod,    // Window is modulo (mod*N or %N)
    Any,    // Wildcard window size (*,-1)
}

// Canonical TCP Option identifiers in p0f layout.
enum P0fTcpOption {
    Eol,     // End of option list (0)
    Nop,     // No operation / padding (1)
    Mss,     // Maximum segment size (2)
    Ws,      // Window scale (3)
    Sok,     // SACK permitted (4)
    Sack,    // SACK block (5)
    Ts,      // Timestamps (8)
    Unknown, // Generic / other option
}

// Canonical TCP Quirks recognized in p0f v3.
struct P0fQuirks {
    df:         bool = false, // Don't Fragment bit set
    id_plus:    bool = false, // IP ID non-zero when DF set
    id_minus:   bool = false, // IP ID zero when DF NOT set
    ecn:        bool = false, // ECN flags set (ECE/CWR)
    zero_plus:  bool = false, // Reserved bits non-zero
    flow:       bool = false, // IPv6 flow label non-zero
    seq_minus:  bool = false, // Sequence number zero
    ack_plus:   bool = false, // ACK non-zero in pure SYN
    ack_minus:  bool = false, // ACK zero in SYN+ACK
    uptr_plus:  bool = false, // Urgent pointer non-zero
    urgf_plus:  bool = false, // URG flag set
    pushf_plus: bool = false, // PUSH flag set
    ts1_minus:  bool = false, // Own timestamp zero
    ts2_plus:   bool = false, // Peer timestamp non-zero in initial SYN
    opt_plus:   bool = false, // Trailing data after EOL
    expt:       bool = false, // Experimental option ID (253, 254)
    bad:        bool = false, // Malformed option
}

// Complete parsed p0f v3 TCP SYN signature structure (8 fields).
// format: ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
struct P0fSignature {
    ip_version:    u8                 = 0,     // 4, 6, or 0 (wildcard '*')
    ttl:           u8                 = 64,    // Initial TTL (e.g. 64, 128)
    has_ttl_minus: bool               = false, // TTL tolerance wildcard (e.g. '64-')
    ip_opt_len:    u8                 = 0,     // Length of IP options (usually 0)
    mss:           i32                = -1,    // MSS value or -1 for wildcard '*'
    window_type:   P0fWindowType      = P0fWindowType.Mss,
    window_size:   i32                = 20, // Value or multiplier
    window_scale:  i16                = 10, // Scale factor (0..14, or -1 for any)
    options:       P0fTcpOption[..16] = [], // Ordered TCP options
    quirks:        P0fQuirks          = P0fQuirks { .. },
    payload:       u8[..8]            = [], // "0", "+", or "*"
}

// Concrete OS socket parameters derived from a p0f signature.
struct P0fSocketOpts {
    ttl:                 u8   = 64,
    dont_fragment:       bool = true,
    receive_buffer_size: i32  = 262144,
}

// ---- Client Persona & Settings Types ---------------------------------------

// Client identity profile mode.
enum Profile {
    Wing,   // Authentic Wing Zero-Heap Systems Engine identity (Default)
    Custom, // User-controlled custom profile
    None,   // Minimal raw client without default headers
}

// HTTP/2 protocol settings for the persona.
struct H2Settings {
    header_table_size:      u32 = 65536,
    enable_push:            u32 = 0,
    max_concurrent_streams: u32 = 100,
    initial_window_size:    u32 = 6291456,
    max_frame_size:         u32 = 16384,
    max_header_list_size:   u32 = 262144,
}

// HTTP/3 protocol settings for the persona.
struct H3Settings {
    qpack_max_table_capacity:  u64 = 4096,
    max_field_section_size:    u64 = 65536,
    qpack_blocked_streams:     u64 = 16,
    enable_connect_protocol:   u64 = 1,
    h3_datagram:               u64 = 0,
    enable_webtransport:       u64 = 0,
    webtransport_max_sessions: u64 = 0,
}

// TLS ClientHello specification for JA4 fingerprinting and transport configuration.
struct TlsFingerprintSpec {
    ciphers:            u16[..32] = [],
    extensions:         u16[..32] = [],
    supported_versions: u16[..8]  = [],
    sig_algorithms:     u16[..16] = [],
    alpn:               u8[..16]  = [],
}

// Client profile specification governing outbound request appearance and wire fingerprint.
struct ClientProfile {
    kind:                      Profile            = Profile.Wing,
    user_agent:                u8[..256]          = [],
    accept:                    u8[..192]          = [],
    accept_encoding:           u8[..64]           = [],
    accept_language:           u8[..64]           = [],
    upgrade_insecure_requests: u8[..8]            = [],
    extra_headers:             http::HeaderMap    = http::HeaderMap { .. },
    h2:                        H2Settings         = H2Settings { .. },
    h3:                        H3Settings         = H3Settings { .. },
    tls:                       TlsFingerprintSpec = TlsFingerprintSpec { .. },
    p0f:                       P0fSignature       = P0fSignature { .. },
    akamai:                    AkamaiFingerprint  = AkamaiFingerprint { .. },
}

// Options controlling JA4 TLS fingerprint generation from a ClientProfile.
struct Ja4Options {
    is_quic: bool = false,
    sni:     bool = true,
}

// Options controlling JA4H HTTP fingerprint generation from a ClientProfile.
struct Ja4hOptions {
    has_cookie:  bool = false,
    has_referer: bool = false,
}
