# Client fingerprinting and profiles (`fingerprint/`)

Passive client fingerprinting, default `Wing` identity, and custom TLS, HTTP/2,
and TCP Layer 4 profile builders implementing FoxIO JA4/JA4H, Akamai HTTP/2
fingerprinting, and p0f v3 TCP SYN identification in `namespace
fingerprint;`.

```goose
import wing;

var profile = fingerprint::wing_default_profile();
let ja4_str = profile.ja4();
let akamai_md5 = profile.akamai_hash();
let p0f_str = profile.format_p0f();
```

## Public API

### Shared data types (`fingerprint/types.goose`)

`fingerprint/types.goose` exports the structs and enums shared across the JA4,
Akamai HTTP/2, p0f v3, and profile modules (`Ja4hFlags`, `AkamaiSetting`,
`AkamaiPriorityFrame`, `AkamaiFingerprint`, `AkamaiAnomaly`, `P0fWindowType`,
`P0fTcpOption`, `P0fQuirks`, `P0fSignature`, `P0fSocketOpts`, `Profile`,
`H2Settings`, `H3Settings`, `TlsFingerprintSpec`, `ClientProfile`, `Ja4Options`,
and `Ja4hOptions`). Internal-only parsers and formatting helpers live separately
in `namespace fingerprint_internal;` (`fingerprint/internal.goose`).

### FoxIO JA4 and JA4H fingerprinting (`fingerprint/ja4.goose`)

```goose
struct Ja4hFlags { has_cookie: bool, has_referer: bool }

fn compute_ja4<B>(
    ciphers:            const u16[:],
    extensions:         const u16[:],
    supported_versions: const u16[:],
    sni:                bool,
    alpn_protocol:      const u8[:],
    sig_algorithms:     const u16[:],
    is_quic:            bool,
    out:                B&,
)
fn compute_ja4(
    ciphers:            const u16[:],
    extensions:         const u16[:],
    supported_versions: const u16[:],
    sni:                bool         = true,
    alpn_protocol:      const u8[:]  = "h2",
    sig_algorithms:     const u16[:] = [],
    is_quic:            bool         = false,
) -> u8[..64]
fn compute_ja4h<B>(
    method:          const u8[:],
    proto:           const u8[:],
    header_names:    const u8[:][:],
    flags:           Ja4hFlags,
    accept_language: const u8[:],
    cookie_names:    const u8[:][:],
    cookie_values:   const u8[:][:],
    out:             B&,
)
fn compute_ja4h(
    method:          const u8[:],
    proto:           const u8[:],
    header_names:    const u8[:][:],
    flags:           Ja4hFlags      = Ja4hFlags { .. },
    accept_language: const u8[:]    = "",
    cookie_names:    const u8[:][:] = [],
    cookie_values:   const u8[:][:] = [],
) -> u8[..64]
```

`compute_ja4` and `compute_ja4h` generate FoxIO JA4 TLS client fingerprints and
JA4H HTTP request fingerprints either into a caller-supplied buffer `out` or by
returning a stack-bounded `u8[..64]` value. Internal helpers in
`fingerprint_internal` strip RFC 8701 GREASE values, format the TLS version and
ALPN fields, and sort cipher suites, extensions, and cookies.

### Akamai HTTP/2 fingerprinting (`fingerprint/akamai.goose`)

```goose
struct AkamaiSetting { id: u16, val: u32 }
struct AkamaiPriorityFrame {
    stream_id:     u32,
    exclusive:     u8,
    dep_stream_id: u32,
    weight:        u16,
}
struct AkamaiFingerprint {
    settings:        AkamaiSetting[..16],
    window_update:   u32,
    priority_frames: AkamaiPriorityFrame[..8],
    pseudo_headers:  u8[..8],
}
enum AkamaiAnomaly {
    None,
    MissingPseudoHeaders,
    PseudoHeaderOrderMismatch,
    WindowUpdateAnomaly,
    SettingsMismatch,
}

fn format_akamai<B>(fp: const AkamaiFingerprint&, out: B&)
fn format_akamai(fp: const AkamaiFingerprint&) -> u8[..640]
fn compute_akamai_hash<B>(fp: const AkamaiFingerprint&, out: B&)
fn akamai_hash(fp: const AkamaiFingerprint&) -> u8[..32]
fn akamai_wing_preset() -> AkamaiFingerprint
fn custom_akamai_fingerprint(
    window_update:  u32         = 0,
    pseudo_headers: const u8[:] = "m,a,s,p",
) -> AkamaiFingerprint
fn push_setting(fp: AkamaiFingerprint&, id: u16, val: u32) -> bool
fn push_priority(
    fp:            AkamaiFingerprint&,
    stream_id:     u32,
    exclusive:     u8,
    dep_stream_id: u32,
    weight:        u16,
) -> bool
fn set_pseudo_headers(fp: AkamaiFingerprint&, order: const u8[:]) -> bool
fn parse_akamai_fingerprint(raw: const u8[:]) -> AkamaiFingerprint, bool
fn match_akamai(a: const AkamaiFingerprint&, b: const AkamaiFingerprint&) -> bool
fn detect_akamai_anomaly(
    actual:   const AkamaiFingerprint&,
    expected: const AkamaiFingerprint&,
) -> AkamaiAnomaly, const u8[:]
fn extract_akamai_from_wire(
    wire_bytes:           const u8[:],
    pseudo_headers_order: const u8[:],
) -> AkamaiFingerprint, bool
fn encode_akamai_handshake_frames<B>(fp: const AkamaiFingerprint&, out: B&) -> bool
fn order_pseudo_headers(
    fp:        const AkamaiFingerprint&,
    method:    const u8[:],
    authority: const u8[:],
    scheme:    const u8[:],
    path:      const u8[:],
    out:       wing::HeaderMap&,
) -> bool
```

`AkamaiFingerprint` captures HTTP/2 connection preface parameters in canonical
`S|W|P|PS` notation (up to 16 `SETTINGS` pairs, initial `WINDOW_UPDATE`, up to 8
`PRIORITY` frames, and pseudo-header ordering) and hashes them into a
32-character lowercase hexadecimal MD5 digest (`u8[..32]`).
`extract_akamai_from_wire` and `parse_akamai_fingerprint` return `false` on
malformed frames or syntax. `encode_akamai_handshake_frames` and
`order_pseudo_headers` roll back partial writes to `out` and return `false` on
overflow or missing pseudo-header fields. `detect_akamai_anomaly` compares an
observed fingerprint against a reference profile (`akamai_wing_preset` or a
custom profile) across settings, window update, and pseudo-header ordering.

### p0f v3 TCP SYN fingerprinting (`fingerprint/p0f.goose`)

```goose
enum P0fWindowType { Normal, Mss, Mtu, Mod, Any }
enum P0fTcpOption { Eol, Nop, Mss, Ws, Sok, Sack, Ts, Unknown }
struct P0fQuirks { .. }
struct P0fSignature {
    ip_version:    u8,
    ttl:           u8,
    has_ttl_minus: bool,
    ip_opt_len:    u8,
    mss:           i32,
    window_type:   P0fWindowType,
    window_size:   i32,
    window_scale:  i16,
    options:       P0fTcpOption[..16],
    quirks:        P0fQuirks,
    payload:       u8[..8],
}
struct P0fSocketOpts {
    ttl:                 u8,
    dont_fragment:       bool,
    receive_buffer_size: i32,
}

fn wing_p0f_signature() -> P0fSignature
fn custom_p0f_signature(
    ip_version:    u8            = 0,
    ttl:           u8            = 64,
    has_ttl_minus: bool          = false,
    mss:           i32           = -1,
    window_type:   P0fWindowType = P0fWindowType.Mss,
    window_size:   i32           = 20,
    window_scale:  i16           = 10,
) -> P0fSignature
fn format_p0f(sig: const P0fSignature&) -> u8[..256]
fn parse_p0f(raw: const u8[:]) -> P0fSignature, bool
fn match_p0f(actual: const P0fSignature&, target: const P0fSignature&) -> bool
fn push_option(sig: P0fSignature&, opt: P0fTcpOption) -> bool
fn set_quirk(sig: P0fSignature&, quirk_name: const u8[:], enabled: bool) -> bool
fn has_quirk(sig: const P0fSignature&, quirk_name: const u8[:]) -> bool
fn to_socket_opts(sig: const P0fSignature&, base_mss: i32 = 1460) -> P0fSocketOpts
```

`P0fSignature` models passive and active TCP SYN fingerprints in
`ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass` notation (`u8[..256]`),
recording IP/TCP header quirks (`df`, `id+`, `id-`, `ecn`, `0+`, `flow`, `seq-`,
`ack+`, `ack-`, `uptr+`, `urgf+`, `pushf+`, `ts1-`, `ts2+`, `opt+`, `expt`,
`bad`) in `P0fQuirks`. `push_option` and `set_quirk` return `false` on capacity
overflow or unknown quirk tokens. `to_socket_opts` translates a signature into
L4 socket configuration parameters (`P0fSocketOpts`).

### Coordinated client profiles (`fingerprint/profile.goose`)

```goose
struct H2Settings { .. }
struct H3Settings { .. }
struct TlsFingerprintSpec { .. }
struct ClientProfile { .. }
struct Ja4Options { is_quic: bool, sni: bool }
struct Ja4hOptions { has_cookie: bool, has_referer: bool }

fn user_agent(profile: Profile) -> const u8[:]
fn name(profile: Profile) -> const u8[:]
fn wing_default_profile() -> ClientProfile
fn custom_profile() -> ClientProfile
fn none_profile() -> ClientProfile
fn new_client_profile(kind: Profile) -> ClientProfile
fn ja4(profile: const ClientProfile&, opts: Ja4Options = Ja4Options { .. }) -> u8[..64]
fn ja4h(
    profile:       const ClientProfile&,
    method:        const u8[:],
    proto:         const u8[:],
    opts:          Ja4hOptions    = Ja4hOptions { .. },
    cookie_names:  const u8[:][:] = [],
    cookie_values: const u8[:][:] = [],
) -> u8[..64]
fn set_header(profile: ClientProfile&, name: const u8[:], value: const u8[:])
fn set_user_agent(profile: ClientProfile&, ua: const u8[:])
fn set_accept(profile: ClientProfile&, accept_str: const u8[:])
fn set_accept_encoding(profile: ClientProfile&, enc: const u8[:])
fn set_accept_language(profile: ClientProfile&, lang: const u8[:])
fn set_p0f(profile: ClientProfile&, sig: const P0fSignature&)
fn format_p0f(profile: const ClientProfile&) -> u8[..256]
fn set_akamai(profile: ClientProfile&, fp: const AkamaiFingerprint&)
fn format_akamai(profile: const ClientProfile&) -> u8[..640]
fn akamai_hash(profile: const ClientProfile&) -> u8[..32]
```

`ClientProfile` coordinates `TlsFingerprintSpec` (`ciphers`, `extensions`,
`supported_versions`, `sig_algorithms`, `alpn`), `H2Settings`, `H3Settings`,
default HTTP headers, `P0fSignature`, and `AkamaiFingerprint` into one client
persona. Calling `set_akamai` binds the HTTP/2 fingerprint and updates
`H2Settings` to match.
