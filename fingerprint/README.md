# Client Fingerprinting & Profiles (`fingerprint/`)

Passive client fingerprinting, native `Wing` identity, and custom TLS, HTTP/2,
and TCP Layer 4 profile builders implementing FoxIO JA4/JA4H, Akamai HTTP/2
fingerprinting, and p0f v3 TCP SYN OS identification.

```goose
import wing;

var profile = wing_default_profile();
let ja4_str = ja4(profile);
let akamai_md5 = akamai_hash(profile);
```

## Public API

### FoxIO JA4 & JA4H Fingerprinting (`fingerprint/ja4.goose`)

```goose
struct Ja4hFlags { has_cookie: bool, has_referer: bool }

fn compute_ja4<B>(ciphers: const u16[:], extensions: const u16[:], supported_versions: const u16[:], sni: bool, alpn_protocol: const u8[:], sig_algorithms: const u16[:], is_quic: bool, out: B&)
fn compute_ja4(ciphers: const u16[:], extensions: const u16[:], supported_versions: const u16[:], sni: bool = true, alpn_protocol: const u8[:] = "h2", sig_algorithms: const u16[:] = [], is_quic: bool = false) -> u8[..64]
fn compute_ja4h<B>(method: const u8[:], proto: const u8[:], header_names: const u8[:][:], flags: Ja4hFlags, accept_language: const u8[:], cookie_names: const u8[:][:], cookie_values: const u8[:][:], out: B&)
fn compute_ja4h(method: const u8[:], proto: const u8[:], header_names: const u8[:][:], flags: Ja4hFlags = Ja4hFlags { .. }, accept_language: const u8[:] = "", cookie_names: const u8[:][:] = [], cookie_values: const u8[:][:] = []) -> u8[..64]
fn ja4_version_string(supported_versions: const u16[:]) -> const u8[:]
fn ja4_alpn_string<B>(alpn_protocol: const u8[:], out: B&)
fn filter_grease_u16(vals: const u16[:], out: u16[>..]&)
```

`compute_ja4` and `compute_ja4h` generate FoxIO JA4 TLS client fingerprints and
JA4H HTTP request fingerprints either into a caller-supplied buffer `out` or by
returning a stack-bounded `u8[..64]` value. `filter_grease_u16` strips RFC 8701
GREASE values before sorting cipher suites and extensions, while
`ja4_version_string` and `ja4_alpn_string` format the 2-character TLS version
and ALPN prefix fields.

### Akamai HTTP/2 Fingerprinting & Anomaly Detection (`fingerprint/akamai.goose`)

```goose
struct AkamaiSetting { id: u16, val: u32 }
struct AkamaiPriorityFrame { stream_id: u32, exclusive: u8, dep_id: u32, weight: u16 }
struct AkamaiFingerprint {
    settings: AkamaiSetting[..16],
    window_update: u32,
    priority: AkamaiPriorityFrame[..8],
    pseudo_headers: u8[..16],
}
enum AkamaiAnomaly {
    None,
    MissingPseudoHeaders,
    PseudoHeaderOrderMismatch,
    WindowUpdateAnomaly,
    SettingsMismatch,
}

fn format_akamai_fingerprint<B>(fp: const AkamaiFingerprint&, out: B&)
fn akamai_fingerprint_to_string(fp: const AkamaiFingerprint&) -> u8[..640]
fn compute_akamai_hash<B>(fp: const AkamaiFingerprint&, dst: B&)
fn akamai_fingerprint_hash(fp: const AkamaiFingerprint&) -> u8[..32]
fn parse_akamai_fingerprint(raw: const u8[:]) -> AkamaiFingerprint, bool
fn match_akamai_fingerprints(a: const AkamaiFingerprint&, b: const AkamaiFingerprint&) -> bool
fn detect_akamai_anomaly(actual: const AkamaiFingerprint&, expected: const AkamaiFingerprint&) -> AkamaiAnomaly, const u8[:]
fn extract_akamai_from_wire(wire_bytes: const u8[:], pseudo_headers_order: const u8[:]) -> AkamaiFingerprint, bool
fn encode_akamai_handshake_frames<B>(fp: const AkamaiFingerprint&, out: B&)
fn order_pseudo_headers(fp: const AkamaiFingerprint&, method: const u8[:], authority: const u8[:], scheme: const u8[:], path: const u8[:], out: HeaderMap&)
fn akamai_wing_preset() -> AkamaiFingerprint
fn custom_akamai_fingerprint(window_update: u32 = 0, pseudo_headers: const u8[:] = "m,a,s,p") -> AkamaiFingerprint
fn akamai_push_setting(fp: AkamaiFingerprint&, id: u16, val: u32) -> bool
fn akamai_push_priority(fp: AkamaiFingerprint&, stream_id: u32, exclusive: u8, dep_stream_id: u32, weight: u16) -> bool
fn akamai_set_pseudo_headers(fp: AkamaiFingerprint&, order: const u8[:]) -> bool
```

`AkamaiFingerprint` captures HTTP/2 connection preface parameters in canonical
`S|W|P|PS` notation (up to 16 `SETTINGS` pairs, initial `WINDOW_UPDATE`, up to 8
`PRIORITY` frames, and pseudo-header ordering) and hashes them into a
32-character hexadecimal MD5 digest (`u8[..32]`). `extract_akamai_from_wire` and
`parse_akamai_fingerprint` return `false` on malformed frames or syntax.
`detect_akamai_anomaly` compares an observed HTTP/2 fingerprint against an
expected reference profile (`akamai_wing_preset` or a custom profile) across
settings, window update, and pseudo-header ordering (`order_pseudo_headers`).

### p0f v3 TCP SYN Fingerprinting (`fingerprint/p0f.goose`)

```goose
enum P0fWindowType { Normal, Mss, Mtu, Wildcard }
enum P0fTcpOption { Mss, Nop, Sok, Ws, Ts, Eol }
struct P0fQuirks { .. }
struct P0fSignature {
    ip_version: u8,
    ttl: u8,
    has_ttl_minus: bool,
    ip_opt_len: u8,
    mss: i32,
    window_type: P0fWindowType,
    window_size: i32,
    window_scale: i16,
    options: P0fTcpOption[..16],
    quirks: P0fQuirks,
    payload_class: u8,
}
struct P0fSocketOpts {
    ttl: u8,
    mss: i32,
    rcvbuf: i32,
    window_scale: i16,
    df_bit: bool,
    ecn: bool,
    sack_perm: bool,
    timestamps: bool,
}

fn wing_p0f_signature() -> P0fSignature
fn custom_p0f_signature(ip_version: u8 = 0, ttl: u8 = 64, has_ttl_minus: bool = false, mss: i32 = -1, window_type: P0fWindowType = P0fWindowType.Mss, window_size: i32 = 20, window_scale: i16 = 10) -> P0fSignature
fn format_p0f(sig: const P0fSignature&) -> u8[..256]
fn parse_p0f(raw: const u8[:]) -> P0fSignature, bool
fn match_p0f(actual: const P0fSignature&, target: const P0fSignature&) -> bool
fn p0f_push_option(sig: P0fSignature&, opt: P0fTcpOption)
fn p0f_set_quirk(sig: P0fSignature&, quirk_name: const u8[:], enabled: bool)
fn p0f_has_quirk(sig: const P0fSignature&, quirk_name: const u8[:]) -> bool
fn p0f_to_socket_opts(sig: const P0fSignature&, base_mss: i32 = 1460) -> P0fSocketOpts
```

`P0fSignature` models passive and active TCP SYN fingerprints in
`ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass` notation (`u8[..256]`),
recording IP/TCP header quirks (`df`, `id+`, `id-`, `ecn`, `0+`, `flow`, `seq-`,
`ack+`, `ack-`, `uptr+`, `urgf+`, `pushf+`, `ts1-`, `ts2+`, `opt+`, `exws`,
`bad`) in `P0fQuirks`. `p0f_to_socket_opts` translates a signature into L4
socket configuration parameters (`P0fSocketOpts`).

### Coordinated Client Profiles (`fingerprint/profile.goose`)

```goose
struct H2Settings { .. }
struct H3Settings { .. }
struct TlsFingerprintSpec { .. }
struct ClientProfile { .. }
struct Ja4Options { sni: bool, alpn: u8[..16], is_quic: bool }
struct Ja4hOptions { has_cookie: bool, has_referer: bool, accept_language: u8[..64] }

fn wing_default_profile() -> ClientProfile
fn custom_profile() -> ClientProfile
fn none_profile() -> ClientProfile
fn new_client_profile(kind: Profile) -> ClientProfile
fn push_header_order(profile: ClientProfile&, header_name: const u8[:])
fn ja4(profile: const ClientProfile&, opts: Ja4Options = Ja4Options { .. }) -> u8[..64]
fn ja4h(profile: const ClientProfile&, method: const u8[:], proto: const u8[:], opts: Ja4hOptions = Ja4hOptions { .. }, cookie_names: const u8[:][:] = [], cookie_values: const u8[:][:] = []) -> u8[..64]
fn set_header(profile: ClientProfile&, name: const u8[:], value: const u8[:])
fn set_user_agent(profile: ClientProfile&, ua: const u8[:])
fn set_accept(profile: ClientProfile&, accept_str: const u8[:])
fn set_accept_encoding(profile: ClientProfile&, enc: const u8[:])
fn set_accept_language(profile: ClientProfile&, lang: const u8[:])
fn set_p0f(profile: ClientProfile&, sig: const P0fSignature&)
fn p0f(profile: const ClientProfile&) -> u8[..256]
fn set_akamai(profile: ClientProfile&, fp: const AkamaiFingerprint&)
fn akamai(profile: const ClientProfile&) -> u8[..640]
fn akamai_hash(profile: const ClientProfile&) -> u8[..32]
```

`ClientProfile` coordinates `TlsFingerprintSpec` (`ciphers`, `extensions`,
`supported_versions`, `sig_algorithms`, `alpn`), `H2Settings`, `H3Settings`,
default HTTP headers and wire ordering, `P0fSignature`, and `AkamaiFingerprint`
into a unified client persona. Calling `set_akamai` binds the HTTP/2 fingerprint
and synchronizes `H2Settings` to match.
