# `fingerprint`

Passive client fingerprinting, active browser impersonation profiles, and TLS / HTTP/2 / TCP Layer 4 identity tracking for `goose-wing`. Implements FoxIO JA4 / JA4H, Akamai HTTP/2 fingerprinting, and p0f v3 passive TCP SYN OS identification.

## Public API

### FoxIO JA4 & JA4H Fingerprinting (`ja4.goose`)

- **`struct Ja4TlsClientHello`**: Parsed TLS ClientHello features (`protocol`, `sni_present`, `ciphers: u16[..64]`, `alpn: u8[..16]`, `extensions: u16[..64]`, `sig_algs: u16[..32]`).
- **`fn compute_ja4(client_hello: const Ja4TlsClientHello&, out_ja4: u8[..36]&)`**: Generates canonical FoxIO JA4 36-character TLS client fingerprint string (`{proto}{sni}{ciphers}_{ciphers_hash}_{exts_hash}`).
- **`fn compute_ja4_from_wire(wire_client_hello: const u8[:], out_ja4: u8[..36]&) -> bool`**: Zero-allocation parser directly decoding wire ClientHello bytes and synthesizing JA4.
- **`struct Ja4hRequest`**: Parsed HTTP request features (`method`, `http_version`, `cookie_present`, `referer_present`, `headers: u8[..64][..32]`).
- **`fn compute_ja4h(req: const Ja4hRequest&, out_ja4h: u8[..36]&)`**: Generates canonical FoxIO JA4H 36-character HTTP request fingerprint string (`{method}{version}{cookie}{referer}_{headers_hash}_{cookie_hash}`).
- **`fn compute_ja4h_from_headers(method: const u8[:], version: const u8[:], headers: const HeaderMap&, out_ja4h: u8[..36]&)`**: Computes JA4H directly from an active `HeaderMap`.

### Akamai HTTP/2 Fingerprinting & Anomaly Detection (`akamai.goose`)

- **`struct AkamaiSetting`**: Single HTTP/2 SETTINGS frame parameter (`id: u16`, `val: u32`).
- **`struct AkamaiFingerprint`**: Decoded HTTP/2 connection parameters (`settings: AkamaiSetting[..16]`, `window_update: u32`, `priority_stream_id: u32`, `priority_exclusive: bool`, `priority_depends_on: u32`, `priority_weight: u8`, `pseudo_headers: u8[..16]`).
- **`enum AkamaiBrowserFamily`**: Detected client browser family (`Chrome`, `Firefox`, `Safari`, `Unknown`).
- **`enum AkamaiAnomaly`**: Discrepancies between User-Agent declarations and HTTP/2 wire fingerprints (`None`, `MissingPseudoHeaders`, `PseudoHeaderOrderMismatch`, `WindowUpdateAnomaly`, `SettingsMismatch`, `BotPattern`).
- **`fn compute_akamai_hash(fp: const AkamaiFingerprint&, out_hash: u8[..32]&)`**: Generates 32-character hexadecimal MD5 digest of canonical Akamai HTTP/2 fingerprint string.
- **`fn format_akamai_fingerprint<B>(fp: const AkamaiFingerprint&, out: B&)`**: Serializes fingerprint to standard Akamai notation (`settings|window_update|priority|pseudo_headers`).
- **`fn parse_akamai_fingerprint(str: const u8[:], out_fp: AkamaiFingerprint&) -> bool`**: Parses serialized Akamai fingerprint string into typed structure.
- **`fn classify_akamai_fingerprint(fp: const AkamaiFingerprint&) -> AkamaiBrowserFamily`**: Identifies browser engine from SETTINGS defaults and pseudo-header ordering.
- **`fn detect_akamai_anomaly(user_agent: const u8[:], fp: const AkamaiFingerprint&) -> AkamaiAnomaly, const u8[:]`**: Validates User-Agent consistency against wire HTTP/2 behavior, flagging spoofed bot signatures.
- **`fn akamai_preset_chrome_120() -> AkamaiFingerprint`**: Preset fingerprint matching authentic Chromium 120+.
- **`fn akamai_preset_firefox_120() -> AkamaiFingerprint`**: Preset fingerprint matching authentic Firefox 120+.
- **`fn akamai_preset_safari_17() -> AkamaiFingerprint`**: Preset fingerprint matching authentic Safari 17+.

### p0f v3 Passive TCP SYN Fingerprinting (`p0f.goose`)

- **`struct P0fSynSignature`**: Passive OS fingerprint signature extracted from TCP SYN packet (`ip_ver`, `initial_ttl`, `ip_opt_len`, `mss`, `window_size`, `window_scale`, `w_scale_val`, `olayout: u8[..16]`, `quirks: u32`).
- **`enum P0fOsFamily`**: Operating system classification (`Linux`, `Windows`, `FreeBsd`, `MacOS`, `OpenBsd`, `Solaris`, `Unknown`).
- **`fn parse_p0f_syn(ip_tcp_wire: const u8[:], out_sig: P0fSynSignature&) -> bool`**: Zero-allocation parser extracting TCP SYN options, MSS, window scale, and IP header quirks from raw L4 wire bytes.
- **`fn format_p0f_signature<B>(sig: const P0fSynSignature&, out: B&)`**: Formats p0f signature to standard v3 text representation.
- **`fn match_p0f_os(sig: const P0fSynSignature&) -> P0fOsFamily`**: Matches signature against passive fingerprint database.

### Coordinated Browser Profiles (`profile.goose`)

- **`struct BrowserProfile`**: Coordinated client personality matching TLS, HTTP/2, and header profiles (`family`, `ja4: u8[..36]`, `akamai_hash: u8[..32]`, `akamai: AkamaiFingerprint`, `user_agent: u8[..256]`).
- **`fn new_browser_profile(family: AkamaiBrowserFamily) -> BrowserProfile`**: Instantiates a coordinated browser profile (Chrome, Firefox, Safari) with matching User-Agent, headers, and HTTP/2 settings.
- **`fn apply_browser_profile(profile: const BrowserProfile&, out_headers: HeaderMap&)`**: Injects authentic browser headers and pseudo-headers into outgoing client requests.
