# goose-wing browser fingerprints and WPT conformance suite

Wire-level TLS and HTTP/2 client fingerprint parity harness (JA3, FoxIO JA4,
JA4H, and Akamai HTTP/2 against [ja4db_reference.json](ja4db_reference.json))
paired with a 35-vector Web Platform Tests (WPT) conformance suite for
`cookie::CanonicalCookieJar`, `client` redirects, and `security` CORS policies
via [fp_wpt_harness.goose](fp_wpt_harness.goose).

## Quick start

### Local offline mode (40 vectors: 5 fingerprint + 35 WPT)

```bash
python tools/fingerprint_wpt.py --local
```

### Live fingerprint echo probes (requires internet access)

```bash
python tools/fingerprint_wpt.py --live --profile Wing
```

Connects via `goose-wing`'s native HTTP/TLS client to
`https://tls.peet.ws/api/all` and `https://tls.browserleaks.com/json` and
compares the observed JA3, JA4, and Akamai HTTP/2 JSON fields against the
expected profile.

### Docker mode

```bash
python tools/fingerprint_wpt.py --docker
```

## Verified conformance areas

| Category | Vectors | Verified rules |
| :--- | :--- | :--- |
| Browser fingerprints | 5 | Independent wire ClientHello JA3/JA4 parsing and raw HTTP/2 frame Akamai extraction for `Chrome`, `Firefox`, `Safari`, and `Wing` profiles, GREASE filtering, H2 wire round-trip anomaly checks, and native `tls::build_client_hello_payload` validation. |
| WPT Cookies (RFC 6265bis) | 15 | `__Host-` and `__Secure-` prefix invariants, host-only vs `Domain` scoping, Public Suffix List rejection, `Path` boundary matching, `SameSite` (`Strict`, `Lax`, `None` + `Secure`), `Max-Age` precedence over `Expires`, `Max-Age=0` eviction, 4096-byte size limit, and `HttpOnly` API isolation. |
| WPT Redirects (RFC 9110 / Fetch) | 10 | `301`/`302`/`303` method rewrite to `GET` and body/payload header clearing, `307`/`308` method and body preservation, same-origin vs cross-origin `Authorization`/`DPoP`/`Cookie` stripping, HTTPS-to-HTTP downgrade stripping, `Referrer-Policy` origin trimming, and forbidden scheme rejection. |
| WPT CORS (WHATWG Fetch) | 10 | Exact origin matching with `Vary: Origin`, wildcard `*` without credentials, unlisted origin rejection, preflight method and custom private header enforcement, wildcard non-coverage of `Authorization`, credentials + `*` `InvalidConfig`, `null` origin rejection, and client-side `verify_client_cors_response`. |
