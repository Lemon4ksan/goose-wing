# goose-wing TLS interop canary (badssl.com + offline local CA matrix)

TLS certificate verification and protocol floor canary testing `PureGoose`,
`SystemOpenSsl`, and `SystemSchannel` (when available) via
[canary.goose](canary.goose) against both a deterministic local ECDSA P-256 PKI
matrix (`--offline`) and public `badssl.com` endpoints (`--live`).

## Quick start

### Deterministic offline local CA matrix

```bash
python tools/badssl_canary.py --offline
```

### Live public badssl.com matrix (requires internet access)

```bash
python tools/badssl_canary.py --live
```

### Docker offline mode

```bash
python tools/badssl_canary.py --docker
```

## Verified matrix

| Scenario | Default `Tls13` | Opt-in `Tls12` (`SystemOpenSsl`) |
| :--- | :--- | :--- |
| Valid CA-signed certificate, matching SAN, ALPN `h2` | `Ok` (`h2`) | `Ok` |
| Expired certificate (`notAfter` in the past) | `VerifyError` | `VerifyError` |
| Wrong hostname (SAN mismatch) | `VerifyError` | `VerifyError` |
| Untrusted self-signed certificate | `VerifyError` | `VerifyError` |
| Certificate signed by untrusted root CA | `VerifyError` | `VerifyError` |
| TLS 1.2-only server peer | `HandshakeError` (rejected) | `Ok` (accepted) |
