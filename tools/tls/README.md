# goose-wing TLS 1.3 interop verification suite

End-to-end verification suite testing `goose-wing`'s RFC 8446 TLS 1.3 stack,
pluggable `SystemOpenSsl` and `PureGoose` backends against live `openssl
s_server` (`-tls1_2` and `-tls1_3`), strict TLS 1.3 default vs opt-in
`TlsMinVersion.Tls12` fallback, and negative TLS state-machine attacks.

## Quick start

### Host mode (local compiler)

```bash
python tools/tls.py
```

### Docker mode (containerized suite)

```bash
docker compose -f tools/tls/docker-compose.yml up --build --abort-on-container-exit
```

## Verified scenarios

| Category | Verification details |
| :--- | :--- |
| RFC 8446 TLS 1.3 handshake | ClientHello/ServerHello negotiation (`TLS_AES_128_GCM_SHA256`, `supported_versions` `0x0304`), middlebox CCS, SNI normalization, ALPN `h2`, Ed25519 PKI verification, and pooled HTTP/2 reuse. |
| Strict TLS 1.3 vs opt-in TLS 1.2 | Against live `openssl s_server -tls1_2`, default `TlsMinVersion.Tls13` rejects TLS 1.2 on both `PureGoose` and `SystemOpenSsl`; opt-in `SystemOpenSsl` with `TlsMinVersion.Tls12` succeeds. |
| Pluggable `SystemOpenSsl` interop | Against live `openssl s_server -tls1_3 -alpn h2,http/1.1`, verifies matching SAN + ALPN `"h2"` negotiation and `VerifyError` on hostname mismatch. |
| Negative state-machine attacks | Verifies 1-byte TCP fragmented ClientHello reassembly, unexpected pre-handshake CCS (`unexpected_message` alert 10), post-handshake corrupted AEAD record MAC teardown, `DOWNGRD\x01` downgrade sentinel rejection, unmatched ALPN (alert 120), duplicate extensions, and TLS 1.2-only ClientHello rejection (alert 70). |
