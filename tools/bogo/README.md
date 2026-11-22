# goose-wing BoGo TLS protocol test suite

BoringSSL BoGo protocol shim ([shim.goose](shim.goose)) and local TLS 1.3
conformance runner implementing the BoGo `shim-id` header and XOR-`0xFF` echo
loop for `PureGoose` and `SystemOpenSsl`.

## Quick start

### Local BoGo-style TLS 1.3 conformance suite

```bash
python tools/bogo.py --local
```

### Upstream BoringSSL BoGo runner in Docker

```bash
python tools/bogo.py --docker
```

## Supported shim flags

| Flag | Behavior |
| :--- | :--- |
| `-port <u16>` | TCP port on `127.0.0.1` (or `::1` with `-ipv6`). |
| `-is-server` | Run the shim as the TLS server endpoint. |
| `-shim-id <u64>` | 64-bit test identifier sent in 8-byte little-endian order. |
| `-host-name <name>` | SNI and peer hostname expectation for client handshakes. |
| `-min-version <ver>` | Minimum TLS version (decimal or `0x` hex); TLS <= 1.2 exits `89` on `PureGoose`. |
| `-max-version <ver>` | Maximum TLS version (decimal or `0x` hex); TLS <= 1.2 exits `89` on `PureGoose`. |
| `-cert-file <path>` | PEM certificate file for server identity or client mTLS. |
| `-key-file <path>` | PEM private key file matching `-cert-file`. |
| `-trust-cert <path>` | PEM CA certificate bundle used to verify the peer. |
| `-alpn-protos <val>` | Offered ALPN list in RFC 7301 wire format or ASCII CSV. |
| `-verify-peer` | Enable peer certificate verification (mTLS on OpenSSL server). |
| `-expect-alpn <name>` | Assert the negotiated ALPN protocol name. |
| `-fallback-scsv` | Rejected with exit `89` (`UNIMPLEMENTED`). |
| `-ipv6` | Connect to IPv6 loopback (`::1`) instead of `127.0.0.1`. |
| `-backend <kind>` | Select `pure` (`PureGoose`, default) or `openssl` (`SystemOpenSsl`). |
| `-key-update` | Send an RFC 8446 Section 4.6.3 `KeyUpdate` after handshake. |

## Verified local matrix

The `--local` runner verifies 20+ BoGo-style cases across `PureGoose` and
`SystemOpenSsl`:

- BoGo 8-byte little-endian `shim-id` framing and XOR-`0xFF` echo over IPv4 and
  IPv6 (`[::1]`).
- `PureGoose` client and server against OpenSSL peers and self-peer relays.
- ALPN negotiation (`h2`, `http/1.1`) and mismatch rejection (`-expect-alpn`).
- Untrusted certificate and wrong-hostname rejection (`-verify-peer`).
- Client mTLS on `PureGoose` and server mTLS on `SystemOpenSsl`.
- Bidirectional RFC 8446 Section 4.6.3 `KeyUpdate` key ratcheting.
- TLS 1.2 rejection, RFC 8446 Section 4.1.3 `DOWNGRD\x01` and `DOWNGRD\x00`
  downgrade sentinels, and exit code `89` for unsupported legacy flags.
- Unexpected pre-handshake CCS, unencrypted `Finished`, corrupted post-handshake
  AEAD record MAC, and fatal TLS alert handling.
