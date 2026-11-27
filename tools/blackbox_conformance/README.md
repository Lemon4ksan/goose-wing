# Black-box conformance and negative testing suite

Zero-dependency Go black-box test runner exercising `goose-wing` TLS 1.3,
X.509/ASN.1, ML-KEM-768, AEAD, Ed25519/ECDSA/RSA, HTTP/1.1 smuggling
differentials, HTTP/2, WebSocket, gRPC, and QUIC/HTTP/3 over loopback sockets
and stdin/stdout vector harnesses.

## Prerequisites

- Go 1.24 or newer.
- Built harnesses in `tools/bin/` (`tls_server`, `bogo_shim`, `tls_client`,
  `x509_harness`, `smuggling_wing`, `smuggling_wing_h1`, `h2spec_server`,
  `http3_server`, `chaos_server`, `autobahn_server`, `grpc_server`) and
  `.lit/cache/crypto_vectors/harness` (built automatically by
  `python tools/crypto_vectors.py`).

## Usage

Run from `tools/blackbox_conformance/`:

```bash
# Round 1: full TLS 1.3 server/client, HTTP/1.1, HTTP/2, HTTP/3, smuggling,
# X.509, and crypto edge suite (538 checks)
go run .

# Round 2: 2025-2026 CVE matrix (ML-KEM-768 1088B mutations, AEAD >2048B
# differential, Ed25519/ECDSA/RSA e=3, X.509 2026 CVEs, TLS 1.3 wire CVEs)
go run . --round2

# Internet & Legacy R1: non-duplicate semi-valid internet/legacy wire probes
# across serve_reactor, H1/H2C listener, TLS GREASE/middleboxes, WebSocket,
# gRPC/gRPC-Web, and UDP/HTTP/3 background noise
go run . --legacy

# Internet & Legacy R2: stateful FSM/lifecycle, buffer capacity cliffs, hidden
# UDP dispatch map, decompression bombs, and cross-engine differentials
go run . --legacy-r2

# Run Round 1, Round 2, and Internet/Legacy R1+R2 suites sequentially
go run . --all

# Deep diagnostic wire probes
go run . --probe

# Optional flags
go run . --repo-root /path/to/goose-wing --log-dir /tmp/wing-bb-logs --legacy-r2
```

Temporary PKI certificates and TSV vector files are created inside an isolated
`os.MkdirTemp` directory and removed on exit. Pass `--log-dir` to persist
`results.log`, `round2_results.log`, `legacy_results.log`, and
`legacy_r2_results.log`.
