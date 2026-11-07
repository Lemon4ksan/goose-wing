# Security policy

## Supported versions

`goose-wing` is in alpha (`0.x`). Security fixes are applied only to the `main`
branch and the latest tagged release in `version.txt`.

## Reporting a vulnerability

Do not open public GitHub issues or pull requests for suspected vulnerabilities.
Report security bugs through [GitHub Private Vulnerability
Reporting](https://github.com/Lemon4ksan/goose-wing/security/advisories/new).

Include the following details in your report:

- Affected subsystem and source file path (for example, `http2/framing.goose` or
  `tls/x509.goose`).
- A reproduction test case written in Goose or raw wire bytes (hex or PCAP) that
  triggers the bug.
- The impact class: out-of-bounds read or write in C shims, unbounded loop or
  CPU exhaustion, request smuggling, TLS validation bypass, or SSRF filter
  bypass.

Reports receive an initial triage response within 7 days. Once a fix is verified
on `main`, an advisory is published upon release.

## Scope

The security boundary covers untrusted network wire input and peer behavior
across these areas:

- Memory safety and bounds checking in C shims (`shim/simd.c`, `shim/tcp.c`,
  `shim/rio.c`, `shim/uring.c`, `shim/kqueue.c`, `shim/af_xdp.c`,
  `shim/smartnic.c`).
- HTTP/1.1 framing, chunked transfer coding, and `Content-Length` /
  `Transfer-Encoding` smuggling defenses in `http/headers/`.
- HTTP/2 frame decoding, HPACK decompression, flow control arithmetic, and
  CONTINUATION or RST_STREAM flood limits in `http2/framing.goose`,
  `http2/connection.goose`, and `http2/`.
- HTTP/3 framing, QPACK decoding, and QUIC packet parsing in `http3/` and
  `quic/`.
- TLS 1.3 record framing, X.509 certificate chain validation, HPKE, ECH, and
  ML-KEM-768 key exchange in `tls/`.
- SSRF IPv4/IPv6 private range blocks and DNS rebinding checks in
  `client/session/ssrf.goose`.
- Cookie domain matching, Public Suffix List checks, and `__Host-` / `__Secure-`
  prefix enforcement in `cookie/` and `security/crypto_jar.goose`.
- JWT signature verification, JWKS key rotation, DPoP proofs, and HTTP Message
  Signatures in `auth/`.

## Out of scope

- Denial of service requiring local root or administrator privileges on the host
  machine.
- Exhaustion of fixed compile-time buffer capacities (`u8[..N]`) when the parser
  returns a bounded error status without panicking or corrupting memory.
- Vulnerabilities in third-party dependencies unless reachable through
  `goose-wing` APIs.
