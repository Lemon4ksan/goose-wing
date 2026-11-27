# Contributing to goose-wing

This document covers architectural invariants, repository layout, and testing
workflows for `goose-wing`.

## Architectural invariants

`goose-wing` is a zero-allocation systems networking engine written in
[Goose](https://github.com/aardappel/goose). Contributions must follow four
rules:

1. Do not use dynamic heap allocations (`[>..]`) on request, response, framing,
   or wire serialization paths. Use stack-allocated bounded arrays (`u8[..N]`,
   `HeaderItem[..32]`, `QueryItem[..16]`) with compile-time capacities, and
   parse wire input from borrowed byte slices (`const u8[:]`).
2. Keep the client identity as `Profile.Wing`. Do not add browser persona mocks
   (`Chrome`, `Firefox`, `Safari`) or fake browser TLS fingerprints.
3. Return error status enums or `(result, bool)` tuples on invalid wire bytes.
   Never panic on untrusted network input. Parsers must reject HTTP request
   smuggling (RFC 9112 §6.1, §7.1), CRLF injection, and SSRF (RFC 6797, RFC
   6265bis).
4. Write mutating APIs as free functions that take the target struct by
   reference as the first parameter
   (`fn set_header(req: Request&, name: const u8[:], val: const u8[:])`) so
   callers can chain methods with Uniform Function Call Syntax (UFCS).

## Prerequisites

- Goose compiler `v2026.4+` on `PATH`.
- GCC 14+ (MinGW-w64 on Windows, native GCC on Linux) or Clang 18+.
- Python 3.10+ for `tools/test_runner.py`, `tools/licensing.py`, and E2E
  harnesses.
- `just` (optional) for running recipes from [`Justfile`](Justfile).

## Repository layout

```text
goose-wing/
├── auth/             # Digest, PKCE, DPoP, JWT, and JWKS
├── cli/              # Standalone wing curl/serve CLI
├── client/           # Client sessions, redirects, SSRF guard, interceptors, and streaming
├── cookie/           # RFC 6265bis CookieMonster engine, PSL matcher, and eviction store
├── core/             # Byte search, math, monotonic time, compression, crypto (ECDSA, RSA, Ed25519), URL, IO, and UFCS
├── docs/             # Architecture, caller reference, and security documentation
├── examples/         # Standalone sample programs
├── fingerprint/      # JA4 TLS, p0f TCP, and Akamai HTTP/2 fingerprinting
├── grpc/             # gRPC and gRPC-Web framing, client, and server dispatcher
├── http/             # HTTP/1.1 framing, SWAR header scanner, RFC 9111 cache, and extensions
├── http2/            # RFC 9113 frame codec, HPACK Huffman FSM, and connection state
├── http3/            # RFC 9114 frame codec, QPACK, and H3 connection state
├── net/              # TCP, UDP, Happy Eyeballs v2, SOCKS5, PROXY protocol, DNS, and poller
├── proxy/            # Reverse proxy, upstream cluster health checking, and load balancing
├── quic/             # RFC 9000 packet codec, ACK frames, and BBR v1/v2 congestion control
├── realtime/         # RFC 6455 WebSocket, TopicTree pub/sub, SSE, and WebTransport
├── rfc/              # Standardized IETF RFC wire constants namespace
├── scripts/          # Invariant linter, G-CRAP ratchet, and LIT test runners
├── security/         # CryptoJar, Fetch Metadata CSRF, CORS, GCRA rate limiter, and Privacy Pass
├── server/           # Radix router, Tako v2 pool, HTTP/1.1 pipeline, and H2 multiplexer
├── shim/             # C11 shims for Windows RIO, Linux io_uring, kqueue, AF_XDP, and SIMD
├── tests/            # Protocol verification test suites
├── tls/              # TLS 1.3 record and handshake, X.509, HPKE, ECH, and ML-KEM-768
├── tools/            # Python parallel test runner, SPDX check, and Docker protocol harnesses
└── wire/             # Sans-IO wire framing codecs and composable L7 pipeline stages
```

## Development and testing workflow

### 1. Parallel typechecking

Verify that `core.goose`, `wing.goose`, examples, and all test suites pass
typechecking without compiling native binaries:

```bash
python tools/test_runner.py --check-only
```

Or using `just`:

```bash
just check
```

### 2. Running specific test suites

Compile and execute a single test file or glob pattern:

```bash
python tools/test_runner.py --pattern "*grpc*"
python tools/test_runner.py --pattern "http1_test.goose"
```

### 3. End-to-end protocol harnesses

Run the Docker-based integration suites when modifying protocol state machines:

```bash
python tools/grpc.py --docker
python tools/tls.py --docker
python tools/http3.py --docker
python tools/toxiproxy.py --docker
```

### 4. Formatting and license headers

Format all `.goose` files and verify Apache-2.0 SPDX headers before committing:

```bash
goose format .
goose format --check .
python tools/licensing.py --check
```

If new files are missing SPDX headers, run `python tools/licensing.py --fix`.

## Coding standards

### Bounded arrays

Define explicit compile-time capacity bounds for collections:

```goose
// Stack-allocated bounded arrays
var headers: HeaderItem[..32] = [];
var buffer: u8[..4096] = [];

// Do not use dynamic heap arrays on wire paths
var dynamic_list: u8[>..] = [];
```

### C shims and extern declarations

C11 shims reside in `shim/`. Any change to a C file must compile with zero
warnings under `-Wall -Wextra -Werror` on both GCC and Clang.

Declare extern symbols in Goose using the postfix symbol syntax (Goose §7.10):

```goose
extern fn native_fast_find_crlfcrlf(s: const u8[:]) -> i64 = "wing_fast_find_crlfcrlf";
```

Register new C source files across Windows, Linux, and macOS in
[`wing.build`](wing.build).

## Pull request checklist

- [ ] All test suites pass `python tools/test_runner.py --check-only`.
- [ ] All changed `.goose` files are formatted with `goose format`.
- [ ] No heap allocations (`[>..]`) are introduced on wire parsing or
  serialization paths.
- [ ] C shims compile without warnings under `-Wall -Wextra -Werror`.
- [ ] License header check passes (`python tools/licensing.py --check`).
- [ ] Commit messages follow Conventional Commits (`feat:`, `fix:`, `refactor:`,
  `perf:`, `style:`, `test:`, `chore:`).
