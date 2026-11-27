# goose-wing

Zero-allocation HTTP/1.1, HTTP/2, HTTP/3, and TLS 1.3 protocol engine and web
framework for the [Goose programming
language](https://github.com/aardappel/goose).

## Architecture

`goose-wing` pairs session and server APIs with a fixed-capacity wire stack.
Every protocol parser, header container, and connection table lives inline in
compile-time bounded `u8[..N]` buffers on the stack or in static arenas, doing
zero heap allocations on packet paths and event loops.

The reactor tracks 1,024 concurrent connections in a Structure-of-Arrays table,
`SoAConnTable`, which separates 1-byte timeout ticks and 8-byte file descriptors
from the 8 KB per-connection leftover buffers. During the 1-second Slowloris
sweep, the reactor scans all 1,024 connection deadlines across 1 KB of L1D cache
without touching payload memory. Outbound frames assemble inside bounded buffers
and flush in batches over `io_uring`, `epoll`, `kqueue`, or Windows RIO.

Protocol decoders read borrowed `const u8[:]` slices and write 9-byte
`HeaderSpan` offsets and 16-byte `HeaderEntry` records that index directly into
an 8 KB `HeaderMap` buffer. A 64-slot `inline_slots` index resolves standard
HTTP headers in $O(1)$ using 32-bit and 64-bit SWAR case-folded word
comparisons. Before scanning slots, a 256-bit `HeaderBloomFilter` hashes
case-folded header names with keyed SipHash-1-3 (per-process random 128-bit key,
fixed under DST) across four `u64` registers, rejecting missing headers in
constant time without hash-flood saturation.

Core parsers validate RFC framing rules once at the ingress boundary and contain
no compatibility workarounds for broken peers. The `wire` package splits
protocol framing and L7 middleware into two composable tiers:

- Tier 1 provides stateless slice-to-slice Sans-IO codecs for HTTP/1.1, HPACK,
  HTTP/2, and QPACK/HTTP/3, together with in-place 9-byte HTTP/2 frame header
  backpatching.
- Tier 2 drives client and server L7 execution through `WirePipeline`, selecting
  active stages via 64-bit `ingress_mask` and `egress_mask` bitsets and
  compile-time `StageChain` hooks returning `StageVerdict`.

Applications talking to non-compliant endpoints can normalize raw wire slices
before Tier 1 decoding or toggle and replace Tier 2 stages in `WirePipeline`
without modifying the core decoders.

## Subsystems

| Subsystem | Implementation scope |
| :--- | :--- |
| L4 transport and OS drivers | Non-blocking reactor over Windows Registered I/O, Linux `io_uring` SQ/CQ rings and fixed buffers, Linux `epoll` with `SO_REUSEPORT`, macOS `kqueue`, and POSIX/WinSock sockets. |
| HTTP/1.1 wire stack | `HeaderMap` with 64 static and dynamic slots, 64-bit SWAR lexical tokenizer, RFC 9112 chunked transfer coding and trailer FSM, TE.CL and CL.TE desync rejection for CVE-2023-39326. |
| HTTP caching | RFC 9111 cache engine, RFC 9875 `Cache-Groups` and `Cache-Group-Invalidation` header parser and group invalidation, RFC 5861 `stale-while-revalidate` and `stale-if-error`. |
| HTTP/2 protocol stack | RFC 9113 9-byte frame codec and `CONTINUATION` FSM, RFC 7541 HPACK codec with 256-state Huffman L1 table, signed 64-bit flow control, RFC 9218 stream prioritization, CVE-2023-44487 Rapid Reset defense. |
| HTTP/3 and QUIC codecs | RFC 9000 QUIC v1 and RFC 9369 QUIC v2 packet framing, salts, and ACK/loss trackers, RFC 9114 HTTP/3 frame codec, RFC 9204 QPACK encoder and blocked-stream decoder, BBR congestion control state machine. |
| TLS 1.3 and X.509 | RFC 8446 record framer and handshake state machine, X.509 ASN.1 DER validator, RFC 9849 Encrypted Client Hello extension and RFC 9180 HPKE key schedule, RFC 8879 Zstd certificate compression, RFC 8555 ACME HTTP-01 responder. |
| Realtime and RPC framing | RFC 6455 WebSocket frame codec and fragmentation FSM with 64-bit XOR masking, RFC 8441 Extended CONNECT over H2/H3, W3C Server-Sent Events line parser, length-prefixed gRPC and gRPC-Web codecs. |
| Compression codecs | RFC 7932 Brotli decoder and encoder with 122 KB static `.rodata` dictionary, RFC 9842 Dictionary-Compressed Brotli and Zstandard framing, RFC 8478 Zstandard, Deflate, Gzip, and Zlib. |
| L7 security and auth | W3C Fetch Metadata CSRF guard, CORS policy matcher, GCRA rate limiter, 3-tier SSRF IP and DNS guard, RFC 7519 JWT and RFC 7515 JWS with HS256..512 and EdDSA, RFC 7517 JWKS, RFC 9449 DPoP, RFC 7636 PKCE, RFC 7616 Digest, RFC 9421 HTTP Message Signatures. |
| OHTTP and Binary HTTP | RFC 9458 Oblivious HTTP request and response encapsulation over RFC 9180 HPKE, RFC 9292 Binary HTTP known-length and indeterminate-length message codec. |
| Cookie storage | RFC 6265bis cookie jar, CHIPS partitioned cookies, `__Host-` and `__Secure-` prefix enforcement, Mozilla Public Suffix List matcher, 6-round eviction, SQLite v24 schema persistence. |
| Proxies and routing | Insertion-order independent compressed Radix Trie with `ZeroAllocParams`, Tako v2 connection pool, RFC 1928/1929 SOCKS5 and SOCKS5h client handshake, HTTP CONNECT, HAProxy PROXY Protocol v1 and v2 TLV parser, RFC 9440 `Client-Cert` header sanitizer. |

## Quick start

Import `wing` as a single package for the full stack, `core` for base
primitives, or `wing_h1` for the modular zero-copy HTTP/1.1 pipeline without
`tls`, `http2`, `http3`, `quic`, `grpc`, or `realtime` (see
[h1/README.md](h1/README.md)):

```goose
import wing from "github.com/Lemon4ksan/goose-wing@v0.1.0";
import wing_h1 from "github.com/Lemon4ksan/goose-wing@v0.1.0";
```

### 1. HTTP client session

```goose
import std;
import wing;

fn main() {
    var sess = client::new_session("https://api.example.com") { s =>
        s.set_profile(fingerprint::Profile.Wing);
        s.set_timeout_ms(5000);
        s.default_header("Accept", "application/json");
        // Safer in production today: use audited OpenSSL instead of unaudited PureGoose TLS
        // s.set_tls_backend(tls::TlsBackendKind.SystemOpenSsl);
    };

    let res, err = sess.get("/v1/status");
    guard err.ok() && res.is_success() else {
        print("Request failed: ", err.message[..]);
        return;
    }

    print("Status: ", res.status_code);
    print("Body: ", res.body[..]);
}
```

### 2. Non-blocking HTTP reactor server

```goose
import std;
import wing;

fn main() {
    let listener = net::tcp_listen("127.0.0.1", 8080, 128);
    guard listener > 0 else { return; }
    defer net::tcp_close(listener);

    var srv = server::new_http_server("127.0.0.1", 8080);
    srv.add_static_get_route("/health", "application/json", "{\"ok\":true}", 1);
    srv.add_get_route("/api/v1/users/{id}", 2);

    srv.serve_reactor(listener);
}
```

### 3. WebSocket frame encoding

```goose
import wing;

fn main() {
    var hdr = realtime::WsFrameHeader {
        fin: true,
        opcode: realtime::WS_OPCODE_TEXT,
        masked: true,
        mask_key: [0x12, 0x34, 0x56, 0x78],
        payload_len: 5,
    };

    var frame: u8[..64] = [];
    hdr.encode(frame);

    var payload: u8[..32] = [];
    payload.append("Hello");
    realtime::mask_websocket_payload(payload[..], hdr.mask_key);
    frame.append(payload[..]);
}
```

### 4. Pluggable TLS backend (pure-Goose vs. optional OpenSSL / Schannel shim)

By default `goose-wing` uses its self-contained pure-Goose TLS 1.3 engine
(`tls::TlsBackendKind.PureGoose`), which has zero external dependencies and
stays bit-for-bit deterministic under single-seed DST simulation
(`net/dst.goose`). `PureGoose` implements **TLS 1.3 only** (RFC 8446) and does
not support TLS 1.2.

> **Security note**: `PureGoose` has not undergone an independent third-party
> cryptographic audit yet. For production internet-facing services, switching to
> `tls::TlsBackendKind.SystemOpenSsl` (OpenSSL 3 / BoringSSL) is the safer
> option for now.

By default (`min_version = tls::TlsMinVersion.Tls13`), all backends stop
strictly at TLS 1.3 and never fall back to TLS 1.2. Falling back to TLS 1.2
happens only when explicitly opted in via `min_version =
tls::TlsMinVersion.Tls12` on one of the system C-shim backends below.

**OS root certificates (`tls_use_system_roots` / `use_system_roots`)**: Loading
system root CAs (Linux `/etc/ssl`, macOS Keychain, Windows `ROOT` store via
`crypt32.dll`) is **on by default (`true`)** only when neither a custom
`tls_ca_file` nor an in-memory `trust_store` is set. Providing a custom CA
bundle or trust store never inherits OS roots. For air-gapped environments,
deterministic DST runs, or zero-ambient-trust deployments, disable OS root
loading with `tls_use_system_roots: false` (or
`s.set_tls_use_system_roots(false)` /
`TlsBackendConfig.use_system_roots = false`), which fails closed with
`VerifyError` unless explicit roots are configured.

Switch `client::Session`, `server::HttpServer`, or sans-IO `tls::TlsEndpoint` to
an audited system TLS library through the optional C shim
[`shim/tls_backend.c`](shim/tls_backend.c) without changing protocol or
application code:

- `tls::TlsBackendKind.SystemOpenSsl`: OpenSSL 3 / 1.1.1 / BoringSSL via sans-IO
  memory BIOs (strict TLS 1.3 by default; allows TLS 1.2 fallback only when
  `min_version = TlsMinVersion.Tls12`, `SSL_VERIFY_PEER` + `SSL_set1_host`
  hostname verification, custom `ca_file`, server `cert_pem_file` /
  `key_pem_file`, client and server ALPN). Loaded dynamically at runtime via
  `dlopen` / `LoadLibraryA` with zero link-time OpenSSL dependency. Set
  `WING_OPENSSL_LIB` / `WING_CRYPTO_LIB` to load a vendored library path, or
  compile with `-DWING_TLS_LINK_OPENSSL` and link `-lssl -lcrypto` for direct
  linking.
- `tls::TlsBackendKind.SystemSchannel`: Windows native `secur32.dll` Schannel
  client context with zero third-party DLLs (TLS 1.3-only via `SCH_CREDENTIALS`
  v5 by default; TLS 1.2 + TLS 1.3 fallback only when `min_version =
  TlsMinVersion.Tls12`).
- `tls::TlsBackendKind.SystemSecureTransport`: macOS native `Security.framework`
  client context (`dlopen`, zero link flags). Opt-in only: excluded from `Auto`
  and `SystemOnly` modes, and accepted only when `min_version =
  TlsMinVersion.Tls12` is set (rejected on default `TlsMinVersion.Tls13`).
- `tls::TlsBackendKind.Auto`: selects `SystemOpenSsl` if installed (Linux
  `libssl.so.3`, macOS Homebrew/MacPorts `libssl.3.dylib`, Windows
  `libssl-3*.dll`), then `SystemSchannel` on Windows client endpoints, and falls
  back to `PureGoose` (TLS 1.3 only) otherwise.

```goose
import wing;

fn main() {
    // 1. Client session backed by OpenSSL
    var sess = client::new_client(client::Config {
        base_url:             "https://api.example.com",
        tls_backend:          tls::TlsBackendKind.SystemOpenSsl,
        // tls_min_version:      tls::TlsMinVersion.Tls12, // uncomment to allow TLS 1.2 fallback
        // tls_ca_file:          "/etc/ssl/certs/ca-certificates.crt",
        // tls_use_system_roots: false, // disable OS root store (fails closed without tls_ca_file)
        ..
    });
    let _, _ = sess.get("/v1/status");

    // 2. Server backed by OpenSSL with PEM certificate and private key
    var srv = server::new_http_server("0.0.0.0", 8443);
    let _ = srv.configure_server_tls_backend(
        tls::TlsBackendKind.SystemOpenSsl,
        tls::TlsMinVersion.Tls13,
        "cert.pem",
        "key.pem",
    );
}
```

For direct sans-IO usage without sockets, open `tls::TlsEndpoint` via
`tls::tls_endpoint_open` with `kind: tls::TlsBackendKind.SystemOpenSsl` (see
[tls/README.md](tls/README.md)). See also [net/README.md](net/README.md) for
single-seed Deterministic Simulation Testing (`DstWorld`),
[wire/README.md](wire/README.md) for compile-time ingress RAM budgets
(`wire/budget.goose`), and [server/README.md](server/README.md) for unified
H1/H2/H3 streaming with flow-control backpressure (`ResponseStream`).

## Build and test

Typecheck the core libraries, examples, and test suites, then run the native LIT
verification suites:

```bash
python tools/test_runner.py --check-only
goose-lit tests
```

For full-stack binaries combining `server::HttpServer`, `client::Session`, and
TLS on memory-constrained Windows hosts, pass `--cc clang`, `-O1`, or
`--debug -O0` to keep C compiler peak memory low.

With [`just`](https://github.com/casey/just) installed:

```bash
just check
just lit
just shims
```

Run the standalone `wing` CLI directly from source:

```bash
goose run cli/main.goose -- https://example.com
goose run cli/main.goose -- serve --port 8080
```

Synchronize upstream reference corpora and Wycheproof vectors in `vendor/`, then
run coverage-guided fuzzing, differential reference comparison, constant-time
machine-code and Dudect verification, BoGo and x509-limbo conformance vectors,
and live TCP reactor soak tests:

```bash
python scripts/vendor_fuzz.py --sync
python scripts/sancov_runner.py --execs 5000
python scripts/diff_fuzz.py --rounds 100
python scripts/verify_ct_asm.py
goose-lit tests/lit/verify_bogo_x509_limbo.goose
python scripts/soak_test.py
```

## Benchmarks

### Benchmarks vs. uWebSockets

Measured on an Intel Core i5-12400F (6 P-cores / 12 threads) in an Ubuntu 24.04
container using Linux `io_uring`/`epoll` and `gcc -O3 -flto` (0 errors and 0
timeouts across all suites):

| Workload / Benchmark Suite | goose-wing (Goose) | uWebSockets (C++) | Delta |
| :--- | :---: | :---: | :---: |
| 1 Worker: Ping-Pong (`wrk`, 64 conns) | 178,859 req/s (27.12 MB/s) | 134,802 req/s (19.67 MB/s) | +32.7% (p50: 334 µs vs 445 µs, -24.9%) |
| 1 Worker: 32x Pipelined (`wrk`, 64 conns) | 176,433 req/s (26.75 MB/s) | 125,263 req/s (18.28 MB/s) | +40.8% (p99: 723 µs vs 1,100 µs, -34.3%) |
| 3 Workers: Ping-Pong (`wrk`, 96 conns) | 515,458 req/s (78.16 MB/s) | 494,432 req/s (72.14 MB/s) | +4.3% (p50: 102 µs vs 115 µs, -11.3%) |
| 3 Workers: 32x Pipelined (`wrk`, 96 conns) | 535,148 req/s (81.15 MB/s) | 508,459 req/s (74.19 MB/s) | +5.2% (p99.9: 385 µs vs 466 µs, -17.4%) |
| 4 Workers: Ping-Pong (`wrk`, 128 conns) | 679,778 req/s (103.08 MB/s) | 659,075 req/s (96.17 MB/s) | +3.1% (p99.9: 680 µs vs 853 µs, -20.3%) |
| 4 Workers: 32x Pipelined (`wrk`, 128 conns) | 625,234 req/s (94.81 MB/s) | 584,258 req/s (85.25 MB/s) | +7.0% (p50: 109 µs vs 127 µs, -14.2%) |
| 4 Workers: Keep-Alive 10k conns (`wrk`) | 385,007 req/s (58.38 MB/s) | 376,188 req/s (54.89 MB/s) | +2.3% (p99.9: 21.5 ms vs 25.8 ms, -16.6%) |
| 4 Workers: Dynamic Route + 2KB JSON (`wrk`, 128 conns) | 460,460 req/s (972.80 MB/s) | 301,484 req/s (635.42 MB/s) | +52.7% (p95: 1,342 µs vs 6,041 µs, -77.8%) |
| 4 Workers: HTTP/2 h2c (`h2load`, 64c x 16) | 161,184 req/s (6.00 MB/s) | N/A | Full native RFC 9113 |
| 4 Workers: TLS 1.3 HTTP/2 (`h2load`, 64c x 16) | 183,978 req/s (6.85 MB/s) | N/A | Full native TLS 1.3 + HTTP/2 |
| 6 Workers: 128x Pipelined (`wrk`, 512 conns) | 830,063 req/s (125.87 MB/s) | 763,720 req/s (111.44 MB/s) | +8.7% (p50: 334 µs vs 376 µs, -11.2%) |
| 6 Workers: C Burst (`bench_burst`, 512 conns, 64x) | 9,766,267 req/s (1,480.90 MB/s) | 7,944,337 req/s (1,159.18 MB/s) | +22.9% (+27.8% transfer) |
| Heap allocations per request | 0 B (0 allocs) | 0 B (0 allocs) | Parity |

### L0 and L7 pipeline CPU clock cycles

Serialized `rdtscp` cycle count, throughput, and three-channel Goose data-stack
watermarks from `bench/server_profiling_benchmark.goose` across HTTP/1.1 framing
and L7 security and caching stages:

| Benchmark scenario | Latency (`ns/op`) | Cycles (`cyc/op`) | Throughput (`MB/s`) | Net / Scratch (`B/op`) | `allocs/op` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `L0_Plaintext_GET` | 159.1 ns | 397.1 cyc | 729.1 MB/s | 0 B / 0 B | 0 |
| `HTTP1_Pipelined_16x` (16 reqs/op) | 283.0 ns (17.7 ns/req) | 706.3 cyc (44.1 cyc/req) | 6,559.2 MB/s | 0 B / 0 B | 0 |
| `Full_Pipeline_Auth_Cache_Hit` (15 stages) | 1,139.9 ns | 2,845.1 cyc | 114.9 MB/s | 0 B / 0 B | 0 |
| `Full_Pipeline_Auth_Cache_Miss` (17 stages) | 1,167.7 ns | 2,914.5 cyc | 112.2 MB/s | 0 B / 0 B | 0 |
| `Full_Pipeline_Gzip_Compress` (15 stages) | 1,159.4 ns | 2,893.8 cyc | 103.5 MB/s | 0 B / 0 B | 0 |

## Documentation

- [Architecture](docs/architecture.md): Memory model, ingress boundaries, module
  layout, and request/response data flow.
- [Modular HTTP/1.1 pipeline](h1/README.md): Minimal `wing_h1` entrypoint for
  zero-copy `Tcp -> Http1 -> Router` services and clients.
- [Features and nuances](docs/features_and_nuances.md): Buffer budgets,
  algorithm complexities, fail-closed thresholds, and edge cases.
- [Security defenses](docs/security_defenses.md): CVE defenses, protocol attack
  mitigations, constant-time arithmetic, and zero-heap invariants.
- [Caller reference](docs/caller_reference.md): Container capacities, time
  arithmetic, and concurrency primitives.
- [RFC conformance](docs/rfc_conformance.md): IETF RFC compliance matrix and
  test vectors.
- [External conformance](docs/conformance_matrix.md): Reproducible `h2spec`,
  Autobahn, Wycheproof, BoGo/x509-limbo, QPACK, and TLS 1.3 oracle metrics.
- [Benchmarks](docs/benchmarks.md): Hardware cycle breakdowns and load-testing
  methods.
- [Soak test report](docs/soak_test_report.md): RSS stability and latency under
  TCP resets, fragmentation, smuggling, and Slowloris faults.
- [Contributing](CONTRIBUTING.md) and [Security policy](SECURITY.md):
  Development workflow, coding standards, and vulnerability disclosure.

## License

`goose-wing` uses the Apache License, Version 2.0. See [LICENSE](LICENSE) for
details.

Copyright (c) 2026 Lemon4ksan (Komolov Arsenii).
