# goose-wing

Zero-allocation HTTP/1.1, HTTP/2, HTTP/3, and TLS 1.3 protocol engine and web
framework for [Goose](https://github.com/aardappel/goose).

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
comparisons. Before reading `HeaderMap`, a 256-bit `HeaderBloomFilter` hashes
four case-folded feature bytes from the header name by multiplier `1843993368`
across four `u64` registers to reject missing headers in 1 to 3 CPU cycles.

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

Import `wing` as a single package (it exposes `core::*` and all protocol
namespaces; submodules can import `wing.core` or `wing.http.multipart`):

```goose
import wing from "github.com/Lemon4ksan/goose-wing@v0.1.0";
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

Measured on an Intel Core i5-12400F with 12 hardware threads in an Ubuntu 24.04
container using Linux `epoll` and `gcc -O3 -flto`:

| Workload / Benchmark Suite | goose-wing (Goose) | uWebSockets (C++) | Delta |
| :--- | :---: | :---: | :---: |
| 1 Worker: Standard Ping-Pong (`wrk`, 64 conns) | 165,874 req/s (25.15 MB/s) | 148,306 req/s (21.64 MB/s) | +11.8% (p50: 358 µs vs 407 µs, -12.0%) |
| 1 Worker: 32x Pipelined (`wrk`, 64 conns) | 177,853 req/s (26.98 MB/s) | 140,557 req/s (20.51 MB/s) | +26.5% (p99: 756 µs vs 930 µs, -18.7%) |
| Multi-Core Peak 1M Target (6 workers, `wrk` 128x, 512 conns) | 954,939 req/s (122.94 MB/s) | 785,073 req/s (114.55 MB/s) | +21.6% (p99: 2,090 µs vs 3,980 µs, -47.5%) |
| 6 Workers: Unbounded C Burst (`bench_burst`, 384 conns) | 25,016,380 req/s (3,793.34 MB/s) | 7,922,812 req/s (1,156.03 MB/s) | +215.8% / 3.16x (+228.1% transfer) |
| 6 Workers: Unbounded C Burst (`bench_burst`, 512 conns) | 24,039,728 req/s (3,645.25 MB/s) | 7,631,240 req/s (1,113.49 MB/s) | +215.0% / 3.15x (+227.4% transfer) |
| 8 Workers: High-Concurrency (`wrk`, 256 conns, 64x) | 420,205 req/s (63.72 MB/s) | 404,932 req/s (59.08 MB/s) | +3.8% (+7.9% transfer, p99: 651 µs) |
| Heap allocations per request | 0 B (0 allocs) | 0 B (0 allocs) | Parity |
| Process RSS footprint | 3.1 MB | 18.2 MB | 5.9x lower |

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

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for
details.
