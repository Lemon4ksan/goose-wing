# goose-wing

Vulkan-style, zero-allocation web framework and HTTP/1.1, HTTP/2, HTTP/3
protocol stack for Goose.

[![Goose
Language](https://img.shields.io/badge/lang-goose-blue.svg?style=flat-square)](https://github.com/Lemon4ksan/goose)
[![License](https://img.shields.io/badge/license-Apache%202.0-lightgrey.svg?style=flat-square)](LICENSE)

## Design and scope

High-throughput networking hits the same hardware bottlenecks that graphics APIs
hit a decade ago: memory bandwidth, L1/L2 cache misses, per-call heap
allocations, and OS context switches. `wing` applies the explicit resource model
of Vulkan and DPDK to the HTTP/1.1, HTTP/2, and HTTP/3 protocol stack:

- Caller-owned memory and descriptor pools: Functions take caller-allocated
  slices and fixed-capacity buffers (`u8[..N]`). Connection states and ring
  buffers (`SoAConnTable`, `PageRingBuffer`) are pre-allocated upfront. The
  engine does 0 heap allocations on packet paths and event loops.
- Buffer views instead of string copies: Protocol parsers do not allocate
  strings or header objects. `HeaderSpan` stores a 9-byte offset-and-length view
  (`name_pos: u16, name_len: u16, val_pos: u16, val_len: u16, id: u8`) over the
  raw packet buffer, while `presence_mask: u32` and a 256-bit
  `HeaderBloomFilter` (four `u64` registers) reject missing headers in 1 to 3
  CPU cycles before reading memory.
- Command batching and explicit state machines: Outbound writes batch into
  `CorkBuffer` and OS ring queues (`io_uring`, Windows RIO) to amortize
  syscalls. Decoders use SIMD and 64-bit SWAR scanners and return explicit
  cursor offsets and error states rather than throwing exceptions.
- Strict RFC conformance and composable stages: Core parsers enforce RFC wire
  rules and reject non-compliant framing, ambiguous delimiters, and broken
  server quirks at the ingress boundary. Instead of adding compatibility
  workarounds to core decoders, `wing` exposes slice-driven (`const u8[:]`)
  Sans-IO codecs (`wire/`) and bitmask-configured L7 pipelines (`WirePipeline`,
  `StageVerdict`). Applications that need to talk to non-compliant endpoints can
  normalize wire buffers or replace individual pipeline stages without forking
  the project.

This makes `wing` suited for reverse proxies, gateways, and edge services where
predictable clock cycles and zero allocations are required (a complete HTTP/1.1
L0 request-response turn takes ~397 cycles, or ~44 cycles/req when pipelined on
x86_64).

It is not a high-level HTTP client like Python's `requests`. Sending a request
requires setting up buffers, arenas, and transport state. High-level application
APIs belong in separate libraries built on top of `wing`.

## Subsystems

| Subsystem | Standards and capabilities |
| :--- | :--- |
| L4 transport and OS drivers | Windows Registered I/O (RIO), Linux `io_uring` (SQ/CQ rings, fixed buffers), Linux `epoll` with `SO_REUSEPORT`, macOS `kqueue`, POSIX/WinSock, non-blocking reactor loops. |
| HTTP/1.1 wire stack | HeaderMap with 64 static/dynamic slots, 64-bit SWAR lexical tokenizer, RFC 9112 chunked transfer coding and trailers, TE.CL / CL.TE request smuggling defenses (CVE-2023-39326). |
| HTTP caching and Cache Groups | RFC 9111 HTTP caching engine, RFC 9875 HTTP Cache Groups tag parsing and group invalidation (`Cache-Groups`, `Cache-Group-Invalidation`), RFC 5861 stale-while-revalidate / stale-if-error. |
| HTTP/2 protocol stack | RFC 9113 9-byte frame codec, RFC 7541 HPACK 256-state Huffman L1 FSM, signed 64-bit flow control, RFC 9218 stream prioritization, Rapid Reset DoS defense (CVE-2023-44487). |
| HTTP/3 and QUIC engine | RFC 9000 QUIC packet wire codec, RFC 9369 QUIC Version 2 (`0x6b3343cf`) wire framing, salts, and header types, RFC 9204 QPACK encoder/decoder, BBR congestion control, RFC 9221 datagrams, RFC 7838 Alt-Svc racing, W3C WebTransport over H3. |
| TLS 1.3 and PKI | RFC 8446 record layer and key schedule, X.509 ASN.1 DER parser, RFC 9849 Encrypted Client Hello (ECH / HPKE RFC 9180), RFC 8555 ACME HTTP-01 key authorization and challenge responder, RFC 8879 Zstd certificate compression, Hybrid ML-KEM-768. |
| Streaming and RPC | RFC 6455 WebSocket with unrolled 64-bit XOR masking, RFC 8441 Extended CONNECT over H2/H3, W3C EventSource (SSE), gRPC over HTTP/2, and gRPC-Web (binary and base64 text). |
| Compression suite | RFC 7932 Brotli with 122 KB static dictionary in `.rodata`, RFC 9842 Dictionary-Compressed Brotli (DCB) and DCZ, RFC 8478 Zstandard, Deflate, Gzip, and Zlib. |
| Application security | W3C Fetch Metadata decision matrix ($\pi_{FM}$ CSRF protection), CORS origin matcher, GCRA rate limiter with TAT, 3-tier SSRF and DNS rebinding guard, Privacy Pass tokens. |
| Oblivious HTTP and Binary HTTP | RFC 9458 Oblivious HTTP (OHTTP) request/response encapsulation over HPKE (RFC 9180), RFC 9292 Binary Representation of HTTP Messages (bhttp) zero-allocation codec. |
| Authentication and tokens | RFC 7519 JWT / RFC 7515 JWS (HS256..512, EdDSA), RFC 7517 JWKS with rotation, RFC 9449 OAuth 2.0 DPoP, RFC 7636/9700 PKCE, RFC 7616 Digest, RFC 9421 HTTP Message Signatures. |
| Chromium CookieMonster | RFC 6265bis engine, CHIPS (partitioned cookies), prefixes (`__Host-`, `__Secure-`), Mozilla Public Suffix List (PSL), 6-round garbage collection, SQLite v24 persistence. |
| Tunneling and proxies | RFC 9440 Client-Cert and Client-Cert-Chain header codec and reverse proxy sanitization, SOCKS5 / SOCKS5h (RFC 1928/1929 ATYP=0x03 DNS leak prevention), HTTP CONNECT tunneling, HAProxy PROXY Protocol v1 and v2 (TLV parsing), Slowloris tarpit defenses. |
| Server engine and router | Compressed Radix Trie (`ZeroAllocParams`, insertion-order independence), Tako v2 connection pool, HTTP/2 server frame multiplexer, gRPC server dispatcher. |

## Quick start

### 1. HTTP client session

```goose
import std;
import core;
import wing;

fn main() {
    var sess = wing::new_session("https://api.example.com") { s =>
        s.set_profile(wing::Profile.Wing);
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

### 2. Radix router and HTTP server

```goose
import std;
import core;
import wing;

fn main() {
    var server = wing::new_http_server("127.0.0.1", 8080);

    // Register routes with zero-allocation parameters
    server.add_get_route("/api/v1/users/{id}", 1);
    server.add_post_route("/api/v1/orders", 2);

    print("Wing Server listening on http://127.0.0.1:8080 (HTTP/1.1 & HTTP/2)...");
}
```

### 3. WebSocket frame encoding

```goose
import core;
import wing;

fn main() {
    var hdr = wing::WsFrameHeader {
        fin: true,
        opcode: wing::WS_OPCODE_TEXT,
        masked: true,
        mask_key: [0x12, 0x34, 0x56, 0x78],
        payload_len: 5,
    };

    var frame: u8[..64] = [];
    hdr.encode(frame);

    var payload: u8[..32] = [];
    payload.append("Hello");
    wing::mask_websocket_payload(payload[..], hdr.mask_key);
    frame.append(payload[..]);
}
```

## Benchmarks

### Benchmarks vs. uWebSockets (Linux epoll, GCC -O3 -flto, 12 cores)

Measured on an Intel Core i5-12400F in an Ubuntu 24.04 container:

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

### L0 and L7 pipeline CPU clock cycles (`bench/server_profiling_benchmark.goose`)

Serialized `rdtscp` cycle count, throughput, and three-channel Goose data-stack
watermarks across HTTP/1.1 framing and L7 security/caching stages:

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
- [Benchmarks](docs/benchmarks.md): Hardware cycle breakdowns and load-testing
  methods.
- [Contributing](CONTRIBUTING.md) and [Security policy](SECURITY.md):
  Development workflow, coding standards, and vulnerability disclosure.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for
details.
