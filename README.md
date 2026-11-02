# goose-wing

[![Goose Language](https://img.shields.io/badge/lang-goose-blue.svg?style=flat-square)](https://github.com/Lemon4ksan/goose)
[![License](https://img.shields.io/badge/license-Apache%202.0-lightgrey.svg?style=flat-square)](LICENSE)

Zero-allocation networking engine and protocol stack for Goose.

## Design and scope

`wing` is a low-level networking engine, designed on the same principles as Vulkan or DPDK:

- Memory is managed by the caller. Functions accept caller-owned slices and stack buffers (`u8[..N]`). The engine performs 0 heap allocations on packet paths and event loops.
- Protocol decoders work directly on byte slices using SIMD and 64-bit SWAR scanners rather than allocating strings or intermediate objects.
- State machines expose explicit cursor offsets and error boundaries instead of hiding failures behind exceptions or dynamic fallbacks.

This makes `wing` suited for reverse proxies, gateways, and edge services where predictable clock cycles and zero allocations are required (a complete HTTP/1.1 request-response cycle takes ~820 cycles on x86_64).

It is not an ergonomic, high-level HTTP client like Python's `requests`. Writing a simple GET request requires setting up buffers, arenas, and handling transport states. Ergonomic application-level APIs belong in separate libraries built on top of `wing`.

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
import wing from "..";

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
import wing;

fn stream_websocket_frame() {
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
    payload.append_slice("Hello");
    wing::mask_websocket_payload(payload[..], hdr.mask_key);
    frame.append(payload[..]);
}
```

## Benchmarks

### Benchmarks vs. uWebSockets (Linux epoll, GCC -O3 -flto, 12 cores)

Measured on an Intel Core i5-12400F in an Ubuntu 24.04 container:

| Workload / Benchmark Suite | goose-wing (Goose) | uWebSockets (C++) | Delta |
| :--- | :---: | :---: | :---: |
| **HTTP/1.1 Plaintext GET** (wrk, 4 threads, 64 conns, 5s) | **183,658 req/s** | 153,084 req/s | **+20.0%** |
| • *Median latency (p50)* | **321.0 µs** | 390.0 µs | **-17.7%** |
| • *Tail latency (p99)* | **749.0 µs** | 920.0 µs | **-18.6%** |
| • *Transfer rate* | **23.65 MB/s** | 22.34 MB/s | **+5.9%** |
| **Multi-Core Peak 1M Target** (6 workers, wrk 128x pipeline, 512 conns) | **954,939 req/s** | 785,073 req/s | **+21.6%** |
| • *Median latency (p50)* | **314.0 µs** | 395.0 µs | **-20.5%** |
| • *Tail latency (p99)* | **5,510.0 µs** | 7,710.0 µs | **-28.5%** |
| • *Transfer rate* | **122.94 MB/s** | 114.55 MB/s | **+7.3%** |
| **Unbounded Line-Rate Burst** (6 workers, dedicated C burst, 512 conns) | **9,688,950 req/s** | 7,884,619 req/s | **+22.9%** |
| • *Transfer rate* | **1,247.41 MB/s** | 1,150.46 MB/s | **+8.4%** |
| **Heap allocations per request** | **0 B (0 allocs)** | 0 B (0 allocs) | Parity |

### CPU clock cycles (RDTSC, Intel i5-12400F @ 4.4 GHz)

Hardware instruction and cycle breakdown per request across pipeline stages (`bench/prof.exe`, 50,000 samples per stage):

| Pipeline stage | Plaintext GET (50k) | Param JSON (50k) | 10-Header POST (50k) |
| :--- | :---: | :---: | :---: |
| 0. CRLFCRLF delimiter search | 59.0 cycles | 82.8 cycles | 91.9 cycles |
| 1. Request-line SWAR parse | 55.8 cycles | 57.9 cycles | 53.0 cycles |
| 2. Header tokenization & spans | 274.8 cycles | 296.9 cycles | 643.5 cycles |
| 3. Host validation & RFC checks | 30.6 cycles | 30.4 cycles | 34.4 cycles |
| 4. GCRA rate limiter & pipeline | 68.6 cycles | 67.0 cycles | 61.1 cycles |
| 5. Radix router route match | 62.9 cycles | 57.8 cycles | 57.0 cycles |
| 6. Handler execution | 58.5 cycles | 57.4 cycles | 59.5 cycles |
| 7. HTTP/1.1 response serialization | 167.7 cycles | 148.0 cycles | 155.1 cycles |
| 8. Output buffer / cork append | 47.1 cycles | 47.0 cycles | 46.1 cycles |
| **Total pipeline CPU cycles** | **~824 cycles/req** | **~845 cycles/req** | **~1,201 cycles/req** |

## Verification

```bash
# Static typecheck validation across core, wing, and all 36 suites
python tools/test_runner.py --check-only

# 62 parallel LIT verification suites (spec invariants, wire fuzzing, CVE regressions)
python scripts/test_lit.py

# G-CRAP complexity and branch ratchet enforcement
python scripts/ratchet.py

# Invariant linter (line length, no pass-through aliases, zero heap loops)
python scripts/lint_invariants.py
```

## Documentation

- [Architecture](ARCHITECTURE.md): Memory model, ingress boundaries, module layout, and request/response data flow.
- [Features and nuances](docs/FEATURES_AND_NUANCES.md): Buffer budgets, algorithm complexities, fail-closed thresholds, and edge cases.
- [Security defenses](docs/SECURITY_DEFENSES.md): CVE defenses, protocol attack mitigations, constant-time arithmetic, and zero-heap invariants.
- [Caller reference](docs/CALLER_REFERENCE.md): Container capacities, time arithmetic, and concurrency primitives.
- [Contributing](CONTRIBUTING.md) and [Security policy](SECURITY.md): Development workflow, coding standards, and vulnerability disclosure.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
