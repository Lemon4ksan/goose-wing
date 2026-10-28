# goose-wing

[![Goose Language](https://img.shields.io/badge/lang-goose-blue.svg?style=flat-square)](https://github.com/Lemon4ksan/goose)
[![License](https://img.shields.io/badge/license-Apache%202.0-lightgrey.svg?style=flat-square)](LICENSE)
[![Throughput](https://img.shields.io/badge/throughput-1.23M%20TCP%20%7C%2024.6M%20In--Memory-brightgreen.svg?style=flat-square)](#benchmarks)

Zero-allocation systems networking and HTTP engine for Goose

Current project status: Feature-Complete Alpha. Expect breaking changes.

## Overview

`goose-wing` is a zero-allocation networking and HTTP server engine written in [Goose](https://github.com/Lemon4ksan/goose). It implements IETF and W3C specifications without runtime garbage collection. The stack uses bounded inline buffers, SIMD and SWAR tokenizers, and deterministic state machines.

## Subsystems

| Subsystem | Standards and capabilities |
| :--- | :--- |
| L4 transport and OS drivers | Windows Registered I/O (RIO), Linux `io_uring` (SQ/CQ rings and fixed buffers), macOS `kqueue` (kevent64), POSIX/WinSock, non-blocking poller and event loop with nanosecond timer wheels. |
| HTTP/1.1 wire stack | HeaderMap with 64 static and 64 dynamic slots, 64-bit SWAR lexical tokenizer, obs-fold handling, RFC 9112 chunked transfer coding and trailers, TE.CL / CL.TE request smuggling defenses (CVE-2023-39326). |
| HTTP/2 protocol stack | RFC 9113 9-byte frame codec, RFC 7541 HPACK 256-state Huffman L1 FSM, signed 64-bit flow control, RFC 9218 stream prioritization, Rapid Reset DoS defense (CVE-2023-44487), CONTINUATION flood defense. |
| HTTP/3 and QUIC engine | RFC 9000 QUIC packet wire codec, RFC 9204 QPACK encoder/decoder, BBR v1/v2 congestion control, RFC 9221 datagrams, RFC 7838 Alt-Svc racing with exponential backoff, W3C WebTransport over H3. |
| TLS 1.3 and post-quantum PKI | RFC 8446 record layer and key schedule, X.509 ASN.1 DER parser, Encrypted Client Hello (ECH / HPKE RFC 9180), RFC 8879 Zstd certificate compression, ClientHello fragmentation, RFC 10024 and FIPS 203 Hybrid ML-KEM-768. |
| Streaming and RPC | RFC 6455 WebSocket with unrolled 64-bit XOR masking, RFC 8441 Extended CONNECT over H2/H3, W3C EventSource (SSE), gRPC over HTTP/2, and gRPC-Web (binary and base64 text). |
| Compression suite | RFC 7932 Brotli with 122 KB static dictionary and 121 transformations in `.rodata`, RFC 9842 Dictionary-Compressed Brotli (DCB) and DCZ, RFC 8478 Zstandard, Deflate, Gzip, and Zlib. |
| Application security | W3C Fetch Metadata 9-row decision matrix ($\pi_{FM}$ CSRF protection), CORS origin matcher, GCRA rate limiter with Theoretical Arrival Time (TAT), 3-tier SSRF and DNS rebinding guard, RFC 9576–9578 Privacy Pass tokens. |
| Authentication and tokens | RFC 7519 JWT / RFC 7515 JWS (HS256..512 and EdDSA), RFC 7517 JWKS with key rotation, RFC 9449 OAuth 2.0 DPoP, RFC 7636/9700 PKCE, AWS SigV4, RFC 7616 Digest and Basic, RFC 9421 HTTP Message Signatures. |
| Chromium CookieMonster | RFC 6265bis engine, CHIPS (partitioned cookies), prefixes (`__Host-`, `__Secure-`), Mozilla Public Suffix List (PSL), 6-round garbage collection, SQLite v24 persistence. |
| Tunneling and proxies | SOCKS5 / SOCKS5h (RFC 1928/1929 ATYP=0x03 DNS leak prevention), HTTP CONNECT tunneling with credential stripping, HAProxy PROXY Protocol v1 and v2 (with TLV parsing), 4-tier Slowloris tarpit defenses. |
| Server engine and router | Compressed Radix Trie (`ZeroAllocParams`, insertion-order independence), Tako v2 connection pool, HTTP/2 server frame multiplexer, gRPC server dispatcher. |

## Quick start

### 1. HTTP client session

```goose
import std;
import wing from "..";

fn main() {
    var sess = wing::new_session("https://api.example.com") { s =>
        s.set_profile(wing::Profile.Wing);
        s.set_timeout_ms(5000);
        s.default_header("Accept", "application/json");
    };

    let res, ok = sess.get("/v1/status");
    guard ok && res.is_success() else {
        print("Request failed!");
        return;
    }

    print("Status: ", res.status_code);
    print("Body: ", res.body);
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

### 3. Encrypted cookies (`CryptoJar`)

```goose
import wing;

fn run_crypto_jar() {
    var raw_key: u8[..32] = [];
    raw_key.append_slice("01234567890123456789012345678901");
    let store = wing::new_key_store(wing::new_key_slot(raw_key));

    // Authenticated encryption: XChaCha20-Poly1305 with AAD name binding
    var private_jar = wing::new_private_jar(store, wing::CipherType.XChaCha20Poly1305);
    var ciphertext: u8[..256] = [];
    private_jar.seal("session_token", "user_admin_privileges", ciphertext);

    var decrypted: u8[..256] = [];
    if private_jar.open("session_token", ciphertext, decrypted) {
        print("Authenticated Session: ", decrypted);
    }
}
```

### 4. WebSocket frame codec

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

Benchmarks were conducted on an Intel Core i5-12400F at 4.4 GHz (6 P-cores, 12 threads) running Windows 11 amd64, compiled with MinGW-w64 GCC 16.2.0 (`-O2`). Measurements cover in-memory throughput and loopback networking (`127.0.0.1`).

### 1. Multi-core performance (Intel i5-12400F)

| Execution domain | Concurrency | Total requests | Throughput (req/s) | Latency (ns/req) | Heap allocations |
| :--- | :---: | :---: | :---: | :---: | :---: |
| In-memory core (fast path) | 1 core | 1,000,000 | 4,241,792 req/s | 235 ns | 0 B (0 allocs) |
| In-memory cluster | 6 P-cores | 6,000,000 | 19,404,564 req/s | 51 ns | 0 B (0 allocs) |
| In-memory cluster | 12 threads | 12,000,000 | 24,662,169 req/s | 40 ns | 0 B (0 allocs) |
| Real TCP (HTTP/1.1 ping-pong) | 1 core | 20,000 | 31,613 req/s | 31.6 µs | 0 B (0 allocs) |
| Real TCP (batch depth = 32) | 1 core | 200,000 | 218,049 req/s | 4.59 µs | 0 B (0 allocs) |
| Real TCP cluster (batch depth = 32) | 6 P-cores | 600,000 | 964,864 req/s | 1.04 µs | 0 B (0 allocs) |
| Real TCP cluster (batch depth = 32) | 12 threads | 1,200,000 | 1,227,087 req/s | 810 ns (0.81 µs) | 0 B (0 allocs) |

### 2. Comparison with `aoni/fast`

Comparison against [`aoni/fast`](https://github.com/lemon4ksan/aoni), a zero-allocation Go HTTP engine, on identical hardware:

| Scenario | aoni/fast (Go 1.27) | goose-wing (Goose / GCC -O2) | Delta |
| :--- | :---: | :---: | :---: |
| In-memory core (single core) | 2,126,754 req/s (470 ns) | 4,241,792 req/s (235 ns) | 2.0x faster |
| In-memory cluster (12 threads) | ~12M–14M req/s | 24,662,169 req/s | 1.8x–2.0x faster |
| In-memory heap allocations | 0 B / 0 allocs (`PerPStorage`) | 0 B / 0 allocs (bounded stack) | 0 B / 0 allocs on both |
| Real TCP (1 thread, ping-pong) | 23,195 req/s (43.1 µs) | 31,613 req/s (31.6 µs) | 36% faster |
| Real TCP (cluster, parallel) | 193,000 req/s (6.6 µs) | 1,227,087 req/s (0.81 µs) | 6.3x faster |
| Real TCP memory and allocations | 2,160 B / 21 allocs | 0 B / 0 allocs | 0 B / 0 allocs vs 2,160 B / 21 allocs |

## Tests

The test suite validates RFC compliance, Chromium edge cases, cryptographic vectors, and CVE defenses across 95 test suites:

```powershell
# Typecheck the entire library and all 95 test suites
powershell -ExecutionPolicy Bypass -File .\scripts\test_all.ps1 -CheckOnly

# Run all test suites in parallel with native execution
powershell -ExecutionPolicy Bypass -File .\scripts\test_all.ps1
```

```text
============================================================
 goose-wing High-Performance Test Runner
============================================================
[1/3] Typechecking core and wing libraries...
  OK: core, wing & examples typechecked cleanly in 1168ms.
[2/2] Running typecheck on 95 suites...
  OK: All 95 suites typechecked cleanly in 104.70s.
============================================================
 Typecheck Complete: 100% Valid, 0 Errors, 0 Warnings
============================================================
```

## Documentation

- [Architecture](ARCHITECTURE.md): Memory model, ingress boundaries, module layout, and request/response data flow.
- [Features and nuances](docs/FEATURES_AND_NUANCES.md): 52 implementation phases, buffer budgets, algorithm complexities, fail-closed thresholds, and edge cases.
- [Security defenses](docs/SECURITY_DEFENSES.md): CVE defenses, protocol attack mitigations, constant-time arithmetic, and zero-heap invariants.
- [Caller reference](docs/CALLER_REFERENCE.md): Container capacities, time arithmetic, and concurrency primitives.
- [Contributing](CONTRIBUTING.md) and [Security policy](SECURITY.md): Development workflow, coding standards, and vulnerability disclosure.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
