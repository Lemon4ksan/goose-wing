# Goose-Wing: Master Features, Architecture & Nuances Specification

---

## Document Index & Table of Contents

- [1. Systems Architecture & Zero-Heap Philosophy](#1-systems-architecture--zero-heap-philosophy)
- [2. L4 Transport Drivers & Event Loop](#2-l4-transport-drivers--event-loop)
- [3. L4 Network Transport & Multi-Protocol Proxying](#3-l4-network-transport--multi-protocol-proxying)
- [4. HTTP/1.1 Wire Stack & Smuggling Mitigations](#4-http11-wire-stack--smuggling-mitigations)
- [5. HTTP/2 Protocol Stack & Server Multiplexer](#5-http2-protocol-stack--server-multiplexer)
- [6. HTTP/3, QUIC & WebTransport](#6-http3-quic--webtransport)
- [7. Bidirectional Streaming & RPC (WebSocket, SSE, gRPC)](#7-bidirectional-streaming--rpc-websocket-sse-grpc)
- [8. TLS 1.3, PKI & Post-Quantum Cryptography](#8-tls-13-pki--post-quantum-cryptography)
- [9. Compression Suite (Brotli, Zstandard, DCB/DCZ)](#9-compression-suite-brotli-zstandard-dcbdcz)
- [10. Authentication, Tokens & Identity](#10-authentication-tokens--identity)
- [11. Chromium CookieMonster & Partitioning (CHIPS)](#11-chromium-cookiemonster--partitioning-chips)
- [12. Server Engine, Radix Router & Pipeline Dispatch](#12-server-engine-radix-router--pipeline-dispatch)
- [13. Comprehensive Nuance, Buffer Budget & Gotchas Catalog](#13-comprehensive-nuance-buffer-budget--gotchas-catalog)

---

## 1. Systems Architecture & Zero-Heap Philosophy

### 1.1 Zero-Heap Memory Model
Unlike managed languages that rely on tracing garbage collectors or non-deterministic heap reallocations, `goose-wing` is engineered for bare-metal systems performance:
- **Hot-Path Zero-Allocation Guarantee**: Parsing HTTP request lines, headers, query strings, cookies, JSON tokens, and multipart boundaries executes with **zero heap allocations**.
- **Bounded Inline Buffers**: Variable-length strings and structures employ compile-time sized arrays (e.g. `u8[..2048]`, `HeaderMap` with 64 static slots and 64 dynamic entries). If an incoming protocol element exceeds its budget, the parser fails closed immediately, terminating the connection and preventing memory exhaustion DoS attacks.
- **Slice Views Over Flat Memory**: Headers, URLs, and token streams operate as lightweight slice views (`const u8[:]`) referencing underlying slab memory or continuous flat buffers without cloning.
- **No Implicit Boxing or Forwarding Proxies**: All function signatures in `wing` adhere strictly to direct canonical calls without proxy alias wrappers ("никаких алиасингов").

### 1.2 Deterministic Monotonic Timekeeping
- **Separation of Clocks**: Real-world dates use `Time` (civil Gregorian calendar via Howard Hinnant algorithms), while timeouts, rate-limiters, deadlines, and metrics use monotonically increasing nanoseconds (`clock_ns()`).
- **No Background Timer Threads**: `Deadline` and `Stopwatch` are zero-cost stack-allocated structures. Checking `deadline.is_expired()` compiles to a single branchless CPU register comparison without creating runtime timer channels or Goroutines.
- **Saturated Arithmetic**: Differences between timestamps $> 292$ years saturate at `INT64_MAX` or `INT64_MIN` without two's-complement integer wraparound.

---

## 2. L4 Transport Drivers & Event Loop

`goose-wing` implements native transport drivers for all tier-1 operating systems ("Большая Тройка"), complete with a unified non-blocking `Poller` and `EventLoop` in `net/driver/` and `net/poller.goose`.

### 2.1 Driver Implementations
1. **Windows Registered I/O (RIO)**:
   - High-performance kernel-bypass networking via `mswsock.dll` (`WSAID_MULTIPLE_RIO`).
   - Pre-allocated, page-locked virtual memory buffers (`RioBufferDescriptor`) eliminate page faults and double-buffering.
   - Dedicated completion queues (`RIO_CQ`) with non-blocking dequeue (`wing_rio_dequeue_completion`).
2. **Linux `io_uring`**:
   - Kernel 6.1+ interface utilizing direct submission and completion queues (`io_uring_setup`, `io_uring_enter`).
   - Fixed buffers (`IORING_REGISTER_BUFFERS`) and direct descriptor tables minimize syscall overhead.
   - Multishot receive modes (`IORING_RECV_MULTISHOT`) enable continuous data streaming into ring buffers.
3. **macOS / BSD `kqueue`**:
   - Kernel event multiplexer (`kevent64`) with batched changelists.
   - Nanosecond timer filters (`EVFILT_TIMER`) and exact byte-metric accounting on socket read buffers (`data` field).
4. **Standard POSIX / WinSock Driver**:
   - Zero-dependency cross-platform fallback maintaining 100% feature parity on standard non-blocking BSD sockets.

### 2.2 Poller & EventLoop
- **Socket Registration Table**: Fixed 64-slot table (`SocketRegistration[..64]`) managing read/write interests (`PollInterest.Read`, `Write`, `ReadWrite`) and triggering models (`PollTrigger.Level`, `Edge`).
- **High-Resolution Timer Wheels**: Stack-allocated timer table (`PollerTimer[..32]`) supporting one-shot and recurring periodic timers with sub-millisecond precision.
- **Connection Buffering**: Integrated 4 KB ring buffers (`RingBuffer`) per connection, enabling non-blocking zero-copy reads, buffered writes, and single-pass pipeline flushes.

---

## 3. L4 Network Transport & Multi-Protocol Proxying

### 3.1 Happy Eyeballs v2/v3 (RFC 8305)
- **Asymmetric IPv6 Priority**: Initiates DNS resolution for IPv6 (AAAA) and IPv4 (A) concurrently. If IPv4 finishes first, a 50 ms Resolution Delay (RD) timer is armed, allowing IPv6 to catch up before falling back.
- **Connection Attempt Delay (CAD)**: 250 ms default pacing between parallel TCP connections with an absolute floor $\ge 10\text{ ms}$ preventing network congestion storms.
- **RFC 6724 Address Interleaving**: Alternates address families ($\text{IPv6}_1 \to \text{IPv4}_1 \to \text{IPv6}_2 \to \text{IPv4}_2$).
- **NAT64 Local Synthesis**: 2000 ms timer triggering RFC 7050 prefix synthesis (`64:ff9b::/96`) on pure IPv6 networks.

### 3.2 Multi-Protocol Proxy Engine (`net/proxy.goose`)
- **SOCKS5 / SOCKS5h (RFC 1928 & RFC 1929)**:
  - Phase 1: Authentication negotiation (Method `0x00` No Auth or `0x02` Username/Password).
  - Phase 2: RFC 1929 subnegotiation with mandatory version byte `0x01`.
  - Phase 3: Command dispatch with `ATYP = 0x03` (Domain Name) routing for `socks5h://`, ensuring DNS resolution occurs exclusively on the remote proxy server and eliminating client DNS leaks.
  - Phase 4: Full consumption and validation of the BND.ADDR reply frame.
- **HTTP CONNECT Tunneling**:
  - RFC 9110 compliant tunnel establishment with zero-alloc request formatting.
  - Automatic isolation and stripping of `Proxy-Authorization` headers from downstream origin requests.
  - OkHttp leftover buffer defense: strictly verifies that no extraneous unrequested bytes were buffered during the TLS handshake tunnel establishment, aborting immediately on prefix-injection attacks.
- **HAProxy PROXY Protocol v1 & v2 (`net/proxy_protocol.goose`)**:
  - Version 1: Text-based parser (`PROXY TCP4|TCP6 ... \r\n`) with port and IP validation.
  - Version 2: Binary 12-byte signature parser (`\r\n\r\n\0\r\nQUIT\n`) supporting `INET4`, `INET6`, and `UNIX` families.
  - Full TLV (Type-Length-Value) parsing: ALPN (`0x01`), Authority/SNI (`0x02`), Unique-ID (`0x05`), NetNS (`0x30`), and SSL flags (`0x20` with client verification and cipher attributes).
- **4-Tier Slowloris Tarpit Defenses**:
  - 10-second non-resetting cumulative header deadline.
  - 1-second `Expect: 100-continue` transition ceiling.
  - 64 KB cumulative header buffer memory limit.
  - 256 B/s Byte-Drip gate terminating clients that intentionally trickle header bytes to hold connections open.

### 3.3 Two-Tier Retry & Resilience Engine (`net/retry.goose`)
- **Tier 1: Zero-Delay Stale Socket Recovery**:
  - Recovers from half-closed keep-alive connections closed by the server while idle in the pool.
  - Requires 4 strict invariants: `reused == true`, `headers_received == false`, request is idempotent (GET, HEAD, PUT, DELETE, OPTIONS) or carries `Idempotency-Key`, and request body is rewindable (`BodyRewind`).
- **Tier 2: Exponential Backoff & Jitter**:
  - Full Jitter, Equal Jitter, and Decorrelated Jitter algorithms preventing synchronized retry storms.
  - RFC 9110 `Retry-After` parsing supporting both integer delay-seconds and `IMF-fixdate` timestamps with UTC round-trip verification.
  - Google SRE adaptive retry budget capping retries at 20% of normal traffic.

---

## 4. HTTP/1.1 Wire Stack & Smuggling Mitigations

### 4.1 Zero-Heap Flat Buffer `HeaderMap` (`http/headers.goose`)
- **Continuous Buffer Architecture**: Stores raw header text in a flat 8 KB continuous buffer with `\0\0` termination (Chromium `raw_headers_` pattern) accompanied by 128 compact 16-byte `HeaderEntry` descriptor records.
- **O(1) Inline Lookups**: 64 compile-time slots (`inline_slots[64]`) provide instant index-based lookups for canonical headers (`Host`, `Authorization`, `Content-Type`, `User-Agent`, `Set-Cookie`, etc.) without hashing.
- **Vectorized SWAR Tokenizer**: 64-bit SIMD Within A Register algorithms (`swar_has_zero_byte`, `swar_has_byte`, `swar_has_ctl_or_del`) accelerate delimiter and control character validation.
- **Chromium 304 Cache Merging**: In-place replacement of cached headers on HTTP 304 Not Modified responses.

### 4.2 RFC 9112 Chunked Transfer Coding & Smuggling Mitigations
- **Strict CRLF Invariants (CVE-2025-22871 Defense)**: Rejects bare LF (`\n`) in chunk-size lines, chunk data boundaries, and trailers. Any bare LF immediately aborts parsing with a 400 Bad Request error.
- **Anti-Smuggling TE.CL / CL.TE Resolution**:
  - If both `Transfer-Encoding` and `Content-Length` are present, `Content-Length` is either stripped or rejected per RFC 9112 §6.3, eliminating frontend/backend desynchronization.
  - Duplicate `Content-Length` headers are rejected unless all values are identical digits.
- **Trailer Security & Bounds**:
  - Capped at **16 headers** and **4,096 total bytes**.
  - Forbidden trailer headers per RFC 9112 §7.1.2 are stripped and rejected: `Authorization`, `Set-Cookie`, `Cookie`, `Content-Length`, `Transfer-Encoding`, `Host`, and `TE`.
- **Incremental Streaming Decoder (`ChunkedStreamDecoder`)**:
  - 6-state zero-alloc state machine (`ChunkSizeLine`, `ChunkData`, `ChunkDataCrlf`, `Trailers`, `Complete`, `Error`) capable of consuming fragmented streams down to 1 byte per iteration.


---

## 5. HTTP/2 Protocol Stack & Server Multiplexer

`goose-wing` provides a clean-room reference implementation of HTTP/2 (RFC 9113), HPACK (RFC 7541), and Extensible Priorities (RFC 9218) in `http2/` and `server/h2_multiplexer.goose`.

### 5.1 Binary Framing & HPACK Codec
- **9-Byte Frame Header**: Zero-copy parser and serializer for all 10 standard HTTP/2 frame types (`DATA`, `HEADERS`, `PRIORITY`, `RST_STREAM`, `SETTINGS`, `PUSH_PROMISE`, `PING`, `GOAWAY`, `WINDOW_UPDATE`, `CONTINUATION`).
- **HPACK 256-State Huffman FSM**: Nibble-based Huffman decoder operating on 4-bit nibbles with a compact 16 KiB table fitting entirely into CPU L1 data cache.
- **Dynamic Table with In-Place Ring Buffer**: Zero-heap sliding window table with byte-exact eviction and integer shift bounds preventing Trail of Bits FIND-401 integer overflow (CVE-2022-41723).
- **Lowercase Header Invariant**: In compliance with RFC 9113 §8.2.1, all outgoing response headers are strictly lowercased during serialization.

### 5.2 Server Frame Multiplexer (`server/h2_multiplexer.goose`)
- **Connection Preface Validation**: Strictly validates the 24-byte client connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`).
- **Stream State Machine**: Manages concurrent stream states (`Idle`, `Open`, `HalfClosedRemote`, `HalfClosedLocal`, `Closed`) across multiple streams simultaneously with zero dynamic heap allocations.
- **Two-Level Flow Control**: Tracks signed 64-bit connection and stream flow-control windows, correctly accommodating negative stream windows when the remote peer reduces the initial window via `SETTINGS_INITIAL_WINDOW_SIZE`.
- **Anti-DoS Defenses**:
  - *Rapid Reset Protection (CVE-2023-44487)*: GCRA token-bucket tracking the frequency of client-initiated `RST_STREAM` frames. If the client exceeds the burst threshold, the server emits a `GOAWAY` frame with `ENHANCE_YOUR_CALM` (0xb) and closes the connection.
  - *CONTINUATION Flood Shield (CVE-2024-27983)*: Enters an exclusive continuation lock when a `HEADERS` frame lacks the `END_HEADERS` flag. Interleaved frames on other streams or header blocks exceeding 64 KB are terminated with `PROTOCOL_ERROR` (0x1).
  - *Control Frame Flood Protection (CVE-2019-9512 / CVE-2019-9515)*: Enforces quotas on consecutive `PING`, `SETTINGS`, and empty `DATA` frames.

---

## 6. HTTP/3, QUIC & WebTransport

Implemented in `quic/`, `http3/`, and `realtime/webtransport.goose`, supporting modern UDP-based transport protocols.

### 6.1 QUIC Core (RFC 9000 & RFC 9002)
- **Variable-Length Integer Codec (Varint)**: Zero-alloc 2-bit tagged prefix encoder/decoder for 8-bit, 16-bit, 32-bit, and 62-bit integer ranges.
- **Packet Protection & Header Protection**: AES-128/256-ECB and ChaCha20 sample-based header protection concealing packet numbers and key phase bits.
- **ACK Frame Serialization (`quic/AckFrame.goose`)**: Efficient run-length encoded ACK ranges with ECN (Explicit Congestion Notification) counter tracking.
- **BBR v1 & v2 Congestion Control (`quic/bbr.goose`)**: State machine (`Startup`, `Drain`, `ProbeBW`, `ProbeRTT`) tracking minimum RTT and bottleneck bandwidth estimates.

### 6.2 HTTP/3 & QPACK (RFC 9114 & RFC 9204)
- **QPACK Dynamic & Static Codec**: Complete 99-entry static table codec and encoder/decoder stream framing with prefix integer decoders.
- **Unidirectional Stream Coordination**:
  - Control Stream (type `0x00`) with mandatory initial `SETTINGS` frame.
  - QPACK Encoder (`0x02`) and Decoder (`0x03`) unidirectional streams.
  - Critical Stream Protection: Immediate connection termination (`H3_CLOSED_CRITICAL_STREAM`) if any critical stream is closed by the peer.
- **Alt-Svc Promotion (RFC 7838)**:
  - Cache tracking advertised HTTP/3 endpoints with `ma` (max-age) and exponential failure backoff ($5\text{s}, 10\text{s}, 20\text{s} \dots 320\text{s}$).

### 6.3 WebTransport over HTTP/3 (Draft-16 & RFC 9221)
- **Extended CONNECT Initiation**: Initiates bidirectional WebTransport sessions via `:protocol = webtransport`.
- **Datagram Transport**: Encapsulates unreliable UDP datagrams (`DATAGRAM` frames `0x30`/`0x31`) with varint Session ID multiplexing.

---

## 7. Bidirectional Streaming & RPC (WebSocket, SSE, gRPC)

### 7.1 WebSocket (RFC 6455 & RFC 8441)
- **64-Bit SWAR Masking**: Accelerated payload masking and unmasking using 64-bit unrolled XOR iterations (`core::read_be_u64` and `core::write_be_u64_at`), processing 8 bytes per CPU cycle.
- **Control Frame Invariants**: Enforces `FIN == 1`, payload length $\le 125$ bytes, and immediate rejection of fragmented control frames (`PING`, `PONG`, `CLOSE`).
- **Extended CONNECT**: Multiplexes WebSocket connections over HTTP/2 and HTTP/3 streams without spawning dedicated TCP connections.
- **Zero-Alloc Handshake**: Calculates `Sec-WebSocket-Accept` using fixed-stack 128-byte SHA-1 and Base64 buffers.

### 7.2 Server-Sent Events (W3C EventSource)
- **Incremental Line Normalizer**: Robust stream parser normalizing `CR`, `LF`, and `CRLF` boundaries across fragmented network reads.
- **Field Parsing**: Dispatches multi-line `data:`, `event:`, `id:`, `retry:`, and comment keep-alives (`:`) without heap allocations.

### 7.3 gRPC over HTTP/2 & gRPC-Web (`grpc/`)
- **Length-Prefixed Messages (LPM)**: 5-byte header codec (`[compression_flag: u8] || [message_length: u32_be]`).
- **Streaming Dispatcher**: Supports Unary, Server Streaming, Client Streaming, and Bidirectional Streaming RPCs.
- **Trailers-Only Optimization**: Emits compact trailers-only HTTP/2 responses for immediate errors (e.g. `NotFound`, `PermissionDenied`, `DeadlineExceeded`).
- **gRPC-Web Support**: Wire-compatible translation for browser clients:
  - Binary framing with trailer flags (`0x80`).
  - Base64 gRPC-Web-Text for legacy proxy environments.

### 7.4 MASQUE & Capsule Protocol (RFC 9297 & RFC 9298)
- **CONNECT-UDP Tunneling**: Translates IP UDP packets across HTTP/2 and HTTP/3 capsules.
- **Capsule Framer**: Variable-length integer framing for Datagram, Address Assign, and Route Request capsules.

---

## 8. TLS 1.3, PKI & Post-Quantum Cryptography

`goose-wing` contains a complete pure-Goose cryptographic core and TLS 1.3 implementation in `core/crypto/` and `tls/`.

### 8.1 TLS 1.3 Handshake & Record Layer (RFC 8446)
- **Cryptographic Cipher Suites**:
  - `TLS_AES_128_GCM_SHA256`
  - `TLS_AES_256_GCM_SHA384`
  - `TLS_CHACHA20_POLY1305_SHA256`
- **Key Schedule & Transcript Hash**: HKDF-Extract and HKDF-Expand-Label state machine driving Client Early Traffic, Handshake Traffic, and Application Traffic secrets.
- **X.509 ASN.1 DER Parser**: Zero-heap certificate parser validating validity dates, Subject Alternative Names (SAN: DNS & IP), and RSA/ECDSA/Ed25519 public keys.
- **Encrypted Client Hello (ECH / RFC 9180 HPKE)**: Fully encrypts ClientHello inner payloads using HPKE DHKEM(X25519, HKDF-SHA256), shielding SNI and ALPN from intermediate observers.
- **Certificate Compression (RFC 8879)**: Native Zstandard decompressor decompresses X.509 certificate chains directly in the TLS handshake, reducing handshake latency.
- **ClientHello Fragmentation**: Splits initial ClientHello records across multiple TLS fragments without altering cryptographic hashes, bypassing Deep Packet Inspection (DPI) censorship filters.

### 8.2 Post-Quantum Hybrid Key Exchange (RFC 10024 & FIPS 203)
- **IANA Group `0x11EC` (`X25519MLKEM768`)**:
  - Encodes 1184-byte Client Key Share: `32B X25519 || 1152B ML-KEM-768`.
  - Encodes 1120-byte Server Key Share: `32B X25519 || 1088B ML-KEM-768 Ciphertext`.
  - Derives hybrid shared secret: $\text{SHA-256}(ss_{\text{classical}} \parallel ss_{\text{pq}})$.

### 8.3 Constant-Time Cryptographic Suite (`core/crypto/`)
- **Branchless Primitives**: `ct_eq_u8`, `ct_select_u8`, `ct_eq_bytes` using arithmetic right shifts and two's complement negation to defeat branch-prediction side channels.
- **Statistical Dudect Validation**: Continuous Welch's $t$-test runner verifying $|t| < 4.5$ with outlier cropping ($>2000\text{ ns}$).
- **Ed25519 (RFC 8032)**: Twisted Edwards curve $-x^2 + y^2 = 1 + d x^2 y^2$ over $\mathbb{F}_{2^{255}-19}$ with extended projective coordinates $(X:Y:Z:T)$, branchless scalar multiplication, signature verification, and malleability protection ($S < L$).
- **Privacy Pass Blind Tokens (RFC 9576–9578)**: Zero-alloc wire codec for `TokenChallenge` and `Token`, single-use cache, and GREASE support for Cloudflare Turnstile and Apple Private Access Tokens.


---

## 9. Compression Suite (Brotli, Zstandard, DCB/DCZ)

`goose-wing` embeds a zero-dependency, high-throughput decompression and compression suite in `core/compress/`.

### 9.1 RFC 7932 Brotli Engine
- **In-Memory Static Dictionary**: Embeds the official 122,784-byte static dictionary directly in `.rodata` via a clean string literal, parsed in 41 ms with zero stack footprint.
- **121 String Transformations (Appendix B)**: Complete support for all word transformations (prefixes, suffixes, cut-from-left/right, capitalization, uppercase).
- **Zero-Heap Huffman Bit Reader**: LSB-first bit reader with 64-bit accumulator and 8-bit fast lookahead tables (`fast[256]`).
- **704-Symbol Command Alphabet**: Algorithmic distance code decoding without gigantic static tables; ring buffer history (`[4, 11, 15, 16]`).
- **Decompression Bomb Defense**: Enforces a strict `max_output_bytes` budget, aborting before memory exhaustion.

### 9.2 RFC 9842 Dictionary-Compressed Brotli (DCB) & DCZ
- **Binary Wire Framing**: `[0xFF, 'D', 'C', 'B'] || [32B Dict SHA-256] || [Brotli Payload]`.
- **Transparent Content Negotiation**: Client automatically advertises `dcb, dcz` in `Accept-Encoding` when matching cached dictionaries are present and decompresses payloads transparently.

### 9.3 Zstandard (RFC 8478 / RFC 8879) & Deflate/Gzip
- **Zstandard Decompressor**: Full frame format support, FSE (Finite State Entropy) and Huffman decoding with streaming block assembly.
- **Canonical Signatures**: All decompressors provide the uniform signature `fn <algo>_decompress(src, out) -> bool, CompressError` without proxy adapters.

---

## 10. Authentication, Tokens & Identity

### 10.1 RFC 7519 JWT, RFC 7515 JWS & RFC 7517 JWKS (`auth/`)
- **Zero-Alloc JWT Models**:
  - `JwtHeader`: `alg`, `typ`, `kid`, `cty`.
  - `JwtClaims`: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, plus `ClaimPair[..32]` for custom string, integer, and boolean claims.
- **Supported Algorithms**: `HS256`, `HS384`, `HS512` (FIPS 180-4 HMAC) and `EdDSA` (RFC 8037 Ed25519).
- **RFC 8725 BCP Security Hardening**:
  - *Algorithm Confusion Defense*: Rejects token if `alg` differs from the caller's expected algorithm.
  - *"none" Algorithm Ban*: `alg: none` is rejected unconditionally unless `allow_none_alg` is explicitly configured.
  - *Timing-Attack Protection*: Validates signatures and MAC tags using `core::ct_eq_bytes`.
  - *Clock Skew Leeway*: Configurable `leeway_seconds` on `exp` and `nbf` timestamp evaluations.
- **JWKS Key Rotation**: Holds up to 16 active keys (`OKP` for Ed25519 and `Oct` for HMAC) with instant $O(1)$ lookup by `kid`.

### 10.2 OAuth 2.0 DPoP (RFC 9449) & PKCE (RFC 7636 / RFC 9700)
- **Demonstrating Proof-of-Possession (DPoP)**:
  - Signs JOSE tokens with `typ: "dpop+jwt"`.
  - Canonicalizes HTTP target URI (HTU without query or fragment) and HTTP method (HTM).
  - Calculates Access Token Hash (ATH) via `Base64URL(SHA-256(access_token))`.
  - Validates DPoP proofs with timestamp skew, method, URI, and nonce verification.
- **Proof Key for Code Exchange (PKCE)**:
  - Generates secure random verifiers ($43..128$ characters from the unreserved set).
  - Derives code challenge via `S256` (`Base64URL(SHA-256(verifier))`) or `plain`.
  - Constant-time verification preventing timing side-channels.

### 10.3 AWS SigV4 & RFC 9421 HTTP Message Signatures
- **AWS Signature Version 4**:
  - Canonical request derivation: method, canonical URI, query parameters in ASCII order, headers in lower-case order, signed headers list, and hashed payload (`SHA-256(body)`).
  - Multi-tier key derivation: `kDate = HMAC("AWS4" + secret, date)`, `kRegion = HMAC(kDate, region)`, `kService = HMAC(kRegion, service)`, `kSigning = HMAC(kService, "aws4_request")`.
- **RFC 9421 Message Signatures**:
  - Structured fields serialization of `Signature-Input` and `Signature`.
  - Canonical component basis covering `@method`, `@target-uri`, `@authority`, and selective headers.

---

## 11. Chromium CookieMonster & Partitioning (CHIPS)

Implemented in `cookie/`, strictly reproducing Chromium's `net::CookieMonster`.

### 11.1 Cookie Structure & Prefixes
- **Capacity Caps**: 4096-byte payload (`name + value`), 1024-byte per-attribute limit, CTL character rejection.
- **Layered Security Prefixes**:
  - `__Host-`: Must have `Secure`, must NOT have a `Domain` attribute, and must have `Path=/`.
  - `__Secure-`: Must have `Secure` and must be transmitted over HTTPS.
- **CHIPS Partitioning**: Isolates cookie jars across top-level sites with a 10 KB budget per partition.

### 11.2 Asymmetric 6-Round Garbage Collection
Chromium-grade eviction priority:
1. Purge expired cookies globally.
2. Purge expired cookies in the current domain.
3. If domain quota exceeded (180 cookies), evict non-secure cookies first.
4. Evict domain cookies before host cookies.
5. Evict host cookies.
6. Global LRU eviction respecting 30-day purge immunity.

---

## 12. Server Engine, Radix Router & Pipeline Dispatch

### 12.1 Compressed Radix Router (`server/router.goose`)
- **Zero-Allocation Parameter Extraction**: `ZeroAllocParams` records stack-allocated slice spans (`u8[:]`) referencing parameter tokens without allocating strings.
- **Insertion-Order Independence**: Resolves `matchit` Issue #83 / commit `f607f73` — `{id}.json` and `{id}/comments.json` yield identical routing regardless of registration sequence.
- **Static Route Precedence**: Exact static paths take precedence over parametric or wildcard subtrees.
- **Automatic 405 Method Not Allowed**: Generates standard `405` responses accompanied by dynamic `Allow` headers advertising registered methods.

### 12.2 Tako v2 6-Mechanism Connection Pool (`server/pool.goose`)
Isolated within `namespace internal;`:
- **`HeaderMapPool`**: Reuses pre-allocated 8 KB flat-buffer header structures across keep-alive connections.
- **`ExtensionsPool`**: Slabs for request-scoped metadata, strictly sanitized on release to prevent memory leaks across requests.
- **`SyncHeadRelease`**: Immediate zero-copy handoff of connection heads to worker threads.
- **`InlineHandlerFuture`**: Stack-allocated task completion states avoiding promise/future heap allocations.
- **`ConnectionTimer`**: Slowloris sweeper tracking connection activity and dropping stalled clients.

---

## 13. Comprehensive Nuance, Buffer Budget & Gotchas Catalog

| Subsystem / Type | Bound / Capacity | Behavioral Invariant on Limit Exceeded |
| :--- | :--- | :--- |
| **`HeaderMap` Dynamic Entries** | 64 slots | Rejects subsequent headers fail-closed (`false`); prevents header amplification DoS. |
| **`HeaderMap` Inline Static Slots** | 64 slots | Instant $O(1)$ lookup for canonical well-known headers (`Host`, `User-Agent`, etc.). |
| **`HeaderItem.name`** | 128 bytes | Truncated or rejected during lexical parsing. |
| **`HeaderItem.value`** | 2048 bytes | Values $> 2\text{ KB}$ rejected with 431 Request Header Fields Too Large. |
| **`UrlView` & URL Buffers** | 2048 bytes | URLs $> 2048$ bytes return `UrlParseError.UrlTooLong`. |
| **Cookie Payload (`name + value`)** | 4096 bytes | `Set-Cookie` line rejected immediately without insertion. |
| **Cookie Attribute** | 1024 bytes | Attribute ignored; defaults apply (e.g. default path `/`). |
| **Multipart Boundary** | 70 bytes (RFC 2046) | Boundaries $> 70$ characters rejected (CVE-2026-19484 defense). |
| **HTTP Range Intervals** | 16 ranges | Rejects $> 16$ ranges with 416 Range Not Satisfiable (CVE-2011-3192 defense). |
| **Chunked Trailers** | 16 headers, 4096 bytes | Parsing aborts immediately with framing error. |
| **HTTP/2 Continuous Headers** | 65,536 bytes | Continuation lock terminates connection with `PROTOCOL_ERROR` (CVE-2024-27983). |
| **HTTP/2 Rapid Reset Burst** | 100 resets / sec | Triggers `GOAWAY` with `ENHANCE_YOUR_CALM` (CVE-2023-44487 defense). |
| **Singleflight Key** | 64 bytes | Keys longer than 64 bytes are truncated. |
| **BatonMutex Reentrancy** | Non-reentrant | Locking an already held mutex deadlocks; caller must release before reacquiring. |
| **SOCKS5 Destination Host** | 255 bytes (RFC 1928) | Hostnames $> 255$ bytes return address error. |
| **DPoP Clock Skew** | $\pm 60$ seconds | Rejects proofs with timestamps outside valid window. |
| **JWT Leeway** | Configurable (def. 60s) | Permits clock drift when evaluating `exp` and `nbf`. |
| **Brotli Max Output Decompress** | User-configured budget | Decompression terminates if output exceeds quota (bomb defense). |
