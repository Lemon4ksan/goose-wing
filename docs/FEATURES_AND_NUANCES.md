# Goose-wing features and implementation notes

## Contents

- [1. Memory and time model](#1-memory-and-time-model)
- [2. L4 transport drivers and event loop](#2-l4-transport-drivers-and-event-loop)
- [3. Connection setup and proxies](#3-connection-setup-and-proxies)
- [4. HTTP/1.1 wire stack and request smuggling](#4-http11-wire-stack-and-request-smuggling)
- [5. HTTP/2 stack and server multiplexer](#5-http2-stack-and-server-multiplexer)
- [6. HTTP/3, QUIC, and WebTransport](#6-http3-quic-and-webtransport)
- [7. Streaming and RPC (WebSocket, SSE, gRPC)](#7-streaming-and-rpc-websocket-sse-grpc)
- [8. TLS 1.3, PKI, and post-quantum key exchange](#8-tls-13-pki-and-post-quantum-key-exchange)
- [9. Compression (Brotli, Zstandard, DCB/DCZ)](#9-compression-brotli-zstandard-dcbdcz)
- [10. Authentication and tokens](#10-authentication-and-tokens)
- [11. Cookie store and partitioning (CHIPS)](#11-cookie-store-and-partitioning-chips)
- [12. Server, radix router, and pipeline](#12-server-radix-router-and-pipeline)
- [13. Buffer limits and edge cases](#13-buffer-limits-and-edge-cases)

## 1. Memory and time model

### 1.1 Memory model
`goose-wing` does not use a garbage collector. Memory follows these rules:
- Hot-path allocations: Parsing HTTP request lines, headers, query strings, cookies, JSON tokens, and multipart boundaries executes with zero heap allocations.
- Bounded inline buffers: Variable-length strings and structures employ compile-time sized arrays (e.g. `u8[..2048]`, `HeaderMap` with 64 static slots and 64 dynamic entries). If an incoming protocol element exceeds its budget, the parser fails closed and terminates the connection, so memory use stays bounded.
- Slice views over flat memory: Headers, URLs, and token streams are slice views (`const u8[:]`) referencing underlying slab memory or continuous flat buffers without cloning.
- No implicit boxing or forwarding proxies: Functions in `wing` are called directly, without alias wrappers ("никаких алиасингов").

### 1.2 Monotonic timekeeping
- Separation of clocks: Real-world dates use `Time` (civil Gregorian calendar via Howard Hinnant algorithms), while timeouts, rate-limiters, deadlines, and metrics use monotonically increasing nanoseconds (`clock_ns()`).
- No background timer threads: `Deadline` and `Stopwatch` are stack-allocated structures. Checking `deadline.is_expired()` compiles to a single branchless CPU register comparison without creating runtime timer channels or Goroutines.
- Saturated arithmetic: Differences between timestamps $> 292$ years saturate at `INT64_MAX` or `INT64_MIN` without two's-complement integer wraparound.

## 2. L4 transport drivers and event loop

`goose-wing` implements native transport drivers for all tier-1 operating systems ("Большая Тройка"), with a shared non-blocking `Poller` and `EventLoop` in `net/driver/` and `net/poller.goose`.

### 2.1 Drivers
1. Windows Registered I/O (RIO):
   - Kernel-bypass networking via `mswsock.dll` (`WSAID_MULTIPLE_RIO`).
   - Pre-allocated, page-locked virtual memory buffers (`RioBufferDescriptor`) eliminate page faults and double-buffering.
   - Dedicated completion queues (`RIO_CQ`) with non-blocking dequeue (`wing_rio_dequeue_completion`).
2. Linux `io_uring`:
   - Kernel 6.1+ interface utilizing direct submission and completion queues (`io_uring_setup`, `io_uring_enter`).
   - Fixed buffers (`IORING_REGISTER_BUFFERS`) and direct descriptor tables minimize syscall overhead.
   - Multishot receive modes (`IORING_RECV_MULTISHOT`) enable continuous data streaming into ring buffers.
3. macOS / BSD `kqueue`:
   - Kernel event multiplexer (`kevent64`) with batched changelists.
   - Nanosecond timer filters (`EVFILT_TIMER`) and exact byte-metric accounting on socket read buffers (`data` field).
4. Standard POSIX / WinSock driver:
   - Fallback driver on non-blocking BSD sockets, with no external dependencies and the same feature set as the other drivers.

### 2.2 Poller and EventLoop
- Socket registration table: Fixed 64-slot table (`SocketRegistration[..64]`) managing read/write interests (`PollInterest.Read`, `Write`, `ReadWrite`) and triggering models (`PollTrigger.Level`, `Edge`).
- High-resolution timer wheels: Stack-allocated timer table (`PollerTimer[..32]`) supporting one-shot and recurring periodic timers with sub-millisecond precision.
- Connection buffering: Integrated 4 KB ring buffers (`RingBuffer`) per connection, enabling non-blocking zero-copy reads, buffered writes, and single-pass pipeline flushes.

## 3. Connection setup and proxies

### 3.1 Happy Eyeballs v2/v3 (RFC 8305)
- Asymmetric IPv6 priority: Initiates DNS resolution for IPv6 (AAAA) and IPv4 (A) concurrently. If IPv4 finishes first, a 50 ms Resolution Delay (RD) timer is armed, allowing IPv6 to catch up before falling back.
- Connection attempt delay (CAD): 250 ms default pacing between parallel TCP connections with a floor of 10 ms.
- RFC 6724 address interleaving: Alternates address families ($\text{IPv6}_1 \to \text{IPv4}_1 \to \text{IPv6}_2 \to \text{IPv4}_2$).
- NAT64 local synthesis: 2000 ms timer triggering RFC 7050 prefix synthesis (`64:ff9b::/96`) on pure IPv6 networks.

### 3.2 Proxy support (`net/proxy.goose`)
- SOCKS5 / SOCKS5h (RFC 1928, RFC 1929):
  - Phase 1: Authentication negotiation (Method `0x00` No Auth or `0x02` Username/Password).
  - Phase 2: RFC 1929 subnegotiation with mandatory version byte `0x01`.
  - Phase 3: Command dispatch with `ATYP = 0x03` (Domain Name) routing for `socks5h://`, so DNS resolution happens only on the remote proxy.
  - Phase 4: Full consumption and validation of the BND.ADDR reply frame.
- HTTP CONNECT tunneling:
  - RFC 9110 compliant tunnel establishment with zero-alloc request formatting.
  - Strips `Proxy-Authorization` headers from requests sent to the origin.
  - Leftover buffer check (as in OkHttp): if the proxy sends bytes after the CONNECT response and before the TLS handshake, the connection is aborted.
- HAProxy PROXY Protocol v1 and v2 (`net/proxy_protocol.goose`):
  - Version 1: Text-based parser (`PROXY TCP4|TCP6 ... \r\n`) with port and IP validation.
  - Version 2: Binary 12-byte signature parser (`\r\n\r\n\0\r\nQUIT\n`) supporting `INET4`, `INET6`, and `UNIX` families.
  - TLV (Type-Length-Value) parsing: ALPN (`0x01`), Authority/SNI (`0x02`), Unique-ID (`0x05`), NetNS (`0x30`), and SSL flags (`0x20` with client verification and cipher attributes).
- 4-tier Slowloris tarpit defenses:
  - 10-second non-resetting cumulative header deadline.
  - 1-second `Expect: 100-continue` transition ceiling.
  - 64 KB cumulative header buffer memory limit.
  - 256 B/s Byte-Drip gate terminating clients that intentionally trickle header bytes to hold connections open.

### 3.3 Two-tier retry (`net/retry.goose`)
- Tier 1: zero-delay stale socket recovery:
  - Recovers from half-closed keep-alive connections closed by the server while idle in the pool.
  - Requires 4 conditions: `reused == true`, `headers_received == false`, request is idempotent (GET, HEAD, PUT, DELETE, OPTIONS) or carries `Idempotency-Key`, and request body is rewindable (`BodyRewind`).
- Tier 2: exponential backoff & jitter:
  - Full Jitter, Equal Jitter, and Decorrelated Jitter algorithms.
  - RFC 9110 `Retry-After` parsing supporting both integer delay-seconds and `IMF-fixdate` timestamps with UTC round-trip verification.
  - Google SRE adaptive retry budget capping retries at 20% of normal traffic.

## 4. HTTP/1.1 wire stack and request smuggling

### 4.1 Flat-buffer `HeaderMap` (`http/headers.goose`)
- Flat buffer: Stores raw header text in a flat 8 KB continuous buffer with `\0\0` termination (Chromium `raw_headers_` pattern) accompanied by 128 compact 16-byte `HeaderEntry` descriptor records.
- O(1) inline lookups: 64 compile-time slots (`inline_slots[64]`) provide index-based lookups for canonical headers (`Host`, `Authorization`, `Content-Type`, `User-Agent`, `Set-Cookie`, etc.) without hashing.
- Host header validation (RFC 9112 §7.2, uWebSockets #1949): Enforces that `Host` contains only `uri-host [ ":" port ]`. Rejects values containing `/`, `?`, `#`, or `@` with `HeaderParseError.InvalidHeaderValue`. Rejects duplicate `Host` headers with `HeaderParseError.InvalidHeaderName`.
- Vectorized SWAR tokenizer: 64-bit SIMD Within A Register algorithms (`swar_has_zero_byte`, `swar_has_byte`, `swar_has_ctl_or_del`) accelerate delimiter and control character validation.
- Chromium 304 cache merging: In-place replacement of cached headers on HTTP 304 Not Modified responses.

### 4.2 RFC 9112 chunked transfer coding
- CRLF only (CVE-2025-22871): Rejects bare LF (`\n`) in chunk-size lines, chunk data boundaries, and trailers. A bare LF aborts parsing with a 400 Bad Request error.
- Chunk extension whitespace tolerance (RFC 9112 §7.1.1, Go #82257): Accepts bad whitespace (`' '` or `\t`) preceding the semicolon in chunk extensions without failing.
- TE.CL / CL.TE handling:
  - If both `Transfer-Encoding` and `Content-Length` are present, `Content-Length` is stripped or the request is rejected, per RFC 9112 §6.3.
  - Duplicate `Content-Length` headers are rejected unless all values are identical digits.
- Trailer limits:
  - Capped at 16 headers and 4,096 total bytes.
  - Forbidden trailer headers per RFC 9112 §7.1.2 are stripped and rejected: `Authorization`, `Set-Cookie`, `Cookie`, `Content-Length`, `Transfer-Encoding`, `Host`, and `TE`.
- Incremental streaming decoder (`ChunkedStreamDecoder`):
  - 6-state zero-alloc state machine (`ChunkSizeLine`, `ChunkData`, `ChunkDataCrlf`, `Trailers`, `Complete`, `Error`) that accepts input split into pieces as small as 1 byte.

## 5. HTTP/2 stack and server multiplexer

`goose-wing` implements HTTP/2 (RFC 9113), HPACK (RFC 7541), and Extensible Priorities (RFC 9218) in `http2/` and `server/h2_multiplexer.goose`.

### 5.1 Binary framing and HPACK
- 9-byte frame header: Zero-copy parser and serializer for all 10 standard HTTP/2 frame types (`DATA`, `HEADERS`, `PRIORITY`, `RST_STREAM`, `SETTINGS`, `PUSH_PROMISE`, `PING`, `GOAWAY`, `WINDOW_UPDATE`, `CONTINUATION`).
- HPACK 256-state Huffman FSM: Nibble-based Huffman decoder operating on 4-bit nibbles with a 16 KiB table that fits in the L1 data cache.
- Dynamic table with in-place ring buffer: Zero-heap sliding window table with byte-exact eviction and integer shift bounds preventing Trail of Bits FIND-401 integer overflow (CVE-2022-41723).
- Lowercase header invariant: Per RFC 9113 §8.2.1, outgoing response headers are lowercased during serialization.
- Pseudo-header and trailer rules (RFC 9113 §8.1.2, §8.3, Go #78775): Pseudo-headers starting with `:` are forbidden in trailer sections and return `ERR_PROTOCOL_ERROR`. Trailer sections containing connection-specific or message framing headers (`content-length`, `transfer-encoding`, `host`, `connection`, `keep-alive`, `upgrade`, `trailer`, `te != "trailers"`) return `ERR_PROTOCOL_ERROR`.
- Target URI validation (RFC 9113 §8.3.1, Go #77843, uWebSockets #1949): The `:path` pseudo-header rejects characters `<`, `>`, `"`, `\`, `^`, `{`, `|`, `}`, interior spaces, and ASCII controls. The `:authority` pseudo-header rejects `/`, `?`, `#`, and `@`. Violations fail with `ERR_PROTOCOL_ERROR`.
- Push promise settings negotiation (RFC 9113 §6.5.2): Clients reject server `SETTINGS` frames where `SETTINGS_ENABLE_PUSH != 0` with `ERR_PROTOCOL_ERROR`.
- GOAWAY stream ID parity (RFC 9113 §6.8, Go #80759, Go #82365): Client-sent GOAWAY frames must specify stream ID 0 or an even stream ID. Server-sent GOAWAY frames must specify 0, an odd stream ID, or `0x7FFFFFFF`. Incoming streams with ID greater than `last_stream_id` are rejected with `ERR_REFUSED_STREAM`.

### 5.2 Server frame multiplexer (`server/h2_multiplexer.goose`)
- Connection preface validation: Validates the 24-byte client connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`).
- Stream state machine: Manages concurrent stream states (`Idle`, `Open`, `HalfClosedRemote`, `HalfClosedLocal`, `Closed`) without heap allocations.
- Two-level flow control: Tracks signed 64-bit connection and stream flow-control windows. Stream windows can go negative when the remote peer reduces the initial window via `SETTINGS_INITIAL_WINDOW_SIZE`.
- Anti-DoS defenses:
  - Rapid reset protection (CVE-2023-44487): GCRA token-bucket tracking the frequency of client-initiated `RST_STREAM` frames. If the client exceeds the burst threshold, the server emits a `GOAWAY` frame with `ENHANCE_YOUR_CALM` (0xb) and closes the connection.
  - CONTINUATION flood limit (CVE-2024-27983): Enters an exclusive continuation lock when a `HEADERS` frame lacks the `END_HEADERS` flag. Interleaved frames on other streams or header blocks exceeding 64 KB are terminated with `PROTOCOL_ERROR` (0x1).
  - Control frame flood protection (CVE-2019-9512 / CVE-2019-9515): Enforces quotas on consecutive `PING`, `SETTINGS`, and empty `DATA` frames.

## 6. HTTP/3, QUIC, and WebTransport

Implemented in `quic/`, `http3/`, and `realtime/webtransport.goose`.

### 6.1 QUIC core (RFC 9000, RFC 9002)
- Variable-length integer codec (varint): Zero-alloc 2-bit tagged prefix encoder/decoder for 8-bit, 16-bit, 32-bit, and 62-bit integer ranges.
- Packet and header protection: AES-128/256-ECB and ChaCha20 sample-based header protection concealing packet numbers and key phase bits.
- ACK frame serialization (`quic/AckFrame.goose`): Run-length encoded ACK ranges with ECN (Explicit Congestion Notification) counter tracking.
- BBR v1 and v2 congestion control (`quic/bbr.goose`): State machine (`Startup`, `Drain`, `ProbeBW`, `ProbeRTT`) tracking minimum RTT and bottleneck bandwidth estimates.

### 6.2 HTTP/3 and QPACK (RFC 9114, RFC 9204)
- QPACK dynamic and static codec: 99-entry static table codec and encoder/decoder stream framing with prefix integer decoders.
- Pseudo-header invariants (RFC 9114 §4.3):
  - Duplicate pseudo-headers (`:status`, `:method`, `:scheme`, `:authority`, `:path`) are rejected with `H3_ERR_GENERAL_PROTOCOL` (0x0101).
  - Pseudo-headers must precede regular headers in the decoded field section. Any pseudo-header encountered after regular headers triggers `H3_ERR_GENERAL_PROTOCOL`.
- Unidirectional stream coordination (RFC 9114 §6.2):
  - Control Stream (type `0x00`) with mandatory initial `SETTINGS` frame.
  - QPACK Encoder (`0x02`) and Decoder (`0x03`) unidirectional streams.
  - Duplicate control, encoder, or decoder streams are rejected with `H3_STREAM_CREATION_ERROR` (0x0103).
  - If the peer closes a critical stream, the connection is closed with `H3_CLOSED_CRITICAL_STREAM`.
- Alt-Svc promotion (RFC 7838):
  - Cache tracking advertised HTTP/3 endpoints with `ma` (max-age) and exponential failure backoff ($5\text{s}, 10\text{s}, 20\text{s} \dots 320\text{s}$).

### 6.3 WebTransport over HTTP/3 (draft-16, RFC 9221)
- Extended CONNECT initiation and inspection: Initiates and validates bidirectional WebTransport sessions via `:protocol = webtransport` and `sec-webtransport-http3-draft: draft16`.
- Unidirectional and bidirectional stream framing:
  - Unidirectional streams: Prefixed with VarInt stream type `0x54` (`STREAM_TYPE_WEBTRANSPORT`) and VarInt Session ID.
  - Bidirectional streams: Initiated via VarInt signal `0x41` (`WEBTRANSPORT_BIDI_SIGNAL`) and VarInt Session ID.
- Datagram transport: Encapsulates unreliable UDP datagrams (`DATAGRAM` frames `0x30`/`0x31`) with varint Session ID multiplexing.
- HTTP/3 error code translation: Bidirectional mapping between 32-bit application error codes and HTTP/3 error code range (`0x52e4a40fa8db`..`0x52e5ac983162`) with strict skipping of GREASE points (`(h3 - 0x21) % 0x1F != 0`).
- Capsule protocol (draft-16 Section 8): Zero-allocation codecs for `CLOSE_WEBTRANSPORT` (error code and reason phrase), `DRAIN_WEBTRANSPORT`, `WT_RESET_STREAM`, and `WT_STOP_SENDING`.
- Session lifecycle: State machine handling active, draining, and closed transitions with reason tracking.

## 7. Streaming and RPC (WebSocket, SSE, gRPC)

### 7.1 WebSocket (RFC 6455, RFC 8441)
- 64-bit SWAR masking: Payload masking and unmasking using 64-bit unrolled XOR iterations (`core::read_be_u64` and `core::write_be_u64_at`), 8 bytes per iteration.
- Control frame invariants: Control frames (`PING`, `PONG`, `CLOSE`) must have `FIN == 1` and a payload of at most 125 bytes; fragmented control frames are rejected with close code 1002.
- Ping and Pong handling (RFC 6455 §5.5, Go #7825): Empty Ping frames (`payload.len == 0`) trigger an empty Pong response with matching empty payload without terminating the connection.
- Close frame validation (RFC 6455 §5.5.1, §7.4.2): Payloads of exactly 1 byte and reserved status codes (0-999, 1004, 1005, 1006, 1015, 1016-2999) trigger close code 1002 (Protocol Error).
- Extended CONNECT: Multiplexes WebSocket connections over HTTP/2 and HTTP/3 streams without spawning dedicated TCP connections.
- Zero-alloc handshake:
  - Validates mandatory headers (`Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key`, and RFC 6455 §4.2.1 `Host`). Missing `Host` returns 400 Bad Request.
  - Subprotocol negotiation (RFC 6455 §4.2.2): Matches selected subprotocols against client requested tokens in `Sec-WebSocket-Protocol`. Unmatched subprotocols are never returned.
  - Calculates `Sec-WebSocket-Accept` using fixed-stack 128-byte SHA-1 and Base64 buffers.

### 7.2 Server-sent events (W3C EventSource)
- Incremental line normalizer: Stream parser that normalizes `CR`, `LF`, and `CRLF` boundaries across fragmented network reads.
- Field parsing: Dispatches multi-line `data:`, `event:`, `id:`, `retry:`, and comment keep-alives (`:`) without heap allocations.

### 7.3 gRPC over HTTP/2 and gRPC-Web (`grpc/`)
- Length-prefixed messages (LPM): 5-byte header codec (`[compression_flag: u8] || [message_length: u32_be]`).
- Streaming dispatcher: Supports Unary, Server Streaming, Client Streaming, and Bidirectional Streaming RPCs.
- Trailers-only responses: Emits trailers-only HTTP/2 responses for immediate errors (e.g. `NotFound`, `PermissionDenied`, `DeadlineExceeded`).
- gRPC-Web for browser clients:
  - Binary framing with trailer flags (`0x80`).
  - Base64 gRPC-Web-Text for legacy proxy environments.

### 7.4 MASQUE and the Capsule Protocol (RFC 9297, RFC 9298)
- CONNECT-UDP tunneling: Translates IP UDP packets across HTTP/2 and HTTP/3 capsules.
- Capsule framer: Variable-length integer framing for Datagram, Address Assign, and Route Request capsules.

## 8. TLS 1.3, PKI, and post-quantum key exchange

`goose-wing` contains a cryptographic core and a TLS 1.3 implementation, both written in Goose, in `core/crypto/` and `tls/`.

### 8.1 TLS 1.3 handshake and record layer (RFC 8446)
- Cipher suites:
  - `TLS_AES_128_GCM_SHA256`
  - `TLS_AES_256_GCM_SHA384`
  - `TLS_CHACHA20_POLY1305_SHA256`
- Key schedule and transcript hash: HKDF-Extract and HKDF-Expand-Label state machine driving Client Early Traffic, Handshake Traffic, and Application Traffic secrets.
- X.509 ASN.1 DER parser: Zero-heap certificate parser validating validity dates, Subject Alternative Names (SAN: DNS & IP), and RSA/ECDSA/Ed25519 public keys.
- Encrypted Client Hello (ECH / RFC 9180 HPKE): Encrypts the inner ClientHello with HPKE DHKEM(X25519, HKDF-SHA256), so on-path observers cannot read SNI or ALPN.
- Certificate compression (RFC 8879): The built-in Zstandard decompressor unpacks X.509 certificate chains during the TLS handshake.
- ClientHello fragmentation: Splits initial ClientHello records across multiple TLS fragments without changing the handshake transcript hash, to evade Deep Packet Inspection (DPI) filters.

### 8.2 Hybrid post-quantum key exchange (RFC 10024, FIPS 203)
- IANA group `0x11EC` (`X25519MLKEM768`):
  - Encodes 1184-byte client key share: `32B X25519 || 1152B ML-KEM-768`.
  - Encodes 1120-byte server key share: `32B X25519 || 1088B ML-KEM-768 Ciphertext`.
  - Derives hybrid shared secret: $\text{SHA-256}(ss_{\text{classical}} \parallel ss_{\text{pq}})$.

### 8.3 Constant-time cryptography (`core/crypto/`)
- Branchless primitives: `ct_eq_u8`, `ct_select_u8`, `ct_eq_bytes` using arithmetic right shifts and two's complement negation so execution has no secret-dependent branches.
- Dudect test: Welch's $t$-test runner verifying $|t| < 4.5$ with outlier cropping ($>2000\text{ ns}$).
- Ed25519 (RFC 8032): Twisted Edwards curve $-x^2 + y^2 = 1 + d x^2 y^2$ over $\mathbb{F}_{2^{255}-19}$ with extended projective coordinates $(X:Y:Z:T)$, branchless scalar multiplication, signature verification, and malleability protection ($S < L$).
- Privacy Pass blind tokens (RFC 9576–9578): Zero-alloc wire codec for `TokenChallenge` and `Token`, single-use cache, and GREASE support for Cloudflare Turnstile and Apple Private Access Tokens.

## 9. Compression (Brotli, Zstandard, DCB/DCZ)

`goose-wing` includes compression and decompression code with no external dependencies in `core/compress/`.

### 9.1 RFC 7932 Brotli
- In-memory static dictionary: The 122,784-byte RFC 7932 static dictionary is a string literal in `.rodata`. Parsing it takes 41 ms and uses no stack.
- 121 string transformations (Appendix B): All word transformations (prefixes, suffixes, cut-from-left/right, capitalization, uppercase).
- Zero-heap Huffman bit reader: LSB-first bit reader with 64-bit accumulator and 8-bit fast lookahead tables (`fast[256]`).
- 704-symbol command alphabet: Algorithmic distance code decoding without large static tables; ring buffer history (`[4, 11, 15, 16]`).
- Decompression bomb defense: Decompression stops when output reaches `max_output_bytes`.

### 9.2 RFC 9842 Dictionary-Compressed Brotli (DCB) and DCZ
- Binary wire framing: `[0xFF, 'D', 'C', 'B'] || [32B Dict SHA-256] || [Brotli Payload]`.
- Content negotiation: The client advertises `dcb, dcz` in `Accept-Encoding` when matching cached dictionaries are present and decompresses the response.

### 9.3 Zstandard (RFC 8478, RFC 8879), Deflate, and Gzip
- Zstandard decompressor: Frame format, FSE (Finite State Entropy) and Huffman decoding with streaming block assembly.
- Canonical signatures: All decompressors provide the uniform signature `fn <algo>_decompress(src, out) -> bool, CompressError` without proxy adapters.

## 10. Authentication and tokens

### 10.1 RFC 7519 JWT, RFC 7515 JWS, and RFC 7517 JWKS (`auth/`)
- Zero-alloc JWT models:
  - `JwtHeader`: `alg`, `typ`, `kid`, `cty`.
  - `JwtClaims`: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, plus `ClaimPair[..32]` for custom string, integer, and boolean claims.
- Supported algorithms: `HS256`, `HS384`, `HS512` (FIPS 180-4 HMAC) and `EdDSA` (RFC 8037 Ed25519).
- RFC 8725 checks:
  - Algorithm confusion defense: Rejects token if `alg` differs from the caller's expected algorithm.
  - "none" algorithm ban: `alg: none` is rejected unless `allow_none_alg` is explicitly configured.
  - Timing-attack protection: Validates signatures and MAC tags using `core::ct_eq_bytes`.
  - Clock skew leeway: Configurable `leeway_seconds` on `exp` and `nbf` timestamp evaluations.
- JWKS key rotation: Holds up to 16 active keys (`OKP` for Ed25519 and `Oct` for HMAC) with $O(1)$ lookup by `kid`.

### 10.2 OAuth 2.0 DPoP (RFC 9449) and PKCE (RFC 7636, RFC 9700)
- Demonstrating proof-of-possession (DPoP):
  - Signs JOSE tokens with `typ: "dpop+jwt"`.
  - Canonicalizes HTTP target URI (HTU without query or fragment) and HTTP method (HTM).
  - Calculates Access Token Hash (ATH) via `Base64URL(SHA-256(access_token))`.
  - Validates DPoP proofs with timestamp skew, method, URI, and nonce verification.
- Proof key for code exchange (PKCE):
  - Generates random verifiers ($43..128$ characters from the unreserved set).
  - Derives code challenge via `S256` (`Base64URL(SHA-256(verifier))`) or `plain`.
  - Verification runs in constant time.

### 10.3 RFC 9421 HTTP Message Signatures
- Structured fields serialization of `Signature-Input` and `Signature`.
- Canonical component basis covering `@method`, `@target-uri`, `@authority`, and selective headers.

## 11. Cookie store and partitioning (CHIPS)

Implemented in `cookie/`, following Chromium's `net::CookieMonster`.

### 11.1 Cookie limits and prefixes
- Capacity caps: 4096-byte payload (`name + value`), 1024-byte per-attribute limit, CTL character rejection.
- Prefixes:
  - `__Host-`: Must have `Secure`, must not have a `Domain` attribute, and must have `Path=/`.
  - `__Secure-`: Must have `Secure` and must be transmitted over HTTPS.
- CHIPS partitioning: Isolates cookie jars across top-level sites with a 10 KB budget per partition.

### 11.2 6-round eviction
Eviction order, as in Chromium:
1. Purge expired cookies globally.
2. Purge expired cookies in the current domain.
3. If domain quota exceeded (180 cookies), evict non-secure cookies first.
4. Evict domain cookies before host cookies.
5. Evict host cookies.
6. Global LRU eviction respecting 30-day purge immunity.

## 12. Server, radix router, and pipeline

### 12.1 Compressed radix router (`server/router.goose`)
- Zero-allocation parameter extraction: `ZeroAllocParams` records stack-allocated slice spans (`u8[:]`) referencing parameter tokens without allocating strings.
- Insertion-order independence: `{id}.json` and `{id}/comments.json` route the same way in any registration order (fix for `matchit` issue #83, commit `f607f73`).
- Static route precedence: Exact static paths take precedence over parametric or wildcard subtrees.
- Automatic 405 Method Not Allowed: Returns `405` with an `Allow` header that lists the registered methods.

### 12.2 Tako v2 connection pool (`server/pool.goose`)
Isolated within `namespace internal;`:
- `HeaderMapPool`: Reuses pre-allocated 8 KB flat-buffer header structures across keep-alive connections.
- `ExtensionsPool`: Slabs for request-scoped metadata, sanitized on release so data does not carry over between requests.
- `SyncHeadRelease`: Zero-copy handoff of connection heads to worker threads.
- `InlineHandlerFuture`: Stack-allocated task completion states avoiding promise/future heap allocations.
- `ConnectionTimer`: Slowloris sweeper tracking connection activity and dropping stalled clients.

## 13. Buffer limits and edge cases

| Type | Limit | Behavior when the limit is exceeded |
| :--- | :--- | :--- |
| `HeaderMap` Dynamic Entries | 64 slots | Rejects subsequent headers fail-closed (`false`). |
| `HeaderMap` Inline Static Slots | 64 slots | $O(1)$ lookup for canonical well-known headers (`Host`, `User-Agent`, etc.). |
| `HeaderItem.name` | 128 bytes | Truncated or rejected during lexical parsing. |
| `HeaderItem.value` | 2048 bytes | Values $> 2\text{ KB}$ rejected with 431 Request Header Fields Too Large. |
| `UrlView` & URL Buffers | 2048 bytes | URLs $> 2048$ bytes return `UrlParseError.UrlTooLong`. |
| Cookie Payload (`name + value`) | 4096 bytes | `Set-Cookie` line rejected without insertion. |
| Cookie Attribute | 1024 bytes | Attribute ignored; defaults apply (e.g. default path `/`). |
| Multipart Boundary | 70 bytes (RFC 2046) | Boundaries $> 70$ characters rejected (CVE-2026-19484). |
| HTTP Range Intervals | 16 ranges | Rejects $> 16$ ranges with 416 Range Not Satisfiable (CVE-2011-3192). |
| Chunked Trailers | 16 headers, 4096 bytes | Parsing aborts with a framing error. |
| HTTP/2 Continuous Headers | 65,536 bytes | Continuation lock terminates connection with `PROTOCOL_ERROR` (CVE-2024-27983). |
| HTTP/2 Rapid Reset Burst | 100 resets / sec | Triggers `GOAWAY` with `ENHANCE_YOUR_CALM` (CVE-2023-44487). |
| Singleflight Key | 64 bytes | Keys longer than 64 bytes are truncated. |
| BatonMutex Reentrancy | Non-reentrant | Locking an already held mutex deadlocks; caller must release before reacquiring. |
| SOCKS5 Destination Host | 255 bytes (RFC 1928) | Hostnames $> 255$ bytes return address error. |
| DPoP Clock Skew | $\pm 60$ seconds | Rejects proofs with timestamps outside valid window. |
| JWT Leeway | Configurable (default 60 s) | Permits clock drift when evaluating `exp` and `nbf`. |
| Brotli Max Output Decompress | User-configured budget | Decompression terminates if output exceeds quota (decompression bomb). |
