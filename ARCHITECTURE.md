# Architecture

`goose-wing` is a networking and HTTP engine written in Goose with platform C shims. It consists of two top-level namespaces: `core` (`core.goose`) and `wing` (`wing.goose`).

## Memory and execution model

Wire parsing and serialization routines do not allocate on the heap (`[>..]`). Subsystems store state in fixed-capacity inline buffers (`u8[..N]`, `HeaderMap`) allocated on the stack or embedded inside session structs. Parsers accept borrowed byte slices (`const u8[:]`) and return typed structs paired with an error enum or boolean status.

Raw network bytes are validated once at the ingress boundary: the L4 socket driver, the TLS 1.3 record framer, or the HTTP frame decoder. Internal state machines operate on validated structs without repeating bounds checks.

## Module layout

`core.goose` exports foundational utilities used across all protocol layers:

- `core/bytes/`: byte slice searching, ASCII case folding, integer formatting, and base encodings.
- `core/math/` and `core/time/`: wrapping arithmetic, monotonic clocks, and RFC 9110 HTTP date parsers.
- `core/compress/`: streaming codecs for Zstandard, Brotli (RFC 7932 and RFC 9842 dictionary compression), Gzip, Deflate, and Zlib.
- `core/crypto/`: SHA-2, HMAC, HKDF, ChaCha20-Poly1305, XChaCha20-Poly1305, X25519, and Ed25519 primitives.
- `core/url/`: RFC 3986 URI parser and percent-encoding normalizer.
- `core/io/`, `core/sync/`, and `core/ufcs/`: stream traits, atomic synchronization, and fixed-buffer extension methods (`try_push`, `try_append`).

`wing.goose` assembles the transport and application protocols:

- `shim/`: C11 platform shims (`rio.c` for Windows Registered I/O, `uring.c` for Linux `io_uring`, `kqueue.c` for macOS, `af_xdp.c`, `smartnic.c`, `tcp.c`, and AVX2/NEON routines in `simd.c`).
- `net/`: L4 transport driver, non-blocking event poller, nanosecond tick timer wheel, Happy Eyeballs v2 (RFC 8305), SOCKS5/SOCKS5h and HTTP CONNECT proxies, HAProxy PROXY protocol v1/v2, DNS cache, and MASQUE tunnels.
- `tls/`: TLS 1.3 record layer and handshake state machine (RFC 8446), X.509 ASN.1 DER parser, HPKE (RFC 9180), Encrypted Client Hello (ECH), Zstd certificate compression (RFC 8879), and hybrid ML-KEM-768 key exchange.
- `quic/`: RFC 9000 packet codec, ACK frame tracker, and BBR v1/v2 congestion control.
- `http/`: HTTP/1.1 SWAR header tokenizer (`HeaderMap` with 64 static and 64 dynamic slots), chunked transfer coding FSM, multipart parser, RFC 9111 HTTP cache (`http/cache/`), Alt-Svc, HSTS, Early Hints, HTTP Message Signatures (RFC 9421), and resumable uploads.
- `http2/`: RFC 9113 9-byte frame codec, RFC 7541 HPACK encoder and 256-state Huffman decoder, stream flow control, and priority scheduler.
- `http3/`: RFC 9114 frame codec, RFC 9204 QPACK encoder/decoder, and H3 connection state machine.
- `cookie/`: RFC 6265bis storage engine, Mozilla Public Suffix List matcher, CHIPS partitioned cookies, and 6-round eviction policy.
- `security/` and `auth/`: `CryptoJar` authenticated cookie encryption, W3C Fetch Metadata CSRF guard, CORS policy evaluator, GCRA rate limiter, Privacy Pass (RFC 9576–9578), Digest auth, PKCE, DPoP (RFC 9449), JWT, and JWKS.
- `fingerprint/`: JA4 TLS client fingerprinting, p0f TCP signature analysis, and Akamai HTTP/2 fingerprint generation.
- `wire/`: Two-tier Vulkan-style pipeline skeleton: Tier 1 Sans-IO wire framing codecs (`wire/h1.goose`, `wire/hpack.goose`, `wire/h2.goose`, `wire/h3.goose`) decoding directly into `HeaderMap`, `WireCommandBuffer` / `WireQueue` transport submission (`wire/cmd.goose`, `wire/submit.goose`), and Tier 2 composable L7 `WirePipeline` stage bitmasks and `StageVerdict` combinators (`wire/pipeline.goose`).
- `client/`: connection pool, redirect policy, 3-tier SSRF guard, replay protection, composable L7 client stages (`client/session/stages.goose`), request/response interceptors, and retry backoff.
- `server/`: compressed radix trie router (`ZeroAllocParams`), Tako v2 connection pool, composable L7 server pipeline (`server/pipeline.goose`), and HTTP/2 server frame multiplexer.
- `realtime/` and `grpc/`: RFC 6455 WebSocket codec with 64-bit XOR masking, OASIS MQTT-style `TopicTree` pub/sub router, Server-Sent Events (SSE), WebTransport over H3, and gRPC / gRPC-Web length-prefixed framing.

## Request and response data flow

On the client path, `client/session/exec.goose` orchestrates the composable L7 stage pipeline (`client/session/stages.goose`) controlled by `Client.pipeline` (`wire::WirePipeline`). Ingress stages validate the target URL through `client/session/ssrf.goose`, apply Alt-Svc and HSTS upgrades, load matching cookie indices (`u16[..180]`), check `http/cache/engine.goose`, negotiate compression dictionaries, and acquire a socket from `net/pool.goose`. Outbound headers in `Request.headers: HeaderMap` are framed via `wire/` codecs (`wire::encode_h1_request`, `wire::encode_h2_headers_from_map`, `wire::encode_h3_headers_from_map`) and flushed over `Transport` (`wire/submit.goose`).

On the server path, `net/poller.goose` dispatches readiness events from `io_uring`, `kqueue`, or Windows RIO to `server/server.goose` and `server/reactor.goose`. Incoming bytes pass through the HTTP/1.1 lexical scanner (`http/headers/lexical.goose`), the HTTP/2 multiplexer (`server/h2_multiplexer.goose`), or the HTTP/3 connection coordinator (`http3/connection.goose`), populating `Request.headers: HeaderMap`. `server/pipeline.goose` executes the bitmask-configured L7 ingress and egress stage bricks (`stage_server_*`) around `server/router.goose` and writes the framed response back via `wire/`.
