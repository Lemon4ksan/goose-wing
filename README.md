# goose-wing

An HTTP client stack, zero-allocation time primitives, and Chromium-grade CookieMonster implementation for the [Goose](https://github.com/goose-lang/goose) programming language.

`goose-wing` provides application-layer networking components designed around Goose's memory model: bounded inline storage, explicit growth vectors, UFCS ergonomics, and zero unexpected runtime allocations.

## Overview

The library is organized into ten architectural layers:

1. **`core/time.goose`**: Nanosecond-precision calendar and monotonic time engine based on Howard Hinnant's civil calendar algorithms. Includes RFC 3339, RFC 9110 HTTP-Date codecs, Go-compatible `parse_duration`, monotonic `Stopwatch`, and anti-overflow `Deadline`.
2. **`cookie/`**: Clean-room implementation of Chromium's `net::CookieMonster` adhering to RFC 6265, RFC 6265bis, the Layered Cookies draft, CHIPS (partitioned cookies), and Public Suffix List rules.
3. **`http/`**: High-performance zero-heap HTTP stack:
   - `http/headers.goose`: Continuous Chromium `\0\0` flat buffer, 64-bit SWAR vectorized tokenization, 16-byte `HeaderEntry`, 64 O(1) inline slots for `WellKnownHeader`, RFC 9110 §5.3 / RFC 6265bis Set-Cookie fold isolation (`HEADER_FLAG_NO_COMMA_FOLD`), Chromium 304 merge, and HTTP cache persistence filtering.
   - `http/mime.goose`: Chromium-grade `HttpUtil::StrictUnquote` parser, RFC 9110 §8.3 Media Type parser, RFC 6266 / RFC 7578 Content-Disposition parser, and Structured Field Values (SFV) engine per RFC 8941 & RFC 9651 (`sf-integer`, `sf-decimal`, `sf-string`, `sf-token`, `sf-binary`, `sf-boolean`, `sf-date`, `sf-displaystring`, lists, and dictionaries).
   - `http/multipart.goose`: Streaming zero-copy `multipart/form-data` parser with 70-character RFC 2046 boundary cap and 16-bit BMH shift table (CVE-2026-19484 defense), RFC 9110 Range request parser with 16-range ceiling and interval coalescing (CVE-2011-3192 Apache Killer defense), 416 Range Not Satisfiable generator, sub-second `If-Range` truncation, and `serve_range_request` window reader.
4. **`core/url.goose` & `client/redirect.goose`**: WHATWG URL parser with continuous memory buffer, RFC 5952 IPv6 zero-run compression, Swift Foundation-grade File URL and path manipulation API (cross-platform Windows/POSIX path normalization, component inspection, and fluent UFCS chaining), `Origin` model (`Tuple` vs `Opaque`), and a deterministic HTTP Redirect State Machine (`net::RedirectInfo`) defending against CVE-2023-45143, CVE-2024-1968, CVE-2026-55553, and CVE-2026-64684.
5. **`client/`**: User-Agent Client coordinator (`Client`) orchestrating a Chromium-grade pipeline over `CanonicalCookieJar` and integrated RFC 9111 HTTP Cache (`HttpCache`), with `BodyRewind` (Request.GetBody), 3-tier SSRF/DNS Rebinding guards, browser profiles (Chrome 131, Firefox 133, Safari 18), and resilience policies.
6. **`security/`**: High-performance zero-allocation application security:
   - `security/ct.goose`: Branchless constant-time arithmetic (`ct_eq`, `ct_select`), log-redacting `KeySlot` (`secrecy` pattern), Dudect statistical Welch's $t$-test runner with outlier filtering ($>2000\,\text{ns}$), pure-Goose zero-dependency crypto (NIST SHA-256, RFC 4231 HMAC-SHA256, RFC 5869 HKDF-SHA256, RFC 8439 ChaCha20/HChaCha20/Poly1305, XChaCha20-Poly1305 AEAD, AES-256 block cipher, GHASH, AES-256-GCM AEAD, RFC 4648 Base64URL).
   - `security/crypto_jar.goose`: Cryptographic cookie container (`PrivateJar` with 53B/65B overhead and AAD binding + `SignedJar` with 45B overhead + `KeyStore` rotation).
   - `security/csrf.goose`: W3C Fetch Metadata resource isolation policy $\pi_{FM}(r) = (\sigma, \mu, \delta, u, m)$ covering the 9-row decision matrix (Go 1.25 `net/http.CrossOriginProtection` + Better Auth), fail-closed cookie gate, and mandatory `Vary` / HSTS header injection.
   - `security/cors.goose`: Strict protocol-specific CORS engine with origin matching, wildcard credentials rejection, preflight/actual CORS verification.
   - `security/rate_limiter.goose`: GCRA Rate Limiter with virtual scheduling TAT on monotonic time, fixing `governor` Issue #16 multi-cell starvation via priority slot reservation (`gcra_reserve_n`), 256-micro-shard hash table (`ShardedGcraLimiter`), 5% probabilistic DDoS sampling, and IETF `RateLimit-*` headers.
7. **`server/`**: Zero-allocation routing and high-throughput connection pool:
   - `server/router.goose`: Compressed Radix Trie with `ZeroAllocParams`, strict insertion-order independence (fixing `matchit` Issue #83 / commit `f607f73`), static route precedence, multi-method isolation, automatic `405 Method Not Allowed` with `Allow` header generation.
   - `server/pool.goose`: Tako v2 6-mechanism connection pool (`HeaderMapPool`, sanitized `ExtensionsPool`, bitmask flags, `SyncHeadRelease`, `InlineHandlerFuture`, `ConnectionTimer` Slowloris sweep).
   - `server/pipeline.goose`: Unified ascending-complexity server pipeline ($O(1) \to O(k) \to O(\log N) \to \text{Handler}$).
8. **`core/test.goose`**: Zero-allocation testing framework featuring compile-time structural diffing, table-driven runners, high-resolution `MockClock`, and a deterministic Xorshift64* property fuzzer.
9. **`net/`**: Resilient Network Transport, Connection Pooling & Multi-Protocol Proxying:
   - `net/pool.goose`: 5-dimensional `PoolKey` (`scheme`, `origin_endpoint`, `proxy_chain`, `partition_key` / `NetworkAnonymizationKey`, `tls_and_dns_policy`), two-slice `WantQueue` (Go `wantConnQueue` zero-reallocation dual-slice design), OkHttp `RealConnection.isHealthy` non-blocking FIN detection, HTTP/2 IP connection coalescing with wildcard SAN, soft-cap LRU eviction, and RespectLimits mode.
   - `net/happy_eyeballs.goose`: RFC 8305 Happy Eyeballs v2 & HEv3, Chromium `AttemptManager` & `JobController`, 50 ms DNS Resolution Delay (RD) with asymmetric IPv6 priority, CAD pacing with $\ge 10\text{ ms}$ absolute floor, RFC 6724 First Address Family Count = 1 interleaving, Last Resort Local Synthesis (2000 ms, RFC 7050 NAT64 `64:ff9b::/96`), and winner caching (TTL 600s).
   - `net/proxy.goose`: SOCKS5/SOCKS5h (RFC 1928 & RFC 1929 subnegotiation with mandatory version byte 0x01, socks5 vs socks5h ATYP=0x03 DNS leak delegation), HTTP CONNECT tunneling with credential stripping (`Proxy-Authorization` isolation), OkHttp leftover buffer defense (`"TLS tunnel buffered too many bytes"`), and 4-tier Slowloris / Reverse-Slowloris tarpit defenses (10s monotonic cumulative deadline, 1s 100-continue ceiling, 64 KB memory ceiling, 256 B/s Byte-Drip gate).
   - `net/retry.goose`: Two-tier resilience engine: Tier 1 zero-delay stale socket recovery with 4-condition invariant check (`reused==true`, `!headers_received`, idempotent or `Idempotency-Key`, rewindable body guarding against form-data one-shot-stream bug) + Chromium `ERR_QUIC_PROTOCOL_ERROR` TCP fallback; Tier 2 exponential backoff with Full Jitter, Equal Jitter, and Decorrelated Jitter; RFC 9110 `Retry-After` parser (`1*DIGIT` and `IMF-fixdate` exact UTC round-trip); host circuit breaker; and Google SRE adaptive retry budget.
10. **`http2/`**: Clean Room Reference HTTP/2 Protocol Stack (RFC 7541, RFC 9113, RFC 9218):
   - `http2/hpack.goose`: 256-state 16 KiB L1 cache nibble Huffman FSM, zero-heap ring-buffer dynamic table with in-place compaction, Trail of Bits FIND-401 integer shift guard (CVE-2022-41723), RFC 9113 pseudo-header ordering and duplicate/content-length verification (CVE-2026-78660).
   - `http2/framing.goose`: RFC 9113 9-byte binary frame codec, PADDED extraction, RFC 9218 Structured Field extensible prioritization dictionary codec (`u=0..7, i`), PRIORITY_UPDATE payload codec, and SETTINGS boundary validation.
   - `http2/connection.goose`: Multiplexed transport connection (`H2Connection`), signed 64-bit two-level flow control (supporting negative stream windows on initial window shrink), RFC 9218 progressive write scheduler (8 urgency levels with alternating starvation prevention), and defense-in-depth Anti-DoS engine (Rapid Reset Token Bucket CVE-2023-44487, CONTINUATION flood/size/slow-drip limiters CVE-2024-28182/CVE-2024-27983, empty frame streak cap CVE-2019-9518, control frame quota CVE-2019-9512/CVE-2019-9515).

## Key Modules

### 1. Canonical Cookie Engine (`cookie/`)

Implements the complete semantics of Chromium's `CookieMonster`:

- **Quotas & Parsing**: 4096-byte payload cap (`name + value`), 1024-byte per-attribute limit, 33-byte ASCII CTL character rejection, and nameless cookie support (`=value` and value-only strings per WPT).
- **Domain & PSL Logic**: eTLD+1 boundary extraction, localhost/IPv4/IPv6 address normalization, and protection against public suffix cookie injection.
- **Layered Prefixes**: Strict enforcement for `__Secure-`, `__Host-`, `__Http-`, and `__Host-Http-`.
- **SameSite & Incrementalism**: `Strict`, `Lax`, `None`, and default `Lax` with the 120-second Lax-allowing-unsafe window for top-level `POST` requests.
- **CHIPS (Partitioning)**: Partition-keyed isolation with 10 KB per-partition byte budget enforcement.
- **6-Round Garbage Collection**: Matches Chromium's asymmetric eviction policy (Round 4 domain cookies before host cookies, Round 5 host cookies, Round 6 global eviction) and respects the 30-day purge immunity window.
- **Persistence Store**: SQLite-compatible schema (v24), write-back batching with coalescing, 60-second access time throttling, and constant-time comparison against timing attacks.

### 2. Time & Calendar (`core/time.goose`)

Zero-heap timekeeping and date calculations:

- **Calendar Math**: Hinnant algorithms for conversion between proleptic Gregorian calendar dates and Unix epoch timestamps without lookup tables.
- **Durations**: Full arithmetic (`+`, `-`, `*`, `/`), comparisons, signs (`zero`, `positive`, `negative`), truncation, and rounding.
- **Parsing**: Go-compatible `parse_duration` supporting composite units (`1h30m45s`), decimal fractions (`-2.5s`), and overflow protection.
- **Formatting**: RFC 3339 (with sub-second fractional precision), IMF-fixdate / RFC 1123, RFC 850, and asctime formats per RFC 9110 §5.6.7.
- **Resilience**: Monotonic `Stopwatch`, deadline checking with `deadline_after(dur)`, token-bucket `RateLimiter`, and exponential `Backoff` with jitter.

### 3. WHATWG URL, PSL, File URLs & Redirect FSM (`core/url.goose`, `client/redirect.goose`)

Browser-grade URL parsing, Swift-like path manipulation, origin isolation, and redirect state machine:

- **WHATWG URL Parser**: Single continuous byte buffer with compact offset indices (ada-url / sorug pattern), default port stripping, dot-segment collapsing (`/a/b/../c` -> `/a/c`), and relative base resolution.
- **Swift-Style File URLs & Paths**: First-class support for file paths with bidirectional normalization:
  - `new_file_url(path)`: Normalizes Windows drive letters (`C:\...` -> `file:///C:/...`, spaces -> `%20`), POSIX paths (`/var/log/...`), and Windows UNC shares (`\\nas\share` -> `file://nas/share`).
  - `file_path(url, out)`: Decodes `%20`, drops leading slashes before drive letters, and maps separators back to native OS backslashes (`C:\...`).
  - **Component Inspection**: `last_path_component(url)` (ignoring trailing slashes) and `path_extension(url)` (correctly identifying extensions like `.tar.gz` while ignoring hidden files like `.gitignore`).
  - **Mutations & Navigation**: `deleting_last_path_component` (parent directory), `deleting_path_extension`, `appending_path_component`, `appending_path` (multi-segment subpaths), and `appending_path_extension`.
  - **Fluent UFCS Chaining**: `base.appending("build").appending("bin").appending_path_extension("exe")`.
- **IPv6 RFC 5952 Compression**: Deterministic zero-run compression finding the longest leftmost run of zeros (`[2001:db8::ff00:42:8329]`, `[::1]`) and IPv4-mapped IPv6 normalization.
- **Origin Model**: Strict differentiation between `Tuple` (`scheme://host:port`) and `Opaque` (monotonic random nonces), with cross-origin serialization to `"null"`.
- **Mozilla PSL Scoping**: Full rule matching (Normal, Wildcard `*.`, Exception `!`) with ICANN vs Private tenant isolation (e.g. `foo.github.io` cannot share state with `bar.github.io`).
- **Redirect State Machine (`RedirectInfo`)**: Deterministic pure function transitions per RFC 9110 and WHATWG Fetch §4.5:
  - Method mutation: `POST` -> `GET` on 301/302, non-GET/HEAD -> `GET` on 303 (with payload header stripping: `Content-Type`, `Content-Length`, `Transfer-Encoding`).
  - Method preservation: `POST` stays `POST` on 307/308 with body preservation.
  - Sensitive header stripping: Purges `Authorization`, `X-API-Key`, `X-Auth-Token`, `X-Access-Token` on cross-origin hops or HTTPS -> HTTP downgrades (defending against CVE-2024-1968, CVE-2026-55553, CVE-2026-64684).
  - Cookie stripping: Outgoing `Cookie` header is unconditionally stripped before every redirect hop to prevent session hijacking across domains (CVE-2023-45143).
  - Monotonic chain tainting: Any cross-site hop permanently marks `had_cross_site_hop` to prevent SameSite bypasses.

### 4. User-Agent Client & Security Orchestration (`client/`)

Unified HTTP client ergonomics and defense-in-depth pipeline:

- **6-Phase Execution Pipeline**: Executes requests over `CanonicalCookieJar` with automatic SameSite context evaluation, fresh cookie header synthesis, response Set-Cookie ingestion before 3xx handling, and hop sanitization.
- **BodyRewind Engine**: Implements the Go `Request.GetBody` pattern: rewindable buffered bodies are seamlessly resent on 307/308 redirects, while unrewindable streams fail cleanly with `RedirectError.UnrewindableBodyStream`.
- **3-Tier SSRF & DNS Rebinding Guard**:
  - Tier 1: Hostname validation against loopback (`127.0.0.1`, `[::1]`, `localhost`).
  - Tier 2: IP subnet blacklisting against RFC 1918 private addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local, and cloud metadata services (`169.254.169.254`).
  - Tier 3: DNS Rebinding sweep over all resolved socket IPs before network connection.
  - Dangerous service port filtering (SSH, Redis, SMTP, etc.).
- **Browser Profiles**: Preconfigured header baselines (`User-Agent`, `Accept`, `Sec-CH-UA`, `Sec-Fetch-*`) simulating Chrome 131, Firefox 133, Safari 18, and cURL.

### 5. HTTP Engine: Zero-Heap Headers, MIME, SFV & Streaming Multipart (`http/`)

Zero-allocation HTTP/1.x, HTTP/2, and HTTP/3 application primitives:

- **Zero-Heap HeaderMap (`http/headers.goose`)**:
  - **Memory Layout**: Flat 8 KB continuous byte buffer (`raw_buf`) with embedded `\0\0` termination (Chromium `raw_headers_` model) and 128 compact 16-byte `HeaderEntry` records (`name_begin`, `name_end`, `values_begin`, `values_end`, `next_idx`, `flags`, `well_known_id`, `name_hash`).
  - **O(1) Inline Header Slots**: 64 compile-time slots (`inline_slots[64]`) for instant zero-hash lookups of canonical HTTP headers (`content-type`, `authorization`, `set-cookie`, `host`, `user-agent`, etc.).
  - **Vectorized Tokenization (SWAR)**: 64-bit SIMD Within A Register routines (`swar_has_zero_byte`, `swar_has_byte`, `swar_has_ctl_or_del`) for rapid scanning of delimiters and illegal control characters.
  - **RFC 9110 §5.3 / RFC 6265bis Isolation**: Strict `HEADER_FLAG_NO_COMMA_FOLD` isolation preventing folding of `Set-Cookie` or `WWW-Authenticate` into comma-separated lines.
  - **Security & Regressions**: Defense against httparse PR #223 (whitespace-only lines cause clean syntax error), `obs-fold` line folding, Chromium 304 cache header merging, and HTTP cache persistence bitmask filtering.
  - **Connection Recycling**: Instant `reset_for_keep_alive()` zeroing indices and preserving pre-allocated buffer capacity across keep-alive connections.

- **MIME & Structured Field Values (`http/mime.goose`)**:
  - **Chromium `HttpUtil::StrictUnquote`**: Validates quoted strings per Chromium security invariants (rejects single quotes, trailing unescaped slashes, unclosed quotes, and correctly preserves double-escaped slashes `\\` as single `\`).
  - **RFC 9110 §8.3 Media Type & RFC 6266 / RFC 7578 Content-Disposition**: Robust parameter parsing with case-insensitive token folding and strict whitespace stripping.
  - **RFC 8941 & RFC 9651 SFV Engine**: Complete structured header codec supporting `sf-integer`, fixed-point `sf-decimal` (milliths scaled by $10^3$), `sf-string`, `sf-token`, `sf-binary` (base64), `sf-boolean`, `sf-date` (`@<epoch>`), and `sf-displaystring` (`%"` UTF-8).
  - **SFV Invariants**: Hard failure on uppercase dictionary keys per RFC 8941 §3.1.2, in-place dictionary mutation, and inner lists with item parameters.

- **Streaming Multipart & Range Engine (`http/multipart.goose`)**:
  - **Boundary Validation (CVE-2026-19484 Barrier 1)**: Strict enforcement of RFC 2046 §5.1.1 70-character boundary length limit, stopping allocation bomb attacks prior to buffer allocation.
  - **Boyer-Moore-Horspool Search (CVE-2026-19484 Barrier 2)**: 16-bit shift table (`u16[256]`) guaranteeing forward progress and $O(N)$ streaming search.
  - **Lookbehind Streaming Buffer**: Trailing window retention (`boundary.len + 4`) to seamlessly resume parsing when boundary delimiters span across network packet chunks.
  - **RFC 9110 Range Parser & Coalescing (CVE-2011-3192 Defense)**: Hard ceiling of 16 ranges (defending against Apache Killer algorithmic DoS) and automatic coalescing of overlapping ($s_2 \le e_1$) and contiguous ($s_2 = e_1 + 1$) range slices.
  - **Sub-Second `If-Range` Truncation**: RFC 9110 compliant validator truncating validator dates to 1-second precision before comparisons.
  - **Higher-Order Window Reader (`serve_range_request`)**: Unified zero-copy range slice emitter with trailing closure execution.

### 6. Testing Framework (`core/test.goose`)

A standalone test library designed for Goose:

- **Assertions**: `assert_eq`, `assert_bytes_eq`, `assert_struct_eq`, `assert_true`, `assert_in_delta`, `assert_contains`, plus terminating `require_*` variants.
- **Virtual Mock Clock**: `new_mock_clock(initial_us)` for time-travel testing with `advance_sec`, `advance_ms`, and `advance_days`.
- **Property Fuzzer**: Zero-allocation Xorshift64* PRNG (`new_fuzz_rng`) for randomized invariant testing.

### 7. Cryptography & CryptoJar (`security/ct.goose`, `security/crypto_jar.goose`)

High-performance zero-dependency cryptographic foundation and tamper-proof cookie jar:

- **Branchless Constant-Time Math**: `ct_eq`, `ct_select`, and `ct_is_zero` preventing compiler-introduced timing side-channels.
- **Log-Redacted Secret Storage (`KeySlot`)**: Rust `secrecy` pattern redacting private keys from memory dumps and log output (`display_redacted`), bound to zeroize-on-drop semantics.
- **Dudect Statistical Harness**: High-resolution Welch's $t$-test runner with outlier filtering ($>2000\,\text{ns}$) proving $|t| < 4.5$ hypothesis under 10,000+ trial iterations.
- **Pure-Goose Cryptographic Primitives**:
  - NIST SHA-256 and RFC 4231 HMAC-SHA256 with bitwise state rotation.
  - RFC 5869 HKDF-SHA256 (Extract & Expand) key derivation.
  - RFC 8439 ChaCha20, HChaCha20, Poly1305, and XChaCha20-Poly1305 AEAD with 192-bit nonces (immune to random nonce collisions).
  - AES-256 Block Cipher and GHASH Galois Field multiplier over $GF(2^{128})$ powering AES-256-GCM AEAD.
  - RFC 4648 Base64URL encoder/decoder without padding.
- **CryptoJar**:
  - **`PrivateJar`**: Encrypted + authenticated cookie container with cookie name bound in Additional Authenticated Data (AAD), defending against cross-cookie swapping attacks. Supports XChaCha20-Poly1305 (53B overhead) and AES-256-GCM (65B overhead).
  - **`SignedJar`**: HMAC-SHA256 signed tamper-evident container with 45B overhead.
  - **`KeyStore`**: Seamless key rotation supporting active primary key and fallback retired verification keys.

### 8. Resource Isolation: CSRF & CORS (`security/csrf.goose`, `security/cors.goose`)

Stateless deterministic defense-in-depth resource isolation:

- **W3C Fetch Metadata Resource Isolation Policy $\pi_{FM}(r) = (\sigma, \mu, \delta, u, m)$**:
  - Complete 9-row decision matrix combining Go 1.25 `net/http.CrossOriginProtection` and Better Auth semantics.
  - Granular `Sec-Fetch-Site` inspection (`same-origin`, `same-site`, `none`, `cross-site`, `missing`).
  - Safe-list top-level navigations (`Sec-Fetch-Mode: navigate` with GET/HEAD) defending against CSRF while allowing external links.
  - Fail-closed cookie gate: strictly rejects cross-site state-changing requests before payload decryption or session access.
  - Mandatory response header injection: `Vary: Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest` and `Strict-Transport-Security`.
- **Protocol-Specific CORS Engine**:
  - Strict scheme-host-port matching avoiding insecure wildcard origins (`*`) when credentials are requested.
  - Fast-path preflight `OPTIONS` short-circuiting with maximum cache age (`Access-Control-Max-Age`).

### 9. GCRA Rate Limiter (`security/rate_limiter.goose`)

Mathematical Generic Cell Rate Algorithm (GCRA) traffic shaper:

- **Virtual Scheduling Model**: Tracks Theoretical Arrival Time ($TAT$) on monotonic nanosecond clocks: $TAT \leftarrow \max(t, TAT) + T$.
- **Anti-Starvation Multi-Cell Priority Reservation (`gcra_reserve_n`)**: Fixes `governor` Issue #16 where bulk requests starve under continuous small requests by atomically reserving future execution slots.
- **256-Micro-Shard Table (`ShardedGcraLimiter`)**: Low-overhead lock-free CAS emulation with deterministic FNV-1a distribution for multi-million ops/sec throughput.
- **5% Probabilistic DDoS Sampling**: High-load bypass reducing hash table pressure by 95% during volumetric attack floods.
- **IETF RFC Standard Headers**: Synthesizes `RateLimit-Limit`, `RateLimit-Remaining`, and `RateLimit-Reset` compliant headers.

### 10. High-Performance Radix Router & Tako v2 Server Pool (`server/`)

Zero-allocation HTTP request routing and server lifecycle management:

- **Compressed Radix Trie (`server/router.goose`)**:
  - `ZeroAllocParams`: Fixed-capacity parameter extraction storing 0-byte slice references on the stack without heap allocation.
  - Insertion Order Independence: Solves `matchit` Issue #83 / commit `f607f73` ensuring `{id}.json` and `{id}/comments.json` yield identical routing regardless of insertion order.
  - Static Route Precedence: Always prioritizes exact static matches over parameterized or wildcard nodes.
  - Multi-Method Isolation: HTTP-method-specific route tables generating RFC-compliant `405 Method Not Allowed` with dynamically built `Allow` headers.
- **Tako v2 6-Mechanism Connection Pool (`server/pool.goose`)**:
  - `HeaderMapPool`: Flat-buffer header recycling avoiding per-request allocations.
  - `ExtensionsPool`: Request extensions pool with strict sanitization on release preventing inter-request memory leaks.
  - Bitmask Flags (`ENTRIES`): Bitwise tracking of active and recycled structures.
  - `SyncHeadRelease`: Immediate zero-copy pipeline handoff.
  - `InlineHandlerFuture`: Stack-allocated request completion futures.
  - `ConnectionTimer`: Slowloris attack sweeper terminating idle and hung connections.
- **Unified Server Pipeline (`server/pipeline.goose`)**: Ascending computational complexity pipeline ($O(1) \to O(k) \to O(\log N) \to \text{Handler}$).

### 11. Resilient Network Transport, Connection Pool & Multi-Protocol Proxying (`net/`)

Clean-room industrial network transport implementing Chromium and Go primitives:

- **Connection Pool & Partitioning (`net/pool.goose`)**:
  - **5-Dimensional `PoolKey`**: Strict isolation over `scheme`, `origin_endpoint` (`host:port`), `proxy_chain`, `partition_key` (`NetworkAnonymizationKey` covering `top_frame_site`, `is_cross_site`, `nonce`, `network_isolation_partition`, and `worker_session_id`), and `tls_and_dns_policy` (`privacy_mode`, `secure_dns_policy`, cert flags, and `target_network_id`).
  - **Two-Slice `WantQueue`**: Zero-reallocation dual-slice queue (`head`, `head_pos`, `tail`) matching Go `wantConnQueue` performance.
  - **OkHttp Liveness Checks (`is_connection_healthy`)**: Tracks monotonic `idle_at_ns`; performs non-blocking `source_exhausted` (`MSG_PEEK | MSG_DONTWAIT`) checks when idle beyond `IDLE_CONNECTION_HEALTHY_NS`, evicting dead sockets prior to request dispatch.
  - **HTTP/2 IP-Based Coalescing**: Dynamically reuses existing HTTP/2 TLS connections to matching IP addresses when TLS certificate SAN covers the target hostname and partition/proxy policies match.
  - **Soft-Cap Quotas & Priority Reuse**: Enforces per-group, per-proxy-chain, and global soft caps with LRU eviction of oldest idle connections, adhering to OkHttp #7186 pooled reuse priority.

- **Happy Eyeballs v2/v3 Engine (`net/happy_eyeballs.goose`)**:
  - **RFC 8305 & HEv3 Racing**: Chromium `AttemptManager` state machine coordinating `main_job`, `alternative_job` (Alt-Svc H3), and `dns_alpn_h3_job`.
  - **Phase 1 DNS Race & 50 ms Resolution Delay (RD)**: Prioritizes IPv6 (AAAA); arms a 50 ms RD timer if IPv4 (A) arrives first, cancelling immediately if AAAA arrives or unblocking IPv4 on timeout.
  - **RFC 6724 Interleaving**: First Address Family Count = 1 interleaving ($\text{IPv6}_1 \to \text{IPv4}_1 \to \text{IPv6}_2 \to \text{IPv4}_2$) and HEv3 QUIC/TCP interleaving.
  - **Connection Attempt Delay (CAD)**: 250 ms default pacing with dynamic RTT bounds and strict absolute floor $\ge 10\text{ ms}$ preventing congestion collapse.
  - **Last Resort Local Synthesis**: 2000 ms timer triggering RFC 7050 NAT64 synthesis (`64:ff9b::/96`).

- **Multi-Protocol Proxying & Slowloris Defenses (`net/proxy.goose`)**:
  - **Byte-Exact SOCKS5 / SOCKS5h (RFC 1928 & RFC 1929)**: Phase 1 greeting negotiation; Phase 2 subnegotiation with mandatory version byte `0x01`; Phase 3 command with `ATYP = 0x03` domain routing for `socks5h://` eliminating client DNS leaks; Phase 4 complete BND.ADDR consumption.
  - **HTTP CONNECT Tunnel Hygiene**: Strips `Proxy-Authorization` from outgoing origin requests; enforces OkHttp leftover buffer defense (`"TLS tunnel buffered too many bytes"`), aborting on prefix injection attacks.
  - **4-Layer Slowloris Tarpit Defenses**: Monotonic cumulative header deadline (10s non-resetting), 1s `Expect: 100-continue` timeout, 64 KB header memory ceiling, and 256 B/s Byte-Drip gate.

- **Two-Tier Resilience & Retry Engine (`net/retry.goose`)**:
  - **Tier 1 Zero-Delay Stale Socket Recovery**: Evaluates 4 mandatory conditions (`reused == true`, `!headers_received`, idempotent method or `Idempotency-Key`, rewindable body), preventing the form-data one-shot-stream retry bug; automatic Chromium `ERR_QUIC_PROTOCOL_ERROR` TCP fallback.
  - **Tier 2 Exponential Backoff & Jitter**: Full Jitter ($s_a = \mathcal{U}(0, \min(c, b \cdot 2^a))$), Equal Jitter ($t/2 + \mathcal{U}(0, t/2)$), and Decorrelated Jitter.
  - **RFC 9110 `Retry-After` Parser**: Strictly parses `1*DIGIT` (delay-seconds) and `IMF-fixdate` with exact UTC calendar round-trip validation; past dates clamp to 0 ms; ceiling rounding for sub-second deltas.
  - **Circuit Breaker & Adaptive Retry Budget**: Trips host circuit breaker when `Retry-After` exceeds threshold; enforces Google SRE retry budgets capping retry storms at 20% of traffic.

## Usage Examples

### Unified HTTP Client Session

```goose
import std;
import wing from "..";

struct OrderPayload {
    symbol: const u8[:] = "BTC-USDT",
    amount: f64 = 0.5,
}

struct OrderResponse {
    order_id: i64 = 0,
    status: u8[..32] = [],
}

fn main() {
    var session = wing::new_session("https://api.exchange.io") { sess =>
        sess.set_profile(wing::Profile.Chrome131);
        sess.set_proxy("socks5://127.0.0.1:1080");
        sess.set_timeout_ms(5000);
        sess.default_header("Accept", "application/json");
    };

    let order = OrderPayload { symbol: "BTC-USDT", amount: 1.25 };

    let res, err = session.post("/v1/orders") { req =>
        req.bearer("jwt-auth-token-xyz");
        req.query("dry_run", "false");
        req.json(order);
    };

    guard err.ok() && res.is_success() else {
        print("Order failed: ", err.message);
        return;
    }

    var resp = OrderResponse { .. };
    if res.json(resp).ok() {
        print("Order created: id=", resp.order_id, " status=", resp.status);
    }
}
```

### Canonical Cookie Engine

```goose
import wing;

fn handle_incoming_cookies() {
    var jar = wing::new_canonical_cookie_jar();
    let clock = wing::new_mock_clock();

    // Ingest Set-Cookie headers with security context
    jar.set_cookie_header(
        "https://api.crypto-dex.io/v1",
        "auth_token=secret; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600",
        clock.now_us
    );

    // Build standalone cookies via builder pattern
    var custom = wing::new_canonical_cookie("theme", "dark");
    custom.with_domain("crypto-dex.io")
          .with_path("/")
          .with_secure();
    jar.set(custom, clock.now_us);

    // Generate RFC 6265 §5.4 Cookie header for an outbound request
    var header_buf: u8[>..] = [];
    jar.get_canonical_cookies_for_request(
        "https://api.crypto-dex.io/v1/orders",
        clock.now_us,
        header_buf,
        true,  // is_same_site
        true,  // is_top_level_navigation
        true   // is_safe_method (GET/HEAD)
    );

    print("Outbound Cookie: ", header_buf);
}
```

### Calendar Math & Deadlines

```goose
import wing;

fn run_time_example() {
    // Parse ISO 8601 / RFC 3339 timestamps
    let parsed_time, ok = wing::parse_rfc3339("2026-10-23T14:30:00Z");
    guard ok else { return; }

    // Civil calendar projections
    let year = parsed_time.year();       // 2026
    let month = parsed_time.month();     // October
    let is_leap = parsed_time.is_leap_year(); // false

    // Go-compatible duration parsing
    let dur, dur_ok = wing::parse_duration("2h45m30s");

    // Monotonic deadlines with anti-overflow protection
    let deadline = wing::deadline_after(wing::secs(10));
    if !deadline.is_expired() {
        let remaining_dur = deadline.remaining();
        print("Remaining seconds: ", remaining_dur.seconds());
    }
}
```

### File URLs & Fluent Path Chaining

```goose
import wing;

fn run_file_url_example() {
    // Construct normalized file URL from native Windows path (spaces -> %20)
    let project_dir = wing::new_file_url("C:\\Users\\senya\\My Projects");

    // Fluent UFCS method chaining for subpaths and extensions
    let binary_url = project_dir.appending("build")
                                .appending("release")
                                .appending("goose-server")
                                .appending_path_extension("exe");

    // Path component inspection (Swift Foundation style)
    let filename = binary_url.last_path_component(); // "goose-server.exe"
    let file_ext = binary_url.path_extension();      // "exe"

    // Navigate to parent directory
    let parent_dir = binary_url.deleting_last_path_component(); // file:///C:/Users/senya/My%20Projects/build/release/

    // Extract native OS path for system calls (replaces / with \, decodes %20)
    var native_path: u8[..256] = [];
    if binary_url.file_path(native_path) {
        print("Ready for OS exec: ", native_path); // "C:\Users\user\My Projects\build\release\goose-server.exe"
    }
}
```

### Tamper-Proof Cryptographic Cookies (`CryptoJar`)

```goose
import wing;

fn run_crypto_jar_example() {
    // Initialize key store with 32-byte secret (e.g. from KMS or env)
    var raw_key: u8[..32] = [];
    raw_key.append_slice("my-super-secret-key-32-bytes-long");
    let key_slot = wing::new_key_slot(raw_key);
    let store = wing::new_key_store(key_slot);

    // PrivateJar: authenticated encryption (XChaCha20-Poly1305 with AAD binding)
    var private_jar = wing::new_private_jar(store, wing::CipherType.XChaCha20Poly1305);
    var ciphertext: u8[..256] = [];
    private_jar.seal("session_id", "usr_998124_admin_privileges", ciphertext);

    // Decrypt and verify AAD binding
    var decrypted: u8[..256] = [];
    if private_jar.open("session_id", ciphertext, decrypted) {
        print("Authenticated Session: ", decrypted);
    }

    // Swapping attack defense: opening under wrong cookie name fails cleanly
    var fake_out: u8[..256] = [];
    let swapped = private_jar.open("wrong_name", ciphertext, fake_out);
    // swapped == false
}
```

### W3C Fetch Metadata & Fail-Closed CSRF Protection

```goose
import wing;

fn run_csrf_filter_example() {
    let policy = wing::new_w3c_fetch_metadata_policy();
    var req = wing::new_request();
    req.method = wing::Method.Post;
    req.url.parse("https://bank.internal/api/transfer");

    // Incoming request headers
    req.headers.set("Sec-Fetch-Site", "cross-site");
    req.headers.set("Sec-Fetch-Mode", "cors");
    req.headers.set("Sec-Fetch-Dest", "empty");

    // Evaluate against 9-row Fetch Metadata decision matrix
    let verdict = policy.evaluate(req);
    guard verdict.allowed else {
        print("Blocked CSRF attack: status=", verdict.status_code, " reason=", verdict.reason);
        return;
    }
}
```

### GCRA Rate Limiter & Multi-Cell Reservation

```goose
import wing;

fn run_rate_limiter_example() {
    // 100 requests per minute with burst capacity of 10
    let limiter = wing::new_gcra_limiter(100, wing::secs(60), 10);
    let now = wing::now_monotonic_us();

    // Check single cell conformance
    var check_res = limiter.check(now);
    if check_res.allowed {
        print("Request allowed! Remaining burst: ", check_res.burst_remaining);
    }

    // Anti-starvation priority reservation for batch processing (5 cells)
    var reserve_res = limiter.reserve_n(5, now);
    if reserve_res.allowed {
        print("Batch approved, delay until execution: ", reserve_res.delay_us, "us");
    }
}
```

### Zero-Allocation Radix Router

```goose
import wing;

fn run_router_example() {
    var router = wing::new_router();

    // Register routes with typed route handlers
    router.insert(wing::Method.Get, "/api/v1/users", 1);
    router.insert(wing::Method.Get, "/api/v1/users/{id}", 2);
    router.insert(wing::Method.Get, "/api/v1/users/{id}/comments", 3);
    router.insert(wing::Method.Get, "/static/*path", 4);

    // Fast zero-allocation path lookup
    var params = wing::new_zero_alloc_params();
    let handler_id, status = router.lookup(wing::Method.Get, "/api/v1/users/42", params);

    if status == wing::RouteLookupStatus.Matched {
        print("Matched handler: ", handler_id);
        print("User ID: ", params.get("id")); // "42" without heap allocation
    } else if status == wing::RouteLookupStatus.MethodNotAllowed {
        var allow_buf: u8[..64] = [];
        router.get_allowed_methods("/api/v1/users/42", allow_buf);
        print("405 Method Not Allowed. Allowed methods: ", allow_buf);
    }
}
```

## Verification & Test Suite

The test suite covers full RFC specifications, Chromium edge cases, audit regressions, mathematical timing tests, and property-based randomized testing across **2,750+ checks**:

### Test Taxonomy

All verification suites live in `tests/` and adhere to a strict, scalable `<subsystem>_<topic>_test.goose` convention:

| Subsystem Prefix | Scope & Responsibilities | Example Files |
|---|---|---|
| `core_*` | Core runtime primitives (time, calendar, URL, sync, concurrency, actors) | `core_time_test.goose`, `core_url_test.goose`, `core_sync_test.goose` |
| `cookie_*` | RFC 6265bis engine, WPT clean-room compliance, and 1..16 edge vectors | `cookie_engine_test.goose`, `cookie_vectors_test.goose` |
| `http_*` | Zero-heap HeaderMap, MIME / SFV (RFC 8941/9651), streaming multipart & Range | `http_headers_test.goose`, `http_mime_test.goose`, `http_multipart_test.goose` |
| `app_*` | Client session pipelines, redirect FSM, profiles, request/response | `app_session_test.goose` |
| `sec_*` | Security regressions, CVE validations, constant-time cryptography, CSRF/CORS, GCRA | `sec_ct_test.goose`, `sec_csrf_test.goose`, `sec_rate_limiter_test.goose`, `sec_cve_test.goose`, `sec_protocol_test.goose`, `sec_cookie_test.goose`, `sec_concurrency_test.goose` |
| `server_*` | Zero-allocation Radix Router, Tako v2 pool, pipeline orchestration | `server_router_test.goose` |
| `cache_*` | RFC 9111 HTTP caching engine, freshness hierarchy, 304 merge & revalidation | `cache_engine_test.goose` |
| *Future: `proto_*`* | Wire protocols (HTTP/1.1, HTTP/2, HTTP/3, QUIC, WebSocket) | `proto_h1_test.goose`, `proto_h2_test.goose`, `proto_quic_test.goose` |
| *Future: `compress_*`* | Compression codecs (Deflate/zlib, Brotli, Zstandard) | `compress_zstd_test.goose`, `compress_brotli_test.goose` |

### Suite Breakdown

| Test Suite | File | Focus Areas | Checks |
|---|---|---|---|
| **Core Time & Calendar** | `tests/core_time_test.goose` | Hinnant calendar math, leap years, ReDoS protection, RFC 3339, RFC 9110 HTTP-date | 334 checks |
| **Core WHATWG URL** | `tests/core_url_test.goose` | WHATWG URL, IPv6 RFC 5952, Swift File URLs & Path API, dual-mode resolution, UrlView zero-copy | 357 checks |
| **Core Concurrency** | `tests/core_sync_test.goose` | BatonMutex, Semaphore, CyclicBarrier, CSP patterns, Actors, OTP supervision trees | 68 checks |
| **Clean Room Cookie Jar** | `tests/cookie_engine_test.goose` | WPT compliance, domain quotas, eviction ordering, persistence keys | 78 checks |
| **Cookie Edge Matrices** | `tests/cookie_vectors_test.goose` | Matrices 1..16 (Lexer limits, CTL sweep, PSL, prefixes, SameSite, CHIPS, 6-round GC, SQLite v24, clock skew, PRNG fuzzer) | 1,113 checks |
| **HTTP Headers & Lexical** | `tests/http_headers_test.goose` | Zero-heap HeaderMap, 64-bit SWAR tokenization, O(1) inline slots, Set-Cookie fold isolation, httparse #223, 304 merge | 65 checks |
| **HTTP MIME & SFV** | `tests/http_mime_test.goose` | Chromium StrictUnquote, RFC 9110 MediaType, RFC 8941/9651 SFV (integers, fixed-point decimals, tokens, dates, UTF-8 display strings) | 87 checks |
| **HTTP Multipart & Range** | `tests/http_multipart_test.goose` | Streaming multipart BMH shift table (CVE-2026-19484), 70-byte boundary cap, RFC 9110 Range & coalescing (CVE-2011-3192), 416 handler | 60 checks |
| **HTTP Client & Cache** | `tests/client_test.goose` | PSL tenant isolation, SiteForCookies, Redirect FSM, 6-Phase Client pipeline, BodyRewind, SSRF Guard, RFC 9111 Cache hit/invalidation | 92 checks |
| **CVE Security Regression** | `tests/sec_cve_test.goose` | CVE-2021-28918/29922 (octal/hex IP SSRF), CVE-2024-24790 (RFC 6761 localhost), CVE-2023-26159 (CRLF headers), CVE-2022-27776 (port leaks), CVE-2023-27534 (URL/query ambiguity), CVE-2016-8616 (PSL import) | 35 checks |
| **Protocol Security** | `tests/sec_protocol_test.goose` | IPv4-mapped IPv6 SSRF defense, HTTPS->HTTP scheme downgrade header stripping, file URL drive normalization | 36 checks |
| **Cookie Chaos Defense** | `tests/sec_cookie_test.goose` | RFC 6265bis §5.6 cookie shadowing, case-insensitive prefixes (`__Host-`, `__Secure-`), Max-Age 400-day capping | 38 checks |
| **Concurrency Hardening** | `tests/sec_concurrency_test.goose` | WaitGroup capacity limits, bounded channel timeouts, worker crash containment & supervisor restarts | 18 checks |
| **Constant-Time & CryptoJar** | `tests/sec_ct_test.goose` | Constant-time math, Dudect Welch's $t$-test ($|t| < 4.5$), SHA-256, HMAC, HKDF, ChaCha20, Poly1305, XChaCha20, AES-256, GHASH, AES-GCM, Base64URL, PrivateJar (53B/65B), SignedJar (45B), KeyStore rotation | 263 checks |
| **Resource Isolation & CORS** | `tests/sec_csrf_test.goose` | W3C Fetch Metadata 9-row decision matrix, fail-closed cookie gate, Vary & HSTS injection, protocol-specific CORS origin matching | 41 checks |
| **GCRA Virtual Scheduling** | `tests/sec_rate_limiter_test.goose` | GCRA TAT virtual scheduling, anti-starvation slot reservation (governor #16), 256-shard hash table, 5% DDoS sampling, IETF RateLimit-* headers | 38 checks |
| **Zero-Alloc Router & Pipeline** | `tests/server_router_test.goose` | Compressed Radix Trie, ZeroAllocParams stack spans, insertion order independence (matchit #83), static precedence, 405 Method Not Allowed + Allow, Tako v2 6-mechanism pool, unified pipeline | 45 checks |
| **RFC 9111 HTTP Cache Engine** | `tests/cache_engine_test.goose` | Single-pass Cache-Control bitmask, delta-seconds clamp, freshness math, clock skew protection, ETag weak/strong, Vary normalization (CVE-2026-93750), max-stale guards (CVE-2026-93748), 304 merge, request collapsing | 98 checks |
| **Total** | **18 verification suites** | | **2,854 checks** |

### Running the Tests

To typecheck the entire library and run verification suites:

```powershell
# Typecheck and compilation validation
goose check wing.goose

# Run individual test suites via compilation (supports threads & JIT)
goose build -o tests/sec_ct_test.exe tests/sec_ct_test.goose; .\tests\sec_ct_test.exe
goose build -o tests/sec_csrf_test.exe tests/sec_csrf_test.goose; .\tests\sec_csrf_test.exe
goose build -o tests/sec_rate_limiter_test.exe tests/sec_rate_limiter_test.goose; .\tests\sec_rate_limiter_test.exe
goose build -o tests/server_router_test.exe tests/server_router_test.goose; .\tests\server_router_test.exe
goose build -o tests/http_headers_test.exe tests/http_headers_test.goose; .\tests\http_headers_test.exe
goose build -o tests/cookie_vectors_test.exe tests/cookie_vectors_test.goose; .\tests\cookie_vectors_test.exe

# Or run all 30 suites in parallel via automated test runner
.\scripts\test_all.ps1
```

```powershell
# Run end-to-end demonstrations
goose run examples/unified_demo.goose
goose run examples/cookie_demo.goose
goose run examples/time_demo.goose
```

## Design Principles

- **Zero Hidden Allocations**: Core structs use bounded fixed-capacity byte arrays (`u8[..N]`) for common headers, paths, and URLs, falling back to explicit dynamic vectors (`u8[>..]`) only for long-lived payload bodies.
- **Deterministic Clocks**: Time-dependent logic accepts an explicit microsecond timestamp (`now_us`), allowing comprehensive time-travel testing via `MockClock` without real system sleep calls.
- **Standard Conformance**: Strict alignment with RFC 6265bis, RFC 9110, and Chromium CookieMonster implementation details rather than loose interpretations.
- **Idiomatic Goose DX**: Uniform Function Call Syntax (UFCS) support throughout, allowing both `jar.get(...)` and `wing::get(jar, ...)`.

## Documentation & Reference Manuals

- **[Security & Architecture Defense Manual](docs/SECURITY_DEFENSES.md)**: Comprehensive catalog of RFC specifications, vulnerability vectors (CVEs), and architectural defense mechanisms implemented across the stack.
- **[Caller Contract & Nuances Manual](docs/CALLER_REFERENCE.md)**: Developer guide covering runtime semantics, buffer budgets, fail-closed constraints, error modes, and operational gotchas for API consumers.

## License

Apache License, Version 2.0. See `LICENSE` for details.
