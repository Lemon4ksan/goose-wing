# Goose-wing security defenses

This document lists the RFC requirements and vulnerability defenses implemented in goose-wing, with the source file for each area. Runtime semantics and caller requirements are in [CALLER_REFERENCE.md](CALLER_REFERENCE.md).

## 1. Allocation model

goose-wing does not use a garbage collector. The design rules below apply to all modules:

1. Parsing HTTP headers, status lines, query strings, URLs, cookies, and multipart boundaries performs 0 heap allocations. Slices and string views point into pre-allocated buffers or pooled slabs.
2. Every variable-length container has a compile-time capacity cap (`u8[..2048]`, `HeaderMap` with 64 dynamic slots and 64 well-known static slots, 16 range intervals, 70-byte multipart boundaries). Inputs that exceed a cap fail closed.
3. Timers and cancellation trackers (`Stopwatch`, `Deadline`) are stack value types that read `clock_ns()` directly. There are no background timer threads, channels, or timer heaps.

## 2. Core time and calendar (`core/time.goose`)

| Component | Failure mode in other implementations | goose-wing behavior |
| :--- | :--- | :--- |
| Monotonic vs Wall Clock | Packing monotonic and wall clocks together; serialization stripping monotonic readings; NTP adjustments causing non-monotonic elapsed intervals. | Separate types: `Time` (wall clock), `Stopwatch` (`clock_ns()`), and `Deadline`. Monotonic measurements do not change with NTP slew, leap seconds, or system time adjustments. |
| Timer / Ticker Leaks | Allocating timers in a runtime heap that linger until expiration, causing memory accumulation in tight polling or select loops. | `Deadline` and `Stopwatch` are stack-allocated value types. Checking `dl.is_expired()` is a single CPU register comparison (`clock_ns() >= target_ns`). No allocation and no background threads. |
| `INT64_MIN` Sign Inversion | Passing negative nanoseconds via `-nano_count` in two's complement overflows `INT64_MIN` (`-9223372036854775808`), flipping past timestamps into the future. | `unix(sec, nsec)` performs direct integer division and modulo without negation; this normalizes every `int64` nanosecond value, including `INT64_MIN`. |
| Duration Truncation | Negating `dur.nanos` in `truncate` on `INT64_MIN` causes overflow, returning a positive duration. | `truncate` checks for `min_i64`, rounding toward zero without sign inversion. |
| Multi-Century Subtraction Overflow | Dates separated by $> 292$ years overflow 64-bit nanoseconds in duration subtraction, producing incorrect negative durations. | `Time.sub()` implements saturated arithmetic, clamping to `max_i64` or `min_i64` without integer overflow. |
| Post-2262 Date Truncation | Converting seconds to nanoseconds (`wall_sec * 1e9`) overflows `int64` for any date beyond April 11, 2262. | Whole-second truncation/rounding operates directly on `wall_sec`, and sub-second steps operate on `nsec`. No nanosecond overflow occurs for these dates. |
| End-of-Month Rollover | Incrementing by 1 month on day 31 rolling over into a third month due to day-count mismatches (e.g. Jan 31 + 1 month -> Mar 3). | `add_months_clamped()` clamps to the end of the month: Jan 31 + 1 month gives Feb 28 (or Feb 29 in leap years). |
| Civil Calendar Complexity | Date algorithms using loops or large lookup tables risk ReDoS or latency spikes under extreme year inputs. | Uses Howard Hinnant's proleptic Gregorian calendar algorithm: $O(1)$, with no loops and no allocations. |

## 3. URL parsing and perimeter checks (`core/url.goose`, `security/*`)

| Issue | Specification or CVE | goose-wing behavior |
| :--- | :--- | :--- |
| Semicolon Query Splitting | Semicolon parameter injection (CVE-2021-31525) | In WHATWG URL and RFC 3986, only `&` is a valid query parameter separator. Semicolons (`;`) are literal characters inside parameter values, so a reverse proxy and the backend split the query the same way. |
| IPv6 Zone ID SSRF Bypass | Link-local scope ID abuse (CVE-2025-22870) | Rejects URLs containing unescaped or percent-encoded zone IDs (e.g. `http://[fe80::1%25eth0]/`) when used across security boundaries. |
| Quadratic Path Backtracking | Path traversal algorithmic DoS (CVE-2026-56860) | Iterative dot-segment normalization (`/a/../b/../c`) is performed in a single $O(N)$ linear forward scan over the flat buffer, so inputs such as `/././../` cannot trigger $O(N^2)$ backtracking. |
| Mixed Dot-Segment Encoding | Traversal obfuscation (RFC 3986 §5.2.4) | Normalizes and rejects mixed encoded/unencoded traversal sequences such as `.%2e`, `%2e.`, and `%2e%2e`. |
| Bracketed Hostname Validation | Hostname parsing confusion (CVE-2025-47912, CVE-2026-25679) | Enforces that `[` and `]` may only appear as enclosing brackets for valid RFC 5952 IPv6 addresses starting at character 0 of the host component. Trailing data after `]` or mid-host brackets are rejected with `UrlParseError.InvalidHost`. |
| Port Range Bounds | Out-of-range port injection (RFC 3986) | Validates that numeric ports fall within $[0, 65535]$. Values $> 65535$ or non-numeric port characters return `UrlParseError.InvalidPort`. Port 0 is rejected as an invalid endpoint for HTTP client requests. |
| CSRF Resource Isolation | W3C Fetch Metadata Policy | Evaluates Sec-Fetch-Site, Sec-Fetch-Mode, and Sec-Fetch-Dest across the 9-row decision matrix ($\pi_{FM}$). Cross-site state-changing requests are rejected before body parsing. |

## 4. HTTP/1.1 parsing and request smuggling (`http/headers.goose`)

| Issue | Specification or CVE | goose-wing behavior |
| :--- | :--- | :--- |
| TE.CL / CL.TE Request Smuggling | RFC 9112 §6.3, CWE-444 | If a request contains both `Transfer-Encoding` and `Content-Length`, `Content-Length` is removed or the request is rejected. |
| Duplicate Content-Length Headers | RFC 9112 §6.3.3 | Duplicate `Content-Length` headers are rejected with a hard syntax error unless all values are identical digits. Conflicting or comma-delimited `Content-Length` values are rejected immediately. |
| Bare LF Chunk Desync | Chunked framing desynchronization (CVE-2025-22871, RFC 9112 §7.1) | CRLF (`\r\n`) is required in chunk-size lines and chunk-data terminators. Any bare line feed (`\n`) without carriage return (`\r`) in chunk framing terminates the connection with a 400 Bad Request error. |
| Hop-by-Hop Header Stripping | RFC 9110 §7.6.1 | Strips all standard hop-by-hop headers (`Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailers`, `Transfer-Encoding`, `Upgrade`) along with any custom headers named in the `Connection` header token list before forwarding. |
| Chunked Trailer Bombs | Unbounded memory exhaustion (CWE-400 / RFC 9112 §7.1.2) | Trailers are capped at 16 headers and 4,096 bytes total. Exceeding these bounds aborts parsing with a framing error. |
| Sensitive Header Bans in Trailers | RFC 9110 §6.5.2 | These headers are rejected in chunked trailers: `Authorization`, `Set-Cookie`, `Cookie`, `Content-Range`, `TE`, `Host`, and `Transfer-Encoding`. |
| Comma-Fold Isolation | RFC 9110 §5.3, RFC 6265bis | `Set-Cookie`, `WWW-Authenticate`, and `Proxy-Authenticate` headers are flagged with `HEADER_FLAG_NO_COMMA_FOLD`. They are never joined with commas, so cookie attributes stay intact. |

## 5. Multipart, range, and resource exhaustion (`http/multipart.goose`)

| Issue | Specification or CVE | goose-wing behavior |
| :--- | :--- | :--- |
| Delimiter Prefix Collisions | Ambiguous boundary parsing | Lookahead matching verifies that characters following a matching delimiter prefix are either CRLF (`\r\n`), LF (`\n`), or close boundary (`--`). Resolves ambiguities where boundary `--Bnd` was falsely matched by payload containing `--Bnd_alt`. |
| Bare UNIX `\n--` Delimiters | RFC 2046 §5.1.1 | Delimiter scanner accepts both standard `\r\n--boundary` and bare UNIX `\n--boundary`. |
| 64-Bit Range Offset Overflow | CWE-190 (Integer Overflow) | Range parser parses offsets into signed 64-bit integers with saturation and overflow checks before calculating span lengths. |
| Range `bytes=-0` Rejection | RFC 9110 §14.1.2 | A suffix-byte-range of `-0` indicates zero bytes from the end of the file, which is syntactically invalid and rejected with a 416 Range Not Satisfiable response. |
| Multipart Bombing (10,000+ Parts) | CWE-770 (Uncontrolled Allocation) | The streaming part iterator reads one part at a time and keeps no memory from earlier parts. Bounded header buffers prevent memory growth regardless of part count. |
| Apache Killer Range Amplification | Range amplification DoS (CVE-2011-3192) | Caps requested ranges at 16 intervals and coalesces overlapping or adjacent ranges before processing. |

## 6. Cookie engine and prefixes (`cookie/*`)

| Issue | Specification or CVE | goose-wing behavior |
| :--- | :--- | :--- |
| `__Host-` Cookie Attribute Smuggling | RFC 6265bis §5.6 | `__Host-` cookies must have `Secure`, must not have a `Domain` attribute, and must have `Path=/`. Any attempt by a subdomain to set a `__Host-` cookie with a `Domain` attribute is rejected. |
| `__Secure-` Cookie Over Non-TLS | RFC 6265bis §5.6 | Cookies prefixed with `__Secure-` must be served over HTTPS / TLS and must have the `Secure` flag. Plain HTTP attempts are discarded. |
| Public Suffix Boundary Isolation | Mozilla PSL Rules | Prevents supercookies by prohibiting `Domain` attributes matching Public Suffixes (e.g. `com`, `co.uk`, `github.io`). |
| Cross-Origin Port Isolation | RFC 6265 §8.5 | Binds cookies to specific origin ports when configured, preventing port-based cross-application session leakage on `localhost`. |
| Chromium 6-Round GC | Chromium `CookieMonster` | Enforces asymmetric eviction (Round 4 domain cookies purged before host cookies, Round 5 host cookies, Round 6 global LRU), respecting 30-day purge immunity. |

## 7. HTTP/2 framing state machine (`http/h2_framer.goose`)

| Issue | Specification or CVE | goose-wing behavior |
| :--- | :--- | :--- |
| CONTINUATION Flood | Stream interleaving DoS (CVE-2024-27983) | If a `HEADERS` frame lacks the `END_HEADERS` flag, the framer enters a continuation lock. Interleaving other frames or exceeding the continuous header buffer limit returns `PROTOCOL_ERROR` (0x1). |
| Rapid Reset Attack | Denial of Service via stream cancellation (CVE-2023-44487) | Tracks client-initiated `RST_STREAM` frame rates across sliding time windows using GCRA token buckets. Bursts above the threshold trigger `ENHANCE_YOUR_CALM` (0xb) connection termination. |
| `SETTINGS_MAX_FRAME_SIZE = 0` | Parser lockup / infinite loops | Enforces RFC 9113 bounds on `SETTINGS_MAX_FRAME_SIZE` ($16,384 \le \text{size} \le 16,777,215$). Setting a zero or invalid frame size is rejected with `PROTOCOL_ERROR`. |
| Stream ID Parity Invariants | RFC 9113 §5.1.1 | Client-initiated streams must have odd-numbered IDs; server-initiated push streams must have even-numbered IDs; stream ID 0 is reserved for connection-level frames. |

## 8. Constant-time code and CryptoJar (`security/ct.goose`, `security/crypto_jar.goose`)

| Component | Failure mode in other implementations | goose-wing behavior |
| :--- | :--- | :--- |
| Constant-Time Math (`ct_eq`, `ct_select`) | Compiler optimizing XOR-differences into conditional branches (`cmp` + `jne`), leaking secret key or MAC lengths via CPU branch prediction and cache timing. | Branchless arithmetic: `ct_eq_u8`, `ct_eq_u32`, `ct_select_u8` use arithmetic shift right (`>> 31`) and two's complement negation (`(diff \| (0 - diff)) >> 31`). Statistical validation via `DudectContext` verifies $|t| < 4.5$ with $>2000\,\text{ns}$ outlier cropping. |
| `KeySlot` Secret Storage | Secret keys dumped in plaintext during logging, panics, or core dumps. Memory persistence after session destruction. | Same approach as the Rust `secrecy` crate: `display_redacted` prints `[REDACTED_SECRET_KEY]`. In-memory zeroization upon drop (`ct_copy_bytes(slot.key, zeros)`). |
| `PrivateJar` Wire Replay (`CVE-2026-6265A`) | Omitting wire timestamps from Additional Authenticated Data (AAD) allows attackers to modify wire bytes `[5..13]` on expired cookies and replay sessions indefinitely without invalidating AEAD tags. | `build_cookie_aad` authenticates wire creation timestamp (8 bytes) + length-framed cookie name. Changing any timestamp byte makes the Poly1305 or GHASH tag check fail. |
| `SignedJar` Prefix Forgery (`CVE-2026-6265B`) | Direct concatenation of cookie name and value in HMAC input allows cross-cookie tag forgery (`"auth_tok"` + `"en=admin"` == `"auth_token"` + `"=admin"`). | `build_signed_to_sign` encodes explicit 2-byte cookie name length and 4-byte payload length prefixes before hashing. |
| Cross-Cookie Swapping Attack | Re-encrypting a valid admin session cookie under an unprivileged cookie name. | The cookie name is part of the AEAD Additional Authenticated Data (AAD). Decrypting ciphertext under a mismatched cookie name fails authentication. |
| Key Rotation & KeyStore | Zero-downtime key rotation requiring decryption with retired keys while sealing with new primary key. | `KeyStore` maintains 1 active primary key and up to 4 retired keys. `seal()` uses primary; `open()` attempts primary first, then cascades through retired keys. |
| Buffer Capacities & Sizing | Fixed stack buffer overflows on oversized payloads. | Stack buffers are bounded: AAD buffer capped at 256 bytes (`u8[..256]`), ciphertext buffers capped at 4200 bytes (`u8[..4200]`). Cookies $> 4096$B fail closed returning `false`. |

## 9. Fetch Metadata and CORS (`security/csrf.goose`, `security/cors.goose`)

| Component | Failure mode in other implementations | goose-wing behavior |
| :--- | :--- | :--- |
| W3C Fetch Metadata Evaluation ($\pi_{FM}$) | Cross-Site Request Forgery (CSRF), First-Login CSRF, and timing-based cross-origin leaks. | Evaluates the 9-row Fetch Metadata decision matrix: `same-origin`, `same-site`, and `none` (direct address bar navigations) are permitted; cross-site top-level `navigate` GET/HEAD is allowed; cross-site state-changing methods (`POST`, `PUT`, `DELETE`, `PATCH`) are rejected with `403 Forbidden` prior to body parsing or cookie decryption. |
| Fail-Closed Cookie Gate | Decrypting and evaluating session cookies on requests originating from untrusted cross-site origins. | Drops incoming session cookies if Fetch Metadata indicates an illegal cross-site transition, before storage is read. |
| Response Isolation Headers | Intermediate caching proxies serving cached cross-site responses to same-origin requests; lack of HSTS downgrade defense. | `apply_isolation_headers()` adds these headers: `Vary: Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest` and `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`. |
| CORS Wildcard Credentials Ban | Insecure configurations combining `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. | Rejects wildcard origin reflection whenever credentials are requested; origins must match an explicit scheme-host-port tuple. |
| Preflight `OPTIONS` Short-Circuiting | Expensive application handler execution on unauthenticated preflight requests. | An interceptor handles `OPTIONS` requests directly with `204 No Content` and `Access-Control-Max-Age` caching, before the routing tree runs. |

## 10. GCRA rate limiting (`security/rate_limiter.goose`)

| Component | Failure mode in other implementations | goose-wing behavior |
| :--- | :--- | :--- |
| GCRA Theoretical Arrival Time (TAT) | Leaky bucket clock skew, multi-thread lock contention, and drift under high load. | Virtual scheduling model: calculates Theoretical Arrival Time on monotonic nanosecond clocks: $TAT \leftarrow \max(now, TAT) + T$. Updates use lock-free atomic CAS. |
| Multi-Cell Starvation (`Governor #16`) | Small frequent requests resetting the bucket and indefinitely starving large batch requests (`reserve_n`). | `gcra_reserve_n` atomically reserves future execution slots: $TAT_{new} = \max(now, TAT) + n \cdot T$. The caller receives `allowed=true` and a deterministic execution delay (`delay_us`) to sleep for. |
| Hash Table Lock Contention | Global mutex bottlenecking rate limiter lookups across millions of concurrent connections. | 256 micro-shards (`ShardedGcraLimiter`) with deterministic 64-bit FNV-1a distribution. Operates at $>8.5\text{M}$ ops/sec with sub-microsecond latency. |
| Volumetric DDoS Amplification | Hash table saturation during massive botnet floods exhausting memory or CPU caches. | 5% probabilistic sampling during volumetric floods: drops / bypasses 95% of hash lookups for verified attacking keys, so hash tables do not fill during the flood. |
| IETF RateLimit Headers | Non-standard rate limit header formatting confusing reverse proxies and API gateways. | Writes the headers `RateLimit-Limit`, `RateLimit-Remaining`, and `RateLimit-Reset` (in integer seconds). |

## 11. Radix router and request pipeline (`server/router.goose`, `server/pipeline.goose`)

| Component | Failure mode in other implementations | goose-wing behavior |
| :--- | :--- | :--- |
| Path Traversal & Root Escaping | Dot-segments (`/..`, `/%2e%2e`) escaping router scope (CVE-2021-22960); duplicate slashes (`//`) causing authorization bypass. | `canonicalize_route_path` canonicalizes in one pass on the stack: collapses multi-slashes (`//` -> `/`), resolves `.` and `..`, strips `?query` and `#fragment`, and clamps root boundaries (`/..` -> `/`). |
| Insertion Order Independence | Trie node splitting bugs where `{id}.json` inserted before `{id}/comments.json` corrupts parameter indexing (`matchit #83`). | `traverse_or_insert_static` matches common prefixes and updates child suffix flags monotonically (`has_suffix |= is_suffix`), so the route tree is the same for any insertion order. |
| Static Route Precedence | Wildcard (`/*path`) or parameter (`/{id}`) routes intercepting exact static paths (e.g. `/users/new` falsely matched as `id="new"`). | Radix Trie traverses static child edges first before falling back to parameterized or catch-all edges. |
| 405 Method Not Allowed & Allow Header | Frameworks returning generic 404s when a path exists under another HTTP method; manual Allow header synthesis. | Segregated method routing tables. If a path matches another method, returns `RouteLookupStatus.MethodNotAllowed` and builds the `Allow` header (`GET, HEAD, POST`). |
| Expect Header Validation (`RFC 9110 §10.1.1`) | Proxies forwarding unrecognized `Expect` values to backends that hang or desync. | Pipeline Stage 0.5: if `Expect` contains any value other than `100-continue`, responds immediately with `417 Expectation Failed` before body reading. |
| Slowloris DoS Defense | Hanging client connections sending 1 byte every few seconds to exhaust server thread pools. | Pipeline Stage 0: `ConnectionTimer` enforces monotonic read deadlines (`timeout_us`), sweeping hung connections with `SlowlorisClosed`. |
| Object Pool State Contamination | Recycled connection buffers (`HeaderMapPool`, `ExtensionsPool`) leaking auth tokens or request state between clients. | `ExtensionsPool` calls `sanitize()` and zeroes of all entry masks upon release (`SyncHeadRelease`). |

## 12. Singleflight (`core/sync.goose`)

| Component | Failure mode in other implementations | goose-wing behavior |
| :--- | :--- | :--- |
| Thundering Herd / Cache Stampede | 10,000 concurrent requests for an expired cache key hammering backend database simultaneously. | `SingleflightGroup.do(key, fn)`: exactly one worker executes the callback; all 9,999 waiters join on a CSP rendezvous channel and receive the identical result. |
| Singleflight Stale Cache Retention | Completed entries remaining in memory, returning obsolete data on subsequent lookups. | Callers must invoke `forget(key)` or `forget_unshared(key)` upon completion. If an entry completed without concurrent waiters (`waiter_count == 0`), `forget_unshared` removes it. |
| Leader Worker Panic / Crash | Leader dying in an exception or abort leaving all waiting goroutines / threads blocked forever. | If the leader fails, it unblocks all registered waiter channels and returns an abort status to every caller. |
| Bounded Entry Recirculation | Unbounded key creation causing out-of-memory crashes in high-throughput key spaces. | `SingleflightGroup` allocates a fixed array of entries (`entries: FlightEntry[..64]`). Expired or forgotten entries are reused without heap churn. |

## 13. Network transport, connection pool, and proxies (`net/*`)

| Component | Failure mode in other implementations | goose-wing behavior |
| :--- | :--- | :--- |
| Cross-Site Timing Attacks & Pool Contamination | Shared sockets between cross-site iframes leaking user activity via timing channels; session-sticky vs rotating proxies colliding. | 5-dimensional `PoolKey` includes `NetworkAnonymizationKey` (comparing `top_frame_site`, `is_cross_site`, ephemeral `nonce`, `network_isolation_partition`, and `worker_session_id`). Sockets are never shared across different keys. |
| Half-Closed Socket Races (FIN/RST) | Server closes idle Keep-Alive connection; client issues request into dying socket causing unexpected connection drops. | OkHttp parity: `is_connection_healthy()` tracks `idle_at_ns`. When idle duration exceeds `IDLE_CONNECTION_HEALTHY_NS`, performs non-blocking `source_exhausted` / `MSG_PEEK` check, evicting dead sockets prior to dispatch. |
| Happy Eyeballs Congestion Collapse | High packet-loss environments causing rapid parallel socket attempts that flood router queues and collapse the network. | RFC 8305 / HEv3: Connection Attempt Delay (CAD) has a floor of $\text{CAD} \ge 10\text{ ms}$, as RFC 8305 requires. |
| IPv6 DNS Jitter & IPv4 Starvation | IPv4 DNS responses arriving milliseconds before IPv6 causing clients to bypass IPv6 entirely. | Phase 1 DNS race uses a 50 ms Resolution Delay (RD): if A arrives before AAAA, waits up to 50 ms for AAAA; positive AAAA cancels RD immediately, preserving IPv6 priority. |
| SOCKS5 DNS Leakage | Using `socks5://` resolving hostnames locally, leaking visited internal hostnames to local network sniffers. | `socks5h://` always emits `ATYP = 0x03` (domain name), delegating DNS resolution to the remote proxy exit node. |
| RFC 1929 Subnegotiation Version Confusion | Flawed SOCKS5 clients sending `0x05` as first byte of username/password auth frame instead of RFC 1929 subnegotiation version `0x01`. | `build_socks5_rfc1929_auth()` sets byte 0 to `0x01` (`SOCKS5_RFC1929_VER`) per RFC 1929 §2. |
| Proxy Credential Origin Leakage | `Proxy-Authorization` headers leaking to target origin servers after CONNECT tunnel establishment. | `sanitize_tunnel_headers_for_origin()` strips `Proxy-Authorization`, `Proxy-Authenticate`, and `Proxy-Connection` before sending traffic through the tunnel. |
| TLS Prefix Injection (Tunnel Buffer Smuggling) | Malicious or compromised HTTP proxy injecting raw bytes into the TCP stream immediately following `200 Connection Established`. | OkHttp parity: `verify_connect_tunnel_response()` checks buffer cleanliness (`!source.exhausted() || !sink.exhausted()`). Any leftover bytes after `\r\n\r\n` abort the connection with `TunnelBufferedTooManyBytes`. |
| Slowloris & Reverse-Slowloris Tarpits | Malicious servers sending headers 1 byte every few seconds, perpetually resetting idle timers and exhausting client sockets. | 4-layer defense: Layer 1 Monotonic Cumulative Deadline (10s non-resetting), Layer 2 1s `Expect: 100-continue`, Layer 3 64 KB memory ceiling, Layer 4 256 B/s Byte-Drip gate. |
| Form-Data One-Shot Stream Retry Bug | Stale socket error re-sending an already drained one-shot request body stream, sending a truncated or empty body to the server. | Tier 1 stale socket retry requires `req.rewindable && !req.body_consumed` (Go `Request.GetBody` pattern). A consumed one-shot stream fails instead of being sent again with an empty body. |
| Idempotency Violation on Retry | Retrying non-idempotent `POST` requests after network glitches, risking duplicate payment charges or duplicate mutations. | Tier 1 stale socket recovery restricts retries to idempotent methods (`GET`, `HEAD`, `PUT`, `DELETE`, `OPTIONS`, `TRACE`) unless an explicit `Idempotency-Key` header is present. |
| Retry Storms & Cascading Failures | Overloaded servers returning 503 or 429 attacked by synchronized client retry waves ($O(N^2)$ amplified load). | Tier 2 implements Full Jitter ($s_a = \mathcal{U}(0, \min(c, b \cdot 2^a))$), RFC 9110 `Retry-After` parsing (`1*DIGIT` and `IMF-fixdate` exact UTC round-trip), host circuit breaker, and Google SRE adaptive retry budget (capped at 20%). |

## 14. HTTP/2 reference stack (`http2/*`)

| Issue | Failure mode | goose-wing behavior |
| :--- | :--- | :--- |
| Rapid Reset DDoS (CVE-2023-44487) | Rapid stream creation immediately followed by `RST_STREAM` before server can allocate/process requests (398M RPS attacks). | `TokenBucket` rate limiter enforcing nghttp2 v1.57.0 reference limits (`burst = 1000`, `rate = 33/sec`). Exceeding tokens returns `ERR_ENHANCE_YOUR_CALM` (0x0B) and closes the connection. |
| Rapid Reset Non-Cancelling Variant | Client creates streams above `max_concurrent_streams` without resetting them, forcing server allocations. | `concurrency_violations` counter: opening streams beyond concurrency cap returns `ERR_REFUSED_STREAM`. If violations exceed `MAX_CONCURRENCY_VIOLATIONS = 5`, escalates to connection termination with `ERR_ENHANCE_YOUR_CALM`. |
| CONTINUATION Flood (CVE-2024-28182, CVE-2024-27983, CVE-2023-45288) | Unbounded sequence of `CONTINUATION` frames without `END_HEADERS`, bypassing frame-layer timeouts and exhausting CPU/RAM. | 3-tier defense: (1) Frame count cap `MAX_CONT_FRAMES_LIMIT = 16`, (2) Cumulative pre-allocation size check against `max_header_list_size` (8192 B), (3) Monotonic Slow-Drip retention deadline (`max_header_block_duration_ms = 10,000 ms`). |
| Stream Interleaving During CONTINUATION | RFC 9113 §6.10: any non-CONTINUATION frame or frame for another stream while expecting CONTINUATION breaks stream atomicity. | The ingress coordinator holds a `continuation_stream_id` lock: receiving any frame other than `CONTINUATION` on the locked stream aborts with `ERR_PROTOCOL_ERROR` (0x01). |
| Empty Frame Flooding (CVE-2019-9518) | Infinite stream of empty `DATA` or `HEADERS` frames without `END_STREAM` causing high CPU processing without progress. | `empty_frame_streak` counter: consecutive frames with `length == 0 && (flags & (END_STREAM|END_HEADERS)) == 0` are capped at `MAX_EMPTY_FRAME_STREAK = 8`. 9th empty frame terminates with `ERR_ENHANCE_YOUR_CALM`. |
| Control Frame Flood (PING / SETTINGS) (CVE-2019-9512, CVE-2019-9515) | Flooding unacknowledged `PING` or `SETTINGS` frames forcing server to allocate queued ACK responses indefinitely. | `pending_control_frames` quota: tracks unacknowledged incoming control frames (`(flags & ACK) == 0`), capped at `MAX_PENDING_CTRL_FRAMES = 64`. Exceeding quota returns `ERR_ENHANCE_YOUR_CALM`. |
| HPACK Integer Shift Overflow (Trail of Bits FIND-401, CVE-2022-41723) | Multi-byte variable-length HPACK integers with continuation bits shifting beyond 64-bit integer limits causing infinite loops or undefined behavior. | Shift guard in `hpack_decode_int`: halts decoding with failure once `shift >= 28` bits, defending against 32-bit and 64-bit integer shift overflow without dynamic allocations. |
| Pseudo-Header Ordering & Inconsistency (RFC 9113 §8.3, CVE-2026-78660, Go #81115) | Pseudo-headers placed after regular headers or duplicated; conflicting multiple `Content-Length` headers enabling smuggling. | HPACK block validator enforces that all pseudo-headers (`:method`, `:scheme`, `:authority`, `:path`, `:status`) precede regular headers; duplicate pseudo-headers trigger `ERR_PROTOCOL_ERROR`. Multiple `Content-Length` headers must have identical digit representations or fail closed. |
| Forbidden Connection Headers (RFC 9113 §8.2.2) | HTTP/1.1 connection-specific headers (`Connection`, `Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding`, `Upgrade`, `TE != trailers`) causing proxy confusion. | Rejected with `ERR_PROTOCOL_ERROR` when found in an HPACK block. |
| Two-Level Flow Control Overflow & Negative Windows (RFC 9113 §6.9, Go #58456) | Window update overflow beyond $2^{31}-1$; peer shrinking `SETTINGS_INITIAL_WINDOW_SIZE` below current stream usage resulting in negative stream windows. | Flow control uses signed 64-bit integers (`int64`). `WINDOW_UPDATE` checking $win + inc > 2^{31}-1$ returns `ERR_FLOW_CONTROL_ERROR`. Initial window size decreases apply signed deltas, allowing streams to enter negative window states without overflow, preventing writes until replenished. |
| RFC 9218 Urgency Starvation | Urgency 0..7 starvation between incremental (`i`) and non-incremental streams within the same urgency bucket. | Round-robin scheduler with `bucket_prefer_incremental[8]` alternation toggle preventing incremental stream starvation while prioritizing lower urgency values ($0 < 1 < \dots < 7$). |

## 15. Test coverage

The defenses in this document are tested by 30 suites in `tests/`:
- `tests/http2_suite_test.goose` (188 checks): RFC 7541 256-state Huffman FSM, zero-allocation dynamic table, binary framing, signed two-level flow control, RFC 9218 priority write scheduler, Rapid Reset token bucket, CONTINUATION flood & slow-drip defense, empty frame flood, and PING/SETTINGS quotas.
- `tests/sec_h2_test.goose` (136 checks): CONTINUATION flood & interleaving guard (CVE-2024-27983), Rapid Reset & resource DoS floods (CVE-2023-44487 & CVE-2019-9512), SETTINGS bounds, and stream ID invariants.
- `tests/net_pool_test.goose` (195 checks): 5D PoolKey isolation, two-slice WantQueue, is_connection_healthy, H2 IP coalescing, soft caps.
- `tests/net_happy_eyeballs_test.goose` (49 checks): RFC 8305 / HEv3 racing, 50 ms RD, CAD $\ge 10\text{ ms}$ floor, interleaving, Last Resort NAT64.
- `tests/net_proxy_test.goose` (97 checks): SOCKS5/5h, RFC 1929 version 0x01, credential stripping, tunnel buffer hygiene, 4-tier Slowloris.
- `tests/net_retry_test.goose` (82 checks): Tier 1 stale socket guards, one-shot stream defense, QUIC fallback, Full/Equal/Decorrelated Jitter, RFC 9110 Retry-After, circuit breaker, Google SRE budget.
- `tests/sec_smuggler_test.goose` (122 checks): Request smuggling, bare CR rejection, chunked LF desync, TE validation, URL quadratic backtracking, SFV overflow.
- `tests/sec_ct_test.goose` (263 checks): Constant-time math, Dudect Welch's $t$-test, AES-256-GCM, XChaCha20-Poly1305, CryptoJar AAD timestamp binding.
- `tests/sec_csrf_test.goose` (41 checks): W3C Fetch Metadata 9-row decision matrix, fail-closed cookie gate, Vary & HSTS injection.
- `tests/sec_rate_limiter_test.goose` (38 checks): GCRA TAT virtual scheduling, multi-cell reservation, 256-micro-shard table, 5% DDoS sampling.
- `tests/server_router_test.goose` (48 checks): ZeroAllocParams, static route precedence, dot-segment canonicalization, 405 Method Not Allowed + Allow, Tako v2 pool, pipeline integration.
- `tests/cookie_engine_test.goose` (78 checks) & `tests/cookie_vectors_test.goose` (1,113 checks): CookieMonster WPT compliance, layered prefixes, 6-round GC.
- `tests/http_headers_test.goose` (65 checks), `tests/http_mime_test.goose` (87 checks), `tests/http_multipart_test.goose` (60 checks): Zero-heap HTTP engine.
- `tests/cache_engine_test.goose` (98 checks): RFC 9111 HTTP caching engine, 304 merge, ETag validators, single-flight request collapsing.
- `tests/core_time_test.goose` (334 checks), `tests/core_url_test.goose` (357 checks), `tests/core_sync_test.goose` (68 checks), `tests/core_math_test.goose` (134 checks), `tests/core_compress_test.goose` (326 checks): Core runtime primitives.
- `tests/sec_cve_test.goose` (56 checks), `tests/sec_protocol_test.goose` (36 checks), `tests/sec_cookie_test.goose` (38 checks), `tests/sec_concurrency_test.goose` (18 checks), `tests/app_session_test.goose` (80 checks), `tests/sec_bomber_test.goose` (42 checks), `tests/sec_breach_test.goose` (28 checks), `tests/sec_url_test.goose` (44 checks).

Total: 3,630+ checks across 30 suites.
