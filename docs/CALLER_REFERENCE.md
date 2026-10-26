# Goose-wing caller contract and reference manual

This manual lists runtime semantics, input constraints, caller requirements, and edge-case behaviors for goose-wing. Security defenses are documented separately in [SECURITY_DEFENSES.md](SECURITY_DEFENSES.md).

## 1. Allocation model and buffer budgets

Containers carry compile-time capacity caps:

| Type or field | Capacity limit | Behavior on exceeding budget |
| :--- | :--- | :--- |
| `HeaderMap` | 64 dynamic + 64 well-known static slots | Header insertion fails closed or returns false. Headers beyond 64 are rejected. |
| `HeaderItem.name` | 128 bytes | Header name is truncated or rejected during parsing. |
| `HeaderItem.value` | 2048 bytes | Header values exceeding 2 KB are rejected to prevent header bomb DoS. |
| `UrlView` and URL buffers | 2048 bytes | URLs longer than 2048 bytes fail with `UrlParseError.UrlTooLong`. |
| `SingleflightGroup` key | 64 bytes | Keys longer than 64 bytes are truncated to 64 bytes. |
| Cookie payload | 4096 bytes (`name + value`) | Rejects Set-Cookie header immediately (returns false). |
| Cookie attribute | 1024 bytes | Attribute value is ignored, reverting to the default (e.g. default path `/`). |
| Multipart boundary | 70 bytes (RFC 2046 §5.1.1) | Boundaries longer than 70 bytes are rejected. |
| Chunked trailers | 16 headers, 4096 total bytes | Trailer parsing aborts with a framing error. |
| HTTP range intervals | 16 intervals | Ranges exceeding 16 are rejected with 416 Range Not Satisfiable. |

When designing request payloads or long headers, ensure strings fit within the fixed inline capacities, or use dynamic growth vectors (`u8[>..]`) where supported (such as streaming bodies).

## 2. Core time and calendar (`core/time.goose`)

### `Time.sub(time_a, time_b) -> Duration`

Nanosecond differences exceeding $\approx \pm 292$ years ($2^{63}-1$ nanoseconds) saturate at `Duration.max` (`9223372036854775807 ns`) or `Duration.min` (`-9223372036854775808 ns`). Subtracting an ancient epoch from a distant future time does not wrap around to negative numbers.

### `parse_duration(str) -> Duration, bool`

The function returns `(Duration, false)` on failure and does not panic on invalid input. Parsing rules:
- Shorthand with a leading decimal point such as `".5s"` parses as `500ms`.
- Composite formats like `"1h30m45s"` and `"-2.5s"` are supported.
- Trailing characters, embedded whitespace, duplicate unit suffixes, and multiple signs (such as `"--5s"`) cause parsing to return `false`.
- Intermediate multiplications check for 64-bit integer overflow and return `false` on overflow.

### `add_months_clamped(time, months) -> Time`

Adding 1 month to `2026-01-31` produces `2026-02-28` (or `2026-02-29` in a leap year), not `2026-03-03`. Hours, minutes, seconds, and time zone offsets remain unchanged.

### `truncate` and `round`

For whole-second intervals ($\ge 1\text{ s}$), truncation operates directly on `wall_sec`, avoiding the 64-bit nanosecond overflow that occurs past April 11, 2262. Truncating `INT64_MIN` nanoseconds rounds toward zero without sign-inversion overflow.

### `Stopwatch` and `Deadline`

These types are stack-allocated structs querying CPU monotonic counters via `clock_ns()`. They do not create background threads, timer queues, or heap allocations. Once expired, `deadline.remaining()` returns `wing::nanos(0)`.

## 3. Concurrency and deduplication (`core/sync.goose`)

### `SingleflightGroup`

`g.do(key, fn)` ensures that only one execution of `fn` runs concurrently for a given key. The return signature is `(result, shared, error)`. `shared == true` indicates that the caller received a cached result computed by another caller. If the executing function errors or aborts, all joined callers unblock immediately and receive the error.

Key deletion options:
- `g.forget(key)` deletes the key immediately, allowing subsequent requests to start a new execution.
- `g.forget_unshared(key)` deletes the key only if no other callers joined (`waiters == 0`).
- Keys longer than 64 bytes (`u8[..64]`) are truncated to 64 bytes.

### `BatonMutex`

Sequential spinlock with FIFO baton passing between threads. The lock is non-reentrant: attempting to acquire a lock already held by the current thread deadlocks.

## 4. URL parsing and sanitization (`core/url.goose`)

### Semicolons in query strings

Following RFC 3986 and WHATWG standards, only `&` delimits query parameters. In `?filter=a;sort=b`, `a;sort=b` is parsed as the literal value of `filter`. Applications requiring semicolon splitting must split parameters explicitly.

### IPv6 host formatting

IPv6 addresses must start with `[` at index 0 and end with `]`. Any trailing characters other than `:port` produce `UrlParseError.InvalidHost`. Zone identifiers (such as `[fe80::1%eth0]` or `[fe80::1%25eth0]`) are rejected or stripped to prevent SSRF bypasses.

### Path normalization

Dot segments (`/./`, `/../`) resolve in a single $O(N)$ pass. Traversals above root such as `/../../../etc/passwd` normalize to `/etc/passwd`. Mixed encodings such as `%2e.`, `.%2e`, and `%2e%2e` decode during path normalization.

### Port constraints

Ports must be in the range `0..65535`. Port 0 is rejected for client requests (`UrlParseError.InvalidPort`). Unspecified ports normalize to 80 for `http` and 443 for `https`.

## 5. HTTP framing, headers, and chunking (`http/headers.goose`)

### Hop-by-hop header stripping

When forwarding requests with `strip_hop_by_hop_headers`, the following headers are removed:
- `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`
- `TE`, `Trailers`, `Transfer-Encoding`, `Upgrade`
- Any custom header named in the `Connection` header value (for example `Connection: X-Foo`).

### `Content-Length` and `Transfer-Encoding`

Under RFC 9112 section 6.3, if both headers are present, `Content-Length` is removed or rejected to prevent request smuggling (TE.CL / CL.TE). Multiple `Content-Length` headers are permitted only when all values are identical digits. Differing or comma-separated values return a 400 Bad Request error.

### Chunked decoder (`decode_chunked_body`)

Bare LF (`\n`) characters in chunk sizes, data, or trailers return errors (`ChunkedDecodeError.BareLfInChunkSize`, `BareLfInTrailer`). Extensions delimited by semicolons cannot contain bare CR or control characters other than HTAB.
Trailers are limited to 16 headers and 4,096 total bytes. The following trailer headers are rejected: `Authorization`, `Cookie`, `Set-Cookie`, `Host`, `Content-Length`, `Transfer-Encoding`, and `Content-Range`.

## 6. HTTP/2 framing state machine (`http/h2_framer.goose`)

### `SETTINGS_MAX_FRAME_SIZE`

The valid range is $16384 \le \text{size} \le 16777215$ (16 KB to 16 MB). Values outside this range or equal to 0 trigger a `PROTOCOL_ERROR` (0x1).

### CONTINUATION frame lock

If a `HEADERS` or `PUSH_PROMISE` frame does not set `END_HEADERS`, the framer enters a CONTINUATION lock. Receiving any frame other than `CONTINUATION` on the same stream while locked terminates the connection with `PROTOCOL_ERROR`.

### Rapid reset mitigation

Stream cancellations via `RST_STREAM` are rate-limited with a sliding-window GCRA. Bursts exceeding configured thresholds return `ENHANCE_YOUR_CALM` (0xb) and terminate the connection.

### Stream identifier parity

Client-initiated streams use odd identifiers (1, 3, 5, ...). Server-initiated push streams use even identifiers (2, 4, 6, ...). Stream 0 is reserved for connection-level frames (`SETTINGS`, `PING`, connection `WINDOW_UPDATE`).

## 7. Cookie storage and management (`cookie/*`)

### Ingestion limits

Payloads must satisfy `name.len + value.len <= 4096`. Set-Cookie headers exceeding this return `false` without modifying the cookie jar. Individual attributes (Path, Domain) exceeding 1,024 bytes are discarded while keeping the cookie with default values. ASCII control characters ($0x00..0x1F$ and $0x7F$) in Set-Cookie cause immediate rejection.

### Nameless cookies

Strings without `=` (such as `Set-Cookie: auth_token; Secure`) or starting with `=value` parse with `name=""` and `value="auth_token"`.

### Cookie prefixes

- `__Host-`: Requires `Secure`, `Path=/`, no `Domain` attribute, and an HTTPS context.
- `__Secure-`: Requires `Secure` and an HTTPS context.

### SameSite Lax+POST window

Cookies with default SameSite (`CookieSameSite.Default`) allow cross-site top-level POST requests only within 120 seconds of `creation_utc`. After 120 seconds, standard Lax rules apply.

### Eviction order

When a domain exceeds the 180-cookie limit:
1. Expired cookies are purged first.
2. Low-priority cookies are evicted before medium and high priority.
3. In round 4, domain cookies (`.example.com`) are evicted before host-only cookies (`example.com`) in round 5.
4. In global eviction (maximum 3,000 cookies), cookies accessed within the last 30 days are immune until non-recent cookies are exhausted.

### Access time throttling

`last_access_utc` updates are throttled to 60 seconds (`access_update_threshold_us = 60_000_000`). Reads within this interval do not trigger disk writes.

## 8. HTTP client and private network defenses (`client/client.goose`)

### Private network access

When creating a `Client`, outbound destinations are checked against private and local IP blocks:
- IPv4: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `0.0.0.0/8`.
- IPv6: `::1`, `fe80::/10`, `fc00::/7`.

Requests targeting these addresses from untrusted inputs are blocked unless explicitly allowed.

### Browser profile headers

Setting a profile with `client.set_profile(wing::Profile.Chrome131)` sets standard browser header ordering:
- `User-Agent`
- `Sec-CH-UA`, `Sec-CH-UA-Mobile`, `Sec-CH-UA-Platform`
- `Accept`, `Accept-Language`, `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`

Explicitly added headers overwrite profile defaults.

### HTTP cache

When `ClientConfig.enable_cache` is `true`, `Client` checks its embedded `HttpCache` before dispatching network requests and records cacheable responses or performs 304 revalidations. Unsafe methods (`POST`, `PUT`, `DELETE`, `PATCH`) invalidate matching cached representations.

## 9. HTTP server pipeline (`server/pipeline.goose`)

### `Expect: 100-continue`

The server validates the `Expect` header before body ingestion. The standard `100-continue` generates an immediate intermediate response. Unrecognized expectations return `417 Expectation Failed` without reading the body.

### Slowloris timeouts

Read deadlines are enforced across header parsing. If the complete request header block is not received within the timeout window, the connection is closed (`PipelineOutcome.SlowlorisClosed`).

## 10. Network transport and connections (`net/*`)

### Connection pool key and isolation (`net/pool.goose`)

Sockets are partitioned by `(scheme, origin_endpoint, proxy_chain, partition_key, tls_and_dns_policy)`.
`NetworkAnonymizationKey` checks `top_frame_site`, `is_cross_site`, ephemeral `nonce`, and `network_isolation_partition`. Sockets are never shared across disparate partitions.
Requests to distinct domains share an established HTTP/2 TLS socket only if the resolved IP, TLS certificate SAN, partition key, privacy mode, and proxy chain match.
Sockets idle longer than `IDLE_CONNECTION_HEALTHY_NS` (1 second) trigger non-blocking `MSG_PEEK` checks to detect server-sent FIN packets before dispatch.

### Happy Eyeballs v2 and v3 (`net/happy_eyeballs.goose`)

A 50 ms DNS resolution delay gives IPv6 (AAAA) an opportunity to complete if IPv4 (A) arrives first. Connection attempt delay uses a 250 ms default pacing between socket attempts, with dynamic RTT clamped to $\text{CAD} \ge 10\text{ ms}$. Address interleaving alternates families: $\text{IPv6}_1 \to \text{IPv4}_1 \to \text{IPv6}_2 \to \text{IPv4}_2$. A 2,000 ms timer triggers RFC 7050 NAT64 synthesis (`64:ff9b::/96`) if all IPv6 attempts fail.

### Proxy integration and credentials (`net/proxy.goose`)

Callers requiring remote proxy DNS resolution must use `socks5h://` (`ATYP = 0x03`). SOCKS5 authentication frames start with subnegotiation version byte `0x01`. `Proxy-Authorization` is removed from origin-bound headers after tunnel establishment. If bytes follow `\r\n\r\n` on a `200 OK` CONNECT response, the connection aborts with `TunnelBufferedTooManyBytes`. The proxy stack enforces a 10-second non-resetting deadline, a 1-second `Expect: 100-continue` timeout, a 64 KB header limit, and a 256 B/s minimum drip rate.

### Retry policies (`net/retry.goose`)

Zero-delay retry occurs only when four conditions are met:
1. The connection was reused from the pool.
2. The failure occurred before response headers arrived.
3. The method is idempotent or carries an `Idempotency-Key`.
4. The body is empty or rewindable.

Unrewindable streams fail without retry. On `ERR_QUIC_PROTOCOL_ERROR` before headers, the client retries over TCP/TLS with `disable_alternative_services = true`. Backoff calculations support full jitter ($s_a = \mathcal{U}(0, \min(c, b \cdot 2^a))$), equal jitter, and decorrelated jitter. `Retry-After` headers parse `1*DIGIT` (delay-seconds) or `IMF-fixdate` with a UTC calendar round-trip check. Delays exceeding `max_retry_after_ms` open the circuit breaker. Total retries are capped at 20% of requests.

## 11. HTTP/2 reference stack (`http2/*`)

### HPACK codec and dynamic table (`http2/hpack.goose`)

Huffman decoding uses a 4,096-entry `u32` packed transition table (`HUFF_DECODE_TABLE_PACKED`) fitting within 16 KiB of L1 cache, emitting up to 1 symbol per 4-bit nibble. Padding bits must consist of ones, and state must be accepted at end-of-stream; embedded EOS or padding over 7 bits fails decoding. Integer decoding in `hpack_decode_int` halts when `shift >= 28` (Trail of Bits FIND-401, CVE-2022-41723).
The dynamic table uses a 128-entry descriptor ring with a 4,096-byte arena. External indexes $idx \ge 62$ map through `(head + count - 1 - (idx - 62)) & 127`, so eviction cannot underflow (Go #69316, #72940). When `arena_write_pos + total_raw > 4096`, live entries are compacted in place to offset 0.
Pseudo-headers (`:method`, `:scheme`, `:path`, `:authority`, `:status`) must precede regular headers without duplicates. Multiple `Content-Length` headers must match or trigger `ERR_PROTOCOL_ERROR` (CVE-2026-78660, Go #81115). Connection-specific headers (`Connection`, `Keep-Alive`, `Upgrade`, and `TE != trailers`) are rejected.

### Framing and prioritization (`http2/framing.goose`)

Fixed 9-byte headers are handled by `parse_frame_header` and `encode_frame_header`. The reserved stream bit is masked on output. Payload extractors strip padding lengths, trailing padding, and 5-byte priority trees. RFC 9218 priority parser extracts `urgency` ($0 \dots 7$) and boolean `incremental` (`i`). `PRIORITY_UPDATE` frames encode type `0x10` payloads. Frame size parameters enforce $16384 \le \text{size} \le 16777215$, initial window size enforces $\le 2^{31}-1$, and boolean flags must be 0 or 1.

### Flow control and scheduler (`http2/connection.goose`)

Window updates exceeding $2^{31}-1$ trigger `ERR_FLOW_CONTROL_ERROR`. Decreases in `SETTINGS_INITIAL_WINDOW_SIZE` apply signed deltas across active streams; streams with negative windows halt sending until replenished by `WINDOW_UPDATE`.
The write scheduler iterates urgency buckets $u = 0 \dots 7$ and alternates between incremental and non-incremental streams via `bucket_prefer_incremental[8]`.
`RST_STREAM` frames are limited by a token bucket with burst capacity 1,000 and refill rate 33/sec; exceeding this returns `ERR_ENHANCE_YOUR_CALM` (CVE-2023-44487).
`CONTINUATION` sequences are limited to 16 frames, cumulative wire size $\le 8192$ bytes, and a 10-second monotonic deadline (CVE-2024-28182, CVE-2024-27983).
Consecutive empty `DATA` or `HEADERS` frames without termination flags are capped at 8 (CVE-2019-9518). Unacknowledged `PING` and `SETTINGS` frames are capped at 64 (CVE-2019-9512, CVE-2019-9515).
