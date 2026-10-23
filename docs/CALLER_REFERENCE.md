# Goose-Wing Caller Contract & Nuances Manual

This document is the practical reference manual for developers building applications or subsystems with **goose-wing**. While `docs/SECURITY_DEFENSES.md` details how goose-wing defends against attacks and protocol vulnerabilities, this guide details the **runtime semantics, input constraints, caller obligations, and edge-case behaviors** of the API.

## 1. Zero-Heap Allocation Model & Buffer Budgets

Goose-wing is designed around bounded inline storage. To avoid unexpected memory growth and runtime allocations, containers carry compile-time capacity caps:

| Type / Field | Capacity Limit | Behavior on Exceeding Budget |
| :--- | :--- | :--- |
| **`HeaderMap`** | 64 dynamic + 64 well-known static slots | Header insertion fails closed or returns false. Headers beyond 64 are rejected. |
| **`HeaderItem.name`** | 128 bytes | Header name is truncated or rejected during parsing. |
| **`HeaderItem.value`** | 2048 bytes | Header values exceeding 2 KB are rejected to prevent header bomb DoS. |
| **`UrlView` / URL Buffers** | 2048 bytes | URLs longer than 2048 bytes fail with `UrlParseError.UrlTooLong`. |
| **`SingleflightGroup` key** | 64 bytes | Keys longer than 64 bytes are truncated to 64 bytes. |
| **Cookie Payload** | 4096 bytes (`name + value`) | Rejects Set-Cookie header immediately (returns false). |
| **Cookie Attribute** | 1024 bytes | Attribute value is ignored, reverting to the default (e.g. default path `/`). |
| **Multipart Boundary** | 70 bytes (RFC 2046 §5.1.1) | Boundaries longer than 70 bytes are rejected. |
| **Chunked Trailers** | 16 headers, 4096 total bytes | Trailer parsing aborts with a framing error. |
| **HTTP Range Intervals** | 16 intervals | Ranges exceeding 16 are rejected with 416 Range Not Satisfiable. |

> **Caller Rule**: When designing request payloads or long headers, ensure strings fit within the fixed inline capacities, or use dynamic growth vectors (`u8[>..]`) where supported (e.g. streaming bodies).

## 2. Core Time & Calendar (`core/time.goose`)

### `Time.sub(time_a, time_b) -> Duration`
- **Saturated Arithmetic**: Nanosecond differences exceeding $\approx \pm 292$ years ($2^{63}-1$ nanoseconds) **saturate** at `Duration.max` (`9223372036854775807 ns`) or `Duration.min` (`-9223372036854775808 ns`).
- **No Wrap-Around**: Subtracting an ancient epoch from a distant future time will never wrap around to negative numbers.

### `parse_duration(str) -> Duration, bool`
- **Returns `(Duration, false)` on failure**: Never panics on invalid, malformed, or hostile input.
- **Leading Decimal Point**: Shorthand like `".5s"` is parsed as `500ms`.
- **Composite Formats**: Handles strings like `"1h30m45s"` or `"-2.5s"`.
- **Strict Syntax**: Rejects trailing garbage, embedded whitespace, duplicate unit suffixes, or multiple signs (`"--5s"`).
- **Overflow Bound**: Intermediate multiplications are guarded against 64-bit integer overflow; overflowing values return `false`.

### `add_months_clamped(time, months) -> Time`
- **End-of-Month Clamping**: Adding 1 month to `2026-01-31` produces `2026-02-28` (or `2026-02-29` in a leap year), **never** `2026-03-03`.
- **Preserved Offsets**: Wall clock hours, minutes, seconds, and time zone offsets remain unchanged.

### `truncate` and `round`
- **Post-2262 Safety**: For whole-second intervals ($\ge 1\text{ s}$), truncation operates directly on `wall_sec`, avoiding the 64-bit nanosecond overflow that occurs past April 11, 2262.
- **`INT64_MIN` Safety**: Truncating `INT64_MIN` nanoseconds rounds toward zero without sign-inversion overflow.

### `Stopwatch` & `Deadline`
- **Value Types**: Stack-allocated structs querying CPU monotonic counters (`clock_ns()`).
- **Zero Leaks**: No background threads, timer queues, or heap allocations.
- **`deadline.remaining()`**: Returns `wing::nanos(0)` once expired; never returns negative duration.

## 3. Concurrency & Deduplication (`core/sync.goose`)

### `SingleflightGroup`
- **Thundering Herd Suppression**: `g.do(key, fn)` ensures only one execution of `fn` runs concurrently for any given key.
- **Return Signature**: Returns `(result, shared, error)`. `shared == true` indicates the caller received a cached in-flight result computed by another caller.
- **Leader Failure Resilience**: If the executing leader aborts or errors, all joined waiters are unblocked immediately and receive the error. Waiters never hang.
- **`forget(key)` vs `forget_unshared(key)`**:
  - `g.forget(key)`: Deletes the key immediately, allowing subsequent requests to trigger a new execution.
  - `g.forget_unshared(key)`: Deletes the key **only if** no other callers joined the flight (`waiters == 0`). If other callers joined, it remains to serve them.
- **Key Limit**: Maximum key length is 64 bytes (`u8[..64]`). Longer keys are truncated.

### `BatonMutex`
- **Fair Handoff**: Sequential spinlock ensuring FIFO baton passing between threads.
- **Non-Reentrant**: Attempting to lock a mutex already held by the same thread will deadlock. Always release before acquiring again.

## 4. URL Parsing & Sanitization (`core/url.goose`)

### Semicolons in Query Strings
- **RFC 3986 & WHATWG Conformance**: Only `&` is treated as a query parameter delimiter.
- **Literal Value Semantics**: In `?filter=a;sort=b`, `a;sort=b` is parsed as the literal value of `filter`. Applications requiring semicolon splitting must explicitly split within their parameter handlers.

### IPv6 Host Formatting
- **Bracket Requirement**: RFC 5952 IPv6 addresses must start with `[` at index 0 of the host and end with `]`.
- **Trailing Junk**: Any characters after `]` (other than `:port`) produce `UrlParseError.InvalidHost`.
- **Zone IDs / Scope IDs**: URLs containing unescaped or percent-encoded zone IDs (e.g. `[fe80::1%eth0]` or `[fe80::1%25eth0]`) are stripped or rejected across security boundaries to prevent SSRF bypasses.

### Path Normalization
- **Linear Scan**: Dot segments (`/./`, `/../`) are resolved in a single $O(N)$ pass.
- **Root Bounding**: Attempting to traverse above root (`/../../../etc/passwd`) is normalized to `/etc/passwd`.
- **Encoded Dots**: Mixed encodings (`%2e.`, `.%2e`, `%2e%2e`) are decoded and normalized during traversal resolution.

### Port Constraints
- **Range**: Must be an integer within `0..65535`.
- **Client Disallowed**: Port 0 is rejected for HTTP client requests (`UrlParseError.InvalidPort`).
- **Default Schemes**: Port is automatically normalized to `80` for `http` and `443` for `https` if unspecified.

## 5. HTTP Framing, Headers & Chunking (`http/headers.goose`)

### Hop-by-Hop Header Stripping
When proxying or forwarding requests via `strip_hop_by_hop_headers`, the following headers are automatically removed:
- `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`
- `TE`, `Trailers`, `Transfer-Encoding`, `Upgrade`
- Any custom header name listed as a token in the `Connection` header value (e.g. `Connection: X-Foo`).

### `Content-Length` vs `Transfer-Encoding`
- **Precedence**: In accordance with RFC 9112 §6.3, if both headers are present, `Content-Length` is removed or rejected to prevent HTTP Request Smuggling (TE.CL / CL.TE).
- **Duplicate Detection**: Multiple `Content-Length` headers are permitted **only** if all values are identical numeric digits. Comma-separated or differing values fail immediately with a 400 Bad Request error.

### Chunked Decoder (`decode_chunked_body`)
- **Strict CRLF**: Bare LF (`\n`) in chunk-size lines, chunk data, or trailers is strictly rejected (`ChunkedDecodeError.BareLfInChunkSize`, `BareLfInTrailer`).
- **Chunk Extensions**: Semicolon-delimited extensions cannot contain bare CR or non-HTAB control characters (RFC 9112 §7.1.1).
- **Trailer Restrictions**:
  - Maximum 16 trailers and 4096 total bytes.
  - Prohibited trailer headers are rejected: `Authorization`, `Cookie`, `Set-Cookie`, `Host`, `Content-Length`, `Transfer-Encoding`, `Content-Range`.

## 6. HTTP/2 Framing State Machine (`http/h2_framer.goose`)

### `SETTINGS_MAX_FRAME_SIZE`
- **Valid Range**: $16,384 \le \text{size} \le 16,777,215$ (16 KB to 16 MB).
- **Fail-Closed**: Passing $0$ or any value $< 16,384$ triggers a `PROTOCOL_ERROR` (0x1) to prevent zero-length frame read loops.

### CONTINUATION Frame Lock
- If a `HEADERS` or `PUSH_PROMISE` frame does not set the `END_HEADERS` flag, the framer enters an exclusive CONTINUATION lock.
- Feeding any frame other than `CONTINUATION` on the same stream while locked terminates the connection with `PROTOCOL_ERROR`.

### Rapid Reset Mitigation
- Stream cancellations via `RST_STREAM` are monitored using a sliding-window GCRA rate limiter.
- Rapid bursts exceeding configured thresholds return `ENHANCE_YOUR_CALM` (0xb) connection termination.

### Stream ID Parity
- Client-initiated streams must have odd IDs ($1, 3, 5, \dots$).
- Server-initiated push streams must have even IDs ($2, 4, 6, \dots$).
- Stream 0 is strictly reserved for connection-level frames (`SETTINGS`, `PING`, connection `WINDOW_UPDATE`).

## 7. Canonical Cookie Monster (`cookie/*`)

### Ingestion Quotas
- **Payload Limit**: `name.len + value.len <= 4096`. Set-Cookie headers exceeding this return `false` without modifying the jar.
- **Attribute Limit**: Individual attributes (Path, Domain) exceeding 1024 bytes are discarded; the cookie itself is kept with default attributes.
- **ASCII CTL Rejection**: Any control character ($0x00..0x1F$ or $0x7F$) anywhere in the Set-Cookie string causes immediate rejection.

### Nameless Cookies (Omnomnom Standard)
- Strings without `=` (e.g. `Set-Cookie: auth_token; Secure`) or `=value` are parsed with `name=""` and `value="auth_token"`.

### Layered Prefix Rules
- **`__Host-`**: Must have `Secure`, `Path=/`, and **must NOT** have a `Domain` attribute. Must originate from an HTTPS context.
- **`__Secure-`**: Must have `Secure` and originate from an HTTPS context.

### SameSite Lax+POST 120s Window
- Cookies with default SameSite (`CookieSameSite.Default`) allow cross-site top-level `POST` requests **only within 120 seconds** of `creation_utc`.
- After 120 seconds, they enforce standard `Lax` rules (sent on top-level safe GET/HEAD, blocked on unsafe POST).

### Eviction Order (6-Round GC)
When a domain exceeds the 180-cookie limit:
1. Expired cookies are purged first.
2. Low-priority cookies are evicted before medium and high priority.
3. **Round 4 vs Round 5 Asymmetry**: In Round 4, domain cookies (`.example.com`) are evicted before host-only cookies (`example.com`) in Round 5.
4. **30-Day Purge Immunity**: In global eviction (max 3000 cookies), cookies accessed within the last 30 days are immune to eviction until non-recent cookies are exhausted.

### Access Time Throttling
- `last_access_utc` is throttled by 60 seconds (`access_update_threshold_us = 60_000_000`). Repeated reads within 60 seconds do not generate disk write-back tasks.

## 8. HTTP Client Session & SSRF Defenses (`app/session.goose`)

### Private Network Access Protection
When creating a client session, outbound destinations are validated against private, reserved, and local IP blocks:
- **IPv4**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8` (loopback), `169.254.0.0/16` (link-local), `0.0.0.0/8`.
- **IPv6**: `::1` (loopback), `fe80::/10` (link-local), `fc00::/7` (unique local).
- Requests targeting these addresses from untrusted client input are blocked unless explicitly configured.

### Browser Profile Headers
Setting a profile via `sess.set_profile(wing::Profile.Chrome131)` automatically configures standard browser header ordering:
- `User-Agent`
- `Sec-CH-UA`, `Sec-CH-UA-Mobile`, `Sec-CH-UA-Platform`
- `Accept`, `Accept-Language`, `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`
Manual header additions with conflicting names overwrite profile defaults.

## 9. HTTP Server Pipeline (`server/pipeline.goose`)

### `Expect: 100-continue` Handling
- Servers running `execute_pipeline` validate the `Expect` header before body ingestion.
- Standard `100-continue` generates an immediate intermediate response.
- Any unrecognized expectation string returns `417 Expectation Failed` without reading the request body.

### Slowloris Mitigation
- Active read deadlines are enforced across header parsing. If the complete request header block is not received within the timeout window, the socket is closed immediately (`PipelineOutcome.SlowlorisClosed`).
