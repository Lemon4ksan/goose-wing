# goose-wing HTTP cache conformance suite

Structured HTTP caching conformance harness (`mnot/http-tests` style) driving
`http::Cache` and `proxy::filter_and_forward_headers` across 29 multi-step
scenarios (25 virtual-clock plus 4 live HTTP/1.1 origin) covering RFC 9111, RFC
5861, RFC 8246, and RFC 9875.

## Quick start

### Local mode (virtual clock + loopback HTTP/1.1 origin)

```bash
python tools/cache_conformance.py --local
```

### Docker mode (containerized origin + cache runner)

```bash
python tools/cache_conformance.py --docker
```

## Verified conformance areas

| Standard | Scenarios | Verified rules |
| :--- | :--- | :--- |
| RFC 9111 `Cache-Control` | 10 | `no-store`, `private` (shared vs private cache), `no-cache`, `max-age=0`, `s-maxage` precedence, `must-revalidate` blocking `max-stale`, `immutable` (RFC 8246). |
| RFC 9111 freshness | 4 | `Age` subtraction, `Expires` future/past handling, `max-age` precedence over `Expires`, and 10% `Last-Modified` heuristic freshness. |
| RFC 9111 `Vary` and 304 revalidation | 4 | `Vary: Accept-Encoding` matching and absence checks, `Vary: *` non-reuse, `ETag` + `If-None-Match` 304 header merge (protecting `Content-Type`), and `Last-Modified` + `If-Modified-Since` 304 freshening. |
| RFC 9111 unsafe invalidation | 3 | `POST`, `PUT`, and `DELETE` target URI eviction, same-origin `Location` and `Content-Location` eviction, cross-origin isolation, and non-invalidation on 4xx/5xx. |
| RFC 5861 stale extensions | 2 | `stale-while-revalidate` background refresh flag and `stale-if-error` fallback on 503 origin outages. |
| RFC 9875 cache groups | 2 | `Cache-Groups` membership, `Cache-Group-Invalidation` same-origin targeted purge, and case-sensitive group matching. |
| Live HTTP/1.1 origin wire tests | 4 | Live TCP HTTP/1.1 requests with `Via` injection, ETag 304 merge, `Vary: Accept-Encoding`, `Cache-Groups` invalidation, and `no-store`. |
