# `http/cache`

Zero-allocation RFC 9111 HTTP caching engine, RFC 9875 Cache Groups
invalidation, freshness evaluation model, and storage coordinator.

## Public API

### Cache-Control Directives (`cache_control.goose`)

```goose
struct CacheControl
struct CacheControlParseOptions

fn parse_cache_control_str(raw: const u8[:], cc: CacheControl&, ignore_cargo_cult: bool = true)
fn parse_cache_control_headers(map: const HeaderMap&, opts: CacheControlParseOptions = CacheControlParseOptions { .. }) -> CacheControl
fn contains_pragma_no_cache(pragma_val: const u8[:]) -> bool
fn has_flag(cc: const CacheControl&, flag: u32) -> bool
fn is_no_store(cc: const CacheControl&) -> bool
fn is_no_cache(cc: const CacheControl&) -> bool
fn is_must_revalidate(cc: const CacheControl&) -> bool
fn is_proxy_revalidate(cc: const CacheControl&) -> bool
fn is_must_understand(cc: const CacheControl&) -> bool
fn is_private(cc: const CacheControl&) -> bool
fn is_public(cc: const CacheControl&) -> bool
fn is_immutable(cc: const CacheControl&) -> bool
fn is_only_if_cached(cc: const CacheControl&) -> bool
fn is_no_transform(cc: const CacheControl&) -> bool
fn has_max_age(cc: const CacheControl&) -> bool
fn has_s_maxage(cc: const CacheControl&) -> bool
fn has_max_stale(cc: const CacheControl&) -> bool
fn has_min_fresh(cc: const CacheControl&) -> bool
fn has_stale_while_revalidate(cc: const CacheControl&) -> bool
fn has_stale_if_error(cc: const CacheControl&) -> bool
fn is_private_field(cc: const CacheControl&, field_name: const u8[:]) -> bool
fn is_no_cache_field(cc: const CacheControl&, field_name: const u8[:]) -> bool
```

`CacheControl` represents parsed RFC 9111 §5.2, RFC 5861
(`stale-while-revalidate`, `stale-if-error`), and RFC 8246 (`immutable`)
directives using a 32-bit bitmask and clamped delta-seconds values.
`parse_cache_control_headers` aggregates all `Cache-Control` lines (and
`Pragma: no-cache` fallback when no `Cache-Control` header is present) from a
`HeaderMap` according to `CacheControlParseOptions` (`is_request`,
`ignore_cargo_cult`). `is_private_field` and `is_no_cache_field` check whether a
header field name is nominated by a qualified `private="field"` or
`no-cache="field"` directive.

```goose
let cc = wing::parse_cache_control_headers(resp.headers);
if !wing::is_no_store(cc) && wing::has_max_age(cc) {
    let immutable = wing::is_immutable(cc);
}
```

### Freshness & Clock Skew Model (`freshness.goose`)

```goose
struct CacheTimestamps
struct FreshnessMetrics
struct FreshnessPolicy

fn new_cache_timestamps(req_time: core::Time, resp_time: core::Time, cur_now: core::Time) -> CacheTimestamps
fn with_monotonic(ts: CacheTimestamps, req_mono: core::MonotonicInstant, resp_mono: core::MonotonicInstant, cur_mono: core::MonotonicInstant) -> CacheTimestamps
fn parse_age_header(raw_age: const u8[:]) -> i64
fn compute_apparent_age(response_time: core::Time, date_value: core::Time) -> i64
fn compute_response_delay(ts: const CacheTimestamps&) -> i64
fn compute_corrected_initial_age(apparent_age: i64, age_hdr: i64, response_delay: i64) -> i64
fn compute_resident_time(ts: const CacheTimestamps&) -> i64
fn compute_current_age(apparent_age: i64, age_hdr: i64, ts: const CacheTimestamps&) -> i64
fn compute_freshness_lifetime(resp_cc: const CacheControl&, resp_headers: const HeaderMap&, ts: const CacheTimestamps&, shared: bool = false, heuristic_fraction: i64 = 10, immutable_min_ttl_sec: i64 = 31536000) -> i64
fn evaluate_freshness(resp_cc: const CacheControl&, req_cc: const CacheControl&, resp_headers: const HeaderMap&, ts: const CacheTimestamps&, policy: FreshnessPolicy = FreshnessPolicy { .. }, heuristic_fraction: i64 = 10, immutable_min_ttl_sec: i64 = 31536000) -> FreshnessMetrics
```

`CacheTimestamps` captures wall-clock (`core::Time`) and optional monotonic
(`core::MonotonicInstant`) checkpoints to compute RFC 9111 §4.2.3 apparent age,
network response delay, corrected initial age, and cache resident time without
wall-clock jump distortion. `compute_freshness_lifetime` resolves freshness
precedence across `s-maxage` (when `shared` is true), `max-age`, `Expires`,
`immutable`, and `Last-Modified` heuristics (`1 / heuristic_fraction`).
`evaluate_freshness` combines response freshness with request constraints
(`min-fresh`, `max-age`, `max-stale`) and RFC 5861 stale serving windows under
`FreshnessPolicy` (`shared`, `security_zeroed`).

### Validators & Vary Engine (`validators.goose`)

```goose
struct EntityTag
struct VaryItem
struct VarySnapshot

fn parse_etag(raw: const u8[:]) -> EntityTag
fn weak_eq(a: EntityTag, b: EntityTag) -> bool
fn strong_eq(a: EntityTag, b: EntityTag) -> bool
fn match_if_none_match(raw_if_none_match: const u8[:], cached_etag: const EntityTag&) -> bool
fn match_if_match(raw_if_match: const u8[:], cached_etag: const EntityTag&) -> bool
fn evaluate_cache_if_range(raw_if_range: const u8[:], cached_etag: const EntityTag&, cached_last_modified: core::Time) -> bool
fn record_vary_snapshot(cached_vary_raw: const u8[:], req_headers: const HeaderMap&) -> VarySnapshot
fn matches_vary(snap: const VarySnapshot&, incoming_req_headers: const HeaderMap&) -> bool
fn sanitize_for_storage(src: const HeaderMap&, dst: HeaderMap&, shared: bool = false, cc: const CacheControl& = CacheControl { .. })
fn merge_cached_headers_304(cached: HeaderMap&, resp_304: const HeaderMap&)
```

`EntityTag` parses RFC 9110 §8.8.3 weak (`W/"..."`) and strong (`"..."`)
validators; `match_if_none_match` uses `weak_eq`, while `match_if_match` and
`evaluate_cache_if_range` require `strong_eq`. `VarySnapshot` records nominated
request headers (`VaryItem`) and rejects oversized header values to prevent
cache-poisoning mismatches. `sanitize_for_storage` strips hop-by-hop,
non-cacheable, and qualified `private` or `no-cache` fields per RFC 9111 §3.1,
and `merge_cached_headers_304` updates stored headers with end-to-end fields
from a `304 Not Modified` response (RFC 9111 §4.3.4).

### Cache Engine & Storage Coordinator (`engine.goose`)

```goose
struct CacheOptions
struct CachedEntry
enum LookupResultKind { Miss, Hit, Revalidate, Fail504 }
struct LookupDecision
enum ResponseDecisionKind { StoreAndReturn, FreshenAndReturn, PassThrough }
struct ResponseDecision
struct CacheWriters
struct HttpCache

fn new_http_cache(options: CacheOptions = CacheOptions { .. }) -> HttpCache
fn lookup(cache: HttpCache&, req: const Request&, cur_now: core::Time, cur_mono: core::MonotonicInstant = core::MonotonicInstant { .. }) -> LookupDecision
fn on_response(cache: HttpCache&, req: const Request&, resp: const Response&, ts: const CacheTimestamps&, revalidate_entry_idx: i64 = -1) -> ResponseDecision
fn freshen_cached_entry_304(cache: HttpCache&, revalidate_entry_idx: i64, resp: const Response&, ts: const CacheTimestamps&, req_headers: const HeaderMap& = HeaderMap { .. }) -> ResponseDecision
fn invalidate_matching_url(cache: HttpCache&, target_url: const u8[:]) -> i64
fn check_invalidation(cache: HttpCache&, req: const Request&, resp: const Response&) -> i64
```

`HttpCache` is a fixed-capacity LRU store configured by `CacheOptions` that
stores `CachedEntry` representations and coordinates singleflight request
coalescing through `CacheWriters`. `lookup` evaluates stored entries and returns
a `LookupDecision` (`Miss`, `Hit`, `Revalidate` with synthesized conditional
headers, or `Fail504` when `only-if-cached` misses). `on_response` handles
post-response storage, `304 Not Modified` freshening via
`freshen_cached_entry_304`, `stale-if-error` fallback, and unsafe method
invalidation (`check_invalidation` and `invalidate_matching_url`).

### HTTP Cache Groups (`cache_groups.goose`, RFC 9875)

```goose
struct CacheGroupTag

fn parse_cache_group_list(raw: const u8[:], out_tags: CacheGroupTag[..32]&, out_count: i32&) -> bool
fn serialize_cache_group_list(tags: const CacheGroupTag[..32]&, count: i32, out: u8[..512]&) -> i32
fn entry_has_group(entry: const CachedEntry&, group: const u8[:]) -> bool
fn invalidate_group(cache: HttpCache&, group: const u8[:], base_orig: core::Origin = core::Origin { .. }) -> i64
```

Implements RFC 9875 HTTP Cache Groups. `CacheGroupTag` stores a group string up
to 64 bytes (`name: u8[..64]`), and `parse_cache_group_list` extracts up to 32
group tags (`CacheGroupTag[..32]`) from `Cache-Groups` or
`Cache-Group-Invalidation` Structured Field List-of-Strings headers.
`entry_has_group` compares group names case-sensitively per RFC 9875 §2.1, and
`invalidate_group` evicts all matching entries sharing the same `core::Origin`.
