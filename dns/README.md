# `dns`

Package `dns` provides a deterministic, zero-allocation DNS engine conforming to
RFC 1035 wire messaging, RFC 2181 TTL handling, RFC 9460 HTTPS/SVCB Resource
Records (Type 65), RFC 8484 DNS-over-HTTPS (DoH), and RFC 5861
Stale-While-Revalidate caching for `goose-wing`.

All parsers, serializers, and cache lookups operate without dynamic heap
allocations on the hot path, using stack-bounded buffers (`u8[..N]`) and
zero-copy byte slices (`const u8[:]`). Internal-only wire and LRU helpers live
in `namespace dns_internal`.

```goose
import wing;

var query: u8[..512] = [];
let ok = dns::build_query("example.com", 1, 0x1234, query);

let resp, parsed = dns::parse_response(query[..]);
```

## Public API Reference

### 1. RFC 9460 HTTPS and SVCB Resource Records (`dns/svcb.goose`)

```goose
struct HttpsRecord {
    priority:        u16           = 0,
    target_name:     u8[..255]     = [],
    alpns:           u8[..32][..4] = [],
    port:            u16           = 443,
    no_default_alpn: bool          = false,
    ipv4_hints:      u32[..8]      = [],
    ipv6_hints:      u8[16][..8]   = [],
    ech_config_list: u8[..512]     = [],
    has_ech:         bool          = false,
}

struct MandatorySvcParams {
    has_unsupported: bool = false,
    has_ech:         bool = false,
}

fn parse_mandatory_svc_param(val: const u8[:]) -> MandatorySvcParams, bool
fn parse_https_svc_params(rec: HttpsRecord&, rdata: const u8[:]) -> bool
```

`HttpsRecord` models RFC 9460 Type 65 parameters for ALPN extraction (`h2`,
`h3`), port overrides, IPv4/IPv6 address hints, and Encrypted Client Hello
(`ech_config_list`). `rec.parse_https_svc_params(rdata)` validates strictly
ascending `SvcParamKey` order, checks mandatory key lists, and rolls back `rec`
on malformed or incompatible records.

### 2. RFC 1035 DNS Wire Codec (`dns/wire.goose`)

```goose
struct Response {
    tx_id:          u16              = 0,
    rcode:          u8               = rfc::DNS_RCODE_NOERROR,
    is_response:    bool             = false,
    question_count: u16              = 0,
    answer_count:   u16              = 0,
    a_records:      u32[..8]         = [],
    aaaa_records:   u8[16][..8]      = [],
    https_records:  HttpsRecord[..4] = [],
    min_ttl_sec:    u32              = 0,
}

fn encode_name<B>(domain: const u8[:], out: B&) -> bool
fn decode_name<B>(raw: const u8[:], idx: i64&, out: B&) -> bool
fn build_query<B>(domain: const u8[:], qtype: u16, tx_id: u16, out: B&) -> bool
fn parse_response(raw: const u8[:]) -> Response, bool
```

`build_query` constructs standard 12-byte header + question queries.
`decode_name` resolves RFC 1035 §4.1.4 compression pointers (`0xC0`) with loop
detection (max 127 jumps) and backward-only verification. `parse_response`
rejects truncated packets and returns `(Response, bool)` for IN-class A, AAAA,
and HTTPS answers, enforcing RFC 9460 §2.5.1 uncompressed `TargetName` rules.

### 3. DNS Cache with TTL & Stale-While-Revalidate (`dns/cache.goose`)

```goose
enum CacheStatus { Fresh, Stale, Expired }

struct CacheEntry {
    domain:          u8[..255]        = [],
    qtype:           u16              = rfc::DNS_QTYPE_A,
    ipv4_hints:      u32[..8]         = [],
    ipv6_hints:      u8[16][..8]      = [],
    https_records:   HttpsRecord[..2] = [],
    inserted_at_sec: i64              = 0,
    ttl_sec:         u32              = 300,
    stale_ttl_sec:   u32              = 86400,
    valid:           bool             = false,
    lru_prev:        i32              = -1,
    lru_next:        i32              = -1,
}

struct Cache {
    entries:  CacheEntry[..16] = [],
    lru_head: i32              = -1,
    lru_tail: i32              = -1,
}

fn lookup(cache: const Cache&, domain: const u8[:], qtype: u16, now_sec: i64) -> const CacheEntry?, CacheStatus
fn insert(cache: Cache&, entry: const CacheEntry&)
```

`Cache` provides fixed 16-entry LRU storage with RFC 5861 Stale-While-Revalidate
grace periods (default 24h). `cache.lookup` returns a zero-copy
`const CacheEntry?` alongside `CacheStatus.Fresh` when within TTL,
`CacheStatus.Stale` during the grace window, or `(null, CacheStatus.Expired)`
past expiration.

### 4. DNS over HTTPS (DoH) Wire Helpers (`dns/doh.goose`)

```goose
struct DohResolver {
    endpoint: u8[..256] = "https://cloudflare-dns.com/dns-query",
    use_post: bool      = true,
}

fn build_doh_post_body<B>(domain: const u8[:], qtype: u16, tx_id: u16, out: B&) -> bool
fn build_doh_get_url<B>(server_url: const u8[:], domain: const u8[:], qtype: u16, out: B&) -> bool
```

`build_doh_post_body` formats standard `application/dns-message` bodies.
`build_doh_get_url` encodes Base64URL `?dns=` query parameters adhering to RFC
8484 §4.1.
