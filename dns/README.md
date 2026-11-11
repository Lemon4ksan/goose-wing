# `dns`

Package `dns` provides a deterministic, zero-allocation DNS engine conforming to
RFC 1035 wire messaging, RFC 2181 TTL handling, RFC 9460 HTTPS/SVCB Resource
Records (Type 65), RFC 8484 DNS-over-HTTPS (DoH), and RFC 5861
Stale-While-Revalidate caching for `goose-wing`.

All parsers, serializers, and cache lookups operate without dynamic heap
allocations on the hot path, using stack-bounded buffers (`u8[..N]`) and
zero-copy byte slices (`const u8[:]`).

```goose
import wing;

var query: u8[..512] = [];
let ok = wing::build_dns_query("example.com", 1, 0x1234, query);

var resp = wing::DnsResponse { .. };
let parsed = wing::parse_dns_response(query[..], resp);
```

## Public API Reference

### 1. RFC 9460 HTTPS and SVCB Resource Records (`dns/svcb.goose`)

```goose
struct HttpsRecord {
    priority:        u16           = 0,
    target_name:     u8[..255]     = [],
    alpns:           u8[..16][..8] = [],
    port:            u16           = 443,
    no_default_alpn: bool          = false,
    ipv4_hints:      u32[..8]      = [],
    ipv6_hints:      u8[16][..8]   = [],
    ech_config_list: u8[..512]     = [],
    has_ech:         bool          = false,
}

fn parse_alpn_svc_param(val: const u8[:], rec: HttpsRecord&) -> bool
fn parse_mandatory_svc_param(val: const u8[:]) -> u32, bool
fn parse_ipv4_hints(val: const u8[:], rec: HttpsRecord&) -> bool
fn parse_ipv6_hints(val: const u8[:], rec: HttpsRecord&) -> bool
fn parse_https_svc_params(rdata: const u8[:], rec: HttpsRecord&) -> bool
```

`HttpsRecord` models RFC 9460 Type 65 parameters for ALPN extraction (`h2`,
`h3`), port overrides, IPv4/IPv6 address hints, and Encrypted Client Hello
(`ech_config_list`). `parse_https_svc_params` validates strictly ascending
`SvcParamKey` order and checks mandatory key masks.

### 2. RFC 1035 DNS Wire Codec (`dns/wire.goose`)

```goose
struct DnsResponse {
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

fn dns_encode_name<B>(domain: const u8[:], out: B&) -> bool
fn dns_decode_name<B>(raw: const u8[:], offset: i64&, domain: B&) -> bool
fn dns_decode_uncompressed_name<B>(raw: const u8[:], offset: i64&, max_offset: i64, domain: B&) -> bool
fn serialize_dns_header<B>(tx_id: u16, qd_count: u16, flags: u16, out: B&)
fn serialize_dns_question<B>(domain: const u8[:], qtype: u16, qclass: u16, out: B&) -> bool
fn build_dns_query<B>(domain: const u8[:], qtype: u16, tx_id: u16, out: B&) -> bool
fn parse_dns_answer_record(raw: const u8[:], rtype: u16, rdlength: i64, rdata_start: i64, out: DnsResponse&) -> bool
fn skip_dns_questions(raw: const u8[:], off: i64&, count: u16) -> bool
fn parse_dns_answers(raw: const u8[:], off: i64&, out: DnsResponse&) -> bool
fn parse_dns_response(raw: const u8[:], out: DnsResponse&) -> bool
```

`build_dns_query` constructs standard 12-byte header + question queries.
`dns_decode_name` resolves RFC 1035 §4.1.4 compression pointers (`0xC0`) with
loop detection (max 16 jumps) and backward-only verification.
`dns_decode_uncompressed_name` enforces RFC 9460 §2.5.1 pointer prohibitions on
HTTPS/SVCB `TargetName` fields. `parse_dns_response` rejects truncated packets
and parses IN class A, AAAA, and HTTPS answers.

### 3. DNS Cache with TTL & Stale-While-Revalidate (`dns/cache.goose`)

```goose
enum DnsCacheStatus { Fresh, Stale, Expired }

struct DnsCacheEntry {
    domain:          u8[..255]        = [],
    qtype:           u16              = rfc::DNS_QTYPE_A,
    ipv4_hints:      u32[..8]         = [],
    ipv6_hints:      u8[16][..8]      = [],
    https_records:   HttpsRecord[..4] = [],
    inserted_at_sec: i64              = 0,
    ttl_sec:         u32              = 300,
    stale_ttl_sec:   u32              = 86400,
    valid:           bool             = false,
    lru_prev:        i32              = -1,
    lru_next:        i32              = -1,
}

struct DnsCache {
    entries:  DnsCacheEntry[..64] = [],
    lru_head: i32                 = -1,
    lru_tail: i32                 = -1,
}

fn detach_dns_lru(cache: DnsCache&, idx: i32)
fn attach_dns_lru_tail(cache: DnsCache&, idx: i32)
fn touch_dns_lru(cache: DnsCache&, idx: i32)
fn dns_cache_lookup(cache: const DnsCache&, domain: const u8[:], qtype: u16, now_sec: i64, out_entry: DnsCacheEntry&) -> DnsCacheStatus
fn dns_cache_insert(cache: DnsCache&, entry: const DnsCacheEntry&)
```

`DnsCache` provides fixed 64-entry LRU storage with RFC 5861
Stale-While-Revalidate grace periods (default 24h). `dns_cache_lookup` returns
`DnsCacheStatus.Fresh` when within TTL, `DnsCacheStatus.Stale` during the grace
window, and `DnsCacheStatus.Expired` past expiration.

### 4. DNS over HTTPS (DoH) Wire Helpers (`dns/doh.goose`)

```goose
struct DohResolver {
    endpoint: u8[..256] = "https://cloudflare-dns.com/dns-query",
    use_post: bool      = true,
}

fn build_doh_post_body<B>(domain: const u8[:], qtype: u16, tx_id: u16, out_body: B&) -> bool
fn build_doh_get_url<B>(server_url: const u8[:], domain: const u8[:], qtype: u16, out_url: B&) -> bool
```

`build_doh_post_body` formats standard `application/dns-message` bodies.
`build_doh_get_url` encodes Base64URL `?dns=` query parameters adhering to RFC
8484 §4.1.
