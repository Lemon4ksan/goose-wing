# `cookie`

`cookie` implements RFC 6265bis and CHIPS (Cookies Having Independent
Partitioned State) cookie parsing, Mozilla Public Suffix List (PSL) domain
scoping, Schemeful Same-Site evaluation, priority-based eviction, and persistent
store serialization.

All public symbols live in `namespace cookie`, while internal helpers and quota
constants live in `namespace cookie_internal`.

```goose
import cookie;

var jar = cookie::CanonicalCookieJar { .. };
let _ = jar.set_cookie_header(
    "https://app.example.com/login",
    "sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax",
    1700000000000000,
);
var hdr: u8[..256] = [];
jar.build_cookie_header("https://app.example.com/dashboard", 1700000000000000, hdr);
```

## Public API

### Canonical cookie model & constants (`cookie/canonical.goose`, `cookie/constants.goose`, RFC 6265bis)

```goose
enum SameSite { Default, Lax, Strict, None, Unknown }
enum Priority { Low, Medium, High, Unknown }
enum SourceScheme { Unset, NonSecure, Secure, Unknown }
enum DeleteCause {
    UNKNOWN, EXPIRED, OVERWRITE, EXPLICIT, UNKNOWN_DELETION, DONT_RECORD,
    EVICTED_DOMAIN, EVICTED_GLOBAL, EXPIRED_OVERWRITE, CONTROL_CHAR, NON_SECURE,
}

struct AccessOptions {
    is_same_site:            bool = true,
    is_top_level_navigation: bool = true,
    is_safe_method:          bool = true,
    had_cross_site_hop:      bool = false,
}

struct SourceOptions {
    is_http_api:   bool = true,
    url_is_secure: bool = true,
}

struct InclusionOptions {
    is_main_frame:     bool = true,
    is_secure_channel: bool = true,
}

struct CanonicalCookie {
    name:            u8[..256]    = [],
    value:           u8[..4096]   = [],
    encrypted_value: u8[..4096]   = [],
    domain:          u8[..256]    = [],
    path:            u8[..1024]   = "/",
    creation_utc:    i64          = 0,
    last_access_utc: i64          = 0,
    last_update_utc: i64          = 0,
    expires_utc:     i64          = 0,
    partition_key:   u8[..256]    = [],
    source_port:     i32          = -1,
    host_only:       bool         = true,
    has_domain_attr: bool         = false,
    has_path_attr:   bool         = false,
    persistent:      bool         = false,
    secure:          bool         = false,
    httponly:        bool         = false,
    partitioned:     bool         = false,
    same_site:       SameSite     = SameSite.Default,
    priority:        Priority     = Priority.Medium,
    source_scheme:   SourceScheme = SourceScheme.Unset,
    creation_seq:    i64          = 0,
}

struct ServerCookieDeltaJar {
    cookies: CanonicalCookie[..64] = [],
    states:  u8[..64]              = [],
}

fn parse_same_site(raw_val: const u8[:]) -> SameSite
fn parse_priority(raw_val: const u8[:]) -> Priority
fn new_canonical_cookie(name: const u8[:], val: const u8[:]) -> CanonicalCookie
fn is_expired(cookie_val: const CanonicalCookie&, now_us: i64) -> bool
fn payload_size(cookie_val: const CanonicalCookie&) -> i64
fn with_value(cookie_ref: CanonicalCookie&, val: const u8[:]) -> CanonicalCookie&
fn with_domain(cookie_ref: CanonicalCookie&, domain_val: const u8[:], host_only: bool = false) -> CanonicalCookie&
fn with_host(cookie_ref: CanonicalCookie&, host_val: const u8[:]) -> CanonicalCookie&
fn with_path(cookie_ref: CanonicalCookie&, path_val: const u8[:]) -> CanonicalCookie&
fn with_secure(cookie_ref: CanonicalCookie&, is_secure: bool = true) -> CanonicalCookie&
fn with_http_only(cookie_ref: CanonicalCookie&, is_http_only: bool = true) -> CanonicalCookie&
fn with_same_site(cookie_ref: CanonicalCookie&, same_site_mode: SameSite) -> CanonicalCookie&
fn with_priority(cookie_ref: CanonicalCookie&, priority_level: Priority) -> CanonicalCookie&
fn with_partition_key(cookie_ref: CanonicalCookie&, key: const u8[:]) -> CanonicalCookie&
fn with_max_age_seconds(cookie_ref: CanonicalCookie&, seconds: i64, now_us: i64) -> CanonicalCookie&
fn with_expires_utc(cookie_ref: CanonicalCookie&, expires_us: i64) -> CanonicalCookie&
fn with_source(cookie_ref: CanonicalCookie&, scheme: SourceScheme, port: i32) -> CanonicalCookie&
fn matches_domain(cookie_val: const CanonicalCookie&, host: const u8[:]) -> bool
fn matches_path(cookie_val: const CanonicalCookie&, req_path: const u8[:]) -> bool
fn format<B>(cookie_val: const CanonicalCookie&, out: B&)
fn add_original(jar: ServerCookieDeltaJar&, c: CanonicalCookie) -> bool
fn add(jar: ServerCookieDeltaJar&, c: CanonicalCookie) -> bool
fn remove(jar: ServerCookieDeltaJar&, c: CanonicalCookie) -> bool
fn flush_deltas(jar: const ServerCookieDeltaJar&, headers: wing::HeaderMap&) -> bool
```

`CanonicalCookie` stores microsecond UTC timestamps (`creation_utc`,
`last_access_utc`, `last_update_utc`, `expires_utc`) and caps persistent
lifetimes at 400 days (34,560,000 seconds) per RFC 6265bis §5.5. `with_domain`
sets `host_only = false` by default, while `with_host` sets `host_only = true`.
`ServerCookieDeltaJar` tracks initial request cookies and flushes net
`Set-Cookie` additions and `Max-Age=0` deletions via `flush_deltas`.

### Cookie jar engine (`cookie/engine.goose`, RFC 6265)

```goose
struct DeletionInfo {
    start_utc:          i64       = 0,
    end_utc:            i64       = 0,
    session_only:       bool      = false,
    domain:             u8[..128] = [],
    name:               u8[..128] = [],
    partition_key:      u8[..256] = [],
    top_frame_site_key: u8[..256] = [],
    purge_non_secure:   bool      = false,
}

struct CanonicalCookieJar {
    max_cookies_per_domain:     i64                  = 180,
    target_cookies_per_domain:  i64                  = 150,
    quota_low:                  i64                  = 30,
    quota_medium:               i64                  = 50,
    quota_high:                 i64                  = 70,
    max_cookies_global:         i64                  = 3300,
    purge_cookies_global:       i64                  = 300,
    target_cookies_global:      i64                  = 3000,
    seq_counter:                i64                  = 1,
    overwritten_count:          i64                  = 0,
    evicted_expired_count:      i64                  = 0,
    evicted_domain_count:       i64                  = 0,
    evicted_global_count:       i64                  = 0,
    evicted_chips_count:        i64                  = 0,
    expired_overwrite_count:    i64                  = 0,
    rejected_security_count:    i64                  = 0,
    strict_secure_cookies:      bool                 = false,
    access_update_threshold_us: i64                  = 60000000,
    cookies:                    CanonicalCookie[>..] = [],
}

fn add(jar: CanonicalCookieJar&, name: const u8[:], val: const u8[:]) -> CanonicalCookie&
fn purge_expired(jar: CanonicalCookieJar&, now_us: i64) -> i64
fn delete_matching(jar: CanonicalCookieJar&, filter: const DeletionInfo&) -> i64
fn delete_all_created_in_time_range(jar: CanonicalCookieJar&, start_utc: i64, end_utc: i64) -> i64
fn delete_session_cookies(jar: CanonicalCookieJar&, purge_non_secure: bool = false) -> i64
fn set(jar: CanonicalCookieJar&, cookie_val: CanonicalCookie, now_us: i64) -> bool
fn get(jar: CanonicalCookieJar&, req_url: const u8[:], name: const u8[:], now_us: i64, access: AccessOptions = AccessOptions { .. }, partition_key: const u8[:] = "") -> const u8[:]
fn get(jar: const CanonicalCookieJar&, name: const u8[:]) -> const u8[:]
fn set_canonical_cookie(jar: CanonicalCookieJar&, new_cookie: CanonicalCookie&, opts: SourceOptions, now_us: i64) -> bool
fn set_cookie_header(jar: CanonicalCookieJar&, req_url: const u8[:], set_cookie_raw: const u8[:], now_us: i64, is_http_api: bool = true, partition_key: const u8[:] = "") -> bool
fn set_cookie_header(jar: CanonicalCookieJar&, req_url: const u8[:], set_cookie_raw: const u8[:], now_us: i64, partition_key: const u8[:]) -> bool
fn build_cookie_header<B>(jar: CanonicalCookieJar&, host: const u8[:], path: const u8[:], is_secure: bool, now_us: i64, out: B&)
fn build_cookie_header<B>(jar: CanonicalCookieJar&, req_url: const u8[:], now_us: i64, out: B&)
fn build_cookie_header<B>(jar: CanonicalCookieJar&, req_url: const u8[:], now_us: i64, partition_key: const u8[:], out: B&)
fn build_request_cookie_header<B>(jar: CanonicalCookieJar&, req_url: const u8[:], is_http_api: bool, partition_key: const u8[:], now_us: i64, out: B&)
fn get_canonical_cookies_for_request(jar: CanonicalCookieJar&, req_url: const u8[:], is_http_api: bool, partition_key: const u8[:], now_us: i64, out_indices: u16[..180]&, access: AccessOptions = AccessOptions { .. })
fn get_canonical_cookies_for_request(jar: CanonicalCookieJar&, host: const u8[:], path: const u8[:], scheme: const u8[:], port: i32, source: SourceOptions, partition_key: const u8[:], now_us: i64, out_indices: u16[..180]&, access: AccessOptions = AccessOptions { .. })
fn encode_cookie_header_to_map(jar: CanonicalCookieJar&, host: const u8[:], path: const u8[:], scheme: const u8[:], port: i32, source: SourceOptions, partition_key: const u8[:], now_us: i64, access: AccessOptions, headers: wing::HeaderMap&) -> bool
fn garbage_collect_global(jar: CanonicalCookieJar&, now_us: i64) -> i64
```

`get_canonical_cookies_for_request` populates `out_indices` sorted by longest
`path` descending, then earliest `creation_utc` ascending (RFC 6265 §5.4). When
a domain exceeds 180 cookies, insertion runs 6-round priority-aware eviction
down to 150 cookies while protecting at least 30 `Low`, 50 `Medium`, and 70
`High` priority slots, and CHIPS enforces 10 KB and 180 cookies per
`(partition_key, domain)` pair.

### Set-Cookie & Cookie header parser (`cookie/parser.goose`, RFC 6265bis §5.5)

```goose
struct CanonicalCookieURL {
    scheme:    u8[..16]   = [],
    host:      u8[..256]  = [],
    path:      u8[..2048] = "/",
    port:      i32        = 80,
    is_secure: bool       = false,
}

struct Span {
    name_pos: u16 = 0,
    name_len: u16 = 0,
    val_pos:  u16 = 0,
    val_len:  u16 = 0,
}

fn parse_canonical_set_cookie(header_val: const u8[:], default_domain: const u8[:], default_path: const u8[:], now_us: i64) -> CanonicalCookie, DeleteCause, bool
fn parse_date_us(raw: const u8[:]) -> i64, bool
fn parse_canonical_cookie_url(raw_url: const u8[:]) -> CanonicalCookieURL
fn apply_parsed_path_attribute(cookie_ref: CanonicalCookie&, attr_val: const u8[:], default_path: const u8[:] = "")
fn parse_kv_span(raw: const u8[:], pair_start: i64, pair_end: i64) -> Span
fn next_span(raw_header: const u8[:], cursor: i64&) -> Span, bool
fn span_value(raw: const u8[:], span: Span) -> const u8[:]
fn span_name(raw: const u8[:], span: Span) -> const u8[:]
fn find_cookie_value(raw_header: const u8[:], name: const u8[:]) -> const u8[:], bool
fn decode_percent<B>(src: const u8[:], out: B&) -> bool
fn encode_percent<B>(src: const u8[:], out: B&) -> bool
```

`parse_canonical_set_cookie` rejects headers containing prohibited ASCII control
bytes (`0x00..0x08`, `0x0A..0x1F`, `0x7F`), enforces combined name+value size
limits, and validates security prefix rules (`__Secure-`, `__Host-`, `__Http-`,
`__Host-Http-`) and `SameSite=None` `Secure` requirements. `next_span` advances
`cursor` across `;`-separated pairs in a `Cookie` request header and yields
zero-copy `Span` offsets for `span_name` and `span_value`.

### Policy & SameSite evaluation (`cookie/policy.goose`, RFC 6265bis)

```goose
enum FirstPartyURLPolicy { NEVER_CHANGE_FIRST_PARTY_URL, UPDATE_FIRST_PARTY_URL_ON_REDIRECT }
enum SameSiteContextType { CrossSite, SameSiteLaxMethodUnsafe, SameSiteLax, SameSiteStrict }

struct SameSiteCookieContext {
    context_type:       SameSiteContextType = SameSiteContextType.CrossSite,
    schemefully_same:   bool                = true,
    is_reload:          bool                = false,
    had_cross_site_hop: bool                = false,
}

fn is_trustworthy_non_crypto_host(host: const u8[:]) -> bool
fn validate_security(cookie_val: const CanonicalCookie&, opts: SourceOptions = SourceOptions { .. }) -> bool
fn is_schemeful_same_site(scheme1: const u8[:], host1: const u8[:], scheme2: const u8[:], host2: const u8[:]) -> bool
fn is_sendable_for_samesite(cookie_val: const CanonicalCookie&, access: AccessOptions, now_us: i64) -> bool
fn site_for_cookies_from_url(url: const u8[:]) -> wing::SiteForCookies
fn site_for_cookies_from_parsed_url(url_val: const core::Url&) -> wing::SiteForCookies
fn null_site_for_cookies() -> wing::SiteForCookies
fn format_site_for_cookies<B>(site: const wing::SiteForCookies&, out: B&)
fn compare_with_frame_tree_site_and_revise(site: wing::SiteForCookies&, frame_url: const u8[:])
fn compute_site_for_cookies_with_ancestors(top_url: const u8[:], ancestor_urls: const u8[:][:], is_sandboxed: bool = false) -> wing::SiteForCookies
fn is_first_party(site: const wing::SiteForCookies&, req_url: const u8[:], compute_schemefully: bool = true) -> bool
fn is_request_same_site(site: const wing::SiteForCookies&, req_url: const u8[:]) -> bool
fn can_set_for_context(cookie_val: const CanonicalCookie&, context: const SameSiteCookieContext&, opts: InclusionOptions = InclusionOptions { .. }) -> i64, bool
```

`is_schemeful_same_site` requires both URLs to share the same scheme and
registrable domain (`eTLD+1`). `wing::SiteForCookies` (defined in
`http/request.goose`) represents the first-party site context for a frame tree;
`compare_with_frame_tree_site_and_revise` and
`compute_site_for_cookies_with_ancestors` mark `SiteForCookies` as null when any
ancestor frame is cross-site or sandboxed.

### Mozilla Public Suffix List (`cookie/psl.goose`)

```goose
enum PslRuleType { Normal, Wildcard, Exception }
enum PslSection { Icann, Private }

struct PslRule {
    pattern:   u8[..64]    = [],
    rule_type: PslRuleType = PslRuleType.Normal,
    section:   PslSection  = PslSection.Icann,
}

struct PslDatabase {
    use_dafsa: bool          = false,
    rules:     PslRule[..64] = [],
}

fn is_public_suffix(domain: const u8[:]) -> bool
fn new_psl_database() -> PslDatabase
fn add_rule(db: PslDatabase&, pattern: const u8[:], rule_type: PslRuleType, section: PslSection)
fn update_with_list(db: PslDatabase&, psl_text: const u8[:])
fn parse_rule_line(line: const u8[:], sec: PslSection) -> PslRule, bool
fn normalize_domain<B>(domain: const u8[:], out: B&) -> bool
fn find_public_suffix<B>(db: const PslDatabase&, domain: const u8[:], out: B&) -> bool, bool
fn is_known_public_suffix(db: const PslDatabase&, domain: const u8[:]) -> bool
fn is_public_suffix(db: const PslDatabase&, domain: const u8[:], is_icann_only: bool = false) -> bool
fn extract_etld_plus_one<B>(db: const PslDatabase&, host: const u8[:], out: B&)
fn extract_etld_plus_one<B>(host: const u8[:], out: B&)
fn is_public_suffix_domain(domain: const u8[:]) -> bool
fn domain_match(host: const u8[:], cookie_domain: const u8[:]) -> bool
fn domain_match(db: const PslDatabase&, host: const u8[:], cookie_domain: const u8[:]) -> bool
fn compute_default_path<B>(uri_path: const u8[:], out: B&)
fn path_match(req_path: const u8[:], cookie_path: const u8[:]) -> bool
```

`PslDatabase` combines a compiled 920-byte DAFSA
(`cookie_internal::PSL_DAFSA_GRAPH`) with dynamic `PslRule` entries loaded via
`add_rule` or `update_with_list`. `core::punycode_encode_label` and
`core::punycode_encode_domain` normalize UTF-8 labels to `xn--` ASCII per RFC
3492 before suffix lookup. `domain_match` enforces RFC 6265 §5.1.3 domain suffix
matching on DNS names and exact byte matching on IPv4/IPv6 literals per
RFC 6055.

### Persistence, SQLite v24 schema & write-back batcher (`cookie/store.goose`)

```goose
enum StoreOpType { InsertOrUpdate, Delete }

struct PendingStoreOp {
    op_type: StoreOpType     = StoreOpType.InsertOrUpdate,
    cookie:  CanonicalCookie = CanonicalCookie { .. },
}

struct WriteBackBatcher {
    max_batch_size:      i64                   = 512,
    commit_interval_ms:  i64                   = 30000,
    last_commit_ms:      i64                   = 0,
    total_committed_ops: i64                   = 0,
    total_coalesced_ops: i64                   = 0,
    ops:                 PendingStoreOp[..256] = [],
}

fn new_write_back_batcher(now_ms: i64 = 0) -> WriteBackBatcher
fn queue_insert(batcher: WriteBackBatcher&, cookie_val: const CanonicalCookie&) -> bool
fn queue_delete(batcher: WriteBackBatcher&, cookie_val: const CanonicalCookie&) -> bool
fn generate_sqlite_insert_sql<B>(cookie_val: const CanonicalCookie&, out: B&)
fn generate_sqlite_delete_sql<B>(cookie_val: const CanonicalCookie&, out: B&)
fn format_cookie_header_value<B>(cookies: const CanonicalCookie[:], out: B&)
fn parse_server_cookie_header<C>(raw_header: const u8[:], now_us: i64, out: C&, max_cookies: i64 = 100)
fn parse_server_cookie_header<C>(raw_header: const u8[:], out: C&, max_cookies: i64 = 100)
fn parse_server_cookie_header(raw_header: const u8[:]) -> CanonicalCookie[>..]
fn get_server_cookie(cookies: const CanonicalCookie[:], name: const u8[:]) -> const u8[:]
fn export_netscape<B>(jar: const CanonicalCookieJar&, out: B&)
fn import_netscape(jar: CanonicalCookieJar&, content: const u8[:], now_us: i64) -> i64
fn try_parse_netscape_cookie_line(raw_line: const u8[:]) -> CanonicalCookie, bool
fn export_json<B>(jar: const CanonicalCookieJar&, out: B&)
fn import_json(jar: CanonicalCookieJar&, json_text: const u8[:], now_us: i64) -> i64
```

`WriteBackBatcher` coalesces up to 256 pending mutations by store key `(domain,
name, path, partition_key, host_only, source_port)` and formats SQLite v24
`INSERT` and `DELETE` statements via `generate_sqlite_insert_sql` and
`generate_sqlite_delete_sql`. `import_netscape` / `export_netscape` and
`import_json` / `export_json` serialize persistent cookies to Netscape
`cookies.txt` and JSON formats.

## Invariants

| Invariant | Limit / Rule |
| :--- | :--- |
| RFC 6265 §5.4 sorting | Query results order by longest `path` descending, then earliest `creation_utc` ascending. |
| Max-Age cap | Persistent cookie lifetimes cap at 400 days (34,560,000 seconds) per RFC 6265bis §5.5. |
| Control character rejection | `0x00..0x08`, `0x0A..0x1F`, and `0x7F` are rejected across names, values, domains, and paths. |
| CHIPS memory quota | Partitioned cookies cap at 10 KB and 180 cookies per `(partition_key, domain)` pair. |
| Prefix enforcement | `__Secure-`, `__Host-`, `__Http-`, and `__Host-Http-` rules apply case-insensitively. |

## Verification

```bash
python tools/test_runner.py -p "*cookie*"
python tools/test_runner.py --check-only
python scripts/lint_invariants.py --target-file cookie/engine.goose --strict-examples
```
