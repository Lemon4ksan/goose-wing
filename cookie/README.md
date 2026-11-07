# `cookie`

`cookie` implements RFC 6265bis and CHIPS (Cookies Having Independent
Partitioned State) cookie parsing, Mozilla Public Suffix List (PSL) domain
scoping, Schemeful Same-Site evaluation, priority-based eviction, and persistent
store serialization.

```goose
import wing;

var jar = wing::CanonicalCookieJar { .. };
let _ = wing::set(jar, "https://app.example.com/login", "sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax");
var hdr: u8[..256] = [];
wing::get(jar, "https://app.example.com/dashboard", hdr);
```

## Public API

### Canonical Cookie Model & Constants (`cookie/canonical.goose`, `cookie/constants.goose`, `cookie/limits.goose`, RFC 6265bis)

```goose
enum CookieSameSite { Default, Lax, Strict, None, Unknown }
enum CookiePriority { Low, Medium, High, Unknown }
enum CookieSourceScheme { Unset, NonSecure, Secure }
enum CookieDeleteCause { Inserted, Explicit, Overwrite, Expired, Evicted, ExpiredOverwrite, SessionCleanup }

struct CookieAccessOptions {
    is_same_site:            bool = true,
    is_top_level_navigation: bool = true,
    is_safe_method:          bool = true,
    had_cross_site_hop:      bool = false,
}

struct CookieSourceOptions {
    is_http_api:   bool = true,
    url_is_secure: bool = true,
}

struct CookieInclusionOptions {
    is_main_frame:     bool = true,
    is_secure_channel: bool = true,
}

struct CanonicalCookie {
    name:            u8[..256]          = [],
    value:           u8[..4096]         = [],
    encrypted_value: u8[..4096]         = [],
    domain:          u8[..256]          = [],
    path:            u8[..256]          = "/",
    creation_utc:    i64                = 0,
    last_access_utc: i64                = 0,
    last_update_utc: i64                = 0,
    expires_utc:     i64                = 0,
    partition_key:   u8[..256]          = [],
    source_port:     i32                = -1,
    host_only:       bool               = true,
    has_domain_attr: bool               = false,
    has_path_attr:   bool               = false,
    persistent:      bool               = false,
    secure:          bool               = false,
    httponly:        bool               = false,
    partitioned:     bool               = false,
    same_site:       CookieSameSite     = CookieSameSite.Default,
    priority:        CookiePriority     = CookiePriority.Medium,
    source_scheme:   CookieSourceScheme = CookieSourceScheme.Unset,
    creation_seq:    i64                = 0,
}

struct ServerCookieDeltaJar {
    originals: CanonicalCookie[..64] = [],
    delta:     CanonicalCookie[..64] = [],
}

fn new_canonical_cookie(name: const u8[:], value: const u8[:]) -> CanonicalCookie
fn matches_domain(cookie: const CanonicalCookie&, host: const u8[:]) -> bool
fn matches_path(cookie: const CanonicalCookie&, req_path: const u8[:]) -> bool
fn is_expired(cookie: const CanonicalCookie&, now_us: i64) -> bool
fn is_in_lax_allowing_unsafe_window(cookie: const CanonicalCookie&, now_us: i64) -> bool
fn payload_size(cookie: const CanonicalCookie&) -> i64
fn with_value(c: CanonicalCookie&, val: const u8[:]) -> CanonicalCookie&
fn with_domain(c: CanonicalCookie&, dom: const u8[:]) -> CanonicalCookie&
fn with_host(c: CanonicalCookie&, host: const u8[:]) -> CanonicalCookie&
fn with_path(c: CanonicalCookie&, p: const u8[:]) -> CanonicalCookie&
fn with_secure(c: CanonicalCookie&, sec: bool = true) -> CanonicalCookie&
fn with_http_only(c: CanonicalCookie&, ho: bool = true) -> CanonicalCookie&
fn with_same_site(c: CanonicalCookie&, ss: CookieSameSite) -> CanonicalCookie&
fn with_priority(c: CanonicalCookie&, prio: CookiePriority) -> CanonicalCookie&
fn with_partition_key(c: CanonicalCookie&, pk: const u8[:]) -> CanonicalCookie&
fn with_max_age_seconds(c: CanonicalCookie&, max_age_sec: i64, now_us: i64) -> CanonicalCookie&
fn with_expires_utc(c: CanonicalCookie&, exp_us: i64, now_us: i64 = 0) -> CanonicalCookie&
fn with_source(c: CanonicalCookie&, scheme: CookieSourceScheme, port: i32) -> CanonicalCookie&
fn format<B>(cookie: const CanonicalCookie&, out: B&)
fn make_removal(name: const u8[:], domain: const u8[:] = "", path: const u8[:] = "/") -> CanonicalCookie
fn add_original(jar: ServerCookieDeltaJar&, c: const CanonicalCookie&)
fn add(jar: ServerCookieDeltaJar&, c: const CanonicalCookie&)
fn remove(jar: ServerCookieDeltaJar&, c: const CanonicalCookie&)
```

`CanonicalCookie` stores microsecond UTC timestamps (`creation_utc`,
`last_access_utc`, `last_update_utc`, `expires_utc`) and caps persistent
lifetimes at 400 days (34,560,000 seconds) per RFC 6265bis §5.5. `with_domain`
sets `host_only = false`, but `with_host` sets `host_only = true`.
`is_in_lax_allowing_unsafe_window` evaluates the 2-minute window for cookies
without an explicit `SameSite` attribute. `ServerCookieDeltaJar` tracks incoming
request cookies in `originals` and queues `Set-Cookie` additions or `Max-Age=0`
removals in `delta`.

### Cookie Jar Engine (`cookie/engine.goose`, RFC 6265)

```goose
struct CookieDeletionInfo {
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
    max_cookies_per_domain:    i64                  = 180,
    purge_cookies_per_domain:  i64                  = 30,
    target_cookies_per_domain: i64                  = 150,
    quota_low:                 i64                  = 30,
    quota_medium:              i64                  = 50,
    quota_high:                i64                  = 70,
    max_cookies_global:        i64                  = 3300,
    purge_cookies_global:      i64                  = 300,
    target_cookies_global:     i64                  = 3000,
    cookies:                   CanonicalCookie[>..] = [],
}

fn set_canonical_cookie(jar: CanonicalCookieJar&, new_cookie: CanonicalCookie&, opts: CookieSourceOptions, now_us: i64) -> bool
fn set_cookie_header(jar: CanonicalCookieJar&, req_url: const u8[:], set_cookie_raw: const u8[:], now_us: i64, is_http_api: bool = true, partition_key: const u8[:] = "") -> bool
fn set(jar: CanonicalCookieJar&, req_url: const u8[:], set_cookie_raw: const u8[:], now_us: i64 = 1700000000000000) -> bool
fn get_canonical_cookies_for_request(jar: CanonicalCookieJar&, req_url: const u8[:], is_http_api: bool, partition_key: const u8[:], now_us: i64, out_indices: u16[..180]&, access: CookieAccessOptions = CookieAccessOptions { .. })
fn get<B>(jar: CanonicalCookieJar&, req_url: const u8[:], out: B&, now_us: i64 = 1700000000000000)
fn build_cookie_header<B>(jar: CanonicalCookieJar&, out: B&, host: const u8[:], path: const u8[:], is_secure: bool, now_us: i64)
fn build_request_cookie_header<B>(jar: CanonicalCookieJar&, req_url: const u8[:], is_http_api: bool, partition_key: const u8[:], now_us: i64, out_header: B&, access: CookieAccessOptions = CookieAccessOptions { .. })
fn encode_cookie_header_to_map(jar: CanonicalCookieJar&, req_url: const u8[:], is_http_api: bool, partition_key: const u8[:], now_us: i64, headers: HeaderMap&, access: CookieAccessOptions = CookieAccessOptions { .. }) -> bool
fn delete_matching(jar: CanonicalCookieJar&, filter: const CookieDeletionInfo&) -> i64
fn delete_all_created_in_time_range(jar: CanonicalCookieJar&, start_us: i64, end_us: i64) -> i64
fn delete_session_cookies(jar: CanonicalCookieJar&, purge_non_secure: bool = false) -> i64
fn purge_expired(jar: CanonicalCookieJar&, now_us: i64) -> i64
fn garbage_collect_per_domain(jar: CanonicalCookieJar&, domain_key: const u8[:], now_us: i64) -> i64
fn garbage_collect_global(jar: CanonicalCookieJar&, now_us: i64) -> i64
fn enforce_chips_quota(jar: CanonicalCookieJar&, partition_key: const u8[:], domain: const u8[:], incoming_bytes: i64, incoming_count: i64 = 1) -> i64
fn has_secure_shadowing_collision(jar: const CanonicalCookieJar&, cand: const CanonicalCookie&, is_secure_origin: bool, now_us: i64) -> bool
fn has_httponly_shadowing_collision(jar: const CanonicalCookieJar&, cand: const CanonicalCookie&, is_http_api: bool, now_us: i64) -> bool
```

`get_canonical_cookies_for_request` populates `out_indices` sorted by longest
`path` descending, then earliest `creation_utc` ascending (RFC 6265 §5.4). When
a domain exceeds 180 cookies, `garbage_collect_per_domain` runs 6-round
priority-aware eviction down to 150 cookies while preserving at least 30 `Low`,
50 `Medium`, and 70 `High` priority slots. `enforce_chips_quota` evicts oldest
partitioned cookies when a `(partition_key, domain)` pair exceeds 10 KB or 180
cookies. `has_secure_shadowing_collision` and `has_httponly_shadowing_collision`
prevent non-secure origins or script APIs from overwriting or shadowing existing
`Secure` or `HttpOnly` cookies.

### Set-Cookie & Cookie Parser (`cookie/parser.goose`, RFC 6265bis §5.5)

```goose
struct CanonicalCookieURL {
    scheme:    u8[..16]  = [],
    host:      u8[..256] = [],
    path:      u8[..256] = "/",
    port:      i32       = -1,
    is_secure: bool      = false,
    valid:     bool      = false,
}

struct CookieSpan {
    name_start: i64 = 0,
    name_end:   i64 = 0,
    val_start:  i64 = 0,
    val_end:    i64 = 0,
}

fn parse_canonical_set_cookie(header_val: const u8[:], default_domain: const u8[:], default_path: const u8[:], now_us: i64) -> CanonicalCookie, CookieDeleteCause, bool
fn parse_canonical_cookie_url(raw_url: const u8[:]) -> CanonicalCookieURL
fn has_prohibited_cookie_ctl(s: const u8[:]) -> bool
fn parse_cookie_date_us(date_str: const u8[:]) -> i64, bool
fn next_cookie_span(raw_header: const u8[:], cursor: i64&) -> CookieSpan, bool
fn cookie_name(raw_header: const u8[:], span: CookieSpan) -> const u8[:]
fn cookie_value(raw_header: const u8[:], span: CookieSpan) -> const u8[:]
fn find_cookie_value(raw_header: const u8[:], target_name: const u8[:]) -> const u8[:], bool
fn decode_cookie_percent<B>(src: const u8[:], out: B&) -> bool
fn encode_cookie_percent<B>(src: const u8[:], out: B&) -> bool
```

`parse_canonical_set_cookie` rejects any header containing prohibited ASCII
control bytes (`0x00..0x08`, `0x0A..0x1F`, `0x7F` checked via
`has_prohibited_cookie_ctl`), enforces combined name+value size limits, and
validates security prefix rules (`__Secure-`, `__Host-`, `__Http-`,
`__Host-Http-`) and `SameSite=None` `Secure` requirements. `next_cookie_span`
advances `cursor` across `;`-separated pairs in a `Cookie` request header and
yields zero-copy `CookieSpan` offsets for `cookie_name` and `cookie_value`.

### Policy & SameSite Evaluation (`cookie/policy.goose`, RFC 6265bis)

```goose
enum SameSiteContextType { CrossSite, SameSiteLaxMethodUnsafe, SameSiteLax, SameSiteStrict }
enum FirstPartyURLPolicy { Default, IgnoreTopLevelNavigation }

struct SameSiteCookieContext {
    context_type:       SameSiteContextType = SameSiteContextType.CrossSite,
    schemefully_same:   bool                = false,
    is_reload:          bool                = false,
    had_cross_site_hop: bool                = false,
}

struct SiteForCookies {
    scheme:             u8[..16]  = [],
    registrable_domain: u8[..256] = [],
    schemefully_same:   bool      = true,
    is_null:            bool      = true,
}

fn is_trustworthy_non_crypto_host(host: const u8[:]) -> bool
fn adjust_origin_bound_cookies_on_insert(c: CanonicalCookie&, opts: CookieSourceOptions)
fn is_cookie_sendable_for_obc(c: const CanonicalCookie&, req_is_secure: bool, req_port: i32, host: const u8[:]) -> bool
fn validate_script_cookie_name(name: const u8[:], is_http_api: bool) -> bool
fn validate_security_cookie_prefixes(cookie_val: const CanonicalCookie&, cookie_name: const u8[:], opts: CookieSourceOptions) -> bool
fn validate_canonical_cookie_security(c: const CanonicalCookie&, opts: CookieSourceOptions, host: const u8[:]) -> u64, bool
fn is_schemeful_same_site(url_a: const u8[:], url_b: const u8[:], db: const PslDatabase&) -> bool
fn is_cookie_sendable_for_samesite(c: const CanonicalCookie&, ctx: const SameSiteCookieContext&, is_safe_method: bool, is_top_level_nav: bool, now_us: i64, lax_by_default: bool = true) -> bool
fn site_for_cookies_from_parsed_url(parsed: const CanonicalCookieURL&, db: const PslDatabase&) -> SiteForCookies
fn site_for_cookies_from_url(url: const u8[:], db: const PslDatabase&) -> SiteForCookies
fn null_site_for_cookies() -> SiteForCookies
fn format_site_for_cookies<B>(sfc: const SiteForCookies&, out: B&)
fn compare_with_frame_tree_site_and_revise(sfc: SiteForCookies&, frame_url: const u8[:], db: const PslDatabase&) -> bool
fn compute_site_for_cookies_with_ancestors(top_url: const u8[:], ancestor_urls: const u8[:][:], db: const PslDatabase&, is_sandboxed: bool = false) -> SiteForCookies
fn is_first_party(req_url: const u8[:], site_for_cookies: const SiteForCookies&, top_frame_origin: const u8[:], db: const PslDatabase&, policy: FirstPartyURLPolicy = FirstPartyURLPolicy.Default) -> bool
fn is_request_same_site(req_url: const u8[:], site_for_cookies: const SiteForCookies&, db: const PslDatabase&) -> bool
fn can_set_canonical_cookie_for_context(c: const CanonicalCookie&, req_url: const u8[:], site_for_cookies: const SiteForCookies&, db: const PslDatabase&, opts: CookieSourceOptions) -> bool
```

`is_schemeful_same_site` requires both URLs to share the same scheme and
registrable domain (`eTLD+1`). `SiteForCookies` represents the first-party site
context for a document or frame hierarchy;
`compare_with_frame_tree_site_and_revise` and
`compute_site_for_cookies_with_ancestors` nullify `SiteForCookies` (`is_null =
true`) when any ancestor frame is cross-site or sandboxed.
`adjust_origin_bound_cookies_on_insert` and `is_cookie_sendable_for_obc` track
origin scheme and port provenance (Origin-Bound Cookies), rewriting loopback
`Secure` cookies on port 80 to port 443.

### Mozilla Public Suffix List (`cookie/psl.goose`)

```goose
enum PslRuleType { Normal, Wildcard, Exception }
enum PslSection { Icann, Private }

struct PslRule {
    pattern:   u8[..128]   = [],
    rule_type: PslRuleType = PslRuleType.Normal,
    section:   PslSection  = PslSection.Icann,
}

struct PslMatch {
    suffix_len:    i64        = 0,
    is_known_rule: bool       = false,
    is_exception:  bool       = false,
    section:       PslSection = PslSection.Icann,
}

struct PslDatabase {
    rules: PslRule[..256] = [],
}

fn new_psl_database() -> PslDatabase
fn add_psl_rule(db: PslDatabase&, pattern: const u8[:], rule_type: PslRuleType, section: PslSection) -> bool
fn update_with_list(db: PslDatabase&, raw_list: const u8[:]) -> i64
fn punycode_encode_label<B>(utf8_label: const u8[:], out: B&) -> bool
fn punycode_encode_domain<B>(domain: const u8[:], out: B&) -> bool
fn match_public_suffix(db: const PslDatabase&, domain: const u8[:], include_private: bool = true) -> PslMatch
fn find_public_suffix<B>(db: const PslDatabase&, domain: const u8[:], out: B&) -> bool, bool
fn extract_etld_plus_one<B>(db: const PslDatabase&, host: const u8[:], out: B&) -> bool
fn is_public_suffix(db: const PslDatabase&, domain: const u8[:], include_private: bool = true) -> bool
fn psl_is_public_suffix(domain: const u8[:]) -> bool
fn psl_extract_etld_plus_one<B>(host: const u8[:], out: B&) -> bool
fn cookie_domain_match(host: const u8[:], cookie_domain: const u8[:]) -> bool
fn cookie_path_match(req_path: const u8[:], cookie_path: const u8[:]) -> bool
fn compute_default_cookie_path<B>(uri_path: const u8[:], out: B&)
```

`PslDatabase` combines a compiled 920-byte Deterministic Acyclic Finite State
Automaton (`PSL_DAFSA_GRAPH`) with dynamic `PslRule` entries loaded via
`add_psl_rule` or `update_with_list`. `punycode_encode_label` and
`punycode_encode_domain` convert internationalized UTF-8 labels to `xn--` ASCII
per RFC 3492 before suffix lookup. `cookie_domain_match` enforces RFC 6265
§5.1.3 domain suffix matching on DNS names and exact byte matching on IPv4/IPv6
literals per RFC 6055.

### Persistence, SQLite v24 Schema & Write-Back Batcher (`cookie/store.goose`)

```goose
enum StoreOpType { InsertOrUpdate, Delete }

struct PendingStoreOp {
    op_type: StoreOpType     = StoreOpType.InsertOrUpdate,
    cookie:  CanonicalCookie = CanonicalCookie { .. },
}

struct WriteBackBatcher {
    ops:                   PendingStoreOp[..128] = [],
    last_commit_us:        i64                   = 0,
    commit_interval_us:    i64                   = 30000000,
    max_pending_threshold: i64                   = 64,
}

fn new_write_back_batcher(commit_interval_us: i64 = 30000000, max_pending_threshold: i64 = 64) -> WriteBackBatcher
fn queue_store_mutation(batcher: WriteBackBatcher&, op_type: StoreOpType, c: const CanonicalCookie&) -> bool
fn queue_insert(batcher: WriteBackBatcher&, c: const CanonicalCookie&) -> bool
fn queue_delete(batcher: WriteBackBatcher&, c: const CanonicalCookie&) -> bool
fn should_commit_batch(batcher: const WriteBackBatcher&, now_us: i64) -> bool
fn flush_store_batch<B>(batcher: WriteBackBatcher&, now_us: i64, out_sql: B&) -> i64
fn generate_sqlite_v24_schema<B>(out: B&)
fn generate_sqlite_insert_sql<B>(c: const CanonicalCookie&, out: B&)
fn generate_sqlite_delete_sql<B>(c: const CanonicalCookie&, out: B&)
fn generate_sqlite_session_cleanup_sql<B>(purge_non_secure: bool, out: B&)
fn format_cookie_header_from_indices<B>(jar: const CanonicalCookieJar&, indices: const u16[:], out: B&)
fn format_cookie_header_value<B>(cookies: const CanonicalCookie[:], out: B&)
fn parse_server_cookie_header(raw_cookie_hdr: const u8[:], out_cookies: CanonicalCookie[..64]&) -> i64
fn get_server_cookie(raw_cookie_hdr: const u8[:], target_name: const u8[:]) -> const u8[:], bool
fn are_cookies_store_identical(a: const CanonicalCookie&, b: const CanonicalCookie&) -> bool
fn import_netscape(jar: CanonicalCookieJar&, text: const u8[:], now_us: i64) -> i64
fn export_netscape<B>(jar: const CanonicalCookieJar&, out: B&)
fn import_json(jar: CanonicalCookieJar&, json_text: const u8[:], now_us: i64) -> i64
fn export_json<B>(jar: const CanonicalCookieJar&, out: B&)
```

`WriteBackBatcher` coalesces up to 128 pending mutations by the 6-tuple unique
store key `(domain, name, path, partition_key, host_only, source_port)` checked
via `are_cookies_store_identical`, flushing transactional SQLite v24 statements
when `should_commit_batch` triggers (default 64 operations or 30 seconds).
`import_netscape` / `export_netscape` and `import_json` / `export_json`
serialize persistent cookies to Netscape `cookies.txt` and JSON formats.

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
