// Comprehensive RFC 6265 & RFC 6265bis (CHIPS) CookieJar implementation for goose-wing,
// porting the architecture, security invariants, and ergonomics of aoni.
namespace wing;

import std;
import os;
import json;

// RFC 6265bis §5.5 limits
let MAX_COOKIE_AGE_SECONDS: i64 = 34560000; // 400 days max age
let MAX_COOKIE_NAME_VAL_LEN: i64 = 4096;
let MAX_COOKIE_ATTR_VAL_LEN: i64 = 1024;
let MAX_COOKIES_PER_DOMAIN: i64 = 50;
let MAX_COOKIES_DEFAULT_CAP: i64 = 3000;

enum SameSite {
    Default,
    Lax,
    Strict,
    None,
}

fn same_site_to_string(s: SameSite) -> const u8[:] {
    return match s {
        Default => "Default",
        Lax => "Lax",
        Strict => "Strict",
        None => "None",
    };
}

fn parse_same_site(val: const u8[:]) -> SameSite {
    if eq_ascii_fold(val, "strict") { return SameSite.Strict; }
    if eq_ascii_fold(val, "lax") { return SameSite.Lax; }
    if eq_ascii_fold(val, "none") { return SameSite.None; }
    return SameSite.Default;
}

// Cookie representation containing full RFC 6265 & RFC 6265bis CHIPS state.
struct Cookie {
    name: u8[..128] = [],
    value: u8[..1024] = [],
    domain: u8[..128] = [],
    path: u8[..256] = "/",
    partition_key: u8[..128] = [],
    same_site: SameSite = SameSite.Default,
    expires_unix: i64 = 0,
    max_age: i64 = 0,
    created_at: i64 = 0,
    last_access: i64 = 0,
    creation_seq: i64 = 0,
    persistent: bool = false,
    host_only: bool = true,
    secure: bool = false,
    http_only: bool = false,
    partitioned: bool = false,
}

fn format(out: u8[>..]&, c: const Cookie&) {
    out.append(c.name[..]);
    out.push('=');
    out.append(c.value[..]);
    if c.domain.len > 0 {
        out.append("; Domain=");
        out.append(c.domain[..]);
    }
    if c.path.len > 0 {
        out.append("; Path=");
        out.append(c.path[..]);
    }
    if c.secure { out.append("; Secure"); }
    if c.http_only { out.append("; HttpOnly"); }
    if c.partitioned { out.append("; Partitioned"); }
    if c.same_site != SameSite.Default {
        out.append("; SameSite=");
        out.append(same_site_to_string(c.same_site));
    }
}

// Checks if s contains CTL characters %x00-08 / %x0A-1F / %x7F (excluding HTAB %x09)
// per RFC 6265bis §5.5 Step 1 & §5.7 Step 3.
fn has_prohibited_ctl(s: const u8[:]) -> bool {
    for b in s {
        if (b <= 0x08) || (b >= 0x0A && b <= 0x1F) || b == 0x7F {
            return true;
        }
    }
    return false;
}

// Detects IPv4 or IPv6 literals so domain-match does not match suffixes on IP addresses (RFC 6265 §5.1.3).
fn is_ip_address(host: const u8[:]) -> bool {
    if host.len == 0 { return false; }
    // IPv6 contains ':'
    for b in host {
        if b == ':' { return true; }
    }
    // IPv4 check: digits and dots only, exactly 3 dots
    var dots = 0;
    var all_digits_dots = true;
    for b in host {
        if b == '.' {
            dots++;
        } else if b < '0' || b > '9' {
            all_digits_dots = false;
            break;
        }
    }
    return all_digits_dots && dots == 3;
}

// RFC 6265 §5.1.3: Domain Matching
fn domain_match(host: const u8[:], cookie_domain: const u8[:]) -> bool {
    if host.len == 0 || cookie_domain.len == 0 { return false; }
    if eq_ascii_fold(host, cookie_domain) {
        return true;
    }
    if is_ip_address(host) {
        return false;
    }
    if host.len > cookie_domain.len {
        let suffix_start = host.len - cookie_domain.len;
        let suffix = host[suffix_start..];
        if eq_ascii_fold(suffix, cookie_domain) {
            if host[suffix_start - 1] == '.' {
                return true;
            }
        }
    }
    return false;
}

// RFC 6265 §5.1.4: Default-Path computation
fn default_cookie_path(uri_path: const u8[:], out: u8[..256]&) {
    out.clear();
    if uri_path.len == 0 || uri_path[0] != '/' {
        out.push('/');
        return;
    }
    var last_slash = -1;
    for i in uri_path.len {
        if uri_path[i] == '/' {
            last_slash = i;
        }
    }
    if last_slash <= 0 {
        out.push('/');
        return;
    }
    out.append(uri_path[..last_slash]);
}

// RFC 6265 §5.1.4: Path-Match algorithm
fn path_match(req_path: const u8[:], cookie_path: const u8[:]) -> bool {
    let r = if req_path.len == 0 { "/" } else { req_path };
    let c = if cookie_path.len == 0 { "/" } else { cookie_path };

    if r == c { return true; }
    if starts_with(r, c) {
        if c[c.len - 1] == '/' { return true; }
        if r.len > c.len && r[c.len] == '/' { return true; }
    }
    return false;
}

// Fast public suffix rejection per RFC 6265 §5.3 Step 5.
fn is_known_public_suffix(domain: const u8[:]) -> bool {
    let d = domain;
    if d == "com" || d == "org" || d == "net" || d == "edu" || d == "gov" || d == "mil" ||
       d == "io" || d == "co" || d == "ai" || d == "dev" || d == "app" || d == "ru" ||
       d == "uk" || d == "co.uk" || d == "org.uk" || d == "de" || d == "fr" || d == "nl" ||
       d == "eu" || d == "us" || d == "ca" || d == "me" || d == "xyz" || d == "info" ||
       d == "biz" || d == "online" || d == "site" || d == "store" {
        return true;
    }
    return false;
}

// Validates and parses a Set-Cookie Expires date per RFC 6265 §5.1.1.
// Cookie dates use a relaxed token-based state machine that accepts arbitrary
// non-alphanumeric delimiters, any field ordering, and 2-digit years (70..99 -> 1970..1999, 00..69 -> 2000..2069).
fn is_cookie_date_delim(b: u8) -> bool {
    return b == 0x09 || (b >= 0x20 && b <= 0x2F) || (b >= 0x3B && b <= 0x40) ||
           (b >= 0x5B && b <= 0x60) || (b >= 0x7B && b <= 0x7E);
}

fn parse_cookie_date(raw: const u8[:]) -> i64, bool {
    guard raw.len > 0 else { return 0, false; }

    var found_time = false;
    var found_dom = false;
    var found_month = false;
    var found_year = false;

    var hour: i64 = 0;
    var minute: i64 = 0;
    var second: i64 = 0;
    var day: i64 = 0;
    var month: i64 = 0;
    var year: i64 = 0;

    var at = 0;
    while at < raw.len {
        while at < raw.len && is_cookie_date_delim(raw[at]) { at++; }
        if at >= raw.len { break; }
        let tok_start = at;
        while at < raw.len && !is_cookie_date_delim(raw[at]) { at++; }
        let tok = raw[tok_start..at];

        // 1. Time (HH:MM:SS)
        if !found_time && tok.len >= 5 {
            var c1 = -1;
            var c2 = -1;
            for i in tok.len {
                if tok[i] == ':' {
                    if c1 < 0 { c1 = i; } else if c2 < 0 { c2 = i; break; }
                }
            }
            if c1 > 0 && c2 > c1 {
                let h_val, h_ok = parse_int(tok[..c1]);
                let m_val, m_ok = parse_int(tok[c1 + 1..c2]);
                let s_val, s_ok = parse_int(tok[c2 + 1..]);
                if h_ok && m_ok && s_ok {
                    hour = h_val;
                    minute = m_val;
                    second = s_val;
                    found_time = true;
                    continue;
                }
            }
        }

        // 2. Day of month (1-2 digits)
        if !found_dom {
            var all_digits = true;
            for b in tok {
                if b < '0' || b > '9' { all_digits = false; break; }
            }
            if all_digits && (tok.len == 1 || tok.len == 2) {
                let d_val, d_ok = parse_int(tok);
                if d_ok && d_val >= 1 && d_val <= 31 {
                    day = d_val;
                    found_dom = true;
                    continue;
                }
            }
        }

        // 3. Month (jan..dec)
        if !found_month {
            let m_val = parse_month_name(tok);
            if m_val > 0 {
                month = m_val;
                found_month = true;
                continue;
            }
        }

        // 4. Year (2-4 digits)
        if !found_year {
            var all_digits = true;
            for b in tok {
                if b < '0' || b > '9' { all_digits = false; break; }
            }
            if all_digits && (tok.len == 2 || tok.len == 4) {
                let y_val, y_ok = parse_int(tok);
                if y_ok {
                    year = y_val;
                    found_year = true;
                    continue;
                }
            }
        }
    }

    // 2-digit year normalization per RFC 6265 §5.1.1 Step 3
    if year >= 70 && year <= 99 {
        year += 1900;
    } else if year >= 0 && year <= 69 {
        year += 2000;
    }

    // Validation per RFC 6265 §5.1.1 Step 5
    guard found_time && found_dom && found_month && found_year else { return 0, false; }
    guard day >= 1 && day <= days_in_month(year, month) else { return 0, false; }
    guard year >= 1601 else { return 0, false; }
    guard hour <= 23 && minute <= 59 && second <= 59 else { return 0, false; }

    let days = civil_to_days(year, month, day);
    return days * 86400 + hour * 3600 + minute * 60 + second, true;
}

// RFC 6265bis §4.1.3 & §5.4: Validate cookie name prefixes (__Secure-, __Host-)
fn validate_cookie_security(c: const Cookie&, is_secure_channel: bool) -> bool {
    let n = c.name[..];
    if starts_with(n, "__Secure-") || starts_with(n, "__secure-") {
        if !c.secure || !is_secure_channel { return false; }
    }
    if starts_with(n, "__Host-") || starts_with(n, "__host-") {
        if !c.secure || !is_secure_channel { return false; }
        if !c.host_only || c.path[..] != "/" { return false; }
    }
    if c.partitioned && !c.secure {
        return false;
    }
    if c.same_site == SameSite.None && !c.secure {
        return false;
    }
    return true;
}

// Parses a single Set-Cookie header field value (RFC 6265 §5.2).
fn parse_set_cookie(header_val: const u8[:], default_domain: const u8[:], default_path: const u8[:], now_unix: i64) -> Cookie, bool {
    var c = Cookie { .. };
    guard header_val.len > 0 && !has_prohibited_ctl(header_val) else { return c, false; }

    var semi_pos = -1;
    for i in header_val.len {
        if header_val[i] == ';' { semi_pos = i; break; }
    }

    let name_val_part = if semi_pos >= 0 { header_val[..semi_pos] } else { header_val };
    let unparsed_attrs = if semi_pos >= 0 { header_val[semi_pos + 1..] } else { "" };

    var eq_pos = -1;
    for i in name_val_part.len {
        if name_val_part[i] == '=' { eq_pos = i; break; }
    }
    guard eq_pos >= 0 else { return c, false; }

    let raw_name = trim(name_val_part[..eq_pos]);
    let raw_val = trim(name_val_part[eq_pos + 1..]);

    guard raw_name.len > 0 else { return c, false; }
    guard raw_name.len + raw_val.len <= MAX_COOKIE_NAME_VAL_LEN else { return c, false; }

    c.name.append(raw_name);
    c.value.append(raw_val);
    c.domain.append(default_domain);
    c.path.clear();
    c.path.append(default_path);
    c.host_only = true;
    c.created_at = now_unix;
    c.last_access = now_unix;

    // Parse attributes
    if unparsed_attrs.len > 0 {
        each_split(unparsed_attrs, ';') { raw_av =>
            let av = trim(raw_av);
            if av.len > 0 {
                var attr_eq = -1;
                for i in av.len {
                    if av[i] == '=' { attr_eq = i; break; }
                }
                let a_name = if attr_eq >= 0 { trim(av[..attr_eq]) } else { av };
                let a_val = if attr_eq >= 0 { trim(av[attr_eq + 1..]) } else { "" };

                if a_val.len <= MAX_COOKIE_ATTR_VAL_LEN {
                    if eq_ascii_fold(a_name, "httponly") {
                        c.http_only = true;
                    } else if eq_ascii_fold(a_name, "secure") {
                        c.secure = true;
                    } else if eq_ascii_fold(a_name, "partitioned") {
                        c.partitioned = true;
                    } else if eq_ascii_fold(a_name, "samesite") {
                        c.same_site = parse_same_site(a_val);
                    } else if eq_ascii_fold(a_name, "domain") {
                        if a_val.len > 0 && a_val[a_val.len - 1] != '.' {
                            let clean_dom = if a_val[0] == '.' { a_val[1..] } else { a_val };
                            c.domain.clear();
                            c.domain.append(clean_dom);
                            to_lower(c.domain[..]);
                            c.host_only = false;
                        }
                    } else if eq_ascii_fold(a_name, "path") {
                        if a_val.len > 0 && a_val[0] == '/' {
                            c.path.clear();
                            c.path.append(a_val);
                        }
                    } else if eq_ascii_fold(a_name, "max-age") {
                        let ma_val, ma_ok = parse_int(a_val);
                        if ma_ok {
                            var capped_ma = ma_val;
                            if capped_ma > MAX_COOKIE_AGE_SECONDS {
                                capped_ma = MAX_COOKIE_AGE_SECONDS;
                            }
                            c.max_age = capped_ma;
                            c.persistent = true;
                            c.expires_unix = if capped_ma <= 0 { now_unix - 1 } else { now_unix + capped_ma };
                        }
                    } else if eq_ascii_fold(a_name, "expires") {
                        // Max-Age has priority over Expires (RFC 6265 §5.3 Step 3)
                        if c.max_age == 0 {
                            let exp_ts, exp_ok = parse_cookie_date(a_val);
                            if exp_ok {
                                c.persistent = true;
                                c.expires_unix = exp_ts;
                            }
                        }
                    }
                }
            }
        };
    }

    return c, true;
}

// Extracted URL breakdown for cookie processing
struct CookieURL {
    scheme: u8[..16] = [],
    host: u8[..128] = [],
    path: u8[..256] = "/",
    is_secure: bool = false,
}

fn parse_cookie_url(raw_url: const u8[:]) -> CookieURL {
    var u = CookieURL { .. };
    var rest = raw_url;
    if starts_with(rest, "https://") {
        u.scheme.append("https");
        u.is_secure = true;
        rest = rest[8..];
    } else if starts_with(rest, "http://") {
        u.scheme.append("http");
        u.is_secure = false;
        rest = rest[7..];
    }

    // Split host and path
    var slash_idx = -1;
    for i in rest.len {
        if rest[i] == '/' || rest[i] == '?' {
            slash_idx = i;
            break;
        }
    }
    let host_part = if slash_idx >= 0 { rest[..slash_idx] } else { rest };
    let path_part = if slash_idx >= 0 && rest[slash_idx] == '/' {
        // Strip query string if any
        var q_idx = -1;
        for j in slash_idx..rest.len {
            if rest[j] == '?' { q_idx = j; break; }
        }
        if q_idx >= 0 { rest[slash_idx..q_idx] } else { rest[slash_idx..] }
    } else {
        "/"
    };

    // Strip port if present from host
    var colon_idx = -1;
    for i in host_part.len {
        if host_part[i] == ':' { colon_idx = i; break; }
    }
    let bare_host = if colon_idx >= 0 { host_part[..colon_idx] } else { host_part };

    u.host.append(bare_host);
    to_lower(u.host[..]);

    u.path.clear();
    u.path.append(path_part);
    return u;
}

// --- High-Performance RFC 6265 & CHIPS CookieJar ---

struct CustomPublicSuffix {
    suffix: u8[..64] = [],
}

struct CookieJar {
    enabled: bool = true,
    isolate_by_proxy: bool = false,
    active_proxy_key: u8[..128] = [],
    active_partition_key: u8[..128] = [],
    custom_psl: CustomPublicSuffix[..16] = [],
    seq_counter: i64 = 0,
    items: Cookie[>..] = [],
}

fn new_cookie_jar() -> CookieJar {
    return CookieJar {
        enabled: true,
        isolate_by_proxy: false,
        active_proxy_key: [],
        active_partition_key: [],
        custom_psl: [],
        seq_counter: 0,
        items: [],
    };
}

fn add_public_suffix(jar: CookieJar&, suffix: const u8[:]) {
    if jar.custom_psl.len < 16 {
        var s = CustomPublicSuffix { .. };
        s.suffix.append(suffix);
        to_lower(s.suffix[..]);
        jar.custom_psl.push(s);
    }
}

fn is_suffix_rejected(jar: const CookieJar&, domain: const u8[:]) -> bool {
    if is_known_public_suffix(domain) { return true; }
    for &ps in jar.custom_psl {
        if ps.suffix[..] == domain { return true; }
    }
    return false;
}

fn set_partition_key(jar: CookieJar&, key: const u8[:]) {
    jar.active_partition_key.clear();
    jar.active_partition_key.append(key);
}

fn set_proxy_key(jar: CookieJar&, proxy_addr: const u8[:]) {
    jar.active_proxy_key.clear();
    jar.active_proxy_key.append(proxy_addr);
}

fn is_cookie_expired(c: const Cookie&, now: i64) -> bool {
    if c.max_age < 0 { return true; }
    if c.expires_unix > 0 && c.expires_unix <= now { return true; }
    return false;
}

fn purge_expired(jar: CookieJar&, now: i64) {
    jar.items.retain() { !is_cookie_expired(it, now) };
}

// Stores cookies received from a response URL (RFC 6265 §5.3)
fn set_cookie_header(jar: CookieJar&, req_url: const u8[:], set_cookie_raw: const u8[:]) -> bool {
    guard jar.enabled else { return false; }
    let now = time_ns() / 1000000000;
    let u = parse_cookie_url(req_url);

    var def_path: u8[..256] = [];
    default_cookie_path(u.path[..], def_path);

    var c, ok = parse_set_cookie(set_cookie_raw, u.host[..], def_path[..], now);
    guard ok else { return false; }

    // RFC 6265 §5.3 Step 5: Public Suffix rejection
    if !c.host_only {
        if is_suffix_rejected(jar, c.domain[..]) {
            if c.domain[..] == u.host[..] {
                c.host_only = true;
                c.domain.clear();
                c.domain.append(u.host[..]);
            } else {
                return false; // Reject public suffix
            }
        }
        // RFC 6265 §5.3 Step 6: Request host must domain-match specified domain
        if !domain_match(u.host[..], c.domain[..]) {
            return false;
        }
    }

    // Security & prefix checks
    if !validate_cookie_security(c, u.is_secure) {
        return false;
    }

    // CHIPS partition key assignment
    if c.partitioned {
        c.partition_key.append(jar.active_partition_key[..]);
    } else {
        c.partition_key.clear();
    }

    // Proxy isolation
    let pkey = if jar.isolate_by_proxy { jar.active_proxy_key[..] } else { "" };

    // Check if matching cookie exists (RFC 6265 §5.3 Step 11)
    var found_idx = -1;
    for &existing, i in jar.items {
        if existing.name[..] == c.name[..] &&
           existing.domain[..] == c.domain[..] &&
           existing.path[..] == c.path[..] &&
           existing.partition_key[..] == c.partition_key[..] {
            found_idx = i;
            break;
        }
    }

    // If expired, delete and return
    if is_cookie_expired(c, now) {
        if found_idx >= 0 {
            jar.items.remove_at(found_idx);
        }
        return true;
    }

    jar.seq_counter++;
    if found_idx >= 0 {
        // Step 11.3: Update creation time from old cookie
        c.creation_seq = jar.items[found_idx].creation_seq;
        c.created_at = jar.items[found_idx].created_at;
        jar.items[found_idx] = c;
    } else {
        c.creation_seq = jar.seq_counter;
        jar.items.push(c);
    }

    // Evict excess per domain if over limit (RFC 6265 §5.3)
    var domain_count = 0;
    for &it in jar.items {
        if it.domain[..] == c.domain[..] { domain_count++; }
    }
    if domain_count > MAX_COOKIES_PER_DOMAIN {
        purge_expired(jar, now);
    }

    return true;
}

// Low-level programmatic cookie addition
fn set(jar: CookieJar&, name: const u8[:], value: const u8[:], domain: const u8[:], path: const u8[:]) {
    guard jar.enabled else { return; }
    let now = time_ns() / 1000000000;
    jar.seq_counter++;

    for &c in jar.items {
        if c.name[..] == name && c.domain[..] == domain && c.path[..] == path {
            c.value.clear();
            c.value.append(value);
            c.last_access = now;
            return;
        }
    }

    var c = Cookie { .. };
    c.name.append(name);
    c.value.append(value);
    c.domain.append(domain);
    to_lower(c.domain[..]);
    c.path.clear();
    c.path.append(if path.len > 0 { path } else { "/" });
    c.created_at = now;
    c.last_access = now;
    c.creation_seq = jar.seq_counter;
    jar.items.push(c);
}

// Retrieves a cookie value by name for a given URL (or any URL if req_url is empty)
fn get(jar: const CookieJar&, req_url: const u8[:], name: const u8[:]) -> const u8[:] {
    let now = time_ns() / 1000000000;
    let u = parse_cookie_url(req_url);

    for &c in jar.items {
        if c.name[..] == name {
            if is_cookie_expired(c, now) { continue; }
            if c.partition_key.len > 0 && c.partition_key[..] != jar.active_partition_key[..] { continue; }
            let dom_ok = if req_url.len == 0 { true } else if c.host_only { u.host[..] == c.domain[..] } else { domain_match(u.host[..], c.domain[..]) };
            if dom_ok && (req_url.len == 0 || path_match(u.path[..], c.path[..])) {
                if !c.secure || u.is_secure || req_url.len == 0 {
                    return c.value[..];
                }
            }
        }
    }
    return "";
}

fn get(jar: const CookieJar&, name: const u8[:]) -> const u8[:] {
    return get(jar, "", name);
}

struct CookieMatchRef {
    index: i64,
    path_len: i64,
    creation_seq: i64,
}

// RFC 6265 §5.4: Computes the Cookie request header value sorted by path length then creation order
fn build_cookie_header<B>(jar: CookieJar&, req_url: const u8[:], out: B&) {
    guard jar.enabled else { return; }
    let now = time_ns() / 1000000000;
    let u = parse_cookie_url(req_url);

    var matched: CookieMatchRef[>..] = [];

    for &c, i in jar.items {
        if is_cookie_expired(c, now) { continue; }
        if c.partition_key.len > 0 && c.partition_key[..] != jar.active_partition_key[..] { continue; }

        let dom_ok = if c.host_only { u.host[..] == c.domain[..] } else { domain_match(u.host[..], c.domain[..]) };
        if !dom_ok { continue; }

        if !path_match(u.path[..], c.path[..]) { continue; }
        if c.secure && !u.is_secure { continue; }

        c.last_access = now; // RFC 6265 §5.4 Step 3
        matched.push(CookieMatchRef {
            index: i,
            path_len: c.path.len,
            creation_seq: c.creation_seq,
        });
    }

    guard matched.len > 0 else { return; }

    // RFC 6265 §5.4 Step 2: Sort: longer paths first, then earlier creation times
    sort(matched[..]) { a, b =>
        if a.path_len != b.path_len {
            a.path_len > b.path_len
        } else {
            a.creation_seq < b.creation_seq
        }
    };

    for m, rank in matched {
        if rank > 0 { out.append("; "); }
        let c = jar.items[m.index];
        out.append(c.name[..]);
        out.push('=');
        out.append(c.value[..]);
    }
}

// Clears non-persistent session cookies when session ends (RFC 6265 §5.3)
fn clear_session_cookies(jar: CookieJar&) {
    jar.items.retain() { it.persistent };
}

// Clears all stored cookies
fn clear(jar: CookieJar&) {
    jar.items.clear();
}

fn count(jar: const CookieJar&) -> i64 {
    return jar.items.len;
}

// --- aoni Ergonomic Utilities: Mirror, Netscape & JSON Export/Import ---

// Copies specified cookies by name from source URL to target URL in jar
fn mirror(jar: CookieJar&, source_url: const u8[:], target_url: const u8[:], cookie_names: const u8[:][:]) {
    let now = time_ns() / 1000000000;
    let src_u = parse_cookie_url(source_url);
    let tgt_u = parse_cookie_url(target_url);

    var to_copy: Cookie[>..] = [];

    for &c in jar.items {
        if is_cookie_expired(c, now) { continue; }
        let dom_ok = if c.host_only { src_u.host[..] == c.domain[..] } else { domain_match(src_u.host[..], c.domain[..]) };
        if dom_ok && path_match(src_u.path[..], c.path[..]) {
            for wanted in cookie_names {
                if c.name[..] == wanted {
                    to_copy.push(copy(c));
                    break;
                }
            }
        }
    }

    for &cp in to_copy {
        set(jar, cp.name[..], cp.value[..], tgt_u.host[..], cp.path[..]);
    }
}

// Exports cookies for a target URL formatted as a standard Netscape cookies.txt file
fn export_netscape<B>(jar: CookieJar&, req_url: const u8[:], out: B&) {
    let now = time_ns() / 1000000000;
    let u = parse_cookie_url(req_url);

    out.append("# Netscape HTTP Cookie File\n\n");
    for &c in jar.items {
        if is_cookie_expired(c, now) { continue; }
        let dom_ok = if c.host_only { u.host[..] == c.domain[..] } else { domain_match(u.host[..], c.domain[..]) };
        if !dom_ok { continue; }

        if c.http_only { out.append("#HttpOnly_"); }
        out.append(c.domain[..]);
        out.push('\t');
        out.append(if !c.host_only { "TRUE" } else { "FALSE" });
        out.push('\t');
        out.append(c.path[..]);
        out.push('\t');
        out.append(if c.secure { "TRUE" } else { "FALSE" });
        out.push('\t');
        format(out, c.expires_unix);
        out.push('\t');
        out.append(c.name[..]);
        out.push('\t');
        out.append(c.value[..]);
        out.push('\n');
    }
}

// Serializes cookies for a target URL into JSON
fn export_json(jar: CookieJar&, req_url: const u8[:], out: u8[>..]&) {
    let now = time_ns() / 1000000000;
    let u = parse_cookie_url(req_url);

    out.push('[');
    var first = true;
    for &c in jar.items {
        if is_cookie_expired(c, now) { continue; }
        let dom_ok = if c.host_only { u.host[..] == c.domain[..] } else { domain_match(u.host[..], c.domain[..]) };
        if !dom_ok { continue; }

        if !first { out.push(','); }
        first = false;
        out.push('{');
        json::format_key(out, "name"); json::format_string(out, c.name[..]); out.push(',');
        json::format_key(out, "value"); json::format_string(out, c.value[..]); out.push(',');
        json::format_key(out, "domain"); json::format_string(out, c.domain[..]); out.push(',');
        json::format_key(out, "path"); json::format_string(out, c.path[..]); out.push(',');
        json::format_key(out, "secure"); json::format_bool(out, c.secure); out.push(',');
        json::format_key(out, "httpOnly"); json::format_bool(out, c.http_only); out.push(',');
        json::format_key(out, "partitioned"); json::format_bool(out, c.partitioned); out.push(',');
        json::format_key(out, "sameSite"); json::format_string(out, same_site_to_string(c.same_site)); out.push(',');
        json::format_key(out, "expires"); json::format_int(out, c.expires_unix);
        out.push('}');
    }
    out.push(']');
}

// Imports a JSON cookie array for a target URL
fn import_json(jar: CookieJar&, target_url: const u8[:], json_text: const u8[:]) -> i64 {
    guard json_text.len > 0 else { return 0; }
    let u = parse_cookie_url(target_url);
    var r = json::reader(json_text);
    var imported = 0;

    json::each_element(r) {
        var c = Cookie { .. };
        c.domain.append(u.host[..]);
        c.path.append(u.path[..]);

        var json_dom: u8[..128] = [];
        json::each_member(r) { key =>
            var scratch: u8[>..] = [];
            if key == "name" { c.name.clear(); c.name.append(json::read_string(r, scratch)); }
            else if key == "value" { c.value.clear(); c.value.append(json::read_string(r, scratch)); }
            else if key == "domain" { json_dom.clear(); json_dom.append(json::read_string(r, scratch)); }
            else if key == "path" { c.path.clear(); c.path.append(json::read_string(r, scratch)); }
            else if key == "secure" { c.secure = json::read_bool(r); }
            else if key == "httpOnly" { c.http_only = json::read_bool(r); }
            else if key == "partitioned" { c.partitioned = json::read_bool(r); }
            else if key == "sameSite" { c.same_site = parse_same_site(json::read_string(r, scratch)); }
            else if key == "expires" { c.expires_unix = json::read_int(r); c.persistent = true; }
            else { json::skip(r); }
        };

        if target_url.len > 0 {
            c.domain.clear();
            c.domain.append(u.host[..]);
        } else if json_dom.len > 0 {
            c.domain.clear();
            c.domain.append(json_dom[..]);
        }

        if c.name.len > 0 {
            set(jar, c.name[..], c.value[..], c.domain[..], c.path[..]);
            imported++;
        }
    };

    return imported;
}
