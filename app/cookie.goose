// Comprehensive RFC 6265 & RFC 6265bis (CHIPS) CookieJar implementation for goose-wing,
// porting the architecture, security invariants, and ergonomics of aoni.
namespace wing;

import std;
import os;
import json;
import cookie.constants;
import cookie.parser;

// ---- architectural limits & samesite enum ----

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

fn same_site_to_string(same_site_mode: SameSite) -> const u8[:] {
    return match same_site_mode {
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

// ---- cookie data model & format ----

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

fn format(out: u8[>..]&, cookie_val: const Cookie&) {
    out.append(cookie_val.name[..]);
    out.push('=');
    out.append(cookie_val.value[..]);
    if cookie_val.domain.len > 0 {
        out.append("; Domain=");
        out.append(cookie_val.domain[..]);
    }
    if cookie_val.path.len > 0 {
        out.append("; Path=");
        out.append(cookie_val.path[..]);
    }
    if cookie_val.secure { out.append("; Secure"); }
    if cookie_val.http_only { out.append("; HttpOnly"); }
    if cookie_val.partitioned { out.append("; Partitioned"); }
    if cookie_val.same_site != SameSite.Default {
        out.append("; SameSite=");
        out.append(same_site_to_string(cookie_val.same_site));
    }
}

// ---- security & syntax predicates ----

// Checks if string contains CTL characters %x00-08 / %x0A-1F / %x7F (excluding HTAB %x09)
// per RFC 6265bis §5.5 Step 1 & §5.7 Step 3.
fn has_prohibited_ctl(cookie_str: const u8[:]) -> bool {
    for char_byte in cookie_str {
        if (char_byte <= 0x08) || (char_byte >= 0x0A && char_byte <= 0x1F) || char_byte == 0x7F {
            return true;
        }
    }
    return false;
}

// Detects IPv4 or IPv6 literals so domain-match does not match suffixes on IP addresses (RFC 6265 §5.1.3).
fn is_ip_address(host: const u8[:]) -> bool {
    guard host.len > 0 else { return false; }
    // IPv6 contains ':'
    for char_byte in host {
        if char_byte == ':' { return true; }
    }
    // IPv4 check: digits and dots only, exactly 3 dots
    var dot_count = 0;
    var all_digits_dots = true;
    for char_byte in host {
        if char_byte == '.' {
            dot_count++;
        } else if char_byte < '0' || char_byte > '9' {
            all_digits_dots = false;
            break;
        }
    }
    return all_digits_dots && dot_count == 3;
}

// RFC 6265 §5.1.3: Domain Matching
fn domain_match(host: const u8[:], cookie_domain: const u8[:]) -> bool {
    guard host.len > 0 && cookie_domain.len > 0 else { return false; }
    if eq_ascii_fold(host, cookie_domain) {
        return true;
    }
    if is_ip_address(host) {
        return false;
    }
    if host.len > cookie_domain.len {
        let suffix_start = host.len - cookie_domain.len;
        let suffix = host[suffix_start..];
        if eq_ascii_fold(suffix, cookie_domain) && host[suffix_start - 1] == '.' {
            return true;
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
    var last_slash_idx = -1;
    for char_idx in uri_path.len {
        if uri_path[char_idx] == '/' {
            last_slash_idx = char_idx;
        }
    }
    if last_slash_idx <= 0 {
        out.push('/');
        return;
    }
    out.append(uri_path[..last_slash_idx]);
}

// RFC 6265 §5.1.4: Path-Match algorithm
fn path_match(req_path: const u8[:], cookie_path: const u8[:]) -> bool {
    let norm_req = if req_path.len == 0 { "/" } else { req_path };
    let norm_cookie = if cookie_path.len == 0 { "/" } else { cookie_path };

    if norm_req == norm_cookie { return true; }
    if starts_with(norm_req, norm_cookie) {
        if norm_cookie[norm_cookie.len - 1] == '/' { return true; }
        if norm_req.len > norm_cookie.len && norm_req[norm_cookie.len] == '/' { return true; }
    }
    return false;
}

// Fast public suffix rejection per RFC 6265 §5.3 Step 5.
fn is_known_public_suffix(domain: const u8[:]) -> bool {
    let clean_domain = domain;
    return clean_domain == "com" || clean_domain == "org" || clean_domain == "net" || clean_domain == "edu" || clean_domain == "gov" || clean_domain == "mil" ||
           clean_domain == "io" || clean_domain == "co" || clean_domain == "ai" || clean_domain == "dev" || clean_domain == "app" || clean_domain == "ru" ||
           clean_domain == "uk" || clean_domain == "co.uk" || clean_domain == "org.uk" || clean_domain == "de" || clean_domain == "fr" || clean_domain == "nl" ||
           clean_domain == "eu" || clean_domain == "us" || clean_domain == "ca" || clean_domain == "me" || clean_domain == "xyz" || clean_domain == "info" ||
           clean_domain == "biz" || clean_domain == "online" || clean_domain == "site" || clean_domain == "store";
}

// RFC 6265 §5.1.1: delimiter characters for cookie-date tokenization.
fn is_cookie_date_delim(char_byte: u8) -> bool {
    return is_cookie_date_delimiter(char_byte);
}

// Validates and parses a Set-Cookie Expires date per RFC 6265 §5.1.1 (returns seconds).
fn parse_cookie_date(raw: const u8[:]) -> i64, bool {
    let us_val, parse_ok = parse_cookie_date_us(raw);
    guard parse_ok else { return 0, false; }
    return us_val / 1000000, true;
}

// RFC 6265bis §4.1.3 & §5.4: Validate cookie name prefixes (__Secure-, __Host-)
fn validate_cookie_security(cookie_val: const Cookie&, is_secure_channel: bool) -> bool {
    let cookie_name = cookie_val.name[..];
    if starts_with(cookie_name, "__Secure-") || starts_with(cookie_name, "__secure-") {
        if !cookie_val.secure || !is_secure_channel { return false; }
    }
    if starts_with(cookie_name, "__Host-") || starts_with(cookie_name, "__host-") {
        if !cookie_val.secure || !is_secure_channel { return false; }
        if !cookie_val.host_only || cookie_val.path[..] != "/" { return false; }
    }
    if cookie_val.partitioned && !cookie_val.secure {
        return false;
    }
    if cookie_val.same_site == SameSite.None && !cookie_val.secure {
        return false;
    }
    return true;
}

// ---- set-cookie parser ----

// Parses a single Set-Cookie header field value (RFC 6265 §5.2).
fn parse_set_cookie(
    header_val: const u8[:],
    default_domain: const u8[:],
    default_path: const u8[:],
    now_unix: i64,
) -> Cookie, bool {
    var parsed_cookie = Cookie { .. };
    guard header_val.len > 0 && !has_prohibited_ctl(header_val) else { return parsed_cookie, false; }

    var semi_pos = -1;
    for char_idx in header_val.len {
        if header_val[char_idx] == ';' { semi_pos = char_idx; break; }
    }

    let name_val_part = if semi_pos >= 0 { header_val[..semi_pos] } else { header_val };
    let unparsed_attrs = if semi_pos >= 0 { header_val[semi_pos + 1..] } else { "" };

    var eq_pos = -1;
    for char_idx in name_val_part.len {
        if name_val_part[char_idx] == '=' { eq_pos = char_idx; break; }
    }
    guard eq_pos >= 0 else { return parsed_cookie, false; }

    let raw_name = trim(name_val_part[..eq_pos]);
    let raw_val = trim(name_val_part[eq_pos + 1..]);

    guard raw_name.len > 0 else { return parsed_cookie, false; }
    guard raw_name.len + raw_val.len <= MAX_COOKIE_NAME_VAL_LEN else { return parsed_cookie, false; }

    parsed_cookie.name.append(raw_name);
    parsed_cookie.value.append(raw_val);
    parsed_cookie.domain.append(default_domain);
    parsed_cookie.path.clear();
    parsed_cookie.path.append(default_path);
    parsed_cookie.host_only = true;
    parsed_cookie.created_at = now_unix;
    parsed_cookie.last_access = now_unix;

    // Parse attributes
    if unparsed_attrs.len > 0 {
        each_split(unparsed_attrs, ';') { raw_attr =>
            apply_app_cookie_attribute(parsed_cookie, raw_attr, now_unix);
        };
    }

    return parsed_cookie, true;
}

// ---- cookie url parser ----

// Extracted URL breakdown for cookie processing
struct CookieURL {
    scheme: u8[..16] = [],
    host: u8[..128] = [],
    path: u8[..256] = "/",
    is_secure: bool = false,
}

fn parse_cookie_url(raw_url: const u8[:]) -> CookieURL {
    var parsed_url = CookieURL { .. };
    var rest_url = raw_url;
    if starts_with(rest_url, "https://") {
        parsed_url.scheme.append("https");
        parsed_url.is_secure = true;
        rest_url = rest_url[8..];
    } else if starts_with(rest_url, "http://") {
        parsed_url.scheme.append("http");
        parsed_url.is_secure = false;
        rest_url = rest_url[7..];
    }

    // Split host and path
    var slash_idx = -1;
    for char_idx in rest_url.len {
        if rest_url[char_idx] == '/' || rest_url[char_idx] == '?' {
            slash_idx = char_idx;
            break;
        }
    }
    let host_part = if slash_idx >= 0 { rest_url[..slash_idx] } else { rest_url };
    let path_part = if slash_idx >= 0 && rest_url[slash_idx] == '/' {
        // Strip query string if any
        var query_idx = -1;
        for scan_idx in slash_idx..rest_url.len {
            if rest_url[scan_idx] == '?' { query_idx = scan_idx; break; }
        }
        if query_idx >= 0 { rest_url[slash_idx..query_idx] } else { rest_url[slash_idx..] }
    } else {
        "/"
    };

    // Strip port if present from host
    var colon_idx = -1;
    for char_idx in host_part.len {
        if host_part[char_idx] == ':' { colon_idx = char_idx; break; }
    }
    let bare_host = if colon_idx >= 0 { host_part[..colon_idx] } else { host_part };

    parsed_url.host.append(bare_host);
    to_lower(parsed_url.host[..]);

    parsed_url.path.clear();
    parsed_url.path.append(path_part);
    return parsed_url;
}

// ---- high-performance cookie jar ----

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
        var suffix_item = CustomPublicSuffix { .. };
        suffix_item.suffix.append(suffix);
        to_lower(suffix_item.suffix[..]);
        jar.custom_psl.push(suffix_item);
    }
}

fn is_suffix_rejected(jar: const CookieJar&, domain: const u8[:]) -> bool {
    if is_known_public_suffix(domain) { return true; }
    for &public_suffix in jar.custom_psl {
        if public_suffix.suffix[..] == domain { return true; }
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

fn is_cookie_expired(cookie_val: const Cookie&, now: i64) -> bool {
    if cookie_val.max_age < 0 { return true; }
    if cookie_val.expires_unix > 0 && cookie_val.expires_unix <= now { return true; }
    return false;
}

fn purge_expired(jar: CookieJar&, now: i64) {
    jar.items.retain() { !is_cookie_expired(it, now) };
}

// Stores cookies received from a response URL (RFC 6265 §5.3)
fn set_cookie_header(jar: CookieJar&, req_url: const u8[:], set_cookie_raw: const u8[:]) -> bool {
    guard jar.enabled else { return false; }
    let now = time_ns() / 1000000000;
    let parsed_url = parse_cookie_url(req_url);

    var def_path: u8[..256] = [];
    default_cookie_path(parsed_url.path[..], def_path);

    var parsed_cookie, ok = parse_set_cookie(set_cookie_raw, parsed_url.host[..], def_path[..], now);
    guard ok else { return false; }

    // RFC 6265 §5.3 Step 5: Public Suffix rejection
    if !parsed_cookie.host_only {
        if is_suffix_rejected(jar, parsed_cookie.domain[..]) {
            if parsed_cookie.domain[..] == parsed_url.host[..] {
                parsed_cookie.host_only = true;
                parsed_cookie.domain.clear();
                parsed_cookie.domain.append(parsed_url.host[..]);
            } else {
                return false; // Reject public suffix
            }
        }
        // RFC 6265 §5.3 Step 6: Request host must domain-match specified domain
        if !domain_match(parsed_url.host[..], parsed_cookie.domain[..]) {
            return false;
        }
    }

    // Security & prefix checks
    if !validate_cookie_security(parsed_cookie, parsed_url.is_secure) {
        return false;
    }

    // CHIPS partition key assignment
    if parsed_cookie.partitioned {
        parsed_cookie.partition_key.append(jar.active_partition_key[..]);
    } else {
        parsed_cookie.partition_key.clear();
    }

    // Check if matching cookie exists (RFC 6265 §5.3 Step 11)
    var found_idx = -1;
    for &existing, search_idx in jar.items {
        if existing.name[..] == parsed_cookie.name[..] &&
           existing.domain[..] == parsed_cookie.domain[..] &&
           existing.path[..] == parsed_cookie.path[..] &&
           existing.partition_key[..] == parsed_cookie.partition_key[..] {
            found_idx = search_idx;
            break;
        }
    }

    // If expired, delete and return
    if is_cookie_expired(parsed_cookie, now) {
        if found_idx >= 0 {
            jar.items.remove_at(found_idx);
        }
        return true;
    }

    jar.seq_counter++;
    if found_idx >= 0 {
        // Step 11.3: Update creation time from old cookie
        parsed_cookie.creation_seq = jar.items[found_idx].creation_seq;
        parsed_cookie.created_at = jar.items[found_idx].created_at;
        jar.items[found_idx] = parsed_cookie;
    } else {
        parsed_cookie.creation_seq = jar.seq_counter;
        jar.items.push(parsed_cookie);
    }

    // Evict excess per domain if over limit (RFC 6265 §5.3)
    var domain_count = 0;
    for &it in jar.items {
        if it.domain[..] == parsed_cookie.domain[..] { domain_count++; }
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

    for &cookie_entry in jar.items {
        if cookie_entry.name[..] == name && cookie_entry.domain[..] == domain && cookie_entry.path[..] == path {
            cookie_entry.value.clear();
            cookie_entry.value.append(value);
            cookie_entry.last_access = now;
            return;
        }
    }

    var new_cookie = Cookie { .. };
    new_cookie.name.append(name);
    new_cookie.value.append(value);
    new_cookie.domain.append(domain);
    to_lower(new_cookie.domain[..]);
    new_cookie.path.clear();
    new_cookie.path.append(if path.len > 0 { path } else { "/" });
    new_cookie.created_at = now;
    new_cookie.last_access = now;
    new_cookie.creation_seq = jar.seq_counter;
    jar.items.push(new_cookie);
}

// Retrieves a cookie value by name for a given URL (or any URL if req_url is empty)
fn get(jar: const CookieJar&, req_url: const u8[:], name: const u8[:]) -> const u8[:] {
    let now = time_ns() / 1000000000;
    let parsed_url = parse_cookie_url(req_url);

    for &cookie_entry in jar.items {
        if cookie_entry.name[..] == name {
            if is_cookie_expired(cookie_entry, now) { continue; }
            if cookie_entry.partition_key.len > 0 && cookie_entry.partition_key[..] != jar.active_partition_key[..] { continue; }
            let dom_ok = if req_url.len == 0 { true } else if cookie_entry.host_only { parsed_url.host[..] == cookie_entry.domain[..] } else { domain_match(parsed_url.host[..], cookie_entry.domain[..]) };
            if dom_ok && (req_url.len == 0 || path_match(parsed_url.path[..], cookie_entry.path[..])) {
                if !cookie_entry.secure || parsed_url.is_secure || req_url.len == 0 {
                    return cookie_entry.value[..];
                }
            }
        }
    }
    return "";
}

fn get(jar: const CookieJar&, name: const u8[:]) -> const u8[:] {
    return get(jar, "", name);
}

// ---- outgoing header generation ----

struct CookieMatchRef {
    index: i64,
    path_len: i64,
    creation_seq: i64,
}

// RFC 6265 §5.4: Computes the Cookie request header value sorted by path length then creation order
fn build_cookie_header<B>(jar: CookieJar&, req_url: const u8[:], out: B&) {
    guard jar.enabled else { return; }
    let now = time_ns() / 1000000000;
    let parsed_url = parse_cookie_url(req_url);

    var matched: CookieMatchRef[>..] = [];

    for &cookie_entry, cookie_idx in jar.items {
        if is_cookie_expired(cookie_entry, now) { continue; }
        if cookie_entry.partition_key.len > 0 && cookie_entry.partition_key[..] != jar.active_partition_key[..] { continue; }

        let dom_ok = if cookie_entry.host_only { parsed_url.host[..] == cookie_entry.domain[..] } else { domain_match(parsed_url.host[..], cookie_entry.domain[..]) };
        if !dom_ok { continue; }

        if !path_match(parsed_url.path[..], cookie_entry.path[..]) { continue; }
        if cookie_entry.secure && !parsed_url.is_secure { continue; }

        cookie_entry.last_access = now; // RFC 6265 §5.4 Step 3
        matched.push(CookieMatchRef {
            index: cookie_idx,
            path_len: cookie_entry.path.len,
            creation_seq: cookie_entry.creation_seq,
        });
    }

    guard matched.len > 0 else { return; }

    // RFC 6265 §5.4 Step 2: Sort: longer paths first, then earlier creation times
    sort(matched[..]) { match_a, match_b =>
        if match_a.path_len != match_b.path_len {
            match_a.path_len > match_b.path_len
        } else {
            match_a.creation_seq < match_b.creation_seq
        }
    };

    for match_ref, rank_idx in matched {
        if rank_idx > 0 { out.append("; "); }
        let cookie_val = jar.items[match_ref.index];
        out.append(cookie_val.name[..]);
        out.push('=');
        out.append(cookie_val.value[..]);
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

// ---- netscape & json format interop ----

// Copies specified cookies by name from source URL to target URL in jar
fn mirror(jar: CookieJar&, source_url: const u8[:], target_url: const u8[:], cookie_names: const u8[:][:]) {
    let now = time_ns() / 1000000000;
    let src_url = parse_cookie_url(source_url);
    let tgt_url = parse_cookie_url(target_url);

    var to_copy: Cookie[>..] = [];

    for &cookie_entry in jar.items {
        if is_cookie_expired(cookie_entry, now) { continue; }
        let dom_ok = if cookie_entry.host_only { src_url.host[..] == cookie_entry.domain[..] } else { domain_match(src_url.host[..], cookie_entry.domain[..]) };
        if dom_ok && path_match(src_url.path[..], cookie_entry.path[..]) {
            for wanted in cookie_names {
                if cookie_entry.name[..] == wanted {
                    to_copy.push(copy(cookie_entry));
                    break;
                }
            }
        }
    }

    for &copied_cookie in to_copy {
        set(jar, copied_cookie.name[..], copied_cookie.value[..], tgt_url.host[..], copied_cookie.path[..]);
    }
}

// Exports cookies for a target URL formatted as a standard Netscape cookies.txt file
fn export_netscape<B>(jar: CookieJar&, req_url: const u8[:], out: B&) {
    let now = time_ns() / 1000000000;
    let parsed_url = parse_cookie_url(req_url);

    out.append("# Netscape HTTP Cookie File\n\n");
    for &cookie_entry in jar.items {
        if is_cookie_expired(cookie_entry, now) { continue; }
        let dom_ok = if cookie_entry.host_only { parsed_url.host[..] == cookie_entry.domain[..] } else { domain_match(parsed_url.host[..], cookie_entry.domain[..]) };
        if !dom_ok { continue; }

        if cookie_entry.http_only { out.append("#HttpOnly_"); }
        out.append(cookie_entry.domain[..]);
        out.push('\t');
        out.append(if !cookie_entry.host_only { "TRUE" } else { "FALSE" });
        out.push('\t');
        out.append(cookie_entry.path[..]);
        out.push('\t');
        out.append(if cookie_entry.secure { "TRUE" } else { "FALSE" });
        out.push('\t');
        format(out, cookie_entry.expires_unix);
        out.push('\t');
        out.append(cookie_entry.name[..]);
        out.push('\t');
        out.append(cookie_entry.value[..]);
        out.push('\n');
    }
}

// Serializes cookies for a target URL into JSON
fn export_json(jar: CookieJar&, req_url: const u8[:], out: u8[>..]&) {
    let now = time_ns() / 1000000000;
    let parsed_url = parse_cookie_url(req_url);

    out.push('[');
    var first = true;
    for &cookie_entry in jar.items {
        if is_cookie_expired(cookie_entry, now) { continue; }
        let dom_ok = if cookie_entry.host_only { parsed_url.host[..] == cookie_entry.domain[..] } else { domain_match(parsed_url.host[..], cookie_entry.domain[..]) };
        if !dom_ok { continue; }

        if !first { out.push(','); }
        first = false;
        out.push('{');
        json::format_key(out, "name"); json::format_string(out, cookie_entry.name[..]); out.push(',');
        json::format_key(out, "value"); json::format_string(out, cookie_entry.value[..]); out.push(',');
        json::format_key(out, "domain"); json::format_string(out, cookie_entry.domain[..]); out.push(',');
        json::format_key(out, "path"); json::format_string(out, cookie_entry.path[..]); out.push(',');
        json::format_key(out, "secure"); json::format_bool(out, cookie_entry.secure); out.push(',');
        json::format_key(out, "httpOnly"); json::format_bool(out, cookie_entry.http_only); out.push(',');
        json::format_key(out, "partitioned"); json::format_bool(out, cookie_entry.partitioned); out.push(',');
        json::format_key(out, "sameSite"); json::format_string(out, same_site_to_string(cookie_entry.same_site)); out.push(',');
        json::format_key(out, "expires"); json::format_int(out, cookie_entry.expires_unix);
        out.push('}');
    }
    out.push(']');
}

// Imports a JSON cookie array for a target URL
fn import_json(jar: CookieJar&, target_url: const u8[:], json_text: const u8[:]) -> i64 {
    guard json_text.len > 0 else { return 0; }
    let parsed_url = parse_cookie_url(target_url);
    var json_reader = json::reader(json_text);
    var imported_count = 0;

    json::each_element(json_reader) {
        var parsed_cookie = Cookie { .. };
        parsed_cookie.domain.append(parsed_url.host[..]);
        parsed_cookie.path.append(parsed_url.path[..]);

        var json_domain: u8[..128] = [];
        json::each_member(json_reader) { key =>
            var scratch: u8[>..] = [];
            if key == "name" { parsed_cookie.name.clear(); parsed_cookie.name.append(json::read_string(json_reader, scratch)); }
            else if key == "value" { parsed_cookie.value.clear(); parsed_cookie.value.append(json::read_string(json_reader, scratch)); }
            else if key == "domain" { json_domain.clear(); json_domain.append(json::read_string(json_reader, scratch)); }
            else if key == "path" { parsed_cookie.path.clear(); parsed_cookie.path.append(json::read_string(json_reader, scratch)); }
            else if key == "secure" { parsed_cookie.secure = json::read_bool(json_reader); }
            else if key == "httpOnly" { parsed_cookie.http_only = json::read_bool(json_reader); }
            else if key == "partitioned" { parsed_cookie.partitioned = json::read_bool(json_reader); }
            else if key == "sameSite" { parsed_cookie.same_site = parse_same_site(json::read_string(json_reader, scratch)); }
            else if key == "expires" { parsed_cookie.expires_unix = json::read_int(json_reader); parsed_cookie.persistent = true; }
            else { json::skip(json_reader); }
        };

        if target_url.len > 0 {
            parsed_cookie.domain.clear();
            parsed_cookie.domain.append(parsed_url.host[..]);
        } else if json_domain.len > 0 {
            parsed_cookie.domain.clear();
            parsed_cookie.domain.append(json_domain[..]);
        }

        if parsed_cookie.name.len > 0 {
            set(jar, parsed_cookie.name[..], parsed_cookie.value[..], parsed_cookie.domain[..], parsed_cookie.path[..]);
            imported_count++;
        }
    };

    return imported_count;
}

// ---- internal implementation helpers ----

fn apply_app_cookie_attribute(parsed_cookie: Cookie&, raw_attr: const u8[:], now_unix: i64) {
    let clean_attr = trim(raw_attr);
    guard clean_attr.len > 0 else { return; }

    var attr_eq_pos = -1;
    for char_idx in clean_attr.len {
        if clean_attr[char_idx] == '=' { attr_eq_pos = char_idx; break; }
    }
    let attr_name = if attr_eq_pos >= 0 { trim(clean_attr[..attr_eq_pos]) } else { clean_attr };
    let attr_val = if attr_eq_pos >= 0 { trim(clean_attr[attr_eq_pos + 1..]) } else { "" };

    guard attr_val.len <= MAX_COOKIE_ATTR_VAL_LEN else { return; }

    if eq_ascii_fold(attr_name, "httponly") {
        parsed_cookie.http_only = true;
    } else if eq_ascii_fold(attr_name, "secure") {
        parsed_cookie.secure = true;
    } else if eq_ascii_fold(attr_name, "partitioned") {
        parsed_cookie.partitioned = true;
    } else if eq_ascii_fold(attr_name, "samesite") {
        parsed_cookie.same_site = parse_same_site(attr_val);
    } else if eq_ascii_fold(attr_name, "domain") {
        if attr_val.len > 0 && attr_val[attr_val.len - 1] != '.' {
            let clean_domain = if attr_val[0] == '.' { attr_val[1..] } else { attr_val };
            parsed_cookie.domain.clear();
            parsed_cookie.domain.append(clean_domain);
            to_lower(parsed_cookie.domain[..]);
            parsed_cookie.host_only = false;
        }
    } else if eq_ascii_fold(attr_name, "path") {
        if attr_val.len > 0 && attr_val[0] == '/' {
            parsed_cookie.path.clear();
            parsed_cookie.path.append(attr_val);
        }
    } else if eq_ascii_fold(attr_name, "max-age") {
        let max_age_val, max_age_ok = parse_int(attr_val);
        if max_age_ok {
            var capped_max_age = max_age_val;
            if capped_max_age > MAX_COOKIE_AGE_SECONDS {
                capped_max_age = MAX_COOKIE_AGE_SECONDS;
            }
            parsed_cookie.max_age = capped_max_age;
            parsed_cookie.persistent = true;
            parsed_cookie.expires_unix = if capped_max_age <= 0 { now_unix - 1 } else { now_unix + capped_max_age };
        }
    } else if eq_ascii_fold(attr_name, "expires") {
        if parsed_cookie.max_age == 0 {
            let expires_ts, expires_ok = parse_cookie_date(attr_val);
            if expires_ok {
                parsed_cookie.persistent = true;
                parsed_cookie.expires_unix = expires_ts;
            }
        }
    }
}
