// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Set-Cookie header parsing, date tokenization, and cookie URL models (RFC 6265bis).
namespace wing;

import std;
import core from "..";
import .limits;
import .constants;
import .canonical;
import .psl;

// ---- ingestion pipeline & set-cookie parser --------------------------------

// Parses a Set-Cookie header value into a CanonicalCookie (RFC 6265bis Section 5.5).
// Enforces payload length caps, validates control characters, and applies TTL limits.
//
// Example:
//   header_val = "id=123; Secure; SameSite=Strict"
//   returns: cookie, cause = UNKNOWN, ok = true
fn parse_canonical_set_cookie(
    header_val:     const u8[:],
    default_domain: const u8[:],
    default_path:   const u8[:],
    now_us:         i64,
) -> CanonicalCookie, CookieDeleteCause, bool {
    var parsed_cookie = CanonicalCookie { .. };

    guard header_val.len > 0 else {
        return parsed_cookie, CookieDeleteCause.UNKNOWN, false;
    }
    if has_prohibited_cookie_ctl(header_val) {
        return parsed_cookie, CookieDeleteCause.CONTROL_CHAR, false;
    }

    let unparsed_attrs, payload_ok = parse_cookie_payload_pair(header_val, parsed_cookie);
    guard payload_ok else {
        return parsed_cookie, CookieDeleteCause.UNKNOWN, false;
    }

    let clean_def_domain = core::trim_byte(core::trim_byte(default_domain, '['), ']');
    guard parsed_cookie.domain.try_set(clean_def_domain) else {
        return parsed_cookie, CookieDeleteCause.UNKNOWN, false;
    }
    to_lower(parsed_cookie.domain[..]);
    guard parsed_cookie.path.try_set(default_path) else {
        return parsed_cookie, CookieDeleteCause.UNKNOWN, false;
    }
    parsed_cookie.host_only = true;
    parsed_cookie.creation_utc = now_us;
    parsed_cookie.last_access_utc = now_us;
    parsed_cookie.last_update_utc = now_us;

    var has_max_age = false;
    if unparsed_attrs.len > 0 {
        each_split(unparsed_attrs, ';') { raw_attr =>
            apply_parsed_cookie_attribute(parsed_cookie, raw_attr, has_max_age, clean_def_domain, default_path, now_us);
        };
    }

    if !validate_parsed_cookie_domain(parsed_cookie, clean_def_domain) {
        return parsed_cookie, CookieDeleteCause.UNKNOWN, false;
    }

    // RFC 6265bis Section 5.6: Cookie security prefixes
    if starts_with_fold(parsed_cookie.name[..], "__secure-") {
        if !parsed_cookie.secure {
            return parsed_cookie, CookieDeleteCause.UNKNOWN, false;
        }
    } else if starts_with_fold(parsed_cookie.name[..], "__host-http-") {
        let bad = !parsed_cookie.secure || parsed_cookie.has_domain_attr;
        let bad_path = !parsed_cookie.has_path_attr || parsed_cookie.path[..] != "/";
        if bad || bad_path || !parsed_cookie.httponly {
            return parsed_cookie, CookieDeleteCause.UNKNOWN, false;
        }
    } else if starts_with_fold(parsed_cookie.name[..], "__host-") {
        let bad = !parsed_cookie.secure || parsed_cookie.has_domain_attr;
        let bad_path = !parsed_cookie.has_path_attr || parsed_cookie.path[..] != "/";
        if bad || bad_path {
            return parsed_cookie, CookieDeleteCause.UNKNOWN, false;
        }
    } else if starts_with_fold(parsed_cookie.name[..], "__http-") {
        if !parsed_cookie.secure || !parsed_cookie.httponly {
            return parsed_cookie, CookieDeleteCause.UNKNOWN, false;
        }
    }

    // Nameless cookies with security prefixes in value (RFC 6265bis §5.6.1)
    if parsed_cookie.name.len == 0 {
        let val = parsed_cookie.value[..];
        if starts_with_fold(val, "__host-") || starts_with_fold(val, "__secure-")
            || starts_with_fold(val, "__http-") || starts_with_fold(val, "__host-http-") {
            return parsed_cookie, CookieDeleteCause.UNKNOWN, false;
        }
    }

    // RFC 6265bis Section 5.5.7: SameSite=None strictly requires Secure
    if parsed_cookie.same_site == CookieSameSite.None && !parsed_cookie.secure {
        return parsed_cookie, CookieDeleteCause.UNKNOWN, false;
    }

    // RFC 6265bis / CHIPS: Partitioned cookies strictly require Secure
    if parsed_cookie.partitioned && !parsed_cookie.secure {
        return parsed_cookie, CookieDeleteCause.UNKNOWN, false;
    }

    return parsed_cookie, CookieDeleteCause.UNKNOWN, true;
}

// Whether s contains ASCII control characters (%x00-08, %x0A-1F, %x7F).
// HTAB (%x09) is permitted (RFC 6265bis Section 5.5).
fn has_prohibited_cookie_ctl(cookie_str: const u8[:]) -> bool {
    for char_byte in cookie_str {
        if (char_byte <= 0x08) || (char_byte >= 0x0A && char_byte <= 0x1F) || char_byte == 0x7F {
            return true;
        }
    }
    return false;
}

// ---- date parser -----------------------------------------------------------

// Parses a cookie date string into a microsecond UTC timestamp (RFC 6265 Section 5.1.1).
//
// Example:
//   raw = "Wed, 09 Jun 2021 10:18:14 GMT"
//   returns: 1623233894000000, ok = true
fn parse_cookie_date_us(raw: const u8[:]) -> i64, bool {
    guard raw.len > 0 else { return 0, false; }

    var hour:   i64 = 0;
    var minute: i64 = 0;
    var second: i64 = 0;
    var day:    i64 = 0;
    var month:  i64 = 0;
    var year:   i64 = 0;

    let scanned = scan_cookie_date_tokens(raw, hour, minute, second, day, month, year);
    guard scanned else { return 0, false; }

    year = normalize_cookie_year(year);
    guard is_valid_cookie_calendar_date(year, month, day, hour, minute, second) else { return 0, false; }

    let total_days = core::civil_to_days(year, month, day);
    let total_sec = total_days * 86400 + hour * 3600 + minute * 60 + second;
    return total_sec * 1000000, true; // Microseconds UTC
}

// ---- url dissection & routing model --------------------------------------

// CanonicalCookieURL represents a dissected URL for cookie routing and origin binding.
struct CanonicalCookieURL {
    scheme:    u8[..16]   = [],
    host:      u8[..256]  = [],
    path:      u8[..2048] = "/",
    port:      i32        = 80,
    is_secure: bool       = false,
}

// Parses a URL into CanonicalCookieURL components, normalizing IPv6 brackets
// and defaulting empty paths to '/' (RFC 6265bis).
//
// Example:
//   raw_url = "https://example.com/path"
//   returns: CanonicalCookieURL { host: "example.com", path: "/path", .. }
fn parse_canonical_cookie_url(raw_url: const u8[:]) -> CanonicalCookieURL {
    var parsed_url = CanonicalCookieURL { .. };
    let parsed = core::new_url(raw_url);
    if parsed.valid {
        let _ = parsed_url.scheme.try_set(parsed.scheme());
        parsed_url.is_secure = parsed.is_secure_scheme();
        let h_str = parsed.hostname();
        let clean_h = if h_str.len > 2 && h_str[0] == '[' && h_str[h_str.len - 1] == ']' {
            h_str[1..h_str.len - 1]
        } else {
            h_str
        };
        let _ = parsed_url.host.try_set(clean_h);
        to_lower(parsed_url.host[..]);
        let p_str = parsed.pathname();
        let _ = parsed_url.path.try_set(if p_str.len > 0 { p_str } else { "/" });
        parsed_url.port = parsed.effective_port();
        return parsed_url;
    }

    var rest_url = raw_url;

    if starts_with(rest_url, "https://") {
        let _ = parsed_url.scheme.try_set("https");
        parsed_url.is_secure = true;
        parsed_url.port = 443;
        rest_url = rest_url[8..];
    } else if starts_with(rest_url, "http://") {
        let _ = parsed_url.scheme.try_set("http");
        parsed_url.is_secure = false;
        parsed_url.port = 80;
        rest_url = rest_url[7..];
    }

    let host_part, path_part = split_url_host_and_path(rest_url);
    extract_url_host_and_port(host_part, parsed_url.host, parsed_url.port);
    to_lower(parsed_url.host[..]);

    let _ = parsed_url.path.try_set(if path_part.len > 0 { path_part } else { "/" });
    return parsed_url;
}

fn split_url_host_and_path(rest_url: const u8[:]) -> const u8[:], const u8[:] {
    var slash_idx = -1;
    for char_idx in rest_url.len {
        if rest_url[char_idx] == '/' || rest_url[char_idx] == '?' || rest_url[char_idx] == '#' {
            slash_idx = char_idx;
            break;
        }
    }
    let host_part = if slash_idx >= 0 { rest_url[..slash_idx] } else { rest_url };
    let path_part = if slash_idx >= 0 && rest_url[slash_idx] == '/' {
        var query_idx = -1;
        for scan_idx in slash_idx..rest_url.len {
            if rest_url[scan_idx] == '?' || rest_url[scan_idx] == '#' { query_idx = scan_idx; break; }
        }
        if query_idx >= 0 { rest_url[slash_idx..query_idx] } else { rest_url[slash_idx..] }
    } else {
        "/"
    };
    return host_part, path_part;
}

// Extracts host slice and port from host:port string.
//
// Example:
//   host_part = "localhost:8080", port_out = 80
//   returns: "localhost", port_out = 8080
fn extract_url_host_and_port_slice(host_part: const u8[:], port_out: i32&) -> const u8[:] {
    guard host_part.len > 0 else { return ""; }
    if host_part[0] == '[' {
        let close_bracket = core::index_of_byte(host_part, ']');
        guard close_bracket > 0 else { return host_part; }
        if close_bracket + 1 < host_part.len && host_part[close_bracket + 1] == ':' {
            let port_val, port_ok = parse_int(host_part[close_bracket + 2..]);
            if port_ok && port_val > 0 && port_val <= 65535 {
                port_out = port_val as i32;
            }
        }
        return host_part[1..close_bracket];
    }
    let colon_idx = core::index_of_byte(host_part, ':');
    if colon_idx < 0 {
        return host_part;
    }
    let port_val, port_ok = parse_int(host_part[colon_idx + 1..]);
    if port_ok && port_val > 0 && port_val <= 65535 {
        port_out = port_val as i32;
    }
    return host_part[..colon_idx];
}

// Extracts bare host and port into bounded buffer.
//
// Example:
//   host_part = "example.com:443"
//   bare_host_out = "example.com", port_out = 443
fn extract_url_host_and_port<B>(host_part: const u8[:], bare_host_out: B&, port_out: i32&) {
    bare_host_out.clear();
    let host = extract_url_host_and_port_slice(host_part, port_out);
    guard host.len <= bare_host_out.cap else { return; }
    bare_host_out.append(host);
}

// ---- internal implementation helpers ---------------------------------------

// Scans cookie date tokens into day, month, year, and time components.
//
// Example:
//   raw = "Wed, 09 Jun 2021 10:18:14 GMT"
//   returns: true
fn scan_cookie_date_tokens(
    raw:  const u8[:],
    hour: i64&, minute: i64&, second: i64&,
    day:  i64&, month: i64&, year: i64&,
) -> bool {
    var found_time = false;
    var found_dom = false;
    var found_month = false;
    var found_year = false;

    var scan_pos = 0;
    while scan_pos < raw.len {
        while scan_pos < raw.len && is_cookie_date_delimiter(raw[scan_pos]) { scan_pos++; }
        if scan_pos >= raw.len { break; }
        let token_start = scan_pos;
        while scan_pos < raw.len && !is_cookie_date_delimiter(raw[scan_pos]) { scan_pos++; }
        let token = raw[token_start..scan_pos];

        if !found_time && try_parse_cookie_time(token, hour, minute, second) {
            found_time = true;
        } else if !found_dom && try_parse_cookie_dom(token, day) {
            found_dom = true;
        } else if !found_month && try_parse_cookie_month(token, month) {
            found_month = true;
        } else if !found_year && try_parse_cookie_year(token, year) {
            found_year = true;
        }
    }

    return found_time && found_dom && found_month && found_year;
}

fn is_valid_cookie_calendar_date(
    year:   i64,
    month:  i64,
    day:    i64,
    hour:   i64,
    minute: i64,
    second: i64,
) -> bool {
    guard month >= 1 && month <= 12 else { return false; }
    guard day >= 1 && day <= core::days_in_month(year, month) else { return false; }
    guard year >= 1601 && year <= 9999 else { return false; }
    guard hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59 && second >= 0 && second <= 59 else { return false; }
    return true;
}

fn is_cookie_date_delimiter(char_byte: u8) -> bool {
    return char_byte == 0x09 ||
           (char_byte >= 0x20 && char_byte <= 0x2F) ||
           (char_byte >= 0x3B && char_byte <= 0x40) ||
           (char_byte >= 0x5B && char_byte <= 0x60) ||
           (char_byte >= 0x7B && char_byte <= 0x7E);
}

fn try_parse_cookie_time(token: const u8[:], hour: i64&, minute: i64&, second: i64&) -> bool {
    guard token.len >= 5 else { return false; }
    let colon_pos1 = core::index_of_byte(token, ':');
    guard colon_pos1 == 1 || colon_pos1 == 2 else { return false; }
    let after_h = if colon_pos1 == 1 { token[2..] } else { token[3..] };
    let min_len = core::index_of_byte(after_h, ':');
    guard min_len == 1 || min_len == 2 else { return false; }
    let sec_part = if min_len == 1 { after_h[2..] } else { after_h[3..] };
    guard sec_part.len >= 1 else { return false; }

    let s1 = sec_part.len >= 2 && sec_part[1] >= '0' && sec_part[1] <= '9';
    let s2 = sec_part.len >= 3 && sec_part[2] >= '0' && sec_part[2] <= '9';
    guard !s2 else { return false; }
    let sec_slice = if s1 { sec_part[..2] } else { sec_part[..1] };
    guard token[0] >= '0' && after_h[0] >= '0' && sec_slice[0] >= '0' else { return false; }

    let hour_val, hour_ok = parse_int(token[..colon_pos1]);
    let minute_val, minute_ok = parse_int(after_h[..min_len]);
    let second_val, second_ok = parse_int(sec_slice);
    guard hour_ok && minute_ok && second_ok else { return false; }

    hour = hour_val;
    minute = minute_val;
    second = second_val;
    return true;
}

fn try_parse_cookie_dom(token: const u8[:], day: i64&) -> bool {
    guard token.len >= 1 else { return false; }
    let b0 = token[0];
    guard b0 >= '0' && b0 <= '9' else { return false; }
    var d1 = false;
    if token.len >= 2 {
        let b1 = token[1];
        d1 = b1 >= '0' && b1 <= '9';
    }
    var d2 = false;
    if token.len >= 3 {
        let b2 = token[2];
        d2 = b2 >= '0' && b2 <= '9';
    }
    guard !d2 else { return false; }
    let digits = if d1 { token[..2] } else { token[..1] };
    let day_val, day_ok = parse_int(digits);
    guard day_ok else { return false; }
    day = day_val;
    return true;
}

fn try_parse_cookie_month(token: const u8[:], month: i64&) -> bool {
    let month_val = parse_cookie_month_name(token);
    guard month_val > 0 else { return false; }
    month = month_val;
    return true;
}

fn try_parse_cookie_year(token: const u8[:], year: i64&) -> bool {
    var digit_len: i64 = 0;
    while digit_len < token.len && digit_len < 5 {
        let ch = token[digit_len];
        if ch >= '0' && ch <= '9' {
            digit_len = core::add_sat_i64(digit_len, 1);
        } else {
            break;
        }
    }
    guard digit_len >= 2 && digit_len <= 4 else { return false; }
    let year_val, year_ok = parse_int(token[..digit_len]);
    guard year_ok else { return false; }
    let norm_yr = normalize_cookie_year(year_val);
    guard norm_yr >= 1601 else { return false; }
    year = norm_yr;
    return true;
}

fn normalize_cookie_year(year: i64) -> i64 {
    if year >= 70 && year <= 99 { return core::add_sat_i64(year, 1900); }
    if year >= 0 && year <= 69 { return core::add_sat_i64(year, 2000); }
    return year;
}

// Parses a three-letter, abbreviated, or full month name to 1-based month index (RFC 6265 §5.1.1).
//
// Example:
//   token = "Sept"
//   returns: 9
fn parse_cookie_month_name(token: const u8[:]) -> i64 {
    guard token.len >= 3 else { return 0; }

    if eq_ascii_fold(token, "jan") || eq_ascii_fold(token, "january") { return 1; }
    if eq_ascii_fold(token, "feb") || eq_ascii_fold(token, "february") { return 2; }
    if eq_ascii_fold(token, "mar") || eq_ascii_fold(token, "march") { return 3; }
    if eq_ascii_fold(token, "apr") || eq_ascii_fold(token, "april") { return 4; }
    if eq_ascii_fold(token, "may") { return 5; }
    if eq_ascii_fold(token, "jun") || eq_ascii_fold(token, "june") { return 6; }
    if eq_ascii_fold(token, "jul") || eq_ascii_fold(token, "july") { return 7; }
    if eq_ascii_fold(token, "aug") || eq_ascii_fold(token, "august") { return 8; }
    if eq_ascii_fold(token, "sep") || eq_ascii_fold(token, "sept") || eq_ascii_fold(token, "september") { return 9; }
    if eq_ascii_fold(token, "oct") || eq_ascii_fold(token, "october") { return 10; }
    if eq_ascii_fold(token, "nov") || eq_ascii_fold(token, "november") { return 11; }
    if eq_ascii_fold(token, "dec") || eq_ascii_fold(token, "december") { return 12; }

    return 0;
}

// RFC 6265 Section 4.1.1 cookie-octet validator (%x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E).
fn is_cookie_octet(b: u8) -> bool {
    guard core::is_ascii_vchar(b) else { return false; }
    return b != '"' && b != ',' && b != ';' && b != '\\';
}

// RFC 6265 Section 4.1.1 cookie-value syntax validator: *cookie-octet / (DQUOTE *cookie-octet DQUOTE).
fn is_valid_cookie_value(val: const u8[:]) -> bool {
    let is_quoted = val.len >= 2 && val[0] == '"' && val[val.len - 1] == '"';
    let target = if is_quoted { val[1..val.len - 1] } else { val };
    for b in target {
        guard is_cookie_octet(b) else { return false; }
    }
    return true;
}

fn validate_cookie_name(name: const u8[:]) -> bool {
    guard name.len > 0 else { return true; }
    for b in name {
        guard core::is_tchar(b) else { return false; }
    }
    return true;
}

fn validate_nameless_cookie_value(val: const u8[:]) -> bool {
    for b in val {
        guard b != '=' else { return false; }
    }
    return true;
}

// Parses the initial name=value pair of a Set-Cookie header (RFC 6265 §5.2).
//
// Example:
//   header_val = "session=xyz; Secure"
//   returns: " Secure", ok = true
fn parse_cookie_payload_pair(
    header_val: const u8[:],
    cookie_ref: CanonicalCookie&,
) -> const u8[:], bool {
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

    let raw_name = if eq_pos >= 0 { trim(name_val_part[..eq_pos]) } else { "" };
    let raw_val = if eq_pos >= 0 { trim(name_val_part[eq_pos + 1..]) } else { trim(name_val_part) };

    guard raw_name.len > 0 || raw_val.len > 0 else { return "", false; }
    guard raw_name.len <= cookie_ref.name.cap && raw_val.len <= cookie_ref.value.cap else { return "", false; }
    if raw_name.len + raw_val.len > internal::K_MAX_COOKIE_NAME_VAL_LEN {
        return "", false;
    }

    guard validate_cookie_name(raw_name) else { return "", false; }
    guard is_valid_cookie_value(raw_val) else { return "", false; }
    guard raw_name.len > 0 || validate_nameless_cookie_value(raw_val) else { return "", false; }

    cookie_ref.name.append(raw_name);
    cookie_ref.value.append(raw_val);
    return unparsed_attrs, true;
}

fn apply_parsed_cookie_attribute(
    cookie_ref:     CanonicalCookie&,
    raw_attr:       const u8[:],
    has_max_age:    bool&,
    default_domain: const u8[:],
    default_path:   const u8[:],
    now_us:         i64,
) {
    let clean_attr = trim(raw_attr);
    guard clean_attr.len > 0 else { return; }

    var attr_eq_pos = -1;
    for char_idx in clean_attr.len {
        if clean_attr[char_idx] == '=' { attr_eq_pos = char_idx; break; }
    }
    let attr_name = if attr_eq_pos >= 0 { trim(clean_attr[..attr_eq_pos]) } else { clean_attr };
    let attr_val = if attr_eq_pos >= 0 { trim(clean_attr[attr_eq_pos + 1..]) } else { "" };

    guard attr_val.len <= internal::K_MAX_COOKIE_ATTR_VAL_LEN else { return; }

    if eq_ascii_fold(attr_name, "httponly") {
        cookie_ref.httponly = true;
    } else if eq_ascii_fold(attr_name, "secure") {
        cookie_ref.secure = true;
    } else if eq_ascii_fold(attr_name, "partitioned") {
        cookie_ref.partitioned = true;
    } else if eq_ascii_fold(attr_name, "samesite") {
        cookie_ref.same_site = parse_cookie_same_site(attr_val);
    } else if eq_ascii_fold(attr_name, "priority") {
        cookie_ref.priority = parse_cookie_priority(attr_val);
    } else if eq_ascii_fold(attr_name, "domain") {
        cookie_ref.has_domain_attr = true;
        apply_parsed_domain_attribute(cookie_ref, attr_val, default_domain);
    } else if eq_ascii_fold(attr_name, "path") {
        apply_parsed_path_attribute(cookie_ref, attr_val, default_path);
    } else if eq_ascii_fold(attr_name, "max-age") {
        apply_parsed_max_age_attribute(cookie_ref, attr_val, has_max_age, now_us);
    } else if eq_ascii_fold(attr_name, "expires") {
        apply_parsed_expires_attribute(cookie_ref, attr_val, has_max_age, now_us);
    }
}

fn apply_parsed_domain_attribute(cookie_ref: CanonicalCookie&, attr_val: const u8[:], default_domain: const u8[:]) {
    cookie_ref.host_only = true;
    let _ = cookie_ref.domain.try_set(default_domain);
    to_lower(cookie_ref.domain[..]);
    guard attr_val.len > 0 else { return; }
    let clean_domain = if attr_val[0] == '.' { attr_val[1..] } else { attr_val };
    // RFC 6265 Section 5.2.3: If domain still begins with '.', ignore the domain attribute
    guard clean_domain.len > 0 && clean_domain[0] != '.' else { return; }
    guard cookie_ref.domain.try_set(clean_domain) else {
        cookie_ref.domain.clear();
        cookie_ref.host_only = false;
        return;
    }
    to_lower(cookie_ref.domain[..]);
    cookie_ref.host_only = false;
}

fn apply_parsed_path_attribute(cookie_ref: CanonicalCookie&, attr_val: const u8[:], default_path: const u8[:] = "") {
    if attr_val.len == 0 || attr_val[0] != '/' {
        cookie_ref.has_path_attr = false;
        guard default_path.len > 0 else { return; }
        let _ = cookie_ref.path.try_set(default_path);
        return;
    }
    guard cookie_ref.path.try_set(attr_val) else { return; }
    cookie_ref.has_path_attr = true;
}

fn apply_parsed_max_age_attribute(
    cookie_ref:  CanonicalCookie&,
    attr_val:    const u8[:],
    has_max_age: bool&,
    now_us:      i64,
) {
    let max_age_val, max_age_ok = parse_int(attr_val);
    guard max_age_ok else { return; }

    has_max_age = true;
    cookie_ref.persistent = true;
    if max_age_val <= 0 {
        cookie_ref.expires_utc = core::sub_sat_i64(now_us, 1000000);
        return;
    }

    let max_allowed_seconds = internal::K_MAX_COOKIE_AGE_US / 1000000;
    let capped_sec = min(max_age_val, max_allowed_seconds);
    cookie_ref.expires_utc = core::add_sat_i64(now_us, core::mul_sat_i64(capped_sec, 1000000));
}

fn apply_parsed_expires_attribute(
    cookie_ref:  CanonicalCookie&,
    attr_val:    const u8[:],
    has_max_age: bool,
    now_us:      i64,
) {
    guard !has_max_age else { return; }

    let expires_us, expires_ok = parse_cookie_date_us(attr_val);
    guard expires_ok else { return; }

    cookie_ref.persistent = true;
    if expires_us > now_us && (core::sub_sat_i64(expires_us, now_us) > internal::K_MAX_COOKIE_AGE_US) {
        cookie_ref.expires_utc = core::add_sat_i64(now_us, internal::K_MAX_COOKIE_AGE_US); // 400 days cap
    } else {
        cookie_ref.expires_utc = expires_us;
    }
}

inline fn try_fallback_exact_host_only(cookie_ref: CanonicalCookie&, default_domain: const u8[:]) -> bool {
    if default_domain.len > 0 && eq_ascii_fold(cookie_ref.domain[..], default_domain) {
        cookie_ref.host_only = true;
        return true;
    }
    return false;
}

inline fn is_domain_syntax_invalid(domain: const u8[:]) -> bool {
    if domain.len == 0 || domain[domain.len - 1] == '.' {
        return true;
    }
    return core::contains_byte(domain, '/') || core::contains_byte(domain, ':');
}

fn validate_parsed_cookie_domain(cookie_ref: CanonicalCookie&, default_domain: const u8[:]) -> bool {
    guard !cookie_ref.host_only else { return true; }

    if is_domain_syntax_invalid(cookie_ref.domain[..]) {
        return false;
    }

    if core::is_ip_address_literal(cookie_ref.domain[..])
        || (default_domain.len > 0 && core::is_ip_address_literal(default_domain)) {
        return try_fallback_exact_host_only(cookie_ref, default_domain);
    }

    if is_public_suffix_domain(cookie_ref.domain[..]) {
        return try_fallback_exact_host_only(cookie_ref, default_domain);
    }

    // Single-label hosts without dots cannot set domain cookies
    if core::count_byte(cookie_ref.domain[..], '.') == 0 {
        return try_fallback_exact_host_only(cookie_ref, default_domain);
    }

    if default_domain.len > 0 && !cookie_domain_match(default_domain, cookie_ref.domain[..]) {
        return false;
    }

    return true;
}

// Zero-allocation 8-byte span descriptor for a cookie name-value pair in a raw Cookie: header.
struct CookieSpan {
    name_pos: u16 = 0,
    name_len: u16 = 0,
    val_pos:  u16 = 0,
    val_len:  u16 = 0,
}

inline fn trim_kv_trailing_ows(raw: const u8[:], start: i64, end_bound: i64) -> i64 {
    var end_pos = end_bound;
    while end_pos > start {
        let ch = raw[end_pos - 1];
        if ch == ' ' || ch == '\t' {
            end_pos -= 1;
        } else {
            break;
        }
    }
    return end_pos;
}

inline fn trim_kv_leading_ows(raw: const u8[:], start_bound: i64, end_pos: i64) -> i64 {
    var start = start_bound;
    while start < end_pos {
        let ch = raw[start];
        if ch == ' ' || ch == '\t' {
            start += 1;
        } else {
            break;
        }
    }
    return start;
}

// Builds a CookieSpan from trimmed pair slice bounds.
//
// Example:
//   raw = "sid=xyz", pair_start = 0, pair_end = 7
//   returns: CookieSpan { name_pos: 0, name_len: 3, val_pos: 4, val_len: 3 }
fn parse_cookie_kv_span(raw: const u8[:], pair_start: i64, pair_end: i64) -> CookieSpan {
    guard raw.len <= 65535 && pair_end <= 65535 else {
        return CookieSpan { .. };
    }

    var eq_pos = -1;
    var idx = pair_start;
    while idx < pair_end {
        if raw[idx] == '=' {
            eq_pos = idx;
            break;
        }
        idx += 1;
    }

    if eq_pos >= pair_start {
        let name_end = trim_kv_trailing_ows(raw, pair_start, eq_pos);
        let val_start = trim_kv_leading_ows(raw, eq_pos + 1, pair_end);

        return CookieSpan {
            name_pos: pair_start as u16,
            name_len: (name_end - pair_start) as u16,
            val_pos:  val_start as u16,
            val_len:  (pair_end - val_start) as u16,
        };
    }

    return CookieSpan {
        name_pos: pair_start as u16,
        name_len: (pair_end - pair_start) as u16,
        val_pos:  pair_end as u16,
        val_len:  0,
    };
}

// Parses next cookie pair from raw Cookie: header slice without heap allocations.
// Trims leading/trailing OWS and advances cursor past the delimiter on success.
// On failure (`ok = false`), `cursor` remains unchanged.
//
// Example:
//   raw_header = "sid=xyz; theme=dark", cursor = 0
//   returns: span{0, 3, 4, 3}, ok = true, cursor = 9 (points after ';')
fn next_cookie_span(
    raw_header: const u8[:],
    cursor:     i64&,
) -> CookieSpan, bool {
    var empty_span = CookieSpan { .. };
    guard cursor >= 0 && cursor < raw_header.len else { return empty_span, false; }

    var cur = cursor;

    // Skip leading spaces, tabs, and leading semicolons
    while cur < raw_header.len {
        let ch = raw_header[cur];
        if ch == ' ' || ch == '\t' || ch == ';' {
            cur += 1;
        } else {
            break;
        }
    }
    guard cur < raw_header.len else { return empty_span, false; }

    let pair_start = cur;
    var pair_end = cur;
    while pair_end < raw_header.len && raw_header[pair_end] != ';' {
        pair_end += 1;
    }

    let next_cur = if pair_end < raw_header.len { pair_end + 1 } else { pair_end };

    // Trim trailing OWS from pair_end
    while pair_end > pair_start {
        let ch = raw_header[pair_end - 1];
        if ch == ' ' || ch == '\t' {
            pair_end -= 1;
        } else {
            break;
        }
    }
    guard pair_end > pair_start else { return empty_span, false; }

    cursor = next_cur;
    return parse_cookie_kv_span(raw_header, pair_start, pair_end), true;
}

// Extracts cookie value slice from raw wire header using span coordinates.
inline fn cookie_value(raw: const u8[:], span: CookieSpan) -> const u8[:] {
    let start: i64 = span.val_pos;
    let end:   i64 = start + span.val_len;
    guard end <= raw.len && start <= end else { return ""; }
    return raw[start..end];
}

// Extracts cookie name slice from raw wire header using span coordinates.
inline fn cookie_name(raw: const u8[:], span: CookieSpan) -> const u8[:] {
    let start: i64 = span.name_pos;
    let end:   i64 = start + span.name_len;
    guard end <= raw.len && start <= end else { return ""; }
    return raw[start..end];
}

// Fast-path lookup for a specific cookie name directly in raw wire buffer.
// Iterates cookie spans without allocating and returns the first matching value.
//
// Example:
//   raw_header = "theme=dark; sid=abc123", name = "sid"
//   returns: "abc123", true
fn find_cookie_value(raw_header: const u8[:], name: const u8[:]) -> const u8[:], bool {
    var cursor: i64 = 0;
    while cursor < raw_header.len {
        let span, ok = next_cookie_span(raw_header, cursor);
        guard ok else { break; }
        let cname = cookie_name(raw_header, span);
        if cname == name {
            return cookie_value(raw_header, span), true;
        }
    }
    return "", false;
}

// Percent-decodes a cookie name or value into `out` and validates that the decoded
// bytes form valid UTF-8 (cookie-rs `parse_encoded` compatibility).
//
// Example:
//   src = "hello%20world%21", out = []
//   returns: true, out = "hello world!"
fn decode_cookie_percent(src: const u8[:], out: u8[..4096]&) -> bool {
    out.clear();
    guard core::percent_decode(src, out) else {
        out.clear();
        return false;
    }
    guard core::validate_utf8(out[..]) else {
        out.clear();
        return false;
    }
    return true;
}

const COOKIE_UPPER_HEX: u8[16] = [
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];

// Percent-encodes bytes outside RFC 6265 `cookie-octet` (or '%') into `%XX` uppercase hex.
//
// Example:
//   src = "a b;c", out = []
//   returns: true, out = "a%20b%3Bc"
fn encode_cookie_percent(src: const u8[:], out: u8[..4096]&) -> bool {
    out.clear();
    for b in src {
        if is_cookie_octet(b) && b != '%' {
            guard out.try_push(b) else {
                out.clear();
                return false;
            }
        } else {
            let hi = ((b >> 4) & 0x0F) as i64;
            let lo = (b & 0x0F) as i64;
            let hi_ch = COOKIE_UPPER_HEX[hi];
            let lo_ch = COOKIE_UPPER_HEX[lo];
            guard out.try_push('%') && out.try_push(hi_ch) && out.try_push(lo_ch) else {
                out.clear();
                return false;
            }
        }
    }
    return true;
}
