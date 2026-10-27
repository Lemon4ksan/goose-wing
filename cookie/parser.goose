// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Set-Cookie header parsing, date tokenization, and cookie URL models (RFC 6265bis).
namespace wing;

import std;
import core from "..";
import .constants;
import .canonical;
import .psl;

// ---- ingestion pipeline & set-cookie parser --------------------------------

// Parses a Set-Cookie header value into a CanonicalCookie (RFC 6265bis Section 5.5).
// Enforces payload length caps, validates control characters, and applies TTL limits.
fn parse_canonical_set_cookie(
    header_val: const u8[:],
    default_domain: const u8[:],
    default_path: const u8[:],
    now_us: i64,
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

    if default_domain.len <= parsed_cookie.domain.cap {
        parsed_cookie.domain.append(default_domain);
    }
    to_lower(parsed_cookie.domain[..]);
    parsed_cookie.path.clear();
    if default_path.len <= parsed_cookie.path.cap {
        parsed_cookie.path.append(default_path);
    }
    parsed_cookie.host_only = true;
    parsed_cookie.creation_utc = now_us;
    parsed_cookie.last_access_utc = now_us;
    parsed_cookie.last_update_utc = now_us;

    var has_max_age = false;
    if unparsed_attrs.len > 0 {
        each_split(unparsed_attrs, ';') { raw_attr =>
            apply_parsed_cookie_attribute(parsed_cookie, raw_attr, has_max_age, now_us);
        };
    }

    if !validate_parsed_cookie_domain(parsed_cookie, default_domain) {
        return parsed_cookie, CookieDeleteCause.UNKNOWN, false;
    }

    if (starts_with_fold(parsed_cookie.name[..], "__host-") || starts_with_fold(parsed_cookie.name[..], "__host-http-")) && parsed_cookie.has_domain_attr {
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
fn parse_cookie_date_us(raw: const u8[:]) -> i64, bool {
    guard raw.len > 0 else { return 0, false; }

    var hour: i64 = 0;
    var minute: i64 = 0;
    var second: i64 = 0;
    var day: i64 = 0;
    var month: i64 = 0;
    var year: i64 = 0;

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
    scheme: u8[..16] = [],
    host: u8[..256] = [],
    path: u8[..256] = "/",
    port: i32 = 80,
    is_secure: bool = false,
}

// Parses a URL into CanonicalCookieURL components, normalizing IPv6 brackets
// and defaulting empty paths to '/' (RFC 6265bis).
fn parse_canonical_cookie_url(raw_url: const u8[:]) -> CanonicalCookieURL {
    var parsed_url = CanonicalCookieURL { .. };
    let parsed = core::new_url(raw_url);
    if parsed.valid {
        parsed_url.scheme.append(scheme(parsed));
        parsed_url.is_secure = is_secure_scheme(parsed);
        let h_str = hostname(parsed);
        let clean_h = if h_str.len > 2 && h_str[0] == '[' && h_str[h_str.len - 1] == ']' { h_str[1..h_str.len - 1] } else { h_str };
        parsed_url.host.append(clean_h);
        to_lower(parsed_url.host[..]);
        parsed_url.path.clear();
        let p_str = pathname(parsed);
        parsed_url.path.append(if p_str.len > 0 { p_str } else { "/" });
        parsed_url.port = effective_port(parsed);
        return parsed_url;
    }

    var rest_url = raw_url;

    if starts_with(rest_url, "https://") {
        parsed_url.scheme.append("https");
        parsed_url.is_secure = true;
        parsed_url.port = 443;
        rest_url = rest_url[8..];
    } else if starts_with(rest_url, "http://") {
        parsed_url.scheme.append("http");
        parsed_url.is_secure = false;
        parsed_url.port = 80;
        rest_url = rest_url[7..];
    }

    let host_part, path_part = split_url_host_and_path(rest_url);
    extract_url_host_and_port(host_part, parsed_url.host, parsed_url.port);
    to_lower(parsed_url.host[..]);

    parsed_url.path.clear();
    parsed_url.path.append(if path_part.len > 0 { path_part } else { "/" });
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

fn extract_url_host_and_port<B>(host_part: const u8[:], bare_host_out: B&, port_out: i32&) {
    bare_host_out.clear();
    guard host_part.len > 0 else { return; }

    if extract_ipv6_host_and_port(host_part, bare_host_out, port_out) {
        return;
    }

    var colon_idx = -1;
    for char_idx in host_part.len {
        if host_part[char_idx] == ':' { colon_idx = char_idx; break; }
    }
    if colon_idx < 0 {
        bare_host_out.append(host_part);
        return;
    }

    bare_host_out.append(host_part[..colon_idx]);
    let port_val, port_ok = parse_int(host_part[colon_idx + 1..]);
    if port_ok && port_val > 0 && port_val <= 65535 {
        port_out = port_val as i32;
    }
}

// ---- internal implementation helpers ---------------------------------------

fn scan_cookie_date_tokens(
    raw: const u8[:],
    hour: i64&, minute: i64&, second: i64&,
    day: i64&, month: i64&, year: i64&,
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

fn is_valid_cookie_calendar_date(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> bool {
    guard month >= 1 && month <= 12 else { return false; }
    guard day >= 1 && day <= days_in_month(year, month) else { return false; }
    guard year >= 1601 else { return false; }
    guard hour <= 23 && minute <= 59 && second <= 59 else { return false; }
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
    var colon_pos1 = -1;
    var colon_pos2 = -1;
    for char_idx in token.len {
        if token[char_idx] == ':' {
            if colon_pos1 < 0 { colon_pos1 = char_idx; }
            else if colon_pos2 < 0 { colon_pos2 = char_idx; break; }
        }
    }
    guard colon_pos1 > 0 && colon_pos2 > colon_pos1 else { return false; }

    let hour_val, hour_ok = parse_int(token[..colon_pos1]);
    let minute_val, minute_ok = parse_int(token[colon_pos1 + 1..colon_pos2]);
    let second_val, second_ok = parse_int(token[colon_pos2 + 1..]);
    guard hour_ok && minute_ok && second_ok else { return false; }

    hour = hour_val;
    minute = minute_val;
    second = second_val;
    return true;
}

fn try_parse_cookie_dom(token: const u8[:], day: i64&) -> bool {
    guard token.len == 1 || token.len == 2 else { return false; }
    for char_byte in token {
        if char_byte < '0' || char_byte > '9' { return false; }
    }
    let day_val, day_ok = parse_int(token);
    guard day_ok && day_val >= 1 && day_val <= 31 else { return false; }
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
    guard token.len == 2 || token.len == 4 else { return false; }
    for char_byte in token {
        if char_byte < '0' || char_byte > '9' { return false; }
    }
    let year_val, year_ok = parse_int(token);
    guard year_ok else { return false; }
    year = year_val;
    return true;
}

fn normalize_cookie_year(year: i64) -> i64 {
    if year >= 70 && year <= 99 { return year + 1900; }
    if year >= 0 && year <= 69 { return year + 2000; }
    return year;
}

fn parse_cookie_month_name(token: const u8[:]) -> i64 {
    guard token.len >= 3 else { return 0; }
    var char0 = if token[0] >= 'A' && token[0] <= 'Z' { token[0] + 32 } else { token[0] };
    var char1 = if token[1] >= 'A' && token[1] <= 'Z' { token[1] + 32 } else { token[1] };
    var char2 = if token[2] >= 'A' && token[2] <= 'Z' { token[2] + 32 } else { token[2] };

    if char0 == 'j' && char1 == 'a' && char2 == 'n' { return 1; }
    if char0 == 'f' && char1 == 'e' && char2 == 'b' { return 2; }
    if char0 == 'm' && char1 == 'a' && char2 == 'r' { return 3; }
    if char0 == 'a' && char1 == 'p' && char2 == 'r' { return 4; }
    if char0 == 'm' && char1 == 'a' && char2 == 'y' { return 5; }
    if char0 == 'j' && char1 == 'u' && char2 == 'n' { return 6; }
    if char0 == 'j' && char1 == 'u' && char2 == 'l' { return 7; }
    if char0 == 'a' && char1 == 'u' && char2 == 'g' { return 8; }
    if char0 == 's' && char1 == 'e' && char2 == 'p' { return 9; }
    if char0 == 'o' && char1 == 'c' && char2 == 't' { return 10; }
    if char0 == 'n' && char1 == 'o' && char2 == 'v' { return 11; }
    if char0 == 'd' && char1 == 'e' && char2 == 'c' { return 12; }
    return 0;
}

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

    if raw_name.len == 0 {
        // Nameless cookie values must not contain '=' to prevent key shadowing
        for char_byte in raw_val {
            if char_byte == '=' { return "", false; }
        }
    }

    cookie_ref.name.append(raw_name);
    cookie_ref.value.append(raw_val);
    return unparsed_attrs, true;
}

fn apply_parsed_cookie_attribute(
    cookie_ref: CanonicalCookie&,
    raw_attr: const u8[:],
    has_max_age: bool&,
    now_us: i64,
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
        apply_parsed_domain_attribute(cookie_ref, attr_val);
    } else if eq_ascii_fold(attr_name, "path") {
        apply_parsed_path_attribute(cookie_ref, attr_val);
    } else if eq_ascii_fold(attr_name, "max-age") {
        apply_parsed_max_age_attribute(cookie_ref, attr_val, has_max_age, now_us);
    } else if eq_ascii_fold(attr_name, "expires") {
        apply_parsed_expires_attribute(cookie_ref, attr_val, has_max_age, now_us);
    }
}

fn apply_parsed_domain_attribute(cookie_ref: CanonicalCookie&, attr_val: const u8[:]) {
    guard attr_val.len > 0 && attr_val[attr_val.len - 1] != '.' else { return; }
    let clean_domain = if attr_val[0] == '.' { attr_val[1..] } else { attr_val };
    // RFC 6265 Section 5.2.3: If domain still begins with '.', ignore the domain attribute
    guard clean_domain.len > 0 && clean_domain[0] != '.' else { return; }
    guard clean_domain.len <= cookie_ref.domain.cap else { return; }
    cookie_ref.domain.clear();
    cookie_ref.domain.append(clean_domain);
    to_lower(cookie_ref.domain[..]);
    cookie_ref.host_only = false;
}

fn apply_parsed_path_attribute(cookie_ref: CanonicalCookie&, attr_val: const u8[:]) {
    guard attr_val.len > 0 && attr_val[0] == '/' else { return; }
    guard attr_val.len <= cookie_ref.path.cap else { return; }
    cookie_ref.path.clear();
    cookie_ref.path.append(attr_val);
}

fn apply_parsed_max_age_attribute(
    cookie_ref: CanonicalCookie&,
    attr_val: const u8[:],
    has_max_age: bool&,
    now_us: i64,
) {
    let max_age_val, max_age_ok = parse_int(attr_val);
    guard max_age_ok else { return; }

    has_max_age = true;
    cookie_ref.persistent = true;
    if max_age_val <= 0 {
        cookie_ref.expires_utc = now_us - 1000000;
        return;
    }

    let max_allowed_seconds = internal::K_MAX_COOKIE_AGE_US / 1000000;
    let capped_sec = core::ct_min_i64(max_age_val, max_allowed_seconds);
    cookie_ref.expires_utc = now_us + capped_sec * 1000000;
}

fn apply_parsed_expires_attribute(
    cookie_ref: CanonicalCookie&,
    attr_val: const u8[:],
    has_max_age: bool,
    now_us: i64,
) {
    guard !has_max_age else { return; }

    let expires_us, expires_ok = parse_cookie_date_us(attr_val);
    guard expires_ok else { return; }

    cookie_ref.persistent = true;
    if expires_us > now_us && (expires_us - now_us > internal::K_MAX_COOKIE_AGE_US) {
        cookie_ref.expires_utc = now_us + internal::K_MAX_COOKIE_AGE_US; // 400 days cap
    } else {
        cookie_ref.expires_utc = expires_us;
    }
}

fn validate_parsed_cookie_domain(cookie_ref: CanonicalCookie&, default_domain: const u8[:]) -> bool {
    guard !cookie_ref.host_only else { return true; }

    if core::is_ip_address_literal(cookie_ref.domain[..]) || (default_domain.len > 0 && core::is_ip_address_literal(default_domain)) {
        if default_domain.len > 0 && eq_ascii_fold(cookie_ref.domain[..], default_domain) {
            cookie_ref.host_only = true;
            return true;
        }
        return false;
    }

    if is_public_suffix_domain(cookie_ref.domain[..]) {
        if default_domain.len > 0 && eq_ascii_fold(cookie_ref.domain[..], default_domain) {
            cookie_ref.host_only = true;
            return true;
        }
        return false;
    }

    // Single-label hosts without dots cannot set domain cookies
    if core::count_byte(cookie_ref.domain[..], '.') == 0 {
        cookie_ref.host_only = true;
        return true;
    }

    if default_domain.len > 0 && !cookie_domain_match(default_domain, cookie_ref.domain[..]) {
        return false;
    }

    return true;
}

fn extract_ipv6_host_and_port<B>(host_part: const u8[:], bare_host_out: B&, port_out: i32&) -> bool {
    guard host_part.len > 0 && host_part[0] == '[' else { return false; }
    var close_bracket = -1;
    for char_idx in host_part.len {
        if host_part[char_idx] == ']' { close_bracket = char_idx; break; }
    }
    guard close_bracket > 0 else { return false; }

    bare_host_out.append(host_part[1..close_bracket]);
    if close_bracket + 1 < host_part.len && host_part[close_bracket + 1] == ':' {
        let port_val, port_ok = parse_int(host_part[close_bracket + 2..]);
        if port_ok && port_val > 0 && port_val <= 65535 {
            port_out = port_val as i32;
        }
    }
    return true;
}
