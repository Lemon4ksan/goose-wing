// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Set-Cookie header parsing, date tokenization, and cookie URL models (RFC 6265bis).
namespace cookie;

import std;
import core from "..";
import .limits;
import .constants;
import .canonical;
import .psl;

// ---- ingestion pipeline & set-cookie parser --------------------------------

fn cookie_internal::normalize_default_domain(default_domain: const u8[:]) -> u8[..256], bool {
    var out: u8[..256] = [];
    let raw = default_domain.trim_byte('[').trim_byte(']');
    guard raw.len > 0 else { return out, true; }
    if !core::is_pure_ascii(raw) {
        let ok = core::punycode_encode_domain(raw, out);
        return out, ok;
    }
    guard out.try_set(raw) else { return out, false; }
    to_lower(out[..]);
    return out, true;
}

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
) -> CanonicalCookie, DeleteCause, bool {
    var parsed_cookie = CanonicalCookie { .. };

    guard header_val.len > 0 else {
        return parsed_cookie, DeleteCause.UNKNOWN, false;
    }
    if cookie_internal::has_prohibited_ctl(header_val) {
        return parsed_cookie, DeleteCause.CONTROL_CHAR, false;
    }

    let unparsed_attrs, payload_ok = cookie_internal::parse_payload_pair(header_val, parsed_cookie);
    guard payload_ok else {
        return parsed_cookie, DeleteCause.UNKNOWN, false;
    }

    let def_dom_buf, dom_ok = cookie_internal::normalize_default_domain(default_domain);
    guard dom_ok else {
        return parsed_cookie, DeleteCause.UNKNOWN, false;
    }
    let clean_def_domain = def_dom_buf[..];
    guard parsed_cookie.domain.try_set(clean_def_domain) else {
        return parsed_cookie, DeleteCause.UNKNOWN, false;
    }
    let eff_default_path = if default_path.len > 0 && default_path[0] == '/' { default_path } else { "/" };
    guard parsed_cookie.path.try_set(eff_default_path) else {
        return parsed_cookie, DeleteCause.UNKNOWN, false;
    }
    parsed_cookie.host_only = true;
    parsed_cookie.creation_utc = now_us;
    parsed_cookie.last_access_utc = now_us;
    parsed_cookie.last_update_utc = now_us;

    var has_max_age = false;
    if unparsed_attrs.len > 0 {
        var tok = core::make_byte_tokenizer(unparsed_attrs, ';');
        loop {
            let raw_attr, has_attr = core::token_next(tok);
            guard has_attr else { break; }
            cookie_internal::apply_parsed_attribute(
                parsed_cookie, raw_attr, has_max_age, clean_def_domain, eff_default_path, now_us,
            );
        }
    }

    guard cookie_internal::validate_parsed_domain(parsed_cookie, clean_def_domain)
        && cookie_internal::has_valid_prefix_attributes(parsed_cookie, parsed_cookie.name[..]) else {
        return parsed_cookie, DeleteCause.UNKNOWN, false;
    }

    // RFC 6265bis Section 5.5.7 & CHIPS: SameSite=None and Partitioned require Secure
    if (parsed_cookie.same_site == SameSite.None || parsed_cookie.partitioned) && !parsed_cookie.secure {
        return parsed_cookie, DeleteCause.UNKNOWN, false;
    }

    return parsed_cookie, DeleteCause.UNKNOWN, true;
}

// ---- date parser -----------------------------------------------------------

struct cookie_internal::DateParts {
    hour:   i64 = 0,
    minute: i64 = 0,
    second: i64 = 0,
    day:    i64 = 0,
    month:  i64 = 0,
    year:   i64 = 0,
}

// Parses a cookie date string into a microsecond UTC timestamp (RFC 6265 Section 5.1.1).
//
// Example:
//   raw = "Wed, 09 Jun 2021 10:18:14 GMT"
//   returns: 1623233894000000, ok = true
fn parse_date_us(raw: const u8[:]) -> i64, bool {
    guard raw.len > 0 else { return 0, false; }

    var parts, scanned = cookie_internal::scan_date_tokens(raw);
    guard scanned else { return 0, false; }

    parts.year = cookie_internal::normalize_year(parts.year);
    guard cookie_internal::is_valid_calendar_date(parts) else { return 0, false; }

    let total_days = core::civil_to_days(parts.year, parts.month, parts.day);
    let days_sec = core::mul_sat_i64(total_days, 86400);
    let min_sec = core::add_sat_i64(core::mul_sat_i64(parts.minute, 60), parts.second);
    let hms_sec = core::add_sat_i64(core::mul_sat_i64(parts.hour, 3600), min_sec);
    let total_sec = core::add_sat_i64(days_sec, hms_sec);
    return core::mul_sat_i64(total_sec, 1000000), true; // Microseconds UTC
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
    let parsed, url_err = core::parse_url(raw_url);
    if parsed.valid {
        guard parsed_url.scheme.try_set(parsed.scheme()) else {
            return CanonicalCookieURL { .. };
        }
        parsed_url.is_secure = parsed.is_secure_scheme();
        let h_str = parsed.hostname();
        let clean_h = if h_str.len > 2 && h_str[0] == '[' && h_str[core::sub_sat_i64(h_str.len, 1)] == ']' {
            h_str[1..^1]
        } else {
            h_str
        };
        guard clean_h.len > 0 && parsed_url.host.try_set(clean_h) else {
            return CanonicalCookieURL { .. };
        }
        to_lower(parsed_url.host[..]);
        let p_str = parsed.pathname();
        let eff_p = if p_str.len > 0 { p_str } else { "/" };
        guard parsed_url.path.try_set(eff_p) else {
            return CanonicalCookieURL { .. };
        }
        parsed_url.port = parsed.effective_port();
        return parsed_url;
    }

    guard url_err == core::UrlParseError.RelativeWithoutBase
        || url_err == core::UrlParseError.InputTooLong else {
        return CanonicalCookieURL { .. };
    }

    var rest_url = raw_url;
    if rest_url.starts_with_fold("https://") {
        let _ = parsed_url.scheme.try_set("https");
        parsed_url.is_secure = true;
        parsed_url.port = 443;
        rest_url = rest_url[8..];
    } else if rest_url.starts_with_fold("http://") {
        let _ = parsed_url.scheme.try_set("http");
        parsed_url.is_secure = false;
        parsed_url.port = 80;
        rest_url = rest_url[7..];
    } else if core::contains(rest_url, "://") {
        return CanonicalCookieURL { .. };
    }

    let host_part, path_part = cookie_internal::split_url_host_and_path(rest_url);
    var port_val = parsed_url.port;
    let host_slice = cookie_internal::extract_url_host_and_port_slice(host_part, port_val);
    guard host_slice.len > 0 && parsed_url.host.try_set(host_slice) else {
        return CanonicalCookieURL { .. };
    }
    to_lower(parsed_url.host[..]);

    let eff_path = if path_part.len > 0 { path_part } else { "/" };
    guard parsed_url.path.try_set(eff_path) else {
        return CanonicalCookieURL { .. };
    }
    parsed_url.port = port_val;
    return parsed_url;
}

fn cookie_internal::split_url_host_and_path(rest_url: const u8[:]) -> const u8[:], const u8[:] {
    let slash_idx = core::find_byteset(rest_url, "/?#");
    let host_part = if slash_idx >= 0 { rest_url[..slash_idx] } else { rest_url };
    let path_part = if slash_idx >= 0 && rest_url[slash_idx] == '/' {
        let rel_q = core::find_byteset(rest_url[slash_idx..], "?#");
        if rel_q >= 0 { rest_url[slash_idx..core::add_sat_i64(slash_idx, rel_q)] } else { rest_url[slash_idx..] }
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
fn cookie_internal::extract_url_host_and_port_slice(host_part: const u8[:], port_out: i32&) -> const u8[:] {
    guard host_part.len > 0 else { return ""; }
    if host_part[0] == '[' {
        let close_bracket = host_part.index_of_byte(']');
        guard close_bracket > 1 else { return ""; }
        let ipv6_slice = host_part[1..close_bracket];
        guard core::is_ip_address_literal(ipv6_slice) else { return ""; }
        let colon_pos = core::add_sat_i64(close_bracket, 1);
        if colon_pos == host_part.len {
            return ipv6_slice;
        }
        guard host_part[colon_pos] == ':' else { return ""; }
        let port_start = core::add_sat_i64(close_bracket, 2);
        let port_val, port_ok = host_part[port_start..].parse_i64_dec();
        guard port_ok && port_val > 0 && port_val <= 65535 else { return ""; }
        port_out = port_val as i32;
        return ipv6_slice;
    }
    if core::is_ip_address_literal(host_part) {
        return host_part;
    }
    let host_slice, port_slice, has_colon = host_part.split_once_byte(':');
    var port_parsed: i32 = port_out;
    if has_colon {
        guard host_slice.len > 0 else { return ""; }
        let port_val, port_ok = port_slice.parse_i64_dec();
        guard port_ok && port_val > 0 && port_val <= 65535 else { return ""; }
        port_parsed = port_val as i32;
    }
    let candidate = if has_colon { host_slice } else { host_part };
    guard !cookie_internal::is_domain_syntax_invalid(candidate) && !candidate.contains_byte('@') else {
        return "";
    }
    if has_colon {
        port_out = port_parsed;
    }
    return candidate;
}

// ---- internal implementation helpers ---------------------------------------

// Scans cookie date tokens into day, month, year, and time components.
//
// Example:
//   raw = "Wed, 09 Jun 2021 10:18:14 GMT"
//   returns: DateParts{hour=10, minute=18, second=14, day=9, month=6, year=2021}, true
fn cookie_internal::scan_date_tokens(raw: const u8[:]) -> cookie_internal::DateParts, bool {
    var parts = cookie_internal::DateParts { .. };
    var found_time = false;
    var found_dom = false;
    var found_month = false;
    var found_year = false;

    var scan_pos: i64 = 0;
    while scan_pos < raw.len {
        while scan_pos < raw.len && cookie_internal::is_date_delimiter(raw[scan_pos]) {
            scan_pos = core::add_sat_i64(scan_pos, 1);
        }
        if scan_pos >= raw.len { break; }
        let token_start = scan_pos;
        while scan_pos < raw.len && !cookie_internal::is_date_delimiter(raw[scan_pos]) {
            scan_pos = core::add_sat_i64(scan_pos, 1);
        }
        let token = raw[token_start..scan_pos];

        if !found_time && cookie_internal::try_parse_time(token, parts.hour, parts.minute, parts.second) {
            found_time = true;
        } else if !found_dom && cookie_internal::try_parse_dom(token, parts.day) {
            found_dom = true;
        } else if !found_month && cookie_internal::try_parse_month(token, parts.month) {
            found_month = true;
        } else if !found_year && cookie_internal::try_parse_year(token, parts.year) {
            found_year = true;
        }
    }

    return parts, found_time && found_dom && found_month && found_year;
}

fn cookie_internal::is_valid_calendar_date(parts: const cookie_internal::DateParts&) -> bool {
    guard parts.month >= 1 && parts.month <= 12 else { return false; }
    guard parts.day >= 1 && parts.day <= core::days_in_month(parts.year, parts.month) else { return false; }
    guard parts.year >= 1601 && parts.year <= 9999 else { return false; }
    guard parts.hour >= 0 && parts.hour <= 23
        && parts.minute >= 0 && parts.minute <= 59
        && parts.second >= 0 && parts.second <= 59 else { return false; }
    return true;
}

fn cookie_internal::is_date_delimiter(char_byte: u8) -> bool {
    return char_byte == 0x09 ||
           (char_byte >= 0x20 && char_byte <= 0x2F) ||
           (char_byte >= 0x3B && char_byte <= 0x40) ||
           (char_byte >= 0x5B && char_byte <= 0x60) ||
           (char_byte >= 0x7B && char_byte <= 0x7E);
}

// Parses an RFC 6265 `time` token (`HH:MM:SS`) into hour, minute, and second.
//
// Example:
//   token = "08:49:37" -> returns: true, hour = 8, minute = 49, second = 37
fn cookie_internal::try_parse_time(token: const u8[:], hour: i64&, minute: i64&, second: i64&) -> bool {
    guard token.len >= 5 else { return false; }
    let colon_pos1 = token.index_of_byte(':');
    guard colon_pos1 == 1 || colon_pos1 == 2 else { return false; }
    let after_h = if colon_pos1 == 1 { token[2..] } else { token[3..] };
    let min_len = after_h.index_of_byte(':');
    guard min_len == 1 || min_len == 2 else { return false; }
    let sec_part = if min_len == 1 { after_h[2..] } else { after_h[3..] };
    guard sec_part.len >= 1 else { return false; }

    let s1 = sec_part.len >= 2 && core::is_ascii_digit(sec_part[1]);
    let s2 = sec_part.len >= 3 && core::is_ascii_digit(sec_part[2]);
    guard !s2 else { return false; }
    let sec_slice = if s1 { sec_part[..2] } else { sec_part[..1] };
    guard core::is_ascii_digit(token[0])
        && core::is_ascii_digit(after_h[0])
        && core::is_ascii_digit(sec_slice[0]) else { return false; }

    let hour_val, hour_ok = token[..colon_pos1].parse_i64_dec();
    let minute_val, minute_ok = after_h[..min_len].parse_i64_dec();
    let second_val, second_ok = sec_slice.parse_i64_dec();
    guard hour_ok && minute_ok && second_ok else { return false; }

    hour = hour_val;
    minute = minute_val;
    second = second_val;
    return true;
}

// Parses a 1-2 digit day-of-month prefix from `token`.
//
// Example:
//   token = "06" -> returns: true, day = 6
fn cookie_internal::try_parse_dom(token: const u8[:], day: i64&) -> bool {
    guard token.len >= 1 && core::is_ascii_digit(token[0]) else { return false; }
    let d1 = token.len >= 2 && core::is_ascii_digit(token[1]);
    let d2 = token.len >= 3 && core::is_ascii_digit(token[2]);
    guard !d2 else { return false; }
    let digits = if d1 { token[..2] } else { token[..1] };
    let day_val, day_ok = digits.parse_i64_dec();
    guard day_ok else { return false; }
    day = day_val;
    return true;
}

// Parses a 3-letter month prefix into `month` (1..12).
//
// Example:
//   token = "Nov" -> returns: true, month = 11
fn cookie_internal::try_parse_month(token: const u8[:], month: i64&) -> bool {
    let month_val = cookie_internal::parse_month_name(token);
    guard month_val > 0 else { return false; }
    month = month_val;
    return true;
}

// Parses a 2-4 digit year token and normalizes 2-digit years per RFC 6265 Section 5.1.1.
//
// Example:
//   token = "94" -> returns: true, year = 1994
fn cookie_internal::try_parse_year(token: const u8[:], year: i64&) -> bool {
    var digit_len: i64 = 0;
    while digit_len < token.len && digit_len < 5 {
        if core::is_ascii_digit(token[digit_len]) {
            digit_len = core::add_sat_i64(digit_len, 1);
        } else {
            break;
        }
    }
    guard digit_len >= 2 && digit_len <= 4 else { return false; }
    let year_val, year_ok = token[..digit_len].parse_i64_dec();
    guard year_ok else { return false; }
    let norm_yr = cookie_internal::normalize_year(year_val);
    guard norm_yr >= 1601 else { return false; }
    year = norm_yr;
    return true;
}

fn cookie_internal::normalize_year(year: i64) -> i64 {
    if year >= 70 && year <= 99 { return core::add_sat_i64(year, 1900); }
    if year >= 0 && year <= 69 { return core::add_sat_i64(year, 2000); }
    return year;
}

// Parses a three-letter, abbreviated, or full month name to 1-based month index (RFC 6265 Section 5.1.1).
//
// Example:
//   token = "Sept"
//   returns: 9
fn cookie_internal::parse_month_name(token: const u8[:]) -> i64 {
    guard token.len >= 3 else { return 0; }

    if token.eq_ascii_fold("jan") || token.eq_ascii_fold("january") { return 1; }
    if token.eq_ascii_fold("feb") || token.eq_ascii_fold("february") { return 2; }
    if token.eq_ascii_fold("mar") || token.eq_ascii_fold("march") { return 3; }
    if token.eq_ascii_fold("apr") || token.eq_ascii_fold("april") { return 4; }
    if token.eq_ascii_fold("may") { return 5; }
    if token.eq_ascii_fold("jun") || token.eq_ascii_fold("june") { return 6; }
    if token.eq_ascii_fold("jul") || token.eq_ascii_fold("july") { return 7; }
    if token.eq_ascii_fold("aug") || token.eq_ascii_fold("august") { return 8; }
    if token.eq_ascii_fold("sep") || token.eq_ascii_fold("sept") || token.eq_ascii_fold("september") { return 9; }
    if token.eq_ascii_fold("oct") || token.eq_ascii_fold("october") { return 10; }
    if token.eq_ascii_fold("nov") || token.eq_ascii_fold("november") { return 11; }
    if token.eq_ascii_fold("dec") || token.eq_ascii_fold("december") { return 12; }

    return 0;
}

// Validates RFC 6265bis Section 5.6 cookie prefix attributes on `cookie_val`.
fn cookie_internal::has_valid_prefix_attributes(
    cookie_val:  const cookie::CanonicalCookie&,
    cookie_name: const u8[:],
) -> bool {
    if cookie_name.len == 0 {
        let cookie_value = cookie_val.value[..];
        if cookie_value.starts_with_fold("__host-http-") ||
           cookie_value.starts_with_fold("__host-") ||
           cookie_value.starts_with_fold("__http-") ||
           cookie_value.starts_with_fold("__secure-") {
            return false;
        }
    }

    if cookie_name.starts_with_fold("__host-http-") {
        return cookie_val.secure && cookie_val.httponly && !cookie_val.has_domain_attr
            && cookie_val.host_only && cookie_val.has_path_attr && cookie_val.path[..] == "/";
    }
    if cookie_name.starts_with_fold("__host-") {
        return cookie_val.secure && !cookie_val.has_domain_attr
            && cookie_val.host_only && cookie_val.has_path_attr && cookie_val.path[..] == "/";
    }
    if cookie_name.starts_with_fold("__http-") {
        return cookie_val.secure && cookie_val.httponly;
    }
    if cookie_name.starts_with_fold("__secure-") {
        return cookie_val.secure;
    }
    return true;
}

// Parses the initial name=value pair of a Set-Cookie header (RFC 6265 Section 5.2).
//
// Example:
//   header_val = "session=xyz; Secure"
//   returns: " Secure", ok = true
fn cookie_internal::parse_payload_pair(
    header_val: const u8[:],
    cookie_ref: cookie::CanonicalCookie&,
) -> const u8[:], bool {
    let name_val_part, unparsed_attrs, _ = header_val.split_once_byte(';');
    let lhs, rhs, has_eq = name_val_part.split_once_byte('=');
    let raw_name = if has_eq { lhs.trim_lws() } else { "" };
    let raw_val = if has_eq { rhs.trim_lws() } else { name_val_part.trim_lws() };

    guard raw_name.len > 0 || raw_val.len > 0 else { return "", false; }
    if core::add_sat_i64(raw_name.len, raw_val.len) > cookie_internal::K_MAX_COOKIE_NAME_VAL_LEN {
        return "", false;
    }

    guard cookie_internal::is_valid_cookie_name(raw_name) else { return "", false; }
    guard cookie_internal::is_valid_cookie_val(raw_val) else { return "", false; }
    guard raw_name.len > 0 || !raw_val.contains_byte('=') else { return "", false; }

    var committed = false;
    defer if !committed {
        cookie_ref.name.clear();
        cookie_ref.value.clear();
    };
    guard cookie_ref.name.try_set(raw_name) && cookie_ref.value.try_set(raw_val) else {
        return "", false;
    }
    committed = true;
    return unparsed_attrs, true;
}

fn cookie_internal::apply_parsed_attribute(
    cookie_ref:     cookie::CanonicalCookie&,
    raw_attr:       const u8[:],
    has_max_age:    bool&,
    default_domain: const u8[:],
    default_path:   const u8[:],
    now_us:         i64,
) {
    let clean_attr = raw_attr.trim_lws();
    guard clean_attr.len > 0 else { return; }

    let lhs, rhs, has_eq = clean_attr.split_once_byte('=');
    let attr_name = if has_eq { lhs.trim_lws() } else { clean_attr };
    let attr_val = if has_eq { rhs.trim_lws() } else { "" };

    if attr_name.eq_ascii_fold("domain") {
        cookie_ref.has_domain_attr = true;
        if attr_val.len > cookie_internal::K_MAX_COOKIE_ATTR_VAL_LEN {
            cookie_ref.domain.clear();
            cookie_ref.host_only = false;
            return;
        }
        cookie_internal::apply_parsed_domain_attribute(cookie_ref, attr_val, default_domain);
        return;
    }

    guard attr_val.len <= cookie_internal::K_MAX_COOKIE_ATTR_VAL_LEN else { return; }

    if attr_name.eq_ascii_fold("httponly") {
        cookie_ref.httponly = true;
    } else if attr_name.eq_ascii_fold("secure") {
        cookie_ref.secure = true;
    } else if attr_name.eq_ascii_fold("partitioned") {
        cookie_ref.partitioned = true;
    } else if attr_name.eq_ascii_fold("samesite") {
        cookie_ref.same_site = cookie::parse_same_site(attr_val);
    } else if attr_name.eq_ascii_fold("priority") {
        cookie_ref.priority = cookie::parse_priority(attr_val);
    } else if attr_name.eq_ascii_fold("path") {
        cookie_ref.apply_parsed_path_attribute(attr_val, default_path);
    } else if attr_name.eq_ascii_fold("max-age") {
        cookie_internal::apply_parsed_max_age_attribute(cookie_ref, attr_val, has_max_age, now_us);
    } else if attr_name.eq_ascii_fold("expires") {
        cookie_internal::apply_parsed_expires_attribute(cookie_ref, attr_val, has_max_age, now_us);
    }
}

fn cookie_internal::apply_parsed_domain_attribute(
    cookie_ref:     cookie::CanonicalCookie&,
    attr_val:       const u8[:],
    default_domain: const u8[:],
) {
    if attr_val.len == 0 {
        cookie_ref.host_only = true;
        let _ = cookie_ref.domain.try_set(default_domain);
        to_lower(cookie_ref.domain[..]);
        return;
    }
    let clean_domain = if attr_val[0] == '.' { attr_val[1..] } else { attr_val };
    // RFC 6265 Section 5.2.3: If domain still begins with '.', ignore the domain attribute
    guard clean_domain.len > 0 && clean_domain[0] != '.' else { return; }
    if !core::is_pure_ascii(clean_domain) {
        var ace_buf: u8[..256] = [];
        guard core::punycode_encode_domain(clean_domain, ace_buf)
            && cookie_ref.domain.try_set(ace_buf[..]) else {
            cookie_ref.domain.clear();
            cookie_ref.host_only = false;
            return;
        }
        cookie_ref.host_only = false;
        return;
    }
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
        if !cookie_ref.path.try_set(default_path) {
            let _ = cookie_ref.path.try_set("/");
        }
        return;
    }
    guard cookie_ref.path.try_set(attr_val) else {
        cookie_ref.has_path_attr = false;
        let _ = cookie_ref.path.try_set("/");
        return;
    }
    cookie_ref.has_path_attr = true;
}

fn cookie_internal::apply_parsed_max_age_attribute(
    cookie_ref:  cookie::CanonicalCookie&,
    attr_val:    const u8[:],
    has_max_age: bool&,
    now_us:      i64,
) {
    // RFC 6265 Section 5.2.2: The Max-Age Attribute - ignore if first char is not DIGIT or '-'
    guard attr_val.len > 0 && attr_val[0] != '+' else { return; }
    let is_neg = attr_val[0] == '-';
    let digits = if is_neg { attr_val[1..] } else { attr_val };
    guard digits.len > 0 else { return; }
    for b in digits {
        guard core::is_ascii_digit(b) else { return; }
    }
    let parsed_val, max_age_ok = attr_val.parse_i64_dec();
    let max_age_val = if max_age_ok {
        parsed_val
    } else if is_neg {
        -1
    } else {
        cookie_internal::K_MAX_COOKIE_AGE_SEC
    };

    has_max_age = true;
    cookie_ref.persistent = true;
    if max_age_val <= 0 {
        cookie_ref.expires_utc = core::sub_sat_i64(now_us, 1000000);
        return;
    }

    let capped_sec = min(max_age_val, cookie_internal::K_MAX_COOKIE_AGE_SEC);
    cookie_ref.expires_utc = core::add_sat_i64(now_us, core::mul_sat_i64(capped_sec, 1000000));
}

fn cookie_internal::apply_parsed_expires_attribute(
    cookie_ref:  cookie::CanonicalCookie&,
    attr_val:    const u8[:],
    has_max_age: bool,
    now_us:      i64,
) {
    guard !has_max_age else { return; }

    let expires_us, expires_ok = cookie::parse_date_us(attr_val);
    guard expires_ok else { return; }

    cookie_ref.persistent = true;
    cookie_ref.expires_utc = min(expires_us, core::add_sat_i64(now_us, cookie_internal::K_MAX_COOKIE_AGE_US));
}

inline fn cookie_internal::try_fallback_exact_host_only(
    cookie_ref:     cookie::CanonicalCookie&,
    default_domain: const u8[:],
) -> bool {
    if default_domain.len > 0 && cookie_ref.domain[..].eq_ascii_fold(default_domain) {
        cookie_ref.host_only = true;
        return true;
    }
    return false;
}

inline fn cookie_internal::is_domain_syntax_invalid(domain: const u8[:]) -> bool {
    if domain.len == 0 || domain[core::sub_sat_i64(domain.len, 1)] == '.' || core::contains(domain, "..") {
        return true;
    }
    for b in domain {
        if b <= 0x20 || b >= 0x7F || b == '/' || b == ':' || b == '?' || b == '#' {
            return true;
        }
    }
    return false;
}

fn cookie_internal::validate_parsed_domain(
    cookie_ref:     cookie::CanonicalCookie&,
    default_domain: const u8[:],
) -> bool {
    guard !cookie_ref.host_only else { return true; }

    if cookie_internal::is_domain_syntax_invalid(cookie_ref.domain[..]) {
        return false;
    }

    if core::is_ip_address_literal(cookie_ref.domain[..])
        || (default_domain.len > 0 && core::is_ip_address_literal(default_domain)) {
        return cookie_internal::try_fallback_exact_host_only(cookie_ref, default_domain);
    }

    if cookie::is_public_suffix_domain(cookie_ref.domain[..]) {
        return cookie_internal::try_fallback_exact_host_only(cookie_ref, default_domain);
    }

    // Single-label hosts without dots cannot set domain cookies
    if cookie_ref.domain[..].count_byte('.') == 0 {
        return cookie_internal::try_fallback_exact_host_only(cookie_ref, default_domain);
    }

    if default_domain.len > 0 && !cookie::domain_match(default_domain, cookie_ref.domain[..]) {
        return false;
    }

    return true;
}

// Zero-allocation 8-byte span descriptor for a cookie name-value pair in a raw Cookie: header.
struct Span {
    name_pos: u16 = 0,
    name_len: u16 = 0,
    val_pos:  u16 = 0,
    val_len:  u16 = 0,
}

// Builds a Span from trimmed pair slice bounds.
//
// Example:
//   raw = "sid=xyz", pair_start = 0, pair_end = 7
//   returns: Span { name_pos: 0, name_len: 3, val_pos: 4, val_len: 3 }
fn parse_kv_span(raw: const u8[:], pair_start: i64, pair_end: i64) -> Span {
    guard raw.len <= 65535 && pair_end <= 65535 && pair_start >= 0 && pair_start <= pair_end
        && pair_end <= raw.len else {
        return Span { .. };
    }

    let raw_pair = raw[pair_start..pair_end];
    let no_lead = raw_pair.trim_lws_start();
    let start = core::sub_sat_i64(pair_end, no_lead.len);
    let pair_slice = no_lead.trim_lws_end();
    let end = core::add_sat_i64(start, pair_slice.len);

    let name_raw, val_raw, has_eq = pair_slice.split_once_byte('=');
    if has_eq {
        let name_clean = name_raw.trim_lws_end();
        let val_clean = val_raw.trim_lws_start();
        let val_start = core::sub_sat_i64(end, val_clean.len);

        return Span {
            name_pos: start as u16,
            name_len: name_clean.len as u16,
            val_pos:  val_start as u16,
            val_len:  val_clean.len as u16,
        };
    }

    return Span {
        name_pos: start as u16,
        name_len: pair_slice.len as u16,
        val_pos:  end as u16,
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
fn next_span(
    raw_header: const u8[:],
    cursor:     i64&,
) -> Span, bool {
    var empty_span = Span { .. };
    guard cursor >= 0 && cursor < raw_header.len && raw_header.len <= 65535 else {
        return empty_span, false;
    }

    let rem = raw_header[cursor..].trim_start_bytes(" \t;");
    guard rem.len > 0 else { return empty_span, false; }

    let pair_start = core::sub_sat_i64(raw_header.len, rem.len);
    let pair_raw, rest, has_semi = rem.split_once_byte(';');
    let next_cur = if has_semi { core::sub_sat_i64(raw_header.len, rest.len) } else { raw_header.len };

    let pair_trimmed = pair_raw.trim_lws_end();
    guard pair_trimmed.len > 0 else { return empty_span, false; }
    let pair_end = core::add_sat_i64(pair_start, pair_trimmed.len);

    cursor = next_cur;
    return parse_kv_span(raw_header, pair_start, pair_end), true;
}

// Extracts cookie value slice from raw wire header using span coordinates.
inline fn span_value(raw: const u8[:], span: Span) -> const u8[:] {
    let start: i64 = span.val_pos;
    let end:   i64 = core::add_sat_i64(start, span.val_len);
    guard end <= raw.len && start <= end else { return ""; }
    return raw[start..end];
}

// Extracts cookie name slice from raw wire header using span coordinates.
inline fn span_name(raw: const u8[:], span: Span) -> const u8[:] {
    let start: i64 = span.name_pos;
    let end:   i64 = core::add_sat_i64(start, span.name_len);
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
        let span, ok = next_span(raw_header, cursor);
        guard ok else { break; }
        let cname = span_name(raw_header, span);
        if cname == name {
            return span_value(raw_header, span), true;
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
fn decode_percent<B>(src: const u8[:], out: B&) -> bool {
    var tmp: u8[..4096] = [];
    guard core::percent_decode(src, tmp) && tmp[..].validate_utf8() else {
        return false;
    }
    return out.try_set(tmp[..]);
}

const cookie_internal::UPPER_HEX: u8[16] = [
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];

// Percent-encodes bytes outside RFC 6265 `cookie-octet` (or '%') into `%XX` uppercase hex.
//
// Example:
//   src = "a b;c", out = []
//   returns: true, out = "a%20b%3Bc"
fn encode_percent<B>(src: const u8[:], out: B&) -> bool {
    var tmp: u8[..12288] = [];
    for b in src {
        if cookie_internal::is_cookie_octet(b) && b != '%' {
            guard tmp.try_push(b) else { return false; }
        } else {
            let hi = ((b >> 4) & 0x0F) as i64;
            let lo = (b & 0x0F) as i64;
            guard tmp.try_push('%')
                && tmp.try_push(cookie_internal::UPPER_HEX[hi])
                && tmp.try_push(cookie_internal::UPPER_HEX[lo]) else {
                return false;
            }
        }
    }
    return out.try_set(tmp[..]);
}
