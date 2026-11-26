// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for CORS origin/header policy and SSRF IP/domain validation.
namespace security_internal;

import std;
import core;
import rfc.http;

// ---- CORS internal helpers -------------------------------------------------

// Validates characters in a CORS subdomain label sequence (RFC 1035 / WHATWG Fetch §3.2).
//
// Example:
//   sub = "stage.app"
//   returns: true
inline fn validate_cors_subdomain(sub: const u8[:]) -> bool {
    var prev_dot = false;
    let last_idx = core::sub_sat_i64(sub.len, 1);
    for i in sub.len {
        let b = sub[i];
        if b == '.' {
            if prev_dot || i == 0 || i == last_idx { return false; }
            prev_dot = true;
        } else if b == '-' {
            if prev_dot || i == 0 || i == last_idx { return false; }
            let next_idx = core::add_sat_i64(i, 1);
            if next_idx < sub.len && sub[next_idx] == '.' { return false; }
            prev_dot = false;
        } else if core::is_ascii_alphanumeric(b) {
            prev_dot = false;
        } else {
            return false;
        }
    }
    return true;
}

// Verifies whether candidate host matches wildcard domain suffix "*.domain.tld".
//
// Example:
//   cand_rest = "api.example.com", pat_rest = "*.example.com"
//   returns: true
inline fn match_cors_wildcard_host(cand_rest: const u8[:], pat_rest: const u8[:]) -> bool {
    guard pat_rest.starts_with_fold("*.") else { return false; }
    let domain_suffix = pat_rest[2..];
    guard domain_suffix.contains_byte('.') else { return false; }
    guard cand_rest.len > domain_suffix.len && cand_rest.ends_with_fold(domain_suffix) else { return false; }
    let prefix_len = core::sub_sat_i64(cand_rest.len, domain_suffix.len);
    let dot_idx = core::sub_sat_i64(prefix_len, 1);
    guard dot_idx > 0 && cand_rest[dot_idx] == '.' else { return false; }

    let sub = cand_rest[..dot_idx];
    return validate_cors_subdomain(sub);
}

fn has_wildcard_origin(policy: const security::CorsPolicy&) -> bool {
    guard policy.allowed_origins.len > 0 else { return false; }
    for &orig in policy.allowed_origins {
        if orig[..].trim_lws() == "*" {
            return true;
        }
    }
    return false;
}

inline fn is_valid_cors_token(tok: const u8[:]) -> bool {
    guard tok.len > 0 else { return false; }
    for b in tok {
        guard core::is_tchar(b) else { return false; }
    }
    return true;
}

inline fn validate_cors_token_list(list: const u8[:], allow_wildcard: bool) -> bool {
    guard list.trim_lws().len > 0 else { return true; }
    var tok_iter = core::make_byte_tokenizer(list, ',');
    loop {
        let item, ok = core::token_next(tok_iter);
        guard ok else { break; }
        let trimmed = item.trim_lws();
        if trimmed == "*" {
            guard allow_wildcard else { return false; }
            continue;
        }
        guard !trimmed.contains_byte('*') && is_valid_cors_token(trimmed) else { return false; }
    }
    return true;
}

inline fn header_list_has_token(
    header_val:     const u8[:],
    token:          const u8[:],
    allow_wildcard: bool = true,
) -> bool {
    var tok_iter = core::make_byte_tokenizer(header_val, ',');
    loop {
        let item, ok = core::token_next(tok_iter);
        guard ok else { break; }
        let trimmed = item.trim_lws();
        if (allow_wildcard && trimmed == "*") || trimmed.eq_ascii_fold(token) {
            return true;
        }
    }
    return false;
}

inline fn headers_vary_has_token<H>(headers: const H&, token: const u8[:]) -> bool {
    for &e in headers.entries {
        guard headers.entry_name(e).eq_ascii_fold(rfc::HEADER_VARY) else { continue; }
        if header_list_has_token(headers.entry_value(e), token) {
            return true;
        }
    }
    return false;
}

inline fn headers_vary_has_all_tokens<H>(headers: const H&, required_list: const u8[:]) -> bool {
    var tok_iter = core::make_byte_tokenizer(required_list, ',');
    loop {
        let item, ok = core::token_next(tok_iter);
        guard ok else { break; }
        let tok = item.trim_lws();
        if tok.len > 0 && !headers_vary_has_token(headers, tok) {
            return false;
        }
    }
    return true;
}

inline fn append_missing_vary_tokens<H>(
    headers:       const H&,
    required_list: const u8[:],
    merged:        u8[..2048]&,
) -> bool {
    var tok_iter = core::make_byte_tokenizer(required_list, ',');
    loop {
        let item, ok = core::token_next(tok_iter);
        guard ok else { break; }
        let tok = item.trim_lws();
        if tok.len == 0 || headers_vary_has_token(headers, tok) {
            continue;
        }
        if merged.len > 0 && !merged.try_append(", ") {
            return false;
        }
        guard merged.try_append(tok) else { return false; }
    }
    return true;
}

// Merges `required_list` tokens across all existing `Vary` header lines (RFC 9110 Section 12.5.5).
// Falls back to `Vary: *` if combined `Vary` value exceeds 2048 bytes.
fn merge_response_vary_tokens<H>(headers: H&, required_list: const u8[:]) {
    if headers_vary_has_all_tokens(headers, required_list) {
        return;
    }
    var merged: u8[..2048] = [];
    for &e in headers.entries {
        guard headers.entry_name(e).eq_ascii_fold(rfc::HEADER_VARY) else { continue; }
        let val = headers.entry_value(e).trim_lws();
        guard val.len > 0 else { continue; }
        if merged.len > 0 && !merged.try_append(", ") {
            headers.set_header(rfc::HEADER_VARY, "*");
            return;
        }
        if !merged.try_append(val) {
            headers.set_header(rfc::HEADER_VARY, "*");
            return;
        }
    }
    if !append_missing_vary_tokens(headers, required_list, merged) {
        headers.set_header(rfc::HEADER_VARY, "*");
        return;
    }
    headers.set_header(rfc::HEADER_VARY, merged[..]);
}

fn apply_cors_preflight_headers<Res>(policy: const security::CorsPolicy&, res: Res&) {
    if policy.allowed_methods.len > 0 {
        res.headers.set_header(rfc::HEADER_ACCESS_CONTROL_ALLOW_METHODS, policy.allowed_methods[..]);
    }
    if policy.allowed_headers.len > 0 {
        res.headers.set_header(rfc::HEADER_ACCESS_CONTROL_ALLOW_HEADERS, policy.allowed_headers[..]);
    }
    if policy.max_age_sec > 0 {
        var age_str: u8[..32] = [];
        policy.max_age_sec.format_i64_dec(age_str);
        res.headers.set_header(rfc::HEADER_ACCESS_CONTROL_MAX_AGE, age_str[..]);
    }
    res.status_code = rfc::STATUS_NO_CONTENT;
}

inline fn find_unique_cors_header<H>(headers: const H&, target_name: const u8[:]) -> const u8[:], bool {
    var val = headers.raw_buf[..0];
    var seen = false;
    for &e in headers.entries {
        guard headers.entry_name(e).eq_ascii_fold(target_name) else { continue; }
        guard !seen else { return headers.raw_buf[..0], false; }
        val = headers.entry_value(e).trim_lws();
        seen = true;
    }
    return val, true;
}

// ---- SSRF IP & domain validation internal helpers --------------------------

enum MetadataIpMatch {
    NotMatched,
    Allowed,
    Blocked,
}

fn is_private_ipv4_octets(octet0: i32, octet1: i32) -> bool {
    if octet0 == 0 { return true; }                                      // 0.0.0.0/8
    if octet0 == 10 { return true; }                                     // 10.0.0.0/8
    if octet0 == 127 { return true; }                                    // 127.0.0.0/8 Loopback
    if octet0 == 169 && octet1 == 254 { return true; }                   // 169.254.0.0/16 Link-Local / Cloud Metadata
    if octet0 == 172 && (octet1 >= 16 && octet1 <= 31) { return true; }  // 172.16.0.0/12
    if octet0 == 192 && octet1 == 168 { return true; }                   // 192.168.0.0/16
    // 198.18.0.0/15 Benchmarking (RFC 2544 / RFC 6890)
    if octet0 == 198 && (octet1 == 18 || octet1 == 19) { return true; }
    if octet0 == 100 && (octet1 >= 64 && octet1 <= 127) { return true; } // 100.64.0.0/10 CGNAT
    if octet0 >= 224 { return true; }                                    // 224.0.0.0/4 Multicast & Reserved
    return false;
}

fn is_private_ipv4_4octets(octet0: i32, octet1: i32, octet2: i32, octet3: i32) -> bool {
    if is_private_ipv4_octets(octet0, octet1) { return true; }
    if octet0 == 192 && octet1 == 0 && octet2 == 0 { return true; }    // 192.0.0.0/24 (RFC 6890 §2.1)
    if octet0 == 192 && octet1 == 0 && octet2 == 2 { return true; }    // 192.0.2.0/24 TEST-NET-1 (RFC 5737)
    if octet0 == 192 && octet1 == 88 && octet2 == 99 { return true; }  // 192.88.99.0/24 6to4 Relay Anycast (RFC 7526)
    if octet0 == 198 && octet1 == 51 && octet2 == 100 { return true; } // 198.51.100.0/24 TEST-NET-2 (RFC 5737)
    if octet0 == 203 && octet1 == 0 && octet2 == 113 { return true; }  // 203.0.113.0/24 TEST-NET-3 (RFC 5737)
    return false;
}

// Parses an IPv4 octet/part in decimal, octal (leading 0), or hex (0x prefix).
//
// Example:
//   part = "0x7f"
//   returns: val = 127, ok = true
fn parse_ipv4_part(part: const u8[:]) -> u64, bool {
    guard part.len > 0 else { return 0, false; }
    var base: u64 = 10;
    var start_idx = 0;
    if part.starts_with_fold("0x") {
        base = 16;
        start_idx = 2;
        guard part.len > 2 else { return 0, false; }
    } else if part.len >= 2 && part[0] == '0' {
        base = 8;
        start_idx = 1;
    }

    var val: u64 = 0;
    for i in start_idx..part.len {
        let hex = core::hex_digit_to_val(part[i]);
        guard hex >= 0 else { return 0, false; }
        let digit = hex as u64;
        val = core::add_sat_u64(core::mul_sat_u64(val, base), digit);
        guard digit < base && val <= 0xFFFFFFFF else { return 0, false; }
    }
    return val, true;
}

inline fn pack_flexible_ipv4_octets(nums: const u64[4]&, n: i64, octets: u8[4]&) -> bool {
    var ip_u32: u64 = 0;
    if n == 1 {
        guard nums[0] <= 0xFFFFFFFF else { return false; }
        ip_u32 = nums[0];
    } else if n == 2 {
        guard nums[0] <= 0xFF && nums[1] <= 0xFFFFFF else { return false; }
        ip_u32 = (nums[0] << 24) | nums[1];
    } else if n == 3 {
        guard nums[0] <= 0xFF && nums[1] <= 0xFF && nums[2] <= 0xFFFF else { return false; }
        ip_u32 = (nums[0] << 24) | (nums[1] << 16) | nums[2];
    } else if n == 4 {
        guard nums[0] <= 0xFF && nums[1] <= 0xFF && nums[2] <= 0xFF && nums[3] <= 0xFF else { return false; }
        ip_u32 = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3];
    } else {
        return false;
    }
    octets[0] = ((ip_u32 >> 24) & 0xFF) as u8;
    octets[1] = ((ip_u32 >> 16) & 0xFF) as u8;
    octets[2] = ((ip_u32 >> 8) & 0xFF) as u8;
    octets[3] = (ip_u32 & 0xFF) as u8;
    return true;
}

// Parses IPv4 addresses in standard dotted-decimal, octal, hex, dword, or
// shorthand notation into 4 canonical octets.
//
// Example:
//   clean_ip = "127.0.0.1"
//   returns: ok = true, octets = [127, 0, 0, 1]
fn parse_flexible_ipv4(clean_ip: const u8[:], octets: u8[4]&) -> bool {
    guard clean_ip.len > 0 && clean_ip[0] != '.' && clean_ip[clean_ip.len - 1] != '.' else {
        return false;
    }
    var nums:  u64[4] = [0, 0, 0, 0];
    var count: i64    = 0;
    var tok = core::make_byte_tokenizer(clean_ip, '.');
    loop {
        let part, has_tok = core::token_next(tok);
        guard has_tok else { break; }
        guard part.len > 0 && count < 4 else { return false; }
        let val, ok = parse_ipv4_part(part);
        guard ok else { return false; }
        nums[count] = val;
        count = core::add_sat_i64(count, 1);
    }
    return pack_flexible_ipv4_octets(nums, count, octets);
}

fn is_private_ipv4(clean_ip: const u8[:]) -> bool {
    var octets: u8[4] = [0, 0, 0, 0];
    guard parse_flexible_ipv4(clean_ip, octets) else { return false; }
    return is_private_ipv4_4octets(octets[0], octets[1], octets[2], octets[3]);
}

// Parses a 1..4 digit hexadecimal IPv6 segment into a 16-bit integer.
//
// Example:
//   s = "1f90"
//   returns: 8080, ok = true
fn parse_ssrf_hex_u16(s: const u8[:]) -> u16, bool {
    guard s.len > 0 && s.len <= 4 else { return 0, false; }
    var val: u32 = 0;
    for b in s {
        let h = core::hex_digit_to_val(b);
        guard h >= 0 else { return 0, false; }
        val = (val << 4) | (h as u32);
    }
    return val as u16, true;
}

fn is_private_ipv4_mapped_hex(suffix: const u8[:]) -> bool {
    let part1, part2, has_colon = suffix.split_once_byte(':');
    if !has_colon {
        let val_low, ok_low = parse_ssrf_hex_u16(suffix);
        guard ok_low else { return false; }
        let o2 = ((val_low >> 8) & 0xFF) as i32;
        let o3 = (val_low & 0xFF) as i32;
        return is_private_ipv4_4octets(0, 0, o2, o3);
    }
    guard part1.len > 0 && part2.len > 0 && !part2.contains_byte(':') else { return false; }

    let val1, ok1 = parse_ssrf_hex_u16(part1);
    let val2, ok2 = parse_ssrf_hex_u16(part2);
    guard ok1 && ok2 else { return false; }

    return is_private_ipv4_4octets(
        (val1 >> 8) & 0xFF,
        val1 & 0xFF,
        (val2 >> 8) & 0xFF,
        val2 & 0xFF,
    );
}

fn is_private_6to4_prefix(eff_ip: const u8[:]) -> bool {
    guard core::starts_with(eff_ip, "2002:") else { return false; }
    let rem = eff_ip[5..];
    let seg1, rem2, has_col = rem.split_once_byte(':');
    let p1 = if has_col { seg1 } else { rem };
    guard p1.len > 0 else { return true; }
    let hex_val1, ok1 = parse_ssrf_hex_u16(p1);
    guard ok1 else { return true; }
    let o0 = ((hex_val1 >> 8) & 0xFF) as i32;
    let o1 = (hex_val1 & 0xFF) as i32;
    if is_private_ipv4_octets(o0, o1) {
        return true;
    }
    guard has_col && rem2.len > 0 else { return false; }
    var o2: i32 = 0;
    if rem2[0] != ':' {
        let seg2, _, has_col2 = rem2.split_once_byte(':');
        let p2 = if has_col2 { seg2 } else { rem2 };
        guard p2.len > 0 else { return true; }
        let hex_val2, ok2 = parse_ssrf_hex_u16(p2);
        guard ok2 else { return true; }
        o2 = (hex_val2 >> 8) & 0xFF;
    }
    return (o0 == 192 && o1 == 0 && (o2 == 0 || o2 == 2)) ||
        (o0 == 198 && o1 == 51 && o2 == 100) ||
        (o0 == 203 && o1 == 0 && o2 == 113) ||
        (o0 == 192 && o1 == 88 && o2 == 99);
}

inline fn is_ipv6_local_or_multicast_prefix(eff_ip: const u8[:]) -> bool {
    if eff_ip == "::1" || eff_ip == "::" {
        return true;
    }
    if core::starts_with(eff_ip, "fc") || core::starts_with(eff_ip, "fd") ||
        core::starts_with(eff_ip, "fe8") || core::starts_with(eff_ip, "fe9") ||
        core::starts_with(eff_ip, "fea") || core::starts_with(eff_ip, "feb") ||
        core::starts_with(eff_ip, "fec") || core::starts_with(eff_ip, "fed") ||
        core::starts_with(eff_ip, "fee") || core::starts_with(eff_ip, "fef") ||
        core::starts_with(eff_ip, "ff") {
        return true;
    }
    // Benchmarking (RFC 5180), Documentation (RFC 3849), Teredo (RFC 4380), Discard-Only (RFC 6666)
    if core::starts_with(eff_ip, "2001:2::") || core::starts_with(eff_ip, "2001:2:0:") ||
        core::starts_with(eff_ip, "2001:db8:") || core::starts_with(eff_ip, "2001:0:") ||
        core::starts_with(eff_ip, "2001::") || core::starts_with(eff_ip, "100::") {
        return true;
    }
    // ORCHIDv2 (RFC 7343: 2001:20::/28)
    return core::starts_with(eff_ip, "2001:2") && eff_ip.len >= 8 &&
        eff_ip[7] == ':' && core::is_ascii_hexdigit(eff_ip[6]);
}

fn is_private_or_reserved_ipv6(eff_ip: const u8[:]) -> bool {
    if is_ipv6_local_or_multicast_prefix(eff_ip) {
        return true;
    }
    if core::starts_with(eff_ip, "::ffff:") || core::starts_with(eff_ip, "0:0:0:0:0:ffff:") {
        let raw_suffix = if core::starts_with(eff_ip, "::ffff:") { eff_ip[7..] } else { eff_ip[15..] };
        let suffix = if core::starts_with(raw_suffix, "0:") { raw_suffix[2..] } else { raw_suffix };
        return is_private_ipv4(suffix) || is_private_ipv4_mapped_hex(suffix);
    }
    if eff_ip.contains_byte('.') {
        let last_colon = eff_ip.last_index_of_byte(':');
        let next_col = core::add_sat_i64(last_colon, 1);
        if last_colon >= 0 && next_col < eff_ip.len && is_private_ipv4(eff_ip[next_col..]) {
            return true;
        }
    }
    if core::starts_with(eff_ip, "::") && !core::starts_with(eff_ip, "::ffff:") {
        let suffix = eff_ip[2..];
        return is_private_ipv4(suffix) || is_private_ipv4_mapped_hex(suffix);
    }
    if core::starts_with(eff_ip, "64:ff9b:1:") || eff_ip == "64:ff9b:1::" {
        return true;
    }
    if core::starts_with(eff_ip, "64:ff9b::") {
        let suffix = eff_ip[9..];
        if suffix.len == 0 { return true; }
        return is_private_ipv4(suffix) || is_private_ipv4_mapped_hex(suffix);
    }
    return is_private_6to4_prefix(eff_ip);
}

inline fn is_forbidden_ipv6(host: const u8[:]) -> bool {
    let h = if host.len >= 2 && host[0] == '[' && host[host.len - 1] == ']' {
        host[1..^1]
    } else {
        host
    };
    if h == "::1" || h == "::" || h == "0:0:0:0:0:0:0:1" || h == "0:0:0:0:0:0:0:0" { return true; }
    if core::starts_with(h, "::ffff:") || core::starts_with(h, "0:0:0:0:0:ffff:") { return true; }
    if core::starts_with(h, "fe8") || core::starts_with(h, "fe9") ||
        core::starts_with(h, "fea") || core::starts_with(h, "feb") {
        return true;
    }
    if core::starts_with(h, "fc") || core::starts_with(h, "fd") {
        return true;
    }
    return core::starts_with(h, "0::") || core::starts_with(h, "0:0:") || core::starts_with(h, "::");
}

inline fn is_all_digits_or_dots(host: const u8[:]) -> bool {
    guard host.len > 0 else { return false; }
    for b in host {
        if b != '.' && !core::is_ascii_digit(b) {
            return false;
        }
    }
    return true;
}

inline fn has_hex_prefix(host: const u8[:]) -> bool {
    guard host.len >= 2 else { return false; }
    let limit = core::sub_sat_i64(host.len, 1);
    for i in limit {
        let next_i = core::add_sat_i64(i, 1);
        if host[i] == '0' && (host[next_i] == 'x' || host[next_i] == 'X') { return true; }
    }
    return false;
}

inline fn is_invalid_ipv4_octet_state(octet_len: i64, first_zero: bool, octet_val: i64) -> bool {
    return octet_len == 0 || (octet_len > 1 && first_zero) || octet_len > 3 || octet_val > 255;
}

inline fn is_forbidden_internal_domain(host: const u8[:]) -> bool {
    let h = host.trim_end_byte('.');
    if h.eq_ascii_fold("localhost") || h.eq_ascii_fold("metadata.google.internal") ||
        h.eq_ascii_fold("instance-data") {
        return true;
    }
    if h.ends_with_fold(".localhost") || h.ends_with_fold(".local") { return true; }
    if h.ends_with_fold(".internal") || h.ends_with_fold(".lan") { return true; }
    return h.ends_with_fold(".corp");
}

inline fn is_cloud_metadata_or_reserved_ipv4_octets(o0: i32, o1: i32) -> bool {
    return o0 == 0 || (o0 == 169 && o1 == 254) || o0 >= 224;
}

fn is_cloud_metadata_ipv4_suffix(suffix: const u8[:]) -> bool {
    var octets: u8[4] = [0, 0, 0, 0];
    if parse_flexible_ipv4(suffix, octets) {
        return is_cloud_metadata_or_reserved_ipv4_octets(octets[0], octets[1]);
    }
    let p1, p2, has_colon = suffix.split_once_byte(':');
    if !has_colon {
        let _, ok_low = parse_ssrf_hex_u16(suffix);
        guard ok_low else { return false; }
        return is_cloud_metadata_or_reserved_ipv4_octets(0, 0);
    }
    guard p1.len > 0 && p2.len > 0 && !p2.contains_byte(':') else { return false; }
    let val1, ok1 = parse_ssrf_hex_u16(p1);
    let _, ok2 = parse_ssrf_hex_u16(p2);
    guard ok1 && ok2 else { return false; }
    return is_cloud_metadata_or_reserved_ipv4_octets((val1 >> 8) & 0xFF, val1 & 0xFF);
}

inline fn is_cloud_metadata_mapped_or_nat64_ipv6(eff_ip: const u8[:]) -> MetadataIpMatch {
    if core::starts_with(eff_ip, "::ffff:") || core::starts_with(eff_ip, "0:0:0:0:0:ffff:") {
        let raw_sfx = if core::starts_with(eff_ip, "::ffff:") { eff_ip[7..] } else { eff_ip[15..] };
        let suffix = if core::starts_with(raw_sfx, "0:") { raw_sfx[2..] } else { raw_sfx };
        return if is_cloud_metadata_ipv4_suffix(suffix) {
            MetadataIpMatch.Blocked
        } else {
            MetadataIpMatch.Allowed
        };
    }
    if core::starts_with(eff_ip, "64:ff9b:1:") || eff_ip == "64:ff9b:1::" {
        return MetadataIpMatch.Blocked;
    }
    if core::starts_with(eff_ip, "64:ff9b::") {
        let suffix = eff_ip[9..];
        let blocked = if suffix.len == 0 { true } else { is_cloud_metadata_ipv4_suffix(suffix) };
        return if blocked { MetadataIpMatch.Blocked } else { MetadataIpMatch.Allowed };
    }
    return MetadataIpMatch.NotMatched;
}

inline fn is_ipv6_link_local_prefix(eff_ip: const u8[:]) -> bool {
    return core::starts_with(eff_ip, "fe8") || core::starts_with(eff_ip, "fe9") ||
        core::starts_with(eff_ip, "fea") || core::starts_with(eff_ip, "feb");
}

fn is_cloud_metadata_or_reserved_ipv6(eff_ip: const u8[:]) -> bool {
    if eff_ip == "::" || core::starts_with(eff_ip, "ff") || eff_ip == "fd00:ec2::254" ||
        is_ipv6_link_local_prefix(eff_ip) {
        return true;
    }
    let map_match = is_cloud_metadata_mapped_or_nat64_ipv6(eff_ip);
    if map_match != MetadataIpMatch.NotMatched {
        return map_match == MetadataIpMatch.Blocked;
    }
    if core::starts_with(eff_ip, "::") && !core::starts_with(eff_ip, "::ffff:") {
        let suffix = eff_ip[2..];
        if suffix.len > 0 && is_cloud_metadata_ipv4_suffix(suffix) {
            return true;
        }
    }
    if eff_ip.contains_byte('.') {
        let last_colon = eff_ip.last_index_of_byte(':');
        let next_col = core::add_sat_i64(last_colon, 1);
        if last_colon >= 0 && next_col < eff_ip.len && is_cloud_metadata_ipv4_suffix(eff_ip[next_col..]) {
            return true;
        }
    }
    if core::starts_with(eff_ip, "2002:") {
        let rem = eff_ip[5..];
        let p1, _, has_col = rem.split_once_byte(':');
        if !has_col || p1.len == 0 { return true; }
        let hex_val1, ok1 = parse_ssrf_hex_u16(p1);
        guard ok1 else { return true; }
        return is_cloud_metadata_or_reserved_ipv4_octets((hex_val1 >> 8) & 0xFF, hex_val1 & 0xFF);
    }
    return false;
}

inline fn strip_ssrf_ip_brackets_and_zone(ip_str: const u8[:]) -> const u8[:] {
    var clean_ip = ip_str;
    if clean_ip.len > 2 && clean_ip[0] == '[' && clean_ip[clean_ip.len - 1] == ']' {
        clean_ip = clean_ip[1..^1];
    }
    let before_pct, _, has_pct = clean_ip.split_once_byte('%');
    if has_pct {
        clean_ip = before_pct;
    }
    return clean_ip;
}

inline fn normalize_ssrf_ip_chars(clean_ip: const u8[:], lower_buf: u8[..256]&) -> const u8[:], bool {
    guard clean_ip.len > 0 && clean_ip.len <= 256 else { return clean_ip[..0], false; }
    lower_buf.clear();
    clean_ip.to_lower_ascii(lower_buf);
    return lower_buf[..], true;
}
