// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// SSRF (Server-Side Request Forgery) protection policy and IP address validation.
namespace wing;

import std;
import client.redirect;

// ---- ssrf guard policy and 3-tier checks -----------------------------------

struct SsrfGuardPolicy {
    enabled:            bool      = false,
    https_only:         bool      = false,
    deny_local_network: bool      = true,
    allowed_ports:      i32[..16] = [],
    denied_ports:       i32[..16] = [],
}

fn new_ssrf_guard_policy() -> SsrfGuardPolicy {
    return SsrfGuardPolicy {
        enabled:            true,
        https_only:         false,
        deny_local_network: true,
        allowed_ports:      [],
        denied_ports:       [],
    };
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
    if octet0 == 192 && octet1 == 0 && octet2 == 0 { return true; }      // 192.0.0.0/24 (RFC 6890 §2.1)
    if octet0 == 192 && octet1 == 0 && octet2 == 2 { return true; }      // 192.0.2.0/24 TEST-NET-1 (RFC 5737)
    if octet0 == 192 && octet1 == 88 && octet2 == 99 { return true; }    // 192.88.99.0/24 6to4 Relay Anycast (RFC 7526)
    if octet0 == 198 && octet1 == 51 && octet2 == 100 { return true; }   // 198.51.100.0/24 TEST-NET-2 (RFC 5737)
    if octet0 == 203 && octet1 == 0 && octet2 == 113 { return true; }    // 203.0.113.0/24 TEST-NET-3 (RFC 5737)

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
    if part.len >= 2 && part[0] == '0' && (part[1] == 'x' || part[1] == 'X') {
        base = 16;
        start_idx = 2;
        guard part.len > 2 else { return 0, false; }
    } else if part.len >= 2 && part[0] == '0' {
        base = 8;
        start_idx = 1;
    }

    var val: u64 = 0;
    for i in start_idx..part.len {
        let b = part[i];
        let hex = core::hex_digit_to_val(b);
        guard hex >= 0 else { return 0, false; }
        let digit = hex as u64;
        if digit >= base { return 0, false; }
        guard val <= 0xFFFFFFFF / base else { return 0, false; }
        val = val * base + digit;
        if val > 0xFFFFFFFF { return 0, false; }
    }
    return val, true;
}

// Parses IPv4 addresses in standard dotted-decimal, octal, hex, dword, or
// shorthand notation into 4 canonical octets.
//
// Example:
//   clean_ip = "127.0.0.1"
//   returns: ok = true, octets = [127, 0, 0, 1]
fn parse_flexible_ipv4(clean_ip: const u8[:], octets: u8[4]&) -> bool {
    guard clean_ip.len > 0 else { return false; }
    var parts: u8[..32][..4] = [];
    var cur:   u8[..32]      = [];
    for b in clean_ip {
        if b == '.' {
            guard parts.len < 4 && cur.len > 0 else { return false; }
            parts.push(copy(cur));
            cur.clear();
        } else {
            if cur.len < 32 { cur.push(b); } else { return false; }
        }
    }
    guard parts.len < 4 && cur.len > 0 else { return false; }
    parts.push(copy(cur));

    let n = parts.len;
    guard n >= 1 && n <= 4 else { return false; }

    var nums: u64[4] = [0, 0, 0, 0];
    for i in n {
        let val, ok = parse_ipv4_part(parts[i][..]);
        guard ok else { return false; }
        nums[i] = val;
    }

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
    }

    octets[0] = ((ip_u32 >> 24) & 0xFF) as u8;
    octets[1] = ((ip_u32 >> 16) & 0xFF) as u8;
    octets[2] = ((ip_u32 >> 8) & 0xFF) as u8;
    octets[3] = (ip_u32 & 0xFF) as u8;
    return true;
}

fn is_private_ipv4(clean_ip: const u8[:]) -> bool {
    var octets: u8[4] = [0, 0, 0, 0];
    guard parse_flexible_ipv4(clean_ip, octets) else { return false; }
    return is_private_ipv4_4octets(octets[0], octets[1], octets[2], octets[3]);
}

fn is_private_ipv4_mapped_hex(suffix: const u8[:]) -> bool {
    let colon_idx = core::index_of_byte(suffix, ':');
    guard colon_idx > 0 && colon_idx + 1 < suffix.len else { return false; }
    if core::last_index_of_byte(suffix, ':') != colon_idx { return false; }

    let part1 = suffix[..colon_idx];
    let part2 = suffix[colon_idx + 1..];
    guard part1.len >= 1 && part1.len <= 4 && part2.len >= 1 && part2.len <= 4 else { return false; }

    let val1 = parse_hex_u16(part1);
    let val2 = parse_hex_u16(part2);

    let octet0 = (val1 >> 8) & 0xFF;
    let octet1 = val1 & 0xFF;
    let octet2 = (val2 >> 8) & 0xFF;
    let octet3 = val2 & 0xFF;
    return is_private_ipv4_4octets(octet0, octet1, octet2, octet3);
}

// Whether host is localhost or a subdomain of localhost (RFC 6761 Section 6.3).
fn is_localhost_name(host: const u8[:]) -> bool {
    if eq_ascii_fold(host, "localhost") || eq_ascii_fold(host, "localhost.") {
        return true;
    }
    if ends_with_fold(host, ".localhost") || ends_with_fold(host, ".localhost.") {
        return true;
    }
    return false;
}

// Parses a hex string up to 4 characters into a 16-bit integer.
//
// Example:
//   s = "1f90"
//   returns: 8080
fn parse_hex_u16(s: const u8[:]) -> i32 {
    guard s.len > 0 && s.len <= 4 else { return -1; }
    var val: i32 = 0;
    for b in s {
        let h = if b >= '0' && b <= '9' { (b - '0') as i32 }
                else if b >= 'a' && b <= 'f' { (b - 'a' + 10) as i32 }
                else if b >= 'A' && b <= 'F' { (b - 'A' + 10) as i32 }
                else { return -1; };
        val = (val << 4) | h;
    }
    return val;
}

fn is_private_6to4_prefix(eff_ip: const u8[:]) -> bool {
    guard starts_with(eff_ip, "2002:") else { return false; }
    let rem = eff_ip[5..];
    let colon_idx = core::index_of_byte(rem, ':');
    let p1 = if colon_idx > 0 { rem[..colon_idx] } else { rem };
    let hex_val1 = parse_hex_u16(p1);
    guard hex_val1 >= 0 else { return true; }
    let o0 = (hex_val1 >> 8) & 0xFF;
    let o1 = hex_val1 & 0xFF;
    if is_private_ipv4_octets(o0, o1) {
        return true;
    }
    guard colon_idx > 0 && colon_idx + 1 < rem.len else { return false; }
    let rem2 = rem[(colon_idx + 1)..];
    let colon_idx2 = core::index_of_byte(rem2, ':');
    let p2 = if colon_idx2 > 0 { rem2[..colon_idx2] } else { rem2 };
    let hex_val2 = parse_hex_u16(p2);
    guard hex_val2 >= 0 else { return true; }
    let o2 = (hex_val2 >> 8) & 0xFF;
    return (o0 == 192 && o1 == 0 && (o2 == 0 || o2 == 2)) ||
           (o0 == 198 && o1 == 51 && o2 == 100) ||
           (o0 == 203 && o1 == 0 && o2 == 113) ||
           (o0 == 192 && o1 == 88 && o2 == 99);
}

fn is_private_or_reserved_ipv6(eff_ip: const u8[:]) -> bool {
    if eff_ip == "::1" || eff_ip == "::" {
        return true;
    }

    if starts_with(eff_ip, "fc") || starts_with(eff_ip, "fd") || // Unique Local fc00::/7
       starts_with(eff_ip, "fe8") || starts_with(eff_ip, "fe9") || // Link-local fe80::/10
       starts_with(eff_ip, "fea") || starts_with(eff_ip, "feb") ||
       starts_with(eff_ip, "fec") || starts_with(eff_ip, "fed") || // Site-local fec0::/10
       starts_with(eff_ip, "fee") || starts_with(eff_ip, "fef") ||
       starts_with(eff_ip, "ff") {                                 // Multicast ff00::/8
        return true;
    }

    // IPv4-mapped IPv6 (RFC 4291 ::ffff:x.x.x.x or ::ffff:hhhh:hhhh, CVE-2024-24790)
    // and SIIT IPv4-translated IPv6 (RFC 2765 / RFC 6052 / RFC 7915 ::ffff:0:x.x.x.x or ::ffff:0:hhhh:hhhh)
    if starts_with(eff_ip, "::ffff:") || starts_with(eff_ip, "0:0:0:0:0:ffff:") {
        let raw_suffix = if starts_with(eff_ip, "::ffff:") { eff_ip[7..] } else { eff_ip[15..] };
        let suffix = if starts_with(raw_suffix, "0:") { raw_suffix[2..] } else { raw_suffix };
        return is_private_ipv4(suffix) || is_private_ipv4_mapped_hex(suffix);
    }

    // Trailing dotted-quad IPv4 in any IPv6 scope (RFC 4291 / CVE-2024-24790)
    if core::contains_byte(eff_ip, '.') {
        let last_colon = core::last_index_of_byte(eff_ip, ':');
        if last_colon >= 0 && last_colon + 1 < eff_ip.len {
            let last_part = eff_ip[last_colon + 1..];
            if is_private_ipv4(last_part) {
                return true;
            }
        }
    }

    // IPv4-compatible IPv6 (::x.x.x.x or ::hhhh:hhhh)
    if starts_with(eff_ip, "::") && !starts_with(eff_ip, "::ffff:") {
        let suffix = eff_ip[2..];
        return is_private_ipv4(suffix) || is_private_ipv4_mapped_hex(suffix);
    }

    // NAT64 well-known prefix 64:ff9b::/96 and local prefix 64:ff9b:1::/48 (RFC 6052 & RFC 8215)
    if starts_with(eff_ip, "64:ff9b::") || starts_with(eff_ip, "64:ff9b:1::") {
        let suffix = if starts_with(eff_ip, "64:ff9b::") { eff_ip[9..] } else { eff_ip[11..] };
        if suffix.len == 0 { return true; } // maps to 0.0.0.0
        return is_private_ipv4(suffix) || is_private_ipv4_mapped_hex(suffix);
    }

    // 6to4 prefix 2002::/16 (RFC 3056)
    if is_private_6to4_prefix(eff_ip) {
        return true;
    }

    // Benchmarking (RFC 5180), ORCHIDv2 (RFC 7343), Documentation (RFC 3849),
    // Teredo (RFC 4380), Discard-Only (RFC 6666)
    if starts_with(eff_ip, "2001:2:") || starts_with(eff_ip, "2001:20:") ||
       starts_with(eff_ip, "2001:db8:") || starts_with(eff_ip, "2001:0:") ||
       starts_with(eff_ip, "2001::") || starts_with(eff_ip, "100::") {
        return true;
    }

    return false;
}

// Whether an IP address is a private, loopback, link-local, or multicast address.
// Strips IPv6 zone identifiers before testing.
fn is_private_or_reserved_ip(ip_str: const u8[:]) -> bool {
    guard ip_str.len > 0 else { return false; }

    if is_localhost_name(ip_str) {
        return true;
    }

    if ip_str == "::1" || ip_str == "[::1]" || ip_str == "::" || ip_str == "[::]" {
        return true;
    }
    var clean_ip = if ip_str.len > 2 && ip_str[0] == '[' && ip_str[ip_str.len - 1] == ']' {
        ip_str[1..ip_str.len - 1]
    } else {
        ip_str
    };

    let pct_idx = core::index_of_byte(clean_ip, '%');
    if pct_idx >= 0 {
        clean_ip = clean_ip[..pct_idx];
    }

    clean_ip = core::trim_end_byte(clean_ip, '.');

    var lower_buf: u8[..256] = [];
    if clean_ip.len <= 256 {
        lower_buf.append(clean_ip);
        to_lower(lower_buf[..]);
    }
    let norm_ip = if lower_buf.len > 0 { lower_buf[..] } else { clean_ip };

    if is_localhost_name(norm_ip) || norm_ip == "::1" || norm_ip == "::" {
        return true;
    }

    if core::contains_byte(norm_ip, ':') {
        var comp_buf: u8[..64] = [];
        let ipv6_ok = core::parse_and_compress_ipv6(norm_ip, comp_buf);
        let eff_ip = if ipv6_ok { comp_buf[..] } else { norm_ip };
        return is_private_or_reserved_ipv6(eff_ip);
    }

    return is_private_ipv4(norm_ip);
}

fn is_dangerous_service_port(port_num: i32) -> bool {
    return port_num <= 0 ||      // Port 0 (reserved / loopback alias)
           port_num == 21 ||     // FTP
           port_num == 22 ||     // SSH
           port_num == 23 ||     // Telnet
           port_num == 25 ||     // SMTP
           port_num == 69 ||     // TFTP
           port_num == 110 ||    // POP3
           port_num == 143 ||    // IMAP
           port_num == 2375 ||   // Docker
           port_num == 2376 ||   // Docker TLS
           port_num == 2379 ||   // etcd client
           port_num == 2380 ||   // etcd peer
           port_num == 3306 ||   // MySQL
           port_num == 5432 ||   // PostgreSQL
           port_num == 6379 ||   // Redis
           port_num == 11211 ||  // Memcached
           port_num == 27017 ||  // MongoDB
           port_num == 28017;    // MongoDB Web Status
}

fn validate_url_against_ssrf(url_val: const core::Url&, policy: const SsrfGuardPolicy&) -> RedirectError {
    guard policy.enabled else { return RedirectError.None; }

    if policy.https_only && scheme(url_val) != "https" {
        return RedirectError.SchemeDowngradeBlocked;
    }

    let raw_port = url_val.port;
    let port_val = if raw_port == 0 { 0 } else { effective_port(url_val) };
    if policy.denied_ports.contains(port_val) {
        return RedirectError.SsrfBlockedUrl;
    }
    if policy.allowed_ports.len > 0 {
        if !policy.allowed_ports.contains(port_val) {
            return RedirectError.SsrfBlockedUrl;
        }
    } else if policy.deny_local_network && is_dangerous_service_port(port_val) {
        return RedirectError.SsrfBlockedUrl;
    }

    let host_str = hostname(url_val);
    if policy.deny_local_network {
        if is_private_or_reserved_ip(host_str) {
            return RedirectError.SsrfBlockedIp;
        }
    }

    return RedirectError.None;
}

fn validate_resolved_ips_against_ssrf(ips: const u8[:][:], policy: const SsrfGuardPolicy&) -> RedirectError {
    guard policy.enabled && policy.deny_local_network else { return RedirectError.None; }
    for ip in ips {
        if is_private_or_reserved_ip(ip) {
            return RedirectError.SsrfBlockedIp;
        }
    }
    return RedirectError.None;
}
