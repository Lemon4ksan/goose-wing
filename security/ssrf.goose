// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// SSRF (Server-Side Request Forgery) protection policy and IP address validation.
namespace security;

import std;
import core;
import .policy_internal;

// ---- SSRF guard policy and 3-tier checks -----------------------------------

struct SsrfGuardPolicy {
    enabled:            bool      = true,
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

// Whether host is localhost or a subdomain of localhost (RFC 6761 Section 6.3).
fn is_localhost_name(host: const u8[:]) -> bool {
    if host.eq_ascii_fold("localhost") || host.eq_ascii_fold("localhost.") {
        return true;
    }
    return host.ends_with_fold(".localhost") || host.ends_with_fold(".localhost.");
}

// Whether an IP address is a private, loopback, link-local, or multicast address.
// Strips IPv6 zone identifiers before testing.
fn is_private_or_reserved_ip(ip_str: const u8[:]) -> bool {
    guard ip_str.len > 0 else { return false; }
    if is_localhost_name(ip_str) { return true; }
    if ip_str == "::1" || ip_str == "[::1]" || ip_str == "::" || ip_str == "[::]" {
        return true;
    }

    let clean_ip = security_internal::strip_ssrf_ip_brackets_and_zone(ip_str).trim_end_byte('.');
    guard clean_ip.len <= 256 else { return true; }

    var lower_buf: u8[..256] = [];
    let norm_ip, has_ip = security_internal::normalize_ssrf_ip_chars(clean_ip, lower_buf);
    guard has_ip else { return false; }

    if is_localhost_name(norm_ip) || norm_ip == "::1" || norm_ip == "::" {
        return true;
    }

    if norm_ip.contains_byte(':') {
        var comp_buf: u8[..64] = [];
        let ipv6_ok = core::parse_and_compress_ipv6(norm_ip, comp_buf);
        let eff_ip = if ipv6_ok { comp_buf[..] } else { norm_ip };
        return security_internal::is_private_or_reserved_ipv6(eff_ip);
    }

    return security_internal::is_private_ipv4(norm_ip);
}

inline fn is_non_canonical_ipv4(host: const u8[:]) -> bool {
    if security_internal::has_hex_prefix(host) { return true; }
    guard security_internal::is_all_digits_or_dots(host) else { return false; }

    var dot_cnt:    i64  = 0;
    var octet_len:  i64  = 0;
    var octet_val:  i64  = 0;
    var first_zero: bool = false;

    for b in host {
        if b == '.' {
            if security_internal::is_invalid_ipv4_octet_state(octet_len, first_zero, octet_val) {
                return true;
            }
            dot_cnt = core::add_sat_i64(dot_cnt, 1);
            octet_len = 0;
            octet_val = 0;
            first_zero = false;
        } else {
            if octet_len == 0 && b == '0' {
                first_zero = true;
            }
            let d = core::sub_sat_i64(b, '0');
            octet_val = core::add_sat_i64(core::mul_sat_i64(octet_val, 10), d);
            octet_len = core::add_sat_i64(octet_len, 1);
        }
    }
    if security_internal::is_invalid_ipv4_octet_state(octet_len, first_zero, octet_val) {
        return true;
    }
    return dot_cnt != 3;
}

inline fn is_cloud_metadata_domain(host: const u8[:]) -> bool {
    let h = host.trim_end_byte('.');
    return h.eq_ascii_fold("metadata.google.internal") || h.eq_ascii_fold("instance-data");
}

inline fn is_forbidden_internal_host(host: const u8[:]) -> bool {
    if security_internal::is_forbidden_internal_domain(host) { return true; }
    if is_private_or_reserved_ip(host) { return true; }
    if security_internal::is_forbidden_ipv6(host) { return true; }
    return is_non_canonical_ipv4(host);
}

fn is_dangerous_service_port(port_num: i32) -> bool {
    return port_num <= 0 ||      // Port 0 (reserved / loopback alias)
        port_num == 21 ||        // FTP
        port_num == 22 ||        // SSH
        port_num == 23 ||        // Telnet
        port_num == 25 ||        // SMTP
        port_num == 69 ||        // TFTP
        port_num == 110 ||       // POP3
        port_num == 143 ||       // IMAP
        port_num == 2375 ||      // Docker
        port_num == 2376 ||      // Docker TLS
        port_num == 2379 ||      // etcd client
        port_num == 2380 ||      // etcd peer
        port_num == 3306 ||      // MySQL
        port_num == 5432 ||      // PostgreSQL
        port_num == 6379 ||      // Redis
        port_num == 11211 ||     // Memcached
        port_num == 27017 ||     // MongoDB
        port_num == 28017;       // MongoDB Web Status
}

fn is_cloud_metadata_or_reserved_ip(ip_str: const u8[:]) -> bool {
    guard ip_str.len > 0 else { return false; }
    if is_cloud_metadata_domain(ip_str) {
        return true;
    }
    let clean_ip = security_internal::strip_ssrf_ip_brackets_and_zone(ip_str).trim_end_byte('.');
    var lower_buf: u8[..256] = [];
    let norm_ip, ok = security_internal::normalize_ssrf_ip_chars(clean_ip, lower_buf);
    guard ok else { return false; }

    var octets: u8[4] = [0, 0, 0, 0];
    if security_internal::parse_flexible_ipv4(norm_ip, octets) {
        return security_internal::is_cloud_metadata_or_reserved_ipv4_octets(octets[0], octets[1]);
    }
    if norm_ip.contains_byte(':') {
        var comp_buf: u8[..64] = [];
        let ipv6_ok = core::parse_and_compress_ipv6(norm_ip, comp_buf);
        let eff_ip = if ipv6_ok { comp_buf[..] } else { norm_ip };
        return security_internal::is_cloud_metadata_or_reserved_ipv6(eff_ip);
    }
    return false;
}

inline fn is_valid_resolved_ip_literal(ip_str: const u8[:]) -> bool {
    guard ip_str.len > 0 && ip_str.len <= 256 else { return false; }
    let clean_ip = security_internal::strip_ssrf_ip_brackets_and_zone(ip_str);
    guard clean_ip.len > 0 else { return false; }
    if clean_ip.contains_byte(':') {
        var comp_buf: u8[..64] = [];
        return core::parse_and_compress_ipv6(clean_ip, comp_buf);
    }
    var octets: u8[4] = [0, 0, 0, 0];
    return security_internal::parse_flexible_ipv4(clean_ip, octets);
}

// ---- Binary octet SSRF checks and proxy port policies --------------------

// Returns true if 4 network-order IPv4 octets fall in private, loopback, CGNAT, link-local, or reserved ranges.
fn is_reserved_ipv4_octets(octs: const u8[4]&) -> bool {
    let b0 = octs[0];
    let b1 = octs[1];
    let b2 = octs[2];
    if b0 == 0 || b0 == 10 || b0 == 127 { return true; }
    if b0 == 100 && (b1 & 0xC0) == 64 { return true; }
    if b0 == 169 && b1 == 254 { return true; }
    if b0 == 172 && b1 >= 16 && b1 <= 31 { return true; }
    if b0 == 192 && b1 == 168 { return true; }
    if b0 == 192 && b1 == 0 && (b2 == 0 || b2 == 2) { return true; }
    if b0 == 192 && b1 == 88 && b2 == 99 { return true; }
    if b0 == 198 && (b1 == 18 || b1 == 19) { return true; }
    if b0 == 198 && b1 == 51 && b2 == 100 { return true; }
    if b0 == 203 && b1 == 0 && b2 == 113 { return true; }
    return b0 >= 224;
}

// Returns true if 16 IPv6 octets use the IPv4-mapped prefix ::ffff:0:0/96.
fn is_ipv4_mapped_v6_octets(octs: const u8[16]&) -> bool {
    for i in 10 {
        if octs[i] != 0 { return false; }
    }
    return octs[10] == 0xFF && octs[11] == 0xFF;
}

inline fn octets_all_zero(slice: const u8[:]) -> bool {
    for b in slice {
        if b != 0 { return false; }
    }
    return true;
}

// Returns true if 16 network-order IPv6 octets fall in reserved, local, tunnel, or mapped private v4 ranges.
fn is_reserved_ipv6_octets(octs: const u8[16]&) -> bool {
    if is_ipv4_mapped_v6_octets(octs) {
        let mapped: u8[4] = [octs[12], octs[13], octs[14], octs[15]];
        return is_reserved_ipv4_octets(mapped);
    }
    // ::/96 (unspecified ::, loopback ::1, deprecated IPv4-compatible ::/96)
    if octets_all_zero(octs[..12]) { return true; }
    let b0 = octs[0];
    let b1 = octs[1];
    // fc00::/7 (ULA), fe80::/10 (Link-Local), fec0::/10 (Deprecated Site-Local), ff00::/8 (Multicast)
    if (b0 & 0xFE) == 0xFC || (b0 == 0xFE && b1 >= 0x80) || b0 == 0xFF { return true; }
    // 100::/64 (Discard-Only RFC 6666)
    if b0 == 0x01 && b1 == 0x00 && octets_all_zero(octs[2..8]) { return true; }
    // 64:ff9b::/96 and 64:ff9b:1::/48 (NAT64 RFC 6052 / RFC 8215)
    if b0 == 0x00 && b1 == 0x64 && octs[2] == 0xFF && octs[3] == 0x9B {
        if octs[4] == 0x00 && octs[5] == 0x01 { return true; }
        if octets_all_zero(octs[4..12]) {
            let nat_v4: u8[4] = [octs[12], octs[13], octs[14], octs[15]];
            return is_reserved_ipv4_octets(nat_v4);
        }
    }
    // 2001::/23 (IETF Protocol Assignments / Teredo RFC 6890), 2001:db8::/32 (Docs), 2002::/16 (6to4)
    if b0 == 0x20 && b1 == 0x01 && ((octs[2] & 0xFE) == 0x00 || (octs[2] == 0x0D && octs[3] == 0xB8)) {
        return true;
    }
    return b0 == 0x20 && b1 == 0x02;
}

// Returns true if a parsed binary IpAddr is reserved, private, loopback, link-local, or unknown.
fn is_reserved_ip_addr(ip: const core::IpAddr&) -> bool {
    if ip.family == core::IpFamily.V4 {
        let octs: u8[4] = [ip.bytes[0], ip.bytes[1], ip.bytes[2], ip.bytes[3]];
        return is_reserved_ipv4_octets(octs);
    }
    if ip.family == core::IpFamily.V6 {
        return is_reserved_ipv6_octets(ip.bytes);
    }
    return true;
}

// Returns true for egress TCP/UDP destination ports banned on open proxies (0, SMTP 25/465/587, SMB 445).
fn is_forbidden_proxy_port(port: u16) -> bool {
    return port == 0 || port == 25 || port == 445 || port == 465 || port == 587;
}

// Returns true for UDP amplification/reflection risk ports (QOTD 17, Chargen 19, RPC 111,
// NTP 123, NetBIOS 137, SNMP 161, CLDAP 389, SSDP 1900, mDNS 5353, Memcached 11211).
fn is_udp_amplification_port(port: u16) -> bool {
    return port == 17 ||
        port == 19 ||
        port == 111 ||
        port == 123 ||
        port == 137 ||
        port == 161 ||
        port == 389 ||
        port == 1900 ||
        port == 5353 ||
        port == 11211;
}
