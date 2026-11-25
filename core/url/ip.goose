// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// IPv4 and IPv6 literal parsing, RFC 5952 zero-run canonical compression,
// RFC 6874 ZoneID validation, and binary IP formatting.
namespace core;

import std;

fn is_valid_ipv4_format(host: const u8[:]) -> bool {
    var dot_count:    i64 = 0;
    var octet_val:    i64 = 0;
    var octet_digits: i64 = 0;

    for char_byte in host {
        if char_byte == '.' {
            guard octet_digits > 0 && octet_val <= 255 && dot_count < 3 else { return false; }
            dot_count += 1;
            octet_val = 0;
            octet_digits = 0;
        } else if char_byte >= '0' && char_byte <= '9' {
            octet_digits += 1;
            guard octet_digits <= 3 else { return false; }
            octet_val = octet_val * 10 + (char_byte - '0');
        } else {
            return false;
        }
    }

    return dot_count == 3 && octet_digits > 0 && octet_val <= 255;
}

fn is_ip_address_literal(host: const u8[:]) -> bool {
    guard host.len > 0 else { return false; }
    if contains_byte(host, ':') { return true; }
    return is_valid_ipv4_format(host);
}

// Strips IPv6 ZoneID (%25...) from host strings (RFC 6874 Section 4).
//
// Example:
//   host_str = "[fe80::1%25eth0]"
//   returns: out = "[fe80::1]"
fn strip_ipv6_zone_id<B>(host_str: const u8[:], out: B&) {
    out.clear();
    guard host_str.len > 0 && host_str[0] == '[' else {
        out.append(host_str);
        return;
    }
    let pct_idx = find(host_str, "%25");
    guard pct_idx >= 0 else {
        out.append(host_str);
        return;
    }
    let close_b = index_of_byte(host_str[pct_idx..], ']');
    guard close_b >= 0 else {
        out.append(host_str);
        return;
    }
    let resume_idx = add_sat_i64(pct_idx, close_b);
    out.append(host_str[..pct_idx]);
    out.append(host_str[resume_idx..]);
}

// RFC 6874 Section 2 & RFC 4007 Section 5: A ZoneID MUST NOT be attached to an address with global scope.
// Permitted scoped IPv6 addresses include link-local unicast (fe80::/10), site-local unicast (fec0::/10),
// and non-global scoped multicast addresses (ff01..ff05, ff08, etc.).
fn is_scoped_ipv6_for_zone_id(comp_ipv6: const u8[:]) -> bool {
    guard comp_ipv6.len >= 5 && comp_ipv6[4] == ':' else { return false; }
    if starts_with(comp_ipv6, "fe8") || starts_with(comp_ipv6, "fe9") ||
       starts_with(comp_ipv6, "fea") || starts_with(comp_ipv6, "feb") {
        return true;
    }
    if starts_with(comp_ipv6, "fec") || starts_with(comp_ipv6, "fed") ||
       starts_with(comp_ipv6, "fee") || starts_with(comp_ipv6, "fef") {
        return true;
    }
    if comp_ipv6[0] == 'f' && comp_ipv6[1] == 'f' {
        let scope_ch = comp_ipv6[3];
        let is_scoped_multicast = scope_ch == '1' || scope_ch == '2' || scope_ch == '3' ||
            scope_ch == '4' || scope_ch == '5' || scope_ch == '8';
        if is_scoped_multicast {
            return true;
        }
    }
    return false;
}

fn validate_zone_id(zone_id: const u8[:]) -> bool {
    let total = zone_id.len;
    guard total > 0 && total <= 64 else { return false; }
    var idx: i64 = 0;
    while idx < total {
        let b = zone_id[idx];
        if is_uri_unreserved(b) {
            idx += 1;
        } else if b == '%' {
            guard idx + 2 < total else { return false; }
            let hi = hex_digit_to_val(zone_id[idx + 1]);
            let lo = hex_digit_to_val(zone_id[idx + 2]);
            guard hi >= 2 && lo >= 0 && !(hi == 7 && lo == 15) else { return false; }
            idx += 3;
        } else {
            return false;
        }
    }
    return true;
}

// Parses a single decimal IPv4 octet (0..255) rejecting leading zeros (RFC 3986 §3.2.2).
//
// Example:
//   octet_str = "192"
//   returns: 192, ok = true
fn parse_ipv4_decimal_octet(octet_str: const u8[:]) -> u16, bool {
    guard octet_str.len > 0 && octet_str.len <= 3 else { return 0, false; }
    guard octet_str.len == 1 || octet_str[0] != '0' else { return 0, false; }
    var val: i64 = 0;
    for char_byte in octet_str {
        guard char_byte >= '0' && char_byte <= '9' else { return 0, false; }
        val = val * 10 + (char_byte - '0');
    }
    guard val <= 255 else { return 0, false; }
    return val as u16, true;
}

// Parses a dotted-quad IPv4 suffix e.g. ::ffff:192.0.2.1 into 2 x 16-bit pieces.
//
// Example:
//   rem_slice = "192.0.2.1", pieces = [0..], piece_count = 6
//   returns: true, piece_count = 8
fn parse_ipv4_mapped_pieces(
    rem_slice:   const u8[:],
    pieces:      u16[8]&,
    piece_count: i64&,
) -> bool {
    guard piece_count >= 0 && piece_count <= 6 else { return false; }
    var octets: u16[4] = [0; 4];
    var rest = rem_slice;
    for idx in 3 {
        let dot_pos = index_of_byte(rest, '.');
        guard dot_pos > 0 else { return false; }
        let oct, ok = parse_ipv4_decimal_octet(rest[..dot_pos]);
        guard ok else { return false; }
        octets[idx] = oct;
        rest = rest[dot_pos + 1..];
    }
    let last_oct, ok_last = parse_ipv4_decimal_octet(rest);
    guard ok_last else { return false; }
    octets[3] = last_oct;

    pieces[piece_count] = (octets[0] << 8) | octets[1];
    pieces[piece_count + 1] = (octets[2] << 8) | octets[3];
    piece_count += 2;
    return true;
}

// Finds the longest continuous run of zero pieces for RFC 5952 canonical compression.
fn find_longest_zero_run(pieces: const u16[8]&) -> i64, i64 {
    var best_start: i64 = -1;
    var best_len:   i64 = 0;
    var cur_start:  i64 = -1;
    var cur_len:    i64 = 0;

    for piece_idx in 8 {
        if pieces[piece_idx] == 0 {
            if cur_start < 0 { cur_start = piece_idx; }
            cur_len += 1;
        } else {
            if cur_len > best_len {
                best_start = cur_start;
                best_len = cur_len;
            }
            cur_start = -1;
            cur_len = 0;
        }
    }
    if cur_len > best_len {
        best_start = cur_start;
        best_len = cur_len;
    }
    if best_len < 2 { return -1, 0; }
    return best_start, best_len;
}

// Parses a 1-4 char hex piece of an IPv6 address.
//
// Example:
//   piece_str = "1a2b", out_val = 0
//   returns: true, out_val = 0x1a2b
fn parse_ipv6_hex_piece(piece_str: const u8[:], out_val: u16&) -> bool {
    guard piece_str.len > 0 && piece_str.len <= 4 else { return false; }
    var piece_val: u32 = 0;
    for char_byte in piece_str {
        let hex_digit = hex_digit_to_val(char_byte);
        guard hex_digit >= 0 else { return false; }
        piece_val = (piece_val << 4) | (hex_digit as u32);
    }
    out_val = piece_val as u16;
    return true;
}

fn expand_ipv6_double_colon(pieces: u16[8]&, piece_count: i64&, double_colon_pos: i64) -> bool {
    guard piece_count >= 0 && piece_count < 8 && double_colon_pos >= 0 && double_colon_pos <= piece_count else {
        return false;
    }
    let missing = 8 - piece_count;
    let tail_count = piece_count - double_colon_pos;
    for rev_idx in tail_count {
        let src = piece_count - 1 - rev_idx;
        pieces[src + missing] = pieces[src];
    }
    for zero_idx in missing {
        pieces[double_colon_pos + zero_idx] = 0;
    }
    piece_count = 8;
    return true;
}

fn format_compressed_ipv6<B>(pieces: const u16[8]&, out: B&) {
    let best_start, best_len = find_longest_zero_run(pieces);
    let best_end = best_start + best_len;
    var format_idx: i64 = 0;
    while format_idx < 8 {
        if format_idx == best_start {
            out.append("::");
            format_idx += best_len;
            continue;
        }
        let is_skip_zero_tail = format_idx == best_end && best_start == 0;
        if format_idx > 0 && !is_skip_zero_tail && out.len > 0 && out[out.len - 1] != ':' {
            out.push(':');
        }
        format_u64_hex(pieces[format_idx] as u64, out, false);
        format_idx += 1;
    }
}

fn advance_after_ipv6_colon(
    rem_slice:        const u8[:],
    colon_idx:        i64,
    piece_count:      i64,
    double_colon_pos: i64&,
) -> const u8[:], bool {
    guard colon_idx >= 0 else { return rem_slice[rem_slice.len..], true; }
    let next_idx = colon_idx + 1;
    guard next_idx < rem_slice.len else { return "", false; }
    if rem_slice[next_idx] == ':' {
        guard double_colon_pos < 0 else { return "", false; }
        double_colon_pos = piece_count;
        return rem_slice[colon_idx + 2..], true;
    }
    return rem_slice[next_idx..], true;
}

fn consume_leading_ipv6_double_colon(
    raw_ipv6:         const u8[:],
    double_colon_pos: i64&,
) -> const u8[:], bool {
    guard raw_ipv6.len > 0 && raw_ipv6[0] == ':' else { return raw_ipv6, true; }
    guard starts_with(raw_ipv6, "::") else { return "", false; }
    double_colon_pos = 0;
    return raw_ipv6[2..], true;
}

// Parses raw IPv6 text (with optional `::` and IPv4-mapped tail) into 8 host-order 16-bit groups.
//
fn step_ipv6_piece(
    rem_slice:        const u8[:],
    pieces:           u16[8]&,
    piece_count:      i64&,
    double_colon_pos: i64&,
) -> const u8[:], bool {
    let colon_idx = index_of_byte(rem_slice, ':');
    let piece_str = if colon_idx >= 0 { rem_slice[..colon_idx] } else { rem_slice };
    if piece_str.len == 0 {
        guard double_colon_pos < 0 else { return "", false; }
        double_colon_pos = piece_count;
        return rem_slice[1..], true;
    }
    if contains_byte(piece_str, '.') {
        guard parse_ipv4_mapped_pieces(rem_slice, pieces, piece_count) else { return "", false; }
        return "", true;
    }
    var piece_val: u16 = 0;
    guard parse_ipv6_hex_piece(piece_str, piece_val) else { return "", false; }
    pieces[piece_count] = piece_val;
    piece_count += 1;
    return advance_after_ipv6_colon(rem_slice, colon_idx, piece_count, double_colon_pos);
}

// Parses IPv6 text into 8 host-order 16-bit hextets (RFC 4291 / RFC 5952).
//
// Example:
//   raw_ipv6 = "2001:db8::1", pieces = [0; 8]
//   returns: true, pieces = [0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]
fn parse_ipv6_pieces(raw_ipv6: const u8[:], pieces: u16[8]&) -> bool {
    var piece_count:      i64 = 0;
    var double_colon_pos: i64 = -1;
    let init_rem, ok_init = consume_leading_ipv6_double_colon(raw_ipv6, double_colon_pos);
    guard ok_init else { return false; }
    var rem_slice = init_rem;

    while rem_slice.len > 0 && piece_count < 8 {
        let next_rem, ok_step = step_ipv6_piece(rem_slice, pieces, piece_count, double_colon_pos);
        guard ok_step else { return false; }
        rem_slice = next_rem;
    }
    guard rem_slice.len == 0 else { return false; }
    if double_colon_pos >= 0 {
        guard expand_ipv6_double_colon(pieces, piece_count, double_colon_pos) else { return false; }
    }
    return piece_count == 8;
}

// RFC 5952 / WHATWG IPv6 Parser and Zero-Run Canonical Compression.
//
// Example:
//   raw_ipv6 = "2001:0db8:0000:0000:0000:ff00:0042:8329"
//   out = "2001:db8::ff00:42:8329", returns: true
fn parse_and_compress_ipv6<B>(raw_ipv6: const u8[:], out: B&) -> bool {
    out.clear();
    var pieces: u16[8] = [0; 8];
    guard parse_ipv6_pieces(raw_ipv6, pieces) else { return false; }
    // RFC 5952 Section 4: A Recommendation for IPv6 Text Representation - Canonical IPv6 text is at most 39 bytes.
    var formatted: u8[..40] = [];
    format_compressed_ipv6(pieces, formatted);
    return out.try_append(formatted[..]);
}

// Parses a text IPv6 literal into 16 big-endian octets (RFC 4291 Section 2.2).
//
// Example:
//   raw_ipv6 = "2001:db8::1"
//   returns: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], ok = true
fn parse_ipv6_octets(raw_ipv6: const u8[:]) -> u8[16], bool {
    var out: u8[16] = [0; 16];
    guard raw_ipv6.len >= 2 && contains_byte(raw_ipv6, ':') && !contains_byte(raw_ipv6, '%') else {
        return out, false;
    }
    var pieces: u16[8] = [0; 8];
    guard parse_ipv6_pieces(raw_ipv6, pieces) else { return out, false; }
    for g in 8 {
        out[g * 2] = ((pieces[g] >> 8) & 0xFF) as u8;
        out[g * 2 + 1] = (pieces[g] & 0xFF) as u8;
    }
    return out, true;
}

const IPV4_OCTET_SHIFTS: u32[4] = [24, 16, 8, 0];

fn format_ipv4_u32(ip4: u32, out: u8[..64]&) {
    out.clear();
    for i in 4 {
        if i > 0 { out.push('.'); }
        format_u64_dec((ip4 >> IPV4_OCTET_SHIFTS[i]) & 0xFF, out);
    }
}

fn format_ipv6_bytes(ip6: const u8[16]&, out: u8[..64]&) {
    out.clear();
    for g in 8 {
        if g > 0 { out.push(':'); }
        let base = mul_sat_i64(g, 2);
        format_u8_hex(ip6[base], out, false);
        format_u8_hex(ip6[add_sat_i64(base, 1)], out, false);
    }
}

// ---- Unified IPv4/IPv6/CIDR model and matchers ------------------------------

enum IpFamily {
    Unknown,
    V4,
    V6,
}

struct IpAddr {
    family: IpFamily = IpFamily.Unknown,
    bytes:  u8[16]   = [0; 16],
}

struct IpCidr {
    addr:       IpAddr = IpAddr { .. },
    prefix_len: u8     = 0,
}

// Parses a canonical dotted-quad IPv4 literal into 4 network-order octets.
// Rejects leading zeros, whitespace, ports, and out-of-range octets.
//
// Example:
//   raw = "185.10.40.7"
//   returns: [185, 10, 40, 7], true
fn parse_ipv4_octets(raw: const u8[:]) -> u8[4], bool {
    var out: u8[4] = [0; 4];
    guard raw.len >= 7 && raw.len <= 15 else { return out, false; }
    var rest = raw;
    for i in 4 {
        let part, rem, has_dot = split_once_byte(rest, '.');
        if i < 3 {
            guard has_dot else { return out, false; }
        } else {
            guard !has_dot else { return out, false; }
        }
        let val, ok_v = parse_ipv4_decimal_octet(part);
        guard ok_v else { return out, false; }
        out[i] = val as u8;
        rest = rem;
    }
    return out, true;
}

// Parses a canonical dotted-quad IPv4 literal into a big-endian u32.
//
// Example:
//   raw = "127.0.0.1"
//   returns: 0x7F000001, true
fn parse_ipv4_u32(raw: const u8[:]) -> u32, bool {
    let octs, ok = parse_ipv4_octets(raw);
    guard ok else { return 0, false; }
    return read_be_u32(octs[..], 0), true;
}

// Parses a dotted-quad IPv4 literal into an IpAddr value.
//
// Example:
//   raw = "185.10.40.7"
//   returns: IpAddr { family: IpFamily.V4, .. }, true
fn parse_ipv4_addr(raw: const u8[:]) -> IpAddr, bool {
    var out = IpAddr { .. };
    let octs, ok = parse_ipv4_octets(raw);
    guard ok else { return out, false; }
    out.family = IpFamily.V4;
    for i in 4 {
        out.bytes[i] = octs[i];
    }
    return out, true;
}

// Parses an IPv6 literal (without brackets or zone ID) into an IpAddr value.
//
// Example:
//   raw = "2001:db8::1"
//   returns: IpAddr { family: IpFamily.V6, .. }, true
fn parse_ipv6_addr(raw: const u8[:]) -> IpAddr, bool {
    let octs, ok = parse_ipv6_octets(raw);
    guard ok else { return IpAddr { .. }, false; }
    return IpAddr { family: IpFamily.V6, bytes: octs }, true;
}

// Parses a literal IPv4 or IPv6 address (strips optional brackets on IPv6).
//
// Example:
//   raw = "[2001:db8::1]"
//   returns: IpAddr { family: IpFamily.V6, .. }, true
fn parse_ip_addr(raw: const u8[:]) -> IpAddr, bool {
    guard raw.len > 0 else { return IpAddr { .. }, false; }
    if contains_byte(raw, ':') {
        var clean = raw;
        if clean.len >= 2 && clean[0] == '[' && clean[sub_sat_i64(clean.len, 1)] == ']' {
            clean = clean[1..^1];
        }
        return parse_ipv6_addr(clean);
    }
    return parse_ipv4_addr(raw);
}

// Parses an IPv4 or IPv6 CIDR ("10.0.0.0/8", "2001:db8::/64").
//
// Example:
//   raw = "185.10.40.0/24"
//   returns: IpCidr { addr: 185.10.40.0, prefix_len: 24 }, true
fn parse_cidr(raw: const u8[:]) -> IpCidr, bool {
    let ip_part, len_part, has_slash = split_once_byte(raw, '/');
    guard has_slash && ip_part.len > 0 && len_part.len > 0 else { return IpCidr { .. }, false; }
    let addr, ok_ip = parse_ip_addr(ip_part);
    guard ok_ip else { return IpCidr { .. }, false; }
    let pfx, ok_pfx = parse_u32_dec(len_part);
    let max_pfx: u32 = if addr.family == IpFamily.V4 { 32 } else { 128 };
    guard ok_pfx && pfx <= max_pfx else { return IpCidr { .. }, false; }
    return IpCidr { addr: addr, prefix_len: pfx as u8 }, true;
}

fn ip_addr_equals(a: const IpAddr&, b: const IpAddr&) -> bool {
    guard a.family == b.family && a.family != IpFamily.Unknown else { return false; }
    let byte_cnt = if a.family == IpFamily.V4 { 4 } else { 16 };
    for i in byte_cnt {
        if a.bytes[i] != b.bytes[i] { return false; }
    }
    return true;
}

const CIDR_REM_MASKS: u8[8] = [0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE];

fn cidr_contains_ip(cidr: const IpCidr&, ip: const IpAddr&) -> bool {
    guard cidr.addr.family == ip.family && ip.family != IpFamily.Unknown else { return false; }
    let max_bits: i64 = if ip.family == IpFamily.V4 { 32 } else { 128 };
    let pfx = cidr.prefix_len as i64;
    guard pfx >= 0 && pfx <= max_bits else { return false; }
    let full_bytes = ((pfx as u64) >> 3) as i64;
    guard full_bytes >= 0 && full_bytes <= 16 else { return false; }
    for i in full_bytes {
        if cidr.addr.bytes[i] != ip.bytes[i] { return false; }
    }
    let rem_bits = ((pfx as u64) & 7) as i64;
    if rem_bits > 0 && rem_bits < 8 && full_bytes < 16 {
        let mask = CIDR_REM_MASKS[rem_bits];
        if (cidr.addr.bytes[full_bytes] & mask) != (ip.bytes[full_bytes] & mask) {
            return false;
        }
    }
    return true;
}

fn cidr_contains_cidr(outer: const IpCidr&, inner: const IpCidr&) -> bool {
    guard outer.addr.family == inner.addr.family && outer.addr.family != IpFamily.Unknown else {
        return false;
    }
    guard outer.prefix_len <= inner.prefix_len else { return false; }
    return cidr_contains_ip(outer, inner.addr);
}

fn format_ipv4_octets<B>(octs: const u8[4]&, out: B&) -> bool {
    let packed = read_be_u32(octs[..], 0);
    var tmp: u8[..64] = [];
    format_ipv4_u32(packed, tmp);
    guard out.try_set(tmp[..]) else {
        out.clear();
        return false;
    }
    return true;
}

fn format_ipv6_compressed<B>(octs: const u8[16]&, out: B&) -> bool {
    var pieces: u16[8] = [0; 8];
    for g in 8 {
        pieces[g] = read_be_u16(octs[..], mul_sat_i64(g, 2));
    }
    var tmp: u8[..64] = [];
    format_compressed_ipv6(pieces, tmp);
    guard out.try_set(tmp[..]) else {
        out.clear();
        return false;
    }
    return true;
}

fn format_ip_addr<B>(ip: const IpAddr&, out: B&) -> bool {
    if ip.family == IpFamily.V4 {
        let octs: u8[4] = [ip.bytes[0], ip.bytes[1], ip.bytes[2], ip.bytes[3]];
        return format_ipv4_octets(octs, out);
    }
    if ip.family == IpFamily.V6 {
        return format_ipv6_compressed(ip.bytes, out);
    }
    out.clear();
    return false;
}
