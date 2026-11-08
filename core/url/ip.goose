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
            if octet_digits == 0 || octet_val > 255 { return false; }
            dot_count = add_sat_i64(dot_count, 1);
            octet_val = 0;
            octet_digits = 0;
        } else if char_byte >= '0' && char_byte <= '9' {
            let d = hex_digit_to_val(char_byte) as i64;
            octet_val = add_sat_i64(mul_sat_i64(octet_val, 10), d);
            octet_digits = add_sat_i64(octet_digits, 1);
            if octet_digits > 3 { return false; }
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

inline fn validate_zone_id(zone_id: const u8[:]) -> bool {
    guard zone_id.len > 0 && zone_id.len <= 64 else { return false; }
    var idx: i64 = 0;
    while idx < zone_id.len {
        let b = zone_id[idx];
        if is_uri_unreserved(b) {
            idx = add_sat_i64(idx, 1);
        } else if b == '%' {
            let idx1 = add_sat_i64(idx, 1);
            let idx2 = add_sat_i64(idx, 2);
            guard idx2 < zone_id.len else { return false; }
            guard is_ascii_hexdigit(zone_id[idx1]) && is_ascii_hexdigit(zone_id[idx2]) else { return false; }
            idx = add_sat_i64(idx, 3);
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
        let d = hex_digit_to_val(char_byte) as i64;
        val = add_sat_i64(mul_sat_i64(val, 10), d);
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
    var octets: u16[4] = [0, 0, 0, 0];
    var rest = rem_slice;
    for idx in 3 {
        let dot_pos = index_of_byte(rest, '.');
        guard dot_pos > 0 else { return false; }
        let oct, ok = parse_ipv4_decimal_octet(rest[..dot_pos]);
        guard ok else { return false; }
        octets[idx] = oct;
        let next_start = add_sat_i64(dot_pos, 1);
        rest = rest[next_start..];
    }
    let last_oct, ok_last = parse_ipv4_decimal_octet(rest);
    guard ok_last else { return false; }
    octets[3] = last_oct;

    pieces[piece_count] = (mul_sat_u32(octets[0], 256) as u16) | octets[1];
    let next_pc = add_sat_i64(piece_count, 1);
    pieces[next_pc] = (mul_sat_u32(octets[2], 256) as u16) | octets[3];
    piece_count = add_sat_i64(next_pc, 1);
    return true;
}

// Finds the longest continuous run of zero pieces for RFC 5952 canonical compression.
fn find_longest_zero_run(pieces: const u16[8]&) -> i64, i64 {
    var best_run_start:    i64 = -1;
    var best_run_len:      i64 = 0;
    var current_run_start: i64 = -1;
    var current_run_len:   i64 = 0;

    for piece_idx in 8 {
        if pieces[piece_idx] == 0 {
            if current_run_start < 0 {
                current_run_start = piece_idx;
                current_run_len = 1;
            } else {
                current_run_len = add_sat_i64(current_run_len, 1);
            }
        } else {
            if current_run_len > best_run_len {
                best_run_start = current_run_start;
                best_run_len = current_run_len;
            }
            current_run_start = -1;
            current_run_len = 0;
        }
    }

    if current_run_len > best_run_len {
        best_run_start = current_run_start;
        best_run_len = current_run_len;
    }

    if best_run_len < 2 {
        best_run_start = -1;
        best_run_len = 0;
    }

    return best_run_start, best_run_len;
}

// Parses a 1-4 char hex piece of an IPv6 address.
//
// Example:
//   piece_str = "1a2b", out_val = 0
//   returns: true, out_val = 0x1a2b
fn parse_ipv6_hex_piece(piece_str: const u8[:], out_val: u16&) -> bool {
    guard piece_str.len > 0 && piece_str.len <= 4 else { return false; }
    var piece_val: i64 = 0;
    for char_byte in piece_str {
        let hex_digit = hex_digit_to_val(char_byte) as i64;
        guard hex_digit >= 0 else { return false; }
        piece_val = add_sat_i64(mul_sat_i64(piece_val, 16), hex_digit);
    }
    out_val = piece_val as u16;
    return true;
}

fn expand_ipv6_double_colon(pieces: u16[8]&, piece_count: i64&, double_colon_pos: i64) -> bool {
    guard piece_count >= 0 && piece_count < 8 && double_colon_pos >= 0 && double_colon_pos <= piece_count else {
        return false;
    }
    let missing = sub_sat_i64(8, piece_count);
    let tail_count = sub_sat_i64(piece_count, double_colon_pos);
    for rev_idx in tail_count {
        let last_src = sub_sat_i64(piece_count, 1);
        let src = sub_sat_i64(last_src, rev_idx);
        let dst = add_sat_i64(src, missing);
        if src >= 0 && src < 8 && dst >= 0 && dst < 8 {
            pieces[dst] = pieces[src];
        }
    }
    for zero_idx in missing {
        let z_pos = add_sat_i64(double_colon_pos, zero_idx);
        if z_pos >= 0 && z_pos < 8 {
            pieces[z_pos] = 0;
        }
    }
    piece_count = 8;
    return true;
}

fn format_compressed_ipv6<B>(pieces: const u16[8]&, out: B&) {
    let best_run_start, best_run_len = find_longest_zero_run(pieces);
    let best_run_end = add_sat_i64(best_run_start, best_run_len);
    var format_idx: i64 = 0;
    while format_idx < 8 {
        if format_idx == best_run_start {
            out.append("::");
            format_idx = add_sat_i64(format_idx, best_run_len);
            continue;
        }
        let is_skip_zero_tail = format_idx == best_run_end && best_run_start == 0;
        let last_out = sub_sat_i64(out.len, 1);
        if format_idx > 0 && !is_skip_zero_tail && out.len > 0 && out[last_out] != ':' {
            out.push(':');
        }
        format_u64_hex(pieces[format_idx] as u64, out, false);
        format_idx = add_sat_i64(format_idx, 1);
    }
}

fn advance_after_ipv6_colon(
    rem_slice:        const u8[:],
    colon_idx:        i64,
    piece_count:      i64,
    double_colon_pos: i64&,
) -> const u8[:], bool {
    guard colon_idx >= 0 else {
        return rem_slice[rem_slice.len..], true;
    }
    let next_idx = add_sat_i64(colon_idx, 1);
    guard next_idx < rem_slice.len else { return "", false; }
    if rem_slice[next_idx] == ':' {
        guard double_colon_pos < 0 else { return "", false; }
        double_colon_pos = piece_count;
        let after_dc = add_sat_i64(colon_idx, 2);
        return rem_slice[after_dc..], true;
    }
    return rem_slice[next_idx..], true;
}

fn consume_leading_ipv6_double_colon(
    raw_ipv6:         const u8[:],
    double_colon_pos: i64&,
) -> const u8[:], bool {
    guard raw_ipv6.len > 0 && raw_ipv6[0] == ':' else {
        return raw_ipv6, true;
    }
    guard starts_with(raw_ipv6, "::") else { return "", false; }
    double_colon_pos = 0;
    return raw_ipv6[2..], true;
}

fn collect_ipv6_pieces(
    raw_ipv6:         const u8[:],
    pieces:           u16[8]&,
    piece_count:      i64&,
    double_colon_pos: i64&,
) -> bool {
    let init_rem, ok_init = consume_leading_ipv6_double_colon(raw_ipv6, double_colon_pos);
    guard ok_init else { return false; }
    var rem_slice = init_rem;

    while rem_slice.len > 0 && piece_count < 8 {
        let colon_idx = index_of_byte(rem_slice, ':');
        let piece_str = if colon_idx >= 0 { rem_slice[..colon_idx] } else { rem_slice };
        if piece_str.len == 0 {
            guard double_colon_pos < 0 else { return false; }
            double_colon_pos = piece_count;
            rem_slice = rem_slice[1..];
            continue;
        }

        if contains_byte(piece_str, '.') {
            guard parse_ipv4_mapped_pieces(rem_slice, pieces, piece_count) else { return false; }
            return true;
        }

        var piece_val: u16 = 0;
        guard parse_ipv6_hex_piece(piece_str, piece_val) else { return false; }
        pieces[piece_count] = piece_val;
        piece_count = add_sat_i64(piece_count, 1);

        let next_rem, ok_adv = advance_after_ipv6_colon(rem_slice, colon_idx, piece_count, double_colon_pos);
        guard ok_adv else { return false; }
        rem_slice = next_rem;
    }

    return rem_slice.len == 0;
}

// RFC 5952 / WHATWG IPv6 Parser and Zero-Run Canonical Compression.
//
// Example:
//   raw_ipv6 = "2001:0db8:0000:0000:0000:ff00:0042:8329"
//   out = "2001:db8::ff00:42:8329", returns: true
fn parse_and_compress_ipv6<B>(raw_ipv6: const u8[:], out: B&) -> bool {
    out.clear();
    var pieces:           u16[8] = [0, 0, 0, 0, 0, 0, 0, 0];
    var piece_count:      i64    = 0;
    var double_colon_pos: i64    = -1;

    guard collect_ipv6_pieces(raw_ipv6, pieces, piece_count, double_colon_pos) else {
        return false;
    }

    if double_colon_pos >= 0 {
        guard expand_ipv6_double_colon(pieces, piece_count, double_colon_pos) else { return false; }
    }

    guard piece_count == 8 else { return false; }

    format_compressed_ipv6(pieces, out);
    return true;
}

fn format_ipv4_u32(ip4: u32, out: u8[..64]&) {
    out.clear();
    let b0 = ((ip4 >> 24) & 0xFF) as u64;
    let b1 = ((ip4 >> 16) & 0xFF) as u64;
    let b2 = ((ip4 >> 8) & 0xFF) as u64;
    let b3 = (ip4 & 0xFF) as u64;
    format_u64_dec(b0, out);
    out.push('.');
    format_u64_dec(b1, out);
    out.push('.');
    format_u64_dec(b2, out);
    out.push('.');
    format_u64_dec(b3, out);
}

fn format_ipv6_bytes(ip6: const u8[16]&, out: u8[..64]&) {
    out.clear();
    let hex_chars: const u8[:] = "0123456789abcdef";
    for g in 8 {
        if g > 0 { out.push(':'); }
        let idx0 = mul_sat_i64(g, 2);
        let idx1 = add_sat_i64(idx0, 1);
        let hi = ip6[idx0];
        let lo = ip6[idx1];
        out.push(hex_chars[((hi >> 4) & 0x0F) as i64]);
        out.push(hex_chars[(hi & 0x0F) as i64]);
        out.push(hex_chars[((lo >> 4) & 0x0F) as i64]);
        out.push(hex_chars[(lo & 0x0F) as i64]);
    }
}
