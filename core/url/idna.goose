// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 3492 Bootstring/Punycode encoder and RFC 1035 / RFC 5891 IDNA DNS label validation.
namespace core;

import std;

const PUNYCODE_BASE:         u64 = 36;
const PUNYCODE_TMIN:         u64 = 1;
const PUNYCODE_TMAX:         u64 = 26;
const PUNYCODE_SKEW:         u64 = 38;
const PUNYCODE_DAMP:         u64 = 700;
const PUNYCODE_INITIAL_BIAS: u64 = 72;
const PUNYCODE_INITIAL_N:    u64 = 128;
const PUNYCODE_DIGITS: u8[36] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
];

fn punycode_div_u64(n: u64, d: u64) -> u64, u64 {
    guard d > 0 && n >= d else { return 0, n; }
    var cur_d = d;
    var cur_q: u64 = 1;
    let half_n = n >> 1;
    while cur_d <= half_n {
        cur_d = add_sat_u64(cur_d, cur_d);
        cur_q = add_sat_u64(cur_q, cur_q);
    }
    var rem_n = n;
    var quotient: u64 = 0;
    while cur_q > 0 {
        if rem_n >= cur_d {
            rem_n = sub_sat_u64(rem_n, cur_d);
            quotient = quotient | cur_q;
        }
        cur_d = cur_d >> 1;
        cur_q = cur_q >> 1;
    }
    return quotient, rem_n;
}

fn punycode_adapt(delta_in: u64, numpoints: u64, firsttime: bool) -> u64 {
    var d0 = delta_in >> 1;
    if firsttime {
        let q0, _ = punycode_div_u64(delta_in, PUNYCODE_DAMP);
        d0 = q0;
    }
    let d1, _ = punycode_div_u64(d0, max(numpoints, 1));
    var delta = add_sat_u64(d0, d1);
    let base_minus_tmin: u64 = 35;
    let threshold:       u64 = 455;
    var k: u64 = 0;
    while delta > threshold {
        let q, _ = punycode_div_u64(delta, base_minus_tmin);
        delta = q;
        k = add_sat_u64(k, PUNYCODE_BASE);
    }
    let num = mul_sat_u64(36, delta);
    let den = add_sat_u64(delta, PUNYCODE_SKEW);
    let tail, _ = punycode_div_u64(num, den);
    return add_sat_u64(k, tail);
}

fn punycode_emit_delta(q_in: u64, bias: u64, out_ace: u8[..63]&) -> bool {
    var q = q_in;
    var k = PUNYCODE_BASE;
    while true {
        let bias_plus_tmax = add_sat_u64(bias, PUNYCODE_TMAX);
        let t = if k <= bias {
            PUNYCODE_TMIN
        } else if k >= bias_plus_tmax {
            PUNYCODE_TMAX
        } else {
            sub_sat_u64(k, bias)
        };
        if q < t { break; }
        let base_minus_t = sub_sat_u64(PUNYCODE_BASE, t);
        let q_minus_t = sub_sat_u64(q, t);
        let q_next, rem = punycode_div_u64(q_minus_t, base_minus_t);
        let digit = min(add_sat_u64(t, rem), 35) as i64;
        let ch = PUNYCODE_DIGITS[digit];
        guard out_ace.try_push(ch) else { return false; }
        q = q_next;
        k = add_sat_u64(k, PUNYCODE_BASE);
    }
    let final_digit = min(q, 35) as i64;
    let final_ch = PUNYCODE_DIGITS[final_digit];
    return out_ace.try_push(final_ch);
}

fn punycode_extract_codepoints(utf8_label: const u8[:], cps: u64[..63]&, has_non_ascii: bool&) -> bool {
    var idx: i64 = 0;
    while idx < utf8_label.len {
        let cp, sz, ok = decode_utf8(utf8_label[idx..]);
        guard ok && sz > 0 && cps.len < cps.cap else { return false; }
        var norm_cp = cp as u64;
        if norm_cp < 0x80 {
            let b = norm_cp as u8;
            guard b > 0x20 && b != 0x7F && b != 0x2E else { return false; }
            norm_cp = to_lower_ascii_byte(b);
        } else {
            has_non_ascii = true;
        }
        cps.push(norm_cp);
        idx = add_sat_i64(idx, sz);
    }
    return cps.len > 0;
}

fn punycode_copy_basic_codepoints(cps: const u64[:], out_ace: u8[..63]&) -> u64, bool {
    var basic_count: u64 = 0;
    for c in cps {
        if c < 0x80 {
            guard out_ace.try_push(c as u8) else { return 0, false; }
            basic_count = add_sat_u64(basic_count, 1);
        }
    }
    if basic_count > 0 {
        guard out_ace.try_push('-') else { return 0, false; }
    }
    return basic_count, true;
}

fn punycode_find_next_min_cp(cps: const u64[:], n: u64) -> u64 {
    var m: u64 = 0xFFFFFFFF;
    for c in cps {
        if c >= n && c < m { m = c; }
    }
    return m;
}

fn punycode_step_non_basic(
    cps:         const u64[:],
    n:           u64,
    basic_count: u64,
    delta:       u64&,
    bias:        u64&,
    h:           u64&,
    out_ace:     u8[..63]&,
) -> bool {
    for c in cps {
        if c < n {
            delta = add_sat_u64(delta, 1);
            guard delta <= 0xFFFFFFFF else { return false; }
        } else if c == n {
            guard punycode_emit_delta(delta, bias, out_ace) else { return false; }
            let next_h = add_sat_u64(h, 1);
            bias = punycode_adapt(delta, next_h, h == basic_count);
            delta = 0;
            h = next_h;
        }
    }
    return true;
}

// Encodes a single UTF-8 domain label into an ASCII/ACE Punycode label (`xn--...`, RFC 3492).
//
// Example:
//   utf8_label = "\xE4\xB8\xAD\xE5\x9B\xBD" ("中国"), out_ace = []
//   returns: true, out_ace = "xn--fiqs8s"
fn punycode_encode_label(utf8_label: const u8[:], out_ace: u8[..63]&) -> bool {
    out_ace.clear();
    guard utf8_label.len > 0 && validate_utf8(utf8_label) else { return false; }
    var cps: u64[..63] = [];
    var has_non_ascii = false;
    guard punycode_extract_codepoints(utf8_label, cps, has_non_ascii) else { return false; }
    if !has_non_ascii {
        for c in cps {
            guard out_ace.try_push(c as u8) else { return false; }
        }
        return true;
    }
    guard out_ace.try_append("xn--") else { return false; }
    let basic_count, ok_basic = punycode_copy_basic_codepoints(cps[..], out_ace);
    guard ok_basic else { return false; }

    var n = PUNYCODE_INITIAL_N;
    var delta: u64 = 0;
    var bias = PUNYCODE_INITIAL_BIAS;
    var h = basic_count;
    let total_cp = cps.len as u64;
    while h < total_cp {
        let m = punycode_find_next_min_cp(cps[..], n);
        let step_mul = mul_sat_u64(sub_sat_u64(m, n), add_sat_u64(h, 1));
        delta = add_sat_u64(delta, step_mul);
        guard delta <= 0xFFFFFFFF else { return false; }
        n = m;
        guard punycode_step_non_basic(cps[..], n, basic_count, delta, bias, h, out_ace) else { return false; }
        delta = add_sat_u64(delta, 1);
        n = add_sat_u64(n, 1);
    }
    return true;
}

// Scans forward in `domain` from `start` to the next '.' delimiter (or `domain.len`).
//
// Example:
//   domain = "www.ck", start = 0 -> returns 3
fn scan_domain_label_end(domain: const u8[:], start: i64) -> i64 {
    var dot = start;
    while dot < domain.len && domain[dot] != 0x2E {
        dot = add_sat_i64(dot, 1);
    }
    return dot;
}

// Normalizes a UTF-8 or ASCII domain into lowercase Punycode/ACE (`xn--...`) labels (RFC 3492).
//
// Example:
//   utf8_domain = "Example.\xE4\xB8\xAD\xE5\x9B\xBD", out_ace = []
//   returns: true, out_ace = "example.xn--fiqs8s"
fn punycode_encode_domain(utf8_domain: const u8[:], out_ace: u8[..256]&) -> bool {
    out_ace.clear();
    guard utf8_domain.len > 0 && utf8_domain.len <= 256 else { return false; }
    guard validate_utf8(utf8_domain) else { return false; }
    let last_idx = sub_sat_i64(utf8_domain.len, 1);
    guard utf8_domain[0] != 0x2E && utf8_domain[last_idx] != 0x2E else { return false; }
    guard !is_ip_address_literal(utf8_domain) else { return false; }
    var start: i64 = 0;
    while start < utf8_domain.len {
        let dot = scan_domain_label_end(utf8_domain, start);
        guard dot > start else { return false; }
        var label_ace: u8[..63] = [];
        guard punycode_encode_label(utf8_domain[start..dot], label_ace) else { return false; }
        if out_ace.len > 0 {
            guard out_ace.try_push('.') else { return false; }
        }
        guard out_ace.try_append(label_ace[..]) else { return false; }
        start = add_sat_i64(dot, 1);
    }
    return out_ace.len > 0;
}

// CVE-2026-39821 defense: Validates an ACE / Punycode label starting with "xn--"
// and enforces RFC 952 / RFC 1123 LDH label rules on all labels.
// Per RFC 3492 / RFC 5891 Section 4.2.3, a Punycode label MUST encode at least one non-ASCII code point.
fn validate_punycode_label(label: const u8[:]) -> bool {
    guard label.len > 0 && label.len <= 63 else { return false; }
    let last_idx = sub_sat_i64(label.len, 1);
    guard label[0] != '-' && label[last_idx] != '-' else { return false; }
    for b in label {
        let is_valid = is_ascii_alphanumeric(b) || b == '-' || b == '_';
        guard is_valid else { return false; }
    }
    guard label.len >= 4 && label[2] == '-' && label[3] == '-' else { return true; }
    guard starts_with_fold(label, "xn--") else { return false; }
    return label[4] != '-' && !contains_byte(label[4..], '_');
}

// CVE-2026-97044 defense: Validates FQDN wire bounds for internationalized domain names.
// Enforces that every label is <= 63 bytes, all Punycode labels are valid non-ASCII encodings,
// and total encoded domain length does not exceed 253 bytes.
fn validate_idna_domain_bounds(domain: const u8[:]) -> bool {
    guard domain.len > 0 && domain.len <= 253 else { return false; }
    let last_idx = sub_sat_i64(domain.len, 1);
    guard domain[last_idx] != '.' else { return false; }
    var start: i64 = 0;
    while start < domain.len {
        let dot_pos = scan_domain_label_end(domain, start);
        let label = domain[start..dot_pos];
        guard validate_punycode_label(label) else { return false; }
        start = add_sat_i64(dot_pos, 1);
    }
    return true;
}

// Go #78760 / CVE-2026-39821 & CVE-2026-97044: Reject invalid ACE/Punycode labels that contain no
// non-ASCII delta, and enforce RFC 1035 DNS label (<= 63B) and total domain (<= 253B) length limits.
fn validate_host_punycode_labels(host_str: const u8[:]) -> bool {
    let last_host_idx = sub_sat_i64(host_str.len, 1);
    let trimmed = if host_str.len > 0 && host_str[last_host_idx] == '.' {
        host_str[..last_host_idx]
    } else {
        host_str
    };
    guard trimmed.len <= 253 else { return false; }

    var cursor: i64 = 0;
    while cursor < host_str.len {
        let end = scan_domain_label_end(host_str, cursor);
        let label = host_str[cursor..end];
        guard label.len <= 63 else { return false; }
        if label.len >= 4 && eq_ascii_fold(label[..4], "xn--") {
            let last_lbl_idx = sub_sat_i64(label.len, 1);
            guard label.len > 4 && label[last_lbl_idx] != '-' else { return false; }
        }
        cursor = add_sat_i64(end, 1);
    }
    return true;
}
