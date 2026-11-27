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

fn punycode_adapt(delta_in: u64, numpoints: u64, firsttime: bool) -> u64 {
    let d0 = if firsttime { delta_in / PUNYCODE_DAMP } else { delta_in >> 1 };
    var delta = d0 + (d0 / max(numpoints, 1));
    var k: u64 = 0;
    while delta > 455 {
        delta /= 35;
        k += PUNYCODE_BASE;
    }
    return k + ((36 * delta) / (delta + PUNYCODE_SKEW));
}

fn punycode_emit_delta(q_in: u64, bias: u64, out_ace: u8[..63]&) -> bool {
    var q = q_in;
    var k = PUNYCODE_BASE;
    while true {
        let t = if k <= bias {
            PUNYCODE_TMIN
        } else if k >= bias + PUNYCODE_TMAX {
            PUNYCODE_TMAX
        } else {
            k - bias
        };
        if q < t { break; }
        let base_minus_t = PUNYCODE_BASE - t;
        let q_minus_t = q - t;
        let digit = min(t + (q_minus_t % base_minus_t), 35) as i64;
        guard out_ace.try_push(PUNYCODE_DIGITS[digit]) else { return false; }
        q = q_minus_t / base_minus_t;
        k += PUNYCODE_BASE;
    }
    return out_ace.try_push(PUNYCODE_DIGITS[min(q, 35) as i64]);
}

fn punycode_extract_codepoints(utf8_label: const u8[:], cps: u64[..63]&, has_non_ascii: bool&) -> bool {
    var idx: i64 = 0;
    let total = utf8_label.len;
    while idx < total {
        let cp, sz, ok = decode_utf8(utf8_label[idx..]);
        guard ok && sz > 0 else { return false; }
        var norm_cp = cp as u64;
        if norm_cp < 0x80 {
            let b = norm_cp as u8;
            guard b > 0x20 && b != 0x7F && b != 0x2E else { return false; }
            norm_cp = to_lower_ascii_byte(b);
        } else {
            has_non_ascii = true;
        }
        guard cps.try_push(norm_cp) else { return false; }
        idx += sz;
    }
    return cps.len > 0;
}

fn punycode_copy_basic_codepoints(cps: const u64[:], out_ace: u8[..63]&) -> u64, bool {
    var basic_count: u64 = 0;
    for c in cps {
        if c < 0x80 {
            guard out_ace.try_push(c as u8) else { return 0, false; }
            basic_count += 1;
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
            delta += 1;
            guard delta <= 0xFFFFFFFF else { return false; }
        } else if c == n {
            guard punycode_emit_delta(delta, bias, out_ace) else { return false; }
            let next_h = h + 1;
            bias = punycode_adapt(delta, next_h, h == basic_count);
            delta = 0;
            h = next_h;
        }
    }
    return true;
}

fn punycode_encode_non_ascii_cps(cps: const u64[:], out_ace: u8[..63]&) -> bool {
    out_ace.clear();
    guard out_ace.try_append("xn--") else { return false; }
    let basic_count, ok_basic = punycode_copy_basic_codepoints(cps, out_ace);
    guard ok_basic else { return false; }

    var n = PUNYCODE_INITIAL_N;
    var delta: u64 = 0;
    var bias = PUNYCODE_INITIAL_BIAS;
    var h = basic_count;
    let total_cp = cps.len as u64;
    while h < total_cp {
        let m = punycode_find_next_min_cp(cps, n);
        delta = add_sat_u64(delta, mul_sat_u64(m - n, h + 1));
        guard delta <= 0xFFFFFFFF else { return false; }
        n = m;
        guard punycode_step_non_basic(cps, n, basic_count, delta, bias, h, out_ace) else {
            return false;
        }
        delta += 1;
        n += 1;
    }
    return true;
}

// Encodes a single UTF-8 domain label into an ASCII/ACE Punycode label (`xn--...`, RFC 3492).
//
// Example:
//   utf8_label = "\xE4\xB8\xAD\xE5\x9B\xBD", out_ace = []
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
    return punycode_encode_non_ascii_cps(cps[..], out_ace);
}

// Scans forward in `domain` from `start` to the next '.' delimiter (or `domain.len`).
//
// Example:
//   domain = "www.ck", start = 0 -> returns 3
fn scan_domain_label_end(domain: const u8[:], start: i64) -> i64 {
    let rel = index_of_byte(domain[start..], '.');
    return if rel >= 0 { start + rel } else { domain.len };
}

// Normalizes a UTF-8 or ASCII domain into lowercase Punycode/ACE (`xn--...`) labels (RFC 3492).
//
// Example:
//   utf8_domain = "Example.\xE4\xB8\xAD\xE5\x9B\xBD", out_ace = []
//   returns: true, out_ace = "example.xn--fiqs8s"
fn punycode_encode_domain(utf8_domain: const u8[:], out_ace: u8[..256]&) -> bool {
    out_ace.clear();
    let total = utf8_domain.len;
    guard total > 0 && total <= 256 && validate_utf8(utf8_domain) else { return false; }
    guard utf8_domain[0] != '.' && utf8_domain[total - 1] != '.' else { return false; }
    guard !is_ip_address_literal(utf8_domain) else { return false; }
    var start: i64 = 0;
    while start < total {
        let dot = scan_domain_label_end(utf8_domain, start);
        guard dot > start else { return false; }
        var label_ace: u8[..63] = [];
        guard punycode_encode_label(utf8_domain[start..dot], label_ace) else { return false; }
        if out_ace.len > 0 {
            guard out_ace.try_push('.') else { return false; }
        }
        guard out_ace.try_append(label_ace[..]) else { return false; }
        start = dot + 1;
    }
    return out_ace.len > 0;
}

fn punycode_base36_digit(b: u8) -> i32 {
    if b >= 'a' && b <= 'z' { return (b - 'a'); }
    if b >= 'A' && b <= 'Z' { return (b - 'A'); }
    if b >= '0' && b <= '9' { return (b - '0' + 26); }
    return -1;
}

fn is_valid_punycode_basic_prefix(prefix: const u8[:]) -> bool {
    for b in prefix {
        let is_low = (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-';
        guard is_low else { return false; }
    }
    return true;
}

// Decodes one variable-length Bootstring integer delta from `ace_body[pos..]` (RFC 3492 Section 6.2).
// Leaves `pos` unchanged if decoding fails.
//
// Example:
//   ace_body = "kva", pos = 0, i = 0, bias = 72
//   returns: ok = true, pos = 3, i = 745
fn punycode_decode_delta(
    ace_body: const u8[:],
    pos:      i64&,
    i:        u64&,
    bias:     u64,
) -> bool {
    let saved_pos = pos;
    let saved_i = i;
    var committed = false;
    defer if !committed { pos = saved_pos; i = saved_i; };

    var w: u64 = 1;
    var k = PUNYCODE_BASE;
    let body_len = ace_body.len;
    while true {
        guard pos < body_len else { return false; }
        let d_raw = punycode_base36_digit(ace_body[pos]);
        guard d_raw >= 0 else { return false; }
        let d = d_raw as u64;
        pos += 1;

        guard d <= (0xFFFFFFFF - i) / w else { return false; }
        i += d * w;

        let t = if k <= bias {
            PUNYCODE_TMIN
        } else if k >= bias + PUNYCODE_TMAX {
            PUNYCODE_TMAX
        } else {
            k - bias
        };
        if d < t { break; }

        let base_minus_t = PUNYCODE_BASE - t;
        guard w <= 0xFFFFFFFF / base_minus_t else { return false; }
        w *= base_minus_t;
        k += PUNYCODE_BASE;
    }
    committed = true;
    return true;
}

inline fn is_valid_decoded_non_ascii_scalar(cp: u64) -> bool {
    guard cp > 0x9F && cp <= 0x10FFFF && (cp < 0xD800 || cp > 0xDFFF) else { return false; }
    guard (cp & 0xFFFE) != 0xFFFE && !(cp >= 0xFDD0 && cp <= 0xFDEF) else { return false; }
    guard cp != 0x00AD && cp != 0xFFFD && cp != 0xFEFF else { return false; }
    return !(cp == 0x200B || (cp >= 0x200E && cp <= 0x200F) ||
        (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2060 && cp <= 0x206F));
}

inline fn insert_punycode_cp(u_cps: u64[..63]&, idx: i64, cp: u64) -> bool {
    guard idx >= 0 && idx <= u_cps.len && u_cps.len < 63 else { return false; }
    guard u_cps.try_push(0) else { return false; }
    var k = u_cps.len - 1;
    while k > idx {
        u_cps[k] = u_cps[k - 1];
        k -= 1;
    }
    u_cps[idx] = cp;
    return true;
}

fn push_punycode_basic_cps(prefix: const u8[:], u_cps: u64[..63]&) -> bool {
    guard is_valid_punycode_basic_prefix(prefix) else { return false; }
    for b in prefix {
        guard u_cps.try_push(b as u64) else { return false; }
    }
    return true;
}

// Validates that `ace_body` (after `xn--`) is a canonical RFC 3492 Bootstring encoding
// whose decoded U-label contains at least one valid non-ASCII scalar, no uppercase ASCII,
// no controls or disallowed format chars, valid hyphen placement, and matches roundtrip encoding.
//
// Example:
//   ace_body = "bcher-kva"
//   returns: true
fn is_valid_punycode_ace_body(ace_body: const u8[:]) -> bool {
    let body_len = ace_body.len;
    guard body_len > 0 else { return false; }
    let delim = last_index_of_byte(ace_body, '-');
    // RFC 3492 Section 3.1: Delimiter '-' MUST NOT appear at index 0 with empty basic-char prefix.
    guard delim != 0 else { return false; }
    let basic_len = max(0, delim) as u64;
    var u_cps: u64[..63] = [];
    if delim > 0 {
        guard push_punycode_basic_cps(ace_body[..delim], u_cps) else { return false; }
    }
    var pos = max(0, delim + 1);
    guard pos < body_len else { return false; }

    var out_len = basic_len;
    var n = PUNYCODE_INITIAL_N;
    var i: u64 = 0;
    var bias = PUNYCODE_INITIAL_BIAS;

    while pos < body_len {
        let oldi = i;
        guard punycode_decode_delta(ace_body, pos, i, bias) else { return false; }
        let next_len = out_len + 1;
        guard next_len <= 63 else { return false; }
        bias = punycode_adapt(i - oldi, next_len, oldi == 0);
        let q_n = i / next_len;
        guard q_n <= 0x10FFFF - n else { return false; }
        n += q_n;
        guard is_valid_decoded_non_ascii_scalar(n) else { return false; }
        let ins_idx = (i % next_len) as i64;
        guard insert_punycode_cp(u_cps, ins_idx, n) else { return false; }
        i = (i % next_len) + 1;
        out_len = next_len;
    }
    guard out_len > basic_len && u_cps.len > 0 else { return false; }
    let hyphen = '-' as u64;
    guard u_cps[0] != hyphen && u_cps[u_cps.len - 1] != hyphen else { return false; }
    if u_cps.len >= 4 && u_cps[2] == hyphen && u_cps[3] == hyphen {
        return false;
    }
    var re_ace: u8[..63] = [];
    guard punycode_encode_non_ascii_cps(u_cps[..], re_ace) else { return false; }
    return re_ace.len == 4 + body_len && re_ace[4..].eq_ascii_fold(ace_body);
}

// CVE-2026-39821 defense: Validates an ACE / Punycode label starting with "xn--"
// and enforces RFC 952 / RFC 1123 STD3 LDH + CheckHyphens rules on all labels.
fn validate_punycode_label(label: const u8[:]) -> bool {
    guard label.len > 0 && label.len <= 63 else { return false; }
    guard label[0] != '-' && label[label.len - 1] != '-' else { return false; }
    for b in label {
        guard is_ascii_alphanumeric(b) || b == '-' else { return false; }
    }
    guard label.len >= 4 && label[2] == '-' && label[3] == '-' else { return true; }
    let ace_body, is_xn = strip_prefix_fold(label, "xn--");
    guard is_xn else { return false; }
    return is_valid_punycode_ace_body(ace_body);
}

// CVE-2026-97044 defense: Validates FQDN wire bounds for internationalized domain names.
// Enforces that every label is <= 63 bytes, all Punycode labels are valid non-ASCII encodings,
// and total encoded domain length does not exceed 253 bytes.
fn validate_idna_domain_bounds(domain: const u8[:]) -> bool {
    let total = domain.len;
    guard total > 0 && total <= 253 && domain[total - 1] != '.' else { return false; }
    var start: i64 = 0;
    while start < total {
        let dot_pos = scan_domain_label_end(domain, start);
        guard dot_pos > start && validate_punycode_label(domain[start..dot_pos]) else { return false; }
        if dot_pos == total { break; }
        start = dot_pos + 1;
    }
    return true;
}

// Go #78760 / CVE-2026-39821 & CVE-2026-97044: Reject invalid ACE/Punycode labels and
// enforce STD3 LDH + CheckHyphens + RFC 1035 DNS label (<= 63B) and total domain (<= 253B) limits.
fn validate_host_punycode_labels(host_str: const u8[:]) -> bool {
    if host_str.len == 0 { return true; }
    let trimmed, _ = strip_suffix(host_str, ".");
    let total = trimmed.len;
    guard total > 0 && total <= 253 else { return false; }

    var start: i64 = 0;
    while start < total {
        let dot_pos = scan_domain_label_end(trimmed, start);
        guard dot_pos > start && validate_punycode_label(trimmed[start..dot_pos]) else {
            return false;
        }
        if dot_pos == total { break; }
        start = dot_pos + 1;
        guard start < total else { return false; }
    }
    return true;
}
