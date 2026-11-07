// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// FoxIO JA4+ network fingerprinting algorithms: JA4 (TLS) and JA4H (HTTP).
// Conforms to FoxIO JA4 specification with zero dynamic allocations.
namespace wing;

import std;
import core from "..";

// ---- grease detection & filtering (rfc 8701) -------------------------------

// Filters out GREASE values from a list of 16-bit values into out.
fn filter_grease_u16(vals: const u16[:], out: u16[>..]&) {
    for v in vals {
        if !rfc::is_grease_u16(v) {
            out.push(v);
        }
    }
}

// In-place insertion sort for 16-bit values (deterministic, zero-heap).
fn sort_u16(arr: u16[>..]&) {
    if arr.len <= 1 { return; }
    for i in 1..arr.len {
        let key = arr[i];
        var j = i - 1;
        while j >= 0 && arr[j] > key {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

// ---- formatting helpers ----------------------------------------------------

fn append_hex4<B>(val: u16, out: B&) {
    let hex_chars = "0123456789abcdef";
    out.push(hex_chars[((val >> 12) & 0x0F) as i64]);
    out.push(hex_chars[((val >> 8) & 0x0F) as i64]);
    out.push(hex_chars[((val >> 4) & 0x0F) as i64]);
    out.push(hex_chars[(val & 0x0F) as i64]);
}

fn append_two_digits<B>(n: i64, out: B&) {
    let clamped = min(max(n, 0), 99);
    out.push(('0' as i64 + (clamped / 10)) as u8);
    out.push(('0' as i64 + (clamped % 10)) as u8);
}

// Produces first 12 hex characters of SHA-256 (FoxIO 12-char hash truncation).
fn hash_12_hex<B>(data: const u8[:], out: B&) {
    if data.len == 0 {
        out.append("000000000000");
        return;
    }
    let sum = core::sha256(data);
    let hex_chars = "0123456789abcdef";
    for i in 6 {
        out.push(hex_chars[((sum[i] >> 4) & 0x0F) as i64]);
        out.push(hex_chars[(sum[i] & 0x0F) as i64]);
    }
}

inline fn ja4_version_rank(v: u16) -> i32 {
    if v == 0x0304 || v == 0xFEFC { return 6; }
    if v == 0x0303 || v == 0xFEFD { return 5; }
    if v == 0x0302 { return 4; }
    if v == 0x0301 || v == 0xFEFF { return 3; }
    if v == 0x0300 { return 2; }
    if v == 0x0002 { return 1; }
    return 0;
}

// Maps highest supported TLS/DTLS version to 2-character JA4 code.
fn ja4_version_string(supported_versions: const u16[:]) -> const u8[:] {
    var best_ver:  u16 = 0;
    var best_rank: i32 = 0;
    for v in supported_versions {
        if !rfc::is_grease_u16(v) {
            let r = ja4_version_rank(v);
            if r > best_rank {
                best_rank = r;
                best_ver = v;
            }
        }
    }
    if best_ver == 0x0304 { return "13"; } // TLS 1.3
    if best_ver == 0x0303 { return "12"; } // TLS 1.2
    if best_ver == 0x0302 { return "11"; } // TLS 1.1
    if best_ver == 0x0301 { return "10"; } // TLS 1.0
    if best_ver == 0x0300 { return "s3"; } // SSL 3.0
    if best_ver == 0x0002 { return "s2"; } // SSL 2.0
    if best_ver == 0xFEFC { return "d3"; } // DTLS 1.3
    if best_ver == 0xFEFD { return "d2"; } // DTLS 1.2
    if best_ver == 0xFEFF { return "d1"; } // DTLS 1.0
    return "00";
}

fn is_ja4_alnum(b: u8) -> bool {
    return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z');
}

// Extracts 2-character ALPN code (first and last char of first protocol).
// Falls back to first/last hex nibble if either character is non-alphanumeric.
fn ja4_alpn_string<B>(alpn_protocol: const u8[:], out: B&) {
    var first_len = alpn_protocol.len;
    for i in alpn_protocol.len {
        if alpn_protocol[i] == ',' {
            first_len = i;
            break;
        }
    }
    if first_len == 0 {
        out.append("00");
        return;
    }
    let hex_chars = "0123456789abcdef";
    let b_first = alpn_protocol[0];
    let b_last = alpn_protocol[first_len - 1];

    if is_ja4_alnum(b_first) && is_ja4_alnum(b_last) {
        out.push(b_first);
        out.push(b_last);
    } else {
        out.push(hex_chars[((b_first >> 4) & 0x0F) as i64]);
        out.push(hex_chars[(b_last & 0x0F) as i64]);
    }
}

// ---- ja4 tls client fingerprint calculation --------------------------------

fn append_ja4_ciphers_hash<B>(filtered_ciphers: u16[>..]&, out: B&) {
    if filtered_ciphers.len == 0 {
        out.append("000000000000");
        return;
    }
    sort_u16(filtered_ciphers);
    var cipher_buf: u8[>..] = [];
    for i in filtered_ciphers.len {
        if i > 0 { cipher_buf.push(','); }
        append_hex4(filtered_ciphers[i], cipher_buf);
    }
    hash_12_hex(cipher_buf[..], out);
}

fn append_ja4_extensions_hash<B>(
    filtered_exts:  const u16[:],
    sig_algorithms: const u16[:],
    out:            B&,
) {
    var hash_exts: u16[>..] = [];
    for e in filtered_exts {
        if e != 0x0000 && e != 0x0010 { // Exclude SNI and ALPN per JA4 standard
            hash_exts.push(e);
        }
    }

    var filtered_sigs: u16[>..] = [];
    filter_grease_u16(sig_algorithms, filtered_sigs);

    if hash_exts.len == 0 && filtered_sigs.len == 0 {
        out.append("000000000000");
        return;
    }
    sort_u16(hash_exts);
    var ext_buf: u8[>..] = [];
    for i in hash_exts.len {
        if i > 0 { ext_buf.push(','); }
        append_hex4(hash_exts[i], ext_buf);
    }
    if filtered_sigs.len > 0 {
        if hash_exts.len > 0 {
            ext_buf.push('_');
        }
        for i in filtered_sigs.len {
            if i > 0 { ext_buf.push(','); }
            append_hex4(filtered_sigs[i], ext_buf);
        }
    }
    hash_12_hex(ext_buf[..], out);
}

// Computes the FoxIO JA4 TLS client fingerprint in format:
// {protocol}{version}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}
// E.g.: "t13d1516h2_8daaf6152771_e5627efa2ab1"
fn compute_ja4<B>(
    ciphers:            const u16[:],
    extensions:         const u16[:],
    supported_versions: const u16[:],
    sni:                bool,
    alpn_protocol:      const u8[:],
    sig_algorithms:     const u16[:],
    is_quic:            bool,
    out:                B&,
) {
    out.clear();
    out.push(if is_quic { 'q' } else { 't' });
    out.append(ja4_version_string(supported_versions));
    out.push(if sni { 'd' } else { 'i' });

    var filtered_ciphers: u16[>..] = [];
    filter_grease_u16(ciphers, filtered_ciphers);
    append_two_digits(filtered_ciphers.len, out);

    var filtered_exts: u16[>..] = [];
    filter_grease_u16(extensions, filtered_exts);
    append_two_digits(filtered_exts.len, out);

    ja4_alpn_string(alpn_protocol, out);
    out.push('_');
    append_ja4_ciphers_hash(filtered_ciphers, out);
    out.push('_');
    append_ja4_extensions_hash(filtered_exts[..], sig_algorithms, out);
}

// Convenience wrapper returning a fixed-capacity buffer.
fn compute_ja4(
    ciphers:            const u16[:],
    extensions:         const u16[:],
    supported_versions: const u16[:],
    sni:                bool         = true,
    alpn_protocol:      const u8[:]  = "h2",
    sig_algorithms:     const u16[:] = [],
    is_quic:            bool         = false,
) -> u8[..64] {
    var out: u8[..64] = [];
    compute_ja4(ciphers, extensions, supported_versions, sni, alpn_protocol, sig_algorithms, is_quic, out);
    return out;
}

// ---- ja4h http client fingerprint calculation ------------------------------

fn compare_lower_ascii(a: const u8[:], b: const u8[:]) -> i32 {
    let min_len = min(a.len, b.len);
    for i in min_len {
        let ca = if a[i] >= 'A' && a[i] <= 'Z' { a[i] + 32 } else { a[i] };
        let cb = if b[i] >= 'A' && b[i] <= 'Z' { b[i] + 32 } else { b[i] };
        if ca != cb {
            return if ca < cb { -1 } else { 1 };
        }
    }
    if a.len < b.len { return -1; }
    if a.len > b.len { return 1; }
    return 0;
}

fn sort_cookie_indices(names: const u8[:][:], order: i64[>..]&) {
    if order.len <= 1 { return; }
    for i in 1..order.len {
        let key_idx = order[i];
        let key_name = names[key_idx];
        var j = i - 1;
        while j >= 0 && compare_lower_ascii(names[order[j]], key_name) > 0 {
            order[j + 1] = order[j];
            j--;
        }
        order[j + 1] = key_idx;
    }
}

fn append_ja4h_language<B>(accept_lang: const u8[:], out: B&) {
    if accept_lang.len == 0 {
        out.append("0000");
        return;
    }
    var count = 0;
    for b in accept_lang {
        if count == 4 || b == ',' || b == ';' { break; }
        if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') {
            out.push(b);
            count++;
        } else if b >= 'A' && b <= 'Z' {
            out.push(b + 32);
            count++;
        }
    }
    if count == 0 {
        out.append("0000");
        return;
    }
    while count < 4 {
        out.push('0');
        count++;
    }
}

struct Ja4hFlags {
    has_cookie:  bool = false,
    has_referer: bool = false,
}

fn append_ja4h_headers_hash<B>(filtered_headers: const u8[:][:], out: B&) {
    if filtered_headers.len == 0 {
        out.append("000000000000");
        return;
    }
    var hbuf: u8[>..] = [];
    for i in filtered_headers.len {
        if i > 0 { hbuf.push(','); }
        core::to_lower_ascii(filtered_headers[i], hbuf);
    }
    hash_12_hex(hbuf[..], out);
}

fn append_ja4h_cookies_hash<B>(
    cookie_names:  const u8[:][:],
    cookie_values: const u8[:][:],
    out:           B&,
) {
    if cookie_names.len == 0 {
        out.append("000000000000_000000000000");
        return;
    }
    var order: i64[>..] = [];
    for i in cookie_names.len { order.push(i); }
    sort_cookie_indices(cookie_names, order);

    var cbuf: u8[>..] = [];
    for i in order.len {
        if i > 0 { cbuf.push(','); }
        cbuf.append(cookie_names[order[i]]);
    }
    hash_12_hex(cbuf[..], out);

    out.push('_');

    var vbuf: u8[>..] = [];
    for i in order.len {
        if i > 0 { vbuf.push(','); }
        let idx = order[i];
        vbuf.append(cookie_names[idx]);
        vbuf.push('=');
        if idx < cookie_values.len {
            vbuf.append(cookie_values[idx]);
        }
    }
    hash_12_hex(vbuf[..], out);
}

inline fn ja4h_proto_string(proto: const u8[:]) -> const u8[:] {
    if eq_ascii_fold(proto, "HTTP/1.0") || proto == "1.0" { return "10"; }
    if eq_ascii_fold(proto, "HTTP/1.1") || proto == "1.1" { return "11"; }
    let is_h2 = eq_ascii_fold(proto, "HTTP/2") || eq_ascii_fold(proto, "HTTP/2.0") || eq_ascii_fold(proto, "h2");
    if is_h2 || proto == "2" || proto == "2.0" {
        return "20";
    }
    let is_h3 = eq_ascii_fold(proto, "HTTP/3") || eq_ascii_fold(proto, "HTTP/3.0") || eq_ascii_fold(proto, "h3");
    if is_h3 || proto == "3" || proto == "3.0" {
        return "30";
    }
    return "00";
}

// Computes the FoxIO JA4H HTTP client fingerprint in format:
// {method}{version}{cookie}{referer}{header_count}{lang}_{headers_hash}_{cookie_names}_{cookie_values}
// E.g.: "ge20cn04enus_1c8f3b0e29d1_000000000000_000000000000"
fn compute_ja4h<B>(
    method:          const u8[:],
    proto:           const u8[:],
    header_names:    const u8[:][:],
    flags:           Ja4hFlags,
    accept_language: const u8[:],
    cookie_names:    const u8[:][:],
    cookie_values:   const u8[:][:],
    out:             B&,
) {
    out.clear();
    if method.len >= 2 {
        out.push(if method[0] >= 'A' && method[0] <= 'Z' { method[0] + 32 } else { method[0] });
        out.push(if method[1] >= 'A' && method[1] <= 'Z' { method[1] + 32 } else { method[1] });
    } else {
        out.append("00");
    }

    out.append(ja4h_proto_string(proto));

    var has_cookie = flags.has_cookie || cookie_names.len > 0;
    var has_referer = flags.has_referer;
    var filtered_headers: const u8[:][>..] = [];
    for h in header_names {
        if h.len == 0 || h[0] == ':' {
            continue;
        }
        if eq_ascii_fold(h, "cookie") {
            has_cookie = true;
            continue;
        }
        if eq_ascii_fold(h, "referer") {
            has_referer = true;
            continue;
        }
        filtered_headers.push(h);
    }

    out.push(if has_cookie { 'c' } else { 'n' });
    out.push(if has_referer { 'r' } else { 'n' });
    append_two_digits(filtered_headers.len, out);
    append_ja4h_language(accept_language, out);
    out.push('_');
    append_ja4h_headers_hash(filtered_headers[..], out);
    out.push('_');
    append_ja4h_cookies_hash(cookie_names, cookie_values, out);
}

// Convenience wrapper for JA4H returning a fixed-capacity buffer.
fn compute_ja4h(
    method:          const u8[:],
    proto:           const u8[:],
    header_names:    const u8[:][:],
    flags:           Ja4hFlags      = Ja4hFlags { .. },
    accept_language: const u8[:]    = "",
    cookie_names:    const u8[:][:] = [],
    cookie_values:   const u8[:][:] = [],
) -> u8[..64] {
    var out: u8[..64] = [];
    compute_ja4h(
        method,
        proto,
        header_names,
        flags,
        accept_language,
        cookie_names,
        cookie_values,
        out,
    );
    return out;
}
