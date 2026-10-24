// FoxIO JA4+ network fingerprinting algorithms: JA4 (TLS) and JA4H (HTTP).
// Conforms to FoxIO JA4 specification with zero dynamic allocations.
namespace wing;

import std;
import core from "..";

// ---- grease detection & filtering (rfc 8701) -------------------------------

// Checks whether a 16-bit code point is a reserved TLS GREASE value (RFC 8701 Section 2).
// GREASE values are of the form 0x?a?a where both nibbles match (0x0a0a, 0x1a1a, ..., 0xfafa).
fn is_grease_u16(val: u16) -> bool {
    return (val & 0x0F0F) == 0x0A0A && ((val >> 8) == (val & 0x00FF));
}

// Filters out GREASE values from a list of 16-bit values into out.
fn filter_grease_u16(vals: const u16[:], out: u16[>..]&) {
    for v in vals {
        if !is_grease_u16(v) {
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
    let clamped = if n < 0 { 0 } else if n > 99 { 99 } else { n };
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

// Maps highest supported TLS version to 2-character JA4 code.
fn ja4_version_string(supported_versions: const u16[:]) -> const u8[:] {
    var highest: u16 = 0;
    for v in supported_versions {
        if !is_grease_u16(v) && v > highest {
            highest = v;
        }
    }
    if highest == 0x0304 { return "13"; } // TLS 1.3
    if highest == 0x0303 { return "12"; } // TLS 1.2
    if highest == 0x0302 { return "11"; } // TLS 1.1
    if highest == 0x0301 { return "10"; } // TLS 1.0
    if highest == 0x0300 { return "s3"; } // SSL 3.0
    if highest == 0x0002 { return "s2"; } // SSL 2.0
    return "00";
}

// Extracts 2-character ALPN code (first and last char of first protocol).
fn ja4_alpn_string<B>(alpn_protocol: const u8[:], out: B&) {
    if alpn_protocol.len == 0 {
        out.append("00");
        return;
    }
    out.push(alpn_protocol[0]);
    out.push(alpn_protocol[alpn_protocol.len - 1]);
}

// ---- ja4 tls client fingerprint calculation --------------------------------

// Computes the FoxIO JA4 TLS client fingerprint in format:
// {protocol}{version}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}
// E.g.: "t13d1516h2_8daaf6152771_e5627efa2ab1"
fn compute_ja4<B>(
    ciphers: const u16[:],
    extensions: const u16[:],
    supported_versions: const u16[:],
    sni: bool,
    alpn_protocol: const u8[:],
    sig_algorithms: const u16[:],
    is_quic: bool,
    out: B&,
) {
    // 1. Protocol prefix: 't' for TCP TLS, 'q' for QUIC
    out.push(if is_quic { 'q' } else { 't' });

    // 2. TLS Version (2 chars)
    out.append(ja4_version_string(supported_versions));

    // 3. SNI indicator: 'd' for domain, 'i' for IP / none
    out.push(if sni { 'd' } else { 'i' });

    // 4. Filter and count non-GREASE ciphers
    var filtered_ciphers: u16[>..] = [];
    filter_grease_u16(ciphers, filtered_ciphers);
    append_two_digits(filtered_ciphers.len, out);

    // 5. Filter and count non-GREASE extensions
    var filtered_exts: u16[>..] = [];
    filter_grease_u16(extensions, filtered_exts);
    append_two_digits(filtered_exts.len, out);

    // 6. ALPN (2 chars)
    ja4_alpn_string(alpn_protocol, out);

    out.push('_');

    // 7. Cipher Hash: sorted non-GREASE ciphers as comma-separated 4-hex values
    if filtered_ciphers.len == 0 {
        out.append("000000000000");
    } else {
        sort_u16(filtered_ciphers);
        var cipher_buf: u8[>..] = [];
        for i in filtered_ciphers.len {
            if i > 0 { cipher_buf.push(','); }
            append_hex4(filtered_ciphers[i], cipher_buf);
        }
        hash_12_hex(cipher_buf[..], out);
    }

    out.push('_');

    // 8. Extension Hash: sorted non-GREASE extensions (excluding SNI 0x0000 and ALPN 0x0010)
    // followed by '_' and raw signature algorithms if present
    var hash_exts: u16[>..] = [];
    for e in filtered_exts {
        if e != 0x0000 && e != 0x0010 { // Exclude SNI and ALPN per JA4 standard
            hash_exts.push(e);
        }
    }

    if hash_exts.len == 0 && sig_algorithms.len == 0 {
        out.append("000000000000");
    } else {
        sort_u16(hash_exts);
        var ext_buf: u8[>..] = [];
        for i in hash_exts.len {
            if i > 0 { ext_buf.push(','); }
            append_hex4(hash_exts[i], ext_buf);
        }
        if sig_algorithms.len > 0 {
            if hash_exts.len > 0 {
                ext_buf.push('_');
            }
            for i in sig_algorithms.len {
                if i > 0 { ext_buf.push(','); }
                append_hex4(sig_algorithms[i], ext_buf);
            }
        }
        hash_12_hex(ext_buf[..], out);
    }
}

// Convenience wrapper returning a fixed-capacity buffer.
fn compute_ja4(
    ciphers: const u16[:],
    extensions: const u16[:],
    supported_versions: const u16[:],
    sni: bool = true,
    alpn_protocol: const u8[:] = "h2",
    sig_algorithms: const u16[:] = [],
    is_quic: bool = false,
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

fn sort_header_names(arr: const u8[:][>..]&) {
    if arr.len <= 1 { return; }
    for i in 1..arr.len {
        let key = arr[i];
        var j = i - 1;
        while j >= 0 && compare_lower_ascii(arr[j], key) > 0 {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

fn append_ja4h_language<B>(accept_lang: const u8[:], out: B&) {
    if accept_lang.len == 0 {
        out.append("0000");
        return;
    }
    var count = 0;
    for b in accept_lang {
        if count == 4 { break; }
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

fn append_lowercase<B>(src: const u8[:], out: B&) {
    for b in src {
        out.push(if b >= 'A' && b <= 'Z' { b + 32 } else { b });
    }
}

// Computes the FoxIO JA4H HTTP client fingerprint in format:
// {method}{version}{cookie}{referer}{header_count}{lang}_{headers_hash}_{cookie_names}_{cookie_values}
// E.g.: "ge20cn04enus_1c8f3b0e29d1_000000000000_000000000000"
fn compute_ja4h<B>(
    method: const u8[:],
    proto: const u8[:],
    header_names: const u8[:][:],
    has_cookie: bool,
    has_referer: bool,
    accept_language: const u8[:],
    cookie_names: const u8[:][:],
    cookie_values: const u8[:][:],
    out: B&,
) {
    // 1. Method (2 chars lowercased)
    if method.len >= 2 {
        out.push(if method[0] >= 'A' && method[0] <= 'Z' { method[0] + 32 } else { method[0] });
        out.push(if method[1] >= 'A' && method[1] <= 'Z' { method[1] + 32 } else { method[1] });
    } else {
        out.append("00");
    }

    // 2. Protocol version (2 chars)
    if proto == "HTTP/1.0" {
        out.append("10");
    } else if proto == "HTTP/1.1" {
        out.append("11");
    } else if proto == "HTTP/2" {
        out.append("20");
    } else if proto == "HTTP/3" {
        out.append("30");
    } else {
        out.append("00");
    }

    // 3. Cookie present ('c' / 'n')
    out.push(if has_cookie { 'c' } else { 'n' });

    // 4. Referer present ('r' / 'n')
    out.push(if has_referer { 'r' } else { 'n' });

    // 5. Header count (excluding Cookie and Referer, 2 digits)
    var filtered_headers: const u8[:][>..] = [];
    for h in header_names {
        if !eq_ascii_fold(h, "cookie") && !eq_ascii_fold(h, "referer") {
            filtered_headers.push(h);
        }
    }
    append_two_digits(filtered_headers.len, out);

    // 6. Language code (4 chars)
    append_ja4h_language(accept_language, out);

    out.push('_');

    // 7. Headers Hash (sorted lowercase header names joined by comma)
    if filtered_headers.len == 0 {
        out.append("000000000000");
    } else {
        sort_header_names(filtered_headers);
        var hbuf: u8[>..] = [];
        for i in filtered_headers.len {
            if i > 0 { hbuf.push(','); }
            append_lowercase(filtered_headers[i], hbuf);
        }
        hash_12_hex(hbuf[..], out);
    }

    out.push('_');

    // 8. Cookie Names Hash
    if cookie_names.len == 0 {
        out.append("000000000000");
    } else {
        var cbuf: u8[>..] = [];
        for i in cookie_names.len {
            if i > 0 { cbuf.push(','); }
            cbuf.append(cookie_names[i]);
        }
        hash_12_hex(cbuf[..], out);
    }

    out.push('_');

    // 9. Cookie Values Hash
    if cookie_values.len == 0 {
        out.append("000000000000");
    } else {
        var vbuf: u8[>..] = [];
        for i in cookie_values.len {
            if i > 0 { vbuf.push(','); }
            vbuf.append(cookie_values[i]);
        }
        hash_12_hex(vbuf[..], out);
    }
}

// Convenience wrapper for JA4H returning a fixed-capacity buffer.
fn compute_ja4h(
    method: const u8[:],
    proto: const u8[:],
    header_names: const u8[:][:],
    has_cookie: bool,
    has_referer: bool,
    accept_language: const u8[:] = "",
    cookie_names: const u8[:][:] = [],
    cookie_values: const u8[:][:] = [],
) -> u8[..64] {
    var out: u8[..64] = [];
    compute_ja4h(method, proto, header_names, has_cookie, has_referer, accept_language, cookie_names, cookie_values, out);
    return out;
}
