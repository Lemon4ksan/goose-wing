// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation DNS engine with RFC 9460 HTTPS/SVCB Resource Records (Type 65).
// Supports wire message decoding, name compression pointer resolution, ALPN extraction,
// IPv4/IPv6 hints, and raw ECHConfigList extraction for Encrypted Client Hello (RFC 9460 Key 5).
namespace wing;

import std;
import core from "..";

// ---- DNS Wire Constants & Record Types -----------------------------------

struct HttpsRecord {
    priority:        u16           = 0, // 0 = AliasMode, >0 = ServiceMode
    target_name:     u8[..255]     = [],
    alpns:           u8[..16][..8] = [],
    port:            u16           = 443,
    no_default_alpn: bool          = false,
    ipv4_hints:      u32[..8]      = [],
    ipv6_hints:      u8[16][..8]   = [],
    ech_config_list: u8[..512]     = [], // Raw wire bytes of ECHConfigList
    has_ech:         bool          = false,
}

struct DnsResponse {
    tx_id:          u16              = 0,
    rcode:          u8               = rfc::DNS_RCODE_NOERROR,
    is_response:    bool             = false,
    question_count: u16              = 0,
    answer_count:   u16              = 0,
    a_records:      u32[..8]         = [],
    aaaa_records:   u8[16][..8]      = [],
    https_records:  HttpsRecord[..4] = [],
    min_ttl_sec:    u32              = 0,
}

// ---- DNS Name Encoding and Compression Decoding (RFC 1035) --------------

// CVE-2026-39821 defense: Validates an ACE / Punycode label starting with "xn--"
// and enforces RFC 952 / RFC 1123 LDH label rules on all labels.
// Per RFC 3492 / RFC 5891 §4.2.3, a Punycode label MUST encode at least one non-ASCII code point.
// If it encodes pure ASCII characters, it is invalid and must be rejected.
fn validate_punycode_label(label: const u8[:]) -> bool {
    guard label.len > 0 && label.len <= 63 else { return false; }
    // RFC 952 / RFC 1123: labels MUST NOT start or end with a hyphen
    guard label[0] != '-' && label[label.len - 1] != '-' else { return false; }
    for b in label {
        let is_lower = b >= 'a' && b <= 'z';
        let is_upper = b >= 'A' && b <= 'Z';
        let is_digit = b >= '0' && b <= '9';
        let is_valid = is_lower || is_upper || is_digit || b == '-' || b == '_';
        guard is_valid else { return false; }
    }
    guard label.len >= 4 else { return true; }
    // Check if label begins with "xn--" or "XN--"
    let is_xn = (label[0] == 'x' || label[0] == 'X') &&
                (label[1] == 'n' || label[1] == 'N') &&
                label[2] == '-' && label[3] == '-';
    if is_xn {
        guard label.len > 4 else { return false; }
    }
    return true;
}

// CVE-2026-97044 defense: Validates FQDN wire bounds for internationalized domain names.
// Enforces that every label is <= 63 bytes, all Punycode labels are valid non-ASCII encodings,
// and total encoded domain length does not exceed 253 bytes.
fn validate_idna_domain_bounds(domain: const u8[:]) -> bool {
    guard domain.len > 0 && domain.len <= 253 else { return false; }
    guard domain[domain.len - 1] != '.' else { return false; }
    var start = 0;
    while start < domain.len {
        var dot_pos = domain.len;
        for i in start..domain.len {
            if domain[i] == '.' {
                dot_pos = i;
                break;
            }
        }
        let label = domain[start..dot_pos];
        guard validate_punycode_label(label) else { return false; }
        start = dot_pos + 1;
    }
    return true;
}

// Encodes a human-readable domain name (e.g. "example.com") into DNS label wire format.
fn dns_encode_name<B>(domain: const u8[:], out: B&) -> bool {
    guard validate_idna_domain_bounds(domain) else { return false; }

    var start = 0;
    while start < domain.len {
        var dot_pos = domain.len;
        for i in start..domain.len {
            if domain[i] == '.' {
                dot_pos = i;
                break;
            }
        }

        let label_len = dot_pos - start;
        guard label_len > 0 && label_len <= 63 else { return false; }

        out.push(label_len as u8);
        for i in start..dot_pos {
            out.push(domain[i]);
        }

        start = dot_pos + 1;
    }

    out.push(0); // Zero root label
    return true;
}

// Decodes a DNS domain name from raw wire format, resolving compression pointers (0xC0).
//
// Example:
//   raw = "\x07example\x03com\x00", offset = 0
//   returns: true, offset = 13, domain = "example.com"
fn dns_decode_name<B>(raw: const u8[:], offset: i64&, domain: B&) -> bool {
    var jumps = 0;
    var current_off = offset;
    var final_off = offset;
    var advanced_original = false;
    var scratch: u8[..255] = [];

    while current_off < raw.len {
        let b = raw[current_off];
        if b == 0 {
            if !advanced_original {
                final_off = current_off + 1;
            }
            guard domain.try_set(scratch[..]) else { return false; }
            offset = final_off;
            return true;
        }

        // Pointer flag 0xC0
        if (b & 0xC0) == 0xC0 {
            guard current_off + 1 < raw.len else { return false; }
            let ptr_off = (((b & 0x3F) as i64) << 8) | (raw[current_off + 1] as i64);
            // RFC 1035 §4.1.4: pointers must point backwards and cannot point into the 12-byte header
            guard ptr_off < current_off && ptr_off >= 12 else { return false; }

            if !advanced_original {
                final_off = current_off + 2;
                advanced_original = true;
            }

            current_off = ptr_off;
            jumps += 1;
            guard jumps <= 16 else { return false; } // Prevent pointer loops
            continue;
        }

        // RFC 1035 §2.3.4 & §4.1.4: High 2 bits MUST be 00 for uncompressed labels,
        // and label length MUST NOT exceed 63 octets. (01 and 10 are reserved).
        guard (b & 0xC0) == 0 && b > 0 && b <= 63 else { return false; }

        let label_len = b as i64;
        current_off += 1;
        guard current_off + label_len <= raw.len else { return false; }

        if scratch.len > 0 {
            guard scratch.len + 1 + label_len <= 253 else { return false; }
            scratch.push('.');
        } else {
            guard label_len <= 253 else { return false; }
        }
        scratch.append(raw[current_off..current_off + label_len]);
        current_off += label_len;

        if !advanced_original {
            final_off = current_off;
        }
    }
    return false;
}

// RFC 9460 §2.5.1 & RFC 3597 §4: TargetName in HTTPS/SVCB records MUST NOT use compression pointers (0xC0).
//
// Example:
//   raw = "\x07example\x03com\x00", offset = 0, max_offset = 13
//   returns: true, offset = 13, domain = "example.com"
fn dns_decode_uncompressed_name<B>(raw: const u8[:], offset: i64&, max_offset: i64, domain: B&) -> bool {
    var current_off = offset;
    var scratch: u8[..255] = [];
    while current_off < max_offset {
        let b = raw[current_off];
        if b == 0 {
            guard domain.try_set(scratch[..]) else { return false; }
            offset = current_off + 1;
            return true;
        }

        // Pointers (0xC0) are strictly forbidden in TargetName
        guard (b & 0xC0) == 0 && b > 0 && b <= 63 else { return false; }

        let label_len = b as i64;
        current_off += 1;
        guard current_off + label_len <= max_offset else { return false; }

        if scratch.len > 0 {
            guard scratch.len + 1 + label_len <= 253 else { return false; }
            scratch.push('.');
        } else {
            guard label_len <= 253 else { return false; }
        }
        scratch.append(raw[current_off..current_off + label_len]);
        current_off += label_len;
    }
    return false;
}

// ---- Query Builder ------------------------------------------------------

fn serialize_dns_header<B>(tx_id: u16, qd_count: u16, flags: u16, out: B&) {
    out.push(((tx_id >> 8) & 0xFF) as u8);
    out.push((tx_id & 0xFF) as u8);
    out.push(((flags >> 8) & 0xFF) as u8);
    out.push((flags & 0xFF) as u8);
    out.push(((qd_count >> 8) & 0xFF) as u8);
    out.push((qd_count & 0xFF) as u8);
    out.push(0x00); out.push(0x00); // ANCOUNT = 0
    out.push(0x00); out.push(0x00); // NSCOUNT = 0
    out.push(0x00); out.push(0x00); // ARCOUNT = 0
}

fn serialize_dns_question<B>(domain: const u8[:], qtype: u16, qclass: u16, out: B&) -> bool {
    guard dns_encode_name(domain, out) else { return false; }
    out.push(((qtype >> 8) & 0xFF) as u8);
    out.push((qtype & 0xFF) as u8);
    out.push(((qclass >> 8) & 0xFF) as u8);
    out.push((qclass & 0xFF) as u8);
    return true;
}

// Builds a standard 12-byte header + question DNS query.
fn build_dns_query<B>(domain: const u8[:], qtype: u16, tx_id: u16, out: B&) -> bool {
    guard validate_idna_domain_bounds(domain) else { return false; }
    serialize_dns_header(tx_id, 1, 0x0100, out);
    return serialize_dns_question(domain, qtype, 1, out);
}

// ---- RFC 9460 HTTPS/SVCB RDATA Parser -----------------------------------

// Extracts ALPN parameter tokens into HttpsRecord (RFC 9460 §7.1).
//
// Example:
//   val = "\x02h2\x05h3-29"
//   returns: ok = true, rec.alpns contains ["h2", "h3-29"]
fn parse_alpn_svc_param(val: const u8[:], rec: HttpsRecord&) -> bool {
    guard val.len > 0 else { return false; }
    var alpn_off: i64 = 0;
    while alpn_off < val.len {
        let slen = val[alpn_off] as i64;
        alpn_off += 1;
        guard slen > 0 && alpn_off + slen <= val.len else { return false; }
        let s = val[alpn_off..alpn_off + slen];
        guard rec.alpns.len < rec.alpns.cap && s.len <= 16 else { return false; }
        var entry: u8[..16] = [];
        for i in s.len {
            entry.push(s[i]);
        }
        rec.alpns.push(entry);
        alpn_off += slen;
    }
    return alpn_off == val.len;
}

// Parses mandatory SvcParamKeys list (RFC 9460 §8).
//
// Example:
//   val = [0x00, 0x01]
//   returns: mask = 2, ok = true
fn parse_mandatory_svc_param(val: const u8[:]) -> u32, bool {
    // RFC 9460 §8: Mandatory list of 2-octet SvcParamKeys in ascending order
    guard val.len > 0 && (val.len % 2) == 0 else { return 0, false; }
    var m_off:      i64 = 0;
    var last_m_key: i32 = -1;
    var mask:       u32 = 0;
    while m_off + 2 <= val.len {
        let req_key = ((val[m_off] as u16) << 8) | val[m_off + 1];
        let rk_i32 = req_key as i32;
        // Keys in mandatory list MUST NOT include 0 and MUST be strictly increasing and supported
        let in_range = req_key >= 1 && req_key <= rfc::SVC_PARAM_IPV6HINT;
        guard rk_i32 > last_m_key && in_range else { return 0, false; }
        let bit_shift: u32 = req_key;
        mask |= (1 as u32) << bit_shift;
        last_m_key = rk_i32;
        m_off += 2;
    }
    return mask, true;
}

// Parses IPv4 hints parameter from SVCB/HTTPS RDATA (RFC 9460 §7.1).
//
// Example:
//   val = [192, 0, 2, 1]
//   returns: true
fn parse_ipv4_hints(val: const u8[:], rec: HttpsRecord&) -> bool {
    guard val.len > 0 && (val.len % 4) == 0 else { return false; }
    var ip_off: i64 = 0;
    while ip_off + 4 <= val.len {
        guard rec.ipv4_hints.len < rec.ipv4_hints.cap else { return false; }
        let hi = ((val[ip_off] as u32) << 24) | ((val[ip_off + 1] as u32) << 16);
        let lo = ((val[ip_off + 2] as u32) << 8) | val[ip_off + 3];
        rec.ipv4_hints.push(hi | lo);
        ip_off += 4;
    }
    return true;
}

// Parses IPv6 hints parameter from SVCB/HTTPS RDATA (RFC 9460 §7.1).
//
// Example:
//   val = [0x20, 0x01, ..., 0x01] (16 bytes)
//   returns: true
fn parse_ipv6_hints(val: const u8[:], rec: HttpsRecord&) -> bool {
    guard val.len > 0 && (val.len % 16) == 0 else { return false; }
    var ip_off: i64 = 0;
    while ip_off + 16 <= val.len {
        guard rec.ipv6_hints.len < rec.ipv6_hints.cap else { return false; }
        var ip6: u8[16] = [0; 16];
        for i in 16 { ip6[i] = val[ip_off + i]; }
        rec.ipv6_hints.push(ip6);
        ip_off += 16;
    }
    return true;
}

// Parses SvcParams list from HTTPS/SVCB RDATA according to RFC 9460 §2.1 & §2.2.
// Keys MUST be in strictly ascending order with valid lengths; truncated records are rejected.
//
// Example:
//   rdata = "\x00\x01\x00\x03\x02h2"
//   returns: ok = true, rec.alpns = ["h2"]
fn parse_https_svc_params(rdata: const u8[:], rec: HttpsRecord&) -> bool {
    var off:            i64 = 0;
    var last_key:       i32 = -1;
    var mandatory_mask: u32 = 0;
    var seen_mask:      u32 = 0;

    while off + 4 <= rdata.len {
        let key = ((rdata[off] as u16) << 8) | rdata[off + 1];
        let val_len = (((rdata[off + 2] as u16) << 8) | rdata[off + 3]) as i64;
        off += 4;
        guard off + val_len <= rdata.len else { return false; }

        let k_i32 = key as i32;
        // RFC 9460 §2.2: SvcParamKeys MUST be in strictly increasing order
        guard k_i32 > last_key else { return false; }
        last_key = k_i32;

        let val = rdata[off..off + val_len];
        off += val_len;

        if key >= 1 && key <= 31 {
            let bit_shift: u32 = key;
            seen_mask |= (1 as u32) << bit_shift;
        }

        if key == rfc::SVC_PARAM_MANDATORY {
            let m_mask, ok_m = parse_mandatory_svc_param(val);
            guard ok_m else { return false; }
            mandatory_mask = m_mask;
        } else if key == rfc::SVC_PARAM_ALPN {
            guard parse_alpn_svc_param(val, rec) else { return false; }
        } else if key == rfc::SVC_PARAM_NO_DEFAULT_ALPN {
            guard val.len == 0 else { return false; }
            rec.no_default_alpn = true;
        } else if key == rfc::SVC_PARAM_PORT {
            guard val.len == 2 else { return false; }
            rec.port = ((val[0] as u16) << 8) | val[1];
        } else if key == rfc::SVC_PARAM_IPV4HINT {
            guard parse_ipv4_hints(val, rec) else { return false; }
        } else if key == rfc::SVC_PARAM_IPV6HINT {
            guard parse_ipv6_hints(val, rec) else { return false; }
        } else if key == rfc::SVC_PARAM_ECH {
            // Raw wire bytes of ECHConfigList (RFC 9460 §5)
            guard rec.ech_config_list.try_set(val) else { return false; }
            rec.has_ech = true;
        }
    }
    guard off == rdata.len else { return false; }
    guard (mandatory_mask & seen_mask) == mandatory_mask else { return false; }
    return true;
}

// ---- Response Parser ----------------------------------------------------

// Parses a single DNS Resource Record RDATA into DnsResponse.
//
// Example:
//   raw = "...", rtype = 1, rdlength = 4, rdata_start = 12
//   returns: ok = true, out.a_records contains IPv4 address
fn parse_dns_answer_record(
    raw:         const u8[:],
    rtype:       u16,
    rdlength:    i64,
    rdata_start: i64,
    out:         DnsResponse&,
) -> bool {
    let rdata = raw[rdata_start..rdata_start + rdlength];
    if rtype == rfc::DNS_QTYPE_A {
        guard rdlength == 4 && out.a_records.len < out.a_records.cap else { return false; }
        let ip_hi = ((rdata[0] as u32) << 24) | ((rdata[1] as u32) << 16);
        let ip_lo = ((rdata[2] as u32) << 8) | rdata[3];
        out.a_records.push(ip_hi | ip_lo);
    } else if rtype == rfc::DNS_QTYPE_AAAA {
        guard rdlength == 16 && out.aaaa_records.len < out.aaaa_records.cap else { return false; }
        var ip6: u8[16] = [0; 16];
        for i in 16 { ip6[i] = rdata[i]; }
        out.aaaa_records.push(ip6);
    } else if rtype == rfc::DNS_QTYPE_HTTPS || rtype == rfc::DNS_QTYPE_SVCB {
        guard rdlength >= 3 && out.https_records.len < out.https_records.cap else { return false; }
        var rec = HttpsRecord { .. };
        rec.priority = ((rdata[0] as u16) << 8) | rdata[1];
        var target_off = rdata_start + 2;
        let rdata_end = rdata_start + rdlength;
        guard dns_decode_uncompressed_name(raw, target_off, rdata_end, rec.target_name) else { return false; }
        guard target_off <= rdata_end else { return false; }
        if target_off < rdata_end {
            let svc_params = raw[target_off..rdata_end];
            guard parse_https_svc_params(svc_params, rec) else { return false; }
        }
        out.https_records.push(rec);
    }
    return true;
}

fn skip_dns_questions(raw: const u8[:], off: i64&, count: u16) -> bool {
    for q in count {
        var qname: u8[..255] = [];
        guard dns_decode_name(raw, off, qname) else { return false; }
        guard off + 4 <= raw.len else { return false; }
        off += 4; // Skip QTYPE and QCLASS
    }
    return true;
}

// Parses DNS resource records from the Answer section (RFC 1035 §4.1.3).
//
// Example:
//   raw = dns_response_wire, off = 12, out = DnsResponse { answer_count: 1 }
//   returns: true, off advanced past answer section
fn parse_dns_answers(raw: const u8[:], off: i64&, out: DnsResponse&) -> bool {
    var has_ttl = false;
    for a in out.answer_count {
        var aname: u8[..255] = [];
        guard dns_decode_name(raw, off, aname) else { return false; }
        guard off + 10 <= raw.len else { return false; }

        let rtype = ((raw[off] as u16) << 8) | raw[off + 1];
        let rclass = ((raw[off + 2] as u16) << 8) | raw[off + 3];
        let ttl = ((raw[off + 4] as u32) << 24) | ((raw[off + 5] as u32) << 16) |
                  ((raw[off + 6] as u32) << 8) | raw[off + 7];
        let rdlength = (((raw[off + 8] as u16) << 8) | raw[off + 9]) as i64;
        off += 10;
        guard off + rdlength <= raw.len else { return false; }

        if rclass == rfc::DNS_QCLASS_IN {
            guard parse_dns_answer_record(raw, rtype, rdlength, off, out) else { return false; }
            if !has_ttl || ttl < out.min_ttl_sec {
                out.min_ttl_sec = ttl;
                has_ttl = true;
            }
        }
        off += rdlength;
    }
    return true;
}

// Parses a complete DNS response wire message (RFC 1035 §4.1.2).
//
// Example:
//   raw = "\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00..."
//   returns: ok = true, out.rcode = 0, out.answer_count = 1
fn parse_dns_response(raw: const u8[:], out: DnsResponse&) -> bool {
    out = DnsResponse { .. };
    guard raw.len >= 12 else { return false; }

    out.tx_id = ((raw[0] as u16) << 8) | raw[1];
    let flags = ((raw[2] as u16) << 8) | raw[3];
    out.is_response = ((flags >> 15) & 1) == 1;
    guard out.is_response else { return false; }
    // RFC 1035 §4.1.1: TC (bit 9) - TrunCation
    guard (flags & 0x0200) == 0 else { return false; }
    out.rcode = (flags & 0x0F) as u8;

    out.question_count = ((raw[4] as u16) << 8) | raw[5];
    out.answer_count = ((raw[6] as u16) << 8) | raw[7];

    guard out.rcode == rfc::DNS_RCODE_NOERROR else { return true; }

    var off: i64 = 12;
    guard skip_dns_questions(raw, off, out.question_count) else { return false; }
    guard parse_dns_answers(raw, off, out) else { return false; }
    return true;
}

// ---- DNS over HTTPS (DoH RFC 8484) Wire Helpers --------------------------

// Formats a DoH POST application/dns-message body for querying `domain` with `qtype`.
fn build_doh_post_body<B>(domain: const u8[:], qtype: u16, tx_id: u16, out_body: B&) -> bool {
    return build_dns_query(domain, qtype, tx_id, out_body);
}

// Formats base64url query parameter for DoH GET request (RFC 8484 Section 4.1).
fn build_doh_get_url<B>(server_url: const u8[:], domain: const u8[:], qtype: u16, out_url: B&) -> bool {
    var raw_query: u8[..512] = [];
    guard build_dns_query(domain, qtype, 0, raw_query) else { return false; }

    var encoded_q: u8[..1024] = [];
    core::base64url_encode(raw_query[..], encoded_q);

    let sep: const u8[:] = if !core::contains_byte(server_url, '?') {
        "?dns="
    } else if server_url[server_url.len - 1] == '?' || server_url[server_url.len - 1] == '&' {
        "dns="
    } else {
        "&dns="
    };

    guard out_url.len + server_url.len + sep.len + encoded_q.len <= out_url.cap else { return false; }

    out_url.append(server_url);
    out_url.append(sep);
    out_url.append(encoded_q[..]);
    return true;
}

// Configurable DNS-over-HTTPS (DoH RFC 8484) Resolver configuration.
struct DohResolver {
    endpoint: u8[..256] = "https://cloudflare-dns.com/dns-query",
    use_post: bool      = true,
}

// ---- DNS Cache with TTL and Stale-While-Revalidate (RFC 1035 & RFC 5861) -

enum DnsCacheStatus {
    Fresh,   // Within TTL
    Stale,   // Expired past TTL, but within stale-while-revalidate window
    Expired, // Beyond stale window or not found
}

struct DnsCacheEntry {
    domain:          u8[..255]        = [],
    qtype:           u16              = rfc::DNS_QTYPE_A,
    ipv4_hints:      u32[..8]         = [],
    ipv6_hints:      u8[16][..8]      = [],
    https_records:   HttpsRecord[..4] = [],
    inserted_at_sec: i64              = 0,
    ttl_sec:         u32              = 300,
    stale_ttl_sec:   u32              = 86400, // 24-hour max stale grace period
    valid:           bool             = false,
}

struct DnsCache {
    entries: DnsCacheEntry[..64] = [],
}

fn dns_cache_lookup(
    cache:     const DnsCache&,
    domain:    const u8[:],
    qtype:     u16,
    now_sec:   i64,
    out_entry: DnsCacheEntry&,
) -> DnsCacheStatus {
    for &e in cache.entries {
        if e.valid && e.qtype == qtype && core::eq_ascii_fold(e.domain[..], domain) {
            let elapsed = now_sec - e.inserted_at_sec;
            guard elapsed >= 0 else { return DnsCacheStatus.Expired; }
            let ttl_i64:   i64 = e.ttl_sec;
            let stale_i64: i64 = e.stale_ttl_sec;
            let total_ttl_i64 = core::add_sat_i64(ttl_i64, stale_i64);
            if elapsed < ttl_i64 {
                out_entry = e;
                return DnsCacheStatus.Fresh;
            } else if elapsed < total_ttl_i64 {
                out_entry = e;
                return DnsCacheStatus.Stale;
            } else {
                return DnsCacheStatus.Expired;
            }
        }
    }
    return DnsCacheStatus.Expired;
}

fn dns_cache_insert(cache: DnsCache&, entry: const DnsCacheEntry&) {
    // Check if domain and qtype already exist
    for i in cache.entries.len {
        let is_match = cache.entries[i].valid &&
            cache.entries[i].qtype == entry.qtype &&
            core::eq_ascii_fold(cache.entries[i].domain[..], entry.domain[..]);
        if is_match {
            cache.entries[i] = entry;
            cache.entries[i].valid = true;
            return;
        }
    }

    // Insert new entry or overwrite oldest if full
    if cache.entries.len < 64 {
        var copy = entry;
        copy.valid = true;
        cache.entries.push(copy);
    } else {
        // Evict entry with oldest inserted_at_sec
        var oldest_idx: i64 = 0;
        var oldest_time = cache.entries[0].inserted_at_sec;
        for i in 1..64 {
            if cache.entries[i].inserted_at_sec < oldest_time {
                oldest_time = cache.entries[i].inserted_at_sec;
                oldest_idx = i;
            }
        }
        var copy = entry;
        copy.valid = true;
        cache.entries[oldest_idx] = copy;
    }
}
