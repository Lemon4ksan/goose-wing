// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation DNS engine with RFC 9460 HTTPS/SVCB Resource Records (Type 65).
// Supports wire message decoding, name compression pointer resolution, ALPN extraction,
// IPv4/IPv6 hints, and raw ECHConfigList extraction for Encrypted Client Hello (RFC 9460 Key 5).
namespace wing;

import std;
import core from "..";

// ---- 1. DNS Wire Constants & Record Types -----------------------------------

const DNS_QTYPE_A: u16 = 1;
const DNS_QTYPE_AAAA: u16 = 28;
const DNS_QTYPE_SVCB: u16 = 64;  // RFC 9460
const DNS_QTYPE_HTTPS: u16 = 65; // RFC 9460

const DNS_QCLASS_IN: u16 = 1;

const DNS_RCODE_NOERROR: u8 = 0;
const DNS_RCODE_FORMERR: u8 = 1;
const DNS_RCODE_SERVFAIL: u8 = 2;
const DNS_RCODE_NXDOMAIN: u8 = 3;

// RFC 9460 SvcParamKey Registrations (Section 14.3)
const SVC_PARAM_MANDATORY: u16 = 0;
const SVC_PARAM_ALPN: u16 = 1;
const SVC_PARAM_NO_DEFAULT_ALPN: u16 = 2;
const SVC_PARAM_PORT: u16 = 3;
const SVC_PARAM_IPV4HINT: u16 = 4;
const SVC_PARAM_ECH: u16 = 5; // Encrypted Client Hello ECHConfigList
const SVC_PARAM_IPV6HINT: u16 = 6;

// ---- 2. Data Structures ----------------------------------------------------

struct HttpsRecord {
    priority: u16 = 0,               // 0 = AliasMode, >0 = ServiceMode
    target_name: u8[..255] = [],
    alpns: u8[..16][..8] = [],
    port: u16 = 443,
    no_default_alpn: bool = false,
    ipv4_hints: u32[..8] = [],
    ipv6_hints: u8[16][..8] = [],
    ech_config_list: u8[..512] = [], // Raw wire bytes of ECHConfigList
    has_ech: bool = false,
}

struct DnsResponse {
    tx_id: u16 = 0,
    rcode: u8 = DNS_RCODE_NOERROR,
    is_response: bool = false,
    question_count: u16 = 0,
    answer_count: u16 = 0,
    a_records: u32[..8] = [],
    aaaa_records: u8[16][..8] = [],
    https_records: HttpsRecord[..4] = [],
    min_ttl_sec: u32 = 0,
}

// ---- 3. DNS Name Encoding and Compression Decoding (RFC 1035) --------------

// CVE-2026-39821 defense: Validates an ACE / Punycode label starting with "xn--".
// Per RFC 3492 / RFC 5891 §4.2.3, a Punycode label MUST encode at least one non-ASCII code point.
// If it encodes pure ASCII characters, it is invalid and must be rejected.
fn validate_punycode_label(label: const u8[:]) -> bool {
    guard label.len >= 4 else { return true; }
    // Check if label begins with "xn--" or "XN--"
    if (label[0] == 'x' || label[0] == 'X') &&
       (label[1] == 'n' || label[1] == 'N') &&
       label[2] == '-' && label[3] == '-' {
        // Label after "xn--" cannot be empty or exceed 63 bytes total
        guard label.len > 4 && label.len <= 63 else { return false; }
        let payload = label[4..];

        // In Punycode, if there is a delimiter '-', the portion before '-' is literal ASCII,
        // and the portion after '-' contains the base-36 delta encodings.
        // If there is NO delimiter '-', the entire payload is base-36 delta encodings.
        // If the payload ends with '-' (e.g. "xn--test-"), there are NO non-ASCII deltas!
        // That means it encodes pure ASCII, which is an invalid ACE label (CVE-2026-39821).
        if payload[payload.len - 1] == '-' {
            return false;
        }

        // Verify all characters are valid LDH (letters, digits, hyphen)
        for b in payload {
            let is_ldh = (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-';
            guard is_ldh else { return false; }
        }
    }
    return true;
}

// CVE-2026-97044 defense: Validates FQDN wire bounds for internationalized domain names.
// Enforces that every label is <= 63 bytes, all Punycode labels are valid non-ASCII encodings,
// and total encoded domain length does not exceed 253 bytes.
fn validate_idna_domain_bounds(domain: const u8[:]) -> bool {
    guard domain.len > 0 && domain.len <= 253 else { return false; }
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
        guard label.len > 0 && label.len <= 63 else { return false; }
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
fn dns_decode_name<B>(raw: const u8[:], offset: i64&, out: B&) -> bool {
    var jumps = 0;
    var current_off = offset;
    var advanced_original = false;

    while current_off < raw.len {
        let b = raw[current_off];
        if b == 0 {
            if !advanced_original {
                offset = current_off + 1;
            }
            return true;
        }

        // Pointer flag 0xC0
        if (b & 0xC0) == 0xC0 {
            guard current_off + 1 < raw.len else { return false; }
            let ptr_off = (((b & 0x3F) as i64) << 8) | (raw[current_off + 1] as i64);
            // RFC 1035 §4.1.4: pointers must point backwards and cannot point into the 12-byte header
            guard ptr_off < current_off && ptr_off >= 12 else { return false; }

            if !advanced_original {
                offset = current_off + 2;
                advanced_original = true;
            }

            current_off = ptr_off;
            jumps += 1;
            guard jumps <= 16 else { return false; } // Prevent pointer loops
            continue;
        }

        // RFC 1035 §2.3.4 & §4.1.4: High 2 bits MUST be 00 for uncompressed labels,
        // and label length MUST NOT exceed 63 octets. (01 and 10 are reserved).
        guard (b & 0xC0) == 0 && b <= 63 else { return false; }

        let label_len = b;
        current_off += 1;
        guard current_off + label_len <= raw.len else { return false; }

        if out.len > 0 {
            guard out.len + 1 + (label_len as i64) <= 253 else { return false; }
            out.push('.');
        } else {
            guard (label_len as i64) <= 253 else { return false; }
        }
        for i in current_off..current_off + label_len {
            guard out.len < 253 else { return false; }
            out.push(raw[i]);
        }
        current_off += label_len;

        if !advanced_original {
            offset = current_off;
        }
    }
    return false;
}

// RFC 9460 §2.5.1 & RFC 3597 §4: TargetName in HTTPS/SVCB records MUST NOT use compression pointers (0xC0).
fn dns_decode_uncompressed_name<B>(raw: const u8[:], offset: i64&, max_offset: i64, out: B&) -> bool {
    var current_off = offset;
    while current_off < max_offset {
        let b = raw[current_off];
        if b == 0 {
            offset = current_off + 1;
            return true;
        }

        // Pointers (0xC0) are strictly forbidden in TargetName
        guard (b & 0xC0) == 0 && b <= 63 else { return false; }

        let label_len = b as i64;
        current_off += 1;
        guard current_off + label_len <= max_offset else { return false; }

        if out.len > 0 {
            guard out.len + 1 + label_len <= 253 else { return false; }
            out.push('.');
        } else {
            guard label_len <= 253 else { return false; }
        }
        for i in current_off..current_off + label_len {
            guard out.len < 253 else { return false; }
            out.push(raw[i]);
        }
        current_off += label_len;
    }
    return false;
}

// ---- 4. Query Builder ------------------------------------------------------

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
    serialize_dns_header(tx_id, 1, 0x0100, out);
    return serialize_dns_question(domain, qtype, 1, out);
}

// ---- 5. RFC 9460 HTTPS/SVCB RDATA Parser -----------------------------------

// Parses SvcParams list from HTTPS/SVCB RDATA according to RFC 9460 Section 2.1 & 2.2.
// Keys MUST be in strictly ascending order with valid lengths; truncated records are rejected.
fn parse_https_svc_params(rdata: const u8[:], rec: HttpsRecord&) -> bool {
    var off: i64 = 0;
    var last_key: i32 = -1;

    while off + 4 <= rdata.len {
        let key = ((rdata[off] as u16) << 8) | rdata[off + 1];
        let val_len = (((rdata[off + 2] as u16) << 8) | rdata[off + 3]) as i64;
        off += 4;
        guard off + val_len <= rdata.len else { return false; }

        let k_i32 = key as i32;
        // RFC 9460 Section 2.2: SvcParamKeys MUST be in strictly increasing order
        guard k_i32 > last_key else { return false; }
        last_key = k_i32;

        let val = rdata[off..off + val_len];
        off += val_len;

        if key == SVC_PARAM_ALPN {
            guard val.len > 0 else { return false; }
            var alpn_off: i64 = 0;
            while alpn_off < val.len {
                let slen = val[alpn_off] as i64;
                alpn_off += 1;
                guard slen > 0 && alpn_off + slen <= val.len else { return false; }
                let s = val[alpn_off..alpn_off + slen];
                if rec.alpns.len < rec.alpns.cap {
                    var entry: u8[..16] = [];
                    for i in s.len {
                        if entry.len < entry.cap { entry.push(s[i]); }
                    }
                    rec.alpns.push(entry);
                }
                alpn_off += slen;
            }
            guard alpn_off == val.len else { return false; }
        } else if key == SVC_PARAM_NO_DEFAULT_ALPN {
            guard val.len == 0 else { return false; }
            rec.no_default_alpn = true;
        } else if key == SVC_PARAM_PORT {
            guard val.len == 2 else { return false; }
            rec.port = ((val[0] as u16) << 8) | val[1];
        } else if key == SVC_PARAM_IPV4HINT {
            guard val.len > 0 && (val.len % 4) == 0 else { return false; }
            var ip_off: i64 = 0;
            while ip_off + 4 <= val.len && rec.ipv4_hints.len < rec.ipv4_hints.cap {
                let ip = ((val[ip_off] as u32) << 24) |
                         ((val[ip_off + 1] as u32) << 16) |
                         ((val[ip_off + 2] as u32) << 8) |
                         val[ip_off + 3];
                rec.ipv4_hints.push(ip);
                ip_off += 4;
            }
        } else if key == SVC_PARAM_IPV6HINT {
            guard val.len > 0 && (val.len % 16) == 0 else { return false; }
            var ip_off: i64 = 0;
            while ip_off + 16 <= val.len && rec.ipv6_hints.len < rec.ipv6_hints.cap {
                var ip6: u8[16] = [0; 16];
                for i in 16 { ip6[i] = val[ip_off + i]; }
                rec.ipv6_hints.push(ip6);
                ip_off += 16;
            }
        } else if key == SVC_PARAM_ECH {
            // Raw wire bytes of ECHConfigList (RFC 9460 Section 5)
            guard val.len <= rec.ech_config_list.cap else { return false; }
            rec.has_ech = true;
            for i in val.len {
                rec.ech_config_list.push(val[i]);
            }
        }
    }
    guard off == rdata.len else { return false; }
    return true;
}

// ---- 6. Response Parser ----------------------------------------------------

// Parses a complete DNS response wire message.
fn parse_dns_response(raw: const u8[:], out: DnsResponse&) -> bool {
    guard raw.len >= 12 else { return false; }

    out.tx_id = ((raw[0] as u16) << 8) | raw[1];
    let flags = ((raw[2] as u16) << 8) | raw[3];
    out.is_response = ((flags >> 15) & 1) == 1;
    out.rcode = (flags & 0x0F) as u8;

    out.question_count = ((raw[4] as u16) << 8) | raw[5];
    out.answer_count = ((raw[6] as u16) << 8) | raw[7];
    out.min_ttl_sec = if out.answer_count > 0 { 0xFFFFFFFF } else { 0 };

    guard out.rcode == DNS_RCODE_NOERROR else { return true; }

    var off: i64 = 12;

    // Skip question section
    for q in out.question_count {
        var qname: u8[..255] = [];
        guard dns_decode_name(raw, off, qname) else { return false; }
        guard off + 4 <= raw.len else { return false; }
        off += 4; // Skip QTYPE and QCLASS
    }

    // Parse answer section
    for a in out.answer_count {
        var aname: u8[..255] = [];
        guard dns_decode_name(raw, off, aname) else { return false; }
        guard off + 10 <= raw.len else { return false; }

        let rtype = ((raw[off] as u16) << 8) | raw[off + 1];
        let rclass = ((raw[off + 2] as u16) << 8) | raw[off + 3];
        let ttl = ((raw[off + 4] as u32) << 24) | ((raw[off + 5] as u32) << 16) |
                  ((raw[off + 6] as u32) << 8) | raw[off + 7];
        if ttl < out.min_ttl_sec {
            out.min_ttl_sec = ttl;
        }
        let rdlength = (((raw[off + 8] as u16) << 8) | raw[off + 9]) as i64;
        off += 10;
        guard off + rdlength <= raw.len else { return false; }

        let rdata_start = off;
        let rdata = raw[off..off + rdlength];
        off += rdlength;

        if rtype == DNS_QTYPE_A {
            guard rdlength == 4 else { return false; }
            if out.a_records.len < out.a_records.cap {
                let ip4 = ((rdata[0] as u32) << 24) | ((rdata[1] as u32) << 16) |
                          ((rdata[2] as u32) << 8) | rdata[3];
                out.a_records.push(ip4);
            }
        } else if rtype == DNS_QTYPE_AAAA {
            guard rdlength == 16 else { return false; }
            if out.aaaa_records.len < out.aaaa_records.cap {
                var ip6: u8[16] = [0; 16];
                for i in 16 { ip6[i] = rdata[i]; }
                out.aaaa_records.push(ip6);
            }
        } else if rtype == DNS_QTYPE_HTTPS || rtype == DNS_QTYPE_SVCB {
            guard rdlength >= 3 else { return false; }
            if out.https_records.len < out.https_records.cap {
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
        }
    }

    return true;
}

// ---- 7. DNS over HTTPS (DoH RFC 8484) Wire Helpers --------------------------

// Formats a DoH POST application/dns-message body for querying `domain` with `qtype`.
fn build_doh_post_body<B>(domain: const u8[:], qtype: u16, tx_id: u16, out_body: B&) -> bool {
    return build_dns_query(domain, qtype, tx_id, out_body);
}

// Formats base64url query parameter for DoH GET request (RFC 8484 Section 4.1).
fn build_doh_get_url<B>(server_url: const u8[:], domain: const u8[:], qtype: u16, out_url: B&) -> bool {
    var raw_query: u8[..512] = [];
    guard build_dns_query(domain, qtype, 0, raw_query) else { return false; }

    out_url.append(server_url);
    out_url.append("?dns=");
    core::base64url_encode(raw_query[..], out_url);
    return true;
}

// Configurable DNS-over-HTTPS (DoH RFC 8484) Resolver configuration.
struct DohResolver {
    endpoint: u8[..256] = "https://cloudflare-dns.com/dns-query",
    use_post: bool = true,
}

fn new_doh_resolver(endpoint: const u8[:] = "https://cloudflare-dns.com/dns-query", use_post: bool = true) -> DohResolver {
    var r = DohResolver { use_post: use_post, .. };
    r.endpoint.append(endpoint);
    return r;
}

// ---- 8. DNS Cache with TTL and Stale-While-Revalidate (RFC 1035 & RFC 5861) -

enum DnsCacheStatus {
    Fresh,   // Within TTL
    Stale,   // Expired past TTL, but within stale-while-revalidate window
    Expired, // Beyond stale window or not found
}

struct DnsCacheEntry {
    domain: u8[..255] = [],
    qtype: u16 = DNS_QTYPE_A,
    ipv4_hints: u32[..8] = [],
    ipv6_hints: u8[16][..8] = [],
    https_records: HttpsRecord[..4] = [],
    inserted_at_sec: i64 = 0,
    ttl_sec: u32 = 300,
    stale_ttl_sec: u32 = 86400, // 24-hour max stale grace period
    valid: bool = false,
}

struct DnsCache {
    entries: DnsCacheEntry[..64] = [],
}

fn dns_cache_lookup(
    cache: const DnsCache&,
    domain: const u8[:],
    qtype: u16,
    now_sec: i64,
    out_entry: DnsCacheEntry&,
) -> DnsCacheStatus {
    for &e in cache.entries {
        if e.valid && e.qtype == qtype && e.domain[..] == domain {
            let elapsed = now_sec - e.inserted_at_sec;
            if elapsed < e.ttl_sec {
                out_entry = e;
                return DnsCacheStatus.Fresh;
            } else if elapsed < (e.ttl_sec + e.stale_ttl_sec) {
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
        if cache.entries[i].valid && cache.entries[i].qtype == entry.qtype && cache.entries[i].domain[..] == entry.domain[..] {
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
