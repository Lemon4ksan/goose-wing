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

// Encodes a human-readable domain name (e.g. "example.com") into DNS label wire format.
fn dns_encode_name<B>(domain: const u8[:], out: B&) -> bool {
    guard core::validate_idna_domain_bounds(domain) else { return false; }
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };

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
    committed = true;
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
    out.append_u16_be(tx_id);
    out.append_u16_be(flags);
    out.append_u16_be(qd_count);
    out.append_u16_be(0); // ANCOUNT = 0
    out.append_u16_be(0); // NSCOUNT = 0
    out.append_u16_be(0); // ARCOUNT = 0
}

fn serialize_dns_question<B>(domain: const u8[:], qtype: u16, qclass: u16, out: B&) -> bool {
    guard dns_encode_name(domain, out) else { return false; }
    out.append_u16_be(qtype);
    out.append_u16_be(qclass);
    return true;
}

// Builds a standard 12-byte header + question DNS query.
fn build_dns_query<B>(domain: const u8[:], qtype: u16, tx_id: u16, out: B&) -> bool {
    guard core::validate_idna_domain_bounds(domain) else { return false; }
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    serialize_dns_header(tx_id, 1, 0x0100, out);
    guard serialize_dns_question(domain, qtype, 1, out) else { return false; }
    committed = true;
    return true;
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
        var entry: u8[..16] = [];
        guard entry.try_set(s) && rec.alpns.try_push(entry) else { return false; }
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
        let hi = ((val[ip_off] as u32) << 24) | ((val[ip_off + 1] as u32) << 16);
        let lo = ((val[ip_off + 2] as u32) << 8) | val[ip_off + 3];
        guard rec.ipv4_hints.try_push(hi | lo) else { return false; }
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
        var ip6: u8[16] = [0; 16];
        for i in 16 { ip6[i] = val[ip_off + i]; }
        guard rec.ipv6_hints.try_push(ip6) else { return false; }
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
            guard val.len > 0 && rec.ech_config_list.try_set(val) else { return false; }
            rec.has_ech = true;
        }
    }
    guard off == rdata.len else { return false; }
    guard (mandatory_mask & seen_mask) == mandatory_mask else { return false; }
    // RFC 9460 §7.1.1 & §2.4.3: no-default-alpn requires alpn to be present
    guard !rec.no_default_alpn || rec.alpns.len > 0 else { return false; }
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
        guard rdlength == 4 else { return false; }
        let ip_hi = ((rdata[0] as u32) << 24) | ((rdata[1] as u32) << 16);
        let ip_lo = ((rdata[2] as u32) << 8) | rdata[3];
        let _ = out.a_records.try_push(ip_hi | ip_lo);
    } else if rtype == rfc::DNS_QTYPE_AAAA {
        guard rdlength == 16 else { return false; }
        var ip6: u8[16] = [0; 16];
        for i in 16 { ip6[i] = rdata[i]; }
        let _ = out.aaaa_records.try_push(ip6);
    } else if rtype == rfc::DNS_QTYPE_HTTPS {
        guard rdlength >= 3 else { return false; }
        var rec = HttpsRecord { .. };
        rec.priority = ((rdata[0] as u16) << 8) | rdata[1];
        var target_off = rdata_start + 2;
        let rdata_end = rdata_start + rdlength;
        guard dns_decode_uncompressed_name(raw, target_off, rdata_end, rec.target_name) else { return false; }
        guard target_off <= rdata_end else { return false; }
        // RFC 9460 §2.4.2: In AliasMode (priority == 0), recipients MUST ignore any SvcParams
        if target_off < rdata_end && rec.priority != 0 {
            let svc_params = raw[target_off..rdata_end];
            guard parse_https_svc_params(svc_params, rec) else { return false; }
        }
        let _ = out.https_records.try_push(rec);
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
        let ttl_hi = ((raw[off + 4] as u32) << 24) | ((raw[off + 5] as u32) << 16);
        let raw_ttl = ttl_hi | ((raw[off + 6] as u32) << 8) | raw[off + 7];
        // RFC 2181 §8: If MSB (0x80000000) is set, treat TTL as 0
        let ttl: u32 = if (raw_ttl & 0x80000000) != 0 { 0 } else { raw_ttl };
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

    let sep: const u8[:] = if !server_url.contains_byte('?') {
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
    lru_prev:        i32              = -1,
    lru_next:        i32              = -1,
}

struct DnsCache {
    entries:  DnsCacheEntry[..64] = [],
    lru_head: i32                 = -1,
    lru_tail: i32                 = -1,
}

// Detaches `idx` from the intrusive doubly-linked DNS LRU list in O(1).
fn detach_dns_lru(cache: DnsCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    let node .= cache.entries[idx as i64];
    let prev = node.lru_prev;
    let next = node.lru_next;
    if prev >= 0 {
        cache.entries[prev as i64].lru_next = next;
    } else if cache.lru_head == idx {
        cache.lru_head = next;
    }
    if next >= 0 {
        cache.entries[next as i64].lru_prev = prev;
    } else if cache.lru_tail == idx {
        cache.lru_tail = prev;
    }
    node.lru_prev = -1;
    node.lru_next = -1;
}

// Appends `idx` to the MRU tail (`lru_tail`) of the intrusive DNS LRU list in O(1).
fn attach_dns_lru_tail(cache: DnsCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    let node .= cache.entries[idx as i64];
    node.lru_prev = cache.lru_tail;
    node.lru_next = -1;
    if cache.lru_tail >= 0 {
        cache.entries[cache.lru_tail as i64].lru_next = idx;
    } else {
        cache.lru_head = idx;
    }
    cache.lru_tail = idx;
}

// Promotes `idx` to the MRU tail in O(1) (`OrderedDict.move_to_end` equivalent).
fn touch_dns_lru(cache: DnsCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    if cache.lru_tail == idx {
        return;
    }
    detach_dns_lru(cache, idx);
    attach_dns_lru_tail(cache, idx);
}

fn dns_cache_lookup(
    cache:     const DnsCache&,
    domain:    const u8[:],
    qtype:     u16,
    now_sec:   i64,
    out_entry: DnsCacheEntry&,
) -> DnsCacheStatus {
    for &e in cache.entries {
        if e.valid && e.qtype == qtype && e.domain[..].eq_ascii_fold(domain) {
            guard e.ttl_sec > 0 && now_sec >= e.inserted_at_sec else { return DnsCacheStatus.Expired; }
            let elapsed = core::sub_sat_i64(now_sec, e.inserted_at_sec);
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
    for i in cache.entries.len {
        let cur .= cache.entries[i];
        let is_match = cur.valid &&
            cur.qtype == entry.qtype &&
            cur.domain[..].eq_ascii_fold(entry.domain[..]);
        if is_match {
            let prev = cur.lru_prev;
            let next = cur.lru_next;
            cur = entry;
            cur.valid = true;
            cur.lru_prev = prev;
            cur.lru_next = next;
            touch_dns_lru(cache, i as i32);
            return;
        }
    }

    let new_idx = cache.entries.len as i32;
    var copy = entry;
    copy.valid = true;
    copy.lru_prev = -1;
    copy.lru_next = -1;
    if cache.entries.try_push(copy) {
        attach_dns_lru_tail(cache, new_idx);
    } else {
        let victim_idx: i32 = if cache.lru_head >= 0 && cache.lru_head < cache.entries.len {
            cache.lru_head
        } else {
            0
        };
        detach_dns_lru(cache, victim_idx);
        cache.entries[victim_idx as i64] = copy;
        attach_dns_lru_tail(cache, victim_idx);
    }
}
