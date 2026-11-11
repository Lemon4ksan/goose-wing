// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation DNS wire message codec conforming to RFC 1035 and RFC 2181.
// Supports wire message decoding, name compression pointer resolution, and query building.
namespace wing;

import std;
import core from "..";
import .svcb;

// ---- DNS Response & Query Models ----------------------------------------

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
    var committed = false;
    defer if !committed { out = DnsResponse { .. }; };
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

    if out.rcode != rfc::DNS_RCODE_NOERROR {
        committed = true;
        return true;
    }

    var off: i64 = 12;
    guard skip_dns_questions(raw, off, out.question_count) else { return false; }
    guard parse_dns_answers(raw, off, out) else { return false; }
    committed = true;
    return true;
}
