// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation DNS wire message codec conforming to RFC 1035 and RFC 2181.
// Supports wire message decoding, name compression pointer resolution, and query building.
namespace wing;

import std;
import core from "..";
import .svcb;

// ---- DNS Response & Query Models ----------------------------------------

// RFC 1035 Section 2.3.4: Size limits - maximum backward compression pointer hops over a 255-octet wire name
const DNS_MAX_POINTER_JUMPS: i64 = 127;

// RFC 1035 Section 3.2.2: TYPE values - canonical name for an alias
const DNS_QTYPE_CNAME: u16 = 5;

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

inline fn strip_fqdn_trailing_dot(domain: const u8[:]) -> const u8[:] {
    if domain.len > 1 && domain[domain.len - 1] == '.' {
        return domain[..^1];
    }
    return domain;
}

// Encodes a human-readable domain name (e.g. "example.com") into DNS label wire format.
//
// Example:
//   domain = "example.com", out = []
//   returns: true, out = "\x07example\x03com\x00"
fn dns_encode_name<B>(domain: const u8[:], out: B&) -> bool {
    let clean = strip_fqdn_trailing_dot(domain);
    guard core::validate_idna_domain_bounds(clean) else { return false; }
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };

    var start = 0;
    while start < clean.len {
        let rem = clean[start..];
        let rel_dot = rem.index_of_byte('.');
        let dot_pos = if rel_dot >= 0 { start + rel_dot } else { clean.len };
        let label_len = dot_pos - start;
        guard label_len > 0 && label_len <= 63 else { return false; }
        guard out.try_push(label_len as u8) else { return false; }
        guard out.try_append(clean[start..dot_pos]) else { return false; }
        start = dot_pos + 1;
    }

    guard out.try_push(0 as u8) else { return false; }
    committed = true;
    return true;
}

// Decodes a DNS domain name from raw wire format, resolving compression pointers (0xC0).
// Leaves `offset` unchanged if decoding fails.
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

        if (b & 0xC0) == 0xC0 {
            guard current_off + 1 < raw.len else { return false; }
            let ptr_off = (((b & 0x3F) as i64) << 8) | (raw[current_off + 1] as i64);
            // RFC 1035 Section 4.1.4: Message compression - pointers must point backwards past 12-byte header
            guard ptr_off < current_off && ptr_off >= 12 else { return false; }

            if !advanced_original {
                final_off = current_off + 2;
                advanced_original = true;
            }

            current_off = ptr_off;
            jumps += 1;
            guard jumps <= DNS_MAX_POINTER_JUMPS else { return false; }
            continue;
        }

        // RFC 1035 Section 2.3.4: Size limits - high 2 bits MUST be 00 and label length <= 63 octets
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

// RFC 9460 Section 2.5.1: AliasMode - TargetName in HTTPS/SVCB records MUST NOT use compression pointers.
// Leaves `offset` unchanged if decoding fails.
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
    let hdr: const u8[12] = [
        (tx_id >> 8) as u8, (tx_id & 0xFF) as u8,
        (flags >> 8) as u8, (flags & 0xFF) as u8,
        (qd_count >> 8) as u8, (qd_count & 0xFF) as u8,
        0, 0, 0, 0, 0, 0,
    ];
    let _ = out.try_append(hdr[..]);
}

fn serialize_dns_question<B>(domain: const u8[:], qtype: u16, qclass: u16, out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard dns_encode_name(domain, out) else { return false; }
    let tail: const u8[4] = [
        (qtype >> 8) as u8, (qtype & 0xFF) as u8,
        (qclass >> 8) as u8, (qclass & 0xFF) as u8,
    ];
    guard out.try_append(tail[..]) else { return false; }
    committed = true;
    return true;
}

// Builds a standard 12-byte header + question DNS query.
fn build_dns_query<B>(domain: const u8[:], qtype: u16, tx_id: u16, out: B&) -> bool {
    let clean = strip_fqdn_trailing_dot(domain);
    guard core::validate_idna_domain_bounds(clean) else { return false; }
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    serialize_dns_header(tx_id, 1, 0x0100, out);
    guard out.len == saved_len + 12 else { return false; }
    guard serialize_dns_question(clean, qtype, 1, out) else { return false; }
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
        var keep_rec = true;
        guard apply_https_svc_params_tail(raw[target_off..rdata_end], rec, keep_rec) else {
            return false;
        }
        if keep_rec {
            let _ = out.https_records.try_push(rec);
        }
    }
    return true;
}

// Skips `count` DNS Question entries while validating wire bounds (RFC 1035 Section 4.1.2).
// Rolls back `off` on failure.
//
// Example:
//   raw = "\x07example\x03com\x00\x00\x01\x00\x01", off = 0, count = 1
//   returns: true, off = 17
fn skip_dns_questions(raw: const u8[:], off: i64&, count: u16) -> bool {
    let saved_off = off;
    var committed = false;
    defer if !committed { off = saved_off; };
    for q in count {
        var qname: u8[..255] = [];
        guard dns_decode_name(raw, off, qname) else { return false; }
        guard off + 4 <= raw.len else { return false; }
        off += 4;
    }
    committed = true;
    return true;
}

// Parses `count` DNS Question entries and extracts the primary QNAME (RFC 1035 Section 4.1.2).
// Rolls back `off` and `first_qname` on failure.
//
// Example:
//   raw = "\x07example\x03com\x00\x00\x01\x00\x01", off = 0, count = 1
//   returns: true, off = 17, first_qname = "example.com"
fn parse_dns_questions(raw: const u8[:], off: i64&, count: u16, first_qname: u8[..255]&) -> bool {
    let saved_off = off;
    var committed = false;
    defer if !committed { off = saved_off; first_qname.clear(); };
    first_qname.clear();
    for q in count {
        var qname: u8[..255] = [];
        guard dns_decode_name(raw, off, qname) else { return false; }
        guard off + 4 <= raw.len else { return false; }
        if q == 0 {
            guard first_qname.try_set(qname[..]) else { return false; }
        }
        off += 4;
    }
    committed = true;
    return true;
}

// Skips `count` trailing DNS Resource Records while validating wire framing (RFC 1035 Section 4.1.3).
// Rolls back `off` on failure.
//
// Example:
//   raw = "\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00", off = 0, count = 1
//   returns: true, off = 11
fn skip_dns_records(raw: const u8[:], off: i64&, count: u32) -> bool {
    let saved_off = off;
    var committed = false;
    defer if !committed { off = saved_off; };
    for _ in count {
        var rname: u8[..255] = [];
        guard dns_decode_name(raw, off, rname) else { return false; }
        guard off + 10 <= raw.len else { return false; }
        let rdlength = (((raw[off + 8] as u16) << 8) | raw[off + 9]) as i64;
        off += 10;
        guard off + rdlength <= raw.len else { return false; }
        off += rdlength;
    }
    committed = true;
    return true;
}

inline fn apply_https_svc_params_tail(svc_params: const u8[:], rec: HttpsRecord&, keep_rec: bool&) -> bool {
    keep_rec = true;
    guard svc_params.len > 0 else { return true; }
    if rec.priority == 0 {
        // RFC 9460 Section 2.4.2: AliasMode - SvcParams ignored if well-formed, rejected if malformed
        return validate_svc_params_framing(svc_params);
    }
    let status, _ = parse_https_svc_params_status(svc_params, rec);
    guard status != SvcParamStatus.Malformed else { return false; }
    if status == SvcParamStatus.Incompatible {
        keep_rec = false;
    }
    return true;
}

inline fn prune_service_mode_when_alias_present(records: HttpsRecord[..4]&) {
    var has_alias = false;
    for &rec in records {
        if rec.priority == 0 {
            has_alias = true;
            break;
        }
    }
    guard has_alias else { return; }
    // RFC 9460 Section 2.4.1: SvcPriority - ServiceMode RRs MUST be ignored if AliasMode RR is present
    var write_idx: i64 = 0;
    for read_idx in records.len {
        if records[read_idx].priority == 0 {
            if write_idx != read_idx {
                records[write_idx] = records[read_idx];
            }
            write_idx += 1;
        }
    }
    records.resize(write_idx);
}

// Decodes a CNAME RDATA target domain name and verifies exact RDLENGTH consumption.
//
// Example:
//   raw = "\x03www\x07example\x03com\x00", rdata_off = 0, rdlength = 17
//   returns: true, out_target = "www.example.com"
inline fn decode_cname_rdata_target(
    raw:        const u8[:],
    rdata_off:  i64,
    rdlength:   i64,
    out_target: u8[..255]&,
) -> bool {
    var cname_off = rdata_off;
    guard dns_decode_name(raw, cname_off, out_target) else { return false; }
    return cname_off == rdata_off + rdlength;
}

// Parses DNS resource records from the Answer section (RFC 1035 Section 4.1.3).
// Rolls back `off` and `out` on failure.
//
// Example:
//   raw = dns_response_wire, off = 12, out = DnsResponse { answer_count: 1 }
//   returns: true, off advanced past answer section
fn parse_dns_answers(
    raw:            const u8[:],
    off:            i64&,
    out:            DnsResponse&,
    expected_qname: const u8[:] = "",
) -> bool {
    let saved_off = off;
    let saved_out = out;
    var committed = false;
    defer if !committed { off = saved_off; out = saved_out; };

    var expected_owner: u8[..255] = [];
    let check_owner = out.question_count > 0 && expected_qname.len > 0;
    if check_owner {
        guard expected_owner.try_set(expected_qname) else { return false; }
    }

    var has_ttl = false;
    for _ in out.answer_count {
        var aname: u8[..255] = [];
        guard dns_decode_name(raw, off, aname) else { return false; }
        guard off + 10 <= raw.len else { return false; }

        let rtype = ((raw[off] as u16) << 8) | raw[off + 1];
        let rclass = ((raw[off + 2] as u16) << 8) | raw[off + 3];
        let ttl_hi = ((raw[off + 4] as u32) << 24) | ((raw[off + 5] as u32) << 16);
        let raw_ttl = ttl_hi | ((raw[off + 6] as u32) << 8) | raw[off + 7];
        let ttl: u32 = if (raw_ttl & 0x80000000) != 0 { 0 } else { raw_ttl };
        let rdlength = (((raw[off + 8] as u16) << 8) | raw[off + 9]) as i64;
        off += 10;
        guard off + rdlength <= raw.len else { return false; }

        let owner_ok = !check_owner || aname[..].eq_ascii_fold(expected_owner[..]);
        if rclass == rfc::DNS_QCLASS_IN && owner_ok {
            if rtype == DNS_QTYPE_CNAME && check_owner {
                guard decode_cname_rdata_target(raw, off, rdlength, expected_owner) else { return false; }
            } else {
                guard parse_dns_answer_record(raw, rtype, rdlength, off, out) else { return false; }
            }
            if !has_ttl || ttl < out.min_ttl_sec {
                out.min_ttl_sec = ttl;
                has_ttl = true;
            }
        }
        off += rdlength;
    }
    prune_service_mode_when_alias_present(out.https_records);
    committed = true;
    return true;
}

// Parses a complete DNS response wire message (RFC 1035 Section 4.1.1).
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
    // RFC 1035 Section 4.1.1: Header section format - OPCODE MUST be 0 (standard query) and TC bit 0
    guard ((flags >> 11) & 0x0F) == 0 && (flags & 0x0200) == 0 else { return false; }
    out.rcode = (flags & 0x0F) as u8;

    out.question_count = ((raw[4] as u16) << 8) | raw[5];
    out.answer_count = ((raw[6] as u16) << 8) | raw[7];
    let ns_count = ((raw[8] as u16) << 8) | raw[9];
    let ar_count = ((raw[10] as u16) << 8) | raw[11];

    var off: i64 = 12;
    if out.rcode != rfc::DNS_RCODE_NOERROR {
        guard skip_dns_questions(raw, off, out.question_count) else { return false; }
        let trailing_rrs = (out.answer_count as u32) + ns_count + ar_count;
        if trailing_rrs > 0 {
            guard skip_dns_records(raw, off, trailing_rrs) else { return false; }
        }
        out.answer_count = 0;
        committed = true;
        return true;
    }

    var qname: u8[..255] = [];
    guard parse_dns_questions(raw, off, out.question_count, qname) else { return false; }
    guard parse_dns_answers(raw, off, out, qname[..]) else { return false; }
    let extra_rrs = (ns_count as u32) + ar_count;
    if extra_rrs > 0 {
        guard skip_dns_records(raw, off, extra_rrs) else { return false; }
    }
    committed = true;
    return true;
}
