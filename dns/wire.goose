// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation DNS wire message codec conforming to RFC 1035 and RFC 2181.
// Supports wire message decoding, name compression pointer resolution, and query building.
namespace dns;

import std;
import core;
import .svcb;
import .internal;

// ---- DNS Response Model -------------------------------------------------

struct Response {
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
// Leaves `out` unchanged on failure.
//
// Example:
//   domain = "example.com", out = []
//   returns: true, out = "\x07example\x03com\x00"
fn encode_name<B>(domain: const u8[:], out: B&) -> bool {
    let clean = dns_internal::strip_trailing_dot(domain);
    guard core::validate_idna_domain_bounds(clean) else { return false; }
    return dns_internal::encode_clean_name(clean, out);
}

// Decodes a DNS domain name from raw wire format, resolving compression pointers (0xC0).
// Leaves `idx` and `out` unchanged if decoding fails.
//
// Example:
//   raw = "\x07example\x03com\x00", idx = 0
//   returns: true, idx = 13, out = "example.com"
fn decode_name<B>(raw: const u8[:], idx: i64&, out: B&) -> bool {
    guard idx >= 0 && idx < raw.len else { return false; }
    var jumps = 0;
    var current_off = idx;
    var final_off = idx;
    var advanced_original = false;
    var scratch: u8[..255] = [];

    while current_off < raw.len {
        let b = raw[current_off];
        if b == 0 {
            if !advanced_original {
                final_off = current_off + 1;
            }
            guard out.try_set(scratch[..]) else { return false; }
            idx = final_off;
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
            guard jumps <= dns_internal::MAX_POINTER_JUMPS else { return false; }
            continue;
        }

        guard dns_internal::append_wire_label(raw, current_off, raw.len, scratch) else {
            return false;
        }
        if !advanced_original {
            final_off = current_off;
        }
    }
    return false;
}

// ---- Query Building and Response Parsing --------------------------------

// Builds a standard 12-byte header + question DNS query.
// Leaves `out` unchanged on failure.
fn build_query<B>(domain: const u8[:], qtype: u16, tx_id: u16, out: B&) -> bool {
    let clean = dns_internal::strip_trailing_dot(domain);
    guard core::validate_idna_domain_bounds(clean) else { return false; }
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard dns_internal::serialize_header(tx_id, 1, 0x0100, out) else { return false; }
    guard dns_internal::serialize_question(clean, qtype, 1, out) else { return false; }
    committed = true;
    return true;
}

// Parses a complete DNS response wire message (RFC 1035 Section 4.1.1).
//
// Example:
//   raw = "\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00..."
//   returns: Response { rcode: 0, answer_count: 1, .. }, true
fn parse_response(raw: const u8[:]) -> Response, bool {
    guard raw.len >= 12 else { return Response { .. }, false; }
    let flags = core::read_be_u16(raw, 2);
    let is_resp = ((flags >> 15) & 1) == 1;
    // RFC 1035 Section 4.1.1: Header section format - OPCODE MUST be 0 (standard query) and TC bit 0
    guard is_resp && ((flags >> 11) & 0x0F) == 0 && (flags & 0x0200) == 0 else {
        return Response { .. }, false;
    }

    var resp = Response {
        tx_id:          core::read_be_u16(raw, 0),
        rcode:          (flags & 0x0F) as u8,
        is_response:    true,
        question_count: core::read_be_u16(raw, 4),
        answer_count:   core::read_be_u16(raw, 6),
        ..
    };
    let ns_count = core::read_be_u16(raw, 8);
    let ar_count = core::read_be_u16(raw, 10);

    var off: i64 = 12;
    if resp.rcode != rfc::DNS_RCODE_NOERROR {
        guard dns_internal::skip_questions(raw, off, resp.question_count) else {
            return Response { .. }, false;
        }
        let trailing_rrs = (resp.answer_count as u32) + ns_count + ar_count;
        if trailing_rrs > 0 {
            guard dns_internal::skip_records(raw, off, trailing_rrs) else {
                return Response { .. }, false;
            }
        }
        resp.answer_count = 0;
        return resp, true;
    }

    let qname, ok_q = dns_internal::parse_questions(raw, off, resp.question_count);
    guard ok_q else { return Response { .. }, false; }
    guard dns_internal::parse_answers(resp, raw, off, qname[..]) else {
        return Response { .. }, false;
    }
    let extra_rrs = (ns_count as u32) + ar_count;
    if extra_rrs > 0 {
        guard dns_internal::skip_records(raw, off, extra_rrs) else {
            return Response { .. }, false;
        }
    }
    return resp, true;
}
