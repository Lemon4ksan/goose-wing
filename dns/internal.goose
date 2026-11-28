// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers, constants, and LRU/wire mechanics for package `dns`.
namespace dns_internal;

import std;
import core;
import rfc.dns;
import .svcb;
import .wire;
import .cache;

// ---- Internal Protocol Ceilings & Types ---------------------------------

// RFC 1035 Section 2.3.4: Size limits - maximum backward compression pointer hops over a 255-octet wire name
const MAX_POINTER_JUMPS:        i64 = 127;
const MAX_PACKET_POINTER_JUMPS: i64 = 512;
const MAX_CNAME_CHAIN_HOPS:     i64 = 8;
const MAX_TOTAL_PACKET_RRS:     u32 = 1024;

enum SvcParamStatus {
    Ok,
    Incompatible,
    Malformed,
}

struct SvcParamParseFlags {
    saw_alpn:     bool = false,
    ech_dropped:  bool = false,
    incompatible: bool = false,
}

// ---- Intrusive DNS Cache LRU Mechanics (RFC 5861) -----------------------

// Detaches `idx` from the intrusive doubly-linked DNS LRU list in O(1).
fn detach_lru(cache: dns::Cache&, idx: i32) {
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
fn attach_lru_tail(cache: dns::Cache&, idx: i32) {
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
fn touch_lru(cache: dns::Cache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    if cache.lru_tail == idx {
        return;
    }
    detach_lru(cache, idx);
    attach_lru_tail(cache, idx);
}

inline fn init_slot_at_tail(cache: dns::Cache&, idx: i32) {
    let cur .= cache.entries[idx as i64];
    cur.valid = true;
    cur.lru_prev = -1;
    cur.lru_next = -1;
    attach_lru_tail(cache, idx);
}

inline fn place_entry_at_tail(cache: dns::Cache&, idx: i32, entry: const dns::CacheEntry&) {
    cache.entries[idx as i64] = entry;
    init_slot_at_tail(cache, idx);
}

// Decodes a big-endian u16 from `s` at `off` after proving 2-byte wire bounds.
checkfree inline fn read_dns_u16(s: const u8[:], off: i64) -> u16 {
    if off < 0 || off > s.len { return 0; }
    let tail = s[off..];
    if tail.len < 2 { return 0; }
    return ((tail[0] as u16) << 8) | tail[1];
}

// Decodes a big-endian u32 from `s` at `off` after proving 4-byte wire bounds.
checkfree inline fn read_dns_u32(s: const u8[:], off: i64) -> u32 {
    if off < 0 || off > s.len { return 0; }
    let tail = s[off..];
    if tail.len < 4 { return 0; }
    let hi = read_dns_u16(tail, 0) as u32;
    let lo = read_dns_u16(tail[2..], 0) as u32;
    return (hi << 16) | lo;
}

// ---- RFC 9460 HTTPS/SVCB RDATA Helpers ----------------------------------

// Extracts ALPN parameter tokens into HttpsRecord (RFC 9460 Section 7.1.1).
//
// Example:
//   val = "\x02h2\x05h3-29"
//   returns: ok = true, rec.alpns contains ["h2", "h3-29"]
checkfree fn parse_alpn_param(rec: dns::HttpsRecord&, val: const u8[:]) -> bool {
    let saved_len = rec.alpns.len;
    var committed = false;
    defer if !committed { rec.alpns.resize(saved_len); };
    guard val.len > 0 else { return false; }
    var alpn_off: i64      = 0;
    var entry:    u8[..32] = [];
    while alpn_off < val.len {
        let slen = val[alpn_off] as i64;
        alpn_off += 1;
        let end = alpn_off + slen;
        guard slen > 0 && end <= val.len else { return false; }
        let s = val[alpn_off..end];
        if s.len <= 32 && rec.alpns.len < rec.alpns.cap {
            entry.clear();
            entry.append(s);
            rec.alpns.push(entry);
        } else {
            // RFC 9460 Section 7.1.1: skip ALPN tokens exceeding local storage slots or 32-byte limit.
        }
        alpn_off = end;
    }
    committed = alpn_off == val.len;
    return committed;
}

// Parses IPv4 hints parameter from SVCB/HTTPS RDATA (RFC 9460 Section 7.1.1).
//
// Example:
//   val = [192, 0, 2, 1]
//   returns: true
checkfree fn parse_ipv4_hints(rec: dns::HttpsRecord&, val: const u8[:]) -> bool {
    let saved_len = rec.ipv4_hints.len;
    var committed = false;
    defer if !committed { rec.ipv4_hints.resize(saved_len); };
    guard val.len > 0 && (val.len & 3) == 0 else { return false; }
    var ip_off: i64 = 0;
    while ip_off + 4 <= val.len {
        if rec.ipv4_hints.len < rec.ipv4_hints.cap {
            rec.ipv4_hints.push(read_dns_u32(val, ip_off));
        } else {
            // RFC 9460 Section 7.1.1: skip IPv4 hints exceeding local storage slots.
        }
        ip_off += 4;
    }
    committed = true;
    return true;
}

// Parses IPv6 hints parameter from SVCB/HTTPS RDATA (RFC 9460 Section 7.1.1).
//
// Example:
//   val = [0x20, 0x01, ..., 0x01] (16 bytes)
//   returns: true
checkfree fn parse_ipv6_hints(rec: dns::HttpsRecord&, val: const u8[:]) -> bool {
    let saved_len = rec.ipv6_hints.len;
    var committed = false;
    defer if !committed { rec.ipv6_hints.resize(saved_len); };
    guard val.len > 0 && (val.len & 15) == 0 else { return false; }
    var ip_off: i64    = 0;
    var ip6:    u8[16] = [0; 16];
    while ip_off <= val.len - 16 {
        if rec.ipv6_hints.len < rec.ipv6_hints.cap {
            for i in 16 { ip6[i] = val[ip_off + i]; }
            rec.ipv6_hints.push(ip6);
        } else {
            // RFC 9460 Section 7.1.1: skip IPv6 hints exceeding local storage slots.
        }
        ip_off += 16;
    }
    committed = true;
    return true;
}

// Validates wire framing and ascending SvcParamKey order without mutating record state (RFC 9460 Section 2.2).
//
// Example:
//   rdata = "\x00\x03\x00\x02\x01\xbb"
//   returns: true
checkfree fn validate_svc_params_framing(rdata: const u8[:]) -> bool {
    var off:      i64 = 0;
    var last_key: i32 = -1;
    while off + 4 <= rdata.len {
        let key = read_dns_u16(rdata, off) as i32;
        let val_len = read_dns_u16(rdata, off + 2) as i64;
        off += 4;
        // RFC 9460 Section 2.1 / 2.2: SvcParamKeys MUST be strictly increasing; key 65535 is reserved/invalid.
        guard key > last_key && key < 65535 && off + val_len <= rdata.len else { return false; }
        last_key = key;
        off += val_len;
    }
    return off == rdata.len;
}

checkfree inline fn reset_svc_params(rec: dns::HttpsRecord&) {
    rec.alpns.clear();
    rec.port = 443;
    rec.no_default_alpn = false;
    rec.ipv4_hints.clear();
    rec.ipv6_hints.clear();
    rec.ech_config_list.clear();
    rec.has_ech = false;
}

checkfree inline fn apply_known_svc_param(
    rec:   dns::HttpsRecord&,
    key:   u16,
    val:   const u8[:],
    flags: SvcParamParseFlags&,
) -> bool {
    if key == rfc::SVC_PARAM_ALPN {
        guard rec.parse_alpn_param(val) else { return false; }
        flags.saw_alpn = true;
        if rec.alpns.len == 0 {
            // RFC 9460 Section 7.1.2: Use - RR is incompatible when no advertised ALPN protocol is supported
            flags.incompatible = true;
        }
    } else if key == rfc::SVC_PARAM_NO_DEFAULT_ALPN {
        guard val.len == 0 else { return false; }
        rec.no_default_alpn = true;
    } else if key == rfc::SVC_PARAM_PORT {
        guard val.len == 2 else { return false; }
        rec.port = read_dns_u16(val, 0);
    } else if key == rfc::SVC_PARAM_IPV4HINT {
        guard rec.parse_ipv4_hints(val) else { return false; }
    } else if key == rfc::SVC_PARAM_IPV6HINT {
        guard rec.parse_ipv6_hints(val) else { return false; }
    } else if key == rfc::SVC_PARAM_ECH {
        guard val.len > 0 else { return false; }
        if val.len <= rec.ech_config_list.cap {
            rec.ech_config_list.clear();
            rec.ech_config_list.append(val);
            rec.has_ech = true;
        } else {
            flags.ech_dropped = true;
        }
    }
    return true;
}

// Parses SvcParams list into HttpsRecord, distinguishing incompatible mandatory keys from wire corruption.
//
// Example:
//   rdata = "\x00\x01\x00\x03\x02h2"
//   returns: SvcParamStatus.Ok, ok = true, rec.alpns = ["h2"]
checkfree fn parse_https_svc_params_status(rec: dns::HttpsRecord&, rdata: const u8[:]) -> SvcParamStatus, bool {
    let saved_rec = rec;
    var committed = false;
    defer if !committed { rec = saved_rec; };
    rec.reset_svc_params();

    var off:      i64 = 0;
    var last_key: i32 = -1;
    var mand_off: i64 = 0;
    var mand_end: i64 = 0;
    var flags = SvcParamParseFlags { .. };

    while off + 4 <= rdata.len {
        let key = read_dns_u16(rdata, off);
        let val_len = read_dns_u16(rdata, off + 2) as i64;
        off += 4;
        let val_start = off;
        let val_end = val_start + val_len;
        guard key > last_key && key < 65535 && val_start >= 0 && val_start <= val_end && val_end <= rdata.len else {
            return SvcParamStatus.Malformed, false;
        }
        last_key = key;
        let val = rdata[val_start..val_end];
        off = val_end;

        if key == rfc::SVC_PARAM_MANDATORY {
            let mand, ok_m = dns::parse_mandatory_svc_param(val);
            guard ok_m else { return SvcParamStatus.Malformed, false; }
            mand_off = val_start;
            mand_end = off;
            if mand.has_unsupported { flags.incompatible = true; }
            continue;
        }
        if mand_off + 2 <= mand_end {
            let req_key = read_dns_u16(rdata, mand_off);
            guard key <= req_key else { return SvcParamStatus.Malformed, false; }
            if key == req_key { mand_off += 2; }
        }
        guard rec.apply_known_svc_param(key, val, flags) else {
            return SvcParamStatus.Malformed, false;
        }
    }
    guard off == rdata.len && mand_off == mand_end else { return SvcParamStatus.Malformed, false; }
    // RFC 9460 Section 7.1.1: Representation - "no-default-alpn" MUST NOT appear without "alpn"
    guard !rec.no_default_alpn || flags.saw_alpn else { return SvcParamStatus.Malformed, false; }
    if flags.incompatible || flags.ech_dropped {
        return SvcParamStatus.Incompatible, false;
    }
    committed = true;
    return SvcParamStatus.Ok, true;
}

// ---- DNS Wire Helpers (RFC 1035 & RFC 2181) -----------------------------

checkfree inline fn strip_trailing_dot(domain: const u8[:]) -> const u8[:] {
    if domain.len > 1 && domain[domain.len - 1] == '.' {
        return domain[..^1];
    }
    return domain;
}

checkfree inline fn is_valid_wire_label(label: const u8[:]) -> bool {
    for b in label {
        if b <= 0x20 || b >= 0x7F || b == '.' {
            return false;
        }
    }
    return true;
}

checkfree inline fn copy_dns_name_out<B>(out: B&, src: const u8[:]) -> bool {
    guard src.len >= 0 && src.len <= out.cap else { return false; }
    out.clear();
    out.append(src);
    return true;
}

checkfree inline fn copy_dns_name_out(out: u8[>..]&, src: const u8[:]) -> bool {
    guard src.len >= 0 && src.len <= 255 else { return false; }
    out.clear();
    out.append(src);
    return true;
}

checkfree inline fn dns_names_eq_fold(a: const u8[:], b: const u8[:]) -> bool {
    guard a.len == b.len else { return false; }
    for i in a.len {
        let ca = if a[i] >= 'A' && a[i] <= 'Z' { a[i] | 0x20 } else { a[i] };
        let cb = if b[i] >= 'A' && b[i] <= 'Z' { b[i] | 0x20 } else { b[i] };
        if ca != cb { return false; }
    }
    return true;
}

checkfree inline fn append_wire_label(
    raw:         const u8[:],
    current_off: i64&,
    max_off:     i64,
    scratch:     u8[..255]&,
) -> bool {
    let cur = current_off;
    guard cur >= 0 && max_off <= raw.len && cur < max_off else { return false; }
    let b = raw[cur];
    // RFC 1035 Section 2.3.4: Size limits - high 2 bits MUST be 00 and label length <= 63 octets
    guard (b & 0xC0) == 0 && b > 0 && b <= 63 else { return false; }

    let label_len = b as i64;
    let start_off = cur + 1;
    let end_off = start_off + label_len;
    guard start_off >= 0 && start_off <= end_off && end_off <= max_off else { return false; }
    let label_bytes = raw[start_off..end_off];
    guard is_valid_wire_label(label_bytes) else { return false; }

    if scratch.len > 0 {
        guard scratch.len + 1 + label_len <= 253 else { return false; }
        scratch.push('.');
    } else {
        guard label_len <= 253 else { return false; }
    }
    scratch.append(label_bytes);
    current_off = end_off;
    return true;
}

fn encode_clean_name<B>(clean: const u8[:], out: B&) -> bool {
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

// RFC 9460 Section 2.5.1: AliasMode - TargetName in HTTPS/SVCB records MUST NOT use compression pointers.
// Leaves `idx` and `out` unchanged if decoding fails.
//
// Example:
//   raw = "\x07example\x03com\x00", idx = 0, max_off = 13
//   returns: true, idx = 13, out = "example.com"
checkfree fn decode_uncompressed_name<B>(raw: const u8[:], idx: i64&, max_off: i64, out: B&) -> bool {
    guard idx >= 0 && max_off <= raw.len && idx < max_off else { return false; }
    var current_off = idx;
    var scratch: u8[..255] = [];
    while current_off >= 0 && current_off < max_off {
        if raw[current_off] == 0 {
            guard copy_dns_name_out(out, scratch[..]) else { return false; }
            idx = current_off + 1;
            return true;
        }
        guard append_wire_label(raw, current_off, max_off, scratch) else { return false; }
    }
    return false;
}

fn serialize_header<B>(tx_id: u16, qd_count: u16, flags: u16, out: B&) -> bool {
    let hdr: const u8[12] = [
        (tx_id >> 8) as u8, (tx_id & 0xFF) as u8,
        (flags >> 8) as u8, (flags & 0xFF) as u8,
        (qd_count >> 8) as u8, (qd_count & 0xFF) as u8,
        0, 0, 0, 0, 0, 0,
    ];
    return out.try_append(hdr[..]);
}

fn serialize_question<B>(clean: const u8[:], qtype: u16, qclass: u16, out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard encode_clean_name(clean, out) else { return false; }
    let tail: const u8[4] = [
        (qtype >> 8) as u8, (qtype & 0xFF) as u8,
        (qclass >> 8) as u8, (qclass & 0xFF) as u8,
    ];
    guard out.try_append(tail[..]) else { return false; }
    committed = true;
    return true;
}

checkfree inline fn apply_https_svc_params_tail(
    rec:        dns::HttpsRecord&,
    svc_params: const u8[:],
    keep_rec:   bool&,
) -> bool {
    keep_rec = true;
    guard svc_params.len > 0 else { return true; }
    if rec.priority == 0 {
        // RFC 9460 Section 2.4.2: AliasMode - SvcParams ignored if well-formed, rejected if malformed
        return validate_svc_params_framing(svc_params);
    }
    let status, _ = rec.parse_https_svc_params_status(svc_params);
    guard status != SvcParamStatus.Malformed else { return false; }
    if status == SvcParamStatus.Incompatible {
        keep_rec = false;
    }
    return true;
}

// Decodes a DNS wire name while charging compression pointer hops against `rem_jumps`.
// Leaves `idx` and `out` unchanged on failure.
//
// Example:
//   raw = "\x07example\x03com\x00", idx = 0, rem_jumps = 512
//   returns: true, idx = 13, out = "example.com"
checkfree fn decode_name_with_budget<B>(
    raw:       const u8[:],
    idx:       i64&,
    rem_jumps: i64&,
    out:       B&,
) -> bool {
    guard raw.len <= rfc::DOH_MAX_MESSAGE_OCTETS && idx >= 0 && idx < raw.len else {
        return false;
    }
    var jumps: i64 = 0;
    var current_off = idx;
    var final_off = idx;
    var advanced_original = false;
    var scratch: u8[..255] = [];

    while current_off >= 0 && current_off < raw.len {
        let b = raw[current_off];
        if b == 0 {
            if !advanced_original { final_off = current_off + 1; }
            guard copy_dns_name_out(out, scratch[..]) else { return false; }
            idx = final_off;
            return true;
        }
        if (b & rfc::DNS_POINTER_TAG) == rfc::DNS_POINTER_TAG {
            guard current_off < raw.len - 1 else { return false; }
            let ptr_off = (((b & 0x3F) as i64) << 8) | (raw[current_off + 1] as i64);
            // RFC 1035 Section 4.1.4: Message compression - pointers must point backwards past 12-byte header
            guard ptr_off < current_off && ptr_off >= rfc::DNS_HEADER_LEN else { return false; }
            if !advanced_original {
                final_off = current_off + 2;
                advanced_original = true;
            }
            current_off = ptr_off;
            jumps += 1;
            guard jumps <= MAX_POINTER_JUMPS && rem_jumps > 0 else { return false; }
            rem_jumps -= 1;
            continue;
        }
        guard append_wire_label(raw, current_off, raw.len, scratch) else { return false; }
        if !advanced_original { final_off = current_off; }
    }
    return false;
}

// Parses a single DNS Resource Record RDATA into `resp`.
//
// Example:
//   raw = "...", rtype = 1, rdlength = 4, rdata_start = 12
//   returns: true, resp.a_records contains IPv4 address
checkfree fn parse_answer_record(
    resp:        dns::Response&,
    raw:         const u8[:],
    owner_name:  const u8[:],
    rtype:       u16,
    rdlength:    i64,
    rdata_start: i64,
    saw_alias:   bool&,
) -> bool {
    let rdata_end = rdata_start + rdlength;
    guard rdata_start >= 0 && rdlength >= 0 && rdata_start <= rdata_end && rdata_end <= raw.len else {
        return false;
    }
    let rdata = raw[rdata_start..rdata_end];
    if rtype == rfc::DNS_QTYPE_A {
        guard rdata.len == 4 else { return false; }
        let ip4 = read_dns_u32(rdata, 0);
        if resp.a_records.len < resp.a_records.cap {
            resp.a_records.push(ip4);
        } else {
            // Bounded to 8 A records per response; extra records are validated and ignored.
        }
    } else if rtype == rfc::DNS_QTYPE_AAAA {
        guard rdata.len == 16 else { return false; }
        var ip6: u8[16] = [0; 16];
        for i in 16 { ip6[i] = rdata[i]; }
        if resp.aaaa_records.len < resp.aaaa_records.cap {
            resp.aaaa_records.push(ip6);
        } else {
            // Bounded to 8 AAAA records per response; extra records are validated and ignored.
        }
    } else if rtype == rfc::DNS_QTYPE_HTTPS {
        guard rdata.len >= 3 else { return false; }
        var rec = dns::HttpsRecord { priority: read_dns_u16(rdata, 0), .. };
        var target_off = rdata_start + 2;
        guard decode_uncompressed_name(raw, target_off, rdata_end, rec.target_name) else {
            return false;
        }
        guard target_off >= 0 && target_off <= rdata_end else { return false; }
        if rec.priority == 0 && rec.target_name.len > 0 &&
            dns_names_eq_fold(rec.target_name[..], owner_name) {
            return false;
        }
        var keep_rec = true;
        guard rec.apply_https_svc_params_tail(raw[target_off..rdata_end], keep_rec) else {
            return false;
        }
        if keep_rec {
            if rec.priority == 0 && !saw_alias {
                // RFC 9460 Section 2.4.1: ServiceMode RRs MUST be ignored if AliasMode RR is present
                resp.https_records.clear();
                saw_alias = true;
            }
            let accept = rec.priority == 0 || !saw_alias;
            if accept && resp.https_records.len < resp.https_records.cap {
                resp.https_records.push(rec);
            } else {
                // Bounded to 4 HTTPS records per response; ignored or excess validated.
            }
        }
    }
    return true;
}

// Skips `count` DNS Question entries while validating wire bounds (RFC 1035 Section 4.1.2).
// Rolls back `idx` on failure.
//
// Example:
//   raw = "\x07example\x03com\x00\x00\x01\x00\x01", idx = 0, count = 1, rem_jumps = 512
//   returns: true, idx = 17
checkfree fn skip_questions(
    raw:       const u8[:],
    idx:       i64&,
    count:     u16,
    rem_jumps: i64&,
) -> bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    var qname: u8[..255] = [];
    for _ in count {
        guard decode_name_with_budget(raw, idx, rem_jumps, qname) else { return false; }
        guard idx + 4 <= raw.len else { return false; }
        idx += 4;
    }
    committed = true;
    return true;
}

// Parses `count` DNS Question entries and returns primary QNAME, QTYPE, QCLASS (RFC 1035 §4.1.2).
// Rolls back `idx` on failure.
//
// Example:
//   raw = "\x07example\x03com\x00\x00\x01\x00\x01", idx = 0, count = 1, rem_jumps = 512
//   returns: "example.com", 1, 1, true (idx = 17)
checkfree fn parse_questions(
    raw:       const u8[:],
    idx:       i64&,
    count:     u16,
    rem_jumps: i64&,
) -> u8[..255], u16, u16, bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    var first_qname: u8[..255] = [];
    var first_qtype: u16       = 0;
    var first_qcls:  u16       = 0;
    var qname:       u8[..255] = [];
    for q in count {
        guard decode_name_with_budget(raw, idx, rem_jumps, qname) else {
            return [], 0, 0, false;
        }
        let pos = idx;
        guard pos >= 0 && pos <= raw.len && pos + 4 <= raw.len else { return [], 0, 0, false; }
        let qtype = read_dns_u16(raw[pos..], 0);
        let qclass = read_dns_u16(raw[pos..], 2);
        guard qclass == rfc::DNS_QCLASS_IN else { return [], 0, 0, false; }
        if q == 0 {
            guard copy_dns_name_out(first_qname, qname[..]) else { return [], 0, 0, false; }
            first_qtype = qtype;
            first_qcls = qclass;
        }
        idx += 4;
    }
    committed = true;
    return first_qname, first_qtype, first_qcls, true;
}

// Skips `count` trailing DNS Resource Records while validating wire framing (RFC 1035 Section 4.1.3).
// Rolls back `idx` on failure.
//
// Example:
//   raw = "\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00", idx = 0, count = 1, rem_jumps = 512
//   returns: true, idx = 11
checkfree fn skip_records(
    raw:       const u8[:],
    idx:       i64&,
    count:     u32,
    rem_jumps: i64&,
) -> bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };
    var rname: u8[..255] = [];
    for _ in count {
        guard decode_name_with_budget(raw, idx, rem_jumps, rname) else { return false; }
        guard idx + 10 <= raw.len else { return false; }
        let rdlength = read_dns_u16(raw, idx + 8) as i64;
        idx += 10;
        guard idx + rdlength <= raw.len else { return false; }
        idx += rdlength;
    }
    committed = true;
    return true;
}

checkfree inline fn is_dns_name_in_list(name: const u8[:], list: const u8[..255][:]) -> bool {
    for &item in list {
        if dns_names_eq_fold(name, item[..]) {
            return true;
        }
    }
    return false;
}

// Decodes a CNAME RDATA target domain name and verifies exact RDLENGTH consumption.
//
// Example:
//   raw = "\x03www\x07example\x03com\x00", rdata_off = 0, rdlength = 17, rem_jumps = 512
//   returns: true, target = "www.example.com"
checkfree inline fn decode_cname_rdata_target(
    raw:       const u8[:],
    rdata_off: i64,
    rdlength:  i64,
    rem_jumps: i64&,
    target:    u8[..255]&,
) -> bool {
    var cname_off = rdata_off;
    guard decode_name_with_budget(raw, cname_off, rem_jumps, target) else { return false; }
    return cname_off == rdata_off + rdlength;
}

checkfree inline fn advance_cname_chain(
    raw:          const u8[:],
    rdata_off:    i64,
    rdlength:     i64,
    rem_jumps:    i64&,
    owner:        u8[..255]&,
    seen_owners:  u8[..255][..9]&,
    cname_owners: u8[..255][..8]&,
) -> bool {
    guard cname_owners.len < MAX_CNAME_CHAIN_HOPS else { return false; }
    var next_target: u8[..255] = [];
    guard decode_cname_rdata_target(raw, rdata_off, rdlength, rem_jumps, next_target) else {
        return false;
    }
    guard next_target.len > 0 && !is_dns_name_in_list(next_target[..], seen_owners[..]) else {
        return false;
    }
    guard cname_owners.try_push(copy(owner)) && seen_owners.try_push(copy(next_target)) else {
        return false;
    }
    owner = copy(next_target);
    return true;
}

// Parses DNS resource records from the Answer section (RFC 1035 Section 4.1.3).
// Rolls back `idx` and `resp` on failure.
//
// Example:
//   raw = dns_response_wire, idx = 12, resp = dns::Response { answer_count: 1 }
//   returns: true, idx advanced past answer section
checkfree fn parse_answers(
    resp:           dns::Response&,
    raw:            const u8[:],
    idx:            i64&,
    expected_qname: const u8[:],
    rem_jumps:      i64&,
) -> bool {
    var expected_owner: u8[..255] = [];
    if resp.answer_count > 0 {
        guard resp.question_count == 1 && expected_qname.len > 0 else { return false; }
        guard copy_dns_name_out(expected_owner, expected_qname) else { return false; }
    } else {
        return true;
    }

    let saved_idx = idx;
    let saved_resp = resp;
    var committed = false;
    defer if !committed { idx = saved_idx; resp = saved_resp; };

    var seen_owners:  u8[..255][..9] = [];
    var cname_owners: u8[..255][..8] = [];
    guard seen_owners.try_push(copy(expected_owner)) else { return false; }
    var saw_non_cname = false;
    var saw_alias = false;
    var has_ttl = false;
    var aname: u8[..255] = [];
    for _ in resp.answer_count {
        guard decode_name_with_budget(raw, idx, rem_jumps, aname) else { return false; }
        guard idx + 10 <= raw.len else { return false; }

        let rtype = read_dns_u16(raw, idx);
        let rclass = read_dns_u16(raw, idx + 2);
        let raw_ttl = read_dns_u32(raw, idx + 4);
        let rdlength = read_dns_u16(raw, idx + 8) as i64;
        idx += 10;
        guard idx + rdlength <= raw.len else { return false; }

        if rclass != rfc::DNS_QCLASS_IN {
            idx += rdlength;
            continue;
        }
        let owner_ok = dns_names_eq_fold(aname[..], expected_owner[..]);
        if !owner_ok {
            let is_rr = rtype == rfc::DNS_QTYPE_A || rtype == rfc::DNS_QTYPE_AAAA ||
                rtype == rfc::DNS_QTYPE_HTTPS || rtype == rfc::DNS_QTYPE_CNAME;
            guard !(is_rr && is_dns_name_in_list(aname[..], cname_owners[..])) else {
                return false;
            }
            idx += rdlength;
            continue;
        }
        if rtype == rfc::DNS_QTYPE_CNAME {
            guard !saw_non_cname && advance_cname_chain(
                raw, idx, rdlength, rem_jumps, expected_owner, seen_owners, cname_owners,
            ) else { return false; }
        } else if rtype == resp.qtype {
            if rtype == rfc::DNS_QTYPE_A || rtype == rfc::DNS_QTYPE_AAAA ||
                rtype == rfc::DNS_QTYPE_HTTPS {
                saw_non_cname = true;
            }
            guard resp.parse_answer_record(
                raw, expected_owner[..], rtype, rdlength, idx, saw_alias,
            ) else { return false; }
        } else {
            idx += rdlength;
            continue;
        }
        let ttl: u32 = if (raw_ttl & 0x80000000) != 0 { 0 } else { raw_ttl };
        if !has_ttl || ttl < resp.min_ttl_sec {
            resp.min_ttl_sec = ttl;
            has_ttl = true;
        }
        idx += rdlength;
    }
    committed = true;
    return true;
}
