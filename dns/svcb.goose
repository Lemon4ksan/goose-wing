// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation RFC 9460 HTTPS/SVCB Resource Records (Type 65) parser.
// Supports ALPN extraction, IPv4/IPv6 hints, SvcParams ordering, and raw ECHConfigList.
namespace wing;

import std;
import core from "..";

// ---- DNS Wire Constants & Record Types -----------------------------------

enum SvcParamStatus {
    Ok,
    Incompatible,
    Malformed,
}

struct HttpsRecord {
    priority:        u16           = 0, // 0 = AliasMode, >0 = ServiceMode
    target_name:     u8[..255]     = [],
    alpns:           u8[..64][..8] = [],
    port:            u16           = 443,
    no_default_alpn: bool          = false,
    ipv4_hints:      u32[..8]      = [],
    ipv6_hints:      u8[16][..8]   = [],
    ech_config_list: u8[..512]     = [], // Raw wire bytes of ECHConfigList
    has_ech:         bool          = false,
}

// ---- RFC 9460 HTTPS/SVCB RDATA Parser -----------------------------------

// Extracts ALPN parameter tokens into HttpsRecord (RFC 9460 Section 7.1.1).
//
// Example:
//   val = "\x02h2\x05h3-29"
//   returns: ok = true, rec.alpns contains ["h2", "h3-29"]
fn parse_alpn_svc_param(val: const u8[:], rec: HttpsRecord&) -> bool {
    let saved_len = rec.alpns.len;
    var committed = false;
    defer if !committed { rec.alpns.resize(saved_len); };
    guard val.len > 0 else { return false; }
    var alpn_off: i64 = 0;
    while alpn_off < val.len {
        let slen = val[alpn_off] as i64;
        alpn_off += 1;
        guard slen > 0 && alpn_off + slen <= val.len else { return false; }
        let s = val[alpn_off..alpn_off + slen];
        if s.len <= 64 && rec.alpns.len < rec.alpns.cap {
            var entry: u8[..64] = [];
            guard entry.try_set(s) && rec.alpns.try_push(entry) else { return false; }
        }
        alpn_off += slen;
    }
    committed = alpn_off == val.len;
    return committed;
}

// Validates mandatory SvcParamKeys list ordering and reports unsupported keys (RFC 9460 Section 8).
//
// Example:
//   val = [0x00, 0x01]
//   returns: has_unsupported = false, has_ech_mand = false, ok = true
fn parse_mandatory_svc_param(val: const u8[:]) -> bool, bool, bool {
    // RFC 9460 Section 8: ServiceMode RR Compatibility and Mandatory Keys - ascending 2-octet keys > 0
    guard val.len > 0 && (val.len & 1) == 0 else { return false, false, false; }
    var m_off:           i64  = 0;
    var last_m_key:      i32  = -1;
    var has_unsupported: bool = false;
    var has_ech_mand:    bool = false;
    while m_off + 2 <= val.len {
        let req_key = ((val[m_off] as u16) << 8) | val[m_off + 1];
        let rk_i32 = req_key as i32;
        guard req_key >= 1 && rk_i32 > last_m_key else { return false, false, false; }
        if req_key > rfc::SVC_PARAM_IPV6HINT {
            has_unsupported = true;
        } else if req_key == rfc::SVC_PARAM_ECH {
            has_ech_mand = true;
        }
        last_m_key = rk_i32;
        m_off += 2;
    }
    return has_unsupported, has_ech_mand, true;
}

// Parses IPv4 hints parameter from SVCB/HTTPS RDATA (RFC 9460 Section 7.1.1).
//
// Example:
//   val = [192, 0, 2, 1]
//   returns: true
fn parse_ipv4_hints(val: const u8[:], rec: HttpsRecord&) -> bool {
    let saved_len = rec.ipv4_hints.len;
    var committed = false;
    defer if !committed { rec.ipv4_hints.resize(saved_len); };
    guard val.len > 0 && (val.len % 4) == 0 else { return false; }
    var ip_off: i64 = 0;
    while ip_off + 4 <= val.len {
        let hi = ((val[ip_off] as u32) << 24) | ((val[ip_off + 1] as u32) << 16);
        let lo = ((val[ip_off + 2] as u32) << 8) | val[ip_off + 3];
        guard rec.ipv4_hints.try_push(hi | lo) else { return false; }
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
fn parse_ipv6_hints(val: const u8[:], rec: HttpsRecord&) -> bool {
    let saved_len = rec.ipv6_hints.len;
    var committed = false;
    defer if !committed { rec.ipv6_hints.resize(saved_len); };
    guard val.len > 0 && (val.len % 16) == 0 else { return false; }
    var ip_off: i64 = 0;
    while ip_off + 16 <= val.len {
        var ip6: u8[16] = [0; 16];
        for i in 16 { ip6[i] = val[ip_off + i]; }
        guard rec.ipv6_hints.try_push(ip6) else { return false; }
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
fn validate_svc_params_framing(rdata: const u8[:]) -> bool {
    var off:      i64 = 0;
    var last_key: i32 = -1;
    while off + 4 <= rdata.len {
        let key = (((rdata[off] as u16) << 8) | rdata[off + 1]) as i32;
        let val_len = (((rdata[off + 2] as u16) << 8) | rdata[off + 3]) as i64;
        off += 4;
        // RFC 9460 Section 2.2: RDATA Wire Format - SvcParamKeys MUST be in strictly increasing numeric order
        guard key > last_key && off + val_len <= rdata.len else { return false; }
        last_key = key;
        off += val_len;
    }
    return off == rdata.len;
}

inline fn reset_https_record_svc_params(rec: HttpsRecord&) {
    rec.alpns.clear();
    rec.port = 443;
    rec.no_default_alpn = false;
    rec.ipv4_hints.clear();
    rec.ipv6_hints.clear();
    rec.ech_config_list.clear();
    rec.has_ech = false;
}

inline fn apply_known_svc_param(
    key:          u16,
    val:          const u8[:],
    rec:          HttpsRecord&,
    saw_alpn:     bool&,
    ech_dropped:  bool&,
    incompatible: bool&,
) -> bool {
    if key == rfc::SVC_PARAM_ALPN {
        guard parse_alpn_svc_param(val, rec) else { return false; }
        saw_alpn = true;
        if rec.alpns.len == 0 {
            // RFC 9460 Section 7.1.2: Use - RR is incompatible when no advertised ALPN protocol is supported
            incompatible = true;
        }
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
        guard val.len > 0 else { return false; }
        if rec.ech_config_list.try_set(val) {
            rec.has_ech = true;
        } else {
            ech_dropped = true;
        }
    }
    return true;
}

// Parses SvcParams list into HttpsRecord, distinguishing incompatible mandatory keys from wire corruption.
//
// Example:
//   rdata = "\x00\x01\x00\x03\x02h2"
//   returns: SvcParamStatus.Ok, ok = true, rec.alpns = ["h2"]
fn parse_https_svc_params_status(rdata: const u8[:], rec: HttpsRecord&) -> SvcParamStatus, bool {
    let saved_rec = rec;
    var committed = false;
    defer if !committed { rec = saved_rec; };
    reset_https_record_svc_params(rec);

    var off:          i64  = 0;
    var last_key:     i32  = -1;
    var mand_off:     i64  = 0;
    var mand_end:     i64  = 0;
    var mand_ech:     bool = false;
    var ech_dropped:  bool = false;
    var saw_alpn:     bool = false;
    var incompatible: bool = false;

    while off + 4 <= rdata.len {
        let key = ((rdata[off] as u16) << 8) | rdata[off + 1];
        let val_len = (((rdata[off + 2] as u16) << 8) | rdata[off + 3]) as i64;
        off += 4;
        guard key > last_key && off + val_len <= rdata.len else { return SvcParamStatus.Malformed, false; }
        last_key = key;
        let val_start = off;
        let val = rdata[val_start..val_start + val_len];
        off += val_len;

        if key == rfc::SVC_PARAM_MANDATORY {
            let has_unsup, has_ech_m, ok_m = parse_mandatory_svc_param(val);
            guard ok_m else { return SvcParamStatus.Malformed, false; }
            mand_off = val_start;
            mand_end = off;
            mand_ech = has_ech_m;
            if has_unsup { incompatible = true; }
            continue;
        }
        if mand_off + 2 <= mand_end {
            let req_key = ((rdata[mand_off] as u16) << 8) | rdata[mand_off + 1];
            guard key <= req_key else { return SvcParamStatus.Malformed, false; }
            if key == req_key { mand_off += 2; }
        }
        guard apply_known_svc_param(key, val, rec, saw_alpn, ech_dropped, incompatible) else {
            return SvcParamStatus.Malformed, false;
        }
    }
    guard off == rdata.len && mand_off == mand_end else { return SvcParamStatus.Malformed, false; }
    // RFC 9460 Section 7.1.1: Representation - "no-default-alpn" MUST NOT appear without "alpn"
    guard !rec.no_default_alpn || saw_alpn else { return SvcParamStatus.Malformed, false; }
    if incompatible || (mand_ech && ech_dropped) {
        return SvcParamStatus.Incompatible, false;
    }
    committed = true;
    return SvcParamStatus.Ok, true;
}

// Parses SvcParams list from HTTPS/SVCB RDATA according to RFC 9460 Section 2.2.
// Keys MUST be in strictly ascending order with valid lengths; truncated or incompatible records return false.
//
// Example:
//   rdata = "\x00\x01\x00\x03\x02h2"
//   returns: ok = true, rec.alpns = ["h2"]
fn parse_https_svc_params(rdata: const u8[:], rec: HttpsRecord&) -> bool {
    let _, ok = parse_https_svc_params_status(rdata, rec);
    return ok;
}
