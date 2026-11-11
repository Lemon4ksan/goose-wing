// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation RFC 9460 HTTPS/SVCB Resource Records (Type 65) parser.
// Supports ALPN extraction, IPv4/IPv6 hints, SvcParams ordering, and raw ECHConfigList.
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

// ---- RFC 9460 HTTPS/SVCB RDATA Parser -----------------------------------

// Extracts ALPN parameter tokens into HttpsRecord (RFC 9460 §7.1).
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
        var entry: u8[..16] = [];
        guard entry.try_set(s) && rec.alpns.try_push(entry) else { return false; }
        alpn_off += slen;
    }
    committed = alpn_off == val.len;
    return committed;
}

// Parses mandatory SvcParamKeys list (RFC 9460 §8).
//
// Example:
//   val = [0x00, 0x01]
//   returns: mask = 2, ok = true
fn parse_mandatory_svc_param(val: const u8[:]) -> u32, bool {
    // RFC 9460 §8: Mandatory list of 2-octet SvcParamKeys in ascending order
    guard val.len > 0 && (val.len & 1) == 0 else { return 0, false; }
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

// Parses IPv6 hints parameter from SVCB/HTTPS RDATA (RFC 9460 §7.1).
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

// Parses SvcParams list from HTTPS/SVCB RDATA according to RFC 9460 §2.1 & §2.2.
// Keys MUST be in strictly ascending order with valid lengths; truncated records are rejected.
//
// Example:
//   rdata = "\x00\x01\x00\x03\x02h2"
//   returns: ok = true, rec.alpns = ["h2"]
fn parse_https_svc_params(rdata: const u8[:], rec: HttpsRecord&) -> bool {
    let saved_rec = rec;
    var committed = false;
    defer if !committed { rec = saved_rec; };
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
    committed = true;
    return true;
}
