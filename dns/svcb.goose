// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation RFC 9460 HTTPS/SVCB Resource Records (Type 65) parser.
// Supports ALPN extraction, IPv4/IPv6 hints, SvcParams ordering, and raw ECHConfigList.
namespace dns;

import std;
import core;
import .internal;

// ---- RFC 9460 HTTPS/SVCB Record Models ----------------------------------

struct HttpsRecord {
    priority:        u16           = 0, // 0 = AliasMode, >0 = ServiceMode
    target_name:     u8[..255]     = [],
    alpns:           u8[..32][..4] = [],
    port:            u16           = 443,
    no_default_alpn: bool          = false,
    ipv4_hints:      u32[..8]      = [],
    ipv6_hints:      u8[16][..8]   = [],
    ech_config_list: u8[..512]     = [], // Raw wire bytes of ECHConfigList
    has_ech:         bool          = false,
}

struct MandatorySvcParams {
    has_unsupported: bool = false,
    has_ech:         bool = false,
}

// ---- RFC 9460 HTTPS/SVCB RDATA Parser -----------------------------------

// Validates mandatory SvcParamKeys list ordering and reports unsupported or ECH keys (RFC 9460 Section 8).
//
// Example:
//   val = "\x00\x01"
//   returns: MandatorySvcParams { has_unsupported: false, has_ech: false }, true
checkfree fn parse_mandatory_svc_param(val: const u8[:]) -> MandatorySvcParams, bool {
    // RFC 9460 Section 8: ServiceMode RR Compatibility and Mandatory Keys - ascending 2-octet keys > 0
    guard val.len > 0 && (val.len & 1) == 0 else { return MandatorySvcParams { .. }, false; }
    var res = MandatorySvcParams { .. };
    var m_off:      i64 = 0;
    var last_m_key: i32 = -1;
    while m_off + 2 <= val.len {
        let req_key = dns_internal::read_dns_u16(val, m_off);
        let rk_i32 = req_key as i32;
        guard req_key >= 1 && req_key != rfc::SVC_PARAM_NO_DEFAULT_ALPN && rk_i32 > last_m_key else {
            return MandatorySvcParams { .. }, false;
        }
        if req_key > rfc::SVC_PARAM_IPV6HINT {
            res.has_unsupported = true;
        } else if req_key == rfc::SVC_PARAM_ECH {
            res.has_ech = true;
        }
        last_m_key = rk_i32;
        m_off += 2;
    }
    return res, true;
}

// Parses SvcParams list from HTTPS/SVCB RDATA according to RFC 9460 Section 2.2.
// Keys MUST be in strictly ascending order; rolls back `rec` on malformed or incompatible records.
//
// Example:
//   rdata = "\x00\x01\x00\x03\x02h2"
//   returns: true, rec.alpns = ["h2"]
checkfree fn parse_https_svc_params(rec: HttpsRecord&, rdata: const u8[:]) -> bool {
    let _, ok = dns_internal::parse_https_svc_params_status(rec, rdata);
    return ok;
}
