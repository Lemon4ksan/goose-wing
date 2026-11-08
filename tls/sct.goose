// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 6962 Certificate Transparency v1 SignedCertificateTimestamp (SCT) wire parser.
namespace wing;

import std;
import core from "..";
import .asn1;

struct ParsedSct {
    version:      u8     = 0,
    log_id:       u8[32] = [0; 32],
    timestamp_ms: u64    = 0,
    hash_alg:     u8     = 0,
    sig_alg:      u8     = 0,
    signature:    Span16 = Span16 { offset: 0, length: 0 },
}

// Packs two big-endian 32-bit halves into an RFC 6962 §3.2 64-bit millisecond timestamp.
//
// Example:
//   ts_hi = 0x0000018E, ts_lo = 0x00000001
//   returns: 0x0000018E00000001
inline fn pack_sct_timestamp_ms(ts_hi: u32, ts_lo: u32) -> u64 {
    return ((ts_hi as u64) << 32) | ts_lo;
}

// Parses a single RFC 6962 §3.2 v1 SignedCertificateTimestamp entry from `raw`.
//
// Example:
//   raw = [0x00, <32B log_id>, <8B timestamp_ms>, 0x00, 0x00, 0x04, 0x03, 0x00, 0x02, 0xAA, 0xBB]
//   returns: true, out.version = 0, out.hash_alg = 4, out.sig_alg = 3, out.signature.length = 2
fn parse_sct_entry(raw: const u8[:], out: ParsedSct&) -> bool {
    guard raw.len >= rfc::SCT_V1_HEADER_MIN_LEN && raw.len <= 65535 else { return false; }
    var c = core::cursor_from(raw);
    var ver: u8 = 0;
    guard c.get_u8(ver) && ver == rfc::SCT_VERSION_V1 else { return false; }

    var log_cursor = core::cursor_from(raw[..0]);
    guard c.get_bytes(log_cursor, rfc::SCT_LOG_ID_LEN) else { return false; }

    var ts_hi: u32 = 0;
    var ts_lo: u32 = 0;
    guard c.get_u32(ts_hi) && c.get_u32(ts_lo) else { return false; }

    var ext_cursor = core::cursor_from(raw[..0]);
    guard c.get_u16_length_prefixed(ext_cursor) else { return false; }

    var hash_alg: u8 = 0;
    var sig_alg:  u8 = 0;
    guard c.get_u8(hash_alg) && c.get_u8(sig_alg) else { return false; }

    var sig_cursor = core::cursor_from(raw[..0]);
    guard c.get_u16_length_prefixed(sig_cursor) &&
        sig_cursor.buf.len > 0 && c.cursor_len() == 0 else { return false; }

    out.version = ver;
    core::ct_copy_bytes(out.log_id[..], log_cursor.buf);
    out.timestamp_ms = pack_sct_timestamp_ms(ts_hi, ts_lo);
    out.hash_alg = hash_alg;
    out.sig_alg = sig_alg;
    out.signature = make_span(raw, sig_cursor.buf);
    return true;
}

// Parses an RFC 6962 §3.3 `SignedCertificateTimestampList` into `out_scts`.
//
// Example:
//   raw_list = [0x00, 0x31, 0x00, 0x2F, <47B v1 SerializedSCT>]
//   returns: true, out_scts.len = 1
fn parse_sct_list(raw_list: const u8[:], out_scts: ParsedSct[..8]&) -> bool {
    out_scts.clear();
    var c = core::cursor_from(raw_list);
    var list_cursor = core::cursor_from(raw_list[..0]);
    guard c.get_u16_length_prefixed(list_cursor) &&
        c.cursor_len() == 0 && list_cursor.cursor_len() > 0 else { return false; }

    while list_cursor.cursor_len() > 0 {
        var sct_cursor = core::cursor_from(list_cursor.buf[..0]);
        guard list_cursor.get_u16_length_prefixed(sct_cursor) &&
            sct_cursor.buf.len > 0 && out_scts.len < out_scts.cap else { return false; }
        var sct = ParsedSct { .. };
        guard parse_sct_entry(sct_cursor.buf, sct) else { return false; }
        out_scts.push(sct);
    }
    return out_scts.len > 0;
}
