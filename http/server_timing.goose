// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// W3C Server-Timing header telemetry recorder and formatter.
namespace http;

import std;
import core;
import rfc.http;
import .headers;
import .response;
import http.meta_internal;

struct ServerTimingSpan {
    name:     u8[..32] = [],
    desc:     u8[..64] = [],
    start_ns: u64      = 0,
    dur_ns:   u64      = 0,
    has_dur:  bool     = false,
    active:   bool     = false,
}

struct ServerTimingRecorder {
    spans: ServerTimingSpan[..8] = [],
}

fn clear(rec: ServerTimingRecorder&) {
    rec.spans.clear();
}

// Starts a monotonic span in `rec` and returns its slot index (or -1 if full/invalid).
fn start_span(
    rec:    ServerTimingRecorder&,
    name:   const u8[:],
    now_ns: u64,
    desc:   const u8[:] = "",
) -> i32 {
    guard is_valid_token_swar(name) && rec.spans.len < rec.spans.cap else { return -1; }
    var sp = ServerTimingSpan { start_ns: now_ns, active: true, .. };
    guard sp.name.try_set(name) else { return -1; }
    if desc.len > 0 {
        guard http_internal::copy_valid_timing_desc(desc, sp.desc) else { return -1; }
    }
    let idx = rec.spans.len as i32;
    guard rec.spans.try_push(sp) else { return -1; }
    return idx;
}

// Completes a span started via `start_span` using saturating monotonic subtraction.
fn end_span(rec: ServerTimingRecorder&, span_idx: i32, now_ns: u64) -> bool {
    guard span_idx >= 0 && span_idx < rec.spans.len else { return false; }
    let sp .= rec.spans[span_idx];
    guard sp.active else { return false; }
    sp.dur_ns = core::sub_sat_u64(now_ns, sp.start_ns);
    sp.has_dur = true;
    sp.active = false;
    return true;
}

// Records a completed duration in nanoseconds (`dur_ns`) into `rec`.
fn record_duration_ns(
    rec:    ServerTimingRecorder&,
    name:   const u8[:],
    dur_ns: u64,
    desc:   const u8[:] = "",
) -> bool {
    guard is_valid_token_swar(name) && rec.spans.len < rec.spans.cap else { return false; }
    var sp = ServerTimingSpan { dur_ns: dur_ns, has_dur: true, .. };
    guard sp.name.try_set(name) else { return false; }
    if desc.len > 0 {
        guard http_internal::copy_valid_timing_desc(desc, sp.desc) else { return false; }
    }
    return rec.spans.try_push(sp);
}

// Formats nanoseconds as W3C Server-Timing milliseconds with 1 decimal place (tenths of ms).
//
// Example:
//   dur_ns = 47250000, out = []
//   out becomes "47.2", returns true
fn format_dur_ms_tenths<B>(dur_ns: u64, out: B&) -> bool {
    let saved_len = out.len;
    var ns_str: u8[..24] = [];
    dur_ns.format_u64_dec(ns_str);
    var padded_ns: u8[..24] = [];
    while core::add_sat_i64(padded_ns.len, ns_str.len) < 7 {
        let _ = padded_ns.try_push('0');
    }
    let _ = padded_ns.try_append(ns_str[..]);
    guard out.try_append(padded_ns[..^6]) && out.try_push('.') && out.try_append(padded_ns[^6..^5]) else {
        out.resize(saved_len);
        return false;
    }
    return true;
}

inline fn append_timing_desc_quoted<B>(desc: const u8[:], out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard out.try_append(";desc=\"") else { return false; }
    for b in desc {
        if (b == '"' || b == '\\') && !out.try_push('\\') {
            return false;
        }
        guard out.try_push(b) else { return false; }
    }
    guard out.try_push('"') else { return false; }
    committed = true;
    return true;
}

// Serializes recorded spans into W3C `Server-Timing` header syntax (quoted-string safe).
//
// Example:
//   rec.spans = [{ name: "db", dur_ns: 5300000, desc: "pg" }]
//   out becomes "db;dur=5.3;desc=\"pg\"", returns true
fn format_server_timing<B>(rec: const ServerTimingRecorder&, out: B&) -> bool {
    let saved_len = out.len;
    var wrote_any = false;
    for &sp in rec.spans {
        if sp.active || sp.name.len == 0 { continue; }
        if wrote_any {
            guard out.try_append(", ") else { out.resize(saved_len); return false; }
        }
        guard out.try_append(sp.name[..]) else { out.resize(saved_len); return false; }
        if sp.has_dur {
            guard out.try_append(";dur=") && format_dur_ms_tenths(sp.dur_ns, out) else {
                out.resize(saved_len);
                return false;
            }
        }
        if sp.desc.len > 0 && !append_timing_desc_quoted(sp.desc[..], out) {
            out.resize(saved_len);
            return false;
        }
        wrote_any = true;
    }
    return wrote_any;
}

fn emit_server_timing(rec: const ServerTimingRecorder&, res: Response&) -> bool {
    var hdr_buf: u8[..512] = [];
    guard format_server_timing(rec, hdr_buf) else { return false; }
    return append_header(res.headers, rfc::HEADER_SERVER_TIMING, hdr_buf[..]);
}
