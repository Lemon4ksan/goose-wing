// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Network Telemetry, Microsecond Waterfall Timings, and HAR 1.2 Log Engine.
// Provides zero-allocation metrics collection across request lifecycle stages:
// Blocked -> DNS -> Connect -> SSL -> Send -> Wait (TTFB) -> Receive
namespace wing;

import std;
import json;
import core from "..";

// ---- Waterfall Timing Model ---------------------------------------------

struct RequestTimings {
    blocked_us: i64 = 0, // Queue wait time
    dns_us:     i64 = 0, // DNS lookup duration
    connect_us: i64 = 0, // TCP / UDP socket connect duration
    ssl_us:     i64 = 0, // TLS 1.3 handshake duration
    send_us:    i64 = 0, // Wire transmission duration
    wait_us:    i64 = 0, // TTFB (Time to First Byte)
    receive_us: i64 = 0, // Body download duration
}

// Computes total roundtrip duration in microseconds
fn compute_total_timing_us(t: const RequestTimings&) -> i64 {
    return max(0, t.blocked_us) +
        max(0, t.dns_us) +
        max(0, t.connect_us) +
        max(0, t.ssl_us) +
        max(0, t.send_us) +
        max(0, t.wait_us) +
        max(0, t.receive_us);
}

// Converts microsecond duration to milliseconds with 2 fractional digits: e.g. 1520 us -> 1.52 ms
fn format_us_as_ms<B>(us: i64, out: B&) {
    if us < 0 {
        out.append("-1");
        return;
    }
    let ms_int = us / 1000;
    let frac = (us % 1000) / 10; // 2 digits
    format(out, ms_int);
    out.push('.');
    if frac < 10 { out.push('0'); }
    format(out, frac);
}

// ---- HAR 1.2 Entry Serialization ----------------------------------------

struct HarEntry {
    started_iso8601: u8[..32]       = [],
    method:          u8[..16]       = [],
    url:             u8[..2048]     = [],
    http_version:    u8[..16]       = [],
    status:          u16            = rfc::STATUS_OK as! u16,
    status_text:     u8[..32]       = [],
    request_bytes:   i64            = 0,
    response_bytes:  i64            = 0,
    timings:         RequestTimings = RequestTimings { .. },
}

// Serializes a single entry object conforming to HTTP Archive (HAR 1.2) specification
fn serialize_har_entry_json<B>(entry: const HarEntry&, out: B&) {
    out.append("{\"startedDateTime\":");
    core::format_json_string(out, entry.started_iso8601[..]);
    out.append(",\"time\":");
    let total_us = compute_total_timing_us(entry.timings);
    format_us_as_ms(total_us, out);

    out.append(",\"request\":{\"method\":");
    core::format_json_string(out, entry.method[..]);
    out.append(",\"url\":");
    core::format_json_string(out, entry.url[..]);
    out.append(",\"httpVersion\":");
    core::format_json_string(out, entry.http_version[..]);
    out.append(",\"bodySize\":");
    entry.request_bytes.format_i64_dec(out);
    out.append("}");

    out.append(",\"response\":{\"status\":");
    (entry.status as u32).format_u32_dec(out);
    out.append(",\"statusText\":");
    core::format_json_string(out, entry.status_text[..]);
    out.append(",\"httpVersion\":");
    core::format_json_string(out, entry.http_version[..]);
    out.append(",\"bodySize\":");
    entry.response_bytes.format_i64_dec(out);
    out.append("}");

    // Timings object
    out.append(",\"timings\":{\"blocked\":");
    format_us_as_ms(entry.timings.blocked_us, out);
    out.append(",\"dns\":");
    format_us_as_ms(entry.timings.dns_us, out);
    out.append(",\"connect\":");
    format_us_as_ms(entry.timings.connect_us, out);
    out.append(",\"ssl\":");
    format_us_as_ms(entry.timings.ssl_us, out);
    out.append(",\"send\":");
    format_us_as_ms(entry.timings.send_us, out);
    out.append(",\"wait\":");
    format_us_as_ms(entry.timings.wait_us, out);
    out.append(",\"receive\":");
    format_us_as_ms(entry.timings.receive_us, out);
    out.append("}}");
}
