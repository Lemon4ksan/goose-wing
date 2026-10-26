// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Network Telemetry, Microsecond Waterfall Timings, and HAR 1.2 Log Engine.
// Provides zero-allocation metrics collection across request lifecycle stages:
// Blocked -> DNS -> Connect -> SSL -> Send -> Wait (TTFB) -> Receive
namespace wing;

import std;

// ---- 1. Waterfall Timing Model ---------------------------------------------

struct RequestTimings {
    blocked_us: i64 = 0, // Queue wait time
    dns_us: i64 = 0,     // DNS lookup duration
    connect_us: i64 = 0, // TCP / UDP socket connect duration
    ssl_us: i64 = 0,     // TLS 1.3 handshake duration
    send_us: i64 = 0,    // Wire transmission duration
    wait_us: i64 = 0,    // TTFB (Time to First Byte)
    receive_us: i64 = 0, // Body download duration
}

// Computes total roundtrip duration in microseconds
fn compute_total_timing_us(t: const RequestTimings&) -> i64 {
    var total: i64 = 0;
    if t.blocked_us > 0 { total += t.blocked_us; }
    if t.dns_us > 0 { total += t.dns_us; }
    if t.connect_us > 0 { total += t.connect_us; }
    if t.ssl_us > 0 { total += t.ssl_us; }
    if t.send_us > 0 { total += t.send_us; }
    if t.wait_us > 0 { total += t.wait_us; }
    if t.receive_us > 0 { total += t.receive_us; }
    return total;
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

// ---- 2. HAR 1.2 Entry Serialization ----------------------------------------

struct HarEntry {
    started_iso8601: u8[..32] = [],
    method: u8[..16] = [],
    url: u8[..256] = [],
    http_version: u8[..16] = [],
    status: u16 = 200,
    status_text: u8[..32] = [],
    request_bytes: i64 = 0,
    response_bytes: i64 = 0,
    timings: RequestTimings = RequestTimings { .. },
}

// Serializes a single entry object conforming to HTTP Archive (HAR 1.2) specification
fn serialize_har_entry_json<B>(entry: const HarEntry&, out: B&) {
    out.append("{\"startedDateTime\":\"");
    out.append(entry.started_iso8601[..]);
    out.append("\",\"time\":");
    let total_us = compute_total_timing_us(entry.timings);
    format_us_as_ms(total_us, out);

    out.append(",\"request\":{\"method\":\"");
    out.append(entry.method[..]);
    out.append("\",\"url\":\"");
    out.append(entry.url[..]);
    out.append("\",\"httpVersion\":\"");
    out.append(entry.http_version[..]);
    out.append("\",\"bodySize\":");
    format(out, entry.request_bytes);
    out.append("}");

    out.append(",\"response\":{\"status\":");
    format(out, entry.status as u32);
    out.append(",\"statusText\":\"");
    out.append(entry.status_text[..]);
    out.append("\",\"httpVersion\":\"");
    out.append(entry.http_version[..]);
    out.append("\",\"bodySize\":");
    format(out, entry.response_bytes);
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
