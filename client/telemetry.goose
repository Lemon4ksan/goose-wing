// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Network Telemetry, Microsecond Waterfall Timings, and HAR 1.2 Log Engine.
// Provides zero-allocation metrics collection across request lifecycle stages:
// Blocked -> DNS -> Connect -> SSL -> Send -> Wait (TTFB) -> Receive
namespace client;

import std;
import core from "..";
import rfc.http;
import .internal;

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

// Computes total roundtrip duration in microseconds.
fn compute_total_timing_us(t: const RequestTimings&) -> i64 {
    var total: i64 = 0;
    const for <N, A> in fields<RequestTimings> {
        total = core::add_sat_i64(total, max(t.A, 0));
    }
    return total;
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

// Serializes a single entry object conforming to HTTP Archive (HAR 1.2) specification.
fn serialize_har_entry_json<B>(entry: const HarEntry&, out: B&) {
    out.append("{\"startedDateTime\":");
    core::format_json_string(out, entry.started_iso8601[..]);
    out.append(",\"time\":");
    let total_us = compute_total_timing_us(entry.timings);
    client_internal::format_us_as_ms(total_us, out);

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
    entry.status.format_i64_dec(out);
    out.append(",\"statusText\":");
    core::format_json_string(out, entry.status_text[..]);
    out.append(",\"httpVersion\":");
    core::format_json_string(out, entry.http_version[..]);
    out.append(",\"bodySize\":");
    entry.response_bytes.format_i64_dec(out);
    out.append("}");

    out.append(",\"timings\":{");
    var first = true;
    const for <N, A> in fields<RequestTimings> {
        if !first { out.push(','); }
        first = false;
        let key, _ = N.strip_suffix("_us");
        core::format_json_key(out, key);
        client_internal::format_us_as_ms(entry.timings.A, out);
    }
    out.append("}}");
}
