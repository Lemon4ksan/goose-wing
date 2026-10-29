// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_sse_wire.goose
// Verification of W3C EventSource Server-Sent Events (SSE) wire protocol:
// multi-line data concatenation, keepalive comments, retry delays,
// BOM stripping, and split-stream event dispatch.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// Wire bridge to SSE streaming parser for split stream and fuzz verification
fn decode_sse_frame_wire(buf: const u8[:]) -> i64 {
    var p = wing::SseParser { .. };
    var events: wing::SseEvent[..4] = [];
    wing::sse_feed(p, buf, events);
    if events.len == 0 { return -1; }
    return events[0].data.len;
}

fn test_sse_event_formatting_and_feed() {
    var wire_out: u8[>..] = [];
    wing::sse_format_event(wire_out, "update", "first line\nsecond line", "101", 5000);

    var p = wing::SseParser { .. };
    var events: wing::SseEvent[..4] = [];
    wing::sse_feed(p, wire_out[..], events);

    assert(events.len == 1);
    assert(events[0].event == "update");
    assert(events[0].id == "101");
    assert(events[0].data == "first line\nsecond line");
    assert(p.retry_ms == 5000);
    print("SSE_FORMAT_AND_FEED: OK");
}

fn test_sse_split_stream_and_fuzz() {
    let wire_data = "event: msg\ndata: hello\n\n";
    assert(wire_kit::verify_split_stream(wire_data, -1, 5, decode_sse_frame_wire));
    assert(wire_kit::fuzz_payload(wire_data, 100, decode_sse_frame_wire));
    print("SSE_SPLIT_AND_FUZZ: OK");
}

fn test_sse_comments_and_bom() {
    // 1. Keep-alive comment line + retry directive
    let comment_wire = ": keepalive ping\nretry: 4500\n\n";
    var p = wing::SseParser { .. };
    var events: wing::SseEvent[..4] = [];
    wing::sse_feed(p, comment_wire, events);
    assert(events.len == 0); // Comments do not generate events
    assert(p.retry_ms == 4500);

    // 2. UTF-8 BOM stripping (\xEF\xBB\xBF)
    var bom_wire: u8[>..] = [];
    bom_wire.push(0xEF);
    bom_wire.push(0xBB);
    bom_wire.push(0xBF);
    bom_wire.append("data: payload-with-bom\n\n");

    var p_bom = wing::SseParser { .. };
    var bom_events: wing::SseEvent[..4] = [];
    wing::sse_feed(p_bom, bom_wire[..], bom_events);
    assert(bom_events.len == 1);
    assert(bom_events[0].data == "payload-with-bom");

    print("SSE_COMMENTS_AND_BOM: OK");
}

fn main() {
    test_sse_event_formatting_and_feed();
    test_sse_split_stream_and_fuzz();
    test_sse_comments_and_bom();
    print("SSE_WIRE: ALL INVARIANTS PASS");
}

// CHECK: SSE_FORMAT_AND_FEED: OK
// CHECK: SSE_SPLIT_AND_FUZZ: OK
// CHECK: SSE_COMMENTS_AND_BOM: OK
// CHECK: SSE_WIRE: ALL INVARIANTS PASS
