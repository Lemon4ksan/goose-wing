// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Server-Sent Events (SSE) Protocol Engine (W3C EventSource Specification).
// Zero-heap, streaming line-based parser and serializer for `text/event-stream`:
// - Accurate handling of CR, LF, and CRLF line endings
// - Multi-line data concatenation with embedded newlines
// - Comment line stripping (keepalive pings)
// - Event ID tracking and reconnection retry milliseconds management
namespace wing;

import std;
import client.request;
import client.response;

// ---- 1. SSE Event Model ----------------------------------------------------

struct SseEvent {
    event:    u8[..64]   = [],  // Event type, default "message"
    data:     u8[..4096] = [],  // Aggregated payload
    id:       u8[..128]  = [],  // Event ID
    retry_ms: u32        = 0,   // Reconnection delay in milliseconds (0 if unchanged)
    is_valid: bool       = false,
}

struct SseParser {
    cur_event:     u8[..64]   = [],
    cur_data:      u8[..4096] = [],
    last_event_id: u8[..128]  = [],
    retry_ms:      u32        = 3000,
    line_buf:      u8[..4112] = [],
    prev_was_cr:   bool       = false,
    has_data:      bool       = false,
    bom_checked:   bool       = false,
}

// ---- 2. Line Dispatch and Event Dispatch (W3C Section 6) -------------------

// Parses an SSE retry milliseconds field value.
//
// Example:
//   field_val = "3000"
//   returns: 3000, true
fn parse_sse_retry(field_val: const u8[:]) -> u32, bool {
    guard field_val.len > 0 else { return 0, false; }
    var num: u32 = 0;
    for b in field_val {
        guard b >= '0' && b <= '9' else { return 0, false; }
        let digit = (b - '0') as u32;
        if num > (0xFFFFFFFF - digit) / 10 {
            num = 0xFFFFFFFF;
        } else {
            num = num * 10 + digit;
        }
    }
    return num, true;
}

fn sse_process_field(p: SseParser&, field_name: const u8[:], field_val: const u8[:]) {
    if field_name == "event" {
        p.cur_event.clear();
        let copy_len = if field_val.len <= p.cur_event.cap { field_val.len } else { p.cur_event.cap };
        p.cur_event.append(field_val[..copy_len]);
    } else if field_name == "data" {
        if p.has_data && p.cur_data.len < 4096 {
            p.cur_data.push('\n');
        }
        p.has_data = true;
        for b in field_val {
            if p.cur_data.len < 4096 {
                p.cur_data.push(b);
            }
        }
    } else if field_name == "id" {
        // Must not contain NUL byte
        var has_null = false;
        for b in field_val {
            if b == 0 { has_null = true; break; }
        }
        if !has_null {
            p.last_event_id.clear();
            let copy_len = if field_val.len <= p.last_event_id.cap { field_val.len } else { p.last_event_id.cap };
            p.last_event_id.append(field_val[..copy_len]);
        }
    } else if field_name == "retry" {
        let num, ok = parse_sse_retry(field_val);
        if ok {
            p.retry_ms = num;
        }
    }
}

// Processes a complete line buffer
fn sse_process_line<E>(p: SseParser&, out_events: E&) {
    var line = p.line_buf[..];

    // W3C EventSource §9.2.5: One leading U+FEFF BOM (0xEF 0xBB 0xBF) must be stripped if present
    if !p.bom_checked {
        p.bom_checked = true;
        if line.len >= 3 && line[0] == 0xEF && line[1] == 0xBB && line[2] == 0xBF {
            line = line[3..];
        }
    }

    // Empty line indicates event boundary (W3C Section 6 / §9.2.6: dispatch the event)
    if line.len == 0 {
        if p.has_data {
            var ev = SseEvent {
                retry_ms: p.retry_ms,
                is_valid: true,
                ..
            };
            if p.cur_event.len > 0 {
                ev.event.append(p.cur_event[..]);
            } else {
                ev.event.append("message");
            }
            ev.data.append(p.cur_data[..]);
            ev.id.append(p.last_event_id[..]);

            if out_events.len < out_events.cap {
                out_events.push(ev);
            } else {
                return;
            }

            // Reset current event buffer, keep last_event_id and retry_ms
            p.cur_event.clear();
            p.cur_data.clear();
            p.has_data = false;
        } else {
            p.cur_event.clear();
        }
        return;
    }

    // Lines starting with ':' are comments (keep-alive)
    if line[0] == ':' {
        return;
    }

    // Find colon separating field name from value
    let colon_pos = core::index_of_byte(line, ':');
    if colon_pos >= 0 {
        let field_name = line[..colon_pos];
        var val_start = colon_pos + 1;
        // If character after colon is a single space, skip it per W3C spec
        if val_start < line.len && line[val_start] == ' ' {
            val_start++;
        }
        let field_val = line[val_start..];
        sse_process_field(p, field_name, field_val);
    } else {
        // Line without colon: field name is the whole line with empty value
        sse_process_field(p, line, "");
    }
}

// Feeds a stream chunk into parser, extracting all completed SseEvents into out_events
fn sse_feed<E>(p: SseParser&, chunk: const u8[:], out_events: E&) {
    for b in chunk {
        if b == '\r' {
            sse_process_line(p, out_events);
            p.line_buf.clear();
            p.prev_was_cr = true;
        } else if b == '\n' {
            if p.prev_was_cr {
                // CRLF sequence: already dispatched line on '\r', ignore '\n'
                p.prev_was_cr = false;
            } else {
                sse_process_line(p, out_events);
                p.line_buf.clear();
                p.prev_was_cr = false;
            }
        } else {
            p.prev_was_cr = false;
            if p.line_buf.len < 4112 {
                p.line_buf.push(b);
            }
        }
    }
}

// Flushes any trailing buffered line at end of stream
fn sse_flush<E>(p: SseParser&, out_events: E&) {
    if p.line_buf.len > 0 {
        sse_process_line(p, out_events);
        p.line_buf.clear();
    }
    // Final empty line boundary to dispatch last event if pending
    sse_process_line(p, out_events);
}

// ---- 3. SSE Serializer -----------------------------------------------------

fn sse_clean_token_len(s: const u8[:]) -> i64 {
    for i in s.len {
        if s[i] == '\r' || s[i] == '\n' {
            return i;
        }
    }
    return s.len;
}

fn sse_format_data_lines<B>(out: B&, data: const u8[:]) {
    var start: i64 = 0;
    var i:     i64 = 0;
    while i < data.len {
        if data[i] == '\r' || data[i] == '\n' {
            out.append("data: ");
            out.append(data[start..i]);
            out.push('\n');
            if data[i] == '\r' && i + 1 < data.len && data[i + 1] == '\n' {
                i += 2;
            } else {
                i += 1;
            }
            start = i;
        } else {
            i += 1;
        }
    }
    out.append("data: ");
    out.append(data[start..]);
    out.push('\n');
}

// Serializes an SSE event into standard wire format
fn sse_format_event<B>(
    out:        B&,
    event_type: const u8[:],
    data:       const u8[:],
    id:         const u8[:] = "",
    retry_ms:   u32         = 0,
) {
    if retry_ms > 0 {
        out.append("retry: ");
        format(out, retry_ms);
        out.push('\n');
    }
    if id.len > 0 {
        let clean_id_len = sse_clean_token_len(id);
        if clean_id_len > 0 {
            out.append("id: ");
            out.append(id[..clean_id_len]);
            out.push('\n');
        }
    }
    if event_type.len > 0 {
        let clean_ev_len = sse_clean_token_len(event_type);
        let clean_ev = event_type[..clean_ev_len];
        if clean_ev.len > 0 && clean_ev != "message" {
            out.append("event: ");
            out.append(clean_ev);
            out.push('\n');
        }
    }

    sse_format_data_lines(out, data);
    out.push('\n');
}

// ---- 4. High-Level Ergonomic SSE Subscription ------------------------------

struct SseSubscription {
    parser:    SseParser = SseParser { .. },
    url:       u8[..256] = [],
    connected: bool      = false,
}

fn new_sse_subscription(url: const u8[:] = "") -> SseSubscription {
    var sub = SseSubscription { .. };
    if url.len > 0 {
        let copy_len = if url.len <= sub.url.cap { url.len } else { sub.url.cap };
        sub.url.append(url[..copy_len]);
    }
    return sub;
}

// Formats HTTP/1.1 or H2/H3 GET headers for SSE subscription per W3C EventSource
fn sse_build_request_headers<B>(
    sub:  const SseSubscription&,
    host: const u8[:],
    path: const u8[:],
    out:  B&,
) {
    let eff_path = if path.len > 0 { path } else { "/" };
    out.append("GET ");
    out.append(eff_path);
    out.append(" HTTP/1.1\r\nHost: ");
    out.append(host);
    out.append("\r\nAccept: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive");
    if sub.parser.last_event_id.len > 0 {
        out.append("\r\nLast-Event-ID: ");
        out.append(sub.parser.last_event_id[..]);
    }
    out.append("\r\n\r\n");
}

// Feeds incoming network chunk into subscription and dispatches parsed events
fn consume<E>(sub: SseSubscription&, chunk: const u8[:], out_events: E&) {
    sse_feed(sub.parser, chunk, out_events);
}

// Configures an HTTP request for SSE streaming per W3C EventSource
fn prepare_request(sub: const SseSubscription&, req: Request&) {
    set_header(req, "Accept", "text/event-stream");
    set_header(req, "Cache-Control", "no-cache");
    set_header(req, "Connection", "keep-alive");
    if sub.parser.last_event_id.len > 0 {
        set_header(req, "Last-Event-ID", sub.parser.last_event_id[..]);
    }
}

// Configures a server HTTP response for SSE streaming (text/event-stream)
fn init_response(res: Response&) {
    res.status_code = 200;
    set_header(res, "Content-Type", "text/event-stream");
    set_header(res, "Cache-Control", "no-cache");
    set_header(res, "Connection", "keep-alive");
    set_header(res, "X-Accel-Buffering", "no");
}
