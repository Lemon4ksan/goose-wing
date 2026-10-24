// Server-Sent Events (SSE) Protocol Engine (W3C EventSource Specification).
// Zero-heap, streaming line-based parser and serializer for `text/event-stream`:
// - Accurate handling of CR, LF, and CRLF line endings
// - Multi-line data concatenation with embedded newlines
// - Comment line stripping (keepalive pings)
// - Event ID tracking and reconnection retry milliseconds management
namespace wing;

import std;

// ---- 1. SSE Event Model ----------------------------------------------------

struct SseEvent {
    event: u8[..64] = [],       // Event type, default "message"
    data: u8[..4096] = [],      // Aggregated payload
    id: u8[..128] = [],         // Event ID
    retry_ms: u32 = 0,          // Reconnection delay in milliseconds (0 if unchanged)
    is_valid: bool = false,
}

struct SseParser {
    cur_event: u8[..64] = [],
    cur_data: u8[..4096] = [],
    last_event_id: u8[..128] = [],
    retry_ms: u32 = 3000,
    line_buf: u8[..4096] = [],
    prev_was_cr: bool = false,
}

fn new_sse_parser() -> SseParser {
    return SseParser { .. };
}

// ---- 2. Line Dispatch and Event Dispatch (W3C Section 6) -------------------

fn sse_process_field(p: SseParser&, field_name: const u8[:], field_val: const u8[:]) {
    if field_name == "event" {
        p.cur_event.clear();
        p.cur_event.append(field_val);
    } else if field_name == "data" {
        if p.cur_data.len > 0 && p.cur_data.len < 4096 {
            p.cur_data.push('\n');
        }
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
            p.last_event_id.append(field_val);
        }
    } else if field_name == "retry" {
        var num: u32 = 0;
        var valid_digits = field_val.len > 0;
        for b in field_val {
            if b >= '0' && b <= '9' {
                num = num * 10 + (b - '0');
            } else {
                valid_digits = false;
                break;
            }
        }
        if valid_digits {
            p.retry_ms = num;
        }
    }
}

// Processes a complete line buffer
fn sse_process_line<E>(p: SseParser&, out_events: E&) {
    let line = p.line_buf[..];

    // Empty line indicates event boundary (W3C Section 6: dispatch the event)
    if line.len == 0 {
        if p.cur_data.len > 0 || p.cur_event.len > 0 {
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

            out_events.push(ev);

            // Reset current event buffer, keep last_event_id and retry_ms
            p.cur_event.clear();
            p.cur_data.clear();
        }
        return;
    }

    // Lines starting with ':' are comments (keep-alive)
    if line[0] == ':' {
        return;
    }

    // Find colon separating field name from value
    var colon_pos: i64 = -1;
    for i in line.len {
        if line[i] == ':' {
            colon_pos = i;
            break;
        }
    }

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
            if p.line_buf.len < 4096 {
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

// Serializes an SSE event into standard wire format
fn sse_format_event<B>(
    out: B&,
    event_type: const u8[:],
    data: const u8[:],
    id: const u8[:] = "",
    retry_ms: u32 = 0
) {
    if retry_ms > 0 {
        out.append("retry: ");
        format(out, retry_ms);
        out.push('\n');
    }
    if id.len > 0 {
        out.append("id: ");
        out.append(id);
        out.push('\n');
    }
    if event_type.len > 0 && event_type != "message" {
        out.append("event: ");
        out.append(event_type);
        out.push('\n');
    }

    // Split multi-line data into separate data: lines
    var start: i64 = 0;
    for i in data.len {
        if data[i] == '\n' {
            out.append("data: ");
            out.append(data[start..i]);
            out.push('\n');
            start = i + 1;
        }
    }
    out.append("data: ");
    out.append(data[start..]);
    out.push('\n');

    // Terminal newline to dispatch event
    out.push('\n');
}

// ---- 4. High-Level Ergonomic SSE Subscription ------------------------------

struct SseSubscription {
    parser: SseParser = SseParser { .. },
    url: u8[..256] = [],
    connected: bool = false,
}

fn new_sse_subscription(url: const u8[:] = "") -> SseSubscription {
    var sub = SseSubscription { .. };
    if url.len > 0 {
        sub.url.append(url);
    }
    return sub;
}

// Formats HTTP/1.1 or H2/H3 GET headers for SSE subscription per W3C EventSource
fn sse_build_request_headers<B>(
    sub: const SseSubscription&,
    host: const u8[:],
    path: const u8[:],
    out: B&
) {
    out.append("GET ");
    out.append(path);
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
fn sse_consume<E>(sub: SseSubscription&, chunk: const u8[:], out_events: E&) {
    sse_feed(sub.parser, chunk, out_events);
}

