// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Server-Sent Events (SSE) Protocol Engine (W3C EventSource Specification).
// Zero-heap, streaming line-based parser and serializer for `text/event-stream`:
// - Accurate handling of CR, LF, and CRLF line endings
// - Multi-line data concatenation with embedded newlines
// - Comment line stripping (keepalive pings)
// - Event ID tracking and reconnection retry milliseconds management
namespace realtime;

import std;
import core;
import http.request;
import http.response;
import .internal;

// ---- SSE Event Model ----------------------------------------------------

struct SseEvent {
    event:    u8[..64]   = [],  // Event type, default "message"
    data:     u8[..4096] = [],  // Aggregated payload
    id:       u8[..128]  = [],  // Event ID
    retry_ms: u32        = 0,   // Reconnection delay in milliseconds (0 if unchanged)
    is_valid: bool       = false,
}

struct SseParser {
    cur_event:      u8[..64]   = [],
    cur_data:       u8[..4096] = [],
    last_event_id:  u8[..128]  = [],
    pending_id:     u8[..128]  = [],
    retry_ms:       u32        = 3000,
    line_buf:       u8[..4112] = [],
    prev_was_cr:    bool       = false,
    has_data:       bool       = false,
    has_pending_id: bool       = false,
    bom_checked:    bool       = false,
}

// ---- Stream Feeding & EOF Reset (W3C EventSource §9.2.6) ----------------

// Feeds a stream chunk into parser, extracting all completed SseEvents into out_events.
fn sse_feed<E>(p: SseParser&, chunk: const u8[:], out_events: E&) {
    for b in chunk {
        if b == '\r' {
            realtime_internal::sse_process_line(p, out_events);
            p.line_buf.clear();
            p.prev_was_cr = true;
        } else if b == '\n' {
            if p.prev_was_cr {
                // CRLF sequence: already dispatched line on '\r', ignore '\n'
                p.prev_was_cr = false;
            } else {
                realtime_internal::sse_process_line(p, out_events);
                p.line_buf.clear();
                p.prev_was_cr = false;
            }
        } else {
            p.prev_was_cr = false;
            if p.line_buf.len < realtime_internal::SSE_MAX_LINE_LEN {
                let _ = p.line_buf.try_push(b);
            }
        }
    }
}

// Resets transient stream state at EOF or reconnection while preserving last_event_id and retry_ms.
// W3C EventSource §9.2.6: Once the end of the file is reached, any pending data must be discarded
// (incomplete events without a trailing empty line are NOT dispatched).
fn sse_flush(p: SseParser&) {
    p.line_buf.clear();
    p.cur_event.clear();
    p.cur_data.clear();
    p.pending_id.clear();
    p.prev_was_cr = false;
    p.has_data = false;
    p.has_pending_id = false;
    p.bom_checked = false;
}

// ---- SSE Serializer -----------------------------------------------------

// Serializes an SSE event into standard wire format.
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
        let clean_id_len = realtime_internal::sse_clean_token_len(id);
        if clean_id_len > 0 {
            out.append("id: ");
            out.append(id[..clean_id_len]);
            out.push('\n');
        }
    }
    if event_type.len > 0 {
        let clean_ev_len = realtime_internal::sse_clean_token_len(event_type);
        let clean_ev = event_type[..clean_ev_len];
        if clean_ev.len > 0 && clean_ev != "message" {
            out.append("event: ");
            out.append(clean_ev);
            out.push('\n');
        }
    }

    realtime_internal::sse_format_data_lines(out, data);
    out.push('\n');
}

// ---- High-Level Ergonomic SSE Subscription ------------------------------

struct SseSubscription {
    parser:    SseParser  = SseParser { .. },
    url:       u8[..2048] = [],
    connected: bool       = false,
}

fn new_sse_subscription(url: const u8[:] = "") -> SseSubscription {
    var sub = SseSubscription { .. };
    if url.len > 0 {
        let copy_len = min(url.len, sub.url.cap);
        sub.url.append(url[..copy_len]);
    }
    return sub;
}

// Formats HTTP/1.1 or H2/H3 GET headers for SSE subscription per W3C EventSource.
fn sse_build_request_headers<B>(
    sub:  const SseSubscription&,
    host: const u8[:],
    path: const u8[:],
    out:  B&,
) {
    let raw_path = if path.len > 0 { path } else { "/" };
    let clean_path = raw_path[..realtime_internal::sse_clean_token_len(raw_path)];
    let eff_path = if clean_path.len > 0 { clean_path } else { "/" };
    let clean_host = host[..realtime_internal::sse_clean_token_len(host)];

    out.append("GET ");
    out.append(eff_path);
    out.append(" HTTP/1.1\r\nHost: ");
    out.append(clean_host);
    out.append("\r\nAccept: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive");
    if sub.parser.last_event_id.len > 0 {
        let raw_id = sub.parser.last_event_id[..];
        let clean_id = raw_id[..realtime_internal::sse_clean_token_len(raw_id)];
        if clean_id.len > 0 {
            out.append("\r\nLast-Event-ID: ");
            out.append(clean_id);
        }
    }
    out.append("\r\n\r\n");
}

// Feeds incoming network chunk into subscription and dispatches parsed events.
fn consume<E>(sub: SseSubscription&, chunk: const u8[:], out_events: E&) {
    sse_feed(sub.parser, chunk, out_events);
}

// Configures an HTTP request for SSE streaming per W3C EventSource.
fn prepare_request(sub: const SseSubscription&, req: http::Request&) {
    http::set_header(req, "Accept", "text/event-stream");
    http::set_header(req, "Cache-Control", "no-cache");
    http::set_header(req, "Connection", "keep-alive");
    if sub.parser.last_event_id.len > 0 {
        let raw_id = sub.parser.last_event_id[..];
        let clean_id = raw_id[..realtime_internal::sse_clean_token_len(raw_id)];
        if clean_id.len > 0 {
            http::set_header(req, "Last-Event-ID", clean_id);
        }
    }
}

// Configures a server HTTP response for SSE streaming (text/event-stream).
fn init_response(res: http::Response&) {
    res.status_code = 200;
    http::set_header(res, "Content-Type", "text/event-stream");
    http::set_header(res, "Cache-Control", "no-cache");
    http::set_header(res, "Connection", "keep-alive");
    http::set_header(res, "X-Accel-Buffering", "no");
}
