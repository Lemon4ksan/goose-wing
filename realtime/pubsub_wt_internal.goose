// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for Server-Sent Events, TopicTree pub/sub, and WebTransport.
namespace realtime_internal;

import std;
import core;
import rfc.ws;
import rfc.h3_quic;
import net.tcp;
import .sse;
import .topic_tree;
import .websocket;
import .webtransport;

// ---- SSE Internal Helpers (W3C EventSource) ------------------------------

const SSE_MAX_DATA_LEN: i64 = 4096;
const SSE_MAX_LINE_LEN: i64 = 4112;

// Parses an SSE retry milliseconds field value.
//
// Example:
//   field_val = "3000"
//   returns: 3000, true
fn parse_sse_retry(field_val: const u8[:]) -> u32, bool {
    guard field_val.len > 0 else { return 0, false; }
    var num: u32 = 0;
    for b in field_val {
        guard core::is_ascii_digit(b) else { return 0, false; }
        let digit = core::sub_sat_u64(b, '0') as u32;
        num = core::add_sat_u32(core::mul_sat_u32(num, 10), digit);
    }
    return num, true;
}

fn sse_process_field(
    p:          realtime::SseParser&,
    field_name: const u8[:],
    field_val:  const u8[:],
) {
    if field_name == "event" {
        let copy_len = min(field_val.len, p.cur_event.cap);
        let _ = p.cur_event.try_set(field_val[..copy_len]);
    } else if field_name == "data" {
        if p.has_data && p.cur_data.len < SSE_MAX_DATA_LEN {
            let _ = p.cur_data.try_push('\n');
        }
        p.has_data = true;
        let rem = core::sub_sat_i64(SSE_MAX_DATA_LEN, p.cur_data.len);
        let copy_len = min(field_val.len, rem);
        if copy_len > 0 {
            let _ = p.cur_data.try_append(field_val[..copy_len]);
        }
    } else if field_name == "id" {
        // Must not contain NUL byte (W3C EventSource §9.2.6)
        if !field_val.contains_byte(0) {
            let copy_len = min(field_val.len, p.pending_id.cap);
            let _ = p.pending_id.try_set(field_val[..copy_len]);
            p.has_pending_id = true;
        }
    } else if field_name == "retry" {
        let num, ok = parse_sse_retry(field_val);
        if ok {
            p.retry_ms = num;
        }
    }
}

fn sse_dispatch_event<E>(p: realtime::SseParser&, out_events: E&) {
    if p.has_pending_id {
        let _ = p.last_event_id.try_set(p.pending_id[..]);
        p.has_pending_id = false;
    }
    guard p.has_data else {
        p.cur_event.clear();
        return;
    }
    var ev = realtime::SseEvent {
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

    p.cur_event.clear();
    p.cur_data.clear();
    p.has_data = false;
    let _ = out_events.try_push(ev);
}

fn sse_process_line<E>(p: realtime::SseParser&, out_events: E&) {
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
        sse_dispatch_event(p, out_events);
        return;
    }

    if line[0] == ':' {
        return;
    }

    // Split on first colon separating field name from value (W3C EventSource §9.2.6)
    let field_name, raw_val, has_colon = line.split_once_byte(':');
    if has_colon {
        let field_val = if raw_val.len > 0 && raw_val[0] == ' ' { raw_val[1..] } else { raw_val };
        sse_process_field(p, field_name, field_val);
    } else {
        sse_process_field(p, line, "");
    }
}

// Scans for the first line break or NUL byte in an SSE header token.
//
// Example:
//   s = "id-42\r\ninjected"
//   returns: 5
fn sse_clean_token_len(s: const u8[:]) -> i64 {
    for i in s.len {
        if s[i] == '\r' || s[i] == '\n' || s[i] == 0 {
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
            let next_i = core::add_sat_i64(i, 1);
            if data[i] == '\r' && next_i < data.len && data[next_i] == '\n' {
                i = core::add_sat_i64(i, 2);
            } else {
                i = next_i;
            }
            start = i;
        } else {
            i = core::add_sat_i64(i, 1);
        }
    }
    out.append("data: ");
    out.append(data[start..]);
    out.push('\n');
}

// ---- TopicTree Internal Helpers (OASIS MQTT v5.0 §4.7) -------------------

const TOPIC_TREE_MAX_BUCKETS:           i64 = 256;
const TOPIC_TREE_MAX_SUBSCRIPTIONS:     i64 = 4096;
const TOPIC_PALETTE_CAP:                i64 = 64;
const TOPIC_MAX_SUBSCRIBERS_PER_BUCKET: i32 = 512;

enum BatchSeenResult {
    Added,
    AlreadySeen,
    CapacityExceeded,
}

// Scans forward from `start` until '/' or end of slice (OASIS MQTT v5.0 §4.7).
//
// Example:
//   raw = "sensors/temp", start = 0
//   returns: 7
fn scan_topic_segment_end(raw: const u8[:], start: i64) -> i64 {
    var next = start;
    while next < raw.len && raw[next] != '/' {
        next = core::add_sat_i64(next, 1);
    }
    return next;
}

inline fn is_valid_wildcard_char(pattern: const u8[:], i: i64, b: u8) -> bool {
    guard b != 0 else { return false; }
    if b == '#' {
        guard i == core::sub_sat_i64(pattern.len, 1) else { return false; }
        if i > 0 {
            guard pattern[core::sub_sat_i64(i, 1)] == '/' else { return false; }
        }
        return true;
    }
    if b == '+' {
        if i > 0 {
            guard pattern[core::sub_sat_i64(i, 1)] == '/' else { return false; }
        }
        let next_i = core::add_sat_i64(i, 1);
        if next_i < pattern.len {
            guard pattern[next_i] == '/' else { return false; }
        }
    }
    return true;
}

inline fn compute_topic_first_seg_hash(s: const u8[:]) -> u32 {
    let seg_end = scan_topic_segment_end(s, 0);
    let seg = s[..seg_end];
    if seg == "+" || seg == "#" {
        return 0;
    }
    return core::fnv1a_32(seg);
}

inline fn does_bucket_match_topic(
    b_entry:    const realtime::TopicBucket&,
    topic:      const u8[:],
    t_hash:     u32,
    t_seg_hash: u32,
) -> bool {
    if !b_entry.has_wildcard {
        return b_entry.pattern_hash == t_hash && b_entry.topic_pattern[..] == topic;
    }
    if b_entry.first_seg_hash != 0 && b_entry.first_seg_hash != t_seg_hash {
        return false;
    }
    return realtime::match_topic(b_entry.topic_pattern[..], topic);
}

// Finds the index of a bucket matching the given topic pattern.
//
// Example:
//   pattern = "chat/general"
//   returns: idx = 0, ok = true (or 0, false if not found)
fn find_topic_bucket(tree: const realtime::TopicTree&, pattern: const u8[:]) -> i32, bool {
    let p_hash = core::fnv1a_32(pattern);
    for &b_entry, i in tree.buckets {
        if b_entry.in_use && b_entry.pattern_hash == p_hash && b_entry.topic_pattern[..] == pattern {
            return i as i32, true;
        }
    }
    return 0, false;
}

// Allocates or retrieves a topic bucket for the given pattern.
fn get_or_create_topic_bucket(tree: realtime::TopicTree&, pattern: const u8[:]) -> i32, bool {
    guard realtime::is_valid_topic_filter(pattern) else { return 0, false; }

    let existing, found = find_topic_bucket(tree, pattern);
    if found {
        return existing, true;
    }

    let p_hash = core::fnv1a_32(pattern);
    let seg_hash = compute_topic_first_seg_hash(pattern);
    for &b_entry, i in tree.buckets {
        if !b_entry.in_use {
            let _ = b_entry.topic_pattern.try_set(pattern);
            b_entry.pattern_hash = p_hash;
            b_entry.first_seg_hash = seg_hash;
            b_entry.head_sub = -1;
            b_entry.subscriber_count = 0;
            b_entry.has_wildcard = pattern.contains_byte('+') || pattern.contains_byte('#');
            b_entry.in_use = true;
            tree.active_buckets = core::add_sat_i64(tree.active_buckets, 1) as i32;
            return i as i32, true;
        }
    }

    return 0, false;
}

fn is_subscribed_in_bucket(tree: const realtime::TopicTree&, b: i64, sock_fd: i64) -> bool {
    var cur = tree.buckets[b].head_sub;
    while cur >= 0 {
        let cur_i64 = cur as i64;
        let node .= tree.nodes[cur_i64];
        if node.in_use && node.sock_fd == sock_fd {
            return true;
        }
        cur = node.next_sub;
    }
    return false;
}

fn unlink_drainable_node(tree: realtime::TopicTree&, node_idx: i32) {
    guard node_idx >= 0 && node_idx < tree.nodes.len as i32 else { return; }
    let n_i64 = node_idx as i64;
    let prev = tree.nodes[n_i64].prev_drainable;
    let next = tree.nodes[n_i64].next_drainable;

    if prev >= 0 {
        tree.nodes[prev as i64].next_drainable = next;
    }
    if next >= 0 {
        tree.nodes[next as i64].prev_drainable = prev;
    }
    if tree.drainable_head == node_idx {
        tree.drainable_head = next;
    }
    tree.nodes[n_i64].prev_drainable = -1;
    tree.nodes[n_i64].next_drainable = -1;
}

fn link_drainable_head(tree: realtime::TopicTree&, cur: i32, c_i64: i64) {
    tree.nodes[c_i64].next_drainable = tree.drainable_head;
    tree.nodes[c_i64].prev_drainable = -1;
    if tree.drainable_head >= 0 {
        tree.nodes[tree.drainable_head as i64].prev_drainable = cur;
    }
    tree.drainable_head = cur;
}

fn migrate_drainable_queue_if_subscribed(
    tree:    realtime::TopicTree&,
    cur:     i32,
    cur_i64: i64,
    fd:      i64,
) {
    let count = tree.nodes[cur_i64].num_message_indices;
    unlink_drainable_node(tree, cur);
    tree.nodes[cur_i64].num_message_indices = 0;
    for i in tree.nodes.len {
        if i != cur_i64 && tree.nodes[i].in_use && tree.nodes[i].sock_fd == fd &&
            tree.nodes[i].num_message_indices == 0 {
            for m in count as i64 {
                tree.nodes[i].message_indices[m] = tree.nodes[cur_i64].message_indices[m];
            }
            tree.nodes[i].num_message_indices = count;
            link_drainable_head(tree, i as i32, i);
            return;
        }
    }
}

fn release_subscription_node(
    tree: realtime::TopicTree&,
    b:    i64,
    prev: i32,
    cur:  i32,
) -> i32, i32 {
    let cur_i64 = cur as i64;
    let fd = tree.nodes[cur_i64].sock_fd;
    let next = tree.nodes[cur_i64].next_sub;
    if prev < 0 {
        tree.buckets[b].head_sub = next;
    } else {
        tree.nodes[prev as i64].next_sub = next;
    }

    if tree.nodes[cur_i64].num_message_indices > 0 {
        migrate_drainable_queue_if_subscribed(tree, cur, cur_i64, fd);
    }

    tree.nodes[cur_i64].in_use = false;
    tree.nodes[cur_i64].sock_fd = -1;
    tree.nodes[cur_i64].next_sub = -1;

    let old_cnt = tree.buckets[b].subscriber_count;
    tree.buckets[b].subscriber_count = core::sub_sat_i64(old_cnt, 1) as i32;
    tree.active_subscriptions = core::sub_sat_i64(tree.active_subscriptions, 1) as i32;
    return next, old_cnt;
}

fn reclaim_empty_bucket(tree: realtime::TopicTree&, b: i64) {
    if tree.buckets[b].subscriber_count <= 0 {
        tree.buckets[b].in_use = false;
        tree.buckets[b].head_sub = -1;
        tree.active_buckets = core::sub_sat_i64(tree.active_buckets, 1) as i32;
    }
}

inline fn hash_fd_bucket(fd: i64) -> u64 {
    let u = fd as u64;
    return (u ^ (u >> 8)) & 255;
}

inline fn record_publish_stats(tree: realtime::TopicTree&, delivered: i64) {
    tree.total_publishes = core::add_sat_u64(tree.total_publishes, 1);
    tree.total_messages_delivered = core::add_sat_u64(tree.total_messages_delivered, delivered as u64);
}

fn flush_node_palette_messages(
    tree:  const realtime::TopicTree&,
    n_i64: i64,
    fd:    i64,
    count: i64,
) -> i64 {
    var sent_total: i64 = 0;
    for i in count {
        let msg_idx = tree.nodes[n_i64].message_indices[i] as i64;
        if msg_idx >= 0 && msg_idx < tree.palette_len {
            let sent = net::tcp_send(fd, tree.palette[msg_idx].wire[..]);
            if sent > 0 {
                sent_total = core::add_sat_i64(sent_total, 1);
            }
        }
    }
    return sent_total;
}

fn check_and_mark_batch_seen(
    fd:        i64,
    seen_fds:  i64[..512]&,
    seen_mask: u64[4]&,
) -> BatchSeenResult {
    guard fd > 0 else { return BatchSeenResult.CapacityExceeded; }
    let h = hash_fd_bucket(fd);
    let word_idx = (h >> 6) as i64;
    let bit = core::shl_sat_u64(1, (h & 63) as u32);

    if (seen_mask[word_idx] & bit) == 0 {
        guard seen_fds.try_push(fd) else { return BatchSeenResult.CapacityExceeded; }
        seen_mask[word_idx] |= bit;
        return BatchSeenResult.Added;
    }

    for s_fd in seen_fds {
        if s_fd == fd {
            return BatchSeenResult.AlreadySeen;
        }
    }
    guard seen_fds.try_push(fd) else { return BatchSeenResult.CapacityExceeded; }
    return BatchSeenResult.Added;
}

fn find_drainable_node_for_fd(
    tree:     const realtime::TopicTree&,
    fd:       i64,
    fallback: i32,
) -> i32 {
    var d_cur = tree.drainable_head;
    while d_cur >= 0 {
        let d_i64 = d_cur as i64;
        let node .= tree.nodes[d_i64];
        if node.in_use && node.sock_fd == fd {
            return d_cur;
        }
        d_cur = node.next_drainable;
    }
    return fallback;
}

fn queue_subscriber_batch(
    tree:      realtime::TopicTree&,
    cur:       i32,
    msg_idx:   i64,
    sender_fd: i64,
    seen_fds:  i64[..512]&,
    seen_mask: u64[4]&,
) -> bool {
    let raw_i64 = cur as i64;
    guard tree.nodes[raw_i64].in_use && tree.nodes[raw_i64].sock_fd != sender_fd else { return false; }
    let fd = tree.nodes[raw_i64].sock_fd;

    let seen_res = check_and_mark_batch_seen(fd, seen_fds, seen_mask);
    guard seen_res != BatchSeenResult.CapacityExceeded else { return false; }
    var already_queued = seen_res == BatchSeenResult.AlreadySeen;

    let target_node = find_drainable_node_for_fd(tree, fd, cur);
    let c_i64 = target_node as i64;
    let num = tree.nodes[c_i64].num_message_indices as i64;
    if num > 0 {
        let last_idx = core::sub_sat_i64(num, 1);
        if tree.nodes[c_i64].message_indices[last_idx] == (msg_idx as u16) {
            already_queued = true;
        }
    }

    guard !already_queued else { return false; }

    if tree.nodes[c_i64].num_message_indices >= 32 {
        tree.drain_subscriber(target_node);
    }

    let cur_num = tree.nodes[c_i64].num_message_indices as i64;
    tree.nodes[c_i64].message_indices[cur_num] = msg_idx as u16;
    tree.nodes[c_i64].num_message_indices = core::add_sat_i64(cur_num, 1) as u8;

    if tree.nodes[c_i64].num_message_indices == 1 {
        link_drainable_head(tree, target_node, c_i64);
    }
    return true;
}

inline fn find_retained_slot_for_topic(
    tree:  const realtime::TopicTree&,
    topic: const u8[:],
) -> i64 {
    var free_slot: i64 = -1;
    for i in tree.retained.len {
        let entry .= tree.retained[i];
        if entry.active && entry.topic[..] == topic {
            return i;
        }
        if !entry.active && free_slot < 0 {
            free_slot = i;
        }
    }
    return free_slot;
}

inline fn enqueue_retained_to_subscriber(
    tree:      realtime::TopicTree&,
    sub_fd:    i64,
    payload:   const u8[:],
    is_binary: bool,
) {
    var node_idx: i32 = -1;
    for &n_entry, i in tree.nodes {
        if n_entry.in_use && n_entry.sock_fd == sub_fd {
            node_idx = i as i32;
            break;
        }
    }
    guard node_idx >= 0 else { return; }

    if tree.palette_len >= (tree.palette.cap as i32) {
        tree.drain();
    }

    let msg_idx = tree.palette_len as i64;
    tree.palette[msg_idx].wire.clear();
    let opcode = if is_binary { rfc::WS_OPCODE_BINARY } else { rfc::WS_OPCODE_TEXT };
    let no_mask: u8[4] = [0, 0, 0, 0];
    realtime::encode_ws_frame(tree.palette[msg_idx].wire, opcode, payload, false, no_mask, true);
    tree.palette_len = (core::add_sat_i64(msg_idx, 1)) as i32;

    var seen_fds:  i64[..512] = [];
    var seen_mask: u64[4]     = [0, 0, 0, 0];
    let _ = queue_subscriber_batch(tree, node_idx, msg_idx, -1, seen_fds, seen_mask);
}

// Appends a socket descriptor to `out_fds` if not previously recorded in bitmask or array.
// Returns `(count: i32, ok: bool)` with `ok = false` when `out_fds` reaches its 512-subscriber capacity.
fn add_distinct_subscriber(out_fds: i64[..512]&, seen_mask: u64[4]&, fd: i64) -> i32, bool {
    guard fd > 0 else { return out_fds.len as i32, false; }
    let h = hash_fd_bucket(fd);
    let word_idx = (h >> 6) as i64;
    let bit = core::shl_sat_u64(1, (h & 63) as u32);

    if (seen_mask[word_idx] & bit) == 0 {
        guard out_fds.try_push(fd) else { return out_fds.len as i32, false; }
        seen_mask[word_idx] |= bit;
        return out_fds.len as i32, true;
    }

    for d_fd in out_fds {
        if d_fd == fd { return out_fds.len as i32, true; }
    }
    guard out_fds.try_push(fd) else { return out_fds.len as i32, false; }
    return out_fds.len as i32, true;
}

// ---- WebTransport Internal Helpers (draft-16 & RFC 9000) -----------------

struct WebTransportDemuxHeader {
    kind:       realtime::WebTransportStreamKind = realtime::WebTransportStreamKind.Unknown,
    session_id: u64                              = 0,
    header_len: i64                              = 0,
}

fn write_varint<B>(out: B&, val: u64) {
    guard val <= 0x3FFFFFFFFFFFFFFF else { return; }
    if val <= 63 {
        out.push(val as u8);
    } else if val <= 16383 {
        out.push((0x40 | ((val >> 8) & 0x3F)) as u8);
        out.push((val & 0xFF) as u8);
    } else if val <= 1073741823 {
        out.push((0x80 | ((val >> 24) & 0x3F)) as u8);
        out.push(((val >> 16) & 0xFF) as u8);
        out.push(((val >> 8) & 0xFF) as u8);
        out.push((val & 0xFF) as u8);
    } else {
        out.push((0xC0 | ((val >> 56) & 0x3F)) as u8);
        out.push(((val >> 48) & 0xFF) as u8);
        out.push(((val >> 40) & 0xFF) as u8);
        out.push(((val >> 32) & 0xFF) as u8);
        out.push(((val >> 24) & 0xFF) as u8);
        out.push(((val >> 16) & 0xFF) as u8);
        out.push(((val >> 8) & 0xFF) as u8);
        out.push((val & 0xFF) as u8);
    }
}

// RFC 9000 Section 2.1: Stream Types and Identifiers - Client-initiated bidirectional stream IDs have low bits 0x00.
inline fn is_valid_webtransport_session_id(session_id: u64) -> bool {
    return session_id <= rfc::QUIC_VARINT_MAX && (session_id & 0x03) == 0;
}

// draft-ietf-webtrans-overview Section 4.2: Bidirectional Streams - WebTransport Stream Header Demux
// Demuxes a WebTransport stream header from incoming QUIC stream wire bytes.
//
// Example:
//   wire = [0x40, 0x54, 0x10], is_bidi = false
//   returns: WebTransportDemuxHeader { kind: Unidirectional, session_id: 16, header_len: 3 }, ok = true
fn demux_webtransport_stream_header(
    wire:    const u8[:],
    is_bidi: bool,
) -> WebTransportDemuxHeader, bool {
    if is_bidi {
        let bidi, ok = realtime::decode_webtransport_bidi_stream_header(wire);
        guard ok else { return WebTransportDemuxHeader { .. }, false; }
        return WebTransportDemuxHeader {
            kind:       realtime::WebTransportStreamKind.Bidirectional,
            session_id: bidi.session_id,
            header_len: bidi.header_len,
        }, true;
    }

    let uni, ok = realtime::decode_webtransport_uni_stream_header(wire);
    guard ok else { return WebTransportDemuxHeader { .. }, false; }
    return WebTransportDemuxHeader {
        kind:       realtime::WebTransportStreamKind.Unidirectional,
        session_id: uni.session_id,
        header_len: uni.header_len,
    }, true;
}

fn find_stream_route_index(demuxer: const realtime::WebTransportDemuxer&, stream_id: u64) -> i64, bool {
    for &r, i in demuxer.streams {
        if r.stream_id == stream_id && r.is_open {
            return i, true;
        }
    }
    return -1, false;
}

fn find_session_entry_index(demuxer: const realtime::WebTransportDemuxer&, session_id: u64) -> i64, bool {
    for &s, i in demuxer.sessions {
        if s.session_id == session_id {
            return i, true;
        }
    }
    return -1, false;
}

fn close_session_streams(demuxer: realtime::WebTransportDemuxer&, session_id: u64) {
    for &r in demuxer.streams {
        if r.session_id == session_id {
            r.is_open = false;
        }
    }
}

inline fn is_session_routable(state: realtime::WebTransportSessionState) -> bool {
    return state == realtime::WebTransportSessionState.Active ||
           state == realtime::WebTransportSessionState.Draining;
}

fn record_new_stream_route(
    demuxer:         realtime::WebTransportDemuxer&,
    stream_id:       u64,
    session_id:      u64,
    kind:            realtime::WebTransportStreamKind,
    bytes_delivered: u64,
) -> bool {
    let route = realtime::WebTransportStreamRoute {
        stream_id:       stream_id,
        session_id:      session_id,
        kind:            kind,
        is_open:         true,
        bytes_delivered: bytes_delivered,
    };
    for &r in demuxer.streams {
        if !r.is_open {
            r = route;
            return true;
        }
    }
    return demuxer.streams.try_push(route);
}

fn route_existing_stream(
    demuxer:   realtime::WebTransportDemuxer&,
    route_idx: i64,
    wire:      const u8[:],
    fin:       bool,
    out:       realtime::WebTransportStreamPayload&,
) -> bool {
    guard route_idx >= 0 && route_idx < demuxer.streams.len else { return false; }
    let route .= demuxer.streams[route_idx];
    let sid = route.session_id;

    let s_idx, has_session = find_session_entry_index(demuxer, sid);
    guard has_session && s_idx >= 0 && s_idx < demuxer.sessions.len else {
        demuxer.dropped_frames = core::add_sat_u64(demuxer.dropped_frames, 1);
        return false;
    }

    let sess .= demuxer.sessions[s_idx];
    guard is_session_routable(sess.state) else {
        demuxer.dropped_frames = core::add_sat_u64(demuxer.dropped_frames, 1);
        return false;
    }

    sess.frames_received = core::add_sat_u64(sess.frames_received, 1);
    if fin {
        route.is_open = false;
    }

    out.kind = route.kind;
    out.stream_id = route.stream_id;
    out.session_id = sid;
    out.payload = wire;
    out.fin = fin;

    sess.bytes_received = core::add_sat_u64(sess.bytes_received, wire.len as u64);
    route.bytes_delivered = core::add_sat_u64(route.bytes_delivered, wire.len as u64);
    demuxer.total_dispatched = core::add_sat_u64(demuxer.total_dispatched, 1);
    return true;
}

fn route_new_stream(
    demuxer:   realtime::WebTransportDemuxer&,
    stream_id: u64,
    wire:      const u8[:],
    fin:       bool,
    out:       realtime::WebTransportStreamPayload&,
) -> bool {
    let is_bidi = (stream_id & 0x02) == 0;
    let hdr, ok_hdr = demux_webtransport_stream_header(wire, is_bidi);
    guard ok_hdr else {
        demuxer.dropped_frames = core::add_sat_u64(demuxer.dropped_frames, 1);
        return false;
    }

    let s_idx, has_session = find_session_entry_index(demuxer, hdr.session_id);
    guard has_session && s_idx >= 0 && s_idx < demuxer.sessions.len else {
        demuxer.dropped_frames = core::add_sat_u64(demuxer.dropped_frames, 1);
        return false;
    }

    let sess .= demuxer.sessions[s_idx];
    guard sess.state == realtime::WebTransportSessionState.Active else {
        demuxer.dropped_frames = core::add_sat_u64(demuxer.dropped_frames, 1);
        return false;
    }

    guard hdr.header_len >= 0 && hdr.header_len <= wire.len else { return false; }
    let payload = wire[hdr.header_len..];

    if !fin {
        guard record_new_stream_route(demuxer, stream_id, hdr.session_id, hdr.kind, payload.len as u64) else {
            demuxer.dropped_frames = core::add_sat_u64(demuxer.dropped_frames, 1);
            return false;
        }
    }

    sess.streams_count = core::add_sat_u32(sess.streams_count, 1);
    sess.frames_received = core::add_sat_u64(sess.frames_received, 1);
    sess.bytes_received = core::add_sat_u64(sess.bytes_received, payload.len as u64);

    out.kind = hdr.kind;
    out.stream_id = stream_id;
    out.session_id = hdr.session_id;
    out.payload = payload;
    out.fin = fin;

    demuxer.total_dispatched = core::add_sat_u64(demuxer.total_dispatched, 1);
    return true;
}

// ---- Varint Reader (RFC 9000 Section 16) ---------------------------------

// Reads a variable-length integer (RFC 9000 Section 16).
// Advances `idx` past the consumed integer bytes; leaves `idx` unchanged on error.
//
// Example:
//   wire = [0x25], idx = 0
//   returns: 37, ok = true, idx = 1
fn read_varint(wire: const u8[:], idx: i64&) -> u64, bool {
    guard idx >= 0 && idx < wire.len else { return 0, false; }
    let first = wire[idx];
    let prefix = first >> 6;
    let needed = core::shl_sat_u64(1, prefix) as i64;
    let end_idx = core::add_sat_i64(idx, needed);
    guard end_idx <= wire.len else { return 0, false; }

    var v = (first & 0x3F) as u64;
    for i in 1..needed {
        let byte_idx = core::add_sat_i64(idx, i);
        v = core::shl_sat_u64(v, 8) | wire[byte_idx];
    }
    idx = end_idx;
    return v, true;
}
