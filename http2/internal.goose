// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal HTTP/2 connection state, ingress validation, and RFC 9218 scheduler helpers.
namespace h2_internal;

import std;
import core;
import rfc.h2;
import http.priority;
import .framing;
import .connection;

// ---- Connection State & Scheduler Helpers (RFC 9113 / RFC 9218) ----------

const DEFAULT_RESET_BURST:         u64 = 1000;           // nghttp2 v1.57.0 reference (CVE-2023-44487)
const DEFAULT_RESET_RATE:          u64 = 33;             // Tokens per second
const MAX_HEADER_BLOCK_SIZE_LIMIT: u32 = 65536;          // Hard 64 KB ceiling for any CONTINUATION / HEADERS block
const MAX_CONCURRENCY_VIOLATIONS:  u32 = 5;              // Rapid Reset non-cancelling variant defense
const MAX_HIGH_URGENCY_STREAK:     u32 = 16;             // Max consecutive frames before lower-urgency credit yield

// Checks if the connection has capacity to store an additional active stream descriptor.
fn has_free_stream_slot(s: const http2::Connection&) -> bool {
    if s.streams.len < s.streams.cap {
        return true;
    }
    for &slot in s.streams {
        if !slot.active {
            return true;
        }
    }
    return false;
}

inline fn is_closed_peer_stream_id(s: const http2::Connection&, stream_id: u32) -> bool {
    let _, closed_slot = http2::find_closed_stream_idx(s, stream_id);
    return closed_slot || ((stream_id & 1) == 1 && stream_id <= s.last_peer_stream_id);
}

inline fn is_closed_stream_id(s: const http2::Connection&, stream_id: u32) -> bool {
    guard stream_id > 0 else { return false; }
    if is_closed_peer_stream_id(s, stream_id) {
        return true;
    }
    if !s.is_server && s.last_peer_stream_id > 0 && (s.last_peer_stream_id & 1) == 0 {
        if (stream_id & 1) == 0 && stream_id <= s.last_peer_stream_id {
            return true;
        }
    }
    if s.last_local_stream_id > 0 && stream_id <= s.last_local_stream_id {
        if (stream_id & 1) == (s.last_local_stream_id & 1) {
            return true;
        }
    }
    return false;
}

inline fn should_keep_idle_priority(item: const http2::IdleStreamPriority&, opened_id: u32) -> bool {
    if item.stream_id == opened_id {
        return false;
    }
    return (opened_id & 1) == 0 || (item.stream_id & 1) != 1 || item.stream_id > opened_id;
}

fn take_idle_stream_priority(s: http2::Connection&, stream_id: u32) -> http::PriorityParam, bool {
    var matched_prio = http::PriorityParam { .. };
    var found = false;
    var kept: http2::IdleStreamPriority[..128] = [];
    for &item in s.idle_priorities {
        if item.stream_id == stream_id {
            matched_prio = item.prio;
            found = true;
        } else if should_keep_idle_priority(item, stream_id) {
            guard kept.try_push(item) else { break; }
        }
    }
    s.idle_priorities = kept;
    return matched_prio, found;
}

// Handles remote END_STREAM transition for an active stream.
inline fn apply_stream_end_remote(s: http2::Connection&, s_idx: i32) {
    let st .= s.streams[s_idx];
    if st.state == http2::StreamState.HalfClosedLocal {
        st.state = http2::StreamState.Closed;
        st.active = false;
        let _ = core::flat_index_remove(s.stream_index[..], st.stream_id);
        if s.active_stream_count > 0 {
            s.active_stream_count--;
        }
    } else {
        st.state = http2::StreamState.HalfClosedRemote;
    }
    http2::sync_stream_urgency_node(s, s_idx);
}

fn validate_h2_continuation_state(s: http2::Connection&, hdr: const http2::FrameHeader&, now_ms: u64) -> u32, bool {
    if s.continuation_stream_id != 0 {
        if hdr.frame_type != rfc::H2_FRAME_CONTINUATION || hdr.stream_id != s.continuation_stream_id {
            return rfc::H2_ERR_PROTOCOL_ERROR, true;
        }

        if hdr.length == 0 && (hdr.flags & rfc::H2_FLAG_END_HEADERS) == 0 {
            return rfc::H2_ERR_PROTOCOL_ERROR, true;
        }

        if now_ms > s.continuation_start_ms {
            let duration_ms = now_ms - s.continuation_start_ms;
            if duration_ms > s.max_header_block_duration_ms {
                return rfc::H2_ERR_ENHANCE_YOUR_CALM, true;
            }
        }

        let next_cnt = core::add_sat_u32(s.continuation_frames_cnt, 1);
        if next_cnt > http2::MAX_CONT_FRAMES_LIMIT {
            return rfc::H2_ERR_ENHANCE_YOUR_CALM, true;
        }

        let next_size = core::add_sat_u32(s.accumulated_header_size, hdr.length);
        if next_size > s.max_header_list_size
            || next_size > MAX_HEADER_BLOCK_SIZE_LIMIT {
            return rfc::H2_ERR_ENHANCE_YOUR_CALM, true;
        }

        if (hdr.flags & rfc::H2_FLAG_END_HEADERS) != 0 {
            s.continuation_stream_id = 0;
            s.continuation_frames_cnt = 0;
            s.accumulated_header_size = 0;
        } else {
            s.continuation_frames_cnt = next_cnt;
            s.accumulated_header_size = next_size;
        }
        return rfc::H2_ERR_NO_ERROR, true;
    }

    if hdr.frame_type == rfc::H2_FRAME_CONTINUATION {
        return rfc::H2_ERR_PROTOCOL_ERROR, true;
    }

    return rfc::H2_ERR_NO_ERROR, false;
}

inline fn is_empty_frame_payload(hdr: const http2::FrameHeader&) -> bool {
    if hdr.frame_type == rfc::H2_FRAME_DATA {
        let pad_len: u32 = if (hdr.flags & rfc::H2_FLAG_PADDED) != 0 { 1 } else { 0 };
        return (hdr.length <= pad_len) && ((hdr.flags & rfc::H2_FLAG_END_STREAM) == 0);
    }
    if hdr.frame_type == rfc::H2_FRAME_HEADERS {
        let pad_len:  u32 = if (hdr.flags & rfc::H2_FLAG_PADDED) != 0 { 1 } else { 0 };
        let prio_len: u32 = if (hdr.flags & rfc::H2_FLAG_PRIORITY) != 0 { 5 } else { 0 };
        return (hdr.length <= (pad_len + prio_len))
            && ((hdr.flags & rfc::H2_FLAG_END_STREAM) == 0)
            && ((hdr.flags & rfc::H2_FLAG_END_HEADERS) == 0);
    }
    return false;
}

fn validate_h2_empty_frame_streak(s: http2::Connection&, hdr: const http2::FrameHeader&) -> u32 {
    if is_empty_frame_payload(hdr) {
        s.empty_frame_streak++;
        if s.empty_frame_streak > http2::MAX_EMPTY_FRAME_STREAK {
            return rfc::H2_ERR_ENHANCE_YOUR_CALM;
        }
    } else {
        s.empty_frame_streak = 0;
    }
    return rfc::H2_ERR_NO_ERROR;
}

fn handle_h2_rst_stream_header(s: http2::Connection&, hdr: const http2::FrameHeader&, now_ms: u64) -> u32 {
    if hdr.stream_id == 0 {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }
    if hdr.length != 4 {
        return rfc::H2_ERR_FRAME_SIZE_ERROR;
    }

    let s_idx, found = http2::find_stream_idx(s, hdr.stream_id);
    if !found && !is_closed_stream_id(s, hdr.stream_id) {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }

    if !core::token_bucket_consume(s.reset_limiter, now_ms) {
        return rfc::H2_ERR_ENHANCE_YOUR_CALM;
    }

    if found {
        let st .= s.streams[s_idx];
        st.state = http2::StreamState.Closed;
        st.closed_by_rst = true;
        st.active = false;
        let _ = core::flat_index_remove(s.stream_index[..], hdr.stream_id);
        if s.active_stream_count > 0 {
            s.active_stream_count--;
        }
        http2::sync_stream_urgency_node(s, s_idx);
    }
    return rfc::H2_ERR_NO_ERROR;
}

inline fn calc_headers_hpack_len(hdr: const http2::FrameHeader&) -> u32 {
    var len = hdr.length;
    if (hdr.flags & rfc::H2_FLAG_PADDED) != 0 && len > 0 {
        len--;
    }
    if (hdr.flags & rfc::H2_FLAG_PRIORITY) != 0 && len >= 5 {
        len -= 5;
    }
    return len;
}

fn handle_existing_stream_headers(s: http2::Connection&, s_idx: i32, flags: u8) -> u32 {
    let st .= s.streams[s_idx];
    if st.state == http2::StreamState.HalfClosedRemote ||
       st.state == http2::StreamState.Closed {
        return rfc::H2_ERR_STREAM_CLOSED;
    }
    if st.headers_received {
        if st.trailers_received {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
        // RFC 9113 Section 8.1: A HEADERS frame for trailers MUST carry END_STREAM
        if (flags & rfc::H2_FLAG_END_STREAM) == 0 {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
        let dec_len = st.declared_content_length;
        if dec_len >= 0 && dec_len != st.received_data_bytes {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
        st.trailers_received = true;
        apply_stream_end_remote(s, s_idx);
    } else {
        st.headers_received = true;
        if (flags & rfc::H2_FLAG_END_STREAM) != 0 {
            apply_stream_end_remote(s, s_idx);
        }
    }
    return rfc::H2_ERR_NO_ERROR;
}

fn handle_h2_headers_frame_header(s: http2::Connection&, hdr: const http2::FrameHeader&, now_ms: u64) -> u32 {
    // RFC 9113 Section 4.2: Frame Size - An endpoint MUST send an error code of FRAME_SIZE_ERROR if a frame exceeds the size defined in SETTINGS_MAX_FRAME_SIZE, exceeds any limit defined for the frame type, or is too small to contain mandatory frame data.
    let rule_err = http2::validate_frame_header_rules(hdr, s.local_max_frame_size);
    guard rule_err == rfc::H2_ERR_NO_ERROR else { return rule_err; }

    guard hdr.stream_id != 0 else { return rfc::H2_ERR_PROTOCOL_ERROR; }

    if hdr.length == 0 && (hdr.flags & rfc::H2_FLAG_END_HEADERS) == 0 {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }

    let hpack_len = calc_headers_hpack_len(hdr);
    if hpack_len > s.max_header_list_size || hpack_len > MAX_HEADER_BLOCK_SIZE_LIMIT {
        return rfc::H2_ERR_ENHANCE_YOUR_CALM;
    }

    if (hdr.stream_id & 1) == 0 {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }

    let s_idx, found = http2::find_stream_idx(s, hdr.stream_id);
    if !found {
        if hdr.stream_id <= s.last_peer_stream_id {
            return rfc::H2_ERR_STREAM_CLOSED;
        }

        // RFC 9113 Section 6.8 & Go #82365:
        // After receiving or sending final GOAWAY, any new stream with ID > goaway_last_stream_id must be refused
        if (s.goaway_received || s.goaway_sent) && hdr.stream_id > s.goaway_last_stream_id {
            return rfc::H2_ERR_REFUSED_STREAM;
        }

        if s.active_stream_count >= s.max_concurrent_streams {
            s.concurrency_violations++;
            if s.concurrency_violations > MAX_CONCURRENCY_VIOLATIONS {
                return rfc::H2_ERR_ENHANCE_YOUR_CALM;
            }
            return rfc::H2_ERR_REFUSED_STREAM;
        }

        guard has_free_stream_slot(s) else {
            return rfc::H2_ERR_REFUSED_STREAM;
        }

        s.last_peer_stream_id = hdr.stream_id;
        s.concurrency_violations = 0;
        http2::open_stream(s, hdr.stream_id, (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0);
    } else {
        let err = handle_existing_stream_headers(s, s_idx, hdr.flags);
        guard err == rfc::H2_ERR_NO_ERROR else { return err; }
    }

    if (hdr.flags & rfc::H2_FLAG_END_HEADERS) == 0 {
        s.continuation_stream_id = hdr.stream_id;
        s.continuation_frames_cnt = 0;
        s.accumulated_header_size = hpack_len;
        s.continuation_start_ms = now_ms;
    }
    return rfc::H2_ERR_NO_ERROR;
}

inline fn calc_push_promise_hpack_len(hdr: const http2::FrameHeader&) -> u32 {
    var len = if hdr.length >= 4 { hdr.length - 4 } else { 0 };
    if (hdr.flags & rfc::H2_FLAG_PADDED) != 0 && len > 0 {
        len--;
    }
    return len;
}

// RFC 9113 Section 6.6: PUSH_PROMISE - Tracks CONTINUATION and permits locally RST_STREAM-closed streams.
fn handle_h2_push_promise_frame_header(
    s:      http2::Connection&,
    hdr:    const http2::FrameHeader&,
    now_ms: u64,
) -> u32 {
    let rule_err = http2::validate_frame_header_rules(hdr, s.local_max_frame_size);
    guard rule_err == rfc::H2_ERR_NO_ERROR else { return rule_err; }

    guard !s.is_server && s.enable_push else { return rfc::H2_ERR_PROTOCOL_ERROR; }
    guard hdr.stream_id != 0 && (hdr.stream_id & 1) == 1 else { return rfc::H2_ERR_PROTOCOL_ERROR; }
    let c_idx, is_closed = http2::find_closed_stream_idx(s, hdr.stream_id);
    if is_closed {
        guard s.streams[c_idx].closed_by_rst else { return rfc::H2_ERR_PROTOCOL_ERROR; }
    }
    let s_idx, found = http2::find_stream_idx(s, hdr.stream_id);
    if found {
        let st = s.streams[s_idx].state;
        let ok_state = st == http2::StreamState.Open || st == http2::StreamState.HalfClosedLocal
            || (st == http2::StreamState.Closed && s.streams[s_idx].closed_by_rst);
        guard ok_state else {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
    } else if !is_closed && (s.streams.len > 0 || s.last_local_stream_id > 0) {
        if s.last_local_stream_id == 0 || hdr.stream_id > s.last_local_stream_id {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
    }

    let hpack_len = calc_push_promise_hpack_len(hdr);
    if hpack_len > s.max_header_list_size || hpack_len > MAX_HEADER_BLOCK_SIZE_LIMIT {
        return rfc::H2_ERR_ENHANCE_YOUR_CALM;
    }

    if (hdr.flags & rfc::H2_FLAG_END_HEADERS) == 0 {
        s.continuation_stream_id = hdr.stream_id;
        s.continuation_frames_cnt = 0;
        s.accumulated_header_size = hpack_len;
        s.continuation_start_ms = now_ms;
    }
    return rfc::H2_ERR_NO_ERROR;
}

fn check_h2_control_frame_flood(s: http2::Connection&, hdr: const http2::FrameHeader&) -> u32 {
    let is_ctrl = hdr.frame_type == rfc::H2_FRAME_PING || hdr.frame_type == rfc::H2_FRAME_SETTINGS;
    if is_ctrl && (hdr.flags & rfc::H2_FLAG_ACK) == 0 {
        s.pending_control_frames++;
        if s.pending_control_frames > http2::MAX_PENDING_CTRL_FRAMES {
            return rfc::H2_ERR_ENHANCE_YOUR_CALM;
        }
    }
    return rfc::H2_ERR_NO_ERROR;
}

// Unlinks stream node `s_idx` from its urgency bucket `u` if currently linked.
fn unlink_stream_from_urgency_bucket(s: http2::Connection&, s_idx: i32, u: u8) {
    guard s_idx >= 0 && s_idx < 128 && u <= 7 else { return; }
    let u_idx = u as i64;
    let node .= s.stream_nodes[s_idx];
    let prev = node.prev;
    let next = node.next;
    let is_head = (s.urgency_heads[u_idx] == s_idx);
    let is_tail = (s.urgency_tails[u_idx] == s_idx);
    guard is_head || is_tail || prev >= 0 || next >= 0 else { return; }

    if prev >= 0 {
        s.stream_nodes[prev].next = next;
    } else if is_head {
        s.urgency_heads[u_idx] = next;
    }

    if next >= 0 {
        s.stream_nodes[next].prev = prev;
    } else if is_tail {
        s.urgency_tails[u_idx] = prev;
    }

    node.prev = -1;
    node.next = -1;

    if s.urgency_heads[u_idx] < 0 {
        s.urgency_tails[u_idx] = -1;
        s.active_urgency_mask &= ~(1 << u);
    }
}

// Appends stream node `s_idx` to the tail of urgency bucket `u` and sets the bit in `active_urgency_mask`.
fn link_stream_to_urgency_bucket(s: http2::Connection&, s_idx: i32, u: u8) {
    guard s_idx >= 0 && s_idx < 128 && u <= 7 else { return; }
    unlink_stream_from_urgency_bucket(s, s_idx, u);
    let u_idx = u as i64;
    let node .= s.stream_nodes[s_idx];
    node.stream_id = s.streams[s_idx].stream_id;
    node.next = -1;
    let tail = s.urgency_tails[u_idx];
    if tail >= 0 {
        node.prev = tail;
        s.stream_nodes[tail].next = s_idx;
        s.urgency_tails[u_idx] = s_idx;
    } else {
        node.prev = -1;
        s.urgency_heads[u_idx] = s_idx;
        s.urgency_tails[u_idx] = s_idx;
    }
    s.active_urgency_mask |= (1 << u);
}

// Rebuilds `active_urgency_mask` and `stream_nodes` intrusive lists for any streams modified directly.
fn refresh_active_urgency_buckets(s: http2::Connection&) {
    var u: i64 = 0;
    while u < 8 {
        s.urgency_heads[u] = -1;
        s.urgency_tails[u] = -1;
        u++;
    }
    s.active_urgency_mask = 0;
    var idx: i32 = 0;
    let count = s.streams.len as i32;
    while idx < count {
        let node .= s.stream_nodes[idx];
        let stream .= s.streams[idx];
        node.prev = -1;
        node.next = -1;
        node.stream_id = stream.stream_id;
        let st = stream.state;
        let can_send = (st == http2::StreamState.Open || st == http2::StreamState.HalfClosedRemote);
        if stream.active && can_send && stream.pending_send_bytes > 0
            && stream.send_window > 0 && stream.priority.urgency <= 7 {
            link_stream_to_urgency_bucket(s, idx, stream.priority.urgency);
        }
        idx++;
    }
}

fn record_idle_stream_priority(
    s:         http2::Connection&,
    stream_id: u32,
    prio:      http::PriorityParam,
) -> u32 {
    var final_prio = prio;
    if s.is_behind_proxy {
        final_prio.urgency = 3;
        final_prio.incremental = true;
    }
    for &entry in s.idle_priorities {
        if entry.stream_id == stream_id {
            entry.prio = final_prio;
            return rfc::H2_ERR_NO_ERROR;
        }
    }
    let total_tracked = core::add_sat_i64(core::add_sat_i64(s.active_stream_count, s.idle_priorities.len), 1);
    guard total_tracked <= s.max_concurrent_streams else {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }
    guard s.idle_priorities.try_push(http2::IdleStreamPriority {
        stream_id: stream_id,
        prio:      final_prio,
    }) else {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }
    return rfc::H2_ERR_NO_ERROR;
}

// RFC 9218 Section 4: Priority Parameters - Counts trailing zeros of a non-zero 8-bit urgency mask
// to select the highest priority active bucket (bit 0 = urgency 0) in O(1).
inline fn ctz_urgency_mask(mask: u8) -> u8 {
    if (mask & 0x01) != 0 { return 0; }
    if (mask & 0x02) != 0 { return 1; }
    if (mask & 0x04) != 0 { return 2; }
    if (mask & 0x08) != 0 { return 3; }
    if (mask & 0x10) != 0 { return 4; }
    if (mask & 0x20) != 0 { return 5; }
    if (mask & 0x40) != 0 { return 6; }
    return 7;
}

inline fn commit_stream_send_quota(
    s:             http2::Connection&,
    chosen_idx:    i32,
    max_frame_len: u32,
) -> u32, u32, bool {
    let chosen .= s.streams[chosen_idx];
    let target_stream_id = chosen.stream_id;
    let quota = http2::compute_stream_send_quota(s, target_stream_id);
    guard quota > 0 else { return 0, 0, false; }

    let stream_pending = chosen.pending_send_bytes;
    let quota_u32 = quota as u32;
    let quota_cap = min(
        stream_pending,
        quota_u32,
    );
    let frame_cap = min(
        max_frame_len,
        s.peer_max_frame_size,
    );
    let send_len = min(quota_cap, frame_cap);

    chosen.pending_send_bytes -= send_len;
    chosen.send_window -= send_len;
    s.conn_send_window -= send_len;
    http2::sync_stream_urgency_node(s, chosen_idx);

    if chosen.priority.urgency < 7 {
        s.urgency_streak_count++;
    } else {
        s.urgency_streak_count = 0;
    }

    return target_stream_id, send_len, true;
}

fn has_lower_urgency_ready(s: const http2::Connection&) -> bool {
    if (s.active_urgency_mask & 0xF8) != 0 {
        return true;
    }
    var chk: i32 = 0;
    let stream_count = s.streams.len as i32;
    while chk < stream_count {
        let cur .= s.streams[chk];
        let st = cur.state;
        let can_send = (st == http2::StreamState.Open || st == http2::StreamState.HalfClosedRemote);
        if cur.active && can_send && cur.pending_send_bytes > 0
            && cur.send_window > 0 && cur.priority.urgency >= 3 {
            return true;
        }
        chk++;
    }
    return false;
}

fn find_non_incremental_candidate(s: const http2::Connection&, u: u8) -> i32, bool {
    let u_idx = u as i64;
    var node_idx = s.urgency_heads[u_idx];
    while node_idx >= 0 {
        let cur .= s.streams[node_idx];
        let st = cur.state;
        let can_send = (st == http2::StreamState.Open || st == http2::StreamState.HalfClosedRemote);
        if cur.active && can_send && cur.pending_send_bytes > 0
            && cur.send_window > 0 && cur.priority.urgency == u
            && !cur.priority.incremental {
            return node_idx, true;
        }
        node_idx = s.stream_nodes[node_idx].next;
    }
    var idx: i32 = 0;
    let stream_count = s.streams.len as i32;
    while idx < stream_count {
        let cur .= s.streams[idx];
        let st = cur.state;
        let can_send = (st == http2::StreamState.Open || st == http2::StreamState.HalfClosedRemote);
        if cur.active && can_send && cur.pending_send_bytes > 0
            && cur.send_window > 0 && cur.priority.urgency == u
            && !cur.priority.incremental {
            return idx, true;
        }
        idx++;
    }
    return 0, false;
}

fn find_incremental_candidate(s: const http2::Connection&, u: u8) -> i32, bool {
    let u_idx = u as i64;
    let stream_count = s.streams.len as i32;
    guard stream_count > 0 else { return 0, false; }

    let last_inc = s.bucket_last_inc_idx[u_idx];
    var step: i32 = 1;
    while step <= stream_count {
        let candidate = if last_inc < 0 { step - 1 } else { (last_inc + step) % stream_count };
        if candidate >= 0 && candidate < stream_count {
            let cur .= s.streams[candidate];
            let st = cur.state;
            let can_send = (st == http2::StreamState.Open || st == http2::StreamState.HalfClosedRemote);
            if cur.active && can_send && cur.pending_send_bytes > 0
                && cur.send_window > 0 && cur.priority.urgency == u
                && cur.priority.incremental {
                return candidate, true;
            }
        }
        step++;
    }
    return 0, false;
}

fn select_and_commit_stream(
    s:             http2::Connection&,
    u:             u8,
    max_frame_len: u32,
) -> u32, u32, bool {
    let non_inc_idx, has_non_inc = find_non_incremental_candidate(s, u);
    let inc_idx, has_inc = find_incremental_candidate(s, u);
    let u_idx = u as i64;

    var chosen_idx: i32 = 0;
    var chosen = false;
    if has_non_inc && has_inc {
        if s.bucket_prefer_incremental[u_idx] {
            chosen_idx = inc_idx;
            s.bucket_last_inc_idx[u_idx] = inc_idx;
            s.bucket_prefer_incremental[u_idx] = false;
        } else {
            chosen_idx = non_inc_idx;
            s.bucket_prefer_incremental[u_idx] = true;
        }
        chosen = true;
    } else if has_non_inc {
        chosen_idx = non_inc_idx;
        chosen = true;
    } else if has_inc {
        chosen_idx = inc_idx;
        s.bucket_last_inc_idx[u_idx] = inc_idx;
        chosen = true;
    }

    guard chosen else { return 0, 0, false; }
    return commit_stream_send_quota(s, chosen_idx, max_frame_len);
}

inline fn apply_urgency_anti_starvation(s: http2::Connection&, mask: u8) -> u8 {
    guard s.urgency_streak_count >= MAX_HIGH_URGENCY_STREAK else { return mask; }
    let dominant_u = ctz_urgency_mask(mask);
    guard dominant_u < 7 else {
        s.urgency_streak_count = 0;
        return mask;
    }
    let masked = mask & ~(1 << dominant_u);
    if masked != 0 {
        return masked;
    }
    s.urgency_streak_count = 0;
    return mask;
}

inline fn scan_urgency_mask_for_write(
    s:             http2::Connection&,
    initial_mask:  u8,
    max_frame_len: u32,
) -> u32, u32, bool {
    var mask = initial_mask;
    while mask != 0 {
        let u = ctz_urgency_mask(mask);
        let target_stream_id, send_len, ok = select_and_commit_stream(s, u, max_frame_len);
        if ok {
            return target_stream_id, send_len, true;
        }
        mask &= core::sub_sat_u64(mask, 1) as u8;
    }
    return 0, 0, false;
}
