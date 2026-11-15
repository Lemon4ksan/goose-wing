// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/2 connection session coordinator, RFC 9218 write scheduler,
// two-level credit-based flow control, and defense-in-depth Anti-DoS mitigations (RFC 9113, RFC 9218).
namespace h2_internal;

import std;
import core from "..";
import .framing;
import .hpack;

// ---- session constants & limits ------------------------------------------

const DEFAULT_RESET_BURST:                  u64 = 1000;  // nghttp2 v1.57.0 reference (CVE-2023-44487)
const DEFAULT_RESET_RATE:                   u64 = 33;    // Tokens per second
const MAX_CONT_FRAMES_LIMIT:                u32 = 16;    // CONTINUATION Flood defense (CVE-2024-28182 / CVE-2024-30255)
const MAX_HEADER_BLOCK_SIZE_LIMIT:          u32 = 65536; // Hard 64 KB ceiling for any CONTINUATION / HEADERS block
const MAX_EMPTY_FRAME_STREAK:               u32 = 8;     // Empty Frame Flooding defense (CVE-2019-9518)
const MAX_PENDING_CTRL_FRAMES:              u32 = 64;    // PING/SETTINGS Flood defense (CVE-2019-9512 / CVE-2019-9515)
const MAX_CONCURRENCY_VIOLATIONS:           u32 = 5;     // Rapid Reset non-cancelling variant defense
const DEFAULT_MAX_HEADER_BLOCK_DURATION_MS: u64 = 10000; // Slow-Drip CONTINUATION memory retention defense

// ---- stream state machine & stream descriptors (rfc 9113 section 5.1) ---

enum H2StreamState {
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

struct H2Stream {
    stream_id:                    u32                 = 0,
    state:                        H2StreamState       = H2StreamState.Idle,
    send_window:                  i64                 = 65535, // Signed 64-bit integer to support negative deltas
    recv_window:                  i64                 = 65535,
    priority:                     wing::PriorityParam = wing::PriorityParam { .. },
    has_explicit_priority_update: bool                = false,
    pending_send_bytes:           u32                 = 0,
    declared_content_length:      i64                 = -1,
    received_data_bytes:          i64                 = 0,
    headers_received:             bool                = false,
    trailers_received:            bool                = false,
    closed_by_rst:                bool                = false,
    status_code:                  i32                 = 0,
    active:                       bool                = false,
}

// RFC 9218 Section 4: Priority Parameters - Array-indexed intrusive linked-list node for O(1) priority buckets.
struct StreamNode {
    stream_id: u32 = 0,
    next:      i32 = -1,
    prev:      i32 = -1,
}

// RFC 9218 Section 7.1: HTTP/2 PRIORITY_UPDATE Frame - Buffered priority for an idle peer stream.
struct IdleStreamPriority {
    stream_id: u32                 = 0,
    prio:      wing::PriorityParam = wing::PriorityParam { .. },
}

// ---- http/2 connection state & coordinator -------------------------------

struct H2Connection {
    hpack_dec:                 DynamicTable = DynamicTable { .. },
    conn_send_window:          i64          = 65535,
    conn_recv_window:          i64          = 65535,
    peer_initial_window_size:  i64          = 65535,
    local_initial_window_size: i64          = 65535,
    local_max_frame_size:      u32          = 16384,
    peer_max_frame_size:       u32          = 16384,
    max_header_list_size:      u32          = 8192,
    max_concurrent_streams:    u32          = 128,
    active_stream_count:       u32          = 0,
    last_peer_stream_id:       u32          = 0,
    last_local_stream_id:      u32          = 0,
    is_server:                 bool         = false,
    enable_push:               bool         = true,
    enable_connect_protocol:   u32          = 1,
    unclaimed_recv_window:     i64          = 0,
    coalesce_window_updates:   bool         = false,

    // Active streams table (bounded inline storage)
    streams:         H2Stream[..128]            = [],
    stream_index:    core::FlatIndexBucket[256] = [core::FlatIndexBucket { .. }; 256],
    idle_priorities: IdleStreamPriority[..128]  = [],

    // Exclusive CONTINUATION lock (0 if not expecting CONTINUATION)
    continuation_stream_id:       u32 = 0,
    continuation_frames_cnt:      u32 = 0,
    accumulated_header_size:      u32 = 0,
    continuation_start_ms:        u64 = 0,
    max_header_block_duration_ms: u64 = 10000,

    // Anti-DoS resource limiters
    reset_limiter:               core::TokenBucket = core::TokenBucket { .. },
    empty_frame_streak:          u32               = 0,
    pending_control_frames:      u32               = 0,
    concurrency_violations:      u32               = 0,
    initial_window_update_count: u32               = 0,

    // RFC 9218 prioritization flags
    client_sent_priority:  bool = false,
    no_rfc7540_priorities: bool = false,
    peer_no_rfc7540_set:   bool = false,
    is_behind_proxy:       bool = false,

    // Starvation toggle per urgency bucket (0..7) between incremental and non-incremental
    bucket_prefer_incremental: bool[8]         = [false; 8],
    bucket_last_inc_idx:       i32[8]          = [-1; 8],
    urgency_streak_count:      u32             = 0,
    active_urgency_mask:       u8              = 0,
    urgency_heads:             i32[8]          = [-1; 8],
    urgency_tails:             i32[8]          = [-1; 8],
    stream_nodes:              StreamNode[128] = [StreamNode { .. }; 128],

    // Shutdown / GOAWAY tracking
    shutdown_notice_sent:  bool = false,
    shutdown_ping_opaque:  u64  = 0x57494E47474F4157,
    goaway_sent:           bool = false,
    goaway_received:       bool = false,
    goaway_last_stream_id: u32  = 0,
    goaway_error_code:     u32  = 0,
}

type SessionState = H2Connection;

// Returns a default-initialized H2Connection with RFC 9113 & RFC 9218 baseline invariants.
fn new_h2_connection(
    now_ms:          u64  = 0,
    max_header_list: u32  = 8192,
    behind_proxy:    bool = false,
) -> H2Connection {
    return H2Connection {
        hpack_dec: new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE),
        reset_limiter: core::TokenBucket {
            tokens:         DEFAULT_RESET_BURST,
            burst:          DEFAULT_RESET_BURST,
            rate_per_sec:   DEFAULT_RESET_RATE,
            last_refill_ms: now_ms,
        },
        max_header_list_size: max_header_list,
        is_behind_proxy:      behind_proxy,
        is_server:            false,
        enable_push:          true,
        ..
    };
}

inline fn new_session_state(
    now_ms:          u64  = 0,
    max_header_list: u32  = 8192,
    behind_proxy:    bool = false,
) -> H2Connection {
    return new_h2_connection(now_ms, max_header_list, behind_proxy);
}

// Checks if the connection has capacity to store an additional active stream descriptor.
fn has_free_stream_slot(s: const H2Connection&) -> bool {
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

// Finds an active stream by stream_id. Returns (index, true) or (-1, false).
fn find_h2_stream_idx(s: const H2Connection&, stream_id: u32) -> i32, bool {
    let res = core::flat_index_get(s.stream_index[..], stream_id);
    guard res.found && res.slot_idx >= 0 && res.slot_idx < s.streams.len else {
        return -1, false;
    }
    let st .= s.streams[res.slot_idx];
    if st.active && st.stream_id == stream_id {
        return res.slot_idx, true;
    }
    return -1, false;
}

fn find_session_stream_idx(s: const H2Connection&, stream_id: u32) -> i32, bool {
    let idx, ok = find_h2_stream_idx(s, stream_id);
    return idx, ok;
}

// Finds a previously opened stream that has transitioned to Closed.
fn find_closed_h2_stream_idx(s: const H2Connection&, stream_id: u32) -> i32, bool {
    var idx: i32 = 0;
    while idx < (s.streams.len as i32) {
        let st .= s.streams[idx];
        if !st.active && st.state == H2StreamState.Closed && st.stream_id == stream_id {
            return idx, true;
        }
        idx++;
    }
    return -1, false;
}

inline fn is_closed_peer_stream_id(s: const H2Connection&, stream_id: u32) -> bool {
    let _, closed_slot = find_closed_h2_stream_idx(s, stream_id);
    return closed_slot || ((stream_id & 1) == 1 && stream_id <= s.last_peer_stream_id);
}

inline fn is_closed_stream_id(s: const H2Connection&, stream_id: u32) -> bool {
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

inline fn should_keep_idle_priority(item: const IdleStreamPriority&, opened_id: u32) -> bool {
    if item.stream_id == opened_id {
        return false;
    }
    return (opened_id & 1) == 0 || (item.stream_id & 1) != 1 || item.stream_id > opened_id;
}

fn take_idle_stream_priority(s: H2Connection&, stream_id: u32) -> wing::PriorityParam, bool {
    var matched_prio = wing::PriorityParam { .. };
    var found = false;
    var kept: IdleStreamPriority[..128] = [];
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

// ---- frame ingress coordinator & anti-dos barriers -----------------------

// Opens a new stream descriptor with default RFC 9218 priority.
fn open_new_session_stream(s: H2Connection&, stream_id: u32, end_stream: bool) {
    var def_prio = wing::PriorityParam {
        urgency: 3,
        // Go 1.27 #75500: default to incremental=true before first client priority signal
        incremental: if s.is_behind_proxy { true } else { !s.client_sent_priority },
    };
    let idle_prio, has_idle_prio = take_idle_stream_priority(s, stream_id);
    if has_idle_prio {
        def_prio = idle_prio;
    }

    var new_stream = H2Stream {
        stream_id:                    stream_id,
        state:                        if end_stream { H2StreamState.HalfClosedRemote } else { H2StreamState.Open },
        send_window:                  s.peer_initial_window_size,
        recv_window:                  s.local_initial_window_size,
        priority:                     def_prio,
        has_explicit_priority_update: has_idle_prio,
        headers_received:             true,
        active:                       true,
        ..
    };

    var slot_idx: i32 = -1;
    for i in s.streams.len {
        if !s.streams[i].active {
            s.streams[i] = new_stream;
            slot_idx = i as i32;
            break;
        }
    }
    if slot_idx < 0 {
        guard s.streams.try_push(new_stream) else { return; }
        slot_idx = core::sub_sat_i64(s.streams.len, 1) as i32;
    }
    let res = core::flat_index_get_or_put(s.stream_index[..], stream_id);
    if !res.found && res.bucket_idx >= 0 {
        let _, _ = core::flat_index_commit_put(
            s.stream_index[..],
            res.bucket_idx,
            stream_id,
            slot_idx as u16,
        );
    }
    s.active_stream_count = core::add_sat_u64(s.active_stream_count, 1) as u32;
}

// Marks the local half of a stream as closed (e.g. after sending END_STREAM).
// If the remote half is already closed, transitions stream to Closed and frees active slot.
fn close_local_stream(s: H2Connection&, stream_id: u32) {
    let s_idx, found = find_session_stream_idx(s, stream_id);
    guard found else { return; }

    let st .= s.streams[s_idx];
    if st.state == H2StreamState.HalfClosedRemote {
        st.state = H2StreamState.Closed;
        st.active = false;
        let _ = core::flat_index_remove(s.stream_index[..], stream_id);
        if s.active_stream_count > 0 {
            s.active_stream_count--;
        }
    } else if st.state == H2StreamState.Open {
        st.state = H2StreamState.HalfClosedLocal;
    }
    sync_stream_urgency_node(s, s_idx);
}

// Closes a stream descriptor and frees its active slot on stream error or RST_STREAM (RFC 9113 §5.1.2).
fn reset_session_stream(s: H2Connection&, stream_id: u32) {
    let s_idx, found = find_session_stream_idx(s, stream_id);
    guard found else { return; }

    let st .= s.streams[s_idx];
    st.state = H2StreamState.Closed;
    st.closed_by_rst = true;
    st.active = false;
    let _ = core::flat_index_remove(s.stream_index[..], stream_id);
    if s.active_stream_count > 0 {
        s.active_stream_count--;
    }
    sync_stream_urgency_node(s, s_idx);
}

// Handles remote END_STREAM transition for an active stream.
inline fn apply_stream_end_remote(s: H2Connection&, s_idx: i32) {
    let st .= s.streams[s_idx];
    if st.state == H2StreamState.HalfClosedLocal {
        st.state = H2StreamState.Closed;
        st.active = false;
        let _ = core::flat_index_remove(s.stream_index[..], st.stream_id);
        if s.active_stream_count > 0 {
            s.active_stream_count--;
        }
    } else {
        st.state = H2StreamState.HalfClosedRemote;
    }
    sync_stream_urgency_node(s, s_idx);
}

fn validate_h2_continuation_state(s: H2Connection&, hdr: const FrameHeader&, now_ms: u64) -> u32, bool {
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
        if next_cnt > MAX_CONT_FRAMES_LIMIT {
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

inline fn is_empty_frame_payload(hdr: const FrameHeader&) -> bool {
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

fn validate_h2_empty_frame_streak(s: H2Connection&, hdr: const FrameHeader&) -> u32 {
    if is_empty_frame_payload(hdr) {
        s.empty_frame_streak++;
        if s.empty_frame_streak > MAX_EMPTY_FRAME_STREAK {
            return rfc::H2_ERR_ENHANCE_YOUR_CALM;
        }
    } else {
        s.empty_frame_streak = 0;
    }
    return rfc::H2_ERR_NO_ERROR;
}

fn handle_h2_rst_stream_header(s: H2Connection&, hdr: const FrameHeader&, now_ms: u64) -> u32 {
    if hdr.stream_id == 0 {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }
    if hdr.length != 4 {
        return rfc::H2_ERR_FRAME_SIZE_ERROR;
    }

    let s_idx, found = find_session_stream_idx(s, hdr.stream_id);
    if !found && !is_closed_stream_id(s, hdr.stream_id) {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }

    if !core::token_bucket_consume(s.reset_limiter, now_ms) {
        return rfc::H2_ERR_ENHANCE_YOUR_CALM;
    }

    if found {
        let st .= s.streams[s_idx];
        st.state = H2StreamState.Closed;
        st.closed_by_rst = true;
        st.active = false;
        let _ = core::flat_index_remove(s.stream_index[..], hdr.stream_id);
        if s.active_stream_count > 0 {
            s.active_stream_count--;
        }
        sync_stream_urgency_node(s, s_idx);
    }
    return rfc::H2_ERR_NO_ERROR;
}

inline fn calc_headers_hpack_len(hdr: const FrameHeader&) -> u32 {
    var len = hdr.length;
    if (hdr.flags & rfc::H2_FLAG_PADDED) != 0 && len > 0 {
        len--;
    }
    if (hdr.flags & rfc::H2_FLAG_PRIORITY) != 0 && len >= 5 {
        len -= 5;
    }
    return len;
}

fn handle_existing_stream_headers(s: H2Connection&, s_idx: i32, flags: u8) -> u32 {
    let st .= s.streams[s_idx];
    if st.state == H2StreamState.HalfClosedRemote ||
       st.state == H2StreamState.Closed {
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

fn handle_h2_headers_frame_header(s: H2Connection&, hdr: const FrameHeader&, now_ms: u64) -> u32 {
    // RFC 9113 Section 4.2: Frame Size - An endpoint MUST send an error code of FRAME_SIZE_ERROR if a frame exceeds the size defined in SETTINGS_MAX_FRAME_SIZE, exceeds any limit defined for the frame type, or is too small to contain mandatory frame data.
    let rule_err = validate_frame_header_rules(hdr, s.local_max_frame_size);
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

    let s_idx, found = find_session_stream_idx(s, hdr.stream_id);
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
        open_new_session_stream(s, hdr.stream_id, (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0);
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

inline fn calc_push_promise_hpack_len(hdr: const FrameHeader&) -> u32 {
    var len = if hdr.length >= 4 { hdr.length - 4 } else { 0 };
    if (hdr.flags & rfc::H2_FLAG_PADDED) != 0 && len > 0 {
        len--;
    }
    return len;
}

// RFC 9113 Section 6.6: PUSH_PROMISE - Tracks CONTINUATION and permits locally RST_STREAM-closed streams.
fn handle_h2_push_promise_frame_header(s: H2Connection&, hdr: const FrameHeader&, now_ms: u64) -> u32 {
    let rule_err = validate_frame_header_rules(hdr, s.local_max_frame_size);
    guard rule_err == rfc::H2_ERR_NO_ERROR else { return rule_err; }

    guard !s.is_server && s.enable_push else { return rfc::H2_ERR_PROTOCOL_ERROR; }
    guard hdr.stream_id != 0 && (hdr.stream_id & 1) == 1 else { return rfc::H2_ERR_PROTOCOL_ERROR; }
    let c_idx, is_closed = find_closed_h2_stream_idx(s, hdr.stream_id);
    if is_closed {
        guard s.streams[c_idx].closed_by_rst else { return rfc::H2_ERR_PROTOCOL_ERROR; }
    }
    let s_idx, found = find_session_stream_idx(s, hdr.stream_id);
    if found {
        let st = s.streams[s_idx].state;
        let ok_state = st == H2StreamState.Open || st == H2StreamState.HalfClosedLocal
            || (st == H2StreamState.Closed && s.streams[s_idx].closed_by_rst);
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

fn check_h2_control_frame_flood(s: H2Connection&, hdr: const FrameHeader&) -> u32 {
    let is_ctrl = hdr.frame_type == rfc::H2_FRAME_PING || hdr.frame_type == rfc::H2_FRAME_SETTINGS;
    if is_ctrl && (hdr.flags & rfc::H2_FLAG_ACK) == 0 {
        s.pending_control_frames++;
        if s.pending_control_frames > MAX_PENDING_CTRL_FRAMES {
            return rfc::H2_ERR_ENHANCE_YOUR_CALM;
        }
    }
    return rfc::H2_ERR_NO_ERROR;
}

// Validates protocol and Anti-DoS invariants upon receiving a 9-byte frame header
// strictly before buffering or parsing the frame payload.
fn on_ingress_frame_header(s: H2Connection&, hdr: const FrameHeader&, now_ms: u64) -> u32 {
    if hdr.length > s.local_max_frame_size {
        return rfc::H2_ERR_FRAME_SIZE_ERROR;
    }

    let cont_err, is_cont = validate_h2_continuation_state(s, hdr, now_ms);
    if is_cont {
        return cont_err;
    }

    let streak_err = validate_h2_empty_frame_streak(s, hdr);
    guard streak_err == rfc::H2_ERR_NO_ERROR else { return streak_err; }

    if hdr.frame_type == rfc::H2_FRAME_RST_STREAM {
        return handle_h2_rst_stream_header(s, hdr, now_ms);
    }

    if hdr.frame_type == rfc::H2_FRAME_HEADERS {
        return handle_h2_headers_frame_header(s, hdr, now_ms);
    }

    if hdr.frame_type == rfc::H2_FRAME_PUSH_PROMISE {
        return handle_h2_push_promise_frame_header(s, hdr, now_ms);
    }

    let ctrl_err = check_h2_control_frame_flood(s, hdr);
    guard ctrl_err == rfc::H2_ERR_NO_ERROR else { return ctrl_err; }

    return validate_frame_header_rules(hdr, s.local_max_frame_size);
}

// ---- two-level flow control & signed window deltas (inv-flow-01) ----------

// RFC 9113 Section 6.9.2: Initial Flow-Control Window Size - Applies signed window delta across active streams.
fn apply_peer_initial_window_size_delta(s: H2Connection&, new_init_win: u32) -> u32 {
    let new_win_i64 = new_init_win as i64;
    guard new_win_i64 <= rfc::H2_MAX_WINDOW_SIZE else {
        return rfc::H2_ERR_FLOW_CONTROL_ERROR;
    }

    let delta = core::sub_sat_i64(new_win_i64, s.peer_initial_window_size);
    for &stream in s.streams {
        if stream.active && stream.state != H2StreamState.Closed {
            if core::add_sat_i64(stream.send_window, delta) > rfc::H2_MAX_WINDOW_SIZE {
                return rfc::H2_ERR_FLOW_CONTROL_ERROR;
            }
        }
    }

    let next_cnt = core::add_sat_u32(s.initial_window_update_count, 1);
    s.initial_window_update_count = next_cnt;
    // CVE-2026-78669 defense: prevent excessive CPU consumption from repeated initial window changes
    if next_cnt > 16 {
        return rfc::H2_ERR_ENHANCE_YOUR_CALM;
    }

    s.peer_initial_window_size = new_win_i64;
    for &stream in s.streams {
        if stream.active && stream.state != H2StreamState.Closed {
            // Stream window may become negative if peer shrank initial window size
            stream.send_window = core::add_sat_i64(stream.send_window, delta);
        }
    }

    refresh_active_urgency_buckets(s);
    return rfc::H2_ERR_NO_ERROR;
}

// RFC 9113 Section 6.8 & Go #82365: Ingests GOAWAY frame (last_stream_id and error_code).
fn apply_goaway(s: H2Connection&, last_stream_id: u32, error_code: u32) -> u32 {
    let sender_is_client = s.is_server;
    guard rfc::validate_goaway_last_stream_id(last_stream_id, sender_is_client) else {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }
    let clean_last_id = last_stream_id & 0x7FFFFFFF;
    if s.goaway_received && clean_last_id > s.goaway_last_stream_id {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }
    s.goaway_received = true;
    s.goaway_last_stream_id = clean_last_id;
    s.goaway_error_code = error_code;
    return rfc::H2_ERR_NO_ERROR;
}

// RFC 9113 Section 5.1: Stream States - Returns true when a WINDOW_UPDATE error on `stream_id` is connection-fatal.
fn is_conn_error_on_window_update(s: const H2Connection&, stream_id: u32) -> bool {
    if stream_id == 0 {
        return true;
    }
    let s_idx, found = find_session_stream_idx(s, stream_id);
    if !found {
        return !is_closed_stream_id(s, stream_id);
    }
    let st = s.streams[s_idx].state;
    return st == H2StreamState.Idle || st == H2StreamState.ReservedRemote;
}

// Processes incoming WINDOW_UPDATE frame (RFC 9113 Section 6.9).
fn apply_window_update(s: H2Connection&, stream_id: u32, increment: u32) -> u32 {
    if stream_id != 0 && is_conn_error_on_window_update(s, stream_id) {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }
    guard increment > 0 && increment <= rfc::H2_MAX_WINDOW_SIZE else {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }
    let inc: i64 = increment;

    if stream_id == 0 {
        // Connection-level window
        let next_conn = s.conn_send_window + inc;
        if next_conn > rfc::H2_MAX_WINDOW_SIZE {
            return rfc::H2_ERR_FLOW_CONTROL_ERROR;
        }
        s.conn_send_window = next_conn;
        return rfc::H2_ERR_NO_ERROR;
    }

    // Stream-level window
    let s_idx, found = find_session_stream_idx(s, stream_id);
    guard found else {
        if is_closed_stream_id(s, stream_id) {
            return rfc::H2_ERR_NO_ERROR;
        }
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }

    // RFC 9113 Section 5.1: Stream States - Ignore WINDOW_UPDATE on closed streams.
    let st .= s.streams[s_idx];
    if st.state == H2StreamState.Idle || st.state == H2StreamState.ReservedRemote {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }
    if st.state == H2StreamState.Closed {
        return rfc::H2_ERR_NO_ERROR;
    }

    let next_stream = st.send_window + inc;
    if next_stream > rfc::H2_MAX_WINDOW_SIZE {
        return rfc::H2_ERR_FLOW_CONTROL_ERROR;
    }
    st.send_window = next_stream;
    sync_stream_urgency_node(s, s_idx);
    return rfc::H2_ERR_NO_ERROR;
}

// Computes effective send quota for a stream: min(max(0, ConnWin), max(0, StreamWin)).
fn compute_stream_send_quota(s: const H2Connection&, stream_id: u32) -> i64 {
    if s.conn_send_window <= 0 {
        return 0;
    }
    let s_idx, found = find_session_stream_idx(s, stream_id);
    guard found else { return 0; }

    let st_win = s.streams[s_idx].send_window;
    if st_win <= 0 {
        return 0;
    }
    return min(s.conn_send_window, st_win);
}

// RFC 9113 Section 6.1: DATA - Updates connection and stream receive windows on incoming DATA frames.
fn on_data_frame_received(s: H2Connection&, hdr: const FrameHeader&, payload_len: u32) -> u32 {
    guard hdr.stream_id != 0 && payload_len <= hdr.length && (hdr.length as i64) <= rfc::H2_MAX_WINDOW_SIZE else {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }

    // RFC 9113 §6.9: Always account for DATA frames against connection flow control first
    let total_consumed = hdr.length as i64;
    s.conn_recv_window -= total_consumed;
    if s.conn_recv_window < 0 {
        return rfc::H2_ERR_FLOW_CONTROL_ERROR;
    }

    let s_idx, found = find_session_stream_idx(s, hdr.stream_id);
    guard found else {
        if is_closed_stream_id(s, hdr.stream_id) {
            return rfc::H2_ERR_STREAM_CLOSED;
        }
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }

    let st .= s.streams[s_idx];
    if st.state == H2StreamState.HalfClosedRemote ||
       st.state == H2StreamState.Closed ||
       st.trailers_received {
        return rfc::H2_ERR_STREAM_CLOSED;
    }

    // RFC 9113 §8.1.1 & §8.8: Status 204, 304, or 1xx MUST NOT contain message body / DATA frames
    let sc = st.status_code;
    if sc == 204 || sc == 304 || (sc >= 100 && sc < 200) {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }

    st.recv_window -= total_consumed;
    if st.recv_window < 0 {
        return rfc::H2_ERR_FLOW_CONTROL_ERROR;
    }

    st.received_data_bytes = core::add_sat_i64(st.received_data_bytes, payload_len);

    // RFC 9113 §8.1.2: Check if incoming DATA causes total data to exceed declared Content-Length
    let dec_len = st.declared_content_length;
    if dec_len >= 0 && st.received_data_bytes > dec_len {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }

    if (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 {
        apply_stream_end_remote(s, s_idx);

        // Verify Content-Length match if declared (Go #32728 / #46071)
        if dec_len >= 0 && dec_len != st.received_data_bytes {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
    }

    return rfc::H2_ERR_NO_ERROR;
}

// Decrements pending control frames counter when ACK frames are flushed.
fn ack_control_frame_flushed(s: H2Connection&) {
    if s.pending_control_frames > 0 {
        s.pending_control_frames--;
    }
}

// ---- rfc 9218 extensible write scheduler ---------------------------------

// Unlinks stream node `s_idx` from its urgency bucket `u` if currently linked.
fn unlink_stream_from_urgency_bucket(s: H2Connection&, s_idx: i32, u: u8) {
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
fn link_stream_to_urgency_bucket(s: H2Connection&, s_idx: i32, u: u8) {
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

// Synchronizes stream node membership across the 8 urgency buckets based on send readiness.
fn sync_stream_urgency_node(s: H2Connection&, s_idx: i32) {
    guard s_idx >= 0 && s_idx < (s.streams.len as i32) else { return; }
    let stream .= s.streams[s_idx];
    let u = stream.priority.urgency;
    guard u <= 7 else { return; }
    let st = stream.state;
    let can_send = (st == H2StreamState.Open || st == H2StreamState.HalfClosedRemote);
    let ready = stream.active && can_send
        && stream.pending_send_bytes > 0
        && stream.send_window > 0;
    if ready {
        link_stream_to_urgency_bucket(s, s_idx, u);
    } else {
        unlink_stream_from_urgency_bucket(s, s_idx, u);
    }
}

// Rebuilds `active_urgency_mask` and `stream_nodes` intrusive lists for any streams modified directly.
fn refresh_active_urgency_buckets(s: H2Connection&) {
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
        let can_send = (st == H2StreamState.Open || st == H2StreamState.HalfClosedRemote);
        if stream.active && can_send && stream.pending_send_bytes > 0
            && stream.send_window > 0 && stream.priority.urgency <= 7 {
            link_stream_to_urgency_bucket(s, idx, stream.priority.urgency);
        }
        idx++;
    }
}

// Enqueues pending outbound DATA bytes for `stream_id` and updates the O(1) urgency bitmask.
fn enqueue_stream_send_bytes(s: H2Connection&, stream_id: u32, bytes: u32) -> bool {
    let s_idx, found = find_session_stream_idx(s, stream_id);
    guard found else { return false; }
    s.streams[s_idx].pending_send_bytes += bytes;
    sync_stream_urgency_node(s, s_idx);
    return true;
}

fn record_idle_stream_priority(
    s:         H2Connection&,
    stream_id: u32,
    prio:      wing::PriorityParam,
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
    guard s.idle_priorities.try_push(IdleStreamPriority {
        stream_id: stream_id,
        prio:      final_prio,
    }) else {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }
    return rfc::H2_ERR_NO_ERROR;
}

// RFC 9218 Section 7.1: HTTP/2 PRIORITY_UPDATE Frame - Applies dynamic priority update to active or idle streams.
fn apply_priority_update(s: H2Connection&, prioritized_stream_id: u32, prio: wing::PriorityParam) -> u32 {
    guard prioritized_stream_id != 0 else { return rfc::H2_ERR_PROTOCOL_ERROR; }
    let s_idx, found = find_session_stream_idx(s, prioritized_stream_id);
    if !found {
        if (prioritized_stream_id & 1) == 0 {
            guard is_closed_stream_id(s, prioritized_stream_id) else {
                return rfc::H2_ERR_PROTOCOL_ERROR;
            }
            s.client_sent_priority = true;
            return rfc::H2_ERR_NO_ERROR;
        }
        if is_closed_stream_id(s, prioritized_stream_id) {
            s.client_sent_priority = true;
            return rfc::H2_ERR_NO_ERROR;
        }
        let idle_err = record_idle_stream_priority(s, prioritized_stream_id, prio);
        guard idle_err == rfc::H2_ERR_NO_ERROR else { return idle_err; }
        s.client_sent_priority = true;
        return rfc::H2_ERR_NO_ERROR;
    }
    s.client_sent_priority = true;

    let stream .= s.streams[s_idx];
    let old_u = stream.priority.urgency;
    unlink_stream_from_urgency_bucket(s, s_idx, old_u);

    var final_prio = prio;
    if s.is_behind_proxy {
        final_prio.urgency = 3;
        final_prio.incremental = true;
    }
    stream.priority = final_prio;
    stream.has_explicit_priority_update = true;
    sync_stream_urgency_node(s, s_idx);
    return rfc::H2_ERR_NO_ERROR;
}

const MAX_HIGH_URGENCY_STREAK: u32 = 16; // Max consecutive frames before lower-urgency credit yield

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
    s:             H2Connection&,
    chosen_idx:    i32,
    max_frame_len: u32,
) -> u32, u32, bool {
    let chosen .= s.streams[chosen_idx];
    let target_stream_id = chosen.stream_id;
    let quota = compute_stream_send_quota(s, target_stream_id);
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

    // Deduct from pending and windows
    chosen.pending_send_bytes -= send_len;
    chosen.send_window -= send_len;
    s.conn_send_window -= send_len;
    sync_stream_urgency_node(s, chosen_idx);

    // Update anti-starvation streak tracking
    if chosen.priority.urgency < 7 {
        s.urgency_streak_count++;
    } else {
        s.urgency_streak_count = 0;
    }

    return target_stream_id, send_len, true;
}

fn has_lower_urgency_ready(s: const H2Connection&) -> bool {
    if (s.active_urgency_mask & 0xF8) != 0 {
        return true;
    }
    var chk: i32 = 0;
    let stream_count = s.streams.len as i32;
    while chk < stream_count {
        let cur .= s.streams[chk];
        let st = cur.state;
        let can_send = (st == H2StreamState.Open || st == H2StreamState.HalfClosedRemote);
        if cur.active && can_send && cur.pending_send_bytes > 0
            && cur.send_window > 0 && cur.priority.urgency >= 3 {
            return true;
        }
        chk++;
    }
    return false;
}

fn find_non_incremental_candidate(s: const H2Connection&, u: u8) -> i32 {
    let u_idx = u as i64;
    var node_idx = s.urgency_heads[u_idx];
    while node_idx >= 0 {
        let cur .= s.streams[node_idx];
        let st = cur.state;
        let can_send = (st == H2StreamState.Open || st == H2StreamState.HalfClosedRemote);
        if cur.active && can_send && cur.pending_send_bytes > 0
            && cur.send_window > 0 && cur.priority.urgency == u
            && !cur.priority.incremental {
            return node_idx;
        }
        node_idx = s.stream_nodes[node_idx].next;
    }
    var idx: i32 = 0;
    let stream_count = s.streams.len as i32;
    while idx < stream_count {
        let cur .= s.streams[idx];
        let st = cur.state;
        let can_send = (st == H2StreamState.Open || st == H2StreamState.HalfClosedRemote);
        if cur.active && can_send && cur.pending_send_bytes > 0
            && cur.send_window > 0 && cur.priority.urgency == u
            && !cur.priority.incremental {
            return idx;
        }
        idx++;
    }
    return -1;
}

fn find_incremental_candidate(s: const H2Connection&, u: u8) -> i32 {
    let u_idx = u as i64;
    let stream_count = s.streams.len as i32;
    guard stream_count > 0 else { return -1; }

    let last_inc = s.bucket_last_inc_idx[u_idx];
    var step: i32 = 1;
    while step <= stream_count {
        let candidate = if last_inc < 0 { step - 1 } else { (last_inc + step) % stream_count };
        if candidate >= 0 && candidate < stream_count {
            let cur .= s.streams[candidate];
            let st = cur.state;
            let can_send = (st == H2StreamState.Open || st == H2StreamState.HalfClosedRemote);
            if cur.active && can_send && cur.pending_send_bytes > 0
                && cur.send_window > 0 && cur.priority.urgency == u
                && cur.priority.incremental {
                return candidate;
            }
        }
        step++;
    }
    return -1;
}

fn select_and_commit_stream(
    s:             H2Connection&,
    u:             u8,
    max_frame_len: u32,
) -> u32, u32, bool {
    let non_inc_idx = find_non_incremental_candidate(s, u);
    let inc_idx = find_incremental_candidate(s, u);
    let u_idx = u as i64;

    var chosen_idx: i32 = -1;
    if non_inc_idx >= 0 && inc_idx >= 0 {
        if s.bucket_prefer_incremental[u_idx] {
            chosen_idx = inc_idx;
            s.bucket_last_inc_idx[u_idx] = inc_idx;
            s.bucket_prefer_incremental[u_idx] = false;
        } else {
            chosen_idx = non_inc_idx;
            s.bucket_prefer_incremental[u_idx] = true;
        }
    } else if non_inc_idx >= 0 {
        chosen_idx = non_inc_idx;
    } else if inc_idx >= 0 {
        chosen_idx = inc_idx;
        s.bucket_last_inc_idx[u_idx] = inc_idx;
    }

    guard chosen_idx >= 0 else { return 0, 0, false; }
    return commit_stream_send_quota(s, chosen_idx, max_frame_len);
}

inline fn apply_urgency_anti_starvation(s: H2Connection&, mask: u8) -> u8 {
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
    s:             H2Connection&,
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

// Schedules next stream for DATA frame transmission according to RFC 9218 urgency 0..7.
// Alternates between incremental and non-incremental streams to prevent starvation.
// Implements Round-Robin fair interleaving among concurrent incremental streams within a bucket.
// Implements anti-starvation credit yield when higher-urgency streams dominate for > 16 frames.
// Returns (stream_id, allowed_send_bytes, found).
fn schedule_next_write(s: H2Connection&, max_frame_len: u32) -> u32, u32, bool {
    guard s.conn_send_window > 0 else { return 0, 0, false; }
    if s.active_urgency_mask == 0 {
        refresh_active_urgency_buckets(s);
    }
    guard s.active_urgency_mask != 0 else { return 0, 0, false; }

    let search_mask = apply_urgency_anti_starvation(s, s.active_urgency_mask);
    let sid1, len1, ok1 = scan_urgency_mask_for_write(s, search_mask, max_frame_len);
    if ok1 {
        return sid1, len1, true;
    }
    guard search_mask != s.active_urgency_mask else { return 0, 0, false; }
    s.urgency_streak_count = 0;
    return scan_urgency_mask_for_write(s, s.active_urgency_mask, max_frame_len);
}

// RFC 9218 Section 4: Priority Parameters - O(1) priority scheduler overload using `ctz_urgency_mask`
// on `conn.active_urgency_mask` (bit 0 = urgency 0) with a 16-frame burst quantum cap on Urgency 0.
fn schedule_next_write(conn: H2Connection&) -> u32, bool {
    let stream_id, _, ok = schedule_next_write(conn, conn.peer_max_frame_size);
    return stream_id, ok;
}
