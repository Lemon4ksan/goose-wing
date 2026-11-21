// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/2 connection session coordinator, RFC 9218 write scheduler,
// two-level credit-based flow control, and defense-in-depth Anti-DoS mitigations (RFC 9113, RFC 9218).
namespace http2;

import std;
import core from "..";
import .framing;
import .hpack;
import .internal;

// ---- session public limits -----------------------------------------------

const MAX_CONT_FRAMES_LIMIT:   u32 = 16; // CONTINUATION Flood defense (CVE-2024-28182 / CVE-2024-30255)
const MAX_EMPTY_FRAME_STREAK:  u32 = 8;  // Empty Frame Flooding defense (CVE-2019-9518)
const MAX_PENDING_CTRL_FRAMES: u32 = 64; // PING/SETTINGS Flood defense (CVE-2019-9512 / CVE-2019-9515)

// ---- stream state machine & stream descriptors (rfc 9113 section 5.1) ---

enum StreamState {
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

struct Stream {
    stream_id:                    u32                 = 0,
    state:                        StreamState         = StreamState.Idle,
    send_window:                  i64                 = 65535, // Signed 64-bit integer to support negative deltas
    recv_window:                  i64                 = 65535,
    priority:                     http::PriorityParam = http::PriorityParam { .. },
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
    prio:      http::PriorityParam = http::PriorityParam { .. },
}

// ---- http/2 connection state & coordinator -------------------------------

struct Connection {
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
    streams:         Stream[..128]              = [],
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

// Returns a default-initialized Connection with RFC 9113 & RFC 9218 baseline invariants.
fn new_h2_connection(
    now_ms:          u64  = 0,
    max_header_list: u32  = 8192,
    behind_proxy:    bool = false,
) -> Connection {
    return Connection {
        hpack_dec: new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE),
        reset_limiter: core::TokenBucket {
            tokens:         h2_internal::DEFAULT_RESET_BURST,
            burst:          h2_internal::DEFAULT_RESET_BURST,
            rate_per_sec:   h2_internal::DEFAULT_RESET_RATE,
            last_refill_ms: now_ms,
        },
        max_header_list_size: max_header_list,
        is_behind_proxy:      behind_proxy,
        is_server:            false,
        enable_push:          true,
        ..
    };
}

// Finds an active stream by stream_id. Returns (index, true) or (-1, false).
fn find_stream_idx(s: const Connection&, stream_id: u32) -> i32, bool {
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

// Finds a previously opened stream that has transitioned to Closed.
fn find_closed_stream_idx(s: const Connection&, stream_id: u32) -> i32, bool {
    var idx: i32 = 0;
    while idx < (s.streams.len as i32) {
        let st .= s.streams[idx];
        if !st.active && st.state == StreamState.Closed && st.stream_id == stream_id {
            return idx, true;
        }
        idx++;
    }
    return -1, false;
}

// ---- frame ingress coordinator & anti-dos barriers -----------------------

// Opens a new stream descriptor with default RFC 9218 priority.
fn open_stream(s: Connection&, stream_id: u32, end_stream: bool) {
    var def_prio = http::PriorityParam {
        urgency: 3,
        // Go 1.27 #75500: default to incremental=true before first client priority signal
        incremental: if s.is_behind_proxy { true } else { !s.client_sent_priority },
    };
    let idle_prio, has_idle_prio = h2_internal::take_idle_stream_priority(s, stream_id);
    if has_idle_prio {
        def_prio = idle_prio;
    }

    var new_stream = Stream {
        stream_id:                    stream_id,
        state:                        if end_stream { StreamState.HalfClosedRemote } else { StreamState.Open },
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
fn close_local_stream(s: Connection&, stream_id: u32) {
    let s_idx, found = find_stream_idx(s, stream_id);
    guard found else { return; }

    let st .= s.streams[s_idx];
    if st.state == StreamState.HalfClosedRemote {
        st.state = StreamState.Closed;
        st.active = false;
        let _ = core::flat_index_remove(s.stream_index[..], stream_id);
        if s.active_stream_count > 0 {
            s.active_stream_count--;
        }
    } else if st.state == StreamState.Open {
        st.state = StreamState.HalfClosedLocal;
    }
    sync_stream_urgency_node(s, s_idx);
}

// Closes a stream descriptor and frees its active slot on stream error or RST_STREAM (RFC 9113 §5.1.2).
fn reset_stream(s: Connection&, stream_id: u32) {
    let s_idx, found = find_stream_idx(s, stream_id);
    guard found else { return; }

    let st .= s.streams[s_idx];
    st.state = StreamState.Closed;
    st.closed_by_rst = true;
    st.active = false;
    let _ = core::flat_index_remove(s.stream_index[..], stream_id);
    if s.active_stream_count > 0 {
        s.active_stream_count--;
    }
    sync_stream_urgency_node(s, s_idx);
}

// Validates protocol and Anti-DoS invariants upon receiving a 9-byte frame header
// strictly before buffering or parsing the frame payload.
fn on_ingress_frame_header(s: Connection&, hdr: const FrameHeader&, now_ms: u64) -> u32 {
    if hdr.length > s.local_max_frame_size {
        return rfc::H2_ERR_FRAME_SIZE_ERROR;
    }

    let cont_err, is_cont = h2_internal::validate_h2_continuation_state(s, hdr, now_ms);
    if is_cont {
        return cont_err;
    }

    let streak_err = h2_internal::validate_h2_empty_frame_streak(s, hdr);
    guard streak_err == rfc::H2_ERR_NO_ERROR else { return streak_err; }

    if hdr.frame_type == rfc::H2_FRAME_RST_STREAM {
        return h2_internal::handle_h2_rst_stream_header(s, hdr, now_ms);
    }

    if hdr.frame_type == rfc::H2_FRAME_HEADERS {
        return h2_internal::handle_h2_headers_frame_header(s, hdr, now_ms);
    }

    if hdr.frame_type == rfc::H2_FRAME_PUSH_PROMISE {
        return h2_internal::handle_h2_push_promise_frame_header(s, hdr, now_ms);
    }

    let ctrl_err = h2_internal::check_h2_control_frame_flood(s, hdr);
    guard ctrl_err == rfc::H2_ERR_NO_ERROR else { return ctrl_err; }

    return validate_frame_header_rules(hdr, s.local_max_frame_size);
}

// ---- two-level flow control & signed window deltas (inv-flow-01) ----------

// RFC 9113 Section 6.9.2: Initial Flow-Control Window Size - Applies signed window delta across active streams.
fn apply_peer_initial_window_size_delta(s: Connection&, new_init_win: u32) -> u32 {
    let new_win_i64 = new_init_win as i64;
    guard new_win_i64 <= rfc::H2_MAX_WINDOW_SIZE else {
        return rfc::H2_ERR_FLOW_CONTROL_ERROR;
    }

    let delta = core::sub_sat_i64(new_win_i64, s.peer_initial_window_size);
    for &stream in s.streams {
        if stream.active && stream.state != StreamState.Closed {
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
        if stream.active && stream.state != StreamState.Closed {
            stream.send_window = core::add_sat_i64(stream.send_window, delta);
        }
    }

    h2_internal::refresh_active_urgency_buckets(s);
    return rfc::H2_ERR_NO_ERROR;
}

// RFC 9113 Section 6.8 & Go #82365: Ingests GOAWAY frame (last_stream_id and error_code).
fn apply_goaway(s: Connection&, last_stream_id: u32, error_code: u32) -> u32 {
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
fn is_conn_error_on_window_update(s: const Connection&, stream_id: u32) -> bool {
    if stream_id == 0 {
        return true;
    }
    let s_idx, found = find_stream_idx(s, stream_id);
    if !found {
        return !h2_internal::is_closed_stream_id(s, stream_id);
    }
    let st = s.streams[s_idx].state;
    return st == StreamState.Idle || st == StreamState.ReservedRemote;
}

// Processes incoming WINDOW_UPDATE frame (RFC 9113 Section 6.9).
fn apply_window_update(s: Connection&, stream_id: u32, increment: u32) -> u32 {
    if stream_id != 0 && is_conn_error_on_window_update(s, stream_id) {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }
    guard increment > 0 && increment <= rfc::H2_MAX_WINDOW_SIZE else {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }
    let inc: i64 = increment;

    if stream_id == 0 {
        let next_conn = s.conn_send_window + inc;
        if next_conn > rfc::H2_MAX_WINDOW_SIZE {
            return rfc::H2_ERR_FLOW_CONTROL_ERROR;
        }
        s.conn_send_window = next_conn;
        return rfc::H2_ERR_NO_ERROR;
    }

    let s_idx, found = find_stream_idx(s, stream_id);
    guard found else {
        if h2_internal::is_closed_stream_id(s, stream_id) {
            return rfc::H2_ERR_NO_ERROR;
        }
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }

    // RFC 9113 Section 5.1: Stream States - Ignore WINDOW_UPDATE on closed streams.
    let st .= s.streams[s_idx];
    if st.state == StreamState.Idle || st.state == StreamState.ReservedRemote {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }
    if st.state == StreamState.Closed {
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
fn compute_stream_send_quota(s: const Connection&, stream_id: u32) -> i64 {
    if s.conn_send_window <= 0 {
        return 0;
    }
    let s_idx, found = find_stream_idx(s, stream_id);
    guard found else { return 0; }

    let st_win = s.streams[s_idx].send_window;
    if st_win <= 0 {
        return 0;
    }
    return min(s.conn_send_window, st_win);
}

// RFC 9113 Section 6.1: DATA - Updates connection and stream receive windows on incoming DATA frames.
fn on_data_frame_received(s: Connection&, hdr: const FrameHeader&, payload_len: u32) -> u32 {
    guard hdr.stream_id != 0 && payload_len <= hdr.length && (hdr.length as i64) <= rfc::H2_MAX_WINDOW_SIZE else {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }

    // RFC 9113 §6.9: Always account for DATA frames against connection flow control first
    let total_consumed = hdr.length as i64;
    s.conn_recv_window -= total_consumed;
    if s.conn_recv_window < 0 {
        return rfc::H2_ERR_FLOW_CONTROL_ERROR;
    }

    let s_idx, found = find_stream_idx(s, hdr.stream_id);
    guard found else {
        if h2_internal::is_closed_stream_id(s, hdr.stream_id) {
            return rfc::H2_ERR_STREAM_CLOSED;
        }
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }

    let st .= s.streams[s_idx];
    if st.state == StreamState.HalfClosedRemote ||
       st.state == StreamState.Closed ||
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
        h2_internal::apply_stream_end_remote(s, s_idx);

        if dec_len >= 0 && dec_len != st.received_data_bytes {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
    }

    return rfc::H2_ERR_NO_ERROR;
}

// Decrements pending control frames counter when ACK frames are flushed.
fn ack_control_frame_flushed(s: Connection&) {
    if s.pending_control_frames > 0 {
        s.pending_control_frames--;
    }
}

// ---- rfc 9218 extensible write scheduler ---------------------------------

// Synchronizes stream node membership across the 8 urgency buckets based on send readiness.
fn sync_stream_urgency_node(s: Connection&, s_idx: i32) {
    guard s_idx >= 0 && s_idx < (s.streams.len as i32) else { return; }
    let stream .= s.streams[s_idx];
    let u = stream.priority.urgency;
    guard u <= 7 else { return; }
    let st = stream.state;
    let can_send = (st == StreamState.Open || st == StreamState.HalfClosedRemote);
    let ready = stream.active && can_send
        && stream.pending_send_bytes > 0
        && stream.send_window > 0;
    if ready {
        h2_internal::link_stream_to_urgency_bucket(s, s_idx, u);
    } else {
        h2_internal::unlink_stream_from_urgency_bucket(s, s_idx, u);
    }
}

// Enqueues pending outbound DATA bytes for `stream_id` and updates the O(1) urgency bitmask.
fn enqueue_stream_send_bytes(s: Connection&, stream_id: u32, bytes: u32) -> bool {
    let s_idx, found = find_stream_idx(s, stream_id);
    guard found else { return false; }
    s.streams[s_idx].pending_send_bytes += bytes;
    sync_stream_urgency_node(s, s_idx);
    return true;
}

// RFC 9218 Section 7.1: HTTP/2 PRIORITY_UPDATE Frame - Applies dynamic priority update to active or idle streams.
fn apply_priority_update(s: Connection&, prioritized_stream_id: u32, prio: http::PriorityParam) -> u32 {
    guard prioritized_stream_id != 0 else { return rfc::H2_ERR_PROTOCOL_ERROR; }
    let s_idx, found = find_stream_idx(s, prioritized_stream_id);
    if !found {
        if (prioritized_stream_id & 1) == 0 {
            guard h2_internal::is_closed_stream_id(s, prioritized_stream_id) else {
                return rfc::H2_ERR_PROTOCOL_ERROR;
            }
            s.client_sent_priority = true;
            return rfc::H2_ERR_NO_ERROR;
        }
        if h2_internal::is_closed_stream_id(s, prioritized_stream_id) {
            s.client_sent_priority = true;
            return rfc::H2_ERR_NO_ERROR;
        }
        let idle_err = h2_internal::record_idle_stream_priority(s, prioritized_stream_id, prio);
        guard idle_err == rfc::H2_ERR_NO_ERROR else { return idle_err; }
        s.client_sent_priority = true;
        return rfc::H2_ERR_NO_ERROR;
    }
    s.client_sent_priority = true;

    let stream .= s.streams[s_idx];
    let old_u = stream.priority.urgency;
    h2_internal::unlink_stream_from_urgency_bucket(s, s_idx, old_u);

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

// Schedules next stream for DATA frame transmission according to RFC 9218 urgency 0..7.
// Alternates between incremental and non-incremental streams to prevent starvation.
// Implements Round-Robin fair interleaving among concurrent incremental streams within a bucket.
// Implements anti-starvation credit yield when higher-urgency streams dominate for > 16 frames.
// Returns (stream_id, allowed_send_bytes, found).
fn schedule_next_write(s: Connection&, max_frame_len: u32) -> u32, u32, bool {
    guard s.conn_send_window > 0 else { return 0, 0, false; }
    if s.active_urgency_mask == 0 {
        h2_internal::refresh_active_urgency_buckets(s);
    }
    guard s.active_urgency_mask != 0 else { return 0, 0, false; }

    let search_mask = h2_internal::apply_urgency_anti_starvation(s, s.active_urgency_mask);
    let sid1, len1, ok1 = h2_internal::scan_urgency_mask_for_write(s, search_mask, max_frame_len);
    if ok1 {
        return sid1, len1, true;
    }
    guard search_mask != s.active_urgency_mask else { return 0, 0, false; }
    s.urgency_streak_count = 0;
    return h2_internal::scan_urgency_mask_for_write(s, s.active_urgency_mask, max_frame_len);
}

// RFC 9218 Section 4: Priority Parameters - O(1) priority scheduler overload using `ctz_urgency_mask`
// on `conn.active_urgency_mask` (bit 0 = urgency 0) with a 16-frame burst quantum cap on Urgency 0.
fn schedule_next_write(conn: Connection&) -> u32, bool {
    let stream_id, _, ok = schedule_next_write(conn, conn.peer_max_frame_size);
    return stream_id, ok;
}
