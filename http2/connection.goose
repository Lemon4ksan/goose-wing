// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/2 connection session coordinator, RFC 9218 write scheduler,
// two-level credit-based flow control, and defense-in-depth Anti-DoS mitigations (RFC 9113, RFC 9218).
namespace internal;

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

// ---- token bucket rate limiter (rapid reset cve-2023-44487) -------------

struct TokenBucket {
    tokens:         u64 = 1000,
    burst:          u64 = 1000,
    rate_per_sec:   u64 = 33,
    last_refill_ms: u64 = 0,
}

fn new_h2_token_bucket(burst: u64 = 1000, rate_per_sec: u64 = 33, now_ms: u64 = 0) -> TokenBucket {
    return TokenBucket {
        tokens:         burst,
        burst:          burst,
        rate_per_sec:   rate_per_sec,
        last_refill_ms: now_ms,
    };
}

// Consumes one token from bucket, refilling based on elapsed milliseconds.
// Returns false when rate limit is exceeded.
fn consume_token(tb: TokenBucket&, now_ms: u64) -> bool {
    if now_ms > tb.last_refill_ms {
        let elapsed_ms = now_ms - tb.last_refill_ms;
        if elapsed_ms >= 100000 {
            tb.tokens = tb.burst;
            tb.last_refill_ms = now_ms;
        } else {
            let added = (elapsed_ms * tb.rate_per_sec) / 1000;
            if added > 0 {
                let next_tokens = tb.tokens + added;
                tb.tokens = if next_tokens > tb.burst { tb.burst } else { next_tokens };
                tb.last_refill_ms = now_ms;
            }
        }
    }
    if tb.tokens == 0 {
        return false;
    }
    tb.tokens--;
    return true;
}

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
    stream_id:               u32                 = 0,
    state:                   H2StreamState       = H2StreamState.Idle,
    send_window:             i64                 = 65535, // Signed 64-bit integer to support negative deltas
    recv_window:             i64                 = 65535,
    priority:                wing::PriorityParam = wing::PriorityParam { .. },
    pending_send_bytes:      u32                 = 0,
    declared_content_length: i64                 = -1,
    received_data_bytes:     i64                 = 0,
    headers_received:        bool                = false,
    trailers_received:       bool                = false,
    status_code:             i32                 = 0,
    active:                  bool                = false,
}

// RFC 9218 Section 4: Priority Parameters - Array-indexed intrusive linked-list node for O(1) priority buckets.
struct StreamNode {
    stream_id: u32 = 0,
    next:      i32 = -1,
    prev:      i32 = -1,
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
    is_server:                 bool         = false,
    enable_push:               bool         = true,

    // Active streams table (bounded inline storage)
    streams: H2Stream[..128] = [],

    // Exclusive CONTINUATION lock (0 if not expecting CONTINUATION)
    continuation_stream_id:       u32 = 0,
    continuation_frames_cnt:      u32 = 0,
    accumulated_header_size:      u32 = 0,
    continuation_start_ms:        u64 = 0,
    max_header_block_duration_ms: u64 = 10000,

    // Anti-DoS resource limiters
    reset_limiter:               TokenBucket = TokenBucket { .. },
    empty_frame_streak:          u32         = 0,
    pending_control_frames:      u32         = 0,
    concurrency_violations:      u32         = 0,
    initial_window_update_count: u32         = 0,

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
        hpack_dec:            new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE),
        reset_limiter:        new_h2_token_bucket(DEFAULT_RESET_BURST, DEFAULT_RESET_RATE, now_ms),
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
    var idx: i32 = 0;
    while idx < (s.streams.len as i32) {
        if s.streams[idx].active && s.streams[idx].stream_id == stream_id {
            return idx, true;
        }
        idx++;
    }
    return -1, false;
}

fn find_session_stream_idx(s: const H2Connection&, stream_id: u32) -> i32, bool {
    let idx, ok = find_h2_stream_idx(s, stream_id);
    return idx, ok;
}

// ---- frame ingress coordinator & anti-dos barriers -----------------------

// Opens a new stream descriptor with default RFC 9218 priority.
fn open_new_session_stream(s: H2Connection&, stream_id: u32, end_stream: bool) {
    var def_prio = wing::PriorityParam {
        urgency: 3,
        // Go 1.27 #75500: default to incremental=true before first client priority signal
        incremental: if s.is_behind_proxy { true } else { !s.client_sent_priority },
    };

    var new_stream = H2Stream {
        stream_id:        stream_id,
        state:            if end_stream { H2StreamState.HalfClosedRemote } else { H2StreamState.Open },
        send_window:      s.peer_initial_window_size,
        recv_window:      s.local_initial_window_size,
        priority:         def_prio,
        headers_received: true,
        active:           true,
        ..
    };

    var placed = false;
    for &slot in s.streams {
        if !slot.active {
            slot = new_stream;
            placed = true;
            break;
        }
    }
    if !placed {
        guard s.streams.len < s.streams.cap else { return; }
        s.streams.push(new_stream);
    }
    s.active_stream_count++;
}

// Marks the local half of a stream as closed (e.g. after sending END_STREAM).
// If the remote half is already closed, transitions stream to Closed and frees active slot.
fn close_local_stream(s: H2Connection&, stream_id: u32) {
    let s_idx, found = find_session_stream_idx(s, stream_id);
    guard found else { return; }

    if s.streams[s_idx].state == H2StreamState.HalfClosedRemote {
        s.streams[s_idx].state = H2StreamState.Closed;
        s.streams[s_idx].active = false;
        if s.active_stream_count > 0 {
            s.active_stream_count--;
        }
    } else if s.streams[s_idx].state == H2StreamState.Open {
        s.streams[s_idx].state = H2StreamState.HalfClosedLocal;
    }
    sync_stream_urgency_node(s, s_idx);
}

// Closes a stream descriptor and frees its active slot on stream error or RST_STREAM (RFC 9113 §5.1.2).
fn reset_session_stream(s: H2Connection&, stream_id: u32) {
    let s_idx, found = find_session_stream_idx(s, stream_id);
    guard found else { return; }

    s.streams[s_idx].state = H2StreamState.Closed;
    s.streams[s_idx].active = false;
    if s.active_stream_count > 0 {
        s.active_stream_count--;
    }
    sync_stream_urgency_node(s, s_idx);
}

// Handles remote END_STREAM transition for an active stream.
inline fn apply_stream_end_remote(s: H2Connection&, s_idx: i32) {
    if s.streams[s_idx].state == H2StreamState.HalfClosedLocal {
        s.streams[s_idx].state = H2StreamState.Closed;
        s.streams[s_idx].active = false;
        if s.active_stream_count > 0 {
            s.active_stream_count--;
        }
    } else {
        s.streams[s_idx].state = H2StreamState.HalfClosedRemote;
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

        s.continuation_frames_cnt++;
        if s.continuation_frames_cnt > MAX_CONT_FRAMES_LIMIT {
            return rfc::H2_ERR_ENHANCE_YOUR_CALM, true;
        }

        s.accumulated_header_size += hdr.length;
        if s.accumulated_header_size > s.max_header_list_size
            || s.accumulated_header_size > MAX_HEADER_BLOCK_SIZE_LIMIT {
            return rfc::H2_ERR_ENHANCE_YOUR_CALM, true;
        }

        if (hdr.flags & rfc::H2_FLAG_END_HEADERS) != 0 {
            s.continuation_stream_id = 0;
            s.continuation_frames_cnt = 0;
            s.accumulated_header_size = 0;
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
    if !found && hdr.stream_id > s.last_peer_stream_id {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }

    if !consume_token(s.reset_limiter, now_ms) {
        return rfc::H2_ERR_ENHANCE_YOUR_CALM;
    }

    if found {
        s.streams[s_idx].state = H2StreamState.Closed;
        s.streams[s_idx].active = false;
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
    if s.streams[s_idx].state == H2StreamState.HalfClosedRemote ||
       s.streams[s_idx].state == H2StreamState.Closed {
        return rfc::H2_ERR_STREAM_CLOSED;
    }
    if s.streams[s_idx].headers_received {
        if s.streams[s_idx].trailers_received {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
        // RFC 9113 Section 8.1: A HEADERS frame for trailers MUST carry END_STREAM
        if (flags & rfc::H2_FLAG_END_STREAM) == 0 {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
        let dec_len = s.streams[s_idx].declared_content_length;
        if dec_len >= 0 && dec_len != s.streams[s_idx].received_data_bytes {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
        s.streams[s_idx].trailers_received = true;
        apply_stream_end_remote(s, s_idx);
    } else {
        s.streams[s_idx].headers_received = true;
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

    if (hdr.stream_id % 2) == 0 {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }

    let s_idx, found = find_session_stream_idx(s, hdr.stream_id);
    if !found {
        if hdr.stream_id <= s.last_peer_stream_id {
            return rfc::H2_ERR_STREAM_CLOSED;
        }

        // RFC 9113 Section 6.8 & Go #82365:
        // After receiving GOAWAY, any new stream with ID > goaway_last_stream_id must be refused
        if s.goaway_received && hdr.stream_id > s.goaway_last_stream_id {
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

// RFC 9113 §6.6: Tracks CONTINUATION state machine when PUSH_PROMISE has END_HEADERS cleared.
fn handle_h2_push_promise_frame_header(s: H2Connection&, hdr: const FrameHeader&, now_ms: u64) -> u32 {
    let rule_err = validate_frame_header_rules(hdr, s.local_max_frame_size);
    guard rule_err == rfc::H2_ERR_NO_ERROR else { return rule_err; }

    guard !s.is_server && s.enable_push else { return rfc::H2_ERR_PROTOCOL_ERROR; }
    guard hdr.stream_id != 0 else { return rfc::H2_ERR_PROTOCOL_ERROR; }

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

// Dynamically updates stream send windows upon receiving SETTINGS_INITIAL_WINDOW_SIZE.
// Computes signed delta = int64(new_init_win) - int64(old_init_win).
// Enforces MAX_INITIAL_WINDOW_SIZE ceiling and allows negative stream windows.
fn apply_peer_initial_window_size_delta(s: H2Connection&, new_init_win: u32) -> u32 {
    s.initial_window_update_count++;
    // CVE-2026-78669 defense: prevent excessive CPU consumption from repeated initial window changes
    if s.initial_window_update_count > 16 {
        return rfc::H2_ERR_ENHANCE_YOUR_CALM;
    }

    let new_win_i64 = new_init_win as i64;
    guard new_win_i64 <= rfc::H2_MAX_WINDOW_SIZE else {
        return rfc::H2_ERR_FLOW_CONTROL_ERROR;
    }

    let delta = new_win_i64 - s.peer_initial_window_size;
    s.peer_initial_window_size = new_win_i64;

    for &stream in s.streams {
        if stream.active && stream.state != H2StreamState.Closed {
            let next_win = stream.send_window + delta;
            // Overflows beyond 2^31 - 1 trigger flow control error
            if next_win > rfc::H2_MAX_WINDOW_SIZE {
                return rfc::H2_ERR_FLOW_CONTROL_ERROR;
            }
            // Stream window may become negative if peer shrank initial window size
            stream.send_window = next_win;
        }
    }

    refresh_active_urgency_buckets(s);
    return rfc::H2_ERR_NO_ERROR;
}

// RFC 9113 Section 6.8 & Go #82365: Ingests GOAWAY frame (last_stream_id and error_code).
fn apply_goaway(s: H2Connection&, last_stream_id: u32, error_code: u32) -> u32 {
    s.goaway_received = true;
    s.goaway_last_stream_id = last_stream_id & 0x7FFFFFFF;
    s.goaway_error_code = error_code;
    return rfc::H2_ERR_NO_ERROR;
}

// Processes incoming WINDOW_UPDATE frame (RFC 9113 Section 6.9).
fn apply_window_update(s: H2Connection&, stream_id: u32, increment: u32) -> u32 {
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
        // If stream ID is unknown but <= last seen, ignore update on closed stream
        if stream_id <= s.last_peer_stream_id {
            return rfc::H2_ERR_NO_ERROR;
        }
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }

    // RFC 9113 Section 5.1: Endpoints MUST ignore WINDOW_UPDATE on closed streams
    if s.streams[s_idx].state == H2StreamState.Closed {
        return rfc::H2_ERR_NO_ERROR;
    }

    let next_stream = s.streams[s_idx].send_window + inc;
    if next_stream > rfc::H2_MAX_WINDOW_SIZE {
        return rfc::H2_ERR_FLOW_CONTROL_ERROR;
    }
    s.streams[s_idx].send_window = next_stream;
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
    return if s.conn_send_window < st_win { s.conn_send_window } else { st_win };
}

// Updates receive windows upon processing incoming DATA frame (including padding).
// Conforms to RFC 9113 §5.1 & §6.9: Flow-controlled DATA frames MUST always be accounted
// against the connection flow-control window, even if the stream is closed or in error.
fn on_data_frame_received(s: H2Connection&, hdr: const FrameHeader&, payload_len: u32) -> u32 {
    guard hdr.stream_id != 0 else { return rfc::H2_ERR_PROTOCOL_ERROR; }

    // RFC 9113 §6.9: Always account for DATA frames against connection flow control first
    let total_consumed = hdr.length as i64;
    s.conn_recv_window -= total_consumed;
    if s.conn_recv_window < 0 {
        return rfc::H2_ERR_FLOW_CONTROL_ERROR;
    }

    let s_idx, found = find_session_stream_idx(s, hdr.stream_id);
    guard found else {
        if hdr.stream_id <= s.last_peer_stream_id {
            return rfc::H2_ERR_STREAM_CLOSED;
        }
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }

    if s.streams[s_idx].state == H2StreamState.HalfClosedRemote ||
       s.streams[s_idx].state == H2StreamState.Closed ||
       s.streams[s_idx].trailers_received {
        return rfc::H2_ERR_STREAM_CLOSED;
    }

    // RFC 9113 §8.1.1 & §8.8: Status 204, 304, or 1xx MUST NOT contain message body / DATA frames
    let sc = s.streams[s_idx].status_code;
    if sc == 204 || sc == 304 || (sc >= 100 && sc < 200) {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }

    s.streams[s_idx].recv_window -= total_consumed;
    if s.streams[s_idx].recv_window < 0 {
        return rfc::H2_ERR_FLOW_CONTROL_ERROR;
    }

    s.streams[s_idx].received_data_bytes += payload_len;

    // RFC 9113 §8.1.2: Check if incoming DATA causes total data to exceed declared Content-Length
    let dec_len = s.streams[s_idx].declared_content_length;
    if dec_len >= 0 && s.streams[s_idx].received_data_bytes > dec_len {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }

    if (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 {
        apply_stream_end_remote(s, s_idx);

        // Verify Content-Length match if declared (Go #32728 / #46071)
        if dec_len >= 0 && dec_len != s.streams[s_idx].received_data_bytes {
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
    let prev = s.stream_nodes[s_idx].prev;
    let next = s.stream_nodes[s_idx].next;
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

    s.stream_nodes[s_idx].prev = -1;
    s.stream_nodes[s_idx].next = -1;

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
    s.stream_nodes[s_idx].stream_id = s.streams[s_idx].stream_id;
    s.stream_nodes[s_idx].next = -1;
    let tail = s.urgency_tails[u_idx];
    if tail >= 0 {
        s.stream_nodes[s_idx].prev = tail;
        s.stream_nodes[tail].next = s_idx;
        s.urgency_tails[u_idx] = s_idx;
    } else {
        s.stream_nodes[s_idx].prev = -1;
        s.urgency_heads[u_idx] = s_idx;
        s.urgency_tails[u_idx] = s_idx;
    }
    s.active_urgency_mask |= (1 << u);
}

// Synchronizes stream node membership across the 8 urgency buckets based on send readiness.
fn sync_stream_urgency_node(s: H2Connection&, s_idx: i32) {
    guard s_idx >= 0 && s_idx < (s.streams.len as i32) else { return; }
    let u = s.streams[s_idx].priority.urgency;
    guard u <= 7 else { return; }
    let st = s.streams[s_idx].state;
    let can_send = (st == H2StreamState.Open || st == H2StreamState.HalfClosedRemote);
    let ready = s.streams[s_idx].active && can_send
        && s.streams[s_idx].pending_send_bytes > 0
        && s.streams[s_idx].send_window > 0;
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
        s.stream_nodes[idx].prev = -1;
        s.stream_nodes[idx].next = -1;
        s.stream_nodes[idx].stream_id = s.streams[idx].stream_id;
        let st = s.streams[idx].state;
        let can_send = (st == H2StreamState.Open || st == H2StreamState.HalfClosedRemote);
        if s.streams[idx].active && can_send && s.streams[idx].pending_send_bytes > 0
            && s.streams[idx].send_window > 0 && s.streams[idx].priority.urgency <= 7 {
            link_stream_to_urgency_bucket(s, idx, s.streams[idx].priority.urgency);
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

// Applies dynamic priority update (from PRIORITY_UPDATE frame or Priority header).
fn apply_priority_update(s: H2Connection&, prioritized_stream_id: u32, prio: wing::PriorityParam) -> u32 {
    s.client_sent_priority = true;
    let s_idx, found = find_session_stream_idx(s, prioritized_stream_id);
    guard found else { return rfc::H2_ERR_NO_ERROR; }

    let old_u = s.streams[s_idx].priority.urgency;
    unlink_stream_from_urgency_bucket(s, s_idx, old_u);

    var final_prio = prio;
    if s.is_behind_proxy {
        final_prio.urgency = 3;
        final_prio.incremental = true;
    }
    s.streams[s_idx].priority = final_prio;
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
    let target_stream_id = s.streams[chosen_idx].stream_id;
    let quota = compute_stream_send_quota(s, target_stream_id);
    guard quota > 0 else { return 0, 0, false; }

    var send_len = s.streams[chosen_idx].pending_send_bytes;
    if send_len > quota {
        send_len = quota as u32;
    }
    if send_len > max_frame_len {
        send_len = max_frame_len;
    }
    if send_len > s.peer_max_frame_size {
        send_len = s.peer_max_frame_size;
    }

    // Deduct from pending and windows
    s.streams[chosen_idx].pending_send_bytes -= send_len;
    s.streams[chosen_idx].send_window -= send_len;
    s.conn_send_window -= send_len;
    sync_stream_urgency_node(s, chosen_idx);

    // Update anti-starvation streak tracking
    if s.streams[chosen_idx].priority.urgency < 3 {
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
        let st = s.streams[chk].state;
        let can_send = (st == H2StreamState.Open || st == H2StreamState.HalfClosedRemote);
        if s.streams[chk].active && can_send && s.streams[chk].pending_send_bytes > 0
            && s.streams[chk].send_window > 0 && s.streams[chk].priority.urgency >= 3 {
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
        let st = s.streams[node_idx].state;
        let can_send = (st == H2StreamState.Open || st == H2StreamState.HalfClosedRemote);
        if s.streams[node_idx].active && can_send && s.streams[node_idx].pending_send_bytes > 0
            && s.streams[node_idx].send_window > 0 && s.streams[node_idx].priority.urgency == u
            && !s.streams[node_idx].priority.incremental {
            return node_idx;
        }
        node_idx = s.stream_nodes[node_idx].next;
    }
    var idx: i32 = 0;
    let stream_count = s.streams.len as i32;
    while idx < stream_count {
        let st = s.streams[idx].state;
        let can_send = (st == H2StreamState.Open || st == H2StreamState.HalfClosedRemote);
        if s.streams[idx].active && can_send && s.streams[idx].pending_send_bytes > 0
            && s.streams[idx].send_window > 0 && s.streams[idx].priority.urgency == u
            && !s.streams[idx].priority.incremental {
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
            let st = s.streams[candidate].state;
            let can_send = (st == H2StreamState.Open || st == H2StreamState.HalfClosedRemote);
            if s.streams[candidate].active && can_send && s.streams[candidate].pending_send_bytes > 0
                && s.streams[candidate].send_window > 0 && s.streams[candidate].priority.urgency == u
                && s.streams[candidate].priority.incremental {
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
    guard dominant_u < 3 else {
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

    var search_mask = apply_urgency_anti_starvation(s, s.active_urgency_mask);
    var pass: i32 = 0;
    while pass < 2 {
        var mask = search_mask;
        while mask != 0 {
            let u = ctz_urgency_mask(mask);
            let target_stream_id, send_len, ok = select_and_commit_stream(s, u, max_frame_len);
            if ok {
                return target_stream_id, send_len, true;
            }
            mask &= ~(1 << u);
        }
        if pass == 0 && search_mask != s.active_urgency_mask {
            search_mask = s.active_urgency_mask;
            s.urgency_streak_count = 0;
            pass++;
        } else {
            break;
        }
    }

    return 0, 0, false;
}

// RFC 9218 Section 4: Priority Parameters - O(1) priority scheduler overload using `ctz_urgency_mask`
// on `conn.active_urgency_mask` (bit 0 = urgency 0) with a 16-frame burst quantum cap on Urgency 0.
fn schedule_next_write(conn: H2Connection&) -> u32, bool {
    let stream_id, _, ok = schedule_next_write(conn, conn.peer_max_frame_size);
    return stream_id, ok;
}
