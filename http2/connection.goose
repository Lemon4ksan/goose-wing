// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/2 connection session coordinator, RFC 9218 write scheduler,
// two-level credit-based flow control, and defense-in-depth Anti-DoS mitigations (RFC 9113, RFC 9218).
namespace wing;

import std;
import core from "..";
import .framing;
import .hpack;

// ---- 1. session constants & limits ------------------------------------------

const MAX_INITIAL_WINDOW_SIZE: i64 = 0x7FFFFFFF; // 2^31 - 1
const DEFAULT_WINDOW_SIZE: i64 = 65535;
const DEFAULT_RESET_BURST: u64 = 1000;            // nghttp2 v1.57.0 reference (CVE-2023-44487)
const DEFAULT_RESET_RATE: u64 = 33;               // Tokens per second
const MAX_CONT_FRAMES_LIMIT: u32 = 16;            // CONTINUATION Flood defense (CVE-2024-28182 / CVE-2024-30255)
const MAX_HEADER_BLOCK_SIZE_LIMIT: u32 = 65536;   // Hard 64 KB ceiling for any CONTINUATION / HEADERS block
const MAX_EMPTY_FRAME_STREAK: u32 = 8;            // Empty Frame Flooding defense (CVE-2019-9518)
const MAX_PENDING_CTRL_FRAMES: u32 = 64;          // PING / SETTINGS Flood defense (CVE-2019-9512 / CVE-2019-9515)
const MAX_CONCURRENCY_VIOLATIONS: u32 = 5;        // Rapid Reset non-cancelling variant defense
const DEFAULT_MAX_HEADER_BLOCK_DURATION_MS: u64 = 10000; // Slow-Drip CONTINUATION memory retention defense

// ---- 2. token bucket rate limiter (rapid reset cve-2023-44487) -------------

struct TokenBucket {
    tokens: u64 = 1000,
    burst: u64 = 1000,
    rate_per_sec: u64 = 33,
    last_refill_ms: u64 = 0,
}

fn new_h2_token_bucket(burst: u64 = 1000, rate_per_sec: u64 = 33, now_ms: u64 = 0) -> TokenBucket {
    return TokenBucket {
        tokens: burst,
        burst: burst,
        rate_per_sec: rate_per_sec,
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

// ---- 3. stream state machine & stream descriptors (rfc 9113 section 5.1) ---

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
    stream_id: u32 = 0,
    state: H2StreamState = H2StreamState.Idle,
    send_window: i64 = 65535, // Signed 64-bit integer to support negative deltas
    recv_window: i64 = 65535,
    priority: PriorityParam = PriorityParam { .. },
    pending_send_bytes: u32 = 0,
    declared_content_length: i64 = -1,
    received_data_bytes: i64 = 0,
    headers_received: bool = false,
    trailers_received: bool = false,
    active: bool = false,
}

// ---- 4. http/2 connection state & coordinator -------------------------------

struct H2Connection {
    hpack_dec: DynamicTable = DynamicTable { .. },
    conn_send_window: i64 = 65535,
    conn_recv_window: i64 = 65535,
    peer_initial_window_size: i64 = 65535,
    local_initial_window_size: i64 = 65535,
    local_max_frame_size: u32 = 16384,
    max_header_list_size: u32 = 8192,
    max_concurrent_streams: u32 = 128,
    active_stream_count: u32 = 0,
    last_peer_stream_id: u32 = 0,

    // Active streams table (bounded inline storage)
    streams: H2Stream[..64] = [],

    // Exclusive CONTINUATION lock (0 if not expecting CONTINUATION)
    continuation_stream_id: u32 = 0,
    continuation_frames_cnt: u32 = 0,
    accumulated_header_size: u32 = 0,
    continuation_start_ms: u64 = 0,
    max_header_block_duration_ms: u64 = 10000,

    // Anti-DoS resource limiters
    reset_limiter: TokenBucket = TokenBucket { .. },
    empty_frame_streak: u32 = 0,
    pending_control_frames: u32 = 0,
    concurrency_violations: u32 = 0,
    initial_window_update_count: u32 = 0,

    // RFC 9218 prioritization flags
    client_sent_priority: bool = false,
    no_rfc7540_priorities: bool = false,
    peer_no_rfc7540_set: bool = false,
    is_behind_proxy: bool = false,

    // Starvation toggle per urgency bucket (0..7) between incremental and non-incremental
    bucket_prefer_incremental: bool[8] = [false; 8],
    bucket_last_inc_idx: i32[8] = [-1; 8],
    urgency_streak_count: u32 = 0,

    // Shutdown / GOAWAY tracking
    goaway_sent: bool = false,
    goaway_received: bool = false,
    goaway_last_stream_id: u32 = 0,
    goaway_error_code: u32 = 0,
}

type SessionState = H2Connection;

// Returns a default-initialized H2Connection with RFC 9113 & RFC 9218 baseline invariants.
fn new_h2_connection(
    now_ms: u64 = 0,
    max_header_list: u32 = 8192,
    behind_proxy: bool = false,
) -> H2Connection {
    return H2Connection {
        hpack_dec: new_dynamic_table(HPACK_DEFAULT_MAX_DYN_SIZE),
        reset_limiter: new_h2_token_bucket(DEFAULT_RESET_BURST, DEFAULT_RESET_RATE, now_ms),
        max_header_list_size: max_header_list,
        is_behind_proxy: behind_proxy,
        ..
    };
}

inline fn new_session_state(
    now_ms: u64 = 0,
    max_header_list: u32 = 8192,
    behind_proxy: bool = false,
) -> H2Connection {
    return new_h2_connection(now_ms, max_header_list, behind_proxy);
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

inline fn find_session_stream_idx(s: const H2Connection&, stream_id: u32) -> i32, bool {
    return find_h2_stream_idx(s, stream_id);
}

// ---- 5. frame ingress coordinator & anti-dos barriers -----------------------

// Opens a new stream descriptor with default RFC 9218 priority.
fn open_new_session_stream(s: H2Connection&, stream_id: u32, end_stream: bool) {
    var def_prio = PriorityParam {
        urgency: 3,
        // Go 1.27 #75500: default to incremental=true before first client priority signal
        incremental: if s.is_behind_proxy { true } else { !s.client_sent_priority },
    };

    var new_stream = H2Stream {
        stream_id: stream_id,
        state: if end_stream { H2StreamState.HalfClosedRemote } else { H2StreamState.Open },
        send_window: s.peer_initial_window_size,
        recv_window: s.local_initial_window_size,
        priority: def_prio,
        active: true,
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
    if !placed && s.streams.len < s.streams.cap {
        s.streams.push(new_stream);
    }
    s.active_stream_count++;
}

fn validate_h2_continuation_state(s: H2Connection&, hdr: const FrameHeader&, now_ms: u64) -> u32, bool {
    if s.continuation_stream_id != 0 {
        if hdr.frame_type != FRAME_CONTINUATION || hdr.stream_id != s.continuation_stream_id {
            return ERR_PROTOCOL_ERROR, true;
        }

        if hdr.length == 0 && (hdr.flags & FLAG_END_HEADERS) == 0 {
            return ERR_PROTOCOL_ERROR, true;
        }

        if now_ms > s.continuation_start_ms {
            let duration_ms = now_ms - s.continuation_start_ms;
            if duration_ms > s.max_header_block_duration_ms {
                return ERR_ENHANCE_YOUR_CALM, true;
            }
        }

        s.continuation_frames_cnt++;
        if s.continuation_frames_cnt > MAX_CONT_FRAMES_LIMIT {
            return ERR_ENHANCE_YOUR_CALM, true;
        }

        s.accumulated_header_size += hdr.length;
        if s.accumulated_header_size > s.max_header_list_size || s.accumulated_header_size > MAX_HEADER_BLOCK_SIZE_LIMIT {
            return ERR_ENHANCE_YOUR_CALM, true;
        }

        if (hdr.flags & FLAG_END_HEADERS) != 0 {
            s.continuation_stream_id = 0;
            s.continuation_frames_cnt = 0;
            s.accumulated_header_size = 0;
        }
        return ERR_NO_ERROR, true;
    }

    if hdr.frame_type == FRAME_CONTINUATION {
        return ERR_PROTOCOL_ERROR, true;
    }

    return ERR_NO_ERROR, false;
}

fn validate_h2_empty_frame_streak(s: H2Connection&, hdr: const FrameHeader&) -> u32 {
    if (hdr.frame_type == FRAME_DATA || hdr.frame_type == FRAME_HEADERS) &&
       hdr.length == 0 &&
       (hdr.flags & FLAG_END_STREAM) == 0 &&
       (hdr.flags & FLAG_END_HEADERS) == 0 {
        s.empty_frame_streak++;
        if s.empty_frame_streak > MAX_EMPTY_FRAME_STREAK {
            return ERR_ENHANCE_YOUR_CALM;
        }
    } else {
        s.empty_frame_streak = 0;
    }
    return ERR_NO_ERROR;
}

fn handle_h2_rst_stream_header(s: H2Connection&, hdr: const FrameHeader&, now_ms: u64) -> u32 {
    if hdr.stream_id == 0 {
        return ERR_PROTOCOL_ERROR;
    }
    if hdr.length != 4 {
        return ERR_FRAME_SIZE_ERROR;
    }

    let s_idx, found = find_session_stream_idx(s, hdr.stream_id);
    if !found && hdr.stream_id > s.last_peer_stream_id {
        return ERR_PROTOCOL_ERROR;
    }

    if !consume_token(s.reset_limiter, now_ms) {
        return ERR_ENHANCE_YOUR_CALM;
    }

    if found {
        s.streams[s_idx].state = H2StreamState.Closed;
        s.streams[s_idx].active = false;
        if s.active_stream_count > 0 {
            s.active_stream_count--;
        }
    }
    return ERR_NO_ERROR;
}

fn handle_h2_headers_frame_header(s: H2Connection&, hdr: const FrameHeader&, now_ms: u64) -> u32 {
    if hdr.stream_id == 0 {
        return ERR_PROTOCOL_ERROR;
    }

    if hdr.length == 0 && (hdr.flags & FLAG_END_HEADERS) == 0 {
        return ERR_PROTOCOL_ERROR;
    }

    if hdr.length > s.max_header_list_size || hdr.length > MAX_HEADER_BLOCK_SIZE_LIMIT {
        return ERR_ENHANCE_YOUR_CALM;
    }

    if (hdr.stream_id % 2) == 0 {
        return ERR_PROTOCOL_ERROR;
    }

    let s_idx, found = find_session_stream_idx(s, hdr.stream_id);
    if !found {
        if hdr.stream_id <= s.last_peer_stream_id {
            return ERR_STREAM_CLOSED;
        }

        // RFC 9113 Section 6.8 & Go #82365:
        // After receiving GOAWAY, any new stream with ID > goaway_last_stream_id must be refused
        if s.goaway_received && hdr.stream_id > s.goaway_last_stream_id {
            return ERR_REFUSED_STREAM;
        }

        if s.active_stream_count >= s.max_concurrent_streams {
            s.concurrency_violations++;
            if s.concurrency_violations > MAX_CONCURRENCY_VIOLATIONS {
                return ERR_ENHANCE_YOUR_CALM;
            }
            return ERR_REFUSED_STREAM;
        }

        s.last_peer_stream_id = hdr.stream_id;
        s.concurrency_violations = 0;
        open_new_session_stream(s, hdr.stream_id, (hdr.flags & FLAG_END_STREAM) != 0);
    } else {
        // RFC 9113 Section 5.1: Extra HEADERS after END_STREAM is STREAM_CLOSED error
        if s.streams[s_idx].state == H2StreamState.HalfClosedRemote ||
           s.streams[s_idx].state == H2StreamState.Closed {
            return ERR_STREAM_CLOSED;
        }
        if (hdr.flags & FLAG_END_STREAM) != 0 {
            s.streams[s_idx].trailers_received = true;
            s.streams[s_idx].state = H2StreamState.HalfClosedRemote;
        }
    }

    if (hdr.flags & FLAG_END_HEADERS) == 0 {
        s.continuation_stream_id = hdr.stream_id;
        s.continuation_frames_cnt = 0;
        s.accumulated_header_size = hdr.length;
        s.continuation_start_ms = now_ms;
    }
    return ERR_NO_ERROR;
}

fn check_h2_control_frame_flood(s: H2Connection&, hdr: const FrameHeader&) -> u32 {
    if hdr.frame_type == FRAME_PING || hdr.frame_type == FRAME_SETTINGS {
        s.pending_control_frames++;
        if s.pending_control_frames > MAX_PENDING_CTRL_FRAMES {
            return ERR_ENHANCE_YOUR_CALM;
        }
    }
    return ERR_NO_ERROR;
}

// Validates protocol and Anti-DoS invariants upon receiving a 9-byte frame header
// strictly before buffering or parsing the frame payload.
fn on_ingress_frame_header(s: H2Connection&, hdr: const FrameHeader&, now_ms: u64) -> u32 {
    let cont_err, is_cont = validate_h2_continuation_state(s, hdr, now_ms);
    if is_cont {
        return cont_err;
    }

    let streak_err = validate_h2_empty_frame_streak(s, hdr);
    guard streak_err == ERR_NO_ERROR else { return streak_err; }

    if hdr.frame_type == FRAME_RST_STREAM {
        return handle_h2_rst_stream_header(s, hdr, now_ms);
    }

    if hdr.frame_type == FRAME_HEADERS {
        return handle_h2_headers_frame_header(s, hdr, now_ms);
    }

    let ctrl_err = check_h2_control_frame_flood(s, hdr);
    guard ctrl_err == ERR_NO_ERROR else { return ctrl_err; }

    return validate_frame_header_rules(hdr, s.local_max_frame_size);
}

// ---- 6. two-level flow control & signed window deltas (inv-flow-01) ----------

// Dynamically updates stream send windows upon receiving SETTINGS_INITIAL_WINDOW_SIZE.
// Computes signed delta = int64(new_init_win) - int64(old_init_win).
// Enforces MAX_INITIAL_WINDOW_SIZE ceiling and allows negative stream windows.
fn apply_peer_initial_window_size_delta(s: H2Connection&, new_init_win: u32) -> u32 {
    s.initial_window_update_count++;
    // CVE-2026-78669 defense: prevent excessive CPU consumption from repeated initial window changes
    if s.initial_window_update_count > 16 {
        return ERR_ENHANCE_YOUR_CALM;
    }

    let new_win_i64 = new_init_win as i64;
    guard new_win_i64 <= MAX_INITIAL_WINDOW_SIZE else {
        return ERR_FLOW_CONTROL_ERROR;
    }

    let delta = new_win_i64 - s.peer_initial_window_size;
    s.peer_initial_window_size = new_win_i64;

    for &stream in s.streams {
        if stream.active && stream.state != H2StreamState.Closed {
            let next_win = stream.send_window + delta;
            // Overflows beyond 2^31 - 1 trigger flow control error
            if next_win > MAX_INITIAL_WINDOW_SIZE {
                return ERR_FLOW_CONTROL_ERROR;
            }
            // Stream window may become negative if peer shrank initial window size
            stream.send_window = next_win;
        }
    }

    return ERR_NO_ERROR;
}

// RFC 9113 Section 6.8 & Go #82365: Ingests GOAWAY frame (last_stream_id and error_code).
fn apply_goaway(s: H2Connection&, last_stream_id: u32, error_code: u32) -> u32 {
    s.goaway_received = true;
    s.goaway_last_stream_id = last_stream_id & 0x7FFFFFFF;
    s.goaway_error_code = error_code;
    return ERR_NO_ERROR;
}

// Processes incoming WINDOW_UPDATE frame (RFC 9113 Section 6.9).
fn apply_window_update(s: H2Connection&, stream_id: u32, increment: u32) -> u32 {
    guard increment > 0 && increment <= (MAX_INITIAL_WINDOW_SIZE as u32) else {
        return ERR_PROTOCOL_ERROR;
    }
    let inc: i64 = increment;

    if stream_id == 0 {
        // Connection-level window
        let next_conn = s.conn_send_window + inc;
        if next_conn > MAX_INITIAL_WINDOW_SIZE {
            return ERR_FLOW_CONTROL_ERROR;
        }
        s.conn_send_window = next_conn;
        return ERR_NO_ERROR;
    }

    // Stream-level window
    let s_idx, found = find_session_stream_idx(s, stream_id);
    guard found else {
        // If stream ID is unknown but <= last seen, ignore update on closed stream
        if stream_id <= s.last_peer_stream_id {
            return ERR_NO_ERROR;
        }
        return ERR_PROTOCOL_ERROR;
    }

    // RFC 9113 Section 5.1: Endpoints MUST ignore WINDOW_UPDATE on closed streams
    if s.streams[s_idx].state == H2StreamState.Closed {
        return ERR_NO_ERROR;
    }

    let next_stream = s.streams[s_idx].send_window + inc;
    if next_stream > MAX_INITIAL_WINDOW_SIZE {
        return ERR_FLOW_CONTROL_ERROR;
    }
    s.streams[s_idx].send_window = next_stream;
    return ERR_NO_ERROR;
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
    guard hdr.stream_id != 0 else { return ERR_PROTOCOL_ERROR; }

    // RFC 9113 §6.9: Always account for DATA frames against connection flow control first
    let total_consumed = hdr.length as i64;
    s.conn_recv_window -= total_consumed;
    if s.conn_recv_window < 0 {
        return ERR_FLOW_CONTROL_ERROR;
    }

    let s_idx, found = find_session_stream_idx(s, hdr.stream_id);
    guard found else {
        if hdr.stream_id <= s.last_peer_stream_id {
            return ERR_STREAM_CLOSED;
        }
        return ERR_PROTOCOL_ERROR;
    }

    if s.streams[s_idx].state == H2StreamState.HalfClosedRemote ||
       s.streams[s_idx].state == H2StreamState.Closed {
        return ERR_STREAM_CLOSED;
    }

    s.streams[s_idx].recv_window -= total_consumed;
    if s.streams[s_idx].recv_window < 0 {
        return ERR_FLOW_CONTROL_ERROR;
    }

    s.streams[s_idx].received_data_bytes += payload_len;

    // RFC 9113 §8.1.2: Check if incoming DATA causes total data to exceed declared Content-Length
    let dec_len = s.streams[s_idx].declared_content_length;
    if dec_len >= 0 && s.streams[s_idx].received_data_bytes > dec_len {
        return ERR_PROTOCOL_ERROR;
    }

    if (hdr.flags & FLAG_END_STREAM) != 0 {
        s.streams[s_idx].state = H2StreamState.HalfClosedRemote;

        // Verify Content-Length match if declared (Go #32728 / #46071)
        if dec_len >= 0 && dec_len != s.streams[s_idx].received_data_bytes {
            return ERR_PROTOCOL_ERROR;
        }
    }

    return ERR_NO_ERROR;
}

// Decrements pending control frames counter when ACK frames are flushed.
fn ack_control_frame_flushed(s: H2Connection&) {
    if s.pending_control_frames > 0 {
        s.pending_control_frames--;
    }
}

// ---- 7. rfc 9218 extensible write scheduler ---------------------------------

// Applies dynamic priority update (from PRIORITY_UPDATE frame or Priority header).
fn apply_priority_update(s: H2Connection&, prioritized_stream_id: u32, prio: PriorityParam) -> u32 {
    s.client_sent_priority = true;
    let s_idx, found = find_session_stream_idx(s, prioritized_stream_id);
    guard found else { return ERR_NO_ERROR; }

    var final_prio = prio;
    if s.is_behind_proxy {
        final_prio.urgency = 3;
        final_prio.incremental = true;
    }
    s.streams[s_idx].priority = final_prio;
    return ERR_NO_ERROR;
}

const MAX_HIGH_URGENCY_STREAK: u32 = 16; // Max consecutive frames before lower-urgency credit yield

// Schedules next stream for DATA frame transmission according to RFC 9218 urgency 0..7.
// Alternates between incremental and non-incremental streams to prevent starvation.
// Implements Round-Robin fair interleaving among concurrent incremental streams within a bucket.
// Implements anti-starvation credit yield when higher-urgency streams dominate for > 16 frames.
// Returns (stream_id, allowed_send_bytes, found).
fn schedule_next_write(s: H2Connection&, max_frame_len: u32) -> u32, u32, bool {
    guard s.conn_send_window > 0 else { return 0, 0, false; }

    // Check if anti-starvation yield is triggered for lower-urgency streams
    var force_yield = false;
    if s.urgency_streak_count >= MAX_HIGH_URGENCY_STREAK {
        // Check if there is any ready stream in lower urgency (u >= 3)
        var has_lower_ready = false;
        var chk: i32 = 0;
        while chk < (s.streams.len as i32) {
            if s.streams[chk].active &&
               s.streams[chk].pending_send_bytes > 0 &&
               s.streams[chk].send_window > 0 &&
               s.streams[chk].priority.urgency >= 3 {
                has_lower_ready = true;
                break;
            }
            chk++;
        }
        if has_lower_ready {
            force_yield = true;
        } else {
            s.urgency_streak_count = 0; // No lower streams waiting, reset streak
        }
    }

    var start_u: u8 = if force_yield { 3 } else { 0 };
    var pass: i32 = 0;

    while pass < 2 {
        var u = start_u;
        while u <= 7 {
            let u_idx = u as i64;
            let stream_count = s.streams.len as i32;

            // Collect non-incremental candidate (sequential)
            var non_inc_idx: i32 = -1;
            var idx: i32 = 0;
            while idx < stream_count {
                if s.streams[idx].active &&
                   s.streams[idx].pending_send_bytes > 0 &&
                   s.streams[idx].send_window > 0 &&
                   s.streams[idx].priority.urgency == u &&
                   !s.streams[idx].priority.incremental {
                    non_inc_idx = idx;
                    break;
                }
                idx++;
            }

            // Collect incremental candidate using Round-Robin starting after bucket_last_inc_idx[u]
            var inc_idx: i32 = -1;
            let last_inc = s.bucket_last_inc_idx[u_idx];
            var step: i32 = 1;
            while step <= stream_count {
                let candidate = if last_inc < 0 { step - 1 } else { (last_inc + step) % stream_count };
                if candidate >= 0 && candidate < stream_count {
                    if s.streams[candidate].active &&
                       s.streams[candidate].pending_send_bytes > 0 &&
                       s.streams[candidate].send_window > 0 &&
                       s.streams[candidate].priority.urgency == u &&
                       s.streams[candidate].priority.incremental {
                        inc_idx = candidate;
                        break;
                    }
                }
                step++;
            }

            var chosen_idx: i32 = -1;
            if non_inc_idx >= 0 && inc_idx >= 0 {
                // Both stream types present in bucket: alternate turn
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

            if chosen_idx >= 0 {
                let target_stream_id = s.streams[chosen_idx].stream_id;
                let quota = compute_stream_send_quota(s, target_stream_id);
                if quota > 0 {
                    var send_len = s.streams[chosen_idx].pending_send_bytes;
                    if send_len > quota {
                        send_len = quota as u32;
                    }
                    if send_len > max_frame_len {
                        send_len = max_frame_len;
                    }
                    if send_len > s.local_max_frame_size {
                        send_len = s.local_max_frame_size;
                    }

                    // Deduct from pending and windows
                    s.streams[chosen_idx].pending_send_bytes -= send_len;
                    s.streams[chosen_idx].send_window -= send_len;
                    s.conn_send_window -= send_len;

                    // Update anti-starvation streak tracking
                    if s.streams[chosen_idx].priority.urgency < 3 {
                        s.urgency_streak_count++;
                    } else {
                        s.urgency_streak_count = 0;
                    }

                    return target_stream_id, send_len, true;
                }
            }

            u++;
        }

        // If force_yield pass completed without finding a lower-urgency candidate, fall back to pass 2 from u=0
        if force_yield && pass == 0 {
            start_u = 0;
            s.urgency_streak_count = 0;
            pass++;
        } else {
            break;
        }
    }

    return 0, 0, false;
}
