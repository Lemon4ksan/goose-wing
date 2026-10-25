// HTTP/2 connection session coordinator, RFC 9218 write scheduler,
// two-level credit-based flow control, and defense-in-depth Anti-DoS mitigations (RFC 9113, RFC 9218).
namespace wing;

import std;
import core from "..";
import .framing;
import .hpack;

// ---- 1. session constants & limits ------------------------------------------

const MAX_INITIAL_WINDOW_SIZE: i64  = 0x7FFFFFFF; // 2^31 - 1
const DEFAULT_WINDOW_SIZE:     i64  = 65535;
const DEFAULT_RESET_BURST:     u64  = 1000;       // nghttp2 v1.57.0 reference (CVE-2023-44487)
const DEFAULT_RESET_RATE:      u64  = 33;         // Tokens per second
const MAX_CONT_FRAMES_LIMIT:   u32  = 16;         // CONTINUATION Flood defense (CVE-2024-28182 / CVE-2024-30255)
const MAX_EMPTY_FRAME_STREAK:  u32  = 8;          // Empty Frame Flooding defense (CVE-2019-9518)
const MAX_PENDING_CTRL_FRAMES: u32  = 64;         // PING / SETTINGS Flood defense (CVE-2019-9512 / CVE-2019-9515)
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
    behind_proxy: bool = false
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
    behind_proxy: bool = false
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

// Validates protocol and Anti-DoS invariants upon receiving a 9-byte frame header
// strictly before buffering or parsing the frame payload.
fn on_ingress_frame_header(s: H2Connection&, hdr: const FrameHeader&, now_ms: u64) -> u32 {
    // 1. Strict CONTINUATION state lock (RFC 9113 Section 6.10 & CVE-2024-28182)
    if s.continuation_stream_id != 0 {
        if hdr.frame_type != FRAME_CONTINUATION || hdr.stream_id != s.continuation_stream_id {
            return ERR_PROTOCOL_ERROR;
        }

        // Slow-Drip CONTINUATION memory retention defense
        if now_ms > s.continuation_start_ms {
            let duration_ms = now_ms - s.continuation_start_ms;
            if duration_ms > s.max_header_block_duration_ms {
                return ERR_ENHANCE_YOUR_CALM;
            }
        }

        s.continuation_frames_cnt++;
        if s.continuation_frames_cnt > MAX_CONT_FRAMES_LIMIT {
            return ERR_ENHANCE_YOUR_CALM;
        }

        // Pre-allocation cumulative size check
        s.accumulated_header_size += hdr.length;
        if s.accumulated_header_size > s.max_header_list_size {
            return ERR_ENHANCE_YOUR_CALM;
        }

        if (hdr.flags & FLAG_END_HEADERS) != 0 {
            s.continuation_stream_id = 0;
            s.continuation_frames_cnt = 0;
            s.accumulated_header_size = 0;
        }
        return ERR_NO_ERROR;
    }

    // CONTINUATION outside ExpectContinuation state is a fatal protocol error
    if hdr.frame_type == FRAME_CONTINUATION {
        return ERR_PROTOCOL_ERROR;
    }

    // 2. Empty Frame Flooding defense (CVE-2019-9518)
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

    // 3. Rapid Reset defense (CVE-2023-44487) via Token Bucket
    if hdr.frame_type == FRAME_RST_STREAM {
        if hdr.stream_id == 0 {
            return ERR_PROTOCOL_ERROR;
        }
        if hdr.length != 4 {
            return ERR_FRAME_SIZE_ERROR;
        }

        // RST_STREAM on idle stream is invalid (RFC 9113 Section 6.4)
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

    // 4. Client stream opening & CONTINUATION transition
    if hdr.frame_type == FRAME_HEADERS {
        if hdr.stream_id == 0 {
            return ERR_PROTOCOL_ERROR;
        }

        // Client-initiated streams must be odd (RFC 9113 Section 5.1.1)
        if (hdr.stream_id % 2) == 0 {
            return ERR_PROTOCOL_ERROR;
        }

        let s_idx, found = find_session_stream_idx(s, hdr.stream_id);
        if !found {
            // Monotonic stream ID increase check
            if hdr.stream_id <= s.last_peer_stream_id {
                return ERR_PROTOCOL_ERROR;
            }

            // Rapid Reset non-cancelling variant defense: enforce max_concurrent_streams
            if s.active_stream_count >= s.max_concurrent_streams {
                s.concurrency_violations++;
                if s.concurrency_violations > MAX_CONCURRENCY_VIOLATIONS {
                    return ERR_ENHANCE_YOUR_CALM;
                }
                return ERR_REFUSED_STREAM;
            }

            // Open new stream
            s.last_peer_stream_id = hdr.stream_id;
            s.concurrency_violations = 0;
            open_new_session_stream(s, hdr.stream_id, (hdr.flags & FLAG_END_STREAM) != 0);
        } else {
            // Existing stream headers (trailers)
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

    // 5. PING / SETTINGS Flood defense (CVE-2019-9512 / CVE-2019-9515)
    if (hdr.frame_type == FRAME_PING || hdr.frame_type == FRAME_SETTINGS) &&
       (hdr.flags & FLAG_ACK) == 0 {
        s.pending_control_frames++;
        if s.pending_control_frames > MAX_PENDING_CTRL_FRAMES {
            return ERR_ENHANCE_YOUR_CALM;
        }
    }

    // 6. General stream association and fixed-length validation
    return validate_frame_header_rules(hdr, s.local_max_frame_size);
}

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

    // Find free slot or append
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
fn on_data_frame_received(s: H2Connection&, hdr: const FrameHeader&, payload_len: u32) -> u32 {
    guard hdr.stream_id != 0 else { return ERR_PROTOCOL_ERROR; }

    let s_idx, found = find_session_stream_idx(s, hdr.stream_id);
    guard found else {
        if hdr.stream_id <= s.last_peer_stream_id {
            return ERR_STREAM_CLOSED;
        }
        return ERR_PROTOCOL_ERROR;
    }

    let total_consumed = hdr.length as i64;
    s.conn_recv_window -= total_consumed;
    if s.conn_recv_window < 0 {
        return ERR_FLOW_CONTROL_ERROR;
    }

    s.streams[s_idx].recv_window -= total_consumed;
    if s.streams[s_idx].recv_window < 0 {
        return ERR_FLOW_CONTROL_ERROR;
    }

    s.streams[s_idx].received_data_bytes += payload_len;

    if (hdr.flags & FLAG_END_STREAM) != 0 {
        s.streams[s_idx].state = H2StreamState.HalfClosedRemote;

        // Verify Content-Length match if declared (Go #32728 / #46071)
        let dec_len = s.streams[s_idx].declared_content_length;
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

// Schedules next stream for DATA frame transmission according to RFC 9218 urgency 0..7.
// Alternates between incremental and non-incremental streams to prevent starvation.
// Returns (stream_id, allowed_send_bytes, found).
fn schedule_next_write(s: H2Connection&, max_frame_len: u32) -> u32, u32, bool {
    guard s.conn_send_window > 0 else { return 0, 0, false; }

    var u: u8 = 0;
    while u <= 7 {
        // Collect candidate streams in bucket u
        var non_inc_idx: i32 = -1;
        var inc_idx: i32 = -1;

        var idx: i32 = 0;
        while idx < (s.streams.len as i32) {
            if s.streams[idx].active &&
               s.streams[idx].pending_send_bytes > 0 &&
               s.streams[idx].send_window > 0 &&
               s.streams[idx].priority.urgency == u {

                if s.streams[idx].priority.incremental {
                    if inc_idx < 0 { inc_idx = idx; }
                } else {
                    if non_inc_idx < 0 { non_inc_idx = idx; }
                }
            }
            idx++;
        }

        var chosen_idx: i32 = -1;
        if non_inc_idx >= 0 && inc_idx >= 0 {
            // Both stream types present: alternate turn
            if s.bucket_prefer_incremental[u as i64] {
                chosen_idx = inc_idx;
                s.bucket_prefer_incremental[u as i64] = false;
            } else {
                chosen_idx = non_inc_idx;
                s.bucket_prefer_incremental[u as i64] = true;
            }
        } else if non_inc_idx >= 0 {
            chosen_idx = non_inc_idx;
        } else if inc_idx >= 0 {
            chosen_idx = inc_idx;
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

                return target_stream_id, send_len, true;
            }
        }

        u++;
    }

    return 0, 0, false;
}
