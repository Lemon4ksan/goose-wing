// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic Flow Control Credit Management (RFC 9000 §4).
// Enforces connection-level and stream-level byte budgets,
// detects credit exhaustion, and generates window update thresholds.
namespace internal;

import std;
import core from "..";
import .frames;
import .stream;

// Computes stream offset end position (RFC 9000 §4.1).
// Computes committed credit growth beyond current high watermark (RFC 9000 §4.1).
// Computes projected connection usage allowance (RFC 9000 §4.1).
// Computes unspent flow control allowance safely guarding against underflow (RFC 9000 §4.1).
inline fn calc_unspent_credit(limit: u64, consumed: u64) -> u64 {
    guard limit > consumed else { return 0; }
    return limit - consumed;
}

// Calculates candidate window credit advertisement clamped to 2^62 - 1 (RFC 9000 §4.2).
inline fn calc_advertised_window_candidate(base: u64, window_size: u64) -> u64 {
    let candidate = base + window_size;
    if candidate < base || candidate > rfc::QUIC_VARINT_MAX {
        return rfc::QUIC_VARINT_MAX;
    }
    return candidate;
}

// Returns the effective consumed or received byte marker for flow control accounting (RFC 9000 §4.1).
inline fn calc_effective_credit_usage(recv: u64, read: u64) -> u64 {
    if recv > read {
        return recv;
    }
    return read;
}

// Computes flow control window renewal trigger threshold (RFC 9000 §4.2).
inline fn calc_window_renewal_threshold(window_size: u64) -> u64 {
    return window_size >> 1;
}

// Safely advances consumed byte counter with arithmetic wrap protection (RFC 9000 §4.1).
inline fn calc_safe_accumulate_bytes(current: u64, delta: u64) -> u64 {
    let next = current + delta;
    if next < current {
        return current;
    }
    return next;
}

// Flow control state for connection-level limits (RFC 9000 §4.1).
struct QuicFlowControl {
    // Egress (remote limit advertised by peer via MAX_DATA)
    max_data_remote:  u64  = 0,
    bytes_sent_total: u64  = 0,
    is_data_blocked:  bool = false,

    // Ingress (local limit advertised to peer via MAX_DATA)
    max_data_local:           u64 = 0,
    bytes_recv_total:         u64 = 0,
    bytes_read_total:         u64 = 0,
    local_window_size:        u64 = 65536,
    last_advertised_max_data: u64 = 0,
}

fn new_quic_flow_control(initial_max_data_remote: u64, local_window: u64) -> QuicFlowControl {
    return QuicFlowControl {
        max_data_remote:          initial_max_data_remote,
        bytes_sent_total:         0,
        is_data_blocked:          false,
        max_data_local:           local_window,
        bytes_recv_total:         0,
        bytes_read_total:         0,
        local_window_size:        local_window,
        last_advertised_max_data: local_window,
    };
}

// Returns remaining connection egress credit.
fn quic_fc_remaining_conn_credit(fc: const QuicFlowControl&) -> u64 {
    return calc_unspent_credit(fc.max_data_remote, fc.bytes_sent_total);
}

// Returns remaining stream egress credit.
fn quic_fc_remaining_stream_credit(s: const QuicStream&) -> u64 {
    return calc_unspent_credit(s.send_max_data, s.bytes_sent);
}

// Evaluates whether sending (offset + len) is permitted by both connection and stream limits.
// Returns (can_send: bool, blocked_on_stream: bool, blocked_on_conn: bool).
fn quic_fc_can_send(
    fc:     const QuicFlowControl&,
    s:      const QuicStream&,
    offset: u64,
    len:    u64,
) -> bool, bool, bool {
    guard quic_valid_offset_len(offset, len) else {
        return false, true, true;
    }
    let end_offset = offset + len;

    // Check stream-level flow control
    let stream_ok = end_offset <= s.send_max_data;

    // Check connection-level flow control
    var additional_conn_bytes: u64 = 0;
    if end_offset > s.bytes_sent {
        additional_conn_bytes = end_offset - s.bytes_sent;
    }
    let projected_conn_total = fc.bytes_sent_total + additional_conn_bytes;
    let conn_ok = projected_conn_total <= fc.max_data_remote;

    let can_send = stream_ok && conn_ok;
    let blocked_stream = !stream_ok;
    let blocked_conn = !conn_ok;
    return can_send, blocked_stream, blocked_conn;
}

// Records egress data sent on a stream and updates cumulative connection send count.
// Sets is_data_blocked if connection limit is reached.
fn quic_fc_record_send(
    fc:     QuicFlowControl&,
    s:      QuicStream&,
    offset: u64,
    len:    u64,
) -> bool {
    guard quic_valid_offset_len(offset, len) else {
        return false;
    }
    let end_offset = offset + len;
    guard end_offset <= s.send_max_data else {
        return false;
    }

    var additional_conn_bytes: u64 = 0;
    if end_offset > s.bytes_sent {
        additional_conn_bytes = end_offset - s.bytes_sent;
    }
    let projected_conn_total = fc.bytes_sent_total + additional_conn_bytes;
    guard projected_conn_total <= fc.max_data_remote else {
        fc.is_data_blocked = true;
        return false;
    }

    if end_offset > s.bytes_sent {
        s.bytes_sent = end_offset;
        fc.bytes_sent_total = projected_conn_total;
    }

    fc.is_data_blocked = (fc.bytes_sent_total >= fc.max_data_remote);
    return true;
}

// Records ingress STREAM frame data and validates against flow control limits.
// Returns (ok: bool, err_code: u64). On violation, returns (false, QUIC_ERR_FLOW_CONTROL).
fn quic_fc_record_recv_stream(
    fc:     QuicFlowControl&,
    s:      QuicStream&,
    offset: u64,
    len:    u64,
) -> bool, u64 {
    // RFC 9000 §4.1, §4.5, §19.8: Enforce 62-bit VarInt ceiling and arithmetic wrap prevention
    guard quic_valid_offset_len(offset, len) else {
        return false, rfc::QUIC_ERR_FLOW_CONTROL;
    }
    let end_offset = offset + len;

    // RFC 9000 §4.1: Stream-level flow control check
    guard end_offset <= s.recv_max_data else {
        return false, rfc::QUIC_ERR_FLOW_CONTROL;
    }

    // RFC 9000 §4.1: Connection-level flow control check
    var additional_bytes: u64 = 0;
    if end_offset > s.bytes_recv {
        additional_bytes = end_offset - s.bytes_recv;
    }
    let projected_conn_recv = fc.bytes_recv_total + additional_bytes;
    guard projected_conn_recv <= fc.max_data_local else {
        return false, rfc::QUIC_ERR_FLOW_CONTROL;
    }

    if end_offset > s.bytes_recv {
        s.bytes_recv = end_offset;
        fc.bytes_recv_total = projected_conn_recv;
    }

    return true, rfc::QUIC_ERR_NO_ERROR;
}

// Accounts for newly committed bytes when receiving RESET_STREAM (RFC 9000 §4.5).
// Final size counts toward connection flow control and cannot exceed 2^62 - 1.
// Returns (ok: bool, err_code: u64).
fn quic_fc_record_recv_reset(
    fc:         QuicFlowControl&,
    s:          QuicStream&,
    final_size: u64,
) -> bool, u64 {
    // RFC 9000 §4.5: Final size cannot exceed 2^62 - 1 or the advertised stream limit
    guard final_size <= rfc::QUIC_VARINT_MAX && final_size <= s.recv_max_data else {
        return false, rfc::QUIC_ERR_FLOW_CONTROL;
    }

    var additional_bytes: u64 = 0;
    if final_size > s.bytes_recv {
        additional_bytes = final_size - s.bytes_recv;
    }
    let projected_conn_recv = fc.bytes_recv_total + additional_bytes;
    guard projected_conn_recv <= fc.max_data_local else {
        return false, rfc::QUIC_ERR_FLOW_CONTROL;
    }

    if final_size > s.bytes_recv {
        s.bytes_recv = final_size;
        fc.bytes_recv_total = projected_conn_recv;
    }

    return true, rfc::QUIC_ERR_NO_ERROR;
}

// Records bytes consumed by application, advancing read markers with wrap protection.
fn quic_fc_on_app_read(
    fc:         QuicFlowControl&,
    s:          QuicStream&,
    bytes_read: u64,
) {
    s.recv_consumed = calc_safe_accumulate_bytes(s.recv_consumed, bytes_read);
    fc.bytes_read_total = calc_safe_accumulate_bytes(fc.bytes_read_total, bytes_read);
}

// Handles incoming MAX_DATA frame (RFC 9000 §4.2, §19.9). Monotonic updates only up to 2^62 - 1.
// Returns true if remote limit increased.
fn quic_fc_update_remote_max_data(fc: QuicFlowControl&, new_limit: u64) -> bool {
    guard new_limit <= rfc::QUIC_VARINT_MAX && new_limit > fc.max_data_remote else {
        return false;
    }
    fc.max_data_remote = new_limit;
    fc.is_data_blocked = false;
    return true;
}

// Handles incoming MAX_STREAM_DATA frame (RFC 9000 §4.2, §19.10). Monotonic updates only up to 2^62 - 1.
// Returns true if stream send limit increased.
fn quic_fc_update_stream_send_max_data(s: QuicStream&, new_limit: u64) -> bool {
    guard new_limit <= rfc::QUIC_VARINT_MAX && new_limit > s.send_max_data else {
        return false;
    }
    s.send_max_data = new_limit;
    return true;
}

// Evaluates whether a connection-level MAX_DATA frame should be sent (RFC 9000 §4.2).
// Triggers when available credit falls below half the configured window.
// Credit is evaluated against effective consumed/received bytes (RFC 9000 §4.1).
// Returns (should_send: bool, new_max_data: u64).
fn quic_fc_check_conn_window_update(fc: QuicFlowControl&) -> bool, u64 {
    let consumed = calc_effective_credit_usage(fc.bytes_recv_total, fc.bytes_read_total);
    let available = calc_unspent_credit(fc.max_data_local, consumed);
    let threshold = calc_window_renewal_threshold(fc.local_window_size);

    guard available < threshold else {
        return false, 0;
    }

    let candidate_max = calc_advertised_window_candidate(consumed, fc.local_window_size);
    guard candidate_max > fc.last_advertised_max_data else {
        return false, 0;
    }

    fc.max_data_local = candidate_max;
    fc.last_advertised_max_data = candidate_max;
    return true, candidate_max;
}

// Evaluates whether a stream-level MAX_STREAM_DATA frame should be sent (RFC 9000 §4.2).
// Triggers when available stream credit falls below half the stream window size.
// Credit is evaluated against effective consumed/received bytes (RFC 9000 §4.1).
// Returns (should_send: bool, new_max_stream_data: u64).
fn quic_fc_check_stream_window_update(s: QuicStream&, stream_window_size: u64) -> bool, u64 {
    let consumed = calc_effective_credit_usage(s.bytes_recv, s.recv_consumed);
    let available = calc_unspent_credit(s.recv_max_data, consumed);
    let threshold = calc_window_renewal_threshold(stream_window_size);

    guard available < threshold else {
        return false, 0;
    }

    let candidate_max = calc_advertised_window_candidate(consumed, stream_window_size);
    guard candidate_max > s.recv_max_data else {
        return false, 0;
    }

    s.recv_max_data = candidate_max;
    return true, candidate_max;
}
