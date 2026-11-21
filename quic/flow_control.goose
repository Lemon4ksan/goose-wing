// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic Flow Control Credit Management (RFC 9000 §4).
// Enforces connection-level and stream-level byte budgets,
// detects credit exhaustion, and generates window update thresholds.
namespace quic;

import std;
import core from "..";
import .frames_internal;
import .stream;
import .internal;

// Result of evaluating connection and stream flow-control egress credit.
struct FlowSendCheck {
    allowed:        bool = false,
    blocked_stream: bool = false,
    blocked_conn:   bool = false,
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

fn new_flow_control(initial_max_data_remote: u64, local_window: u64) -> QuicFlowControl {
    let eff_remote = min(initial_max_data_remote, rfc::QUIC_VARINT_MAX);
    let eff_local = min(local_window, rfc::QUIC_VARINT_MAX);
    return QuicFlowControl {
        max_data_remote:          eff_remote,
        bytes_sent_total:         0,
        is_data_blocked:          false,
        max_data_local:           eff_local,
        bytes_recv_total:         0,
        bytes_read_total:         0,
        local_window_size:        eff_local,
        last_advertised_max_data: eff_local,
    };
}

// Returns remaining connection egress credit.
fn remaining_conn_credit(fc: const QuicFlowControl&) -> u64 {
    return quic_internal::calc_unspent_credit(fc.max_data_remote, fc.bytes_sent_total);
}

// Returns remaining stream egress credit.
fn remaining_stream_credit(s: const QuicStream&) -> u64 {
    return quic_internal::calc_unspent_credit(s.send_max_data, s.bytes_sent);
}

// Evaluates whether sending (offset + len) is permitted by both connection and stream limits.
fn can_send(
    fc:     const QuicFlowControl&,
    s:      const QuicStream&,
    offset: u64,
    len:    u64,
) -> FlowSendCheck {
    guard quic_internal::quic_valid_offset_len(offset, len) else {
        return FlowSendCheck { allowed: false, blocked_stream: true, blocked_conn: true };
    }
    let end_offset = offset + len;

    // Check stream-level flow control
    let stream_ok = end_offset <= s.send_max_data;

    // Check connection-level flow control
    var additional_conn_bytes: u64 = 0;
    if end_offset > s.bytes_sent {
        additional_conn_bytes = end_offset - s.bytes_sent;
    }
    let projected_conn_total = core::add_sat_u64(fc.bytes_sent_total, additional_conn_bytes);
    let conn_ok = (0xFFFFFFFFFFFFFFFF - fc.bytes_sent_total >= additional_conn_bytes)
        && (projected_conn_total <= fc.max_data_remote);

    return FlowSendCheck {
        allowed:        stream_ok && conn_ok,
        blocked_stream: !stream_ok,
        blocked_conn:   !conn_ok,
    };
}

// Records egress data sent on a stream and updates cumulative connection send count.
// Sets is_data_blocked if connection limit is reached.
fn record_send(
    fc:     QuicFlowControl&,
    s:      QuicStream&,
    offset: u64,
    len:    u64,
) -> bool {
    guard quic_internal::quic_valid_offset_len(offset, len) else {
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
    guard 0xFFFFFFFFFFFFFFFF - fc.bytes_sent_total >= additional_conn_bytes else {
        fc.is_data_blocked = true;
        return false;
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
// Returns `(err_code, ok)`. On violation, returns `(QUIC_ERR_FLOW_CONTROL, false)`.
fn record_recv_stream(
    fc:     QuicFlowControl&,
    s:      QuicStream&,
    offset: u64,
    len:    u64,
) -> u64, bool {
    // RFC 9000 §4.1, §4.5, §19.8: Enforce 62-bit VarInt ceiling and arithmetic wrap prevention
    guard quic_internal::quic_valid_offset_len(offset, len) else {
        return rfc::QUIC_ERR_FLOW_CONTROL, false;
    }
    let end_offset = offset + len;

    // RFC 9000 §4.1: Stream-level flow control check
    guard end_offset <= s.recv_max_data else {
        return rfc::QUIC_ERR_FLOW_CONTROL, false;
    }

    // RFC 9000 §4.1: Connection-level flow control check
    var additional_bytes: u64 = 0;
    if end_offset > s.bytes_recv {
        additional_bytes = end_offset - s.bytes_recv;
    }
    guard 0xFFFFFFFFFFFFFFFF - fc.bytes_recv_total >= additional_bytes else {
        return rfc::QUIC_ERR_FLOW_CONTROL, false;
    }
    let projected_conn_recv = fc.bytes_recv_total + additional_bytes;
    guard projected_conn_recv <= fc.max_data_local else {
        return rfc::QUIC_ERR_FLOW_CONTROL, false;
    }

    if end_offset > s.bytes_recv {
        s.bytes_recv = end_offset;
        fc.bytes_recv_total = projected_conn_recv;
    }

    return rfc::QUIC_ERR_NO_ERROR, true;
}

// Accounts for newly committed bytes when receiving RESET_STREAM (RFC 9000 §4.5).
// Final size counts toward connection flow control and cannot exceed 2^62 - 1.
// Returns `(err_code, ok)`.
fn record_recv_reset(
    fc:         QuicFlowControl&,
    s:          QuicStream&,
    final_size: u64,
) -> u64, bool {
    // RFC 9000 §4.5: Final size cannot change once known or fall below received/consumed offsets
    if s.has_recv_final_size {
        guard final_size == s.recv_final_size else {
            return rfc::QUIC_ERR_FINAL_SIZE, false;
        }
    }
    guard final_size >= s.bytes_recv && final_size >= s.recv_consumed else {
        return rfc::QUIC_ERR_FINAL_SIZE, false;
    }
    // RFC 9000 §4.5: Final size cannot exceed 2^62 - 1 or the advertised stream limit
    guard final_size <= rfc::QUIC_VARINT_MAX && final_size <= s.recv_max_data else {
        return rfc::QUIC_ERR_FLOW_CONTROL, false;
    }

    let additional_bytes = final_size - s.bytes_recv;
    guard 0xFFFFFFFFFFFFFFFF - fc.bytes_recv_total >= additional_bytes else {
        return rfc::QUIC_ERR_FLOW_CONTROL, false;
    }
    let projected_conn_recv = fc.bytes_recv_total + additional_bytes;
    guard projected_conn_recv <= fc.max_data_local else {
        return rfc::QUIC_ERR_FLOW_CONTROL, false;
    }

    s.bytes_recv = final_size;
    fc.bytes_recv_total = projected_conn_recv;
    let unread_retired = core::sub_sat_u64(final_size, s.recv_consumed);
    s.recv_consumed = final_size;
    fc.bytes_read_total = quic_internal::calc_safe_accumulate_bytes(fc.bytes_read_total, unread_retired);
    s.has_recv_final_size = true;
    s.recv_final_size = final_size;
    return rfc::QUIC_ERR_NO_ERROR, true;
}

// Records bytes consumed by application, advancing read markers with wrap protection.
fn on_app_read(
    fc:         QuicFlowControl&,
    s:          QuicStream&,
    bytes_read: u64,
) {
    s.recv_consumed = quic_internal::calc_safe_accumulate_bytes(s.recv_consumed, bytes_read);
    fc.bytes_read_total = quic_internal::calc_safe_accumulate_bytes(fc.bytes_read_total, bytes_read);
}

// Handles incoming MAX_DATA frame (RFC 9000 §4.2, §19.9). Monotonic updates only up to 2^62 - 1.
// Returns true if remote limit increased.
fn update_remote_max_data(fc: QuicFlowControl&, new_limit: u64) -> bool {
    guard new_limit <= rfc::QUIC_VARINT_MAX && new_limit > fc.max_data_remote else {
        return false;
    }
    fc.max_data_remote = new_limit;
    fc.is_data_blocked = false;
    return true;
}

// Handles incoming MAX_STREAM_DATA frame (RFC 9000 §4.2, §19.10). Monotonic updates only up to 2^62 - 1.
// Returns true if stream send limit increased.
fn update_send_max_data(s: QuicStream&, new_limit: u64) -> bool {
    guard new_limit <= rfc::QUIC_VARINT_MAX && new_limit > s.send_max_data else {
        return false;
    }
    s.send_max_data = new_limit;
    return true;
}

// Evaluates whether a connection-level MAX_DATA frame should be sent (RFC 9000 §4.2).
// Triggers when available credit falls below half the configured window.
// Credit is evaluated against effective consumed/received bytes (RFC 9000 §4.1).
// Returns `(new_max_data, should_send)`.
fn check_conn_window_update(fc: QuicFlowControl&) -> u64, bool {
    let consumed = max(fc.bytes_recv_total, fc.bytes_read_total);
    let available = quic_internal::calc_unspent_credit(fc.max_data_local, consumed);
    let threshold = quic_internal::calc_window_renewal_threshold(fc.local_window_size);

    guard available < threshold else {
        return 0, false;
    }

    let candidate_max = quic_internal::calc_advertised_window_candidate(consumed, fc.local_window_size);
    guard candidate_max > fc.last_advertised_max_data else {
        return 0, false;
    }

    fc.max_data_local = candidate_max;
    fc.last_advertised_max_data = candidate_max;
    return candidate_max, true;
}

// Evaluates whether a stream-level MAX_STREAM_DATA frame should be sent (RFC 9000 §4.2).
// Triggers when available stream credit falls below half the stream window size.
// Credit is evaluated against effective consumed/received bytes (RFC 9000 §4.1).
// Returns `(new_max_stream_data, should_send)`.
fn check_stream_window_update(s: QuicStream&, stream_window_size: u64) -> u64, bool {
    // RFC 9000 Section 19.10: MAX_STREAM_DATA Frames - Only streams in the Recv state advertise receive credit.
    guard s.can_recv && s.recv_state == QuicRecvState.Receive && !s.has_recv_final_size else {
        return 0, false;
    }
    let consumed = max(s.bytes_recv, s.recv_consumed);
    let available = quic_internal::calc_unspent_credit(s.recv_max_data, consumed);
    let threshold = quic_internal::calc_window_renewal_threshold(stream_window_size);

    guard available < threshold else {
        return 0, false;
    }

    let candidate_max = quic_internal::calc_advertised_window_candidate(consumed, stream_window_size);
    guard candidate_max > s.recv_max_data else {
        return 0, false;
    }

    s.recv_max_data = candidate_max;
    return candidate_max, true;
}
