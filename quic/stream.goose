// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// QUIC Stream State Machine & Flow Control Invariants (RFC 9000 Section 3 & 4).
// Implements Sending and Receiving stream state machines, final size enforcement,
// stream directionality / role validation, and zero-allocation stream table.
namespace quic;

import std;
import core;
import .packet;
import .frames_internal;
import .internal;

enum QuicRole {
    Client,
    Server,
}

// ---- Stream Directionality & Classification (RFC 9000 Section 2.1) -------

enum QuicStreamType {
    ClientBidi, // 0b00: 0, 4, 8...
    ServerBidi, // 0b01: 1, 5, 9...
    ClientUni,  // 0b10: 2, 6, 10...
    ServerUni,  // 0b11: 3, 7, 11...
}

// ---- Sending & Receiving Stream States (RFC 9000 Section 3) --------------

enum QuicSendState {
    Ready,      // Opened, can send STREAM or STREAM_DATA_BLOCKED
    Send,       // STREAM frames sent, stream still open
    DataSent,   // STREAM frame with FIN sent
    DataRecvd,  // All stream data (and FIN) acknowledged by peer [Terminal]
    ResetSent,  // RESET_STREAM sent to peer
    ResetRecvd, // RESET_STREAM acknowledged by peer [Terminal]
}

enum QuicRecvState {
    Receive,    // Waiting for or receiving STREAM data
    SizeKnown,  // STREAM with FIN received, waiting for remaining fragments
    DataRecvd,  // All data up to final size received
    DataRead,   // Application read all stream data [Terminal]
    ResetRecvd, // RESET_STREAM received from peer
    ResetRead,  // Application notified of stream reset [Terminal]
}

// Unified QUIC Stream State Model
struct QuicStream {
    stream_id:   u64            = 0,
    stream_type: QuicStreamType = QuicStreamType.ClientBidi,
    send_state:  QuicSendState  = QuicSendState.Ready,
    recv_state:  QuicRecvState  = QuicRecvState.Receive,
    can_recv:    bool           = true,

    // Flow control & Send progress
    bytes_sent:          u64  = 0,
    send_final_size:     u64  = 0,
    has_send_final_size: bool = false,
    send_max_data:       u64  = 65536,
    send_error_code:     u64  = 0,

    // Flow control & Recv progress
    bytes_recv:            u64            = 0,
    recv_consumed:         u64            = 0,
    recv_final_size:       u64            = 0,
    has_recv_final_size:   bool           = false,
    contiguous_recv_bytes: u64            = 0,
    recv_max_data:         u64            = 65536,
    recv_error_code:       u64            = 0,
    recv_ranges:           Interval[..64] = [],

    // STOP_SENDING signaling
    stop_sending_sent: bool = false,
    stop_sending_recv: bool = false,
}

fn new_stream(stream_id: u64, max_recv_flow: u64 = 65536) -> QuicStream {
    let stype = quic_internal::quic_stream_type(stream_id);
    return QuicStream {
        stream_id:     stream_id,
        stream_type:   stype,
        recv_max_data: max_recv_flow,
    };
}

// ---- Sending Stream State Machine (RFC 9000 Section 3.1) -----------------

// Records transmission of stream data and updates sender state.
// Returns `(err_code, ok)`.
fn on_send_data(
    s:      QuicStream&,
    offset: u64,
    len:    u64,
    fin:    bool,
) -> u64, bool {
    guard s.send_state == QuicSendState.Ready || s.send_state == QuicSendState.Send else {
        return rfc::QUIC_ERR_STREAM_STATE, false;
    }
    guard quic_internal::quic_valid_offset_len(offset, len) else {
        return rfc::QUIC_ERR_FLOW_CONTROL, false;
    }
    guard quic_internal::is_within_limit(offset, len, s.send_max_data) else {
        return rfc::QUIC_ERR_FLOW_CONTROL, false;
    }

    let end_offset = offset + len;
    if fin {
        guard end_offset >= s.bytes_sent else {
            return rfc::QUIC_ERR_FINAL_SIZE, false;
        }
        if s.has_send_final_size {
            guard end_offset == s.send_final_size else {
                return rfc::QUIC_ERR_FINAL_SIZE, false;
            }
        }
        s.has_send_final_size = true;
        s.send_final_size = end_offset;
        s.send_state = QuicSendState.DataSent;
    } else if s.send_state == QuicSendState.Ready {
        s.send_state = QuicSendState.Send;
    }

    s.bytes_sent = core::ct_max_u64(s.bytes_sent, end_offset);
    return rfc::QUIC_ERR_NO_ERROR, true;
}

// Initiates stream reset on sender side (RFC 9000 Section 3.1).
// Returns `(err_code, ok)`.
fn on_send_reset(
    s:          QuicStream&,
    error_code: u64,
    final_size: u64,
) -> u64, bool {
    let ok_state = s.send_state == QuicSendState.Ready ||
                   s.send_state == QuicSendState.Send ||
                   s.send_state == QuicSendState.DataSent;
    guard ok_state else { return rfc::QUIC_ERR_STREAM_STATE, false; }
    guard final_size <= rfc::QUIC_VARINT_MAX else { return rfc::QUIC_ERR_FINAL_SIZE, false; }
    guard final_size >= s.bytes_sent else { return rfc::QUIC_ERR_FINAL_SIZE, false; }

    if s.has_send_final_size {
        guard s.send_final_size == final_size else { return rfc::QUIC_ERR_FINAL_SIZE, false; }
    }

    s.send_state = QuicSendState.ResetSent;
    s.send_error_code = error_code;
    s.send_final_size = final_size;
    s.has_send_final_size = true;
    return rfc::QUIC_ERR_NO_ERROR, true;
}

// Handles acknowledgement of all sent data or RESET_STREAM frame.
fn on_send_ack(s: QuicStream&, all_data_acked: bool) -> bool {
    if s.send_state == QuicSendState.DataSent && all_data_acked {
        s.send_state = QuicSendState.DataRecvd;
        return true;
    }
    if s.send_state == QuicSendState.ResetSent {
        s.send_state = QuicSendState.ResetRecvd;
        return true;
    }
    return false;
}

// ---- Receiving Stream State Machine (RFC 9000 Section 3.2) ---------------

// Processes incoming STREAM frame fragments and enforces final size invariants.
// Returns `(err_code, ok)`.
fn on_recv_stream_frame(
    s:      QuicStream&,
    offset: u64,
    len:    u64,
    fin:    bool,
) -> u64, bool {
    guard quic_internal::quic_valid_offset_len(offset, len) else { return rfc::QUIC_ERR_FLOW_CONTROL, false; }
    let end_offset = offset + len;

    // RFC 9000 §4.5: Data exceeding established final size MUST trigger FINAL_SIZE_ERROR
    if s.has_recv_final_size {
        guard end_offset <= s.recv_final_size else { return rfc::QUIC_ERR_FINAL_SIZE, false; }
        if fin {
            guard end_offset == s.recv_final_size else { return rfc::QUIC_ERR_FINAL_SIZE, false; }
        }
    }

    // Duplicate frames within final size on closed streams are ignored
    if s.recv_state == QuicRecvState.ResetRecvd || s.recv_state == QuicRecvState.ResetRead {
        return rfc::QUIC_ERR_NO_ERROR, true;
    }
    if s.recv_state == QuicRecvState.DataRecvd || s.recv_state == QuicRecvState.DataRead {
        return rfc::QUIC_ERR_NO_ERROR, true;
    }

    guard quic_internal::is_within_limit(offset, len, s.recv_max_data) else {
        return rfc::QUIC_ERR_FLOW_CONTROL, false;
    }

    if fin && !s.has_recv_final_size {
        let valid_fs = quic_internal::validate_recv_final_size(false, 0, end_offset, s.bytes_recv, s.recv_consumed);
        guard valid_fs else { return rfc::QUIC_ERR_FINAL_SIZE, false; }
    }

    if len > 0 {
        guard quic_internal::record_stream_recv_range(s, offset, end_offset) else {
            return rfc::QUIC_ERR_FLOW_CONTROL, false;
        }
    }

    if fin && !s.has_recv_final_size {
        s.has_recv_final_size = true;
        s.recv_final_size = end_offset;
        s.recv_state = QuicRecvState.SizeKnown;
    }

    s.bytes_recv = core::ct_max_u64(s.bytes_recv, end_offset);

    if s.has_recv_final_size && s.contiguous_recv_bytes == s.recv_final_size {
        s.recv_state = QuicRecvState.DataRecvd;
    }

    return rfc::QUIC_ERR_NO_ERROR, true;
}

// Processes an incoming RESET_STREAM frame from peer (RFC 9000 Section 3.2).
// Returns `(err_code, ok)`.
fn on_recv_reset(
    s:          QuicStream&,
    error_code: u64,
    final_size: u64,
) -> u64, bool {
    guard final_size <= rfc::QUIC_VARINT_MAX else { return rfc::QUIC_ERR_FINAL_SIZE, false; }
    guard final_size <= s.recv_max_data else { return rfc::QUIC_ERR_FLOW_CONTROL, false; }

    let valid_fs = quic_internal::validate_recv_final_size(
        s.has_recv_final_size,
        s.recv_final_size,
        final_size,
        s.bytes_recv,
        s.recv_consumed,
    );
    guard valid_fs else { return rfc::QUIC_ERR_FINAL_SIZE, false; }

    let is_terminal = s.recv_state == QuicRecvState.DataRecvd
        || s.recv_state == QuicRecvState.DataRead
        || s.recv_state == QuicRecvState.ResetRecvd
        || s.recv_state == QuicRecvState.ResetRead;
    if is_terminal {
        return rfc::QUIC_ERR_NO_ERROR, true;
    }

    s.recv_state = QuicRecvState.ResetRecvd;
    s.recv_error_code = error_code;
    s.recv_final_size = final_size;
    s.has_recv_final_size = true;
    return rfc::QUIC_ERR_NO_ERROR, true;
}

// Processes an incoming STOP_SENDING frame from peer (RFC 9000 Section 3.5 & 19.5).
// Returns `(err_code, ok)`.
fn on_recv_stop_sending(
    s:          QuicStream&,
    error_code: u64,
    role:       QuicRole,
) -> u64, bool {
    // STOP_SENDING cannot be received on a stream where endpoint cannot send (RFC 9000 Section 19.5)
    guard quic_internal::quic_stream_can_send(s.stream_id, role) else {
        return rfc::QUIC_ERR_STREAM_STATE, false;
    }

    s.stop_sending_recv = true;

    // Transition sending side to ResetSent if active
    let is_active = s.send_state == QuicSendState.Ready ||
        s.send_state == QuicSendState.Send ||
        s.send_state == QuicSendState.DataSent;
    if is_active {
        s.send_state = QuicSendState.ResetSent;
        s.send_error_code = error_code;
        s.has_send_final_size = true;
        s.send_final_size = s.bytes_sent;
    }

    return rfc::QUIC_ERR_NO_ERROR, true;
}

// Consumes contiguous stream bytes by application, advancing to DataRead terminal state.
fn on_app_read(s: QuicStream&, bytes: u64) -> bool {
    guard 0xFFFFFFFFFFFFFFFF - s.recv_consumed >= bytes else { return false; }
    guard s.recv_consumed + bytes <= s.contiguous_recv_bytes else { return false; }
    s.recv_consumed = s.recv_consumed + bytes;
    if s.recv_state == QuicRecvState.DataRecvd && s.recv_consumed >= s.recv_final_size {
        s.recv_state = QuicRecvState.DataRead;
        return true;
    }
    return false;
}

// Notifies application of stream reset, advancing to ResetRead terminal state.
fn on_app_read_reset(s: QuicStream&) -> bool {
    if s.recv_state == QuicRecvState.ResetRecvd {
        s.recv_state = QuicRecvState.ResetRead;
        return true;
    }
    return false;
}

// ---- Terminal State Evaluation ------------------------------------------

inline fn is_send_closed(s: const QuicStream&) -> bool {
    return s.send_state == QuicSendState.DataRecvd || s.send_state == QuicSendState.ResetRecvd;
}

inline fn is_recv_closed(s: const QuicStream&) -> bool {
    return s.recv_state == QuicRecvState.DataRead || s.recv_state == QuicRecvState.ResetRead;
}

// Returns true if the stream has reached terminal state in all applicable directions.
fn is_terminal(s: const QuicStream&, role: QuicRole) -> bool {
    let can_tx = quic_internal::quic_stream_can_send(s.stream_id, role);
    let can_rx = quic_internal::quic_stream_can_recv(s.stream_id, role);

    if can_tx && !is_send_closed(s) {
        return false;
    }
    if can_rx && !is_recv_closed(s) {
        return false;
    }
    return true;
}

// ---- Zero-Allocation Stream Table ----------------------------------------

struct QuicStreamTable {
    streams:                     QuicStream[..128] = [],
    evicted_closed_ids:          u64[..64]         = [],
    retired_contiguous_ord:      u64[4]            = [0; 4],
    max_streams_bidi:            u64               = 100,
    max_streams_uni:             u64               = 100,
    remote_max_streams_bidi:     u64               = 0,
    remote_max_streams_uni:      u64               = 0,
    has_remote_max_streams_bidi: bool              = false,
    has_remote_max_streams_uni:  bool              = false,
    next_local_bidi_id:          u64               = 0,
    next_local_uni_id:           u64               = 0,
    role:                        QuicRole          = QuicRole.Server,
}

fn new_stream_table(role: QuicRole) -> QuicStreamTable {
    let init_bidi: u64 = if role == QuicRole.Client { 0 } else { 1 };
    let init_uni:  u64 = if role == QuicRole.Client { 2 } else { 3 };
    return QuicStreamTable {
        role:               role,
        next_local_bidi_id: init_bidi,
        next_local_uni_id:  init_uni,
    };
}

// Looks up stream index in table by stream_id, returning `(index, found)`.
fn find_stream(tbl: const QuicStreamTable&, stream_id: u64) -> i32, bool {
    for &s, i in tbl.streams {
        if s.stream_id == stream_id {
            return i as i32, true;
        }
    }
    return 0, false;
}

// Returns true if `stream_id` was previously closed in a terminal state and evicted from `tbl.streams`.
fn is_evicted_closed_stream(tbl: const QuicStreamTable&, stream_id: u64) -> bool {
    let stype = (stream_id & 3) as i64;
    if (stream_id >> 2) < tbl.retired_contiguous_ord[stype] {
        return true;
    }
    for i in tbl.evicted_closed_ids.len {
        if tbl.evicted_closed_ids[i] == stream_id {
            return true;
        }
    }
    return false;
}

// Looks up existing stream or inserts new stream.
// Enforces MAX_STREAMS limits for peer-initiated streams (RFC 9000 Section 4.6).
// Returns `(stream_index, ok)`.
fn get_or_open_stream(
    tbl:               QuicStreamTable&,
    stream_id:         u64,
    default_recv_flow: u64 = 65536,
) -> i32, bool {
    let existing, found = find_stream(tbl, stream_id);
    if found {
        return existing, true;
    }
    guard !is_evicted_closed_stream(tbl, stream_id) else {
        return 0, false;
    }
    // RFC 9000 §3.1: Ingress frames cannot open uncreated locally-initiated streams
    guard quic_internal::is_peer_initiated_stream(stream_id, tbl.role) else {
        return 0, false;
    }
    guard quic_internal::validate_peer_stream_limit(tbl, stream_id) else {
        return 0, false;
    }
    if tbl.streams.len < tbl.streams.cap {
        let new_idx = quic_internal::quic_table_insert_stream(tbl, stream_id, default_recv_flow);
        return new_idx, true;
    }
    for &slot, i in tbl.streams {
        if is_terminal(slot, tbl.role) {
            quic_internal::record_evicted_closed_stream(tbl, slot.stream_id);
            slot = quic_internal::new_quic_role_stream(stream_id, tbl.role, default_recv_flow);
            return i as i32, true;
        }
    }
    return 0, false;
}

// Opens next local stream ID, advancing stream counter.
fn open_local_stream(
    tbl:               QuicStreamTable&,
    is_bidi:           bool,
    default_recv_flow: u64 = 65536,
) -> u64, i32, bool {
    let next_id = if is_bidi { tbl.next_local_bidi_id } else { tbl.next_local_uni_id };
    let limit = if is_bidi {
        if tbl.has_remote_max_streams_bidi { tbl.remote_max_streams_bidi } else { tbl.max_streams_bidi }
    } else {
        if tbl.has_remote_max_streams_uni { tbl.remote_max_streams_uni } else { tbl.max_streams_uni }
    };
    guard next_id <= rfc::QUIC_VARINT_MAX && (next_id >> 2) < limit else {
        return 0, 0, false;
    }
    if tbl.streams.len < tbl.streams.cap {
        let stream_id = quic_internal::advance_stream_counter(tbl, is_bidi);
        let new_idx = quic_internal::quic_table_insert_stream(tbl, stream_id, default_recv_flow);
        return stream_id, new_idx, true;
    }
    for &slot, i in tbl.streams {
        if is_terminal(slot, tbl.role) {
            quic_internal::record_evicted_closed_stream(tbl, slot.stream_id);
            let stream_id = quic_internal::advance_stream_counter(tbl, is_bidi);
            slot = quic_internal::new_quic_role_stream(stream_id, tbl.role, default_recv_flow);
            return stream_id, i as i32, true;
        }
    }
    return 0, 0, false;
}
