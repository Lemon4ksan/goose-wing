// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// QUIC Stream State Machine & Flow Control Invariants (RFC 9000 Section 3 & 4).
// Implements Sending and Receiving stream state machines, final size enforcement,
// stream directionality / role validation, and zero-allocation stream table.
namespace internal;

import std;
import core from "..";
import .packet;
import .frames;
import .connection;

// ---- Stream Directionality & Classification (RFC 9000 Section 2.1) -------

enum QuicStreamType {
    ClientBidi, // 0b00: 0, 4, 8...
    ServerBidi, // 0b01: 1, 5, 9...
    ClientUni,  // 0b10: 2, 6, 10...
    ServerUni,  // 0b11: 3, 7, 11...
}

inline fn quic_stream_type(id: u64) -> QuicStreamType {
    let t = id & 0x03;
    if t == 0 { return QuicStreamType.ClientBidi; }
    if t == 1 { return QuicStreamType.ServerBidi; }
    if t == 2 { return QuicStreamType.ClientUni; }
    return QuicStreamType.ServerUni;
}

inline fn quic_stream_can_send(id: u64, role: QuicRole) -> bool {
    let t = id & 0x03;
    if t <= 1 { return true; } // Bidi: both endpoints can send
    if role == QuicRole.Client {
        return t == 2; // Client can only send on ClientUni
    }
    return t == 3; // Server can only send on ServerUni
}

inline fn quic_stream_can_recv(id: u64, role: QuicRole) -> bool {
    let t = id & 0x03;
    if t <= 1 { return true; } // Bidi: both endpoints can receive
    if role == QuicRole.Client {
        return t == 3; // Client can receive on ServerUni
    }
    return t == 2; // Server can receive on ClientUni
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
    recv_ranges:           Interval[..16] = [],

    // STOP_SENDING signaling
    stop_sending_sent: bool = false,
    stop_sending_recv: bool = false,
}

fn new_quic_stream(stream_id: u64, max_recv_flow: u64 = 65536) -> QuicStream {
    let stype = quic_stream_type(stream_id);
    return QuicStream {
        stream_id:     stream_id,
        stream_type:   stype,
        recv_max_data: max_recv_flow,
    };
}

// ---- Arithmetic Safety Subroutines ---------------------------------------

inline fn is_within_limit(offset: u64, len: u64, limit: u64) -> bool {
    if offset > limit { return false; }
    let rem = limit - offset;
    return rem >= len;
}

// ---- Sending Stream State Machine (RFC 9000 Section 3.1) -----------------

// Records transmission of stream data and updates sender state.
fn quic_stream_on_send_data(
    s:      QuicStream&,
    offset: u64,
    len:    u64,
    fin:    bool,
) -> bool, u64 {
    guard s.send_state == QuicSendState.Ready || s.send_state == QuicSendState.Send else {
        return false, rfc::QUIC_ERR_STREAM_STATE;
    }
    guard is_within_limit(offset, len, s.send_max_data) else {
        return false, rfc::QUIC_ERR_FLOW_CONTROL;
    }

    let end_offset = offset + len;
    s.bytes_sent = core::ct_max_u64(s.bytes_sent, end_offset);

    if fin {
        s.has_send_final_size = true;
        s.send_final_size = end_offset;
        s.send_state = QuicSendState.DataSent;
    } else if s.send_state == QuicSendState.Ready {
        s.send_state = QuicSendState.Send;
    }

    return true, rfc::QUIC_ERR_NO_ERROR;
}

// Initiates stream reset on sender side (RFC 9000 Section 3.1).
fn quic_stream_on_send_reset(
    s:          QuicStream&,
    error_code: u64,
    final_size: u64,
) -> bool, u64 {
    let ok_state = s.send_state == QuicSendState.Ready ||
                   s.send_state == QuicSendState.Send ||
                   s.send_state == QuicSendState.DataSent;
    guard ok_state else { return false, rfc::QUIC_ERR_STREAM_STATE; }
    guard final_size <= rfc::QUIC_VARINT_MAX else { return false, rfc::QUIC_ERR_FINAL_SIZE; }
    guard final_size >= s.bytes_sent else { return false, rfc::QUIC_ERR_FINAL_SIZE; }

    if s.has_send_final_size {
        guard s.send_final_size == final_size else { return false, rfc::QUIC_ERR_FINAL_SIZE; }
    }

    s.send_state = QuicSendState.ResetSent;
    s.send_error_code = error_code;
    s.send_final_size = final_size;
    s.has_send_final_size = true;
    return true, rfc::QUIC_ERR_NO_ERROR;
}

// Handles acknowledgement of all sent data or RESET_STREAM frame.
fn quic_stream_on_send_ack(s: QuicStream&, all_data_acked: bool) -> bool {
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

// Validates final size invariants upon receiving FIN or RESET_STREAM (RFC 9000 Section 4.5).
inline fn validate_recv_final_size(
    has_final:         bool,
    established_final: u64,
    new_final:         u64,
    bytes_recv:        u64,
    consumed:          u64,
) -> bool {
    if has_final {
        return established_final == new_final;
    }
    if new_final < bytes_recv { return false; }
    if new_final < consumed { return false; }
    return true;
}

inline fn record_stream_recv_range(s: QuicStream&, start: u64, end: u64) {
    guard start < end else { return; }
    var cur_s = start;
    var cur_e = end;
    var i: i64 = 0;
    while i < s.recv_ranges.len {
        let it = s.recv_ranges[i];
        if cur_e < it.start {
            guard s.recv_ranges.len < s.recv_ranges.cap else { break; }
            s.recv_ranges.insert_at(i, Interval { start: cur_s, end: cur_e });
            break;
        }
        if cur_s > it.end {
            i = i + 1;
            continue;
        }
        cur_s = if cur_s < it.start { cur_s } else { it.start };
        cur_e = if cur_e > it.end { cur_e } else { it.end };
        s.recv_ranges.remove_at(i);
    }
    if i == s.recv_ranges.len {
        guard s.recv_ranges.len < s.recv_ranges.cap else { return; }
        s.recv_ranges.push(Interval { start: cur_s, end: cur_e });
    }
    if s.recv_ranges.len > 0 && s.recv_ranges[0].start == 0 {
        s.contiguous_recv_bytes = s.recv_ranges[0].end;
    }
}

// Processes incoming STREAM frame fragments and enforces final size invariants.
fn quic_stream_on_recv_stream_frame(
    s:      QuicStream&,
    offset: u64,
    len:    u64,
    fin:    bool,
) -> bool, u64 {
    let end_offset = offset + len;

    // RFC 9000 §4.5: Data exceeding established final size MUST trigger FINAL_SIZE_ERROR
    if s.has_recv_final_size {
        guard end_offset <= s.recv_final_size else { return false, rfc::QUIC_ERR_FINAL_SIZE; }
        if fin {
            guard end_offset == s.recv_final_size else { return false, rfc::QUIC_ERR_FINAL_SIZE; }
        }
    }

    // Duplicate frames within final size on closed streams are ignored
    if s.recv_state == QuicRecvState.ResetRecvd || s.recv_state == QuicRecvState.ResetRead {
        return true, rfc::QUIC_ERR_NO_ERROR;
    }
    if s.recv_state == QuicRecvState.DataRecvd || s.recv_state == QuicRecvState.DataRead {
        return true, rfc::QUIC_ERR_NO_ERROR;
    }

    guard is_within_limit(offset, len, s.recv_max_data) else {
        return false, rfc::QUIC_ERR_FLOW_CONTROL;
    }

    if fin && !s.has_recv_final_size {
        let valid_fs = validate_recv_final_size(false, 0, end_offset, s.bytes_recv, s.recv_consumed);
        guard valid_fs else { return false, rfc::QUIC_ERR_FINAL_SIZE; }
        s.has_recv_final_size = true;
        s.recv_final_size = end_offset;
        s.recv_state = QuicRecvState.SizeKnown;
    }

    s.bytes_recv = core::ct_max_u64(s.bytes_recv, end_offset);
    if len > 0 {
        record_stream_recv_range(s, offset, end_offset);
    }

    if s.has_recv_final_size && s.contiguous_recv_bytes == s.recv_final_size {
        s.recv_state = QuicRecvState.DataRecvd;
    }

    return true, rfc::QUIC_ERR_NO_ERROR;
}

// Processes an incoming RESET_STREAM frame from peer (RFC 9000 Section 3.2).
fn quic_stream_on_recv_reset(
    s:          QuicStream&,
    error_code: u64,
    final_size: u64,
) -> bool, u64 {
    // RFC 9000 Section 3.2: RESET_STREAM on DataRecvd / DataRead is ignored
    if s.recv_state == QuicRecvState.DataRecvd || s.recv_state == QuicRecvState.DataRead {
        return true, rfc::QUIC_ERR_NO_ERROR;
    }
    // RFC 9000 Section 3.2: Receiving RESET_STREAM on terminal closed stream ResetRead MUST NOT reopen stream
    if s.recv_state == QuicRecvState.ResetRead {
        let valid_fs = validate_recv_final_size(
            s.has_recv_final_size,
            s.recv_final_size,
            final_size,
            s.bytes_recv,
            s.recv_consumed,
        );
        guard valid_fs else { return false, rfc::QUIC_ERR_FINAL_SIZE; }
        return true, rfc::QUIC_ERR_NO_ERROR;
    }
    guard final_size <= rfc::QUIC_VARINT_MAX else { return false, rfc::QUIC_ERR_FINAL_SIZE; }
    guard final_size <= s.recv_max_data else { return false, rfc::QUIC_ERR_FLOW_CONTROL; }

    let valid_fs = validate_recv_final_size(
        s.has_recv_final_size,
        s.recv_final_size,
        final_size,
        s.bytes_recv,
        s.recv_consumed,
    );
    guard valid_fs else { return false, rfc::QUIC_ERR_FINAL_SIZE; }

    s.recv_state = QuicRecvState.ResetRecvd;
    s.recv_error_code = error_code;
    s.recv_final_size = final_size;
    s.has_recv_final_size = true;
    return true, rfc::QUIC_ERR_NO_ERROR;
}

// Processes an incoming STOP_SENDING frame from peer (RFC 9000 Section 3.5 & 19.5).
fn quic_stream_on_recv_stop_sending(
    s:          QuicStream&,
    error_code: u64,
    role:       QuicRole,
) -> bool, u64 {
    // STOP_SENDING cannot be received on a stream where endpoint cannot send (RFC 9000 Section 19.5)
    guard quic_stream_can_send(s.stream_id, role) else {
        return false, rfc::QUIC_ERR_STREAM_STATE;
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

    return true, rfc::QUIC_ERR_NO_ERROR;
}

// Consumes contiguous stream bytes by application, advancing to DataRead terminal state.
fn quic_stream_on_app_read(s: QuicStream&, bytes: u64) -> bool {
    s.recv_consumed = s.recv_consumed + bytes;
    if s.recv_state == QuicRecvState.DataRecvd && s.recv_consumed >= s.recv_final_size {
        s.recv_state = QuicRecvState.DataRead;
        return true;
    }
    return false;
}

// Notifies application of stream reset, advancing to ResetRead terminal state.
fn quic_stream_on_app_read_reset(s: QuicStream&) -> bool {
    if s.recv_state == QuicRecvState.ResetRecvd {
        s.recv_state = QuicRecvState.ResetRead;
        return true;
    }
    return false;
}

// ---- Stream Flow Control Updates (RFC 9000 Section 4) --------------------

// Updates peer-advertised send window limit (MAX_STREAM_DATA cannot decrease).
inline fn quic_stream_update_send_max(s: QuicStream&, limit: u64) {
    if limit > s.send_max_data && limit <= rfc::QUIC_VARINT_MAX {
        s.send_max_data = limit;
    }
}

// Updates locally advertised recv window limit.
inline fn quic_stream_update_recv_max(s: QuicStream&, limit: u64) {
    if limit > s.recv_max_data && limit <= rfc::QUIC_VARINT_MAX {
        s.recv_max_data = limit;
    }
}

// ---- Terminal State Evaluation ------------------------------------------

inline fn quic_stream_is_send_closed(s: const QuicStream&) -> bool {
    return s.send_state == QuicSendState.DataRecvd || s.send_state == QuicSendState.ResetRecvd;
}

inline fn quic_stream_is_recv_closed(s: const QuicStream&) -> bool {
    return s.recv_state == QuicRecvState.DataRead || s.recv_state == QuicRecvState.ResetRead;
}

// Returns true if the stream has reached terminal state in all applicable directions.
fn quic_stream_is_terminal(s: const QuicStream&, role: QuicRole) -> bool {
    let can_tx = quic_stream_can_send(s.stream_id, role);
    let can_rx = quic_stream_can_recv(s.stream_id, role);

    if can_tx && !quic_stream_is_send_closed(s) {
        return false;
    }
    if can_rx && !quic_stream_is_recv_closed(s) {
        return false;
    }
    return true;
}

// ---- Zero-Allocation Stream Table ----------------------------------------

struct QuicStreamTable {
    streams:            QuicStream[..128] = [],
    max_streams_bidi:   u64               = 100,
    max_streams_uni:    u64               = 100,
    next_local_bidi_id: u64               = 0,
    next_local_uni_id:  u64               = 0,
    role:               QuicRole          = QuicRole.Server,
}

fn new_quic_stream_table(role: QuicRole) -> QuicStreamTable {
    let init_bidi: u64 = if role == QuicRole.Client { 0 } else { 1 };
    let init_uni:  u64 = if role == QuicRole.Client { 2 } else { 3 };
    return QuicStreamTable {
        role:               role,
        next_local_bidi_id: init_bidi,
        next_local_uni_id:  init_uni,
    };
}

// Looks up stream index in table by stream_id. Returns -1 if not found.
fn quic_table_find_stream(tbl: const QuicStreamTable&, stream_id: u64) -> i32 {
    for i in tbl.streams.len {
        if tbl.streams[i].stream_id == stream_id {
            return i as i32;
        }
    }
    return -1;
}

// Helper to append a stream into bounded stream table.
fn quic_table_push_stream(tbl: QuicStreamTable&, st: QuicStream) {
    tbl.streams.push(st);
}

// Helper to determine if a stream was initiated by peer (RFC 9000 §2.1).
inline fn is_peer_initiated_stream(stream_id: u64, role: QuicRole) -> bool {
    let init_bit = stream_id & 1;
    if role == QuicRole.Server {
        return init_bit == 0;
    }
    return init_bit == 1;
}

// Validates stream ordinal against configured peer stream limits (RFC 9000 Section 4.6).
inline fn validate_peer_stream_limit(tbl: const QuicStreamTable&, stream_id: u64) -> bool {
    guard is_peer_initiated_stream(stream_id, tbl.role) else { return true; }
    let stream_idx = stream_id >> 2;
    if (stream_id & 2) != 0 {
        return stream_idx < tbl.max_streams_uni;
    }
    return stream_idx < tbl.max_streams_bidi;
}

// Helper to check table capacity and peer stream limit before opening stream.
inline fn can_open_ingress_stream(tbl: const QuicStreamTable&, stream_id: u64) -> bool {
    guard tbl.streams.len < tbl.streams.cap else { return false; }
    return validate_peer_stream_limit(tbl, stream_id);
}

// Appends and initializes new stream into table.
inline fn quic_table_insert_stream(
    tbl:               QuicStreamTable&,
    stream_id:         u64,
    default_recv_flow: u64,
) -> i32 {
    let new_idx = tbl.streams.len as i32;
    let st = new_quic_stream(stream_id, default_recv_flow);
    quic_table_push_stream(tbl, st);
    return new_idx;
}

// Looks up existing stream or inserts new stream.
// Enforces MAX_STREAMS limits for peer-initiated streams (RFC 9000 Section 4.6).
// Returns (stream_index: i32, ok: bool).
fn quic_table_get_or_open_stream(
    tbl:               QuicStreamTable&,
    stream_id:         u64,
    default_recv_flow: u64 = 65536,
) -> i32, bool {
    let existing = quic_table_find_stream(tbl, stream_id);
    if existing >= 0 {
        return existing, true;
    }
    for i in tbl.streams.len {
        if quic_stream_is_terminal(tbl.streams[i], tbl.role) {
            guard validate_peer_stream_limit(tbl, stream_id) else { return 0, false; }
            tbl.streams[i] = new_quic_stream(stream_id, default_recv_flow);
            return i as i32, true;
        }
    }
    guard can_open_ingress_stream(tbl, stream_id) else {
        return 0, false;
    }
    let new_idx = quic_table_insert_stream(tbl, stream_id, default_recv_flow);
    return new_idx, true;
}

// Advances the local stream counter by 4 according to RFC 9000 stream ID rules.
inline fn advance_stream_counter(tbl: QuicStreamTable&, is_bidi: bool) -> u64 {
    if is_bidi {
        let sid = tbl.next_local_bidi_id;
        tbl.next_local_bidi_id = sid + 4;
        return sid;
    }
    let sid = tbl.next_local_uni_id;
    tbl.next_local_uni_id = sid + 4;
    return sid;
}

// Opens next local stream ID, advancing stream counter.
fn quic_table_open_local_stream(
    tbl:               QuicStreamTable&,
    is_bidi:           bool,
    default_recv_flow: u64 = 65536,
) -> u64, i32, bool {
    var has_slot = tbl.streams.len < tbl.streams.cap;
    if !has_slot {
        for s in tbl.streams {
            if quic_stream_is_terminal(s, tbl.role) {
                has_slot = true;
                break;
            }
        }
    }
    guard has_slot else {
        return 0, 0, false;
    }
    let stream_id = advance_stream_counter(tbl, is_bidi);
    let idx, ok = quic_table_get_or_open_stream(tbl, stream_id, default_recv_flow);
    return stream_id, idx, ok;
}
