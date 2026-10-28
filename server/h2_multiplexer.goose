// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation HTTP/2 Server Frame Multiplexer (RFC 9113 & RFC 7541).
// Manages server connection sessions, stream demultiplexing, HPACK decoding/encoding,
// flow control updates, anti-DoS barriers, and dispatching to the Wing Server Pipeline.
namespace wing;

import std;
import core from "..";
import .router;
import .pool;
import .pipeline;

// ---- 1. Server Stream Descriptor --------------------------------------------

struct H2ServerStream {
    stream_id: u32 = 0,
    active: bool = false,
    headers_received: bool = false,
    body_received: bool = false,
    response_sent: bool = false,
    declared_content_length: i64 = -1,
    method: u8[..16] = [],
    path: u8[..2048] = [],
    scheme: u8[..16] = [],
    authority: u8[..128] = [],
    headers: HeaderItem[..32] = [],
    trailers: HeaderItem[..16] = [],
    body: u8[..8192] = [],
}

fn reset_server_stream(st: H2ServerStream&) {
    st.stream_id = 0;
    st.active = false;
    st.headers_received = false;
    st.body_received = false;
    st.response_sent = false;
    st.method.clear();
    st.path.clear();
    st.scheme.clear();
    st.authority.clear();
    st.headers.clear();
    st.trailers.clear();
    st.body.clear();
    st.declared_content_length = -1;
}

// ---- 2. Server Connection Session -------------------------------------------

struct H2ServerSession {
    conn: H2Connection = H2Connection { .. },
    hpack_enc: DynamicTable = DynamicTable { .. },
    streams: H2ServerStream[..16] = [],
    preface_handled: bool = false,
    server_settings_sent: bool = false,
    client_settings_acked: bool = false,
    pending_settings_ack: bool = false,
    server_name: u8[..64] = "goose-wing/1.0",
    header_accumulator: u8[..16384] = [],
    header_accum_stream_id: u32 = 0,
    header_accum_end_stream: bool = false,
    header_accum_is_trailer: bool = false,
}

fn flush_server_control_frames(sess: H2ServerSession&) {
    while sess.conn.pending_control_frames > 0 {
        ack_control_frame_flushed(sess.conn);
    }
}

fn new_h2_server_session(
    server_name_str: const u8[:] = "goose-wing/1.0",
    now_ms: u64 = 0,
) -> H2ServerSession {
    var sess = H2ServerSession {
        conn: new_h2_connection(now_ms),
        hpack_enc: new_dynamic_table(HPACK_DEFAULT_MAX_DYN_SIZE),
        preface_handled: false,
        server_settings_sent: false,
        client_settings_acked: false,
        pending_settings_ack: false,
        server_name: [],
        ..
    };
    sess.server_name.append(server_name_str);
    return sess;
}

// Finds an active server stream slot by stream_id
fn find_server_stream_idx(sess: const H2ServerSession&, stream_id: u32) -> i32, bool {
    for i in sess.streams.len {
        if sess.streams[i].active && sess.streams[i].stream_id == stream_id {
            return i as i32, true;
        }
    }
    return -1, false;
}

// Finds an active server stream slot or an empty slot for a new stream
fn find_or_alloc_stream(sess: H2ServerSession&, stream_id: u32) -> i32, bool {
    for i in sess.streams.len {
        if sess.streams[i].active && sess.streams[i].stream_id == stream_id {
            return i as i32, true;
        }
    }

    for i in sess.streams.len {
        if !sess.streams[i].active {
            reset_server_stream(sess.streams[i]);
            sess.streams[i].stream_id = stream_id;
            sess.streams[i].active = true;
            return i as i32, true;
        }
    }

    if sess.streams.len < sess.streams.cap {
        var new_st = H2ServerStream {
            stream_id: stream_id,
            active: true,
            ..
        };
        sess.streams.push(new_st);
        return (sess.streams.len - 1) as i32, true;
    }

    return -1, false;
}

// ---- 3. Protocol Frame Serialization Helpers --------------------------------

// Emits the server's initial SETTINGS frame (RFC 9113 Section 6.5)
fn emit_server_settings<B>(out: B&) {
    let hdr = FrameHeader {
        length: 24, // 4 settings * 6 bytes
        frame_type: FRAME_SETTINGS,
        flags: 0,
        stream_id: 0,
    };
    encode_frame_header_to(hdr, out);

    core::append_u16_be(out, SETTING_MAX_CONCURRENT_STREAMS);
    core::append_u32_be(out, 128);

    core::append_u16_be(out, SETTING_INITIAL_WINDOW_SIZE);
    core::append_u32_be(out, 65535);

    core::append_u16_be(out, SETTING_MAX_FRAME_SIZE);
    core::append_u32_be(out, 16384);

    core::append_u16_be(out, SETTING_ENABLE_CONNECT_PROTO);
    core::append_u32_be(out, 1);
}

// Emits a SETTINGS ACK frame
fn emit_settings_ack<B>(out: B&) {
    let hdr = FrameHeader {
        length: 0,
        frame_type: FRAME_SETTINGS,
        flags: FLAG_ACK,
        stream_id: 0,
    };
    encode_frame_header_to(hdr, out);
}

// Emits a PING ACK frame echoing the client's 8-byte opaque payload
fn emit_ping_ack<B>(opaque: const u8[8]&, out: B&) {
    let hdr = FrameHeader {
        length: 8,
        frame_type: FRAME_PING,
        flags: FLAG_ACK,
        stream_id: 0,
    };
    encode_frame_header_to(hdr, out);
    for b in opaque {
        out.push(b);
    }
}

// Emits a WINDOW_UPDATE frame
fn emit_window_update<B>(stream_id: u32, increment: u32, out: B&) {
    let hdr = FrameHeader {
        length: 4,
        frame_type: FRAME_WINDOW_UPDATE,
        flags: 0,
        stream_id: stream_id,
    };
    encode_frame_header_to(hdr, out);
    core::append_u32_be(out, increment & 0x7FFFFFFF);
}

// Emits a RST_STREAM frame
fn emit_rst_stream<B>(stream_id: u32, error_code: u32, out: B&) {
    let hdr = FrameHeader {
        length: 4,
        frame_type: FRAME_RST_STREAM,
        flags: 0,
        stream_id: stream_id,
    };
    encode_frame_header_to(hdr, out);
    core::append_u32_be(out, error_code);
}

// Emits a GOAWAY frame
fn emit_goaway<B>(last_stream_id: u32, error_code: u32, out: B&) {
    let hdr = FrameHeader {
        length: 8,
        frame_type: FRAME_GOAWAY,
        flags: 0,
        stream_id: 0,
    };
    encode_frame_header_to(hdr, out);
    core::append_u32_be(out, last_stream_id & 0x7FFFFFFF);
    core::append_u32_be(out, error_code);
}

// Encodes HTTP/2 Response HEADERS using HPACK
fn emit_response_headers<B>(
    sess: H2ServerSession&,
    stream_id: u32,
    res: const Response&,
    end_stream: bool,
    out: B&,
) {
    var hpack_block: u8[..16384] = [];

    var status_buf: u8[..16] = [];
    format(status_buf, res.status_code as i64);
    encode_hpack_field(sess.hpack_enc, hpack_block, ":status", status_buf[..], true, false);

    if sess.server_name.len > 0 {
        encode_hpack_field(sess.hpack_enc, hpack_block, "server", sess.server_name[..], true, false);
    }

    let is_grpc = starts_with_fold(res.header("content-type"), "application/grpc");
    if !is_grpc && res.status_code != 204 && res.status_code != 304 {
        var cl_buf: u8[..32] = [];
        format(cl_buf, res.body.len);
        encode_hpack_field(sess.hpack_enc, hpack_block, "content-length", cl_buf[..], true, false);
    }

    for &hdr in res.headers {
        let name_slice = hdr.name[..];
        let val_slice = hdr.value[..];
        // Skip connection hop-by-hop headers forbidden in HTTP/2 (RFC 9113 Section 8.2.2)
        if !eq_ascii_fold(name_slice, "connection") &&
           !eq_ascii_fold(name_slice, "keep-alive") &&
           !eq_ascii_fold(name_slice, "proxy-connection") &&
           !eq_ascii_fold(name_slice, "transfer-encoding") &&
           !eq_ascii_fold(name_slice, "upgrade") {
            // RFC 9113 Section 8.2.1: Field names MUST be lowercase
            var lower_name: u8[..64] = [];
            for c in name_slice {
                let lc = if c >= 'A' && c <= 'Z' { c + 32 } else { c };
                lower_name.push(lc);
            }
            encode_hpack_field(sess.hpack_enc, hpack_block, lower_name[..], val_slice, true, false);
        }
    }

    var flags: u8 = FLAG_END_HEADERS;
    if end_stream {
        flags |= FLAG_END_STREAM;
    }

    let frame_hdr = FrameHeader {
        length: hpack_block.len as u32,
        frame_type: FRAME_HEADERS,
        flags: flags,
        stream_id: stream_id,
    };
    encode_frame_header_to(frame_hdr, out);
    out.append(hpack_block[..]);
}

// Encodes HTTP/2 Response DATA chunks
fn emit_response_data<B>(
    stream_id: u32,
    body: const u8[:],
    max_frame_size: u32,
    out: B&,
    end_stream: bool = true,
) {
    guard body.len > 0 else { return; }

    var offset: i64 = 0;
    let limit = if max_frame_size >= 16384 { max_frame_size as i64 } else { 16384 };

    while offset < body.len {
        let rem = body.len - offset;
        let chunk_size = if rem < limit { rem } else { limit };
        let is_last = (offset + chunk_size >= body.len);

        let flags: u8 = if is_last && end_stream { FLAG_END_STREAM } else { 0 };
        let hdr = FrameHeader {
            length: chunk_size as u32,
            frame_type: FRAME_DATA,
            flags: flags,
            stream_id: stream_id,
        };
        encode_frame_header_to(hdr, out);
        out.append(body[offset..offset + chunk_size]);
        offset += chunk_size;
    }
}

// Encodes HTTP/2 Response Trailing HEADERS using HPACK
fn emit_response_trailers<B>(
    sess: H2ServerSession&,
    stream_id: u32,
    trailers: const HeaderItem[..16]&,
    out: B&,
) {
    guard trailers.len > 0 else { return; }
    var hpack_block: u8[..4096] = [];

    for &hdr in trailers {
        let name_slice = hdr.name[..];
        let val_slice = hdr.value[..];
        // RFC 9113 §8.1 / §8.2.2 & RFC 9110 §6.5.1: Trailers MUST NOT include pseudo-headers,
        // hop-by-hop connection headers, or disallowed framing/routing trailer fields.
        if name_slice.len > 0 && name_slice[0] != ':' &&
           !eq_ascii_fold(name_slice, "connection") &&
           !eq_ascii_fold(name_slice, "keep-alive") &&
           !eq_ascii_fold(name_slice, "proxy-connection") &&
           !eq_ascii_fold(name_slice, "transfer-encoding") &&
           !eq_ascii_fold(name_slice, "upgrade") &&
           !is_disallowed_trailer_field(name_slice) {
            var lower_name: u8[..64] = [];
            for c in name_slice {
                let lc = if c >= 'A' && c <= 'Z' { c + 32 } else { c };
                lower_name.push(lc);
            }
            encode_hpack_field(sess.hpack_enc, hpack_block, lower_name[..], val_slice, true, false);
        }
    }

    let flags: u8 = FLAG_END_HEADERS | FLAG_END_STREAM;
    let frame_hdr = FrameHeader {
        length: hpack_block.len as u32,
        frame_type: FRAME_HEADERS,
        flags: flags,
        stream_id: stream_id,
    };
    encode_frame_header_to(frame_hdr, out);
    out.append(hpack_block[..]);
}

fn apply_decoded_headers_to_stream(st: H2ServerStream&, dec_list: const DecodedH2HeaderList&) {
    for &entry in dec_list.fields {
        let n = entry.name[..];
        let v = entry.value[..];
        if n == ":method" {
            st.method.clear();
            if v.len <= st.method.cap {
                st.method.append(v);
            }
        } else if n == ":path" {
            st.path.clear();
            if v.len <= st.path.cap {
                st.path.append(v);
            }
        } else if n == ":scheme" {
            st.scheme.clear();
            if v.len <= st.scheme.cap {
                st.scheme.append(v);
            }
        } else if n == ":authority" {
            st.authority.clear();
            if v.len <= st.authority.cap {
                st.authority.append(v);
            }
        } else {
            if st.headers.len < st.headers.cap {
                st.headers.push(make_header(n, v));
            }
        }
    }
    st.headers_received = true;
}

fn apply_decoded_trailers_to_stream(st: H2ServerStream&, dec_list: const DecodedH2HeaderList&) {
    for &entry in dec_list.fields {
        let n = entry.name[..];
        let v = entry.value[..];
        if st.trailers.len < st.trailers.cap {
            st.trailers.push(make_header(n, v));
        }
    }
    st.body_received = true;
}

inline fn is_stream_cancelled_in_batch(cancelled: const u32[:], stream_id: u32) -> bool {
    return cancelled.contains(stream_id);
}

// ---- 4. Complete Ingress Frame Processing & Pipeline Dispatch ---------------

// Processes incoming HTTP/2 wire data, executing complete streams through the server pipeline.
// Returns (total_bytes_consumed, success)
fn handle_h2_server_ingress<B>(
    sess: H2ServerSession&,
    pipeline: ServerPipelineConfig&,
    timer: internal::ConnectionTimer&,
    client_ip: const u8[:],
    wire: const u8[:],
    now_ms: u64,
    out_wire: B&,
) -> i64, bool {
    var offset: i64 = 0;

    if !sess.preface_handled {
        if wire.len >= 24 && wire[..24] == H2_CLIENT_PREFACE[..] {
            sess.preface_handled = true;
            offset += 24;

            emit_server_settings(out_wire);
            sess.server_settings_sent = true;
            sess.pending_settings_ack = true;
        } else {
            return 0, false; // Missing or invalid preface
        }
    }

    // Pre-scan ingress batch for Rapid Reset cancellations (CVE-2023-44487).
    // If a stream in this batch is cancelled via RST_STREAM, we skip full H2ServerStream allocation
    // and route dispatch while still passing the header block through HPACK to keep table state in sync.
    var cancelled_streams: u32[..128] = [];
    var p_scan = offset;
    while p_scan + 9 <= wire.len {
        let sc_hdr, sc_err = parse_frame_header(wire[p_scan..p_scan + 9], sess.conn.local_max_frame_size);
        if sc_err != ERR_NO_ERROR {
            break;
        }
        let sc_tot = 9 + (sc_hdr.length as i64);
        if sc_hdr.frame_type == FRAME_RST_STREAM && sc_hdr.stream_id != 0 {
            if cancelled_streams.len < cancelled_streams.cap {
                cancelled_streams.push(sc_hdr.stream_id);
            }
        }
        p_scan += sc_tot;
    }

    while offset + 9 <= wire.len {
        let hdr, err_hdr = parse_frame_header(wire[offset..offset + 9], sess.conn.local_max_frame_size);
        guard err_hdr == ERR_NO_ERROR else {
            emit_goaway(sess.conn.last_peer_stream_id, err_hdr, out_wire);
            return offset, false;
        }

        let frame_payload_len = hdr.length as i64;
        let total_frame_len = 9 + frame_payload_len;
        guard offset + total_frame_len <= wire.len else {
            // Incomplete frame, wait for more data from socket
            break;
        }

        let frame_payload = wire[offset + 9..offset + total_frame_len];

        // RFC 9113 §6.10: Continuous header block boundaries
        if sess.header_accum_stream_id != 0 {
            if hdr.frame_type != FRAME_CONTINUATION || hdr.stream_id != sess.header_accum_stream_id {
                emit_goaway(sess.conn.last_peer_stream_id, ERR_PROTOCOL_ERROR, out_wire);
                return offset + total_frame_len, false;
            }
        } else if hdr.frame_type == FRAME_CONTINUATION {
            // Unprompted CONTINUATION frame received outside open header block
            emit_goaway(sess.conn.last_peer_stream_id, ERR_PROTOCOL_ERROR, out_wire);
            return offset + total_frame_len, false;
        }

        // Validate Anti-DoS barriers and protocol invariants
        let err = on_ingress_frame_header(sess.conn, hdr, now_ms);
        if err != ERR_NO_ERROR {
            if err == ERR_STREAM_CLOSED || err == ERR_REFUSED_STREAM {
                // RFC 9113 §5.1 & §5.4.2: Stream error must not terminate connection
                emit_rst_stream(hdr.stream_id, err, out_wire);
                offset += total_frame_len;
                continue;
            }
            emit_goaway(sess.conn.last_peer_stream_id, err, out_wire);
            return offset + total_frame_len, false;
        }

        // RFC 9113 §6.6: Servers MUST NOT receive PUSH_PROMISE frames
        if hdr.frame_type == FRAME_PUSH_PROMISE {
            emit_goaway(sess.conn.last_peer_stream_id, ERR_PROTOCOL_ERROR, out_wire);
            return offset + total_frame_len, false;
        }

        // Handle Frame Types
        if hdr.frame_type == FRAME_SETTINGS {
            if (hdr.flags & FLAG_ACK) != 0 {
                // RFC 9113 §6.5: SETTINGS with ACK and length != 0 MUST trigger FRAME_SIZE_ERROR
                if hdr.length != 0 {
                    emit_goaway(sess.conn.last_peer_stream_id, ERR_FRAME_SIZE_ERROR, out_wire);
                    return offset + total_frame_len, false;
                }
                // RFC 9113 §6.5 & §10.5: Reject unexpected or duplicate SETTINGS ACK
                if !sess.pending_settings_ack {
                    emit_goaway(sess.conn.last_peer_stream_id, ERR_PROTOCOL_ERROR, out_wire);
                    return offset + total_frame_len, false;
                }
                sess.pending_settings_ack = false;
                sess.client_settings_acked = true;
                ack_control_frame_flushed(sess.conn);
            } else {
                // Parse client settings (pairs of u16 identifier + u32 value)
                guard (frame_payload.len % 6) == 0 else {
                    emit_goaway(sess.conn.last_peer_stream_id, ERR_FRAME_SIZE_ERROR, out_wire);
                    return offset + total_frame_len, false;
                }
                var settings_r = core::new_slice_reader(frame_payload);
                while settings_r.remaining() >= 6 {
                    let param_id, _ = settings_r.read_u16_be();
                    let param_val, _ = settings_r.read_u32_be();

                    let val_err = validate_settings_parameter(param_id, param_val, false);
                    if val_err != ERR_NO_ERROR {
                        emit_goaway(sess.conn.last_peer_stream_id, val_err, out_wire);
                        return offset + total_frame_len, false;
                    }

                    if param_id == SETTING_INITIAL_WINDOW_SIZE {
                        let win_err = apply_peer_initial_window_size_delta(sess.conn, param_val);
                        if win_err != ERR_NO_ERROR {
                            emit_goaway(sess.conn.last_peer_stream_id, win_err, out_wire);
                            return offset + total_frame_len, false;
                        }
                    } else if param_id == SETTING_MAX_FRAME_SIZE {
                        sess.conn.local_max_frame_size = param_val;
                    } else if param_id == SETTING_HEADER_TABLE_SIZE {
                        let allowed_max: u64 = if (param_val as u64) < HPACK_MAX_ARENA_BYTES { param_val as u64 } else { HPACK_MAX_ARENA_BYTES };
                        sess.hpack_enc.max_allowed_size = allowed_max;
                        if sess.hpack_enc.current_max_size > allowed_max {
                            sess.hpack_enc.current_max_size = allowed_max;
                            evict_until(sess.hpack_enc, allowed_max);
                        }
                    }
                }
                // Send SETTINGS ACK back to client
                emit_settings_ack(out_wire);
            }
        } else if hdr.frame_type == FRAME_PING {
            if (hdr.flags & FLAG_ACK) == 0 && frame_payload.len == 8 {
                var opaque: u8[8] = [0; 8];
                for i in 8 { opaque[i] = frame_payload[i]; }
                emit_ping_ack(opaque, out_wire);
            }
        } else if hdr.frame_type == FRAME_PRIORITY {
            if frame_payload.len == 5 {
                let b0 = frame_payload[0] as u32;
                let b1 = frame_payload[1] as u32;
                let b2 = frame_payload[2] as u32;
                let b3 = frame_payload[3] as u32;
                let dep_raw = ((b0 & 0x7F) << 24) | (b1 << 16) | (b2 << 8) | b3;
                if dep_raw == hdr.stream_id {
                    // RFC 9113 §5.3.1: Stream cannot depend on itself -> stream error PROTOCOL_ERROR
                    emit_rst_stream(hdr.stream_id, ERR_PROTOCOL_ERROR, out_wire);
                }
            }
        } else if hdr.frame_type == FRAME_PRIORITY_UPDATE {
            let prio_stream_id, prio_param, prio_err = parse_priority_update_payload(frame_payload, false);
            if prio_err != ERR_NO_ERROR || (prio_stream_id % 2) == 0 {
                let final_err = if prio_err != ERR_NO_ERROR { prio_err } else { ERR_PROTOCOL_ERROR };
                emit_goaway(sess.conn.last_peer_stream_id, final_err, out_wire);
                return offset + total_frame_len, false;
            }
            apply_priority_update(sess.conn, prio_stream_id, prio_param);
        } else if hdr.frame_type == FRAME_WINDOW_UPDATE {
            if frame_payload.len == 4 {
                var wu_r = core::new_slice_reader(frame_payload);
                let raw_inc, _ = wu_r.read_u32_be();
                let inc = raw_inc & 0x7FFFFFFF;
                let wu_err = apply_window_update(sess.conn, hdr.stream_id, inc);
                if wu_err != ERR_NO_ERROR {
                    if hdr.stream_id == 0 {
                        // Connection-level window error -> connection GOAWAY (RFC 9113 §6.9)
                        emit_goaway(sess.conn.last_peer_stream_id, wu_err, out_wire);
                        return offset + total_frame_len, false;
                    } else {
                        // Stream-level window error -> stream RST_STREAM (RFC 9113 §6.9 / §6.9.1)
                        emit_rst_stream(hdr.stream_id, wu_err, out_wire);
                        let s_idx, found = find_server_stream_idx(sess, hdr.stream_id);
                        if found {
                            sess.streams[s_idx].active = false;
                        }
                    }
                }
            }
        } else if hdr.frame_type == FRAME_RST_STREAM {
            for i in sess.streams.len {
                if sess.streams[i].active && sess.streams[i].stream_id == hdr.stream_id {
                    sess.streams[i].active = false;
                    reset_server_stream(sess.streams[i]);
                }
            }
        } else if hdr.frame_type == FRAME_HEADERS {
            let is_cancelled = is_stream_cancelled_in_batch(cancelled_streams, hdr.stream_id);
            var block_start: i64 = 0;
            var block_end: i64 = frame_payload.len;

            // Handle PADDED flag RFC 9113 Section 6.1 / 6.2
            if (hdr.flags & FLAG_PADDED) != 0 {
                if frame_payload.len < 1 {
                    emit_goaway(sess.conn.last_peer_stream_id, ERR_FRAME_SIZE_ERROR, out_wire);
                    return offset + total_frame_len, false;
                }
                let pad_len = frame_payload[0] as i64;
                if pad_len >= frame_payload.len {
                    emit_goaway(sess.conn.last_peer_stream_id, ERR_PROTOCOL_ERROR, out_wire);
                    return offset + total_frame_len, false;
                }
                block_start += 1;
                block_end -= pad_len;
            }

            // Handle PRIORITY flag (RFC 9113 Section 5.3.1)
            if (hdr.flags & FLAG_PRIORITY) != 0 {
                if (block_end - block_start) < 5 {
                    emit_goaway(sess.conn.last_peer_stream_id, ERR_FRAME_SIZE_ERROR, out_wire);
                    return offset + total_frame_len, false;
                }
                let b0 = frame_payload[block_start] as u32;
                let b1 = frame_payload[block_start + 1] as u32;
                let b2 = frame_payload[block_start + 2] as u32;
                let b3 = frame_payload[block_start + 3] as u32;
                let dep_raw = ((b0 & 0x7F) << 24) | (b1 << 16) | (b2 << 8) | b3;
                if dep_raw == hdr.stream_id {
                    // RFC 9113 §5.3.1: Stream cannot depend on itself
                    emit_rst_stream(hdr.stream_id, ERR_PROTOCOL_ERROR, out_wire);
                    offset += total_frame_len;
                    continue;
                }
                block_start += 5;
            }

            let s_exist_idx, s_exists = find_server_stream_idx(sess, hdr.stream_id);
            let is_trailer = s_exists && sess.streams[s_exist_idx].headers_received;

            if is_trailer {
                // If stream already completed receiving body/trailers, extra HEADERS is invalid
                if sess.streams[s_exist_idx].body_received {
                    // RFC 9113 §5.1: Frame on half-closed (remote) stream
                    emit_rst_stream(hdr.stream_id, ERR_STREAM_CLOSED, out_wire);
                    offset += total_frame_len;
                    continue;
                }
                // RFC 9113 §8.1.2: A HEADERS frame containing a trailer section MUST have END_STREAM set
                if (hdr.flags & FLAG_END_STREAM) == 0 {
                    emit_rst_stream(hdr.stream_id, ERR_PROTOCOL_ERROR, out_wire);
                    offset += total_frame_len;
                    continue;
                }
            }

            if block_start <= block_end && block_end <= frame_payload.len {
                let fragment = frame_payload[block_start..block_end];
                if (hdr.flags & FLAG_END_HEADERS) != 0 {
                    var dec_list = DecodedH2HeaderList { .. };
                    dec_list.is_trailer = is_trailer;
                    let dec_err = decode_hpack_header_block(sess.conn.hpack_dec, fragment, dec_list);
                    if dec_err != ERR_NO_ERROR {
                        if dec_err == ERR_COMPRESSION_ERROR {
                            emit_goaway(sess.conn.last_peer_stream_id, ERR_COMPRESSION_ERROR, out_wire);
                            return offset + total_frame_len, false;
                        } else {
                            // Stream error (e.g. invalid pseudo-header in trailer)
                            emit_rst_stream(hdr.stream_id, dec_err, out_wire);
                            if is_trailer && s_exists {
                                sess.streams[s_exist_idx].active = false;
                            }
                            offset += total_frame_len;
                            continue;
                        }
                    }

                    if is_trailer {
                        if !is_cancelled && s_exists {
                            apply_decoded_trailers_to_stream(sess.streams[s_exist_idx], dec_list);
                            let c_idx, c_found = find_session_stream_idx(sess.conn, hdr.stream_id);
                            if c_found {
                                sess.conn.streams[c_idx].trailers_received = true;
                                sess.conn.streams[c_idx].state = H2StreamState.HalfClosedRemote;
                            }
                        }
                    } else {
                        // RFC 9113 Section 8.3.1: Mandatory request pseudo-headers
                        var has_method = false;
                        var has_scheme = false;
                        var has_path = false;
                        var is_connect = false;
                        for &f in dec_list.fields {
                            if f.name[..] == ":method" {
                                has_method = true;
                                if f.value[..] == "CONNECT" { is_connect = true; }
                            } else if f.name[..] == ":scheme" {
                                has_scheme = true;
                            } else if f.name[..] == ":path" {
                                has_path = true;
                            }
                        }
                        if !has_method || (!is_connect && (!has_scheme || !has_path)) {
                            emit_goaway(sess.conn.last_peer_stream_id, ERR_PROTOCOL_ERROR, out_wire);
                            return offset + total_frame_len, false;
                        }

                        // RFC 9113 Section 8.1.1: Content-Length on END_STREAM
                        if (hdr.flags & FLAG_END_STREAM) != 0 && dec_list.has_content_length && dec_list.content_length_val != 0 {
                            emit_goaway(sess.conn.last_peer_stream_id, ERR_PROTOCOL_ERROR, out_wire);
                            return offset + total_frame_len, false;
                        }

                        if !is_cancelled {
                            let s_idx, found = find_or_alloc_stream(sess, hdr.stream_id);
                            if found {
                                apply_decoded_headers_to_stream(sess.streams[s_idx], dec_list);
                                if dec_list.has_content_length {
                                    sess.streams[s_idx].declared_content_length = dec_list.content_length_val;
                                    let c_idx, c_found = find_session_stream_idx(sess.conn, hdr.stream_id);
                                    if c_found {
                                        sess.conn.streams[c_idx].declared_content_length = dec_list.content_length_val;
                                    }
                                }
                                if (hdr.flags & FLAG_END_STREAM) != 0 {
                                    sess.streams[s_idx].body_received = true;
                                }
                            }
                        }
                    }
                } else {
                    // Multi-frame header block: CONTINUATION follows
                    sess.header_accumulator.clear();
                    sess.header_accum_stream_id = hdr.stream_id;
                    sess.header_accum_end_stream = (hdr.flags & FLAG_END_STREAM) != 0;
                    sess.header_accum_is_trailer = is_trailer;
                    if fragment.len <= sess.header_accumulator.cap {
                        sess.header_accumulator.append(fragment);
                    } else {
                        emit_goaway(sess.conn.last_peer_stream_id, ERR_FRAME_SIZE_ERROR, out_wire);
                        return offset + total_frame_len, false;
                    }
                }
            }
        } else if hdr.frame_type == FRAME_CONTINUATION {
            if hdr.stream_id == sess.header_accum_stream_id {
                let is_cancelled = is_stream_cancelled_in_batch(cancelled_streams, hdr.stream_id);
                if sess.header_accumulator.len + frame_payload.len <= sess.header_accumulator.cap {
                    sess.header_accumulator.append(frame_payload);
                } else {
                    emit_goaway(sess.conn.last_peer_stream_id, ERR_FRAME_SIZE_ERROR, out_wire);
                    return offset + total_frame_len, false;
                }
                if (hdr.flags & FLAG_END_HEADERS) != 0 {
                    var dec_list = DecodedH2HeaderList { .. };
                    dec_list.is_trailer = sess.header_accum_is_trailer;
                    let dec_err = decode_hpack_header_block(sess.conn.hpack_dec, sess.header_accumulator[..], dec_list);
                    if dec_err != ERR_NO_ERROR {
                        if dec_err == ERR_COMPRESSION_ERROR {
                            emit_goaway(sess.conn.last_peer_stream_id, ERR_COMPRESSION_ERROR, out_wire);
                            return offset + total_frame_len, false;
                        } else {
                            emit_rst_stream(hdr.stream_id, dec_err, out_wire);
                            let s_idx, found = find_server_stream_idx(sess, hdr.stream_id);
                            if found { sess.streams[s_idx].active = false; }
                            sess.header_accum_stream_id = 0;
                            sess.header_accumulator.clear();
                            offset += total_frame_len;
                            continue;
                        }
                    }

                    if sess.header_accum_is_trailer {
                        if !is_cancelled {
                            let s_idx, found = find_server_stream_idx(sess, hdr.stream_id);
                            if found {
                                apply_decoded_trailers_to_stream(sess.streams[s_idx], dec_list);
                                let c_idx, c_found = find_session_stream_idx(sess.conn, hdr.stream_id);
                                if c_found {
                                    sess.conn.streams[c_idx].trailers_received = true;
                                    sess.conn.streams[c_idx].state = H2StreamState.HalfClosedRemote;
                                }
                            }
                        }
                    } else {
                        // RFC 9113 Section 8.3.1: Mandatory request pseudo-headers
                        var has_method = false;
                        var has_scheme = false;
                        var has_path = false;
                        var is_connect = false;
                        for &f in dec_list.fields {
                            if f.name[..] == ":method" {
                                has_method = true;
                                if f.value[..] == "CONNECT" { is_connect = true; }
                            } else if f.name[..] == ":scheme" {
                                has_scheme = true;
                            } else if f.name[..] == ":path" {
                                has_path = true;
                            }
                        }
                        if !has_method || (!is_connect && (!has_scheme || !has_path)) {
                            emit_goaway(sess.conn.last_peer_stream_id, ERR_PROTOCOL_ERROR, out_wire);
                            return offset + total_frame_len, false;
                        }

                        if sess.header_accum_end_stream && dec_list.has_content_length && dec_list.content_length_val != 0 {
                            emit_goaway(sess.conn.last_peer_stream_id, ERR_PROTOCOL_ERROR, out_wire);
                            return offset + total_frame_len, false;
                        }

                        if !is_cancelled {
                            let s_idx, found = find_or_alloc_stream(sess, hdr.stream_id);
                            if found {
                                apply_decoded_headers_to_stream(sess.streams[s_idx], dec_list);
                                if dec_list.has_content_length {
                                    sess.streams[s_idx].declared_content_length = dec_list.content_length_val;
                                    let c_idx, c_found = find_session_stream_idx(sess.conn, hdr.stream_id);
                                    if c_found {
                                        sess.conn.streams[c_idx].declared_content_length = dec_list.content_length_val;
                                    }
                                }
                                if sess.header_accum_end_stream {
                                    sess.streams[s_idx].body_received = true;
                                }
                            }
                        }
                    }
                    sess.header_accum_stream_id = 0;
                    sess.header_accumulator.clear();
                }
            }
        } else if hdr.frame_type == FRAME_DATA {
            // Handle PADDED flag RFC 9113 Section 6.1
            if (hdr.flags & FLAG_PADDED) != 0 {
                if frame_payload.len < 1 {
                    emit_goaway(sess.conn.last_peer_stream_id, ERR_FRAME_SIZE_ERROR, out_wire);
                    return offset + total_frame_len, false;
                }
                let pad_len = frame_payload[0] as i64;
                if pad_len >= frame_payload.len {
                    emit_goaway(sess.conn.last_peer_stream_id, ERR_PROTOCOL_ERROR, out_wire);
                    return offset + total_frame_len, false;
                }
            }

            let s_idx, found = find_server_stream_idx(sess, hdr.stream_id);
            if !found {
                if hdr.stream_id <= sess.conn.last_peer_stream_id {
                    // RFC 9113 §5.1: Closed stream receives DATA -> stream error STREAM_CLOSED
                    emit_rst_stream(hdr.stream_id, ERR_STREAM_CLOSED, out_wire);
                    // Account for flow control connection-wide per RFC 9113 §6.9
                    sess.conn.conn_recv_window -= hdr.length as i64;
                    if sess.conn.conn_recv_window < 0 {
                        emit_goaway(sess.conn.last_peer_stream_id, ERR_FLOW_CONTROL_ERROR, out_wire);
                        return offset + total_frame_len, false;
                    }
                    emit_window_update(0, hdr.length, out_wire);
                    sess.conn.conn_recv_window += hdr.length as i64;
                    offset += total_frame_len;
                    continue;
                } else {
                    // Idle stream receives DATA -> connection error PROTOCOL_ERROR (RFC 9113 §5.1)
                    emit_goaway(sess.conn.last_peer_stream_id, ERR_PROTOCOL_ERROR, out_wire);
                    return offset + total_frame_len, false;
                }
            }

            // Stream is found; check if stream is already half-closed (remote)
            if sess.streams[s_idx].body_received {
                // RFC 9113 §5.1: Receiving DATA after END_STREAM is a stream error STREAM_CLOSED
                emit_rst_stream(hdr.stream_id, ERR_STREAM_CLOSED, out_wire);
                sess.conn.conn_recv_window -= hdr.length as i64;
                if sess.conn.conn_recv_window < 0 {
                    emit_goaway(sess.conn.last_peer_stream_id, ERR_FLOW_CONTROL_ERROR, out_wire);
                    return offset + total_frame_len, false;
                }
                emit_window_update(0, hdr.length, out_wire);
                sess.conn.conn_recv_window += hdr.length as i64;
                offset += total_frame_len;
                continue;
            }

            var d_start: i64 = 0;
            var d_end: i64 = frame_payload.len;

            if (hdr.flags & FLAG_PADDED) != 0 && frame_payload.len >= 1 {
                let pad_len = frame_payload[0] as i64;
                d_start += 1;
                d_end -= pad_len;
            }

            if d_start <= d_end && d_end <= frame_payload.len {
                let d_len = d_end - d_start;
                if sess.streams[s_idx].body.len + d_len <= sess.streams[s_idx].body.cap {
                    sess.streams[s_idx].body.append(frame_payload[d_start..d_end]);
                } else {
                    emit_rst_stream(hdr.stream_id, ERR_INTERNAL_ERROR, out_wire);
                    sess.streams[s_idx].active = false;
                }
            }

            let flow_err = on_data_frame_received(sess.conn, hdr, frame_payload.len as u32);
            if flow_err != ERR_NO_ERROR {
                if flow_err == ERR_STREAM_CLOSED {
                    emit_rst_stream(hdr.stream_id, ERR_STREAM_CLOSED, out_wire);
                    sess.streams[s_idx].active = false;
                    offset += total_frame_len;
                    continue;
                }
                emit_goaway(sess.conn.last_peer_stream_id, flow_err, out_wire);
                return offset + total_frame_len, false;
            }

            // Replenish receive windows if consumed and non-zero
            if frame_payload.len > 0 {
                emit_window_update(0, frame_payload.len as u32, out_wire);
                emit_window_update(hdr.stream_id, frame_payload.len as u32, out_wire);
                // Replenish session tracking windows
                sess.conn.conn_recv_window += hdr.length as i64;
                let c_idx, c_found = find_session_stream_idx(sess.conn, hdr.stream_id);
                if c_found {
                    sess.conn.streams[c_idx].recv_window += hdr.length as i64;
                }
            }

            if (hdr.flags & FLAG_END_STREAM) != 0 {
                let dec_cl = sess.streams[s_idx].declared_content_length;
                if dec_cl >= 0 && dec_cl != (sess.streams[s_idx].body.len as i64) {
                    emit_goaway(sess.conn.last_peer_stream_id, ERR_PROTOCOL_ERROR, out_wire);
                    return offset + total_frame_len, false;
                }
                sess.streams[s_idx].body_received = true;
            }
        }

        offset += total_frame_len;
    }

    for i in sess.streams.len {
        if sess.streams[i].active &&
           sess.streams[i].headers_received &&
           sess.streams[i].body_received &&
           !sess.streams[i].response_sent {
            let target_stream_id = sess.streams[i].stream_id;

            // Construct Request
            var req = new_request(sess.streams[i].method[..], sess.streams[i].path[..]);
            for &hdr_item in sess.streams[i].headers {
                if req.headers.len < 32 {
                    req.headers.push(hdr_item);
                }
            }
            for &tr_item in sess.streams[i].trailers {
                if req.trailers.len < 16 {
                    req.trailers.push(tr_item);
                }
            }
            req.body.append(sess.streams[i].body[..]);

            // Execute pipeline
            var res = new_response();
            var future = internal::new_inline_handler_future(0);
            let now_ns = (now_ms as u64) * 1000000;
            execute_pipeline(pipeline, timer, client_ip, req, now_ns, res, future);

            let is_grpc = starts_with_fold(res.header("content-type"), "application/grpc");

            if !is_grpc && res.trailers.len == 0 && res.status_code == 200 && res.body.len == 0 && sess.streams[i].method[..] != "HEAD" {
                res.body.append("OK\n");
            }

            // Emit Response
            let has_body = res.body.len > 0;
            let has_trailers = res.trailers.len > 0;
            let end_headers = !has_body && !has_trailers;
            emit_response_headers(sess, target_stream_id, res, end_headers, out_wire);
            if has_body {
                let end_data = !has_trailers;
                emit_response_data(target_stream_id, res.body[..], sess.conn.local_max_frame_size, out_wire, end_data);
            }
            if has_trailers {
                emit_response_trailers(sess, target_stream_id, res.trailers, out_wire);
            }

            sess.streams[i].response_sent = true;
            sess.streams[i].active = false;

            // RFC 9113 §5.1: Response sent with END_STREAM -> stream transitions to Closed
            let c_idx, c_found = find_session_stream_idx(sess.conn, target_stream_id);
            if c_found {
                sess.conn.streams[c_idx].state = H2StreamState.Closed;
                sess.conn.streams[c_idx].active = false;
                if sess.conn.active_stream_count > 0 {
                    sess.conn.active_stream_count--;
                }
            }
        }
    }

    flush_server_control_frames(sess);
    return offset, true;
}
