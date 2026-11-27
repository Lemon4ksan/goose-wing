// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal QUIC transport parameter codec helpers (RFC 9000 Section 18).
namespace quic_internal;

import std;
import core;
import .packet;
import .frames;

// ---- QUIC Transport Parameters Internal Helpers (RFC 9000 §18) -----------

const QUIC_TP_BIT_ODCID:            u64 = (1 as u64) << 0;
const QUIC_TP_BIT_IDLE_TIMEOUT:     u64 = (1 as u64) << 1;
const QUIC_TP_BIT_SR_TOKEN:         u64 = (1 as u64) << 2;
const QUIC_TP_BIT_MAX_UDP_PAYLOAD:  u64 = (1 as u64) << 3;
const QUIC_TP_BIT_MAX_DATA:         u64 = (1 as u64) << 4;
const QUIC_TP_BIT_MAX_SD_BIDI_LOC:  u64 = (1 as u64) << 5;
const QUIC_TP_BIT_MAX_SD_BIDI_REM:  u64 = (1 as u64) << 6;
const QUIC_TP_BIT_MAX_SD_UNI:       u64 = (1 as u64) << 7;
const QUIC_TP_BIT_MAX_STREAMS_BIDI: u64 = (1 as u64) << 8;
const QUIC_TP_BIT_MAX_STREAMS_UNI:  u64 = (1 as u64) << 9;
const QUIC_TP_BIT_ACK_DELAY_EXP:    u64 = (1 as u64) << 10;
const QUIC_TP_BIT_MAX_ACK_DELAY:    u64 = (1 as u64) << 11;
const QUIC_TP_BIT_DISABLE_MIG:      u64 = (1 as u64) << 12;
const QUIC_TP_BIT_PREF_ADDR:        u64 = (1 as u64) << 13;
const QUIC_TP_BIT_ACTIVE_CID_LIM:   u64 = (1 as u64) << 14;
const QUIC_TP_BIT_ISCID:            u64 = (1 as u64) << 15;
const QUIC_TP_BIT_RSCID:            u64 = (1 as u64) << 16;
const QUIC_TP_BIT_VERSION_INFO:     u64 = (1 as u64) << 17;
const QUIC_TP_BIT_MAX_DATAGRAM:     u64 = (1 as u64) << 18;
const QUIC_TP_BIT_GREASE_QUIC_BIT:  u64 = (1 as u64) << 19;
const QUIC_TP_BIT_MIN_ACK_DELAY:    u64 = (1 as u64) << 20;

// Appends a varint-valued transport parameter `(id, varint_len(val), val)` into `out`.
fn encode_tp_varint<B>(id: u64, val: u64, out: B&) -> bool {
    var vbuf: u8[..8] = [];
    guard quic::encode_varint(val, vbuf) else { return false; }
    let orig_len = out.len;
    var committed = false;
    defer if !committed { out.resize(orig_len); };
    guard quic::encode_varint(id, out)
        && quic::encode_varint(vbuf.len as u64, out)
        && out.try_append(vbuf[..]) else {
        return false;
    }
    committed = true;
    return true;
}

// Appends a raw byte-slice transport parameter `(id, bytes.len, bytes)` into `out`.
fn encode_tp_bytes<B>(id: u64, bytes: const u8[:], out: B&) -> bool {
    let orig_len = out.len;
    var committed = false;
    defer if !committed { out.resize(orig_len); };
    guard quic::encode_varint(id, out)
        && quic::encode_varint(bytes.len as u64, out)
        && out.try_append(bytes) else {
        return false;
    }
    committed = true;
    return true;
}

// Encodes connection-level and stream data flow-control transport parameters (`0x01`, `0x03..0x07`).
fn encode_tp_flow_data<B>(tp: const quic::QuicTransportParams&, out: B&) -> bool {
    if tp.max_idle_timeout > 0 {
        guard encode_tp_varint(rfc::QUIC_TP_MAX_IDLE_TIMEOUT, tp.max_idle_timeout, out) else { return false; }
    }
    if tp.max_udp_payload_size != 65527 {
        guard tp.max_udp_payload_size >= rfc::QUIC_MIN_INITIAL_DATAGRAM_LEN else { return false; }
        guard encode_tp_varint(rfc::QUIC_TP_MAX_UDP_PAYLOAD_SIZE, tp.max_udp_payload_size, out) else { return false; }
    }
    if tp.initial_max_data > 0 {
        guard encode_tp_varint(rfc::QUIC_TP_INITIAL_MAX_DATA, tp.initial_max_data, out) else { return false; }
    }
    if tp.initial_max_stream_data_bidi_local > 0 {
        let id = rfc::QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL;
        guard encode_tp_varint(id, tp.initial_max_stream_data_bidi_local, out) else { return false; }
    }
    if tp.initial_max_stream_data_bidi_remote > 0 {
        let id = rfc::QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE;
        guard encode_tp_varint(id, tp.initial_max_stream_data_bidi_remote, out) else { return false; }
    }
    if tp.initial_max_stream_data_uni > 0 {
        let id = rfc::QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI;
        guard encode_tp_varint(id, tp.initial_max_stream_data_uni, out) else { return false; }
    }
    return true;
}

// Encodes stream-count and ACK timing transport parameters (`0x08..0x0c`).
fn encode_tp_streams_and_ack<B>(tp: const quic::QuicTransportParams&, out: B&) -> bool {
    if tp.initial_max_streams_bidi > 0 {
        guard tp.initial_max_streams_bidi <= rfc::QUIC_MAX_STREAMS_LIMIT else { return false; }
        let id = rfc::QUIC_TP_INITIAL_MAX_STREAMS_BIDI;
        guard encode_tp_varint(id, tp.initial_max_streams_bidi, out) else { return false; }
    }
    if tp.initial_max_streams_uni > 0 {
        guard tp.initial_max_streams_uni <= rfc::QUIC_MAX_STREAMS_LIMIT else { return false; }
        let id = rfc::QUIC_TP_INITIAL_MAX_STREAMS_UNI;
        guard encode_tp_varint(id, tp.initial_max_streams_uni, out) else { return false; }
    }
    if tp.ack_delay_exponent != 3 {
        guard tp.ack_delay_exponent <= 20 else { return false; }
        guard encode_tp_varint(rfc::QUIC_TP_ACK_DELAY_EXPONENT, tp.ack_delay_exponent, out) else { return false; }
    }
    if tp.max_ack_delay != 25 {
        guard tp.max_ack_delay < 16384 else { return false; }
        guard encode_tp_varint(rfc::QUIC_TP_MAX_ACK_DELAY, tp.max_ack_delay, out) else { return false; }
    }
    if tp.disable_active_migration {
        guard encode_tp_bytes(rfc::QUIC_TP_DISABLE_ACTIVE_MIGRATION, "", out) else { return false; }
    }
    return true;
}

// RFC 9000 Section 18.2: Transport Parameter Definitions - Validates preferred_address structure and IP/port invariants.
//
// crap:trusted-bounds
inline fn is_valid_tp_preferred_address(val: const u8[:]) -> bool {
    var cur = core::cursor_from(val);
    let v4, ok4 = cur.read_bytes(4);
    let p4, okp4 = cur.read_u16();
    let v6, ok6 = cur.read_bytes(16);
    let p6, okp6 = cur.read_u16();
    let cid_slice, ok_cid = cur.read_u8_prefixed();
    let _, ok_tok = cur.read_bytes(16);
    guard ok4 && okp4 && ok6 && okp6 && ok_cid && ok_tok && cur.buf.len == 0 else { return false; }
    guard cid_slice.len >= 1 && cid_slice.len <= 20 else { return false; }
    let has_v4 = (v4[0] | v4[1] | v4[2] | v4[3]) != 0;
    var v6_or: u8 = 0;
    for i in 16 {
        v6_or = v6_or | v6[i];
    }
    let has_v6 = v6_or != 0;
    return has_v4 == (p4 != 0) && has_v6 == (p6 != 0) && (has_v4 || has_v6);
}

// Encodes CID limit and extension transport parameters (`0x0e`, `0x20`, `0x2ab2`, `0xde1a`).
fn encode_tp_extensions<B>(tp: const quic::QuicTransportParams&, out: B&) -> bool {
    if tp.active_connection_id_limit != 2 {
        guard tp.active_connection_id_limit >= 2 else { return false; }
        let id = rfc::QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT;
        guard encode_tp_varint(id, tp.active_connection_id_limit, out) else { return false; }
    }
    if tp.max_datagram_frame_size > 0 {
        let id = rfc::QUIC_TP_MAX_DATAGRAM_FRAME_SIZE;
        guard encode_tp_varint(id, tp.max_datagram_frame_size, out) else { return false; }
    }
    if tp.grease_quic_bit {
        guard encode_tp_bytes(rfc::QUIC_TP_GREASE_QUIC_BIT, "", out) else { return false; }
    }
    if tp.min_ack_delay_us > 0 {
        guard tp.min_ack_delay_us <= core::mul_sat_u64(tp.max_ack_delay, 1000) else { return false; }
        guard encode_tp_varint(rfc::QUIC_TP_MIN_ACK_DELAY, tp.min_ack_delay_us, out) else { return false; }
    }
    return true;
}

// Encodes RFC 9368 `version_information` (`0x11`) transport parameter into `out`.
fn encode_tp_version_info<B>(tp: const quic::QuicTransportParams&, out: B&) -> bool {
    // RFC 9369 Section 4: Version Negotiation Considerations - Reject non-empty available_versions when chosen_version is 0.
    if tp.chosen_version == 0 {
        return tp.available_versions.len == 0;
    }
    var vbuf: u8[..40] = [];
    vbuf.append_u32_be(tp.chosen_version);
    for i in tp.available_versions.len {
        let av = tp.available_versions[i];
        guard av != 0 else { return false; }
        vbuf.append_u32_be(av);
    }
    return encode_tp_bytes(rfc::QUIC_TP_VERSION_INFORMATION, vbuf[..], out);
}

// Encodes server-only and CID transport parameters into `out`.
fn encode_tp_cids_and_server<B>(
    tp:        const quic::QuicTransportParams&,
    is_server: bool,
    out:       B&,
) -> bool {
    if !is_server {
        return !tp.has_stateless_reset_token
            && tp.preferred_address.len == 0
            && tp.original_destination_connection_id.len == 0
            && tp.retry_source_connection_id.len == 0;
    }
    // RFC 9000 Section 7.3: Authenticating Connection IDs - Servers MUST send original_destination_connection_id.
    let odcid_id = rfc::QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID;
    guard encode_tp_bytes(odcid_id, tp.original_destination_connection_id[..], out) else { return false; }
    if tp.has_stateless_reset_token {
        guard encode_tp_bytes(rfc::QUIC_TP_STATELESS_RESET_TOKEN, tp.stateless_reset_token[..], out) else {
            return false;
        }
    }
    if tp.preferred_address.len > 0 {
        guard is_valid_tp_preferred_address(tp.preferred_address[..])
            && encode_tp_bytes(rfc::QUIC_TP_PREFERRED_ADDRESS, tp.preferred_address[..], out) else {
            return false;
        }
    }
    if tp.retry_source_connection_id.len > 0 {
        let id = rfc::QUIC_TP_RETRY_SOURCE_CONNECTION_ID;
        guard encode_tp_bytes(id, tp.retry_source_connection_id[..], out) else { return false; }
    }
    return true;
}

// Decodes a single exact-fitting varint from a transport parameter value slice.
//
// Example:
//   val = [0x44, 0xB0] (varint 1200)
//   returns: v = 1200, ok = true
checkfree inline fn decode_tp_exact_varint(val: const u8[:]) -> u64, bool {
    var v_idx: i64 = 0;
    let v, ok = quic::decode_varint_cursor(val, v_idx);
    guard ok && v_idx == val.len else { return 0, false; }
    return v, true;
}

// Marks `bit` in `seen_mask`, returning `false` on duplicate transport parameter ID.
inline fn mark_tp_seen(seen_mask: u64&, bit: u64) -> bool {
    guard (seen_mask & bit) == 0 else { return false; }
    seen_mask |= bit;
    return true;
}

// Decodes RFC 9368 `version_information` (`0x11`) transport parameter value slice.
//
// Example:
//   val = [0x00, 0x00, 0x00, 0x01, 0x6b, 0x33, 0x43, 0xcf]
//   returns: true, tp.chosen_version = 1, tp.available_versions = [0x6b3343cf]
//
// crap:trusted-bounds
inline fn decode_tp_version_info(val: const u8[:], tp: quic::QuicTransportParams&) -> bool {
    guard val.len >= 4 && (val.len & 3) == 0 else { return false; }
    var cur = core::cursor_from(val);
    let chosen, ok_c = cur.read_u32();
    guard ok_c && chosen != 0 else { return false; }
    var parsed_vers: u32[..8] = [];
    while cur.buf.len >= 4 {
        let av, ok_a = cur.read_u32();
        guard ok_a && av != 0 && parsed_vers.try_push(av) else { return false; }
    }
    tp.chosen_version = chosen;
    tp.available_versions = parsed_vers;
    return true;
}

// Validates RFC 9000 §18.2 `preferred_address` (`0x0d`) wire structure and copies into `tp`.
//
// Example:
//   val = [4B ipv4, 2B port, 16B ipv6, 2B port, cid_len=4, 1, 2, 3, 4, 16B reset_token]
//   returns: true, tp.preferred_address = val
//
// crap:trusted-bounds
inline fn decode_tp_preferred_addr(val: const u8[:], tp: quic::QuicTransportParams&) -> bool {
    guard is_valid_tp_preferred_address(val) else { return false; }
    return tp.preferred_address.try_set(val);
}

// Decodes connection and stream data flow-control parameters (`0x01`, `0x03..0x06`).
//
// Example:
//   id = 0x03 (max_udp_payload_size), val = [0x45, 0xDC] (1500)
//   returns: true, tp.max_udp_payload_size = 1500
fn decode_tp_flow_data(id: u64, v: u64, tp: quic::QuicTransportParams&) -> bool {
    if id == rfc::QUIC_TP_MAX_IDLE_TIMEOUT {
        guard mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_IDLE_TIMEOUT) else { return false; }
        tp.max_idle_timeout = v;
        return true;
    }
    if id == rfc::QUIC_TP_MAX_UDP_PAYLOAD_SIZE {
        guard v >= rfc::QUIC_MIN_INITIAL_DATAGRAM_LEN else { return false; }
        guard mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MAX_UDP_PAYLOAD) else { return false; }
        tp.max_udp_payload_size = v;
        return true;
    }
    if id == rfc::QUIC_TP_INITIAL_MAX_DATA {
        guard mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MAX_DATA) else { return false; }
        tp.initial_max_data = v;
        return true;
    }
    if id == rfc::QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL {
        guard mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MAX_SD_BIDI_LOC) else { return false; }
        tp.initial_max_stream_data_bidi_local = v;
        return true;
    }
    if id == rfc::QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE {
        guard mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MAX_SD_BIDI_REM) else { return false; }
        tp.initial_max_stream_data_bidi_remote = v;
        return true;
    }
    return false;
}

// Decodes unidirectional stream data and stream count transport parameters (`0x07..0x09`).
//
// Example:
//   id = 0x08 (initial_max_streams_bidi), val = [0x40, 0x64] (100)
//   returns: true, tp.initial_max_streams_bidi = 100
fn decode_tp_flow_param(id: u64, val: const u8[:], tp: quic::QuicTransportParams&) -> bool {
    let v, ok = decode_tp_exact_varint(val);
    guard ok else { return false; }
    if id <= rfc::QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE {
        return decode_tp_flow_data(id, v, tp);
    }
    if id == rfc::QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI {
        guard mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MAX_SD_UNI) else { return false; }
        tp.initial_max_stream_data_uni = v;
        return true;
    }
    if id == rfc::QUIC_TP_INITIAL_MAX_STREAMS_BIDI {
        guard v <= rfc::QUIC_MAX_STREAMS_LIMIT else { return false; }
        guard mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MAX_STREAMS_BIDI) else { return false; }
        tp.initial_max_streams_bidi = v;
        return true;
    }
    if id == rfc::QUIC_TP_INITIAL_MAX_STREAMS_UNI {
        guard v <= rfc::QUIC_MAX_STREAMS_LIMIT else { return false; }
        guard mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MAX_STREAMS_UNI) else { return false; }
        tp.initial_max_streams_uni = v;
        return true;
    }
    return false;
}

// Copies a 16-byte stateless reset token slice into `tp`.
//
// crap:trusted-bounds
checkfree inline fn set_tp_stateless_reset_token(val: const u8[:], tp: quic::QuicTransportParams&) -> bool {
    guard val.len == 16 else { return false; }
    for i in 16 {
        tp.stateless_reset_token[i] = val[i];
    }
    tp.has_stateless_reset_token = true;
    return true;
}

// Decodes server-only and CID transport parameters (`0x00`, `0x02`, `0x0d`, `0x0f`, `0x10`).
//
// Example:
//   id = 0x0f (initial_source_connection_id), val = [1, 2, 3, 4], is_server = true
//   returns: true, tp.initial_source_connection_id = [1, 2, 3, 4]
fn decode_tp_cid_or_server_param(
    id:        u64,
    val:       const u8[:],
    is_server: bool,
    tp:        quic::QuicTransportParams&,
) -> bool {
    if id == rfc::QUIC_TP_INITIAL_SOURCE_CONNECTION_ID {
        return tp.initial_source_connection_id.try_set(val) && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_ISCID);
    }
    guard is_server else { return false; }
    if id == rfc::QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID {
        return tp.original_destination_connection_id.try_set(val) && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_ODCID);
    }
    if id == rfc::QUIC_TP_STATELESS_RESET_TOKEN {
        return set_tp_stateless_reset_token(val, tp) && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_SR_TOKEN);
    }
    if id == rfc::QUIC_TP_PREFERRED_ADDRESS {
        return decode_tp_preferred_addr(val, tp) && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_PREF_ADDR);
    }
    if id == rfc::QUIC_TP_RETRY_SOURCE_CONNECTION_ID {
        return tp.retry_source_connection_id.try_set(val) && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_RSCID);
    }
    return false;
}

// Decodes standard ACK timing and migration transport parameters (`0x0a..0x0c`, `0x0e`).
//
// Example:
//   id = 0x0a (ack_delay_exponent), val = [0x04]
//   returns: true, tp.ack_delay_exponent = 4
fn decode_tp_ack_and_mig(id: u64, val: const u8[:], tp: quic::QuicTransportParams&) -> bool {
    if id == rfc::QUIC_TP_DISABLE_ACTIVE_MIGRATION {
        guard val.len == 0 && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_DISABLE_MIG) else { return false; }
        tp.disable_active_migration = true;
        return true;
    }
    let v, ok = decode_tp_exact_varint(val);
    guard ok else { return false; }
    if id == rfc::QUIC_TP_ACK_DELAY_EXPONENT {
        guard v <= 20 && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_ACK_DELAY_EXP) else { return false; }
        tp.ack_delay_exponent = v;
        return true;
    }
    if id == rfc::QUIC_TP_MAX_ACK_DELAY {
        guard v < 16384 && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MAX_ACK_DELAY) else { return false; }
        tp.max_ack_delay = v;
        return true;
    }
    if id == rfc::QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT {
        guard v >= 2 && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_ACTIVE_CID_LIM) else { return false; }
        tp.active_connection_id_limit = v;
        return true;
    }
    return false;
}

// Decodes extension transport parameters (`0x11`, `0x20`, `0x2ab2`, `0xde1a`).
//
// Example:
//   id = 0x2ab2 (grease_quic_bit), val = []
//   returns: true, tp.grease_quic_bit = true
fn decode_tp_ext_param(id: u64, val: const u8[:], tp: quic::QuicTransportParams&) -> bool {
    if id <= rfc::QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT {
        return decode_tp_ack_and_mig(id, val, tp);
    }
    if id == rfc::QUIC_TP_VERSION_INFORMATION {
        guard (tp.seen_mask & QUIC_TP_BIT_VERSION_INFO) == 0
            && decode_tp_version_info(val, tp) else {
            return false;
        }
        tp.seen_mask |= QUIC_TP_BIT_VERSION_INFO;
        return true;
    }
    if id == rfc::QUIC_TP_MAX_DATAGRAM_FRAME_SIZE {
        let v, ok = decode_tp_exact_varint(val);
        guard ok && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MAX_DATAGRAM) else { return false; }
        tp.max_datagram_frame_size = v;
        return true;
    }
    if id == rfc::QUIC_TP_GREASE_QUIC_BIT {
        guard val.len == 0 && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_GREASE_QUIC_BIT) else { return false; }
        tp.grease_quic_bit = true;
        return true;
    }
    if id == rfc::QUIC_TP_MIN_ACK_DELAY {
        let v, ok = decode_tp_exact_varint(val);
        guard ok && mark_tp_seen(tp.seen_mask, QUIC_TP_BIT_MIN_ACK_DELAY) else { return false; }
        tp.min_ack_delay_us = v;
        return true;
    }
    return true;
}

// Decodes a single transport parameter `(id, val)` into `tp`.
//
// Example:
//   id = 0x04 (initial_max_data), val = [0x44, 0x00], is_server = true
//   returns: true, tp.initial_max_data = 1024
inline fn decode_single_tp(
    id:        u64,
    val:       const u8[:],
    is_server: bool,
    tp:        quic::QuicTransportParams&,
) -> bool {
    if id == rfc::QUIC_TP_MAX_IDLE_TIMEOUT
        || (id >= rfc::QUIC_TP_MAX_UDP_PAYLOAD_SIZE && id <= rfc::QUIC_TP_INITIAL_MAX_STREAMS_UNI) {
        return decode_tp_flow_param(id, val, tp);
    }
    if id == rfc::QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID
        || id == rfc::QUIC_TP_STATELESS_RESET_TOKEN
        || id == rfc::QUIC_TP_PREFERRED_ADDRESS
        || id == rfc::QUIC_TP_INITIAL_SOURCE_CONNECTION_ID
        || id == rfc::QUIC_TP_RETRY_SOURCE_CONNECTION_ID {
        return decode_tp_cid_or_server_param(id, val, is_server, tp);
    }
    return decode_tp_ext_param(id, val, tp);
}
