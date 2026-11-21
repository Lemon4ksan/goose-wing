// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// QUIC Transport Framing, Packet Headers, Header Protection & Stream Reassembly (RFC 9000, RFC 9001).
// Implements VarInt codecs, Long/Short header parsers, AES/ChaCha Header Protection,
// packet number reconstruction, path anti-amplification 3x limits, and zero-heap reassembler.
namespace quic;

import std;
import core from "..";
import .packet_internal;

// ---- Variable-Length Integer Codec (RFC 9000 Section 16) -----------------

// Encodes a 62-bit unsigned integer into big-endian wire format using core/io.
fn encode_varint<B>(val: u64, out: B&) -> bool {
    guard val <= 0x3FFFFFFFFFFFFFFF else { return false; }

    if val <= 63 {
        return out.try_push(val as u8);
    }
    if val <= 16383 {
        guard out.cap - out.len >= 2 else { return false; }
        let masked = (0x4000 | val) as u16;
        out.append_u16_be(masked);
        return true;
    }
    if val <= 1073741823 {
        guard out.cap - out.len >= 4 else { return false; }
        let masked = (0x80000000 | val) as u32;
        out.append_u32_be(masked);
        return true;
    }

    guard out.cap - out.len >= 8 else { return false; }
    let masked = 0xC000000000000000 | val;
    out.append_u64_be(masked);
    return true;
}

// Decodes a QUIC variable-length integer directly from a byte slice with an in-out cursor (RFC 9000 §16).
//
// Example:
//   src = [0x40, 0x25], idx = 0
//   returns: val = 37, ok = true, idx = 2
inline fn decode_varint_cursor(src: const u8[:], idx: i64&) -> u64, bool {
    guard idx >= 0 && idx < src.len else { return 0, false; }
    let first = src[idx];
    let vlen = quic_internal::quic_varint_len(first) as i64;
    let next_idx = idx + vlen;
    guard next_idx <= src.len else { return 0, false; }

    if vlen == 1 {
        let val: u64 = first & 0x3F;
        idx = next_idx;
        return val, true;
    }
    if vlen == 2 {
        let val = quic_internal::varint_read_2(src, idx, first);
        idx = next_idx;
        return val, true;
    }
    if vlen == 4 {
        let val = quic_internal::varint_read_4(src, idx, first);
        idx = next_idx;
        return val, true;
    }
    let val = quic_internal::varint_read_8(src, idx, first);
    idx = next_idx;
    return val, true;
}

// Decodes a variable-length integer from big-endian wire format (RFC 9000 §16).
//
// Example:
//   src = [0x40, 0x25], offset = 0
//   returns: val = 37, next_offset = 2, ok = true
fn decode_varint(src: const u8[:], offset: u64) -> u64, u64, bool {
    guard offset < (src.len as u64) else { return 0, offset, false; }
    var idx = offset as i64;
    let val, ok = decode_varint_cursor(src, idx);
    guard ok else { return 0, offset, false; }
    return val, idx as u64, true;
}

// Stream identifier classification helpers (RFC 9000 Section 2.1)
inline fn is_client_stream(id: u64) -> bool { return (id & 0x01) == 0; }
inline fn is_server_stream(id: u64) -> bool { return (id & 0x01) != 0; }
inline fn is_bidi_stream(id: u64) -> bool { return (id & 0x02) == 0; }
inline fn is_uni_stream(id: u64) -> bool { return (id & 0x02) != 0; }

// ---- Packet Header Parsing & Formatting (RFC 9000 Section 17) ------------

enum QuicHeaderType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    OneRtt,
    VersionNegotiation,
}

struct QuicHeader {
    header_type:    QuicHeaderType = QuicHeaderType.OneRtt,
    version:        u32            = rfc::QUIC_VERSION_1,
    dcid:           u8[..20]       = [],
    scid:           u8[..20]       = [],
    token:          u8[..512]      = [],
    payload_length: u64            = 0,
    packet_number:  u64            = 0,
    pn_offset:      u32            = 0,
    pn_length:      u8             = 0,
    key_phase:      bool           = false,
    spin_bit:       bool           = false,
    header_len:     u32            = 0,
}

// Parses unmasked QUIC Long or Short header up to the payload boundary (RFC 9000 §17).
//
// Example:
//   src = [0x40, 0x01, 0x02, 0x03, 0x04, 0x05], dcid_len_short = 4
//   returns: QuicHeader { header_type: OneRtt, dcid: [1, 2, 3, 4] }, ok = true
fn parse_header(src: const u8[:], dcid_len_short: u8 = 0) -> QuicHeader, bool {
    guard src.len > 0 else { return QuicHeader { .. }, false; }
    let first = src[0];
    if (first & 0x80) != 0 {
        return quic_internal::parse_quic_long_header(src, first);
    }
    return quic_internal::parse_quic_short_header(src, first, dcid_len_short);
}

// Encodes a QUIC Long or Short header in unmasked form into out buffer.
fn encode_header<B>(hdr: const QuicHeader&, pn_len: u8, out: B&) -> bool {
    // RFC 9000 Section 17.2.5: Retry Packet - Retry packets carry no packet number; permit pn_len == 0.
    let is_retry = hdr.header_type == QuicHeaderType.Retry;
    guard (is_retry && pn_len <= 4) || (pn_len >= 1 && pn_len <= 4) else { return false; }
    guard hdr.dcid.len <= rfc::QUIC_MAX_CID_LEN && hdr.scid.len <= rfc::QUIC_MAX_CID_LEN else { return false; }

    let pn_bits = if pn_len == 0 { 0 } else { (pn_len - 1) & 0x03 };

    if hdr.header_type != QuicHeaderType.OneRtt {
        return quic_internal::encode_quic_long_header(hdr, pn_len, pn_bits, out);
    }

    // Short Header (1-RTT)
    guard out.cap - out.len >= 1 + hdr.dcid.len + (pn_len as i64) else { return false; }
    var b0: u8 = 0x40 | pn_bits;
    if hdr.spin_bit { b0 = b0 | 0x20; }
    if hdr.key_phase { b0 = b0 | 0x04; }
    out.push(b0);

    if hdr.dcid.len > 0 {
        out.append(hdr.dcid[..]);
    }
    return quic_internal::encode_packet_number(hdr.packet_number, pn_len, out);
}

// Encodes an RFC 9000 §10.3 Stateless Reset packet (at least 21 bytes: 0b01xxxxxx first byte,
// unpredictable random bytes >= 5 total, and 16-byte Stateless Reset Token).
fn encode_stateless_reset_packet<B>(
    rand_bytes: const u8[:],
    token:      const u8[16]&,
    out:        B&,
) -> bool {
    guard rand_bytes.len >= 5 else { return false; }
    let orig_len = out.len;
    let first_byte = (rand_bytes[0] & 0x3F) | 0x40;
    guard out.try_push(first_byte)
        && out.try_append(rand_bytes[1..])
        && out.try_append(token[..]) else {
        out.resize(orig_len, 0);
        return false;
    }
    return true;
}

// ---- Header Protection (AES / ChaCha20) (RFC 9001 Section 5.4) -----------

// Computes up to 8 5-byte QUIC header protection masks in a batch (RFC 9001 §5.4).
fn compute_hp_masks_batch(
    cipher_suite: u16,
    hp_key:       const u8[:],
    samples:      const u8[16][:],
    masks:        u8[5][:],
) -> i64 {
    let n = min(min(samples.len, masks.len), 8);
    guard n > 0 else { return 0; }
    if cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 {
        return quic_internal::compute_batch_aes128_masks(hp_key, samples, masks, n);
    }
    if cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        return quic_internal::compute_batch_aes256_masks(hp_key, samples, masks, n);
    }
    if cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        guard hp_key.len == 32 else { return 0; }
        var k32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(k32);
        for i in 32 { k32[i] = hp_key[i]; }
        for b in n { masks[b] = quic_internal::chacha20_header_protect_mask(k32, samples[b]); }
        return n;
    }
    return 0;
}

// Applies header protection mask to packet header and packet number field (RFC 9001 Section 5.4.1).
fn apply_header_protection(pkt: u8[:], pn_offset: u32, pn_len: u8, hp_mask: const u8[5]&) {
    guard pkt.len > 0 && pn_len >= 1 && pn_len <= 4 else { return; }
    let pn_end = (pn_offset as u64) + pn_len;
    guard pn_end <= (pkt.len as u64) else { return; }
    let is_long = (pkt[0] & 0x80) != 0;
    quic_internal::toggle_first_byte_protection(pkt, is_long, hp_mask[0]);
    for i in (pn_len as i64) {
        let _ = quic_internal::xor_pn_byte_at(pkt, pn_offset, hp_mask, i);
    }
}

// Removes header protection mask in-place, returning true packet number length and truncated PN.
fn remove_header_protection(pkt: u8[:], pn_offset: u32, hp_mask: const u8[5]&) -> u8, u64 {
    guard pkt.len > 0 else { return 0, 0; }
    let is_long = (pkt[0] & 0x80) != 0;
    quic_internal::toggle_first_byte_protection(pkt, is_long, hp_mask[0]);
    let pn_len: u8 = (pkt[0] & 0x03) + 1;
    let pn_end = (pn_offset as u64) + pn_len;
    if pn_end > (pkt.len as u64) {
        // Revert first byte unmasking on bounds violation
        quic_internal::toggle_first_byte_protection(pkt, is_long, hp_mask[0]);
        return 0, 0;
    }
    var trunc_pn: u64 = 0;

    for i in (pn_len as i64) {
        let unmasked = quic_internal::xor_pn_byte_at(pkt, pn_offset, hp_mask, i);
        trunc_pn = (trunc_pn << 8) | unmasked;
    }
    return pn_len, trunc_pn;
}

// Reconstructs full 62-bit packet number from truncated wire representation (RFC 9000 Appendix A.3).
// Returns (reconstructed_pn, ok). If reconstructed PN exceeds 2^62 - 1 or pn_len is invalid, ok is false.
//
// Example:
//   largest_acked_pn = 100, truncated_pn = 101, pn_len = 1
//   returns: 101, ok = true
fn decode_packet_number_checked(largest_acked_pn: u64, truncated_pn: u64, pn_len: u8) -> u64, bool {
    guard pn_len >= 1 && pn_len <= 4 else { return truncated_pn, false; }
    guard largest_acked_pn <= rfc::QUIC_MAX_PN else { return 0, false; }
    guard truncated_pn <= rfc::QUIC_MAX_PN else { return 0, false; }

    let pn_nbits = (pn_len as u64) << 3;
    let pn_win = (1 as u64) << pn_nbits;
    guard truncated_pn < pn_win else { return 0, false; }
    guard 0xFFFFFFFFFFFFFFFF - largest_acked_pn >= 1 else { return 0, false; }
    let expected_pn = largest_acked_pn + 1;
    let pnhwin = pn_win >> 1;
    let pn_mask = pn_win - 1;
    let inv_mask = ~pn_mask;
    let high_bits = expected_pn & inv_mask;
    let candidate_pn = high_bits | truncated_pn;
    let win_limit = rfc::QUIC_PN_LIMIT - pn_win;

    if expected_pn >= pnhwin {
        let lower_bound = expected_pn - pnhwin;
        if candidate_pn <= lower_bound && candidate_pn < win_limit {
            let res = candidate_pn + pn_win;
            return res, res <= rfc::QUIC_MAX_PN;
        }
    }
    if 0xFFFFFFFFFFFFFFFF - expected_pn >= pnhwin {
        let upper_bound = expected_pn + pnhwin;
        if candidate_pn > upper_bound && candidate_pn >= pn_win {
            let res = candidate_pn - pn_win;
            return res, res <= rfc::QUIC_MAX_PN;
        }
    }
    return candidate_pn, candidate_pn <= rfc::QUIC_MAX_PN;
}

// Reconstructs full 62-bit packet number from truncated wire representation (RFC 9000 Appendix A.3).
//
// Example:
//   largest_acked_pn = 100, truncated_pn = 101, pn_len = 1
//   returns: 101
fn decode_packet_number(largest_acked_pn: u64, truncated_pn: u64, pn_len: u8) -> u64 {
    guard pn_len >= 1 && pn_len <= 4 else { return truncated_pn; }
    let pn, _ = decode_packet_number_checked(largest_acked_pn, truncated_pn, pn_len);
    return pn;
}

// ---- Path State & Anti-Amplification 3x Limit (RFC 9000 Section 8.1) -----

struct PathState {
    remote_ip:      u8[16] = [0; 16],
    remote_port:    u16    = 0,
    bytes_received: u64    = 0,
    bytes_sent:     u64    = 0,
    is_validated:   bool   = false,
}

fn new_path_state(ip: const u8[16]&, port: u16, validated: bool = false) -> PathState {
    var p = PathState { remote_port: port, is_validated: validated, .. };
    for i in 16 { p.remote_ip[i] = ip[i]; }
    return p;
}

// Validates whether server can send additional bytes on path under 3x Anti-Amplification rule.
fn can_send(path: const PathState&, packet_bytes: u64) -> bool {
    if path.is_validated {
        return true;
    }
    let max_allow = if path.bytes_received > quic_internal::PATH_AMPLIFICATION_CAP {
        0xFFFFFFFFFFFFFFFF
    } else {
        3 * path.bytes_received
    };
    if 0xFFFFFFFFFFFFFFFF - path.bytes_sent < packet_bytes {
        return false;
    }
    let next_sent = path.bytes_sent + packet_bytes;
    return next_sent <= max_allow;
}

fn on_bytes_received(path: PathState&, bytes: u64) {
    path.bytes_received = core::add_sat_u64(path.bytes_received, bytes);
}

fn on_bytes_sent(path: PathState&, bytes: u64) {
    path.bytes_sent = core::add_sat_u64(path.bytes_sent, bytes);
}

fn validate(path: PathState&) {
    path.is_validated = true;
}

// ---- Stream & Crypto Interval Reassembly Buffer --------------------------

struct Interval {
    start: u64 = 0,
    end:   u64 = 0, // [start, end)
}

struct SegmentedArena {
    chunks:           u8[..16384] = [],
    allocated_chunks: i32         = 0,
    data_len:         i64         = 0,
}

struct ReassemblyBuffer {
    intervals:       Interval[..64] = [],
    consumed_offset: u64            = 0,
    max_data_limit:  u64            = 1048576,
    final_size:      u64            = 0xFFFFFFFFFFFFFFFF,
    fin_received:    bool           = false,
    arena:           SegmentedArena = SegmentedArena { .. },
}

fn new_reassembly_buffer(max_flow_limit: u64 = 1048576) -> ReassemblyBuffer {
    return ReassemblyBuffer { max_data_limit: max_flow_limit, .. };
}

// Inserts incoming STREAM or CRYPTO fragment, enforcing flow control, FIN, and SegmentedArena bounds.
fn insert_fragment(
    buf:     ReassemblyBuffer&,
    offset:  u64,
    payload: const u8[:],
    is_fin:  bool,
) -> bool {
    guard payload.len >= 0 else { return false; }
    let plen_u64 = payload.len as u64;
    guard 0xFFFFFFFFFFFFFFFF - offset >= plen_u64 else { return false; }
    let frag_end = offset + plen_u64;
    guard frag_end <= rfc::QUIC_VARINT_MAX && frag_end <= buf.max_data_limit else {
        return false; // QUIC_ERR_FLOW_CONTROL
    }

    if buf.fin_received && frag_end > buf.final_size {
        return false; // QUIC_ERR_FINAL_SIZE: data exceeds already established final size
    }

    if is_fin {
        guard quic_internal::validate_fin_constraints(buf, frag_end) else { return false; }
    }

    if frag_end <= buf.consumed_offset {
        if is_fin {
            buf.fin_received = true;
            buf.final_size = frag_end;
        }
        return true; // Duplicate of already consumed stream data
    }

    let eff_start = max(offset, buf.consumed_offset);
    let needed_len = frag_end - buf.consumed_offset;

    guard needed_len <= quic_internal::ARENA_MAX_BYTES else { return false; }
    var next_intervals = buf.intervals;
    guard quic_internal::merge_reassembly_interval(next_intervals, eff_start, frag_end) else { return false; }
    guard quic_internal::arena_ensure_bytes(buf.arena, needed_len) else { return false; }

    // RFC 9000 Section 2.2: Sending and Receiving Data - Preserve already received stream bytes on overlap.
    quic_internal::arena_write_uncovered_gaps(
        buf.arena,
        buf.intervals,
        buf.consumed_offset,
        offset,
        payload,
        eff_start,
        frag_end,
    );
    buf.intervals = next_intervals;

    if is_fin {
        buf.fin_received = true;
        buf.final_size = frag_end;
    }
    return true;
}

// Reads contiguous in-order stream bytes from buffer head into out.
// If max_bytes >= 0, limits read to at most max_bytes without discarding unread bytes.
fn read_contiguous<B>(buf: ReassemblyBuffer&, out: B&, max_bytes: i64 = -1) -> u64 {
    guard buf.intervals.len > 0 else { return 0; }
    guard buf.intervals[0].start == buf.consumed_offset else { return 0; }

    let avail_end = buf.intervals[0].end;
    let total_avail = (avail_end - buf.consumed_offset) as i64;
    guard total_avail > 0 && total_avail <= (buf.arena.chunks.len as i64) else { return 0; }
    let avail_out = out.cap - out.len;
    guard avail_out > 0 else { return 0; }

    var take_bytes = min(total_avail, avail_out);
    if max_bytes >= 0 {
        take_bytes = min(take_bytes, max_bytes);
    }
    guard take_bytes > 0 else { return 0; }

    out.append(buf.arena.chunks[0..take_bytes]);
    buf.consumed_offset += take_bytes as u64;

    if take_bytes == total_avail {
        buf.intervals.remove_at(0);
    } else {
        buf.intervals[0].start = buf.consumed_offset;
    }

    quic_internal::arena_consume_front(buf.arena, take_bytes);
    return take_bytes as u64;
}
