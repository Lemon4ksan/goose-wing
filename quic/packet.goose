// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// QUIC Transport Framing, Packet Headers, Header Protection & Stream Reassembly (RFC 9000, RFC 9001).
// Implements VarInt codecs, Long/Short header parsers, AES/ChaCha Header Protection,
// packet number reconstruction, path anti-amplification 3x limits, and zero-heap reassembler.
namespace wing;

import std;
import core from "..";

// ---- 1. constants and error codes (rfc 9000 section 20) ---------------------

const QUIC_VERSION_1: u32 = 0x00000001;
const QUIC_VERSION_NEGOTIATION: u32 = 0x00000000;
const QUIC_MIN_INITIAL_DATAGRAM_LEN: u64 = 1200; // RFC 9000 Section 8.1
const QUIC_MAX_CID_LEN: u8 = 20;

// QUIC Transport Error Codes (RFC 9000 Section 20.1)
const QUIC_ERR_NO_ERROR: u64 = 0x00;
const QUIC_ERR_INTERNAL: u64 = 0x01;
const QUIC_ERR_CONNECTION_REFUSED: u64 = 0x02;
const QUIC_ERR_FLOW_CONTROL: u64 = 0x03;
const QUIC_ERR_STREAM_LIMIT: u64 = 0x04;
const QUIC_ERR_STREAM_STATE: u64 = 0x05;
const QUIC_ERR_FINAL_SIZE: u64 = 0x06;
const QUIC_ERR_FRAME_ENCODING: u64 = 0x07;
const QUIC_ERR_TRANSPORT_PARAMETER: u64 = 0x08;
const QUIC_ERR_CONNECTION_ID_LIMIT: u64 = 0x09;
const QUIC_ERR_PROTOCOL_VIOLATION: u64 = 0x0A;
const QUIC_ERR_INVALID_TOKEN: u64 = 0x0B;
const QUIC_ERR_APPLICATION_ERROR: u64 = 0x0C;
const QUIC_ERR_CRYPTO_BUFFER_EXCEEDED: u64 = 0x0D;
const QUIC_ERR_KEY_UPDATE_ERROR: u64 = 0x0E;
const QUIC_ERR_AEAD_LIMIT_REACHED: u64 = 0x0F;
const QUIC_ERR_NO_VIABLE_PATH: u64 = 0x10;

// Frame Types (RFC 9000 Section 19)
const QUIC_FRAME_PADDING: u64 = 0x00;
const QUIC_FRAME_PING: u64 = 0x01;
const QUIC_FRAME_ACK: u64 = 0x02;
const QUIC_FRAME_ACK_ECN: u64 = 0x03;
const QUIC_FRAME_RESET_STREAM: u64 = 0x04;
const QUIC_FRAME_STOP_SENDING: u64 = 0x05;
const QUIC_FRAME_CRYPTO: u64 = 0x06;
const QUIC_FRAME_NEW_TOKEN: u64 = 0x07;
const QUIC_FRAME_STREAM_BASE: u64 = 0x08; // 0x08..0x0F
const QUIC_FRAME_MAX_DATA: u64 = 0x10;
const QUIC_FRAME_MAX_STREAM_DATA: u64 = 0x11;
const QUIC_FRAME_MAX_STREAMS_BIDI: u64 = 0x12;
const QUIC_FRAME_MAX_STREAMS_UNI: u64 = 0x13;
const QUIC_FRAME_DATA_BLOCKED: u64 = 0x14;
const QUIC_FRAME_STREAM_DATA_BLOCKED: u64 = 0x15;
const QUIC_FRAME_STREAMS_BLOCKED_BIDI: u64 = 0x16;
const QUIC_FRAME_STREAMS_BLOCKED_UNI: u64 = 0x17;
const QUIC_FRAME_NEW_CONNECTION_ID: u64 = 0x18;
const QUIC_FRAME_RETIRE_CONNECTION_ID: u64 = 0x19;
const QUIC_FRAME_PATH_CHALLENGE: u64 = 0x1A;
const QUIC_FRAME_PATH_RESPONSE: u64 = 0x1B;
const QUIC_FRAME_CONNECTION_CLOSE: u64 = 0x1C;
const QUIC_FRAME_CONNECTION_CLOSE_APP: u64 = 0x1D;
const QUIC_FRAME_HANDSHAKE_DONE: u64 = 0x1E;
const QUIC_FRAME_DATAGRAM: u64 = 0x30;            // RFC 9221 Section 3: DATAGRAM without Length
const QUIC_FRAME_DATAGRAM_LEN: u64 = 0x31;        // RFC 9221 Section 3: DATAGRAM with Length

// ---- 2. variable-length integer codec (rfc 9000 section 16) ----------------

// Returns byte length (1, 2, 4, 8) indicated by 2-bit prefix.
inline fn quic_varint_len(first_byte: u8) -> u8 {
    return (1 as u8) << ((first_byte >> 6) & 0x03);
}

// Encodes a 62-bit unsigned integer into big-endian wire format using core/io.
fn quic_encode_varint<B>(out: B&, val: u64) -> bool {
    guard val <= 0x3FFFFFFFFFFFFFFF else { return false; }

    if val <= 63 {
        out.push(val as u8);
        return true;
    }
    if val <= 16383 {
        core::append_u16_be(out, (0x4000 | (val & 0x3FFF)) as u16);
        return true;
    }
    if val <= 1073741823 {
        core::append_u32_be(out, (0x80000000 | (val & 0x3FFFFFFF)) as u32);
        return true;
    }

    core::append_u64_be(out, 0xC000000000000000 | (val & 0x3FFFFFFFFFFFFFFF));
    return true;
}

// Decodes a QUIC variable-length integer directly from a SliceReader.
fn quic_decode_varint_reader(r: core::SliceReader&) -> u64, bool {
    guard !r.is_eof() else { return 0, false; }
    let first, ok = r.peek();
    guard ok else { return 0, false; }

    let vlen = quic_varint_len(first);
    guard r.remaining() >= vlen else { return 0, false; }

    if vlen == 1 {
        let b, _ = r.read_u8();
        return (b & 0x3F), true;
    }
    if vlen == 2 {
        let v16, _ = r.read_u16_be();
        return (v16 & 0x3FFF), true;
    }
    if vlen == 4 {
        let v32, _ = r.read_u32_be();
        return (v32 & 0x3FFFFFFF), true;
    }
    if vlen == 8 {
        let v64, _ = r.read_u64_be();
        return (v64 & 0x3FFFFFFFFFFFFFFF), true;
    }
    return 0, false;
}

// Decodes a variable-length integer from big-endian wire format.
fn quic_decode_varint(src: const u8[:], offset: u64) -> u64, u64, bool {
    guard offset < (src.len as u64) else { return 0, offset, false; }
    var r = core::new_slice_reader(src[(offset as i64)..]);
    let val, ok = quic_decode_varint_reader(r);
    guard ok else { return 0, offset, false; }
    guard (0xFFFFFFFFFFFFFFFF - offset) >= (r.cursor as u64) else { return 0, offset, false; }
    return val, offset + (r.cursor as u64), true;
}

// Stream identifier classification helpers (RFC 9000 Section 2.1)
inline fn quic_is_client_stream(id: u64) -> bool { return (id & 0x01) == 0; }
inline fn quic_is_server_stream(id: u64) -> bool { return (id & 0x01) != 0; }
inline fn quic_is_bidi_stream(id: u64) -> bool { return (id & 0x02) == 0; }
inline fn quic_is_uni_stream(id: u64) -> bool { return (id & 0x02) != 0; }

// ---- 3. packet header parsing & formatting (rfc 9000 section 17) ------------

enum QuicHeaderType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    OneRtt,
    VersionNegotiation,
}

struct QuicHeader {
    header_type: QuicHeaderType = QuicHeaderType.OneRtt,
    version: u32 = QUIC_VERSION_1,
    dcid: u8[..20] = [],
    scid: u8[..20] = [],
    token: u8[..512] = [],
    payload_length: u64 = 0,
    packet_number: u64 = 0,
    pn_offset: u32 = 0,
    pn_length: u8 = 0,
    key_phase: bool = false,
    spin_bit: bool = false,
    header_len: u32 = 0,
}

// Parses unmasked QUIC Long or Short header up to the payload boundary.
fn parse_quic_header(src: const u8[:], dcid_len_short: u8 = 0) -> QuicHeader, bool {
    var hdr = QuicHeader {};
    guard src.len > 0 else { return hdr, false; }

    let first = src[0];
    let is_long = (first & 0x80) != 0;

    if is_long {
        guard src.len >= 5 else { return hdr, false; }
        let ver = ((src[1] as u32) << 24) | ((src[2] as u32) << 16) |
                  ((src[3] as u32) << 8) | src[4];
        hdr.version = ver;

        if ver == QUIC_VERSION_NEGOTIATION {
            hdr.header_type = QuicHeaderType.VersionNegotiation;
            guard src.len >= 7 else { return hdr, false; }
            let dlen = src[5];
            guard dlen <= QUIC_MAX_CID_LEN && (7 + dlen) <= src.len else { return hdr, false; }
            hdr.dcid.append(src[6..6 + dlen]);
            let slen = src[6 + dlen];
            guard slen <= QUIC_MAX_CID_LEN && (7 + dlen + slen) <= src.len else { return hdr, false; }
            hdr.scid.append(src[7 + dlen..7 + dlen + slen]);

            // RFC 9000 §17.2.1: Version Negotiation packet MUST contain one or more 32-bit versions
            let rem_versions = src.len - (7 + dlen + slen);
            guard rem_versions >= 4 && (rem_versions & 3) == 0 else { return hdr, false; }

            hdr.header_len = 7 + dlen + slen;
            return hdr, true;
        }

        // Fixed bit (0x40) MUST be set for non-Version Negotiation Long Headers (RFC 9000 §17.2)
        guard (first & 0x40) != 0 else { return hdr, false; }

        let long_type = (first >> 4) & 0x03;
        hdr.header_type = if long_type == 0 {
            QuicHeaderType.Initial
        } else if long_type == 1 {
            QuicHeaderType.ZeroRtt
        } else if long_type == 2 {
            QuicHeaderType.Handshake
        } else {
            QuicHeaderType.Retry
        };

        // Reserved bits check (RFC 9000 §17.2): For Initial, 0-RTT, and Handshake,
        // bits 2 and 3 of byte 0 (mask 0x0C) are reserved and MUST be 0.
        if hdr.header_type != QuicHeaderType.Retry {
            guard (first & 0x0C) == 0 else { return hdr, false; }
        }

        var off: u64 = 5;
        guard off < (src.len as u64) else { return hdr, false; }
        let dlen = src[off]; off++;
        guard dlen <= QUIC_MAX_CID_LEN && (off + dlen) <= (src.len as u64) else { return hdr, false; }
        hdr.dcid.append(src[off..off + dlen]);
        off += dlen;

        guard off < (src.len as u64) else { return hdr, false; }
        let slen = src[off]; off++;
        guard slen <= QUIC_MAX_CID_LEN && (off + slen) <= (src.len as u64) else { return hdr, false; }
        hdr.scid.append(src[off..off + slen]);
        off += slen;

        if hdr.header_type == QuicHeaderType.Initial {
            let tok_len, next_tok, ok_tok = quic_decode_varint(src, off);
            guard ok_tok && (next_tok + tok_len) <= (src.len as u64) && tok_len <= (hdr.token.cap as u64) else { return hdr, false; }
            if tok_len > 0 {
                hdr.token.append(src[next_tok..next_tok + tok_len]);
            }
            off = next_tok + tok_len;
        }

        if hdr.header_type == QuicHeaderType.Retry {
            hdr.header_len = off as u32;
            return hdr, true;
        }

        let plen, next_plen, ok_plen = quic_decode_varint(src, off);
        guard ok_plen else { return hdr, false; }
        hdr.payload_length = plen;
        hdr.pn_offset = next_plen as u32;
        hdr.pn_length = (first & 0x03) + 1;
        guard plen >= hdr.pn_length else { return hdr, false; }
        guard (0xFFFFFFFFFFFFFFFF - next_plen) >= hdr.pn_length && (next_plen + hdr.pn_length) <= (src.len as u64) else { return hdr, false; }
        hdr.header_len = (next_plen + hdr.pn_length) as u32;
        return hdr, true;
    }

    // Short Header (1-RTT)
    // Fixed bit (0x40) MUST be set (RFC 9000 §17.3)
    guard (first & 0x40) != 0 else { return hdr, false; }
    // Reserved bits check (RFC 9000 §17.3): Bits 3 and 4 of byte 0 (mask 0x18) MUST be 0
    guard (first & 0x18) == 0 else { return hdr, false; }
    guard dcid_len_short <= QUIC_MAX_CID_LEN else { return hdr, false; }
    hdr.header_type = QuicHeaderType.OneRtt;
    hdr.spin_bit = (first & 0x20) != 0;
    hdr.key_phase = (first & 0x04) != 0;

    var off: u64 = 1;
    guard (off + dcid_len_short) <= (src.len as u64) else { return hdr, false; }
    if dcid_len_short > 0 {
        hdr.dcid.append(src[off..off + dcid_len_short]);
        off += dcid_len_short;
    }
    hdr.pn_offset = off as u32;
    hdr.pn_length = (first & 0x03) + 1;
    guard (off + hdr.pn_length) <= (src.len as u64) else { return hdr, false; }
    hdr.header_len = (off + hdr.pn_length) as u32;
    return hdr, true;
}

// Encodes a QUIC Long or Short header in unmasked form into out buffer.
fn encode_quic_header<B>(out: B&, hdr: const QuicHeader&, pn_len: u8) -> bool {
    guard pn_len >= 1 && pn_len <= 4 else { return false; }
    guard hdr.dcid.len <= QUIC_MAX_CID_LEN && hdr.scid.len <= QUIC_MAX_CID_LEN else { return false; }
    let pn_bits = (pn_len - 1) & 0x03;

    if hdr.header_type != QuicHeaderType.OneRtt {
        // Long Header
        var b0: u8 = 0xC0 | pn_bits;
        match hdr.header_type {
            Initial => {},
            ZeroRtt => { b0 |= 0x10; },
            Handshake => { b0 |= 0x20; },
            Retry => { b0 |= 0x30; },
            _ => { return false; },
        }
        out.push(b0);
        out.push(((hdr.version >> 24) & 0xFF) as u8);
        out.push(((hdr.version >> 16) & 0xFF) as u8);
        out.push(((hdr.version >> 8) & 0xFF) as u8);
        out.push((hdr.version & 0xFF) as u8);

        out.push(hdr.dcid.len as u8);
        out.append(hdr.dcid[..]);
        out.push(hdr.scid.len as u8);
        out.append(hdr.scid[..]);

        if hdr.header_type == QuicHeaderType.Initial {
            guard quic_encode_varint(out, hdr.token.len as u64) else { return false; }
            if hdr.token.len > 0 {
                out.append(hdr.token[..]);
            }
        }

        if hdr.header_type != QuicHeaderType.Retry {
            guard quic_encode_varint(out, hdr.payload_length) else { return false; }
            guard encode_packet_number(out, hdr.packet_number, pn_len) else { return false; }
        }
        return true;
    }

    // Short Header (1-RTT)
    var b0: u8 = 0x40 | pn_bits;
    if hdr.spin_bit { b0 |= 0x20; }
    if hdr.key_phase { b0 |= 0x04; }
    out.push(b0);

    if hdr.dcid.len > 0 {
        out.append(hdr.dcid[..]);
    }
    guard encode_packet_number(out, hdr.packet_number, pn_len) else { return false; }
    return true;
}

// ---- 4. header protection (aes / chacha20) (rfc 9001 section 5.4) -----------

// Generates 5-byte header protection mask using AES-128-ECB (RFC 9001 Section 5.4.3).
fn aes128_header_protect_mask(hp_key: const u8[16]&, sample: const u8[16]&) -> u8[5] {
    let ks = core::aes128_key_schedule(hp_key);
    let enc = core::aes128_encrypt_block(ks, sample);
    return [enc[0], enc[1], enc[2], enc[3], enc[4]];
}

// Generates 5-byte header protection mask using AES-256-ECB.
fn aes256_header_protect_mask(hp_key: const u8[32]&, sample: const u8[16]&) -> u8[5] {
    let ks = core::aes256_key_schedule(hp_key);
    let enc = core::aes_encrypt_block(ks, sample);
    return [enc[0], enc[1], enc[2], enc[3], enc[4]];
}

// Generates 5-byte header protection mask using ChaCha20 (RFC 9001 Section 5.4.4).
fn chacha20_header_protect_mask(hp_key: const u8[32]&, sample: const u8[16]&) -> u8[5] {
    let counter = core::load_u32_le(sample[..], 0);
    var nonce12: u8[12] = [0; 12];
    for i in 12 { nonce12[i] = sample[4 + i]; }
    let blk = core::chacha20_block(hp_key, counter, nonce12);
    return [blk[0], blk[1], blk[2], blk[3], blk[4]];
}

// Applies header protection mask to packet header and packet number field (RFC 9001 Section 5.4.1).
fn apply_header_protection(pkt: u8[:], pn_offset: u32, pn_len: u8, hp_mask: const u8[5]&) {
    guard pkt.len > 0 && pn_len >= 1 && pn_len <= 4 else { return; }
    guard (pn_offset as u64) + pn_len <= (pkt.len as u64) else { return; }
    let is_long = (pkt[0] & 0x80) != 0;
    if is_long {
        pkt[0] ^= (hp_mask[0] & 0x0F);
    } else {
        pkt[0] ^= (hp_mask[0] & 0x1F);
    }
    for i in (pn_len as i64) {
        let idx = pn_offset + (i as u32);
        pkt[idx] ^= hp_mask[1 + (i as u32)];
    }
}

// Removes header protection mask in-place, returning true packet number length and truncated PN.
fn remove_header_protection(pkt: u8[:], pn_offset: u32, hp_mask: const u8[5]&) -> u8, u64 {
    guard pkt.len > 0 else { return 0, 0; }
    let is_long = (pkt[0] & 0x80) != 0;
    if is_long {
        pkt[0] ^= (hp_mask[0] & 0x0F);
    } else {
        pkt[0] ^= (hp_mask[0] & 0x1F);
    }
    let pn_len: u8 = (pkt[0] & 0x03) + 1;
    if (pn_offset as u64) + pn_len > (pkt.len as u64) {
        // Revert first byte unmasking on bounds violation
        if is_long {
            pkt[0] ^= (hp_mask[0] & 0x0F);
        } else {
            pkt[0] ^= (hp_mask[0] & 0x1F);
        }
        return 0, 0;
    }
    var trunc_pn: u64 = 0;

    for i in (pn_len as i64) {
        let idx = pn_offset + (i as u32);
        pkt[idx] ^= hp_mask[1 + (i as u32)];
        trunc_pn = (trunc_pn << 8) | pkt[idx];
    }
    return pn_len, trunc_pn;
}

// Encodes truncated packet number (1 to 4 bytes) in big-endian order (RFC 9000 Appendix A.2).
fn encode_packet_number<B>(out: B&, pn: u64, pn_len: u8) -> bool {
    guard pn_len >= 1 && pn_len <= 4 else { return false; }
    if pn_len == 1 {
        out.push((pn & 0xFF) as u8);
    } else if pn_len == 2 {
        out.push(((pn >> 8) & 0xFF) as u8);
        out.push((pn & 0xFF) as u8);
    } else if pn_len == 3 {
        out.push(((pn >> 16) & 0xFF) as u8);
        out.push(((pn >> 8) & 0xFF) as u8);
        out.push((pn & 0xFF) as u8);
    } else {
        out.push(((pn >> 24) & 0xFF) as u8);
        out.push(((pn >> 16) & 0xFF) as u8);
        out.push(((pn >> 8) & 0xFF) as u8);
        out.push((pn & 0xFF) as u8);
    }
    return true;
}

const QUIC_MAX_PN: u64 = 0x3FFFFFFFFFFFFFFF; // 2^62 - 1 (RFC 9000 Section 17.1)
const QUIC_PN_LIMIT: u64 = (1 as u64) << 62; // 2^62

// Reconstructs full 62-bit packet number from truncated wire representation (RFC 9000 Appendix A.3).
// Returns (reconstructed_pn, ok). If reconstructed PN exceeds 2^62 - 1 or pn_len is invalid, ok is false.
fn decode_packet_number_checked(largest_acked_pn: u64, truncated_pn: u64, pn_len: u8) -> u64, bool {
    guard pn_len >= 1 && pn_len <= 4 else { return truncated_pn, false; }
    guard largest_acked_pn <= QUIC_MAX_PN else { return 0, false; }
    guard truncated_pn <= QUIC_MAX_PN else { return 0, false; }

    let pn_nbits: u64 = (pn_len as u64) * 8;
    guard (0xFFFFFFFFFFFFFFFF - largest_acked_pn) >= 1 else { return 0, false; }
    let expected_pn: u64 = largest_acked_pn + 1;
    let pn_win: u64 = (1 as u64) << pn_nbits;
    let pnhwin: u64 = pn_win / 2;
    let pn_mask: u64 = pn_win - 1;

    let candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

    if expected_pn >= pnhwin && candidate_pn <= (expected_pn - pnhwin) && candidate_pn < (QUIC_PN_LIMIT - pn_win) {
        let res = candidate_pn + pn_win;
        return res, res <= QUIC_MAX_PN;
    }
    if (0xFFFFFFFFFFFFFFFF - expected_pn) >= pnhwin && candidate_pn > (expected_pn + pnhwin) && candidate_pn >= pn_win {
        let res = candidate_pn - pn_win;
        return res, res <= QUIC_MAX_PN;
    }
    return candidate_pn, candidate_pn <= QUIC_MAX_PN;
}

// Reconstructs full 62-bit packet number from truncated wire representation (RFC 9000 Appendix A.3).
fn decode_packet_number(largest_acked_pn: u64, truncated_pn: u64, pn_len: u8) -> u64 {
    guard pn_len >= 1 && pn_len <= 4 else { return truncated_pn; }
    let pn, _ = decode_packet_number_checked(largest_acked_pn, truncated_pn, pn_len);
    return pn;
}

// ---- 5. path state and anti-amplification 3x limit (rfc 9000 section 8.1) ---

struct PathState {
    remote_ip: u8[16] = [0; 16],
    remote_port: u16 = 0,
    bytes_received: u64 = 0,
    bytes_sent: u64 = 0,
    is_validated: bool = false,
}

fn new_path_state(ip: const u8[16]&, port: u16, validated: bool = false) -> PathState {
    var p = PathState { remote_port: port, is_validated: validated, .. };
    for i in 16 { p.remote_ip[i] = ip[i]; }
    return p;
}

// Validates whether server can send additional bytes on path under 3x Anti-Amplification rule.
fn can_send_on_path(path: const PathState&, packet_bytes: u64) -> bool {
    if path.is_validated {
        return true;
    }
    let max_allow = if path.bytes_received > (0xFFFFFFFFFFFFFFFF / 3) {
        0xFFFFFFFFFFFFFFFF
    } else {
        3 * path.bytes_received
    };
    if (0xFFFFFFFFFFFFFFFF - path.bytes_sent) < packet_bytes {
        return false;
    }
    return (path.bytes_sent + packet_bytes) <= max_allow;
}

fn on_path_bytes_received(path: PathState&, bytes: u64) {
    path.bytes_received += bytes;
}

fn on_path_bytes_sent(path: PathState&, bytes: u64) {
    path.bytes_sent += bytes;
}

fn validate_path(path: PathState&) {
    path.is_validated = true;
}

// ---- 6. stream / crypto interval reassembly buffer --------------------------

struct Interval {
    start: u64 = 0,
    end: u64 = 0, // [start, end)
}

struct ReassemblyBuffer {
    intervals: Interval[..64] = [],
    consumed_offset: u64 = 0,
    max_data_limit: u64 = 1048576,
    final_size: u64 = 0xFFFFFFFFFFFFFFFF,
    fin_received: bool = false,
    data_slab: u8[>..<] = [], // Must be last!
}

fn new_reassembly_buffer(max_flow_limit: u64 = 1048576) -> ReassemblyBuffer {
    return ReassemblyBuffer { max_data_limit: max_flow_limit, .. };
}

// Merges a new interval [new_start, new_end) into sorted non-overlapping intervals array.
fn merge_reassembly_interval(intervals: Interval[..64]&, new_start: u64, new_end: u64) -> bool {
    guard new_start < new_end else { return true; }
    var cur_s = new_start;
    var cur_e = new_end;
    var i = 0;

    while i < intervals.len {
        let it = intervals[i];
        if cur_e < it.start {
            if intervals.len < intervals.cap {
                intervals.insert_at(i, Interval { start: cur_s, end: cur_e });
                return true;
            }
            return false;
        }
        if cur_s > it.end {
            i++;
            continue;
        }
        cur_s = if cur_s < it.start { cur_s } else { it.start };
        cur_e = if cur_e > it.end { cur_e } else { it.end };
        intervals.remove_at(i);
    }

    if intervals.len < intervals.cap {
        intervals.push(Interval { start: cur_s, end: cur_e });
        return true;
    }
    return false;
}

// Inserts incoming STREAM or CRYPTO fragment, enforcing flow control and FIN invariants.
fn insert_fragment(
    buf: ReassemblyBuffer&,
    offset: u64,
    payload: const u8[:],
    is_fin: bool,
) -> bool {
    guard (0xFFFFFFFFFFFFFFFF - offset) >= (payload.len as u64) else { return false; }
    let frag_end = offset + (payload.len as u64);
    guard frag_end <= buf.max_data_limit else { return false; } // QUIC_ERR_FLOW_CONTROL

    if buf.fin_received && frag_end > buf.final_size {
        return false; // QUIC_ERR_FINAL_SIZE: data exceeds already established final size
    }

    if is_fin {
        if buf.fin_received && buf.final_size != frag_end {
            return false; // QUIC_ERR_FINAL_SIZE
        }
        if frag_end < buf.consumed_offset {
            return false; // QUIC_ERR_FINAL_SIZE
        }
        for i in buf.intervals.len {
            if buf.intervals[i].end > frag_end {
                return false; // QUIC_ERR_FINAL_SIZE: data already buffered beyond declared final size
            }
        }
        buf.fin_received = true;
        buf.final_size = frag_end;
    }

    if frag_end <= buf.consumed_offset {
        return true; // Duplicate of already consumed stream data
    }

    let eff_start = if offset < buf.consumed_offset { buf.consumed_offset } else { offset };
    let payload_skip = (eff_start - offset) as i64;
    let needed_len = frag_end - buf.consumed_offset;

    if (buf.data_slab.len as u64) < needed_len {
        buf.data_slab.resize(needed_len as i64, 0);
    }

    for idx in payload.len - payload_skip {
        let slab_idx = (eff_start - buf.consumed_offset) as i64 + idx;
        buf.data_slab[slab_idx] = payload[payload_skip + idx];
    }

    guard merge_reassembly_interval(buf.intervals, eff_start, frag_end) else { return false; }
    return true;
}

// Reads contiguous in-order stream bytes from buffer head into out.
fn read_contiguous<B>(buf: ReassemblyBuffer&, out: B&) -> u64 {
    guard buf.intervals.len > 0 else { return 0; }
    guard buf.intervals[0].start == buf.consumed_offset else { return 0; }

    let avail_end = buf.intervals[0].end;
    let take_bytes = (avail_end - buf.consumed_offset) as i64;
    guard take_bytes > 0 && take_bytes <= (buf.data_slab.len as i64) else { return 0; }

    out.append(buf.data_slab[0..take_bytes]);
    buf.consumed_offset = avail_end;
    buf.intervals.remove_at(0);

    let remaining = (buf.data_slab.len as i64) - take_bytes;
    for i in remaining {
        buf.data_slab[i] = buf.data_slab[take_bytes + i];
    }
    buf.data_slab.resize(remaining, 0);
    return take_bytes as u64;
}

// ---- 6. unreliable datagram extension (rfc 9221) ----------------------------

// Encodes an RFC 9221 QUIC DATAGRAM frame into buffer.
// If with_length is true (default), encodes frame type 0x31 with VarInt length prefix.
// If with_length is false, encodes frame type 0x30 consuming remainder of packet.
fn encode_quic_datagram_frame<B>(out: B&, payload: const u8[:], with_length: bool = true) -> bool {
    if with_length {
        guard quic_encode_varint(out, QUIC_FRAME_DATAGRAM_LEN) else { return false; }
        guard quic_encode_varint(out, payload.len as u64) else { return false; }
    } else {
        guard quic_encode_varint(out, QUIC_FRAME_DATAGRAM) else { return false; }
    }
    out.append(payload);
    return true;
}

// Decodes an RFC 9221 QUIC DATAGRAM frame from wire slice.
fn decode_quic_datagram_frame(src: const u8[:], offset: u64, packet_end: u64 = 0) -> const u8[:], u64, bool {
    guard offset < src.len as u64 else { return "", offset, false; }
    let ftype, off1, ok1 = quic_decode_varint(src, offset);
    guard ok1 else { return "", offset, false; }

    if ftype == QUIC_FRAME_DATAGRAM {
        let eff_end = if packet_end > 0 && packet_end <= src.len as u64 { packet_end } else { src.len as u64 };
        guard off1 <= eff_end else { return "", offset, false; }
        return src[(off1 as i64)..(eff_end as i64)], eff_end, true;
    } else if ftype == QUIC_FRAME_DATAGRAM_LEN {
        let dlen, off2, ok2 = quic_decode_varint(src, off1);
        guard ok2 else { return "", offset, false; }
        let limit = if packet_end > 0 && packet_end <= (src.len as u64) { packet_end } else { src.len as u64 };
        guard (0xFFFFFFFFFFFFFFFF - off2) >= dlen && (off2 + dlen) <= limit else { return "", offset, false; }
        let eff_end = off2 + dlen;
        return src[(off2 as i64)..(eff_end as i64)], eff_end, true;
    }
    return "", offset, false;
}
