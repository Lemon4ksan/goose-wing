// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// QUIC Transport Framing, Packet Headers, Header Protection & Stream Reassembly (RFC 9000, RFC 9001).
// Implements VarInt codecs, Long/Short header parsers, AES/ChaCha Header Protection,
// packet number reconstruction, path anti-amplification 3x limits, and zero-heap reassembler.
namespace internal;

import std;
import core from "..";

// ---- Initial Salts & HKDF Label Prefixes (RFC 9001 §5.2, RFC 9369 §3.3) --

// Selects the Initial salt for a QUIC version; empty for unknown versions.
//
// Example:
//   version = 0x6b3343cf -> 20-byte v2 salt, ok via non-empty slice
//   version = 0x0a0a0a0a -> empty slice
fn quic_initial_salt(version: u32) -> const u8[:] {
    if version == rfc::QUIC_VERSION_1 { return rfc::QUIC_V1_INITIAL_SALT[..]; }
    if version == rfc::QUIC_VERSION_2 { return rfc::QUIC_V2_INITIAL_SALT[..]; }
    return "";
}

// Returns the HKDF label prefix for a QUIC version: "quic " (v1) or
// "quicv2 " (v2, RFC 9369 §3.3.2); empty for unknown versions.
fn quic_hkdf_label_prefix(version: u32) -> const u8[:] {
    if version == rfc::QUIC_VERSION_1 { return "quic "; }
    if version == rfc::QUIC_VERSION_2 { return "quicv2 "; }
    return "";
}

// ---- Variable-Length Integer Codec (RFC 9000 Section 16) -----------------

// Returns the wire byte length (1, 2, 4, or 8) of a QUIC Variable-Length Integer from its first byte.
inline fn quic_varint_len(first_byte: u8) -> u8 {
    let tag = (first_byte >> 6) & 0x03;
    return (1 as u8) << tag;
}

inline fn varint_read_2(src: const u8[:], idx: i64, first: u8) -> u64 {
    let hi: u64 = first & 0x3F;
    return (hi << 8) | src[idx + 1];
}

inline fn varint_read_4(src: const u8[:], idx: i64, first: u8) -> u64 {
    let v1 = varint_read_2(src, idx, first);
    let v2 = (v1 << 8) | src[idx + 2];
    return (v2 << 8) | src[idx + 3];
}

inline fn varint_read_8(src: const u8[:], idx: i64, first: u8) -> u64 {
    let v3 = varint_read_4(src, idx, first);
    let v4 = (v3 << 8) | src[idx + 4];
    let v5 = (v4 << 8) | src[idx + 5];
    let v6 = (v5 << 8) | src[idx + 6];
    return (v6 << 8) | src[idx + 7];
}

// Encodes a 62-bit unsigned integer into big-endian wire format using core/io.
fn quic_encode_varint<B>(out: B&, val: u64) -> bool {
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
inline fn quic_decode_varint_cursor(src: const u8[:], idx: i64&) -> u64, bool {
    guard idx >= 0 && idx < src.len else { return 0, false; }
    let first = src[idx];
    let vlen = quic_varint_len(first) as i64;
    let next_idx = idx + vlen;
    guard next_idx <= src.len else { return 0, false; }

    if vlen == 1 {
        let val: u64 = first & 0x3F;
        idx = next_idx;
        return val, true;
    }
    if vlen == 2 {
        let val = varint_read_2(src, idx, first);
        idx = next_idx;
        return val, true;
    }
    if vlen == 4 {
        let val = varint_read_4(src, idx, first);
        idx = next_idx;
        return val, true;
    }
    let val = varint_read_8(src, idx, first);
    idx = next_idx;
    return val, true;
}

// Decodes a variable-length integer from big-endian wire format (RFC 9000 §16).
//
// Example:
//   src = [0x40, 0x25], offset = 0
//   returns: val = 37, next_offset = 2, ok = true
fn quic_decode_varint(src: const u8[:], offset: u64) -> u64, u64, bool {
    guard offset < (src.len as u64) else { return 0, offset, false; }
    var idx = offset as i64;
    let val, ok = quic_decode_varint_cursor(src, idx);
    guard ok else { return 0, offset, false; }
    return val, idx as u64, true;
}

// Stream identifier classification helpers (RFC 9000 Section 2.1)
inline fn quic_is_client_stream(id: u64) -> bool { return (id & 0x01) == 0; }
inline fn quic_is_server_stream(id: u64) -> bool { return (id & 0x01) != 0; }
inline fn quic_is_bidi_stream(id: u64) -> bool { return (id & 0x02) == 0; }
inline fn quic_is_uni_stream(id: u64) -> bool { return (id & 0x02) != 0; }

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

// Parses a Version Negotiation Long Header (RFC 9000 §17.2.1).
//
// Example:
//   src = [0x80, 0x00, 0x00, 0x00, 0x00, 0x04, ...], in_hdr = initial header
//   returns: QuicHeader { header_type: VersionNegotiation, version: 0 }, ok = true
fn parse_quic_version_negotiation(src: const u8[:], in_hdr: QuicHeader) -> QuicHeader, bool {
    var hdr = in_hdr;
    hdr.header_type = QuicHeaderType.VersionNegotiation;
    guard src.len >= 7 else { return hdr, false; }
    let dlen: i64 = src[5];
    let d_end = 6 + dlen;
    let s_start = 7 + dlen;
    guard dlen <= rfc::QUIC_MAX_CID_LEN && s_start <= src.len else { return hdr, false; }
    hdr.dcid.append(src[6..d_end]);
    let slen: i64 = src[d_end];
    let s_end = s_start + slen;
    guard slen <= rfc::QUIC_MAX_CID_LEN && s_end <= src.len else { return hdr, false; }
    hdr.scid.append(src[s_start..s_end]);

    // RFC 9000 §17.2.1: Version Negotiation packet MUST contain one or more 32-bit versions
    let rem_versions = src.len - s_end;
    guard rem_versions >= 4 && (rem_versions & 3) == 0 else { return hdr, false; }

    hdr.header_len = s_end as u32;
    return hdr, true;
}

// Extracts DCID and SCID for Long Headers (RFC 9000 §17.2).
//
// Example:
//   src = [0x04, 1, 2, 3, 4, 0x00], idx = 0
//   returns: true, idx = 6, dcid = [1, 2, 3, 4], scid = []
fn parse_quic_long_cids(
    src:  const u8[:],
    idx:  i64&,
    dcid: u8[..20]&,
    scid: u8[..20]&,
) -> bool {
    let initial_idx = idx;
    guard idx < src.len else { return false; }
    let dlen: i64 = src[idx];
    let d_start = idx + 1;
    let d_end = d_start + dlen;
    guard dlen <= rfc::QUIC_MAX_CID_LEN && d_end <= src.len else {
        idx = initial_idx;
        return false;
    }

    guard d_end < src.len else {
        idx = initial_idx;
        return false;
    }
    let slen: i64 = src[d_end];
    let s_start = d_end + 1;
    let s_end = s_start + slen;
    guard slen <= rfc::QUIC_MAX_CID_LEN && s_end <= src.len else {
        idx = initial_idx;
        return false;
    }

    idx = s_end;
    dcid.append(src[d_start..d_end]);
    scid.append(src[s_start..s_end]);
    return true;
}

// Parses variable-length initial token for Initial packets (RFC 9000 §17.2.2).
//
// Example:
//   src = [0x04, 't', 'o', 'k', 'n'], idx = 0
//   returns: true, idx = 5, token = "tokn"
fn parse_quic_initial_token(src: const u8[:], idx: i64&, token: u8[..512]&) -> bool {
    let initial_idx = idx;
    let tok_len, ok_tok = quic_decode_varint_cursor(src, idx);
    let itok = tok_len as i64;
    let tok_end = idx + itok;
    guard ok_tok && itok >= 0 && tok_end <= src.len && token.try_append(src[idx..tok_end]) else {
        idx = initial_idx;
        return false;
    }
    idx = tok_end;
    return true;
}

// Maps the 2-bit long header Type field to QuicHeaderType for the given QUIC
// version (RFC 9000 §17.2; RFC 9369 §3.2 remaps v2: 0b01=Initial, 0b10=0-RTT,
// 0b11=Handshake, 0b00=Retry). Returns false for unknown versions or when
// two_bits exceeds 0b11.
//
// Example:
//   version = 0x00000001, two_bits = 0b00 -> Initial, true
//   version = 0x6b3343cf, two_bits = 0b01 -> Initial, true
//   version = 0x6b3343cf, two_bits = 0b00 -> Retry, true
fn quic_long_header_type(version: u32, two_bits: u8) -> QuicHeaderType, bool {
    guard two_bits <= 0x03 else { return QuicHeaderType.Retry, false; }
    if version == rfc::QUIC_VERSION_2 {
        if two_bits == 0x01 { return QuicHeaderType.Initial, true; }
        if two_bits == 0x02 { return QuicHeaderType.ZeroRtt, true; }
        if two_bits == 0x03 { return QuicHeaderType.Handshake, true; }
        return QuicHeaderType.Retry, true;
    }
    if version == rfc::QUIC_VERSION_1 {
        if two_bits == 0x00 { return QuicHeaderType.Initial, true; }
        if two_bits == 0x01 { return QuicHeaderType.ZeroRtt, true; }
        if two_bits == 0x02 { return QuicHeaderType.Handshake, true; }
        return QuicHeaderType.Retry, true;
    }
    return QuicHeaderType.Retry, false;
}

inline fn read_version_u32_be(src: const u8[:]) -> u32 {
    let v0: u64 = src[1];
    let v1 = (v0 << 8) | src[2];
    let v2 = (v1 << 8) | src[3];
    let v3 = (v2 << 8) | src[4];
    return v3 as u32;
}

// Decodes a big-endian truncated packet number of 1-4 bytes (RFC 9000 §17.1).
//
// Example:
//   src = [0x01, 0x02], idx = 0, pn_len = 2
//   returns: 0x0102
inline fn decode_unmasked_pn(src: const u8[:], idx: i64, pn_len: i64) -> u64 {
    var pn_val: u64 = 0;
    for i in pn_len {
        pn_val = (pn_val << 8) | src[idx + i];
    }
    return pn_val;
}

// Parses a QUIC Long Header (RFC 9000 §17.2).
//
// Example:
//   src = [0xC0, 0x00, 0x00, 0x00, 0x01, ...], first = 0xC0
//   returns: QuicHeader { header_type: Initial, version: 1 }, ok = true
fn parse_quic_long_header(src: const u8[:], first: u8) -> QuicHeader, bool {
    var hdr = QuicHeader {};
    guard src.len >= 5 else { return hdr, false; }
    let ver = read_version_u32_be(src);
    hdr.version = ver;

    if ver == rfc::QUIC_VERSION_NEGOTIATION {
        return parse_quic_version_negotiation(src, hdr);
    }

    // Fixed bit (0x40) MUST be set for non-Version Negotiation Long Headers (RFC 9000 §17.2)
    guard (first & 0x40) != 0 else { return hdr, false; }

    let type_bits = (first >> 4) & 0x03;
    let ht, ok_ht = quic_long_header_type(ver, type_bits);
    if ok_ht {
        hdr.header_type = ht;
    } else {
        // Unknown version: decode with the v1 Type layout so DCID/SCID stay
        // parseable for Version Negotiation (RFC 9000 §17.2.1).
        let ht1, _ = quic_long_header_type(rfc::QUIC_VERSION_1, type_bits);
        hdr.header_type = ht1;
    }

    // Reserved bits check (RFC 9000 §17.2): For Initial, 0-RTT, and Handshake,
    // bits 2 and 3 of byte 0 (mask 0x0C) are reserved and MUST be 0.
    if hdr.header_type != QuicHeaderType.Retry {
        guard (first & 0x0C) == 0 else { return hdr, false; }
    }

    var idx: i64 = 5;
    guard parse_quic_long_cids(src, idx, hdr.dcid, hdr.scid) else { return hdr, false; }

    if hdr.header_type == QuicHeaderType.Initial {
        guard parse_quic_initial_token(src, idx, hdr.token) else { return hdr, false; }
    }

    if hdr.header_type == QuicHeaderType.Retry {
        hdr.header_len = idx as u32;
        return hdr, true;
    }

    let plen, ok_plen = quic_decode_varint_cursor(src, idx);
    guard ok_plen else { return hdr, false; }
    hdr.payload_length = plen;
    hdr.pn_offset = idx as u32;
    hdr.pn_length = (first & 0x03) + 1;
    let ipn: i64 = hdr.pn_length;
    let hdr_end = idx + ipn;
    guard plen >= hdr.pn_length && hdr_end <= src.len else { return hdr, false; }
    hdr.packet_number = decode_unmasked_pn(src, idx, ipn);
    hdr.header_len = hdr_end as u32;
    return hdr, true;
}

// Parses a Short Header (1-RTT) (RFC 9000 §17.3).
//
// Example:
//   src = [0x40, 0x01, 0x02, 0x03, 0x04, 0x05], first = 0x40, dcid_len_short = 4
//   returns: QuicHeader { header_type: OneRtt, dcid: [1, 2, 3, 4] }, ok = true
fn parse_quic_short_header(
    src:            const u8[:],
    first:          u8,
    dcid_len_short: u8,
) -> QuicHeader, bool {
    var hdr = QuicHeader {};
    // Fixed bit (0x40) MUST be set (RFC 9000 §17.3)
    guard (first & 0x40) != 0 else { return hdr, false; }
    // Reserved bits check (RFC 9000 §17.3): Bits 3 and 4 of byte 0 (mask 0x18) MUST be 0
    guard (first & 0x18) == 0 else { return hdr, false; }
    guard dcid_len_short <= rfc::QUIC_MAX_CID_LEN else { return hdr, false; }
    hdr.header_type = QuicHeaderType.OneRtt;
    hdr.spin_bit = (first & 0x20) != 0;
    hdr.key_phase = (first & 0x04) != 0;

    let dlen: i64 = dcid_len_short;
    var idx: i64 = 1;
    let d_end = idx + dlen;
    guard d_end <= src.len else { return hdr, false; }
    if dlen > 0 {
        hdr.dcid.append(src[idx..d_end]);
        idx = d_end;
    }
    hdr.pn_offset = idx as u32;
    hdr.pn_length = (first & 0x03) + 1;
    let ipn: i64 = hdr.pn_length;
    let hdr_end = idx + ipn;
    guard hdr_end <= src.len else { return hdr, false; }
    hdr.packet_number = decode_unmasked_pn(src, idx, ipn);
    hdr.header_len = hdr_end as u32;
    return hdr, true;
}

// Parses unmasked QUIC Long or Short header up to the payload boundary (RFC 9000 §17).
//
// Example:
//   src = [0x40, 0x01, 0x02, 0x03, 0x04, 0x05], dcid_len_short = 4
//   returns: QuicHeader { header_type: OneRtt, dcid: [1, 2, 3, 4] }, ok = true
fn parse_quic_header(src: const u8[:], dcid_len_short: u8 = 0) -> QuicHeader, bool {
    guard src.len > 0 else { return QuicHeader { .. }, false; }
    let first = src[0];
    if (first & 0x80) != 0 {
        return parse_quic_long_header(src, first);
    }
    return parse_quic_short_header(src, first, dcid_len_short);
}

// Builds the first byte of a QUIC Long Header (RFC 9000 §17.2, RFC 9369 §3.2).
//
// Example:
//   ht = QuicHeaderType.Initial, pn_bits = 0, version = 1
//   returns: 0xC0, ok = true
fn build_long_header_first_byte(ht: QuicHeaderType, pn_bits: u8, version: u32 = rfc::QUIC_VERSION_1) -> u8, bool {
    guard pn_bits <= 0x03 else { return 0, false; }
    guard version == rfc::QUIC_VERSION_1 || version == rfc::QUIC_VERSION_2 else { return 0, false; }
    let base = 0xC0 | pn_bits;
    if version == rfc::QUIC_VERSION_2 {
        match ht {
            Initial => { return base | 0x10, true; },
            ZeroRtt => { return base | 0x20, true; },
            Handshake => { return base | 0x30, true; },
            Retry => { return base, true; },
            _ => { return 0, false; },
        }
    }
    match ht {
        Initial => { return base, true; },
        ZeroRtt => { return base | 0x10, true; },
        Handshake => { return base | 0x20, true; },
        Retry => { return base | 0x30, true; },
        _ => { return 0, false; },
    }
}

fn encode_quic_long_header<B>(out: B&, hdr: const QuicHeader&, pn_len: u8, pn_bits: u8) -> bool {
    let orig_len = out.len;
    let b0, ok_b0 = build_long_header_first_byte(hdr.header_type, pn_bits, hdr.version);
    guard ok_b0 else { return false; }
    let min_fixed = 7 + hdr.dcid.len + hdr.scid.len;
    guard out.cap - out.len >= min_fixed else { return false; }
    out.push(b0);
    out.append_u32_be(hdr.version);

    out.push(hdr.dcid.len as u8);
    out.append(hdr.dcid[..]);
    out.push(hdr.scid.len as u8);
    out.append(hdr.scid[..]);

    if hdr.header_type == QuicHeaderType.Initial {
        guard quic_encode_varint(out, hdr.token.len as u64) && out.try_append(hdr.token[..]) else {
            out.resize(orig_len, 0);
            return false;
        }
    }

    if hdr.header_type != QuicHeaderType.Retry {
        guard quic_encode_varint(out, hdr.payload_length)
            && encode_packet_number(out, hdr.packet_number, pn_len) else {
            out.resize(orig_len, 0);
            return false;
        }
    }
    return true;
}

// Encodes a QUIC Long or Short header in unmasked form into out buffer.
fn encode_quic_header<B>(out: B&, hdr: const QuicHeader&, pn_len: u8) -> bool {
    guard pn_len >= 1 && pn_len <= 4 else { return false; }
    guard hdr.dcid.len <= rfc::QUIC_MAX_CID_LEN && hdr.scid.len <= rfc::QUIC_MAX_CID_LEN else { return false; }

    let pn_bits = (pn_len - 1) & 0x03;

    if hdr.header_type != QuicHeaderType.OneRtt {
        return encode_quic_long_header(out, hdr, pn_len, pn_bits);
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
    return encode_packet_number(out, hdr.packet_number, pn_len);
}

// Encodes an RFC 9000 §10.3 Stateless Reset packet (at least 21 bytes: 0b01xxxxxx first byte,
// unpredictable random bytes >= 5 total, and 16-byte Stateless Reset Token).
fn encode_stateless_reset_packet<B>(
    out:        B&,
    rand_bytes: const u8[:],
    token:      const u8[16]&,
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

inline fn compute_batch_aes128_masks(
    hp_key:    const u8[:],
    samples:   const u8[16][:],
    out_masks: u8[5][:],
    n:         i64,
) -> i64 {
    guard hp_key.len == 16 else { return 0; }
    var k16: u8[16] = [0; 16];
    defer core::secure_zeroize_16(k16);
    for i in 16 { k16[i] = hp_key[i]; }
    let ks = core::aes128_key_schedule(k16);
    for b in n {
        let enc = core::aes128_encrypt_block(ks, samples[b]);
        out_masks[b] = [enc[0], enc[1], enc[2], enc[3], enc[4]];
    }
    return n;
}

inline fn compute_batch_aes256_masks(
    hp_key:    const u8[:],
    samples:   const u8[16][:],
    out_masks: u8[5][:],
    n:         i64,
) -> i64 {
    guard hp_key.len == 32 else { return 0; }
    var k32: u8[32] = [0; 32];
    defer core::secure_zeroize_32(k32);
    for i in 32 { k32[i] = hp_key[i]; }
    let ks = core::aes256_key_schedule(k32);
    for b in n {
        let enc = core::aes_encrypt_block(ks, samples[b]);
        out_masks[b] = [enc[0], enc[1], enc[2], enc[3], enc[4]];
    }
    return n;
}

// Computes up to 8 5-byte QUIC header protection masks in a batch (RFC 9001 §5.4).
fn compute_quic_hp_masks_batch(
    cipher_suite: u16,
    hp_key:       const u8[:],
    samples:      const u8[16][:],
    out_masks:    u8[5][:],
) -> i64 {
    let n = min(min(samples.len, out_masks.len), 8);
    guard n > 0 else { return 0; }
    if cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 {
        return compute_batch_aes128_masks(hp_key, samples, out_masks, n);
    }
    if cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        return compute_batch_aes256_masks(hp_key, samples, out_masks, n);
    }
    if cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        guard hp_key.len == 32 else { return 0; }
        var k32: u8[32] = [0; 32];
        defer core::secure_zeroize_32(k32);
        for i in 32 { k32[i] = hp_key[i]; }
        for b in n { out_masks[b] = chacha20_header_protect_mask(k32, samples[b]); }
        return n;
    }
    return 0;
}

inline fn toggle_first_byte_protection(pkt: u8[:], is_long: bool, m0: u8) {
    let mask = if is_long { m0 & 0x0F } else { m0 & 0x1F };
    pkt[0] = pkt[0] ^ mask;
}

inline fn xor_pn_byte_at(pkt: u8[:], pn_offset: u32, hp_mask: const u8[5]&, i: i64) -> u8 {
    let idx = pn_offset + i;
    let m_idx = 1 + i;
    let unmasked = pkt[idx] ^ hp_mask[m_idx];
    pkt[idx] = unmasked;
    return unmasked;
}

// Applies header protection mask to packet header and packet number field (RFC 9001 Section 5.4.1).
fn apply_header_protection(pkt: u8[:], pn_offset: u32, pn_len: u8, hp_mask: const u8[5]&) {
    guard pkt.len > 0 && pn_len >= 1 && pn_len <= 4 else { return; }
    let pn_end = (pn_offset as u64) + pn_len;
    guard pn_end <= (pkt.len as u64) else { return; }
    let is_long = (pkt[0] & 0x80) != 0;
    toggle_first_byte_protection(pkt, is_long, hp_mask[0]);
    for i in (pn_len as i64) {
        let _ = xor_pn_byte_at(pkt, pn_offset, hp_mask, i);
    }
}

// Removes header protection mask in-place, returning true packet number length and truncated PN.
fn remove_header_protection(pkt: u8[:], pn_offset: u32, hp_mask: const u8[5]&) -> u8, u64 {
    guard pkt.len > 0 else { return 0, 0; }
    let is_long = (pkt[0] & 0x80) != 0;
    toggle_first_byte_protection(pkt, is_long, hp_mask[0]);
    let pn_len: u8 = (pkt[0] & 0x03) + 1;
    let pn_end = (pn_offset as u64) + pn_len;
    if pn_end > (pkt.len as u64) {
        // Revert first byte unmasking on bounds violation
        toggle_first_byte_protection(pkt, is_long, hp_mask[0]);
        return 0, 0;
    }
    var trunc_pn: u64 = 0;

    for i in (pn_len as i64) {
        let unmasked = xor_pn_byte_at(pkt, pn_offset, hp_mask, i);
        trunc_pn = (trunc_pn << 8) | unmasked;
    }
    return pn_len, trunc_pn;
}

// Encodes truncated packet number (1 to 4 bytes) in big-endian order (RFC 9000 Appendix A.2).
fn encode_packet_number<B>(out: B&, pn: u64, pn_len: u8) -> bool {
    guard pn_len >= 1 && pn_len <= 4 else { return false; }
    guard out.cap - out.len >= (pn_len as i64) else { return false; }
    let b0 = (pn & 0xFF) as u8;
    let b1 = ((pn >> 8) & 0xFF) as u8;
    let b2 = ((pn >> 16) & 0xFF) as u8;
    let b3 = ((pn >> 24) & 0xFF) as u8;
    if pn_len == 1 {
        out.push(b0);
    } else if pn_len == 2 {
        out.push(b1);
        out.push(b0);
    } else if pn_len == 3 {
        out.push(b2);
        out.push(b1);
        out.push(b0);
    } else {
        out.push(b3);
        out.push(b2);
        out.push(b1);
        out.push(b0);
    }
    return true;
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

const PATH_AMPLIFICATION_CAP: u64 = 0x5555555555555555; // 0xFFFFFFFFFFFFFFFF / 3

// Validates whether server can send additional bytes on path under 3x Anti-Amplification rule.
fn can_send_on_path(path: const PathState&, packet_bytes: u64) -> bool {
    if path.is_validated {
        return true;
    }
    let max_allow = if path.bytes_received > PATH_AMPLIFICATION_CAP {
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

fn on_path_bytes_received(path: PathState&, bytes: u64) {
    path.bytes_received = core::add_sat_u64(path.bytes_received, bytes);
}

fn on_path_bytes_sent(path: PathState&, bytes: u64) {
    path.bytes_sent = core::add_sat_u64(path.bytes_sent, bytes);
}

fn validate_path(path: PathState&) {
    path.is_validated = true;
}

// ---- Stream & Crypto Interval Reassembly Buffer --------------------------

struct Interval {
    start: u64 = 0,
    end:   u64 = 0, // [start, end)
}

const ARENA_CHUNK_SIZE: i64 = 1024;
const ARENA_MAX_CHUNKS: i32 = 16;
const ARENA_MAX_BYTES:  u64 = 16384;

struct SegmentedArena {
    chunks:           u8[..16384] = [],
    allocated_chunks: i32         = 0,
    data_len:         i64         = 0,
}

// Allocates a single 1024-byte chunk inside the bounded 16-chunk arena.
// Rejects allocation past 16 chunks (16384 bytes) per Invariant 13.
fn arena_alloc_chunk(arena: SegmentedArena&) -> bool {
    guard arena.allocated_chunks < ARENA_MAX_CHUNKS else { return false; }
    let next_len = arena.chunks.len + ARENA_CHUNK_SIZE;
    guard next_len <= arena.chunks.cap else { return false; }
    arena.chunks.resize(next_len, 0);
    arena.allocated_chunks = arena.allocated_chunks + 1;
    return true;
}

// Ensures at least `needed_bytes` of chunk capacity are allocated in `arena`.
// Rejects requests exceeding 16 chunks (16384 bytes) per Invariant 13.
fn arena_ensure_bytes(arena: SegmentedArena&, needed_bytes: u64) -> bool {
    guard needed_bytes <= ARENA_MAX_BYTES else { return false; }
    while (arena.chunks.len as u64) < needed_bytes {
        guard arena_alloc_chunk(arena) else { return false; }
    }
    return true;
}

// Shifts out `consumed` bytes from the front of the segmented arena and updates `allocated_chunks`.
fn arena_consume_front(arena: SegmentedArena&, consumed: i64) {
    guard consumed > 0 else { return; }
    if consumed >= arena.data_len {
        arena.chunks.clear();
        arena.allocated_chunks = 0;
        arena.data_len = 0;
        return;
    }
    let remaining = arena.data_len - consumed;
    for i in remaining {
        arena.chunks[i] = arena.chunks[consumed + i];
    }
    arena.data_len = remaining;
    if remaining == 0 {
        arena.chunks.clear();
        arena.allocated_chunks = 0;
    } else {
        let chunks_needed = (remaining + 1023) >> 10;
        let new_byte_len = chunks_needed << 10;
        arena.chunks.resize(new_byte_len, 0);
        arena.allocated_chunks = chunks_needed as i32;
    }
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

// Merges a new interval [new_start, new_end) into sorted non-overlapping intervals array.
fn merge_reassembly_interval(intervals: Interval[..64]&, new_start: u64, new_end: u64) -> bool {
    guard new_start < new_end else { return true; }
    var cur_s = new_start;
    var cur_e = new_end;
    var i: i64 = 0;

    while i < intervals.len {
        let it = intervals[i];
        if cur_e < it.start {
            guard intervals.len < intervals.cap else { return false; }
            intervals.insert_at(i, Interval { start: cur_s, end: cur_e });
            return true;
        }
        if cur_s > it.end {
            i = i + 1;
            continue;
        }
        cur_s = min(cur_s, it.start);
        cur_e = max(cur_e, it.end);
        intervals.remove_at(i);
    }

    return intervals.try_push(Interval { start: cur_s, end: cur_e });
}

fn validate_fin_constraints(buf: const ReassemblyBuffer&, frag_end: u64) -> bool {
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
    return true;
}

inline fn arena_write_payload(arena: SegmentedArena&, base_slab: i64, payload: const u8[:], payload_skip: i64) {
    let copy_len = payload.len - payload_skip;
    for idx in copy_len {
        arena.chunks[base_slab + idx] = payload[payload_skip + idx];
    }
    let write_end = base_slab + copy_len;
    if write_end > arena.data_len {
        arena.data_len = write_end;
    }
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
        guard validate_fin_constraints(buf, frag_end) else { return false; }
    }

    if frag_end <= buf.consumed_offset {
        if is_fin {
            buf.fin_received = true;
            buf.final_size = frag_end;
        }
        return true; // Duplicate of already consumed stream data
    }

    let eff_start = max(offset, buf.consumed_offset);
    let payload_skip = (eff_start - offset) as i64;
    let needed_len = frag_end - buf.consumed_offset;

    guard needed_len <= ARENA_MAX_BYTES else { return false; }
    guard merge_reassembly_interval(buf.intervals, eff_start, frag_end) else { return false; }
    guard arena_ensure_bytes(buf.arena, needed_len) else { return false; }

    let base_slab = (eff_start - buf.consumed_offset) as i64;
    arena_write_payload(buf.arena, base_slab, payload, payload_skip);

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

    arena_consume_front(buf.arena, take_bytes);
    return take_bytes as u64;
}
