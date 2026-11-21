// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal VarInt, Long/Short header, Header Protection, and SegmentedArena helpers for `quic`.
namespace quic_internal;

import std;
import core;
import .packet;

// ---- Variable-Length Integer Bit Helpers (RFC 9000 Section 16) -----------

checkfree inline fn quic_read_be_u16(s: const u8[:]) -> u16 {
    if s.len < 2 { return 0; }
    return ((s[0] as u16) << 8) | s[1];
}

checkfree inline fn quic_read_be_u32(s: const u8[:]) -> u32 {
    if s.len < 4 { return 0; }
    let hi = quic_read_be_u16(s) as u32;
    let lo = quic_read_be_u16(s[2..]) as u32;
    return (hi << 16) | lo;
}

checkfree inline fn quic_set_cid(dst: u8[..20]&, src: const u8[:]) -> bool {
    if src.len < 0 || src.len > dst.cap { return false; }
    dst.clear();
    dst.append(src);
    return true;
}

checkfree inline fn quic_append_token(dst: u8[..512]&, src: const u8[:]) -> bool {
    let rem = dst.cap - dst.len;
    if dst.len < 0 || src.len < 0 || src.len > rem { return false; }
    dst.append(src);
    return true;
}

// Returns the wire byte length (1, 2, 4, or 8) of a QUIC Variable-Length Integer from its first byte.
checkfree inline fn quic_varint_len(first_byte: u8) -> u8 {
    let tag = (first_byte >> 6) & 0x03;
    return (1 as u8) << tag;
}

checkfree inline fn varint_read_2(src: const u8[:], idx: i64, first: u8) -> u64 {
    if idx < 0 || idx > src.len { return 0; }
    let tail = src[idx..];
    if tail.len < 2 { return 0; }
    let hi: u64 = first & 0x3F;
    return (hi << 8) | tail[1];
}

checkfree inline fn varint_read_4(src: const u8[:], idx: i64, first: u8) -> u64 {
    if idx < 0 || idx > src.len { return 0; }
    let tail = src[idx..];
    if tail.len < 4 { return 0; }
    let v1 = varint_read_2(tail, 0, first);
    let v2 = (v1 << 8) | tail[2];
    return (v2 << 8) | tail[3];
}

checkfree inline fn varint_read_8(src: const u8[:], idx: i64, first: u8) -> u64 {
    if idx < 0 || idx > src.len { return 0; }
    let tail = src[idx..];
    if tail.len < 8 { return 0; }
    let v3 = varint_read_4(tail, 0, first);
    let v4 = (v3 << 8) | tail[4];
    let v5 = (v4 << 8) | tail[5];
    let v6 = (v5 << 8) | tail[6];
    return (v6 << 8) | tail[7];
}

// ---- Packet Header Internal Parsers & Encoders (RFC 9000 Section 17) -----

struct QuicHeaderOptions {
    allow_grease: bool = false,
    is_masked:    bool = false,
}

// Parses a Version Negotiation Long Header (RFC 9000 §17.2.1).
//
// Example:
//   src = [0x80, 0x00, 0x00, 0x00, 0x00, 0x04, ...], in_hdr = initial header
//   returns: QuicHeader { header_type: VersionNegotiation, version: 0 }, ok = true
checkfree fn parse_quic_version_negotiation(src: const u8[:], in_hdr: quic::QuicHeader) -> quic::QuicHeader, bool {
    // RFC 9000 Section 17.2.1: Version Negotiation Packet - Header Form bit MUST be 1 and Version MUST be 0.
    guard src.len >= 7
        && (src[0] & 0x80) != 0
        && quic_read_be_u32(src[1..]) == rfc::QUIC_VERSION_NEGOTIATION else {
        return in_hdr, false;
    }
    let dlen: i64 = src[5];
    let d_end = 6 + dlen;
    let s_start = 7 + dlen;
    guard dlen <= rfc::QUIC_MAX_CID_LEN && d_end >= 6 && d_end < src.len
        && s_start >= 7 && s_start <= src.len else {
        return in_hdr, false;
    }
    let slen: i64 = src[d_end];
    let s_end = s_start + slen;
    guard slen <= rfc::QUIC_MAX_CID_LEN && s_end >= s_start && s_end <= src.len else { return in_hdr, false; }

    // RFC 9000 Section 17.2.1: Version Negotiation Packet - Must contain one or more 32-bit versions.
    let rem_versions = src.len - s_end;
    guard rem_versions >= 4 && (rem_versions & 3) == 0 else { return in_hdr, false; }

    var hdr = in_hdr;
    guard quic_set_cid(hdr.dcid, src[6..d_end]) && quic_set_cid(hdr.scid, src[s_start..s_end]) else {
        return in_hdr, false;
    }
    hdr.header_type = quic::QuicHeaderType.VersionNegotiation;
    hdr.version = rfc::QUIC_VERSION_NEGOTIATION;
    hdr.header_len = s_end as u32;
    return hdr, true;
}

// Extracts DCID and SCID for Long Headers (RFC 9000 §17.2).
//
// Example:
//   src = [0x04, 1, 2, 3, 4, 0x00], idx = 0
//   returns: true, idx = 6, dcid = [1, 2, 3, 4], scid = []
checkfree fn parse_quic_long_cids(
    src:  const u8[:],
    idx:  i64&,
    dcid: u8[..20]&,
    scid: u8[..20]&,
) -> bool {
    let initial_idx = idx;
    guard initial_idx >= 0 && initial_idx < src.len else { return false; }
    let dlen: i64 = src[initial_idx];
    let d_start = initial_idx + 1;
    let d_end = d_start + dlen;
    guard dlen <= rfc::QUIC_MAX_CID_LEN && d_start >= 0 && d_end >= d_start && d_end < src.len else {
        idx = initial_idx;
        return false;
    }

    let slen: i64 = src[d_end];
    let s_start = d_end + 1;
    let s_end = s_start + slen;
    guard slen <= rfc::QUIC_MAX_CID_LEN && s_start >= 0 && s_end >= s_start && s_end <= src.len else {
        idx = initial_idx;
        return false;
    }

    guard quic_set_cid(dcid, src[d_start..d_end]) && quic_set_cid(scid, src[s_start..s_end]) else {
        idx = initial_idx;
        return false;
    }
    idx = s_end;
    return true;
}

// Parses variable-length initial token for Initial packets (RFC 9000 §17.2.2).
//
// Example:
//   src = [0x04, 't', 'o', 'k', 'n'], idx = 0
//   returns: true, idx = 5, token = "tokn"
checkfree fn parse_quic_initial_token(src: const u8[:], idx: i64&, token: u8[..512]&) -> bool {
    let initial_idx = idx;
    let initial_len = token.len;
    var committed = false;
    defer if !committed {
        token.resize(initial_len);
        idx = initial_idx;
    };
    let tok_len, ok_tok = quic::decode_varint_cursor(src, idx);
    let pos = idx;
    let itok = tok_len as i64;
    let tok_end = pos + itok;
    guard ok_tok && pos >= 0 && pos <= src.len && itok >= 0 else { return false; }
    let tail = src[pos..];
    guard itok <= tail.len && quic_append_token(token, tail[..itok]) else {
        return false;
    }
    idx = tok_end;
    committed = true;
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
checkfree fn quic_long_header_type(version: u32, two_bits: u8) -> quic::QuicHeaderType, bool {
    guard two_bits <= 0x03 else { return quic::QuicHeaderType.Retry, false; }
    if version == rfc::QUIC_VERSION_2 {
        if two_bits == 0x01 { return quic::QuicHeaderType.Initial, true; }
        if two_bits == 0x02 { return quic::QuicHeaderType.ZeroRtt, true; }
        if two_bits == 0x03 { return quic::QuicHeaderType.Handshake, true; }
        return quic::QuicHeaderType.Retry, true;
    }
    if version == rfc::QUIC_VERSION_1 {
        if two_bits == 0x00 { return quic::QuicHeaderType.Initial, true; }
        if two_bits == 0x01 { return quic::QuicHeaderType.ZeroRtt, true; }
        if two_bits == 0x02 { return quic::QuicHeaderType.Handshake, true; }
        return quic::QuicHeaderType.Retry, true;
    }
    return quic::QuicHeaderType.Retry, false;
}

// Decodes a big-endian truncated packet number of 1-4 bytes (RFC 9000 §17.1).
//
// Example:
//   src = [0x01, 0x02], idx = 0, pn_len = 2
//   returns: 0x0102
checkfree inline fn decode_unmasked_pn(src: const u8[:], idx: i64, pn_len: i64) -> u64 {
    if idx < 0 || idx > src.len || pn_len < 0 { return 0; }
    let tail = src[idx..];
    if pn_len > tail.len { return 0; }
    var pn_val: u64 = 0;
    for i in pn_len {
        pn_val = (pn_val << 8) | tail[i];
    }
    return pn_val;
}

// Parses a QUIC Long Header (RFC 9000 §17.2).
//
// Example:
//   src = [0xC0, 0x00, 0x00, 0x00, 0x01, ...], first = 0xC0
//   returns: QuicHeader { header_type: Initial, version: 1 }, ok = true
checkfree fn parse_quic_long_header(
    src:   const u8[:],
    first: u8,
    opts:  QuicHeaderOptions = QuicHeaderOptions { .. },
) -> quic::QuicHeader, bool {
    var hdr = quic::QuicHeader {};
    guard src.len >= 5 else { return hdr, false; }
    let ver = quic_read_be_u32(src[1..]);
    hdr.version = ver;

    if ver == rfc::QUIC_VERSION_NEGOTIATION {
        return parse_quic_version_negotiation(src, hdr);
    }

    // Fixed bit (0x40) MUST be set for non-Version Negotiation Long Headers
    // unless GREASE was negotiated (RFC 9000 §17.2, RFC 9287).
    guard (first & 0x40) != 0 || opts.allow_grease else { return hdr, false; }

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

    // Reserved bits check (RFC 9000 §17.2, RFC 9001 §5.4.1): Only checked for unmasked headers.
    // Masked headers check reserved bits strictly after AEAD decryption.
    if !opts.is_masked && hdr.header_type != quic::QuicHeaderType.Retry {
        guard (first & 0x0C) == 0 else { return hdr, false; }
    }

    var idx: i64 = 5;
    guard parse_quic_long_cids(src, idx, hdr.dcid, hdr.scid) else { return hdr, false; }

    if hdr.header_type == quic::QuicHeaderType.Initial {
        guard parse_quic_initial_token(src, idx, hdr.token) else { return hdr, false; }
    }

    if hdr.header_type == quic::QuicHeaderType.Retry {
        hdr.header_len = idx as u32;
        return hdr, true;
    }

    let plen, ok_plen = quic::decode_varint_cursor(src, idx);
    guard ok_plen else { return hdr, false; }
    hdr.payload_length = plen;
    hdr.pn_offset = idx as u32;

    if opts.is_masked {
        hdr.pn_length = 0;
        hdr.header_len = hdr.pn_offset;
        return hdr, true;
    }

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
checkfree fn parse_quic_short_header(
    src:            const u8[:],
    first:          u8,
    dcid_len_short: u8,
    opts:           QuicHeaderOptions = QuicHeaderOptions { .. },
) -> quic::QuicHeader, bool {
    var hdr = quic::QuicHeader {};
    // Fixed bit (0x40) MUST be set unless GREASE negotiated (RFC 9000 §17.3, RFC 9287)
    guard (first & 0x40) != 0 || opts.allow_grease else { return hdr, false; }
    // Reserved bits check (RFC 9000 §17.3, RFC 9001 §5.4.1): Only checked for unmasked headers.
    if !opts.is_masked {
        guard (first & 0x18) == 0 else { return hdr, false; }
    }
    guard dcid_len_short <= rfc::QUIC_MAX_CID_LEN else { return hdr, false; }
    hdr.header_type = quic::QuicHeaderType.OneRtt;
    hdr.spin_bit = (first & 0x20) != 0;
    if !opts.is_masked {
        hdr.key_phase = (first & 0x04) != 0;
    }

    let dlen: i64 = dcid_len_short;
    var idx: i64 = 1;
    let d_end = idx + dlen;
    guard d_end >= 1 && d_end <= src.len else { return hdr, false; }
    if dlen > 0 {
        hdr.dcid.append(src[idx..d_end]);
        idx = d_end;
    }
    hdr.pn_offset = idx as u32;

    if opts.is_masked {
        hdr.pn_length = 0;
        hdr.header_len = hdr.pn_offset;
        return hdr, true;
    }

    hdr.pn_length = (first & 0x03) + 1;
    let ipn: i64 = hdr.pn_length;
    let hdr_end = idx + ipn;
    guard hdr_end <= src.len else { return hdr, false; }
    hdr.packet_number = decode_unmasked_pn(src, idx, ipn);
    hdr.header_len = hdr_end as u32;
    return hdr, true;
}

// Builds the first byte of a QUIC Long Header (RFC 9000 §17.2, RFC 9369 §3.2).
//
// Example:
//   ht = QuicHeaderType.Initial, pn_bits = 0, version = 1
//   returns: 0xC0, ok = true
checkfree fn build_long_header_first_byte(
    ht:      quic::QuicHeaderType,
    pn_bits: u8,
    version: u32 = rfc::QUIC_VERSION_1,
) -> u8, bool {
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

// Encodes truncated packet number (1 to 4 bytes) in big-endian order (RFC 9000 Appendix A.2).
fn encode_packet_number<B>(pn: u64, pn_len: u8, out: B&) -> bool {
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

fn encode_quic_long_header<B>(
    hdr:     const quic::QuicHeader&,
    pn_len:  u8,
    pn_bits: u8,
    out:     B&,
) -> bool {
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

    if hdr.header_type == quic::QuicHeaderType.Initial {
        guard quic::encode_varint(hdr.token.len as u64, out) && out.try_append(hdr.token[..]) else {
            out.resize(orig_len, 0);
            return false;
        }
    }

    if hdr.header_type != quic::QuicHeaderType.Retry {
        guard quic::encode_varint(hdr.payload_length, out)
            && encode_packet_number(hdr.packet_number, pn_len, out) else {
            out.resize(orig_len, 0);
            return false;
        }
    }
    return true;
}

// ---- Header Protection Internal Helpers (RFC 9001 Section 5.4) ----------

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
    hp_key:  const u8[:],
    samples: const u8[16][:],
    masks:   u8[5][:],
    n:       i64,
) -> i64 {
    guard hp_key.len == 16 else { return 0; }
    var k16: u8[16] = [0; 16];
    defer core::secure_zeroize_16(k16);
    for i in 16 { k16[i] = hp_key[i]; }
    let ks = core::aes128_key_schedule(k16);
    for b in n {
        let enc = core::aes128_encrypt_block(ks, samples[b]);
        masks[b] = [enc[0], enc[1], enc[2], enc[3], enc[4]];
    }
    return n;
}

inline fn compute_batch_aes256_masks(
    hp_key:  const u8[:],
    samples: const u8[16][:],
    masks:   u8[5][:],
    n:       i64,
) -> i64 {
    guard hp_key.len == 32 else { return 0; }
    var k32: u8[32] = [0; 32];
    defer core::secure_zeroize_32(k32);
    for i in 32 { k32[i] = hp_key[i]; }
    let ks = core::aes256_key_schedule(k32);
    for b in n {
        let enc = core::aes_encrypt_block(ks, samples[b]);
        masks[b] = [enc[0], enc[1], enc[2], enc[3], enc[4]];
    }
    return n;
}

checkfree inline fn toggle_first_byte_protection(pkt: u8[:], is_long: bool, m0: u8) {
    guard pkt.len > 0 else { return; }
    let mask = if is_long { m0 & 0x0F } else { m0 & 0x1F };
    pkt[0] = pkt[0] ^ mask;
}

checkfree inline fn xor_pn_byte_at(pkt: u8[:], pn_offset: u32, hp_mask: const u8[5]&, i: i64) -> u8 {
    let idx = pn_offset + i;
    let m_idx = 1 + i;
    if idx < 0 || idx >= pkt.len || m_idx < 0 || m_idx >= 5 { return 0; }
    let unmasked = pkt[idx] ^ hp_mask[m_idx];
    pkt[idx] = unmasked;
    return unmasked;
}

// ---- Path & Arena Internal Constants and Helpers -------------------------

const PATH_AMPLIFICATION_CAP: u64 = 0x5555555555555555; // 0xFFFFFFFFFFFFFFFF / 3
const ARENA_CHUNK_SIZE:       i64 = 1024;
const ARENA_MAX_CHUNKS:       i32 = 16;
const ARENA_MAX_BYTES:        u64 = 16384;

// Allocates a single 1024-byte chunk inside the bounded 16-chunk arena.
// Rejects allocation past 16 chunks (16384 bytes) per Invariant 13.
checkfree fn arena_alloc_chunk(arena: quic::SegmentedArena&) -> bool {
    guard arena.allocated_chunks < ARENA_MAX_CHUNKS else { return false; }
    let next_len = arena.chunks.len + ARENA_CHUNK_SIZE;
    guard next_len <= arena.chunks.cap else { return false; }
    arena.chunks.resize(next_len, 0);
    arena.allocated_chunks = arena.allocated_chunks + 1;
    return true;
}

// Ensures at least `needed_bytes` of chunk capacity are allocated in `arena`.
// Rejects requests exceeding 16 chunks (16384 bytes) per Invariant 13.
checkfree fn arena_ensure_bytes(arena: quic::SegmentedArena&, needed_bytes: u64) -> bool {
    guard needed_bytes <= ARENA_MAX_BYTES else { return false; }
    while (arena.chunks.len as u64) < needed_bytes {
        guard arena_alloc_chunk(arena) else { return false; }
    }
    return true;
}

// Shifts out `consumed` bytes from the front of the segmented arena and updates `allocated_chunks`.
checkfree fn arena_consume_front(arena: quic::SegmentedArena&, consumed: i64) {
    guard consumed > 0 else { return; }
    if consumed >= arena.data_len {
        arena.chunks.clear();
        arena.allocated_chunks = 0;
        arena.data_len = 0;
        return;
    }
    let remaining = arena.data_len - consumed;
    let clen = arena.chunks.len;
    for i in remaining {
        let src_i = consumed + i;
        if i >= clen || src_i < 0 || src_i >= clen { break; }
        arena.chunks[i] = arena.chunks[src_i];
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

// Merges a new interval [new_start, new_end) into sorted non-overlapping intervals array.
fn merge_reassembly_interval(intervals: quic::Interval[..64]&, new_start: u64, new_end: u64) -> bool {
    guard new_start < new_end else { return true; }
    var cur_s = new_start;
    var cur_e = new_end;
    var i: i64 = 0;

    while i < intervals.len {
        let it = intervals[i];
        if cur_e < it.start {
            guard intervals.len < intervals.cap else { return false; }
            intervals.insert_at(i, quic::Interval { start: cur_s, end: cur_e });
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

    return intervals.try_push(quic::Interval { start: cur_s, end: cur_e });
}

checkfree fn validate_fin_constraints(buf: const quic::ReassemblyBuffer&, frag_end: u64) -> bool {
    if buf.fin_received && buf.final_size != frag_end {
        return false; // QUIC_ERR_FINAL_SIZE
    }
    if frag_end < buf.consumed_offset {
        return false; // QUIC_ERR_FINAL_SIZE
    }
    for &it in buf.intervals {
        if it.end > frag_end {
            return false; // QUIC_ERR_FINAL_SIZE: data already buffered beyond declared final size
        }
    }
    return true;
}

inline fn arena_write_gap(
    arena:        quic::SegmentedArena&,
    consumed_off: u64,
    frag_offset:  u64,
    payload:      const u8[:],
    gap_start:    u64,
    gap_end:      u64,
) {
    guard gap_start < gap_end else { return; }
    let base_slab = core::sub_sat_u64(gap_start, consumed_off) as i64;
    let payload_skip = core::sub_sat_u64(gap_start, frag_offset) as i64;
    let copy_len = core::sub_sat_u64(gap_end, gap_start) as i64;
    for idx in copy_len {
        arena.chunks[core::add_sat_i64(base_slab, idx)] = payload[core::add_sat_i64(payload_skip, idx)];
    }
    let write_end = core::add_sat_i64(base_slab, copy_len);
    if write_end > arena.data_len {
        arena.data_len = write_end;
    }
}

inline fn arena_write_uncovered_gaps(
    arena:        quic::SegmentedArena&,
    intervals:    const quic::Interval[..64]&,
    consumed_off: u64,
    frag_offset:  u64,
    payload:      const u8[:],
    eff_start:    u64,
    frag_end:     u64,
) {
    var cur = eff_start;
    for i in intervals.len {
        let it = intervals[i];
        if it.end <= cur {
            continue;
        }
        if it.start >= frag_end {
            break;
        }
        if cur < it.start {
            arena_write_gap(arena, consumed_off, frag_offset, payload, cur, it.start);
        }
        cur = max(cur, it.end);
    }
    if cur < frag_end {
        arena_write_gap(arena, consumed_off, frag_offset, payload, cur, frag_end);
    }
}
