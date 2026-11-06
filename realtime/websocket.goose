// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// WebSocket Protocol Framing and Handshake Engine (RFC 6455 & RFC 8441).
// Features:
// - Zero-copy in-place 64-bit unrolled payload masking / unmasking
// - Complete frame header parser, serializer, and control frame invariant enforcer
// - RFC 6455 Section 4.2.2 Sec-WebSocket-Key / Accept handshake verification via SHA-1
// - Close frame payload encoding and status code validation
namespace wing;

import std;
import core from "..";

// Native CSPRNG & SIMD shims
extern fn native_crypto_random_bytes(out: u8[:]) -> i32 = "wing_crypto_random_bytes";
extern fn native_simd_mask_websocket(data: u8[:], mask: const u8[4]&) = "wing_simd_mask_websocket";
extern fn native_simd_unmask_shifted(
    slice:       u8[:],
    header_len:  i64,
    payload_len: i64,
    mask:        const u8[4]&,
) = "wing_simd_unmask_shifted";

// In-place zero-copy unmasking that shifts the unmasked payload back over the frame header
// (uWebSockets unmaskImprecise8). Overwrites header directly in slice and returns payload slice.
fn unmask_websocket_shifted(frame: u8[:], header_len: i64, payload_len: i64, mask_key: const u8[4]&) -> u8[:] {
    guard payload_len > 0 && header_len > 0 && header_len <= frame.len && payload_len <= frame.len - header_len else {
        return frame[..0];
    }
    native_simd_unmask_shifted(frame, header_len, payload_len, mask_key);
    return frame[..payload_len];
}

// ---- Frame Header Structure and Invariants ------------------------------

struct WsFrameHeader {
    fin:         bool  = true,
    rsv1:        bool  = false,
    rsv2:        bool  = false,
    rsv3:        bool  = false,
    opcode:      u8    = rfc::WS_OPCODE_TEXT,
    masked:      bool  = false,
    mask_key:    u8[4] = [0; 4],
    payload_len: u64   = 0,
    header_len:  u16   = 0,
}

// In-place SWAR 64-bit/32-bit XOR masking loop (RFC 6455 Section 5.3)
// Vectorizes payload masking in pure Goose using 64-bit word iterations without heap allocations
// or out-of-bounds reads.
fn apply_mask_in_place(data: u8[:], mask_key: const u8[4]&) {
    let n = data.len;
    guard n > 0 else { return; }

    let m0 = mask_key[0] as u64;
    let m1 = mask_key[1] as u64;
    let m2 = mask_key[2] as u64;
    let m3 = mask_key[3] as u64;

    let m32_be = (m0 << 24) | (m1 << 16) | (m2 << 8) | m3;
    let m64_be = (m32_be << 32) | m32_be;

    var i: i64 = 0;

    // 64-bit SWAR loop: process 8 bytes per iteration
    while i + 8 <= n {
        let w = core::read_be_u64(data, i);
        core::write_be_u64_at(data, i, w ^ m64_be);
        i += 8;
    }

    // 32-bit SWAR tail: process remaining 4 bytes if present
    if i + 4 <= n {
        let w = core::read_be_u32(data, i);
        core::write_be_u32_at(data, i, w ^ (m32_be as u32));
        i += 4;
    }

    // Scalar byte-by-byte tail (0..3 bytes)
    while i < n {
        data[i] = data[i] ^ mask_key[i % 4];
        i++;
    }
}

// In-place masking / unmasking using vectorized SIMD acceleration with 64-bit unrolled fallback (RFC 6455 Section 5.3)
fn mask_websocket_payload(data: u8[:], mask_key: const u8[4]&) {
    let n = data.len;
    guard n > 0 else { return; }
    if n >= 64 {
        native_simd_mask_websocket(data, mask_key);
    } else {
        apply_mask_in_place(data, mask_key);
    }
}

// Parses RFC 6455 Frame Header with strict protocol validation
//
// Example:
//   src = [0x81, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F]
//   returns: WsFrameHeader { fin: true, opcode: 1, payload_len: 5, header_len: 2, ... }, ok = true
fn parse_ws_frame_header(src: const u8[:]) -> WsFrameHeader, bool {
    var hdr = WsFrameHeader { .. };
    guard src.len >= 2 else { return hdr, false; }

    let b0 = src[0];
    let b1 = src[1];

    let fin = (b0 & 0x80) != 0;
    let rsv1 = (b0 & 0x40) != 0;
    let rsv2 = (b0 & 0x20) != 0;
    let rsv3 = (b0 & 0x10) != 0;
    let opcode = b0 & 0x0F;

    guard rfc::is_valid_ws_opcode(opcode) else { return hdr, false; }

    let masked = (b1 & 0x80) != 0;
    let raw_len = (b1 & 0x7F) as u64;

    // Control frame invariants (RFC 6455 Section 5.5):
    // 1. MUST NOT be fragmented (FIN MUST be 1)
    // 2. Payload length MUST be <= 125 (extended length encodings 126/127 are forbidden)
    if rfc::is_ws_control_opcode(opcode) {
        guard fin && raw_len <= 125 else { return hdr, false; }
    }

    var offset:      i64 = 2;
    var payload_len: u64 = 0;

    if raw_len <= 125 {
        payload_len = raw_len;
    } else if raw_len == 126 {
        guard src.len >= offset + 2 else { return hdr, false; }
        payload_len = core::read_be_u16(src, offset);
        // RFC 6455 Section 5.2: minimal encoding check (must be >= 126)
        guard payload_len >= 126 else { return hdr, false; }
        offset += 2;
    } else {
        // raw_len == 127
        guard src.len >= offset + 8 else { return hdr, false; }
        // High bit must be 0 per RFC 6455 Section 5.2
        guard (src[offset] & 0x80) == 0 else { return hdr, false; }
        payload_len = core::read_be_u64(src, offset);
        // Minimal encoding check (must be > 65535)
        guard payload_len > 65535 else { return hdr, false; }
        offset += 8;
    }

    // Control frames payload length must not exceed 125 bytes
    if rfc::is_ws_control_opcode(opcode) {
        guard payload_len <= 125 else { return hdr, false; }
    }

    var mask_key: u8[4] = [0; 4];
    if masked {
        guard src.len >= offset + 4 else { return hdr, false; }
        mask_key = [src[offset], src[offset + 1], src[offset + 2], src[offset + 3]];
        offset += 4;
    }

    hdr.fin = fin;
    hdr.rsv1 = rsv1;
    hdr.rsv2 = rsv2;
    hdr.rsv3 = rsv3;
    hdr.opcode = opcode;
    hdr.masked = masked;
    hdr.mask_key = mask_key;
    hdr.payload_len = payload_len;
    hdr.header_len = offset as u16;

    return hdr, true;
}

// Encodes RFC 6455 Frame Header
fn encode<B>(hdr: const WsFrameHeader&, out: B&) {
    let eff_fin = if rfc::is_ws_control_opcode(hdr.opcode) { true } else { hdr.fin };
    var b0: u8 = hdr.opcode & 0x0F;
    if eff_fin { b0 |= 0x80; }
    if hdr.rsv1 { b0 |= 0x40; }
    if hdr.rsv2 { b0 |= 0x20; }
    if hdr.rsv3 { b0 |= 0x10; }
    out.push(b0);

    let mask_bit: u8 = if hdr.masked { 0x80 } else { 0x00 };

    // RFC 6455 §5.5 & uWS #1407: Control frames MUST NOT exceed 125 bytes and MUST NEVER use extended length
    let eff_len = if rfc::is_ws_control_opcode(hdr.opcode) && hdr.payload_len > 125 {
        125 as u64
    } else {
        hdr.payload_len
    };

    if eff_len <= 125 {
        out.push(mask_bit | (eff_len as u8));
    } else if eff_len <= 65535 {
        out.push(mask_bit | 126);
        core::write_be_u16(out, eff_len as u16);
    } else {
        out.push(mask_bit | 127);
        core::write_be_u64(out, eff_len);
    }

    if hdr.masked {
        out.append(hdr.mask_key[..]);
    }
}

// High-level frame serializer: writes header + payload (masked if is_client)
fn encode_ws_frame<B>(
    out:       B&,
    opcode:    u8,
    payload:   const u8[:],
    is_client: bool        = true,
    mask_key:  const u8[4] = [0 as u8; 4],
    fin:       bool        = true,
) {
    // RFC 6455 §5.5: Control frames MUST NOT exceed 125 bytes and MUST NOT be fragmented
    let eff_payload = if rfc::is_ws_control_opcode(opcode) && payload.len > 125 { payload[..125] } else { payload };
    let eff_fin = if rfc::is_ws_control_opcode(opcode) { true } else { fin };

    let hdr = WsFrameHeader {
        fin:         eff_fin,
        opcode:      opcode,
        masked:      is_client,
        mask_key:    mask_key,
        payload_len: eff_payload.len as u64,
        ..
    };
    hdr.encode(out);

    if is_client {
        for i in eff_payload.len {
            out.push(eff_payload[i] ^ mask_key[i & 3]);
        }
    } else {
        out.append(eff_payload);
    }
}

// Computes exact WebSocket frame wire length including header, extended length, mask key, and payload
fn calc_ws_frame_len(payload_len: u64, is_client: bool) -> u64 {
    let ext_len:  u64 = if payload_len > 65535 { 8 } else if payload_len > 125 { 2 } else { 0 };
    let mask_len: u64 = if is_client { 4 } else { 0 };
    return 2 + ext_len + mask_len + payload_len;
}

// ---- PerMessageDeflate Shared Compressor Engine (RFC 7692 / uWebSockets pattern)

// Compression options matching uWebSockets CompressOptions
const WS_COMPRESS_DISABLED:            u16 = 0;
const WS_COMPRESS_SHARED_COMPRESSOR:   u16 = 1;        // Shared zlib deflate context on reactor (0B heap/socket)
const WS_COMPRESS_SHARED_DECOMPRESSOR: u16 = 1 << 8;   // Shared inflate context on reactor
const WS_COMPRESS_DEDICATED:           u16 = 15 << 4 | 8; // Dedicated 256 KB compressor per connection

// Shared reactor-level WebSocket compression/decompression context.
// Avoids 256 KB allocation per connection, allowing 100K+ concurrent connections with 0B heap allocations.
struct SharedWsCompressor {
    compress_buf:       u8[..65536] = [],
    decompress_buf:     u8[..65536] = [],
    total_compressed:   u64         = 0,
    total_uncompressed: u64         = 0,
    total_decompressed: u64         = 0,
    reset_window:       bool        = true,
}

// Compresses raw payload using raw Deflate (RFC 1951) and strips trailing 0x00 0x00 0xFF 0xFF (RFC 7692 §7.2.1).
// Returns a zero-copy slice to shared.compress_buf containing the compressed bytes.
//
// Example:
//   raw = "hello", reset_window = true
//   returns: comp_slice = [0xca, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00], ok = true
fn ws_deflate_message_slice(
    shared:       SharedWsCompressor&,
    raw:          const u8[:],
    reset_window: bool = true,
) -> const u8[:], bool {
    guard raw.len > 0 else { return "", false; }
    shared.compress_buf.clear();
    let ok = core::deflate(raw, shared.compress_buf, 6);
    guard ok && shared.compress_buf.len > 0 else {
        if reset_window {
            shared.compress_buf.clear();
            shared.decompress_buf.clear();
        }
        return "", false;
    }

    var eff_len = shared.compress_buf.len;
    // RFC 7692 Section 7.2.1: Strip 4 trailing bytes 0x00 0x00 0xFF 0xFF
    if eff_len >= 4 {
        let b0 = shared.compress_buf[eff_len - 4];
        let b1 = shared.compress_buf[eff_len - 3];
        let b2 = shared.compress_buf[eff_len - 2];
        let b3 = shared.compress_buf[eff_len - 1];
        if b0 == 0x00 && b1 == 0x00 && b2 == 0xFF && b3 == 0xFF {
            eff_len -= 4;
        }
    }

    shared.total_compressed += eff_len as u64;
    shared.total_uncompressed += raw.len as u64;

    return shared.compress_buf[..eff_len], true;
}

// Appends compressed message to caller-supplied buffer out_wire
fn ws_deflate_message<B>(
    shared:       SharedWsCompressor&,
    raw:          const u8[:],
    out_wire:     B&,
    reset_window: bool = true,
) -> bool {
    let comp_slice, ok = ws_deflate_message_slice(shared, raw, reset_window);
    guard ok else { return false; }
    out_wire.append(comp_slice);
    return true;
}

// Decompresses RFC 7692 payload by appending 0x00 0x00 0xFF 0xFF and performing raw Inflate (RFC 7692 §7.2.2).
// With reset_window=true (Z_FULL_FLUSH equivalent), resets dictionary state immediately.
fn ws_inflate_message<B>(
    shared:       SharedWsCompressor&,
    compressed:   const u8[:],
    out_plain:    B&,
    max_payload:  i64  = 65536,
    reset_window: bool = true,
) -> bool {
    out_plain.clear();
    guard compressed.len > 0 else { return false; }
    shared.decompress_buf.clear();

    // RFC 7692 Section 7.2.2: Restore 4-byte tail 0x00 0x00 0xFF 0xFF
    guard compressed.len + 4 <= shared.decompress_buf.cap else { return false; }
    shared.decompress_buf.append(compressed);
    let tail: u8[4] = [0x00, 0x00, 0xFF, 0xFF];
    shared.decompress_buf.append(tail[..]);

    let ok_d, err = core::inflate_with_limit(shared.decompress_buf[..], out_plain, max_payload);
    if !ok_d {
        out_plain.clear();
        // OutputBufferOverflow indicates a decompression bomb exceeding max_payload: abort immediately!
        if err == core::CompressError.OutputBufferOverflow {
            if reset_window {
                shared.decompress_buf.clear();
                shared.compress_buf.clear();
            }
            return false;
        }
        // Fallback: try direct inflate without appended tail
        let ok_raw, _ = core::inflate_with_limit(compressed, out_plain, max_payload);
        if !ok_raw {
            out_plain.clear();
            if reset_window {
                shared.decompress_buf.clear();
                shared.compress_buf.clear();
            }
            return false;
        }
    }

    shared.total_decompressed += out_plain.len as u64;
    if reset_window {
        shared.decompress_buf.clear();
        shared.compress_buf.clear();
    }
    return true;
}

// Dedicated Sliding-Window Deflate / Inflate Context (uWebSockets dedicated compressor 3KB..64KB)
// Retains sliding dictionary across messages on a persistent connection for maximum compression ratio.
struct DedicatedWsCompressor {
    window_kb:          i64         = 32,
    history:            u8[..65536] = [],
    compress_buf:       u8[..65536] = [],
    decompress_buf:     u8[..65536] = [],
    total_compressed:   u64         = 0,
    total_uncompressed: u64         = 0,
    total_decompressed: u64         = 0,
}

fn new_dedicated_ws_compressor(window_kb: i64 = 32) -> DedicatedWsCompressor {
    return DedicatedWsCompressor {
        window_kb: window_kb,
        ..
    };
}

// Updates the sliding dictionary window with new uncompressed bytes up to `window_kb * 1024` (max 32 KB).
fn update_dedicated_history(dedicated: DedicatedWsCompressor&, raw: const u8[:]) {
    let win_bytes = if dedicated.window_kb > 0 { dedicated.window_kb * 1024 } else { 32768 };
    let max_win = min(win_bytes, min(32768, dedicated.history.cap));
    guard max_win > 0 && raw.len > 0 else { return; }

    if raw.len >= max_win {
        dedicated.history.clear();
        dedicated.history.append(raw[raw.len - max_win..]);
        return;
    }

    let total = dedicated.history.len + raw.len;
    if total > max_win {
        let drop_len = total - max_win;
        let keep_len = dedicated.history.len - drop_len;
        for i in keep_len {
            dedicated.history[i] = dedicated.history[drop_len + i];
        }
        dedicated.history.resize(keep_len);
    }
    dedicated.history.append(raw);
}

fn deflate_message_dedicated<B>(
    dedicated:    DedicatedWsCompressor&,
    raw:          const u8[:],
    out_wire:     B&,
    reset_window: bool = false,
) -> bool {
    guard raw.len > 0 else { return false; }
    dedicated.compress_buf.clear();

    let dict = if reset_window { "" } else { dedicated.history[..] };
    let ok = core::deflate_with_dict(raw, dedicated.compress_buf, 6, dict);
    guard ok && dedicated.compress_buf.len > 0 else {
        dedicated.compress_buf.clear();
        return false;
    }

    var eff_len = dedicated.compress_buf.len;
    // RFC 7692 §7.2.1: Strip 4 trailing bytes 0x00 0x00 0xFF 0xFF
    if eff_len >= 4 {
        let b0 = dedicated.compress_buf[eff_len - 4];
        let b1 = dedicated.compress_buf[eff_len - 3];
        let b2 = dedicated.compress_buf[eff_len - 2];
        let b3 = dedicated.compress_buf[eff_len - 1];
        if b0 == 0x00 && b1 == 0x00 && b2 == 0xFF && b3 == 0xFF {
            eff_len -= 4;
        }
    }

    out_wire.append(dedicated.compress_buf[..eff_len]);
    dedicated.total_compressed += eff_len as u64;
    dedicated.total_uncompressed += raw.len as u64;

    if reset_window {
        dedicated.history.clear();
        dedicated.compress_buf.clear();
    } else {
        update_dedicated_history(dedicated, raw);
    }
    return true;
}

fn inflate_message_dedicated<B>(
    dedicated:    DedicatedWsCompressor&,
    compressed:   const u8[:],
    out_plain:    B&,
    max_payload:  i64  = 65536,
    reset_window: bool = false,
) -> bool {
    out_plain.clear();
    guard compressed.len > 0 else { return false; }
    dedicated.decompress_buf.clear();

    guard compressed.len + 4 <= dedicated.decompress_buf.cap else { return false; }
    dedicated.decompress_buf.append(compressed);
    let tail: u8[4] = [0x00, 0x00, 0xFF, 0xFF];
    dedicated.decompress_buf.append(tail[..]);

    let dict = if reset_window { "" } else { dedicated.history[..] };
    let ok_d, err = core::inflate_with_dict_limit(dedicated.decompress_buf[..], out_plain, dict, max_payload);
    if !ok_d {
        out_plain.clear();
        if err == core::CompressError.OutputBufferOverflow {
            dedicated.decompress_buf.clear();
            return false;
        }
        let ok_raw, _ = core::inflate_with_dict_limit(compressed, out_plain, dict, max_payload);
        if !ok_raw {
            out_plain.clear();
            dedicated.decompress_buf.clear();
            return false;
        }
    }

    dedicated.total_decompressed += out_plain.len as u64;
    if reset_window {
        dedicated.history.clear();
        dedicated.decompress_buf.clear();
    } else {
        update_dedicated_history(dedicated, out_plain[..]);
    }
    return true;
}

// Encodes a compressed RFC 7692 WebSocket frame with RSV1 bit set (0x40).
fn encode_ws_frame_compressed<B>(
    out:                B&,
    opcode:             u8,
    compressed_payload: const u8[:],
    masked:             bool         = false,
    mask_key:           const u8[4]& = [0, 0, 0, 0],
    fin:                bool         = true,
) {
    let eff_payload = if rfc::is_ws_control_opcode(opcode) && compressed_payload.len > 125 {
        compressed_payload[..125]
    } else {
        compressed_payload
    };
    let eff_fin = if rfc::is_ws_control_opcode(opcode) { true } else { fin };
    // RFC 7692 §5.1: RSV1 MUST NOT be set on control frames or continuation frames
    let eff_rsv1 = !rfc::is_ws_control_opcode(opcode) && opcode != rfc::WS_OPCODE_CONTINUATION;
    let hdr = WsFrameHeader {
        fin:         eff_fin,
        rsv1:        eff_rsv1, // Signals compressed frame only for initial data frames
        opcode:      opcode,
        masked:      masked,
        mask_key:    mask_key,
        payload_len: eff_payload.len as u64,
        ..
    };
    hdr.encode(out);
    if masked {
        for i in eff_payload.len {
            out.push(eff_payload[i] ^ mask_key[i % 4]);
        }
    } else {
        out.append(eff_payload);
    }
}

// ---- Handshake Engine (RFC 6455 Section 4.2.2 & RFC 8441) ---------------

// Fast-path template blocks for 24-byte RFC 6455 client key hashing (uWebSockets WebSocketHandshake pattern).
// Block 1: 24 bytes client key + 36 bytes GUID + 0x80 padding + 3 zero bytes = 64 bytes.
let WS_SHA1_BLOCK1_GUID: const u8[40] = [
    '2', '5', '8', 'E', 'A', 'F', 'A', '5', '-', 'E', '9', '1', '4', '-', '4', '7', 'D', 'A',
    '-', '9', '5', 'C', 'A', '-', 'C', '5', 'A', 'B', '0', 'D', 'C', '8', '5', 'B', '1', '1',
    0x80, 0, 0, 0,
];

// Block 2: 56 zero bytes + big-endian 480 bit length (0x01E0) = 64 bytes.
let WS_SHA1_BLOCK2_TEMPLATE: const u8[64] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xE0,
];

// Computes standard `Sec-WebSocket-Accept` from `Sec-WebSocket-Key`.
// Uses zero-allocation unrolled 2-block SHA-1 compression for 24-byte keys (Alex Hultman / uWebSockets pattern).
fn compute_websocket_accept<B>(client_key: const u8[:], out: B&) {
    if client_key.len == 24 {
        var blk1: u8[64] = [0; 64];
        for i in 24 {
            blk1[i] = client_key[i];
        }
        for i in 40 {
            blk1[24 + i] = WS_SHA1_BLOCK1_GUID[i];
        }

        var state: u32[5] = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        ];
        core::sha1_compress(state, blk1[..]);
        core::sha1_compress(state, WS_SHA1_BLOCK2_TEMPLATE[..]);

        var digest: u8[20] = [0; 20];
        for i in 5 {
            let val = state[i];
            digest[i * 4] = ((val >> 24) & 0xFF) as u8;
            digest[i * 4 + 1] = ((val >> 16) & 0xFF) as u8;
            digest[i * 4 + 2] = ((val >> 8) & 0xFF) as u8;
            digest[i * 4 + 3] = (val & 0xFF) as u8;
        }
        core::base64_encode(digest[..], out);
        return;
    }

    // Generic fallback for non-standard key lengths
    var combined: u8[..128] = [];
    guard client_key.len + rfc::WS_HANDSHAKE_GUID.len <= combined.cap else { return; }
    combined.append(client_key);
    combined.append(rfc::WS_HANDSHAKE_GUID);
    let digest = core::sha1(combined[..]);
    core::base64_encode(digest[..], out);
}

// Validates an RFC 6455 §4.2.1 client Sec-WebSocket-Key:
// Must be exactly 24 characters, end in "==", and contain valid Base64 characters representing a 16-byte nonce.
fn is_valid_websocket_key(key: const u8[:]) -> bool {
    guard key.len == 24 else { return false; }
    guard key[22] == '=' && key[23] == '=' else { return false; }

    for i in 22 {
        guard core::base64_val(key[i]) >= 0 else { return false; }
    }
    // RFC 4648 §3.5 / RFC 6455 §4.2.1: 16 bytes (128 bits) encoded in 22 Base64 sextets (132 bits)
    // must have the 4 trailing padding bits of the 22nd character equal to zero.
    return (core::base64_val(key[21]) & 0x0F) == 0;
}

// Validates server `Sec-WebSocket-Accept` against client key
fn validate_websocket_accept(client_key: const u8[:], server_accept: const u8[:]) -> bool {
    guard server_accept.len == 28 else { return false; }
    var expected: u8[..64] = [];
    compute_websocket_accept(client_key, expected);
    guard expected.len == 28 else { return false; }
    return core::ct_eq_bytes(expected[..], server_accept);
}

// Formats a 16-byte random nonce into a 24-character Base64 client key
fn generate_websocket_key<B>(random_16: const u8[16]&, out: B&) {
    core::base64_encode(random_16[..], out);
}

// ---- Close Frame Helpers (RFC 6455 Section 5.5.1) -----------------------

// Encodes a Close frame payload (2-byte status code + optional UTF-8 reason)
fn encode_close_payload<B>(out: B&, status_code: u16, reason: const u8[:]) {
    core::write_be_u16(out, status_code);
    // RFC 6455 §5.5 & §5.5.1 / uWS #1407: Control frame payload must NOT exceed 125 bytes.
    // Close payload contains 2-byte status code, so reason is clamped to at most 123 bytes.
    var eff_len = reason.len;
    if eff_len > 123 {
        eff_len = 123;
        // Avoid truncating in the middle of a multi-byte UTF-8 sequence:
        // A cut at eff_len splits a UTF-8 codepoint iff reason[eff_len] is a continuation byte (10xxxxxx).
        while eff_len > 0 && (reason[eff_len] & 0xC0) == 0x80 {
            eff_len--;
        }
    }
    out.append(reason[..eff_len]);
}

// Parses a Close frame payload into (status_code, reason_slice, ok)
//
// Example:
//   payload = [0x03, 0xE8, 'b', 'y', 'e']
//   returns: status_code = 1000, reason = "bye", ok = true
fn parse_close_payload(payload: const u8[:]) -> u16, const u8[:], bool {
    if payload.len == 0 {
        return rfc::WS_STATUS_NO_STATUS, "", true;
    }
    guard payload.len >= 2 else { return 0, "", false; }
    // RFC 6455 Section 5.5 & 5.5.1: Control frame payload must not exceed 125 bytes
    guard payload.len <= 125 else { return 0, "", false; }

    let status_code = core::read_be_u16(payload, 0);
    let reason = payload[2..];

    // RFC 6455 Section 7.4.1 & 7.4.2: Validate permitted status codes on wire
    guard rfc::is_valid_ws_close_code(status_code) else { return 0, "", false; }

    return status_code, reason, true;
}

// ---- High-Level Ergonomic WebSocket Client Session -----------------------

// Backpressure and Send Status Codes (uWebSockets pattern)
enum WsSendStatus {
    Success,      // Sent immediately or queued below backpressure threshold
    Backpressure, // Queued successfully, but socket has active backpressure (buffered_amount > 0)
    Dropped,      // Message dropped because max_backpressure limit was exceeded
    Closed,       // Socket was closed or aborted due to backpressure overflow
}

// Declarative WebSocket Endpoint Behavior Specification (uWebSockets App::ws pattern)
struct WsBehavior {
    compression:                 u16      = WS_COMPRESS_DISABLED, // WS_COMPRESS_SHARED_COMPRESSOR
    max_payload_length:          u64      = 65536,
    idle_timeout_s:              u32      = 120,
    max_lifetime_s:              u32      = 0, // Maximum session duration in seconds (0 = unlimited)
    max_backpressure:            u64      = 1048576, // 1 MB default
    close_on_backpressure_limit: bool     = false,
    reset_idle_timeout_on_send:  bool     = true,
    send_pings_automatically:    bool     = false,
    subprotocol:                 u8[..64] = [],
    handler_id:                  i32      = -1,
}

fn new_ws_behavior(handler_id: i32 = -1) -> WsBehavior {
    return WsBehavior { handler_id: handler_id, .. };
}

// Detects Safari 15.0 - 15.3 user-agents with broken permessage-deflate implementations (uWebSockets #1347).
fn ws_has_broken_compression(user_agent: const u8[:]) -> bool {
    let marker = " Version/15.";
    let pos = find(user_agent, marker);
    guard pos >= 0 else { return false; }

    var idx = pos + marker.len;
    guard idx < user_agent.len else { return false; }

    var minor: u32 = 0;
    var has_digits = false;
    while idx < user_agent.len && user_agent[idx] >= '0' && user_agent[idx] <= '9' {
        minor = minor * 10 + (user_agent[idx] - '0');
        // Safari 15.0 - 15.3 were affected; 15.4+ fixed the bug
        guard minor <= 3 else { return false; }
        has_digits = true;
        idx++;
    }
    guard has_digits && idx < user_agent.len && user_agent[idx] == ' ' else { return false; }

    let safari_marker = " Safari/";
    let safari_pos = find(user_agent[idx..], safari_marker);
    return safari_pos >= 0;
}

struct WebSocketSession {
    is_client:          bool     = true,
    subprotocol:        u8[..64] = [],
    is_closed:          bool     = false,
    close_received:     bool     = false, // RFC 6455 §5.5.1: Peer close frame received
    close_code:         u16      = 0,
    max_payload_length: u64      = 65536, // Maximum allowed frame payload length (0 = unlimited)
    mask_rng_state:     u32      = 0x9E3779B9, // Fast linear congruential PRNG for 4-byte client masking keys

    // Multi-frame fragmented message assembly (RFC 6455 §5.4 & RFC 7692 §5.1)
    frag_opcode:      u8          = 0,     // 0 if no active fragmentation; WS_OPCODE_TEXT or WS_OPCODE_BINARY
    frag_compressed:  bool        = false, // RFC 7692: remembers if initial fragment had RSV1 set
    frag_utf8_offset: i64         = 0,     // Validated UTF-8 prefix byte offset across streaming fragments
    frag_buffer:      u8[..65536] = [],    // Assembly buffer for fragmented messages

    // RFC 7692 PerMessageDeflate configuration (uWebSockets pattern)
    compress_mode:              u16  = WS_COMPRESS_DISABLED,
    permessage_deflate:         bool = false,
    server_no_context_takeover: bool = true,
    client_no_context_takeover: bool = true,

    // Per-socket UserData / Typed User Context (uWebSockets getUserData pattern)
    user_tag:  u64       = 0,
    user_data: u8[..128] = [],

    // Backpressure & Dynamic Flow Control (uWebSockets Backpressure pattern)
    buffered_amount:             u64  = 0,
    max_backpressure:            u64  = 1048576, // 1 MB default
    close_on_backpressure_limit: bool = false,
    is_backpressured:            bool = false,
    dropped_messages_count:      u64  = 0,

    // Keep-Alive & Auto-Ping Heartbeat (uWebSockets sendPingsAutomatically & idleTimeout)
    idle_timeout_s:             u32  = 120,
    max_lifetime_s:             u32  = 0,
    elapsed_lifetime_s:         u32  = 0,
    send_pings_automatically:   bool = false,
    reset_idle_timeout_on_send: bool = true,
    timeout_slot:               u8   = TICK_TIMER_DISARMED,
    ping_slot:                  u8   = TICK_TIMER_DISARMED,
    pings_sent:                 u64  = 0,
    pongs_received:             u64  = 0,
}

fn new_websocket_session(is_client: bool = true) -> WebSocketSession {
    return WebSocketSession { is_client: is_client, .. };
}

fn set_max_payload_length(ws: WebSocketSession&, max_len: u64) {
    ws.max_payload_length = max_len;
}

// Configuration options for RFC 7692 context takeover sliding window boundaries
struct WsContextTakeoverOptions {
    server_no_context: bool = false,
    client_no_context: bool = false,
}

// RFC 7692 §7.1.1: Configures sliding window context takeover boundaries
fn set_context_takeover(ws: WebSocketSession&, opts: WsContextTakeoverOptions) {
    ws.server_no_context_takeover = opts.server_no_context;
    ws.client_no_context_takeover = opts.client_no_context;
}

// RFC 7692 §7.1.1: Determines if outbound compressor sliding window must be reset after sending
fn ws_should_reset_compressor(ws: const WebSocketSession&) -> bool {
    let should_reset = if ws.is_client {
        ws.client_no_context_takeover
    } else {
        ws.server_no_context_takeover
    };
    return should_reset;
}

// RFC 7692 §7.1.1: Determines if inbound decompressor sliding window must be reset after receiving
fn ws_should_reset_decompressor(ws: const WebSocketSession&) -> bool {
    let should_reset = if ws.is_client {
        ws.server_no_context_takeover
    } else {
        ws.client_no_context_takeover
    };
    return should_reset;
}

// Heartbeat action result for WebSocket keep-alive / auto-ping daemon
enum WsHeartbeatAction {
    None,
    SendPing,
    CloseIdle,
    CloseMaxLifetime,
}

// Arms connection slot timeouts in modular tick wheel (uSockets loop.c / uWebSockets pattern)
fn arm_heartbeat(ws: WebSocketSession&, wheel: const TickTimerWheel&) {
    if ws.idle_timeout_s > 0 {
        let idle_sec = if ws.idle_timeout_s > 239 { 239 as u8 } else { ws.idle_timeout_s as u8 };
        ws.timeout_slot = tick_timer_arm(wheel, idle_sec);
        if ws.send_pings_automatically && ws.idle_timeout_s > 1 {
            let ping_delay = ((ws.idle_timeout_s / 2) % 240) as u8;
            ws.ping_slot = tick_timer_arm(wheel, if ping_delay > 0 { ping_delay } else { 1 });
        } else {
            ws.ping_slot = TICK_TIMER_DISARMED;
        }
    } else {
        ws.timeout_slot = TICK_TIMER_DISARMED;
        ws.ping_slot = TICK_TIMER_DISARMED;
    }
}

// Disarms heartbeat timers
fn disarm_heartbeat(ws: WebSocketSession&) {
    ws.timeout_slot = TICK_TIMER_DISARMED;
    ws.ping_slot = TICK_TIMER_DISARMED;
}

// Advances session lifetime counter by elapsed_seconds (uWebSockets maxLifetime sweeper).
fn ws_advance_lifetime(ws: WebSocketSession&, elapsed_seconds: u32 = 1) {
    ws.elapsed_lifetime_s += elapsed_seconds;
}

// Touches the session to reset idle timeout on incoming frame or send
fn touch(ws: WebSocketSession&, wheel: const TickTimerWheel&) {
    if ws.timeout_slot != TICK_TIMER_DISARMED {
        arm_heartbeat(ws, wheel);
    }
}

// Evaluates heartbeat tick without serializing wire bytes
fn check_heartbeat(ws: WebSocketSession&, wheel: const TickTimerWheel&) -> WsHeartbeatAction {
    if ws.is_closed { return WsHeartbeatAction.None; }
    if ws.max_lifetime_s > 0 && ws.elapsed_lifetime_s >= ws.max_lifetime_s {
        return WsHeartbeatAction.CloseMaxLifetime;
    }
    if ws.timeout_slot != TICK_TIMER_DISARMED && tick_timer_is_expired(wheel, ws.timeout_slot) {
        return WsHeartbeatAction.CloseIdle;
    }
    if !ws.close_received && ws.send_pings_automatically && ws.ping_slot != TICK_TIMER_DISARMED &&
        tick_timer_is_expired(wheel, ws.ping_slot) {
        return WsHeartbeatAction.SendPing;
    }
    return WsHeartbeatAction.None;
}

// Executes periodic heartbeat check and automatically writes Ping or Close frame
fn tick_heartbeat<B>(ws: WebSocketSession&, wheel: const TickTimerWheel&, out_wire: B&) -> WsHeartbeatAction {
    let action = check_heartbeat(ws, wheel);
    if action == WsHeartbeatAction.SendPing {
        send_ping(ws, "", out_wire);
        let ping_delay = if ws.idle_timeout_s > 1 { ((ws.idle_timeout_s / 2) % 240) as u8 } else { 1 as u8 };
        ws.ping_slot = tick_timer_arm(wheel, ping_delay);
    } else if action == WsHeartbeatAction.CloseIdle {
        close(ws, rfc::WS_STATUS_NORMAL, "Idle timeout", out_wire);
        ws.is_closed = true;
        ws.close_code = rfc::WS_STATUS_NORMAL;
    } else if action == WsHeartbeatAction.CloseMaxLifetime {
        close(ws, rfc::WS_STATUS_NORMAL, "Max lifetime reached", out_wire);
        ws.is_closed = true;
        ws.close_code = rfc::WS_STATUS_NORMAL;
    }
    return action;
}

// Asynchronous WebSocket Upgrade Pending Context (uWebSockets res->onAborted & res->upgrade pattern)
struct WsPendingUpgrade {
    sock_fd:     i64       = -1,
    route_idx:   i32       = -1,
    client_key:  u8[..64]  = [],
    subprotocol: u8[..64]  = [],
    extensions:  u8[..256] = [],
    user_tag:    u64       = 0,
    user_data:   u8[..128] = [],
    is_aborted:  bool      = false,
    in_use:      bool      = false,
}

fn new_ws_pending_upgrade(
    sock_fd:     i64,
    client_key:  const u8[:],
    route_idx:   i32         = -1,
    subprotocol: const u8[:] = "",
    extensions:  const u8[:] = "",
) -> WsPendingUpgrade {
    var p = WsPendingUpgrade {
        sock_fd:    sock_fd,
        route_idx:  route_idx,
        is_aborted: false,
        in_use:     true,
        ..
    };
    let k_len = min(client_key.len, p.client_key.cap);
    p.client_key.append(client_key[..k_len]);
    if subprotocol.len > 0 {
        let s_len = min(subprotocol.len, p.subprotocol.cap);
        p.subprotocol.append(subprotocol[..s_len]);
    }
    if extensions.len > 0 {
        let e_len = min(extensions.len, p.extensions.cap);
        p.extensions.append(extensions[..e_len]);
    }
    return p;
}

fn abort(pending: WsPendingUpgrade&) {
    pending.is_aborted = true;
    pending.in_use = false;
}

fn abort_with_hook<AbortFn: fn(i64, u64)>(pending: WsPendingUpgrade&) {
    pending.is_aborted = true;
    pending.in_use = false;
    AbortFn(pending.sock_fd, pending.user_tag);
}

fn set_user_data(pending: WsPendingUpgrade&, data: const u8[:]) -> bool {
    pending.user_data.clear();
    guard data.len <= pending.user_data.cap else { return false; }
    pending.user_data.append(data);
    return true;
}

fn set_user_tag(pending: WsPendingUpgrade&, tag: u64) {
    pending.user_tag = tag;
}

// Per-Socket UserData accessors (zero-alloc inline context)
fn set_user_data(ws: WebSocketSession&, data: const u8[:]) -> bool {
    ws.user_data.clear();
    guard data.len <= ws.user_data.cap else { return false; }
    ws.user_data.append(data);
    return true;
}

fn set_user_tag(ws: WebSocketSession&, tag: u64) {
    ws.user_tag = tag;
}

fn set_max_backpressure(ws: WebSocketSession&, max_bytes: u64, close_on_limit: bool = false) {
    ws.max_backpressure = max_bytes;
    ws.close_on_backpressure_limit = close_on_limit;
}

// Notifies the session of outbound bytes buffered for delivery.
// Enforces max_backpressure and overflow drop/close policies.
fn notify_buffered<B>(ws: WebSocketSession&, bytes_added: u64, out_close: B&) -> WsSendStatus {
    guard !ws.is_closed && !ws.close_received else { return WsSendStatus.Closed; }
    if bytes_added > ws.max_backpressure || ws.buffered_amount > ws.max_backpressure - bytes_added {
        if ws.close_on_backpressure_limit {
            close(ws, rfc::WS_STATUS_POLICY_VIOLATION, "backpressure limit exceeded", out_close);
            return WsSendStatus.Closed;
        } else {
            ws.dropped_messages_count += 1;
            return WsSendStatus.Dropped;
        }
    }
    ws.buffered_amount += bytes_added;
    if ws.buffered_amount > 0 {
        ws.is_backpressured = true;
        return WsSendStatus.Backpressure;
    }
    return WsSendStatus.Success;
}

// Notifies the session of completed network buffer drainage.
// Returns true when the buffer drops to 0 from a backpressured state, triggering the 'drain' event.
fn notify_drained(ws: WebSocketSession&, bytes_drained: u64) -> bool {
    if bytes_drained >= ws.buffered_amount {
        ws.buffered_amount = 0;
    } else {
        ws.buffered_amount -= bytes_drained;
    }
    if ws.buffered_amount == 0 && ws.is_backpressured {
        ws.is_backpressured = false;
        return true;
    }
    return false;
}

// Configures PerMessageDeflate (RFC 7692) on the WebSocket session
fn enable_permessage_deflate(
    ws:   WebSocketSession&,
    mode: u16 = WS_COMPRESS_SHARED_COMPRESSOR,
    opts: WsContextTakeoverOptions = WsContextTakeoverOptions {
        server_no_context: true,
        client_no_context: true,
    },
) {
    ws.permessage_deflate = true;
    ws.compress_mode = mode;
    ws.server_no_context_takeover = opts.server_no_context;
    ws.client_no_context_takeover = opts.client_no_context;
}

// Generates cryptographically secure 4-byte masking key for client frames per RFC 6455 Section 5.3.
fn ws_next_mask_key(ws: WebSocketSession&) -> u8[4] {
    var mask: u8[4] = [0; 4];
    if native_crypto_random_bytes(mask[..]) == 0 {
        return mask;
    }
    // High-entropy fallback if OS CSPRNG is unavailable
    ws.mask_rng_state = ws.mask_rng_state * 1664525 + 1013904223;
    let s = ws.mask_rng_state;
    return [
        ((s >> 24) & 0xFF) as u8,
        ((s >> 16) & 0xFF) as u8,
        ((s >> 8) & 0xFF) as u8,
        (s & 0xFF) as u8,
    ];
}

// Formats outbound RFC 6455 Handshake HTTP/1.1 Upgrade Request
fn build_handshake_request<B>(
    ws:         const WebSocketSession&,
    host:       const u8[:],
    path:       const u8[:],
    client_key: const u8[:],
    out:        B&,
) {
    // RFC 6455 §4.1 & RFC 9112 §3.2.1 & Go #76635: If path is empty, default to '/'
    let eff_path = if path.len > 0 { path } else { "/" };
    format(out, "GET ", eff_path, " HTTP/1.1\r\nHost: ", host);
    format(
        out,
        "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ",
        client_key,
    );
    if ws.subprotocol.len > 0 {
        format(out, "\r\nSec-WebSocket-Protocol: ", ws.subprotocol[..]);
    }
    out.append("\r\n\r\n");
}

// High-level method: sends UTF-8 text message
fn send_text<B>(ws: WebSocketSession&, text: const u8[:], out: B&) {
    // RFC 6455 §5.5.1 & uWS #1932: Once closed or close received, drop outgoing message writes
    guard !ws.is_closed && !ws.close_received else { return; }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, rfc::WS_OPCODE_TEXT, text, ws.is_client, mask, true);
}

// Sends UTF-8 text message with backpressure tracking and status code (uWebSockets sendStatus pattern)
fn send_text_with_status<B>(
    ws:       WebSocketSession&,
    text:     const u8[:],
    out:      B&,
    compress: bool = false,
) -> WsSendStatus {
    guard !ws.is_closed && !ws.close_received else { return WsSendStatus.Closed; }
    let frame_len = calc_ws_frame_len(text.len as u64, ws.is_client);
    let status = notify_buffered(ws, frame_len, out);
    if status == WsSendStatus.Dropped || status == WsSendStatus.Closed {
        return status;
    }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, rfc::WS_OPCODE_TEXT, text, ws.is_client, mask, true);
    return status;
}

// Sends UTF-8 text message with shared compressor and backpressure tracking
fn send_text_compressed_with_status<B>(
    ws:          WebSocketSession&,
    text:        const u8[:],
    shared_comp: SharedWsCompressor&,
    out:         B&,
    compress:    bool = true,
) -> WsSendStatus {
    guard !ws.is_closed && !ws.close_received else { return WsSendStatus.Closed; }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };

    if compress && ws.permessage_deflate && text.len > 0 {
        let reset_win = ws_should_reset_compressor(ws);
        let comp_wire, ok_comp = ws_deflate_message_slice(shared_comp, text, reset_win);
        if ok_comp && comp_wire.len < text.len {
            let frame_len = calc_ws_frame_len(comp_wire.len as u64, ws.is_client);
            let status = notify_buffered(ws, frame_len, out);
            if status == WsSendStatus.Dropped || status == WsSendStatus.Closed {
                return status;
            }
            encode_ws_frame_compressed(out, rfc::WS_OPCODE_TEXT, comp_wire, ws.is_client, mask, true);
            return status;
        }
    }

    let frame_len = calc_ws_frame_len(text.len as u64, ws.is_client);
    let status = notify_buffered(ws, frame_len, out);
    if status == WsSendStatus.Dropped || status == WsSendStatus.Closed {
        return status;
    }
    encode_ws_frame(out, rfc::WS_OPCODE_TEXT, text, ws.is_client, mask, true);
    return status;
}

// High-level method: sends binary message
fn send_binary<B>(ws: WebSocketSession&, data: const u8[:], out: B&) {
    // RFC 6455 §5.5.1 & uWS #1932: Once closed or close received, drop outgoing message writes
    guard !ws.is_closed && !ws.close_received else { return; }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, rfc::WS_OPCODE_BINARY, data, ws.is_client, mask, true);
}

// Sends binary message with backpressure tracking and status code (uWebSockets sendStatus pattern)
fn send_binary_with_status<B>(
    ws:       WebSocketSession&,
    data:     const u8[:],
    out:      B&,
    compress: bool = false,
) -> WsSendStatus {
    guard !ws.is_closed && !ws.close_received else { return WsSendStatus.Closed; }
    let frame_len = calc_ws_frame_len(data.len as u64, ws.is_client);
    let status = notify_buffered(ws, frame_len, out);
    if status == WsSendStatus.Dropped || status == WsSendStatus.Closed {
        return status;
    }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, rfc::WS_OPCODE_BINARY, data, ws.is_client, mask, true);
    return status;
}

// Sends binary message with shared compressor and backpressure tracking
fn send_binary_compressed_with_status<B>(
    ws:          WebSocketSession&,
    data:        const u8[:],
    shared_comp: SharedWsCompressor&,
    out:         B&,
    compress:    bool = true,
) -> WsSendStatus {
    guard !ws.is_closed && !ws.close_received else { return WsSendStatus.Closed; }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };

    if compress && ws.permessage_deflate && data.len > 0 {
        let reset_win = ws_should_reset_compressor(ws);
        let comp_wire, ok_comp = ws_deflate_message_slice(shared_comp, data, reset_win);
        if ok_comp && comp_wire.len < data.len {
            let frame_len = calc_ws_frame_len(comp_wire.len as u64, ws.is_client);
            let status = notify_buffered(ws, frame_len, out);
            if status == WsSendStatus.Dropped || status == WsSendStatus.Closed {
                return status;
            }
            encode_ws_frame_compressed(out, rfc::WS_OPCODE_BINARY, comp_wire, ws.is_client, mask, true);
            return status;
        }
    }

    let frame_len = calc_ws_frame_len(data.len as u64, ws.is_client);
    let status = notify_buffered(ws, frame_len, out);
    if status == WsSendStatus.Dropped || status == WsSendStatus.Closed {
        return status;
    }
    encode_ws_frame(out, rfc::WS_OPCODE_BINARY, data, ws.is_client, mask, true);
    return status;
}

// High-level method: sends Ping heartbeat
fn send_ping<B>(ws: WebSocketSession&, ping_payload: const u8[:], out: B&) {
    // RFC 6455 §5.5.1 & uWS #1932: Once closed or close received, drop outgoing heartbeat writes
    guard !ws.is_closed && !ws.close_received else { return; }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, rfc::WS_OPCODE_PING, ping_payload, ws.is_client, mask, true);
    ws.pings_sent += 1;
}

// High-level method: sends Pong heartbeat response
fn send_pong<B>(ws: WebSocketSession&, pong_payload: const u8[:], out: B&) {
    // RFC 6455 §5.5.1 & uWS #1932: Once closed or close received, drop outgoing heartbeat writes
    guard !ws.is_closed && !ws.close_received else { return; }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, rfc::WS_OPCODE_PONG, pong_payload, ws.is_client, mask, true);
}

// High-level method: sends Close handshake
fn close<B>(ws: WebSocketSession&, status_code: u16, reason: const u8[:], out: B&) {
    guard !ws.is_closed else { return; }
    var payload: u8[..128] = [];
    // RFC 6455 §7.4.1 / Autobahn 7.1.x:
    // Status codes 1005 (No Status), 1006 (Abnormal), and 0 are internal and MUST NOT be sent on the wire.
    // Invalid codes (<1000, >=5000, 1016..2999, 1004, 1015) MUST NOT be sent on the wire.
    if rfc::is_valid_ws_close_code(status_code) {
        // RFC 6455 §5.5.1: Close reason MUST be valid UTF-8
        let eff_reason = if reason.len > 0 && core::validate_utf8(reason) { reason } else { "" };
        encode_close_payload(payload, status_code, eff_reason);
    }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, rfc::WS_OPCODE_CLOSE, payload[..], ws.is_client, mask, true);
    ws.is_closed = true;
    ws.close_code = status_code;
    ws.frag_opcode = 0;
    ws.frag_compressed = false;
    ws.frag_utf8_offset = 0;
    ws.frag_buffer.clear();
}

// ---- High-Level Message Dispatcher & Server Upgrade ---------------------

struct WsMessage {
    opcode:       u8          = rfc::WS_OPCODE_TEXT,
    data:         u8[..16384] = [],
    close_code:   u16         = 0,
    close_reason: u8[..128]   = [],
    is_valid:     bool        = false,
}

// Zero-copy non-owning view of a WebSocket message pointing directly into the ingress buffer.
// Matches uWebSockets std::string_view on_message callback pattern with 0 heap allocs and 0 memcpy.
struct WsMessageView {
    opcode:        u8          = rfc::WS_OPCODE_TEXT,
    payload:       const u8[:] = "",
    close_code:    u16         = 0,
    close_reason:  const u8[:] = "",
    is_valid:      bool        = false,
    is_compressed: bool        = false,
}

enum WsRole {
    Client,
    Server,
}

fn is_ws_masking_valid(role: WsRole, masked: bool) -> bool {
    if role == WsRole.Client && masked {
        return false;
    }
    if role == WsRole.Server && !masked {
        return false;
    }
    return true;
}

// Dispatches incoming raw frame wire bytes using zero-copy non-owning payload views:
// unmasks payload in-place, handles Ping/Pong and Close echoes, validates strict streaming UTF-8,
// and returns (handled, view) with a direct slice of the wire ingress buffer into view without copying.
fn receive_view_into<B, F>(
    ws:           WebSocketSession&,
    wire:         u8[:],
    frag_buf:     F&,
    max_frag_cap: i64,
    out_reply:    B&,
) -> bool, WsMessageView {
    var out_view = WsMessageView { .. };

    // RFC 6455 §5.5 & uWS #1407: Fail connection with PROTOCOL_ERROR (1002) upon fatal header invariant violations
    if wire.len >= 2 {
        let b0 = wire[0];
        let b1 = wire[1];
        let fin = (b0 & 0x80) != 0;
        let opcode = b0 & 0x0F;
        let raw_len = (b1 & 0x7F);

        if !rfc::is_valid_ws_opcode(opcode) {
            close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "unknown opcode", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return true, out_view;
        }

        if rfc::is_ws_control_opcode(opcode) && !fin {
            close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "fragmented control frame", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return true, out_view;
        }

        if rfc::is_ws_control_opcode(opcode) && raw_len > 125 {
            close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "control frame payload > 125", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return true, out_view;
        }

        // RFC 6455 §5.4: Interleaved data frame during fragmentation
        if (opcode == rfc::WS_OPCODE_TEXT || opcode == rfc::WS_OPCODE_BINARY) && ws.frag_opcode != 0 {
            close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "interleaved data frame during fragmentation", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            ws.frag_opcode = 0;
            ws.frag_compressed = false;
            ws.frag_utf8_offset = 0;
            frag_buf.clear();
            return true, out_view;
        }

        // RFC 6455 §5.4: Continuation frame without starting fragment
        if opcode == rfc::WS_OPCODE_CONTINUATION && ws.frag_opcode == 0 {
            close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "continuation frame without starting fragment", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return true, out_view;
        }

        // RFC 6455 §5.1: Masking enforcement - check immediately upon receiving header
        let masked = (b1 & 0x80) != 0;
        let role = if ws.is_client { WsRole.Client } else { WsRole.Server };
        if !is_ws_masking_valid(role, masked) {
            let reason = if ws.is_client {
                "masked frame received by client"
            } else {
                "unmasked frame received by server"
            };
            close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, reason, out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return true, out_view;
        }

        // RFC 6455 §5.2 & RFC 7692 §5.1: RSV bit enforcement - check immediately upon receiving header
        let rsv1_bit = (b0 & 0x40) != 0;
        let rsv2_bit = (b0 & 0x20) != 0;
        let rsv3_bit = (b0 & 0x10) != 0;
        let rsv1_allowed = ws.permessage_deflate && (opcode == rfc::WS_OPCODE_TEXT || opcode == rfc::WS_OPCODE_BINARY);
        if (rsv1_bit && !rsv1_allowed) || rsv2_bit || rsv3_bit {
            close(
                ws, rfc::WS_STATUS_PROTOCOL_ERROR,
                "RSV bits set without extension or on non-initial data frame", out_reply,
            );
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return true, out_view;
        }

        // RFC 6455 §5.2 & Autobahn Cases 3.1..3.4:
        // Fail connection with 1002 on non-minimal length representations or high bit set in 64-bit length
        if raw_len == 126 && wire.len >= 4 {
            let p_len = core::read_be_u16(wire, 2);
            if p_len < 126 {
                close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "non-minimal 16-bit length encoding", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
                return true, out_view;
            }
        } else if raw_len == 127 && wire.len >= 10 {
            if (wire[2] & 0x80) != 0 {
                close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "high bit set in 64-bit length", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
                return true, out_view;
            }
            let p_len = core::read_be_u64(wire, 2);
            if p_len <= 65535 {
                close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "non-minimal 64-bit length encoding", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
                return true, out_view;
            }
        }
    }

    let hdr, ok = parse_ws_frame_header(wire);
    guard ok else { return false, out_view; }

    // RFC 6455 §5.5.1: If connection is closing or closed, incoming data frames MUST be discarded
    if ws.is_closed || ws.close_received {
        if !rfc::is_ws_control_opcode(hdr.opcode) {
            out_view.is_valid = false;
            return false, out_view;
        }
    }

    // RFC 6455 §7.4.1 (1009) & Memory Safety:
    // Fast-fail oversized frames immediately from header without waiting to buffer the full wire payload
    if !rfc::is_ws_control_opcode(hdr.opcode) && ws.max_payload_length > 0 && hdr.payload_len > ws.max_payload_length {
        close(ws, rfc::WS_STATUS_MESSAGE_TOO_BIG, "payload length exceeds max_payload_length", out_reply);
        ws.is_closed = true;
        ws.close_code = rfc::WS_STATUS_MESSAGE_TOO_BIG;
        ws.frag_opcode = 0;
        ws.frag_compressed = false;
        ws.frag_utf8_offset = 0;
        frag_buf.clear();
        return true, out_view;
    }

    let wire_len = wire.len as u64;
    let p_start_u = hdr.header_len as u64;
    guard p_start_u <= wire_len && hdr.payload_len <= (wire_len - p_start_u) else { return false, out_view; }
    let p_start = hdr.header_len as i64;
    let p_len = hdr.payload_len as i64;
    let payload = wire[p_start..(p_start + p_len)];

    if hdr.masked {
        mask_websocket_payload(payload, hdr.mask_key);
    }

    // Control frames (RFC 6455 §5.5) - can arrive interleaved in fragmented messages
    if rfc::is_ws_control_opcode(hdr.opcode) {
        if hdr.opcode == rfc::WS_OPCODE_PING {
            send_pong(ws, payload, out_reply);
            out_view.opcode = rfc::WS_OPCODE_PING;
            out_view.payload = payload;
            out_view.is_valid = true;
            return true, out_view;
        } else if hdr.opcode == rfc::WS_OPCODE_PONG {
            ws.pongs_received += 1;
            out_view.opcode = rfc::WS_OPCODE_PONG;
            out_view.payload = payload;
            out_view.is_valid = true;
            return true, out_view;
        } else if hdr.opcode == rfc::WS_OPCODE_CLOSE {
            if ws.close_received {
                // RFC 6455 §5.5.1: Duplicate Close frame received; ignore/discard
                out_view.is_valid = false;
                return false, out_view;
            }
            ws.close_received = true;
            let code, reason, ok_close = parse_close_payload(payload);
            if !ok_close {
                close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "invalid close frame payload", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
                ws.frag_opcode = 0;
                ws.frag_compressed = false;
                ws.frag_utf8_offset = 0;
                frag_buf.clear();
                return true, out_view;
            }
            // RFC 6455 §5.5.1 / §8.1 / §7.4.1 / Autobahn 6.4.1: Close reason MUST be valid UTF-8
            if reason.len > 0 && !core::validate_utf8(reason) {
                close(ws, rfc::WS_STATUS_INVALID_PAYLOAD, "invalid UTF-8 in close reason", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_INVALID_PAYLOAD;
                ws.frag_opcode = 0;
                ws.frag_compressed = false;
                ws.frag_utf8_offset = 0;
                frag_buf.clear();
                return true, out_view;
            }
            out_view.opcode = rfc::WS_OPCODE_CLOSE;
            out_view.close_code = code;
            out_view.close_reason = reason;
            out_view.is_valid = true;
            if !ws.is_closed {
                // RFC 6455 §7.1.5: If received close contains no body (code 1005), response contains no body
                let reply_code = if code == rfc::WS_STATUS_NO_STATUS { rfc::WS_STATUS_NO_STATUS } else { code };
                close(ws, reply_code, reason, out_reply);
            }
            ws.is_closed = true;
            ws.close_code = code;
            ws.frag_opcode = 0;
            ws.frag_compressed = false;
            ws.frag_utf8_offset = 0;
            frag_buf.clear();
            return true, out_view;
        }
    }

    // Data frames (RFC 6455 §5.4 & §5.6)
    if hdr.opcode == rfc::WS_OPCODE_TEXT || hdr.opcode == rfc::WS_OPCODE_BINARY {
        if ws.frag_opcode != 0 {
            close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "interleaved data frame during fragmentation", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            ws.frag_opcode = 0;
            ws.frag_compressed = false;
            ws.frag_utf8_offset = 0;
            frag_buf.clear();
            return true, out_view;
        }

        if hdr.fin {
            // Unfragmented single-frame message: Zero-copy direct slice!
            if ws.max_payload_length > 0 && (payload.len as u64) > ws.max_payload_length {
                close(ws, rfc::WS_STATUS_MESSAGE_TOO_BIG, "payload exceeds capacity", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_MESSAGE_TOO_BIG;
                out_view.is_valid = false;
                return true, out_view;
            }
            // RFC 7692 Section 6.1: Compression - UTF-8 validation only applies to uncompressed plaintext payload
            let need_utf8 = hdr.opcode == rfc::WS_OPCODE_TEXT && !hdr.rsv1;
            if need_utf8 && !core::validate_utf8(payload) {
                close(ws, rfc::WS_STATUS_INVALID_PAYLOAD, "invalid UTF-8 in text frame", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_INVALID_PAYLOAD;
                return true, out_view;
            }
            out_view.opcode = hdr.opcode;
            out_view.payload = payload;
            out_view.is_valid = true;
            out_view.is_compressed = hdr.rsv1;
            return true, out_view;
        }

        // Initial fragment of a multi-frame message
        ws.frag_opcode = hdr.opcode;
        ws.frag_compressed = hdr.rsv1;
        ws.frag_utf8_offset = 0;
        frag_buf.clear();
        let max_len_i64 = min(ws.max_payload_length, 0x7FFFFFFFFFFFFFFF) as i64;
        let eff_cap = if ws.max_payload_length > 0 && max_len_i64 < max_frag_cap {
            max_len_i64
        } else {
            max_frag_cap
        };
        if eff_cap <= 0 || payload.len > eff_cap {
            close(ws, rfc::WS_STATUS_MESSAGE_TOO_BIG, "fragment exceeds capacity", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_MESSAGE_TOO_BIG;
            ws.frag_opcode = 0;
            ws.frag_compressed = false;
            ws.frag_utf8_offset = 0;
            frag_buf.clear();
            return true, out_view;
        }
        frag_buf.append(payload);

        // RFC 6455 §8.1 / Autobahn 6.4.x: Fast streaming UTF-8 validation on initial fragment
        if ws.frag_opcode == rfc::WS_OPCODE_TEXT && !ws.frag_compressed {
            let valid_len, ok_u8 = core::validate_utf8_streaming(frag_buf[..], false);
            if !ok_u8 {
                close(ws, rfc::WS_STATUS_INVALID_PAYLOAD, "invalid UTF-8 in initial fragment", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_INVALID_PAYLOAD;
                ws.frag_opcode = 0;
                ws.frag_compressed = false;
                ws.frag_utf8_offset = 0;
                frag_buf.clear();
                return true, out_view;
            }
            ws.frag_utf8_offset = valid_len;
        }

        out_view.is_valid = false;
        return true, out_view;
    } else if hdr.opcode == rfc::WS_OPCODE_CONTINUATION {
        if ws.frag_opcode == 0 {
            close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "continuation frame without starting fragment", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return true, out_view;
        }

        let max_len_i64 = min(ws.max_payload_length, 0x7FFFFFFFFFFFFFFF) as i64;
        let eff_cap = if ws.max_payload_length > 0 && max_len_i64 < max_frag_cap {
            max_len_i64
        } else {
            max_frag_cap
        };
        if eff_cap <= 0 || payload.len > eff_cap - frag_buf.len {
            close(ws, rfc::WS_STATUS_MESSAGE_TOO_BIG, "assembled payload exceeds capacity", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_MESSAGE_TOO_BIG;
            ws.frag_opcode = 0;
            ws.frag_compressed = false;
            ws.frag_utf8_offset = 0;
            frag_buf.clear();
            return true, out_view;
        }
        frag_buf.append(payload);

        // RFC 6455 §8.1 / Autobahn 6.4.x: Fast streaming UTF-8 validation across fragment boundary
        if ws.frag_opcode == rfc::WS_OPCODE_TEXT && !ws.frag_compressed {
            let valid_len, ok_u8 = core::validate_utf8_streaming(frag_buf[ws.frag_utf8_offset..], hdr.fin);
            if !ok_u8 {
                let err_msg = if hdr.fin { "invalid UTF-8 in assembled message" } else { "invalid UTF-8 in fragment" };
                close(ws, rfc::WS_STATUS_INVALID_PAYLOAD, err_msg, out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_INVALID_PAYLOAD;
                ws.frag_opcode = 0;
                ws.frag_compressed = false;
                ws.frag_utf8_offset = 0;
                frag_buf.clear();
                return true, out_view;
            }
            ws.frag_utf8_offset += valid_len;
        }

        if hdr.fin {
            let was_compressed = ws.frag_compressed;
            out_view.opcode = ws.frag_opcode;
            out_view.payload = frag_buf[..];
            out_view.is_valid = true;
            out_view.is_compressed = was_compressed;

            ws.frag_opcode = 0;
            ws.frag_compressed = false;
            ws.frag_utf8_offset = 0;
            return true, out_view;
        } else {
            out_view.is_valid = false;
            return true, out_view;
        }
    }

    return true, out_view;
}

// Dispatches incoming raw frame wire bytes using zero-copy non-owning payload views:
// unmasks payload in-place, handles Ping/Pong and Close echoes, validates strict UTF-8,
// and yields a direct slice of the wire ingress buffer into out_view without copying.
fn receive_view<B>(ws: WebSocketSession&, wire: u8[:], out_view: WsMessageView&, out_reply: B&) -> bool {
    let handled, view = receive_view_into(ws, wire, ws.frag_buffer, ws.frag_buffer.cap, out_reply);
    out_view = view;
    return handled;
}

// Streams and dispatches a single WebSocket frame from the front of `wire` into a caller-supplied assembly buffer:
// - Returns `(0, false, view)` when `wire` contains an incomplete frame header or payload.
// - Returns `(consumed, true, view)` when a complete frame was processed or a fatal violation closed the session.
fn consume_frame_view_into<B, F>(
    ws:           WebSocketSession&,
    wire:         u8[:],
    frag_buf:     F&,
    max_frag_cap: i64,
    out_reply:    B&,
) -> i64, bool, WsMessageView {
    guard !ws.is_closed && wire.len >= 2 else { return 0, false, WsMessageView { .. }; }

    let hdr, ok_hdr = parse_ws_frame_header(wire);
    if ok_hdr {
        let hdr_len = hdr.header_len as u64;
        let wire_len = wire.len as u64;
        if hdr_len <= wire_len && hdr.payload_len <= (wire_len - hdr_len) {
            let total_len = (hdr_len + hdr.payload_len) as i64;
            let handled, view = receive_view_into(ws, wire[..total_len], frag_buf, max_frag_cap, out_reply);
            return total_len, handled || ws.is_closed, view;
        }
    }

    // Incomplete frame header or payload: check if header already violates RFC 6455 invariants
    let handled, view = receive_view_into(ws, wire, frag_buf, max_frag_cap, out_reply);
    if handled || ws.is_closed {
        return wire.len, true, view;
    }
    return 0, false, view;
}

// Streams and dispatches a single WebSocket frame from the front of `wire`:
// - Returns `(0, false)` when `wire` contains an incomplete frame header or payload and more socket bytes are needed.
// - Returns `(consumed, true)` when a complete frame was processed or a fatal header violation closed the session.
fn consume_frame_view<B>(ws: WebSocketSession&, wire: u8[:], out_view: WsMessageView&, out_reply: B&) -> i64, bool {
    let consumed, handled, view = consume_frame_view_into(ws, wire, ws.frag_buffer, ws.frag_buffer.cap, out_reply);
    out_view = view;
    return consumed, handled;
}

// Dispatches incoming raw frame wire bytes: unmasks payload, automatically prepares Pong for Ping,
// answers Close with Close echo, reassembles multi-frame fragmented messages (RFC 6455 §5.4),
// validates strict UTF-8 on text and close frames, and populates out_msg upon message completion.
fn receive<B>(ws: WebSocketSession&, wire: u8[:], out_msg: WsMessage&, out_reply: B&) -> bool {
    var view = WsMessageView { .. };
    let ok = receive_view(ws, wire, view, out_reply);
    guard ok else { return false; }

    if view.payload.len > out_msg.data.cap {
        close(ws, rfc::WS_STATUS_MESSAGE_TOO_BIG, "message exceeds buffer capacity", out_reply);
        ws.is_closed = true;
        ws.close_code = rfc::WS_STATUS_MESSAGE_TOO_BIG;
        out_msg.is_valid = false;
        return false;
    }

    out_msg.is_valid = view.is_valid;
    out_msg.opcode = view.opcode;
    out_msg.close_code = view.close_code;
    out_msg.close_reason.clear();
    guard view.close_reason.len <= out_msg.close_reason.cap else { return false; }
    if view.close_reason.len > 0 {
        out_msg.close_reason.append(view.close_reason);
    }
    out_msg.data.clear();
    if view.payload.len > 0 {
        out_msg.data.append(view.payload);
    }
    return true;
}

// Checks if a requested token is present in the comma-separated header value list (RFC 6455 §4.2.1).
fn has_header_token_fold(list: const u8[:], target: const u8[:]) -> bool {
    guard list.len > 0 && target.len > 0 else { return false; }
    var tok = make_byte_tokenizer(list, ',');
    loop {
        let part, ok = tok.token_next();
        guard ok else { break; }
        if core::eq_ascii_fold(part.trim_lws(), target) {
            return true;
        }
    }
    return false;
}

// Checks if a requested subprotocol is present in the comma-separated Sec-WebSocket-Protocol
// header list (RFC 6455 §4.2.2).
fn has_subprotocol_token(list: const u8[:], target: const u8[:]) -> bool {
    guard list.len > 0 && target.len > 0 else { return false; }
    var tok = make_byte_tokenizer(list, ',');
    loop {
        let part, ok = tok.token_next();
        guard ok else { break; }
        if part.trim_lws() == target {
            return true;
        }
    }
    return false;
}

// Helper to search for a token inside a specified HTTP header across all matching lines.
fn req_has_header_token(req: const Request&, header_name: const u8[:], token: const u8[:]) -> bool {
    for &e in req.headers.entries {
        if core::eq_ascii_fold(entry_name(req.headers, e), header_name) {
            if has_header_token_fold(entry_value(req.headers, e), token) {
                return true;
            }
        }
    }
    return false;
}

// Helper to determine if a subprotocol is requested by the client in Sec-WebSocket-Protocol.
fn req_has_subprotocol(req: const Request&, subprotocol: const u8[:]) -> bool {
    for &e in req.headers.entries {
        if core::eq_ascii_fold(entry_name(req.headers, e), "sec-websocket-protocol") {
            if has_subprotocol_token(entry_value(req.headers, e), subprotocol) {
                return true;
            }
        }
    }
    return false;
}

// Server-side WebSocket upgrade handler (RFC 6455). Validates client request and populates 101 response.
fn ws_upgrade_request(
    req:         const Request&,
    out_resp:    Response&,
    subprotocol: const u8[:] = "",
) -> WebSocketSession, bool {
    guard req.method[..] == "GET" else {
        out_resp.status_code = 405;
        return WebSocketSession { .. }, false;
    }

    // RFC 6455 §4.2.1 item 2: Request MUST contain a Host header field or absolute URI authority
    var has_host = req.headers.find_header("Host").len > 0;
    if !has_host && req.url.len > 0 {
        let u = core::new_url(req.url[..]);
        let h = core::host(u);
        if u.valid && h.len > 0 {
            has_host = true;
        }
    }
    guard has_host else {
        out_resp.status_code = 400;
        return WebSocketSession { .. }, false;
    }

    guard req_has_header_token(req, "upgrade", "websocket") else {
        out_resp.status_code = 400;
        return WebSocketSession { .. }, false;
    }

    guard req_has_header_token(req, "connection", "upgrade") else {
        out_resp.status_code = 400;
        return WebSocketSession { .. }, false;
    }

    let ver = req.headers.find_header("Sec-WebSocket-Version");
    guard ver == "13" else {
        out_resp.status_code = 426;
        out_resp.set_header("Sec-WebSocket-Version", "13");
        return WebSocketSession { .. }, false;
    }

    let client_key = req.headers.find_header("Sec-WebSocket-Key");
    guard is_valid_websocket_key(client_key) else {
        out_resp.status_code = 400;
        return WebSocketSession { .. }, false;
    }

    var session = new_websocket_session(false);
    if subprotocol.len > 0 {
        guard subprotocol.len <= session.subprotocol.cap else {
            out_resp.status_code = 400;
            return WebSocketSession { .. }, false;
        }
    }

    var accept_key: u8[..64] = [];
    compute_websocket_accept(client_key, accept_key);

    out_resp.status_code = 101;
    out_resp.set_header("Upgrade", "websocket");
    out_resp.set_header("Connection", "Upgrade");
    out_resp.set_header("Sec-WebSocket-Accept", accept_key[..]);

    if subprotocol.len > 0 {
        // RFC 6455 §4.1 & §4.2.2 item 5: Server MUST only select a subprotocol requested by the client
        // across one or more Sec-WebSocket-Protocol header fields.
        if req_has_subprotocol(req, subprotocol) {
            out_resp.set_header("Sec-WebSocket-Protocol", subprotocol);
            session.subprotocol.append(subprotocol);
        }
    }

    return session, true;
}

// Inspects an incoming HTTP Request to determine if it is an RFC 6455 WebSocket Upgrade request
fn is_websocket_upgrade_request(req: const Request&) -> bool {
    guard req.method[..] == "GET" else { return false; }
    let ws_mask = HDR_PRESENCE_HOST | HDR_PRESENCE_UPGRADE | HDR_PRESENCE_CONNECTION | HDR_PRESENCE_SEC_WEBSOCKET_KEY;
    if req.presence_mask != 0 {
        guard (req.presence_mask & ws_mask) == ws_mask else { return false; }
    }
    // RFC 6455 §4.2.1 item 2: Request MUST contain a Host header field
    let host = req.headers.find_header("Host");
    guard host.len > 0 else { return false; }
    guard req_has_header_token(req, "upgrade", "websocket") else { return false; }
    guard req_has_header_token(req, "connection", "upgrade") else { return false; }
    let ver = req.headers.find_header("Sec-WebSocket-Version");
    guard ver == "13" else { return false; }
    let key = req.headers.find_header("Sec-WebSocket-Key");
    guard is_valid_websocket_key(key) else { return false; }
    return true;
}

// ---- Bootstrapping WebSockets with HTTP/2 (RFC 8441) ---------------------

// Inspects an incoming HTTP Request to determine if it is an RFC 8441 WebSocket Extended CONNECT request
fn is_h2_websocket_request(req: const Request&) -> bool {
    guard req.method[..] == "CONNECT" else { return false; }
    let proto = req.headers.find_header(":protocol");
    guard core::eq_ascii_fold(proto, "websocket") else { return false; }
    let ver = req.headers.find_header("sec-websocket-version");
    guard ver == "13" else { return false; }
    return true;
}

// Validates an RFC 8441 WebSocket Extended CONNECT request according to strict protocol rules:
// - :method MUST be CONNECT
// - :protocol MUST be websocket
// - :scheme MUST be http or https
// - :path and :authority MUST be present
// - sec-websocket-version MUST be 13
// - MUST NOT contain connection, upgrade, keep-alive, transfer-encoding, proxy-connection, or sec-websocket-key
fn validate_h2_websocket_request(req: const Request&) -> bool {
    guard is_h2_websocket_request(req) else { return false; }

    let scheme = req.headers.find_header(":scheme");
    guard core::eq_ascii_fold(scheme, "http") || core::eq_ascii_fold(scheme, "https") else { return false; }
    let path = req.headers.find_header(":path");
    guard path.len > 0 else { return false; }
    let auth = req.headers.find_header(":authority");
    guard auth.len > 0 else { return false; }

    // RFC 8441 §4: Connection-specific headers and Sec-WebSocket-Key MUST NOT be present
    for &e in req.headers.entries {
        let name = entry_name(req.headers, e);
        if core::eq_ascii_fold(name, "connection") ||
           core::eq_ascii_fold(name, "upgrade") ||
           core::eq_ascii_fold(name, "keep-alive") ||
           core::eq_ascii_fold(name, "transfer-encoding") ||
           core::eq_ascii_fold(name, "proxy-connection") ||
           core::eq_ascii_fold(name, "sec-websocket-key") {
            return false;
        }
    }
    return true;
}

// Formats an outbound RFC 8441 WebSocket Extended CONNECT Request for HTTP/2
fn format_h2_websocket_request(
    req:         Request&,
    path:        const u8[:],
    authority:   const u8[:],
    scheme:      const u8[:] = "https",
    subprotocol: const u8[:] = "",
) {
    req = new_request("CONNECT", path);
    set_header(req, ":method", "CONNECT");
    set_header(req, ":protocol", "websocket");
    set_header(req, ":scheme", scheme);
    set_header(req, ":authority", authority);
    set_header(req, ":path", path);
    set_header(req, "sec-websocket-version", "13");

    if subprotocol.len > 0 {
        set_header(req, "sec-websocket-protocol", subprotocol);
    }
}

// Server-side RFC 8441 WebSocket Extended CONNECT upgrade handler.
// Validates client request and populates 200 OK response (NOT 101 per RFC 8441 §5).
fn ws_h2_upgrade_request(
    req:         const Request&,
    out_resp:    Response&,
    subprotocol: const u8[:] = "",
) -> WebSocketSession, bool {
    guard validate_h2_websocket_request(req) else {
        out_resp.status_code = 400;
        return WebSocketSession { .. }, false;
    }

    var session = new_websocket_session(false);
    if subprotocol.len > 0 {
        guard subprotocol.len <= session.subprotocol.cap else {
            out_resp.status_code = 400;
            return WebSocketSession { .. }, false;
        }
    }

    out_resp.status_code = 200;

    if subprotocol.len > 0 {
        if req_has_subprotocol(req, subprotocol) {
            out_resp.set_header("sec-websocket-protocol", subprotocol);
            session.subprotocol.append(subprotocol);
        }
    }

    return session, true;
}

// Formats an HTTP/2 response accepting an RFC 8441 WebSocket session
fn format_h2_websocket_response(res: Response&, subprotocol: const u8[:] = "") {
    res.status_code = 200;
    if subprotocol.len > 0 {
        res.set_header("sec-websocket-protocol", subprotocol);
    }
}

// Inspects an HTTP/2 Response to determine if it accepted an RFC 8441 WebSocket session
fn is_h2_websocket_response(res: const Response&) -> bool {
    return res.status_code == 200;
}

// ---- RFC 9220 Bootstrapping WebSockets with HTTP/3 ---------------------

// Formats an outbound RFC 9220 WebSocket Extended CONNECT Request for HTTP/3
fn format_h3_websocket_request(
    req:         Request&,
    path:        const u8[:],
    authority:   const u8[:],
    scheme:      const u8[:] = "https",
    subprotocol: const u8[:] = "",
) {
    format_h2_websocket_request(req, path, authority, scheme, subprotocol);
}

// Validates an RFC 9220 WebSocket Extended CONNECT request over HTTP/3.
// Follows exact same validation rules as RFC 8441 per RFC 9220 Section 3.
fn validate_h3_websocket_request(req: const Request&) -> bool {
    guard req.method == "CONNECT" else { return false; }
    return validate_h2_websocket_request(req);
}

// Server-side RFC 9220 WebSocket Extended CONNECT upgrade handler for HTTP/3.
fn ws_h3_upgrade_request(
    req:         const Request&,
    out_resp:    Response&,
    subprotocol: const u8[:] = "",
) -> WebSocketSession, bool {
    return ws_h2_upgrade_request(req, out_resp, subprotocol);
}

// Formats an HTTP/3 response accepting an RFC 9220 WebSocket session (200 OK)
fn format_h3_websocket_response(res: Response&, subprotocol: const u8[:] = "") {
    res.status_code = 200;
    format_h2_websocket_response(res, subprotocol);
}

// Inspects an HTTP/3 Response to determine if it accepted an RFC 9220 WebSocket session
fn is_h3_websocket_response(res: const Response&) -> bool {
    guard res.status_code == 200 else { return false; }
    return is_h2_websocket_response(res);
}

// Checks if an arbitrary HTTP request is an RFC 8441 / RFC 9220 Extended CONNECT request
fn is_extended_connect_request(req: const Request&) -> bool {
    guard req.method == "CONNECT" else { return false; }
    let proto = req.headers.find_header(":protocol");
    return proto.len > 0;
}

// Encapsulates a WebSocket message into an HTTP/2 or HTTP/3 stream DATA frame payload
fn ws_encapsulate_stream_data<B>(
    out:       B&,
    opcode:    u8,
    payload:   const u8[:],
    is_client: bool,
    mask_key:  const u8[4] = [0x11, 0x22, 0x33, 0x44],
) {
    if is_client {
        encode_ws_frame(out, opcode, payload, true, mask_key);
    } else {
        let empty_mask: const u8[4] = [0, 0, 0, 0];
        encode_ws_frame(out, opcode, payload, false, empty_mask);
    }
}
