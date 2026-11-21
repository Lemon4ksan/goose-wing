// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 7692 Compression Extensions for WebSocket (`permessage-deflate`) negotiation,
// shared reactor-level compressor, and dedicated sliding-window compressor/decompressor.
namespace realtime;

import std;
import core;
import rfc.ws;
import .internal;
import .websocket;

// Compression options matching uWebSockets CompressOptions
const WS_COMPRESS_DISABLED:            u16 = 0;
const WS_COMPRESS_SHARED_COMPRESSOR:   u16 = 1;           // Shared zlib deflate context on reactor (0B heap/socket)
const WS_COMPRESS_SHARED_DECOMPRESSOR: u16 = 1 << 8;      // Shared inflate context on reactor
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

    let eff_len = realtime_internal::strip_pmd_sync_flush_tail(shared.compress_buf[..]);
    shared.total_compressed = core::add_sat_u64(shared.total_compressed, eff_len as u64);
    shared.total_uncompressed = core::add_sat_u64(shared.total_uncompressed, raw.len as u64);

    return shared.compress_buf[..eff_len], true;
}

// Appends compressed message to caller-supplied buffer out_wire.
fn ws_deflate_message<B>(
    shared:       SharedWsCompressor&,
    raw:          const u8[:],
    out_wire:     B&,
    reset_window: bool = true,
) -> bool {
    let comp_slice, ok = ws_deflate_message_slice(shared, raw, reset_window);
    guard ok && core::add_sat_i64(out_wire.len, comp_slice.len) <= realtime_internal::ws_buf_cap(out_wire) else {
        return false;
    }
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
    let eff_limit = min(max_payload, realtime_internal::ws_buf_cap(out_plain));
    guard compressed.len > 0 && eff_limit > 0 else {
        out_plain.clear();
        return false;
    }
    out_plain.clear();

    var committed = false;
    defer if !committed {
        out_plain.clear();
        if reset_window {
            shared.decompress_buf.clear();
            shared.compress_buf.clear();
        }
    };

    // RFC 7692 §7.2.2: Restore 4-byte sync-flush tail 0x00 0x00 0xFF 0xFF followed by a 2-byte
    // BFINAL=1 empty Fixed Huffman block (0x03 0x00) so BFINAL=0 sync-flush streams terminate cleanly.
    let tail: u8[6] = [0x00, 0x00, 0xFF, 0xFF, 0x03, 0x00];
    guard shared.decompress_buf.try_set(compressed) && shared.decompress_buf.try_append(tail[..]) else {
        return false;
    }

    let ok_d, err = core::inflate_with_limit(shared.decompress_buf[..], out_plain, eff_limit);
    if !ok_d {
        out_plain.clear();
        guard err != core::CompressError.OutputBufferOverflow else { return false; }
        let ok_raw, _ = core::inflate_with_limit(compressed, out_plain, eff_limit);
        guard ok_raw else { return false; }
    }

    shared.total_decompressed = core::add_sat_u64(shared.total_decompressed, out_plain.len as u64);
    if reset_window {
        shared.decompress_buf.clear();
        shared.compress_buf.clear();
    }
    committed = true;
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
    let clamped_kb = if window_kb > 0 { min(window_kb, 64) } else { 32 };
    return DedicatedWsCompressor {
        window_kb: clamped_kb,
        ..
    };
}

fn deflate_message_dedicated<B>(
    dedicated:    DedicatedWsCompressor&,
    raw:          const u8[:],
    out_wire:     B&,
    reset_window: bool = false,
) -> bool {
    guard raw.len > 0 else { return false; }
    dedicated.compress_buf.clear();
    var committed = false;
    defer if !committed { dedicated.compress_buf.clear(); };

    let dict = if reset_window { "" } else { dedicated.history[..] };
    let ok = core::deflate_with_dict(raw, dedicated.compress_buf, 6, dict);
    guard ok && dedicated.compress_buf.len > 0 else { return false; }

    let eff_len = realtime_internal::strip_pmd_sync_flush_tail(dedicated.compress_buf[..]);
    guard core::add_sat_i64(out_wire.len, eff_len) <= realtime_internal::ws_buf_cap(out_wire) else {
        return false;
    }
    out_wire.append(dedicated.compress_buf[..eff_len]);
    dedicated.total_compressed = core::add_sat_u64(dedicated.total_compressed, eff_len as u64);
    dedicated.total_uncompressed = core::add_sat_u64(dedicated.total_uncompressed, raw.len as u64);

    if reset_window {
        dedicated.history.clear();
        dedicated.compress_buf.clear();
    } else {
        realtime_internal::update_dedicated_history(dedicated, raw);
    }
    committed = true;
    return true;
}

fn inflate_message_dedicated<B>(
    dedicated:    DedicatedWsCompressor&,
    compressed:   const u8[:],
    out_plain:    B&,
    max_payload:  i64  = 65536,
    reset_window: bool = false,
) -> bool {
    let eff_limit = min(max_payload, realtime_internal::ws_buf_cap(out_plain));
    guard compressed.len > 0 && eff_limit > 0 else {
        out_plain.clear();
        return false;
    }
    out_plain.clear();

    var committed = false;
    defer if !committed {
        out_plain.clear();
        dedicated.decompress_buf.clear();
    };

    let tail: u8[6] = [0x00, 0x00, 0xFF, 0xFF, 0x03, 0x00];
    guard dedicated.decompress_buf.try_set(compressed) && dedicated.decompress_buf.try_append(tail[..]) else {
        return false;
    }

    let dict = if reset_window { "" } else { dedicated.history[..] };
    let ok_d, err = core::inflate_with_dict_limit(dedicated.decompress_buf[..], out_plain, dict, eff_limit);
    if !ok_d {
        out_plain.clear();
        guard err != core::CompressError.OutputBufferOverflow else { return false; }
        let ok_raw, _ = core::inflate_with_dict_limit(compressed, out_plain, dict, eff_limit);
        guard ok_raw else { return false; }
    }

    dedicated.total_decompressed = core::add_sat_u64(dedicated.total_decompressed, out_plain.len as u64);
    if reset_window {
        dedicated.history.clear();
        dedicated.decompress_buf.clear();
    } else {
        realtime_internal::update_dedicated_history(dedicated, out_plain[..]);
    }
    committed = true;
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
        rsv1:        eff_rsv1,
        opcode:      opcode,
        masked:      masked,
        mask_key:    mask_key,
        payload_len: eff_payload.len as u64,
        ..
    };
    let saved_len = out.len;
    guard realtime_internal::try_encode_ws_header(hdr, out) else { return; }
    let payload_start = out.len;
    guard out.try_append(eff_payload) else {
        out.resize(saved_len);
        return;
    }
    if masked {
        mask_websocket_payload(out[payload_start..out.len], mask_key);
    }
}

// Detects Safari 15.0 - 15.3 user-agents with broken permessage-deflate implementations (uWebSockets #1347).
fn ws_has_broken_compression(user_agent: const u8[:]) -> bool {
    let marker = " Version/15.";
    let pos = core::find(user_agent, marker);
    guard pos >= 0 else { return false; }

    var idx = core::add_sat_i64(pos, marker.len);
    guard idx < user_agent.len else { return false; }

    var minor: u32 = 0;
    var has_digits = false;
    while idx < user_agent.len && core::is_ascii_digit(user_agent[idx]) {
        let digit = (user_agent[idx] - '0') as u32;
        minor = core::add_sat_u32(core::mul_sat_u32(minor, 10), digit);
        guard minor <= 3 else { return false; }
        has_digits = true;
        idx = core::add_sat_i64(idx, 1);
    }
    guard has_digits && idx < user_agent.len && user_agent[idx] == ' ' else { return false; }

    let safari_marker = " Safari/";
    let safari_pos = core::find(user_agent[idx..], safari_marker);
    return safari_pos >= 0;
}

// Configuration options for RFC 7692 context takeover sliding window boundaries
struct WsContextTakeoverOptions {
    server_no_context: bool = false,
    client_no_context: bool = false,
}

// RFC 7692 §7.1: PerMessageDeflate negotiation parameters (sliding window bits & context takeover)
struct PerMessageDeflateConfig {
    server_max_window_bits:     u8   = rfc::WS_PMD_MAX_WINDOW_BITS,
    client_max_window_bits:     u8   = rfc::WS_PMD_MAX_WINDOW_BITS,
    server_no_context_takeover: bool = false,
    client_no_context_takeover: bool = false,
}

// Negotiates RFC 7692 `permessage-deflate` from a `Sec-WebSocket-Extensions` header.
// Evaluates comma-separated extension offers in preference order and returns the first valid offer.
fn negotiate_permessage_deflate(
    ext_header: const u8[:],
    server_cfg: const PerMessageDeflateConfig&,
) -> PerMessageDeflateConfig, bool {
    let hdr = ext_header.trim_lws();
    guard hdr.len > 0 else { return PerMessageDeflateConfig { .. }, false; }

    var rem = hdr;
    var more = true;
    while more {
        let offer_raw, next_rem, has_next = rem.split_once_unquoted_byte(',');
        let cfg, ok = realtime_internal::parse_single_pmd_offer(offer_raw, server_cfg);
        if ok {
            return cfg, true;
        }
        rem = next_rem;
        more = has_next;
    }
    return PerMessageDeflateConfig { .. }, false;
}

// Formats negotiated RFC 7692 `permessage-deflate` response parameters into `out`.
fn append_permessage_deflate_response<B>(cfg: const PerMessageDeflateConfig&, out: B&) {
    out.append(rfc::WS_PMD_EXTENSION_NAME);
    if cfg.server_no_context_takeover {
        out.append("; server_no_context_takeover");
    }
    if cfg.client_no_context_takeover {
        out.append("; client_no_context_takeover");
    }
    if cfg.server_max_window_bits >= rfc::WS_PMD_MIN_WINDOW_BITS &&
       cfg.server_max_window_bits < rfc::WS_PMD_MAX_WINDOW_BITS {
        format(out, "; server_max_window_bits=", cfg.server_max_window_bits as u64);
    }
    if cfg.client_max_window_bits >= rfc::WS_PMD_MIN_WINDOW_BITS &&
       cfg.client_max_window_bits < rfc::WS_PMD_MAX_WINDOW_BITS {
        format(out, "; client_max_window_bits=", cfg.client_max_window_bits as u64);
    }
}

// RFC 7692 §7.1.1: Configures sliding window context takeover boundaries
fn set_context_takeover(ws: WebSocketSession&, opts: WsContextTakeoverOptions) {
    ws.server_no_context_takeover = opts.server_no_context;
    ws.client_no_context_takeover = opts.client_no_context;
}

// RFC 7692 §7.1.1: Determines if outbound compressor sliding window must be reset after sending
fn ws_should_reset_compressor(ws: const WebSocketSession&) -> bool {
    return if ws.is_client { ws.client_no_context_takeover } else { ws.server_no_context_takeover };
}

// RFC 7692 §7.1.1: Determines if inbound decompressor sliding window must be reset after receiving
fn ws_should_reset_decompressor(ws: const WebSocketSession&) -> bool {
    return if ws.is_client { ws.server_no_context_takeover } else { ws.client_no_context_takeover };
}
