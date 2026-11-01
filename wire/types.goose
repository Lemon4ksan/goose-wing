// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Vulkan-style zero-allocation wire framing primitives and queue configurations.
namespace wire;

import std;

// ---- Transport Driver Kinds & Capabilities -------------------------------

enum WireDriverKind {
    Standard,
    WindowsRIO,
    IoUring,
    Kqueue,
    AfXdp,
    Mock,
}

// Low-level socket configuration matching physical device creation parameters.
struct WireDeviceConfig {
    driver:            WireDriverKind = WireDriverKind.Standard,
    tcp_nodelay:       bool           = true,
    tcp_keepalive:     bool           = true,
    has_dont_fragment: bool           = true,
    ip_ttl:            i32            = 64,
    rx_buf_size:       i32            = 65536,
    tx_buf_size:       i32            = 65536,
    wscale:            i32            = 8,
    mss:               i32            = 1460,
}

// ---- HTTP/2 Wire Frame Types (RFC 9113 §6 & RFC 9218 §7.1) ----------------

const H2_FRAME_DATA:            u8 = 0x00;
const H2_FRAME_HEADERS:         u8 = 0x01;
const H2_FRAME_PRIORITY:        u8 = 0x02;
const H2_FRAME_RST_STREAM:      u8 = 0x03;
const H2_FRAME_SETTINGS:        u8 = 0x04;
const H2_FRAME_PUSH_PROMISE:    u8 = 0x05;
const H2_FRAME_PING:            u8 = 0x06;
const H2_FRAME_GOAWAY:          u8 = 0x07;
const H2_FRAME_WINDOW_UPDATE:   u8 = 0x08;
const H2_FRAME_CONTINUATION:    u8 = 0x09;
const H2_FRAME_PRIORITY_UPDATE: u8 = 0x10; // RFC 9218 Section 7.1

// ---- HTTP/2 Wire Flags (RFC 9113 §4.1) -----------------------------------

const H2_FLAG_NONE:        u8 = 0x00;
const H2_FLAG_END_STREAM:  u8 = 0x01;
const H2_FLAG_ACK:         u8 = 0x01;
const H2_FLAG_END_HEADERS: u8 = 0x04;
const H2_FLAG_PADDED:      u8 = 0x08;
const H2_FLAG_PRIORITY:    u8 = 0x20;

// ---- HTTP/2 Setting Identifiers (RFC 9113 §6.5.2 & RFC 9218 §5.1) --------

const H2_SETTING_HEADER_TABLE_SIZE:      u16 = 0x01; // default 4096
const H2_SETTING_ENABLE_PUSH:            u16 = 0x02; // default 1
const H2_SETTING_MAX_CONCURRENT_STREAMS: u16 = 0x03; // unlimited
const H2_SETTING_INITIAL_WINDOW_SIZE:    u16 = 0x04; // default 65535
const H2_SETTING_MAX_FRAME_SIZE:         u16 = 0x05; // default 16384
const H2_SETTING_MAX_HEADER_LIST_SIZE:   u16 = 0x06; // unlimited
const H2_SETTING_ENABLE_CONNECT_PROTO:   u16 = 0x08; // RFC 8441
const H2_SETTING_NO_RFC7540_PRIORITIES:  u16 = 0x09; // RFC 9218 Section 5.1

// Single HTTP/2 setting parameter.
struct WireSetting {
    id:  u16 = 0,
    val: u32 = 0,
}

// Constructs a WireSetting entry without alias overhead.
inline fn h2_setting(setting_id: u16, setting_val: u32) -> WireSetting {
    return WireSetting {
        id:  setting_id,
        val: setting_val,
    };
}

// 9-byte HTTP/2 Binary Frame Header (RFC 9113 Section 4.1).
struct WireFrameHeader {
    length:     u32 = 0, // 24-bit big-endian unsigned
    frame_type: u8  = 0, // 8-bit wire frame type code
    flags:      u8  = 0, // 8-bit type-specific bitmask
    stream_id:  u32 = 0, // 31-bit stream identifier
}

// Client Connection Preface (RFC 9113 Section 3.4).
let H2_CLIENT_PREFACE: const u8[24] = [
    'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P', '/', '2', '.', '0',
    '\r', '\n', '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n',
];
