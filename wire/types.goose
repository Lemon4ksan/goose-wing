// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Shared wire framing structs for HTTP/2 headers and settings.
namespace wire;

import std;

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
