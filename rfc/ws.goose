// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// WebSocket (RFC 6455 & RFC 8441) wire framing constants and status validators.
namespace rfc;

import std;

// ---- WebSocket Opcodes (RFC 6455 Section 5.2) ----------------------------

const WS_OPCODE_CONTINUATION: u8 = 0x0;
const WS_OPCODE_TEXT:         u8 = 0x1;
const WS_OPCODE_BINARY:       u8 = 0x2;
const WS_OPCODE_CLOSE:        u8 = 0x8;
const WS_OPCODE_PING:         u8 = 0x9;
const WS_OPCODE_PONG:         u8 = 0xA;

// ---- WebSocket Frame Header Bitmasks & Sentinels (RFC 6455 Section 5.2) --

// RFC 6455 Section 5.2: Base Framing Protocol - Frame header bitmasks and length sentinels.
const WS_FIN_BIT:          u8  = 0x80;
const WS_RSV1_BIT:         u8  = 0x40;
const WS_RSV2_BIT:         u8  = 0x20;
const WS_RSV3_BIT:         u8  = 0x10;
const WS_OPCODE_MASK:      u8  = 0x0F;
const WS_MASK_BIT:         u8  = 0x80;
const WS_PAYLOAD_LEN_MASK: u8  = 0x7F;
const WS_LEN16_SENTINEL:   u64 = 126;
const WS_MAX_CONTROL_LEN:  u64 = 125;

// ---- WebSocket Close Status Codes (RFC 6455 Section 7.4.1) ---------------

const WS_STATUS_NORMAL:           u16 = 1000;
const WS_STATUS_GOING_AWAY:       u16 = 1001;
const WS_STATUS_PROTOCOL_ERROR:   u16 = 1002;
const WS_STATUS_UNSUPPORTED_DATA: u16 = 1003;
const WS_STATUS_NO_STATUS:        u16 = 1005;
const WS_STATUS_ABNORMAL_CLOSURE: u16 = 1006;
const WS_STATUS_INVALID_PAYLOAD:  u16 = 1007;
const WS_STATUS_POLICY_VIOLATION: u16 = 1008;
const WS_STATUS_MESSAGE_TOO_BIG:  u16 = 1009;
const WS_STATUS_MANDATORY_EXT:    u16 = 1010;
const WS_STATUS_INTERNAL_ERROR:   u16 = 1011;

// RFC 6455 Section 1.3: Opening Handshake GUID
let WS_HANDSHAKE_GUID: const u8[:] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// RFC 6455 Section 4.1 & RFC 7692 Section 7: WebSocket Version & PerMessageDeflate Constants
const WS_RFC6455_VERSION:     const u8[:] = "13";                 // RFC 6455 Section 4.1
const WS_PMD_EXTENSION_NAME:  const u8[:] = "permessage-deflate"; // RFC 7692 Section 7
const WS_PMD_MIN_WINDOW_BITS: u8          = 8;                    // RFC 7692 Section 7.1.2
const WS_PMD_MAX_WINDOW_BITS: u8          = 15;                   // RFC 7692 Section 7.1.2

// RFC 6455 Section 5.2: Base Framing Protocol - Lookup table of valid WebSocket opcodes.
const WS_OPCODE_LUT: const bool[256] = [
    true, true, true, false, false, false, false, false, true, true, true, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
];

// RFC 6455 Section 5.2: Base Framing Protocol - Checks if a 4-bit WebSocket opcode is in the control range (0x08..0x0F).
checkfree inline fn is_ws_control_opcode(opcode: u8) -> bool {
    return (opcode & 0xF8) == 0x08;
}

// RFC 6455 Section 5.2: Base Framing Protocol - Checks if an opcode is a valid defined WebSocket opcode.
checkfree inline fn is_valid_ws_opcode(opcode: u8) -> bool {
    return WS_OPCODE_LUT[opcode];
}

// RFC 6455 Section 7.4: Status Codes - Validates whether a WebSocket close status code is permitted on the wire.
inline fn is_valid_ws_close_code(code: u16) -> bool {
    // RFC 6455 Section 7.4.2: Range 1000..4999
    if code < 1000 || code >= 5000 {
        return false;
    }
    // RFC 6455 Section 7.4.1: Reserved / forbidden status codes that MUST NOT be sent on the wire
    if code == 1004 || code == 1005 || code == 1006 || code == 1015 {
        return false;
    }
    // RFC 6455 Section 7.4.2: Codes 1016..2999 are reserved and unassigned
    if code >= 1016 && code < 3000 {
        return false;
    }
    return true;
}
