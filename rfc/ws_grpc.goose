// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// WebSocket (RFC 6455) and gRPC over HTTP/2 wire framing constants.
namespace rfc;

import std;

// ---- WebSocket Opcodes (RFC 6455 Section 5.2) ----------------------------

const WS_OPCODE_CONTINUATION: u8 = 0x0;
const WS_OPCODE_TEXT:         u8 = 0x1;
const WS_OPCODE_BINARY:       u8 = 0x2;
const WS_OPCODE_CLOSE:        u8 = 0x8;
const WS_OPCODE_PING:         u8 = 0x9;
const WS_OPCODE_PONG:         u8 = 0xA;

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

// ---- gRPC Wire Framing Constants (Length-Prefixed Message) ---------------

const GRPC_LPM_HEADER_LEN:      u32         = 5;
const GRPC_FLAG_UNCOMPRESSED:   u8          = 0x00;
const GRPC_FLAG_COMPRESSED:     u8          = 0x01;
const GRPC_WEB_FLAG_TRAILERS:   u8          = 0x80;
const MIME_GRPC:                const u8[:] = "application/grpc";
const MIME_GRPC_PROTO:          const u8[:] = "application/grpc+proto";
const PROTO_TAG_STATUS_CODE:    u8          = 0x08;
const PROTO_TAG_STATUS_MESSAGE: u8          = 0x12;
