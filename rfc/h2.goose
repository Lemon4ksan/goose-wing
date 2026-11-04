// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/2 binary framing constants, flags, error codes, settings, and HPACK limits.
// Conforms to RFC 9113, RFC 7541, RFC 9218, RFC 8336, RFC 7838, and RFC 8441.
namespace rfc;

import std;

// ---- HTTP/2 Frame Types (RFC 9113 Section 6 & RFC 9218 Section 7.1) ------

const H2_FRAME_DATA:            u8 = 0x00; // RFC 9113 Section 6.1
const H2_FRAME_HEADERS:         u8 = 0x01; // RFC 9113 Section 6.2
const H2_FRAME_PRIORITY:        u8 = 0x02; // RFC 9113 Section 6.3
const H2_FRAME_RST_STREAM:      u8 = 0x03; // RFC 9113 Section 6.4
const H2_FRAME_SETTINGS:        u8 = 0x04; // RFC 9113 Section 6.5
const H2_FRAME_PUSH_PROMISE:    u8 = 0x05; // RFC 9113 Section 6.6
const H2_FRAME_PING:            u8 = 0x06; // RFC 9113 Section 6.7
const H2_FRAME_GOAWAY:          u8 = 0x07; // RFC 9113 Section 6.8
const H2_FRAME_WINDOW_UPDATE:   u8 = 0x08; // RFC 9113 Section 6.9
const H2_FRAME_CONTINUATION:    u8 = 0x09; // RFC 9113 Section 6.10
const H2_FRAME_ALTSVC:          u8 = 0x0A; // RFC 7838 Section 4
const H2_FRAME_ORIGIN:          u8 = 0x0C; // RFC 8336 Section 2
const H2_FRAME_PRIORITY_UPDATE: u8 = 0x10; // RFC 9218 Section 7.1

// ---- HTTP/2 Frame Flags (RFC 9113 Section 4.1) ---------------------------

const H2_FLAG_NONE:        u8 = 0x00;
const H2_FLAG_END_STREAM:  u8 = 0x01;
const H2_FLAG_ACK:         u8 = 0x01;
const H2_FLAG_END_HEADERS: u8 = 0x04;
const H2_FLAG_PADDED:      u8 = 0x08;
const H2_FLAG_PRIORITY:    u8 = 0x20;

// ---- HTTP/2 Error Codes (RFC 9113 Section 7) -----------------------------

const H2_ERR_NO_ERROR:            u32 = 0x00;
const H2_ERR_PROTOCOL_ERROR:      u32 = 0x01;
const H2_ERR_INTERNAL_ERROR:      u32 = 0x02;
const H2_ERR_FLOW_CONTROL_ERROR:  u32 = 0x03;
const H2_ERR_SETTINGS_TIMEOUT:    u32 = 0x04;
const H2_ERR_STREAM_CLOSED:       u32 = 0x05;
const H2_ERR_FRAME_SIZE_ERROR:    u32 = 0x06;
const H2_ERR_REFUSED_STREAM:      u32 = 0x07;
const H2_ERR_CANCEL:              u32 = 0x08;
const H2_ERR_COMPRESSION_ERROR:   u32 = 0x09;
const H2_ERR_CONNECT_ERROR:       u32 = 0x0A;
const H2_ERR_ENHANCE_YOUR_CALM:   u32 = 0x0B;
const H2_ERR_INADEQUATE_SECURITY: u32 = 0x0C;
const H2_ERR_HTTP_1_1_REQUIRED:   u32 = 0x0D;

// ---- HTTP/2 Setting Identifiers (RFC 9113 Section 6.5.2 & RFC 9218) ------

const H2_SETTING_HEADER_TABLE_SIZE:      u16 = 0x01;
const H2_SETTING_ENABLE_PUSH:            u16 = 0x02;
const H2_SETTING_MAX_CONCURRENT_STREAMS: u16 = 0x03;
const H2_SETTING_INITIAL_WINDOW_SIZE:    u16 = 0x04;
const H2_SETTING_MAX_FRAME_SIZE:         u16 = 0x05;
const H2_SETTING_MAX_HEADER_LIST_SIZE:   u16 = 0x06;
const H2_SETTING_ENABLE_CONNECT_PROTO:   u16 = 0x08; // RFC 8441 Section 3
const H2_SETTING_NO_RFC7540_PRIORITIES:  u16 = 0x09; // RFC 9218 Section 5.1

// ---- HTTP/2 & HPACK Protocol Wire Limits (RFC 9113 & RFC 7541) -----------

const H2_FRAME_HEADER_LEN:          i64 = 9;          // RFC 9113 Section 4.1
const H2_DEFAULT_WINDOW_SIZE:       u32 = 65535;      // RFC 9113 Section 6.5.2
const H2_MAX_WINDOW_SIZE:           u32 = 0x7FFFFFFF; // RFC 9113 Section 6.9.1
const H2_DEFAULT_MAX_FRAME_SIZE:    u32 = 16384;      // RFC 9113 Section 4.2
const H2_MAX_FRAME_SIZE_LIMIT:      u32 = 16777215;   // RFC 9113 Section 4.2
const H2_DEFAULT_HEADER_TABLE_SIZE: u32 = 4096;       // RFC 9113 Section 6.5.2

const HPACK_STATIC_TABLE_ENTRIES: u64 = 61;   // RFC 7541 Appendix A
const HPACK_ENTRY_OVERHEAD:       u64 = 32;   // RFC 7541 Section 4.1
const HPACK_DEFAULT_MAX_DYN_SIZE: u64 = 4096; // RFC 9113 Section 6.5.2

// RFC 9113 Section 3.4: HTTP/2 Connection Preface
let H2_CLIENT_PREFACE: const u8[24] = [
    'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P', '/', '2', '.', '0',
    '\r', '\n', '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n',
];

// RFC 9113 Section 5.1.1: Stream Identifiers - Stream ID 0 rules and stream association.
inline fn validate_stream_id_association(stream_id: u32, frame_type: u8) -> u32 {
    if stream_id == 0 {
        if frame_type == H2_FRAME_DATA ||
           frame_type == H2_FRAME_HEADERS ||
           frame_type == H2_FRAME_PRIORITY ||
           frame_type == H2_FRAME_RST_STREAM ||
           frame_type == H2_FRAME_CONTINUATION ||
           frame_type == H2_FRAME_PUSH_PROMISE {
            return H2_ERR_PROTOCOL_ERROR;
        }
    } else {
        if frame_type == H2_FRAME_SETTINGS ||
           frame_type == H2_FRAME_PING ||
           frame_type == H2_FRAME_GOAWAY ||
           frame_type == H2_FRAME_PRIORITY_UPDATE ||
           frame_type == H2_FRAME_ORIGIN {
            return H2_ERR_PROTOCOL_ERROR;
        }
    }
    return H2_ERR_NO_ERROR;
}

// RFC 9113 Section 6.8: GOAWAY - Validates Last-Stream-ID based on peer stream initiation roles.
// A client can only acknowledge peer streams (server-initiated: even or 0).
// A server can only acknowledge peer streams (client-initiated: odd or 0, or 2^31 - 1 for graceful shutdown).
inline fn validate_goaway_last_stream_id(last_stream_id: u32, sender_is_client: bool) -> bool {
    let sid = last_stream_id & 0x7FFFFFFF;
    if sid == 0 || sid == 0x7FFFFFFF {
        return true;
    }
    if sender_is_client {
        return (sid & 1) == 0;
    } else {
        return (sid & 1) != 0;
    }
}
