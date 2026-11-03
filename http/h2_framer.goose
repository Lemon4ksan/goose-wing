// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/2 frame parsing, validation, and connection state machine (RFC 9113).
namespace internal;

import std;

// ---- frame types -----------------------------------------------------------

// HTTP/2 frame type identifiers (RFC 9113 Section 6).
enum H2FrameType {
    Data,          // 0x0
    Headers,       // 0x1
    Priority,      // 0x2
    RstStream,     // 0x3
    Settings,      // 0x4
    PushPromise,   // 0x5
    Ping,          // 0x6
    GoAway,        // 0x7
    WindowUpdate,  // 0x8
    Continuation,  // 0x9
    Unknown,       // Unsupported / extension
}

// Maps an 8-bit wire frame type code to H2FrameType, or Unknown for extensions.
fn byte_to_frame_type(b: u8) -> H2FrameType {
    return match b {
        rfc::H2_FRAME_DATA => H2FrameType.Data,
        rfc::H2_FRAME_HEADERS => H2FrameType.Headers,
        rfc::H2_FRAME_PRIORITY => H2FrameType.Priority,
        rfc::H2_FRAME_RST_STREAM => H2FrameType.RstStream,
        rfc::H2_FRAME_SETTINGS => H2FrameType.Settings,
        rfc::H2_FRAME_PUSH_PROMISE => H2FrameType.PushPromise,
        rfc::H2_FRAME_PING => H2FrameType.Ping,
        rfc::H2_FRAME_GOAWAY => H2FrameType.GoAway,
        rfc::H2_FRAME_WINDOW_UPDATE => H2FrameType.WindowUpdate,
        rfc::H2_FRAME_CONTINUATION => H2FrameType.Continuation,
        _ => H2FrameType.Unknown,
    };
}

// ---- error codes -----------------------------------------------------------

// HTTP/2 status codes used in RST_STREAM and GOAWAY frames (RFC 9113 Section 7).
enum H2ErrorCode {
    NoError,            // 0x0
    ProtocolError,      // 0x1
    InternalError,      // 0x2
    FlowControlError,   // 0x3
    SettingsTimeout,    // 0x4
    StreamClosed,       // 0x5
    FrameSizeError,     // 0x6
    RefusedStream,      // 0x7
    Cancel,             // 0x8
    CompressionError,   // 0x9
    ConnectError,       // 0xa
    EnhanceYourCalm,    // 0xb - flood or quota limit triggered
    InadequateSecurity, // 0xc
    Http11Required,     // 0xd
}

// ---- frame header ----------------------------------------------------------

// Decoded 9-byte HTTP/2 frame header (RFC 9113 Section 4.1).
struct H2FrameHeader {
    payload_len: i32         = 0, // 24-bit unsigned int
    frame_type:  H2FrameType = H2FrameType.Unknown,
    raw_type:    u8          = 0,
    flags:       u8          = 0,
    stream_id:   i32         = 0, // 31-bit unsigned int
    valid:       bool        = false,
}

// Decodes a 9-byte HTTP/2 binary frame header (RFC 9113 Section 4.1).
// Masks out the reserved high bit of the stream identifier.
//
// Example:
//   raw = [0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01]
//   returns: hdr with payload_len=4, frame_type=Data, stream_id=1, code=NoError
fn parse_h2_frame_header(raw: const u8[:]) -> H2FrameHeader, H2ErrorCode {
    var hdr = H2FrameHeader { .. };
    guard raw.len >= 9 else {
        return hdr, H2ErrorCode.FrameSizeError;
    }

    let len_val = core::read_be_u24(raw, 0) as! i32;
    let f_type = byte_to_frame_type(raw[3]);
    let flags_val = raw[4];
    let s_id = (core::read_be_u32(raw, 5) & 0x7FFFFFFF) as! i32;

    hdr.payload_len = len_val;
    hdr.frame_type = f_type;
    hdr.raw_type = raw[3];
    hdr.flags = flags_val;
    hdr.stream_id = s_id;
    hdr.valid = true;

    return hdr, H2ErrorCode.NoError;
}

// ---- connection state and limits -------------------------------------------

// HTTP/2 connection framing state for CONTINUATION and terminal error tracking.
enum H2ConnState {
    Idle,
    ExpectContinuation,
    Closed,
}

// Tracks HTTP/2 connection framing state and DoS flood counters (RFC 9113 Section 10.5).
struct H2SecurityFramer {
    state:                  H2ConnState = H2ConnState.Idle,
    continuation_stream_id: i32         = 0,
    continuation_count:     i32         = 0,
    header_block_bytes:     i32         = 0,

    rapid_reset_count:    i32 = 0,
    ping_flood_count:     i32 = 0,
    settings_flood_count: i32 = 0,

    max_frame_size:          i32 = 16384, // default 16 KB
    max_header_block_bytes:  i32 = 8192,  // 8 KB cumulative limit
    max_continuation_frames: i32 = 5,     // limit on consecutive CONTINUATION frames
    max_rapid_resets:        i32 = 100,   // reset flood threshold
    max_unack_pings:         i32 = 10,    // unacknowledged ping limit
    max_unack_settings:      i32 = 10,    // unacknowledged settings flood limit
}

// Returns a default-initialized H2SecurityFramer with RFC 9113 baseline limits.
// Validates whether a frame type is permitted on stream 0 or a non-zero stream (RFC 9113 Section 5.1.1).
fn validate_h2_stream_association(hdr: const H2FrameHeader&) -> H2ErrorCode {
    if hdr.stream_id == 0 {
        if hdr.frame_type == H2FrameType.Data ||
           hdr.frame_type == H2FrameType.Headers ||
           hdr.frame_type == H2FrameType.Priority ||
           hdr.frame_type == H2FrameType.RstStream ||
           hdr.frame_type == H2FrameType.PushPromise ||
           hdr.frame_type == H2FrameType.Continuation {
            return H2ErrorCode.ProtocolError;
        }
        return H2ErrorCode.NoError;
    }

    if hdr.frame_type == H2FrameType.Settings ||
       hdr.frame_type == H2FrameType.Ping ||
       hdr.frame_type == H2FrameType.GoAway {
        return H2ErrorCode.ProtocolError;
    }
    return H2ErrorCode.NoError;
}

// Processes a CONTINUATION frame while in ExpectContinuation state (RFC 9113 Section 6.10).
fn process_h2_continuation_frame(framer: H2SecurityFramer&, hdr: const H2FrameHeader&) -> H2ErrorCode {
    if hdr.frame_type != H2FrameType.Continuation || hdr.stream_id != framer.continuation_stream_id {
        framer.state = H2ConnState.Closed;
        return H2ErrorCode.ProtocolError;
    }

    framer.continuation_count++;
    guard framer.continuation_count <= framer.max_continuation_frames else {
        framer.state = H2ConnState.Closed;
        return H2ErrorCode.EnhanceYourCalm;
    }

    framer.header_block_bytes += hdr.payload_len;
    guard framer.header_block_bytes <= framer.max_header_block_bytes else {
        framer.state = H2ConnState.Closed;
        return H2ErrorCode.EnhanceYourCalm;
    }

    if (hdr.flags & rfc::H2_FLAG_END_HEADERS) != 0 {
        framer.state = H2ConnState.Idle;
        framer.continuation_stream_id = 0;
        framer.continuation_count = 0;
        framer.header_block_bytes = 0;
    }
    return H2ErrorCode.NoError;
}

// Processes a HEADERS frame, enforcing client stream parity and CONTINUATION transitions.
fn process_h2_headers_frame(framer: H2SecurityFramer&, hdr: const H2FrameHeader&) -> H2ErrorCode {
    // Client-initiated stream IDs must be odd (RFC 9113 Section 5.1.1).
    guard (hdr.stream_id % 2) != 0 else {
        return H2ErrorCode.ProtocolError;
    }

    guard hdr.payload_len <= framer.max_header_block_bytes else {
        framer.state = H2ConnState.Closed;
        return H2ErrorCode.EnhanceYourCalm;
    }

    if (hdr.flags & rfc::H2_FLAG_END_HEADERS) == 0 {
        framer.state = H2ConnState.ExpectContinuation;
        framer.continuation_stream_id = hdr.stream_id;
        framer.continuation_count = 0;
        framer.header_block_bytes = hdr.payload_len;
    }
    return H2ErrorCode.NoError;
}

inline fn dec_flood_count(count: i32&) {
    if count > 0 {
        count--;
    }
}

inline fn track_unack_flood(count: i32&, max_limit: i32, flags: u8) -> bool {
    if (flags & rfc::H2_FLAG_ACK) != 0 {
        dec_flood_count(count);
        return true;
    }
    count++;
    return count <= max_limit;
}

// Validates frame payload length against RFC 9113 Section 6 requirements.
fn validate_h2_frame_length(hdr: const H2FrameHeader&) -> H2ErrorCode {
    if hdr.frame_type == H2FrameType.Ping {
        if hdr.payload_len != 8 { return H2ErrorCode.FrameSizeError; }
    } else if hdr.frame_type == H2FrameType.RstStream {
        if hdr.payload_len != 4 { return H2ErrorCode.FrameSizeError; }
    } else if hdr.frame_type == H2FrameType.Priority {
        if hdr.payload_len != 5 { return H2ErrorCode.FrameSizeError; }
    } else if hdr.frame_type == H2FrameType.WindowUpdate {
        if hdr.payload_len != 4 { return H2ErrorCode.FrameSizeError; }
    } else if hdr.frame_type == H2FrameType.Settings {
        if (hdr.flags & rfc::H2_FLAG_ACK) != 0 {
            if hdr.payload_len != 0 { return H2ErrorCode.FrameSizeError; }
        } else if (hdr.payload_len % 6) != 0 {
            return H2ErrorCode.FrameSizeError;
        }
    }
    return H2ErrorCode.NoError;
}

inline fn on_h2_payload_activity(framer: H2SecurityFramer&, hdr: const H2FrameHeader&) {
    if (hdr.frame_type == H2FrameType.Data || hdr.frame_type == H2FrameType.Headers) && hdr.payload_len > 0 {
        if framer.rapid_reset_count > 0 {
            framer.rapid_reset_count--;
        }
    }
}

// Checks and increments connection-level DoS flood counters for RST_STREAM, PING, and SETTINGS.
fn process_h2_flood_limits(framer: H2SecurityFramer&, hdr: const H2FrameHeader&) -> H2ErrorCode {
    if hdr.frame_type == H2FrameType.RstStream {
        framer.rapid_reset_count++;
        guard framer.rapid_reset_count <= framer.max_rapid_resets else {
            framer.state = H2ConnState.Closed;
            return H2ErrorCode.EnhanceYourCalm;
        }
        return H2ErrorCode.NoError;
    }

    if hdr.frame_type == H2FrameType.Ping {
        guard track_unack_flood(framer.ping_flood_count, framer.max_unack_pings, hdr.flags) else {
            framer.state = H2ConnState.Closed;
            return H2ErrorCode.EnhanceYourCalm;
        }
    }

    if hdr.frame_type == H2FrameType.Settings {
        guard track_unack_flood(framer.settings_flood_count, framer.max_unack_settings, hdr.flags) else {
            framer.state = H2ConnState.Closed;
            return H2ErrorCode.EnhanceYourCalm;
        }
    }

    return H2ErrorCode.NoError;
}

// Validates an incoming frame header and transitions the connection state machine.
// Enforces stream ID parity, CONTINUATION sequence rules, frame sizes, and flood limits.
fn process_incoming_frame(framer: H2SecurityFramer&, hdr: const H2FrameHeader&) -> H2ErrorCode {
    guard framer.state != H2ConnState.Closed else { return H2ErrorCode.ProtocolError; }
    guard hdr.valid else { return H2ErrorCode.ProtocolError; }
    guard hdr.payload_len <= framer.max_frame_size else { return H2ErrorCode.FrameSizeError; }

    let assoc_err = validate_h2_stream_association(hdr);
    guard assoc_err == H2ErrorCode.NoError else { return assoc_err; }

    let len_err = validate_h2_frame_length(hdr);
    guard len_err == H2ErrorCode.NoError else { return len_err; }

    if framer.state == H2ConnState.ExpectContinuation {
        return process_h2_continuation_frame(framer, hdr);
    }

    guard hdr.frame_type != H2FrameType.Continuation else {
        return H2ErrorCode.ProtocolError;
    }

    on_h2_payload_activity(framer, hdr);

    if hdr.frame_type == H2FrameType.Headers {
        return process_h2_headers_frame(framer, hdr);
    }

    return process_h2_flood_limits(framer, hdr);
}

// Validates an HTTP/2 SETTINGS parameter (RFC 9113 Section 6.5.2).
// Returns ProtocolError or FlowControlError when the value violates protocol bounds.
fn validate_h2_setting(param_id: u16, val: u32) -> H2ErrorCode {
    if param_id == 0x2 && val != 0 && val != 1 {
        return H2ErrorCode.ProtocolError;
    }
    if param_id == 0x4 && val > 0x7fffffff {
        return H2ErrorCode.FlowControlError;
    }
    if param_id == 0x5 && (val < 16384 || val > 16777215) {
        return H2ErrorCode.ProtocolError;
    }
    return H2ErrorCode.NoError;
}
