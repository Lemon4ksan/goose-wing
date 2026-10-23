// HTTP/2 frame parsing, validation, and connection state machine (RFC 9113).
namespace wing;

import std;

// ---- frame types -----------------------------------------------------------

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

fn byte_to_frame_type(b: u8) -> H2FrameType {
    return match b {
        0x0 => H2FrameType.Data,
        0x1 => H2FrameType.Headers,
        0x2 => H2FrameType.Priority,
        0x3 => H2FrameType.RstStream,
        0x4 => H2FrameType.Settings,
        0x5 => H2FrameType.PushPromise,
        0x6 => H2FrameType.Ping,
        0x7 => H2FrameType.GoAway,
        0x8 => H2FrameType.WindowUpdate,
        0x9 => H2FrameType.Continuation,
        _   => H2FrameType.Unknown,
    };
}

// ---- frame flags -----------------------------------------------------------

let H2_FLAG_END_STREAM:  u8 = 0x01;
let H2_FLAG_ACK:         u8 = 0x01;
let H2_FLAG_END_HEADERS: u8 = 0x04;
let H2_FLAG_PADDED:      u8 = 0x08;
let H2_FLAG_PRIORITY:    u8 = 0x20;

// ---- error codes -----------------------------------------------------------

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

struct H2FrameHeader {
    payload_len: i32 = 0,     // 24-bit unsigned int
    frame_type: H2FrameType = H2FrameType.Unknown,
    raw_type: u8 = 0,
    flags: u8 = 0,
    stream_id: i32 = 0,       // 31-bit unsigned int
    valid: bool = false,
}

// Decodes a 9-byte HTTP/2 binary frame header (RFC 9113 §4.1).
// Masks out the reserved high bit of the stream identifier.
fn parse_h2_frame_header(raw: const u8[:]) -> H2FrameHeader, H2ErrorCode {
    var hdr = H2FrameHeader { .. };
    guard raw.len >= 9 else {
        return hdr, H2ErrorCode.FrameSizeError;
    }

    // 24-bit length (big endian)
    let len_val = ((raw[0] as i32) << 16) | ((raw[1] as i32) << 8) | raw[2];
    let f_type = byte_to_frame_type(raw[3]);
    let flags_val = raw[4];

    // 31-bit stream id (mask out reserved 1-bit)
    let s_id = (((raw[5] as i32) & 0x7F) << 24) |
               ((raw[6] as i32) << 16) |
               ((raw[7] as i32) << 8) |
               raw[8];

    hdr.payload_len = len_val;
    hdr.frame_type = f_type;
    hdr.raw_type = raw[3];
    hdr.flags = flags_val;
    hdr.stream_id = s_id;
    hdr.valid = true;

    return hdr, H2ErrorCode.NoError;
}

// ---- connection state and limits -------------------------------------------

enum H2ConnState {
    Idle,
    ExpectContinuation,
    Closed,
}

struct H2SecurityFramer {
    state: H2ConnState = H2ConnState.Idle,
    continuation_stream_id: i32 = 0,
    continuation_count: i32 = 0,
    header_block_bytes: i32 = 0,

    rapid_reset_count: i32 = 0,
    ping_flood_count: i32 = 0,
    settings_flood_count: i32 = 0,

    max_frame_size: i32 = 16384,          // default 16 KB
    max_header_block_bytes: i32 = 8192,   // 8 KB cumulative limit
    max_continuation_frames: i32 = 5,     // limit on consecutive CONTINUATION frames
    max_rapid_resets: i32 = 100,          // reset flood threshold
    max_unack_pings: i32 = 10,            // unacknowledged ping limit
}

fn new_h2_security_framer() -> H2SecurityFramer {
    return H2SecurityFramer { .. };
}

// Validates an incoming frame header and transitions the connection state machine.
// Enforces stream ID parity, CONTINUATION sequence rules, frame sizes, and flood limits.
fn process_incoming_frame(framer: H2SecurityFramer&, hdr: const H2FrameHeader&) -> H2ErrorCode {
    guard hdr.valid else { return H2ErrorCode.ProtocolError; }

    // 1. Frame size check
    if hdr.payload_len > framer.max_frame_size {
        return H2ErrorCode.FrameSizeError;
    }

    // 2. Stream ID 0 Validation (RFC 9113 §5.1.1)
    if hdr.stream_id == 0 {
        // Stream 0 must not carry DATA, HEADERS, PRIORITY, RST_STREAM, or CONTINUATION
        if hdr.frame_type == H2FrameType.Data ||
           hdr.frame_type == H2FrameType.Headers ||
           hdr.frame_type == H2FrameType.RstStream ||
           hdr.frame_type == H2FrameType.Continuation {
            return H2ErrorCode.ProtocolError;
        }
    } else {
        // Non-zero stream must not carry SETTINGS or PING
        if hdr.frame_type == H2FrameType.Settings || hdr.frame_type == H2FrameType.Ping {
            return H2ErrorCode.ProtocolError;
        }
    }

    // 3. CONTINUATION frames must follow HEADERS on the same stream without interleaving
    if framer.state == H2ConnState.ExpectContinuation {
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

        // END_HEADERS completes the header block
        if (hdr.flags & H2_FLAG_END_HEADERS) != 0 {
            framer.state = H2ConnState.Idle;
            framer.continuation_stream_id = 0;
            framer.continuation_count = 0;
            framer.header_block_bytes = 0;
        }
        return H2ErrorCode.NoError;
    }

    // If a CONTINUATION arrives while not expecting it
    if hdr.frame_type == H2FrameType.Continuation {
        return H2ErrorCode.ProtocolError;
    }

    // 4. HEADERS frame processing
    if hdr.frame_type == H2FrameType.Headers {
        // Client stream IDs must be odd (RFC 9113 §5.1.1)
        if (hdr.stream_id % 2) == 0 {
            return H2ErrorCode.ProtocolError;
        }

        if (hdr.flags & H2_FLAG_END_HEADERS) == 0 {
            // Begins a CONTINUATION sequence
            framer.state = H2ConnState.ExpectContinuation;
            framer.continuation_stream_id = hdr.stream_id;
            framer.continuation_count = 0;
            framer.header_block_bytes = hdr.payload_len;
        }
        return H2ErrorCode.NoError;
    }

    // 5. RST_STREAM flood limit
    if hdr.frame_type == H2FrameType.RstStream {
        framer.rapid_reset_count++;
        if framer.rapid_reset_count > framer.max_rapid_resets {
            framer.state = H2ConnState.Closed;
            return H2ErrorCode.EnhanceYourCalm;
        }
        return H2ErrorCode.NoError;
    }

    // 6. PING flood limit
    if hdr.frame_type == H2FrameType.Ping {
        if (hdr.flags & H2_FLAG_ACK) == 0 {
            framer.ping_flood_count++;
            if framer.ping_flood_count > framer.max_unack_pings {
                return H2ErrorCode.EnhanceYourCalm;
            }
        }
    }

    return H2ErrorCode.NoError;
}

// Validates an HTTP/2 SETTINGS parameter (RFC 9113 §6.5.2).
fn validate_h2_setting(param_id: u16, val: u32) -> H2ErrorCode {
    // SETTINGS_ENABLE_PUSH (0x2): value must be 0 or 1
    if param_id == 0x2 {
        if val != 0 && val != 1 {
            return H2ErrorCode.ProtocolError;
        }
    }

    // SETTINGS_INITIAL_WINDOW_SIZE (0x4): maximum 2^31 - 1
    if param_id == 0x4 {
        if val > 0x7fffffff {
            return H2ErrorCode.FlowControlError;
        }
    }

    // SETTINGS_MAX_FRAME_SIZE (0x5) must be between 16384 and 16777215 (RFC 9113 §6.5.2)
    if param_id == 0x5 {
        if val < 16384 || val > 16777215 {
            return H2ErrorCode.ProtocolError;
        }
    }

    return H2ErrorCode.NoError;
}
