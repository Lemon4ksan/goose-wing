// WebSocket Protocol Framing and Handshake Engine (RFC 6455 & RFC 8441).
// Pure clean-room zero-allocation implementation:
// - Zero-copy in-place 64-bit unrolled payload masking / unmasking
// - Complete frame header parser, serializer, and control frame invariant enforcer
// - RFC 6455 Section 4.2.2 Sec-WebSocket-Key / Accept handshake verification via SHA-1
// - Close frame payload encoding and status code validation
namespace wing;

import std;
import core from "..";

// ---- 1. Opcodes and Protocol Constants (RFC 6455 Section 5.2) --------------

const WS_OPCODE_CONTINUATION: u8 = 0x0;
const WS_OPCODE_TEXT:         u8 = 0x1;
const WS_OPCODE_BINARY:       u8 = 0x2;
const WS_OPCODE_CLOSE:        u8 = 0x8;
const WS_OPCODE_PING:         u8 = 0x9;
const WS_OPCODE_PONG:         u8 = 0xA;

// Close Status Codes (RFC 6455 Section 7.4.1)
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

// RFC 6455 Section 1.3 Handshake GUID
let WS_HANDSHAKE_GUID: const u8[:] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// Checks if an opcode represents a control frame (RFC 6455 Section 5.5)
inline fn is_ws_control_opcode(opcode: u8) -> bool {
    return (opcode & 0x08) != 0;
}

// Checks if an opcode is valid
fn is_valid_ws_opcode(opcode: u8) -> bool {
    return opcode == WS_OPCODE_CONTINUATION ||
           opcode == WS_OPCODE_TEXT ||
           opcode == WS_OPCODE_BINARY ||
           opcode == WS_OPCODE_CLOSE ||
           opcode == WS_OPCODE_PING ||
           opcode == WS_OPCODE_PONG;
}

// ---- 2. Frame Header Structure and Invariants ------------------------------

struct WsFrameHeader {
    fin: bool = true,
    rsv1: bool = false,
    rsv2: bool = false,
    rsv3: bool = false,
    opcode: u8 = WS_OPCODE_TEXT,
    masked: bool = false,
    mask_key: u8[4] = [0; 4],
    payload_len: u64 = 0,
    header_len: u16 = 0,
}

// In-place masking / unmasking using 64-bit word XOR unrolling (RFC 6455 Section 5.3)
fn mask_websocket_payload(data: u8[:], mask_key: const u8[4]&) {
    let n = data.len;
    guard n > 0 else { return; }

    // Replicate 4-byte mask key across 64 bits
    let k0 = mask_key[0] as u64;
    let k1 = mask_key[1] as u64;
    let k2 = mask_key[2] as u64;
    let k3 = mask_key[3] as u64;
    let mask64: u64 = (k0 << 56) | (k1 << 48) | (k2 << 40) | (k3 << 32) |
                      (k0 << 24) | (k1 << 16) | (k2 << 8)  | k3;

    var i: i64 = 0;
    while i + 8 <= n {
        let chunk = core::read_be_u64(data, i);
        core::write_be_u64_at(data, i, chunk ^ mask64);
        i += 8;
    }

    // Trailing bytes (0..7)
    while i < n {
        data[i] ^= mask_key[i % 4];
        i++;
    }
}

// Parses RFC 6455 Frame Header with strict protocol validation
fn parse_ws_frame_header(src: const u8[:]) -> WsFrameHeader, bool {
    var hdr = WsFrameHeader { .. };
    guard src.len >= 2 else { return hdr, false; }

    let b0 = src[0];
    let b1 = src[1];

    let fin  = (b0 & 0x80) != 0;
    let rsv1 = (b0 & 0x40) != 0;
    let rsv2 = (b0 & 0x20) != 0;
    let rsv3 = (b0 & 0x10) != 0;
    let opcode = b0 & 0x0F;

    guard is_valid_ws_opcode(opcode) else { return hdr, false; }

    // Control frame invariants (RFC 6455 Section 5.5):
    // 1. MUST NOT be fragmented (FIN MUST be 1)
    // 2. Payload length MUST be <= 125
    if is_ws_control_opcode(opcode) {
        guard fin else { return hdr, false; }
    }

    let masked = (b1 & 0x80) != 0;
    let raw_len = (b1 & 0x7F) as u64;

    var offset: i64 = 2;
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
    if is_ws_control_opcode(opcode) {
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
fn encode_ws_frame_header<B>(out: B&, hdr: const WsFrameHeader&) {
    var b0: u8 = hdr.opcode & 0x0F;
    if hdr.fin  { b0 |= 0x80; }
    if hdr.rsv1 { b0 |= 0x40; }
    if hdr.rsv2 { b0 |= 0x20; }
    if hdr.rsv3 { b0 |= 0x10; }
    out.push(b0);

    let mask_bit: u8 = if hdr.masked { 0x80 } else { 0x00 };

    if hdr.payload_len <= 125 {
        out.push(mask_bit | (hdr.payload_len as u8));
    } else if hdr.payload_len <= 65535 {
        out.push(mask_bit | 126);
        core::write_be_u16(out, hdr.payload_len as u16);
    } else {
        out.push(mask_bit | 127);
        core::write_be_u64(out, hdr.payload_len);
    }

    if hdr.masked {
        out.append(hdr.mask_key[..]);
    }
}

// High-level frame serializer: writes header + payload (masked if is_client)
fn encode_ws_frame<B>(
    out: B&,
    opcode: u8,
    payload: const u8[:],
    is_client: bool = true,
    mask_key: const u8[4]& = [0; 4],
    fin: bool = true
) {
    let hdr = WsFrameHeader {
        fin: fin,
        opcode: opcode,
        masked: is_client,
        mask_key: mask_key,
        payload_len: payload.len as u64,
        ..
    };
    encode_ws_frame_header(out, hdr);

    if is_client {
        for i in payload.len {
            out.push(payload[i] ^ mask_key[i % 4]);
        }
    } else {
        out.append(payload);
    }
}

// ---- 3. Handshake Engine (RFC 6455 Section 4.2.2 & RFC 8441) ---------------

// Computes standard `Sec-WebSocket-Accept` from `Sec-WebSocket-Key`
fn compute_websocket_accept<B>(client_key: const u8[:], out: B&) {
    var combined: u8[..128] = [];
    combined.append(client_key);
    combined.append(WS_HANDSHAKE_GUID);
    let digest = core::sha1(combined[..]);
    core::base64_encode(digest[..], out);
}

// Validates server `Sec-WebSocket-Accept` against client key
fn validate_websocket_accept(client_key: const u8[:], server_accept: const u8[:]) -> bool {
    var expected: u8[..64] = [];
    compute_websocket_accept(client_key, expected);
    return expected[..] == server_accept;
}

// Formats a 16-byte random nonce into a 24-character Base64 client key
fn generate_websocket_key<B>(random_16: const u8[16]&, out: B&) {
    core::base64_encode(random_16[..], out);
}

// ---- 4. Close Frame Helpers (RFC 6455 Section 5.5.1) -----------------------

// Encodes a Close frame payload (2-byte status code + optional UTF-8 reason)
fn encode_ws_close_payload<B>(out: B&, status_code: u16, reason: const u8[:]) {
    core::write_be_u16(out, status_code);
    out.append(reason);
}

// Parses a Close frame payload into (status_code, reason_slice, ok)
fn parse_ws_close_payload(payload: const u8[:]) -> u16, const u8[:], bool {
    if payload.len == 0 {
        return WS_STATUS_NO_STATUS, "", true;
    }
    guard payload.len >= 2 else { return 0, "", false; }

    let status_code = core::read_be_u16(payload, 0);
    let reason = payload[2..];

    // RFC 6455 Section 7.4.2: Reserved / forbidden status codes
    guard status_code != 1004 && status_code != 1005 &&
          status_code != 1006 && status_code != 1015 else {
        return 0, "", false;
    }
    // Status codes 0..999 are forbidden
    guard status_code >= 1000 else { return 0, "", false; }

    return status_code, reason, true;
}

// ---- 5. High-Level Ergonomic WebSocket Client Session -----------------------

struct WebSocketSession {
    is_client: bool = true,
    subprotocol: u8[..64] = [],
    is_closed: bool = false,
    close_code: u16 = 0,
    mask_rng_state: u32 = 0x9E3779B9, // Fast linear congruential PRNG for 4-byte client masking keys
}

fn new_websocket_session(is_client: bool = true) -> WebSocketSession {
    return WebSocketSession { is_client: is_client, .. };
}

// Generates pseudo-random 4-byte masking key for client frames
fn ws_next_mask_key(ws: WebSocketSession&) -> u8[4] {
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
fn ws_build_handshake_request<B>(
    ws: const WebSocketSession&,
    host: const u8[:],
    path: const u8[:],
    client_key: const u8[:],
    out: B&
) {
    format(out, "GET ", path, " HTTP/1.1\r\nHost: ", host, "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ", client_key);
    if ws.subprotocol.len > 0 {
        format(out, "\r\nSec-WebSocket-Protocol: ", ws.subprotocol[..]);
    }
    out.append("\r\n\r\n");
}

// High-level method: sends UTF-8 text message
fn ws_send_text<B>(ws: WebSocketSession&, text: const u8[:], out: B&) {
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, WS_OPCODE_TEXT, text, ws.is_client, mask, true);
}

// High-level method: sends binary message
fn ws_send_binary<B>(ws: WebSocketSession&, data: const u8[:], out: B&) {
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, WS_OPCODE_BINARY, data, ws.is_client, mask, true);
}

// High-level method: sends Ping heartbeat
fn ws_send_ping<B>(ws: WebSocketSession&, ping_payload: const u8[:], out: B&) {
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, WS_OPCODE_PING, ping_payload, ws.is_client, mask, true);
}

// High-level method: sends Pong heartbeat response
fn ws_send_pong<B>(ws: WebSocketSession&, pong_payload: const u8[:], out: B&) {
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, WS_OPCODE_PONG, pong_payload, ws.is_client, mask, true);
}

// High-level method: sends Close handshake
fn ws_close<B>(ws: WebSocketSession&, status_code: u16, reason: const u8[:], out: B&) {
    var payload: u8[..128] = [];
    encode_ws_close_payload(payload, status_code, reason);
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, WS_OPCODE_CLOSE, payload[..], ws.is_client, mask, true);
    ws.is_closed = true;
    ws.close_code = status_code;
}

// ---- 6. High-Level Message Dispatcher & Server Upgrade ---------------------

struct WsMessage {
    opcode: u8 = WS_OPCODE_TEXT,
    data: u8[..4096] = [],
    close_code: u16 = 0,
    close_reason: u8[..128] = [],
    is_valid: bool = false,
}

// Dispatches incoming raw frame wire bytes: unmasks payload, automatically prepares Pong for Ping,
// answers Close with Close echo, and populates out_msg for data frames.
fn ws_receive<B>(ws: WebSocketSession&, wire: u8[:], out_msg: WsMessage&, out_reply: B&) -> bool {
    out_msg.is_valid = false;
    out_msg.data.clear();
    out_msg.close_reason.clear();
    out_msg.close_code = 0;

    let hdr, ok = parse_ws_frame_header(wire);
    guard ok else { return false; }

    let p_start = hdr.header_len as i64;
    let p_len = hdr.payload_len as i64;
    guard p_start + p_len <= wire.len else { return false; }
    let payload = wire[p_start..(p_start + p_len)];

    // Protocol validations (RFC 6455 Section 5.1 & 5.2):
    // 1. RSV bits must be 0 unless an extension is negotiated.
    if hdr.rsv1 || hdr.rsv2 || hdr.rsv3 {
        ws_close(ws, WS_STATUS_PROTOCOL_ERROR, "RSV bits set without extension", out_reply);
        ws.is_closed = true;
        ws.close_code = WS_STATUS_PROTOCOL_ERROR;
        return true;
    }

    // 2. Client MUST NOT receive masked frames from server.
    if ws.is_client && hdr.masked {
        ws_close(ws, WS_STATUS_PROTOCOL_ERROR, "masked frame received by client", out_reply);
        ws.is_closed = true;
        ws.close_code = WS_STATUS_PROTOCOL_ERROR;
        return true;
    }

    // 3. Server MUST NOT receive unmasked frames from client.
    if !ws.is_client && !hdr.masked {
        ws_close(ws, WS_STATUS_PROTOCOL_ERROR, "unmasked frame received by server", out_reply);
        ws.is_closed = true;
        ws.close_code = WS_STATUS_PROTOCOL_ERROR;
        return true;
    }

    if hdr.masked {
        mask_websocket_payload(payload, hdr.mask_key);
    }

    if hdr.opcode == WS_OPCODE_PING {
        ws_send_pong(ws, payload, out_reply);
        out_msg.opcode = WS_OPCODE_PING;
        out_msg.data.append(payload);
        out_msg.is_valid = true;
        return true;
    } else if hdr.opcode == WS_OPCODE_PONG {
        out_msg.opcode = WS_OPCODE_PONG;
        out_msg.data.append(payload);
        out_msg.is_valid = true;
        return true;
    } else if hdr.opcode == WS_OPCODE_CLOSE {
        let code, reason, _ = parse_ws_close_payload(payload);
        out_msg.opcode = WS_OPCODE_CLOSE;
        out_msg.close_code = code;
        out_msg.close_reason.append(reason);
        out_msg.is_valid = true;
        if !ws.is_closed {
            ws_close(ws, code, reason, out_reply);
        }
        ws.is_closed = true;
        ws.close_code = code;
        return true;
    } else if hdr.opcode == WS_OPCODE_TEXT || hdr.opcode == WS_OPCODE_BINARY {
        out_msg.opcode = hdr.opcode;
        out_msg.data.append(payload);
        out_msg.is_valid = true;
        return true;
    }

    return true;
}

// Server-side WebSocket upgrade handler (RFC 6455). Validates client request and populates 101 response.
fn ws_upgrade_request(req: const Request&, out_resp: Response&, subprotocol: const u8[:] = "") -> WebSocketSession, bool {
    let method = req.method[..];
    if method != "GET" {
        out_resp.status_code = 405;
        return WebSocketSession { .. }, false;
    }

    let upg = req.headers.find_header("Upgrade");
    if !core::eq_ascii_fold(upg, "websocket") {
        out_resp.status_code = 400;
        return WebSocketSession { .. }, false;
    }

    let conn = req.headers.find_header("Connection");
    if !core::contains_fold(conn, "upgrade") {
        out_resp.status_code = 400;
        return WebSocketSession { .. }, false;
    }

    let ver = req.headers.find_header("Sec-WebSocket-Version");
    if ver != "13" {
        out_resp.status_code = 426;
        out_resp.set_header("Sec-WebSocket-Version", "13");
        return WebSocketSession { .. }, false;
    }

    let client_key = req.headers.find_header("Sec-WebSocket-Key");
    if client_key.len == 0 {
        out_resp.status_code = 400;
        return WebSocketSession { .. }, false;
    }

    var accept_key: u8[..64] = [];
    compute_websocket_accept(client_key, accept_key);

    out_resp.status_code = 101;
    out_resp.set_header("Upgrade", "websocket");
    out_resp.set_header("Connection", "Upgrade");
    out_resp.set_header("Sec-WebSocket-Accept", accept_key[..]);

    var session = new_websocket_session(false);
    if subprotocol.len > 0 {
        out_resp.set_header("Sec-WebSocket-Protocol", subprotocol);
        session.subprotocol.append(subprotocol);
    }

    return session, true;
}
