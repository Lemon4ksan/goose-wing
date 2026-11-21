// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Demonstration of goose-wing Realtime Engine:
// Zero-Allocation WebSocket framing and TopicTree pub/sub message broadcasting.
import std;
import wing from "..";

fn main() {
    print("goose-wing Realtime WebSocket & Pub/Sub Engine Demo\n");

    // 1. Initialize Zero-Heap TopicTree (OASIS MQTT / uWebSockets architecture)
    var tree = realtime::TopicTree { .. };

    // 2. Subscribe simulated client sockets to topic channels
    let client1_fd: i64 = 101;
    let client2_fd: i64 = 102;
    let monitor_fd: i64 = 999;

    // Direct room subscriptions
    tree.subscribe(client1_fd, "chat/crypto/general");
    tree.subscribe(client2_fd, "chat/crypto/general");

    // Wildcard subscription (# matches all sub-levels)
    tree.subscribe(monitor_fd, "chat/#");

    print("[1] Topic Subscriptions Registered:");
    print("    Client 101 -> chat/crypto/general");
    print("    Client 102 -> chat/crypto/general");
    print("    Monitor 999 -> chat/# (Wildcard)");
    print("    Active buckets: ", tree.active_buckets);
    print("    Active subscriptions: ", tree.active_subscriptions);

    // 3. Match subscribers for a broadcast on "chat/crypto/general"
    var matched_fds: i64[..512] = [];
    tree.find_subscribers("chat/crypto/general", matched_fds);

    print("\n[2] Routing Message on topic 'chat/crypto/general':");
    print("    Matched subscriber count: ", matched_fds.len);
    for fd in matched_fds {
        print("    -> Matched socket descriptor: ", fd);
    }

    // 4. Encode an outbound WebSocket RFC 6455 Text Frame
    let chat_json = "{\"sender\":\"alice\",\"text\":\"Goose Wing WebSocket streaming!\"}";
    var frame_out: u8[..256] = [];
    realtime::encode_ws_frame(frame_out, rfc::WS_OPCODE_TEXT, chat_json, false);

    print("\n[3] WebSocket RFC 6455 Frame Encoded:");
    print("    Payload Length: ", chat_json.len, " bytes");
    print("    Wire Frame Size: ", frame_out.len, " bytes");
    print("    Opcode: WS_OPCODE_TEXT (0x01), FIN: 1");

    // 5. Ingest and decode a masked client frame (RFC 6455 Section 5.3)
    let mask_key: u8[4] = [0x1A, 0x2B, 0x3C, 0x4D];
    var masked_wire: u8[..256] = [];

    // Client-to-server frames MUST be masked
    realtime::encode_ws_frame(masked_wire, rfc::WS_OPCODE_TEXT, chat_json, true, mask_key);

    let parsed_header, hdr_ok = realtime::parse_ws_frame_header(masked_wire[..]);

    print("\n[4] Inbound Client Masked Frame Processing:");
    print("    Mask Key: [0x1A, 0x2B, 0x3C, 0x4D]");
    print("    Masked wire frame size: ", masked_wire.len, " bytes");
    print("    Header parsed cleanly: ", hdr_ok);
    print("    Decoded FIN: ", parsed_header.fin);
    print("    Decoded Masked: ", parsed_header.masked);
    print("    Decoded Payload Length: ", parsed_header.payload_len);

    // Unmask payload directly on stack
    var unmasked_payload: u8[..256] = [];
    let payload_bytes = masked_wire[(parsed_header.header_len as i64)..];
    unmasked_payload.append(payload_bytes);
    realtime::mask_websocket_payload(unmasked_payload[..], parsed_header.mask_key);

    print("    Recovered Text: ", unmasked_payload[..]);
}
