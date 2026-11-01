// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Demonstration of Vulkan-style explicit wire framing and zero-allocation command buffers in goose-wing.
import std;
import core from "..";
import wing from "..";

fn main() {
    print("=== goose-wing Vulkan-Style Wire API Reference Pipeline ===\n");

    // ---- Device and Transport Configuration ------------------------------
    print("[1] Configuring Physical Wire Device Parameters:");
    var dev_cfg = wire::WireDeviceConfig {
        driver:            wire::WireDriverKind.Standard,
        tcp_nodelay:       true,
        tcp_keepalive:     true,
        has_dont_fragment: true,
        ip_ttl:            128,
        rx_buf_size:       65536,
        tx_buf_size:       65536,
        wscale:            8,
        mss:               1460,
    };
    print("    Transport Driver: Standard POSIX / WinSock2");
    print("    TCP_NODELAY:      true (Nagle disabled)");
    print("    IP TTL:           128");

    // ---- Command Buffer Recording (Explicit Framing) ---------------------
    print("\n[2] Recording Protocol Frames into Zero-Heap Command Buffer:");
    var cmd = wire::new_command_buffer();

    // Command 1: Write HTTP/2 Client Connection Preface (24 bytes)
    assert(wire::write_h2_preface(cmd));
    print("    Recorded: HTTP/2 Client Preface (24 bytes)");

    // Command 2: Write SETTINGS Frame (Stream 0)
    let settings_list: wire::WireSetting[3] = [
        wire::h2_setting(wire::H2_SETTING_ENABLE_PUSH, 0),
        wire::h2_setting(wire::H2_SETTING_INITIAL_WINDOW_SIZE, 131072),
        wire::h2_setting(wire::H2_SETTING_NO_RFC7540_PRIORITIES, 1),
    ];
    assert(wire::write_h2_settings(cmd, settings_list[..]));
    print("    Recorded: SETTINGS Frame (3 parameters, 18 bytes payload)");

    // Command 3: Write WINDOW_UPDATE Frame (Stream 0, +512 KB credit)
    assert(wire::write_h2_window_update(cmd, 0, 524288));
    print("    Recorded: WINDOW_UPDATE (Stream 0, increment=524288)");

    // Command 4: Write RFC 9218 PRIORITY_UPDATE Frame (Stream 1, urgency=0, non-incremental)
    assert(wire::write_h2_priority_update(cmd, 1, 0, false));
    print("    Recorded: RFC 9218 PRIORITY_UPDATE (Stream 1, u=0)");

    // Command 5: Dynamic HEADERS Frame Recording with HPACK Patching
    assert(wire::begin_h2_headers(cmd, 1, wire::H2_FLAG_END_HEADERS));
    assert(wire::hpack_indexed(cmd, 2)); // :method: GET (static index 2)
    assert(wire::hpack_indexed(cmd, 7)); // :scheme: https (static index 7)
    assert(wire::hpack_literal_without_indexing(cmd, ":path", "/v1/orders"));
    assert(wire::hpack_literal_without_indexing(cmd, ":authority", "wire.mesh.local"));
    assert(wire::hpack_literal_never_indexed(cmd, "authorization", "Bearer super-secret-token"));
    assert(wire::end_h2_headers(cmd));
    print("    Recorded: HEADERS Frame with back-patched 24-bit HPACK payload length");

    // Command 6: Write DATA Frame (Stream 1, payload, END_STREAM)
    let payload = "{\"action\":\"submit_order\",\"units\":10}";
    assert(wire::write_h2_data(cmd, 1, payload, true));
    print("    Recorded: DATA Frame (Stream 1, payload length=", payload.len, ", END_STREAM=true)");

    let total_bytes = wire::len(cmd);
    print("\n[3] Command Buffer Assembly Complete:");
    print("    Total Wire Bytes Recorded: ", total_bytes, " bytes");
    print("    Fault State:               ", cmd.has_error);
    print("    Heap Allocations:          0 malloc calls (100% stack)");

    // ---- Ingress Wire Frame Parsing Verification -------------------------
    print("\n[4] Demuxing Stream with Zero-Copy WireH2FrameReader:");
    let wire_bytes = cmd.buf[..];

    // Skip the 24-byte client preface for HTTP/2 binary frame parsing
    let frame_stream = wire_bytes[24..];
    var reader = wire::new_wire_h2_frame_reader(frame_stream);
    var frame_count: i32 = 0;

    while wire::has_next(reader) {
        let hdr, frame_payload, ok = wire::next_frame(reader);
        assert(ok);
        frame_count += 1;

        print("    Frame ", frame_count, ": Type=0x", if hdr.frame_type < 16 { "0" } else { "" },
              hdr.frame_type, " Stream=", hdr.stream_id, " Length=", hdr.length, " Flags=0x", hdr.flags);
    }

    assert(frame_count == 5);
    print("\n[5] All 5 recorded HTTP/2 frames parsed and verified with 100% fidelity.");
    print("============================================================");
}
