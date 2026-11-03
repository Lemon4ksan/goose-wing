// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_ws_masking_simd.goose
// Verification of WebSocket Payload XOR Masking (RFC 6455 §5.3) & Invariants (§5.1).
// Tests SWAR 64-bit vectorization, scalar unaligned offsets (1..63 bytes),
// roundtrip mask/unmask symmetry, and client/server mask validation.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

fn verify_single_size_mask(sz: i64, mask: const u8[4]&) {
    var buf: u8[>..] = [];
    for i in sz {
        let val: u8 = ((i * 7 + 13) & 0xFF) as u8;
        buf.push(val);
    }

    var original: u8[>..] = [];
    for b in buf { original.push(b); }

    // Mask in place
    wing::mask_websocket_payload(buf[..], mask);

    // Unmask with identical key
    wing::mask_websocket_payload(buf[..], mask);

    for i in sz {
        assert(buf[i] == original[i]);
    }
}

fn test_masking_roundtrip_across_sizes() {
    let mask: u8[4] = [0x37, 0xFA, 0x21, 0x3D];
    // Sample across scalar tails, SWAR, and SIMD boundary
    let sizes: i64[10] = [1, 3, 7, 8, 15, 31, 32, 63, 64, 129];
    for s in sizes {
        verify_single_size_mask(s, mask);
    }
    print("WS_MASK_ROUNDTRIP_ALL_SIZES: OK");
}

fn verify_single_swar_equivalence(sz: i64, mask: const u8[4]&) {
    var buf_swar:   u8[>..] = [];
    var buf_scalar: u8[>..] = [];

    for i in sz {
        let val: u8 = ((i * 31 + 4) & 0xFF) as u8;
        buf_swar.push(val);
        buf_scalar.push(val);
    }

    wing::apply_mask_in_place(buf_swar[..], mask);

    for i in sz {
        let m = mask[i % 4];
        buf_scalar[i] = buf_scalar[i] ^ m;
    }

    for i in sz {
        assert(buf_swar[i] == buf_scalar[i]);
    }
}

fn test_swar_vs_scalar_equivalence() {
    let mask:       u8[4]  = [0xA5, 0x5A, 0xF0, 0x0F];
    let test_sizes: i64[6] = [1, 7, 8, 15, 33, 63];
    for s in test_sizes {
        verify_single_swar_equivalence(s, mask);
    }
    print("WS_SWAR_EQUIVALENCE: OK");
}

fn test_masking_enforcement_invariants() {
    let client_recv_masked = wing::is_ws_masking_valid(wing::WsRole.Client, true);
    assert(!client_recv_masked);
    print("CLIENT_RECV_MASKED_INVALID: OK");

    let client_recv_unmasked = wing::is_ws_masking_valid(wing::WsRole.Client, false);
    assert(client_recv_unmasked);
    print("CLIENT_RECV_UNMASKED_VALID: OK");

    let server_recv_unmasked = wing::is_ws_masking_valid(wing::WsRole.Server, false);
    assert(!server_recv_unmasked);
    print("SERVER_RECV_UNMASKED_INVALID: OK");

    let server_recv_masked = wing::is_ws_masking_valid(wing::WsRole.Server, true);
    assert(server_recv_masked);
    print("SERVER_RECV_MASKED_VALID: OK");
}

fn parse_ws_frame_step(buf: const u8[:]) -> i64 {
    guard buf.len >= 2 else { return -1; }
    let hdr, ok = wing::parse_ws_frame_header(buf);
    guard ok else { return -1; }
    let hlen: i64 = hdr.header_len;
    let plen: i64 = hdr.payload_len as i64;
    guard buf.len - hlen >= plen else { return -1; }
    return hdr.opcode;
}

fn test_ws_split_stream() {
    var frame_out: u8[>..] = [];
    let payload = "Antigravity";
    let mask: u8[4] = [0x12, 0x34, 0x56, 0x78];
    wing::encode_ws_frame(frame_out, rfc::WS_OPCODE_TEXT, payload, true, mask, true);

    let ok = wire_kit::verify_split_stream(frame_out[..], -1, rfc::WS_OPCODE_TEXT as i64, parse_ws_frame_step);
    assert(ok);
    assert(wire_kit::fuzz_payload(frame_out[..], 100, parse_ws_frame_step));
    print("WS_SPLIT_STREAM_VERIFIED: OK");
}

fn main() {
    print("=== RUNNING WS MASKING AND INVARIANTS SUITE ===");
    test_masking_roundtrip_across_sizes();
    test_swar_vs_scalar_equivalence();
    test_masking_enforcement_invariants();
    test_ws_split_stream();
    print("WS MASKING COMPLETE: ALL INVARIANTS PASSED");
}

// CHECK: === RUNNING WS MASKING AND INVARIANTS SUITE ===
// CHECK: WS_MASK_ROUNDTRIP_ALL_SIZES: OK
// CHECK: WS_SWAR_EQUIVALENCE: OK
// CHECK: CLIENT_RECV_MASKED_INVALID: OK
// CHECK: CLIENT_RECV_UNMASKED_VALID: OK
// CHECK: SERVER_RECV_UNMASKED_INVALID: OK
// CHECK: SERVER_RECV_MASKED_VALID: OK
// CHECK: WS_SPLIT_STREAM_VERIFIED: OK
// CHECK: WS MASKING COMPLETE: ALL INVARIANTS PASSED
