// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_zstd_and_quic_edge.goose
// Verification of RFC 8878 Zstandard 4-stream literals partition invariants,
// RFC 9000 §17.2.1 Version Negotiation payload boundaries, and QUIC ACK frame offset chaining.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s && %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_zstd_4stream_partition() {
    // RFC 8878 §3.1.1.3.1.2: 4 Streams Regenerated Size Partition Invariant
    // Stream 1: (N + 3) / 4
    // Stream 2: (N + 2) / 4
    // Stream 3: (N + 1) / 4
    // Stream 4: N / 4
    // Sum MUST equal N for all N >= 6.
    let test_sizes: const i64[10] = [6, 7, 8, 9, 10, 11, 12, 100, 1023, 65536];
    var all_sums_match = true;

    for n in test_sizes {
        let sz1 = (n + 3) / 4;
        let sz2 = (n + 2) / 4;
        let sz3 = (n + 1) / 4;
        let sz4 = n / 4;
        let sum = sz1 + sz2 + sz3 + sz4;
        if sum != n {
            all_sums_match = false;
        }
    }
    print("ZSTD_4STREAM_PARTITION_SUM: ", if all_sums_match { "OK" } else { "FAIL" });

    // Specific boundary checks for N = 6 (minimum 4-stream regenerated size)
    let n6 = 6;
    let n6_s1 = (n6 + 3) / 4; // 2
    let n6_s2 = (n6 + 2) / 4; // 2
    let n6_s3 = (n6 + 1) / 4; // 1
    let n6_s4 = n6 / 4;       // 1
    assert(n6_s1 == 2 && n6_s2 == 2 && n6_s3 == 1 && n6_s4 == 1);
    print("ZSTD_4STREAM_N6_SIZES: s1=", n6_s1, " s2=", n6_s2, " s3=", n6_s3, " s4=", n6_s4);

    // Specific boundary checks for N = 10
    let n10 = 10;
    let n10_s1 = (n10 + 3) / 4; // 3
    let n10_s2 = (n10 + 2) / 4; // 3
    let n10_s3 = (n10 + 1) / 4; // 2
    let n10_s4 = n10 / 4;       // 2
    assert(n10_s1 == 3 && n10_s2 == 3 && n10_s3 == 2 && n10_s4 == 2);
    print("ZSTD_4STREAM_N10_SIZES: s1=", n10_s1, " s2=", n10_s2, " s3=", n10_s3, " s4=", n10_s4);

    // Verify round-trip zstd compress/decompress with declared frame content size
    var raw_input: u8[>..] = [];
    raw_input.append("The quick brown fox jumps over the lazy dog. Zstandard RFC 8878 high-throughput framing verification.");
    var compressed: u8[>..] = [];
    let ok_comp = core::zstd_compress(raw_input[..], compressed);
    assert(ok_comp);

    var decompressed: u8[>..] = [];
    let ok_decomp, decomp_err = core::zstd_decompress(compressed[..], decompressed);
    assert(ok_decomp);
    assert(decomp_err == core::CompressError.None);
    assert(decompressed.len == raw_input.len);
    print("ZSTD_ROUNDTRIP_DECOMPRESS: OK, len=", decompressed.len);
}

fn test_quic_vn_boundaries() {
    // 1. Valid Version Negotiation with 1 version (4 bytes)
    var vn_1: u8[>..] = [];
    vn_1.push(0x80); // Long header (bit 7 = 1)
    core::append_u32_be(vn_1, internal::QUIC_VERSION_NEGOTIATION); // Version 0x00000000
    vn_1.push(4); // DCID len
    vn_1.append("DCID");
    vn_1.push(4); // SCID len
    vn_1.append("SCID");
    core::append_u32_be(vn_1, internal::QUIC_VERSION_1); // 1 Supported Version (4 bytes)

    let hdr_1, ok_vn_1 = internal::parse_quic_header(vn_1[..], 0);
    let type_str_1 = if hdr_1.header_type == internal::QuicHeaderType.VersionNegotiation { "VN" } else { "OTHER" };
    print("QUIC_VN_1_VER: ", if ok_vn_1 { "OK" } else { "FAIL" }, " type=", type_str_1);

    // 2. Valid Version Negotiation with 2 versions (8 bytes)
    var vn_2: u8[>..] = [];
    vn_2.push(0x80);
    core::append_u32_be(vn_2, internal::QUIC_VERSION_NEGOTIATION);
    vn_2.push(4);
    vn_2.append("DCID");
    vn_2.push(4);
    vn_2.append("SCID");
    core::append_u32_be(vn_2, internal::QUIC_VERSION_1);
    core::append_u32_be(vn_2, 0xFACEB00C); // Second version

    let hdr_2, ok_vn_2 = internal::parse_quic_header(vn_2[..], 0);
    let type_str_2 = if hdr_2.header_type == internal::QuicHeaderType.VersionNegotiation { "VN" } else { "OTHER" };
    print("QUIC_VN_2_VER: ", if ok_vn_2 { "OK" } else { "FAIL" }, " type=", type_str_2);

    // 3. Malformed Version Negotiation with 0 versions (RFC 9000 §17.2.1: MUST have >= 1 version)
    var vn_empty: u8[>..] = [];
    vn_empty.push(0x80);
    core::append_u32_be(vn_empty, internal::QUIC_VERSION_NEGOTIATION);
    vn_empty.push(4);
    vn_empty.append("DCID");
    vn_empty.push(4);
    vn_empty.append("SCID");
    // No versions follow!

    let _, ok_vn_empty = internal::parse_quic_header(vn_empty[..], 0);
    print("QUIC_VN_EMPTY: ", if !ok_vn_empty { "REJECTED" } else { "ACCEPTED" });

    // 4. Malformed Version Negotiation with truncated 3-byte version
    var vn_trunc: u8[>..] = [];
    vn_trunc.push(0x80);
    core::append_u32_be(vn_trunc, internal::QUIC_VERSION_NEGOTIATION);
    vn_trunc.push(4);
    vn_trunc.append("DCID");
    vn_trunc.push(4);
    vn_trunc.append("SCID");
    vn_trunc.append([0x00, 0x00, 0x01]); // 3 bytes (not a multiple of 4!)

    let _, ok_vn_trunc = internal::parse_quic_header(vn_trunc[..], 0);
    print("QUIC_VN_TRUNC: ", if !ok_vn_trunc { "REJECTED" } else { "ACCEPTED" });

    // 5. Malformed Version Negotiation with 5 bytes (1 version + 1 dangling byte)
    var vn_dangling: u8[>..] = [];
    vn_dangling.push(0x80);
    core::append_u32_be(vn_dangling, internal::QUIC_VERSION_NEGOTIATION);
    vn_dangling.push(4);
    vn_dangling.append("DCID");
    vn_dangling.push(4);
    vn_dangling.append("SCID");
    core::append_u32_be(vn_dangling, internal::QUIC_VERSION_1);
    vn_dangling.push(0xFF); // 1 extra byte

    let _, ok_vn_dangling = internal::parse_quic_header(vn_dangling[..], 0);
    print("QUIC_VN_DANGLING: ", if !ok_vn_dangling { "REJECTED" } else { "ACCEPTED" });
}

fn test_quic_ack_offset_chaining() {
    var ack1 = internal::AckFrame {
        is_ecn:          false,
        largest_acked:   200,
        ack_delay:       15,
        first_ack_range: 5,
        ..
    };
    var wire: u8[>..] = [];
    // Prefix wire with 3 padding bytes (PING or PADDING frames)
    wire.append([0x00, 0x00, 0x01]);

    let ok_enc = internal::encode_ack_frame(wire, ack1);
    assert(ok_enc);

    let prefix_off: u64 = 3;
    let dec_ack, next_off, ok_dec = internal::decode_ack_frame(wire[..], prefix_off);
    print("QUIC_ACK_CHAIN_DECODE: ", if ok_dec { "OK" } else { "FAIL" });
    assert(ok_dec);
    assert(dec_ack.largest_acked == 200);
    assert(dec_ack.first_ack_range == 5);
    assert(next_off == (wire.len as u64));
    print("QUIC_ACK_CHAIN_OFFSET: start=", prefix_off, " next=", next_off, " total=", wire.len);

    // Decoding beyond wire boundary returns original offset and false
    let _, err_off, ok_bad = internal::decode_ack_frame(wire[..], next_off + 1);
    print("QUIC_ACK_CHAIN_EOF: ", if !ok_bad && err_off == next_off + 1 { "OK" } else { "FAIL" });
}

fn main() {
    test_zstd_4stream_partition();
    test_quic_vn_boundaries();
    test_quic_ack_offset_chaining();
}

// CHECK-DAG: ZSTD_4STREAM_PARTITION_SUM: OK
// CHECK-DAG: ZSTD_4STREAM_N6_SIZES: s1=2 s2=2 s3=1 s4=1
// CHECK-DAG: ZSTD_4STREAM_N10_SIZES: s1=3 s2=3 s3=2 s4=2
// CHECK-DAG: ZSTD_ROUNDTRIP_DECOMPRESS: OK, len=[[REG_SZ:[0-9]+]]
// CHECK-DAG: QUIC_VN_1_VER: OK type=VN
// CHECK-DAG: QUIC_VN_2_VER: OK type=VN
// CHECK-DAG: QUIC_VN_EMPTY: REJECTED
// CHECK-DAG: QUIC_VN_TRUNC: REJECTED
// CHECK-DAG: QUIC_VN_DANGLING: REJECTED
// CHECK-DAG: QUIC_ACK_CHAIN_DECODE: OK
// CHECK-DAG: QUIC_ACK_CHAIN_OFFSET: start=3 next=[[END_OFF:[0-9]+]] total=[[END_OFF]]
// CHECK-DAG: QUIC_ACK_CHAIN_EOF: OK
