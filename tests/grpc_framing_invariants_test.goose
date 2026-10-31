// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Hardening & Security Invariants Suite for gRPC Binary LPM & gRPC-Web Framing:
// 1. 32-bit integer overflow protection on 4-byte big-endian message lengths.
// 2. Reserved flag bits validation (only compressed 0x01 and gRPC-Web trailers 0x80 allowed).
// 3. Streaming parser reassembly bounds and memory safety.
// 4. gRPC-Web trailers parsing and status code extraction.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn test_grpc_lpm_integer_overflows(t: lit::T&) {
    t.run("GRPC-SEC-01: 32-bit Integer Overflow in decode_grpc_lpm_slice") { sub =>
        // 0xFFFFFFFF (4294967295) length
        let ovf_hdr: u8[5] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF];
        let _, _, _, ok_ovf = wing::decode_grpc_lpm_slice(ovf_hdr[..], 0);
        sub.assert_false(ok_ovf, "overflow length 0xFFFFFFFF must not wrap around or succeed");

        // 0xFFFFFFFB (4294967291) length: 5 + 0xFFFFFFFB would wrap to 0 if evaluated in u32
        let ovf_wrap: u8[5] = [0x00, 0xFF, 0xFF, 0xFF, 0xFB];
        let _, _, _, ok_wrap = wing::decode_grpc_lpm_slice(ovf_wrap[..], 0);
        sub.assert_false(ok_wrap, "overflow length 0xFFFFFFFB must not wrap around or succeed");
    };

    t.run("GRPC-SEC-02: 32-bit Integer Overflow in GrpcStreamParser") { sub =>
        var parser = wing::new_grpc_stream_parser();
        let ovf_chunk: u8[5] = [0x00, 0xFF, 0xFF, 0xFF, 0xFB];
        let ok_feed = wing::feed(parser, ovf_chunk[..]);
        sub.assert_true(ok_feed, "feeding 5-byte header succeeds");

        var payload: u8[..64] = [];
        var compressed = false;
        let ok_msg = wing::next_message(parser, payload, compressed);
        sub.assert_false(ok_msg, "next_message must not return true on wrapped length");
    };

    t.run("GRPC-SEC-03: 32-bit Integer Overflow in decode_grpc_web_frame") { sub =>
        let ovf_web: u8[5] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF];
        var payload: u8[..64] = [];
        var is_trailers = false;
        var compressed = false;
        let ok_web, _ = wing::decode_grpc_web_frame(ovf_web[..], 0, payload, is_trailers, compressed);
        sub.assert_false(ok_web, "decode_grpc_web_frame must reject overflow length 0xFFFFFFFF");
    };

    t.run("GRPC-SEC-04: Reserved Flag Bits Validation") { sub =>
        // Flag 0x02 (reserved, not compressed 0x01)
        let bad_flag: u8[5] = [0x02, 0x00, 0x00, 0x00, 0x00];
        let _, _, _, ok_flag = wing::decode_grpc_lpm_slice(bad_flag[..], 0);
        sub.assert_false(ok_flag, "LPM flag with reserved bits must be rejected");

        // Flag 0xFE (reserved bits set)
        let bad_flag2: u8[5] = [0xFE, 0x00, 0x00, 0x00, 0x00];
        let _, _, _, ok_flag2 = wing::decode_grpc_lpm_slice(bad_flag2[..], 0);
        sub.assert_false(ok_flag2, "LPM flag 0xFE must be rejected");
    };
}

fn test_grpc_web_trailers_parsing(t: lit::T&) {
    t.run("GRPC-SEC-05: Valid gRPC-Web Trailers Parsing") { sub =>
        let trailer_raw = "grpc-status: 0\r\ngrpc-message: OK\r\n";
        var status = wing::GrpcStatusCode.Internal;
        var msg: u8[..256] = [];
        let ok = wing::parse_grpc_web_trailers(trailer_raw, status, msg);
        sub.assert_true(ok, "parsing valid gRPC-Web trailers succeeds");
        sub.assert_eq(status, wing::GrpcStatusCode.Ok, "grpc-status is Ok");
    };

    t.run("GRPC-SEC-06: Error Status and Non-Zero Error Code") { sub =>
        let trailer_raw = "grpc-status: 14\r\ngrpc-message: Service Unavailable\r\n";
        var status = wing::GrpcStatusCode.Ok;
        var msg: u8[..256] = [];
        let ok = wing::parse_grpc_web_trailers(trailer_raw, status, msg);
        sub.assert_true(ok, "parsing status 14 succeeds");
        sub.assert_eq(status, wing::GrpcStatusCode.Unavailable, "status mapped to Unavailable");
    };
}

fn main() {
    var runner = lit::new_runner("gRPC Binary Framing & Length Overflow Security Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. 32-bit LPM Length Overflows & Flag Invariants", test_grpc_lpm_integer_overflows);
    lit::run_case(runner, "2. gRPC-Web Trailers Status Parsing", test_grpc_web_trailers_parsing);

    let ok = lit::finish(runner);
    assert(ok);
}
