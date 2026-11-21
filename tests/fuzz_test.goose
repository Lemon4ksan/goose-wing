// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Native OSS-Fuzz Protocol Harness & Mutation Engine Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";
import fuzz.oss_fuzz;

// ----------------------------------------------------------------------------
// 1. FuzzedDataProvider & libFuzzer Mutator Invariants
// ----------------------------------------------------------------------------
fn test_oss_fuzz_fuzzed_data_provider_and_mutator(t: lit::T&) {
    t.run("FUZZ-ENGINE-01: FuzzedDataProvider deterministic consumption & bounds") { sub =>
        let raw: u8[16] = [
            0x01, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE,
            0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ];
        var fdp = new_fdp(raw[..]);
        sub.assert_eq(fdp_remaining(fdp), 16, "initial remaining is 16");
        sub.assert_true(fdp_consume_bool(fdp), "0x01 consumes as true");
        sub.assert_eq(fdp_consume_u16(fdp), 0x1234, "consume_u16 reads 0x1234");
        sub.assert_eq(fdp_consume_u32(fdp), 0x56789ABC, "consume_u32 reads 0x56789ABC");
        let ranged = fdp_consume_u64_in_range(fdp, 100, 200);
        sub.assert_true(ranged >= 100 && ranged <= 200, "consume_u64_in_range stays within [100..200]");
        let tail = fdp_consume_remaining(fdp);
        sub.assert_eq(tail.len, 1, "1 byte remained for tail");
        sub.assert_eq(fdp_remaining(fdp), 0, "0 bytes remaining after consume_remaining");
        sub.assert_eq(fdp_consume_u8(fdp), 0, "exhausted FDP returns 0 without out-of-bounds read");
    };

    t.run("FUZZ-ENGINE-02: libFuzzer 8-operator mutation engine preserves buffer bounds") { sub =>
        var rng = new_fuzz_rng(0xCAFEBABE12345678);
        var buf: u8[..512] = [];
        buf.append("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n");

        for _ in 128 {
            libfuzzer_mutate_inplace(rng, buf);
            sub.assert_true(buf.len <= buf.cap, "mutated buffer never exceeds capacity");
        }
    };
}

// ----------------------------------------------------------------------------
// 2. 12 Protocol OSS-Fuzz Targets Corpus & Mutation Sweep
// ----------------------------------------------------------------------------
fn test_oss_fuzz_all_12_protocol_targets(t: lit::T&) {
    t.run("OSS-FUZZ-01: HTTP/1.1, HTTP/2 HPACK/Session, HTTP/3 QPACK/Conn (llhttp, nghttp2, nghttp3)") { sub =>
        var rng = new_fuzz_rng(0x1111222233334444);
        var buf: u8[..1024] = [];

        for i in 24 {
            let _ = buf.try_set(OSS_FUZZ_DICT[i]);
            fuzz_target_http1(buf[..]);
            fuzz_target_http2_hpack_and_frames(buf[..]);
            fuzz_target_http2_session(buf[..]);
            fuzz_target_http3_qpack(buf[..]);
            fuzz_target_http3_conn(buf[..]);

            for _ in 8 {
                libfuzzer_mutate_inplace(rng, buf);
                fuzz_target_http1(buf[..]);
                fuzz_target_http2_hpack_and_frames(buf[..]);
                fuzz_target_http2_session(buf[..]);
                fuzz_target_http3_qpack(buf[..]);
                fuzz_target_http3_conn(buf[..]);
            }
        }
        sub.assert_true(true, "HTTP/1.1, HTTP/2, and HTTP/3 fuzz targets survived 216 mutated corpus inputs");
    };

    t.run("OSS-FUZZ-02: QUIC Packets, Frames, ROB, Streams & Connection (ngtcp2 & quinn)") { sub =>
        var rng = new_fuzz_rng(0x5555666677778888);
        var buf: u8[..1024] = [];

        for i in 24 {
            let _ = buf.try_set(OSS_FUZZ_DICT[i]);
            fuzz_target_quic_packets_and_frames(buf[..]);
            fuzz_target_quic_rob_and_streams(buf[..]);
            fuzz_target_quic_conn(buf[..]);

            for _ in 8 {
                libfuzzer_mutate_inplace(rng, buf);
                fuzz_target_quic_packets_and_frames(buf[..]);
                fuzz_target_quic_rob_and_streams(buf[..]);
                fuzz_target_quic_conn(buf[..]);
            }
        }
        sub.assert_true(true, "QUIC packets, frames, ROB, streams & connection targets survived 216 mutated inputs");
    };

    t.run("OSS-FUZZ-03: TLS 1.3 Deframer/Handshake, X.509 ASN.1, WebSocket, gRPC, SFV, Cookie, URL & Compress") { sub =>
        var rng = new_fuzz_rng(0x9999AAAABBBBCCCC);
        var buf: u8[..1024] = [];

        for i in 24 {
            let _ = buf.try_set(OSS_FUZZ_DICT[i]);
            fuzz_target_tls13_deframer_and_handshake(buf[..]);
            fuzz_target_x509_asn1(buf[..]);
            fuzz_target_websocket_and_grpc(buf[..]);
            fuzz_target_url_cookie_sfv_compress(buf[..]);

            for _ in 8 {
                libfuzzer_mutate_inplace(rng, buf);
                fuzz_target_tls13_deframer_and_handshake(buf[..]);
                fuzz_target_x509_asn1(buf[..]);
                fuzz_target_websocket_and_grpc(buf[..]);
                fuzz_target_url_cookie_sfv_compress(buf[..]);
            }
        }
        let tid = parse_fuzz_target_id("all");
        oss_fuzz_run_target_id(tid, buf[..]);
        sub.assert_true(true, "TLS 1.3, X.509, WebSocket, gRPC, SFV, Cookie, URL & Compress targets survived 216 mutated inputs");
    };
}

fn main() {
    var runner = lit::new_runner("Native OSS-Fuzz Protocol Harness & Mutation Engine Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. FuzzedDataProvider & libFuzzer Mutator Invariants", test_oss_fuzz_fuzzed_data_provider_and_mutator);
    lit::run_case(runner, "2. 12 Protocol OSS-Fuzz Targets Corpus & Mutation Sweep", test_oss_fuzz_all_12_protocol_targets);

    let ok = lit::finish(runner);
    assert(ok);
}
