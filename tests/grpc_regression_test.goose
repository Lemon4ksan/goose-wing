// RUN: goose %s
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Regression test suite for gRPC framing, client, status and server dispatch bugs.
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn dummy_unary_handler(
    _handler_id: u16,
    _ctx:        wing::GrpcServerContext&,
    _req:        const u8[:],
    _res:        u8[>..]&,
) -> wing::GrpcStatus {
    return wing::grpc_ok();
}

fn test_grpc_status_regressions(t: lit::T&) {
    t.run("BUG-1: parse_grpc_status_code rejects non-numeric strings") { sub =>
        let code = wing::parse_grpc_status_code("UNAVAILABLE");
        sub.assert_false(code == 0, "non-numeric status string must not parse as OK (0)");
    };

    t.run("BUG-6: build_grpc_status_details rejects negative code") { sub =>
        var dst: u8[64] = [0; 64];
        let n, ok = wing::build_grpc_status_details(-1, "negative status", dst[..]);
        sub.assert_false(ok, "negative code must be safely rejected");
        sub.assert_false(n < 0, "returned written length must be 0");
    };

    t.run("BUG-4: decode_grpc_message bounded buffer safety") { sub =>
        var long_msg:    u8[300]   = ['a'; 300];
        var out_bounded: u8[..256] = [];
        wing::decode_grpc_message(long_msg[..], out_bounded);
        sub.assert_eq(out_bounded.len, 256, "decode_grpc_message must not exceed out.cap (256)");
    };

    t.run("BUG-5: encode_grpc_message bounded buffer safety") { sub =>
        var raw_msg:     u8[500]   = ['%'; 500];
        var out_bounded: u8[..256] = [];
        wing::encode_grpc_message(raw_msg[..], out_bounded, out_bounded.cap);
        sub.assert_true(out_bounded.len <= 256, "encode_grpc_message must not exceed out.cap (256)");
    };
}
fn test_grpc_server_and_client_regressions(t: lit::T&) {
    t.run("BUG-2: build_grpc_request_headers with max service and method") { sub =>
        var s: u8[128] = ['s'; 128];
        var m: u8[128] = ['m'; 128];
        var cfg = wing::GrpcCallConfig { .. };
        let _ = cfg.service.try_set(s[..]);
        let _ = cfg.method.try_set(m[..]);
        var headers = wing::HeaderMap { .. };
        wing::build_grpc_request_headers(cfg, "example.com", "https", headers);
        let path = wing::get_header(headers, ":path");
        sub.assert_eq(path.len, 258, "path must not be truncated to 256 bytes");
    };

    t.run("BUG-3: register_method with 64-byte service and 64-byte method") { sub =>
        var d = wing::new_grpc_server_dispatcher();
        var s: u8[64] = ['s'; 64];
        var m: u8[64] = ['m'; 64];
        let ok_reg = wing::register_unary(d, s[..], m[..], 1);
        sub.assert_true(ok_reg, "register_unary for 64-byte service and method must succeed");

        var path_buf: u8[..160] = [];
        path_buf.push('/');
        path_buf.append(s[..]);
        path_buf.push('/');
        path_buf.append(m[..]);
        let idx = wing::find_method(d, path_buf[..]);
        sub.assert_false(idx < 0, "registered method must be found by find_method");
    };

    t.run("BUG-7: Unary 0-byte body rejected with InvalidArgument") { sub =>
        var d = wing::new_grpc_server_dispatcher();
        let _ = wing::register_unary(d, "test.Service", "EmptyUnary", 1);
        var req = wing::new_request("POST", "/test.Service/EmptyUnary");
        wing::set_header(req, "content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
        // 0-byte body (no 5-byte LPM header)
        var res = wing::Response { .. };
        let handled = wing::dispatch_grpc_unary(d, req, 1000, res, dummy_unary_handler);
        sub.assert_true(handled, "handled");
        let st = wing::header(res, rfc::HEADER_GRPC_STATUS);
        sub.assert_bytes_eq(st, "3", "0-byte body must return InvalidArgument (3)");
    };

    t.run("BUG-8: Protobuf 64-bit tag narrowing & field 0 rejection") { sub =>
        let hi_varint: u8[7] = [0x88, 0x80, 0x80, 0x80, 0x80, 0x01, 0x2A];
        let _, ok_v1 = wing::pb_read_varint_field(hi_varint[..], 1);
        sub.assert_false(ok_v1, "64-bit tag overflowing u32 must not wrap to field 1");

        let zero_fnum: u8[4] = [0x00, 0x01, 0x08, 0x2A];
        let _, ok_v0 = wing::pb_read_varint_field(zero_fnum[..], 1);
        sub.assert_false(ok_v0, "field number 0 must be rejected");
    };

    t.run("BUG-9: gRPC-Web trailer CRLF injection & multi-chunk Base64") { sub =>
        var ctx = wing::GrpcServerContext { .. };
        sub.assert_false(wing::add_response_trailer(ctx, "x-inj", "v\r\ngrpc-status: 0"), "CRLF rejected");
        sub.assert_false(wing::add_response_trailer(ctx, "grpc-status", "0"), "reserved key rejected");

        var f1: u8[>..] = [];
        wing::encode_grpc_lpm("", f1, false);
        var b64_1: u8[>..] = [];
        wing::encode_grpc_web_text(f1[..], b64_1);
        var f2: u8[>..] = [];
        wing::encode_grpc_web_trailers(wing::GrpcStatusCode.Ok, "ok", f2);
        var b64_2: u8[>..] = [];
        wing::encode_grpc_web_text(f2[..], b64_2);
        var cat: u8[>..] = [];
        cat.append(b64_1[..]);
        cat.append(b64_2[..]);
        var dec: u8[>..] = [];
        sub.assert_true(wing::decode_grpc_web_text(cat[..], dec), "multi-chunk Base64 decoded");
    };

    t.run("BUG-10: Timeout >8 digits & 0S deadline & status HTTP fallback") { sub =>
        var to_buf: u8[..32] = [];
        wing::encode_grpc_timeout(100000500, to_buf);
        let _, ok_to = wing::parse_grpc_timeout(to_buf[..]);
        sub.assert_true(ok_to, "encoded timeout must be <= 8 digits and valid");

        var hdrs = wing::HeaderMap { .. };
        hdrs.status_code = 503;
        let _ = wing::append_header(hdrs, rfc::HEADER_GRPC_STATUS, "0");
        var trs = wing::HeaderMap { .. };
        var msg: u8[..256] = [];
        var st = wing::GrpcStatusCode.Ok;
        let _ = wing::extract_grpc_status(hdrs, trs, st, msg);
        sub.assert_eq(st, wing::GrpcStatusCode.Unavailable, "HTTP 503 overrides grpc-status: 0");
    };
}

fn main() {
    var runner = lit::new_runner("gRPC Protocol Bug Regressions Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. Status & Buffer Bounds Regressions", test_grpc_status_regressions);
    lit::run_case(runner, "2. Server & Client Regressions", test_grpc_server_and_client_regressions);

    let ok = lit::finish(runner);
    assert(ok);
}
