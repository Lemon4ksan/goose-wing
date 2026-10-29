// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_slice_stream_reassembly() {
    var out_buf: u8[64] = [0; 64];
    var w = core::new_slice_writer(out_buf[..]);

    let chunks: const u8[:][5] = [
        "GET ",
        "/a",
        "pi/v1/",
        "stream",
        " HTTP/1",
    ];

    for c in chunks {
        let n, err = core::write(w, c);
        assert(err == core::IoError.None);
        assert(n == c.len);
    }

    assert(core::written(w) == 25);
    let reassembled = core::as_written_slice(w);
    assert(reassembled.len == 25);
    assert(reassembled == "GET /api/v1/stream HTTP/1");

    var r = core::new_slice_reader(reassembled);
    let m, err_m = core::read_slice(r, 4);
    assert(err_m == core::IoError.None);
    assert(m == "GET ");

    let p, err_p = core::read_slice(r, 14);
    assert(err_p == core::IoError.None);
    assert(p == "/api/v1/stream");

    let v, err_v = core::read_slice(r, 7);
    assert(err_v == core::IoError.None);
    assert(v == " HTTP/1");
    assert(core::is_eof(r));
}

fn test_limit_reader_bounds() {
    let wire_data = "GET /api/v1/stream HTTP/1.1\r\n";
    var lr = core::new_limit_reader(wire_data, 14);
    var tmp: u8[14] = [0; 14];
    let n, err = core::read(lr, tmp[..]);
    assert(err == core::IoError.None);
    assert(n == 14);
    assert(tmp[..] == "GET /api/v1/st");

    var extra: u8[1] = [0; 1];
    let n2, err2 = core::read(lr, extra[..]);
    assert(n2 == 0);
    assert(err2 == core::IoError.LimitExceeded);
}

fn test_ring_buffer_streaming() {
    var rb = core::new_ring_buffer();
    assert(core::is_empty(rb));

    let w1, err1 = core::write(rb, "GET /api/v1/");
    assert(err1 == core::IoError.None && w1 == 12);

    var tmp1: u8[12] = [0; 12];
    let r1, err_r1 = core::read(rb, tmp1[..]);
    assert(err_r1 == core::IoError.None && r1 == 12);
    assert(tmp1[..] == "GET /api/v1/");

    let w2, err2 = core::write(rb, "stream HTTP/1");
    assert(err2 == core::IoError.None && w2 == 13);

    var tmp2: u8[13] = [0; 13];
    let r2, err_r2 = core::read(rb, tmp2[..]);
    assert(err_r2 == core::IoError.None && r2 == 13);
    assert(tmp2[..] == "stream HTTP/1");
    assert(core::is_empty(rb));
}

fn main() {
    test_slice_stream_reassembly();
    test_limit_reader_bounds();
    test_ring_buffer_streaming();
    print("CHAOS_SLICER: DRAINED 25 BYTES OK");
}

// CHECK: CHAOS_SLICER: DRAINED 25 BYTES OK
