// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_pipe_buffer_reassembly() {
    var pipe = core::new_pipe_buffer();

    let chunks: const u8[:][5] = [
        "GET ",
        "/a",
        "pi/v1/",
        "stream",
        " HTTP/1",
    ];

    for c in chunks {
        let n, err = core::write(pipe, c);
        assert(err == core::IoError.None);
        assert(n == c.len);
    }

    assert(core::readable_len(pipe) == 25);
    var target: u8[64] = [0; 64];
    let n, err = core::read(pipe, target[..25]);
    assert(err == core::IoError.None);
    assert(n == 25);
    assert(target[..25] == "GET /api/v1/stream HTTP/1");
}

fn test_cork_buffer_streaming() {
    var cb = core::new_cork_buffer();
    assert(core::cork_is_empty(cb));

    let err = core::cork_write_exact(cb, "GET /api/v1/stream HTTP/1.1\r\n");
    assert(err == core::IoError.None);
    assert(core::cork_pending(cb) == 29);
    assert(core::cork_as_slice(cb) == "GET /api/v1/stream HTTP/1.1\r\n");
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
    test_pipe_buffer_reassembly();
    test_cork_buffer_streaming();
    test_ring_buffer_streaming();
    print("CHAOS_SLICER: DRAINED 25 BYTES OK");
}

// CHECK: CHAOS_SLICER: DRAINED 25 BYTES OK
