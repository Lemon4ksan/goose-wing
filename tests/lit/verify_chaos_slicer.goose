// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;

struct Socket {
    buffer: u8[..512] = [],
    is_open: bool = false,
}

struct SocketPool {
    sockets: Socket[8] = [
        Socket {}, Socket {}, Socket {}, Socket {},
        Socket {}, Socket {}, Socket {}, Socket {},
    ],
}

fn sock_send(pool: SocketPool&, id: i32, data: const u8[:]) -> i32 {
    for b in data {
        pool.sockets[id].buffer.push(b);
    }
    return data.len as! i32;
}

fn sock_recv(pool: SocketPool&, id: i32, out: u8[:], off: i64) -> i32 {
    let avail = pool.sockets[id].buffer.len - off;
    if avail <= 0 { return 0; }
    let count = if out.len < avail { out.len } else { avail };
    for i in count {
        out[i] = pool.sockets[id].buffer[off + i];
    }
    return count as! i32;
}

fn main() {
    var pool = SocketPool {};
    let cli: i32 = 1;
    let srv: i32 = 2;
    pool.sockets[cli].is_open = true;
    pool.sockets[srv].is_open = true;

    // Send chunks: "GET ", "/a", "pi/v1/", "stream", " HTTP/1"
    let s1 = sock_send(pool, srv, "GET ");
    assert(s1 == 4);
    let s2 = sock_send(pool, srv, "/a");
    assert(s2 == 2);
    let s3 = sock_send(pool, srv, "pi/v1/");
    assert(s3 == 6);
    let s4 = sock_send(pool, srv, "stream");
    assert(s4 == 6);
    let s5 = sock_send(pool, srv, " HTTP/1");
    assert(s5 == 7);

    var reassembled: u8[25] = [0; 25];
    var offset: i64 = 0;
    while offset < 25 {
        let chunk_len = 25 - offset;
        var tmp: u8[25] = [0; 25];
        let r = sock_recv(pool, srv, tmp[..chunk_len], offset);
        assert(r > 0);
        for i in r {
            reassembled[offset + i] = tmp[i];
        }
        offset += r;
    }

    assert(offset == 25);
    // "GET /api/v1/stream HTTP/1"
    assert(reassembled[0] == 71 && reassembled[1] == 69 && reassembled[2] == 84 && reassembled[3] == 32);
    assert(reassembled[4] == 47 && reassembled[5] == 97 && reassembled[6] == 112 && reassembled[7] == 105);
    assert(reassembled[23] == 47 && reassembled[24] == 49);

    print("CHAOS_SLICER: DRAINED 25 BYTES OK");
}

// CHECK: CHAOS_SLICER: DRAINED 25 BYTES OK
