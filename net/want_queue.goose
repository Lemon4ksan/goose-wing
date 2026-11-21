// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-allocation dual-slice waiter queue for connection pools.
// Separates consumer (head, head_pos) and producer (tail) cache lines to avoid false sharing.
namespace net;

import std;
import core from "..";
import .internal;

struct WantConn {
    req_id:           u64  = 0,
    ready:            bool = false,
    cancelled:        bool = false,
    assigned_conn_id: i32  = -1,
    reused:           bool = false,
    err_code:         i32  = 0,
}

// Zero-reallocation dual-slice queue avoiding shifts during frequent push/pop operations.
struct WantQueue {
    head:          WantConn[..32] = [],
    head_pos:      i64            = 0,
    _pad_consumer: u8[56]         = [0; 56],
    tail:          WantConn[..32] = [],
}

fn queue_len(q: const WantQueue&) -> i64 {
    let head_remaining = core::ct_max_i64(0, core::sub_sat_i64(q.head.len, q.head_pos));
    return core::add_sat_i64(head_remaining, q.tail.len);
}

fn is_queue_empty(q: const WantQueue&) -> bool {
    return q.queue_len() == 0;
}

// Appends a connection requirement to the tail slice.
fn push_want(q: WantQueue&, item: WantConn) -> bool {
    if q.tail.try_push(item) {
        return true;
    }
    net_internal::compact_want_queue(q);
    return q.tail.try_push(item);
}

// Pops the front item from the queue, promoting tail to head when head is exhausted.
fn pop_want(q: WantQueue&) -> WantConn, bool {
    while q.head_pos < q.head.len {
        let item = q.head[q.head_pos];
        q.head_pos = core::add_sat_i64(q.head_pos, 1);
        if !item.cancelled {
            return item, true;
        }
    }

    if q.tail.len > 0 {
        q.head.clear();
        for &t_item in q.tail {
            q.head.push(copy(t_item));
        }
        q.head_pos = 0;
        q.tail.clear();

        while q.head_pos < q.head.len {
            let item = q.head[q.head_pos];
            q.head_pos = core::add_sat_i64(q.head_pos, 1);
            if !item.cancelled {
                return item, true;
            }
        }
    }

    return WantConn { .. }, false;
}

// Cancels a waiter by request ID and compacts cancelled entries.
fn cancel_want(q: WantQueue&, req_id: u64) -> bool {
    for &item in q.head[q.head_pos..] {
        if item.req_id == req_id && !item.cancelled {
            item.cancelled = true;
            net_internal::compact_want_queue(q);
            return true;
        }
    }
    for &item in q.tail {
        if item.req_id == req_id && !item.cancelled {
            item.cancelled = true;
            net_internal::compact_want_queue(q);
            return true;
        }
    }
    return false;
}
