// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-heap O(1) singly-linked free-list over a caller-owned `next: i32[:]` slot array.
namespace core;

import std;

struct FreeIndexList {
    head:   i32 = -1,
    active: i32 = 0,
}

// Initializes `next[0..len]` into a singly-linked free-list (`0 -> 1 -> ... -> -1`).
fn free_list_init(fl: FreeIndexList&, next: i32[:]) {
    let n = next.len;
    if n == 0 {
        fl.head = -1;
        fl.active = 0;
        return;
    }
    var i: i64 = 0;
    while i < n {
        let nxt = add_sat_i64(i, 1);
        next[i] = if nxt < n { nxt as i32 } else { -1 };
        i = nxt;
    }
    fl.head = 0;
    fl.active = 0;
}

// Pops a free slot index in O(1) time. Returns `(-1, false)` when exhausted.
//
// Example:
//   fl = { head: 0, active: 0 }, next = [1, -1] -> returns (0, true), fl = { head: 1, active: 1 }
fn free_list_alloc(fl: FreeIndexList&, next: i32[:]) -> i32, bool {
    let idx = fl.head;
    guard idx >= 0 && idx < next.len else { return -1, false; }
    fl.head = next[idx];
    next[idx] = -1;
    fl.active = add_sat_i64(fl.active, 1) as i32;
    return idx, true;
}

// Pushes `idx` back onto the free-list in O(1) time. Returns false if out of bounds.
//
// Example:
//   fl = { head: 1, active: 1 }, free_list_free(fl, next, 0) -> true, fl = { head: 0, active: 0 }
fn free_list_free(fl: FreeIndexList&, next: i32[:], idx: i32) -> bool {
    guard idx >= 0 && idx < next.len else { return false; }
    next[idx] = fl.head;
    fl.head = idx;
    if fl.active > 0 {
        fl.active = sub_sat_i64(fl.active, 1) as i32;
    }
    return true;
}
