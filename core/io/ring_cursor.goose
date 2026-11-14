// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Power-of-two circular index cursor (head/tail/mask) for lock-free and driver ring queues.
namespace core;

import std;
import core.math;

struct RingCursor {
    head: u64 = 0,
    tail: u64 = 0,
    mask: u64 = 63,
}

// Returns the number of occupied slots in `c`.
inline fn ring_cursor_len(c: const RingCursor&) -> u64 {
    return sub_sat_u64(c.head, c.tail);
}

// Returns the total power-of-two capacity (`mask + 1`) of `c`.
inline fn ring_cursor_cap(c: const RingCursor&) -> u64 {
    return add_sat_u64(c.mask, 1);
}

// Returns the number of free slots remaining in `c`.
inline fn ring_cursor_free(c: const RingCursor&) -> u64 {
    return sub_sat_u64(ring_cursor_cap(c), ring_cursor_len(c));
}

// Advances `c.head` by one slot if space is available and returns `(slot_idx, true)`.
//
// Example:
//   c = RingCursor { head: 0, tail: 0, mask: 63 } -> returns (0, true), c.head = 1
inline fn ring_cursor_push(c: RingCursor&) -> i64, bool {
    guard ring_cursor_free(c) > 0 else { return -1, false; }
    let idx = (c.head & c.mask) as i64;
    c.head = add_sat_u64(c.head, 1);
    return idx, true;
}

// Advances `c.tail` by one slot if non-empty and returns `(slot_idx, true)`.
//
// Example:
//   c = RingCursor { head: 1, tail: 0, mask: 63 } -> returns (0, true), c.tail = 1
inline fn ring_cursor_pop(c: RingCursor&) -> i64, bool {
    guard ring_cursor_len(c) > 0 else { return -1, false; }
    let idx = (c.tail & c.mask) as i64;
    c.tail = add_sat_u64(c.tail, 1);
    return idx, true;
}
