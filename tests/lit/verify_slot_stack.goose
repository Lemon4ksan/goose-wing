// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_slot_stack.goose
// Verification of O(1) FreeSlotStack for reactor connection slots.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    var stack = wing::FreeSlotStack { .. };
    wing::init_free_slots(stack, 4);

    // Initial pop order should be deterministic 0, 1, 2, 3
    let s0 = wing::pop_free_slot(stack);
    let s1 = wing::pop_free_slot(stack);
    let s2 = wing::pop_free_slot(stack);
    let s3 = wing::pop_free_slot(stack);
    let s4 = wing::pop_free_slot(stack);

    assert(s0 == 0);
    assert(s1 == 1);
    assert(s2 == 2);
    assert(s3 == 3);
    assert(s4 == -1); // Empty stack returns -1

    // Push slot 2 back, pop returns 2
    assert(wing::push_free_slot(stack, 2));
    assert(wing::pop_free_slot(stack) == 2);
    assert(wing::pop_free_slot(stack) == -1);

    // Out of bounds rejection
    assert(!wing::push_free_slot(stack, -1));
    assert(!wing::push_free_slot(stack, 2048));

    print("FREE_SLOT_STACK: OK");
}

// CHECK: FREE_SLOT_STACK: OK
