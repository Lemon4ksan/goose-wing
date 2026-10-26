// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Rich soft (assert_*) and hard (require_*) test assertions with detailed failure context.
namespace core;

import std;
import core.test.context;
import core.test.diff;

// Soft assertions (assert_*)

fn assert_true(t: T&, cond: bool, label: const u8[:] = "expected true") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if !cond {
        record_failure(t, "assert_true failed", label);
        return false;
    }
    return true;
}

fn assert_false(t: T&, cond: bool, label: const u8[:] = "expected false") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if cond {
        record_failure(t, "assert_false failed", label);
        return false;
    }
    return true;
}

fn assert_ok(t: T&, ok_cond: bool, label: const u8[:] = "expected operation ok == true") -> bool {
    return assert_true(t, ok_cond, label);
}

fn assert_eq<Val>(t: T&, got: Val, want: Val, label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if got != want {
        var det: u8[..512] = [];
        if label.len > 0 { format(det, label, "\n"); }
        format(det, "  got:  ", got, "\n  want: ", want);
        record_failure(t, "assert_eq mismatch", det[..]);
        return false;
    }
    return true;
}

fn assert_bytes_eq(t: T&, got: const u8[:], want: const u8[:], label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if got != want {
        var det: u8[..512] = [];
        if label.len > 0 { format(det, label, "\n"); }
        format_bytes_diff(det, got, want);
        record_failure(t, "assert_bytes_eq mismatch", det[..]);
        return false;
    }
    return true;
}

fn assert_struct_eq<Val>(t: T&, got: const Val&, want: const Val&, label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    var det: u8[..512] = [];
    if label.len > 0 { format(det, label, "\n"); }
    if diff_struct_fields(det, got, want) {
        record_failure(t, "assert_struct_eq field mismatch", det[..]);
        return false;
    }
    return true;
}

fn assert_ne<Val>(t: T&, got: Val, want: Val, label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if got == want {
        var det: u8[..512] = [];
        if label.len > 0 { format(det, label, ": "); }
        format(det, "both values equal ", got);
        record_failure(t, "assert_ne violated", det[..]);
        return false;
    }
    return true;
}

fn assert_gt<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if !(got > bound) {
        var det: u8[..256] = [];
        format(det, label, " expected ", got, " > ", bound);
        record_failure(t, "assert_gt failed", det[..]);
        return false;
    }
    return true;
}

fn assert_ge<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if !(got >= bound) {
        var det: u8[..256] = [];
        format(det, label, " expected ", got, " >= ", bound);
        record_failure(t, "assert_ge failed", det[..]);
        return false;
    }
    return true;
}

fn assert_lt<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if !(got < bound) {
        var det: u8[..256] = [];
        format(det, label, " expected ", got, " < ", bound);
        record_failure(t, "assert_lt failed", det[..]);
        return false;
    }
    return true;
}

fn assert_le<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if !(got <= bound) {
        var det: u8[..256] = [];
        format(det, label, " expected ", got, " <= ", bound);
        record_failure(t, "assert_le failed", det[..]);
        return false;
    }
    return true;
}

fn assert_in_delta(t: T&, got: f64, want: f64, delta: f64, label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    let diff = ::abs(got - want);
    if diff > delta {
        var det: u8[..256] = [];
        format(det, label, "\n  got: ", got, ", want: ", want, " (|diff|=", diff, " > ", delta, ")");
        record_failure(t, "assert_in_delta exceeded", det[..]);
        return false;
    }
    return true;
}

fn assert_contains(t: T&, haystack: const u8[:], needle: const u8[:], label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if find(haystack, needle) < 0 {
        var det: u8[..512] = [];
        format(det, label, "\n  haystack: \"", haystack, "\"\n  missing:  \"", needle, "\"");
        record_failure(t, "assert_contains failed", det[..]);
        return false;
    }
    return true;
}

fn assert_not_contains(t: T&, haystack: const u8[:], needle: const u8[:], label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if find(haystack, needle) >= 0 {
        var det: u8[..512] = [];
        format(det, label, "\n  haystack:  \"", haystack, "\"\n  forbidden: \"", needle, "\"");
        record_failure(t, "assert_not_contains failed", det[..]);
        return false;
    }
    return true;
}

// Asserts that two slices contain the same elements regardless of order (up to 256 elements).
fn assert_elements_match<Val>(t: T&, a: const Val[:], b: const Val[:], label: const u8[:] = "") -> bool {
    if t.aborted { return false; }
    t.assertions_count += 1;
    if a.len != b.len || b.len > 256 {
        var det: u8[..256] = [];
        format(det, label, " length mismatch: a.len=", a.len, ", b.len=", b.len);
        record_failure(t, "assert_elements_match failed", det[..]);
        return false;
    }
    var used: bool[..256] = [];
    for i in b.len { used.push(false); }

    for i in a.len {
        var found = false;
        for j in b.len {
            if !used[j] && a[i] == b[j] {
                used[j] = true;
                found = true;
                break;
            }
        }
        if !found {
            var det: u8[..256] = [];
            format(det, label, " element at a[", i, "] = ", a[i], " has no unmatched counterpart in b");
            record_failure(t, "assert_elements_match mismatch", det[..]);
            return false;
        }
    }
    return true;
}

// Hard assertions (require_*)

fn require_true(t: T&, cond: bool, label: const u8[:] = "required true") -> bool {
    if !assert_true(t, cond, label) {
        t.aborted = true;
        return false;
    }
    return true;
}

fn require_false(t: T&, cond: bool, label: const u8[:] = "required false") -> bool {
    if !assert_false(t, cond, label) {
        t.aborted = true;
        return false;
    }
    return true;
}

fn require_ok(t: T&, ok_cond: bool, label: const u8[:] = "required ok == true") -> bool {
    return require_true(t, ok_cond, label);
}

fn require_eq<Val>(t: T&, got: Val, want: Val, label: const u8[:] = "") -> bool {
    if !assert_eq(t, got, want, label) {
        t.aborted = true;
        return false;
    }
    return true;
}

fn require_bytes_eq(t: T&, got: const u8[:], want: const u8[:], label: const u8[:] = "") -> bool {
    if !assert_bytes_eq(t, got, want, label) {
        t.aborted = true;
        return false;
    }
    return true;
}

fn require_ne<Val>(t: T&, got: Val, want: Val, label: const u8[:] = "") -> bool {
    if !assert_ne(t, got, want, label) {
        t.aborted = true;
        return false;
    }
    return true;
}

fn require_gt<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    if !assert_gt(t, got, bound, label) {
        t.aborted = true;
        return false;
    }
    return true;
}

fn require_ge<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    if !assert_ge(t, got, bound, label) {
        t.aborted = true;
        return false;
    }
    return true;
}

fn require_lt<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    if !assert_lt(t, got, bound, label) {
        t.aborted = true;
        return false;
    }
    return true;
}

fn require_le<Val>(t: T&, got: Val, bound: Val, label: const u8[:] = "") -> bool {
    if !assert_le(t, got, bound, label) {
        t.aborted = true;
        return false;
    }
    return true;
}
