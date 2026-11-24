// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// C-callable fuzzing and differential oracle entrypoints for libFuzzer and
// compiler SanitizerCoverage (`-fsanitize-coverage=trace-pc`) harnesses.
// Build C library via:
//   goose --standalone --header .lit/cache/fuzz/c_fuzz_entry.h -o .lit/cache/fuzz/c_fuzz_entry.c tests/fuzz/c_fuzz_entry.goose

import std;
import wing from "../..";
import .oss_fuzz;

// Returns the exact number of registered protocol fuzz targets (`0..count-1`).
export fn lit_fuzz_target_count() -> i32 {
    return FUZZ_TARGET_COUNT;
}

// Copies the canonical name of `target_id` into `dst` and returns bytes written (0 if invalid).
export fn lit_fuzz_target_name(target_id: i32, dst: u8[:]) -> i32 {
    guard target_id >= 0 && target_id < FUZZ_TARGET_COUNT && dst.len > 0 else {
        return 0;
    }
    let name = FUZZ_TARGET_NAMES[target_id as i64];
    let n = min(name.len, dst.len);
    for i in n {
        dst[i] = name[i];
    }
    return n as i32;
}

// Executes a single fuzz input slice against a specific protocol target (`0..count-1`)
// or fans out across all targets when `target_id < 0`.
// Returns a 64-bit state transition signature.
//
// Example:
//   target_id = 0, raw = "GET / HTTP/1.1\r\nHost: a\r\n\r\n"
//   returns: non-zero 64-bit state hash
export fn lit_fuzz_test_one(target_id: i32, raw: const u8[:]) -> u64 {
    let capped_len = max(0, min(raw.len, 16384));
    let payload = raw[..capped_len];
    if payload.len == 0 {
        return 0;
    }
    return oss_fuzz_run_target_id(target_id, payload);
}

fn main() {
    // Runtime initialization hook invoked once by C host `goose_init(argc, argv)`.
}
