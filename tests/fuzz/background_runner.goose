// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Standalone Native OSS-Fuzz Background Worker Binary.
// Compiles with `goose build --cc gcc -O2 -o .lit/cache/fuzz/fuzz_runner.exe tests/fuzz/background_runner.goose`
// and executes continuous libFuzzer mutational fuzzing across all 12 protocol targets and
// the 2,430 real OSS-Fuzz binary corpus files in `vendor/*/fuzz/corpus`.

import std;
import os;
import core from "../..";
import wing from "../..";
import .oss_fuzz;

fn parse_u64_or_default(raw: const u8[:], fallback: u64) -> u64 {
    let val, ok = core::parse_u64_dec(raw);
    return if ok { val } else { fallback };
}

fn record_state_and_evolve(
    sig:          u64,
    mut_buf:      const u8[..4096]&,
    seen:         u64[256]&,
    evolved_pool: u8[..1024][..16]&,
    new_states:   u64&,
) {
    let slot = (sig & 0xFF) as i64;
    if seen[slot] == sig { return; }
    seen[slot] = sig;
    new_states = core::add_sat_u64(new_states, 1);

    var entry: u8[..1024] = [];
    let take = min(mut_buf.len, entry.cap);
    entry.append(mut_buf[..take]);
    if evolved_pool.len < evolved_pool.cap {
        evolved_pool.push(entry);
    } else {
        let ev_idx = (new_states & 0x0F) as i64;
        evolved_pool[ev_idx] = entry;
    }
}

fn reset_mut_buf_for_trial(
    rng:          FuzzRng&,
    orig_buf:     const u8[..4096]&,
    evolved_pool: const u8[..1024][..16]&,
    mut_buf:      u8[..4096]&,
) {
    if evolved_pool.len > 0 && (fuzz_rng_next(rng) & 3) == 0 {
        let idx = fuzz_rng_bound(rng, evolved_pool.len as u64) as i64;
        let _ = mut_buf.try_set(evolved_pool[idx][..]);
        return;
    }
    let _ = mut_buf.try_set(orig_buf[..]);
}

fn run_seed_and_mutations(
    target_id:      i32,
    iters_per_seed: u64,
    rng:            FuzzRng&,
    orig_buf:       const u8[..4096]&,
    mut_buf:        u8[..4096]&,
    seen:           u64[256]&,
    evolved_pool:   u8[..1024][..16]&,
    new_states:     u64&,
) -> u64 {
    let _ = mut_buf.try_set(orig_buf[..]);
    let base_sig = oss_fuzz_run_target_id(target_id, mut_buf[..]);
    record_state_and_evolve(base_sig, mut_buf, seen, evolved_pool, new_states);
    var execs: u64 = 1;

    var i: u64 = 0;
    while i < iters_per_seed {
        i = core::add_sat_u64(i, 1);
        reset_mut_buf_for_trial(rng, orig_buf, evolved_pool, mut_buf);
        libfuzzer_mutate_inplace(rng, mut_buf);
        let sig = oss_fuzz_run_target_id(target_id, mut_buf[..]);
        record_state_and_evolve(sig, mut_buf, seen, evolved_pool, new_states);
        execs = core::add_sat_u64(execs, 1);
    }
    return execs;
}

fn main() {
    let a = args();
    let target_name = if a.len >= 2 { a[1] } else { "all" };
    let target_id = parse_fuzz_target_id(target_name);
    let iters_per_seed = if a.len >= 3 { parse_u64_or_default(a[2], 64) } else { 64 };
    let base_seed = if a.len >= 4 { parse_u64_or_default(a[3], 0xCAFEBABE12345678) } else { 0xCAFEBABE12345678 };

    var rng = new_fuzz_rng(base_seed);
    var raw_file:     u8[>..]          = [];
    var orig_buf:     u8[..4096]       = [];
    var mut_buf:      u8[..4096]       = [];
    var seen:         u64[256]         = [0; 256];
    var evolved_pool: u8[..1024][..16] = [];
    var total_execs:  u64              = 0;
    var total_seeds:  u64              = 0;
    var new_states:   u64              = 0;

    if a.len >= 5 {
        var idx: i64 = 4;
        while idx < a.len {
            let path = a[idx];
            idx = core::add_sat_i64(idx, 1);
            raw_file.clear();
            if read_file(path, raw_file) {
                total_seeds = core::add_sat_u64(total_seeds, 1);
                let take = min(raw_file.len, orig_buf.cap);
                orig_buf.clear();
                orig_buf.append(raw_file[..take]);
                let ran = run_seed_and_mutations(
                    target_id,
                    iters_per_seed,
                    rng,
                    orig_buf,
                    mut_buf,
                    seen,
                    evolved_pool,
                    new_states,
                );
                total_execs = core::add_sat_u64(total_execs, ran);
            }
        }
    } else {
        for i in 24 {
            total_seeds = core::add_sat_u64(total_seeds, 1);
            let _ = orig_buf.try_set(OSS_FUZZ_DICT[i]);
            let ran = run_seed_and_mutations(
                target_id,
                iters_per_seed,
                rng,
                orig_buf,
                mut_buf,
                seen,
                evolved_pool,
                new_states,
            );
            total_execs = core::add_sat_u64(total_execs, ran);
        }
    }

    print("OK EXECS: ", total_execs, " SEEDS: ", total_seeds, " NEW_STATES: ", new_states);
}
