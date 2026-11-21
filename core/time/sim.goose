// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic virtual clock and CSPRNG override layer for simulation testing (DST).
// When inactive (default), adds a single predicted branch before OS clock/entropy calls.
namespace core;

import std;
import os;
import core.math.arithmetic;
import core.math.random;

const SIM_RNG_DOMAIN_MIX: u64 = 0x517cc1b727220a95;

var g_sim_clock_active: bool   = false;
var g_sim_clock_ns:     i64    = 0;
var g_sim_rng_active:   bool   = false;
var g_sim_rng_epoch:    u64    = 0;
var g_sim_rng_state:    WyRand = WyRand { state: 0x9e3779b97f4a7c15 };

// Enables the deterministic virtual monotonic clock starting at `start_ns`.
fn sim_clock_enable(start_ns: i64) {
    g_sim_clock_ns = max(0, start_ns);
    g_sim_clock_active = true;
}

// Disables the deterministic virtual clock and restores live OS `clock_ns()`.
fn sim_clock_disable() {
    g_sim_clock_active = false;
}

// Reports whether the deterministic virtual clock is currently active.
inline fn sim_clock_is_active() -> bool {
    return g_sim_clock_active;
}

// Sets the deterministic virtual clock directly to `now_ns`.
fn sim_clock_set(now_ns: i64) {
    g_sim_clock_ns = max(0, now_ns);
}

// Advances the deterministic virtual clock forward by `delta_ns` nanoseconds.
fn sim_clock_advance(delta_ns: i64) -> i64 {
    if delta_ns > 0 {
        g_sim_clock_ns = add_sat_i64(g_sim_clock_ns, delta_ns);
    }
    return g_sim_clock_ns;
}

// Returns virtual time in nanoseconds when simulation mode is enabled, or OS `clock_ns()`.
inline fn sim_now_ns() -> i64 {
    if g_sim_clock_active {
        return g_sim_clock_ns;
    }
    return clock_ns();
}

// Enables deterministic simulation entropy derived solely from `seed`.
fn sim_rng_enable(seed: u64) {
    var sm = seed ^ SIM_RNG_DOMAIN_MIX;
    let mixed = splitmix64(sm);
    g_sim_rng_state = new_wyrand(mixed);
    g_sim_rng_epoch = add_sat_u64(g_sim_rng_epoch, 1);
    g_sim_rng_active = true;
}

// Disables deterministic simulation entropy and restores OS CSPRNG calls.
fn sim_rng_disable() {
    g_sim_rng_active = false;
}

// Reports whether deterministic simulation entropy is currently active.
inline fn sim_rng_is_active() -> bool {
    return g_sim_rng_active;
}

// Returns the monotonic activation epoch incremented on every `sim_rng_enable` call.
inline fn sim_rng_epoch() -> u64 {
    return g_sim_rng_epoch;
}

// Draws the next 64-bit deterministic word from the active simulation PRNG stream.
inline fn sim_rng_next_u64() -> u64 {
    return next_u64(g_sim_rng_state);
}

// Fills `dst` with deterministic pseudo-random bytes when simulation entropy is active.
// Returns `false` without mutating `dst` when simulation entropy is disabled.
fn sim_rng_fill(dst: u8[:]) -> bool {
    guard g_sim_rng_active else { return false; }
    var word: u64 = 0;
    for i in dst.len {
        if (i & 7) == 0 {
            word = next_u64(g_sim_rng_state);
        }
        dst[i] = (word & 0xFF) as u8;
        word = word >> 8;
    }
    return true;
}

// Draws a 64-bit entropy seed from the simulation PRNG when active, or `sim_now_ns()`.
inline fn sim_entropy_u64() -> u64 {
    if g_sim_rng_active {
        return next_u64(g_sim_rng_state);
    }
    return sim_now_ns() as u64;
}
