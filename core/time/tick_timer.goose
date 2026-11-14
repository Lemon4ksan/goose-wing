// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// 1-byte modular tick wheel connection timeout sweeper (modulo 240, uSockets loop.c pattern).
namespace core;

import std;
import core.math;

const TICK_TIMER_DISARMED:  u8 = 255;
const TICK_TIMER_MODULO:    u8 = 240;
const TICK_TIMER_MAX_DELTA: u8 = 239;

struct TickTimerWheel {
    current_tick:     u8  = 0,
    prev_tick:        u8  = 0,
    last_elapsed:     u32 = 0,
    idle_timeout_sec: u8  = 10,
}

inline fn clamp_tick_delta(d: u8) -> u8 {
    return min(max(d, 1), TICK_TIMER_MAX_DELTA);
}

// Arms a connection slot timeout for `delay_sec` seconds (0 uses `wheel.idle_timeout_sec`).
inline fn tick_timer_arm(wheel: const TickTimerWheel&, delay_sec: u8 = 0) -> u8 {
    let raw = if delay_sec > 0 { delay_sec } else { wheel.idle_timeout_sec };
    let d:   u64 = clamp_tick_delta(raw);
    let cur: u64 = wheel.current_tick;
    let m:   u64 = TICK_TIMER_MODULO;
    let sum = add_sat_u64(cur, d);
    return (if sum >= m { sub_sat_u64(sum, m) } else { sum }) as u8;
}

// Disarms a connection slot timeout.
inline fn tick_timer_disarm() -> u8 {
    return TICK_TIMER_DISARMED;
}

// Advances the tick counter by `elapsed_seconds`.
fn tick_timer_advance(wheel: TickTimerWheel&, elapsed_seconds: u32 = 1) -> u8 {
    wheel.prev_tick = wheel.current_tick;
    wheel.last_elapsed = elapsed_seconds;
    let cur: i64 = wheel.current_tick;
    let el:  i64 = elapsed_seconds;
    let m:   i64 = TICK_TIMER_MODULO;
    wheel.current_tick = rem_euclid_i64(add_sat_i64(cur, el), m) as u8;
    return wheel.current_tick;
}

inline fn is_slot_in_elapsed_range(slot: u8, prev: u8, elapsed: u32) -> bool {
    let m = TICK_TIMER_MODULO as u64;
    guard elapsed < m else { return true; }
    let s = slot as u64;
    let p = prev as u64;
    let raw = sub_sat_u64(add_sat_u64(s, m), p);
    let dist = if raw >= m { sub_sat_u64(raw, m) } else { raw };
    return dist > 0 && dist <= elapsed;
}

// Checks if an armed slot has reached its timeout.
inline fn tick_timer_is_expired(wheel: const TickTimerWheel&, slot_timeout: u8) -> bool {
    if slot_timeout == TICK_TIMER_DISARMED {
        return false;
    }
    return is_slot_in_elapsed_range(slot_timeout, wheel.prev_tick, wheel.last_elapsed);
}
