// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// net/tick_timer.goose
// 1-byte tick wheel connection timeout sweeper based on uSockets loop.c.
// Uses an 8-bit modular tick counter updated once per second instead of timer heaps.
// Uses an 8-bit modular tick counter (modulo 240) updated every 1 second:
// - Arming a timeout for D seconds costs 1 byte: slot_timeout = (current_tick + D) % 240.
// - Disarming costs 1 byte write: slot_timeout = 255.
// - Sweeping thousands of sockets costs 1 CPU instruction per socket: if slot_timeout == current_tick.
namespace wing;

import std;

const TICK_TIMER_DISARMED: u8 = 255;
const TICK_TIMER_MODULO:   u8 = 240;

struct TickTimerWheel {
    current_tick:     u8  = 0,
    prev_tick:        u8  = 0,
    last_elapsed:     u32 = 0,
    idle_timeout_sec: u8  = 10,
}

fn new_tick_timer_wheel(idle_timeout_sec: u8 = 10) -> TickTimerWheel {
    return TickTimerWheel {
        current_tick:     0,
        prev_tick:        0,
        last_elapsed:     0,
        idle_timeout_sec: idle_timeout_sec,
    };
}

inline fn clamp_tick_delta(d: u8) -> u8 {
    if d >= TICK_TIMER_MODULO {
        return TICK_TIMER_MODULO - 1;
    }
    if d == 0 {
        return 1;
    }
    return d;
}

// Arms a connection slot timeout for delay_sec seconds.
inline fn tick_timer_arm(wheel: const TickTimerWheel&, delay_sec: u8 = 0) -> u8 {
    let raw = if delay_sec > 0 { delay_sec } else { wheel.idle_timeout_sec };
    let d:   u32 = clamp_tick_delta(raw);
    let cur: u32 = wheel.current_tick;
    let m:   u32 = TICK_TIMER_MODULO;
    return ((cur + d) % m) as u8;
}

// Disarms a connection slot timeout.
inline fn tick_timer_disarm() -> u8 {
    return TICK_TIMER_DISARMED;
}

// Advances the tick counter by elapsed_seconds.
fn tick_timer_advance(wheel: TickTimerWheel&, elapsed_seconds: u32 = 1) -> u8 {
    wheel.prev_tick = wheel.current_tick;
    wheel.last_elapsed = elapsed_seconds;
    let cur: u64 = wheel.current_tick;
    let el:  u64 = elapsed_seconds;
    let m:   u64 = TICK_TIMER_MODULO;
    wheel.current_tick = ((cur + el) % m) as u8;
    return wheel.current_tick;
}

inline fn is_slot_in_elapsed_range(slot: u8, prev: u8, elapsed: u32) -> bool {
    let m = TICK_TIMER_MODULO as u32;
    guard elapsed < m else { return true; }
    let s = slot as u32;
    let p = prev as u32;
    let raw = s + m - p;
    let dist = if raw >= m { raw - m } else { raw };
    return dist > 0 && dist <= elapsed;
}

// Checks if an armed slot has reached its timeout.
inline fn tick_timer_is_expired(wheel: const TickTimerWheel&, slot_timeout: u8) -> bool {
    if slot_timeout == TICK_TIMER_DISARMED { return false; }
    return is_slot_in_elapsed_range(slot_timeout, wheel.prev_tick, wheel.last_elapsed);
}
