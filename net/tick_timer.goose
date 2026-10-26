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
const TICK_TIMER_MODULO: u8 = 240;

struct TickTimerWheel {
    current_tick: u8 = 0,
    idle_timeout_sec: u8 = 10,
}

fn new_tick_timer_wheel(idle_timeout_sec: u8 = 10) -> TickTimerWheel {
    return TickTimerWheel {
        current_tick: 0,
        idle_timeout_sec: idle_timeout_sec,
    };
}

// Arms a connection slot timeout for delay_sec seconds.
inline fn tick_timer_arm(wheel: const TickTimerWheel&, delay_sec: u8 = 0) -> u8 {
    let d = if delay_sec > 0 { delay_sec } else { wheel.idle_timeout_sec };
    return (wheel.current_tick + d) % TICK_TIMER_MODULO;
}


// Disarms a connection slot timeout.
inline fn tick_timer_disarm() -> u8 {
    return TICK_TIMER_DISARMED;
}

// Advances the tick counter by elapsed_seconds.
fn tick_timer_advance(wheel: TickTimerWheel&, elapsed_seconds: u32 = 1) -> u8 {
    wheel.current_tick = ((wheel.current_tick + elapsed_seconds) % TICK_TIMER_MODULO) as u8;
    return wheel.current_tick;
}




// Checks if an armed slot has reached its timeout.
inline fn tick_timer_is_expired(wheel: const TickTimerWheel&, slot_timeout: u8) -> bool {
    if slot_timeout == TICK_TIMER_DISARMED { return false; }
    return slot_timeout == wheel.current_tick;
}
