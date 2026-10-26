// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// High-resolution monotonic clock, Instant, Stopwatch, and Deadline.
namespace core;

import std;
import os;

// ---- monotonic primitives: stopwatch & deadline ---------------------------

// High-resolution monotonic instant (CLOCK_MONOTONIC / performance counter in nanoseconds).
struct MonotonicInstant {
    nanos: u64 = 0,
}

fn monotonic_now() -> MonotonicInstant {
    let raw_ns = clock_ns();
    return MonotonicInstant { nanos: if raw_ns > 0 { raw_ns as u64 } else { 0 } };
}

fn new_monotonic_instant(nanos_val: u64) -> MonotonicInstant {
    return MonotonicInstant { nanos: nanos_val };
}

fn as_nanos(inst: MonotonicInstant) -> u64 {
    return inst.nanos;
}

fn duration_since(now_inst: MonotonicInstant, anchor: MonotonicInstant) -> Duration {
    if now_inst.nanos <= anchor.nanos {
        return Duration { nanos: 0 };
    }
    let diff = now_inst.nanos - anchor.nanos;
    let max_i64 = 9223372036854775807 as u64;
    let clamped = if diff > max_i64 { max_i64 } else { diff };
    return Duration { nanos: clamped as i64 };
}

// High-resolution monotonic stopwatch backed by the system performance counter.
struct Stopwatch {
    start_ns: i64 = 0,
}

fn stopwatch() -> Stopwatch {
    return Stopwatch { start_ns: clock_ns() };
}

fn elapsed(watch: const Stopwatch&) -> Duration {
    return Duration { nanos: clock_ns() - watch.start_ns };
}

fn restart(watch: Stopwatch&) -> Duration {
    let now_ns = clock_ns();
    let elapsed_dur = Duration { nanos: now_ns - watch.start_ns };
    watch.start_ns = now_ns;
    return elapsed_dur;
}

// Monotonic timeout tracker for network deadlines and cancellation tokens.
//
// Caller Contract & Nuances:
// - Non-Negative Remaining: remaining() returns Duration{0} when expired; never returns negative duration.
// - Anti-Overflow: deadline_after safely saturates at i64.max if dur would overflow clock_ns() + dur.
// - Zero Timer Heap: expired() evaluates via a single CPU register comparison against clock_ns().
struct Deadline {
    target_mono_ns: i64 = 0,
    has_deadline: bool = false,
}

fn deadline_after(dur: Duration) -> Deadline {
    let now_ns = clock_ns();
    if dur.nanos <= 0 {
        return Deadline { target_mono_ns: now_ns, has_deadline: true };
    }
    let max_i64 = 9223372036854775807;
    let target = if dur.nanos > max_i64 - now_ns { max_i64 } else { now_ns + dur.nanos };
    return Deadline { target_mono_ns: target, has_deadline: true };
}

fn is_expired(deadline_val: const Deadline&) -> bool {
    if !deadline_val.has_deadline { return false; }
    return clock_ns() >= deadline_val.target_mono_ns;
}

fn remaining(deadline_val: const Deadline&) -> Duration {
    if !deadline_val.has_deadline { return Duration { nanos: 9223372036854775807 }; }
    let diff_ns = deadline_val.target_mono_ns - clock_ns();
    return Duration { nanos: if diff_ns > 0 { diff_ns } else { 0 } };
}

fn sleep(dur: Duration) {
    if dur.nanos <= 0 { return; }
    let millis_val = dur.nanos / MILLISECOND;
    if millis_val > 0 {
        sleep_ms(millis_val);
    }
}

