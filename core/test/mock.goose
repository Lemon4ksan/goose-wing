// Deterministic mock clocks, property fuzzing generators, and typed test spies.
namespace core;

import std;
import core.time;

struct MockClock {
    now_us: i64 = 1700000000000000, // Deterministic epoch instant in microseconds
}

fn new_mock_clock(initial_us: i64 = 1700000000000000) -> MockClock {
    return MockClock { now_us: initial_us };
}

fn advance_us(clock: MockClock&, delta_us: i64) -> i64 {
    clock.now_us += delta_us;
    return clock.now_us;
}

fn advance_ms(clock: MockClock&, delta_ms: i64) -> i64 {
    clock.now_us += delta_ms * 1000;
    return clock.now_us;
}

fn advance_sec(clock: MockClock&, delta_sec: i64) -> i64 {
    clock.now_us += delta_sec * 1000000;
    return clock.now_us;
}

fn advance_days(clock: MockClock&, days: i64) -> i64 {
    clock.now_us += days * 86400000000;
    return clock.now_us;
}

fn monotonic_now(clock: const MockClock&) -> MonotonicInstant {
    let ns = if clock.now_us > 0 { (clock.now_us as u64) * 1000 } else { 0 as u64 };
    return MonotonicInstant { nanos: ns };
}

// Deterministic monotonic clock for testing.
struct MockMonoClock {
    now_ns: u64 = 1000000000,
}

fn new_mock_mono_clock(initial_ns: u64 = 1000000000) -> MockMonoClock {
    return MockMonoClock { now_ns: initial_ns };
}

fn advance_ns(clock: MockMonoClock&, delta_ns: u64) -> u64 {
    clock.now_ns += delta_ns;
    return clock.now_ns;
}

fn advance_us(clock: MockMonoClock&, delta_us: u64) -> u64 {
    clock.now_ns += delta_us * 1000;
    return clock.now_ns;
}

fn advance_ms(clock: MockMonoClock&, delta_ms: u64) -> u64 {
    clock.now_ns += delta_ms * 1000000;
    return clock.now_ns;
}

fn advance_sec(clock: MockMonoClock&, delta_sec: u64) -> u64 {
    clock.now_ns += delta_sec * 1000000000;
    return clock.now_ns;
}

fn now(clock: const MockMonoClock&) -> MonotonicInstant {
    return MonotonicInstant { nanos: clock.now_ns };
}

fn monotonic_now(clock: const MockMonoClock&) -> MonotonicInstant {
    return MonotonicInstant { nanos: clock.now_ns };
}

// Deterministic Xorshift64* generator for property testing.
struct FuzzRng {
    state: u64 = 0x853c49e6748fea9b,
}

fn new_fuzz_rng(seed: u64 = 0x853c49e6748fea9b) -> FuzzRng {
    let initial_state = if seed == 0 { 0x853c49e6748fea9b } else { seed };
    return FuzzRng { state: initial_state };
}

fn next_u64(rng: FuzzRng&) -> u64 {
    var x = rng.state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng.state = x;
    return x * 0x2545F4914F6CDD1D;
}

fn next_range(rng: FuzzRng&, min_val: i64, max_exclusive: i64) -> i64 {
    if max_exclusive <= min_val { return min_val; }
    let span = (max_exclusive - min_val) as u64;
    return min_val + ((next_u64(rng) % span) as i64);
}

fn next_bool(rng: FuzzRng&) -> bool {
    return (next_u64(rng) & 1) == 1;
}

fn next_ascii_string<B>(rng: FuzzRng&, out: B&, length: i64) {
    let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    for i in length {
        let idx = (next_u64(rng) % 64) as i64;
        out.push(chars[idx]);
    }
}

// Typed test spies & stubs (CallRecord)

struct CallRecord<Args, Ret> {
    call_count: i64 = 0,
    last_args: Args,
    canned_return: Ret,
}

fn spy<Args, Ret>(canned: Ret) -> CallRecord<Args, Ret> {
    return CallRecord<Args, Ret> {
        call_count: 0,
        last_args: Args { .. },
        canned_return: canned,
    };
}

fn record_call<Args, Ret>(spy_ref: CallRecord<Args, Ret>&, args: Args) -> Ret {
    spy_ref.call_count += 1;
    spy_ref.last_args = copy(args);
    return copy(spy_ref.canned_return);
}

fn reset_spy<Args, Ret>(spy_ref: CallRecord<Args, Ret>&) {
    spy_ref.call_count = 0;
}
