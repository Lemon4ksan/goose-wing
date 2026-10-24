// Goose Wing - Core Subsystem Backward-Compatible Facade
//
// This file re-exports all decoupled core symbols (math, time, url, compress,
// sync, test) from namespace `core` into namespace `wing` to maintain 100%
// backward compatibility for all existing Wing application modules and tests.
namespace wing;

import core.math;
import core.time;
import core.test;
import core.url;
import core.compress;
import core.sync;

// ============================================================================
// Core Type Aliases
// ============================================================================

// Math & Numerical Primitives
type wing::CheckedU32 = core::CheckedU32;
type wing::CheckedU64 = core::CheckedU64;
type wing::CheckedI64 = core::CheckedI64;
type wing::WyRand = core::WyRand;
type wing::Xoroshiro64StarStar = core::Xoroshiro64StarStar;
type wing::JacobsonRttEstimator = core::JacobsonRttEstimator;

// Time & Monotonic Primitives
type wing::Duration = core::Duration;
type wing::Time = core::Time;
type wing::Stopwatch = core::Stopwatch;
type wing::Deadline = core::Deadline;
type wing::MonotonicInstant = core::MonotonicInstant;

// URL & Origin Primitives
type wing::Url = core::Url;
type wing::UrlView = core::UrlView;
type wing::Origin = core::Origin;
type wing::RegistrableSite = core::RegistrableSite;
type wing::QueryParamItem = core::QueryParamItem;
type wing::QueryParamsList = core::QueryParamsList;

// Compression Primitives
type wing::ZStreamCompressor = core::ZStreamCompressor;
type wing::ZStreamDecompressor = core::ZStreamDecompressor;
type wing::DeflateConfig = core::DeflateConfig;

// Concurrency & Synchronization Primitives
type wing::SemPermit = core::SemPermit;
type wing::Semaphore = core::Semaphore;
type wing::WaitGroup = core::WaitGroup;
type wing::CountDownLatch = core::CountDownLatch;
type wing::ReassemblerItem = core::ReassemblerItem;
type wing::Reassembler = core::Reassembler;
type wing::ActorRef = core::ActorRef;
type wing::StashedEnvelope = core::StashedEnvelope;
type wing::StashBuffer = core::StashBuffer;
type wing::PriorityItem = core::PriorityItem;
type wing::PriorityMailbox = core::PriorityMailbox;
type wing::ChildSpec = core::ChildSpec;
type wing::SupervisorSpec = core::SupervisorSpec;
type wing::WorkerStatus = core::WorkerStatus;
type wing::Supervisor = core::Supervisor;
type wing::FlightEntry = core::FlightEntry;
type wing::SingleflightGroup = core::SingleflightGroup;
type wing::LatchTick = core::LatchTick;
type wing::BatonMutex = core::BatonMutex;

// Testing Primitives
type wing::T = core::T;
type wing::Runner = core::Runner;
type wing::Failure = core::Failure;
type wing::MockClock = core::MockClock;
type wing::FuzzRng = core::FuzzRng;

// Enum Type Aliases
type wing::Month = core::Month;
type wing::Weekday = core::Weekday;
type wing::CompressError = core::CompressError;
type wing::FlushMode = core::FlushMode;
type wing::ContainerFormat = core::ContainerFormat;
type wing::UrlParseError = core::UrlParseError;
type wing::OriginKind = core::OriginKind;
type wing::Strategy = core::Strategy;
type wing::RestartType = core::RestartType;
type wing::AutoShutdown = core::AutoShutdown;
type wing::ExitReason = core::ExitReason;

// ============================================================================
// Test Runner Compatibility Bridge
// ============================================================================

enum Verbosity {
    Silent,
    Normal,
    Verbose,
    Golden,
}

fn new_runner(suite_name: const u8[:], verb: Verbosity = Verbosity.Normal) -> core::Runner {
    let core_verb = match verb {
        Silent => core::Verbosity.Silent,
        Normal => core::Verbosity.Normal,
        Verbose => core::Verbosity.Verbose,
        Golden => core::Verbosity.Golden,
    };
    return core::new_runner(suite_name, core_verb);
}

fn run_case<F: fn(core::T&)>(runner_ref: core::Runner&, case_name: const u8[:]) -> bool {
    return core::run_case(runner_ref, case_name, F);
}

fn run_table<Row, F: fn(core::T&, const Row&, i64)>(t: core::T&, table_name: const u8[:], rows: const Row[:]) -> bool {
    return core::run_table(t, table_name, rows, F);
}

fn finish(runner_ref: const core::Runner&) -> bool {
    return core::finish(runner_ref);
}

inline fn new_mock_clock(initial_us: i64 = 1700000000000000) -> core::MockClock {
    return core::new_mock_clock(initial_us);
}

inline fn advance_ms(clock: core::MockClock&, delta_ms: i64) -> i64 { return core::advance_ms(clock, delta_ms); }
inline fn advance_sec(clock: core::MockClock&, delta_sec: i64) -> i64 { return core::advance_sec(clock, delta_sec); }
inline fn advance_days(clock: core::MockClock&, days: i64) -> i64 { return core::advance_days(clock, days); }
inline fn advance_us(clock: core::MockClock&, delta_us: i64) -> i64 { return core::advance_us(clock, delta_us); }

inline fn new_fuzz_rng(seed: u64 = 0x853c49e6748fea9b) -> core::FuzzRng { return core::new_fuzz_rng(seed); }
inline fn next_range(rng: core::FuzzRng&, min_val: i64, max_exclusive: i64) -> i64 { return core::next_range(rng, min_val, max_exclusive); }

// ============================================================================
// Core Constants Re-export
// ============================================================================

const NANOSECOND: i64 = core::NANOSECOND;
const MICROSECOND: i64 = core::MICROSECOND;
const MILLISECOND: i64 = core::MILLISECOND;
const SECOND: i64 = core::SECOND;
const MINUTE: i64 = core::MINUTE;
const HOUR: i64 = core::HOUR;
const DAY: i64 = core::DAY;
const WEEK: i64 = core::WEEK;
const SECS_PER_MINUTE: i64 = core::SECS_PER_MINUTE;
const SECS_PER_HOUR: i64 = core::SECS_PER_HOUR;
const SECS_PER_DAY: i64 = core::SECS_PER_DAY;
const NANOS_PER_MICRO: i64 = core::NANOS_PER_MICRO;
const MICROS_PER_MILLI: i64 = core::MICROS_PER_MILLI;
const NANOS_PER_MILLI: i64 = core::NANOS_PER_MILLI;
const NANOS_PER_SEC: i64 = core::NANOS_PER_SEC;
const DURATION_MIN_NANOS: i64 = core::DURATION_MIN_NANOS;
const DURATION_MAX_NANOS: i64 = core::DURATION_MAX_NANOS;
const MAX_WALL_SEC_FOR_NANOS: i64 = core::MAX_WALL_SEC_FOR_NANOS;

const U32_MAX: u32 = core::U32_MAX;
const U64_MAX: u64 = core::U64_MAX;
const I32_MIN: i32 = core::I32_MIN;
const I32_MAX: i32 = core::I32_MAX;
const I64_MIN: i64 = core::I64_MIN;
const I64_MAX: i64 = core::I64_MAX;

const FNV1A_32_OFFSET: u32 = core::FNV1A_32_OFFSET;
const FNV1A_32_PRIME: u32 = core::FNV1A_32_PRIME;
const FNV1A_64_OFFSET: u64 = core::FNV1A_64_OFFSET;
const FNV1A_64_PRIME: u64 = core::FNV1A_64_PRIME;

const XXH_PRIME32_1: u32 = core::XXH_PRIME32_1;
const XXH_PRIME32_2: u32 = core::XXH_PRIME32_2;
const XXH_PRIME32_3: u32 = core::XXH_PRIME32_3;
const XXH_PRIME32_4: u32 = core::XXH_PRIME32_4;
const XXH_PRIME32_5: u32 = core::XXH_PRIME32_5;

const HE_ABSOLUTE_MIN_DELAY_MS: i64 = core::HE_ABSOLUTE_MIN_DELAY_MS;
const HE_RECOMMENDED_MIN_DELAY_MS: i64 = core::HE_RECOMMENDED_MIN_DELAY_MS;
const HE_DEFAULT_ATTEMPT_DELAY_MS: i64 = core::HE_DEFAULT_ATTEMPT_DELAY_MS;
const HE_GO_FALLBACK_DELAY_MS: i64 = core::HE_GO_FALLBACK_DELAY_MS;
const HE_MAX_ATTEMPT_DELAY_MS: i64 = core::HE_MAX_ATTEMPT_DELAY_MS;
const HE_LAST_RESORT_SYNTHESIS_MS: i64 = core::HE_LAST_RESORT_SYNTHESIS_MS;
const QUIC_INITIAL_RTT_US: u64 = core::QUIC_INITIAL_RTT_US;
const QUIC_AGGRESSIVE_INITIAL_RTT_US: u64 = core::QUIC_AGGRESSIVE_INITIAL_RTT_US;
const QUIC_TIMER_GRANULARITY_US: u64 = core::QUIC_TIMER_GRANULARITY_US;
const QUIC_PACKET_THRESHOLD: u64 = core::QUIC_PACKET_THRESHOLD;

const WYP0_V42: u64 = core::WYP0_V42;
const WYP1_V42: u64 = core::WYP1_V42;
const WYP2_V42: u64 = core::WYP2_V42;
const WYP3_V42: u64 = core::WYP3_V42;

// ============================================================================
// Math Functions Re-export
// ============================================================================

// Arithmetic
inline fn mul_wide_u64(a: u64, b: u64) -> u64, u64 { return core::mul_wide_u64(a, b); }
inline fn wymum(a: u64, b: u64) -> u64 { return core::wymum(a, b); }
inline fn add_sat_u32(a: u32, b: u32) -> u32 { return core::add_sat_u32(a, b); }
inline fn add_sat_u64(a: u64, b: u64) -> u64 { return core::add_sat_u64(a, b); }
inline fn sub_sat_u32(a: u32, b: u32) -> u32 { return core::sub_sat_u32(a, b); }
inline fn sub_sat_u64(a: u64, b: u64) -> u64 { return core::sub_sat_u64(a, b); }
inline fn mul_sat_u32(a: u32, b: u32) -> u32 { return core::mul_sat_u32(a, b); }
inline fn mul_sat_u64(a: u64, b: u64) -> u64 { return core::mul_sat_u64(a, b); }
inline fn shl_sat_u64(base: u64, shift: u32) -> u64 { return core::shl_sat_u64(base, shift); }
inline fn add_sat_i64(a: i64, b: i64) -> i64 { return core::add_sat_i64(a, b); }
inline fn sub_sat_i64(a: i64, b: i64) -> i64 { return core::sub_sat_i64(a, b); }
inline fn add_checked_u32(a: u32, b: u32) -> core::CheckedU32 { return core::add_checked_u32(a, b); }
inline fn add_checked_u64(a: u64, b: u64) -> core::CheckedU64 { return core::add_checked_u64(a, b); }
inline fn mul_checked_i64(a: i64, b: i64) -> core::CheckedI64 { return core::mul_checked_i64(a, b); }
inline fn rem_euclid_i64(lhs: i64, rhs: i64) -> i64 { return core::rem_euclid_i64(lhs, rhs); }
inline fn div_euclid_i64(lhs: i64, rhs: i64) -> i64 { return core::div_euclid_i64(lhs, rhs); }
inline fn fast_mod_reduce_i32(x: i32, q: i32) -> i32 { return core::fast_mod_reduce_i32(x, q); }

// Bits
inline fn rotl32(x: u32, r: u32) -> u32 { return core::rotl32(x, r); }
inline fn rotr32(x: u32, r: u32) -> u32 { return core::rotr32(x, r); }
inline fn rotl64(x: u64, r: u32) -> u64 { return core::rotl64(x, r); }
inline fn rotr64(x: u64, r: u32) -> u64 { return core::rotr64(x, r); }
inline fn is_pow2_u32(x: u32) -> bool { return core::is_pow2_u32(x); }
inline fn is_pow2_u64(x: u64) -> bool { return core::is_pow2_u64(x); }
inline fn next_pow2_u32(x: u32) -> u32 { return core::next_pow2_u32(x); }
inline fn next_pow2_u64(x: u64) -> u64 { return core::next_pow2_u64(x); }
inline fn bswap16(x: u16) -> u16 { return core::bswap16(x); }
inline fn bswap32(x: u32) -> u32 { return core::bswap32(x); }
inline fn bswap64(x: u64) -> u64 { return core::bswap64(x); }
inline fn read_le_u16(data: const u8[:], offset: i64) -> u16 { return core::read_le_u16(data, offset); }
inline fn read_le_u32(data: const u8[:], offset: i64) -> u32 { return core::read_le_u32(data, offset); }
inline fn read_le_u64(data: const u8[:], offset: i64) -> u64 { return core::read_le_u64(data, offset); }
inline fn read_be_u16(data: const u8[:], offset: i64) -> u16 { return core::read_be_u16(data, offset); }
inline fn read_be_u24(data: const u8[:], offset: i64) -> u32 { return core::read_be_u24(data, offset); }
inline fn read_be_u32(data: const u8[:], offset: i64) -> u32 { return core::read_be_u32(data, offset); }
inline fn read_be_u64(data: const u8[:], offset: i64) -> u64 { return core::read_be_u64(data, offset); }
inline fn write_be_u16<B>(out: B&, val: u16) { core::write_be_u16(out, val); }
inline fn write_be_u32<B>(out: B&, val: u32) { core::write_be_u32(out, val); }
inline fn write_be_u64<B>(out: B&, val: u64) { core::write_be_u64(out, val); }
inline fn write_le_u16_at<B>(dst: B&, offset: i64, val: u16) { core::write_le_u16_at(dst, offset, val); }
inline fn write_le_u32_at<B>(dst: B&, offset: i64, val: u32) { core::write_le_u32_at(dst, offset, val); }
inline fn write_le_u64_at<B>(dst: B&, offset: i64, val: u64) { core::write_le_u64_at(dst, offset, val); }
inline fn write_le_u16<B>(out: B&, val: u16) { core::write_le_u16(out, val); }
inline fn write_le_u32<B>(out: B&, val: u32) { core::write_le_u32(out, val); }
inline fn write_le_u64<B>(out: B&, val: u64) { core::write_le_u64(out, val); }

// Constant Time & Clamping
inline fn ct_is_zero_u32(x: u32) -> u32 { return core::ct_is_zero_u32(x); }
inline fn ct_is_zero_u64(x: u64) -> u64 { return core::ct_is_zero_u64(x); }
inline fn ct_eq_u32(a: u32, b: u32) -> u32 { return core::ct_eq_u32(a, b); }
inline fn ct_eq_u64(a: u64, b: u64) -> u64 { return core::ct_eq_u64(a, b); }
inline fn ct_lt_u32(a: u32, b: u32) -> u32 { return core::ct_lt_u32(a, b); }
inline fn ct_lt_u64(a: u64, b: u64) -> u64 { return core::ct_lt_u64(a, b); }
inline fn ct_gt_u32(a: u32, b: u32) -> u32 { return core::ct_gt_u32(a, b); }
inline fn ct_gt_u64(a: u64, b: u64) -> u64 { return core::ct_gt_u64(a, b); }
inline fn ct_mask_u32(bit: u32) -> u32 { return core::ct_mask_u32(bit); }
inline fn ct_mask_u64(bit: u64) -> u64 { return core::ct_mask_u64(bit); }
inline fn ct_select_u32(mask: u32, if_true: u32, if_false: u32) -> u32 { return core::ct_select_u32(mask, if_true, if_false); }
inline fn ct_select_u64(mask: u64, if_true: u64, if_false: u64) -> u64 { return core::ct_select_u64(mask, if_true, if_false); }
inline fn ct_min_u32(a: u32, b: u32) -> u32 { return core::ct_min_u32(a, b); }
inline fn ct_max_u32(a: u32, b: u32) -> u32 { return core::ct_max_u32(a, b); }
inline fn ct_min_u64(a: u64, b: u64) -> u64 { return core::ct_min_u64(a, b); }
inline fn ct_max_u64(a: u64, b: u64) -> u64 { return core::ct_max_u64(a, b); }
inline fn ct_min_i64(a: i64, b: i64) -> i64 { return core::ct_min_i64(a, b); }
inline fn ct_max_i64(a: i64, b: i64) -> i64 { return core::ct_max_i64(a, b); }
inline fn ct_abs_i64(x: i64) -> i64 { return core::ct_abs_i64(x); }
inline fn ct_min_i32(a: i32, b: i32) -> i32 { return core::ct_min_i32(a, b); }
inline fn ct_max_i32(a: i32, b: i32) -> i32 { return core::ct_max_i32(a, b); }
inline fn clamp_i32(val: i32, low: i32, high: i32) -> i32 { return core::clamp_i32(val, low, high); }
inline fn clamp_u32(val: u32, low: u32, high: u32) -> u32 { return core::clamp_u32(val, low, high); }
inline fn clamp_u64(val: u64, low: u64, high: u64) -> u64 { return core::clamp_u64(val, low, high); }
inline fn clamp_i64(val: i64, low: i64, high: i64) -> i64 { return core::clamp_i64(val, low, high); }

// Hash
inline fn fnv1a_32(data: const u8[:]) -> u32 { return core::fnv1a_32(data); }
inline fn fnv1a_64(data: const u8[:]) -> u64 { return core::fnv1a_64(data); }
inline fn xxh32_round(acc: u32, input: u32) -> u32 { return core::xxh32_round(acc, input); }
inline fn xxh32_avalanche(h32: u32) -> u32 { return core::xxh32_avalanche(h32); }
fn xxhash32(data: const u8[:], seed: u32 = 0) -> u32 { return core::xxhash32(data, seed); }
inline fn wy_read_small(data: const u8[:], len: i64) -> u64 { return core::wy_read_small(data, len); }
fn wyhash64_with_secret(data: const u8[:], seed_in: u64, secret: const u64[4]&) -> u64 { return core::wyhash64_with_secret(data, seed_in, secret); }
inline fn wyhash64(data: const u8[:], seed: u64 = 0) -> u64 { return core::wyhash64(data, seed); }
inline fn hash_combine_u64(seed: u64, val: u64) -> u64 { return core::hash_combine_u64(seed, val); }
inline fn hash_combine_u32(seed: u32, val: u32) -> u32 { return core::hash_combine_u32(seed, val); }

// Network Math
inline fn retry_after_sec_to_ms_sat(seconds: i64) -> i64 { return core::retry_after_sec_to_ms_sat(seconds); }
inline fn backoff_full_jitter_ms(rng: core::WyRand&, base_ms: u64, cap_ms: u64, attempt: u32) -> u64 { return core::backoff_full_jitter_ms(rng, base_ms, cap_ms, attempt); }
inline fn backoff_equal_jitter_ms(rng: core::WyRand&, base_ms: u64, cap_ms: u64, attempt: u32) -> u64 { return core::backoff_equal_jitter_ms(rng, base_ms, cap_ms, attempt); }
inline fn backoff_decorrelated_jitter_ms(rng: core::WyRand&, base_ms: u64, cap_ms: u64, prev_sleep_ms: u64) -> u64 { return core::backoff_decorrelated_jitter_ms(rng, base_ms, cap_ms, prev_sleep_ms); }
fn clamp_happy_eyeballs_delay_ms(candidate_delay_ms: i64, is_first_family: bool = false) -> i64 { return core::clamp_happy_eyeballs_delay_ms(candidate_delay_ms, is_first_family); }
fn new_jacobson_rtt_estimator(initial_rtt_us: u64 = core::QUIC_INITIAL_RTT_US) -> core::JacobsonRttEstimator { return core::new_jacobson_rtt_estimator(initial_rtt_us); }
inline fn smoothed_rtt_us(est: const core::JacobsonRttEstimator&) -> u64 { return core::smoothed_rtt_us(est); }
inline fn rttvar_us(est: const core::JacobsonRttEstimator&) -> u64 { return core::rttvar_us(est); }
fn on_rtt_sample(est: core::JacobsonRttEstimator&, latest_rtt_us: u64, ack_delay_us: u64, max_ack_delay_us: u64, handshake_confirmed: bool) {
    core::on_rtt_sample(est, latest_rtt_us, ack_delay_us, max_ack_delay_us, handshake_confirmed);
}
inline fn probe_timeout_us(est: const core::JacobsonRttEstimator&, max_ack_delay_us: u64 = 0) -> u64 { return core::probe_timeout_us(est, max_ack_delay_us); }
inline fn loss_time_threshold_us(est: const core::JacobsonRttEstimator&) -> u64 { return core::loss_time_threshold_us(est); }
fn socks5_expected_frame_len_ct(buf: const u8[:]) -> u32 { return core::socks5_expected_frame_len_ct(buf); }

// Random Math
fn splitmix64(seed: u64&) -> u64 { return core::splitmix64(seed); }
fn new_wyrand(seed: u64 = 0) -> core::WyRand { return core::new_wyrand(seed); }
inline fn next_u64(rng: core::WyRand&) -> u64 { return core::next_u64(rng); }
inline fn next_u32(rng: core::WyRand&) -> u32 { return core::next_u32(rng); }
inline fn w1rand_next(state: u64&) -> u32 { return core::w1rand_next(state); }
fn new_xoroshiro64_star_star(seed: u64) -> core::Xoroshiro64StarStar { return core::new_xoroshiro64_star_star(seed); }
inline fn new_xoroshiro64(seed: u64) -> core::Xoroshiro64StarStar { return core::new_xoroshiro64(seed); }
inline fn next_u32(rng: core::Xoroshiro64StarStar&) -> u32 { return core::next_u32(rng); }
inline fn next_star_u32(rng: core::Xoroshiro64StarStar&) -> u32 { return core::next_star_u32(rng); }
inline fn fast_range_biased_u32(random_word: u32, range: u32) -> u32 { return core::fast_range_biased_u32(random_word, range); }
inline fn fast_range_biased_u64(random_word: u64, range: u64) -> u64 { return core::fast_range_biased_u64(random_word, range); }
fn fast_range_unbiased_u32(rng: core::WyRand&, range: u32) -> u32 { return core::fast_range_unbiased_u32(rng, range); }

// ============================================================================
// Time Functions Re-export
// ============================================================================

inline fn nanos(nanos_count: i64) -> core::Duration { return core::nanos(nanos_count); }
inline fn micros(micros_count: i64) -> core::Duration { return core::micros(micros_count); }
inline fn millis(millis_count: i64) -> core::Duration { return core::millis(millis_count); }
inline fn secs(secs_count: i64) -> core::Duration { return core::secs(secs_count); }
inline fn mins(mins_count: i64) -> core::Duration { return core::mins(mins_count); }
inline fn hours(hours_count: i64) -> core::Duration { return core::hours(hours_count); }
inline fn days(days_count: i64) -> core::Duration { return core::days(days_count); }
inline fn weeks(weeks_count: i64) -> core::Duration { return core::weeks(weeks_count); }

inline fn nanoseconds(nanos_count: i64) -> core::Duration { return core::nanoseconds(nanos_count); }
inline fn microseconds(micros_count: i64) -> core::Duration { return core::microseconds(micros_count); }
inline fn milliseconds(millis_count: i64) -> core::Duration { return core::milliseconds(millis_count); }
inline fn seconds(secs_count: i64) -> core::Duration { return core::seconds(secs_count); }
inline fn minutes(mins_count: i64) -> core::Duration { return core::minutes(mins_count); }

inline fn as_nanos(dur: core::Duration) -> i64 { return core::as_nanos(dur); }
inline fn as_micros(dur: core::Duration) -> i64 { return core::as_micros(dur); }
inline fn as_millis(dur: core::Duration) -> i64 { return core::as_millis(dur); }
inline fn as_secs(dur: core::Duration) -> i64 { return core::as_secs(dur); }
inline fn as_mins(dur: core::Duration) -> i64 { return core::as_mins(dur); }
inline fn as_hours(dur: core::Duration) -> i64 { return core::as_hours(dur); }
inline fn as_days(dur: core::Duration) -> i64 { return core::as_days(dur); }
inline fn as_secs_f64(dur: core::Duration) -> f64 { return core::as_secs_f64(dur); }
inline fn as_mins_f64(dur: core::Duration) -> f64 { return core::as_mins_f64(dur); }
inline fn as_hours_f64(dur: core::Duration) -> f64 { return core::as_hours_f64(dur); }

inline fn nanoseconds(dur: core::Duration) -> i64 { return core::nanoseconds(dur); }
inline fn microseconds(dur: core::Duration) -> i64 { return core::microseconds(dur); }
inline fn milliseconds(dur: core::Duration) -> i64 { return core::milliseconds(dur); }
inline fn seconds(dur: core::Duration) -> f64 { return core::seconds(dur); }
inline fn minutes(dur: core::Duration) -> f64 { return core::minutes(dur); }
inline fn hours(dur: core::Duration) -> f64 { return core::hours(dur); }

fn parse_duration(raw_str: const u8[:]) -> core::Duration, bool { return core::parse_duration(raw_str); }
inline fn monotonic_now() -> core::MonotonicInstant { return core::monotonic_now(); }
inline fn new_monotonic_instant(nanos_val: u64) -> core::MonotonicInstant { return core::new_monotonic_instant(nanos_val); }
inline fn as_nanos(inst: core::MonotonicInstant) -> u64 { return core::as_nanos(inst); }
inline fn duration_since(now_inst: core::MonotonicInstant, anchor: core::MonotonicInstant) -> core::Duration { return core::duration_since(now_inst, anchor); }

inline fn stopwatch() -> core::Stopwatch { return core::stopwatch(); }
inline fn elapsed(watch: const core::Stopwatch&) -> core::Duration { return core::elapsed(watch); }
inline fn restart(watch: core::Stopwatch&) -> core::Duration { return core::restart(watch); }

inline fn deadline_after(dur: core::Duration) -> core::Deadline { return core::deadline_after(dur); }
inline fn remaining(dl: const core::Deadline&) -> core::Duration { return core::remaining(dl); }
inline fn is_expired(dl: const core::Deadline&) -> bool { return core::is_expired(dl); }

inline fn now() -> core::Time { return core::now(); }
fn date(year_val: i64, month_val: core::Month, day_val: i64, hour_val: i64 = 0, min_val: i64 = 0, sec_val: i64 = 0, nsec_val: i64 = 0, tz_offset: i32 = 0) -> core::Time {
    return core::date(year_val, month_val, day_val, hour_val, min_val, sec_val, nsec_val, tz_offset);
}
fn date(year_val: i64, month_num: i64, day_val: i64, hour_val: i64 = 0, min_val: i64 = 0, sec_val: i64 = 0, nsec_val: i64 = 0, tz_offset: i32 = 0) -> core::Time {
    return core::date(year_val, month_num, day_val, hour_val, min_val, sec_val, nsec_val, tz_offset);
}
fn civil_parts(time_val: core::Time) -> i64, i64, i64, i64, i64, i64 { return core::civil_parts(time_val); }
inline fn civil_to_days(year_val: i64, month_val: i64, day_val: i64) -> i64 { return core::civil_to_days(year_val, month_val, day_val); }
inline fn days_to_civil(days_since_epoch: i64) -> i64, i64, i64 { return core::days_to_civil(days_since_epoch); }
inline fn year(time_val: core::Time) -> i64 { return core::year(time_val); }
inline fn month(time_val: core::Time) -> core::Month { return core::month(time_val); }
inline fn month_number(time_val: core::Time) -> i64 { return core::month_number(time_val); }
inline fn month_number(month_val: core::Month) -> i64 { return core::month_number(month_val); }
inline fn month_from_number(month_num: i64) -> core::Month { return core::month_from_number(month_num); }
inline fn month_name(month_val: core::Month) -> const u8[:] { return core::month_name(month_val); }
inline fn month_short_name(month_val: core::Month) -> const u8[:] { return core::month_short_name(month_val); }
inline fn day(time_val: core::Time) -> i64 { return core::day(time_val); }
inline fn weekday(time_val: core::Time) -> core::Weekday { return core::weekday(time_val); }
inline fn weekday_number(weekday_val: core::Weekday) -> i64 { return core::weekday_number(weekday_val); }
inline fn weekday_from_number(weekday_num: i64) -> core::Weekday { return core::weekday_from_number(weekday_num); }
inline fn weekday_name(weekday_val: core::Weekday) -> const u8[:] { return core::weekday_name(weekday_val); }
inline fn weekday_short_name(weekday_val: core::Weekday) -> const u8[:] { return core::weekday_short_name(weekday_val); }
inline fn clock(time_val: core::Time) -> i64, i64, i64 { return core::clock(time_val); }
inline fn hour(time_val: core::Time) -> i64 { return core::hour(time_val); }
inline fn minute(time_val: core::Time) -> i64 { return core::minute(time_val); }
inline fn second(time_val: core::Time) -> i64 { return core::second(time_val); }
inline fn nanosecond(time_val: core::Time) -> i64 { return core::nanosecond(time_val); }

inline fn unix(time_val: core::Time) -> i64 { return core::unix(time_val); }
inline fn unix(sec: i64, nsec: i64 = 0) -> core::Time { return core::unix(sec, nsec); }
inline fn unix_milli(time_val: core::Time) -> i64 { return core::unix_milli(time_val); }
inline fn unix_milli(ms: i64) -> core::Time { return core::unix_milli(ms); }
inline fn unix_micro(time_val: core::Time) -> i64 { return core::unix_micro(time_val); }
inline fn unix_micro(us: i64) -> core::Time { return core::unix_micro(us); }
inline fn unix_nano(time_val: core::Time) -> i64 { return core::unix_nano(time_val); }
inline fn unix_nano(ns: i64) -> core::Time { return core::unix_nano(ns); }

inline fn is_zero(time_val: core::Time) -> bool { return core::is_zero(time_val); }
inline fn is_zero(dur: core::Duration) -> bool { return core::is_zero(dur); }

inline fn days_in_month(time_val: core::Time) -> i64 { return core::days_in_month(time_val); }
inline fn days_in_month(year_val: i64, month_val: i64) -> i64 { return core::days_in_month(year_val, month_val); }
inline fn days_in_year(time_val: core::Time) -> i64 { return core::days_in_year(time_val); }
inline fn is_leap_year(time_val: core::Time) -> bool { return core::is_leap_year(time_val); }
inline fn is_leap_year(year_val: i64) -> bool { return core::is_leap_year(year_val); }

inline fn since(time_val: core::Time) -> core::Duration { return core::since(time_val); }
inline fn until(time_val: core::Time) -> core::Duration { return core::until(time_val); }

inline fn truncate(time_val: core::Time, dur: core::Duration) -> core::Time { return core::truncate(time_val, dur); }
inline fn truncate(dur: core::Duration, step_dur: core::Duration) -> core::Duration { return core::truncate(dur, step_dur); }
inline fn round(time_val: core::Time, dur: core::Duration) -> core::Time { return core::round(time_val, dur); }
inline fn round(dur: core::Duration, step_dur: core::Duration) -> core::Duration { return core::round(dur, step_dur); }

inline fn in_offset(time_val: core::Time, tz_offset_seconds: i32) -> core::Time { return core::in_offset(time_val, tz_offset_seconds); }
inline fn in_tz(time_val: core::Time, hours_offset: i64, minutes_offset: i64 = 0) -> core::Time { return core::in_tz(time_val, hours_offset, minutes_offset); }
inline fn utc(time_val: core::Time) -> core::Time { return core::utc(time_val); }
inline fn tz_offset(time_val: core::Time) -> i32 { return core::tz_offset(time_val); }

inline fn start_of_day(time_val: core::Time) -> core::Time { return core::start_of_day(time_val); }
inline fn end_of_day(time_val: core::Time) -> core::Time { return core::end_of_day(time_val); }
inline fn start_of_month(time_val: core::Time) -> core::Time { return core::start_of_month(time_val); }
inline fn end_of_month(time_val: core::Time) -> core::Time { return core::end_of_month(time_val); }
inline fn start_of_year(time_val: core::Time) -> core::Time { return core::start_of_year(time_val); }
inline fn end_of_year(time_val: core::Time) -> core::Time { return core::end_of_year(time_val); }

inline fn sleep(dur: core::Duration) { core::sleep(dur); }
inline fn compare(dur1: core::Duration, dur2: core::Duration) -> i64 { return core::compare(dur1, dur2); }
inline fn compare(time_val: core::Time, other_time: core::Time) -> i64 { return core::compare(time_val, other_time); }
inline fn format<B>(out: B&, dur: core::Duration) { core::format(out, dur); }
inline fn format<B>(out: B&, time_val: core::Time) { core::format(out, time_val); }
inline fn format<B>(out: B&, month_val: core::Month) { core::format(out, month_val); }
inline fn format<B>(out: B&, weekday_val: core::Weekday) { core::format(out, weekday_val); }

inline fn format_rfc3339<B>(out: B&, time_val: core::Time) { core::format_rfc3339(out, time_val); }
inline fn format_rfc3339_nano<B>(out: B&, time_val: core::Time) { core::format_rfc3339_nano(out, time_val); }
inline fn parse_rfc3339(raw_str: const u8[:]) -> core::Time, bool { return core::parse_rfc3339(raw_str); }
inline fn format_http<B>(out: B&, time_val: core::Time) { core::format_http(out, time_val); }
inline fn parse_http_date(raw_str: const u8[:]) -> core::Time, bool { return core::parse_http_date(raw_str); }
inline fn parse_digits(str_val: const u8[:]) -> i64, bool { return core::parse_digits(str_val); }

// ============================================================================
// URL Functions Re-export
// ============================================================================

inline fn new_url(raw_input: const u8[:]) -> core::Url { return core::new_url(raw_input); }
inline fn new_url(raw_input: const u8[:], base_url: const core::Url&) -> core::Url { return core::new_url(raw_input, base_url); }
inline fn parse_url(raw_input: const u8[:]) -> core::Url, core::UrlParseError { return core::parse_url(raw_input); }
inline fn parse_url_with_base(raw_input: const u8[:], base_url: const core::Url&) -> core::Url, core::UrlParseError { return core::parse_url_with_base(raw_input, base_url); }
inline fn parse_url_view(raw_input: const u8[:]) -> core::UrlView, core::UrlParseError { return core::parse_url_view(raw_input); }
inline fn new_url_view(raw_input: const u8[:]) -> core::UrlView { return core::new_url_view(raw_input); }
inline fn format_url<B>(out: B&, url_val: const core::Url&) { core::format_url(out, url_val); }
inline fn format_url_view<B>(out: B&, view: const core::UrlView&) { core::format_url_view(out, view); }

inline fn new_file_url(file_path: const u8[:]) -> core::Url { return core::new_file_url(file_path); }
inline fn is_file_url(url_val: const core::Url&) -> bool { return core::is_file_url(url_val); }
inline fn file_path<B>(url_val: const core::Url&, out: B&) -> bool { return core::file_path(url_val, out); }

inline fn new_opaque_origin() -> core::Origin { return core::new_opaque_origin(); }
inline fn new_origin_tuple(scheme: const u8[:], host: const u8[:], port: i32) -> core::Origin { return core::new_origin_tuple(scheme, host, port); }
inline fn origin_from_url(url_val: const core::Url&) -> core::Origin { return core::origin_from_url(url_val); }
inline fn registrable_site_from_url(url_val: const core::Url&) -> core::RegistrableSite { return core::registrable_site_from_url(url_val); }
inline fn is_same_origin(origin_a: core::Origin, origin_b: core::Origin) -> bool { return core::is_same_origin(origin_a, origin_b); }
inline fn is_same_origin_url(url_a: const core::Url&, url_b: const core::Url&) -> bool { return core::is_same_origin_url(url_a, url_b); }
inline fn serialize_origin<B>(origin_val: core::Origin, out: B&) { core::serialize_origin(origin_val, out); }
inline fn is_schemeful_same_site_urls(url_a: const core::Url&, url_b: const core::Url&) -> bool { return core::is_schemeful_same_site_urls(url_a, url_b); }
inline fn is_same_site_origin_url(origin_val: const core::Origin&, url_val: const core::Url&) -> bool { return core::is_same_site_origin_url(origin_val, url_val); }

inline fn href(view: const core::UrlView&) -> const u8[:] { return core::href(view); }
inline fn scheme(view: const core::UrlView&) -> const u8[:] { return core::scheme(view); }
inline fn host(view: const core::UrlView&) -> const u8[:] { return core::host(view); }
inline fn hostname(view: const core::UrlView&) -> const u8[:] { return core::hostname(view); }
inline fn pathname(view: const core::UrlView&) -> const u8[:] { return core::pathname(view); }
inline fn search(view: const core::UrlView&) -> const u8[:] { return core::search(view); }
inline fn hash(view: const core::UrlView&) -> const u8[:] { return core::hash(view); }
inline fn port(view: const core::UrlView&) -> i32 { return core::port(view); }
inline fn is_valid(view: const core::UrlView&) -> bool { return core::is_valid(view); }

inline fn href(url_val: const core::Url&) -> const u8[:] { return core::href(url_val); }
inline fn scheme(url_val: const core::Url&) -> const u8[:] { return core::scheme(url_val); }
inline fn username(url_val: const core::Url&) -> const u8[:] { return core::username(url_val); }
inline fn password(url_val: const core::Url&) -> const u8[:] { return core::password(url_val); }
inline fn has_credentials(url_val: const core::Url&) -> bool { return core::has_credentials(url_val); }
inline fn hostname(url_val: const core::Url&) -> const u8[:] { return core::hostname(url_val); }
inline fn host(url_val: const core::Url&) -> const u8[:] { return core::host(url_val); }
inline fn port_str(url_val: const core::Url&) -> const u8[:] { return core::port_str(url_val); }
inline fn effective_port(url_val: const core::Url&) -> i32 { return core::effective_port(url_val); }
inline fn pathname(url_val: const core::Url&) -> const u8[:] { return core::pathname(url_val); }
inline fn search(url_val: const core::Url&) -> const u8[:] { return core::search(url_val); }
inline fn hash(url_val: const core::Url&) -> const u8[:] { return core::hash(url_val); }
inline fn is_special(url_val: const core::Url&) -> bool { return core::is_special(url_val); }
inline fn is_http_or_https(url_val: const core::Url&) -> bool { return core::is_http_or_https(url_val); }
inline fn is_secure_scheme(url_val: const core::Url&) -> bool { return core::is_secure_scheme(url_val); }

inline fn last_path_component(url_val: const core::Url&) -> const u8[:] { return core::last_path_component(url_val); }
inline fn path_extension(url_val: const core::Url&) -> const u8[:] { return core::path_extension(url_val); }
inline fn deleting_path_extension(url_val: core::Url) -> core::Url { return core::deleting_path_extension(url_val); }
inline fn deleting_last_path_component(url_val: core::Url) -> core::Url { return core::deleting_last_path_component(url_val); }
inline fn appending_path_component(url_val: core::Url, component: const u8[:]) -> core::Url { return core::appending_path_component(url_val, component); }
inline fn appending_path(url_val: core::Url, subpath: const u8[:]) -> core::Url { return core::appending_path(url_val, subpath); }
inline fn appending_path_extension(url_val: core::Url, ext: const u8[:]) -> core::Url { return core::appending_path_extension(url_val, ext); }

inline fn resolve_reference(base_url: const core::Url&, relative_ref: const u8[:]) -> core::Url { return core::resolve_reference(base_url, relative_ref); }
inline fn parse_reference(base_url: const core::Url&, relative_ref: const u8[:]) -> core::Url, core::UrlParseError { return core::parse_reference(base_url, relative_ref); }
inline fn resolve_endpoint(base_url: const core::Url&, endpoint: const u8[:]) -> core::Url { return core::resolve_endpoint(base_url, endpoint); }
inline fn join_endpoint(base_url: const core::Url&, endpoint: const u8[:]) -> core::Url { return core::join_endpoint(base_url, endpoint); }
inline fn parse_endpoint(base_url: const core::Url&, endpoint: const u8[:]) -> core::Url, core::UrlParseError { return core::parse_endpoint(base_url, endpoint); }

inline fn parse_query_params(raw_search: const u8[:]) -> core::QueryParamsList { return core::parse_query_params(raw_search); }
inline fn get_query_param(list: const core::QueryParamsList&, key_str: const u8[:]) -> const u8[:] { return core::get_query_param(list, key_str); }
inline fn has_query_param(list: const core::QueryParamsList&, key_str: const u8[:]) -> bool { return core::has_query_param(list, key_str); }
inline fn parse_and_compress_ipv6<B>(raw_ipv6: const u8[:], out: B&) -> bool { return core::parse_and_compress_ipv6(raw_ipv6, out); }

// ============================================================================
// Compression Functions Re-export
// ============================================================================

fn compress_gzip<B>(src: const u8[:], out_buf: B&, level: i32 = 6) -> bool {
    return core::compress_gzip(src, out_buf, level);
}
fn compress_gzip_with_header<B>(
    src: const u8[:],
    out_buf: B&,
    level: i32 = 6,
    filename: const u8[:] = "",
    comment: const u8[:] = "",
    include_fhcrc: bool = false
) -> bool {
    return core::compress_gzip_with_header(src, out_buf, level, filename, comment, include_fhcrc);
}
fn decompress_gzip<B>(in_buf: const u8[:], out_buf: B&) -> bool, core::CompressError {
    return core::decompress_gzip(in_buf, out_buf);
}
fn decompress_gzip_with_limit<B>(in_buf: const u8[:], out_buf: B&, max_output_bytes: i64) -> bool, core::CompressError {
    return core::decompress_gzip_with_limit(in_buf, out_buf, max_output_bytes);
}

fn compress_zlib<B>(src: const u8[:], out_buf: B&, level: i32 = 6) -> bool {
    return core::compress_zlib(src, out_buf, level);
}
fn compress_zlib_dict<B>(src: const u8[:], out_buf: B&, level: i32 = 6, dict: const u8[:] = "") -> bool {
    return core::compress_zlib_dict(src, out_buf, level, dict);
}
fn decompress_zlib<B>(in_buf: const u8[:], out_buf: B&) -> bool, core::CompressError {
    return core::decompress_zlib(in_buf, out_buf);
}
fn decompress_zlib_with_limit<B>(in_buf: const u8[:], out_buf: B&, max_output_bytes: i64) -> bool, core::CompressError {
    return core::decompress_zlib_with_limit(in_buf, out_buf, max_output_bytes);
}
fn decompress_zlib_dict<B>(in_buf: const u8[:], out_buf: B&, dict: const u8[:] = "") -> bool, core::CompressError {
    return core::decompress_zlib_dict(in_buf, out_buf, dict);
}

fn compress_deflate<B>(src: const u8[:], out_buf: B&, level: i32 = 6) -> bool {
    return core::compress_deflate(src, out_buf, level);
}
fn compress_deflate_dict<B>(src: const u8[:], out_buf: B&, level: i32 = 6, dict: const u8[:] = "") -> bool {
    return core::compress_deflate_dict(src, out_buf, level, dict);
}
fn decompress_deflate<B>(in_buf: const u8[:], out_buf: B&) -> bool, core::CompressError {
    return core::decompress_deflate(in_buf, out_buf);
}
fn decompress_deflate_with_limit<B>(in_buf: const u8[:], out_buf: B&, max_output_bytes: i64) -> bool, core::CompressError {
    return core::decompress_deflate_with_limit(in_buf, out_buf, max_output_bytes);
}
fn decompress_deflate_dict<B>(in_buf: const u8[:], out_buf: B&, dict: const u8[:] = "") -> bool, core::CompressError {
    return core::decompress_deflate_dict(in_buf, out_buf, dict);
}

fn compress_zstd<B>(src: const u8[:], out_buf: B&, include_checksum: bool = true) -> bool {
    return core::compress_zstd(src, out_buf, include_checksum);
}
fn decompress_zstd<B>(in_buf: const u8[:], out_buf: B&) -> bool, core::CompressError {
    return core::decompress_zstd(in_buf, out_buf);
}
fn decompress_zstd_with_limit<B>(in_buf: const u8[:], out_buf: B&, max_output_bytes: i64) -> bool, core::CompressError {
    return core::decompress_zstd_with_limit(in_buf, out_buf, max_output_bytes);
}

inline fn detect_container_format(src: const u8[:]) -> core::ContainerFormat {
    return core::detect_container_format(src);
}
fn decompress_auto<B>(src: const u8[:], out_buf: B&, dict: const u8[:] = "") -> core::CompressError {
    return core::decompress_auto(src, out_buf, dict);
}
fn decompress<B>(in_buf: const u8[:], out_buf: B&, dict: const u8[:] = "") -> bool, core::CompressError {
    return core::decompress(in_buf, out_buf, dict);
}

inline fn crc32(buf: const u8[:]) -> u32 { return core::crc32(buf); }
inline fn crc32_update(initial: u32, buf: const u8[:]) -> u32 { return core::crc32_update(initial, buf); }
inline fn adler32(buf: const u8[:]) -> u32 { return core::adler32(buf); }
inline fn adler32_update(initial: u32, buf: const u8[:]) -> u32 { return core::adler32_update(initial, buf); }
inline fn xxh64(buf: const u8[:], seed: u64 = 0) -> u64 { return core::xxh64(buf, seed); }
inline fn xxh64_digest_32(buf: const u8[:]) -> u32 { return core::xxh64_digest_32(buf); }

inline fn new_zstream_compressor(format: core::ContainerFormat = core::ContainerFormat.Raw, level: i32 = 6) -> core::ZStreamCompressor {
    return core::new_zstream_compressor(format, level);
}
inline fn new_zstream_decompressor(format: core::ContainerFormat = core::ContainerFormat.Auto, dict: const u8[:] = "") -> core::ZStreamDecompressor {
    return core::new_zstream_decompressor(format, dict);
}
fn zstream_decompress_write_limit<B>(d: core::ZStreamDecompressor&, chunk: const u8[:], out: B&, max_output_bytes: i64 = 0) -> core::CompressError {
    return core::zstream_decompress_write_limit(d, chunk, out, max_output_bytes);
}
fn zstream_decompress_write<B>(d: core::ZStreamDecompressor&, chunk: const u8[:], out: B&) -> core::CompressError {
    return core::zstream_decompress_write(d, chunk, out);
}

// ============================================================================
// Concurrency & Sync Functions Re-export
// ============================================================================

inline fn new_semaphore(capacity: i64) -> core::Semaphore { return core::new_semaphore(capacity); }
inline fn new_wait_group() -> core::WaitGroup { return core::new_wait_group(); }
inline fn new_count_down_latch(expected: i64) -> core::CountDownLatch { return core::new_count_down_latch(expected); }
inline fn new_reassembler(initial_seq: i64 = 0) -> core::Reassembler { return core::new_reassembler(initial_seq); }
inline fn new_actor_ref(actor_id: u32, generation: u32 = 1, node_id: u32 = 0, mailbox_tag: u32 = 0) -> core::ActorRef {
    return core::new_actor_ref(actor_id, generation, node_id, mailbox_tag);
}
inline fn eq_actor_ref(a: const core::ActorRef&, b: const core::ActorRef&) -> bool {
    return core::eq_actor_ref(a, b);
}
inline fn new_stash_buffer() -> core::StashBuffer { return core::new_stash_buffer(); }
inline fn new_priority_mailbox() -> core::PriorityMailbox { return core::new_priority_mailbox(); }
inline fn new_supervisor() -> core::Supervisor { return core::new_supervisor(); }
inline fn new_supervisor(spec: core::SupervisorSpec) -> core::Supervisor { return core::new_supervisor(spec); }
inline fn new_singleflight_group() -> core::SingleflightGroup { return core::new_singleflight_group(); }
inline fn start_or_join(g: core::SingleflightGroup&, key_str: const u8[:]) -> bool, i64, bool { return core::start_or_join(g, key_str); }
inline fn finish_call(g: core::SingleflightGroup&, key_str: const u8[:], val: i64, ok: bool = true) -> bool, i32 { return core::finish_call(g, key_str, val, ok); }
inline fn forget(g: core::SingleflightGroup&, key_str: const u8[:]) -> bool { return core::forget(g, key_str); }
inline fn forget_unshared(g: core::SingleflightGroup&, key_str: const u8[:]) -> bool { return core::forget_unshared(g, key_str); }
inline fn is_in_flight(g: const core::SingleflightGroup&, key_str: const u8[:]) -> bool { return core::is_in_flight(g, key_str); }
inline fn waiter_count(g: const core::SingleflightGroup&, key_str: const u8[:]) -> i32 { return core::waiter_count(g, key_str); }
inline fn is_shared(g: const core::SingleflightGroup&, key_str: const u8[:]) -> bool { return core::is_shared(g, key_str); }
inline fn result_value(g: const core::SingleflightGroup&, key_str: const u8[:]) -> i64, bool { return core::result_value(g, key_str); }
inline fn available_parallelism() -> i64 { return core::available_parallelism(); }

inline fn set_channel_limit<T>(limit: i64) -> bool { return core::set_channel_limit<T>(limit); }
inline fn send_msg<T>(msg: T) -> bool { return core::send_msg<T>(msg); }
inline fn recv_msg<T>() -> T { return core::recv_msg<T>(); }
inline fn recv_msg_timeout<T>(timeout_ms: i64) -> T, bool { return core::recv_msg_timeout<T>(timeout_ms); }
inline fn try_recv_msg<T>() -> T, bool { return core::try_recv_msg<T>(); }

inline fn new_baton_mutex<T>(initial_val: T) { core::new_baton_mutex<T>(initial_val); }
inline fn baton_lock<T>() -> T { return core::baton_lock<T>(); }
inline fn baton_unlock<T>(val: T) -> bool { return core::baton_unlock<T>(val); }

inline fn barrier_start(n_participants: i32) -> i64 { return core::barrier_start(n_participants); }
inline fn barrier_sync(worker_id: i32, local_epoch: u64) -> u64 { return core::barrier_sync(worker_id, local_epoch); }
inline fn barrier_stop() { core::barrier_stop(); }

inline fn chan_recv<Tag, T>() -> T { return core::chan_recv<Tag, T>(); }
inline fn chan_rendezvous<Tag, Req>(req: Req) -> bool { return core::chan_rendezvous<Tag, Req>(req); }
inline fn chan_rendezvous_reply<Tag>(ok: bool = true) -> bool { return core::chan_rendezvous_reply<Tag>(ok); }
