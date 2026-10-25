// Specialized network protocol mathematics:
// Jacobson EWMA RTT estimation (RFC 6298 / RFC 9002 Errata ID 7539),
// Happy Eyeballs CAD pacing (RFC 8305), AWS backoff jitter, and SOCKS5 CT frame validation.
namespace core;

import std;
import core.math.ct;
import core.math.bits;
import core.math.arithmetic;
import core.math.random;

// Happy Eyeballs v2/v3 normative pacing constants (RFC 8305 / draft-ietf-happy-happyeyeballs-v3)
const HE_ABSOLUTE_MIN_DELAY_MS: i64       = 10;   // MUST NOT be less than 10ms
const HE_RECOMMENDED_MIN_DELAY_MS: i64    = 100;
const HE_DEFAULT_ATTEMPT_DELAY_MS: i64    = 250;
const HE_GO_FALLBACK_DELAY_MS: i64        = 300;
const HE_MAX_ATTEMPT_DELAY_MS: i64        = 2000;
const HE_LAST_RESORT_SYNTHESIS_MS: i64    = 2000;

// QUIC loss detection & congestion constants (RFC 9002)
const QUIC_INITIAL_RTT_US: u64            = 333000; // 333 ms
const QUIC_AGGRESSIVE_INITIAL_RTT_US: u64 = 100000; // 100 ms
const QUIC_TIMER_GRANULARITY_US: u64      = 1000;   // 1 ms
const QUIC_PACKET_THRESHOLD: u64          = 3;

// Converts seconds from RFC 9110 Retry-After header to milliseconds with saturation.
inline fn retry_after_sec_to_ms_sat(seconds: i64) -> i64 {
    let clamped_sec = ct_max_i64(seconds, 0) as! u64;
    let ms_u64 = mul_sat_u64(clamped_sec, 1000);
    let max_i64_u = I64_MAX as! u64;
    return ct_min_u64(ms_u64, max_i64_u) as! i64;
}

// Full Jitter backoff strategy: sleep = U(0, min(cap, base * 2^attempt)).
inline fn backoff_full_jitter_ms(rng: WyRand&, base_ms: u64, cap_ms: u64, attempt: u32) -> u64 {
    let exp_bound = shl_sat_u64(base_ms, attempt);
    let target = ct_min_u64(cap_ms, exp_bound);
    if target == 0 {
        return 0;
    }
    return fast_range_biased_u64(next_u64(rng), target + 1);
}

// Equal Jitter backoff strategy: sleep = target/2 + U(0, target/2).
inline fn backoff_equal_jitter_ms(rng: WyRand&, base_ms: u64, cap_ms: u64, attempt: u32) -> u64 {
    let exp_bound = shl_sat_u64(base_ms, attempt);
    let target = ct_min_u64(cap_ms, exp_bound);
    let half = target >> 1;
    let rnd = if half > 0 { fast_range_biased_u64(next_u64(rng), half + 1) } else { 0 };
    return half + rnd;
}

// Decorrelated Jitter strategy without clamping collapse: sleep = min(cap, U(base, prev * 3)).
inline fn backoff_decorrelated_jitter_ms(rng: WyRand&, base_ms: u64, cap_ms: u64, prev_sleep_ms: u64) -> u64 {
    let prev = ct_max_u64(prev_sleep_ms, base_ms);
    let mult = mul_sat_u64(prev, 3);
    let upper = ct_min_u64(cap_ms, mult);

    let span = sub_sat_u64(upper, base_ms);
    let rnd = if span > 0 { fast_range_biased_u64(next_u64(rng), span + 1) } else { 0 };
    return add_sat_u64(base_ms, rnd);
}

// Normalizes and clamps Happy Eyeballs Connection Attempt Delay (RFC 8305).
fn clamp_happy_eyeballs_delay_ms(candidate_delay_ms: i64, is_first_family: bool = false) -> i64 {
    let floor_ms = if is_first_family {
        HE_RECOMMENDED_MIN_DELAY_MS
    } else {
        HE_ABSOLUTE_MIN_DELAY_MS
    };
    return clamp_i64(candidate_delay_ms, floor_ms, HE_MAX_ATTEMPT_DELAY_MS);
}

// Scaled fixed-point Jacobson EWMA RTT estimator.
struct JacobsonRttEstimator {
    min_rtt_us: u64 = 0xFFFFFFFFFFFFFFFF,
    latest_rtt_us: u64 = 0,
    srtt_scaled: u64 = 0,   // 8 * smoothed_rtt (Q61.3)
    rttvar_scaled: u64 = 0, // 4 * rttvar       (Q62.2)
    has_sample: bool = false,
}

fn new_jacobson_rtt_estimator(initial_rtt_us: u64 = QUIC_INITIAL_RTT_US) -> JacobsonRttEstimator {
    return JacobsonRttEstimator {
        min_rtt_us: 0xFFFFFFFFFFFFFFFF,
        latest_rtt_us: 0,
        srtt_scaled: initial_rtt_us << 3,
        rttvar_scaled: initial_rtt_us << 1, // 4 * (initial_rtt / 2)
        has_sample: false,
    };
}

inline fn smoothed_rtt_us(est: const JacobsonRttEstimator&) -> u64 {
    return est.srtt_scaled >> 3;
}

inline fn rttvar_us(est: const JacobsonRttEstimator&) -> u64 {
    return est.rttvar_scaled >> 2;
}

inline fn bound_effective_ack_delay(ack_delay_us: u64, max_ack_delay_us: u64, handshake_confirmed: bool) -> u64 {
    if handshake_confirmed {
        return ct_min_u64(ack_delay_us, max_ack_delay_us);
    }
    return ack_delay_us;
}

inline fn calculate_defensive_adjusted_rtt(latest_rtt_us: u64, min_rtt_us: u64, effective_ack_delay: u64) -> u64 {
    let min_plus_delay = add_sat_u64(min_rtt_us, effective_ack_delay);
    let can_subtract_mask = ct_mask_u64(1 ^ ct_lt_u64(latest_rtt_us, min_plus_delay));
    return ct_select_u64(
        can_subtract_mask,
        latest_rtt_us - effective_ack_delay,
        latest_rtt_us
    );
}

// Ingestion of RTT sample strictly conforming to RFC 9002 Errata ID 7539.
fn on_rtt_sample(
    est: JacobsonRttEstimator&,
    latest_rtt_us: u64,
    ack_delay_us: u64,
    max_ack_delay_us: u64,
    handshake_confirmed: bool
) {
    if latest_rtt_us == 0 {
        return;
    }
    est.latest_rtt_us = latest_rtt_us;

    if !est.has_sample {
        est.min_rtt_us = latest_rtt_us;
        est.srtt_scaled = latest_rtt_us << 3;
        est.rttvar_scaled = latest_rtt_us << 1;
        est.has_sample = true;
        return;
    }

    est.min_rtt_us = ct_min_u64(est.min_rtt_us, latest_rtt_us);
    let effective_ack_delay = bound_effective_ack_delay(ack_delay_us, max_ack_delay_us, handshake_confirmed);
    let adjusted_rtt = calculate_defensive_adjusted_rtt(latest_rtt_us, est.min_rtt_us, effective_ack_delay);

    let prior_srtt = est.srtt_scaled >> 3;
    let abs_diff = ct_select_u64(
        ct_mask_u64(ct_lt_u64(prior_srtt, adjusted_rtt)),
        adjusted_rtt - prior_srtt,
        prior_srtt - adjusted_rtt
    );

    est.rttvar_scaled = (est.rttvar_scaled - (est.rttvar_scaled >> 2)) + abs_diff;
    est.srtt_scaled = (est.srtt_scaled - prior_srtt) + adjusted_rtt;
}

// Probe Timeout (PTO) computation for loss probe scheduling (RFC 9002 Section 5.3 / 6.2.1).
inline fn probe_timeout_us(est: const JacobsonRttEstimator&, max_ack_delay_us: u64 = 0) -> u64 {
    let srtt = est.srtt_scaled >> 3;
    let four_rttvar = est.rttvar_scaled; // 4 * rttvar is exactly rttvar_scaled
    let delay = ct_max_u64(four_rttvar, 4 * QUIC_TIMER_GRANULARITY_US);
    return srtt + delay + max_ack_delay_us;
}

// Packet loss time threshold computation (RFC 9002 Section 6.1.2).
inline fn loss_time_threshold_us(est: const JacobsonRttEstimator&) -> u64 {
    let srtt = est.srtt_scaled >> 3;
    let max_rtt = ct_max_u64(est.latest_rtt_us, srtt);
    let ratio_rtt = max_rtt + (max_rtt >> 3); // 9/8 * max_rtt
    return ct_max_u64(ratio_rtt, QUIC_TIMER_GRANULARITY_US);
}

// Branchless expected frame length calculation for SOCKS5 request/reply frames.
// Returns 0 if version is not 0x05 or ATYP is unrecognized, otherwise returns expected wire length.
fn socks5_expected_frame_len_ct(buf: const u8[:]) -> u32 {
    if buf.len < 5 {
        return 0;
    }
    let ver = buf[0] as u32;
    let atyp = buf[3] as u32;
    let domain_len = buf[4] as u32;

    let is_v5_mask = ct_mask_u32(ct_eq_u32(ver, 0x05));
    let m_ipv4   = ct_mask_u32(ct_eq_u32(atyp, 0x01));
    let m_domain = ct_mask_u32(ct_eq_u32(atyp, 0x03));
    let m_ipv6   = ct_mask_u32(ct_eq_u32(atyp, 0x04));

    // Domain name must contain 1..255 characters
    let valid_domain_mask = m_domain & (~ct_mask_u32(ct_is_zero_u32(domain_len)));

    let len_ipv4: u32   = 10;                 // 4 header + 4 IPv4 + 2 port
    let len_domain: u32 = 7 + domain_len;     // 4 header + 1 len + domain + 2 port
    let len_ipv6: u32   = 22;                 // 4 header + 16 IPv6 + 2 port

    let selected_len = (m_ipv4 & len_ipv4) |
                       (valid_domain_mask & len_domain) |
                       (m_ipv6 & len_ipv6);

    return selected_len & is_v5_mask;
}
