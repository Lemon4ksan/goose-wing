// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// QUIC Congestion Control: BBRv2/v3, CUBIC & User-Space Leaky Bucket Pacer.
// Implements 7-state BBR FSM (draft-ietf-ccwg-bbr-06), dual-envelope [inflight_lo, inflight_hi],
// 2% loss threshold, DCTCP/L4S ECN, 5s ProbeRTT, RFC 9438 CUBIC with app-limited freeze,
// and picoquic-style user-space leaky-bucket pacing.
namespace internal;

import std;

// ---- 1. integer math helpers & cube root ------------------------------------

// Computes floor(cbrt(val)) using integer binary search up to 2,642,245.
fn int_cbrt(val: u64) -> u64 {
    guard val > 0 else { return 0; }
    var low: u64 = 1;
    var high: u64 = 2642245; // 2_642_245^3 = 18_446_742_000_000_000_000 <= u64::MAX
    var ans: u64 = 1;

    while low <= high {
        let mid = (low + high) / 2;
        let sq = mid * mid;
        if sq <= (0xFFFFFFFFFFFFFFFF / mid) && (sq * mid) <= val {
            ans = mid;
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }
    return ans;
}

// ---- 2. user-space leaky bucket pacer (picoquic model) ----------------------

struct Pacer {
    pacing_rate_bps: u64 = 10000000, // 10 Mbps initial default
    bucket_balance_us: i64 = 0,
    last_pacing_time_us: u64 = 0,
    burst_allowance_us: i64 = 20000,     // 20 ms max burst allowance
}

fn new_pacer(initial_rate_bps: u64 = 10000000) -> Pacer {
    return Pacer {
        pacing_rate_bps: if initial_rate_bps > 0 { initial_rate_bps } else { 10000000 },
        ..
    };
}

// Sets current pacing rate, enforcing a 64 kbps safety floor.
fn pacer_set_rate(pacer: Pacer&, rate_bps: u64) {
    pacer.pacing_rate_bps = if rate_bps >= 64000 { rate_bps } else { 64000 };
}

// Queries whether pacer permits transmitting packet_bytes at now_us, updating token bucket.
fn pacer_can_send(pacer: Pacer&, now_us: u64, packet_bytes: u64) -> bool, u64 {
    let dur_us = (packet_bytes * 8 * 1000000) / pacer.pacing_rate_bps;
    if pacer.last_pacing_time_us == 0 {
        pacer.last_pacing_time_us = now_us;
        pacer.bucket_balance_us = -(dur_us as i64);
        return true, 0;
    }

    let elapsed = (now_us - pacer.last_pacing_time_us) as i64;
    pacer.last_pacing_time_us = now_us;
    pacer.bucket_balance_us += elapsed;
    if pacer.bucket_balance_us > pacer.burst_allowance_us {
        pacer.bucket_balance_us = pacer.burst_allowance_us;
    }

    if pacer.bucket_balance_us >= 0 {
        pacer.bucket_balance_us -= (dur_us as i64);
        return true, 0;
    }

    let delay_us = (-pacer.bucket_balance_us) as u64;
    return false, delay_us;
}

// ---- 3. bbrv2 / bbrv3 state machine (draft-ietf-ccwg-bbr-06) ----------------

enum BbrMode {
    Startup,
    Drain,
    ProbeBwDown,
    ProbeBwCruise,
    ProbeBwRefill,
    ProbeBwUp,
    ProbeRtt,
}

const BBR_BETA_NUM: u64 = 70;    // 0.7 inflight reduction on congestion
const BBR_BETA_DENOM: u64 = 100;
const BBR_MIN_CWND_BYTES: u64 = 4 * 1200; // 4 * MSS

struct BbrState {
    mode: BbrMode = BbrMode.Startup,
    pacer: Pacer = Pacer {},
    cwnd_bytes: u64 = 10 * 1200, // Initial cwnd (RFC 9002 Sec 7.2)
    bw_hi_bps: u64 = 0,
    bw_lo_bps: u64 = 0,
    inflight_hi_bytes: u64 = 0xFFFFFFFFFFFFFFFF,
    inflight_lo_bytes: u64 = 0xFFFFFFFFFFFFFFFF,
    min_rtt_us: u64 = 0xFFFFFFFFFFFFFFFF,
    min_rtt_stamp_us: u64 = 0,
    probe_rtt_done_stamp_us: u64 = 0,
    probe_rtt_round_done: bool = false,
    cycle_index: u8 = 0,
    ecn_alpha_scaled: u64 = 0, // EWMA scaled by 1024
    app_limited: bool = false,
}

fn new_bbr_state() -> BbrState {
    return BbrState {
        pacer: new_pacer(10000000),
        ..
    };
}

// Computes Bandwidth-Delay Product (BDP) in bytes.
fn bbr_bdp(bw_bps: u64, min_rtt_us: u64) -> u64 {
    guard min_rtt_us > 0 && min_rtt_us != 0xFFFFFFFFFFFFFFFF else { return 10 * 1200; }
    return (bw_bps * min_rtt_us) / (8 * 1000000);
}

// Updates min_rtt tracking and triggers 5-second ProbeRTT transition.
fn bbr_check_probe_rtt(bbr: BbrState&, now_us: u64, rtt_sample_us: u64) {
    if rtt_sample_us < bbr.min_rtt_us {
        bbr.min_rtt_us = rtt_sample_us;
        bbr.min_rtt_stamp_us = now_us;
    }

    if bbr.mode == BbrMode.ProbeRtt {
        if bbr.probe_rtt_done_stamp_us != 0 && now_us >= bbr.probe_rtt_done_stamp_us {
            bbr.min_rtt_stamp_us = now_us;
            bbr.mode = BbrMode.ProbeBwCruise;
            bbr_update_pacing_and_cwnd(bbr);
        }
        return;
    }

    // 5-second ProbeRTT filter expiration check
    if bbr.min_rtt_stamp_us != 0 && (now_us - bbr.min_rtt_stamp_us) >= 5000000 {
        bbr.mode = BbrMode.ProbeRtt;
        bbr.probe_rtt_done_stamp_us = now_us + 200000; // Hold ProbeRTT for 200 ms
        let bdp = bbr_bdp(bbr.bw_hi_bps, bbr.min_rtt_us);
        let probe_target = (bdp * 50) / 100; // 0.5 BDP floor
        bbr.cwnd_bytes = if probe_target > BBR_MIN_CWND_BYTES { probe_target } else { BBR_MIN_CWND_BYTES };
    }
}

// Updates pacing rate and cwnd according to active BBR state.
fn bbr_update_pacing_and_cwnd(bbr: BbrState&) {
    let eff_bw = if bbr.bw_hi_bps > 0 { bbr.bw_hi_bps } else { 10000000 };
    var gain_num: u64 = 1000;
    var gain_denom: u64 = 1000;

    match bbr.mode {
        Startup => {
            gain_num = 2885; // 2.885
            gain_denom = 1000;
        },
        Drain => {
            gain_num = 1000;
            gain_denom = 2885;
        },
        ProbeBwDown => {
            gain_num = 750;  // 0.75
            gain_denom = 1000;
        },
        ProbeBwCruise => {
            gain_num = 1000; // 1.00
            gain_denom = 1000;
        },
        ProbeBwRefill => {
            gain_num = 1000; // 1.00
            gain_denom = 1000;
        },
        ProbeBwUp => {
            gain_num = 1250; // 1.25
            gain_denom = 1000;
        },
        ProbeRtt => {
            gain_num = 1000;
            gain_denom = 1000;
        },
        _ => {},
    }

    let pacing_bps = (eff_bw * gain_num) / gain_denom;
    pacer_set_rate(bbr.pacer, pacing_bps);

    if bbr.mode != BbrMode.ProbeRtt {
        let bdp = bbr_bdp(eff_bw, bbr.min_rtt_us);
        let target_cwnd = (bdp * 2); // 2 * BDP headroom
        var cwnd = if target_cwnd > BBR_MIN_CWND_BYTES { target_cwnd } else { BBR_MIN_CWND_BYTES };
        if bbr.inflight_hi_bytes > 0 && cwnd > bbr.inflight_hi_bytes {
            cwnd = if bbr.inflight_hi_bytes > BBR_MIN_CWND_BYTES { bbr.inflight_hi_bytes } else { BBR_MIN_CWND_BYTES };
        }
        bbr.cwnd_bytes = cwnd;
    }
}

// Handles packet loss (> 2%) and DCTCP/L4S ECN congestion signals.
fn bbr_on_congestion_signal(
    bbr: BbrState&,
    bytes_in_flight: u64,
    loss_bytes: u64,
    total_acked_bytes: u64,
    ecn_ce_count: u64,
    new_acked_packets: u64,
) {
    var has_loss_signal = false;
    if total_acked_bytes > 0 && (loss_bytes * 100) > (total_acked_bytes * 2) {
        has_loss_signal = true; // Loss rate exceeded 2% threshold
    }

    var has_ecn_signal = false;
    if new_acked_packets > 0 && ecn_ce_count > 0 {
        has_ecn_signal = true;
        // DCTCP/L4S EWMA: alpha = (15 * alpha + (ce_packets * 1024 / acked)) / 16
        let frac = (ecn_ce_count * 1024) / new_acked_packets;
        bbr.ecn_alpha_scaled = (bbr.ecn_alpha_scaled * 15 + frac) / 16;
        let ecn_cut = (bbr.ecn_alpha_scaled / 2); // alpha / 2
        let mult = if ecn_cut < 1024 { 1024 - ecn_cut } else { 512 };
        bbr.cwnd_bytes = (bbr.cwnd_bytes * mult) / 1024;
    }

    if has_loss_signal {
        bbr.inflight_hi_bytes = (bytes_in_flight * BBR_BETA_NUM) / BBR_BETA_DENOM;
        bbr.bw_lo_bps = (bbr.bw_hi_bps * BBR_BETA_NUM) / BBR_BETA_DENOM;
        if bbr.mode == BbrMode.ProbeBwCruise || bbr.mode == BbrMode.ProbeBwUp {
            bbr.mode = BbrMode.ProbeBwDown;
        }
    }
}

// Advances BBR cycle phase transitions.
fn bbr_advance_cycle(bbr: BbrState&, round_done: bool) {
    guard round_done else { return; }
    match bbr.mode {
        Startup => {
            bbr.mode = BbrMode.Drain;
        },
        Drain => {
            bbr.mode = BbrMode.ProbeBwCruise;
        },
        ProbeBwDown => {
            bbr.mode = BbrMode.ProbeBwCruise;
        },
        ProbeBwCruise => {
            bbr.mode = BbrMode.ProbeBwRefill;
        },
        ProbeBwRefill => {
            bbr.mode = BbrMode.ProbeBwUp;
        },
        ProbeBwUp => {
            bbr.mode = BbrMode.ProbeBwDown;
        },
        _ => {},
    }
    bbr_update_pacing_and_cwnd(bbr);
}

// ---- 4. cubic congestion control (rfc 9438) & app-limited freeze -------------

struct CubicState {
    cwnd_segments: u64 = 10,
    w_max_segments: u64 = 10,
    epoch_start_us: u64 = 0,
    k_ms: u64 = 0,
    app_limited: bool = false,
    last_update_us: u64 = 0,
}

// Computes K = cbrt(w_max * beta / C) in milliseconds (RFC 9438 Section 4.1).
fn cubic_compute_k(w_max: u64) -> u64 {
    // K = cbrt((w_max * (1 - 0.7)) / 0.4) = cbrt((w_max * 3) / 4)
    // Multiplied by 10^9 before cbrt to obtain millisecond precision
    let w_diff = (w_max * 3) / 4;
    return int_cbrt(w_diff * 1000000000);
}

// Updates CUBIC window with app-limited freeze (draft-ietf-ccwg-ratelimited-increase-11).
fn cubic_on_ack(
    cubic: CubicState&,
    now_us: u64,
    rtt_us: u64,
    bytes_in_flight: u64,
    mss_bytes: u64 = 1200,
) -> u64 {
    let cur_cwnd_bytes = cubic.cwnd_segments * mss_bytes;
    // App-limited check: pipe utilization < 75%
    if bytes_in_flight < (cur_cwnd_bytes * 3) / 4 {
        cubic.app_limited = true;
        if cubic.last_update_us != 0 && now_us > cubic.last_update_us {
            let elapsed_idle = now_us - cubic.last_update_us;
            cubic.epoch_start_us += elapsed_idle; // Freeze growth epoch
        }
        cubic.last_update_us = now_us;
        return cur_cwnd_bytes;
    }
    cubic.app_limited = false;

    if cubic.epoch_start_us == 0 {
        cubic.epoch_start_us = now_us;
        cubic.k_ms = cubic_compute_k(cubic.w_max_segments);
    }

    let t_ms = (now_us - cubic.epoch_start_us) / 1000;
    var w_cubic: u64 = cubic.w_max_segments;

    let diff_ms = if t_ms < cubic.k_ms { cubic.k_ms - t_ms } else { t_ms - cubic.k_ms };
    var delta: u64 = 0;
    if diff_ms <= 1664000 {
        let d3 = diff_ms * diff_ms * diff_ms;
        delta = (4 * d3) / 10000000000;
    } else {
        let diff_sec = diff_ms / 1000;
        delta = (4 * diff_sec * diff_sec * diff_sec) / 10;
    }

    if t_ms < cubic.k_ms {
        if cubic.w_max_segments > delta {
            w_cubic = cubic.w_max_segments - delta;
        } else {
            w_cubic = 1;
        }
    } else {
        w_cubic = cubic.w_max_segments + delta;
    }

    // Reno-friendly region calculation: W_est(t) = W_max * 0.7 + (9/17) * (t / RTT)
    let rtt_ms = if rtt_us >= 1000 { rtt_us / 1000 } else { 1 };
    let reno_inc = (9 * t_ms) / (17 * rtt_ms);
    let w_est = ((cubic.w_max_segments * 7) / 10) + reno_inc;

    let target_segments = if w_cubic > w_est { w_cubic } else { w_est };
    cubic.cwnd_segments = if target_segments > 2 { target_segments } else { 2 };
    cubic.last_update_us = now_us;
    return cubic.cwnd_segments * mss_bytes;
}

// Multiplicative decrease upon congestion signal (RFC 9438 Section 4.3).
fn cubic_on_loss(cubic: CubicState&, now_us: u64) {
    cubic.w_max_segments = cubic.cwnd_segments;
    cubic.cwnd_segments = (cubic.cwnd_segments * 7) / 10; // beta = 0.7
    if cubic.cwnd_segments < 2 {
        cubic.cwnd_segments = 2;
    }
    cubic.epoch_start_us = now_us;
    cubic.k_ms = cubic_compute_k(cubic.w_max_segments);
    cubic.last_update_us = now_us;
}
