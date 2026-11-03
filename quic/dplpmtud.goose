// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Datagram Packetization Layer PMTU Discovery (DPLPMTUD, RFC 8899) Engine for QUIC.
// Implements zero-allocation state machine (Search, Base, SearchComplete, Error),
// padded probe frame generation, probe acknowledgement tracking, and search interval timers.
namespace internal;

import std;
import core from "..";
import .packet;
import .frames;

// ---- PMTU Constants & Discovery State Enum (RFC 8899 Section 5.1) -------

// RFC 8899 Section 5.1: State Machine - DPLPMTUD state machine states
enum DplpmtudState {
    Search,
    Base,
    SearchComplete,
    Error,
}

// RFC 9000 Section 14.1: Minimum Datagram Size - Baseline PMTU
// IPv4 (20) + UDP (8) + QUIC 1-RTT Short Header (~5) + AEAD Tag (16) ~= 49 bytes.
// IPv6 (40) + UDP (8) + QUIC 1-RTT Short Header (~5) + AEAD Tag (16) ~= 69 bytes.
const DPLPMTUD_OVERHEAD_IPV4: u32 = 49;
const DPLPMTUD_OVERHEAD_IPV6: u32 = 69;

// Calculates maximum probe payload bytes given target link MTU and header encapsulation overhead.
inline fn calc_dplpmtud_probe_payload_size(target_mtu: u32, overhead_bytes: u32) -> u32 {
    if target_mtu > overhead_bytes {
        return target_mtu - overhead_bytes;
    }
    return target_mtu;
}

const CANDIDATE_PMTU_COUNT: u32 = 4;

// RFC 8899 Section 5.1.2: The Searching State - Table of candidate PMTU probe sizes
inline fn get_candidate_pmtu(idx: u32) -> u32 {
    if idx == 0 { return rfc::PMTU_BASE; }
    if idx == 1 { return rfc::PMTU_IPV6_MIN; }
    if idx == 2 { return rfc::PMTU_INTERMEDIATE; }
    return rfc::PMTU_ETHERNET;
}

// ---- Probe Frame Generators (RFC 8899 Section 3) ------------------------

// RFC 8899 Section 3: Probe Packets - Generates padded PING probe frame
//
// Example:
//   target_size = 1200
//   out: appends 1 byte PING (0x01) followed by 1199 bytes PADDING (0x00)
fn generate_ping_probe<B>(out: B&, target_size: u32) -> bool {
    guard target_size >= 1 else { return false; }
    guard encode_ping_frame(out) else { return false; }
    let pad_count = (target_size - 1) as u64;
    return encode_padding_frame(out, pad_count);
}

// RFC 8899 Section 3: Probe Packets - Generates padded PATH_CHALLENGE probe frame
//
// Example:
//   data = [1, 2, 3, 4, 5, 6, 7, 8], target_size = 1200
//   out: appends 9 bytes PATH_CHALLENGE followed by 1191 bytes PADDING
fn generate_path_challenge_probe<B>(out: B&, data: const u8[8]&, target_size: u32) -> bool {
    guard target_size >= 9 else { return false; }
    guard encode_path_challenge_frame(out, data) else { return false; }
    let pad_count = (target_size - 9) as u64;
    return encode_padding_frame(out, pad_count);
}

// ---- DPLPMTUD Controller & State Machine (RFC 8899 Section 5) -----------

// RFC 8899 Section 5.2: Timers and Counters - DPLPMTUD discovery controller
struct Dplpmtud {
    state: DplpmtudState = DplpmtudState.Base,
    // RFC 8899 Section 5.1: State Machine - Confirmed PMTU for current path
    current_pmtu: u32 = rfc::PMTU_BASE,
    // RFC 8899 Section 5.1: State Machine - Target size for next probe packet
    probed_size:        u32 = rfc::PMTU_BASE,
    probe_idx:          u32 = 0,
    probe_count:        u32 = 0,
    max_probes:         u32 = 3,
    search_timer_ms:    u64 = 0,
    search_interval_ms: u64 = 60000,
}

// RFC 8899 Section 5.1.2: The Searching State - Handles acknowledgement of probe
fn dplpmtud_on_probe_acked(d: Dplpmtud&, acked_size: u32) -> bool {
    guard acked_size == d.probed_size else { return false; }
    d.current_pmtu = acked_size;
    d.probe_count = 0;

    if d.state == DplpmtudState.Base {
        d.state = DplpmtudState.Search;
        d.probe_idx = 1;
        d.probed_size = get_candidate_pmtu(1);
        return true;
    }

    if d.state == DplpmtudState.Search {
        d.probe_idx += 1;
        if d.probe_idx < CANDIDATE_PMTU_COUNT {
            d.probed_size = get_candidate_pmtu(d.probe_idx);
        } else {
            d.state = DplpmtudState.SearchComplete;
        }
        return true;
    }

    return true;
}

// RFC 8899 Section 5.1.4: The Error State - Handles loss / timeout of probe packet
fn dplpmtud_on_probe_lost(d: Dplpmtud&, lost_size: u32) -> bool {
    guard lost_size == d.probed_size else { return false; }
    d.probe_count += 1;

    if d.probe_count >= d.max_probes {
        if d.state == DplpmtudState.Base {
            d.state = DplpmtudState.Error;
            return false;
        }
        if d.state == DplpmtudState.Search {
            d.state = DplpmtudState.SearchComplete;
            return false;
        }
    }
    return true;
}

// RFC 8899 Section 5.2: Timers and Counters - Periodic search timer expiry
fn dplpmtud_on_search_timer(d: Dplpmtud&, now_ms: u64) {
    guard d.state == DplpmtudState.SearchComplete else { return; }
    if now_ms >= d.search_timer_ms {
        d.search_timer_ms = now_ms + d.search_interval_ms;
        d.state = DplpmtudState.Search;
        d.probe_idx = 1;
        d.probe_count = 0;
        d.probed_size = get_candidate_pmtu(1);
    }
}
