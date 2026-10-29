// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Happy Eyeballs v2 (RFC 8305) and v3 connection racing, DNS resolution delay,
// CAD pacing with absolute floor, candidate interleaving, and Chromium AttemptManager coordination.
namespace wing;

import std;
import core from "..";

// ---- 1. RFC 8305 and HEv3 normative constants ------------------------------

const HE_RESOLUTION_DELAY_MS: i64 = 50;              // 50 ms DNS resolution delay (RD)
const HE_FIRST_ADDRESS_FAMILY_COUNT: i32 = 1;        // Step for address family interleaving
const HE_DEFAULT_CAD_MS: i64 = 250;                  // 250 ms default Connection Attempt Delay
const HE_MIN_CAD_MS: i64 = 100;                      // 100 ms recommended minimum dynamic CAD
const HE_ABSOLUTE_FLOOR_CAD_MS: i64 = 10;            // Strict absolute floor (>= 10 ms to prevent congestion collapse)
const HE_MAX_CAD_MS: i64 = 2000;                     // 2000 ms maximum CAD
const HE_LAST_RESORT_SYNTHESIS_DELAY_MS: i64 = 2000; // 2000 ms Last Resort Local Synthesis Delay
const HE_ADDRESS_FAMILY_CACHE_TTL_SEC: i64 = 600;    // 600 seconds (10 minutes) winner cache TTL

// Computes Connection Attempt Delay (CAD) strictly enforcing the >= 10 ms absolute floor.
fn compute_effective_cad_ms(
    observed_rtt_ms: i64,
    rtt_known: bool,
    min_cad_ms: i64 = HE_MIN_CAD_MS,
    max_cad_ms: i64 = HE_MAX_CAD_MS,
) -> i64 {
    let eff_min = core::ct_max_i64(min_cad_ms, HE_ABSOLUTE_FLOOR_CAD_MS);
    let eff_max = core::ct_max_i64(max_cad_ms, eff_min);

    if !rtt_known {
        return HE_DEFAULT_CAD_MS;
    }

    let clamped = core::clamp_i64(observed_rtt_ms, eff_min, eff_max);
    return core::ct_max_i64(clamped, HE_ABSOLUTE_FLOOR_CAD_MS);
}

// ---- 2. DNS query models and candidate classification ----------------------

enum AddressFamily {
    IPv6,
    IPv4,
}

enum L4Protocol {
    Tcp,
    QuicUdp,
}

enum DnsQueryStatus {
    Pending,
    InFlight,
    Success,
    Negative,
    Failed,
}

enum SvcbMode {
    None,
    AliasMode,
    ServiceMode,
}

// Metadata parsed from HTTPS/SVCB DNS resource records.
struct ConnectionEndpointMetadata {
    mode: SvcbMode = SvcbMode.None,
    alias_target: u8[..256] = [],
    target_name: u8[..256] = [],
    alpn_h3: bool = false,
    alpn_h2: bool = false,
    ech_config_present: bool = false,
    ipv6_hints: u8[..64][..4] = [],
    ipv4_hints: u8[..64][..4] = [],
}

struct DnsCandidate {
    family: AddressFamily = AddressFamily.IPv6,
    l4_proto: L4Protocol = L4Protocol.Tcp,
    ip: u8[..64] = [],
    port: u16 = 80,
    scope_id: i32 = 0,
    precedence: i32 = 40,
}

fn new_dns_candidate(
    fam: AddressFamily,
    ip_str: const u8[:],
    port_num: u16,
    proto: L4Protocol = L4Protocol.Tcp,
    prec: i32 = 40,
) -> DnsCandidate {
    var c = DnsCandidate {
        family: fam,
        l4_proto: proto,
        port: port_num,
        precedence: prec,
        ..
    };
    c.ip.append(ip_str);
    return c;
}

// ---- 3. RFC 6724 sorting & address interleaving ----------------------------

// Interleaves candidate addresses enforcing First Address Family Count = 1 (IPv6_1 -> IPv4_1 -> IPv6_2 -> IPv4_2).
fn interleave_candidates_he(
    ipv6_list: const DnsCandidate[:],
    ipv4_list: const DnsCandidate[:],
    out: DnsCandidate[..32]&,
    first_family_count: i32 = HE_FIRST_ADDRESS_FAMILY_COUNT,
) {
    out.clear();
    var idx6: i64 = 0;
    var idx4: i64 = 0;

    // First, emit first_family_count from preferred family (IPv6)
    var initial_count = 0;
    while idx6 < ipv6_list.len && initial_count < first_family_count {
        if out.len < 32 { out.push(copy(ipv6_list[idx6])); }
        idx6++;
        initial_count++;
    }

    // Interleave remaining 1-by-1
    while (idx6 < ipv6_list.len || idx4 < ipv4_list.len) && out.len < 32 {
        if idx4 < ipv4_list.len && out.len < 32 {
            out.push(copy(ipv4_list[idx4]));
            idx4++;
        }
        if idx6 < ipv6_list.len && out.len < 32 {
            out.push(copy(ipv6_list[idx6]));
            idx6++;
        }
    }
}

// Interleaves transport protocols (HEv3 QUIC/UDP vs TCP) so UDP firewalls do not block TCP.
fn interleave_protocols_hev3(candidates: const DnsCandidate[:], out: DnsCandidate[..32]&) {
    out.clear();
    for &cand in candidates {
        // Emit QUIC attempt first
        if out.len < 32 {
            var quic_c = copy(cand);
            quic_c.l4_proto = L4Protocol.QuicUdp;
            out.push(quic_c);
        }
        // Emit TCP fallback attempt
        if out.len < 32 {
            var tcp_c = copy(cand);
            tcp_c.l4_proto = L4Protocol.Tcp;
            out.push(tcp_c);
        }
    }
}

// ---- 4. Phase 1: DNS race task & 50 ms Resolution Delay (RD) ---------------

struct DnsRaceTask {
    aaaa_status: DnsQueryStatus = DnsQueryStatus.Pending,
    a_status: DnsQueryStatus = DnsQueryStatus.Pending,
    https_status: DnsQueryStatus = DnsQueryStatus.Pending,
    rd_timer_armed: bool = false,
    rd_deadline_ms: i64 = 0,
    ipv6_candidates: DnsCandidate[..8] = [],
    ipv4_candidates: DnsCandidate[..8] = [],
    metadata: ConnectionEndpointMetadata = ConnectionEndpointMetadata { .. },
    ready_to_connect: bool = false,
}

fn new_dns_race_task() -> DnsRaceTask {
    return DnsRaceTask {
        aaaa_status: DnsQueryStatus.InFlight,
        a_status: DnsQueryStatus.InFlight,
        https_status: DnsQueryStatus.InFlight,
        ..
    };
}

// Handles incoming AAAA response, cancelling RD timer if positive.
fn on_dns_aaaa_response(task: DnsRaceTask&, ips: const u8[:][:], now_ms: i64) {
    if ips.len > 0 {
        task.aaaa_status = DnsQueryStatus.Success;
        task.ipv6_candidates.clear();
        for ip in ips {
            if task.ipv6_candidates.len < 8 {
                task.ipv6_candidates.push(new_dns_candidate(AddressFamily.IPv6, ip, 443, L4Protocol.Tcp, 50));
            }
        }
        // Asymmetric IPv6 Priority: cancel RD timer immediately
        task.rd_timer_armed = false;
        task.ready_to_connect = true;
    } else {
        task.aaaa_status = DnsQueryStatus.Negative;
        // If A already succeeded, negative AAAA immediately unblocks IPv4
        if task.a_status == DnsQueryStatus.Success {
            task.rd_timer_armed = false;
            task.ready_to_connect = true;
        }
    }
}

// Handles incoming A response: if A arrives first, arms 50 ms RD timer.
fn on_dns_a_response(task: DnsRaceTask&, ips: const u8[:][:], now_ms: i64) {
    if ips.len > 0 {
        task.a_status = DnsQueryStatus.Success;
        task.ipv4_candidates.clear();
        for ip in ips {
            if task.ipv4_candidates.len < 8 {
                task.ipv4_candidates.push(new_dns_candidate(AddressFamily.IPv4, ip, 443, L4Protocol.Tcp, 40));
            }
        }

        // If AAAA already arrived, we are ready to connect
        if task.aaaa_status == DnsQueryStatus.Success || task.aaaa_status == DnsQueryStatus.Negative {
            task.ready_to_connect = true;
        } else {
            // A arrived first! Arm Resolution Delay (RD = 50 ms) to wait for AAAA
            task.rd_timer_armed = true;
            task.rd_deadline_ms = now_ms + HE_RESOLUTION_DELAY_MS;
        }
    } else {
        task.a_status = DnsQueryStatus.Negative;
    }
}

// Checks RD timer expiration. If 50 ms elapsed without AAAA, unblocks IPv4.
fn check_dns_resolution_delay_tick(task: DnsRaceTask&, now_ms: i64) -> bool {
    if task.rd_timer_armed && now_ms >= task.rd_deadline_ms {
        task.rd_timer_armed = false;
        if task.a_status == DnsQueryStatus.Success {
            task.ready_to_connect = true;
            return true; // Unblocked by RD timer expiration
        }
    }
    return false;
}

// Injects late DNS responses into an already running candidate list.
fn inject_late_dns_candidates(
    pending_queue: DnsCandidate[..32]&,
    new_candidates: const DnsCandidate[:],
) {
    for &nc in new_candidates {
        if pending_queue.len < 32 {
            pending_queue.push(copy(nc));
        }
    }
}

// ---- 5. Phase 3 & 4: AttemptManager, JobController & Last Resort -----------

enum AttemptState {
    Queued,
    Connecting,
    TlsHandshaking,
    Connected,
    Failed,
    Cancelled,
}

struct ConnectionAttempt {
    attempt_id: i32 = 0,
    candidate: DnsCandidate = DnsCandidate { .. },
    start_time_ms: i64 = 0,
    state: AttemptState = AttemptState.Queued,
}

// Winner address family cache (TTL = 600s)
struct AddressFamilyCacheEntry {
    host: u8[..256] = [],
    preferred_family: AddressFamily = AddressFamily.IPv6,
    expires_at_sec: i64 = 0,
}

struct AttemptManager {
    attempts: ConnectionAttempt[..16] = [],
    pending_candidates: DnsCandidate[..32] = [],
    effective_cad_ms: i64 = HE_DEFAULT_CAD_MS,
    next_attempt_start_ms: i64 = 0,
    current_attempt_idx: i64 = 0,
    winner_attempt_id: i32 = -1,
    has_winner: bool = false,
    alt_svc_broken: bool = false,
    last_resort_armed: bool = false,
    last_resort_deadline_ms: i64 = 0,
    last_resort_triggered: bool = false,
    next_id: i32 = 1,
}

fn new_attempt_manager(cad_ms: i64 = HE_DEFAULT_CAD_MS) -> AttemptManager {
    return AttemptManager {
        effective_cad_ms: cad_ms,
        ..
    };
}

// Starts the Happy Eyeballs socket racing sequence.
fn start_attempt_race(manager: AttemptManager&, candidates: const DnsCandidate[:], now_ms: i64) {
    manager.pending_candidates.clear();
    for &c in candidates {
        if manager.pending_candidates.len < 32 {
            manager.pending_candidates.push(copy(c));
        }
    }
    manager.current_attempt_idx = 0;
    manager.has_winner = false;
    manager.winner_attempt_id = -1;

    // Launch first attempt immediately
    launch_next_candidate_attempt(manager, now_ms);
}

// Launches next candidate and schedules CAD delay for subsequent candidate.
fn launch_next_candidate_attempt(manager: AttemptManager&, now_ms: i64) -> bool {
    guard manager.current_attempt_idx < manager.pending_candidates.len else { return false; }
    guard manager.attempts.len < 16 else { return false; }

    let cand = manager.pending_candidates[manager.current_attempt_idx];
    manager.current_attempt_idx++;

    let aid = manager.next_id;
    manager.next_id++;

    var attempt = ConnectionAttempt {
        attempt_id: aid,
        candidate: copy(cand),
        start_time_ms: now_ms,
        state: AttemptState.Connecting,
    };
    manager.attempts.push(attempt);

    // Schedule next attempt after CAD
    manager.next_attempt_start_ms = now_ms + manager.effective_cad_ms;

    // Arm Last Resort Local Synthesis when the last IPv6 attempt is dispatched
    var has_more_ipv6 = false;
    for i in manager.current_attempt_idx..manager.pending_candidates.len {
        if manager.pending_candidates[i].family == AddressFamily.IPv6 {
            has_more_ipv6 = true;
            break;
        }
    }
    if cand.family == AddressFamily.IPv6 && !has_more_ipv6 && !manager.last_resort_armed {
        manager.last_resort_armed = true;
        manager.last_resort_deadline_ms = now_ms + HE_LAST_RESORT_SYNTHESIS_DELAY_MS;
    }

    return true;
}

// Synthesizes a NAT64 IPv6 address prefix 64:ff9b::/96 per RFC 7050 from IPv4 candidate.
fn synthesize_nat64_candidate(manager: AttemptManager&) {
    guard manager.pending_candidates.len < manager.pending_candidates.cap else { return; }
    var v4_idx: i64 = -1;
    for i in manager.pending_candidates.len {
        guard manager.pending_candidates[i].family == AddressFamily.IPv4 else { continue; }
        v4_idx = i;
        break;
    }
    if v4_idx >= 0 {
        let cand4 = manager.pending_candidates[v4_idx];
        var syn_ip: u8[..64] = [];
        syn_ip.append("64:ff9b::");
        syn_ip.append(cand4.ip[..]);
        var nat64_cand = new_dns_candidate(
            AddressFamily.IPv6,
            syn_ip[..],
            cand4.port,
            cand4.l4_proto,
            cand4.precedence,
        );
        manager.pending_candidates.push(nat64_cand);
        return;
    }
    var nat64_cand = new_dns_candidate(
        AddressFamily.IPv6,
        "64:ff9b::192.0.2.1",
        443,
        L4Protocol.Tcp,
        30,
    );
    manager.pending_candidates.push(nat64_cand);
}

// Advances the connection racing state machine on monotonic time ticks.
fn tick_attempt_manager(manager: AttemptManager&, now_ms: i64) -> bool {
    if manager.has_winner { return false; }

    // Check if Last Resort Local Synthesis Delay expired (2000 ms)
    if manager.last_resort_armed && !manager.last_resort_triggered && now_ms >= manager.last_resort_deadline_ms {
        manager.last_resort_triggered = true;
        synthesize_nat64_candidate(manager);
    }

    // Launch next connection attempt if CAD interval has passed
    if manager.current_attempt_idx < manager.pending_candidates.len && now_ms >= manager.next_attempt_start_ms {
        return launch_next_candidate_attempt(manager, now_ms);
    }

    return false;
}

// Declares an attempt the winner, cancelling all other running sockets (BindJob parity).
fn bind_winner_attempt(manager: AttemptManager&, winner_id: i32, is_alternative_h3: bool = false) -> bool {
    var found = false;
    for &att in manager.attempts {
        if att.attempt_id == winner_id {
            att.state = AttemptState.Connected;
            manager.winner_attempt_id = winner_id;
            manager.has_winner = true;
            found = true;
            break;
        }
    }

    if found {
        // Cancel all other losing attempts and capture their cancellation state
        for &att in manager.attempts {
            if att.attempt_id != winner_id && att.state != AttemptState.Connected && att.state != AttemptState.Failed {
                att.state = AttemptState.Cancelled;
            }
        }
    }

    return found;
}

// Chromium JobController parity: rules governing the creation of dns_alpn_h3_job.
fn should_create_dns_alpn_h3_job(
    is_https: bool,
    quic_enabled: bool,
    uses_proxy: bool,
    has_available_quic_session: bool,
) -> bool {
    // Only created on HTTPS, when QUIC is enabled, no proxy is configured,
    // and no existing QUIC session can be synchronously reused.
    return is_https && quic_enabled && !uses_proxy && !has_available_quic_session;
}

// Computes main_job handicap delay: cancelled (0 ms) if an open TCP socket is already in pool.
fn compute_main_job_waiting_delay_ms(
    has_open_tcp_in_pool: bool,
    dns_alpn_h3_failed_no_match: bool,
    configured_quic_delay_ms: i64 = 200,
) -> i64 {
    // Optimization: if TCP socket already exists or ALPN confirms no HTTP/3, cancel waiting delay
    if has_open_tcp_in_pool || dns_alpn_h3_failed_no_match {
        return 0;
    }
    return configured_quic_delay_ms;
}
