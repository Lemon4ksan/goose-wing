// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Happy Eyeballs v2 (RFC 8305) and v3 connection racing, DNS resolution delay,
// CAD pacing with absolute floor, candidate interleaving, and Chromium AttemptManager coordination.
namespace net;

import std;
import core;
import dns.svcb;
import .internal;
import .pool_internal;

// ---- RFC 8305 and HEv3 normative constants ------------------------------

// Computes Connection Attempt Delay (CAD) strictly enforcing the >= 10 ms absolute floor.
fn compute_effective_cad_ms(
    observed_rtt_ms: i64,
    rtt_known:       bool,
    min_cad_ms:      i64 = rfc::HE_MIN_CAD_MS,
    max_cad_ms:      i64 = rfc::HE_MAX_CAD_MS,
) -> i64 {
    let eff_min = core::ct_max_i64(min_cad_ms, rfc::HE_ABSOLUTE_FLOOR_CAD_MS);
    let eff_max = core::ct_max_i64(max_cad_ms, eff_min);

    if !rtt_known {
        return rfc::HE_DEFAULT_CAD_MS;
    }

    let clamped = core::clamp_i64(observed_rtt_ms, eff_min, eff_max);
    return core::ct_max_i64(clamped, rfc::HE_ABSOLUTE_FLOOR_CAD_MS);
}

// ---- DNS query models and candidate classification ----------------------

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
    mode:               SvcbMode      = SvcbMode.None,
    alias_target:       u8[..256]     = [],
    target_name:        u8[..256]     = [],
    alpn_h3:            bool          = false,
    alpn_h2:            bool          = false,
    ech_config_present: bool          = false,
    ipv6_hints:         u8[..64][..4] = [],
    ipv4_hints:         u8[..64][..4] = [],
}

// Extracts Happy Eyeballs v3 endpoint metadata and effective port from an RFC 9460 HTTPS/SVCB record.
//
// Example:
//   rec = dns::HttpsRecord { priority: 1, port: 8443, alpns: ["h3", "h2"], has_ech: true, .. }, default_port = 443
//   returns: meta = { mode: ServiceMode, alpn_h3: true, alpn_h2: true, ech_config_present: true, .. }, eff_port = 8443
fn extract_https_svcb_metadata(
    rec:          const dns::HttpsRecord&,
    default_port: u16         = 443,
    owner_name:   const u8[:] = "",
) -> ConnectionEndpointMetadata, u16 {
    var meta = ConnectionEndpointMetadata { .. };
    let is_root_target = rec.target_name.len == 0 || rec.target_name[..] == ".";
    if rec.priority == 0 {
        // RFC 9460 Section 2.4.2: AliasMode - TargetName "." indicates service is not available
        guard !is_root_target else { return meta, default_port; }
        meta.mode = SvcbMode.AliasMode;
        let _ = meta.alias_target.try_append(rec.target_name[..]);
        return meta, default_port;
    }
    meta.mode = SvcbMode.ServiceMode;
    // RFC 9460 Section 2.5.2: ServiceMode - TargetName "." resolves to the record's owner name
    if is_root_target {
        if owner_name.len > 0 {
            let _ = meta.target_name.try_append(owner_name);
        }
    } else {
        let _ = meta.target_name.try_append(rec.target_name[..]);
    }
    meta.ech_config_present = rec.has_ech && rec.ech_config_list.len > 0;
    net_internal::populate_svcb_alpn_flags(rec, meta);
    net_internal::populate_svcb_ip_hints(rec, meta);
    let eff_port: u16 = if rec.port > 0 { rec.port } else { default_port };
    return meta, eff_port;
}

struct DnsCandidate {
    family:     AddressFamily = AddressFamily.IPv6,
    l4_proto:   L4Protocol    = L4Protocol.Tcp,
    ip:         u8[..256]     = [],
    port:       u16           = 80,
    scope_id:   i32           = 0,
    precedence: i32           = 40,
}

fn new_dns_candidate(
    fam:      AddressFamily,
    ip_str:   const u8[:],
    port_num: u16,
    proto:    L4Protocol = L4Protocol.Tcp,
    prec:     i32        = 40,
) -> DnsCandidate {
    var c = DnsCandidate {
        family:     fam,
        l4_proto:   proto,
        port:       port_num,
        precedence: prec,
        ..
    };
    guard c.ip.try_append(ip_str) else { return c; }
    return c;
}

// ---- RFC 6724 sorting & address interleaving ----------------------------

// Interleaves candidate addresses enforcing First Address Family Count = 1 (IPv6_1 -> IPv4_1 -> IPv6_2 -> IPv4_2).
fn interleave_candidates_he(
    ipv6_list:          const DnsCandidate[:],
    ipv4_list:          const DnsCandidate[:],
    out:                DnsCandidate[..32]&,
    first_family_count: i32 = rfc::HE_FIRST_ADDRESS_FAMILY_COUNT,
) {
    out.clear();
    var idx6: i64 = 0;
    var idx4: i64 = 0;

    // First, emit first_family_count from preferred family (IPv6)
    var initial_count: i64 = 0;
    let first_limit = first_family_count as i64;
    while idx6 < ipv6_list.len && initial_count < first_limit {
        let _ = out.try_push(copy(ipv6_list[idx6]));
        idx6 = core::add_sat_i64(idx6, 1);
        initial_count = core::add_sat_i64(initial_count, 1);
    }

    // Interleave remaining 1-by-1
    while (idx6 < ipv6_list.len || idx4 < ipv4_list.len) && out.len < 32 {
        if idx4 < ipv4_list.len {
            let _ = out.try_push(copy(ipv4_list[idx4]));
            idx4 = core::add_sat_i64(idx4, 1);
        }
        if idx6 < ipv6_list.len {
            let _ = out.try_push(copy(ipv6_list[idx6]));
            idx6 = core::add_sat_i64(idx6, 1);
        }
    }
}

// Interleaves candidate addresses honoring a cached winning address family (RFC 8305 §5).
fn interleave_candidates_by_preference(
    ipv6_list:          const DnsCandidate[:],
    ipv4_list:          const DnsCandidate[:],
    preferred_family:   AddressFamily,
    out:                DnsCandidate[..32]&,
    first_family_count: i32 = rfc::HE_FIRST_ADDRESS_FAMILY_COUNT,
) {
    if preferred_family == AddressFamily.IPv4 {
        interleave_candidates_he(ipv4_list, ipv6_list, out, first_family_count);
        return;
    }
    interleave_candidates_he(ipv6_list, ipv4_list, out, first_family_count);
}

// Interleaves transport protocols (HEv3 QUIC/UDP vs TCP) so UDP firewalls do not block TCP.
fn interleave_protocols_hev3(candidates: const DnsCandidate[:], out: DnsCandidate[..32]&) {
    out.clear();
    for &cand in candidates {
        // Emit QUIC attempt first
        var quic_c = copy(cand);
        quic_c.l4_proto = L4Protocol.QuicUdp;
        let _ = out.try_push(quic_c);
        // Emit TCP fallback attempt
        var tcp_c = copy(cand);
        tcp_c.l4_proto = L4Protocol.Tcp;
        let _ = out.try_push(tcp_c);
    }
}

// ---- Phase 1: DNS race task & 50 ms Resolution Delay (RD) ---------------

struct DnsRaceTask {
    target_port:      u16                        = 443,
    aaaa_status:      DnsQueryStatus             = DnsQueryStatus.Pending,
    a_status:         DnsQueryStatus             = DnsQueryStatus.Pending,
    https_status:     DnsQueryStatus             = DnsQueryStatus.Pending,
    rd_timer_armed:   bool                       = false,
    rd_deadline_ms:   i64                        = 0,
    ipv6_candidates:  DnsCandidate[..8]          = [],
    ipv4_candidates:  DnsCandidate[..8]          = [],
    metadata:         ConnectionEndpointMetadata = ConnectionEndpointMetadata { .. },
    ready_to_connect: bool                       = false,
}

fn new_dns_race_task(target_port: u16 = 443) -> DnsRaceTask {
    return DnsRaceTask {
        target_port:  target_port,
        aaaa_status:  DnsQueryStatus.InFlight,
        a_status:     DnsQueryStatus.InFlight,
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
            let cand = new_dns_candidate(AddressFamily.IPv6, ip, task.target_port, L4Protocol.Tcp, 50);
            guard task.ipv6_candidates.try_push(cand) else { break; }
        }
        // Asymmetric IPv6 Priority: cancel RD timer immediately
        task.rd_timer_armed = false;
        task.ready_to_connect = true;
    } else {
        task.aaaa_status = DnsQueryStatus.Negative;
        task.rd_timer_armed = false;
        // If A already succeeded, negative AAAA immediately unblocks IPv4
        if task.a_status == DnsQueryStatus.Success {
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
            let cand = new_dns_candidate(AddressFamily.IPv4, ip, task.target_port, L4Protocol.Tcp, 40);
            guard task.ipv4_candidates.try_push(cand) else { break; }
        }

        // If AAAA already arrived, we are ready to connect
        if task.aaaa_status != DnsQueryStatus.Pending && task.aaaa_status != DnsQueryStatus.InFlight {
            task.ready_to_connect = true;
        } else {
            // A arrived first! Arm Resolution Delay (RD = 50 ms) to wait for AAAA
            task.rd_timer_armed = true;
            task.rd_deadline_ms = core::add_sat_i64(now_ms, rfc::HE_RESOLUTION_DELAY_MS);
        }
    } else {
        task.a_status = DnsQueryStatus.Negative;
    }
}

// Checks RD timer expiration. If 50 ms elapsed without AAAA, unblocks IPv4.
fn check_dns_resolution_delay_tick(task: DnsRaceTask&, now_ms: i64) -> bool {
    if task.rd_timer_armed && now_ms >= task.rd_deadline_ms {
        guard task.a_status == DnsQueryStatus.Success else { return false; }
        task.rd_timer_armed = false;
        task.ready_to_connect = true;
        return true;
    }
    return false;
}

// Injects late DNS responses into an already running candidate list.
fn inject_late_dns_candidates(
    pending_queue:  DnsCandidate[..32]&,
    new_candidates: const DnsCandidate[:],
) {
    for &nc in new_candidates {
        guard pending_queue.try_push(copy(nc)) else { break; }
    }
}

// ---- Phase 3 & 4: AttemptManager, JobController & Last Resort -----------

enum AttemptState {
    Queued,
    Connecting,
    TlsHandshaking,
    Connected,
    Failed,
    Cancelled,
}

struct ConnectionAttempt {
    attempt_id:    i32          = 0,
    candidate:     DnsCandidate = DnsCandidate { .. },
    start_time_ms: i64          = 0,
    state:         AttemptState = AttemptState.Queued,
}

// Winner address family cache (TTL = 600s, RFC 8305 §5)
const HE_ADDRESS_FAMILY_CACHE_TTL_SEC: i64 = 600;

struct AddressFamilyCacheEntry {
    host:             u8[..256]     = [],
    preferred_family: AddressFamily = AddressFamily.IPv6,
    expires_at_sec:   i64           = 0,
}

struct AddressFamilyCache {
    entries: AddressFamilyCacheEntry[..16] = [],
}

// Looks up a fresh cached preferred address family for `host` (RFC 8305 §5).
fn lookup_preferred_family(
    cache:   const AddressFamilyCache&,
    host:    const u8[:],
    now_sec: i64,
) -> AddressFamily, bool {
    for &entry in cache.entries {
        if entry.expires_at_sec > now_sec && entry.host[..].eq_ascii_fold(host) {
            return entry.preferred_family, true;
        }
    }
    return AddressFamily.IPv6, false;
}

// Records the winning address family for `host` with a 600-second TTL (RFC 8305 §5).
fn record_preferred_family(
    cache:   AddressFamilyCache&,
    host:    const u8[:],
    family:  AddressFamily,
    now_sec: i64,
) {
    guard host.len > 0 && host.len <= 256 else { return; }
    let exp = core::add_sat_i64(now_sec, HE_ADDRESS_FAMILY_CACHE_TTL_SEC);
    for &entry in cache.entries {
        if entry.host[..].eq_ascii_fold(host) {
            entry.preferred_family = family;
            entry.expires_at_sec = exp;
            return;
        }
    }
    for &entry in cache.entries {
        if entry.expires_at_sec <= now_sec {
            let _ = entry.host.try_set(host);
            entry.preferred_family = family;
            entry.expires_at_sec = exp;
            return;
        }
    }
    var new_entry = AddressFamilyCacheEntry {
        preferred_family: family,
        expires_at_sec:   exp,
        ..
    };
    let _ = new_entry.host.try_set(host);
    let _ = cache.entries.try_push(new_entry);
}

struct AttemptManager {
    attempts:                ConnectionAttempt[..16] = [],
    pending_candidates:      DnsCandidate[..32]      = [],
    effective_cad_ms:        i64                     = rfc::HE_DEFAULT_CAD_MS,
    next_attempt_start_ms:   i64                     = 0,
    current_attempt_idx:     i64                     = 0,
    winner_attempt_id:       i32                     = -1,
    has_winner:              bool                    = false,
    alt_svc_broken:          bool                    = false,
    enable_nat64_synthesis:  bool                    = true,
    last_resort_armed:       bool                    = false,
    last_resort_deadline_ms: i64                     = 0,
    last_resort_triggered:   bool                    = false,
    next_id:                 i32                     = 1,
}

fn new_attempt_manager(cad_ms: i64 = rfc::HE_DEFAULT_CAD_MS) -> AttemptManager {
    return AttemptManager {
        effective_cad_ms: max(cad_ms, rfc::HE_ABSOLUTE_FLOOR_CAD_MS),
        ..
    };
}

// Starts the Happy Eyeballs socket racing sequence.
fn start_attempt_race(manager: AttemptManager&, candidates: const DnsCandidate[:], now_ms: i64) {
    manager.attempts.clear();
    manager.pending_candidates.clear();
    for &c in candidates {
        guard manager.pending_candidates.try_push(copy(c)) else { break; }
    }
    manager.current_attempt_idx = 0;
    manager.has_winner = false;
    manager.winner_attempt_id = -1;
    manager.last_resort_armed = false;
    manager.last_resort_deadline_ms = 0;
    manager.last_resort_triggered = false;

    // Launch first attempt immediately
    let _ = net_internal::launch_next_candidate_attempt(manager, now_ms);
}

// Advances the connection racing state machine on monotonic time ticks.
fn tick_attempt_manager(manager: AttemptManager&, now_ms: i64) -> bool {
    if manager.has_winner { return false; }

    // Check if Last Resort Local Synthesis Delay expired (2000 ms)
    if manager.enable_nat64_synthesis && manager.last_resort_armed && !manager.last_resort_triggered &&
        now_ms >= manager.last_resort_deadline_ms {
        manager.last_resort_triggered = true;
        net_internal::synthesize_nat64_candidate(manager);
    }

    // Launch next connection attempt if CAD interval has passed
    if manager.current_attempt_idx < manager.pending_candidates.len && now_ms >= manager.next_attempt_start_ms {
        return net_internal::launch_next_candidate_attempt(manager, now_ms);
    }

    return false;
}

// Declares an attempt the winner, cancelling all other running sockets (BindJob parity).
fn bind_winner_attempt(manager: AttemptManager&, winner_id: i32, is_alternative_h3: bool = false) -> bool {
    var found = false;
    for &att in manager.attempts {
        if att.attempt_id == winner_id {
            guard att.state != AttemptState.Failed && att.state != AttemptState.Cancelled else {
                return false;
            }
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

// Options controlling HTTP/3 DNS ALPN racing job creation.
struct H3JobOptions {
    is_https:                   bool = false,
    quic_enabled:               bool = false,
    uses_proxy:                 bool = false,
    has_available_quic_session: bool = false,
}

// Chromium JobController parity: rules governing the creation of dns_alpn_h3_job.
fn should_create_dns_alpn_h3_job(opts: H3JobOptions) -> bool {
    // Only created on HTTPS, when QUIC is enabled, no proxy is configured,
    // and no existing QUIC session can be synchronously reused.
    return opts.is_https && opts.quic_enabled && !opts.uses_proxy && !opts.has_available_quic_session;
}

// Computes main_job handicap delay: cancelled (0 ms) if an open TCP socket is already in pool.
fn compute_main_job_waiting_delay_ms(
    has_open_tcp_in_pool:        bool,
    configured_quic_delay_ms:    i64,
    dns_alpn_h3_failed_no_match: bool = false,
) -> i64 {
    // Optimization: if TCP socket already exists or ALPN confirms no HTTP/3, cancel waiting delay
    if has_open_tcp_in_pool || dns_alpn_h3_failed_no_match {
        return 0;
    }
    return configured_quic_delay_ms;
}
