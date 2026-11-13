// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Network Isolation Keys (NIK) and State Partitioning Engine.
// Implements Chromium / W3C Client State Partitioning across:
// - Connection Pools (preventing cross-site socket reuse and timing attacks)
// - DNS Cache partitioning (preventing DNS cache side-channel sniffing)
// - Cookie Jar partitioning (RFC 6265bis Partitioned / CHIPS cookies)
namespace wing;

import std;
import core from "..";

// ---- Network Anonymization Key (NAK) Model --------------------------------

// Network Anonymization Key (Chromium NAK / NIK parity) for cross-site partition isolation.
// All 4 components (top_frame_site, is_cross_site, nonce, network_isolation_partition)
// and optional worker_session_id must be compared to prevent cross-site side-channel leaks.
struct NetworkAnonymizationKey {
    top_frame_site:              u8[..128] = [],
    is_cross_site:               bool      = false,
    nonce:                       u64       = 0,
    network_isolation_partition: u32       = 0,
    worker_session_id:           u32       = 0,
}

fn new_network_anonymization_key(
    top_site:     const u8[:],
    cross_site:   bool = false,
    nonce_val:    u64  = 0,
    partition_id: u32  = 0,
    worker_id:    u32  = 0,
) -> NetworkAnonymizationKey {
    var nak = NetworkAnonymizationKey {
        is_cross_site:               cross_site,
        nonce:                       nonce_val,
        network_isolation_partition: partition_id,
        worker_session_id:           worker_id,
        ..
    };
    if nak.top_frame_site.try_set(top_site) {
        to_lower(nak.top_frame_site[..]);
    }
    return nak;
}

fn network_anonymization_key_equals(a: const NetworkAnonymizationKey&, b: const NetworkAnonymizationKey&) -> bool {
    if a.nonce != b.nonce { return false; }
    if a.is_cross_site != b.is_cross_site { return false; }
    if a.network_isolation_partition != b.network_isolation_partition { return false; }
    if a.worker_session_id != b.worker_session_id { return false; }
    return a.top_frame_site[..].eq_ascii_fold(b.top_frame_site[..]);
}

// ---- Network Isolation Key (NIK) Model -----------------------------------

struct NetworkIsolationKey {
    top_level_site: u8[..128] = [], // e.g. "https://site-a.com"
    frame_site:     u8[..128] = [], // e.g. "https://site-b.com"
    is_cross_site:  bool      = false,
    is_empty:       bool      = true,
}

// Constructs a clean NetworkIsolationKey
fn new_network_isolation_key(top_level: const u8[:], frame: const u8[:]) -> NetworkIsolationKey {
    guard top_level.len > 0 || frame.len > 0 else {
        return empty_network_isolation_key();
    }
    var nik = NetworkIsolationKey { is_empty: false, .. };
    guard nik.top_level_site.try_set(top_level) && nik.frame_site.try_set(frame) else {
        return empty_network_isolation_key();
    }
    to_lower(nik.top_level_site[..]);
    to_lower(nik.frame_site[..]);
    nik.is_cross_site = nik.top_level_site[..] != nik.frame_site[..];
    return nik;
}

// Constructs an empty / unpartitioned key (for standard top-level requests)
fn empty_network_isolation_key() -> NetworkIsolationKey {
    return NetworkIsolationKey { is_empty: true, .. };
}

// Generates a partition-aware cache or connection key:
// If NIK is empty, writes `base_key`.
// If NIK is active, writes `base_key{top_level_site,frame_site}`.
fn format_partitioned_key<B>(base_key: const u8[:], nik: const NetworkIsolationKey&, out: B&) {
    let _ = out.try_append(base_key);
    if !nik.is_empty {
        let _ = out.try_append("{");
        let _ = out.try_append(nik.top_level_site[..]);
        let _ = out.try_append(",");
        let _ = out.try_append(nik.frame_site[..]);
        let _ = out.try_append("}");
    }
}

// Converts a `NetworkIsolationKey` into a `NetworkAnonymizationKey` for connection pool and cache partitioning.
fn nik_to_anonymization_key(
    nik:                const NetworkIsolationKey&,
    had_cross_site_hop: bool = false,
) -> NetworkAnonymizationKey {
    if nik.is_empty {
        return new_network_anonymization_key("", had_cross_site_hop);
    }
    return new_network_anonymization_key(nik.top_level_site[..], nik.is_cross_site || had_cross_site_hop);
}
