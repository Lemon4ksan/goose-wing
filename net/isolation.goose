// Network Isolation Keys (NIK) and State Partitioning Engine.
// Implements Chromium / W3C Client State Partitioning across:
// - Connection Pools (preventing cross-site socket reuse and timing attacks)
// - DNS Cache partitioning (preventing DNS cache side-channel sniffing)
// - Cookie Jar partitioning (RFC 6265bis Partitioned / CHIPS cookies)
namespace wing;

import std;

// ---- 1. Network Isolation Key (NIK) Model -----------------------------------

struct NetworkIsolationKey {
    top_level_site: u8[..128] = [], // e.g. "https://site-a.com"
    frame_site: u8[..128] = [],     // e.g. "https://site-b.com"
    is_cross_site: bool = false,
    is_empty: bool = true,
}

// Constructs a clean NetworkIsolationKey
fn new_network_isolation_key(top_level: const u8[:], frame: const u8[:]) -> NetworkIsolationKey {
    var nik = NetworkIsolationKey { is_empty: false, .. };
    nik.top_level_site.append(top_level);
    nik.frame_site.append(frame);
    nik.is_cross_site = (top_level != frame);
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
    out.append(base_key);
    if !nik.is_empty {
        out.push('{');
        out.append(nik.top_level_site[..]);
        out.push(',');
        out.append(nik.frame_site[..]);
        out.push('}');
    }
}
