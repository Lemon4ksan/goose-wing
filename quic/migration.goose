// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// QUIC Connection Migration and Path Validation FSM (RFC 9000 Section 9 & Section 8.2).
// Implements zero-allocation path validation state machine, unpredictable challenge token generation,
// constant-time response verification, anti-amplification limits, and address migration.
namespace quic;

import std;
import core from "..";
import .internal;

// ---- Path Validation States & Endpoint Representation -------------------

// RFC 9000 Section 8.2: Path Validation - States of path validation
enum PathValidationState {
    Initiated,
    Validating,
    Validated,
    Failed,
}

// RFC 9000 Section 9: Connection Migration - Endpoint network address representation
struct QuicEndpointAddr {
    ip:   u8[..64] = [],
    port: u16      = 0,
}

// RFC 9000 Section 9: Connection Migration - Constructs an endpoint address from IP slice and port
fn new_endpoint_addr(ip: const u8[:], port: u16) -> QuicEndpointAddr {
    var addr = QuicEndpointAddr { port: port, .. };
    if ip.len > 0 {
        let take = min(ip.len, addr.ip.cap);
        addr.ip.append(ip[..take]);
    }
    return addr;
}

// RFC 9000 Section 9: Connection Migration - Compares two endpoint addresses for equality
fn addr_eq(a: const QuicEndpointAddr&, b: const QuicEndpointAddr&) -> bool {
    return a.port == b.port && a.ip[..] == b.ip[..];
}

// ---- Path State Model ----------------------------------------------------

// RFC 9000 Section 9: Connection Migration - Single network path tracking structure
struct QuicPath {
    remote_addr:    QuicEndpointAddr    = QuicEndpointAddr { .. },
    state:          PathValidationState = PathValidationState.Initiated,
    challenge_data: u8[8]               = [0; 8],
    bytes_received: u64                 = 0,
    bytes_sent:     u64                 = 0,
    retry_count:    u32                 = 0,
    max_retries:    u32                 = 3,
}

// RFC 9000 Section 9: Connection Migration - Connection migration state machine manager
struct QuicMigrationManager {
    active_path:        QuicPath = QuicPath { state: PathValidationState.Validated, .. },
    probing_path:       QuicPath = QuicPath { .. },
    has_probing_path:   bool     = false,
    migration_disabled: bool     = false,
}

// RFC 9000 Section 9.6 & Section 18.2: Server's Preferred Address transport parameter (0x0d)
struct QuicPreferredAddress {
    ipv4:                  u8[4]    = [0; 4],
    ipv4_port:             u16      = 0,
    ipv6:                  u8[16]   = [0; 16],
    ipv6_port:             u16      = 0,
    cid:                   u8[..20] = [],
    stateless_reset_token: u8[16]   = [0; 16],
}

// Decodes RFC 9000 §18.2 `preferred_address` (0x0d) transport parameter payload.
// Wire layout: ipv4 (4B) || ipv4_port (2B BE) || ipv6 (16B) || ipv6_port (2B BE)
//              || cid_len (1B, 1..20) || cid (cid_len B) || stateless_reset_token (16B).
//
// Example:
//   src = [192, 0, 2, 1, 0x01, 0xBB, ...16B ipv6..., 0x00, 0x00, 4, 1, 2, 3, 4, ...16B token...]
//   returns: QuicPreferredAddress { ipv4: [192, 0, 2, 1], ipv4_port: 443, cid: [1, 2, 3, 4] }, ok = true
//
// crap:trusted-bounds
fn decode_preferred_address(src: const u8[:]) -> QuicPreferredAddress, bool {
    var cur = core::cursor_from(src);
    let v4_slice, ok_v4 = cur.read_bytes(4);
    let v4_port, ok_p4 = cur.read_u16();
    let v6_slice, ok_v6 = cur.read_bytes(16);
    let v6_port, ok_p6 = cur.read_u16();
    guard ok_v4 && ok_p4 && ok_v6 && ok_p6 else { return QuicPreferredAddress { .. }, false; }

    let has_v4 = (v4_slice[0] | v4_slice[1] | v4_slice[2] | v4_slice[3]) != 0;
    var v6_bits: u8 = 0;
    for i in 16 { v6_bits = v6_bits | v6_slice[i]; }
    let has_v6 = v6_bits != 0;

    // Both cannot have port != 0 while IP is 0, or IP != 0 while port is 0 (RFC 9000 §18.2)
    guard (has_v4 == (v4_port != 0)) && (has_v6 == (v6_port != 0)) else {
        return QuicPreferredAddress { .. }, false;
    }
    // Must contain at least one valid address
    guard has_v4 || has_v6 else { return QuicPreferredAddress { .. }, false; }

    let cid_slice, ok_cid = cur.read_u8_prefixed();
    guard ok_cid && cid_slice.len >= 1 && cid_slice.len <= 20 else {
        return QuicPreferredAddress { .. }, false;
    }
    let tok_slice, ok_tok = cur.read_bytes(16);
    guard ok_tok && cur.buf.len == 0 else { return QuicPreferredAddress { .. }, false; }

    var parsed = QuicPreferredAddress {
        ipv4_port: v4_port,
        ipv6_port: v6_port,
        ..
    };
    for i in 4 {
        parsed.ipv4[i] = v4_slice[i];
    }
    for i in 16 {
        parsed.ipv6[i] = v6_slice[i];
        parsed.stateless_reset_token[i] = tok_slice[i];
    }
    parsed.cid.append(cid_slice);
    return parsed, true;
}

// RFC 9000 Section 9: Connection Migration - Creates a new migration manager with initial active path
fn new_migration_manager(initial_addr: const QuicEndpointAddr&) -> QuicMigrationManager {
    return QuicMigrationManager {
        active_path: QuicPath {
            remote_addr: initial_addr,
            state:       PathValidationState.Validated,
            ..
        },
        probing_path:     QuicPath { .. },
        has_probing_path: false,
    };
}

// ---- Anti-Amplification Budget (RFC 9000 Section 8.1 & Section 9.3) -----

// RFC 9000 Section 9.3: Responding to Connection Migration - Anti-amplification limit enforcement
fn can_send(path: const QuicPath&, bytes_to_send: u64) -> bool {
    guard path.state != PathValidationState.Validated else {
        return true;
    }
    guard 0xFFFFFFFFFFFFFFFF - path.bytes_sent >= bytes_to_send else {
        return false;
    }
    let limit = quic_internal::path_amplification_limit(path.bytes_received);
    return (path.bytes_sent + bytes_to_send) <= limit;
}

// ---- Token Generation & Constant-Time Verification ----------------------

// RFC 9000 Section 8.2.1: Initiating Path Validation - Generation of 8-byte unpredictable challenge token
fn generate_path_challenge_token(rng_seed: u64&) -> u8[8] {
    let rand_val = core::splitmix64(rng_seed);
    var token: u8[8] = [0; 8];
    for i in 8 {
        token[i] = ((rand_val >> ((i as u64) * 8)) & 0xFF) as u8;
    }
    return token;
}

// RFC 9000 Section 8.2.2: Path Validation Responses - Constant-time PATH_RESPONSE verification
fn verify_path_response_token(expected: const u8[8]&, received: const u8[:]) -> bool {
    guard received.len == 8 else { return false; }
    return core::ct_eq_bytes(expected[..], received);
}

// ---- Migration State Machine Transitions (RFC 9000 Section 9) -----------

// RFC 9000 Section 9.1: Probing a New Path - Initiates path validation toward candidate address
fn start_probing(
    mgr:      QuicMigrationManager&,
    new_addr: const QuicEndpointAddr&,
    token:    const u8[8]&,
) {
    mgr.probing_path = QuicPath {
        remote_addr:    new_addr,
        state:          PathValidationState.Validating,
        challenge_data: token,
        bytes_received: 0,
        bytes_sent:     0,
        retry_count:    0,
        max_retries:    3,
    };
    mgr.has_probing_path = true;
}

// RFC 9000 Section 9.6: Server's Preferred Address - Initiates client probing toward server preferred address
fn probe_preferred_address(
    mgr:         QuicMigrationManager&,
    pref:        const QuicPreferredAddress&,
    prefer_ipv6: bool,
    token:       const u8[8]&,
) -> bool {
    guard !mgr.migration_disabled && pref.cid.len >= 1 else { return false; }

    let has_v6 = pref.ipv6_port != 0;
    let has_v4 = pref.ipv4_port != 0;
    guard has_v6 || has_v4 else { return false; }

    let use_v6 = if prefer_ipv6 && has_v6 { true } else { !has_v4 };
    let target = if use_v6 {
        new_endpoint_addr(pref.ipv6[..], pref.ipv6_port)
    } else {
        new_endpoint_addr(pref.ipv4[..], pref.ipv4_port)
    };
    start_probing(mgr, target, token);
    return true;
}

// RFC 9000 Section 8.2.2: Path Validation Responses - Handles received PATH_RESPONSE frame
fn on_path_response(
    mgr:           QuicMigrationManager&,
    response_data: const u8[:],
) -> bool {
    guard mgr.has_probing_path && mgr.probing_path.state == PathValidationState.Validating else {
        return false;
    }
    let matched = verify_path_response_token(mgr.probing_path.challenge_data, response_data);
    guard matched else {
        return false;
    }
    mgr.probing_path.state = PathValidationState.Validated;
    return true;
}

// RFC 9000 Section 9.2: Initiating Connection Migration - Completes migration to validated path
fn complete(mgr: QuicMigrationManager&) -> bool {
    guard mgr.has_probing_path && mgr.probing_path.state == PathValidationState.Validated else {
        return false;
    }
    mgr.active_path = mgr.probing_path;
    mgr.has_probing_path = false;
    return true;
}

// RFC 9000 Section 8.2.4: Failed Path Handling - Aborts candidate path on validation failure
fn fail_probing(mgr: QuicMigrationManager&) {
    if mgr.has_probing_path {
        mgr.probing_path.state = PathValidationState.Failed;
        mgr.has_probing_path = false;
    }
}

// RFC 9000 Section 8.2.4: Failed Path Handling - Retransmits challenge or transitions to Failed
fn retry_probe(mgr: QuicMigrationManager&) -> bool {
    guard mgr.has_probing_path && mgr.probing_path.state == PathValidationState.Validating else {
        return false;
    }
    if mgr.probing_path.retry_count < 0xFFFFFFFF {
        mgr.probing_path.retry_count += 1;
    }
    if mgr.probing_path.retry_count >= mgr.probing_path.max_retries {
        mgr.probing_path.state = PathValidationState.Failed;
        mgr.has_probing_path = false;
        return false;
    }
    return true;
}
