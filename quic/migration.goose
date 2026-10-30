// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// QUIC Connection Migration and Path Validation FSM (RFC 9000 Section 9 & Section 8.2).
// Implements zero-allocation path validation state machine, unpredictable challenge token generation,
// constant-time response verification, anti-amplification limits, and address migration.
namespace internal;

import std;
import core from "..";
import .packet;
import .frames;

// ---- 1. Path Validation States & Endpoint Representation -------------------

// RFC 9000 Section 8.2: Path Validation - States of path validation
enum PathValidationState {
    Initiated,
    Validating,
    Validated,
    Failed,
}

// RFC 9000 Section 9: Connection Migration - Endpoint network address representation
struct QuicEndpointAddr {
    ip: u8[..64] = [],
    port: u16 = 0,
}

// RFC 9000 Section 9: Connection Migration - Constructs an endpoint address from IP slice and port
fn new_quic_endpoint_addr(ip: const u8[:], port: u16) -> QuicEndpointAddr {
    var addr = QuicEndpointAddr { port: port, .. };
    if ip.len > 0 {
        addr.ip.append(ip);
    }
    return addr;
}

// RFC 9000 Section 9: Connection Migration - Compares two endpoint addresses for equality
fn quic_endpoint_addr_eq(a: const QuicEndpointAddr&, b: const QuicEndpointAddr&) -> bool {
    return a.port == b.port && a.ip[..] == b.ip[..];
}

// ---- 2. Path State Model ----------------------------------------------------

// RFC 9000 Section 9: Connection Migration - Single network path tracking structure
struct QuicPath {
    remote_addr: QuicEndpointAddr = QuicEndpointAddr { .. },
    state: PathValidationState = PathValidationState.Initiated,
    challenge_data: u8[8] = [0; 8],
    bytes_received: u64 = 0,
    bytes_sent: u64 = 0,
    retry_count: u32 = 0,
    max_retries: u32 = 3,
}

// RFC 9000 Section 9: Connection Migration - Connection migration state machine manager
struct QuicMigrationManager {
    active_path: QuicPath = QuicPath { state: PathValidationState.Validated, .. },
    probing_path: QuicPath = QuicPath { .. },
    has_probing_path: bool = false,
}

// RFC 9000 Section 9: Connection Migration - Creates a new migration manager with initial active path
fn new_quic_migration_manager(initial_addr: const QuicEndpointAddr&) -> QuicMigrationManager {
    return QuicMigrationManager {
        active_path: QuicPath {
            remote_addr: initial_addr,
            state: PathValidationState.Validated,
            ..
        },
        probing_path: QuicPath { .. },
        has_probing_path: false,
    };
}

// ---- 3. Anti-Amplification Budget (RFC 9000 Section 8.1 & Section 9.3) -----

// RFC 9000 Section 8.1: Address Validation during Connection Initiation - 3x anti-amplification budget
inline fn path_amplification_limit(rx: u64) -> u64 {
    return rx * 3;
}

// RFC 9000 Section 9.3: Responding to Connection Migration - Anti-amplification limit enforcement
fn path_can_send(path: const QuicPath&, bytes_to_send: u64) -> bool {
    guard path.state != PathValidationState.Validated else {
        return true;
    }
    let limit = path_amplification_limit(path.bytes_received);
    return (path.bytes_sent + bytes_to_send) <= limit;
}

// ---- 4. Token Generation & Constant-Time Verification ----------------------

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
//
// Example:
//   expected = [1, 2, 3, 4, 5, 6, 7, 8], received = [1, 2, 3, 4, 5, 6, 7, 8]
//   returns: true
fn verify_path_response_token(expected: const u8[8]&, received: const u8[:]) -> bool {
    guard received.len == 8 else { return false; }
    return core::ct_eq_bytes(expected[..], received);
}

// ---- 5. Migration State Machine Transitions (RFC 9000 Section 9) -----------

// RFC 9000 Section 9.1: Probing a New Path - Initiates path validation toward candidate address
fn quic_migration_start_probing(
    mgr: QuicMigrationManager&,
    new_addr: const QuicEndpointAddr&,
    token: const u8[8]&,
) {
    mgr.probing_path = QuicPath {
        remote_addr: new_addr,
        state: PathValidationState.Validating,
        challenge_data: token,
        bytes_received: 0,
        bytes_sent: 0,
        retry_count: 0,
        max_retries: 3,
    };
    mgr.has_probing_path = true;
}

// RFC 9000 Section 8.2.2: Path Validation Responses - Handles received PATH_RESPONSE frame
fn quic_migration_on_path_response(
    mgr: QuicMigrationManager&,
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
fn quic_migration_complete(mgr: QuicMigrationManager&) -> bool {
    guard mgr.has_probing_path && mgr.probing_path.state == PathValidationState.Validated else {
        return false;
    }
    mgr.active_path = mgr.probing_path;
    mgr.has_probing_path = false;
    return true;
}

// RFC 9000 Section 8.2.4: Failed Path Handling - Aborts candidate path on validation failure
fn quic_migration_fail_probing(mgr: QuicMigrationManager&) {
    if mgr.has_probing_path {
        mgr.probing_path.state = PathValidationState.Failed;
        mgr.has_probing_path = false;
    }
}

// RFC 9000 Section 8.2.4: Failed Path Handling - Retransmits challenge or transitions to Failed
fn quic_migration_retry_probe(mgr: QuicMigrationManager&) -> bool {
    guard mgr.has_probing_path && mgr.probing_path.state == PathValidationState.Validating else {
        return false;
    }
    mgr.probing_path.retry_count += 1;
    if mgr.probing_path.retry_count >= mgr.probing_path.max_retries {
        mgr.probing_path.state = PathValidationState.Failed;
        mgr.has_probing_path = false;
        return false;
    }
    return true;
}
