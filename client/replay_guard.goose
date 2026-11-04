// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 8470 0-RTT Early Data Anti-Replay Guard and HTTP 425 (Too Early) Recovery.
// - Protects state-mutating requests from network replay attacks during TLS 1.3 / QUIC 0-RTT handshakes
// - Signals `Early-Data: 1` header per RFC 8470 Section 5.1
// - Detects HTTP 425 (Too Early) and triggers automatic transparent safe retry over 1-RTT
namespace wing;

import std;

enum EarlyDataDecision {
    Allow,          // Safe idempotent method (GET, HEAD, OPTIONS, TRACE)
    RejectMutating, // Mutating method (POST, PUT, DELETE, PATCH) forbidden in 0-RTT
    RetryOn1Rtt,    // Server returned 425 Too Early, must retry on full 1-RTT
}

// Inspects outbound request for 0-RTT early data eligibility
fn evaluate_early_data_request(method: const u8[:], allow_mutating_override: bool = false) -> EarlyDataDecision {
    if rfc::is_safe_for_early_data(method) || allow_mutating_override {
        return EarlyDataDecision.Allow;
    }
    return EarlyDataDecision.RejectMutating;
}

// Evaluates response status to determine if 425 Too Early recovery retry is required
fn evaluate_early_data_response(status_code: u16, was_sent_early: bool) -> EarlyDataDecision {
    if was_sent_early && status_code == rfc::STATUS_TOO_EARLY {
        return EarlyDataDecision.RetryOn1Rtt;
    }
    return EarlyDataDecision.Allow;
}

// Appends `Early-Data: 1` header to request headers (RFC 8470 Section 5.1)
fn append_early_data_header<B>(out_headers: B&) {
    out_headers.append("Early-Data: 1\r\n");
}
