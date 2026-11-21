// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// End-to-end benchmark verifying that goose2rfc surfaces 5 seeded RFC conformance defects:
// 1. Off-by-one `<` instead of `<=` on `QUIC_VARINT_MAX` (via helper `quic_buggy_varint_bound`)
// 2. Missing bound check on wire-decoded `ack_delay_exponent` (`UNCONSTRAINED_INPUT`)
// 3. Un-restored `idx` cursor on error (`DIRTY_EXPOSED`)
// 4. Unchecked narrowing `as!` cast truncation (`as_truncate u16`)
// 5. Handshake FSM table (`## Machine`) exposing exact transitions for missing TLS alert auditing

// RUN: goose run %S/../../src/main.goose -- compile %s --max-inline-depth 3 --format sm.md -o %t.sm.md
// RUN: "%S/../../../bin/goosemarklint" check %t.sm.md
// RUN: "%S/../../../bin/goosemarklint" fmt --check %t.sm.md
// RUN: %FileCheck %s < %t.sm.md

// CHECK: ### 3. Requirements of `decode_seeded_quic_ack`
// CHECK: - R1: `largest_acked` must be at most `0x3fff_ffff_ffff_ffff - 1`.
// CHECK: - R2: `(raw_len as_truncate u16)` must be at most `1024`.
// CHECK: ### 4. Unchecked surface of `decode_seeded_quic_ack`
// CHECK: | `UNCONSTRAINED_INPUT` | `ack_delay_exponent` | `0..0x3fff_ffff_ffff_ffff` | `decode_seeded_quic_ack` does not check `ack_delay_exponent` bounds. |
// CHECK: ### 5. Error side effects of `decode_seeded_quic_ack`
// CHECK: | `idx` | `DIRTY_EXPOSED` | `decode_seeded_quic_ack` changes `idx` before `return false` without rollback. |
// CHECK: ## Machine `validate_seeded_tls_fsm`
// CHECK: | `ClientState.WaitServerHello` | `TLS_HS_SERVER_HELLO` | `always` | `ClientState.WaitFinished` |

import std;

const QUIC_VARINT_MAX:     u64 = 0x3fffffffffffffff;
const TLS_HS_SERVER_HELLO: u8  = 0x02;

enum ClientState {
    Start,
    WaitServerHello,
    WaitFinished,
    Connected,
}

struct TlsConn {
    state: ClientState = ClientState.Start,
}

fn quic_decode_varint_cursor(src: const u8[:], idx: i64&) -> u64, bool {
    guard idx >= 0 && idx < src.len else { return 0, false; }
    let v = src[idx] as u64;
    idx += 1;
    return v, true;
}

fn quic_buggy_varint_bound(val: u64) -> bool {
    guard val < QUIC_VARINT_MAX else { return false; }
    return true;
}

fn decode_seeded_quic_ack(
    data:          const u8[:],
    idx:           i64&,
    largest_acked: u64,
    raw_len:       u64,
) -> bool {
    let ack_delay_exponent, ok_ade = quic_decode_varint_cursor(data, idx);
    guard ok_ade else { return false; }
    guard quic_buggy_varint_bound(largest_acked) else { return false; }
    guard (raw_len as! u16) <= 1024 else { return false; }
    let _ = ack_delay_exponent;
    return true;
}

fn validate_seeded_tls_fsm(state: ClientState, msg_type: u8) -> ClientState, bool {
    if state == ClientState.Start {
        return ClientState.WaitServerHello, true;
    }
    if state == ClientState.WaitServerHello && msg_type == TLS_HS_SERVER_HELLO {
        return ClientState.WaitFinished, true;
    }
    if state == ClientState.WaitFinished {
        return ClientState.Connected, true;
    }
    return state, false;
}
