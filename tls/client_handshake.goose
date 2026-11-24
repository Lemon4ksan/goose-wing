// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Live TLS 1.3 Client Handshake Orchestrator over unified sans-IO TlsEndpoint engine.
namespace tls;

import std;
import core;
import .types;
import .session;
import .backend;
import .backend_pure_internal;
import .backend_transport_internal;

// Executes full TLS 1.3 client handshake over raw TCP socket, returning slot index (RFC 8446 §4).
fn client_handshake(fd: i64, config: const ClientHandshakeConfig&) -> u16, bool {
    let slot_idx = alloc_cipher_slot();
    guard slot_idx != 0xFFFF else { return 0xFFFF, false; }
    var committed = false;
    defer if !committed { free_cipher_slot(slot_idx); };
    guard fd > 0 else { return 0xFFFF, false; }

    var ep, ok_open = tls_internal::pure_open_blocking_client_endpoint(config, slot_idx);
    guard ok_open else { return 0xFFFF, false; }
    defer {
        let _ = tls_internal::pure_detach_cipher_slot(ep);
        tls_endpoint_close(ep);
    };

    guard tls_internal::tls_drive_blocking_endpoint_handshake(fd, ep, config.handshake_timeout_ms) else {
        return 0xFFFF, false;
    }
    let installed = tls_internal::pure_detach_cipher_slot(ep);
    guard installed == slot_idx else { return 0xFFFF, false; }
    committed = true;
    return slot_idx, true;
}
