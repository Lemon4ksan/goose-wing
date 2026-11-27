// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Live TLS 1.3 Server Handshake Orchestrator over unified sans-IO TlsEndpoint engine.
namespace tls;

import std;
import core;
import .record;
import .handshake;
import .types;
import .session_internal;
import .session_codec_internal;
import .session;
import .backend;
import .backend_pure_internal;
import .backend_transport_internal;

// Reads and validates a single TLS 1.3 plaintext ClientHello handshake message from `fd` (RFC 8446 Section 4.1.2).
// Clears `out_ch_msg` and returns false on timeout, I/O error, or malformed framing.
fn read_client_hello(
    fd:         i64,
    out_ch_msg: u8[..16384]&,
    timeout_ms: u32 = 5000,
) -> bool {
    out_ch_msg.clear();
    guard fd > 0 && tls_internal::read_plaintext_handshake_record(fd, out_ch_msg, timeout_ms) else {
        out_ch_msg.clear();
        return false;
    }
    let msg_type, msg_len, ok_h = parse_handshake_header(out_ch_msg[..]);
    guard ok_h && msg_type == rfc::TLS_HS_CLIENT_HELLO && out_ch_msg.len == core::add_sat_i64(4, msg_len) else {
        out_ch_msg.clear();
        return false;
    }
    return true;
}

// Parses a TLS 1.3 ClientHello handshake message and extracts the normalized SNI hostname (RFC 6066 Section 3).
// Returns true if a valid server_name extension was extracted into `out_sni`; clears `out_sni`
// and returns false if the ClientHello is malformed, omits SNI, or carries an invalid host_name.
//
// Example:
//   ch_msg = [0x01, 0x00, 0x00, 0x46, 0x03, 0x03, ...server_name "Api.Example.COM"...]
//   returns: true, out_sni = "api.example.com"
fn extract_client_hello_sni(ch_msg: const u8[:], out_sni: u8[..255]&) -> bool {
    out_sni.clear();
    var sid:     u8[..32]             = [];
    var entries: ExtensionEntry[..64] = [];
    let _, ok_pre = tls_internal::decode_ch_server_preamble(ch_msg, sid, entries);
    guard ok_pre else { return false; }
    let sni_ext, has_sni = find_extension(entries, rfc::TLS_EXT_SERVER_NAME);
    guard has_sni && parse_sni_extension(sni_ext, out_sni) else {
        out_sni.clear();
        return false;
    }
    return true;
}

fn run_blocking_server_handshake(
    fd:     i64,
    ch_msg: const u8[:],
    config: const ServerHandshakeConfig&,
) -> u16, bool {
    let slot_idx = alloc_cipher_slot();
    guard slot_idx != 0xFFFF else { return 0xFFFF, false; }
    var committed = false;
    defer if !committed { free_cipher_slot(slot_idx); };
    guard fd > 0 && config.cert_der.len > 0 else { return 0xFFFF, false; }

    var ep, ok_open = tls_internal::pure_open_blocking_server_endpoint(config, ch_msg, slot_idx);
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

// Executes full TLS 1.3 server handshake given an already-read ClientHello handshake message (RFC 8446 §4).
fn server_handshake_with_ch(
    fd:     i64,
    ch_msg: const u8[:],
    config: const ServerHandshakeConfig&,
) -> u16, bool {
    guard ch_msg.len > 0 && ch_msg.len <= 16384 else { return 0xFFFF, false; }
    return run_blocking_server_handshake(fd, ch_msg, config);
}

// Executes full TLS 1.3 server handshake over raw TCP socket, returning slot index (RFC 8446 §4).
fn server_handshake(fd: i64, config: const ServerHandshakeConfig&) -> u16, bool {
    return run_blocking_server_handshake(fd, "", config);
}

// Initializes a non-blocking sans-IO TLS 1.3 server handshake endpoint for event-loop driving (RFC 8446 §4).
fn server_handshake_start(config: const ServerHandshakeConfig&) -> TlsEndpoint, bool {
    guard config.cert_der.len > 0 else { return TlsEndpoint { .. }, false; }
    return tls_internal::pure_open_blocking_server_endpoint(config, "", 0xFFFF);
}

// Finalizes an established non-blocking TLS 1.3 server handshake, detaching its cipher slot and trailing bytes.
//
// Example:
//   ep = established_server_endpoint, out_trailing_ct = [0; 16648]
//   returns: slot_idx = 0, trailing_len = 0, ok = true
fn server_handshake_finish_slot(ep: TlsEndpoint&, out_trailing_ct: u8[:]) -> u16, i64, bool {
    guard !ep.closed && tls_endpoint_is_established(ep) else { return 0xFFFF, 0, false; }
    let trailing_len, ok_tr = tls_internal::pure_take_wire_in_leftover(ep, out_trailing_ct);
    if !ok_tr {
        tls_endpoint_close(ep);
        return 0xFFFF, 0, false;
    }
    let slot_idx = tls_internal::pure_detach_cipher_slot(ep);
    tls_endpoint_close(ep);
    guard slot_idx != 0xFFFF else { return 0xFFFF, 0, false; }
    return slot_idx, trailing_len, true;
}
