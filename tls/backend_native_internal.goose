// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal native C-shim FFI bindings and flag/enum conversions for OpenSSL/Schannel backends.
namespace tls_internal;

import std;
import core;
import .types;

const NATIVE_KIND_PURE: i32 = 0;

const NATIVE_KIND_OPENSSL: i32 = 1;

const NATIVE_KIND_SCHANNEL: i32 = 2;

const NATIVE_KIND_SECURE_TRANSPORT: i32 = 3;

const NATIVE_KIND_AUTO: i32 = 4;

const NATIVE_MIN_TLS13: i32 = 0;

const NATIVE_MIN_TLS12: i32 = 1;

const NATIVE_FLAG_INSECURE_SKIP_VERIFY: i32 = 1;

const NATIVE_FLAG_NO_SYSTEM_ROOTS: i32 = 2;

const NATIVE_FLAG_NO_SESSION_TICKETS: i32 = 4;

extern fn native_tls_backend_available(kind: i32) -> i32 = "wing_tls_backend_available";

extern fn native_tls_backend_open(
    kind:                 i32,
    is_server:            i32,
    insecure_skip_verify: i32,
    min_version:          i32,
    server_name:          const u8[:],
    alpn_wire:            const u8[:],
    ca_file:              const u8[:],
    cert_pem_file:        const u8[:],
    key_pem_file:         const u8[:],
    out_status:           i32&,
    out_active_kind:      i32&,
) -> i64 = "wing_tls_backend_open";

extern fn native_tls_backend_close(handle: i64) = "wing_tls_backend_close";

extern fn native_tls_backend_feed_wire(
    handle:     i64,
    ciphertext: const u8[:],
    out_status: i32&,
) -> i64 = "wing_tls_backend_feed_wire";

extern fn native_tls_backend_drain_wire(
    handle:     i64,
    dst:        u8[:],
    out_status: i32&,
) -> i64 = "wing_tls_backend_drain_wire";

extern fn native_tls_backend_step_handshake(handle: i64) -> i32 = "wing_tls_backend_step_handshake";

extern fn native_tls_backend_write_app(
    handle:     i64,
    plaintext:  const u8[:],
    out_status: i32&,
) -> i64 = "wing_tls_backend_write_app";

extern fn native_tls_backend_read_app(
    handle:     i64,
    dst:        u8[:],
    out_status: i32&,
) -> i64 = "wing_tls_backend_read_app";

extern fn native_tls_backend_selected_alpn(handle: i64, dst: u8[:]) -> i64 = "wing_tls_backend_selected_alpn";

extern fn native_tls_backend_peer_cert_der(handle: i64, dst: u8[:]) -> i64 = "wing_tls_backend_peer_cert_der";

extern fn native_tls_backend_is_established(handle: i64) -> i32 = "wing_tls_backend_is_established";

extern fn native_tls_backend_pending_wire(handle: i64) -> i64 = "wing_tls_backend_pending_wire";

extern fn native_tls_backend_shutdown(handle: i64) -> i32 = "wing_tls_backend_shutdown";

extern fn native_tls_backend_set_keylog(handle: i64, path: const u8[:]) -> i32 = "wing_tls_backend_set_keylog";

inline fn kind_to_native_i32(kind: tls::TlsBackendKind) -> i32 {
    return match kind {
        PureGoose => NATIVE_KIND_PURE,
        SystemOpenSsl => NATIVE_KIND_OPENSSL,
        SystemSchannel => NATIVE_KIND_SCHANNEL,
        SystemSecureTransport => NATIVE_KIND_SECURE_TRANSPORT,
        Auto => NATIVE_KIND_AUTO,
    };
}

inline fn min_version_to_native_i32(min_ver: tls::TlsMinVersion) -> i32 {
    return match min_ver {
        Tls13 => NATIVE_MIN_TLS13,
        Tls12 => NATIVE_MIN_TLS12,
    };
}

inline fn native_i32_to_kind(code: i32) -> tls::TlsBackendKind {
    if code == NATIVE_KIND_OPENSSL { return tls::TlsBackendKind.SystemOpenSsl; }
    if code == NATIVE_KIND_SCHANNEL { return tls::TlsBackendKind.SystemSchannel; }
    if code == NATIVE_KIND_SECURE_TRANSPORT { return tls::TlsBackendKind.SystemSecureTransport; }
    return tls::TlsBackendKind.PureGoose;
}

inline fn native_i32_to_status(code: i32) -> tls::TlsBackendStatus {
    return match code {
        0 => tls::TlsBackendStatus.Ok,
        1 => tls::TlsBackendStatus.WantRead,
        2 => tls::TlsBackendStatus.WantWrite,
        3 => tls::TlsBackendStatus.Closed,
        4 => tls::TlsBackendStatus.Unavailable,
        5 => tls::TlsBackendStatus.HandshakeError,
        6 => tls::TlsBackendStatus.VerifyError,
        _ => tls::TlsBackendStatus.Error,
    };
}

fn native_backend_rejects_cfg(cfg: const tls::TlsBackendConfig&, is_server: bool) -> bool {
    if is_server {
        if cfg.cert_der.len > 0 && cfg.cert_pem_file.len == 0 { return true; }
        return cfg.require_client_cert && (cfg.ca_file.len == 0 || cfg.insecure_skip_verify);
    }
    if cfg.enable_pq_hybrid || cfg.require_ocsp_stapling || cfg.crl_der.len > 0 {
        return true;
    }
    return !cfg.insecure_skip_verify && cfg.trust_store.anchors.len > 0 && cfg.ca_file.len == 0;
}

fn should_route_to_pure_backend(cfg: const tls::TlsBackendConfig&, is_server: bool) -> bool {
    if cfg.kind == tls::TlsBackendKind.PureGoose { return true; }
    guard cfg.kind == tls::TlsBackendKind.Auto else { return false; }
    if is_server {
        if cfg.cert_der.len > 0 && cfg.cert_pem_file.len == 0 { return true; }
        if cfg.require_client_cert {
            return cfg.ca_file.len == 0 || !tls::tls_backend_available(tls::TlsBackendKind.SystemOpenSsl);
        }
        return false;
    }
    if cfg.enable_pq_hybrid || cfg.require_ocsp_stapling || cfg.crl_der.len > 0 {
        return true;
    }
    guard !cfg.insecure_skip_verify else { return false; }
    if cfg.trust_store.anchors.len > 0 && cfg.ca_file.len == 0 {
        return true;
    }
    return cfg.ca_file.len > 0 && !tls::tls_backend_available(tls::TlsBackendKind.SystemOpenSsl);
}

// Packs peer verification, OS root-store, and session-ticket flags for `wing_tls_backend_open`.
//
// Example:
//   cfg.insecure_skip_verify = false, cfg.use_system_roots = false, cfg.enable_session_tickets = false
//   returns: 6 (NATIVE_FLAG_NO_SYSTEM_ROOTS | NATIVE_FLAG_NO_SESSION_TICKETS)
inline fn pack_native_verify_flags(cfg: const tls::TlsBackendConfig&) -> i32 {
    let skip_bit = if cfg.insecure_skip_verify { NATIVE_FLAG_INSECURE_SKIP_VERIFY } else { 0 };
    let roots_bit = if !cfg.use_system_roots { NATIVE_FLAG_NO_SYSTEM_ROOTS } else { 0 };
    let tickets_bit = if !cfg.enable_session_tickets { NATIVE_FLAG_NO_SESSION_TICKETS } else { 0 };
    return skip_bit | roots_bit | tickets_bit;
}
