// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Pluggable sans-IO TLS backend contract supporting PureGoose (RFC 8446 native TLS 1.3),
// dynamically-loaded OpenSSL/BoringSSL, and Windows Schannel without changing caller code.
namespace tls;

import std;
import core;
import .internal;
import .record;
import .record_internal;
import .key_schedule;
import .handshake;
import .handshake_internal;
import .types;
import .x509;
import .pem;
import .ticket;
import .pq_ntt_internal;
import .pq_mlkem_internal;
import .session_internal;
import .session_codec_internal;
import .session;
import .handshake_io_client_internal;
import .handshake_io_server_internal;
import net.tcp;
import net.transport;
import .handshake_wire_internal;
import .session_slot_internal;
import .session_wire_internal;
import .backend_native_internal;
import .backend_pure_internal;
import .backend_pure_hs_internal;
import .backend_transport_internal;
import .pki_nc_san_internal;

// Reports whether `kind` is available in the current runtime environment.
fn tls_backend_available(kind: TlsBackendKind) -> bool {
    if kind == TlsBackendKind.PureGoose || kind == TlsBackendKind.Auto {
        return true;
    }
    return tls_internal::native_tls_backend_available(tls_internal::kind_to_native_i32(kind)) != 0;
}

// Opens a sans-IO TLS endpoint using the configured backend (`PureGoose`, `SystemOpenSsl`,
// `SystemSchannel`, or `Auto` with automatic fallback to `PureGoose`).
fn tls_endpoint_open(cfg: const TlsBackendConfig&) -> TlsEndpoint, TlsBackendStatus {
    return tls_internal::open_endpoint_with_role(cfg, cfg.is_server);
}

// Idempotently closes `ep`, zeroizing key material and freeing native handles.
fn tls_endpoint_close(ep: TlsEndpoint&) {
    guard !ep.closed else { return; }
    if ep.active_kind == TlsBackendKind.PureGoose {
        let idx = ep.pure_slot as i64;
        if idx >= 0 &&
            idx < tls_internal::g_pure_tls_slots.len &&
            tls_internal::is_live_pure_slot(tls_internal::g_pure_tls_slots[idx], ep.pure_gen) {
            tls_internal::reset_and_wipe_pure_slot(tls_internal::g_pure_tls_slots[idx]);
        }
    } else if ep.native_id > 0 {
        tls_internal::native_tls_backend_close(ep.native_id);
    }
    ep.pure_slot = -1;
    ep.pure_gen = 0;
    ep.native_id = -1;
    ep.established = false;
    ep.closed = true;
}

// Feeds inbound wire ciphertext bytes into `ep`, returning `(bytes_accepted, status)`.
fn tls_endpoint_feed_wire(ep: TlsEndpoint&, ciphertext: const u8[:]) -> i64, TlsBackendStatus {
    guard !ep.closed else { return 0, TlsBackendStatus.Closed; }
    guard ciphertext.len > 0 else { return 0, TlsBackendStatus.Ok; }
    if ep.active_kind != TlsBackendKind.PureGoose {
        var st_i32: i32 = 0;
        let n = tls_internal::native_tls_backend_feed_wire(ep.native_id, ciphertext, st_i32);
        return n, tls_internal::native_i32_to_status(st_i32);
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 &&
        idx < tls_internal::g_pure_tls_slots.len &&
        tls_internal::is_live_pure_slot(tls_internal::g_pure_tls_slots[idx], ep.pure_gen) else {
        return 0, TlsBackendStatus.Closed;
    }
    let slot .= tls_internal::g_pure_tls_slots[idx];
    let avail = core::sub_sat_i64(slot.wire_in.cap, slot.wire_in.len);
    guard avail > 0 else { return 0, TlsBackendStatus.WantWrite; }
    let take = min(ciphertext.len, avail);
    guard slot.wire_in.try_append(ciphertext[..take]) else { return 0, TlsBackendStatus.Error; }
    return take, TlsBackendStatus.Ok;
}

// Drains pending outbound wire ciphertext bytes from `ep` into `dst`, returning `(bytes_drained, status)`.
fn tls_endpoint_drain_wire(ep: TlsEndpoint&, dst: u8[:]) -> i64, TlsBackendStatus {
    guard !ep.closed else { return 0, TlsBackendStatus.Closed; }
    guard dst.len > 0 else { return 0, TlsBackendStatus.Ok; }
    if ep.active_kind != TlsBackendKind.PureGoose {
        var st_i32: i32 = 0;
        let n = tls_internal::native_tls_backend_drain_wire(ep.native_id, dst, st_i32);
        return n, tls_internal::native_i32_to_status(st_i32);
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 &&
        idx < tls_internal::g_pure_tls_slots.len &&
        tls_internal::is_live_pure_slot(tls_internal::g_pure_tls_slots[idx], ep.pure_gen) else {
        return 0, TlsBackendStatus.Closed;
    }
    let slot .= tls_internal::g_pure_tls_slots[idx];
    guard slot.wire_out.len > 0 else { return 0, TlsBackendStatus.Ok; }
    let take = min(slot.wire_out.len, dst.len);
    core::ct_copy_bytes(dst[..take], slot.wire_out[..take]);
    slot.wire_out.compact_wire_buffer(take);
    return take, TlsBackendStatus.Ok;
}

// Advances the sans-IO TLS handshake state machine until established or more I/O is needed.
fn tls_endpoint_step_handshake(ep: TlsEndpoint&) -> TlsBackendStatus {
    guard !ep.closed else { return TlsBackendStatus.Closed; }
    if ep.established { return TlsBackendStatus.Ok; }
    if ep.active_kind != TlsBackendKind.PureGoose {
        let st = tls_internal::native_i32_to_status(tls_internal::native_tls_backend_step_handshake(ep.native_id));
        if st == TlsBackendStatus.Ok {
            ep.established = true;
        }
        return st;
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 &&
        idx < tls_internal::g_pure_tls_slots.len &&
        tls_internal::is_live_pure_slot(tls_internal::g_pure_tls_slots[idx], ep.pure_gen) else {
        return TlsBackendStatus.Closed;
    }
    let st = tls_internal::pure_step_handshake_loop(tls_internal::g_pure_tls_slots[idx]);
    if st == TlsBackendStatus.Ok {
        ep.established = true;
    }
    return st;
}

// Encrypts application plaintext into `ep`'s outbound wire queue, returning `(bytes_written, status)`.
fn tls_endpoint_write_app(ep: TlsEndpoint&, plaintext: const u8[:]) -> i64, TlsBackendStatus {
    guard !ep.closed else { return 0, TlsBackendStatus.Closed; }
    guard ep.established else { return 0, TlsBackendStatus.HandshakeError; }
    guard plaintext.len > 0 else { return 0, TlsBackendStatus.Ok; }
    if ep.active_kind != TlsBackendKind.PureGoose {
        var st_i32: i32 = 0;
        let n = tls_internal::native_tls_backend_write_app(ep.native_id, plaintext, st_i32);
        return n, tls_internal::native_i32_to_status(st_i32);
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 &&
        idx < tls_internal::g_pure_tls_slots.len &&
        tls_internal::is_live_pure_slot(tls_internal::g_pure_tls_slots[idx], ep.pure_gen) else {
        return 0, TlsBackendStatus.Closed;
    }
    let slot .= tls_internal::g_pure_tls_slots[idx];
    let avail = core::sub_sat_i64(slot.wire_out.cap, slot.wire_out.len);
    let cs_i = slot.cipher_slot as i64;
    let ku_reserve: i64 = if cs_i >= 0 && cs_i < g_tls_cipher_slots.len &&
        tls_internal::slot_needs_sans_io_key_update(g_tls_cipher_slots[cs_i]) {
        27
    } else {
        0
    };
    let overhead = core::add_sat_i64(22, ku_reserve);
    guard avail > overhead else { return 0, TlsBackendStatus.WantWrite; }
    let max_plain = min(core::sub_sat_i64(avail, overhead), rfc::TLS_MAX_RECORD_PLAINTEXT_LEN);
    let take = min(plaintext.len, max_plain);
    guard cipher_slot_seal_app_data(slot.cipher_slot, plaintext[..take], slot.wire_out) else {
        return 0, TlsBackendStatus.Error;
    }
    return take, TlsBackendStatus.Ok;
}

// Decrypts inbound wire ciphertext into `dst`, returning `(bytes_read, status)`.
fn tls_endpoint_read_app(ep: TlsEndpoint&, dst: u8[:]) -> i64, TlsBackendStatus {
    guard !ep.closed else { return 0, TlsBackendStatus.Closed; }
    guard ep.established else { return 0, TlsBackendStatus.HandshakeError; }
    guard dst.len > 0 else { return 0, TlsBackendStatus.Ok; }
    if ep.active_kind != TlsBackendKind.PureGoose {
        var st_i32: i32 = 0;
        let n = tls_internal::native_tls_backend_read_app(ep.native_id, dst, st_i32);
        return n, tls_internal::native_i32_to_status(st_i32);
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 &&
        idx < tls_internal::g_pure_tls_slots.len &&
        tls_internal::is_live_pure_slot(tls_internal::g_pure_tls_slots[idx], ep.pure_gen) else {
        return 0, TlsBackendStatus.Closed;
    }
    let slot .= tls_internal::g_pure_tls_slots[idx];
    if core::sub_sat_i64(slot.app_in.len, slot.app_in_pos) == 0 && slot.wire_in.len > 0 {
        let ust = tls_internal::pure_unseal_one_app_record(slot);
        if ust == TlsBackendStatus.Error { return 0, TlsBackendStatus.Error; }
    }
    let rem = core::sub_sat_i64(slot.app_in.len, slot.app_in_pos);
    if rem > 0 {
        let take = min(rem, dst.len);
        core::ct_copy_bytes(dst[..take], slot.app_in[slot.app_in_pos..core::add_sat_i64(slot.app_in_pos, take)]);
        slot.app_in_pos = core::add_sat_i64(slot.app_in_pos, take);
        if slot.app_in_pos >= slot.app_in.len {
            core::secure_zeroize_slice(slot.app_in[..]);
            slot.app_in.clear();
            slot.app_in_pos = 0;
        }
        return take, TlsBackendStatus.Ok;
    }
    return 0, if slot.peer_closed { TlsBackendStatus.Closed } else { TlsBackendStatus.WantRead };
}

// Returns the normalized client-offered SNI hostname extracted from ClientHello (empty if omitted).
fn tls_endpoint_client_sni(ep: const TlsEndpoint&) -> u8[..255] {
    var out: u8[..255] = [];
    guard !ep.closed && ep.active_kind == TlsBackendKind.PureGoose else { return out; }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 &&
        idx < tls_internal::g_pure_tls_slots.len &&
        tls_internal::is_live_pure_slot(tls_internal::g_pure_tls_slots[idx], ep.pure_gen) else {
        return out;
    }
    let slot .= tls_internal::g_pure_tls_slots[idx];
    guard slot.is_server && slot.client_hello_parsed else { return out; }
    let _ = out.try_set(slot.server_name[..]);
    return out;
}

// Installs PEM-encoded server certificate chain and matching private key on a deferred-SNI endpoint
// paused at `TlsBackendStatus.NeedSniCredentials`. Fails closed and releases temporary key material on error.
fn tls_endpoint_set_server_credentials_pem(
    ep:       TlsEndpoint&,
    cert_pem: const u8[:],
    key_pem:  const u8[:],
) -> TlsBackendStatus {
    guard !ep.closed else { return TlsBackendStatus.Closed; }
    guard ep.active_kind == TlsBackendKind.PureGoose else { return TlsBackendStatus.Unavailable; }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 &&
        idx < tls_internal::g_pure_tls_slots.len &&
        tls_internal::is_live_pure_slot(tls_internal::g_pure_tls_slots[idx], ep.pure_gen) else {
        return TlsBackendStatus.Closed;
    }
    let slot .= tls_internal::g_pure_tls_slots[idx];
    guard slot.is_server && slot.stage == tls_internal::PureHsStage.ServerNeedSniCredentials else {
        return TlsBackendStatus.HandshakeError;
    }
    guard cert_pem.len > 0 && key_pem.len > 0 else {
        slot.stage = tls_internal::PureHsStage.Failed;
        return TlsBackendStatus.HandshakeError;
    }

    var srv_cfg = ServerHandshakeConfig { .. };
    defer release_server_credentials(srv_cfg);
    guard load_server_credentials_pem(cert_pem, key_pem, srv_cfg) &&
        slot.cert_der.try_set(srv_cfg.cert_der[..]) else {
        slot.stage = tls_internal::PureHsStage.Failed;
        return TlsBackendStatus.HandshakeError;
    }
    tls_internal::release_pure_server_signing_creds(slot);
    slot.extra_certs_der = copy(srv_cfg.extra_certs_der);
    slot.priv_seed = srv_cfg.priv_seed;
    slot.key_kind = srv_cfg.key_kind;
    slot.rsa_key_slot = srv_cfg.rsa_key_slot;
    slot.rsa_key_gen = srv_cfg.rsa_key_gen;
    slot.owns_rsa_key_slot = srv_cfg.rsa_key_slot >= 0;
    srv_cfg.rsa_key_slot = -1;
    srv_cfg.rsa_key_gen = 0;
    slot.defer_sni_credentials = false;
    slot.stage = tls_internal::PureHsStage.ServerWaitClientHello;
    return TlsBackendStatus.Ok;
}

// Returns the negotiated ALPN protocol name (empty if none was negotiated).
fn tls_endpoint_selected_alpn(ep: const TlsEndpoint&) -> u8[..255] {
    var out: u8[..255] = [];
    guard !ep.closed else { return out; }
    if ep.active_kind != TlsBackendKind.PureGoose {
        var raw: u8[255] = [0; 255];
        let n = tls_internal::native_tls_backend_selected_alpn(ep.native_id, raw[..]);
        if n > 0 && n <= 255 {
            let _ = out.try_set(raw[..n]);
        }
        return out;
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 &&
        idx < tls_internal::g_pure_tls_slots.len &&
        tls_internal::is_live_pure_slot(tls_internal::g_pure_tls_slots[idx], ep.pure_gen) else {
        return out;
    }
    let _ = out.try_set(tls_internal::g_pure_tls_slots[idx].selected_alpn[..]);
    return out;
}

// Extracts the authenticated peer leaf X.509 certificate in DER form.
fn tls_endpoint_peer_cert_der(ep: const TlsEndpoint&) -> u8[..8192], bool {
    var out: u8[..8192] = [];
    guard !ep.closed && tls_endpoint_is_established(ep) else { return out, false; }
    if ep.active_kind != TlsBackendKind.PureGoose {
        var raw: u8[8192] = [0; 8192];
        let n = tls_internal::native_tls_backend_peer_cert_der(ep.native_id, raw[..]);
        guard n > 0 && n <= 8192 && out.try_set(raw[..n]) else { return out, false; }
        return out, true;
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 &&
        idx < tls_internal::g_pure_tls_slots.len &&
        tls_internal::is_live_pure_slot(tls_internal::g_pure_tls_slots[idx], ep.pure_gen) else {
        return out, false;
    }
    let leaf .= tls_internal::g_pure_tls_slots[idx].peer_leaf_der;
    guard leaf.len > 0 && out.try_set(leaf[..]) else { return out, false; }
    return out, true;
}

// Verifies that the established peer's leaf certificate includes an exact URI SAN matching `expected_uri`
// (for SPIFFE workload identity pinning such as `spiffe://trust-domain/workload`).
fn tls_endpoint_verify_spiffe_uri(ep: const TlsEndpoint&, expected_uri: const u8[:]) -> bool {
    guard expected_uri.len > 9 && expected_uri.starts_with("spiffe://") else { return false; }
    guard expected_uri[9] != '/' &&
        !expected_uri.contains_byte(0) &&
        !expected_uri.contains_byte('%') else {
        return false;
    }
    let peer_der, ok_der = tls_endpoint_peer_cert_der(ep);
    guard ok_der && peer_der.len > 0 else { return false; }

    var cert = ParsedCert { .. };
    guard parse_x509_certificate(peer_der[..], cert) && cert.has_san else { return false; }
    var names_seq = core::cursor_from(peer_der[..0]);
    guard tls_internal::x509_open_san_sequence(span_slice(peer_der[..], cert.san_raw), names_seq) else {
        return false;
    }
    var matched = false;
    while names_seq.cursor_len() > 0 {
        let entry, ok_entry = tls_internal::x509_next_san_entry(names_seq);
        guard ok_entry else { return false; }
        if entry.san_type == SanType.Uri && entry.val == expected_uri {
            matched = true;
        }
    }
    return matched;
}

// Reports whether `ep` has completed the TLS handshake and is ready for application data.
fn tls_endpoint_is_established(ep: const TlsEndpoint&) -> bool {
    guard !ep.closed else { return false; }
    if ep.active_kind != TlsBackendKind.PureGoose {
        return tls_internal::native_tls_backend_is_established(ep.native_id) != 0;
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 &&
        idx < tls_internal::g_pure_tls_slots.len &&
        tls_internal::is_live_pure_slot(tls_internal::g_pure_tls_slots[idx], ep.pure_gen) else {
        return false;
    }
    return ep.established && tls_internal::g_pure_tls_slots[idx].stage == tls_internal::PureHsStage.Established;
}

// Returns the number of outbound wire ciphertext bytes currently buffered in `ep`.
fn tls_endpoint_pending_wire(ep: const TlsEndpoint&) -> i64 {
    guard !ep.closed else { return 0; }
    if ep.active_kind != TlsBackendKind.PureGoose {
        return tls_internal::native_tls_backend_pending_wire(ep.native_id);
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 &&
        idx < tls_internal::g_pure_tls_slots.len &&
        tls_internal::is_live_pure_slot(tls_internal::g_pure_tls_slots[idx], ep.pure_gen) else {
        return 0;
    }
    return tls_internal::g_pure_tls_slots[idx].wire_out.len;
}

// Queues an RFC 8446 Section 6.1 graceful CloseNotify alert into `ep`'s outbound wire queue.
// Call `tls_endpoint_drain_wire` afterwards to flush the alert before closing the socket.
fn tls_endpoint_shutdown(ep: TlsEndpoint&) -> TlsBackendStatus {
    guard !ep.closed else { return TlsBackendStatus.Closed; }
    guard ep.established else { return TlsBackendStatus.Ok; }
    if ep.active_kind != TlsBackendKind.PureGoose {
        return tls_internal::native_i32_to_status(tls_internal::native_tls_backend_shutdown(ep.native_id));
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 &&
        idx < tls_internal::g_pure_tls_slots.len &&
        tls_internal::is_live_pure_slot(tls_internal::g_pure_tls_slots[idx], ep.pure_gen) else {
        return TlsBackendStatus.Closed;
    }
    let slot .= tls_internal::g_pure_tls_slots[idx];
    guard slot.cipher_slot != 0xFFFF else { return TlsBackendStatus.Ok; }
    let avail = core::sub_sat_i64(slot.wire_out.cap, slot.wire_out.len);
    guard avail >= 64 else { return TlsBackendStatus.WantWrite; }
    guard cipher_slot_seal_close_notify(slot.cipher_slot, slot.wire_out) else {
        return TlsBackendStatus.Error;
    }
    return TlsBackendStatus.Ok;
}

// Drives a client-side TLS handshake over live TCP or virtual pipe `fd` using `cfg`.
// Returns `(slot_id, negotiated_alpn, status)`; caller retains `fd` ownership on failure.
fn endpoint_client_handshake_fd(
    fd:         i64,
    cfg:        const TlsBackendConfig&,
    timeout_ms: u32 = 5000,
) -> i64, u8[..64], TlsBackendStatus {
    return tls_internal::endpoint_run_handshake_fd(fd, cfg, false, timeout_ms);
}

// Drives a server-side TLS handshake over live TCP or virtual pipe `fd` using `cfg`.
// Returns `(slot_id, negotiated_alpn, status)`; caller retains `fd` ownership on failure.
fn endpoint_server_handshake_fd(
    fd:         i64,
    cfg:        const TlsBackendConfig&,
    timeout_ms: u32 = 5000,
) -> i64, u8[..64], TlsBackendStatus {
    return tls_internal::endpoint_run_handshake_fd(fd, cfg, true, timeout_ms);
}

// Encrypts `data` via the backend `TlsEndpoint` at `slot_id` and flushes ciphertext to `fd`.
// Returns total plaintext bytes sent (> 0), 0 for empty slice, or -1 on error.
recursive fn endpoint_transport_send(fd: i64, slot_id: i64, data: const u8[:]) -> i32 {
    guard data.len > 0 else { return 0; }
    guard fd > 0 && tls_internal::endpoint_slot_is_ready(slot_id) else { return -1; }
    let slot .= tls_internal::g_backend_transport_slots[slot_id];

    var off:           i64 = 0;
    var zero_progress: i32 = 0;
    while off < data.len {
        let nw, st = tls_endpoint_write_app(slot.ep, data[off..]);
        guard tls_internal::endpoint_drain_to_fd(slot.ep, fd) else { return -1; }
        if nw > 0 {
            off = core::add_sat_i64(off, nw);
            zero_progress = 0;
            continue;
        }
        guard st == TlsBackendStatus.WantWrite && zero_progress < 8 else { return -1; }
        zero_progress = core::add_sat_u32(zero_progress as u32, 1) as i32;
    }
    return (off & 0x7FFFFFFF) as i32;
}

// Decrypts plaintext from the backend `TlsEndpoint` at `slot_id` into `dst`, pulling
// ciphertext from `fd` whenever the endpoint reports `WantRead`.
// Returns plaintext bytes read (> 0), 0 on clean EOF/CloseNotify, -2 on timeout, or -1 on error.
recursive fn endpoint_transport_recv_slice(
    fd:         i64,
    slot_id:    i64,
    dst:        u8[:],
    timeout_ms: u32 = 5000,
) -> i32 {
    guard fd > 0 && dst.len > 0 && tls_internal::endpoint_slot_is_ready(slot_id) else { return -1; }
    let slot .= tls_internal::g_backend_transport_slots[slot_id];

    for _ in 64 {
        let nr, st = tls_internal::endpoint_try_read_buffered(slot, fd, dst);
        if nr > 0 { return (nr & 0x7FFFFFFF) as i32; }
        if st == TlsBackendStatus.Closed { return 0; }
        guard st == TlsBackendStatus.WantRead else { return -1; }

        let rx_st = tls_internal::endpoint_feed_slot_rx(slot, fd, timeout_ms);
        if rx_st <= 0 { return rx_st; }
    }
    return -1;
}

// Idempotently closes the backend endpoint slot and underlying socket/virtual pipe `fd`.
recursive fn endpoint_transport_close(fd: i64, slot_id: i64) {
    if slot_id >= 0 && slot_id < tls_internal::g_backend_transport_slots.len {
        let was_in_use = tls_internal::g_backend_transport_slots[slot_id].in_use;
        if was_in_use {
            tls_internal::release_backend_transport_slot(slot_id);
            net::fd_close(fd);
        }
        return;
    }
    net::fd_close(fd);
}
