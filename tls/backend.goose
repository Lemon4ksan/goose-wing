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
import .session_internal;
import .session;
import .handshake_io_internal;
import net.tcp;
import net.transport;

// ---- Public Pluggable Backend Contract Types -------------------------------

enum TlsBackendKind {
    PureGoose,
    SystemOpenSsl,
    SystemSchannel,
    SystemSecureTransport,
    Auto,
}

enum TlsMinVersion {
    Tls13,
    Tls12,
}

enum TlsBackendStatus {
    Ok,
    WantRead,
    WantWrite,
    Closed,
    Unavailable,
    HandshakeError,
    VerifyError,
    Error,
}

struct TlsBackendConfig {
    kind:                 TlsBackendKind   = TlsBackendKind.PureGoose,
    min_version:          TlsMinVersion    = TlsMinVersion.Tls13,
    is_server:            bool             = false,
    server_name:          u8[..256]        = [],
    alpn_wire:            u8[..64]         = [],
    insecure_skip_verify: bool             = false,
    ca_file:              u8[..256]        = [],
    cert_pem_file:        u8[..256]        = [],
    key_pem_file:         u8[..256]        = [],
    cert_der:             u8[..4096]       = [],
    priv_seed:            u8[32]           = [0; 32],
    trust_store:          TrustAnchorStore = TrustAnchorStore { .. },
}

struct TlsEndpoint {
    kind:        TlsBackendKind = TlsBackendKind.PureGoose,
    active_kind: TlsBackendKind = TlsBackendKind.PureGoose,
    is_server:   bool           = false,
    established: bool           = false,
    closed:      bool           = false,
    pure_slot:   i32            = -1,
    native_id:   i64            = -1,
}

// ---- Native C Shim FFI (shim/tls_backend.c) --------------------------------

const NATIVE_KIND_PURE:             i32 = 0;
const NATIVE_KIND_OPENSSL:          i32 = 1;
const NATIVE_KIND_SCHANNEL:         i32 = 2;
const NATIVE_KIND_SECURE_TRANSPORT: i32 = 3;
const NATIVE_KIND_AUTO:             i32 = 4;

const NATIVE_MIN_TLS13: i32 = 0;
const NATIVE_MIN_TLS12: i32 = 1;

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

extern fn native_tls_backend_is_established(handle: i64) -> i32 = "wing_tls_backend_is_established";

extern fn native_tls_backend_pending_wire(handle: i64) -> i64 = "wing_tls_backend_pending_wire";

extern fn native_tls_backend_shutdown(handle: i64) -> i32 = "wing_tls_backend_shutdown";

inline fn kind_to_native_i32(kind: TlsBackendKind) -> i32 {
    return match kind {
        PureGoose => NATIVE_KIND_PURE,
        SystemOpenSsl => NATIVE_KIND_OPENSSL,
        SystemSchannel => NATIVE_KIND_SCHANNEL,
        SystemSecureTransport => NATIVE_KIND_SECURE_TRANSPORT,
        Auto => NATIVE_KIND_AUTO,
    };
}

inline fn min_version_to_native_i32(min_ver: TlsMinVersion) -> i32 {
    return match min_ver {
        Tls13 => NATIVE_MIN_TLS13,
        Tls12 => NATIVE_MIN_TLS12,
    };
}

inline fn native_i32_to_kind(code: i32) -> TlsBackendKind {
    if code == NATIVE_KIND_OPENSSL { return TlsBackendKind.SystemOpenSsl; }
    if code == NATIVE_KIND_SCHANNEL { return TlsBackendKind.SystemSchannel; }
    if code == NATIVE_KIND_SECURE_TRANSPORT { return TlsBackendKind.SystemSecureTransport; }
    return TlsBackendKind.PureGoose;
}

inline fn native_i32_to_status(code: i32) -> TlsBackendStatus {
    return match code {
        0 => TlsBackendStatus.Ok,
        1 => TlsBackendStatus.WantRead,
        2 => TlsBackendStatus.WantWrite,
        3 => TlsBackendStatus.Closed,
        4 => TlsBackendStatus.Unavailable,
        5 => TlsBackendStatus.HandshakeError,
        6 => TlsBackendStatus.VerifyError,
        _ => TlsBackendStatus.Error,
    };
}

// ---- PureGoose Sans-IO Endpoint Slot Storage -------------------------------

const MAX_PURE_TLS_SLOTS: i64 = 32;

enum PureHsStage {
    ClientInit,
    ClientWaitServerHello,
    ClientWaitEE,
    ClientWaitCert,
    ClientWaitCV,
    ClientWaitFinished,
    ServerWaitClientHello,
    ServerWaitClientFinished,
    Established,
    Failed,
}

struct PureTlsSlot {
    in_use:               bool                      = false,
    is_server:            bool                      = false,
    insecure_skip_verify: bool                      = false,
    peer_closed:          bool                      = false,
    stage:                PureHsStage               = PureHsStage.ClientInit,
    cipher_slot:          u16                       = 0xFFFF,
    cipher_suite:         u16                       = rfc::TLS_CIPHER_AES_128_GCM_SHA256,
    key_len:              u16                       = 16,
    server_name:          u8[..256]                 = [],
    alpn_csv:             u8[..64]                  = [],
    selected_alpn:        u8[..64]                  = [],
    cert_der:             u8[..4096]                = [],
    priv_seed:            u8[32]                    = [0; 32],
    trust_store:          TrustAnchorStore          = TrustAnchorStore { .. },
    client_random:        u8[32]                    = [0; 32],
    eph_priv:             u8[32]                    = [0; 32],
    hs_tx_key:            u8[32]                    = [0; 32],
    hs_tx_iv:             u8[12]                    = [0; 12],
    hs_rx_key:            u8[32]                    = [0; 32],
    hs_rx_iv:             u8[12]                    = [0; 12],
    hs_tx_seq:            u64                       = 0,
    hs_rx_seq:            u64                       = 0,
    ccs_seen:             u32                       = 0,
    transcript:           Transcript                = Transcript { .. },
    ks:                   tls_internal::KeySchedule = tls_internal::KeySchedule { .. },
    srv_fin_hash:         u8[..48]                  = [],
    peer_cert_body:       u8[..8192]                = [],
    hs_plain:             u8[..16384]               = [],
    hs_plain_pos:         i64                       = 0,
    wire_in:              u8[..32768]               = [],
    wire_out:             u8[..32768]               = [],
    app_in:               u8[..16640]               = [],
    app_in_pos:           i64                       = 0,
}

var g_pure_tls_slots: PureTlsSlot[>..] = [];

fn wipe_pure_hs_secrets(slot: PureTlsSlot&) {
    core::secure_zeroize_32(slot.eph_priv);
    core::secure_zeroize_32(slot.hs_tx_key);
    core::secure_zeroize_32(slot.hs_rx_key);
    core::secure_zeroize_slice(slot.hs_tx_iv[..]);
    core::secure_zeroize_slice(slot.hs_rx_iv[..]);
    tls_internal::ks_zeroize(slot.ks);
    core::secure_zeroize_slice(slot.srv_fin_hash[..]);
    slot.srv_fin_hash.clear();
}

fn reset_and_wipe_pure_slot(slot: PureTlsSlot&) {
    if slot.cipher_slot != 0xFFFF {
        free_cipher_slot(slot.cipher_slot);
    }
    wipe_pure_hs_secrets(slot);
    core::secure_zeroize_32(slot.priv_seed);
    core::secure_zeroize_slice(slot.wire_in[..]);
    core::secure_zeroize_slice(slot.wire_out[..]);
    core::secure_zeroize_slice(slot.app_in[..]);
    core::secure_zeroize_slice(slot.hs_plain[..]);
    slot = PureTlsSlot { .. };
}

fn alloc_pure_tls_slot() -> i32 {
    for i in g_pure_tls_slots.len {
        if !g_pure_tls_slots[i].in_use {
            reset_and_wipe_pure_slot(g_pure_tls_slots[i]);
            g_pure_tls_slots[i].in_use = true;
            return i as i32;
        }
    }
    guard g_pure_tls_slots.len < MAX_PURE_TLS_SLOTS else { return -1; }
    let idx = g_pure_tls_slots.len;
    g_pure_tls_slots.push(PureTlsSlot { in_use: true, .. });
    return idx as i32;
}

// Decodes RFC 7301 length-prefixed ALPN wire bytes into comma-separated protocol names.
// Falls back to copying raw ASCII CSV if the input is not length-prefixed wire format.
//
// Example:
//   alpn_wire = [0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1']
//   out_csv = "h2,http/1.1"
fn decode_alpn_wire_to_csv(alpn_wire: const u8[:], out_csv: u8[..64]&) {
    out_csv.clear();
    guard alpn_wire.len > 0 else { return; }
    var c = core::cursor_from(alpn_wire);
    var parsed: u8[..64] = [];
    var ok_wire = true;
    while c.buf.len > 0 {
        let proto, ok = c.read_u8_prefixed();
        if !ok || proto.len == 0 {
            ok_wire = false;
            break;
        }
        if parsed.len > 0 && !parsed.try_push(',') {
            ok_wire = false;
            break;
        }
        if !parsed.try_append(proto) {
            ok_wire = false;
            break;
        }
    }
    if ok_wire && parsed.len > 0 {
        let _ = out_csv.try_set(parsed[..]);
        return;
    }
    let take = min(alpn_wire.len, out_csv.cap);
    let _ = out_csv.try_set(alpn_wire[..take]);
}

// ---- PureGoose Record & Handshake Framing Helpers --------------------------

fn pure_append_plaintext_hs(out: u8[..32768]&, hs_msg: const u8[:]) -> bool {
    guard hs_msg.len > 0 && hs_msg.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else { return false; }
    let saved = out.len;
    var committed = false;
    defer if !committed { out.resize(saved); };
    guard out.try_push(rfc::TLS_CONTENT_HANDSHAKE) &&
        out.try_push(0x03) &&
        out.try_push(0x01) else {
        return false;
    }
    let len_u16 = hs_msg.len as u16;
    guard out.try_push(((len_u16 >> 8) & 0xFF) as u8) &&
        out.try_push((len_u16 & 0xFF) as u8) &&
        out.try_append(hs_msg) else {
        return false;
    }
    committed = true;
    return true;
}

fn pure_seal_hs_to_wire(slot: PureTlsSlot&, hs_msg: const u8[:]) -> bool {
    let klen = slot.key_len as i64;
    let needed = core::add_sat_i64(hs_msg.len, 32);
    guard needed <= 8192 else { return false; }
    var ct_buf: u8[8192] = [0; 8192];
    let s_len, _, ok_s = record_seal_into(
        slot.cipher_suite,
        slot.hs_tx_key[..klen],
        slot.hs_tx_iv,
        slot.hs_tx_seq,
        rfc::TLS_CONTENT_HANDSHAKE,
        hs_msg,
        ct_buf[..needed],
    );
    guard ok_s && s_len > 0 && slot.wire_out.try_append(ct_buf[..s_len]) else { return false; }
    let _ = increment_record_seq_num(slot.hs_tx_seq);
    return true;
}

// Validates a single RFC 8446 Section 5 middlebox-compatibility ChangeCipherSpec record.
fn pure_accept_ccs_record(slot: PureTlsSlot&, ver: u16, body: const u8[:]) -> bool {
    guard slot.ccs_seen < 1 &&
        slot.hs_plain.len == 0 &&
        ver == rfc::TLS_LEGACY_VERSION_1_2 &&
        validate_change_cipher_spec_record(body) == Alert.CloseNotify else {
        return false;
    }
    slot.ccs_seen = core::add_sat_u32(slot.ccs_seen, 1);
    return true;
}

fn pure_pop_plaintext_hs_msg(slot: PureTlsSlot&, out_msg: u8[..16384]&) -> TlsBackendStatus {
    out_msg.clear();
    while true {
        if has_complete_plaintext_handshake_msg(slot.hs_plain[..]) {
            let _, mlen, ok_h = parse_handshake_header(slot.hs_plain[..]);
            guard ok_h else { return TlsBackendStatus.HandshakeError; }
            let full_len = core::add_sat_i64(4, mlen);
            guard out_msg.try_set(slot.hs_plain[..full_len]) else { return TlsBackendStatus.Error; }
            slot.hs_plain.compact_wire_buffer(full_len);
            return TlsBackendStatus.Ok;
        }
        guard slot.wire_in.len >= 5 else { return TlsBackendStatus.WantRead; }
        let ct, ver, plen_u16, _, ok_hdr = parse_record_header(slot.wire_in[..5]);
        guard ok_hdr else { return TlsBackendStatus.HandshakeError; }
        let plen = plen_u16 as i64;
        let rec_total = core::add_sat_i64(5, plen);
        guard plen <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else { return TlsBackendStatus.HandshakeError; }
        guard slot.wire_in.len >= rec_total else { return TlsBackendStatus.WantRead; }
        let body = slot.wire_in[5..rec_total];
        if ct == rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC {
            guard pure_accept_ccs_record(slot, ver, body) else { return TlsBackendStatus.HandshakeError; }
            slot.wire_in.compact_wire_buffer(rec_total);
            continue;
        }
        guard ct == rfc::TLS_CONTENT_HANDSHAKE && slot.hs_plain.try_append(body) else {
            return TlsBackendStatus.HandshakeError;
        }
        slot.wire_in.compact_wire_buffer(rec_total);
    }
    return TlsBackendStatus.WantRead;
}

fn pure_try_consume_hs_plain_msg(
    slot:     PureTlsSlot&,
    out_type: u8&,
    out_body: u8[..16384]&,
) -> bool {
    let rem = core::sub_sat_i64(slot.hs_plain.len, slot.hs_plain_pos);
    guard rem >= 4 else { return false; }
    let slice = slot.hs_plain[slot.hs_plain_pos..];
    let mt, mlen, ok_h = parse_handshake_header(slice);
    guard ok_h else { return false; }
    let total = core::add_sat_i64(4, mlen);
    guard rem >= total && out_body.try_set(slice[4..total]) else { return false; }
    out_type = mt;
    slot.hs_plain_pos = core::add_sat_i64(slot.hs_plain_pos, total);
    if slot.hs_plain_pos >= slot.hs_plain.len {
        slot.hs_plain.clear();
        slot.hs_plain_pos = 0;
    }
    return true;
}

fn pure_decrypt_one_hs_record(slot: PureTlsSlot&) -> TlsBackendStatus {
    guard slot.wire_in.len >= 5 else { return TlsBackendStatus.WantRead; }
    let ct, ver, plen_u16, _, ok_hdr = parse_record_header(slot.wire_in[..5]);
    guard ok_hdr else { return TlsBackendStatus.HandshakeError; }
    let plen = plen_u16 as i64;
    let rec_total = core::add_sat_i64(5, plen);
    guard plen <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else { return TlsBackendStatus.HandshakeError; }
    guard slot.wire_in.len >= rec_total else { return TlsBackendStatus.WantRead; }

    if ct == rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC {
        let ccs_ok = slot.ccs_seen < 1 &&
            slot.hs_plain_pos == slot.hs_plain.len &&
            ver == rfc::TLS_LEGACY_VERSION_1_2 &&
            validate_change_cipher_spec_record(slot.wire_in[5..rec_total]) == Alert.CloseNotify;
        guard ccs_ok else { return TlsBackendStatus.HandshakeError; }
        slot.ccs_seen = core::add_sat_u32(slot.ccs_seen, 1);
        slot.wire_in.compact_wire_buffer(rec_total);
        return TlsBackendStatus.Ok;
    }
    guard ct == rfc::TLS_CONTENT_APPLICATION_DATA else { return TlsBackendStatus.HandshakeError; }

    if slot.hs_plain_pos > 0 {
        slot.hs_plain.compact_wire_buffer(slot.hs_plain_pos);
        slot.hs_plain_pos = 0;
    }
    var plain_dec: u8[16640] = [0; 16640];
    defer core::secure_zeroize_slice(plain_dec[..plen]);
    let klen = slot.key_len as i64;
    let dec_len, inner_t, _, ok_dec = record_decrypt_into(
        slot.cipher_suite,
        slot.hs_rx_key[..klen],
        slot.hs_rx_iv,
        slot.hs_rx_seq,
        slot.wire_in[..5],
        slot.wire_in[5..rec_total],
        plain_dec[..plen],
    );
    guard ok_dec && inner_t == rfc::TLS_CONTENT_HANDSHAKE && dec_len > 0 else {
        return TlsBackendStatus.HandshakeError;
    }
    let _ = increment_record_seq_num(slot.hs_rx_seq);
    slot.wire_in.compact_wire_buffer(rec_total);
    guard slot.hs_plain.try_append(plain_dec[..dec_len]) else { return TlsBackendStatus.Error; }
    return TlsBackendStatus.Ok;
}

fn pure_next_encrypted_hs_msg(
    slot:     PureTlsSlot&,
    out_type: u8&,
    out_body: u8[..16384]&,
) -> TlsBackendStatus {
    while true {
        if pure_try_consume_hs_plain_msg(slot, out_type, out_body) {
            return TlsBackendStatus.Ok;
        }
        let st = pure_decrypt_one_hs_record(slot);
        guard st == TlsBackendStatus.Ok else { return st; }
    }
    return TlsBackendStatus.WantRead;
}

fn pure_derive_hs_traffic_keys(slot: PureTlsSlot&, ecdhe_secret: const u8[:]) -> bool {
    var ks, ok_ks = tls_internal::ks_init(slot.cipher_suite);
    guard ok_ks &&
        tls_internal::ks_init_early_secret(ks, "") &&
        tls_internal::ks_advance_to_handshake(ks, ecdhe_secret) else {
        tls_internal::ks_zeroize(ks);
        return false;
    }
    var ch_sh_hash: u8[..48] = [];
    transcript_current_hash(slot.transcript, ks.hash_id, ch_sh_hash);
    guard tls_internal::ks_derive_handshake_traffic(ks, ch_sh_hash[..]) else {
        tls_internal::ks_zeroize(ks);
        return false;
    }
    let klen_u16 = rfc::tls13_cipher_suite_key_len(slot.cipher_suite);
    let klen = klen_u16 as i64;
    let hlen = ks.hash_len as i64;
    let tx_sec = if slot.is_server { ks.server_hs_traffic[..hlen] } else { ks.client_hs_traffic[..hlen] };
    let rx_sec = if slot.is_server { ks.client_hs_traffic[..hlen] } else { ks.server_hs_traffic[..hlen] };
    let ok_tx = tls_internal::ks_derive_key_iv(ks.hash_id, tx_sec, klen_u16, slot.hs_tx_key[..klen], slot.hs_tx_iv);
    let ok_rx = tls_internal::ks_derive_key_iv(ks.hash_id, rx_sec, klen_u16, slot.hs_rx_key[..klen], slot.hs_rx_iv);
    guard ok_tx && ok_rx else {
        tls_internal::ks_zeroize(ks);
        return false;
    }
    slot.key_len = klen_u16;
    slot.ks = ks;
    slot.hs_tx_seq = 0;
    slot.hs_rx_seq = 0;
    return true;
}

fn pure_install_app_keys(slot: PureTlsSlot&) -> bool {
    let cs_idx = alloc_cipher_slot();
    guard cs_idx != 0xFFFF else { return false; }
    let klen_u16 = slot.key_len;
    let klen = klen_u16 as i64;
    let hlen = slot.ks.hash_len as i64;
    var c_ap_key: u8[32] = [0; 32];
    var s_ap_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(c_ap_key);
    defer core::secure_zeroize_32(s_ap_key);
    var c_ap_iv: u8[12] = [0; 12];
    var s_ap_iv: u8[12] = [0; 12];
    let ok_c = tls_internal::ks_derive_key_iv(
        slot.ks.hash_id, slot.ks.client_ap_traffic[..hlen], klen_u16, c_ap_key[..klen], c_ap_iv,
    );
    let ok_s = tls_internal::ks_derive_key_iv(
        slot.ks.hash_id, slot.ks.server_ap_traffic[..hlen], klen_u16, s_ap_key[..klen], s_ap_iv,
    );
    guard ok_c && ok_s else {
        free_cipher_slot(cs_idx);
        return false;
    }
    if slot.is_server {
        tls_internal::tls_setup_server_cipher_slot(
            cs_idx, slot.cipher_suite, klen_u16, slot.ks,
            s_ap_key[..klen], s_ap_iv, c_ap_key[..klen], c_ap_iv,
        );
        let _ = g_tls_cipher_slots[cs_idx as i64].negotiated_alpn.try_set(slot.selected_alpn[..]);
    } else {
        tls_internal::tls_setup_client_cipher_slot(
            cs_idx, slot.cipher_suite, klen_u16, slot.ks,
            c_ap_key[..klen], c_ap_iv, s_ap_key[..klen], s_ap_iv,
            slot.server_name[..], slot.selected_alpn[..], false,
        );
    }
    slot.cipher_slot = cs_idx;
    wipe_pure_hs_secrets(slot);
    slot.stage = PureHsStage.Established;
    return true;
}

// ---- PureGoose Client Handshake Steps (RFC 8446 Section 2) -----------------

fn pure_client_step_init(slot: PureTlsSlot&) -> TlsBackendStatus {
    slot.client_random = random_bytes_32();
    slot.eph_priv = random_bytes_32();
    let client_pub = core::x25519_base_scalarmult(slot.eph_priv);

    var ch_payload: u8[..4096] = [];
    build_client_hello_payload(
        slot.client_random, client_pub, slot.server_name[..], slot.alpn_csv[..], ch_payload,
    );
    var ch_msg: u8[..4096] = [];
    guard ch_msg.try_push(rfc::TLS_HS_CLIENT_HELLO) &&
        ch_msg.try_push(((ch_payload.len >> 16) & 0xFF) as u8) &&
        ch_msg.try_push(((ch_payload.len >> 8) & 0xFF) as u8) &&
        ch_msg.try_push((ch_payload.len & 0xFF) as u8) &&
        ch_msg.try_append(ch_payload[..]) else {
        return TlsBackendStatus.Error;
    }
    let ccs: u8[6] = [rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    guard pure_append_plaintext_hs(slot.wire_out, ch_msg[..]) && slot.wire_out.try_append(ccs[..]) else {
        return TlsBackendStatus.Error;
    }
    transcript_update(slot.transcript, ch_msg[..]);
    slot.stage = PureHsStage.ClientWaitServerHello;
    return TlsBackendStatus.WantRead;
}

fn pure_client_step_sh(slot: PureTlsSlot&) -> TlsBackendStatus {
    var sh_msg: u8[..16384] = [];
    let st = pure_pop_plaintext_hs_msg(slot, sh_msg);
    guard st == TlsBackendStatus.Ok else { return st; }

    var sh = ParsedServerHello { .. };
    guard parse_live_server_hello(sh_msg[..], sh) &&
        !sh.is_hrr &&
        tls_internal::validate_live_client_sh(sh, slot.client_random) &&
        sh.selected_group == rfc::GROUP_X25519 &&
        sh.server_share.len == 32 else {
        return TlsBackendStatus.HandshakeError;
    }
    transcript_update(slot.transcript, sh_msg[..]);
    slot.cipher_suite = sh.cipher_suite;

    var srv_pub: u8[32] = [0; 32];
    core::ct_copy_bytes(srv_pub[..], sh.server_share[..]);
    var ecdhe_secret, ok_ss = core::x25519_shared_secret(slot.eph_priv, srv_pub);
    core::secure_zeroize_32(slot.eph_priv);
    defer core::secure_zeroize_32(ecdhe_secret);
    guard ok_ss && pure_derive_hs_traffic_keys(slot, ecdhe_secret[..]) else {
        return TlsBackendStatus.HandshakeError;
    }
    slot.stage = PureHsStage.ClientWaitEE;
    return TlsBackendStatus.Ok;
}

fn pure_client_verify_cv(slot: PureTlsSlot&, cv_body: const u8[:]) -> TlsBackendStatus {
    var h_to_cert: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_to_cert);
    var cfg = ClientHandshakeConfig {
        insecure_skip_verify: slot.insecure_skip_verify,
        trust_store:          slot.trust_store,
        ..
    };
    let _ = cfg.server_name.try_set(slot.server_name[..]);
    let ok_v = tls_internal::verify_server_cert_and_signature(
        slot.peer_cert_body[..], cv_body, h_to_cert[..], cfg, 0xFFFF,
    );
    slot.peer_cert_body.clear();
    guard ok_v else { return TlsBackendStatus.VerifyError; }
    transcript_update_msg(slot.transcript, rfc::TLS_HS_CERTIFICATE_VERIFY, cv_body);
    slot.stage = PureHsStage.ClientWaitFinished;
    return TlsBackendStatus.Ok;
}

fn pure_client_finish_hs(slot: PureTlsSlot&, fin_body: const u8[:]) -> TlsBackendStatus {
    let hlen = slot.ks.hash_len as i64;
    guard fin_body.len == hlen else { return TlsBackendStatus.HandshakeError; }
    var h_to_cv: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_to_cv);
    var exp_srv_fin: u8[48] = [0; 48];
    defer core::secure_zeroize_48(exp_srv_fin);
    guard tls_internal::ks_compute_finished_verify_data(
        slot.ks.hash_id, slot.ks.hash_len, slot.ks.server_hs_traffic[..hlen], h_to_cv[..], exp_srv_fin[..hlen],
    ) && core::ct_eq_bytes(exp_srv_fin[..hlen], fin_body[..hlen]) else {
        return TlsBackendStatus.HandshakeError;
    }
    transcript_update_msg(slot.transcript, rfc::TLS_HS_FINISHED, fin_body[..hlen]);

    var h_through_srv: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_through_srv);
    guard tls_internal::ks_advance_to_master(slot.ks, h_through_srv[..]) else {
        return TlsBackendStatus.HandshakeError;
    }

    var cli_fin: u8[48] = [0; 48];
    defer core::secure_zeroize_48(cli_fin);
    guard tls_internal::ks_compute_finished_verify_data(
        slot.ks.hash_id, slot.ks.hash_len, slot.ks.client_hs_traffic[..hlen], h_through_srv[..], cli_fin[..hlen],
    ) else { return TlsBackendStatus.HandshakeError; }

    var cli_msg: u8[64] = [0; 64];
    cli_msg[0] = rfc::TLS_HS_FINISHED;
    cli_msg[3] = slot.ks.hash_len;
    core::ct_copy_bytes(cli_msg[4..core::add_sat_i64(4, hlen)], cli_fin[..hlen]);
    let msg_slice = cli_msg[..core::add_sat_i64(4, hlen)];
    guard pure_seal_hs_to_wire(slot, msg_slice) else { return TlsBackendStatus.Error; }

    transcript_update(slot.transcript, msg_slice);
    var h_through_cli: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_through_cli);
    let _ = tls_internal::ks_advance_to_resumption(slot.ks, h_through_cli[..]);
    guard pure_install_app_keys(slot) else { return TlsBackendStatus.Error; }
    return TlsBackendStatus.Ok;
}

fn pure_client_step_encrypted(slot: PureTlsSlot&) -> TlsBackendStatus {
    var msg_t: u8          = 0;
    var body:  u8[..16384] = [];
    let st = pure_next_encrypted_hs_msg(slot, msg_t, body);
    guard st == TlsBackendStatus.Ok else { return st; }

    if slot.stage == PureHsStage.ClientWaitEE {
        guard msg_t == rfc::TLS_HS_ENCRYPTED_EXTENSIONS else { return TlsBackendStatus.HandshakeError; }
        let sni_st = if tls_internal::validate_sni_host_bytes(slot.server_name[..]) {
            SniOfferState.Offered
        } else {
            SniOfferState.Omitted
        };
        guard parse_encrypted_extensions_alpn(body[..], slot.selected_alpn, slot.alpn_csv[..], sni_st, false) else {
            return TlsBackendStatus.HandshakeError;
        }
        transcript_update_msg(slot.transcript, msg_t, body[..]);
        slot.stage = PureHsStage.ClientWaitCert;
        return TlsBackendStatus.Ok;
    }
    if slot.stage == PureHsStage.ClientWaitCert {
        guard msg_t == rfc::TLS_HS_CERTIFICATE && slot.peer_cert_body.try_set(body[..]) else {
            return TlsBackendStatus.HandshakeError;
        }
        transcript_update_msg(slot.transcript, msg_t, body[..]);
        slot.stage = PureHsStage.ClientWaitCV;
        return TlsBackendStatus.Ok;
    }
    if slot.stage == PureHsStage.ClientWaitCV {
        guard msg_t == rfc::TLS_HS_CERTIFICATE_VERIFY else { return TlsBackendStatus.HandshakeError; }
        return pure_client_verify_cv(slot, body[..]);
    }
    guard msg_t == rfc::TLS_HS_FINISHED else { return TlsBackendStatus.HandshakeError; }
    return pure_client_finish_hs(slot, body[..]);
}

// ---- PureGoose Server Handshake Steps (RFC 8446 Section 2) -----------------

fn pure_server_emit_encrypted_flight(slot: PureTlsSlot&) -> bool {
    var ee_ext: u8[..264] = [];
    if slot.selected_alpn.len > 0 {
        tls_internal::encode_alpn_extension_from_csv(ee_ext, slot.selected_alpn[..]);
    }
    var ee_msg: u8[..280] = [];
    guard ee_msg.try_push(rfc::TLS_HS_ENCRYPTED_EXTENSIONS) else { return false; }
    ee_msg.append_u24_be(core::add_sat_i64(2, ee_ext.len) as u32);
    ee_msg.append_u16_be(ee_ext.len as u16);
    guard ee_msg.try_append(ee_ext[..]) && pure_seal_hs_to_wire(slot, ee_msg[..]) else { return false; }
    transcript_update(slot.transcript, ee_msg[..]);

    var srv_cfg = ServerHandshakeConfig { priv_seed: slot.priv_seed, .. };
    guard srv_cfg.cert_der.try_set(slot.cert_der[..]) else { return false; }
    var cert_msg: u8[..4096] = [];
    guard encode_server_cert_or_compressed_msg(srv_cfg, 0, cert_msg) &&
        pure_seal_hs_to_wire(slot, cert_msg[..]) else { return false; }
    transcript_update(slot.transcript, cert_msg[..]);

    var h_to_cert: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_to_cert);
    var cv_input: u8[160] = [0; 160];
    let cv_len, ok_cv = build_certificate_verify_message(true, h_to_cert[..], cv_input[..]);
    var sig_buf: u8[..128] = [];
    let sig_scheme, ok_sig = sign_certificate_verify(slot.cert_der[..], slot.priv_seed, cv_input[..cv_len], sig_buf);
    var cv_pay: u8[..512] = [];
    guard ok_cv && ok_sig && encode_client_certificate_verify(cv_pay, sig_scheme, sig_buf[..]) else { return false; }
    var cv_msg: u8[..512] = [];
    cv_msg.push(rfc::TLS_HS_CERTIFICATE_VERIFY);
    cv_msg.append_u24_be(cv_pay.len as u32);
    guard cv_msg.try_append(cv_pay[..]) && pure_seal_hs_to_wire(slot, cv_msg[..]) else { return false; }
    transcript_update(slot.transcript, cv_msg[..]);

    var h_to_cv: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_to_cv);
    let hlen = slot.ks.hash_len as i64;
    var srv_fin: u8[48] = [0; 48];
    defer core::secure_zeroize_48(srv_fin);
    guard tls_internal::ks_compute_finished_verify_data(
        slot.ks.hash_id, slot.ks.hash_len, slot.ks.server_hs_traffic[..hlen], h_to_cv[..], srv_fin[..hlen],
    ) else { return false; }
    var fin_msg: u8[64] = [0; 64];
    fin_msg[0] = rfc::TLS_HS_FINISHED;
    fin_msg[3] = slot.ks.hash_len;
    core::ct_copy_bytes(fin_msg[4..core::add_sat_i64(4, hlen)], srv_fin[..hlen]);
    let fin_slice = fin_msg[..core::add_sat_i64(4, hlen)];
    guard pure_seal_hs_to_wire(slot, fin_slice) else { return false; }
    transcript_update(slot.transcript, fin_slice);
    return true;
}

fn pure_server_step_ch(slot: PureTlsSlot&) -> TlsBackendStatus {
    var ch_msg: u8[..16384] = [];
    let st = pure_pop_plaintext_hs_msg(slot, ch_msg);
    guard st == TlsBackendStatus.Ok else { return st; }

    transcript_update(slot.transcript, ch_msg[..]);
    var sid:        u8[..32]  = [];
    var client_pub: u8[32]    = [0; 32];
    var client_sni: u8[..255] = [];
    var psk_res:    bool      = false;
    var psk_sec:    u8[..48]  = [];
    var sel_psk_id: u16       = 0;
    defer core::secure_zeroize_slice(psk_sec[..]);
    let req_sig = tls_internal::detect_cert_sig_scheme(slot.cert_der[..]);
    guard tls_internal::parse_client_hello_for_server_full(
        ch_msg[..], slot.alpn_csv[..], req_sig, sid, client_pub,
        slot.selected_alpn, client_sni, slot.cipher_suite, psk_res, psk_sec, sel_psk_id,
    ) else { return TlsBackendStatus.HandshakeError; }

    let srv_rand = random_bytes_32();
    var srv_priv = random_bytes_32();
    defer core::secure_zeroize_32(srv_priv);
    let srv_pub = core::x25519_base_scalarmult(srv_priv);
    var ecdhe, ok_ss = core::x25519_shared_secret(srv_priv, client_pub);
    defer core::secure_zeroize_32(ecdhe);
    guard ok_ss else { return TlsBackendStatus.HandshakeError; }

    var sh_pay: u8[..2048] = [];
    build_server_hello_payload(srv_rand, sid[..], srv_pub, sh_pay, false, slot.cipher_suite, 0);
    var sh_msg: u8[..2048] = [];
    sh_msg.push(rfc::TLS_HS_SERVER_HELLO);
    sh_msg.append_u24_be(sh_pay.len as u32);
    let ccs: u8[6] = [rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    guard sh_msg.try_append(sh_pay[..]) &&
        pure_append_plaintext_hs(slot.wire_out, sh_msg[..]) &&
        slot.wire_out.try_append(ccs[..]) else {
        return TlsBackendStatus.Error;
    }
    transcript_update(slot.transcript, sh_msg[..]);
    guard pure_derive_hs_traffic_keys(slot, ecdhe[..]) && pure_server_emit_encrypted_flight(slot) else {
        return TlsBackendStatus.HandshakeError;
    }

    transcript_current_hash(slot.transcript, slot.ks.hash_id, slot.srv_fin_hash);
    guard tls_internal::ks_advance_to_master(slot.ks, slot.srv_fin_hash[..]) else {
        return TlsBackendStatus.HandshakeError;
    }
    slot.stage = PureHsStage.ServerWaitClientFinished;
    return TlsBackendStatus.WantRead;
}

fn pure_server_step_fin(slot: PureTlsSlot&) -> TlsBackendStatus {
    var msg_t: u8          = 0;
    var body:  u8[..16384] = [];
    let st = pure_next_encrypted_hs_msg(slot, msg_t, body);
    guard st == TlsBackendStatus.Ok else { return st; }

    let hlen = slot.ks.hash_len as i64;
    guard msg_t == rfc::TLS_HS_FINISHED && body.len == hlen else {
        return TlsBackendStatus.HandshakeError;
    }
    var exp_fin: u8[48] = [0; 48];
    defer core::secure_zeroize_48(exp_fin);
    guard tls_internal::ks_compute_finished_verify_data(
        slot.ks.hash_id, slot.ks.hash_len, slot.ks.client_hs_traffic[..hlen], slot.srv_fin_hash[..], exp_fin[..hlen],
    ) && core::ct_eq_bytes(exp_fin[..hlen], body[..hlen]) else {
        return TlsBackendStatus.HandshakeError;
    }
    transcript_update_msg(slot.transcript, msg_t, body[..hlen]);
    var h_cli: u8[..48] = [];
    transcript_current_hash(slot.transcript, slot.ks.hash_id, h_cli);
    let _ = tls_internal::ks_advance_to_resumption(slot.ks, h_cli[..]);
    guard pure_install_app_keys(slot) else { return TlsBackendStatus.Error; }
    return TlsBackendStatus.Ok;
}

fn pure_step_handshake_loop(slot: PureTlsSlot&) -> TlsBackendStatus {
    for _ in 8 {
        if slot.stage == PureHsStage.Established { return TlsBackendStatus.Ok; }
        if slot.stage == PureHsStage.Failed { return TlsBackendStatus.HandshakeError; }
        let st = match slot.stage {
            ClientInit => pure_client_step_init(slot),
            ClientWaitServerHello => pure_client_step_sh(slot),
            ClientWaitEE => pure_client_step_encrypted(slot),
            ClientWaitCert => pure_client_step_encrypted(slot),
            ClientWaitCV => pure_client_step_encrypted(slot),
            ClientWaitFinished => pure_client_step_encrypted(slot),
            ServerWaitClientHello => pure_server_step_ch(slot),
            ServerWaitClientFinished => pure_server_step_fin(slot),
            _ => TlsBackendStatus.Ok,
        };
        if st != TlsBackendStatus.Ok {
            if st != TlsBackendStatus.WantRead && st != TlsBackendStatus.WantWrite {
                slot.stage = PureHsStage.Failed;
            }
            return st;
        }
    }
    return if slot.stage == PureHsStage.Established { TlsBackendStatus.Ok } else { TlsBackendStatus.WantRead };
}

fn pure_load_server_pem_files(
    cert_path: const u8[:],
    key_path:  const u8[:],
    slot:      PureTlsSlot&,
) -> bool {
    guard cert_path.len > 0 && key_path.len > 0 else { return false; }
    var cert_pem: u8[>..] = [];
    var key_pem:  u8[>..] = [];
    defer core::secure_zeroize_slice(cert_pem[..]);
    defer core::secure_zeroize_slice(key_pem[..]);
    guard read_file(cert_path, cert_pem) && read_file(key_path, key_pem) else { return false; }
    var srv_cfg = ServerHandshakeConfig { .. };
    defer core::secure_zeroize_32(srv_cfg.priv_seed);
    guard load_server_credentials_pem(cert_pem[..], key_pem[..], srv_cfg) else { return false; }
    guard slot.cert_der.try_set(srv_cfg.cert_der[..]) else { return false; }
    slot.priv_seed = srv_cfg.priv_seed;
    return true;
}

fn pure_init_slot_credentials(
    slot:      PureTlsSlot&,
    cfg:       const TlsBackendConfig&,
    is_server: bool,
) -> TlsBackendStatus {
    if is_server {
        if cfg.cert_der.len > 0 {
            let _ = slot.cert_der.try_set(cfg.cert_der[..]);
            slot.priv_seed = cfg.priv_seed;
            return TlsBackendStatus.Ok;
        }
        guard pure_load_server_pem_files(cfg.cert_pem_file[..], cfg.key_pem_file[..], slot) else {
            return TlsBackendStatus.HandshakeError;
        }
        return TlsBackendStatus.Ok;
    }
    if cfg.cert_pem_file.len > 0 || cfg.key_pem_file.len > 0 {
        return TlsBackendStatus.Unavailable;
    }
    slot.trust_store = cfg.trust_store;
    let load_ca = !cfg.insecure_skip_verify && slot.trust_store.anchors.len == 0 && cfg.ca_file.len > 0;
    if load_ca {
        let _, ok_ca = load_trust_anchors_pem_file(slot.trust_store, cfg.ca_file[..]);
        guard ok_ca else { return TlsBackendStatus.VerifyError; }
    }
    return TlsBackendStatus.Ok;
}

fn open_pure_endpoint(cfg: const TlsBackendConfig&, is_server: bool) -> TlsEndpoint, TlsBackendStatus {
    let has_pem = cfg.cert_pem_file.len > 0 && cfg.key_pem_file.len > 0;
    if is_server && cfg.cert_der.len == 0 && !has_pem {
        return TlsEndpoint { .. }, TlsBackendStatus.HandshakeError;
    }
    let idx = alloc_pure_tls_slot();
    guard idx >= 0 else { return TlsEndpoint { .. }, TlsBackendStatus.Error; }
    let slot .= g_pure_tls_slots[idx as i64];
    slot.is_server = is_server;
    slot.insecure_skip_verify = cfg.insecure_skip_verify;
    slot.stage = if is_server { PureHsStage.ServerWaitClientHello } else { PureHsStage.ClientInit };
    let _ = slot.server_name.try_set(cfg.server_name[..]);
    decode_alpn_wire_to_csv(cfg.alpn_wire[..], slot.alpn_csv);
    let cred_st = pure_init_slot_credentials(slot, cfg, is_server);
    guard cred_st == TlsBackendStatus.Ok else {
        reset_and_wipe_pure_slot(slot);
        return TlsEndpoint { .. }, cred_st;
    }
    return TlsEndpoint {
        kind:        cfg.kind,
        active_kind: TlsBackendKind.PureGoose,
        is_server:   is_server,
        established: false,
        closed:      false,
        pure_slot:   idx,
        native_id:   -1,
    }, TlsBackendStatus.Ok;
}

fn open_endpoint_with_role(cfg: const TlsBackendConfig&, is_server: bool) -> TlsEndpoint, TlsBackendStatus {
    let pure_server_der = cfg.kind == TlsBackendKind.Auto && is_server &&
        cfg.cert_der.len > 0 && cfg.cert_pem_file.len == 0;
    let pure_client_custom_ca = cfg.kind == TlsBackendKind.Auto && !is_server &&
        !cfg.insecure_skip_verify && (cfg.ca_file.len > 0 || cfg.trust_store.anchors.len > 0) &&
        !tls_backend_available(TlsBackendKind.SystemOpenSsl);
    if cfg.kind == TlsBackendKind.PureGoose || pure_server_der || pure_client_custom_ca {
        return open_pure_endpoint(cfg, is_server);
    }

    var st_i32:     i32 = 0;
    var active_i32: i32 = 0;
    let nid = native_tls_backend_open(
        kind_to_native_i32(cfg.kind),
        if is_server { 1 } else { 0 },
        if cfg.insecure_skip_verify { 1 } else { 0 },
        min_version_to_native_i32(cfg.min_version),
        cfg.server_name[..],
        cfg.alpn_wire[..],
        cfg.ca_file[..],
        cfg.cert_pem_file[..],
        cfg.key_pem_file[..],
        st_i32,
        active_i32,
    );
    if nid > 0 && st_i32 == 0 {
        return TlsEndpoint {
            kind:        cfg.kind,
            active_kind: native_i32_to_kind(active_i32),
            is_server:   is_server,
            established: false,
            closed:      false,
            pure_slot:   -1,
            native_id:   nid,
        }, TlsBackendStatus.Ok;
    }
    if cfg.kind == TlsBackendKind.Auto {
        return open_pure_endpoint(cfg, is_server);
    }
    return TlsEndpoint { .. }, native_i32_to_status(st_i32);
}

// ---- Public Sans-IO Pluggable TLS Endpoint API -----------------------------

// Reports whether `kind` is available in the current runtime environment.
fn tls_backend_available(kind: TlsBackendKind) -> bool {
    if kind == TlsBackendKind.PureGoose || kind == TlsBackendKind.Auto {
        return true;
    }
    return native_tls_backend_available(kind_to_native_i32(kind)) != 0;
}

// Opens a sans-IO TLS endpoint using the configured backend (`PureGoose`, `SystemOpenSsl`,
// `SystemSchannel`, or `Auto` with automatic fallback to `PureGoose`).
fn tls_endpoint_open(cfg: const TlsBackendConfig&) -> TlsEndpoint, TlsBackendStatus {
    return open_endpoint_with_role(cfg, cfg.is_server);
}

// Idempotently closes `ep`, zeroizing key material and freeing native handles.
fn tls_endpoint_close(ep: TlsEndpoint&) {
    guard !ep.closed else { return; }
    if ep.active_kind == TlsBackendKind.PureGoose {
        let idx = ep.pure_slot as i64;
        if idx >= 0 && idx < g_pure_tls_slots.len {
            reset_and_wipe_pure_slot(g_pure_tls_slots[idx]);
        }
    } else if ep.native_id > 0 {
        native_tls_backend_close(ep.native_id);
    }
    ep.pure_slot = -1;
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
        let n = native_tls_backend_feed_wire(ep.native_id, ciphertext, st_i32);
        return n, native_i32_to_status(st_i32);
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 && idx < g_pure_tls_slots.len && g_pure_tls_slots[idx].in_use else {
        return 0, TlsBackendStatus.Closed;
    }
    let slot .= g_pure_tls_slots[idx];
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
        let n = native_tls_backend_drain_wire(ep.native_id, dst, st_i32);
        return n, native_i32_to_status(st_i32);
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 && idx < g_pure_tls_slots.len && g_pure_tls_slots[idx].in_use else {
        return 0, TlsBackendStatus.Closed;
    }
    let slot .= g_pure_tls_slots[idx];
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
        let st = native_i32_to_status(native_tls_backend_step_handshake(ep.native_id));
        if st == TlsBackendStatus.Ok {
            ep.established = true;
        }
        return st;
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 && idx < g_pure_tls_slots.len && g_pure_tls_slots[idx].in_use else {
        return TlsBackendStatus.Closed;
    }
    let st = pure_step_handshake_loop(g_pure_tls_slots[idx]);
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
        let n = native_tls_backend_write_app(ep.native_id, plaintext, st_i32);
        return n, native_i32_to_status(st_i32);
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 && idx < g_pure_tls_slots.len && g_pure_tls_slots[idx].in_use else {
        return 0, TlsBackendStatus.Closed;
    }
    let slot .= g_pure_tls_slots[idx];
    let avail = core::sub_sat_i64(slot.wire_out.cap, slot.wire_out.len);
    guard avail > 22 else { return 0, TlsBackendStatus.WantWrite; }
    let max_plain = min(core::sub_sat_i64(avail, 22), rfc::TLS_MAX_RECORD_PLAINTEXT_LEN);
    let take = min(plaintext.len, max_plain);
    guard cipher_slot_seal_app_data(slot.cipher_slot, plaintext[..take], slot.wire_out) else {
        return 0, TlsBackendStatus.Error;
    }
    return take, TlsBackendStatus.Ok;
}

// Unseals at most one complete TLS record from `slot.wire_in` into `slot.app_in` so pipelined
// records never overflow the 16640-byte plaintext buffer.
fn pure_unseal_one_app_record(slot: PureTlsSlot&) -> TlsBackendStatus {
    let rec_total, peek_st = tls_internal::peek_ciphertext_record_len(slot.wire_in[..]);
    if peek_st == SliceUnsealStatus.NeedMore { return TlsBackendStatus.WantRead; }
    guard peek_st == SliceUnsealStatus.Ok && rec_total > 0 else { return TlsBackendStatus.Error; }
    slot.app_in.clear();
    slot.app_in_pos = 0;
    let consumed, ust = cipher_slot_unseal_records(slot.cipher_slot, slot.wire_in[..rec_total], slot.app_in);
    if consumed > 0 { slot.wire_in.compact_wire_buffer(consumed); }
    if ust == SliceUnsealStatus.Closed {
        slot.peer_closed = true;
        return TlsBackendStatus.Closed;
    }
    if ust == SliceUnsealStatus.Error { return TlsBackendStatus.Error; }
    return TlsBackendStatus.Ok;
}

// Decrypts inbound wire ciphertext into `dst`, returning `(bytes_read, status)`.
fn tls_endpoint_read_app(ep: TlsEndpoint&, dst: u8[:]) -> i64, TlsBackendStatus {
    guard !ep.closed else { return 0, TlsBackendStatus.Closed; }
    guard ep.established else { return 0, TlsBackendStatus.HandshakeError; }
    guard dst.len > 0 else { return 0, TlsBackendStatus.Ok; }
    if ep.active_kind != TlsBackendKind.PureGoose {
        var st_i32: i32 = 0;
        let n = native_tls_backend_read_app(ep.native_id, dst, st_i32);
        return n, native_i32_to_status(st_i32);
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 && idx < g_pure_tls_slots.len && g_pure_tls_slots[idx].in_use else {
        return 0, TlsBackendStatus.Closed;
    }
    let slot .= g_pure_tls_slots[idx];
    if core::sub_sat_i64(slot.app_in.len, slot.app_in_pos) == 0 && slot.wire_in.len > 0 {
        let ust = pure_unseal_one_app_record(slot);
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

// Returns the negotiated ALPN protocol name (empty if none was negotiated).
fn tls_endpoint_selected_alpn(ep: const TlsEndpoint&) -> u8[..64] {
    var out: u8[..64] = [];
    guard !ep.closed else { return out; }
    if ep.active_kind != TlsBackendKind.PureGoose {
        var raw: u8[64] = [0; 64];
        let n = native_tls_backend_selected_alpn(ep.native_id, raw[..]);
        if n > 0 && n <= 64 {
            let _ = out.try_set(raw[..n]);
        }
        return out;
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 && idx < g_pure_tls_slots.len && g_pure_tls_slots[idx].in_use else { return out; }
    let _ = out.try_set(g_pure_tls_slots[idx].selected_alpn[..]);
    return out;
}

// Reports whether `ep` has completed the TLS handshake and is ready for application data.
fn tls_endpoint_is_established(ep: const TlsEndpoint&) -> bool {
    guard !ep.closed else { return false; }
    if ep.active_kind != TlsBackendKind.PureGoose {
        return ep.established || native_tls_backend_is_established(ep.native_id) != 0;
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 && idx < g_pure_tls_slots.len && g_pure_tls_slots[idx].in_use else { return false; }
    return ep.established && g_pure_tls_slots[idx].stage == PureHsStage.Established;
}

// Returns the number of outbound wire ciphertext bytes currently buffered in `ep`.
fn tls_endpoint_pending_wire(ep: const TlsEndpoint&) -> i64 {
    guard !ep.closed else { return 0; }
    if ep.active_kind != TlsBackendKind.PureGoose {
        return native_tls_backend_pending_wire(ep.native_id);
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 && idx < g_pure_tls_slots.len && g_pure_tls_slots[idx].in_use else { return 0; }
    return g_pure_tls_slots[idx].wire_out.len;
}

// Queues an RFC 8446 Section 6.1 graceful CloseNotify alert into `ep`'s outbound wire queue.
// Call `tls_endpoint_drain_wire` afterwards to flush the alert before closing the socket.
fn tls_endpoint_shutdown(ep: TlsEndpoint&) -> TlsBackendStatus {
    guard !ep.closed else { return TlsBackendStatus.Closed; }
    guard ep.established else { return TlsBackendStatus.Ok; }
    if ep.active_kind != TlsBackendKind.PureGoose {
        return native_i32_to_status(native_tls_backend_shutdown(ep.native_id));
    }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 && idx < g_pure_tls_slots.len && g_pure_tls_slots[idx].in_use else {
        return TlsBackendStatus.Closed;
    }
    let slot .= g_pure_tls_slots[idx];
    guard slot.cipher_slot != 0xFFFF else { return TlsBackendStatus.Ok; }
    let avail = core::sub_sat_i64(slot.wire_out.cap, slot.wire_out.len);
    guard avail >= 64 else { return TlsBackendStatus.WantWrite; }
    guard cipher_slot_seal_close_notify(slot.cipher_slot, slot.wire_out) else {
        return TlsBackendStatus.Error;
    }
    return TlsBackendStatus.Ok;
}

// ---- Socket-Bridged Transport Adapter (TCP & Virtual Pipe Descriptors) -----

const MAX_BACKEND_TRANSPORT_SLOTS: i64 = 64;

struct TlsBackendTransportSlot {
    in_use:     bool        = false,
    ep:         TlsEndpoint = TlsEndpoint { .. },
    rx_pending: u8[..16640] = [],
    rx_pos:     i64         = 0,
}

var g_backend_transport_slots: TlsBackendTransportSlot[>..] = [];

fn alloc_backend_transport_slot(ep: TlsEndpoint) -> i64 {
    for i in g_backend_transport_slots.len {
        let slot .= g_backend_transport_slots[i];
        if !slot.in_use {
            slot.ep = ep;
            slot.rx_pending.clear();
            slot.rx_pos = 0;
            slot.in_use = true;
            return i;
        }
    }
    guard g_backend_transport_slots.len < MAX_BACKEND_TRANSPORT_SLOTS else { return -1; }
    let idx = g_backend_transport_slots.len;
    g_backend_transport_slots.push(TlsBackendTransportSlot { in_use: true, ep: ep, .. });
    return idx;
}

fn release_backend_transport_slot(slot_id: i64) {
    guard slot_id >= 0 && slot_id < g_backend_transport_slots.len else { return; }
    let slot .= g_backend_transport_slots[slot_id];
    guard slot.in_use else { return; }
    tls_endpoint_close(slot.ep);
    core::secure_zeroize_slice(slot.rx_pending[..]);
    slot.rx_pending.clear();
    slot.rx_pos = 0;
    slot.in_use = false;
}

fn endpoint_fd_send_all(fd: i64, data: const u8[:]) -> bool {
    guard fd > 0 else { return false; }
    var off: i64 = 0;
    while off < data.len {
        let sent = if net::is_virtual_pipe_fd(fd) {
            net::virtual_fd_send(fd, data[off..])
        } else {
            net::tcp_send(fd, data[off..])
        };
        guard sent > 0 else { return false; }
        off = core::add_sat_i64(off, sent);
    }
    return true;
}

inline fn endpoint_fd_recv(fd: i64, dst: u8[:], timeout_ms: u32) -> i32 {
    if net::is_virtual_pipe_fd(fd) {
        return net::virtual_fd_recv(fd, dst);
    }
    if timeout_ms == 0 {
        return net::tcp_recv_nonblocking_slice(fd, dst);
    }
    return net::tcp_recv_slice(fd, dst, timeout_ms);
}

inline fn endpoint_fd_close_raw(fd: i64) {
    guard fd > 0 else { return; }
    if net::is_virtual_pipe_fd(fd) {
        net::virtual_fd_close(fd);
    } else {
        net::tcp_close(fd);
    }
}

fn endpoint_drain_to_fd(ep: TlsEndpoint&, fd: i64) -> bool {
    var wire: u8[16640] = [0; 16640];
    for _ in 64 {
        let n, st = tls_endpoint_drain_wire(ep, wire[..]);
        guard st == TlsBackendStatus.Ok else { return false; }
        if n <= 0 { return true; }
        guard n <= wire.len && endpoint_fd_send_all(fd, wire[..n]) else { return false; }
    }
    return true;
}

fn endpoint_feed_staged_rx(slot: TlsBackendTransportSlot&) -> i64, TlsBackendStatus {
    let pos = slot.rx_pos;
    let total = slot.rx_pending.len;
    guard pos >= 0 && pos < total && total <= slot.rx_pending.cap else {
        slot.rx_pending.clear();
        slot.rx_pos = 0;
        return 0, TlsBackendStatus.Ok;
    }
    let fed, fst = tls_endpoint_feed_wire(slot.ep, slot.rx_pending[pos..total]);
    if fed > 0 {
        let next_pos = core::add_sat_i64(pos, fed);
        if next_pos >= total {
            slot.rx_pending.clear();
            slot.rx_pos = 0;
        } else {
            slot.rx_pos = next_pos;
        }
    }
    return fed, fst;
}

fn endpoint_feed_slot_rx(slot: TlsBackendTransportSlot&, fd: i64, timeout_ms: u32) -> i32 {
    if slot.rx_pos < slot.rx_pending.len {
        let fed0, fst0 = endpoint_feed_staged_rx(slot);
        guard fst0 == TlsBackendStatus.Ok || fst0 == TlsBackendStatus.WantWrite else { return -1; }
        if fed0 > 0 || fst0 == TlsBackendStatus.WantWrite { return 1; }
    }
    var rx: u8[16640] = [0; 16640];
    let recvd = endpoint_fd_recv(fd, rx[..], timeout_ms);
    if recvd <= 0 { return recvd; }
    guard recvd <= rx.len else { return -1; }
    let fed, fst = tls_endpoint_feed_wire(slot.ep, rx[..recvd]);
    guard fst == TlsBackendStatus.Ok || fst == TlsBackendStatus.WantWrite else { return -1; }
    if fed >= 0 && fed < recvd {
        let _ = slot.rx_pending.try_set(rx[fed..recvd]);
        slot.rx_pos = 0;
    }
    return 1;
}

inline fn endpoint_slot_is_ready(slot_id: i64) -> bool {
    guard slot_id >= 0 && slot_id < g_backend_transport_slots.len else { return false; }
    let slot .= g_backend_transport_slots[slot_id];
    return slot.in_use && !slot.ep.closed && tls_endpoint_is_established(slot.ep);
}

fn endpoint_try_read_buffered(slot: TlsBackendTransportSlot&, fd: i64, dst: u8[:]) -> i64, TlsBackendStatus {
    for _ in 4 {
        let nr, st = tls_endpoint_read_app(slot.ep, dst);
        if nr > 0 { return nr, TlsBackendStatus.Ok; }
        if st == TlsBackendStatus.WantWrite {
            guard endpoint_drain_to_fd(slot.ep, fd) else { return 0, TlsBackendStatus.Error; }
            continue;
        }
        if st != TlsBackendStatus.WantRead { return 0, st; }
        if slot.rx_pos < slot.rx_pending.len {
            let _, fst = endpoint_feed_staged_rx(slot);
            guard fst == TlsBackendStatus.Ok || fst == TlsBackendStatus.WantWrite else {
                return 0, fst;
            }
        }
    }
    return 0, TlsBackendStatus.WantRead;
}

fn endpoint_run_handshake_fd(
    fd:         i64,
    cfg:        const TlsBackendConfig&,
    is_server:  bool,
    timeout_ms: u32,
) -> i64, u8[..64], TlsBackendStatus {
    var alpn: u8[..64] = [];
    guard fd > 0 else { return -1, alpn, TlsBackendStatus.Error; }
    var ep, open_st = open_endpoint_with_role(cfg, is_server);
    guard open_st == TlsBackendStatus.Ok else { return -1, alpn, open_st; }

    let slot_id = alloc_backend_transport_slot(ep);
    guard slot_id >= 0 else {
        tls_endpoint_close(ep);
        return -1, alpn, TlsBackendStatus.Error;
    }
    var committed = false;
    defer if !committed { release_backend_transport_slot(slot_id); };

    let slot .= g_backend_transport_slots[slot_id];
    for _ in 64 {
        let st = tls_endpoint_step_handshake(slot.ep);
        let flushed = endpoint_drain_to_fd(slot.ep, fd);
        if st == TlsBackendStatus.Ok {
            guard flushed else { return -1, alpn, TlsBackendStatus.Error; }
            alpn = tls_endpoint_selected_alpn(slot.ep);
            committed = true;
            return slot_id, alpn, TlsBackendStatus.Ok;
        }
        guard flushed else { return -1, alpn, TlsBackendStatus.Error; }
        if st == TlsBackendStatus.WantWrite { continue; }
        guard st == TlsBackendStatus.WantRead else { return -1, alpn, st; }
        let fed = endpoint_feed_slot_rx(slot, fd, timeout_ms);
        guard fed > 0 else { return -1, alpn, TlsBackendStatus.HandshakeError; }
    }
    return -1, alpn, TlsBackendStatus.HandshakeError;
}

// Drives a client-side TLS handshake over live TCP or virtual pipe `fd` using `cfg`.
// Returns `(slot_id, negotiated_alpn, status)`; caller retains `fd` ownership on failure.
fn endpoint_client_handshake_fd(
    fd:         i64,
    cfg:        const TlsBackendConfig&,
    timeout_ms: u32 = 5000,
) -> i64, u8[..64], TlsBackendStatus {
    return endpoint_run_handshake_fd(fd, cfg, false, timeout_ms);
}

// Drives a server-side TLS handshake over live TCP or virtual pipe `fd` using `cfg`.
// Returns `(slot_id, negotiated_alpn, status)`; caller retains `fd` ownership on failure.
fn endpoint_server_handshake_fd(
    fd:         i64,
    cfg:        const TlsBackendConfig&,
    timeout_ms: u32 = 5000,
) -> i64, u8[..64], TlsBackendStatus {
    return endpoint_run_handshake_fd(fd, cfg, true, timeout_ms);
}

// Encrypts `data` via the backend `TlsEndpoint` at `slot_id` and flushes ciphertext to `fd`.
// Returns total plaintext bytes sent (> 0), 0 for empty slice, or -1 on error.
fn endpoint_transport_send(fd: i64, slot_id: i64, data: const u8[:]) -> i32 {
    guard data.len > 0 else { return 0; }
    guard fd > 0 && endpoint_slot_is_ready(slot_id) else { return -1; }
    let slot .= g_backend_transport_slots[slot_id];

    var off:           i64 = 0;
    var zero_progress: i32 = 0;
    while off < data.len {
        let nw, st = tls_endpoint_write_app(slot.ep, data[off..]);
        guard endpoint_drain_to_fd(slot.ep, fd) else { return -1; }
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
fn endpoint_transport_recv_slice(
    fd:         i64,
    slot_id:    i64,
    dst:        u8[:],
    timeout_ms: u32 = 5000,
) -> i32 {
    guard fd > 0 && dst.len > 0 && endpoint_slot_is_ready(slot_id) else { return -1; }
    let slot .= g_backend_transport_slots[slot_id];

    for _ in 64 {
        let nr, st = endpoint_try_read_buffered(slot, fd, dst);
        if nr > 0 { return (nr & 0x7FFFFFFF) as i32; }
        if st == TlsBackendStatus.Closed { return 0; }
        guard st == TlsBackendStatus.WantRead else { return -1; }

        let rx_st = endpoint_feed_slot_rx(slot, fd, timeout_ms);
        if rx_st <= 0 { return rx_st; }
    }
    return -1;
}

// Idempotently closes the backend endpoint slot and underlying socket/virtual pipe `fd`.
fn endpoint_transport_close(fd: i64, slot_id: i64) {
    if slot_id >= 0 && slot_id < g_backend_transport_slots.len {
        let was_in_use = g_backend_transport_slots[slot_id].in_use;
        if was_in_use {
            release_backend_transport_slot(slot_id);
            endpoint_fd_close_raw(fd);
        }
        return;
    }
    endpoint_fd_close_raw(fd);
}
