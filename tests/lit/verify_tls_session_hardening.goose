// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of TLS 1.3 session hardening: thread-safe locks for cipher slots,
// entropy pool, and session tickets; fail-closed CSPRNG; and RFC 8446 Section 5.5
// AEAD KeyUpdate and hard record limit enforcement.
// RUN: goose %s | %FileCheck %s

import std;
import wing from "../..";

fn all_bytes_zero(buf: const u8[:]) -> bool {
    for b in buf {
        if b != 0 {
            return false;
        }
    }
    return true;
}

fn test_csprng_checked_dst_and_fail_closed() {
    // 1a. Normal OS CSPRNG path succeeds and ratchets entropy pool.
    var r1: u8[32] = [0; 32];
    var r2: u8[32] = [0; 32];
    assert(tls_internal::random_bytes_32_checked(r1));
    let pool_after_r1 = tls::g_tls_entropy_pool;
    assert(tls_internal::random_bytes_32_checked(r2));
    assert(!all_bytes_zero(r1[..]));
    assert(!all_bytes_zero(r2[..]));
    assert(!core::ct_eq_bytes(r1[..], r2[..]));
    assert(!core::ct_eq_bytes(pool_after_r1[..], r1[..]));
    assert(!core::ct_eq_bytes(tls::g_tls_entropy_pool[..], r2[..]));

    // 1b. DST simulation determinism under sim_rng.
    core::sim_rng_enable(0x1337C0DE);
    var d1: u8[32] = [0; 32];
    var d2: u8[32] = [0; 32];
    assert(tls_internal::random_bytes_32_checked(d1));
    assert(tls_internal::random_bytes_32_checked(d2));
    assert(!core::ct_eq_bytes(d1[..], d2[..]));

    core::sim_rng_enable(0x1337C0DE);
    var d1_rep: u8[32] = [0; 32];
    var d2_rep: u8[32] = [0; 32];
    assert(tls_internal::random_bytes_32_checked(d1_rep));
    assert(tls_internal::random_bytes_32_checked(d2_rep));
    assert(core::ct_eq_bytes(d1[..], d1_rep[..]));
    assert(core::ct_eq_bytes(d2[..], d2_rep[..]));
    core::sim_rng_disable();

    // 1c. Fail-closed CSPRNG fault injection wipes out and entropy pool.
    tls_internal::tls_set_csprng_fault_for_test(true);
    defer tls_internal::tls_set_csprng_fault_for_test(false);

    var tainted: u8[32] = [0xAA; 32];
    assert(!tls_internal::random_bytes_32_checked(tainted));
    assert(all_bytes_zero(tainted[..]));
    assert(all_bytes_zero(tls::g_tls_entropy_pool[..]));
    assert(tls::g_tls_entropy_counter == 0);

    // Handshake entry points abort and release cipher slots on CSPRNG failure.
    var cli_cfg = tls::ClientHandshakeConfig { enable_pq_hybrid: true, .. };
    let cli_slot, ok_cli = tls::client_handshake(-1, cli_cfg);
    assert(!ok_cli && cli_slot == 0xFFFF);
    assert(tls::g_tls_cipher_slots.len > 0 && !tls::g_tls_cipher_slots[0].in_use);

    var srv_cfg = tls::ServerHandshakeConfig { .. };
    var ch_payload: u8[..4096] = [];
    let dummy_rand: u8[32] = [0x11; 32];
    let dummy_pub:  u8[32] = [0x22; 32];
    tls_internal::build_client_hello_payload(dummy_rand, dummy_pub, "hardening.example", "h2", ch_payload);
    var ch_msg: u8[..4096] = [];
    ch_msg.push(rfc::TLS_HS_CLIENT_HELLO);
    ch_msg.append_u24_be(ch_payload.len as u32);
    ch_msg.append(ch_payload[..]);
    let srv_slot, ok_srv = tls::server_handshake_with_ch(-1, ch_msg[..], srv_cfg);
    assert(!ok_srv && srv_slot == 0xFFFF);
    assert(!tls::g_tls_cipher_slots[0].in_use);

    // Recovery after fault cleared.
    tls_internal::tls_set_csprng_fault_for_test(false);
    var rec: u8[32] = [0; 32];
    assert(tls_internal::random_bytes_32_checked(rec));
    assert(!all_bytes_zero(rec[..]));
    print("CSPRNG_FAIL_CLOSED_AND_DST: OK");
}

fn test_locked_cipher_slots_and_ticket_cache() {
    // Out-of-range lock IDs must be ignored safely without crashing or deadlocking.
    tls_internal::native_tls_state_lock(-1);
    tls_internal::native_tls_state_unlock(-1);
    tls_internal::native_tls_state_lock(3);
    tls_internal::native_tls_state_unlock(3);

    // Cipher slot alloc/free/reuse under lock 0.
    let s0 = tls::alloc_cipher_slot();
    let s1 = tls::alloc_cipher_slot();
    assert(s0 != 0xFFFF && s1 != 0xFFFF && s0 != s1);
    tls::free_cipher_slot(s0);
    let s0_reused = tls::alloc_cipher_slot();
    assert(s0_reused == s0);
    tls::free_cipher_slot(s0_reused);
    tls::free_cipher_slot(s1);

    // Session ticket cache store/lookup/identity-lookup/clear under lock 2.
    tls::clear_session_tickets();
    let psk32: u8[32] = [0x42; 32];
    tls::store_session_ticket(
        "locktest.example",
        "TICKET_ID_LOCK_01",
        psk32[..],
        0x11223344,
        3600,
        rfc::TLS_CIPHER_AES_128_GCM_SHA256,
        10000,
    );

    var out_tkt: u8[..256] = [];
    var out_psk: u8[..48]  = [];
    var out_age: u32       = 0;
    var out_cs:  u16       = 0;
    assert(tls::lookup_session_ticket_full("locktest.example", out_tkt, out_psk, out_age, out_cs, 20000));
    assert(out_tkt[..] == "TICKET_ID_LOCK_01");
    assert(out_psk.len == 32 && core::ct_eq_bytes(out_psk[..], psk32[..]));
    assert(out_age == 0x11223344 && out_cs == rfc::TLS_CIPHER_AES_128_GCM_SHA256);

    var out_psk32: u8[32] = [0; 32];
    assert(tls::lookup_session_ticket("locktest.example", out_tkt, out_psk32, out_age, 20000));
    assert(core::ct_eq_bytes(out_psk32[..], psk32[..]));

    var id_psk: u8[..48] = [];
    var id_cs:  u16      = 0;
    // Client-cached ticket MUST NOT be visible in server ticket lookup (TLS-01 isolation).
    assert(!tls_internal::lookup_server_ticket_by_identity(
        "TICKET_ID_LOCK_01", false, id_psk, id_cs, 20000, "locktest.example",
    ));

    // Server-issued non-mTLS ticket MUST be rejected when require_client_cert = true or SNI mismatches.
    tls_internal::store_server_session_ticket(
        "locktest.example",
        "SRV_TKT_NO_MTLS",
        psk32[..],
        0x22334455,
        3600,
        rfc::TLS_CIPHER_AES_128_GCM_SHA256,
        false,
        10000,
    );
    assert(tls_internal::lookup_server_ticket_by_identity(
        "SRV_TKT_NO_MTLS", false, id_psk, id_cs, 20000, "locktest.example",
    ));
    assert(id_psk.len == 32 && id_cs == rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    assert(!tls_internal::lookup_server_ticket_by_identity(
        "SRV_TKT_NO_MTLS", true, id_psk, id_cs, 20000, "locktest.example",
    ));
    assert(!tls_internal::lookup_server_ticket_by_identity(
        "SRV_TKT_NO_MTLS", false, id_psk, id_cs, 20000, "other.example",
    ));

    // Server-issued mTLS-authenticated ticket MUST succeed when require_client_cert = true.
    tls_internal::store_server_session_ticket(
        "locktest.example",
        "SRV_TKT_MTLS",
        psk32[..],
        0x33445566,
        3600,
        rfc::TLS_CIPHER_AES_128_GCM_SHA256,
        true,
        10000,
    );
    assert(tls_internal::lookup_server_ticket_by_identity(
        "SRV_TKT_MTLS", true, id_psk, id_cs, 20000, "locktest.example",
    ));
    assert(id_psk.len == 32 && id_cs == rfc::TLS_CIPHER_AES_128_GCM_SHA256);

    tls::clear_session_tickets();
    assert(!tls::lookup_session_ticket_full("locktest.example", out_tkt, out_psk, out_age, out_cs, 20000));
    assert(!tls_internal::lookup_server_ticket_by_identity(
        "SRV_TKT_MTLS", true, id_psk, id_cs, 20000, "locktest.example",
    ));
    print("LOCKED_SLOTS_AND_TICKETS: OK");
}

fn test_aead_limit_predicates() {
    assert(!tls::aead_needs_key_update(rfc::TLS_CIPHER_AES_128_GCM_SHA256, tls::TLS_AES_GCM_KEY_UPDATE_LIMIT - 1));
    assert(tls::aead_needs_key_update(rfc::TLS_CIPHER_AES_128_GCM_SHA256, tls::TLS_AES_GCM_KEY_UPDATE_LIMIT));
    assert(tls::aead_needs_key_update(rfc::TLS_CIPHER_AES_256_GCM_SHA384, tls::TLS_AES_GCM_KEY_UPDATE_LIMIT));
    assert(!tls::aead_exceeds_hard_limit(rfc::TLS_CIPHER_AES_128_GCM_SHA256, tls::TLS_AES_GCM_HARD_RECORD_LIMIT - 1));
    assert(tls::aead_exceeds_hard_limit(rfc::TLS_CIPHER_AES_128_GCM_SHA256, tls::TLS_AES_GCM_HARD_RECORD_LIMIT));
    assert(tls::aead_exceeds_hard_limit(rfc::TLS_CIPHER_AES_256_GCM_SHA384, tls::TLS_AES_GCM_HARD_RECORD_LIMIT));

    assert(!tls::aead_needs_key_update(rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256, tls::TLS_AES_GCM_HARD_RECORD_LIMIT));
    assert(!tls::aead_needs_key_update(rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256, tls::TLS_CHACHA20_KEY_UPDATE_LIMIT - 1));
    assert(tls::aead_needs_key_update(rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256, tls::TLS_CHACHA20_KEY_UPDATE_LIMIT));
    assert(!tls::aead_exceeds_hard_limit(rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256, tls::TLS_CHACHA20_HARD_RECORD_LIMIT - 1));
    assert(tls::aead_exceeds_hard_limit(rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256, tls::TLS_CHACHA20_HARD_RECORD_LIMIT));
    print("AEAD_LIMIT_PREDICATES: OK");
}

fn test_auto_key_update_and_hard_limit_fail_closed() {
    let vslot, ok_vp = net::alloc_virtual_pipe_slot();
    assert(ok_vp);
    defer net::free_virtual_pipe_slot(vslot);

    let fd_c = net::virtual_pipe_to_fd(vslot, false);
    let fd_s = net::virtual_pipe_to_fd(vslot, true);

    let slot_c = tls::alloc_cipher_slot();
    let slot_s = tls::alloc_cipher_slot();
    assert(slot_c != 0xFFFF && slot_s != 0xFFFF);
    defer tls::free_cipher_slot(slot_c);
    defer tls::free_cipher_slot(slot_s);

    let c2s_sec: u8[32] = [0x31; 32];
    let s2c_sec: u8[32] = [0x57; 32];
    var c2s_key: u8[16] = [0; 16];
    var c2s_iv:  u8[12] = [0; 12];
    var s2c_key: u8[16] = [0; 16];
    var s2c_iv:  u8[12] = [0; 12];
    assert(tls_internal::ks_derive_key_iv(tls_internal::HASH_SHA256, c2s_sec[..], 16, c2s_key[..], c2s_iv));
    assert(tls_internal::ks_derive_key_iv(tls_internal::HASH_SHA256, s2c_sec[..], 16, s2c_key[..], s2c_iv));

    tls_internal::init_cipher_slot_for_test(
        slot_c, rfc::TLS_CIPHER_AES_128_GCM_SHA256, c2s_key[..], c2s_iv, s2c_key[..], s2c_iv,
    );
    tls_internal::init_cipher_slot_for_test(
        slot_s, rfc::TLS_CIPHER_AES_128_GCM_SHA256, s2c_key[..], s2c_iv, c2s_key[..], c2s_iv,
    );

    let c_idx = slot_c as i64;
    let s_idx = slot_s as i64;
    tls::g_tls_cipher_slots[s_idx].is_server = true;
    for i in 32 {
        tls::g_tls_cipher_slots[c_idx].tx_traffic_secret[i] = c2s_sec[i];
        tls::g_tls_cipher_slots[c_idx].rx_traffic_secret[i] = s2c_sec[i];
        tls::g_tls_cipher_slots[s_idx].tx_traffic_secret[i] = s2c_sec[i];
        tls::g_tls_cipher_slots[s_idx].rx_traffic_secret[i] = c2s_sec[i];
    }

    // 3a. Automatic TX KeyUpdate when tx_seq reaches TLS_AES_GCM_KEY_UPDATE_LIMIT.
    tls::g_tls_cipher_slots[c_idx].tx_seq = tls::TLS_AES_GCM_KEY_UPDATE_LIMIT;
    tls::g_tls_cipher_slots[s_idx].rx_seq = tls::TLS_AES_GCM_KEY_UPDATE_LIMIT;

    let msg = "AUTO_KEY_UPDATE_ROUNDTRIP_PAYLOAD";
    let sent = tls::transport_send(fd_c, slot_c, msg);
    assert(sent == (msg.len as i32));
    // KeyUpdate reset tx_seq to 0, then sealing `msg` incremented tx_seq to 1.
    assert(tls::g_tls_cipher_slots[c_idx].tx_seq == 1);
    assert(!core::ct_eq_bytes(tls::g_tls_cipher_slots[c_idx].tx_key[..16], c2s_key[..]));

    var rx_buf: u8[128] = [0; 128];
    let recvd = tls::transport_recv_slice(fd_s, slot_s, rx_buf[..], 1000);
    assert(recvd == (msg.len as i32));
    assert(rx_buf[..recvd as i64] == msg);
    assert(tls::g_tls_cipher_slots[s_idx].rx_seq == 1);
    assert(core::ct_eq_bytes(
        tls::g_tls_cipher_slots[s_idx].rx_key[..16],
        tls::g_tls_cipher_slots[c_idx].tx_key[..16],
    ));
    print("AUTO_KEY_UPDATE_ROTATION: OK");
}

fn test_hard_limit_fail_closed() {
    let vslot, ok_vp = net::alloc_virtual_pipe_slot();
    assert(ok_vp);
    defer net::free_virtual_pipe_slot(vslot);
    let fd_c = net::virtual_pipe_to_fd(vslot, false);
    let fd_s = net::virtual_pipe_to_fd(vslot, true);

    let slot_c = tls::alloc_cipher_slot();
    let slot_s = tls::alloc_cipher_slot();
    assert(slot_c != 0xFFFF && slot_s != 0xFFFF);
    defer tls::free_cipher_slot(slot_c);
    defer tls::free_cipher_slot(slot_s);

    let k16: u8[16] = [0x24; 16];
    let iv:  u8[12] = [0x88; 12];
    tls_internal::init_cipher_slot_for_test(slot_c, rfc::TLS_CIPHER_AES_128_GCM_SHA256, k16[..], iv, k16[..], iv);
    tls_internal::init_cipher_slot_for_test(slot_s, rfc::TLS_CIPHER_AES_128_GCM_SHA256, k16[..], iv, k16[..], iv);
    let c_idx = slot_c as i64;
    let s_idx = slot_s as i64;

    // Socket TX and KeyUpdate fail closed at TLS_AES_GCM_HARD_RECORD_LIMIT.
    tls::g_tls_cipher_slots[c_idx].tx_seq = tls::TLS_AES_GCM_HARD_RECORD_LIMIT;
    assert(!tls_internal::send_encrypted_record(fd_c, slot_c, rfc::TLS_CONTENT_APPLICATION_DATA, "blocked"));
    assert(tls::transport_send(fd_c, slot_c, "blocked") == -1);
    assert(!tls::send_key_update(fd_c, slot_c, rfc::KEY_UPDATE_NOT_REQUESTED));

    // Socket RX fails closed at TLS_AES_GCM_HARD_RECORD_LIMIT.
    tls::g_tls_cipher_slots[s_idx].rx_seq = tls::TLS_AES_GCM_HARD_RECORD_LIMIT;
    var rx_buf: u8[64] = [0; 64];
    assert(tls::transport_recv_slice(fd_s, slot_s, rx_buf[..], 50) == -1);

    // Sans-IO TX and CloseNotify fail closed at TLS_AES_GCM_HARD_RECORD_LIMIT.
    var out_ct: u8[..256] = [];
    assert(!tls::cipher_slot_seal_app_data(slot_c, "blocked", out_ct));
    assert(out_ct.len == 0);
    assert(!tls::cipher_slot_seal_close_notify(slot_c, out_ct));
    assert(out_ct.len == 0);

    // Sans-IO RX fails closed even for cryptographically valid record past hard limit.
    var forged: u8[128] = [0; 128];
    let forged_len, _, ok_f = tls::record_seal_into(
        rfc::TLS_CIPHER_AES_128_GCM_SHA256,
        k16[..],
        iv,
        tls::TLS_AES_GCM_HARD_RECORD_LIMIT,
        rfc::TLS_CONTENT_APPLICATION_DATA,
        "past-limit",
        forged[..],
    );
    assert(ok_f && forged_len > 0);
    var out_plain: u8[..128] = [];
    let consumed, st = tls::cipher_slot_unseal_records(slot_s, forged[..forged_len], out_plain);
    assert(consumed == 0 && st == tls::SliceUnsealStatus.Error && out_plain.len == 0);

    // ChaCha20-Poly1305 allows (HARD_LIMIT - 1) and rejects HARD_LIMIT.
    let k32: u8[32] = [0x66; 32];
    tls_internal::init_cipher_slot_for_test(slot_c, rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256, k32[..], iv, k32[..], iv);
    tls_internal::init_cipher_slot_for_test(slot_s, rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256, k32[..], iv, k32[..], iv);
    tls::g_tls_cipher_slots[c_idx].tx_seq = tls::TLS_CHACHA20_HARD_RECORD_LIMIT - 1;
    tls::g_tls_cipher_slots[s_idx].rx_seq = tls::TLS_CHACHA20_HARD_RECORD_LIMIT - 1;

    assert(tls::cipher_slot_seal_app_data(slot_c, "last-ok", out_ct));
    let n_ch, st_ch = tls::cipher_slot_unseal_records(slot_s, out_ct[..], out_plain);
    assert(st_ch == tls::SliceUnsealStatus.Ok && n_ch == out_ct.len && out_plain[..] == "last-ok");

    // Next record hits TLS_CHACHA20_HARD_RECORD_LIMIT and must fail closed.
    out_ct.clear();
    assert(!tls::cipher_slot_seal_app_data(slot_c, "now-blocked", out_ct));
    assert(out_ct.len == 0);
    print("AEAD_HARD_LIMIT_FAIL_CLOSED: OK");
}

fn test_wave2_key_update_and_backend_guards() {
    let slot_c = tls::alloc_cipher_slot();
    let slot_s = tls::alloc_cipher_slot();
    assert(slot_c != 0xFFFF && slot_s != 0xFFFF);
    defer tls::free_cipher_slot(slot_c);
    defer tls::free_cipher_slot(slot_s);

    let sec_a: u8[32] = [0x31; 32];
    let sec_b: u8[32] = [0x62; 32];
    var ka:  u8[16] = [0; 16];
    var iva: u8[12] = [0; 12];
    var kb:  u8[16] = [0; 16];
    var ivb: u8[12] = [0; 12];
    assert(tls_internal::ks_derive_key_iv(tls_internal::HASH_SHA256, sec_a[..], 16, ka[..], iva));
    assert(tls_internal::ks_derive_key_iv(tls_internal::HASH_SHA256, sec_b[..], 16, kb[..], ivb));

    tls_internal::init_cipher_slot_for_test(slot_c, rfc::TLS_CIPHER_AES_128_GCM_SHA256, ka[..], iva, kb[..], ivb);
    tls_internal::init_cipher_slot_for_test(slot_s, rfc::TLS_CIPHER_AES_128_GCM_SHA256, kb[..], ivb, ka[..], iva);
    let c_idx = slot_c as i64;
    let s_idx = slot_s as i64;
    for i in 32 {
        tls::g_tls_cipher_slots[c_idx].tx_traffic_secret[i] = sec_a[i];
        tls::g_tls_cipher_slots[c_idx].rx_traffic_secret[i] = sec_b[i];
        tls::g_tls_cipher_slots[s_idx].tx_traffic_secret[i] = sec_b[i];
        tls::g_tls_cipher_slots[s_idx].rx_traffic_secret[i] = sec_a[i];
    }

    // Trailing coalesced bytes after KeyUpdate inside one handshake record MUST fail closed (RFC 8446 §5.1).
    let coalesced_ku: u8[6] = [rfc::TLS_HS_KEY_UPDATE, 0x00, 0x00, 0x01, 0x00, 0x00];
    var bad_rec: u8[128] = [0; 128];
    let bad_len, _, ok_bad = tls::record_seal_into(
        rfc::TLS_CIPHER_AES_128_GCM_SHA256, ka[..], iva, 0,
        rfc::TLS_CONTENT_HANDSHAKE, coalesced_ku[..], bad_rec[..],
    );
    assert(ok_bad && bad_len > 0);
    var out_plain: u8[..128] = [];
    let c_bad, st_bad = tls::cipher_slot_unseal_records(slot_s, bad_rec[..bad_len], out_plain);
    assert(c_bad == 0 && st_bad == tls::SliceUnsealStatus.Error);

    // Reset slot_s after fatal protocol error, then test valid KeyUpdate(update_requested=1) -> reply.
    tls_internal::init_cipher_slot_for_test(slot_s, rfc::TLS_CIPHER_AES_128_GCM_SHA256, kb[..], ivb, ka[..], iva);
    for i in 32 {
        tls::g_tls_cipher_slots[s_idx].tx_traffic_secret[i] = sec_b[i];
        tls::g_tls_cipher_slots[s_idx].rx_traffic_secret[i] = sec_a[i];
    }

    // Valid KeyUpdate(update_requested=1) from C -> S sets pending reply on S; S emits KeyUpdate(0) on next seal.
    let ku_req: u8[5] = [rfc::TLS_HS_KEY_UPDATE, 0x00, 0x00, 0x01, 0x01];
    var ku_rec: u8[128] = [0; 128];
    let ku_len, _, ok_ku = tls::record_seal_into(
        rfc::TLS_CIPHER_AES_128_GCM_SHA256, ka[..], iva, 0,
        rfc::TLS_CONTENT_HANDSHAKE, ku_req[..], ku_rec[..],
    );
    assert(ok_ku && ku_len > 0);
    let c_ku, st_ku = tls::cipher_slot_unseal_records(slot_s, ku_rec[..ku_len], out_plain);
    assert(st_ku == tls::SliceUnsealStatus.ControlHandled && c_ku == ku_len && out_plain.len == 0);
    assert(tls::g_tls_cipher_slots[s_idx].key_update_tracker.pending_response);

    var s_out: u8[..256] = [];
    assert(tls::cipher_slot_seal_app_data(slot_s, "after-ku-reply", s_out));
    assert(!tls::g_tls_cipher_slots[s_idx].key_update_tracker.pending_response);
    out_plain.clear();
    let c_reply, st_reply = tls::cipher_slot_unseal_records(slot_c, s_out[..], out_plain);
    assert(st_reply == tls::SliceUnsealStatus.Ok && c_reply == s_out.len && out_plain[..] == "after-ku-reply");

    // Explicit native backend MUST reject mTLS require_client_cert without ca_file (EDGE-01).
    var mtls_cfg = tls::TlsBackendConfig {
        kind:                tls::TlsBackendKind.SystemOpenSsl,
        is_server:           true,
        require_client_cert: true,
        ..
    };
    let _, st_native = tls::tls_endpoint_open(mtls_cfg);
    assert(st_native == tls::TlsBackendStatus.Error || st_native == tls::TlsBackendStatus.Unavailable);

    // PureGoose mTLS server with no trust anchors MUST fail closed with VerifyError (TLS-02).
    var pure_mtls_cfg = tls::TlsBackendConfig {
        kind:                tls::TlsBackendKind.PureGoose,
        is_server:           true,
        require_client_cert: true,
        ..
    };
    let srv_seed: u8[32] = [0x44; 32];
    pure_mtls_cfg.priv_seed = srv_seed;
    var cert2k: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(srv_seed, "mtls.test", "mtls.test", "", cert2k));
    assert(pure_mtls_cfg.cert_der.try_set(cert2k[..]));
    let _, st_pure_mtls = tls::tls_endpoint_open(pure_mtls_cfg);
    assert(st_pure_mtls == tls::TlsBackendStatus.VerifyError);
    print("WAVE2_KEY_UPDATE_AND_GUARDS: OK");
}

// CHECK: CSPRNG_FAIL_CLOSED_AND_DST: OK
// CHECK: LOCKED_SLOTS_AND_TICKETS: OK
// CHECK: AEAD_LIMIT_PREDICATES: OK
// CHECK: AUTO_KEY_UPDATE_ROTATION: OK
// CHECK: AEAD_HARD_LIMIT_FAIL_CLOSED: OK
// CHECK: WAVE2_KEY_UPDATE_AND_GUARDS: OK
fn main() {
    test_csprng_checked_dst_and_fail_closed();
    test_locked_cipher_slots_and_ticket_cache();
    test_aead_limit_predicates();
    test_auto_key_update_and_hard_limit_fail_closed();
    test_hard_limit_fail_closed();
    test_wave2_key_update_and_backend_guards();
}
