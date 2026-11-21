// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of lazy grow-on-demand allocation for `tls::g_tls_cipher_slots`
// and `net::g_virtual_pipes`, zero startup page faults, secret wiping on release,
// slot reuse, and bounds-safe rejection of unallocated or out-of-range slot IDs.
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

fn test_zero_startup_and_oob_rejection() {
    assert(tls::g_tls_cipher_slots.len == 0);
    assert(net::g_virtual_pipes.len == 0);

    // Reject unallocated (0) and out-of-bounds (255, 0xFFFF) TLS cipher slot IDs cleanly.
    assert(tls::session_alpn(0) == "");
    assert(tls::session_alpn(0xFFFF) == "");
    assert(!tls::session_is_resumed(0));
    assert(!tls::session_is_resumed(0xFFFF));

    tls::free_cipher_slot(0);
    tls::free_cipher_slot(255);
    tls::free_cipher_slot(0xFFFF);

    var out_cipher: u8[..256] = [];
    assert(!tls::cipher_slot_seal_app_data(0, "hello", out_cipher));
    assert(!tls::cipher_slot_seal_app_data(0xFFFF, "hello", out_cipher));
    assert(out_cipher.len == 0);

    var out_plain: u8[..256] = [];
    let n_u0, st_u0 = tls::cipher_slot_unseal_records(0, "\x17\x03\x03\x00\x11AAAAAAAAAAAAAAAAA", out_plain);
    assert(n_u0 == 0 && st_u0 == tls::SliceUnsealStatus.Error);
    let n_uf, st_uf = tls::cipher_slot_unseal_records(0xFFFF, "\x17\x03\x03\x00\x11AAAAAAAAAAAAAAAAA", out_plain);
    assert(n_uf == 0 && st_uf == tls::SliceUnsealStatus.Error);

    var exp_buf: u8[..256] = [];
    assert(!tls::session_export_keying_material(0, "EXPORTER-Channel-Binding", "", 32, exp_buf));
    assert(!tls::session_export_keying_material(0xFFFF, "EXPORTER-Channel-Binding", "", 32, exp_buf));

    var sans: u8[..128][..8] = [];
    tls::copy_slot_san_hosts(0, sans);
    assert(sans.len == 0);
    assert(!tls::populate_slot_san_hosts_from_der(0, "DER"));

    let _, ok_ktls = tls::try_enable_ktls(0, 1);
    assert(!ok_ktls);
    assert(!tls::send_encrypted_record(1, 0, rfc::TLS_CONTENT_APPLICATION_DATA, "hi"));
    assert(tls::transport_send(1, 0, "hi") == -1);
    assert(tls::transport_send(1, 0xFFFF, "hi") == -1);

    var rx_buf: u8[32] = [0; 32];
    assert(tls::transport_recv_slice(1, 0, rx_buf[..], 10) == -1);
    assert(tls::transport_recv_slice(1, 0xFFFF, rx_buf[..], 10) == -1);
    assert(!tls::send_key_update(1, 0, 0));
    assert(!tls::send_new_session_ticket(1, 0, 60, "n", "t"));
    assert(!tls::dispatch_post_handshake_record(-1, 0, "\x18\x00\x00\x01\x00"));
    assert(!tls::process_received_nst(0, "1234"));
    assert(!tls::process_received_nst(-1, "1234"));
    tls::transport_close(-1, 0);
    tls::transport_close(-1, 0xFFFF);

    // Reject unallocated (0) and out-of-bounds (31, 0xFFFF) virtual pipe slot IDs cleanly.
    let _, _, ok_dec0 = net::decode_virtual_pipe_fd(net::virtual_pipe_to_fd(0, false));
    assert(!ok_dec0);
    let _, _, ok_decf = net::decode_virtual_pipe_fd(net::virtual_pipe_to_fd(0xFFFF, true));
    assert(!ok_decf);
    assert(net::virtual_pipe_send(0, false, "ping") == -1);
    assert(net::virtual_pipe_send(0xFFFF, true, "ping") == -1);
    assert(net::virtual_pipe_recv(0, false, rx_buf[..]) == -1);
    assert(net::virtual_pipe_recv(0xFFFF, true, rx_buf[..]) == -1);
    assert(net::virtual_fd_send(net::virtual_pipe_to_fd(0, false), "ping") == -1);
    assert(net::virtual_fd_recv(net::virtual_pipe_to_fd(0, false), rx_buf[..]) == -1);
    net::virtual_pipe_close(0, false);
    net::virtual_pipe_close(0xFFFF, true);
    net::free_virtual_pipe_slot(0);
    net::free_virtual_pipe_slot(0xFFFF);

    assert(tls::g_tls_cipher_slots.len == 0);
    assert(net::g_virtual_pipes.len == 0);
    print("ZERO_STARTUP_AND_OOB_GUARD: OK");
}

fn test_tls_lazy_slot_seal_unseal_wipe_and_reuse() {
    let slot_c = tls::alloc_cipher_slot();
    assert(slot_c == 0 && tls::g_tls_cipher_slots.len == 1);

    // Index 1 is still unallocated when len == 1.
    var tmp_cipher: u8[..128] = [];
    assert(!tls::cipher_slot_seal_app_data(1, "unallocated", tmp_cipher));

    let slot_s = tls::alloc_cipher_slot();
    assert(slot_s == 1 && tls::g_tls_cipher_slots.len == 2);

    let c2s_key: u8[16] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01];
    let s2c_key: u8[16] = [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8];
    let c2s_iv:  u8[12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let s2c_iv:  u8[12] = [12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];

    tls::init_cipher_slot_for_test(
        slot_c, rfc::TLS_CIPHER_AES_128_GCM_SHA256, c2s_key[..], c2s_iv, s2c_key[..], s2c_iv,
    );
    tls::init_cipher_slot_for_test(
        slot_s, rfc::TLS_CIPHER_AES_128_GCM_SHA256, s2c_key[..], s2c_iv, c2s_key[..], c2s_iv,
    );

    let c_idx = slot_c as i64;
    for i in 48 {
        tls::g_tls_cipher_slots[c_idx].tx_traffic_secret[i] = (0x50 + i) as u8;
        tls::g_tls_cipher_slots[c_idx].rx_traffic_secret[i] = (0x70 + i) as u8;
        tls::g_tls_cipher_slots[c_idx].exporter_secret[i] = (0x90 + i) as u8;
        tls::g_tls_cipher_slots[c_idx].resumption_secret[i] = (0xB0 + i) as u8;
    }
    let _ = tls::g_tls_cipher_slots[c_idx].rx_plain_buf.try_set("SENSITIVE_BEARER_SECRET");
    let _ = tls::g_tls_cipher_slots[c_idx].negotiated_alpn.try_set("h2");
    let _ = tls::g_tls_cipher_slots[c_idx].server_name.try_set("lazy.example.com");
    assert(tls::session_alpn(slot_c) == "h2");

    let msg = "LAZY_SLOT_TLS13_APP_PAYLOAD";
    var sealed: u8[..256] = [];
    assert(tls::cipher_slot_seal_app_data(slot_c, msg, sealed));
    assert(sealed.len > msg.len);

    var unsealed: u8[..256] = [];
    let consumed, st = tls::cipher_slot_unseal_records(slot_s, sealed[..], unsealed);
    assert(st == tls::SliceUnsealStatus.Ok);
    assert(consumed == sealed.len);
    assert(unsealed[..] == msg);

    // Release slot_c and verify every secret and residual buffer is wiped.
    tls::free_cipher_slot(slot_c);
    assert(tls::g_tls_cipher_slots.len == 2);
    assert(!tls::g_tls_cipher_slots[c_idx].in_use);
    assert(!tls::g_tls_cipher_slots[c_idx].tx_aes_key.valid);
    assert(!tls::g_tls_cipher_slots[c_idx].rx_aes_key.valid);
    assert(all_bytes_zero(tls::g_tls_cipher_slots[c_idx].tx_key[..]));
    assert(all_bytes_zero(tls::g_tls_cipher_slots[c_idx].rx_key[..]));
    assert(all_bytes_zero(tls::g_tls_cipher_slots[c_idx].tx_iv[..]));
    assert(all_bytes_zero(tls::g_tls_cipher_slots[c_idx].rx_iv[..]));
    assert(all_bytes_zero(tls::g_tls_cipher_slots[c_idx].tx_traffic_secret[..]));
    assert(all_bytes_zero(tls::g_tls_cipher_slots[c_idx].rx_traffic_secret[..]));
    assert(all_bytes_zero(tls::g_tls_cipher_slots[c_idx].exporter_secret[..]));
    assert(all_bytes_zero(tls::g_tls_cipher_slots[c_idx].resumption_secret[..]));
    assert(all_bytes_zero(tls::g_tls_cipher_slots[c_idx].tx_aes_key.state[..]));
    assert(all_bytes_zero(tls::g_tls_cipher_slots[c_idx].rx_aes_key.state[..]));
    assert(tls::g_tls_cipher_slots[c_idx].rx_plain_buf.len == 0);
    assert(tls::session_alpn(slot_c) == "");
    assert(!tls::cipher_slot_seal_app_data(slot_c, "rejected", tmp_cipher));

    // Re-allocating reuses slot 0 without growing g_tls_cipher_slots.
    let reused = tls::alloc_cipher_slot();
    assert(reused == 0 && tls::g_tls_cipher_slots.len == 2);

    tls::free_cipher_slot(reused);
    tls::free_cipher_slot(slot_s);
    print("TLS_LAZY_SEAL_WIPE_REUSE: OK");
}

fn test_virtual_pipe_lazy_alloc_and_reuse() {
    assert(net::g_virtual_pipes.len == 0);

    var end_a, end_b, ok_open = net::open_virtual_pipe_pair();
    assert(ok_open && net::g_virtual_pipes.len == 1);

    // Slot 1 is still unallocated when g_virtual_pipes.len == 1.
    assert(net::virtual_pipe_send(1, false, "x") == -1);
    let _, _, ok_dec1 = net::decode_virtual_pipe_fd(net::virtual_pipe_to_fd(1, false));
    assert(!ok_dec1);

    let payload = "LAZY_PIPE_FRAME";
    assert(end_a.send(payload) == (payload.len as i32));
    var rx: u8[64] = [0; 64];
    let n = end_b.recv_slice(rx[..]);
    assert(n == (payload.len as i32) && rx[..n as i64] == payload);

    end_a.close();
    end_b.close();
    assert(!net::g_virtual_pipes[0].in_use);
    assert(all_bytes_zero(net::g_virtual_pipes[0].a_to_b.storage[..]));
    assert(all_bytes_zero(net::g_virtual_pipes[0].b_to_a.storage[..]));

    // Subsequent open reuses slot 0 without growing g_virtual_pipes.
    var end_c, end_d, ok_reopen = net::open_virtual_pipe_pair();
    assert(ok_reopen && net::g_virtual_pipes.len == 1);
    end_c.close();
    end_d.close();
    print("VIRTUAL_PIPE_LAZY_REUSE: OK");
}

fn test_capacity_ceilings() {
    var tls_slots: u16[..256] = [];
    for _ in tls::MAX_CIPHER_SLOTS {
        let s = tls::alloc_cipher_slot();
        assert(s != 0xFFFF);
        assert(tls_slots.try_push(s));
    }
    assert(tls::g_tls_cipher_slots.len == tls::MAX_CIPHER_SLOTS);
    assert(tls::alloc_cipher_slot() == 0xFFFF);
    for s in tls_slots {
        tls::free_cipher_slot(s);
    }

    var pipe_slots: u16[..32] = [];
    for _ in net::MAX_VIRTUAL_PIPES {
        let p, ok = net::alloc_virtual_pipe_slot();
        assert(ok && p != 0xFFFF);
        assert(pipe_slots.try_push(p));
    }
    assert(net::g_virtual_pipes.len == net::MAX_VIRTUAL_PIPES);
    let p_over, ok_over = net::alloc_virtual_pipe_slot();
    assert(!ok_over && p_over == 0xFFFF);
    for p in pipe_slots {
        net::free_virtual_pipe_slot(p);
    }
    print("CAPACITY_CEILINGS: OK");
}

// CHECK: ZERO_STARTUP_AND_OOB_GUARD: OK
// CHECK: TLS_LAZY_SEAL_WIPE_REUSE: OK
// CHECK: VIRTUAL_PIPE_LAZY_REUSE: OK
// CHECK: CAPACITY_CEILINGS: OK
fn main() {
    test_zero_startup_and_oob_rejection();
    test_tls_lazy_slot_seal_unseal_wipe_and_reuse();
    test_virtual_pipe_lazy_alloc_and_reuse();
    test_capacity_ceilings();
}
