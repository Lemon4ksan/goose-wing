// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Goose LIT Regression Suite: Pure-Goose Ports of Removed C Shims (Waves 1-5).
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

fn test_wave1_stdlib_and_tls_helpers() {
    var rnd: u8[32] = [0; 32];
    assert(core::csprng_fill(rnd[..]));
    var any_nonzero = false;
    for b in rnd {
        if b != 0 {
            any_nonzero = true;
            break;
        }
    }
    assert(any_nonzero);

    assert(net::get_env_port(8080) > 0);
    assert(net::get_env_workers(4) > 0);

    let n1, ip1, ok1 = tls_internal::normalize_native_server_name("[::1]");
    assert(ok1 && ip1 && n1 == "::1");
    let _, ip2, ok2 = tls_internal::normalize_native_server_name("[]");
    assert(!ok2 && !ip2);
    let n3, ip3, ok3 = tls_internal::normalize_native_server_name("example.com");
    assert(ok3 && !ip3 && n3 == "example.com");
    let n4, ip4, ok4 = tls_internal::normalize_native_server_name("127.0.0.1");
    assert(ok4 && ip4 && n4 == "127.0.0.1");

    // CHECK: WAVE1_STDLIB_TLS_PORTS: OK
    print("WAVE1_STDLIB_TLS_PORTS: OK");
}

fn test_wave2_simd_strings_and_codecs() {
    var cb = core::new_cork_buffer();
    let w1, err1 = core::cork_write(cb, "HTTP/1.1 ");
    assert(w1 == 9 && err1 == core::IoError.None);
    assert(core::cork_write_exact(cb, "200 OK\r\n") == core::IoError.None);
    assert(core::cork_pending(cb) == 17);
    assert(core::cork_as_slice(cb) == "HTTP/1.1 200 OK\r\n");
    core::cork_consume(cb, 9);
    assert(core::cork_as_slice(cb) == "200 OK\r\n");

    var dec_buf: u8[..32] = [];
    core::format_u64_dec(0, dec_buf);
    assert(dec_buf[..] == "0");
    dec_buf.clear();
    core::format_u64_dec(9, dec_buf);
    assert(dec_buf[..] == "9");
    dec_buf.clear();
    core::format_u64_dec(42, dec_buf);
    assert(dec_buf[..] == "42");
    dec_buf.clear();
    core::format_u64_dec(18446744073709551615, dec_buf);
    assert(dec_buf[..] == "18446744073709551615");

    var case_buf: u8[24] = [0; 24];
    let sample = "Content-Type: Text/Html!";
    for i in sample.len {
        case_buf[i] = sample[i];
    }
    core::make_ascii_lowercase(case_buf[..sample.len]);
    assert(case_buf[..sample.len] == "content-type: text/html!");
    assert(core::eq_ascii_fold(case_buf[..sample.len], sample));
    core::make_ascii_uppercase(case_buf[..sample.len]);
    assert(case_buf[..sample.len] == "CONTENT-TYPE: TEXT/HTML!");

    assert(core::is_pure_ascii("PureAsciiHeaderValue_0123456789!"));
    assert(!core::is_pure_ascii("PrefixWithHighByte_\x80_Suffix"));

    let wire = "GET /api/v1/items HTTP/1.1\r\nHost: example.com\r\nX-Tag: abcd\r\n\r\n";
    assert(core::find_crlf(wire) == 26);
    assert(core::fast_find_crlfcrlf(wire) == 58);
    assert(core::last_index_of_byte(wire, '/') == 22);
    assert(core::count_byte(wire, ':') == 2);
    assert(core::find(wire, "example.com") == 34);
    assert(core::rfind(wire, "X-Tag") == 47);
    assert(core::swar_find_ctl("clean-header-value_0123456789") == 29);
    assert(core::swar_find_ctl("bad-header\x00value") == 10);

    var huff_enc: u8[..64] = [];
    var huff_dec: u8[..64] = [];
    assert(http2::huff_encode_bytes("www.example.com", huff_enc));
    assert(http2::huff_decode_bytes(huff_enc[..], huff_dec));
    assert(huff_dec[..] == "www.example.com");
    let bad_huff: u8[2] = [0xFF, 0x00];
    var bad_out: u8[..16] = [];
    assert(!http2::huff_decode_bytes(bad_huff[..], bad_out));
    assert(bad_out.len == 0);

    let mask: u8[4] = [0x37, 0xFA, 0x21, 0x3D];
    let ws_plain = "Hello, WebSocket SWAR payload!";
    var ws_frame: u8[..64] = [];
    assert(ws_frame.try_append("\x81\x9E\x37\xFA\x21\x3D"));
    let hdr_len = ws_frame.len;
    assert(ws_frame.try_append(ws_plain));
    realtime::apply_mask_in_place(ws_frame[hdr_len..], mask);
    let unmasked = realtime::unmask_websocket_shifted(ws_frame[..], hdr_len, ws_plain.len, mask);
    assert(unmasked == ws_plain);

    var l0 = server::L0RegisterTable { .. };
    assert(server_internal::register_l0_route(l0, 0, "/plaintext", 1));
    assert(server_internal::match_l0("/plaintext", 0, l0) == 0);
    assert(server_internal::match_l0("/plaintext", 1, l0) == -1);
    assert(server_internal::match_l0("/too-long-static-route", 0, l0) == -1);

    // CHECK: WAVE2_SIMD_CODEC_PORTS: OK
    print("WAVE2_SIMD_CODEC_PORTS: OK");
}

fn test_wave3_pure_goose_aead() {
    let aes_key: u8[32] = [0; 32];
    let aes_iv:  u8[12] = [0; 12];
    let aes_pt:  u8[16] = [0; 16];
    let aes_expected_ct: u8[16] = [
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
        0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
    ];
    let aes_expected_tag: u8[16] = [
        0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
        0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
    ];
    var aes_ct: u8[16] = [0; 16];
    let aes_tag, aes_wn, aes_ok = core::aes_gcm_seal_pure(
        aes_key[..],
        aes_iv,
        aes_pt[..],
        "",
        aes_ct[..],
    );
    assert(aes_ok && aes_wn == 16);
    for i in 16 {
        assert(aes_ct[i] == aes_expected_ct[i]);
        assert(aes_tag[i] == aes_expected_tag[i]);
    }
    var aes_dec: u8[16] = [0xAA; 16];
    let aes_dn, aes_open_ok = core::aes_gcm_open_pure(
        aes_key[..],
        aes_iv,
        aes_ct[..],
        "",
        aes_tag,
        aes_dec[..],
    );
    assert(aes_open_ok && aes_dn == 16);
    for i in 16 {
        assert(aes_dec[i] == 0);
    }
    var bad_aes_tag = aes_tag;
    bad_aes_tag[0] ^= 0x01;
    var aes_tamper_dst: u8[16] = [0xCC; 16];
    let aes_bad_n, aes_bad_ok = core::aes_gcm_open_pure(
        aes_key[..],
        aes_iv,
        aes_ct[..],
        "",
        bad_aes_tag,
        aes_tamper_dst[..],
    );
    assert(!aes_bad_ok && aes_bad_n == 0);
    for b in aes_tamper_dst {
        assert(b == 0);
    }

    let cc_key: u8[32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    let cc_nonce: u8[12] = [
        0x07, 0x00, 0x00, 0x00,
        0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47,
    ];
    let cc_aad: u8[12] = [
        0x50, 0x51, 0x52, 0x53,
        0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let cc_pt: const u8[:] =
        "Ladies and Gentlemen of the class of \x2799: If I could offer you only one tip for the future, sunscreen would be it.";
    let cc_expected_tag: u8[16] = [
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    ];
    var cc_ct: u8[..128] = [];
    cc_ct.resize(cc_pt.len, 0);
    let cc_tag, cc_wn, cc_ok = core::chacha20_poly1305_seal_pure(
        cc_key,
        cc_nonce,
        cc_pt,
        cc_aad[..],
        cc_ct[..],
    );
    assert(cc_ok && cc_wn == cc_pt.len);
    for i in 16 {
        assert(cc_tag[i] == cc_expected_tag[i]);
    }
    var cc_dec: u8[..128] = [];
    cc_dec.resize(cc_pt.len, 0);
    let cc_dn, cc_open_ok = core::chacha20_poly1305_open_pure(
        cc_key,
        cc_nonce,
        cc_ct[..],
        cc_aad[..],
        cc_tag,
        cc_dec[..],
    );
    assert(cc_open_ok && cc_dn == cc_pt.len && cc_dec[..] == cc_pt);

    var bad_cc_tag = cc_tag;
    bad_cc_tag[15] ^= 0x80;
    var cc_tamper_dst: u8[..128] = [];
    cc_tamper_dst.resize(cc_pt.len, 0x77);
    let cc_bad_n, cc_bad_ok = core::chacha20_poly1305_open_pure(
        cc_key,
        cc_nonce,
        cc_ct[..],
        cc_aad[..],
        bad_cc_tag,
        cc_tamper_dst[..],
    );
    assert(!cc_bad_ok && cc_bad_n == 0);
    for b in cc_tamper_dst {
        assert(b == 0);
    }

    // CHECK: WAVE3_PURE_AEAD_PORTS: OK
    print("WAVE3_PURE_AEAD_PORTS: OK");
}

fn test_wave4_driver_loopback_ports() {
    let mp = net_internal::dpdk_create_mempool(64, 2048);
    assert(mp.is_created && mp.pool_handle != 0);
    var dev = net_internal::new_dpdk_device(0);
    let port_cfg = net_internal::DpdkPortConfig { port_id: 0, .. };
    assert(net_internal::dpdk_init_port(dev, port_cfg) == 0);
    assert(net_internal::dpdk_start_port(dev) == 0);

    let mbufs: u64[2] = [0x1001, 0x1002];
    assert(net_internal::dpdk_tx_burst(dev, 0, mbufs[..]) == 2);
    var rx_mbufs: u64[..32] = [];
    assert(net_internal::dpdk_rx_burst(dev, 0, rx_mbufs, 32) == 2);
    assert(rx_mbufs.len == 2 && rx_mbufs[0] == 0x1001 && rx_mbufs[1] == 0x1002);

    assert(net_internal::dpdk_tx_packet_push(0, 0, "eth_l2_frame"));
    var rx_frames: u8[..2048][..32] = [];
    assert(net_internal::dpdk_rx_burst_read(0, 0, rx_frames) == 1);
    assert(rx_frames.len == 1 && rx_frames[0][..] == "eth_l2_frame");
    net_internal::dpdk_stop_port(dev);
    assert(!net_internal::dpdk_tx_packet_push(0, 0, "stopped"));

    var xsk, xsk_ok = net_internal::af_xdp_open_loopback(16, 2048);
    assert(xsk_ok && xsk.is_bound && xsk.rings_mapped);
    assert(net_internal::af_xdp_umem_write(xsk, 2048, "xdp_rx_payload"));
    assert(!net_internal::af_xdp_umem_write(xsk, 16 * 2048, "oob"));
    assert(net_internal::af_xdp_fill_push(xsk, 0));
    assert(net_internal::af_xdp_inject_loopback_rx(xsk, 2048, 14));
    let rx_desc, rx_ok = net_internal::af_xdp_rx_poll(xsk);
    assert(rx_ok && rx_desc.addr == 2048 && rx_desc.len == 14);
    var xdp_frame: u8[..2048] = [];
    assert(net_internal::af_xdp_umem_read(xsk, rx_desc.addr, rx_desc.len, xdp_frame));
    assert(xdp_frame[..] == "xdp_rx_payload");
    let tx_desc = net_internal::XdpDesc { addr: 0, len: 14, options: 0 };
    assert(net_internal::af_xdp_tx_submit(xsk, tx_desc));
    let comp_addr, comp_ok = net_internal::af_xdp_complete_pop(xsk);
    assert(comp_ok && comp_addr == 0);
    net_internal::af_xdp_close(xsk);

    let rio_rx = net_internal::RioResult { status: 0, bytes_transferred: 5, .. };
    let rio_tx = net_internal::RioResult { status: 0, bytes_transferred: 5, .. };
    net_internal::rio_hs_defer_push_rx(77, rio_rx);
    net_internal::rio_hs_defer_push_tx(88, rio_tx);
    var leftover: u8[16] = [0; 16];
    assert(net_internal::rio_hs_end(leftover[..]) == 0);

    let dgram, dg_ok = net::build_udp_datagram("quic_dgram", 0x7F000001, 4433);
    assert(dg_ok && dgram.payload[..] == "quic_dgram");
    var big: u8[1500] = [0; 1500];
    let _, big_ok = net::build_udp_datagram(big[..], 0x7F000001, 4433);
    assert(!big_ok);

    // CHECK: WAVE4_DRIVER_PORTS: OK
    print("WAVE4_DRIVER_PORTS: OK");
}

fn test_wave5_wasm_and_tcp_ports() {
    let lis = net_internal::wasm_tcp_listen("127.0.0.1", 0, 8);
    assert(lis > 0);
    let port = net_internal::wasm_tcp_getsockname_port(lis);
    assert(port >= 49152);
    assert(net_internal::wasm_tcp_accept(lis) == 0);

    let cli = net_internal::wasm_tcp_connect("127.0.0.1", port);
    assert(cli > 0);
    let srv = net_internal::wasm_tcp_accept(lis);
    assert(srv > 0);

    let ep = net_internal::wasm_epoll_create();
    assert(ep > 0);
    assert(net_internal::wasm_epoll_add(ep, srv, 1, 101));
    assert(net_internal::wasm_epoll_mod(ep, srv, 5, 202));

    assert(net_internal::wasm_tcp_send(cli, "ping_wasm") == 9);
    assert(net_internal::wasm_tcp_get_readable_bytes(srv) == 9);

    var efds:    i64[4] = [0; 4];
    var eudata:  u64[4] = [0; 4];
    var eevents: u32[4] = [0; 4];
    let ready = net_internal::wasm_epoll_wait(ep, efds[..], eudata[..], eevents[..]);
    assert(ready == 1 && efds[0] == srv && eudata[0] == 202 && (eevents[0] & 1) != 0);

    var peek_buf: u8[16] = [0; 16];
    assert(net_internal::wasm_tcp_recv(srv, peek_buf[..], true) == 9);
    assert(peek_buf[..9] == "ping_wasm");
    assert(net_internal::wasm_tcp_get_readable_bytes(srv) == 9);

    var rx_buf: u8[16] = [0; 16];
    assert(net_internal::wasm_tcp_recv(srv, rx_buf[..], false) == 9);
    assert(rx_buf[..9] == "ping_wasm");
    assert(net_internal::wasm_tcp_get_readable_bytes(srv) == 0);

    assert(net_internal::wasm_tcp_shutdown(cli, 1));
    assert(net_internal::wasm_tcp_recv(srv, rx_buf[..], false) == 0);

    assert(net_internal::wasm_epoll_del(ep, srv));
    net_internal::wasm_epoll_close(ep);
    net_internal::wasm_tcp_close(srv);
    net_internal::wasm_tcp_close(cli);
    net_internal::wasm_tcp_close(lis);

    let expected_smt: i64[8] = [0, 2, 4, 6, 1, 3, 5, 7];
    for c in 8 {
        assert(net::calc_smt_physical_cpu(c, 8) == expected_smt[c]);
    }

    // CHECK: WAVE5_WASM_TCP_PORTS: OK
    print("WAVE5_WASM_TCP_PORTS: OK");
}

fn main() {
    test_wave1_stdlib_and_tls_helpers();
    test_wave2_simd_strings_and_codecs();
    test_wave3_pure_goose_aead();
    test_wave4_driver_loopback_ports();
    test_wave5_wasm_and_tcp_ports();

    // CHECK: ALL_PURE_GOOSE_PORTS_VERIFIED
    print("ALL_PURE_GOOSE_PORTS_VERIFIED");
}
