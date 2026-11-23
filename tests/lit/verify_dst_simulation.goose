// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Full-stack Deterministic Simulation Testing (DST) verification suite:
// Exercises deterministic virtual clock, CSPRNG plumbing, TCP/UDP fault injection,
// net::Host virtual pair bridging, HTTP/1.1, HTTP/2, TLS 1.3, QUIC/HTTP/3,
// auth/cache/rate-limiter clock jumps, 16-seed sweep, and bit-for-bit reproducibility.
// RUN: goose %s | %FileCheck %s

import std;
import os;
import wing from "../..";

const SIM_BASE_UNIX_NS: u64 = 1700000000000000000;
const NS_PER_MS:        u64 = 1000000;
const NS_PER_SEC:       u64 = 1000000000;
const NS_PER_HOUR:      u64 = 3600000000000;
const OWNER_DST_CLI:    u16 = core::IO_OWNER_USER_START + 20;
const OWNER_DST_SRV:    u16 = core::IO_OWNER_USER_START + 21;

struct FullStackRunSummary {
    trace_digest:       u64 = 0,
    events_scheduled:   u64 = 0,
    events_dispatched:  u64 = 0,
    tcp_segments_deliv: u64 = 0,
    tcp_bytes_deliv:    u64 = 0,
    tcp_rsts:           u64 = 0,
    tcp_fins:           u64 = 0,
    tcp_stalls:         u64 = 0,
    udp_sent:           u64 = 0,
    udp_deliv:          u64 = 0,
    udp_dropped:        u64 = 0,
    udp_reordered:      u64 = 0,
    udp_duplicated:     u64 = 0,
    udp_corrupted:      u64 = 0,
    udp_nat_rebinds:    u64 = 0,
    timers_fired:       u64 = 0,
    clock_jumps:        u64 = 0,
    virtual_skipped_ns: u64 = 0,
    tls_transcript_h64: u64 = 0,
    tls_ct_h64:         u64 = 0,
    entropy_h64:        u64 = 0,
}

fn summaries_equal(a: const FullStackRunSummary&, b: const FullStackRunSummary&) -> bool {
    return a.trace_digest == b.trace_digest
        && a.events_scheduled == b.events_scheduled
        && a.events_dispatched == b.events_dispatched
        && a.tcp_segments_deliv == b.tcp_segments_deliv
        && a.tcp_bytes_deliv == b.tcp_bytes_deliv
        && a.tcp_rsts == b.tcp_rsts
        && a.tcp_fins == b.tcp_fins
        && a.tcp_stalls == b.tcp_stalls
        && a.udp_sent == b.udp_sent
        && a.udp_deliv == b.udp_deliv
        && a.udp_dropped == b.udp_dropped
        && a.udp_reordered == b.udp_reordered
        && a.udp_duplicated == b.udp_duplicated
        && a.udp_corrupted == b.udp_corrupted
        && a.udp_nat_rebinds == b.udp_nat_rebinds
        && a.timers_fired == b.timers_fired
        && a.clock_jumps == b.clock_jumps
        && a.virtual_skipped_ns == b.virtual_skipped_ns
        && a.tls_transcript_h64 == b.tls_transcript_h64
        && a.tls_ct_h64 == b.tls_ct_h64
        && a.entropy_h64 == b.entropy_h64;
}

// ---- Helper: Drive a TCP byte stream through DstWorld step-by-step --------

fn pump_tcp_all(
    world:   net::DstWorld&,
    link_id: u16,
    dir:     net::DstDir,
    out:     u8[>..]&,
    max_ops: i64 = 4096,
) -> core::IoError {
    var chunk: u8[256] = [0; 256];
    for _ in max_ops {
        let n, err = net::dst_tcp_recv(world, link_id, dir, chunk[..]);
        if n > 0 {
            out.append(chunk[..n]);
            continue;
        }
        if err == core::IoError.Eof || err == core::IoError.Closed {
            return err;
        }
        let step = net::dst_step(world);
        if !step.fired {
            return core::IoError.WouldBlock;
        }
    }
    return core::IoError.WouldBlock;
}

// ---- Scenario 1: HTTP/1.1 Fragmentation, Pipelining, Chunked RST, Host ----

struct DstHostProbeDriver {
    srv_link:     core::IoLink  = core::IoLink { .. },
    rx_buf:       u8[..512]     = [],
    got_closed:   bool          = false,
    got_timer:    bool          = false,
    closed_error: core::IoError = core::IoError.None,
}

fn core::on_link_event(drv: DstHostProbeDriver&, _host: net::Host&, ev: const core::LinkEvent&) {
    if ev.kind == core::LinkEventKind.Timer && ev.timer_id == 9001 {
        drv.got_timer = true;
        return;
    }
    guard ev.link.raw == drv.srv_link.raw else { return; }
    if ev.kind == core::LinkEventKind.Data {
        let _ = drv.rx_buf.try_append(ev.data);
    } else if ev.kind == core::LinkEventKind.Closed {
        drv.got_closed = true;
        drv.closed_error = ev.err;
    }
}

fn run_http1_dst_scenario(world: net::DstWorld&, ep_c: u16, ep_s: u16) {
    // 1A: 1-byte TCP fragmentation with keep-alive pipelining.
    let frag_cfg = net::dst_fault_profile(net::DstFaultProfile.ByteFragmented);
    let lid, ok_l = net::dst_open_tcp_link(world, ep_c, ep_s, frag_cfg);
    assert(ok_l);

    var hdrs = http::HeaderMap { .. };
    var pipe_req: u8[..1024] = [];
    assert(wire::encode_h1_request("GET", "/one", "dst.local", hdrs, "", wire::H1HeaderFilterMode.PreserveAll, pipe_req));
    assert(wire::encode_h1_request("GET", "/two", "dst.local", hdrs, "", wire::H1HeaderFilterMode.PreserveAll, pipe_req));

    let s_n, s_err = net::dst_tcp_send(world, lid, net::DstDir.AToB, pipe_req[..]);
    assert(s_n == pipe_req.len && s_err == core::IoError.None);
    assert(net::dst_tcp_shutdown_write(world, lid, net::DstDir.AToB));

    var srv_rx: u8[>..] = [];
    let end_err = pump_tcp_all(world, lid, net::DstDir.AToB, srv_rx);
    assert(end_err == core::IoError.Eof);
    assert(srv_rx[..] == pipe_req[..]);
    assert(world.stats.tcp_segments_delivered >= (pipe_req.len as u64));

    // Verify both pipelined requests parse cleanly from reassembled stream.
    let idx1 = core::fast_find_crlfcrlf(srv_rx[..]);
    assert(idx1 > 0);
    let req1_end = idx1 + 4;
    let idx2 = core::fast_find_crlfcrlf(srv_rx[req1_end..]);
    assert(idx2 > 0);
    assert(core::starts_with(srv_rx[..req1_end], "GET /one HTTP/1.1\r\n"));
    assert(core::starts_with(srv_rx[req1_end..], "GET /two HTTP/1.1\r\n"));

    // Send 2 pipelined HTTP/1.1 responses back through 1-byte fragmentation and decode.
    var pipe_resp: u8[..1024] = [];
    assert(wire::encode_h1_response(200, "OK", "goose-dst", hdrs, "ONE", false, pipe_resp));
    assert(wire::encode_h1_response(200, "OK", "goose-dst", hdrs, "TWO", false, pipe_resp));
    let r_n, r_err = net::dst_tcp_send(world, lid, net::DstDir.BToA, pipe_resp[..]);
    assert(r_n == pipe_resp.len && r_err == core::IoError.None);
    assert(net::dst_tcp_shutdown_write(world, lid, net::DstDir.BToA));

    var cli_rx: u8[>..] = [];
    let c_end = pump_tcp_all(world, lid, net::DstDir.BToA, cli_rx);
    assert(c_end == core::IoError.Eof);

    var sc1: u16 = 0;
    var rh1 = http::HeaderMap { .. };
    let off1, he1 = wire::decode_h1_response_head(cli_rx[..], sc1, rh1);
    assert(he1 == http::HeaderParseError.None && sc1 == 200);
    assert(cli_rx[off1..off1 + 3] == "ONE");

    var sc2: u16 = 0;
    var rh2 = http::HeaderMap { .. };
    let off2, he2 = wire::decode_h1_response_head(cli_rx[off1 + 3..], sc2, rh2);
    assert(he2 == http::HeaderParseError.None && sc2 == 200);
    assert(cli_rx[off1 + 3 + off2..off1 + 3 + off2 + 3] == "TWO");

    // 1B: Chunked transfer encoding with mid-stream RST injection -> clean fail-closed error.
    var rst_cfg = net::dst_fault_profile(net::DstFaultProfile.MidStreamRst);
    rst_cfg.tcp_rst_at_byte = 60; // Cuts right inside the second chunk body!
    let lid_rst, ok_rst = net::dst_open_tcp_link(world, ep_c, ep_s, rst_cfg);
    assert(ok_rst);

    let chunked_wire = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\nB\r\nworld_chunk\r\n0\r\n\r\n";
    let sent_c, err_c = net::dst_tcp_send(world, lid_rst, net::DstDir.BToA, chunked_wire);
    assert(sent_c == 60 && err_c == core::IoError.None);

    var trunc_rx: u8[>..] = [];
    let rst_end = pump_tcp_all(world, lid_rst, net::DstDir.BToA, trunc_rx);
    assert(rst_end == core::IoError.Closed);
    assert(trunc_rx.len == 60);

    var sc_c: u16 = 0;
    var hdr_c = http::HeaderMap { .. };
    let body_off, parse_err = wire::decode_h1_response_head(trunc_rx[..], sc_c, hdr_c);
    assert(parse_err == http::HeaderParseError.None && sc_c == 200);

    var cdec = http_internal::new_chunk_fsm_decoder();
    var body_acc: u8[..128] = [];
    var pos = body_off;
    var saw_complete = false;
    while pos < trunc_rx.len {
        let st, used, piece = http_internal::chunk_fsm_feed(cdec, trunc_rx[pos..]);
        if piece.len > 0 {
            let _ = body_acc.try_append(piece);
        }
        if st == http_internal::ChunkFsmStatus.Complete {
            saw_complete = true;
            break;
        }
        if used == 0 || st == http_internal::ChunkFsmStatus.Error {
            break;
        }
        pos += used;
    }
    // Truncated chunked body MUST NOT falsely complete and subsequent send MUST fail closed.
    assert(!saw_complete && body_acc[..] == "hello");
    let _, after_rst_err = net::dst_tcp_send(world, lid_rst, net::DstDir.BToA, "more");
    assert(after_rst_err == core::IoError.Closed);

    // 1C: Receive-window throttling / backpressure + net::Host virtual pair & timer bridge.
    var bp_cfg = net::dst_fault_profile(net::DstFaultProfile.Clean);
    bp_cfg.tcp_rx_window_bytes = 16;
    let lid_bp, ok_bp = net::dst_open_tcp_link(world, ep_c, ep_s, bp_cfg);
    assert(ok_bp);
    assert(net::dst_tcp_set_rx_paused(world, lid_bp, net::DstDir.AToB, true));
    let n_paused, e_paused = net::dst_tcp_send(world, lid_bp, net::DstDir.AToB, "BACKPRESSURE_DATA");
    assert(n_paused == 0 && e_paused == core::IoError.WouldBlock);
    assert(net::dst_tcp_set_rx_paused(world, lid_bp, net::DstDir.AToB, false));
    assert(net::dst_tcp_set_rx_window(world, lid_bp, net::DstDir.AToB, 10));
    let n_short, e_short = net::dst_tcp_send(world, lid_bp, net::DstDir.AToB, "0123456789ABCDEF");
    assert(n_short == 10 && e_short == core::IoError.ShortWrite);

    // Bridge a DstTcpLink onto net::Host virtual pair and test fragmented Data + Timer skip + RST -> Closed!
    var dcfg = net_internal::TransportDriverConfig {
        active_kind: net_internal::TransportDriverKind.Standard,
        is_probed:   true,
        ..
    };
    var host = net::new_host(dcfg);
    defer net::close_host(host);
    var bridge_cfg = net::dst_fault_profile(net::DstFaultProfile.Clean);
    bridge_cfg.tcp_frag_min_bytes = 3;
    bridge_cfg.tcp_frag_max_bytes = 5;
    let lid_h, ok_lh = net::dst_open_tcp_link(world, ep_c, ep_s, bridge_cfg);
    assert(ok_lh);
    let _, srv_lnk, ok_attach = net::dst_attach_host_pair(world, host, lid_h, OWNER_DST_CLI, OWNER_DST_SRV);
    assert(ok_attach);
    assert(net::dst_set_tcp_faults(world, lid_h, bridge_cfg));

    var drv = DstHostProbeDriver { srv_link: srv_lnk, .. };
    let hn, herr = net::dst_tcp_send(world, lid_h, net::DstDir.AToB, "HOST_BRIDGE_OK");
    assert(hn == 14 && herr == core::IoError.None);
    assert(net::dst_tcp_inject_rst(world, lid_h, net::DstDir.AToB, 50 * NS_PER_MS));
    // Schedule a 2-hour host timer to prove instant time-skipping via dst_step_host.
    assert(core::host_add_timer(host, 9001, 7200000, OWNER_DST_SRV, 42, false, world.now_ns));
    for _ in 64 {
        let _ = net::dst_step_host(world, host, drv);
        if drv.got_closed && drv.got_timer {
            break;
        }
    }
    assert(drv.rx_buf[..] == "HOST_BRIDGE_OK");
    assert(drv.got_closed && drv.closed_error == core::IoError.Closed);
    assert(drv.got_timer);
}

// ---- Scenario 2: HTTP/2 HPACK + Fragmented Framing + Window Saturation ----

fn run_http2_dst_scenario(world: net::DstWorld&, ep_c: u16, ep_s: u16) {
    var cfg = net::dst_fault_profile(net::DstFaultProfile.Clean);
    cfg.tcp_frag_min_bytes = 1;
    cfg.tcp_frag_max_bytes = 5;
    let lid, ok_l = net::dst_open_tcp_link(world, ep_c, ep_s, cfg);
    assert(ok_l);

    var cli_h2 = http2::new_h2_connection(world.now_ns / NS_PER_MS);
    var srv_h2 = http2::new_h2_connection(world.now_ns / NS_PER_MS);
    srv_h2.is_server = true;

    // Shrink peer initial window to 64 bytes so a 100-byte body saturates flow control.
    assert(http2::apply_peer_initial_window_size_delta(cli_h2, 64) == rfc::H2_ERR_NO_ERROR);
    http2::open_stream(cli_h2, 1, false);
    assert(http2::compute_stream_send_quota(cli_h2, 1) == 64);

    // Client encodes preface + HPACK HEADERS + first 64-byte DATA chunk under window limit.
    var hpack_enc = http2::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var pseudo = http2::PseudoHeaders {
        has_method:    true,
        has_scheme:    true,
        has_authority: true,
        has_path:      true,
        ..
    };
    assert(pseudo.method.try_set("POST"));
    assert(pseudo.scheme.try_set("https"));
    assert(pseudo.authority.try_set("dst.local"));
    assert(pseudo.path.try_set("/h2-upload"));
    var req_hdrs = http::HeaderMap { .. };
    http::insert_header(req_hdrs, "x-dst-mode", "fragmented");

    var wire_tx: u8[..2048] = [];
    assert(wire_tx.try_append(rfc::H2_CLIENT_PREFACE[..]));
    assert(wire::encode_h2_headers_frame_from_map(hpack_enc, 1, pseudo, req_hdrs, false, wire_tx));

    var body_all: u8[100] = [0x61; 100];
    for i in 100 { body_all[i] = (0x41 + (i % 26)) as u8; }

    assert(http2::enqueue_stream_send_bytes(cli_h2, 1, 100));
    let w_sid, w_len, w_ok = http2::schedule_next_write(cli_h2, 16384);
    assert(w_ok && w_sid == 1 && w_len == 64);
    // Window is now saturated (quota == 0).
    assert(http2::compute_stream_send_quota(cli_h2, 1) == 0);
    let _, _, blocked_ok = http2::schedule_next_write(cli_h2, 16384);
    assert(!blocked_ok);
    assert(wire::encode_data_frame(1, body_all[..64], false, wire_tx));

    let s1, e1 = net::dst_tcp_send(world, lid, net::DstDir.AToB, wire_tx[..]);
    assert(s1 == wire_tx.len && e1 == core::IoError.None);
    let _ = net::dst_run_until(world, world.now_ns + 500 * NS_PER_MS);

    var srv_rx: u8[>..] = [];
    let _ = pump_tcp_all(world, lid, net::DstDir.AToB, srv_rx);
    assert(srv_rx.len == wire_tx.len);
    assert(core::starts_with(srv_rx[..], rfc::H2_CLIENT_PREFACE[..]));

    // Server reads frames incrementally from fragmented wire bytes.
    var cursor: i64 = rfc::H2_CLIENT_PREFACE.len;
    let fh1, pl1, ok_f1 = wire::read_wire_h2_frame(srv_rx[..], cursor);
    assert(ok_f1 && fh1.frame_type == rfc::H2_FRAME_HEADERS && fh1.stream_id == 1);
    let h2_fh1 = http2::FrameHeader {
        length: fh1.length, frame_type: fh1.frame_type, flags: fh1.flags, stream_id: fh1.stream_id,
    };
    assert(http2::on_ingress_frame_header(srv_h2, h2_fh1, world.now_ns / NS_PER_MS) == rfc::H2_ERR_NO_ERROR);
    http2::open_stream(srv_h2, 1, false);
    var dec_pseudo = http2::PseudoHeaders { .. };
    var dec_hdrs = http::HeaderMap { .. };
    let dec_err = http2::decode_hpack_to_map(srv_h2.hpack_dec, pl1, dec_pseudo, dec_hdrs, 8192);
    assert(dec_err == rfc::H2_ERR_NO_ERROR && dec_pseudo.path[..] == "/h2-upload");
    assert(http::get_header(dec_hdrs, "x-dst-mode") == "fragmented");

    let fh2, pl2, ok_f2 = wire::read_wire_h2_frame(srv_rx[..], cursor);
    assert(ok_f2 && fh2.frame_type == rfc::H2_FRAME_DATA && fh2.stream_id == 1 && pl2.len == 64);
    let h2_fh2 = http2::FrameHeader {
        length: fh2.length, frame_type: fh2.frame_type, flags: fh2.flags, stream_id: fh2.stream_id,
    };
    assert(http2::on_data_frame_received(srv_h2, h2_fh2, 64) == rfc::H2_ERR_NO_ERROR);

    // Server sends WINDOW_UPDATE(+64) on stream 1 and connection 0; client recovers and sends tail 36 bytes!
    var wu_wire: u8[..64] = [];
    assert(wire::encode_window_update_frame(0, 64, wu_wire));
    assert(wire::encode_window_update_frame(1, 64, wu_wire));
    let swu, ewu = net::dst_tcp_send(world, lid, net::DstDir.BToA, wu_wire[..]);
    assert(swu == wu_wire.len && ewu == core::IoError.None);
    let _ = net::dst_run_until(world, world.now_ns + 500 * NS_PER_MS);

    var cli_wu: u8[>..] = [];
    let _ = pump_tcp_all(world, lid, net::DstDir.BToA, cli_wu);
    var wu_cur: i64 = 0;
    for _ in 2 {
        let wfh, wpl, wok = wire::read_wire_h2_frame(cli_wu[..], wu_cur);
        assert(wok && wfh.frame_type == rfc::H2_FRAME_WINDOW_UPDATE && wpl.len == 4);
        let inc = core::read_be_u32(wpl, 0) & 0x7FFFFFFF;
        assert(http2::apply_window_update(cli_h2, wfh.stream_id, inc) == rfc::H2_ERR_NO_ERROR);
    }

    let w_sid2, w_len2, w_ok2 = http2::schedule_next_write(cli_h2, 16384);
    assert(w_ok2 && w_sid2 == 1 && w_len2 == 36);
    var tail_wire: u8[..128] = [];
    assert(wire::encode_data_frame(1, body_all[64..100], true, tail_wire));
    let stail, etail = net::dst_tcp_send(world, lid, net::DstDir.AToB, tail_wire[..]);
    assert(stail == tail_wire.len && etail == core::IoError.None);
    let _ = net::dst_run_until(world, world.now_ns + 500 * NS_PER_MS);

    var srv_tail: u8[>..] = [];
    let _ = pump_tcp_all(world, lid, net::DstDir.AToB, srv_tail);
    var t_cur: i64 = 0;
    let fh3, pl3, ok_f3 = wire::read_wire_h2_frame(srv_tail[..], t_cur);
    assert(ok_f3 && fh3.frame_type == rfc::H2_FRAME_DATA && (fh3.flags & rfc::H2_FLAG_END_STREAM) != 0);
    assert(pl3 == body_all[64..100]);
}

// ---- Scenario 3: TLS 1.3 Deterministic Handshake & Record Fail-Closed -----

fn run_tls13_dst_scenario(world: net::DstWorld&, ep_c: u16, ep_s: u16) -> u64, u64 {
    var cfg = net::dst_fault_profile(net::DstFaultProfile.Clean);
    cfg.tcp_frag_min_bytes = 2;
    cfg.tcp_frag_max_bytes = 19;
    let lid, ok_l = net::dst_open_tcp_link(world, ep_c, ep_s, cfg);
    assert(ok_l);

    // Deterministic client random + X25519 keypair via TLS CSPRNG hook -> sim_rng_fill.
    var cli_rand: u8[32] = [0; 32];
    var cli_priv: u8[32] = [0; 32];
    var srv_rand: u8[32] = [0; 32];
    var srv_priv: u8[32] = [0; 32];
    assert(tls_internal::native_tls_csprng_bytes(cli_rand[..]) == 0);
    assert(tls_internal::native_tls_csprng_bytes(cli_priv[..]) == 0);
    assert(tls_internal::native_tls_csprng_bytes(srv_rand[..]) == 0);
    assert(tls_internal::native_tls_csprng_bytes(srv_priv[..]) == 0);
    let cli_pub = core::x25519_base_scalarmult(cli_priv);
    let srv_pub = core::x25519_base_scalarmult(srv_priv);

    var ch_payload: u8[..2048] = [];
    tls_internal::build_client_hello_payload(cli_rand, cli_pub, "dst.tls.local", "h2,http/1.1", ch_payload);
    var ch_msg: u8[..2048] = [];
    ch_msg.push(rfc::TLS_HS_CLIENT_HELLO);
    ch_msg.append_u24_be(ch_payload.len as u32);
    ch_msg.append(ch_payload[..]);

    let sc, ec = net::dst_tcp_send(world, lid, net::DstDir.AToB, ch_msg[..]);
    assert(sc == ch_msg.len && ec == core::IoError.None);
    let _ = net::dst_run_until(world, world.now_ns + 500 * NS_PER_MS);

    var srv_ch_rx: u8[>..] = [];
    let _ = pump_tcp_all(world, lid, net::DstDir.AToB, srv_ch_rx);
    assert(srv_ch_rx[..] == ch_msg[..]);

    var sid_out:     u8[..32]  = [];
    var parsed_cpub: u8[32]    = [0; 32];
    var neg_alpn:    u8[..32]  = [];
    var parsed_sni:  u8[..255] = [];
    var psk_resumed = false;
    var psk_secret: u8[32] = [0; 32];
    assert(tls_internal::parse_client_hello_for_server_sni(
        srv_ch_rx[..], "h2,http/1.1", sid_out, parsed_cpub, neg_alpn, parsed_sni, psk_resumed, psk_secret,
    ));
    assert(parsed_sni[..] == "dst.tls.local" && neg_alpn[..] == "h2");
    assert(core::ct_eq_bytes(parsed_cpub[..], cli_pub[..]));

    // Build and transmit ServerHello back across fragmented DST TCP.
    var sh_payload: u8[..1024] = [];
    tls_internal::build_server_hello_payload(
        srv_rand, sid_out[..], srv_pub, sh_payload, false, rfc::TLS_CIPHER_AES_128_GCM_SHA256, 0,
    );
    var sh_msg: u8[..1024] = [];
    sh_msg.push(rfc::TLS_HS_SERVER_HELLO);
    sh_msg.append_u24_be(sh_payload.len as u32);
    sh_msg.append(sh_payload[..]);

    let ss, es = net::dst_tcp_send(world, lid, net::DstDir.BToA, sh_msg[..]);
    assert(ss == sh_msg.len && es == core::IoError.None);
    let _ = net::dst_run_until(world, world.now_ns + 500 * NS_PER_MS);

    var cli_sh_rx: u8[>..] = [];
    let _ = pump_tcp_all(world, lid, net::DstDir.BToA, cli_sh_rx);
    var parsed_sh = tls::ParsedServerHello { .. };
    assert(tls::parse_live_server_hello(cli_sh_rx[..], parsed_sh));
    assert(parsed_sh.cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256);

    // Derive identical RFC 8446 transcript hash & AES-128-GCM application traffic keys on both sides.
    var tr = tls::Transcript { .. };
    tls_internal::transcript_update(tr, ch_msg[..]);
    tls_internal::transcript_update(tr, sh_msg[..]);
    var tr_hash: u8[..48] = [];
    tls_internal::transcript_current_hash(tr, tls_internal::HASH_SHA256, tr_hash);
    assert(tr_hash.len == 32);

    var srv_share32: u8[32] = [0; 32];
    for i in 32 { srv_share32[i] = parsed_sh.server_share[i]; }
    let ss_cli, ok_ec = core::x25519_shared_secret(cli_priv, srv_share32);
    let ss_srv, ok_es = core::x25519_shared_secret(srv_priv, parsed_cpub);
    assert(ok_ec && ok_es && core::ct_eq_bytes(ss_cli[..], ss_srv[..]));

    var ks, ok_ks = tls_internal::ks_init(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    assert(ok_ks && tls_internal::ks_init_early_secret(ks, ""));
    assert(tls_internal::ks_advance_to_handshake(ks, ss_cli[..]));
    assert(tls_internal::ks_derive_handshake_traffic(ks, tr_hash[..]));
    assert(tls_internal::ks_advance_to_master(ks, tr_hash[..]));

    var c_key: u8[16] = [0; 16];
    var c_iv:  u8[12] = [0; 12];
    assert(tls_internal::ks_derive_key_iv(ks.hash_id, ks.client_ap_traffic[..32], 16, c_key[..], c_iv));

    let app_plain = "GET /tls13-dst-verified HTTP/1.1\r\nHost: dst.tls.local\r\n\r\n";
    var sealed: u8[256] = [0; 256];
    let slen, _, ok_seal = tls::record_seal_into(
        rfc::TLS_CIPHER_AES_128_GCM_SHA256,
        c_key[..],
        c_iv,
        0,
        rfc::TLS_CONTENT_APPLICATION_DATA,
        app_plain,
        sealed[..],
    );
    assert(ok_seal && slen > app_plain.len);

    // Send sealed TLS 1.3 record over fragmented DST TCP and decrypt on server.
    let srec, erec = net::dst_tcp_send(world, lid, net::DstDir.AToB, sealed[..slen]);
    assert(srec == slen && erec == core::IoError.None);
    let _ = net::dst_run_until(world, world.now_ns + 500 * NS_PER_MS);

    var rx_rec: u8[>..] = [];
    let _ = pump_tcp_all(world, lid, net::DstDir.AToB, rx_rec);
    assert(rx_rec.len == slen);

    let r_ct, _, r_len, _, ok_rhdr = tls::parse_record_header(rx_rec[..5]);
    assert(ok_rhdr && r_ct == rfc::TLS_CONTENT_APPLICATION_DATA && r_len == slen - 5);
    var dec_plain: u8[256] = [0; 256];
    let dlen, inner_ct, _, ok_dec = tls::record_decrypt_into(
        rfc::TLS_CIPHER_AES_128_GCM_SHA256,
        c_key[..],
        c_iv,
        0,
        rx_rec[..5],
        rx_rec[5..slen],
        dec_plain[..],
    );
    assert(ok_dec && inner_ct == rfc::TLS_CONTENT_APPLICATION_DATA && dec_plain[..dlen] == app_plain);

    // Fail-closed check 1: 1-bit corruption in TLS ciphertext MUST reject decryption.
    var tampered: u8[..256] = [];
    assert(tampered.try_set(rx_rec[..slen]));
    tampered[12] = tampered[12] ^ 0x01;
    let _, _, _, ok_bad = tls::record_decrypt_into(
        rfc::TLS_CIPHER_AES_128_GCM_SHA256,
        c_key[..],
        c_iv,
        0,
        tampered[..5],
        tampered[5..slen],
        dec_plain[..],
    );
    assert(!ok_bad);

    // Fail-closed check 2: truncated TLS record via mid-stream RST MUST fail closed.
    var tr_cfg = net::dst_fault_profile(net::DstFaultProfile.MidStreamRst);
    tr_cfg.tcp_rst_at_byte = 14;
    let lid_tr, ok_ltr = net::dst_open_tcp_link(world, ep_c, ep_s, tr_cfg);
    assert(ok_ltr);
    let _, _ = net::dst_tcp_send(world, lid_tr, net::DstDir.AToB, sealed[..slen]);
    var trunc_tls: u8[>..] = [];
    let tr_err = pump_tcp_all(world, lid_tr, net::DstDir.AToB, trunc_tls);
    assert(tr_err == core::IoError.Closed && trunc_tls.len == 14 && trunc_tls.len < slen);

    return core::wyhash64(tr_hash[..], 0x71513), core::wyhash64(rx_rec[..slen], 0x71513);
}

// ---- Scenario 4: QUIC / HTTP/3 over Lossy, Reordering, Corrupting UDP -----

fn run_quic_h3_dst_scenario(world: net::DstWorld&, ep_c: u16, ep_s: u16) {
    let quic_cfg = net::dst_fault_profile(net::DstFaultProfile.LossyQuic);
    let uid, ok_u = net::dst_open_udp_link(world, ep_c, ep_s, quic_cfg);
    assert(ok_u);

    let scid: u8[8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let dcid: u8[8] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x08];
    var q_cli = quic::new_client_connection(dcid[..], scid[..]);
    var q_srv = quic::new_server_connection(dcid[..]);
    assert(quic::install_initial_keys(q_cli, dcid[..]));
    assert(quic::install_initial_keys(q_srv, dcid[..]));
    q_cli.tx_app_space = q_cli.tx_initial_space;
    q_cli.tx_app_space.space_id = quic::PnSpaceId.ApplicationData;
    q_srv.app_space = q_srv.initial_space;
    q_srv.app_space.space_id = quic::PnSpaceId.ApplicationData;
    quic::advance_state(q_cli, quic::QuicConnState.Established);
    quic::advance_state(q_srv, quic::QuicConnState.Established);

    // Build an HTTP/3 HEADERS + DATA request using QPACK + H3 framing.
    let h3_settings = fingerprint::H3Settings { .. };
    var h3_cli = http3::new_client_connection(h3_settings);
    var h3_srv = http3::new_server_connection(h3_settings);
    let sid, ok_sid = http3::open_request_stream(h3_cli);
    assert(ok_sid && sid == 0);

    var h3_pseudo = http3::PseudoHeaders {
        has_method:    true,
        has_scheme:    true,
        has_authority: true,
        has_path:      true,
        ..
    };
    assert(h3_pseudo.method.try_set("POST"));
    assert(h3_pseudo.scheme.try_set("https"));
    assert(h3_pseudo.authority.try_set("h3.dst.local"));
    assert(h3_pseudo.path.try_set("/quic-test"));
    var h3_hdrs = http::HeaderMap { .. };
    http::insert_header(h3_hdrs, "x-quic-dst", "lossy");

    var qpack_enc_stream: u8[..256] = [];
    var h3_frame_bytes:   u8[..512] = [];
    assert(wire::encode_h3_headers_from_map(
        h3_cli.qpack_table, sid, h3_pseudo, h3_hdrs, qpack_enc_stream, h3_frame_bytes,
    ));
    let hdr_frame_len = h3_frame_bytes.len;
    assert(wire::encode_h3_data_frame("QUIC_H3_DST_PAYLOAD_OK", h3_frame_bytes));

    // Split HTTP/3 stream bytes into 4 sealed RFC 9001 1-RTT QUIC STREAM packets over LossyQuic UDP.
    let seg_count: i64 = 4;
    var seg_acked: bool[4] = [false; 4];
    var seg_offs:  i64[4]  = [0; 4];
    var seg_lens:  i64[4]  = [0; 4];
    let base_sz = h3_frame_bytes.len / seg_count;
    for k in seg_count {
        seg_offs[k] = k * base_sz;
        seg_lens[k] = if k == seg_count - 1 { h3_frame_bytes.len - seg_offs[k] } else { base_sz };
    }

    var srv_reasm:   u8[512] = [0; 512];
    var srv_got_seg: bool[4] = [false; 4];
    var next_pn:     u64     = 1;
    var saw_nat_rebind = false;
    let initial_cli_port = world.endpoints[ep_c as i64].port;
    var dgram_buf: u8[1500]    = [0; 1500];
    var plain_dec: u8[..16384] = [];

    // Explicit NAT migration mid-transfer on round 2 + probabilistic rebinding from LossyQuic.
    var rounds: i64 = 0;
    while rounds < 40 {
        rounds += 1;
        if rounds == 2 {
            assert(net::dst_udp_rebind_endpoint_port(world, ep_c, 54321));
            let mig_addr = quic::new_endpoint_addr("10.0.0.1", 54321);
            let mig_tok: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
            quic::migrate(q_srv, mig_addr, mig_tok);
        }

        // Transmit any unacknowledged segments in sealed RFC 9001 1-RTT packets carrying STREAM frames.
        var all_acked = true;
        for k in seg_count {
            if !seg_acked[k] {
                all_acked = false;
                var frame_pl: u8[..512] = [];
                let sflags = quic::QuicStreamFlags {
                    fin:         k == seg_count - 1,
                    with_len:    true,
                    with_offset: seg_offs[k] > 0,
                };
                assert(quic::encode_stream_frame(
                    0,
                    seg_offs[k] as u64,
                    h3_frame_bytes[seg_offs[k]..seg_offs[k] + seg_lens[k]],
                    frame_pl,
                    sflags,
                ));
                var hdr = quic::QuicHeader {
                    header_type:   quic::QuicHeaderType.OneRtt,
                    version:       rfc::QUIC_VERSION_1,
                    packet_number: next_pn,
                    ..
                };
                assert(hdr.dcid.try_set(dcid[..]));
                var pkt: u8[..1200] = [];
                assert(quic::seal_packet(q_cli.tx_app_space, hdr, 2, frame_pl[..], pkt));
                quic::record_sent(q_cli, quic::PnSpaceId.ApplicationData, next_pn, pkt.len as u64, true, world.now_ns / 1000);
                assert(net::dst_udp_send(world, uid, net::DstDir.AToB, pkt[..]));
                next_pn += 1;
            }
        }
        if all_acked { break; }

        // Schedule PTO timer and advance virtual clock instantaneously.
        let pto_tid = 7000 + (rounds as u64);
        assert(net::dst_schedule_timer(world, pto_tid, 60 * NS_PER_MS, 1, rounds as u64));
        let _ = net::dst_run_until(world, world.now_ns + 65 * NS_PER_MS);
        let _ = net::dst_cancel_timer(world, pto_tid);

        // Drain server UDP inbox (handles drops, reordering, duplicates, bit-flip corruption, NAT rebind).
        loop {
            let n, _, src_port, ok_r = net::dst_udp_recv(world, uid, net::DstDir.AToB, dgram_buf[..]);
            if !ok_r { break; }
            if src_port != initial_cli_port {
                saw_nat_rebind = true;
            }
            var tmp_hdr, ok_pre = quic_internal::parse_quic_packet_pre_hp(q_srv, dgram_buf[..n], q_srv.scid.len as u8);
            plain_dec.clear();
            var unseal_ok = false;
            if ok_pre {
                let _, ok_v = quic_internal::verify_and_decrypt_packet(
                    q_srv,
                    quic::PnSpaceId.ApplicationData,
                    dgram_buf[..n],
                    n,
                    n,
                    tmp_hdr,
                    plain_dec,
                );
                unseal_ok = ok_v;
            }
            var ack_out = quic::AckFrame { .. };
            let pres = quic::process_datagram(q_srv, dgram_buf[..n], world.now_ns / 1000, ack_out);
            if pres.handled && unseal_ok {
                var f_idx: i64 = 0;
                let qf, ok_qf = quic::decode_frame_cursor(plain_dec[..], f_idx);
                if ok_qf && qf.frame_type == quic::QuicFrameType.Stream {
                    for k in seg_count {
                        if (qf.offset as i64) == seg_offs[k] && qf.payload.len == seg_lens[k] {
                            for b_i in seg_lens[k] {
                                srv_reasm[seg_offs[k] + b_i] = qf.payload[b_i];
                            }
                            srv_got_seg[k] = true;
                        }
                    }
                }
                var mask_b: u8 = 0;
                for k in seg_count {
                    if srv_got_seg[k] { mask_b = mask_b | ((1 as u8) << (k as u8)); }
                }
                let ack_pkt: u8[2] = [0xAC, mask_b];
                let _ = net::dst_udp_send(world, uid, net::DstDir.BToA, ack_pkt[..]);
            }
        }

        // Advance for ACK flight and process client ACK inbox.
        let _ = net::dst_run_until(world, world.now_ns + 50 * NS_PER_MS);
        loop {
            let n, _, _, ok_a = net::dst_udp_recv(world, uid, net::DstDir.BToA, dgram_buf[..]);
            if !ok_a { break; }
            if n == 2 && dgram_buf[0] == 0xAC {
                let mask_b = dgram_buf[1];
                for k in seg_count {
                    if (mask_b & ((1 as u8) << (k as u8))) != 0 {
                        seg_acked[k] = true;
                    }
                }
            }
        }
    }

    for k in seg_count {
        assert(srv_got_seg[k] && seg_acked[k]);
    }

    // Always verify NAT port migration with a sealed 1-RTT PING probe even if round 1 had 0 loss.
    if !saw_nat_rebind {
        assert(net::dst_udp_rebind_endpoint_port(world, ep_c, 54321));
        let mig_addr = quic::new_endpoint_addr("10.0.0.1", 54321);
        let mig_tok: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
        quic::migrate(q_srv, mig_addr, mig_tok);
        var ping_rounds: i64 = 0;
        while !saw_nat_rebind && ping_rounds < 16 {
            ping_rounds += 1;
            var ping_pl: u8[..16] = [];
            assert(quic::encode_ping_frame(ping_pl));
            assert(ping_pl.try_push(0) && ping_pl.try_push(0) && ping_pl.try_push(0));
            var phdr = quic::QuicHeader {
                header_type:   quic::QuicHeaderType.OneRtt,
                version:       rfc::QUIC_VERSION_1,
                packet_number: next_pn,
                ..
            };
            assert(phdr.dcid.try_set(dcid[..]));
            var ppkt: u8[..128] = [];
            assert(quic::seal_packet(q_cli.tx_app_space, phdr, 2, ping_pl[..], ppkt));
            assert(net::dst_udp_send(world, uid, net::DstDir.AToB, ppkt[..]));
            next_pn += 1;
            let _ = net::dst_run_until(world, world.now_ns + 65 * NS_PER_MS);
            loop {
                let n, _, src_port, ok_r = net::dst_udp_recv(world, uid, net::DstDir.AToB, dgram_buf[..]);
                if !ok_r { break; }
                var ack_p = quic::AckFrame { .. };
                let pr = quic::process_datagram(q_srv, dgram_buf[..n], world.now_ns / 1000, ack_p);
                if pr.handled && src_port != initial_cli_port {
                    saw_nat_rebind = true;
                }
            }
        }
    }
    assert(saw_nat_rebind);
    assert(srv_reasm[..h3_frame_bytes.len] == h3_frame_bytes[..]);

    // Decode the reliably transferred HTTP/3 HEADERS + DATA frames via QPACK on server.
    var f_off: i64 = 0;
    let f_type1, ok_ft1 = quic::decode_varint_cursor(srv_reasm[..hdr_frame_len], f_off);
    let f_len1, ok_fl1 = quic::decode_varint_cursor(srv_reasm[..hdr_frame_len], f_off);
    assert(ok_ft1 && ok_fl1 && f_type1 == rfc::H3_FRAME_HEADERS);
    var srv_pseudo = http3::PseudoHeaders { .. };
    var srv_hdrs = http::HeaderMap { .. };
    let qerr = wire::decode_h3_headers_to_map(
        h3_srv.qpack_dec_table,
        0,
        srv_reasm[f_off..f_off + (f_len1 as i64)],
        srv_pseudo,
        srv_hdrs,
    );
    assert(qerr == http3::QpackError.None);
    assert(srv_pseudo.method[..] == "POST" && srv_pseudo.path[..] == "/quic-test");
    assert(http::get_header(srv_hdrs, "x-quic-dst") == "lossy");

    var d_off: i64 = hdr_frame_len;
    let f_type2, ok_ft2 = quic::decode_varint_cursor(srv_reasm[..h3_frame_bytes.len], d_off);
    let f_len2, ok_fl2 = quic::decode_varint_cursor(srv_reasm[..h3_frame_bytes.len], d_off);
    assert(ok_ft2 && ok_fl2 && f_type2 == rfc::H3_FRAME_DATA);
    assert(srv_reasm[d_off..d_off + (f_len2 as i64)] == "QUIC_H3_DST_PAYLOAD_OK");
}

// ---- Scenario 5: Clock Jump/Skew & Deterministic Entropy Plumbing ---------

fn run_clock_and_entropy_dst_scenario(world: net::DstWorld&, ep_c: u16, ep_s: u16) -> u64 {
    // Give server endpoint -600s skew and client endpoint +600s skew, then restore.
    assert(net::dst_set_endpoint_skew(world, ep_c, 600 * (NS_PER_SEC as i64)));
    assert(net::dst_set_endpoint_skew(world, ep_s, -600 * (NS_PER_SEC as i64)));
    let c_sec = net::dst_endpoint_now_sec(world, ep_c);
    let s_sec = net::dst_endpoint_now_sec(world, ep_s);
    assert(c_sec == s_sec + 1200);

    // 5A: JWT exp/nbf validation under endpoint clock skew and 2-hour virtual clock jump.
    let base_sec = net::dst_endpoint_now_sec(world, ep_c);
    let jwt_secret = "0123456789abcdef0123456789abcdef";
    let jhdr = auth::JwtHeader { alg: auth::JwtAlg.HS256, .. };
    var jclm = auth::JwtClaims {
        exp: base_sec + 1800,
        nbf: base_sec - 60,
        iat: base_sec - 60,
        ..
    };
    assert(jclm.sub.try_set("dst-user"));
    var jwt_tok: u8[..2048] = [];
    assert(auth::sign_jwt_hmac(jhdr, jclm, jwt_secret, jwt_tok));

    var opts = auth::JwtValidationOptions {
        expected_alg:   auth::JwtAlg.HS256,
        leeway_seconds: 0,
        ..
    };
    var out_h = auth::JwtHeader { .. };
    var out_c = auth::JwtClaims { .. };
    // Client endpoint is inside [nbf, exp] -> Valid!
    assert(auth::verify_jwt_hmac(jwt_tok[..], jwt_secret, opts, base_sec, out_h, out_c) == auth::JwtError.None);
    // Skewed-behind server endpoint is before nbf -> TokenNotYetValid!
    assert(auth::verify_jwt_hmac(jwt_tok[..], jwt_secret, opts, s_sec, out_h, out_c) == auth::JwtError.TokenNotYetValid);

    // 5B: HTTP RFC 9111 Cache Freshness before & after instant clock jump.
    let t0_sec = net::dst_endpoint_now_sec(world, ep_c);
    let t0_mono = core::monotonic_now().as_nanos();
    let resp_cc = http::CacheControl { flags: http::CC_HAS_MAX_AGE, max_age: 300, .. };
    let req_cc = http::CacheControl { .. };
    let cache_hdrs = http::HeaderMap { .. };
    let ts_fresh = http::with_monotonic(
        http::new_cache_timestamps(t0_sec, t0_sec, t0_sec),
        t0_mono, t0_mono, t0_mono,
    );
    assert(http::evaluate_freshness(resp_cc, req_cc, cache_hdrs, ts_fresh).is_fresh);

    // 5C: client::RateLimiter using zero-arg allow() routed through core::sim_now_ns()!
    var rl = client::new_rate_limiter(1.0, 2);
    assert(client::allow(rl));
    assert(client::allow(rl));
    assert(!client::allow(rl)); // Burst exhausted at t=0

    // 5D: core::Stopwatch, core::Deadline, and core::sleep (virtual instant sleep!).
    let sw = core::stopwatch();
    let dl = core::deadline_after(core::Duration { nanos: 60 * (NS_PER_SEC as i64) });
    assert(!core::is_expired(dl));

    // Jump virtual clock by 2 hours instantly + core::sleep(2 hours) -> 4 virtual hours in < 1 ms!
    net::dst_jump_clock(world, 2 * NS_PER_HOUR);
    core::sleep(core::Duration { nanos: (2 * NS_PER_HOUR) as i64 });
    assert(core::is_expired(dl));
    assert(core::elapsed(sw).nanos >= (4 * NS_PER_HOUR) as i64);
    assert(client::allow(rl)); // Replenished after virtual time jump!

    // JWT is now Expired and HTTP cache entry is now Stale!
    let t_after = net::dst_endpoint_now_sec(world, ep_c);
    assert(auth::verify_jwt_hmac(jwt_tok[..], jwt_secret, opts, t_after, out_h, out_c) == auth::JwtError.TokenExpired);
    let t_after_mono = core::monotonic_now().as_nanos();
    let ts_stale = http::with_monotonic(
        http::new_cache_timestamps(t0_sec, t0_sec, t_after),
        t0_mono, t0_mono, t_after_mono,
    );
    assert(!http::evaluate_freshness(resp_cc, req_cc, cache_hdrs, ts_stale).is_fresh);

    // 5E: Deterministic entropy plumbing across DPoP, PKCE, CryptoJar, GCRA jitter, WebSocket, Multipart!
    let dpop_key: u8[32] = [0x37; 32];
    var dpop_buf: u8[..2048] = [];
    assert(auth::create_dpop_proof(dpop_key[..], "POST", "https://api.dst.local/token", "", "", t_after, "", dpop_buf));

    var pkce_buf: u8[..128] = [];
    assert(auth::generate_code_verifier(pkce_buf));

    var ks = security::KeyStore { max_age_sec: 300, .. };
    var kslot = security::KeySlot { key_id: 1, .. };
    for i in 32 {
        kslot.master_key[i] = (0x50 + i) as u8;
        kslot.encryption_key[i] = (0x70 + i) as u8;
        kslot.signing_key[i] = (0x90 + i) as u8;
    }
    assert(security::add_key(ks, kslot));
    let jar = security::new_private_jar(ks, false);
    var sealed_cookie: u8[..512] = [];
    assert(security::seal(jar, "sid", "session_dst_42", t_after, 7, sealed_cookie));
    var opened_cookie: u8[..256] = [];
    assert(security::open(jar, "sid", sealed_cookie[..], t_after, opened_cookie));
    assert(opened_cookie[..] == "session_dst_42");
    // Cookie expires after jumping 10 minutes (> max_age_sec = 300).
    net::dst_jump_clock(world, 600 * NS_PER_SEC);
    var exp_cookie: u8[..256] = [];
    assert(!security::open(jar, "sid", sealed_cookie[..], net::dst_endpoint_now_sec(world, ep_c), exp_cookie));

    // Probabilistic GCRA + jitter + WebSocket mask key + Multipart boundary.
    let quota = security::new_gcra_quota(10, core::SECOND, 2);
    var pgcra = security::new_probabilistic_gcra(quota, 5);
    let _ = security::check_rate_limit(pgcra, 1, world.now_ns);
    var jdec = security::GcraDecision { allowed: false, retry_after_ns: 1000, wait_ns: 1000, .. };
    var prng_s: u64 = 0;
    let gcra_jit = security::GcraJitter { min_ns: 10, max_ns: 5000 };
    security::apply_jitter_to_decision(jdec, gcra_jit, prng_s);

    var ws_sess = realtime::WebSocketSession { is_client: true, .. };
    let ws_mask, ok_ws_mask = realtime_internal::ws_next_mask_key(ws_sess);
    assert(ok_ws_mask);

    var mw, ok_mw = http::new_multipart_writer();
    assert(ok_mw && mw.boundary.len > 16);

    // Combine all deterministic entropy outputs into a single digest (note: multipart uses global counter).
    var ent_h = core::wyhash64(dpop_buf[..], 0xE170);
    ent_h = core::hash_combine_u64(ent_h, core::wyhash64(pkce_buf[..], ent_h));
    ent_h = core::hash_combine_u64(ent_h, core::wyhash64(sealed_cookie[..], ent_h));
    ent_h = core::hash_combine_u64(ent_h, core::wyhash64(ws_mask[..], ent_h));
    ent_h = core::hash_combine_u64(ent_h, pgcra.rng_state);
    ent_h = core::hash_combine_u64(ent_h, jdec.retry_after_ns);
    return ent_h;
}

// ---- Combined Multi-Protocol Full-Stack DST Run for Any `seed: u64` -------

fn run_full_stack_dst(seed: u64) -> FullStackRunSummary {
    var world = net::DstWorld { .. };
    net::dst_init(world, seed, SIM_BASE_UNIX_NS);
    defer net::dst_shutdown(world);

    let ep_c, ok_c = net::dst_add_endpoint(world, 0x0A000001, 41000, 0);
    let ep_s, ok_s = net::dst_add_endpoint(world, 0x0A000002, 443, 0);
    assert(ok_c && ok_s);

    run_http1_dst_scenario(world, ep_c, ep_s);
    run_http2_dst_scenario(world, ep_c, ep_s);
    let tls_tr_h, tls_ct_h = run_tls13_dst_scenario(world, ep_c, ep_s);
    run_quic_h3_dst_scenario(world, ep_c, ep_s);
    let ent_h = run_clock_and_entropy_dst_scenario(world, ep_c, ep_s);

    // Simulate an additional 10 virtual hours via instant clock jump to verify fast-forward scale.
    net::dst_jump_clock(world, 10 * NS_PER_HOUR);

    return FullStackRunSummary {
        trace_digest:       world.trace_digest,
        events_scheduled:   world.stats.events_scheduled,
        events_dispatched:  world.stats.events_dispatched,
        tcp_segments_deliv: world.stats.tcp_segments_delivered,
        tcp_bytes_deliv:    world.stats.tcp_bytes_delivered,
        tcp_rsts:           world.stats.tcp_rsts_injected,
        tcp_fins:           world.stats.tcp_fins_delivered,
        tcp_stalls:         world.stats.tcp_backpressure_stalls,
        udp_sent:           world.stats.udp_packets_sent,
        udp_deliv:          world.stats.udp_packets_delivered,
        udp_dropped:        world.stats.udp_packets_dropped,
        udp_reordered:      world.stats.udp_packets_reordered,
        udp_duplicated:     world.stats.udp_packets_duplicated,
        udp_corrupted:      world.stats.udp_packets_corrupted,
        udp_nat_rebinds:    world.stats.udp_nat_rebinds,
        timers_fired:       world.stats.timers_fired,
        clock_jumps:        world.stats.clock_jumps,
        virtual_skipped_ns: world.stats.virtual_time_skipped_ns,
        tls_transcript_h64: tls_tr_h,
        tls_ct_h64:         tls_ct_h,
        entropy_h64:        ent_h,
    };
}

// ---- Adversarial Chaos Profile Stress Test --------------------------------

fn run_adversarial_chaos_profile() {
    var world = net::DstWorld { .. };
    net::dst_init(world, 0xC0FFEE9911, SIM_BASE_UNIX_NS);
    defer net::dst_shutdown(world);

    let ep_a, ok_a = net::dst_add_endpoint(world, 0x0A010001, 50000, 0);
    let ep_b, ok_b = net::dst_add_endpoint(world, 0x0A010002, 8443, 0);
    assert(ok_a && ok_b);

    let chaos = net::dst_fault_profile(net::DstFaultProfile.AdversarialChaos);
    let tid, ok_t = net::dst_open_tcp_link(world, ep_a, ep_b, chaos);
    let uid, ok_u = net::dst_open_udp_link(world, ep_a, ep_b, chaos);
    assert(ok_t && ok_u);

    var payload: u8[256] = [0x58; 256];
    let _, _ = net::dst_tcp_send(world, tid, net::DstDir.AToB, payload[..]);
    for i in 40 {
        payload[0] = (i & 0xFF) as u8;
        assert(net::dst_udp_send(world, uid, net::DstDir.AToB, payload[..64]));
    }
    let _ = net::dst_run_until(world, world.now_ns + 10 * NS_PER_SEC);
    assert(world.stats.udp_packets_dropped > 0);
    assert(world.stats.udp_packets_reordered > 0);
    assert(world.stats.udp_packets_duplicated > 0);
    assert(world.stats.udp_packets_corrupted > 0);
    assert(world.stats.udp_nat_rebinds > 0);
}

// CHECK: DST_SCENARIO_BIT_FOR_BIT_DETERMINISM: OK
// CHECK: DST_16_SEEDS_UNIQUE_DIGESTS: OK
// CHECK: DST_ADVERSARIAL_CHAOS_FAULTS: OK
// CHECK: DST_SIM_CLEANUP_INACTIVE: OK
fn main() {
    let wall_start = clock_ns();

    // 1. Bit-for-bit determinism proof: run the exact same seed twice and compare every metric & digest.
    let rep_seed: u64 = 0xDEADBEEFCAFE0042;
    let run_a = run_full_stack_dst(rep_seed);
    let run_b = run_full_stack_dst(rep_seed);
    assert(summaries_equal(run_a, run_b));
    assert(run_a.events_dispatched > 100);
    assert(run_a.tcp_rsts >= 3);
    assert(run_a.tcp_stalls >= 2);
    assert(run_a.udp_sent >= 4);
    assert(run_a.udp_nat_rebinds >= 1);
    assert(run_a.clock_jumps >= 3);
    print("DST_SCENARIO_BIT_FOR_BIT_DETERMINISM: OK");

    // 2. Multi-seed sweep across 16 distinct seeds (1..16) -> all pass invariants & produce unique digests.
    var digests:          u64[16] = [0; 16];
    var total_virtual_ns: u64     = run_a.virtual_skipped_ns;
    var total_events:     u64     = run_a.events_dispatched;
    for s in 16 {
        let seed_val = (s + 1) as u64;
        let res = run_full_stack_dst(seed_val);
        digests[s] = res.trace_digest;
        total_virtual_ns = core::add_sat_u64(total_virtual_ns, res.virtual_skipped_ns);
        total_events = core::add_sat_u64(total_events, res.events_dispatched);
        for prev in s {
            assert(digests[prev] != digests[s]);
        }
    }
    print("DST_16_SEEDS_UNIQUE_DIGESTS: OK");

    // 3. Adversarial chaos profile (drop + reorder + dup + bit-flip corruption + NAT rebind + RST).
    run_adversarial_chaos_profile();
    print("DST_ADVERSARIAL_CHAOS_FAULTS: OK");

    // 4. Verify simulation mode cleanly deactivates after dst_shutdown().
    assert(!core::sim_clock_is_active());
    assert(!core::sim_rng_is_active());
    assert(core::monotonic_now().as_nanos() > 0);
    print("DST_SIM_CLEANUP_INACTIVE: OK");

    let wall_elapsed_ms = (clock_ns() - wall_start) / 1000000;
    let virtual_hours = total_virtual_ns / NS_PER_HOUR;
    print(
        "DST_METRICS seeds=17 events=", total_events,
        " virtual_hours=", virtual_hours,
        " wall_ms=", wall_elapsed_ms,
        " digest_seed_cafe=", run_a.trace_digest,
    );
}
