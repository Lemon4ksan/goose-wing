// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Showcase B: Kernel-Bypass & Registered-Buffer I/O Accelerator Benchmark
// 1. Live Windows Registered I/O (ReactorAccelMode.Rio) vs WSAPoll (ReactorAccelMode.PollFallback)
// 2. L2 HTTP/3 & QUIC datapath: AF_XDP UMEM vs DPDK burst ring vs OS UDP sockets (serve_h3_l2)
import std;
import core from "..";
import wing from "..";

var g_drv_app: server::HttpServer = server::HttpServer { .. };

fn format_x100<B>(val: i64, div_scale: i64, out: B&) {
    let clamped = max(val, 0);
    let scaled = core::div_euclid_i64(clamped, div_scale);
    let whole = core::div_euclid_i64(scaled, 100) as u64;
    let frac = core::rem_euclid_i64(scaled, 100) as u64;
    whole.format_u64_dec(out);
    let _ = out.try_push('.');
    if frac < 10 {
        let _ = out.try_push('0');
    }
    frac.format_u64_dec(out);
}

fn count_substr(hay: const u8[:], needle: const u8[:]) -> i64 {
    var cnt: i64 = 0;
    var pos: i64 = 0;
    while pos + needle.len <= hay.len {
        let hit = core::find(hay[pos..], needle);
        if hit < 0 { break; }
        cnt += 1;
        pos += hit + needle.len;
    }
    return cnt;
}

fn run_rio_server(port: u16, accel_str: const u8[:], max_conns: i64) {
    server::init_http_server_inplace(g_drv_app, "127.0.0.1", port);
    g_drv_app.pipeline.enable_csrf_guard = false;
    g_drv_app.pipeline.enable_cors = false;
    g_drv_app.pipeline.enable_rate_limiter = false;
    g_drv_app.pipeline.enable_slowloris_timer = false;
    g_drv_app.accel_mode = if accel_str == "rio" {
        net::ReactorAccelMode.Rio
    } else {
        net::ReactorAccelMode.PollFallback
    };
    assert(server::add_static_route(g_drv_app.pipeline.router, "GET", "/ping", "text/plain", "PONG"));

    let lfd = if accel_str == "rio" {
        server::reactor_listen_accelerated(g_drv_app, 1024)
    } else {
        net::tcp_listen("127.0.0.1", port, 1024)
    };
    guard lfd > 0 else {
        print("FATAL: failed to listen on port ", port);
        return;
    }
    print("SERVER_READY port=", port, " accel=", accel_str);
    let _ = server::serve_reactor(g_drv_app, lfd, max_conns);
    net::tcp_close(lfd);
}

fn send_recv_batch(fd: i64, wire: const u8[:], pipeline: i64, rx_buf: u8[65536]&) -> bool {
    var sent: i64 = 0;
    while sent < wire.len {
        let n = net::tcp_send(fd, wire[sent..]);
        if n <= 0 { return false; }
        sent += n;
    }
    var got_pongs: i64 = 0;
    while got_pongs < pipeline {
        let nr = net::tcp_recv_slice(fd, rx_buf[..]);
        if nr > 0 {
            got_pongs += count_substr(rx_buf[..nr], "PONG");
        } else if nr == 0 {
            return false;
        }
    }
    return true;
}

fn run_http1_client(port: u16, batches: i64, pipeline: i64) {
    let fd = net::tcp_connect("127.0.0.1", port);
    guard fd > 0 else {
        print("FATAL: client failed to connect");
        return;
    }
    defer net::tcp_close(fd);
    net::tcp_set_nodelay(fd, true);

    var req_wire: u8[..4096] = [];
    let unit = "GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n";
    for _ in pipeline {
        guard req_wire.try_append(unit) else { break; }
    }
    var rx_buf: u8[65536] = [0; 65536];

    let warmup = min(max(batches >> 3, 16), 200);
    for _ in warmup {
        assert(send_recv_batch(fd, req_wire[..], pipeline, rx_buf));
    }

    var latencies: i64[>..] = [];
    let watch = core::stopwatch();
    for _ in batches {
        let t0 = core::stopwatch();
        assert(send_recv_batch(fd, req_wire[..], pipeline, rx_buf));
        latencies.push(core::elapsed(t0).as_nanos());
    }
    let elapsed_ns = max(core::elapsed(watch).as_nanos(), 1);
    sort(latencies[..]);

    let n = latencies.len;
    let total_reqs = core::mul_sat_i64(n, pipeline);
    let rps = core::div_euclid_i64(
        core::mul_sat_u64(total_reqs as u64, 1000000000) as i64,
        elapsed_ns,
    );
    var p50_buf:  u8[..32] = [];
    var p99_buf:  u8[..32] = [];
    var p999_buf: u8[..32] = [];
    var el_buf:   u8[..32] = [];
    format_x100(latencies[(n * 50) / 100], 10000, p50_buf);
    format_x100(latencies[(n * 99) / 100], 10000, p99_buf);
    format_x100(latencies[(n * 999) / 1000], 10000, p999_buf);
    format_x100(elapsed_ns, 10000, el_buf);

    print(
        "H1_ACCEL_RESULT batches=", n,
        " requests=", total_reqs,
        " pipeline=", pipeline,
        " elapsed_ms=", el_buf[..],
        " rps=", rps,
        " p50_ms=", p50_buf[..],
        " p99_ms=", p99_buf[..],
        " p999_ms=", p999_buf[..],
    );
}

fn emit_l2_metrics(name: const u8[:], packets: i64, elapsed_ns: i64, lat_ns: i64[>..]&) {
    sort(lat_ns[..]);
    let n = lat_ns.len;
    let pps = core::div_euclid_i64(
        core::mul_sat_u64(packets as u64, 1000000000) as i64,
        max(elapsed_ns, 1),
    );
    let ns_per_pkt = core::div_euclid_i64(elapsed_ns, max(packets, 1));
    var p50_us: u8[..32] = [];
    var p99_us: u8[..32] = [];
    format_x100(lat_ns[(n * 50) / 100], 10, p50_us);
    format_x100(lat_ns[(n * 99) / 100], 10, p99_us);
    print(
        "L2_BENCH backend=", name,
        " packets=", packets,
        " elapsed_ns=", elapsed_ns,
        " pps=", pps,
        " ns_per_pkt=", ns_per_pkt,
        " p50_us=", p50_us[..],
        " p99_us=", p99_us[..],
    );
}

fn bench_af_xdp_l2(
    h3_ep:    server::H3ServerEndpoint&,
    cfg_xdp:  const server::H3L2Config&,
    l2_frame: const u8[:],
    iters:    i64,
) {
    var xsk, ok_xsk = net_internal::af_xdp_open_loopback(64, 2048);
    assert(ok_xsk);
    defer net_internal::af_xdp_close(xsk);

    let batch: i64 = 16;
    let rounds = max(iters / batch, 1);

    for _ in 16 {
        for k in batch {
            let addr = (k as u64) * 2048;
            assert(net_internal::af_xdp_umem_write(xsk, addr, l2_frame));
            assert(net_internal::af_xdp_inject_loopback_rx(xsk, addr, l2_frame.len as u32));
        }
        assert(server::serve_h3_l2(g_drv_app, h3_ep, cfg_xdp, xsk, batch) == batch);
        loop {
            let _, ok_c = net_internal::af_xdp_complete_pop(xsk);
            if !ok_c { break; }
        }
    }

    var lats: i64[>..] = [];
    let watch = core::stopwatch();
    for _ in rounds {
        let t0 = core::stopwatch();
        for k in batch {
            let addr = (k as u64) * 2048;
            let _ = net_internal::af_xdp_umem_write(xsk, addr, l2_frame);
            let _ = net_internal::af_xdp_inject_loopback_rx(xsk, addr, l2_frame.len as u32);
        }
        let served = server::serve_h3_l2(g_drv_app, h3_ep, cfg_xdp, xsk, batch);
        assert(served == batch);
        loop {
            let _, ok_c = net_internal::af_xdp_complete_pop(xsk);
            if !ok_c { break; }
        }
        lats.push(core::div_euclid_i64(core::elapsed(t0).as_nanos(), batch));
    }
    emit_l2_metrics("af_xdp", rounds * batch, core::elapsed(watch).as_nanos(), lats);
}

fn bench_dpdk_l2(
    h3_ep:    server::H3ServerEndpoint&,
    cfg_dpdk: const server::H3L2Config&,
    xsk:      net_internal::AfXdpSocket&,
    l2_frame: const u8[:],
    iters:    i64,
) {
    var dpdk_dev = net_internal::new_dpdk_device(0);
    let dpdk_cfg = net_internal::DpdkPortConfig { port_id: 0, rx_queues: 1, tx_queues: 1, .. };
    assert(net_internal::dpdk_init_port(dpdk_dev, dpdk_cfg) == 0);
    assert(net_internal::dpdk_start_port(dpdk_dev) == 0);
    defer net_internal::dpdk_stop_port(dpdk_dev);

    let batch: i64 = 16;
    let rounds = max(iters / batch, 1);
    var replies: u8[..2048][..32] = [];

    for _ in 16 {
        for _ in batch {
            assert(net_internal::dpdk_tx_packet_push(0, 0, l2_frame));
        }
        assert(server::serve_h3_l2(g_drv_app, h3_ep, cfg_dpdk, xsk, batch) == batch);
        let _ = net_internal::dpdk_rx_burst_read(0, 0, replies);
    }

    var lats: i64[>..] = [];
    let watch = core::stopwatch();
    for _ in rounds {
        let t0 = core::stopwatch();
        for _ in batch {
            let _ = net_internal::dpdk_tx_packet_push(0, 0, l2_frame);
        }
        let served = server::serve_h3_l2(g_drv_app, h3_ep, cfg_dpdk, xsk, batch);
        assert(served == batch);
        let _ = net_internal::dpdk_rx_burst_read(0, 0, replies);
        lats.push(core::div_euclid_i64(core::elapsed(t0).as_nanos(), batch));
    }
    emit_l2_metrics("dpdk", rounds * batch, core::elapsed(watch).as_nanos(), lats);
}

fn bench_udp_fallback_l2(h3_ep: server::H3ServerEndpoint&, xsk: net_internal::AfXdpSocket&, iters: i64) {
    let udp_srv = net::udp_bind("127.0.0.1", 0);
    let udp_cli = net::udp_bind("127.0.0.1", 0);
    assert(udp_srv > 0 && udp_cli > 0);
    defer net::tcp_close(udp_srv);
    defer net::tcp_close(udp_cli);
    let udp_port = net::tcp_getsockname_port(udp_srv);

    let h3_settings = fingerprint::H3Settings { .. };
    var h3_cli = http3::new_client_connection(h3_settings);
    let sid, ok_sid = http3::open_request_stream(h3_cli);
    assert(ok_sid);
    var extra = http::HeaderMap { .. };
    var req_wire: u8[..1024] = [];
    assert(http3::send_request_headers(h3_cli, sid, "GET", "https", "127.0.0.1", "/", extra, true, req_wire));

    let cfg_fb = server::H3L2Config { backend: server::H3L2Backend.UdpFallback, udp_fd: udp_srv, .. };
    var rx_batch = net::UdpBatchQueue { .. };
    let batch: i64 = 16;
    let rounds = max(iters / batch, 1);

    for _ in 16 {
        for _ in batch {
            assert(net_internal::native_udp_sendto(udp_cli, req_wire[..], "127.0.0.1", udp_port) > 0);
        }
        assert(server::serve_h3_l2(g_drv_app, h3_ep, cfg_fb, xsk, batch) == batch);
        var got_r: i32 = 0;
        while got_r < batch {
            let n_got, ok_g = net::batch_recv_messages(rx_batch, udp_cli as i32);
            if !ok_g || n_got <= 0 { break; }
            got_r += n_got;
        }
    }

    var lats: i64[>..] = [];
    let watch = core::stopwatch();
    for _ in rounds {
        let t0 = core::stopwatch();
        for _ in batch {
            let _ = net_internal::native_udp_sendto(udp_cli, req_wire[..], "127.0.0.1", udp_port);
        }
        let served = server::serve_h3_l2(g_drv_app, h3_ep, cfg_fb, xsk, batch);
        assert(served == batch);
        var got_r: i32 = 0;
        while got_r < batch {
            let n_got, ok_g = net::batch_recv_messages(rx_batch, udp_cli as i32);
            if !ok_g || n_got <= 0 { break; }
            got_r += n_got;
        }
        lats.push(core::div_euclid_i64(core::elapsed(t0).as_nanos(), batch));
    }
    emit_l2_metrics("udp_fallback", rounds * batch, core::elapsed(watch).as_nanos(), lats);
}

fn run_l2_bench(iters: i64) {
    server::init_http_server_inplace(g_drv_app, "127.0.0.1", 0);
    g_drv_app.pipeline.enable_csrf_guard = false;
    g_drv_app.pipeline.enable_cors = false;
    g_drv_app.pipeline.enable_rate_limiter = false;
    g_drv_app.pipeline.enable_slowloris_timer = false;
    server::add_static_get_route(g_drv_app, "/", "text/plain", "L2_OK");

    let cli_ep = net_internal::L2UdpEndpoint {
        mac:     [0x02, 0, 0, 0, 0, 0x11],
        ip:      [192, 168, 1, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        is_ipv6: false,
        port:    55000,
    };
    let srv_ep = net_internal::L2UdpEndpoint {
        mac:     [0x02, 0, 0, 0, 0, 0x22],
        ip:      [192, 168, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        is_ipv6: false,
        port:    443,
    };
    var l2_frame: u8[..2048] = [];
    assert(net_internal::encode_l2_udp_frame(cli_ep, srv_ep, "\x04\x00", 2, l2_frame));

    var h3_ep = server::new_h3_server_endpoint();
    var dummy_xsk = net_internal::new_af_xdp_socket();
    let cfg_xdp = server::H3L2Config { backend: server::H3L2Backend.AfXdp, local_ep: srv_ep, .. };
    let cfg_dpdk = server::H3L2Config {
        backend:       server::H3L2Backend.Dpdk,
        local_ep:      srv_ep,
        dpdk_port_id:  0,
        dpdk_queue_id: 0,
        ..
    };

    bench_af_xdp_l2(h3_ep, cfg_xdp, l2_frame[..], iters);
    bench_dpdk_l2(h3_ep, cfg_dpdk, dummy_xsk, l2_frame[..], iters);
    bench_udp_fallback_l2(h3_ep, dummy_xsk, iters);
}

fn main() {
    let argv = args();
    var mode:      const u8[:] = "";
    var accel:     const u8[:] = "rio";
    var port:      u16         = 8081;
    var iters:     i64         = 4000;
    var pipeline:  i64         = 1;
    var max_conns: i64         = 0;

    var i: u64 = 1;
    let argc = argv.len as u64;
    while i < argc {
        let arg = argv[i];
        let next_i = core::add_sat_u64(i, 1);
        if arg == "--rio-server" && next_i < argc {
            mode = "rio-server";
            let p, ok = argv[next_i].parse_u32_dec();
            if ok && p > 0 && p <= 65535 {
                port = p as u16;
                i = next_i;
            }
        } else if arg == "--http1-client" && next_i < argc {
            mode = "http1-client";
            let p, ok = argv[next_i].parse_u32_dec();
            if ok && p > 0 && p <= 65535 {
                port = p as u16;
                i = next_i;
            }
        } else if arg == "--l2-bench" {
            mode = "l2-bench";
        } else if arg == "--accel" && next_i < argc {
            accel = argv[next_i];
            i = next_i;
        } else if arg == "--iters" && next_i < argc {
            let v, ok = argv[next_i].parse_i64_dec();
            if ok && v > 0 {
                iters = v;
                i = next_i;
            }
        } else if arg == "--pipeline" && next_i < argc {
            let v, ok = argv[next_i].parse_i64_dec();
            if ok && v > 0 {
                pipeline = v;
                i = next_i;
            }
        } else if arg == "--conns" && next_i < argc {
            let v, ok = argv[next_i].parse_i64_dec();
            if ok && v > 0 {
                max_conns = v;
                i = next_i;
            }
        }
        i = core::add_sat_u64(i, 1);
    }

    if mode == "rio-server" {
        run_rio_server(port, accel, max_conns);
    } else if mode == "http1-client" {
        run_http1_client(port, iters, pipeline);
    } else if mode == "l2-bench" {
        run_l2_bench(iters);
    } else {
        print("Usage: driver_accel_benchmark --rio-server PORT --accel rio|poll");
        print("       driver_accel_benchmark --http1-client PORT --iters N --pipeline P");
        print("       driver_accel_benchmark --l2-bench --iters N");
    }
}
