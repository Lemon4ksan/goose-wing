// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Native Goose HTTP/3 & Alt-Svc E2E Verification Client.
// Exercises client::Client Alt-Svc h3 promotion, live UDP HTTP/3 framing,
// and 2 MiB QUIC flow-controlled streaming (`MAX_DATA` / `MAX_STREAM_DATA`)
// with SHA-256 verification against tools/http3/server.goose.
import std;
import wing from "../..";

const STREAM_EXPECT_BYTES: u64 = 2 * 1024 * 1024;

var g_h3_cli_qpack: http3::QpackTable = http3::new_qpack_table(0, 0, 0);

struct H3StreamReceiver {
    headers_ok:   bool            = false,
    data_bytes:   u64             = 0,
    last_seq:     i64             = -1,
    dups_ignored: u64             = 0,
    credits_sent: u64             = 0,
    hasher:       core::Sha256Ctx = core::Sha256Ctx { .. },
    buf:          u8[..32768]     = [],
}

fn make_h3_client(port: u16, out_origin: u8[..128]&) -> client::Client {
    var base: u8[..128] = [];
    let _ = base.try_append("http://127.0.0.1:");
    core::format_u64_dec(port, base);

    out_origin.clear();
    let _ = out_origin.try_append("127.0.0.1:");
    core::format_u64_dec(port, out_origin);

    var s = client::new_client(client::Config {
        base_url:   base[..],
        timeout_ms: 3000,
        ..
    });
    s.ssrf_guard.enabled = false;
    s.enable_altsvc = true;
    s.enable_protocol_racing = true;

    let now_sec = div_euclid(client::effective_clock_us(s), 1000000);
    var altsvc_hdr: u8[..128] = [];
    http::format_altsvc_header(altsvc_hdr, "h3", port, 86400, true);
    http::update(s.altsvc, out_origin[..], altsvc_hdr[..], now_sec);
    return s;
}

fn run_h3_get_root(s: client::Client&, origin: const u8[:]) -> bool {
    let resp, err = client::get(s, "/");
    guard http::ok(err) && resp.status_code == 200 else { return false; }
    guard resp.protocol[..] == "HTTP/3" else { return false; }
    guard resp.body[..] == "Hello from goose-wing HTTP/3!" else { return false; }
    let now_sec = div_euclid(client::effective_clock_us(s), 1000000);
    return http::failed_attempts(s.altsvc, origin) == 0 && !http::is_broken(s.altsvc, origin, now_sec);
}

fn run_h3_get_query_json(s: client::Client&) -> bool {
    let resp, err = client::get(s, "/api/info?client=goose-wing&v=3");
    guard http::ok(err) && resp.status_code == 200 else { return false; }
    guard resp.protocol[..] == "HTTP/3" else { return false; }
    guard resp.header("content-type") == "application/json" else { return false; }
    return resp.body[..] == "{\"protocol\":\"h3\",\"engine\":\"goose-wing\"}";
}

fn run_h3_post_data(s: client::Client&) -> bool {
    let resp, err = client::post(s, "/echo") { req =>
        http::text(req, "NativeH3PostBody_2026");
    };
    guard http::ok(err) && resp.status_code == 200 else { return false; }
    guard resp.protocol[..] == "HTTP/3" else { return false; }
    return resp.body[..] == "H3_POST_ACK";
}

fn consume_h3_stream_wire(r: H3StreamReceiver&, incoming: const u8[:]) -> bool {
    guard r.buf.try_append(incoming) else { return false; }
    while r.buf.len > 0 {
        let fhdr, ok_h = http3::parse_frame_header(r.buf[..], 0);
        if !ok_h { break; }
        let total = core::add_sat_i64(fhdr.header_len as i64, fhdr.payload_len as i64);
        if r.buf.len < total { break; }
        let payload = r.buf[(fhdr.header_len as i64)..total];
        if fhdr.frame_type == rfc::H3_FRAME_HEADERS {
            var pseudo = http3::PseudoHeaders { .. };
            var hmap = http::HeaderMap { .. };
            let qerr = http3::decode_qpack_to_map(g_h3_cli_qpack, payload, pseudo, hmap, 16384);
            guard qerr == http3::QpackError.None && pseudo.status == 200 else { return false; }
            r.headers_ok = true;
        } else if fhdr.frame_type == rfc::H3_FRAME_DATA {
            core::sha256_update(r.hasher, payload);
            r.data_bytes = core::add_sat_u64(r.data_bytes, payload.len as u64);
        }
        r.buf.compact_wire_buffer(total);
    }
    return true;
}

fn send_quic_window_replenish(
    sock:     i64,
    port:     u16,
    win:      server::RequestStreamWindow&,
    step_inc: u64,
) -> bool {
    let rep = server::request_window_on_consume(win, step_inc);
    var wire: u8[..64] = [];
    if rep.should_update_conn || rep.should_update_stream {
        guard server::request_window_encode_quic_updates(win, rep, wire) else { return false; }
    } else {
        let next_conn = core::add_sat_u64(win.advertised_conn_max, 65536);
        let next_strm = core::add_sat_u64(win.advertised_stream_max, 65536);
        win.advertised_conn_max = next_conn;
        win.advertised_stream_max = next_strm;
        let _ = quic::encode_varint(rfc::QUIC_FRAME_MAX_DATA, wire);
        let _ = quic::encode_varint(next_conn, wire);
        let _ = quic::encode_varint(rfc::QUIC_FRAME_MAX_STREAM_DATA, wire);
        let _ = quic::encode_varint(4, wire);
        let _ = quic::encode_varint(next_strm, wire);
    }
    return net::udp_sendto_dual(sock, wire[..], "127.0.0.1", port) > 0;
}

enum StreamStepState {
    Continue,
    DoneOk,
    DoneFail,
}

fn handle_stream_datagram(
    sock:     i64,
    port:     u16,
    pkt:      const u8[:],
    rx_state: H3StreamReceiver&,
    win:      server::RequestStreamWindow&,
    bp_out:   u64&,
) -> StreamStepState {
    if pkt.len >= 8 && pkt[..4] == "H3ST" {
        let seq = core::read_be_u32(pkt, 4) as i64;
        if seq <= rx_state.last_seq {
            rx_state.dups_ignored = core::add_sat_u64(rx_state.dups_ignored, 1);
            return StreamStepState.Continue;
        }
        rx_state.last_seq = seq;
        let payload = pkt[8..];
        let _ = server::request_window_on_ingress(win, payload.len as u64);
        guard consume_h3_stream_wire(rx_state, payload) else { return StreamStepState.DoneFail; }
        return StreamStepState.Continue;
    }
    if pkt.len >= 5 && pkt[..4] == "H3BK" {
        guard send_quic_window_replenish(sock, port, win, 16384) else {
            return StreamStepState.DoneFail;
        }
        rx_state.credits_sent = core::add_sat_u64(rx_state.credits_sent, 1);
        return StreamStepState.Continue;
    }
    guard pkt.len >= 44 && pkt[..4] == "H3DN" else { return StreamStepState.Continue; }
    bp_out = core::read_be_u32(pkt, 8);
    let got_sha = core::sha256_final(rx_state.hasher);
    let ok = rx_state.headers_ok &&
        rx_state.data_bytes == STREAM_EXPECT_BYTES &&
        bp_out > 0 &&
        rx_state.credits_sent > 0 &&
        core::ct_eq_bytes(got_sha[..], pkt[12..44]);
    return if ok { StreamStepState.DoneOk } else { StreamStepState.DoneFail };
}

fn run_h3_2mb_stream_transfer(port: u16) -> bool, u64, u64 {
    let sock = net::udp_bind("127.0.0.1", 0);
    guard sock > 0 else { return false, 0, 0; }
    defer net::tcp_close(sock);

    guard net::udp_sendto_dual(sock, "H3_STREAM_2MB\r\n", "127.0.0.1", port) > 0 else {
        return false, 0, 0;
    }

    var rx_state = H3StreamReceiver { .. };
    var win = server::make_request_stream_window(server::WindowProtocol.Http3, 4, 8192, 16384, 50);
    var pkt:     u8[2048] = [0; 2048];
    var peer_ip: u32      = 0;
    var peer_pt: u16      = 0;
    var bp_hits: u64      = 0;

    for _ in 6000 {
        let n = net::udp_recvfrom(sock, pkt[..], 2000, peer_ip, peer_pt);
        guard n > 0 else { return false, rx_state.data_bytes, bp_hits; }
        let st = handle_stream_datagram(sock, port, pkt[..n], rx_state, win, bp_hits);
        if st == StreamStepState.DoneOk {
            return true, rx_state.data_bytes, bp_hits;
        }
        if st == StreamStepState.DoneFail {
            return false, rx_state.data_bytes, bp_hits;
        }
    }
    return false, rx_state.data_bytes, bp_hits;
}

fn main() {
    let a = args();
    if a.len >= 3 && a[1] == "stream2mb" {
        let port_u, ok_p = a[2].parse_u64_dec();
        if !ok_p || port_u == 0 || port_u > 65535 {
            print("H3_STREAM_2MB: FAIL bytes=0 bp=0\n");
            return;
        }
        let ok_s, nbytes, bp = run_h3_2mb_stream_transfer(port_u as u16);
        print(
            if ok_s { "H3_STREAM_2MB: PASS bytes=" } else { "H3_STREAM_2MB: FAIL bytes=" },
            nbytes, " bp=", bp, "\n",
        );
        return;
    }

    let port = net::get_env_port(0);
    if port == 0 {
        print("H3_CLI_ERR: missing PORT\n");
        return;
    }
    var origin: u8[..128] = [];
    var s = make_h3_client(port, origin);

    let ok1 = run_h3_get_root(s, origin[..]);
    print(if ok1 { "H3_NATIVE_GET_ROOT: PASS\n" } else { "H3_NATIVE_GET_ROOT: FAIL\n" });

    let ok2 = run_h3_get_query_json(s);
    print(if ok2 { "H3_NATIVE_GET_QUERY: PASS\n" } else { "H3_NATIVE_GET_QUERY: FAIL\n" });

    let ok3 = run_h3_post_data(s);
    print(if ok3 { "H3_NATIVE_POST_DATA: PASS\n" } else { "H3_NATIVE_POST_DATA: FAIL\n" });
}
