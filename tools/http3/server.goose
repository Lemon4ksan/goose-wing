// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dedicated HTTP/3 & QUIC UDP Server for goose-wing E2E Verification.
// Conforms to RFC 9000 (QUIC Transport, Flow Control, Connection Migration),
// RFC 9114 (HTTP/3), and RFC 9204 (QPACK).
import std;
import wing from "../..";

// RFC 9000 Section 19: Frame types used for flow-control streaming and path validation.
const QUIC_FRAME_PATH_CHALLENGE: u8  = 0x1A;
const QUIC_FRAME_PATH_RESPONSE:  u8  = 0x1B;
const STREAM_TOTAL_BYTES:        i64 = 2 * 1024 * 1024;
const STREAM_CHUNK_BYTES:        i64 = 32768;
const STREAM_NUM_CHUNKS:         i64 = 64;
const STREAM_INIT_CONN_WIN:      u64 = 16384;
const STREAM_INIT_STRM_WIN:      u64 = 8192;

struct H3MigrationSession {
    initialized: bool                       = false,
    rng_seed:    u64                        = 0xC0FFEE123456789A,
    mgr:         quic::QuicMigrationManager = quic::QuicMigrationManager { .. },
}

fn fill_deterministic_chunk(buf: u8[:], seed: u64) {
    var st: u64 = seed ^ 0x9E3779B97F4A7C15;
    for i in buf.len {
        let v = core::splitmix64(st);
        buf[i] = (v & 0xFF) as u8;
    }
}

fn send_stream_chunk_datagram(
    udp_tr: net::Transport,
    seq_no: u64,
    wire:   const u8[:],
) -> bool {
    var pkt: u8[..1200] = [];
    guard pkt.try_append("H3ST") else { return false; }
    pkt.append_u32_be((seq_no & 0xFFFFFFFF) as u32);
    guard pkt.try_append(wire) else { return false; }
    return net::send(udp_tr, pkt[..]) > 0;
}

fn drain_h3_stream_to_udp(
    udp_tr: net::Transport,
    stream: server::ResponseStream&,
    seq_no: u64&,
) -> bool {
    var wire: u8[1152] = [0; 1152];
    for _ in 64 {
        let n = server::stream_drain_wire(stream, wire[..]);
        if n <= 0 { return true; }
        guard send_stream_chunk_datagram(udp_tr, seq_no, wire[..n]) else { return false; }
        seq_no = core::add_sat_u64(seq_no, 1);
    }
    return true;
}

// Parses RFC 9000 MAX_DATA (0x10) and MAX_STREAM_DATA (0x11) wire updates into `stream`.
//
// Example:
//   frame = [0x10, 0x80, 0x01, 0x00, 0x00, 0x11, 0x04, 0x80, 0x00, 0x80, 0x00]
//   returns: true, stream window credits updated
fn apply_quic_credit_datagram(frame: const u8[:], stream: server::ResponseStream&) -> bool {
    var off:        u64 = 0;
    var max_conn:   u64 = 0;
    var max_stream: u64 = 0;
    var saw_any = false;
    let frame_len = frame.len as u64;
    while off < frame_len {
        let ftype, o1, ok1 = quic::decode_varint(frame, off);
        guard ok1 else { break; }
        if ftype == rfc::QUIC_FRAME_MAX_DATA {
            let val, o2, ok2 = quic::decode_varint(frame, o1);
            guard ok2 else { return false; }
            max_conn = val;
            saw_any = true;
            off = o2;
            continue;
        }
        if ftype == rfc::QUIC_FRAME_MAX_STREAM_DATA {
            let _, o2, ok2 = quic::decode_varint(frame, o1);
            let val, o3, ok3 = quic::decode_varint(frame, o2);
            guard ok2 && ok3 else { return false; }
            max_stream = val;
            saw_any = true;
            off = o3;
            continue;
        }
        break;
    }
    if saw_any {
        server::stream_on_quic_max_data(stream, max_conn, max_stream);
    }
    return saw_any;
}

fn await_quic_window_update(
    sock:   i64,
    udp_tr: net::Transport,
    stream: server::ResponseStream&,
) -> bool {
    let blk: u8[5] = ['H', '3', 'B', 'K', 0x15];
    let _ = net::send(udp_tr, blk[..]);

    var rx:   u8[256] = [0; 256];
    var p_ip: u32     = 0;
    var p_pt: u16     = 0;
    for _ in 8 {
        let n = net::udp_recvfrom(sock, rx[..], 500, p_ip, p_pt);
        if n <= 0 { continue; }
        if apply_quic_credit_datagram(rx[..n], stream) {
            return true;
        }
    }
    return false;
}

fn pump_stream_chunk(
    sock:      i64,
    udp_tr:    net::Transport,
    stream:    server::ResponseStream&,
    chunk_buf: const u8[:],
    seq_no:    u64&,
    bp_hits:   u64&,
) -> bool {
    var off: i64 = 0;
    while off < chunk_buf.len {
        let written, st = server::stream_write(stream, chunk_buf[off..]);
        off = core::add_sat_i64(off, written);
        guard drain_h3_stream_to_udp(udp_tr, stream, seq_no) else { return false; }
        if st == server::StreamWriteStatus.WouldBlock {
            bp_hits = core::add_sat_u64(bp_hits, 1);
            guard await_quic_window_update(sock, udp_tr, stream) else { return false; }
            continue;
        }
        guard st == server::StreamWriteStatus.Ok else { return false; }
    }
    return true;
}

fn send_2mb_h3_stream(sock: i64, udp_tr: net::Transport) {
    var stream = server::make_http3_response_stream(4, STREAM_INIT_CONN_WIN, STREAM_INIT_STRM_WIN);
    var res = http::Response { status_code: rfc::STATUS_OK, .. };
    http::set_header(res, rfc::HEADER_CONTENT_TYPE, "application/octet-stream");
    guard server::stream_begin(stream, res) == server::StreamWriteStatus.Ok else { return; }

    var hasher = core::Sha256Ctx { .. };
    var chunk_buf: u8[32768] = [0; 32768];
    var seq_no:    u64       = 0;
    var bp_hits:   u64       = 0;

    for idx in STREAM_NUM_CHUNKS {
        let seed_idx = core::add_sat_u64(idx as u64, 1);
        fill_deterministic_chunk(chunk_buf[..], seed_idx);
        core::sha256_update(hasher, chunk_buf[..]);
        guard pump_stream_chunk(sock, udp_tr, stream, chunk_buf[..], seq_no, bp_hits) else { return; }
    }
    let _ = server::stream_end(stream);
    let _ = drain_h3_stream_to_udp(udp_tr, stream, seq_no);

    let digest = core::sha256_final(hasher);
    var done_pkt: u8[..64] = [];
    guard done_pkt.try_append("H3DN") else { return; }
    done_pkt.append_u32_be((seq_no & 0xFFFFFFFF) as u32);
    done_pkt.append_u32_be((bp_hits & 0xFFFFFFFF) as u32);
    guard done_pkt.try_append(digest[..]) else { return; }
    let _ = net::send(udp_tr, done_pkt[..]);
}

fn send_path_challenge_for_new_addr(
    udp_tr:    net::Transport,
    mig:       H3MigrationSession&,
    cand_addr: const quic::QuicEndpointAddr&,
    dgram_len: u64,
) {
    if quic::addr_eq(mig.mgr.active_path.remote_addr, cand_addr) {
        let _ = net::send(udp_tr, "MIG_SAME_PATH");
        return;
    }
    let tok, ok_tok = quic::generate_path_challenge_token();
    guard ok_tok else { return; }
    quic::start_probing(mig.mgr, cand_addr, tok);
    mig.mgr.probing_path.bytes_received = dgram_len;
    guard quic::can_send(mig.mgr.probing_path, 9) else { return; }
    var chall: u8[9] = [0; 9];
    chall[0] = QUIC_FRAME_PATH_CHALLENGE;
    core::ct_copy_bytes(chall[1..9], tok[..]);
    mig.mgr.probing_path.bytes_sent = 9;
    let _ = net::send(udp_tr, chall[..]);
}

fn handle_migration_probe(
    udp_tr:    net::Transport,
    mig:       H3MigrationSession&,
    datagram:  const u8[:],
    peer_port: u16,
) -> bool {
    let cand_addr = quic::new_endpoint_addr("127.0.0.1", peer_port);
    if datagram.len >= 12 && datagram[..12] == "MIG_REGISTER" {
        mig.mgr = quic::new_migration_manager(cand_addr);
        mig.initialized = true;
        let _ = net::send(udp_tr, "MIG_REGISTERED");
        return true;
    }
    if datagram.len >= 9 && datagram[0] == QUIC_FRAME_PATH_RESPONSE {
        let ok_resp = quic::on_path_response(mig.mgr, datagram[1..9]) && quic::complete(mig.mgr);
        if ok_resp {
            var ack: u8[..32] = [];
            let _ = ack.try_append("MIG_OK:");
            core::format_u64_dec(mig.mgr.active_path.remote_addr.port, ack);
            let _ = net::send(udp_tr, ack[..]);
        } else {
            let _ = net::send(udp_tr, "MIG_REJECT");
        }
        return true;
    }
    if datagram.len >= 9 && datagram[..9] == "MIG_PROBE" && mig.initialized {
        send_path_challenge_for_new_addr(udp_tr, mig, cand_addr, datagram.len as u64);
        return true;
    }
    return false;
}

fn dispatch_incoming_datagram(
    sock:      i64,
    server:    server::HttpServer&,
    ep:        server::H3ServerEndpoint&,
    mig:       H3MigrationSession&,
    datagram:  const u8[:],
    peer_ip:   u32,
    peer_port: u16,
    out_wire:  u8[..2048]&,
) -> bool {
    let udp_tr = net::Transport.Udp {
        fd:        sock,
        peer_ip4:  peer_ip,
        peer_port: peer_port,
    };
    if datagram.len >= 8 && datagram[..8] == "SHUTDOWN" {
        let _ = net::send(udp_tr, "BYE");
        return false;
    }
    if datagram.len >= 15 && datagram[..15] == "H3_STREAM_2MB\r\n" {
        send_2mb_h3_stream(sock, udp_tr);
        return true;
    }
    if handle_migration_probe(udp_tr, mig, datagram, peer_port) {
        return true;
    }

    let now_ns = core::as_nanos(core::monotonic_now());
    if server::handle_h3_quic_datagram(server, ep, "127.0.0.1", datagram, now_ns, out_wire) {
        let _ = net::send(udp_tr, out_wire[..]);
    }
    return true;
}

inline fn is_recv_timeout(recvd: i32) -> bool {
    return recvd == -2;
}

inline fn is_recv_valid(recvd: i32, max_len: i64) -> bool {
    return recvd > 0 && recvd <= max_len;
}

fn poll_and_dispatch_datagram(
    sock:     i64,
    server:   server::HttpServer&,
    ep:       server::H3ServerEndpoint&,
    mig:      H3MigrationSession&,
    in_buf:   u8[:],
    out_wire: u8[..2048]&,
) -> bool {
    var peer_port: u16 = 0;
    var peer_ip:   u32 = 0;
    let recvd = net::udp_recvfrom(sock, in_buf, 500, peer_ip, peer_port);
    if is_recv_timeout(recvd) || !is_recv_valid(recvd, in_buf.len) {
        return true;
    }
    return dispatch_incoming_datagram(
        sock, server, ep, mig, in_buf[..(recvd as i64)], peer_ip, peer_port, out_wire,
    );
}

fn run_server_loop(sock: i64, server: server::HttpServer&, ep: server::H3ServerEndpoint&) {
    var in_buf:   u8[65536]  = [0; 65536];
    var out_wire: u8[..2048] = [];
    var mig = H3MigrationSession { .. };
    var is_running = true;
    while is_running {
        is_running = poll_and_dispatch_datagram(sock, server, ep, mig, in_buf[..], out_wire);
    }
}

fn main() {
    let port_env = net::get_env_port(0);
    let sock = net::udp_bind("0.0.0.0", port_env);
    guard sock > 0 else {
        print("ERROR_FAILED_TO_BIND\n");
        return;
    }

    let port = net::tcp_getsockname_port(sock);
    var server = server::new_http_server("0.0.0.0", port);
    server::add_static_get_route(server, "/", "text/plain", "Hello from goose-wing HTTP/3!", 1);
    server::add_static_get_route(
        server, "/api/info", "application/json", "{\"protocol\":\"h3\",\"engine\":\"goose-wing\"}", 2,
    );
    let _ = server::add_static_route(server.pipeline.router, "POST", "/echo", "text/plain", "H3_POST_ACK", 3);

    let settings = fingerprint::H3Settings {
        qpack_max_table_capacity: 4096,
        max_field_section_size:   65536,
        qpack_blocked_streams:    16,
        enable_connect_protocol:  1,
    };
    var ep = server::new_h3_server_endpoint(settings);

    print("READY_PORT:", port, "\n");

    run_server_loop(sock, server, ep);

    net::tcp_close(sock);
}
