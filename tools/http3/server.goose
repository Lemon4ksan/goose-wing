// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dedicated HTTP/3 & QUIC UDP Server for goose-wing E2E Verification.
// Conforms to RFC 9000 (QUIC Transport), RFC 9114 (HTTP/3), and RFC 9204 (QPACK).
import std;
import core from "../..";
import wing from "../..";

// Native UDP C bindings (shim/tcp.c)
extern fn native_udp_bind(host: const u8[:], port: u16) -> i64 = "wing_udp_bind";
extern fn native_udp_sendto(sock_fd: i64, data: const u8[:], host: const u8[:], port: u16) -> i32 = "wing_udp_sendto";
extern fn native_udp_sendto_ip4(sock_fd: i64, data: const u8[:], peer_ip4: u32, port: u16) -> i32 = "wing_udp_sendto_ip4";
extern fn native_udp_recvfrom(sock_fd: i64, buf: u8[:], timeout_ms: u32, peer_ip: u32&, peer_port: u16&) -> i32 = "wing_udp_recvfrom";

fn send_h3_connection_close(
    sock: i64,
    err_code: u64,
    peer_ip: u32,
    peer_port: u16,
) {
    var close_pkt: u8[..32] = [];
    internal::quic_encode_varint(close_pkt, 0x1D);
    internal::quic_encode_varint(close_pkt, err_code);
    internal::quic_encode_varint(close_pkt, 0);
    native_udp_sendto_ip4(sock, close_pkt[..], peer_ip, peer_port);
}

fn check_field_pseudo_header(name: const u8[:], mask: u8&) {
    if name == ":method" { mask = mask | 1; }
    if name == ":scheme" { mask = mask | 2; }
    if name == ":path" { mask = mask | 4; }
}

fn validate_h3_request_pseudo_headers(req_fields: const internal::HeaderField[>..]&) -> bool {
    var mask: u8 = 0;
    for &field in req_fields {
        check_field_pseudo_header(field.name[..], mask);
    }
    return mask == 7;
}

fn handle_h3_settings(
    sock: i64,
    payload: const u8[:],
    peer_ip: u32,
    peer_port: u16,
) {
    var set_in = wing::H3Settings { .. };
    let err = internal::parse_h3_settings_frame(payload, set_in);
    guard err == internal::H3_ERR_NO_ERROR else {
        send_h3_connection_close(sock, err, peer_ip, peer_port);
        return;
    }
    var ack: u8[..8] = [0x04, 0x00];
    native_udp_sendto_ip4(sock, ack[..], peer_ip, peer_port);
}

fn send_h3_success_response(sock: i64, peer_ip: u32, peer_port: u16) {
    let qpack_res: const u8[:] = "\x00\x00\xd9";
    var resp_frames: u8[>..] = [];
    internal::encode_h3_headers_frame(resp_frames, qpack_res);
    let body_text: const u8[:] = "Hello from goose-wing HTTP/3!";
    internal::encode_h3_data_frame(resp_frames, body_text);
    native_udp_sendto_ip4(sock, resp_frames[..], peer_ip, peer_port);
}

fn handle_h3_headers(
    sock: i64,
    payload: const u8[:],
    peer_ip: u32,
    peer_port: u16,
) {
    let tbl = internal::QpackTable { .. };
    var req_fields: internal::HeaderField[>..] = [];
    let qerr = internal::decode_qpack_section(tbl, payload, req_fields);
    guard qerr == internal::QpackError.None else {
        send_h3_connection_close(sock, internal::H3_ERR_QPACK_DECOMPRESSION_FAILED, peer_ip, peer_port);
        return;
    }

    guard validate_h3_request_pseudo_headers(req_fields) else {
        send_h3_connection_close(sock, internal::H3_ERR_GENERAL_PROTOCOL, peer_ip, peer_port);
        return;
    }

    send_h3_success_response(sock, peer_ip, peer_port);
}

fn dispatch_h3_frame_type(
    sock: i64,
    ftype: u64,
    payload: const u8[:],
    peer_ip: u32,
    peer_port: u16,
) -> bool {
    if ftype == internal::H3_FRAME_SETTINGS {
        handle_h3_settings(sock, payload, peer_ip, peer_port);
        return true;
    }
    if ftype == internal::H3_FRAME_HEADERS {
        handle_h3_headers(sock, payload, peer_ip, peer_port);
        return true;
    }
    return false;
}

inline fn is_h3_frame_bounded(datagram: const u8[:], hdr: const internal::H3FrameHeader&) -> bool {
    return ((hdr.header_len + hdr.payload_len) as i64) <= datagram.len;
}

inline fn extract_h3_payload(datagram: const u8[:], hdr: const internal::H3FrameHeader&) -> const u8[:] {
    let start = hdr.header_len as i64;
    let end = (hdr.header_len + hdr.payload_len) as i64;
    return datagram[start..end];
}

fn handle_h3_frame(
    sock: i64,
    datagram: const u8[:],
    peer_ip: u32,
    peer_port: u16,
) -> bool {
    let hdr, ok_hdr = internal::parse_h3_frame_header(datagram, 0);
    guard ok_hdr && is_h3_frame_bounded(datagram, hdr) else { return false; }
    return dispatch_h3_frame_type(sock, hdr.frame_type, extract_h3_payload(datagram, hdr), peer_ip, peer_port);
}

fn handle_quic_version_negotiation(
    sock: i64,
    hdr: const internal::QuicHeader&,
    peer_ip: u32,
    peer_port: u16,
) {
    var vn_pkt: u8[>..] = [];
    vn_pkt.push(0xC0);
    core::append_u32_be(vn_pkt, internal::QUIC_VERSION_NEGOTIATION);
    vn_pkt.push(hdr.scid.len as u8);
    vn_pkt.append(hdr.scid[..]);
    vn_pkt.push(hdr.dcid.len as u8);
    vn_pkt.append(hdr.dcid[..]);
    core::append_u32_be(vn_pkt, internal::QUIC_VERSION_1);
    native_udp_sendto_ip4(sock, vn_pkt[..], peer_ip, peer_port);
}

fn handle_quic_initial(
    sock: i64,
    hdr: const internal::QuicHeader&,
    peer_ip: u32,
    peer_port: u16,
) {
    var resp_pkt: u8[>..] = [];
    resp_pkt.push(0xC1);
    core::append_u32_be(resp_pkt, internal::QUIC_VERSION_1);
    resp_pkt.push(hdr.scid.len as u8);
    resp_pkt.append(hdr.scid[..]);
    let srv_cid: const u8[:] = "\x01\x02\x03\x04\x05\x06\x07\x08";
    resp_pkt.push(srv_cid.len as u8);
    resp_pkt.append(srv_cid);
    resp_pkt.push(0);

    var h3_ctrl: u8[..128] = [];
    internal::quic_encode_varint(h3_ctrl, internal::H3_STREAM_CONTROL);
    let settings = wing::H3Settings {
        qpack_max_table_capacity: 4096,
        max_field_section_size: 65536,
        qpack_blocked_streams: 16,
        enable_connect_protocol: 1,
    };
    internal::encode_h3_settings_frame(h3_ctrl, settings);
    internal::encode_h3_frame_header(h3_ctrl, 0x21, 0);

    let payload_len = (2 + h3_ctrl.len) as u64;
    internal::quic_encode_varint(resp_pkt, payload_len);
    core::append_u16_be(resp_pkt, 1);
    resp_pkt.append(h3_ctrl[..]);

    native_udp_sendto_ip4(sock, resp_pkt[..], peer_ip, peer_port);
}

fn handle_quic_packet(
    sock: i64,
    datagram: const u8[:],
    peer_ip: u32,
    peer_port: u16,
) -> bool {
    let quic_hdr, ok_qhdr = internal::parse_quic_header(datagram);
    guard ok_qhdr else { return false; }

    if quic_hdr.version != internal::QUIC_VERSION_1 && quic_hdr.version != internal::QUIC_VERSION_NEGOTIATION {
        handle_quic_version_negotiation(sock, quic_hdr, peer_ip, peer_port);
        return true;
    }

    if quic_hdr.header_type == internal::QuicHeaderType.Initial {
        handle_quic_initial(sock, quic_hdr, peer_ip, peer_port);
        return true;
    }

    return false;
}

fn dispatch_incoming_datagram(
    sock: i64,
    datagram: const u8[:],
    peer_ip: u32,
    peer_port: u16,
) -> bool {
    if datagram.len >= 8 && datagram[..8] == "SHUTDOWN" {
        let bye: const u8[:] = "BYE";
        native_udp_sendto_ip4(sock, bye, peer_ip, peer_port);
        return false;
    }

    if (datagram[0] & 0xC0) == 0 {
        if handle_h3_frame(sock, datagram, peer_ip, peer_port) {
            return true;
        }
    }

    handle_quic_packet(sock, datagram, peer_ip, peer_port);
    return true;
}

inline fn is_recv_timeout(recvd: i32) -> bool {
    return recvd == -2;
}

inline fn is_recv_valid(recvd: i32, max_len: i64) -> bool {
    return recvd > 0 && (recvd as i64) <= max_len;
}

fn poll_and_dispatch_datagram(sock: i64, in_buf: u8[:]) -> bool {
    var peer_port: u16 = 0;
    var peer_ip: u32 = 0;
    let recvd = native_udp_recvfrom(sock, in_buf, 500, peer_ip, peer_port);
    if is_recv_timeout(recvd) {
        return true;
    }
    guard is_recv_valid(recvd, in_buf.len) else {
        return false;
    }
    return dispatch_incoming_datagram(sock, in_buf[..(recvd as i64)], peer_ip, peer_port);
}

fn run_server_loop(sock: i64) {
    var in_buf: u8[65536] = [0; 65536];
    var is_running = true;
    while is_running {
        is_running = poll_and_dispatch_datagram(sock, in_buf[..]);
    }
}

fn main() {
    let port_env = wing::get_env_port(0);
    let sock = native_udp_bind("0.0.0.0", port_env);
    guard sock > 0 else {
        print("ERROR_FAILED_TO_BIND\n");
        return;
    }

    let port = wing::native_tcp_getsockname_port(sock);
    print("READY_PORT:", port, "\n");

    run_server_loop(sock);

    wing::native_tcp_close(sock);
}
