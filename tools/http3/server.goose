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

fn append_u64<B>(out: B&, val: u64) {
    if val == 0 {
        out.push('0');
        return;
    }
    var digits: u8[32] = [0; 32];
    var count = 0;
    var v = val;
    while v > 0 {
        digits[count] = ((v % 10) as u8) + '0';
        v = v / 10;
        count++;
    }
    var i = count - 1;
    while i >= 0 {
        out.push(digits[i]);
        i--;
    }
}

fn main() {
    let port_env = wing::get_env_port(0);
    let sock = native_udp_bind("0.0.0.0", port_env);
    if sock <= 0 {
        print("ERROR_FAILED_TO_BIND\n");
        return;
    }

    let port = wing::native_tcp_getsockname_port(sock);
    print("READY_PORT:", port, "\n");

    var in_buf: u8[65536] = [0; 65536];
    var peer_ip: u32 = 0;
    var peer_port: u16 = 0;

    var is_running = true;
    while is_running {
        peer_port = 0;
        peer_ip = 0;
        let recvd = native_udp_recvfrom(sock, in_buf[..], 500, peer_ip, peer_port);
        if recvd == -2 {
            continue; // Timeout
        }
        if recvd <= 0 {
            break;
        }

        let datagram = in_buf[..recvd];

        // 1. Check for shutdown signal
        if datagram.len >= 8 && datagram[..8] == "SHUTDOWN" {
            let bye: const u8[:] = "BYE";
            native_udp_sendto_ip4(sock, bye, peer_ip, peer_port);
            is_running = false;
            break;
        }

        // 2. Direct HTTP/3 SETTINGS Test Message (Marker: "H3_SET_TEST:")
        if datagram.len >= 12 && datagram[..12] == "H3_SET_TEST:" {
            let payload = datagram[12..];
            var set_in = wing::H3Settings { .. };
            let err = wing::parse_h3_settings_frame(payload, set_in);

            var resp: u8[>..] = [];
            resp.append("ERR:");
            append_u64(resp, err);
            native_udp_sendto_ip4(sock, resp[..], peer_ip, peer_port);
            continue;
        }

        // 3. Direct HTTP/3 Request Test Message (Marker: "H3_REQ:")
        if datagram.len >= 7 && datagram[..7] == "H3_REQ:" {
            let h3_payload = datagram[7..];

            // Parse incoming HEADERS frame
            let hdr, ok_hdr = wing::parse_h3_frame_header(h3_payload, 0);
            if ok_hdr && hdr.frame_type == wing::H3_FRAME_HEADERS {
                // Construct HTTP/3 Response:
                // HEADERS frame with status 200 (QPACK indexed field 25)
                var qpack_res: u8[..128] = [];
                qpack_res.push(0x00); // Required Insert Count (0)
                qpack_res.push(0x00); // Sign bit + Delta Base (0)

                // Indexed field line: static index 25 (:status 200)
                // RFC 9204 Section 4.5.2: 1T (11 = static), 6-bit index -> 0xC0 | 25 = 0xD9
                qpack_res.push(0xD9);

                var resp_frames: u8[>..] = [];
                wing::encode_h3_headers_frame(resp_frames, qpack_res[..]);

                // DATA frame with body
                let body_text: const u8[:] = "Hello from goose-wing HTTP/3!";
                wing::encode_h3_data_frame(resp_frames, body_text);

                native_udp_sendto_ip4(sock, resp_frames[..], peer_ip, peer_port);
            }
            continue;
        }

        // 4. QUIC Datagram Ingestion (RFC 9000)
        let quic_hdr, ok_qhdr = wing::parse_quic_header(datagram);
        if ok_qhdr {
            // Case A: Unsupported QUIC Version -> Version Negotiation (RFC 9000 §17.2.1)
            if quic_hdr.version != wing::QUIC_VERSION_1 && quic_hdr.version != wing::QUIC_VERSION_NEGOTIATION {
                var vn_pkt: u8[>..] = [];
                // First byte: Long Header (0x80) + Random/Unused bits
                vn_pkt.push(0xC0);
                // Version 0x00000000 indicates Version Negotiation
                core::append_u32_be(vn_pkt, wing::QUIC_VERSION_NEGOTIATION);
                // Destination Connection ID (echo client's SCID)
                vn_pkt.push(quic_hdr.scid.len as u8);
                vn_pkt.append(quic_hdr.scid[..]);
                // Source Connection ID (server's SCID)
                vn_pkt.push(quic_hdr.dcid.len as u8);
                vn_pkt.append(quic_hdr.dcid[..]);
                // Supported versions list (Supported: QUIC_VERSION_1)
                core::append_u32_be(vn_pkt, wing::QUIC_VERSION_1);

                native_udp_sendto_ip4(sock, vn_pkt[..], peer_ip, peer_port);
                continue;
            }

            // Case B: QUIC Initial Packet (Version 1)
            if quic_hdr.header_type == wing::QuicHeaderType.Initial {
                // Build QUIC Initial Response Packet
                var resp_pkt: u8[>..] = [];
                // Long header: Type Initial (0), 2-byte packet number length (0x01)
                resp_pkt.push(0xC1);
                core::append_u32_be(resp_pkt, wing::QUIC_VERSION_1);
                // DCID (client SCID)
                resp_pkt.push(quic_hdr.scid.len as u8);
                resp_pkt.append(quic_hdr.scid[..]);
                // SCID (server CID)
                let srv_cid: const u8[:] = "\x01\x02\x03\x04\x05\x06\x07\x08";
                resp_pkt.push(srv_cid.len as u8);
                resp_pkt.append(srv_cid);
                // Token Length: 0
                resp_pkt.push(0);

                // Build H3 Control Stream Payload (Stream Type 0x00 + SETTINGS Frame)
                var h3_ctrl: u8[..128] = [];
                wing::quic_encode_varint(h3_ctrl, wing::H3_STREAM_CONTROL);
                let settings = wing::H3Settings {
                    qpack_max_table_capacity: 4096,
                    max_field_section_size: 65536,
                    qpack_blocked_streams: 16,
                    enable_connect_protocol: 1,
                };
                wing::encode_h3_settings_frame(h3_ctrl, settings);

                // Add GREASE frame (RFC 9114 §7.2.8)
                wing::encode_h3_frame_header(h3_ctrl, 0x21, 0);

                // Payload length varint
                let payload_len = (2 + h3_ctrl.len) as u64; // 2 bytes PN + h3_ctrl
                wing::quic_encode_varint(resp_pkt, payload_len);

                // Packet number (2 bytes)
                core::append_u16_be(resp_pkt, 1);

                // Append H3 control payload
                resp_pkt.append(h3_ctrl[..]);

                native_udp_sendto_ip4(sock, resp_pkt[..], peer_ip, peer_port);
                continue;
            }
        }
    }

    wing::native_tcp_close(sock);
}
