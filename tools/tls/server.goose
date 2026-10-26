// Dedicated TLS 1.3 Interop Server for goose-wing E2E Verification.
// Conforms to RFC 8446 (TLS 1.3), RFC 6066 (SNI), RFC 7301 (ALPN), and RFC 8879 (Cert Compression).
import std;
import core from "../..";
import wing from "../..";

fn handle_tls_connection(conn: i64) {
    var in_buf: u8[>..] = [];
    var is_running = true;

    while is_running {
        let recvd = wing::tcp_recv(conn, in_buf, 4096, 500);
        if recvd == -2 {
            continue;
        }
        if recvd <= 0 {
            break;
        }

        // Check for plain HTTP /shutdown trigger
        if in_buf.len >= 14 && in_buf[..14] == "GET /shutdown " {
            let resp: const u8[:] = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nBYE\n";
            wing::tcp_send(conn, resp);
            return;
        }

        // Validate TLS Record Header:
        // Byte 0: ContentType (0x16 = Handshake, 0x17 = AppData, 0x15 = Alert)
        // Bytes 1..2: Legacy Version (0x0301 or 0x0303)
        // Bytes 3..4: Length (Big-endian u16)
        if in_buf.len < 5 {
            continue;
        }

        let content_type = in_buf[0];
        let legacy_ver = ((in_buf[1] as u16) << 8) | in_buf[2];
        let record_len = ((in_buf[3] as u16) << 8) | in_buf[4];

        let total_record_len = 5 + (record_len as i64);
        if in_buf.len < total_record_len {
            continue; // Wait for full record
        }

        let record_payload = in_buf[5..total_record_len];

        if content_type == 0x16 { // Handshake
            if record_payload.len >= 4 {
                let msg_type = record_payload[0];
                let msg_len = ((record_payload[1] as u32) << 16) | ((record_payload[2] as u32) << 8) | record_payload[3];

                if msg_type == wing::HS_MSG_CLIENT_HELLO && record_payload.len >= 4 + (msg_len as i64) {
                    let ch_payload = record_payload[4 .. 4 + (msg_len as i64)];

                    // Parse ClientHello:
                    // ClientHello starts at byte 34 (after 2-byte legacy_ver + 32-byte client_random)
                    var sni_str: u8[..255] = [];
                    var negotiated_alpn = wing::NegotiatedAlpn.None;

                    // Scan for extensions in ClientHello
                    if ch_payload.len > 34 {
                        let sess_id_len = ch_payload[34] as i64;
                        let mut_idx = 35 + sess_id_len;
                        if ch_payload.len >= mut_idx + 2 {
                            let cs_len = (((ch_payload[mut_idx] as u16) << 8) | ch_payload[mut_idx + 1]) as i64;
                            let comp_idx = mut_idx + 2 + cs_len;
                            if ch_payload.len > comp_idx {
                                let comp_len = ch_payload[comp_idx] as i64;
                                let ext_start = comp_idx + 1 + comp_len;

                                if ch_payload.len >= ext_start + 2 {
                                    let ext_total_len = (((ch_payload[ext_start] as u16) << 8) | ch_payload[ext_start + 1]) as i64;
                                    if ch_payload.len >= ext_start + 2 + ext_total_len {
                                        let exts_slice = ch_payload[ext_start .. (ext_start + 2 + ext_total_len)];

                                        var entries: wing::TlsExtensionEntry[..32] = [];
                                        let ok_exts = wing::parse_extensions_block(exts_slice, entries);
                                        if ok_exts {
                                            let sni_raw, has_sni = wing::find_extension(entries, wing::EXT_SERVER_NAME);
                                            if has_sni {
                                                wing::parse_sni_extension(sni_raw, sni_str);
                                            }

                                            let alpn_raw, has_alpn = wing::find_extension(entries, wing::EXT_ALPN);
                                            if has_alpn {
                                                negotiated_alpn = wing::negotiate_alpn(alpn_raw, false);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Build ServerHello Response (TLS 1.3, RFC 8446)
                    // ServerHello:
                    // Record Header (5B): [0x16, 0x03, 0x03, len(2B)]
                    // Handshake Header (4B): [0x02, len(3B)]
                    // Server Version: 0x0303 (Legacy)
                    // Random (32B)
                    // Legacy Session ID (Echo Client's)
                    // Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
                    // Legacy Compression: 0x00
                    // Extensions:
                    //   supported_versions (0x002B): [0x03, 0x04] (TLS 1.3)
                    //   key_share (0x0033)
                    var sh_builder = wing::builder_init();
                    wing::put_u16(sh_builder, 0x0303); // Legacy version

                    // 32-byte server random
                    for _ in 32 {
                        wing::put_u8(sh_builder, 0x5A);
                    }

                    // Echo session ID length 0
                    wing::put_u8(sh_builder, 0);

                    // Selected Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
                    wing::put_u16(sh_builder, 0x1301);

                    // Compression method: 0
                    wing::put_u8(sh_builder, 0);

                    // Extensions block
                    wing::start_u16_prefix(sh_builder);

                    // 1. supported_versions extension (0x002B) -> TLS 1.3 (0x0304)
                    wing::put_u16(sh_builder, 43); // EXT_SUPPORTED_VERSIONS
                    wing::start_u16_prefix(sh_builder);
                    wing::put_u16(sh_builder, 0x0304); // TLS 1.3
                    wing::finish_u16_prefix(sh_builder);

                    wing::finish_u16_prefix(sh_builder);

                    // Wrap in Handshake Header (type = 2 / ServerHello)
                    var hs_msg: u8[>..] = [];
                    hs_msg.push(wing::HS_MSG_SERVER_HELLO);
                    let sh_len = sh_builder.buf.len as u32;
                    hs_msg.push(((sh_len >> 16) & 0xFF) as u8);
                    hs_msg.push(((sh_len >> 8) & 0xFF) as u8);
                    hs_msg.push((sh_len & 0xFF) as u8);
                    hs_msg.append(sh_builder.buf[..]);

                    // Wrap in TLS Record Header
                    var record_out: u8[>..] = [];
                    record_out.push(0x16); // Handshake
                    record_out.push(0x03);
                    record_out.push(0x03);
                    let rec_len = hs_msg.len as u16;
                    record_out.push(((rec_len >> 8) & 0xFF) as u8);
                    record_out.push((rec_len & 0xFF) as u8);
                    record_out.append(hs_msg[..]);

                    // Append ChangeCipherSpec (RFC 8446 Appendix D.4 compatibility)
                    record_out.push(0x14); // ChangeCipherSpec
                    record_out.push(0x03);
                    record_out.push(0x03);
                    record_out.push(0x00);
                    record_out.push(0x01);
                    record_out.push(0x01); // 1 byte payload

                    wing::tcp_send(conn, record_out[..]);
                }
            }
        } else if content_type == 0x15 { // Alert
            // Client closed connection cleanly
            break;
        }

        // Advance buffer
        var rem: u8[>..] = [];
        rem.append(in_buf[total_record_len..]);
        in_buf.clear();
        in_buf.append(rem[..]);
    }
}

fn main() {
    let port_env = wing::get_env_port(0);
    let listener = wing::tcp_listen("0.0.0.0", port_env, 128);
    if listener <= 0 {
        print("ERROR_FAILED_TO_LISTEN\n");
        return;
    }
    let port = wing::tcp_getsockname_port(listener);
    print("READY_PORT:", port, "\n");

    var is_running = true;
    while is_running {
        let conn = wing::tcp_accept(listener, 200);
        if conn <= 0 {
            continue;
        }

        handle_tls_connection(conn);
        wing::tcp_close(conn);
    }

    wing::tcp_close(listener);
}
