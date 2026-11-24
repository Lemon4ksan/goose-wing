// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Live QUIC + HTTP/3 UDP server driving QuicServerEndpoint, H3EdgeSession,
// encode_server_preambles, and tls::QuicTlsServer over net::udp_open_dual + net::Poller.
import std;
import wing from "../..";

const MAX_H3_CONNS:     i64 = 32;
const H3_POLL_MAX_MS:   i64 = 20;
const H3_IDLE_SHUTDOWN: u64 = 250000000;

struct EdgeH3ConnSlot {
    active:  bool                 = false,
    conn_id: u64                  = 0,
    h3_sess: http3::H3EdgeSession = http3::H3EdgeSession { .. },
}

struct EdgeH3StreamBuf {
    active:       bool         = false,
    conn_id:      u64          = 0,
    stream_id:    u64          = 0,
    is_echo:      bool         = false,
    headers_done: bool         = false,
    resp_off:     i64          = 0,
    method:       u8[..16]     = [],
    path:         u8[..512]    = [],
    data_buf:     u8[..131072] = [],
}

var g_running:  bool                 = true;
var g_stop_ns:  u64                  = 0;
var g_www_dir:  u8[..256]            = [];
var g_cert_pem: u8[>..]              = [];
var g_key_pem:  u8[>..]              = [];
var g_conns:    EdgeH3ConnSlot[32]   = [EdgeH3ConnSlot { .. }; 32];
var g_streams:  EdgeH3StreamBuf[>..] = [];
var g_rx_tmp:   u8[>..]              = [];
var g_tx_tmp:   u8[>..]              = [];

inline fn now_monotonic_ns() -> u64 {
    return max(0, core::monotonic_now().as_nanos());
}

// ---- Self-Signed ECDSA P-256 PEM Certificate Fallback --------------------

fn der_put_len<B>(out: B&, n: i64) {
    if n < 128 {
        let _ = out.try_push(n as u8);
    } else if n < 256 {
        let _ = out.try_push(0x81);
        let _ = out.try_push(n as u8);
    } else {
        let _ = out.try_push(0x82);
        let _ = out.try_push(((n >> 8) & 0xFF) as u8);
        let _ = out.try_push((n & 0xFF) as u8);
    }
}

fn der_tlv<B>(out: B&, tag: u8, val: const u8[:]) {
    let _ = out.try_push(tag);
    der_put_len(out, val.len);
    let _ = out.try_append(val);
}

fn der_wrap<B>(tag: u8, inner: const u8[:], out: B&) {
    out.clear();
    der_tlv(out, tag, inner);
}

fn append_pem_block(label: const u8[:], der: const u8[:], out: u8[>..]&) {
    out.append("-----BEGIN ");
    out.append(label);
    out.append("-----\n");
    var b64: u8[>..] = [];
    core::base64_encode(der, b64);
    var pos: i64 = 0;
    while pos < b64.len {
        let end = min(core::add_sat_i64(pos, 64), b64.len);
        out.append(b64[pos..end]);
        out.push('\n');
        pos = end;
    }
    out.append("-----END ");
    out.append(label);
    out.append("-----\n");
}

fn encode_cn_dn<B>(cn: const u8[:], out: B&) {
    var atv_body: u8[..128] = [];
    der_tlv(atv_body, rfc::ASN1_TAG_OID, rfc::OID_COMMON_NAME[..]);
    der_tlv(atv_body, rfc::ASN1_TAG_UTF8_STRING, cn);
    var atv: u8[..140] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, atv_body[..], atv);
    var rdn: u8[..148] = [];
    der_wrap(rfc::ASN1_TAG_SET, atv[..], rdn);
    der_wrap(rfc::ASN1_TAG_SEQUENCE, rdn[..], out);
}

fn encode_san_extension<B>(out_exts: B&) {
    var san_inner: u8[..128] = [];
    der_tlv(san_inner, 0x82, "localhost");
    der_tlv(san_inner, 0x82, "server");
    der_tlv(san_inner, 0x82, "wing-server");
    let ip4: u8[4] = [127, 0, 0, 1];
    der_tlv(san_inner, 0x87, ip4[..]);
    var san_seq: u8[..140] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, san_inner[..], san_seq);
    var ext_body: u8[..200] = [];
    der_tlv(ext_body, rfc::ASN1_TAG_OID, rfc::OID_SUBJECT_ALT_NAME[..]);
    der_tlv(ext_body, rfc::ASN1_TAG_OCTET_STRING, san_seq[..]);
    der_tlv(out_exts, rfc::ASN1_TAG_SEQUENCE, ext_body[..]);
}

fn build_p256_cert_der<B>(priv_key: const u8[32]&, out_der: B&) {
    let subj_pub = core::ecdsa_p256_public_key(priv_key);
    var tbs_body: u8[..2048] = [];
    let ver_v3: u8[3] = [0x02, 0x01, 0x02];
    der_tlv(tbs_body, 0xA0, ver_v3[..]);
    let ser: u8[2] = [0x01, 0x2A];
    der_tlv(tbs_body, rfc::ASN1_TAG_INTEGER, ser[..]);

    var ecdsa_alg: u8[..16] = [];
    der_tlv(ecdsa_alg, rfc::ASN1_TAG_OID, rfc::OID_SIG_ECDSA_SHA256[..]);
    der_tlv(tbs_body, rfc::ASN1_TAG_SEQUENCE, ecdsa_alg[..]);

    var dn: u8[..160] = [];
    encode_cn_dn("localhost", dn);
    let _ = tbs_body.try_append(dn[..]);

    var val_body: u8[..64] = [];
    der_tlv(val_body, rfc::ASN1_TAG_UTC_TIME, "240101000000Z");
    der_tlv(val_body, rfc::ASN1_TAG_UTC_TIME, "351231235959Z");
    der_tlv(tbs_body, rfc::ASN1_TAG_SEQUENCE, val_body[..]);
    let _ = tbs_body.try_append(dn[..]);

    var spki_alg: u8[..32] = [];
    der_tlv(spki_alg, rfc::ASN1_TAG_OID, rfc::OID_EC_PUBLIC_KEY[..]);
    der_tlv(spki_alg, rfc::ASN1_TAG_OID, rfc::OID_SECP256R1[..]);
    var spki_body: u8[..120] = [];
    der_tlv(spki_body, rfc::ASN1_TAG_SEQUENCE, spki_alg[..]);
    var pk_bits: u8[..66] = [];
    let _ = pk_bits.try_push(0x00);
    let _ = pk_bits.try_append(subj_pub[..]);
    der_tlv(spki_body, rfc::ASN1_TAG_BIT_STRING, pk_bits[..]);
    der_tlv(tbs_body, rfc::ASN1_TAG_SEQUENCE, spki_body[..]);

    var exts_body: u8[..256] = [];
    encode_san_extension(exts_body);
    var exts_seq: u8[..280] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, exts_body[..], exts_seq);
    der_tlv(tbs_body, 0xA3, exts_seq[..]);

    var tbs_der: u8[..2200] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, tbs_body[..], tbs_der);
    let raw_sig = core::ecdsa_p256_sign(priv_key, tbs_der[..]);
    var der_sig: u8[..72] = [];
    let _ = core::ecdsa_p256_encode_der_sig(raw_sig, der_sig);

    var cert_body: u8[..2400] = [];
    let _ = cert_body.try_append(tbs_der[..]);
    der_tlv(cert_body, rfc::ASN1_TAG_SEQUENCE, ecdsa_alg[..]);
    var sig_bits: u8[..80] = [];
    let _ = sig_bits.try_push(0x00);
    let _ = sig_bits.try_append(der_sig[..]);
    der_tlv(cert_body, rfc::ASN1_TAG_BIT_STRING, sig_bits[..]);
    der_wrap(rfc::ASN1_TAG_SEQUENCE, cert_body[..], out_der);
}

fn build_p256_pkcs8_pem(priv_key: const u8[32]&, out_pem: u8[>..]&) {
    out_pem.clear();
    let pub65 = core::ecdsa_p256_public_key(priv_key);
    var b_ec = core::builder_init();
    b_ec.put_bytes("\x02\x01\x01\x04\x20");
    b_ec.put_bytes(priv_key[..]);
    b_ec.put_bytes("\xA1\x44\x03\x42\x00");
    b_ec.put_bytes(pub65[..]);
    var ec_seq: u8[..256] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, b_ec.buf[..], ec_seq);

    var pki: u8[..512] = [];
    let zero_v: u8[1] = [0x00];
    der_tlv(pki, rfc::ASN1_TAG_INTEGER, zero_v[..]);
    var alg_body: u8[..32] = [];
    der_tlv(alg_body, rfc::ASN1_TAG_OID, rfc::OID_EC_PUBLIC_KEY[..]);
    der_tlv(alg_body, rfc::ASN1_TAG_OID, rfc::OID_SECP256R1[..]);
    der_tlv(pki, rfc::ASN1_TAG_SEQUENCE, alg_body[..]);
    der_tlv(pki, rfc::ASN1_TAG_OCTET_STRING, ec_seq[..]);

    var pkcs8_der: u8[..512] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, pki[..], pkcs8_der);
    append_pem_block("PRIVATE KEY", pkcs8_der[..], out_pem);
}

fn init_server_credentials() {
    g_cert_pem.clear();
    g_key_pem.clear();
    if read_file("/certs/cert.pem", g_cert_pem) && read_file("/certs/priv.key", g_key_pem) {
        if g_cert_pem.len > 0 && g_key_pem.len > 0 {
            return;
        }
    }
    g_cert_pem.clear();
    g_key_pem.clear();
    let priv: u8[32] = [
        0x42, 0x19, 0x8F, 0x2C, 0x71, 0xE3, 0x55, 0xA8,
        0x11, 0x90, 0x3D, 0x74, 0xC6, 0x2B, 0x88, 0x4E,
        0x5A, 0x1F, 0x62, 0xD4, 0x93, 0x07, 0xB5, 0x61,
        0xCA, 0x28, 0x4F, 0x99, 0x30, 0xE1, 0x77, 0x15,
    ];
    var cert_der: u8[..2400] = [];
    build_p256_cert_der(priv, cert_der);
    append_pem_block("CERTIFICATE", cert_der[..], g_cert_pem);
    build_p256_pkcs8_pem(priv, g_key_pem);
}

// ---- Connection & Stream State Pools -------------------------------------

fn find_conn_slot(conn_id: u64) -> i64 {
    for i in MAX_H3_CONNS {
        if g_conns[i].active && g_conns[i].conn_id == conn_id {
            return i;
        }
    }
    return -1;
}

fn alloc_conn_slot(conn_id: u64) -> i64 {
    for i in MAX_H3_CONNS {
        if !g_conns[i].active {
            g_conns[i] = EdgeH3ConnSlot {
                active:  true,
                conn_id: conn_id,
                h3_sess: http3::h3_edge_open(),
            };
            return i;
        }
    }
    return -1;
}

fn free_conn_streams(conn_id: u64) {
    for &st in g_streams {
        if st.active && st.conn_id == conn_id {
            st.active = false;
            st.data_buf.clear();
        }
    }
}

fn close_conn_slot(conn_id: u64) {
    free_conn_streams(conn_id);
    let idx = find_conn_slot(conn_id);
    guard idx >= 0 else { return; }
    http3::h3_edge_close(g_conns[idx].h3_sess);
    g_conns[idx] = EdgeH3ConnSlot { .. };
}

fn find_or_alloc_stream(conn_id: u64, stream_id: u64, create: bool) -> i64 {
    for i in g_streams.len {
        if g_streams[i].active && g_streams[i].conn_id == conn_id && g_streams[i].stream_id == stream_id {
            return i;
        }
    }
    guard create else { return -1; }
    for i in g_streams.len {
        if !g_streams[i].active {
            g_streams[i] = EdgeH3StreamBuf {
                active:    true,
                conn_id:   conn_id,
                stream_id: stream_id,
                ..
            };
            return i;
        }
    }
    let idx = g_streams.len;
    g_streams.push(EdgeH3StreamBuf {
        active:    true,
        conn_id:   conn_id,
        stream_id: stream_id,
        ..
    });
    return idx;
}

// ---- HTTP/3 Static & Dynamic Route Dispatch ------------------------------

fn strip_query(raw_path: const u8[:]) -> const u8[:] {
    let head, _, found = raw_path.split_once_byte('?');
    if found { return head; }
    return raw_path;
}

fn try_read_www_file(path: const u8[:], out: u8[>..]&) -> bool {
    guard g_www_dir.len > 0 && path.len > 1 && path[0] == '/' else { return false; }
    let rel = path[1..];
    guard !core::contains(rel, "..") && !rel.contains_byte('\\') else { return false; }
    var full: u8[..512] = [];
    guard full.try_append(g_www_dir[..]) && full.try_push('/') && full.try_append(rel) else {
        return false;
    }
    out.clear();
    return read_file(full[..], out);
}

fn build_h3_route_response(
    method:    const u8[:],
    raw_path:  const u8[:],
    echo_data: const u8[:],
    is_echo:   bool,
    out_ctype: u8[..64]&,
    out_body:  u8[>..]&,
) -> i32 {
    let path = strip_query(raw_path);
    out_body.clear();
    let _ = out_ctype.try_set("text/plain");
    if path == "/shutdown" {
        let _ = out_body.try_append("BYE\n");
        g_stop_ns = core::add_sat_u64(now_monotonic_ns(), H3_IDLE_SHUTDOWN);
        return 200;
    }
    if path == "/" {
        let _ = out_body.try_append("Hello from goose-wing HTTP/3!\n");
        return 200;
    }
    if path == "/ping" {
        let _ = out_body.try_append("PONG_H3_EDGE\n");
        return 200;
    }
    if path == "/api/info" {
        let _ = out_ctype.try_set("application/json");
        let _ = out_body.try_append("{\"protocol\":\"h3\",\"engine\":\"goose-wing\",\"session\":\"edge\"}");
        return 200;
    }
    if path == "/echo" && method == "POST" && is_echo {
        out_body.append(echo_data);
        return 200;
    }
    if try_read_www_file(path, out_body) {
        let _ = out_ctype.try_set("application/octet-stream");
        return 200;
    }
    let _ = out_body.try_append("Not Found\n");
    return 404;
}

fn flush_stream_tx(ep: quic::QuicServerEndpoint&, st_idx: i64) {
    let st .= g_streams[st_idx];
    guard st.active && st.headers_done else { return; }
    if st.resp_off >= st.data_buf.len {
        st.active = false;
        st.data_buf.clear();
        return;
    }
    let written, ok = quic::quic_server_stream_write(
        ep, st.conn_id, st.stream_id, st.data_buf[st.resp_off..], true,
    );
    if !ok {
        st.active = false;
        st.data_buf.clear();
        return;
    }
    st.resp_off = core::add_sat_i64(st.resp_off, written);
    if st.resp_off >= st.data_buf.len {
        st.active = false;
        st.data_buf.clear();
    }
}

fn send_h3_stream_response(
    ep:       quic::QuicServerEndpoint&,
    h3_sess:  http3::H3EdgeSession&,
    st_idx:   i64,
    method:   const u8[:],
    raw_path: const u8[:],
) {
    var ctype: u8[..64] = [];
    var body:  u8[>..]  = [];
    let is_echo = g_streams[st_idx].is_echo;
    let status = build_h3_route_response(method, raw_path, g_streams[st_idx].data_buf[..], is_echo, ctype, body);

    var hdrs = http::HeaderMap { .. };
    http::set_header(hdrs, "content-type", ctype[..]);
    var cl_buf: u8[..24] = [];
    let blen: i64 = body.len;
    blen.format_i64_dec(cl_buf);
    http::set_header(hdrs, "content-length", cl_buf[..]);

    g_tx_tmp.clear();
    guard http3::h3_edge_encode_response_headers(h3_sess, status, hdrs, g_tx_tmp) else {
        g_streams[st_idx].active = false;
        return;
    }
    if method != "HEAD" && body.len > 0 {
        guard http3::h3_edge_encode_data_frame(body[..], g_tx_tmp) else {
            g_streams[st_idx].active = false;
            return;
        }
    }
    guard g_streams[st_idx].data_buf.try_set(g_tx_tmp[..]) else {
        g_streams[st_idx].active = false;
        return;
    }
    g_streams[st_idx].headers_done = true;
    g_streams[st_idx].resp_off = 0;
    flush_stream_tx(ep, st_idx);
}

// ---- QUIC + HTTP/3 Event Engine ------------------------------------------

fn send_h3_server_preambles(ep: quic::QuicServerEndpoint&, conn_id: u64) {
    let srv_settings = fingerprint::H3Settings { .. };
    let srv_cfg = http3::new_server_connection(srv_settings);
    var ctrl_pre: u8[..128] = [];
    var qenc_pre: u8[..16]  = [];
    var qdec_pre: u8[..16]  = [];
    guard http3::encode_server_preambles(srv_cfg, ctrl_pre, qenc_pre, qdec_pre) else { return; }
    let _, _ = quic::quic_server_stream_write(ep, conn_id, 3, ctrl_pre[..], false);
    let _, _ = quic::quic_server_stream_write(ep, conn_id, 7, qenc_pre[..], false);
    let _, _ = quic::quic_server_stream_write(ep, conn_id, 11, qdec_pre[..], false);
}

fn free_stream_entry(conn_id: u64, stream_id: u64) {
    let st_idx = find_or_alloc_stream(conn_id, stream_id, false);
    if st_idx >= 0 {
        g_streams[st_idx].active = false;
        g_streams[st_idx].data_buf.clear();
    }
}

fn handle_h3_event(
    ep:       quic::QuicServerEndpoint&,
    conn_idx: i64,
    conn_id:  u64,
    hev:      const http3::H3EdgeEvent&,
) {
    if hev.kind == http3::H3EdgeEventKind.RequestHead {
        let m = http::get_header(hev.headers, ":method");
        let p = http::get_header(hev.headers, ":path");
        let st_idx = find_or_alloc_stream(conn_id, hev.stream_id, true);
        guard st_idx >= 0 else { return; }
        let _ = g_streams[st_idx].method.try_set(m);
        let _ = g_streams[st_idx].path.try_set(p);
        g_streams[st_idx].is_echo = (m == "POST" && strip_query(p) == "/echo");
        if hev.end_stream {
            send_h3_stream_response(ep, g_conns[conn_idx].h3_sess, st_idx, m, p);
        }
        return;
    }
    if hev.kind == http3::H3EdgeEventKind.RequestData {
        let st_idx = find_or_alloc_stream(conn_id, hev.stream_id, false);
        if st_idx >= 0 && g_streams[st_idx].is_echo && hev.data.len > 0 {
            let _ = g_streams[st_idx].data_buf.try_append(hev.data);
        }
        return;
    }
    if hev.kind == http3::H3EdgeEventKind.RequestEnd {
        let st_idx = find_or_alloc_stream(conn_id, hev.stream_id, false);
        if st_idx >= 0 {
            send_h3_stream_response(
                ep,
                g_conns[conn_idx].h3_sess,
                st_idx,
                g_streams[st_idx].method[..],
                g_streams[st_idx].path[..],
            );
        }
        return;
    }
    if hev.kind == http3::H3EdgeEventKind.StreamReset {
        free_stream_entry(conn_id, hev.stream_id);
        return;
    }
    if hev.kind == http3::H3EdgeEventKind.ProtocolError {
        quic::quic_server_close_conn(ep, conn_id, hev.error_code, "h3 error");
        close_conn_slot(conn_id);
    }
}

fn on_quic_stream_readable(ep: quic::QuicServerEndpoint&, conn_id: u64, stream_id: u64) {
    let conn_idx = find_conn_slot(conn_id);
    guard conn_idx >= 0 else { return; }
    g_rx_tmp.clear();
    var fin = false;
    let n = quic::quic_server_stream_read(ep, conn_id, stream_id, g_rx_tmp, fin);
    guard n >= 0 else { return; }

    let h3 .= g_conns[conn_idx].h3_sess;
    let ok = if (stream_id & 0x02) != 0 {
        http3::h3_edge_feed_uni_stream(h3, stream_id, g_rx_tmp[..], fin)
    } else {
        http3::h3_edge_feed_bidi_stream(h3, stream_id, g_rx_tmp[..], fin)
    };
    if !ok {
        quic::quic_server_close_conn(ep, conn_id, rfc::H3_ERR_FRAME_ERROR, "h3 feed error");
        close_conn_slot(conn_id);
        return;
    }
    var hev = http3::H3EdgeEvent { .. };
    while http3::h3_edge_poll_event(h3, hev) {
        handle_h3_event(ep, conn_idx, conn_id, hev);
    }
}

fn drain_quic_events(ep: quic::QuicServerEndpoint&) {
    var qev = quic::QuicServerEvent { .. };
    while quic::quic_server_poll_event(ep, qev) {
        if qev.kind == quic::QuicServerEventKind.NeedSniCredentials {
            let _ = quic::quic_server_set_credentials_pem(ep, qev.conn_id, g_cert_pem[..], g_key_pem[..]);
        } else if qev.kind == quic::QuicServerEventKind.HandshakeComplete {
            if alloc_conn_slot(qev.conn_id) >= 0 {
                send_h3_server_preambles(ep, qev.conn_id);
            }
        } else if qev.kind == quic::QuicServerEventKind.StreamReadable {
            on_quic_stream_readable(ep, qev.conn_id, qev.stream_id);
        } else if qev.kind == quic::QuicServerEventKind.StreamReset {
            free_stream_entry(qev.conn_id, qev.stream_id);
            let idx = find_conn_slot(qev.conn_id);
            if idx >= 0 {
                http3::h3_edge_reset_stream(g_conns[idx].h3_sess, qev.stream_id);
            }
        } else if qev.kind == quic::QuicServerEventKind.ConnectionClosed {
            close_conn_slot(qev.conn_id);
        }
    }
}

fn pump_quic_egress(ep: quic::QuicServerEndpoint&, sock: i64, now_ns: u64) {
    for i in g_streams.len {
        if g_streams[i].active && g_streams[i].headers_done {
            flush_stream_tx(ep, i);
        }
    }
    var tx_pkt:  u8[..1500] = [];
    var tx_ip:   u8[..64]   = [];
    var tx_port: u16        = 0;
    while quic::quic_server_poll_transmit(ep, now_ns, tx_pkt, tx_ip, tx_port) {
        let _ = net::udp_sendto_dual(sock, tx_pkt[..], tx_ip[..], tx_port);
    }
}

fn drain_udp_ingress(ep: quic::QuicServerEndpoint&, sock: i64, now_ns: u64) {
    var rx_buf:   u8[2048] = [0; 2048];
    var peer_ip:  u8[64]   = [0; 64];
    var peer_ipl: i32      = 0;
    var peer_pt:  u16      = 0;
    var batch:    i64      = 0;
    while batch < 64 {
        let n = net::udp_recvfrom_dual(sock, rx_buf[..], peer_ip[..], peer_ipl, peer_pt);
        guard n > 0 && peer_ipl > 0 else { break; }
        let _ = quic::quic_server_feed_datagram(ep, rx_buf[..n], peer_ip[..peer_ipl], peer_pt, now_ns);
        drain_quic_events(ep);
        batch = core::add_sat_i64(batch, 1);
    }
}

fn calc_poll_wait_ms(ep: const quic::QuicServerEndpoint&, now_ns: u64) -> i64 {
    let next_t = quic::quic_server_next_timeout_ns(ep);
    guard next_t > 0 else { return H3_POLL_MAX_MS; }
    if next_t <= now_ns { return 0; }
    let capped_ns = min(core::sub_sat_u64(next_t, now_ns), 1000000000) as i64;
    let delta_ms = div_euclid(capped_ns, 1000000);
    return max(1, min(delta_ms, H3_POLL_MAX_MS));
}

fn parse_cli_config() -> u16 {
    var port: u16 = 0;
    let env_p = net::get_env_port(0);
    if env_p > 0 {
        port = env_p;
    }
    let a = args();
    if a.len >= 3 && a[1] == "server" {
        let pv, ok_p = a[2].parse_u64_dec();
        if ok_p && pv <= 65535 {
            port = pv as u16;
        }
        if a.len >= 4 {
            let _ = g_www_dir.try_set(a[3]);
        }
    } else if a.len >= 2 {
        let pv, ok_p = a[1].parse_u64_dec();
        if ok_p && pv <= 65535 {
            port = pv as u16;
        }
    }
    return port;
}

fn main() {
    init_server_credentials();
    let bind_port = parse_cli_config();
    let sock = net::udp_open_dual("::", bind_port, 0);
    guard sock > 0 else {
        print("ERROR_FAILED_TO_BIND\n");
        return;
    }
    let port = net::tcp_getsockname_port(sock);
    let alpn_h3: u8[3] = [2, 'h', '3'];
    var ep = quic::quic_server_open(alpn_h3[..], 64, 30000);
    let cfg = net_internal::auto_transport_driver_config();
    var poller = net::new_poller(cfg);
    let _ = net::enable_os_multiplexing(poller);
    let _ = net::poller_register_fd(poller, sock, core::POLL_READ, 1);

    print("READY_PORT:", port, "\n");
    var ready_evs: core::PollReadyEvent[..64] = [];
    while g_running {
        let now_ns = now_monotonic_ns();
        drain_udp_ingress(ep, sock, now_ns);
        let next_t = quic::quic_server_next_timeout_ns(ep);
        if next_t > 0 && now_ns >= next_t {
            quic::quic_server_on_timeout(ep, now_ns);
            drain_quic_events(ep);
        }
        pump_quic_egress(ep, sock, now_ns);
        if g_stop_ns > 0 && now_ns >= g_stop_ns {
            g_running = false;
            break;
        }
        let wait_ms = calc_poll_wait_ms(ep, now_ns);
        if wait_ms > 0 {
            ready_evs.clear();
            let _ = net::poll_events(poller, wait_ms, now_ns, ready_evs);
        }
    }

    quic::quic_server_close(ep);
    net::close_poller(poller);
    net::tcp_close(sock);
}
