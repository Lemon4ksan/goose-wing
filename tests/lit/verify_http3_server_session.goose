// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of Sans-IO Streaming HTTP/3 Server Session (H3EdgeSession),
// server preambles (`encode_server_preambles`), >4 KiB DATA streaming,
// live UDP loopback over QuicServerEndpoint + QuicTlsClient, RFC 9114/9204
// conformance, and Alt-Svc header formatting (RFC 9114, RFC 9204, RFC 7838).
//
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

// ---- Certificate & PEM Test Helpers ----------------------------------------

fn der_push_len<B>(out: B&, len: i64) {
    if len < 128 {
        assert(out.try_push(len as u8));
    } else if len < 256 {
        assert(out.try_push(0x81) && out.try_push(len as u8));
    } else {
        assert(
            out.try_push(0x82) &&
            out.try_push(((len >> 8) & 0xFF) as u8) &&
            out.try_push((len & 0xFF) as u8),
        );
    }
}

fn der_wrap<B>(tag: u8, body: const u8[:], out: B&) {
    out.clear();
    assert(out.try_push(tag));
    der_push_len(out, body.len);
    assert(out.try_append(body));
}

fn der_append_tlv<B>(out: B&, tag: u8, body: const u8[:]) {
    assert(out.try_push(tag));
    der_push_len(out, body.len);
    assert(out.try_append(body));
}

fn der_append_pos_int<B>(out: B&, be: const u8[:]) {
    let needs_pad = be.len > 0 && (be[0] & 0x80) != 0;
    let total = if needs_pad { be.len + 1 } else { be.len };
    assert(out.try_push(rfc::ASN1_TAG_INTEGER));
    der_push_len(out, total);
    if needs_pad { assert(out.try_push(0x00)); }
    assert(out.try_append(be));
}

fn append_pem_block(label: const u8[:], der: const u8[:], out: u8[>..]&) {
    out.append("-----BEGIN ");
    out.append(label);
    out.append("-----\n");
    var b64: u8[>..] = [];
    core::base64_encode(der, b64);
    var pos: i64 = 0;
    while pos < b64.len {
        let end = min(pos + 64, b64.len);
        out.append(b64[pos..end]);
        out.push('\n');
        pos = end;
    }
    out.append("-----END ");
    out.append(label);
    out.append("-----\n");
}

fn encode_name_cn<B>(cn: const u8[:], out: B&) {
    var atv_body: u8[..128] = [];
    der_append_tlv(atv_body, rfc::ASN1_TAG_OID, rfc::OID_COMMON_NAME[..]);
    der_append_tlv(atv_body, rfc::ASN1_TAG_UTF8_STRING, cn);
    var atv: u8[..140] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, atv_body[..], atv);
    var rdn: u8[..148] = [];
    der_wrap(rfc::ASN1_TAG_SET, atv[..], rdn);
    der_wrap(rfc::ASN1_TAG_SEQUENCE, rdn[..], out);
}

fn encode_ext_entry<B>(out: B&, oid: const u8[:], critical: bool, val: const u8[:]) {
    var body: u8[..4096] = [];
    der_append_tlv(body, rfc::ASN1_TAG_OID, oid);
    if critical {
        let crit_val: u8[1] = [0xFF];
        der_append_tlv(body, rfc::ASN1_TAG_BOOLEAN, crit_val[..]);
    }
    der_append_tlv(body, rfc::ASN1_TAG_OCTET_STRING, val);
    der_append_tlv(out, rfc::ASN1_TAG_SEQUENCE, body[..]);
}

fn build_p256_cert_der<B>(
    issuer_priv: const u8[32]&,
    subj_priv:   const u8[32]&,
    issuer_cn:   const u8[:],
    subject_cn:  const u8[:],
    dns_san:     const u8[:],
    out_der:     B&,
) {
    let subj_pub = core::ecdsa_p256_public_key(subj_priv);
    var tbs_body: u8[..4096] = [];
    let ver_v3: u8[3] = [0x02, 0x01, 0x02];
    der_append_tlv(tbs_body, 0xA0, ver_v3[..]);
    let ser: u8[2] = [0x01, 0x19];
    der_append_tlv(tbs_body, rfc::ASN1_TAG_INTEGER, ser[..]);

    var ecdsa_alg: u8[..16] = [];
    der_append_tlv(ecdsa_alg, rfc::ASN1_TAG_OID, rfc::OID_SIG_ECDSA_SHA256[..]);
    der_append_tlv(tbs_body, rfc::ASN1_TAG_SEQUENCE, ecdsa_alg[..]);

    var iss_dn: u8[..160] = [];
    encode_name_cn(issuer_cn, iss_dn);
    assert(tbs_body.try_append(iss_dn[..]));

    var val_body: u8[..64] = [];
    der_append_tlv(val_body, rfc::ASN1_TAG_UTC_TIME, "240101000000Z");
    der_append_tlv(val_body, rfc::ASN1_TAG_UTC_TIME, "351231235959Z");
    der_append_tlv(tbs_body, rfc::ASN1_TAG_SEQUENCE, val_body[..]);

    var sub_dn: u8[..160] = [];
    encode_name_cn(subject_cn, sub_dn);
    assert(tbs_body.try_append(sub_dn[..]));

    var spki_alg: u8[..32] = [];
    der_append_tlv(spki_alg, rfc::ASN1_TAG_OID, rfc::OID_EC_PUBLIC_KEY[..]);
    der_append_tlv(spki_alg, rfc::ASN1_TAG_OID, rfc::OID_SECP256R1[..]);
    var spki_body: u8[..120] = [];
    der_append_tlv(spki_body, rfc::ASN1_TAG_SEQUENCE, spki_alg[..]);
    var pk_bits: u8[66] = [0; 66];
    for i in 65 { pk_bits[i + 1] = subj_pub[i]; }
    der_append_tlv(spki_body, rfc::ASN1_TAG_BIT_STRING, pk_bits[..]);
    der_append_tlv(tbs_body, rfc::ASN1_TAG_SEQUENCE, spki_body[..]);

    var exts_body: u8[..1024] = [];
    let ku_dig: u8[4] = [0x03, 0x02, 0x07, 0x80];
    encode_ext_entry(exts_body, rfc::OID_KEY_USAGE[..], false, ku_dig[..]);
    if dns_san.len > 0 {
        var san_inner: u8[..128] = [];
        der_append_tlv(san_inner, 0x82, dns_san);
        var san_seq: u8[..140] = [];
        der_wrap(rfc::ASN1_TAG_SEQUENCE, san_inner[..], san_seq);
        encode_ext_entry(exts_body, rfc::OID_SUBJECT_ALT_NAME[..], false, san_seq[..]);
    }
    var exts_seq: u8[..1080] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, exts_body[..], exts_seq);
    der_append_tlv(tbs_body, 0xA3, exts_seq[..]);

    var tbs_der: u8[..4040] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, tbs_body[..], tbs_der);
    let raw_sig = core::ecdsa_p256_sign(issuer_priv, tbs_der[..]);
    var der_sig: u8[..72] = [];
    assert(core::ecdsa_p256_encode_der_sig(raw_sig, der_sig));

    var cert_body: u8[..4096] = [];
    assert(cert_body.try_append(tbs_der[..]));
    der_append_tlv(cert_body, rfc::ASN1_TAG_SEQUENCE, ecdsa_alg[..]);
    var sig_bits: u8[..80] = [];
    assert(sig_bits.try_push(0x00) && sig_bits.try_append(der_sig[..]));
    der_append_tlv(cert_body, rfc::ASN1_TAG_BIT_STRING, sig_bits[..]);
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
    var b_ec_seq: u8[..256] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, b_ec.buf[..], b_ec_seq);

    var b_pki: u8[..512] = [];
    let zero_v: u8[1] = [0x00];
    der_append_pos_int(b_pki, zero_v[..]);
    var alg_body: u8[..32] = [];
    der_append_tlv(alg_body, rfc::ASN1_TAG_OID, rfc::OID_EC_PUBLIC_KEY[..]);
    der_append_tlv(alg_body, rfc::ASN1_TAG_OID, rfc::OID_SECP256R1[..]);
    der_append_tlv(b_pki, rfc::ASN1_TAG_SEQUENCE, alg_body[..]);
    der_append_tlv(b_pki, rfc::ASN1_TAG_OCTET_STRING, b_ec_seq[..]);

    var pkcs8_der: u8[..512] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, b_pki[..], pkcs8_der);
    append_pem_block("PRIVATE KEY", pkcs8_der[..], out_pem);
}

// ---- Minimal Loopback QUIC + H3 Client Harness ------------------------------

struct ClientRxStream {
    stream_id: u64                  = 0,
    fin:       bool                 = false,
    contig:    u64                  = 0,
    final_sz:  u64                  = 0,
    intervals: quic::Interval[..64] = [],
    buf:       u8[..8192]           = [],
}

struct LoopbackH3Client {
    fd:              i64                  = -1,
    dst_ip:          u8[..64]             = [],
    dst_port:        u16                  = 0,
    conn:            quic::QuicConnection = quic::QuicConnection { .. },
    tls_cli:         tls::QuicTlsClient   = tls::QuicTlsClient { .. },
    h3_conn:         http3::Connection    = http3::Connection { .. },
    next_init_pn:    u64                  = 0,
    next_hs_pn:      u64                  = 0,
    next_app_pn:     u64                  = 0,
    init_crypto_off: u64                  = 0,
    hs_crypto_off:   u64                  = 0,
    hs_ack_needed:   bool                 = false,
    app_ack_needed:  bool                 = false,
    hs_done_seen:    bool                 = false,
    uni3_buf:        u8[..512]            = [],
    uni7_buf:        u8[..64]             = [],
    uni11_buf:       u8[..64]             = [],
    uni3_fin:        bool                 = false,
    uni7_fin:        bool                 = false,
    uni11_fin:       bool                 = false,
    tx_max_data:     u64                  = 262144,
    tx_max_sd:       u64                  = 262144,
    rx_streams:      ClientRxStream[>..]  = [],
}

fn find_or_add_cli_rx(c: LoopbackH3Client&, stream_id: u64) -> i64 {
    for i in c.rx_streams.len {
        if c.rx_streams[i].stream_id == stream_id {
            return i;
        }
    }
    let idx = c.rx_streams.len;
    c.rx_streams.push(ClientRxStream { stream_id: stream_id, .. });
    return idx;
}

fn cli_record_rx_bytes(c: LoopbackH3Client&, stream_id: u64, offset: u64, data: const u8[:], fin: bool) {
    if stream_id == 3 {
        let _ = c.uni3_buf.try_append(data);
        if fin { c.uni3_fin = true; }
        return;
    }
    if stream_id == 7 {
        let _ = c.uni7_buf.try_append(data);
        if fin { c.uni7_fin = true; }
        return;
    }
    if stream_id == 11 {
        let _ = c.uni11_buf.try_append(data);
        if fin { c.uni11_fin = true; }
        return;
    }

    let idx = find_or_add_cli_rx(c, stream_id);
    let st .= c.rx_streams[idx];
    let end_off = offset + (data.len as u64);
    if data.len > 0 {
        let needed = end_off as i64;
        if st.buf.len < needed {
            assert(needed <= 8192);
            while st.buf.len < needed {
                assert(st.buf.try_push(0));
            }
        }
        for i in data.len {
            st.buf[(offset as i64) + i] = data[i];
        }
        var cur_s = offset;
        var cur_e = end_off;
        var pos: i64 = 0;
        while pos < st.intervals.len {
            let it = st.intervals[pos];
            if cur_e < it.start {
                st.intervals.insert_at(pos, quic::Interval { start: cur_s, end: cur_e });
                break;
            }
            if cur_s > it.end {
                pos += 1;
                continue;
            }
            cur_s = min(cur_s, it.start);
            cur_e = max(cur_e, it.end);
            st.intervals.remove_at(pos);
        }
        if pos == st.intervals.len {
            let _ = st.intervals.try_push(quic::Interval { start: cur_s, end: cur_e });
        }
        if st.intervals.len > 0 && st.intervals[0].start == 0 {
            st.contig = st.intervals[0].end;
        }
    }
    if fin {
        st.fin = true;
        st.final_sz = end_off;
    }
}

fn cli_install_secrets(c: LoopbackH3Client&) {
    var sec = tls::QuicTlsSecrets { .. };
    while tls::quic_tls_client_take_secrets(c.tls_cli, sec) {
        if sec.has_read {
            assert(quic::install_tls_secret(c.conn, sec.level, true, sec.read_secret[..], sec.cipher_suite));
        }
        if sec.has_write {
            assert(quic::install_tls_secret(c.conn, sec.level, false, sec.write_secret[..], sec.cipher_suite));
        }
    }
}

fn cli_inspect_plain(c: LoopbackH3Client&, plain: const u8[:]) {
    var idx: i64 = 0;
    while idx < plain.len {
        let f, ok = quic::decode_frame_cursor(plain, idx);
        if !ok { break; }
        if f.frame_type == quic::QuicFrameType.HandshakeDone {
            c.hs_done_seen = true;
        } else if f.frame_type == quic::QuicFrameType.MaxData {
            if f.max_data > c.tx_max_data { c.tx_max_data = f.max_data; }
        } else if f.frame_type == quic::QuicFrameType.MaxStreamData {
            if f.max_data > c.tx_max_sd { c.tx_max_sd = f.max_data; }
        } else if f.frame_type == quic::QuicFrameType.Stream {
            cli_record_rx_bytes(c, f.stream_id, f.offset, f.payload, f.fin);
        }
    }
}

fn cli_feed_dgram(c: LoopbackH3Client&, dgram: const u8[:], now_us: u64) {
    var off: i64 = 0;
    while off < dgram.len {
        var ack = quic::AckFrame { .. };
        var plain: u8[..16384] = [];
        var htype = quic::QuicHeaderType.Initial;
        let consumed, res = quic::process_coalesced_packet(c.conn, dgram[off..], dgram.len, now_us, ack, plain, htype);
        if !res.handled || consumed <= 0 { break; }
        if htype == quic::QuicHeaderType.Initial {
            let hdr, ok_h = quic_internal::parse_quic_long_header(
                dgram[off..], dgram[off], quic_internal::QuicHeaderOptions { is_masked: true, .. },
            );
            if ok_h && hdr.scid.len > 0 {
                let _ = c.conn.dcid.try_set(hdr.scid[..]);
            }
        } else if htype == quic::QuicHeaderType.Handshake {
            if res.needs_ack { c.hs_ack_needed = true; }
        } else if htype == quic::QuicHeaderType.OneRtt {
            if res.needs_ack { c.app_ack_needed = true; }
            cli_inspect_plain(c, plain[..]);
        }
        if htype == quic::QuicHeaderType.Initial && c.conn.initial_crypto.buf.len > 0 {
            let st = tls::quic_tls_client_provide_crypto(
                c.tls_cli, tls::QuicTlsLevel.Initial, c.conn.initial_crypto.buf[..],
            );
            c.conn.initial_crypto.buf.clear();
            assert(st == tls::QuicTlsStatus.Ok);
            cli_install_secrets(c);
        }
        if htype == quic::QuicHeaderType.Handshake && c.conn.handshake_crypto.buf.len > 0 {
            let st = tls::quic_tls_client_provide_crypto(
                c.tls_cli, tls::QuicTlsLevel.Handshake, c.conn.handshake_crypto.buf[..],
            );
            c.conn.handshake_crypto.buf.clear();
            assert(st == tls::QuicTlsStatus.Ok || st == tls::QuicTlsStatus.WantMore || st == tls::QuicTlsStatus.Established);
            cli_install_secrets(c);
        }
        off += consumed;
    }
}

fn cli_send_1rtt(c: LoopbackH3Client&, plain: const u8[:], ack_el: bool, now_us: u64) {
    var pbuf: u8[..1400] = [];
    assert(pbuf.try_append(plain));
    while pbuf.len < 4 { assert(quic::encode_padding_frame(pbuf, 1)); }
    var hdr = quic::QuicHeader {
        header_type:   quic::QuicHeaderType.OneRtt,
        packet_number: c.next_app_pn,
        ..
    };
    assert(hdr.dcid.try_set(c.conn.dcid[..]));
    var pkt: u8[..1500] = [];
    assert(quic::seal_packet_tracked(c.conn.tx_app_space, hdr, 2, pbuf[..], pkt));
    quic::record_sent(c.conn, quic::PnSpaceId.ApplicationData, c.next_app_pn, pkt.len as u64, ack_el, now_us);
    c.next_app_pn += 1;
    assert(net::udp_sendto_dual(c.fd, pkt[..], c.dst_ip[..], c.dst_port) == (pkt.len as i32));
}

fn cli_send_stream_chunk(
    c:         LoopbackH3Client&,
    stream_id: u64,
    offset:    u64,
    data:      const u8[:],
    fin:       bool,
    now_us:    u64,
) {
    var pos: i64 = 0;
    while pos < data.len || (fin && pos == data.len) {
        let take = min(1150, data.len - pos);
        let send_fin = fin && (pos + take == data.len);
        var plain: u8[..1300] = [];
        let flags = quic::QuicStreamFlags { fin: send_fin, with_len: true, .. };
        assert(quic::encode_stream_frame(stream_id, offset + (pos as u64), data[pos..(pos + take)], plain, flags));
        cli_send_1rtt(c, plain[..], true, now_us);
        pos += take;
        if pos >= data.len { break; }
    }
}

fn pump_srv_to_cli_udp(
    ep:     quic::QuicServerEndpoint&,
    srv_fd: i64,
    c:      LoopbackH3Client&,
    now_ns: u64,
) -> i64 {
    var cnt:     i64        = 0;
    var out_pkt: u8[..1500] = [];
    var out_ip:  u8[..64]   = [];
    var out_p:   u16        = 0;
    var rx_buf:  u8[2048]   = [0; 2048];
    var rip:     u8[64]     = [0; 64];
    var ripl:    i32        = 0;
    var rp:      u16        = 0;
    while quic::quic_server_poll_transmit(ep, now_ns, out_pkt, out_ip, out_p) {
        assert(net::udp_sendto_dual(srv_fd, out_pkt[..], out_ip[..], out_p) == (out_pkt.len as i32));
        let nr = net::udp_recvfrom_dual(c.fd, rx_buf[..], rip[..], ripl, rp);
        if nr > 0 {
            cli_feed_dgram(c, rx_buf[..nr], now_ns / 1000);
        }
        cnt += 1;
    }
    return cnt;
}

fn cli_flush_ack(c: LoopbackH3Client&, now_us: u64) {
    if !c.app_ack_needed || c.conn.app_space.recv_ranges.len == 0 {
        return;
    }
    let ack, ok_a = quic::build_ack_frame(c.conn.app_space.recv_ranges, 0);
    if ok_a {
        var plain: u8[..256] = [];
        if quic::encode_ack_frame(ack, plain) {
            cli_send_1rtt(c, plain[..], false, now_us);
        }
    }
    c.app_ack_needed = false;
}

fn drain_srv_to_cli_udp(
    ep:     quic::QuicServerEndpoint&,
    srv_fd: i64,
    c:      LoopbackH3Client&,
    now_ns: u64&,
) -> i64 {
    var total: i64 = 0;
    for _ in 32 {
        now_ns += 5000000;
        let n = pump_srv_to_cli_udp(ep, srv_fd, c, now_ns);
        total += n;
        if n == 0 {
            break;
        }
    }
    cli_flush_ack(c, now_ns / 1000);
    return total;
}

fn pump_udp_to_srv_and_h3(
    srv_fd:  i64,
    ep:      quic::QuicServerEndpoint&,
    h3_sess: http3::H3EdgeSession&,
    now_ns:  u64,
) {
    var rx_buf: u8[2048] = [0; 2048];
    var rip:    u8[64]   = [0; 64];
    var ripl:   i32      = 0;
    var rp:     u16      = 0;
    while true {
        let nr = net::udp_recvfrom_dual(srv_fd, rx_buf[..], rip[..], ripl, rp);
        if nr <= 0 { break; }
        assert(quic::quic_server_feed_datagram(ep, rx_buf[..nr], rip[..ripl], rp, now_ns));
    }

    var qev = quic::QuicServerEvent { .. };
    var stream_rx: u8[>..] = [];
    while quic::quic_server_poll_event(ep, qev) {
        if qev.kind == quic::QuicServerEventKind.StreamReadable {
            stream_rx.clear();
            var fin = false;
            let nr = quic::quic_server_stream_read(ep, qev.conn_id, qev.stream_id, stream_rx, fin);
            assert(nr >= 0);
            if (qev.stream_id & 0x03) == 2 {
                assert(http3::h3_edge_feed_uni_stream(h3_sess, qev.stream_id, stream_rx[..], fin));
            } else if (qev.stream_id & 0x03) == 0 {
                assert(http3::h3_edge_feed_bidi_stream(h3_sess, qev.stream_id, stream_rx[..], fin));
            }
        } else if qev.kind == quic::QuicServerEventKind.StreamReset {
            http3::h3_edge_reset_stream(h3_sess, qev.stream_id);
        }
    }
}

// ---- Test 1: Live End-to-End HTTP/3 Over UDP Loopback ----------------------

fn encode_cli_qpack_req(
    method:     const u8[:],
    path:       const u8[:],
    authority:  const u8[:],
    extra_name: const u8[:],
    extra_val:  const u8[:],
    cl_val:     const u8[:],
    out_frame:  u8[>..]&,
) {
    var sec: u8[..1024] = [0x00, 0x00];
    assert(http3::encode_qpack_field(sec, ":method", method));
    assert(http3::encode_qpack_field(sec, ":scheme", "https"));
    assert(http3::encode_qpack_field(sec, ":authority", authority));
    assert(http3::encode_qpack_field(sec, ":path", path));
    if extra_name.len > 0 {
        assert(http3::encode_qpack_field(sec, extra_name, extra_val));
    }
    if cl_val.len > 0 {
        assert(http3::encode_qpack_field(sec, "content-length", cl_val));
    }
    assert(http3::encode_headers_frame(out_frame, sec[..]));
}

fn test_live_h3_loopback_e2e() {
    let srv_fd = net::udp_open_dual("::", 0, 0);
    assert(srv_fd > 0);
    defer net::tcp_close(srv_fd);
    let srv_port = net::tcp_getsockname_port(srv_fd);
    assert(srv_port > 0);

    var ep = quic::quic_server_open("\x02h3", 16, 30000);
    defer quic::quic_server_close(ep);

    var h3_sess = http3::h3_edge_open();
    defer http3::h3_edge_close(h3_sess);
    assert(h3_sess.slot_idx >= 0 && h3_sess.generation != 0);

    var priv:     u8[32]     = [0x61; 32];
    var cert_der: u8[..4096] = [];
    build_p256_cert_der(priv, priv, "h3.example.test", "h3.example.test", "h3.example.test", cert_der);
    var cert_pem: u8[>..] = [];
    append_pem_block("CERTIFICATE", cert_der[..], cert_pem);
    var key_pem: u8[>..] = [];
    build_p256_pkcs8_pem(priv, key_pem);

    var c = LoopbackH3Client { fd: net::udp_open_dual("127.0.0.1", 0, 0), .. };
    assert(c.fd > 0);
    defer {
        tls::quic_tls_client_close(c.tls_cli);
        net::tcp_close(c.fd);
    };
    assert(c.dst_ip.try_set("127.0.0.1"));
    c.dst_port = srv_port;
    let odcid: u8[8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
    let scid:  u8[4] = [0x41, 0x42, 0x43, 0x44];
    c.conn = quic::new_client_connection(odcid[..], scid[..]);
    assert(quic::install_initial_keys(c.conn, odcid[..]));
    let cli_h3_cfg = fingerprint::H3Settings { .. };
    c.h3_conn = http3::new_client_connection(cli_h3_cfg);

    var tp = quic::QuicTransportParams {
        max_idle_timeout:                    30000,
        max_udp_payload_size:                1500,
        initial_max_data:                    262144,
        initial_max_stream_data_bidi_local:  262144,
        initial_max_stream_data_bidi_remote: 262144,
        initial_max_stream_data_uni:         16384,
        initial_max_streams_bidi:            16,
        initial_max_streams_uni:             16,
        active_connection_id_limit:          4,
        ..
    };
    assert(tp.initial_source_connection_id.try_set(scid[..]));
    var tp_wire: u8[..256] = [];
    assert(quic::encode_transport_params(tp, false, tp_wire));
    c.tls_cli = tls::quic_tls_client_open("h3.example.test", "\x02h3", tp_wire[..], cert_pem[..]);
    assert(tls::quic_tls_client_start(c.tls_cli) == tls::QuicTlsStatus.Ok);

    // 1. QUIC + TLS 1.3 handshake over UDP
    var now_ns: u64     = 1000000000;
    var ch:     u8[>..] = [];
    let ch_n = tls::quic_tls_client_drain_crypto(c.tls_cli, tls::QuicTlsLevel.Initial, ch);
    assert(ch_n > 0);
    var init_plain: u8[..1300] = [];
    assert(quic::encode_crypto_frame(0, ch[..], init_plain));
    let min_plain = 1200 - (7 + c.conn.dcid.len + c.conn.scid.len + 1 + 2 + 2 + 16);
    if init_plain.len < min_plain {
        assert(quic::encode_padding_frame(init_plain, (min_plain - init_plain.len) as u64));
    }
    var ihdr = quic::QuicHeader {
        header_type: quic::QuicHeaderType.Initial,
        version:     rfc::QUIC_VERSION_1,
        ..
    };
    assert(ihdr.dcid.try_set(c.conn.dcid[..]));
    assert(ihdr.scid.try_set(c.conn.scid[..]));
    var ipkt: u8[..1500] = [];
    assert(quic::seal_packet_tracked(c.conn.tx_initial_space, ihdr, 2, init_plain[..], ipkt));
    quic::record_sent(c.conn, quic::PnSpaceId.Initial, 0, ipkt.len as u64, true, now_ns / 1000);
    c.next_init_pn += 1;
    assert(net::udp_sendto_dual(c.fd, ipkt[..], c.dst_ip[..], c.dst_port) == (ipkt.len as i32));

    var rx_buf: u8[2048] = [0; 2048];
    var rip:    u8[64]   = [0; 64];
    var ripl:   i32      = 0;
    var rp:     u16      = 0;
    let nr_i = net::udp_recvfrom_dual(srv_fd, rx_buf[..], rip[..], ripl, rp);
    assert(nr_i >= 1200);
    assert(quic::quic_server_feed_datagram(ep, rx_buf[..nr_i], rip[..ripl], rp, now_ns));

    var qev = quic::QuicServerEvent { .. };
    var conn_id: u64 = 0;
    while quic::quic_server_poll_event(ep, qev) {
        if qev.kind == quic::QuicServerEventKind.NeedSniCredentials {
            conn_id = qev.conn_id;
            assert(quic::quic_server_set_credentials_pem(ep, conn_id, cert_pem[..], key_pem[..]));
        }
    }
    assert(conn_id != 0);

    now_ns += 5000000;
    assert(pump_srv_to_cli_udp(ep, srv_fd, c, now_ns) >= 1);

    var hs_out: u8[>..] = [];
    let n_hs = tls::quic_tls_client_drain_crypto(c.tls_cli, tls::QuicTlsLevel.Handshake, hs_out);
    var hs_plain: u8[..512] = [];
    if c.hs_ack_needed && c.conn.handshake_space.recv_ranges.len > 0 {
        let ack, ok_a = quic::build_ack_frame(c.conn.handshake_space.recv_ranges, 0);
        if ok_a { assert(quic::encode_ack_frame(ack, hs_plain)); }
        c.hs_ack_needed = false;
    }
    if n_hs > 0 {
        assert(quic::encode_crypto_frame(0, hs_out[..], hs_plain));
    }
    while hs_plain.len < 4 { assert(quic::encode_padding_frame(hs_plain, 1)); }
    var hhdr = quic::QuicHeader {
        header_type:   quic::QuicHeaderType.Handshake,
        version:       rfc::QUIC_VERSION_1,
        packet_number: c.next_hs_pn,
        ..
    };
    assert(hhdr.dcid.try_set(c.conn.dcid[..]));
    assert(hhdr.scid.try_set(c.conn.scid[..]));
    var hpkt: u8[..1500] = [];
    assert(quic::seal_packet_tracked(c.conn.tx_handshake_space, hhdr, 2, hs_plain[..], hpkt));
    quic::record_sent(c.conn, quic::PnSpaceId.Handshake, hhdr.packet_number, hpkt.len as u64, true, now_ns / 1000);
    c.next_hs_pn += 1;
    assert(net::udp_sendto_dual(c.fd, hpkt[..], c.dst_ip[..], c.dst_port) == (hpkt.len as i32));

    now_ns += 5000000;
    let nr_h = net::udp_recvfrom_dual(srv_fd, rx_buf[..], rip[..], ripl, rp);
    assert(nr_h > 0);
    assert(quic::quic_server_feed_datagram(ep, rx_buf[..nr_h], rip[..ripl], rp, now_ns));
    var hs_complete = false;
    while quic::quic_server_poll_event(ep, qev) {
        if qev.kind == quic::QuicServerEventKind.HandshakeComplete {
            hs_complete = true;
        }
    }
    assert(hs_complete);

    // 2. Server emits HTTP/3 preambles (Control 3, QPACK Enc 7, QPACK Dec 11) via encode_server_preambles
    let srv_settings = fingerprint::H3Settings { .. };
    let srv_h3_cfg = http3::new_server_connection(srv_settings);
    var srv_ctrl_pre: u8[..128] = [];
    var srv_qenc_pre: u8[..16]  = [];
    var srv_qdec_pre: u8[..16]  = [];
    assert(http3::encode_server_preambles(srv_h3_cfg, srv_ctrl_pre, srv_qenc_pre, srv_qdec_pre));

    let w3, ok3 = quic::quic_server_stream_write(ep, conn_id, 3, srv_ctrl_pre[..], false);
    let w7, ok7 = quic::quic_server_stream_write(ep, conn_id, 7, srv_qenc_pre[..], false);
    let w11, ok11 = quic::quic_server_stream_write(ep, conn_id, 11, srv_qdec_pre[..], false);
    assert(ok3 && w3 == srv_ctrl_pre.len && ok7 && w7 == srv_qenc_pre.len && ok11 && w11 == srv_qdec_pre.len);

    now_ns += 5000000;
    assert(pump_srv_to_cli_udp(ep, srv_fd, c, now_ns) >= 1);
    assert(c.hs_done_seen);
    assert(!c.uni3_fin && c.uni3_buf.len > 0);
    assert(!c.uni7_fin && c.uni7_buf.len == 1 && c.uni7_buf[0] == rfc::H3_STREAM_QPACK_ENCODER);
    assert(!c.uni11_fin && c.uni11_buf.len == 1 && c.uni11_buf[0] == rfc::H3_STREAM_QPACK_DECODER);

    assert(http3::handle_stream_data(c.h3_conn, 3, false, c.uni3_buf[..], false) == rfc::H3_ERR_NO_ERROR);
    assert(http3::handle_stream_data(c.h3_conn, 7, false, c.uni7_buf[..], false) == rfc::H3_ERR_NO_ERROR);
    assert(http3::handle_stream_data(c.h3_conn, 11, false, c.uni11_buf[..], false) == rfc::H3_ERR_NO_ERROR);
    assert(c.h3_conn.peer_settings_received);

    // 3. Client sends its H3 preambles on uni streams 2, 6, 10
    let u2, _, ok_u2 = quic::open_local_stream(c.conn.stream_table, false, 16384);
    let u6, _, ok_u6 = quic::open_local_stream(c.conn.stream_table, false, 16384);
    let u10, _, ok_u10 = quic::open_local_stream(c.conn.stream_table, false, 16384);
    assert(ok_u2 && u2 == 2 && ok_u6 && u6 == 6 && ok_u10 && u10 == 10);
    var cli_ctrl_pre: u8[..128] = [];
    var cli_qenc_pre: u8[..16]  = [];
    var cli_qdec_pre: u8[..16]  = [];
    assert(http3::encode_client_preambles(c.h3_conn, cli_ctrl_pre, cli_qenc_pre, cli_qdec_pre));
    cli_send_stream_chunk(c, 2, 0, cli_ctrl_pre[..], false, now_ns / 1000);
    cli_send_stream_chunk(c, 6, 0, cli_qenc_pre[..], false, now_ns / 1000);
    cli_send_stream_chunk(c, 10, 0, cli_qdec_pre[..], false, now_ns / 1000);
    pump_udp_to_srv_and_h3(srv_fd, ep, h3_sess, now_ns);

    // 4. Open 3 concurrent bidi streams:
    //    Stream 0: GET /hello (small)
    //    Stream 4: POST /upload (64 KiB single DATA frame!)
    //    Stream 8: GET /events (incremental SSE before fin=true)
    let b0, _, ok_b0_st = quic::open_local_stream(c.conn.stream_table, true, 262144);
    let b4, _, ok_b4_st = quic::open_local_stream(c.conn.stream_table, true, 262144);
    let b8, _, ok_b8_st = quic::open_local_stream(c.conn.stream_table, true, 262144);
    assert(ok_b0_st && b0 == 0 && ok_b4_st && b4 == 4 && ok_b8_st && b8 == 8);
    var req0: u8[>..] = [];
    encode_cli_qpack_req("GET", "/hello", "h3.example.test", "x-req", "alpha", "", req0);
    var req4: u8[>..] = [];
    encode_cli_qpack_req("POST", "/upload", "h3.example.test", "content-type", "application/octet-stream", "65536", req4);
    var req8: u8[>..] = [];
    encode_cli_qpack_req("GET", "/events", "h3.example.test", "accept", "text/event-stream", "", req8);

    cli_send_stream_chunk(c, 0, 0, req0[..], true, now_ns / 1000);
    cli_send_stream_chunk(c, 4, 0, req4[..], false, now_ns / 1000);
    cli_send_stream_chunk(c, 8, 0, req8[..], true, now_ns / 1000);

    now_ns += 5000000;
    pump_udp_to_srv_and_h3(srv_fd, ep, h3_sess, now_ns);

    var saw_h0 = false;
    var saw_h4 = false;
    var saw_h8 = false;
    var hev = http3::H3EdgeEvent { .. };
    while http3::h3_edge_poll_event(h3_sess, hev) {
        assert(hev.kind == http3::H3EdgeEventKind.RequestHead);
        if hev.stream_id == 0 {
            assert(hev.end_stream);
            assert(http::get_header(hev.headers, ":method") == "GET");
            assert(http::get_header(hev.headers, ":path") == "/hello");
            assert(http::get_header(hev.headers, "x-req") == "alpha");
            saw_h0 = true;
        } else if hev.stream_id == 4 {
            assert(!hev.end_stream);
            assert(http::get_header(hev.headers, ":method") == "POST");
            assert(http::get_header(hev.headers, "content-length") == "65536");
            saw_h4 = true;
        } else {
            assert(hev.stream_id == 8 && hev.end_stream);
            assert(http::get_header(hev.headers, ":path") == "/events");
            saw_h8 = true;
        }
    }
    assert(saw_h0 && saw_h4 && saw_h8);

    // 4a. Stream 0 response with Alt-Svc header
    var alt_val: u8[..64] = [];
    http::format_altsvc_header(alt_val, "h3", 443, 86400, false);
    assert(alt_val[..] == "h3=\":443\"; ma=86400");

    var resp0_hdrs = http::HeaderMap { .. };
    assert(http::append_header(resp0_hdrs, "content-type", "text/plain"));
    assert(http::append_header(resp0_hdrs, "alt-svc", alt_val[..]));
    var resp0_wire: u8[>..] = [];
    assert(http3::h3_edge_encode_response_headers(h3_sess, 200, resp0_hdrs, resp0_wire));
    assert(http3::h3_edge_encode_data_frame("hello-h3", resp0_wire));
    let w0, ok0 = quic::quic_server_stream_write(ep, conn_id, 0, resp0_wire[..], true);
    assert(ok0 && w0 == resp0_wire.len);

    // 4b. Stream 8 SSE headers flushed BEFORE DATA and BEFORE fin=true
    var sse_hdrs = http::HeaderMap { .. };
    assert(http::append_header(sse_hdrs, "content-type", "text/event-stream"));
    var sse_wire: u8[>..] = [];
    assert(http3::h3_edge_encode_response_headers(h3_sess, 200, sse_hdrs, sse_wire));
    let w8h, ok8h = quic::quic_server_stream_write(ep, conn_id, 8, sse_wire[..], false);
    assert(ok8h && w8h == sse_wire.len);

    assert(drain_srv_to_cli_udp(ep, srv_fd, c, now_ns) >= 1);
    pump_udp_to_srv_and_h3(srv_fd, ep, h3_sess, now_ns);

    // Verify client receives Stream 0 complete response and Stream 8 SSE headers BEFORE fin=true!
    let idx_r0 = find_or_add_cli_rx(c, 0);
    assert(c.rx_streams[idx_r0].fin);
    let sid_r0, ok_r0 = http3::open_request_stream(c.h3_conn);
    assert(ok_r0 && sid_r0 == 0);
    assert(http3::handle_stream_data(c.h3_conn, 0, true, c.rx_streams[idx_r0].buf[..], true) == rfc::H3_ERR_NO_ERROR);
    let sc0, ok_sc0 = http3::get_status_code(c.h3_conn, 0);
    assert(ok_sc0 && sc0 == 200);
    var r0_h = http::HeaderMap { .. };
    assert(http3::copy_stream_headers(c.h3_conn, 0, r0_h));
    assert(http::get_header(r0_h, "alt-svc") == "h3=\":443\"; ma=86400");
    let body0, ok_b0 = http3::get_response_body(c.h3_conn, 0);
    assert(ok_b0 && body0 == "hello-h3");

    let idx_r8 = find_or_add_cli_rx(c, 8);
    assert(!c.rx_streams[idx_r8].fin && c.rx_streams[idx_r8].contig > 0);
    let sid_r4, _ = http3::open_request_stream(c.h3_conn);
    let sid_r8, _ = http3::open_request_stream(c.h3_conn);
    assert(sid_r4 == 4 && sid_r8 == 8);
    var r8_consumed = c.rx_streams[idx_r8].contig as i64;
    assert(http3::handle_stream_data(c.h3_conn, 8, true, c.rx_streams[idx_r8].buf[..r8_consumed], false) == rfc::H3_ERR_NO_ERROR);
    let sc8, ok_sc8 = http3::get_status_code(c.h3_conn, 8);
    assert(ok_sc8 && sc8 == 200);

    // Flush SSE chunk 1 incrementally (fin = false!)
    sse_wire.clear();
    assert(http3::h3_edge_encode_data_frame("data: tick-1\n\n", sse_wire));
    let w8c1, ok8c1 = quic::quic_server_stream_write(ep, conn_id, 8, sse_wire[..], false);
    assert(ok8c1 && w8c1 == sse_wire.len);
    assert(drain_srv_to_cli_udp(ep, srv_fd, c, now_ns) >= 1);
    pump_udp_to_srv_and_h3(srv_fd, ep, h3_sess, now_ns);
    let r8_next1 = c.rx_streams[idx_r8].contig as i64;
    assert(!c.rx_streams[idx_r8].fin && r8_next1 > r8_consumed);
    assert(http3::handle_stream_data(
        c.h3_conn, 8, true, c.rx_streams[idx_r8].buf[r8_consumed..r8_next1], false,
    ) == rfc::H3_ERR_NO_ERROR);
    r8_consumed = r8_next1;
    let sse_b1, ok_sb1 = http3::get_response_body(c.h3_conn, 8);
    assert(ok_sb1 && sse_b1 == "data: tick-1\n\n");

    // Flush SSE chunk 2 with fin = true
    sse_wire.clear();
    assert(http3::h3_edge_encode_data_frame("data: tick-2\n\n", sse_wire));
    let w8c2, ok8c2 = quic::quic_server_stream_write(ep, conn_id, 8, sse_wire[..], true);
    assert(ok8c2 && w8c2 == sse_wire.len);
    assert(drain_srv_to_cli_udp(ep, srv_fd, c, now_ns) >= 1);
    pump_udp_to_srv_and_h3(srv_fd, ep, h3_sess, now_ns);
    let r8_next2 = c.rx_streams[idx_r8].contig as i64;
    assert(c.rx_streams[idx_r8].fin && r8_next2 > r8_consumed);
    assert(http3::handle_stream_data(
        c.h3_conn, 8, true, c.rx_streams[idx_r8].buf[r8_consumed..r8_next2], true,
    ) == rfc::H3_ERR_NO_ERROR);
    let sse_b2, ok_sb2 = http3::get_response_body(c.h3_conn, 8);
    assert(ok_sb2 && sse_b2 == "data: tick-1\n\ndata: tick-2\n\n");

    // 4c. Stream 4: 64 KiB streaming POST inside a SINGLE 65,536-byte DATA frame over UDP!
    var post_body: u8[>..] = [];
    for i in 65536 {
        post_body.push(((i * 73 + 19) & 0xFF) as u8);
    }
    var post_frame: u8[>..] = [];
    assert(http3::h3_edge_encode_data_frame(post_body[..], post_frame));
    assert(post_frame.len == 65541); // 1 byte type (0x00) + 4 byte varint length (65536) + 65536 payload

    var srv_post_rx: u8[>..] = [];
    var srv_post_end = false;
    var post_off: i64 = 0;
    var req4_off = req4.len as u64;
    for _ in 120 {
        if post_off < post_frame.len {
            let take = min(2300, post_frame.len - post_off);
            let is_fin = (post_off + take) == post_frame.len;
            cli_send_stream_chunk(c, 4, req4_off + (post_off as u64), post_frame[post_off..(post_off + take)], is_fin, now_ns / 1000);
            post_off += take;
        }
        now_ns += 2000000;
        pump_udp_to_srv_and_h3(srv_fd, ep, h3_sess, now_ns);
        while http3::h3_edge_poll_event(h3_sess, hev) {
            if hev.kind == http3::H3EdgeEventKind.RequestData {
                assert(hev.stream_id == 4 && hev.data.len > 0);
                srv_post_rx.append(hev.data);
            } else if hev.kind == http3::H3EdgeEventKind.RequestEnd {
                assert(hev.stream_id == 4 && hev.end_stream);
                srv_post_end = true;
            }
        }
        let _ = pump_srv_to_cli_udp(ep, srv_fd, c, now_ns);
        if srv_post_end { break; }
    }
    assert(srv_post_end && srv_post_rx.len == 65536 && srv_post_rx[..] == post_body[..]);

    var resp4_hdrs = http::HeaderMap { .. };
    var resp4_wire: u8[>..] = [];
    assert(http3::h3_edge_encode_response_headers(h3_sess, 200, resp4_hdrs, resp4_wire));
    assert(http3::h3_edge_encode_data_frame("uploaded=65536", resp4_wire));
    let w4, ok4 = quic::quic_server_stream_write(ep, conn_id, 4, resp4_wire[..], true);
    assert(ok4 && w4 == resp4_wire.len);
    assert(drain_srv_to_cli_udp(ep, srv_fd, c, now_ns) >= 1);

    let idx_r4 = find_or_add_cli_rx(c, 4);
    assert(c.rx_streams[idx_r4].fin);
    assert(http3::handle_stream_data(c.h3_conn, 4, true, c.rx_streams[idx_r4].buf[..], true) == rfc::H3_ERR_NO_ERROR);
    let sc4, ok_sc4 = http3::get_status_code(c.h3_conn, 4);
    let body4, ok_b4 = http3::get_response_body(c.h3_conn, 4);
    assert(ok_sc4 && sc4 == 200 && ok_b4 && body4 == "uploaded=65536");

    print("H3_EDGE_LOOPBACK_E2E: OK\n");
    // CHECK: H3_EDGE_LOOPBACK_E2E: OK
}

// ---- Test 2: Spec Conformance, Chunk Splits, QPACK Block, Alt-Svc & ABA ----

fn test_h3_edge_conformance_and_security() {
    // 1. Forbidden hop-by-hop headers (connection, transfer-encoding, upgrade) -> StreamReset(H3_ERR_MESSAGE_ERROR)
    //    while healthy sibling stream continues succeeding!
    var sess = http3::h3_edge_open();
    defer http3::h3_edge_close(sess);

    var init_ctrl: u8[..64] = [];
    let default_settings = fingerprint::H3Settings { .. };
    assert(quic::encode_varint(rfc::H3_STREAM_CONTROL, init_ctrl));
    assert(http3::encode_settings_frame(init_ctrl, default_settings));
    assert(http3::h3_edge_feed_uni_stream(sess, 2, init_ctrl[..], false));

    let bad_names: const u8[:][3] = ["connection", "transfer-encoding", "upgrade"];
    let bad_vals:  const u8[:][3] = ["close", "chunked", "websocket"];
    for i in 3 {
        let sid = (i * 4) as u64;
        var bad_req: u8[>..] = [];
        encode_cli_qpack_req("GET", "/bad", "h3.example.test", bad_names[i], bad_vals[i], "", bad_req);
        assert(http3::h3_edge_feed_bidi_stream(sess, sid, bad_req[..], true));
        var ev = http3::H3EdgeEvent { .. };
        assert(http3::h3_edge_poll_event(sess, ev));
        assert(ev.kind == http3::H3EdgeEventKind.StreamReset && ev.stream_id == sid);
        assert(ev.error_code == rfc::H3_ERR_MESSAGE_ERROR);
        // Trailing chunks arriving on an already-reset stream MUST NOT fail the connection.
        assert(http3::h3_edge_feed_bidi_stream(sess, sid, "trailing-data-after-reset", false));
        assert(http3::h3_edge_feed_bidi_stream(sess, sid, "", true));
        assert(!http3::h3_edge_poll_event(sess, ev));
    }

    // Valid sibling stream 12 after rejected streams still works, plus 20 KiB DATA split bytewise across frame header
    var ok_req: u8[>..] = [];
    encode_cli_qpack_req("POST", "/split", "h3.example.test", "te", "trailers", "", ok_req);
    var big_20k: u8[>..] = [];
    for i in 20480 {
        big_20k.push(((i * 17 + 3) & 0xFF) as u8);
    }
    assert(http3::h3_edge_encode_data_frame(big_20k[..], ok_req));
    // Feed 1 byte at a time across the first 40 bytes (HEADERS + DATA frame header varint split!), then rest
    for b_idx in 40 {
        assert(http3::h3_edge_feed_bidi_stream(sess, 12, ok_req[b_idx..(b_idx + 1)], false));
    }
    assert(http3::h3_edge_feed_bidi_stream(sess, 12, ok_req[40..], true));

    var rx_12: u8[>..] = [];
    var saw_12_head = false;
    var saw_12_end = false;
    var ev12 = http3::H3EdgeEvent { .. };
    while http3::h3_edge_poll_event(sess, ev12) {
        if ev12.kind == http3::H3EdgeEventKind.RequestHead {
            assert(ev12.stream_id == 12 && !ev12.end_stream);
            assert(http::get_header(ev12.headers, "te") == "trailers");
            saw_12_head = true;
        } else if ev12.kind == http3::H3EdgeEventKind.RequestData {
            assert(ev12.stream_id == 12);
            rx_12.append(ev12.data);
        } else if ev12.kind == http3::H3EdgeEventKind.RequestEnd {
            assert(ev12.stream_id == 12 && ev12.end_stream);
            saw_12_end = true;
        }
    }
    assert(saw_12_head && saw_12_end && rx_12.len == 20480 && rx_12[..] == big_20k[..]);

    // 2. Unknown/GREASE uni stream split 1 byte at a time is ignored cleanly
    var grease_uni: u8[..16] = [];
    assert(quic::encode_varint(0x4021, grease_uni));
    grease_uni.append("ignored");
    for gi in grease_uni.len {
        let is_last = (gi + 1) == grease_uni.len;
        assert(http3::h3_edge_feed_uni_stream(sess, 10, grease_uni[gi..(gi + 1)], is_last));
    }

    // 3. Duplicate control stream -> ProtocolError(H3_ERR_STREAM_CREATION)
    var dup_ctrl: u8[..32] = [];
    assert(quic::encode_varint(rfc::H3_STREAM_CONTROL, dup_ctrl));
    assert(!http3::h3_edge_feed_uni_stream(sess, 6, dup_ctrl[..], false));
    var pev = http3::H3EdgeEvent { .. };
    assert(http3::h3_edge_poll_event(sess, pev));
    assert(pev.kind == http3::H3EdgeEventKind.ProtocolError && pev.error_code == rfc::H3_ERR_STREAM_CREATION);

    // 4. Duplicate QPACK encoder stream -> ProtocolError(H3_ERR_STREAM_CREATION)
    var s_qenc = http3::h3_edge_open();
    defer http3::h3_edge_close(s_qenc);
    var qe_pre: u8[..8] = [];
    assert(quic::encode_varint(rfc::H3_STREAM_QPACK_ENCODER, qe_pre));
    assert(http3::h3_edge_feed_uni_stream(s_qenc, 6, qe_pre[..], false));
    assert(!http3::h3_edge_feed_uni_stream(s_qenc, 14, qe_pre[..], false));
    assert(http3::h3_edge_poll_event(s_qenc, pev));
    assert(pev.kind == http3::H3EdgeEventKind.ProtocolError && pev.error_code == rfc::H3_ERR_STREAM_CREATION);

    // 5. QPACK blocked stream + >4 KiB DATA queued and unblocked on QPACK encoder stream
    var s_blk = http3::h3_edge_open();
    defer http3::h3_edge_close(s_blk);
    var blk_qsec: u8[..128] = [0x02, 0x00];
    assert(http3::encode_qpack_field(blk_qsec, ":method", "POST"));
    assert(http3::encode_qpack_field(blk_qsec, ":scheme", "https"));
    assert(http3::encode_qpack_field(blk_qsec, ":authority", "h3.example.test"));
    assert(http3::encode_qpack_field(blk_qsec, ":path", "/blocked"));
    blk_qsec.push(0x80); // dynamic abs_idx 0
    var blk_wire: u8[>..] = [];
    assert(http3::encode_headers_frame(blk_wire, blk_qsec[..]));
    var blk_body: u8[5000] = ['B'; 5000];
    assert(http3::h3_edge_encode_data_frame(blk_body[..], blk_wire));
    assert(http3::h3_edge_feed_bidi_stream(s_blk, 0, blk_wire[..], true));
    assert(!http3::h3_edge_poll_event(s_blk, pev)); // blocked: no events yet!

    var peer_enc = http3::new_qpack_table(4096, 16);
    assert(http3::qpack_set_capacity(peer_enc, 4096));
    var qenc_stream: u8[..128] = [];
    assert(quic::encode_varint(rfc::H3_STREAM_QPACK_ENCODER, qenc_stream));
    assert(http3::encode_qpack_set_capacity(peer_enc, 4096, qenc_stream));
    // Reconstruct wire set-capacity + insert cleanly onto qenc_stream
    var qenc_wire: u8[..128] = [];
    assert(quic::encode_varint(rfc::H3_STREAM_QPACK_ENCODER, qenc_wire));
    var tmp_tbl = http3::new_qpack_table(4096, 16, 0);
    assert(http3::encode_qpack_set_capacity(tmp_tbl, 4096, qenc_wire));
    let _, ok_ins = http3::encode_qpack_dynamic_insert(tmp_tbl, "x-dyn", "unlocked", qenc_wire, false);
    assert(ok_ins);
    assert(http3::h3_edge_feed_uni_stream(s_blk, 6, qenc_wire[..], false));

    var blk_rx: u8[>..] = [];
    var blk_head = false;
    var blk_end = false;
    while http3::h3_edge_poll_event(s_blk, pev) {
        if pev.kind == http3::H3EdgeEventKind.RequestHead {
            assert(http::get_header(pev.headers, "x-dyn") == "unlocked");
            blk_head = true;
        } else if pev.kind == http3::H3EdgeEventKind.RequestData {
            blk_rx.append(pev.data);
        } else if pev.kind == http3::H3EdgeEventKind.RequestEnd {
            blk_end = true;
        }
    }
    assert(blk_head && blk_end && blk_rx.len == 5000 && blk_rx[..] == blk_body[..]);

    // 6. h3_edge_encode_goaway, Alt-Svc formatting & cache round-trip, and ABA guard
    var ga_buf: u8[..32] = [];
    assert(!http3::h3_edge_encode_goaway(1, ga_buf));
    assert(ga_buf.len == 0);
    assert(http3::h3_edge_encode_goaway(12, ga_buf));
    let ga_hdr, ok_gah = http3::parse_frame_header(ga_buf[..], 0);
    assert(ok_gah && ga_hdr.frame_type == rfc::H3_FRAME_GOAWAY);
    let ga_id, ok_gid = http3::parse_goaway_frame(ga_buf[(ga_hdr.header_len as i64)..]);
    assert(ok_gid && ga_id == 12);

    var alt_no_p: u8[..64] = [];
    http::format_altsvc_header(alt_no_p, "h3", 443, 86400, false);
    assert(alt_no_p[..] == "h3=\":443\"; ma=86400");
    var alt_def: u8[..64] = [];
    http::format_altsvc_header(alt_def, "h3", 443);
    assert(alt_def[..] == "h3=\":443\"; ma=86400; persist=1");
    var cache = http::AltSvcCache { .. };
    http::update(cache, "h3.example.test:443", alt_no_p[..], 100);
    var ep_out = http::AltSvcEndpoint { .. };
    assert(http::lookup_h3(cache, "h3.example.test:443", 101, ep_out));
    assert(ep_out.proto[..] == "h3" && ep_out.port == 443 && ep_out.max_age_sec == 86400);

    var s_aba = http3::h3_edge_open();
    var stale = s_aba;
    http3::h3_edge_close(s_aba);
    http3::h3_edge_close(s_aba); // idempotent double close
    assert(!http3::h3_edge_feed_bidi_stream(stale, 0, "x", false));
    assert(!http3::h3_edge_poll_event(stale, pev));

    // 7. Edge protocol & rollback invariants: GOAWAY, response rollback, Content-Length mismatch,
    //    client push stream rejection, closing critical control stream, and missing SETTINGS.
    var s_ctrl = http3::h3_edge_open();
    defer http3::h3_edge_close(s_ctrl);
    var bad_wire: u8[>..] = [];
    bad_wire.append("KEEP");
    let empty_resp = http::HeaderMap { .. };
    assert(!http3::h3_edge_encode_response_headers(s_ctrl, 99, empty_resp, bad_wire));
    assert(bad_wire[..] == "KEEP");
    var bad_resp_hdr = http::HeaderMap { .. };
    assert(http::append_header(bad_resp_hdr, "Connection", "close"));
    assert(!http3::h3_edge_encode_response_headers(s_ctrl, 200, bad_resp_hdr, bad_wire));
    assert(bad_wire[..] == "KEEP");

    // Control stream: SETTINGS then GOAWAY(4) -> GoAway event; closing control stream -> ClosedCriticalStream
    var ctrl_ga: u8[..64] = [];
    assert(quic::encode_varint(rfc::H3_STREAM_CONTROL, ctrl_ga));
    assert(http3::encode_settings_frame(ctrl_ga, default_settings));
    assert(http3::encode_goaway_frame(ctrl_ga, 4));
    assert(http3::h3_edge_feed_uni_stream(s_ctrl, 2, ctrl_ga[..], false));
    assert(http3::h3_edge_poll_event(s_ctrl, pev));
    assert(pev.kind == http3::H3EdgeEventKind.GoAway && pev.stream_id == 4);

    // Content-Length mismatch -> StreamReset(H3_ERR_MESSAGE_ERROR)
    var cl_bad: u8[>..] = [];
    encode_cli_qpack_req("POST", "/cl", "h3.example.test", "", "", "10", cl_bad);
    assert(http3::h3_edge_encode_data_frame("abc", cl_bad));
    assert(http3::h3_edge_feed_bidi_stream(s_ctrl, 0, cl_bad[..], true));
    var saw_cl_reset = false;
    while http3::h3_edge_poll_event(s_ctrl, pev) {
        if pev.kind == http3::H3EdgeEventKind.StreamReset {
            assert(pev.error_code == rfc::H3_ERR_MESSAGE_ERROR);
            saw_cl_reset = true;
        }
    }
    assert(saw_cl_reset);

    // Closing control stream -> ProtocolError(H3_ERR_CLOSED_CRITICAL_STREAM)
    assert(!http3::h3_edge_feed_uni_stream(s_ctrl, 2, "", true));
    assert(http3::h3_edge_poll_event(s_ctrl, pev));
    assert(pev.kind == http3::H3EdgeEventKind.ProtocolError);
    assert(pev.error_code == rfc::H3_ERR_CLOSED_CRITICAL_STREAM);

    // Client-initiated Push stream -> ProtocolError(H3_ERR_STREAM_CREATION)
    var s_push = http3::h3_edge_open();
    defer http3::h3_edge_close(s_push);
    var push_pre: u8[..8] = [];
    assert(quic::encode_varint(rfc::H3_STREAM_PUSH, push_pre));
    assert(!http3::h3_edge_feed_uni_stream(s_push, 2, push_pre[..], false));
    assert(http3::h3_edge_poll_event(s_push, pev));
    assert(pev.kind == http3::H3EdgeEventKind.ProtocolError && pev.error_code == rfc::H3_ERR_STREAM_CREATION);

    // Control stream starting with GOAWAY instead of SETTINGS -> ProtocolError(H3_ERR_MISSING_SETTINGS)
    var s_noset = http3::h3_edge_open();
    defer http3::h3_edge_close(s_noset);
    var no_set: u8[..32] = [];
    assert(quic::encode_varint(rfc::H3_STREAM_CONTROL, no_set));
    assert(http3::encode_goaway_frame(no_set, 0));
    assert(!http3::h3_edge_feed_uni_stream(s_noset, 2, no_set[..], false));
    assert(http3::h3_edge_poll_event(s_noset, pev));
    assert(pev.kind == http3::H3EdgeEventKind.ProtocolError && pev.error_code == rfc::H3_ERR_MISSING_SETTINGS);

    print("H3_EDGE_CONFORMANCE_AND_SECURITY: OK\n");
    // CHECK: H3_EDGE_CONFORMANCE_AND_SECURITY: OK
}

fn test_h3_edge_review_regressions() {
    var pev = http3::H3EdgeEvent { .. };
    let default_settings = fingerprint::H3Settings { .. };

    // R1: QPACK-blocked HEADERS section > 4096 bytes unblocked by later encoder instructions
    var s_big_blk = http3::h3_edge_open();
    defer http3::h3_edge_close(s_big_blk);
    var big_sec: u8[>..] = [0x02, 0x00];
    assert(http3::encode_qpack_field(big_sec, ":method", "GET"));
    assert(http3::encode_qpack_field(big_sec, ":scheme", "https"));
    assert(http3::encode_qpack_field(big_sec, ":authority", "h3.example.test"));
    assert(http3::encode_qpack_field(big_sec, ":path", "/big-blocked"));
    big_sec.push(0x80); // dynamic abs_idx 0
    var hval180: u8[180] = ['v'; 180];
    for hi in 24 {
        var hname: u8[..16] = "x-pad-";
        (hi as u32).format_u32_dec(hname);
        assert(http3::encode_qpack_field(big_sec, hname[..], hval180[..], false));
    }
    assert(big_sec.len > 4096);
    var big_wire: u8[>..] = [];
    assert(http3::encode_headers_frame(big_wire, big_sec[..]));
    assert(http3::h3_edge_feed_bidi_stream(s_big_blk, 0, big_wire[..], true));
    assert(!http3::h3_edge_poll_event(s_big_blk, pev));

    var qenc_big: u8[..128] = [];
    assert(quic::encode_varint(rfc::H3_STREAM_QPACK_ENCODER, qenc_big));
    var tmp_tbl = http3::new_qpack_table(4096, 16, 0);
    assert(http3::encode_qpack_set_capacity(tmp_tbl, 4096, qenc_big));
    let _, ok_ins = http3::encode_qpack_dynamic_insert(tmp_tbl, "x-dyn", "big-ok", qenc_big, false);
    assert(ok_ins);
    assert(http3::h3_edge_feed_uni_stream(s_big_blk, 6, qenc_big[..], false));
    assert(http3::h3_edge_poll_event(s_big_blk, pev));
    assert(pev.kind == http3::H3EdgeEventKind.RequestHead && pev.end_stream);
    assert(http::get_header(pev.headers, "x-dyn") == "big-ok");

    // R2: QPACK Insert rejected when sent BEFORE Set Dynamic Table Capacity (initial cap = 0)
    var s_qcap0 = http3::h3_edge_open();
    defer http3::h3_edge_close(s_qcap0);
    var qenc_no_cap: u8[..64] = [];
    assert(quic::encode_varint(rfc::H3_STREAM_QPACK_ENCODER, qenc_no_cap));
    qenc_no_cap.push(0x41);
    qenc_no_cap.push('k');
    qenc_no_cap.push(0x01);
    qenc_no_cap.push('v');
    assert(!http3::h3_edge_feed_uni_stream(s_qcap0, 6, qenc_no_cap[..], false));
    assert(http3::h3_edge_poll_event(s_qcap0, pev));
    assert(pev.kind == http3::H3EdgeEventKind.ProtocolError);
    assert(pev.error_code == rfc::H3_ERR_QPACK_ENCODER_STREAM_ERROR);

    // R3: Trailers with fin=false defer RequestEnd until fin=true; CL mismatch resets immediately
    var s_tr = http3::h3_edge_open();
    defer http3::h3_edge_close(s_tr);
    var tr_req: u8[>..] = [];
    encode_cli_qpack_req("POST", "/tr", "h3.example.test", "", "", "5", tr_req);
    assert(http3::h3_edge_encode_data_frame("hello", tr_req));
    assert(http3::h3_edge_feed_bidi_stream(s_tr, 0, tr_req[..], false));
    assert(http3::h3_edge_poll_event(s_tr, pev) && pev.kind == http3::H3EdgeEventKind.RequestHead);
    assert(http3::h3_edge_poll_event(s_tr, pev) && pev.kind == http3::H3EdgeEventKind.RequestData);
    var tr_sec: u8[..64] = [0x00, 0x00];
    assert(http3::encode_qpack_field(tr_sec, "x-checksum", "crc-ok"));
    var tr_frame: u8[>..] = [];
    assert(http3::encode_headers_frame(tr_frame, tr_sec[..]));
    assert(http3::h3_edge_feed_bidi_stream(s_tr, 0, tr_frame[..], false));
    assert(!http3::h3_edge_poll_event(s_tr, pev));
    assert(http3::h3_edge_feed_bidi_stream(s_tr, 0, "", true));
    assert(http3::h3_edge_poll_event(s_tr, pev));
    assert(pev.kind == http3::H3EdgeEventKind.RequestEnd && pev.end_stream);
    assert(http::get_header(pev.headers, "x-checksum") == "crc-ok");

    var tr_cl_bad: u8[>..] = [];
    encode_cli_qpack_req("POST", "/tr-bad", "h3.example.test", "", "", "10", tr_cl_bad);
    assert(http3::h3_edge_encode_data_frame("hi", tr_cl_bad));
    assert(http3::encode_headers_frame(tr_cl_bad, tr_sec[..]));
    assert(http3::h3_edge_feed_bidi_stream(s_tr, 4, tr_cl_bad[..], false));
    var saw_tr_bad_end = false;
    var saw_tr_bad_rst = false;
    while http3::h3_edge_poll_event(s_tr, pev) {
        if pev.kind == http3::H3EdgeEventKind.RequestEnd { saw_tr_bad_end = true; }
        if pev.kind == http3::H3EdgeEventKind.StreamReset {
            assert(pev.error_code == rfc::H3_ERR_MESSAGE_ERROR);
            saw_tr_bad_rst = true;
        }
    }
    assert(!saw_tr_bad_end && saw_tr_bad_rst);

    // R4: > 32 concurrent unknown/GREASE uni streams across multiple chunks
    var s_grease = http3::h3_edge_open();
    defer http3::h3_edge_close(s_grease);
    var grease_open: u8[..16] = [];
    assert(quic::encode_varint(0x4021, grease_open));
    grease_open.append("hdr");
    for gi in 40 {
        let sid = ((gi * 4) + 2) as u64;
        assert(http3::h3_edge_feed_uni_stream(s_grease, sid, grease_open[..], false));
    }
    let push_bait: u8[4] = [0x01, 0x00, 0x01, 0x02];
    for gi in 40 {
        let sid = ((gi * 4) + 2) as u64;
        assert(http3::h3_edge_feed_uni_stream(s_grease, sid, push_bait[..], false));
        assert(http3::h3_edge_feed_uni_stream(s_grease, sid, "", true));
    }
    assert(!http3::h3_edge_poll_event(s_grease, pev));

    // R5: Response status 101 forbidden and max_field_section_size checked on empty headers
    var s_resp = http3::h3_edge_open();
    defer http3::h3_edge_close(s_resp);
    var resp_guard: u8[>..] = [];
    resp_guard.append("KEPT");
    let empty_hdrs = http::HeaderMap { .. };
    assert(!http3::h3_edge_encode_response_headers(s_resp, 101, empty_hdrs, resp_guard));
    assert(resp_guard[..] == "KEPT");

    var small_set = fingerprint::H3Settings { max_field_section_size: 20, .. };
    var ctrl_small: u8[..64] = [];
    assert(quic::encode_varint(rfc::H3_STREAM_CONTROL, ctrl_small));
    assert(http3::encode_settings_frame(ctrl_small, small_set));
    assert(http3::h3_edge_feed_uni_stream(s_resp, 2, ctrl_small[..], false));
    assert(!http3::h3_edge_encode_response_headers(s_resp, 200, empty_hdrs, resp_guard));
    assert(resp_guard[..] == "KEPT");

    // R6: Extended CONNECT (:protocol token syntax + enable_connect_protocol) and sensitivity/overflow
    var s_conn = http3::h3_edge_open();
    defer http3::h3_edge_close(s_conn);
    var ext_ok_sec: u8[..128] = [0x00, 0x00];
    assert(http3::encode_qpack_field(ext_ok_sec, ":method", "CONNECT"));
    assert(http3::encode_qpack_field(ext_ok_sec, ":scheme", "https"));
    assert(http3::encode_qpack_field(ext_ok_sec, ":authority", "h3.example.test"));
    assert(http3::encode_qpack_field(ext_ok_sec, ":path", "/ws"));
    assert(http3::encode_qpack_field(ext_ok_sec, ":protocol", "websocket"));
    var ext_ok_wire: u8[>..] = [];
    assert(http3::encode_headers_frame(ext_ok_wire, ext_ok_sec[..]));
    assert(http3::h3_edge_feed_bidi_stream(s_conn, 0, ext_ok_wire[..], false));
    assert(http3::h3_edge_poll_event(s_conn, pev) && pev.kind == http3::H3EdgeEventKind.RequestHead);
    assert(http::get_header(pev.headers, ":protocol") == "websocket");

    var ext_bad_sec: u8[..128] = [0x00, 0x00];
    assert(http3::encode_qpack_field(ext_bad_sec, ":method", "CONNECT"));
    assert(http3::encode_qpack_field(ext_bad_sec, ":scheme", "https"));
    assert(http3::encode_qpack_field(ext_bad_sec, ":authority", "h3.example.test"));
    assert(http3::encode_qpack_field(ext_bad_sec, ":path", "/ws"));
    assert(http3::encode_qpack_field(ext_bad_sec, ":protocol", "bad proto"));
    var ext_bad_wire: u8[>..] = [];
    assert(http3::encode_headers_frame(ext_bad_wire, ext_bad_sec[..]));
    assert(http3::h3_edge_feed_bidi_stream(s_conn, 4, ext_bad_wire[..], true));
    assert(http3::h3_edge_poll_event(s_conn, pev));
    assert(pev.kind == http3::H3EdgeEventKind.StreamReset && pev.error_code == rfc::H3_ERR_MESSAGE_ERROR);

    http3::g_h3_edge_slots[s_conn.slot_idx].local_settings.enable_connect_protocol = 0;
    assert(http3::h3_edge_feed_bidi_stream(s_conn, 8, ext_ok_wire[..], false));
    assert(http3::h3_edge_poll_event(s_conn, pev));
    assert(pev.kind == http3::H3EdgeEventKind.StreamReset && pev.error_code == rfc::H3_ERR_MESSAGE_ERROR);

    // R7: HEADER_FLAG_SENSITIVE preservation and HeaderMap overflow -> H3_ERR_EXCESSIVE_LOAD
    var sens_sec: u8[..128] = [0x00, 0x00];
    assert(http3::encode_qpack_field(sens_sec, ":method", "GET"));
    assert(http3::encode_qpack_field(sens_sec, ":scheme", "https"));
    assert(http3::encode_qpack_field(sens_sec, ":authority", "h3.example.test"));
    assert(http3::encode_qpack_field(sens_sec, ":path", "/sens"));
    let lit_sens_key: u8[13] = [0x35, 'x', '-', 'k', 'e', 'y', 0x06, 's', 'e', 'c', 'r', 'e', 't'];
    assert(sens_sec.try_append(lit_sens_key[..]));
    let lit_sens_ck: u8[11] = [0x36, 'c', 'o', 'o', 'k', 'i', 'e', 0x03, 'a', '=', '1'];
    assert(sens_sec.try_append(lit_sens_ck[..]));
    var sens_wire: u8[>..] = [];
    assert(http3::encode_headers_frame(sens_wire, sens_sec[..]));
    assert(http3::h3_edge_feed_bidi_stream(s_conn, 12, sens_wire[..], true));
    assert(http3::h3_edge_poll_event(s_conn, pev) && pev.kind == http3::H3EdgeEventKind.RequestHead);
    var saw_sens_key = false;
    var saw_sens_ck = false;
    for idx_e in pev.headers.entries.len {
        let ent .= pev.headers.entries[idx_e];
        let nm = http::entry_name(pev.headers, ent);
        if nm == "x-key" {
            assert(http::is_sensitive(ent));
            saw_sens_key = true;
        }
        if nm == "cookie" {
            assert(http::is_sensitive(ent));
            saw_sens_ck = true;
        }
    }
    assert(saw_sens_key && saw_sens_ck);

    var ovf_sec: u8[>..] = [0x00, 0x00];
    assert(http3::encode_qpack_field(ovf_sec, ":method", "GET"));
    assert(http3::encode_qpack_field(ovf_sec, ":scheme", "https"));
    assert(http3::encode_qpack_field(ovf_sec, ":authority", "h3.example.test"));
    assert(http3::encode_qpack_field(ovf_sec, ":path", "/overflow-target-path-extra"));
    var pad195: u8[195] = ['z'; 195];
    for pi in 40 {
        var pn: u8[..16] = "x-ovf-";
        (pi as u32).format_u32_dec(pn);
        if pn.len == 7 {
            assert(pn.try_push('0'));
        }
        assert(http3::encode_qpack_field(ovf_sec, pn[..], pad195[..], false));
    }
    var ovf_wire: u8[>..] = [];
    assert(http3::encode_headers_frame(ovf_wire, ovf_sec[..]));
    assert(http3::h3_edge_feed_bidi_stream(s_conn, 16, ovf_wire[..], true));
    assert(http3::h3_edge_poll_event(s_conn, pev));
    assert(pev.kind == http3::H3EdgeEventKind.StreamReset && pev.error_code == rfc::H3_ERR_EXCESSIVE_LOAD);

    print("H3_EDGE_REGRESSIONS: OK\n");
    // CHECK: H3_EDGE_REGRESSIONS: OK
}

fn test_h3_edge_ignored_uni_capacity() {
    var s_uni = http3::h3_edge_open();
    defer http3::h3_edge_close(s_uni);

    var grease_open: u8[..16] = [];
    assert(quic::encode_varint(0x4021, grease_open));
    grease_open.append("hdr");

    for gi in 1024 {
        let sid = ((gi * 4) + 2) as u64;
        assert(http3::h3_edge_feed_uni_stream(s_uni, sid, grease_open[..], false));
    }

    let bait_ctrl: u8[3] = [0x00, 0x04, 0x00];
    let bait_push: u8[3] = [0x01, 0x00, 0x01];
    let bait_qenc: u8[3] = [0x02, 0x00, 0x02];
    for gi in 1024 {
        let sid = ((gi * 4) + 2) as u64;
        let sel = gi % 3;
        if sel == 0 {
            assert(http3::h3_edge_feed_uni_stream(s_uni, sid, bait_ctrl[..], false));
        } else if sel == 1 {
            assert(http3::h3_edge_feed_uni_stream(s_uni, sid, bait_push[..], false));
        } else {
            assert(http3::h3_edge_feed_uni_stream(s_uni, sid, bait_qenc[..], false));
        }
    }
    // Verify neither oldest (2) nor newest (4094) stream was evicted.
    assert(http3::h3_edge_feed_uni_stream(s_uni, 2, bait_push[..], false));
    assert(http3::h3_edge_feed_uni_stream(s_uni, 4094, bait_push[..], false));

    var pev = http3::H3EdgeEvent { .. };
    assert(!http3::h3_edge_poll_event(s_uni, pev));

    // Closing one tracked stream via FIN frees a slot for another open unknown uni stream.
    assert(http3::h3_edge_feed_uni_stream(s_uni, 2, "", true));
    let recycled_sid: u64 = (1024 * 4) + 2;
    assert(http3::h3_edge_feed_uni_stream(s_uni, recycled_sid, grease_open[..], false));
    assert(http3::h3_edge_feed_uni_stream(s_uni, recycled_sid, bait_push[..], false));
    assert(!http3::h3_edge_poll_event(s_uni, pev));

    // A 1025-th simultaneous open unknown uni stream emits ProtocolError(H3_ERR_EXCESSIVE_LOAD).
    let ovf_sid: u64 = (1025 * 4) + 2;
    assert(!http3::h3_edge_feed_uni_stream(s_uni, ovf_sid, grease_open[..], false));
    assert(http3::h3_edge_poll_event(s_uni, pev));
    assert(pev.kind == http3::H3EdgeEventKind.ProtocolError);
    assert(pev.stream_id == ovf_sid);
    assert(pev.error_code == rfc::H3_ERR_EXCESSIVE_LOAD);

    print("H3_EDGE_IGNORED_UNI_CAP: OK\n");
    // CHECK: H3_EDGE_IGNORED_UNI_CAP: OK
}

thread_fn h3_edge_worker(arg: i64) {
    let _ = arg;
    var sess = http3::h3_edge_open();
    defer http3::h3_edge_close(sess);
    var req: u8[>..] = [];
    encode_cli_qpack_req("GET", "/worker", "h3.example.test", "", "", "", req);
    assert(http3::h3_edge_feed_bidi_stream(sess, 0, req[..], true));
    var ev = http3::H3EdgeEvent { .. };
    assert(http3::h3_edge_poll_event(sess, ev));
    assert(ev.kind == http3::H3EdgeEventKind.RequestHead && ev.end_stream);
    assert(http::get_header(ev.headers, ":path") == "/worker");
    var resp: u8[>..] = [];
    let empty_hdrs = http::HeaderMap { .. };
    assert(http3::h3_edge_encode_response_headers(sess, 200, empty_hdrs, resp));
    assert(http3::h3_edge_encode_data_frame("ok", resp));
    assert(resp.len > 0);
}

fn test_h3_edge_final_fix_regressions() {
    var sess = http3::h3_edge_open();
    defer http3::h3_edge_close(sess);

    // 1. h3_edge_poll_event clears stale out_ev fields when returning false.
    var pev = http3::H3EdgeEvent {
        kind:       http3::H3EdgeEventKind.ProtocolError,
        stream_id:  999,
        end_stream: true,
        error_code: 0xDEAD,
        ..
    };
    assert(!http3::h3_edge_poll_event(sess, pev));
    assert(pev.kind == http3::H3EdgeEventKind.None && pev.stream_id == 0 && !pev.end_stream && pev.error_code == 0);

    // 2. Non-CONNECT request carrying :protocol is rejected (RFC 9220 Section 3).
    var bad_sec: u8[..128] = [0x00, 0x00];
    assert(http3::encode_qpack_field(bad_sec, ":method", "GET"));
    assert(http3::encode_qpack_field(bad_sec, ":scheme", "https"));
    assert(http3::encode_qpack_field(bad_sec, ":authority", "h3.example.test"));
    assert(http3::encode_qpack_field(bad_sec, ":path", "/ws"));
    assert(http3::encode_qpack_field(bad_sec, ":protocol", "websocket"));
    var bad_frame: u8[..256] = [];
    assert(http3::encode_headers_frame(bad_frame, bad_sec[..]));
    assert(http3::h3_edge_feed_bidi_stream(sess, 0, bad_frame[..], true));
    assert(http3::h3_edge_poll_event(sess, pev));
    assert(pev.kind == http3::H3EdgeEventKind.StreamReset && pev.stream_id == 0);
    assert(pev.error_code == rfc::H3_ERR_MESSAGE_ERROR);

    // 3. h3_edge_reset_stream reclaims aborted hdr_accum & QPACK-blocked slots and keeps stream arena bounded > 128.
    var ctrl_set: u8[..128] = [0x00];
    let def_set = fingerprint::H3Settings { .. };
    assert(http3::encode_settings_frame(ctrl_set, def_set));
    assert(http3::h3_edge_feed_uni_stream(sess, 2, ctrl_set[..], false));

    var part_hdr: u8[..32]  = [0x01, 0x40, 0x64]; // HEADERS frame promising 100 bytes, incomplete!
    var blk_qsec: u8[..128] = [0x02, 0x00];       // Requires Insert Count = 1 (QPACK blocked!)
    assert(http3::encode_qpack_field(blk_qsec, ":method", "GET"));
    var blk_frm: u8[..256] = [];
    assert(http3::encode_headers_frame(blk_frm, blk_qsec[..]));

    for i in 40 {
        let sid = ((i + 1) * 4) as u64;
        if (i % 2) == 0 {
            assert(http3::h3_edge_feed_bidi_stream(sess, sid, part_hdr[..], false));
        } else {
            assert(http3::h3_edge_feed_bidi_stream(sess, sid, blk_frm[..], false));
        }
        http3::h3_edge_reset_stream(sess, sid);
        http3::h3_edge_reset_stream(sess, sid); // Idempotent second reset
    }
    let slot .= http3::g_h3_edge_slots[sess.slot_idx];
    assert(slot.stream_count == 1); // Stream 0 from subtest 2 remains retained until reaped; all 40 aborted streams freed.
    assert(slot.qpack_dec_table.blocked_streams.len == 0);
    http3::h3_edge_reset_stream(sess, 0);
    assert(slot.stream_count == 0);

    var req_ok: u8[>..] = [];
    encode_cli_qpack_req("GET", "/seq", "h3.example.test", "", "", "", req_ok);
    for r in 150 {
        let sid = ((r + 50) * 4) as u64;
        assert(http3::h3_edge_feed_bidi_stream(sess, sid, req_ok[..], true));
        assert(http3::h3_edge_poll_event(sess, pev));
        assert(pev.kind == http3::H3EdgeEventKind.RequestHead && pev.stream_id == sid && pev.end_stream);
    }
    assert(http3::g_h3_edge_slots[sess.slot_idx].stream_count <= 128);
    assert(http3::g_h3_edge_streams.len <= 130);

    // 4. Resetting unknown uni stream succeeds cleanly; resetting critical uni stream emits H3_ERR_CLOSED_CRITICAL_STREAM.
    let unk_uni_hdr: u8[4] = [0x40, 0x21, 0x01, 0x02];
    assert(http3::h3_edge_feed_uni_stream(sess, 6, unk_uni_hdr[..], false));
    http3::h3_edge_reset_stream(sess, 6);
    assert(!http3::h3_edge_poll_event(sess, pev));

    http3::h3_edge_reset_stream(sess, 2);
    assert(http3::h3_edge_poll_event(sess, pev));
    assert(pev.kind == http3::H3EdgeEventKind.ProtocolError && pev.error_code == rfc::H3_ERR_CLOSED_CRITICAL_STREAM);

    // 5. Wrapping non-zero session generation, oversized SETTINGS -> EXCESSIVE_LOAD,
    //    and non-client-bidi PRIORITY_UPDATE element ID -> ID_ERROR.
    let saved_gen = http3::g_h3_edge_next_gen;
    http3::g_h3_edge_next_gen = (0xFFFFFFFFFFFFFFFF as u64);
    var gen_a = http3::h3_edge_open();
    var gen_b = http3::h3_edge_open();
    assert(gen_a.generation == (0xFFFFFFFFFFFFFFFF as u64));
    assert(gen_b.generation == 1);
    http3::h3_edge_close(gen_a);
    http3::h3_edge_close(gen_b);
    http3::g_h3_edge_next_gen = saved_gen;

    var s_big = http3::h3_edge_open();
    defer http3::h3_edge_close(s_big);
    var big_set: u8[..300] = [0x00, 0x04, 0x41, 0x04]; // ctrl stream + SETTINGS len=260 (> 256)
    for _ in 260 { big_set.push(0); }
    assert(!http3::h3_edge_feed_uni_stream(s_big, 2, big_set[..], false));
    assert(http3::h3_edge_poll_event(s_big, pev));
    assert(pev.kind == http3::H3EdgeEventKind.ProtocolError && pev.error_code == rfc::H3_ERR_EXCESSIVE_LOAD);

    var s_pu = http3::h3_edge_open();
    defer http3::h3_edge_close(s_pu);
    assert(http3::h3_edge_feed_uni_stream(s_pu, 2, ctrl_set[..], false));
    // PRIORITY_UPDATE_REQUEST (0xF0700 -> 4-byte varint 0xC0 0x0F 0x07 0x00), len=4, elem_id=1 ("u=1")
    var bad_pu: u8[..32] = [];
    assert(quic::encode_varint(rfc::H3_FRAME_PRIORITY_UPDATE_REQUEST, bad_pu));
    assert(quic::encode_varint(4, bad_pu));
    bad_pu.push(1);
    bad_pu.push('u');
    bad_pu.push('=');
    bad_pu.push('1');
    assert(!http3::h3_edge_feed_uni_stream(s_pu, 2, bad_pu[..], false));
    assert(http3::h3_edge_poll_event(s_pu, pev));
    assert(pev.kind == http3::H3EdgeEventKind.ProtocolError && pev.error_code == rfc::H3_ERR_ID_ERROR);

    print("H3_EDGE_FINAL_FIXES: OK\n");
    // CHECK: H3_EDGE_FINAL_FIXES: OK
}

fn main() {
    test_live_h3_loopback_e2e();
    test_h3_edge_conformance_and_security();
    test_h3_edge_review_regressions();
    test_h3_edge_ignored_uni_capacity();
    test_h3_edge_final_fix_regressions();
    let t1 = thread_spawn(h3_edge_worker, 1);
    let t2 = thread_spawn(h3_edge_worker, 2);
    assert(thread_wait(t1) && thread_wait(t2));
    print("H3_EDGE_THREADS: OK\n");
    // CHECK: H3_EDGE_THREADS: OK
}
