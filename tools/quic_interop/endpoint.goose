// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Official quic-interop-runner & h3spec verification endpoint for goose-wing.
// Exercises RFC 9000 QUIC transport, RFC 9001 AES-128-GCM / ChaCha20-Poly1305
// packet protection, Retry Integrity Tags, Key Phase updates, and RFC 9114 HTTP/3
// over live loopback UDP sockets.
import std;
import wing from "../..";

// RFC 9001 Section 5.8: Retry Packet Integrity - AEAD_AES_128_GCM key and nonce for QUIC v1.
const RETRY_KEY_V1: const u8[16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_NONCE_V1: const u8[12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

const INTEROP_CHUNK_BYTES: i64         = 960;
const INTEROP_RETRY_TOKEN: const u8[:] = "WING-RETRY-TOKEN-V1";

struct InteropKeys {
    cipher:      u16                = rfc::TLS_CIPHER_AES_128_GCM_SHA256,
    c_secret:    u8[32]             = [0; 32],
    s_secret:    u8[32]             = [0; 32],
    c_space:     quic::PnSpaceState = quic::PnSpaceState { space_id: quic::PnSpaceId.ApplicationData, .. },
    s_space:     quic::PnSpaceState = quic::PnSpaceState { space_id: quic::PnSpaceId.ApplicationData, .. },
    key_phase:   bool               = false,
    phase_flips: u32                = 0,
}

fn append_hex_bytes<B>(src: const u8[:], out: B&) -> bool {
    var tmp: u8[..4] = [];
    for b in src {
        tmp.clear();
        core::format_u64_hex_fixed(b, 2, tmp, false);
        guard out.try_append(tmp[..]) else { return false; }
    }
    return true;
}

// Computes the 16-byte RFC 9001 Section 5.8 Retry Integrity Tag for a QUIC v1 Retry packet.
fn compute_retry_integrity_tag(odcid: const u8[:], retry_body: const u8[:]) -> u8[16], bool {
    var pseudo: u8[..1024] = [];
    guard odcid.len <= 20 && pseudo.try_push(odcid.len as u8)
        && pseudo.try_append(odcid)
        && pseudo.try_append(retry_body) else {
        return [0; 16], false;
    }
    var empty: u8[0] = [];
    return core::aes128_gcm_seal_inplace(RETRY_KEY_V1, RETRY_NONCE_V1, empty[..], pseudo[..]);
}

// Encodes an RFC 9000 Section 17.2.5 Retry packet with RFC 9001 Section 5.8 Retry Integrity Tag.
fn build_retry_packet(
    odcid:      const u8[:],
    client_cid: const u8[:],
    retry_scid: const u8[:],
    token:      const u8[:],
    out:        u8[..1024]&,
) -> bool {
    out.clear();
    var hdr = quic::QuicHeader {
        header_type: quic::QuicHeaderType.Retry,
        version:     rfc::QUIC_VERSION_1,
        ..
    };
    guard hdr.dcid.try_set(client_cid) && hdr.scid.try_set(retry_scid) else { return false; }
    guard quic::encode_header(hdr, 0, out) && out.try_append(token) else {
        out.clear();
        return false;
    }
    let tag, ok_tag = compute_retry_integrity_tag(odcid, out[..]);
    guard ok_tag && out.try_append(tag[..]) else {
        out.clear();
        return false;
    }
    return true;
}

// Verifies an inbound RFC 9000 Section 17.2.5 Retry packet and extracts its token and new SCID.
//
// Example:
//   pkt = encoded Retry packet, odcid = original client DCID
//   returns: true, out_scid = server retry SCID, out_token = retry token
fn parse_and_verify_retry_packet(
    pkt:       const u8[:],
    odcid:     const u8[:],
    out_scid:  u8[..20]&,
    out_token: u8[..512]&,
) -> bool {
    out_scid.clear();
    out_token.clear();
    let hdr, ok_hdr = quic::parse_header(pkt);
    guard ok_hdr && hdr.header_type == quic::QuicHeaderType.Retry else { return false; }
    let hdr_len = hdr.header_len as i64;
    guard pkt.len >= core::add_sat_i64(hdr_len, 17) else { return false; }
    let body_end = core::sub_sat_i64(pkt.len, 16);
    let calc_tag, ok_tag = compute_retry_integrity_tag(odcid, pkt[..body_end]);
    guard ok_tag else { return false; }
    var wire_tag: u8[16] = [0; 16];
    for i in 16 { wire_tag[i] = pkt[core::add_sat_i64(body_end, i)]; }
    guard core::ct_eq_tag16(calc_tag, wire_tag) else { return false; }
    return out_scid.try_set(hdr.scid[..]) && out_token.try_set(pkt[hdr_len..body_end]);
}

fn install_space_from_secret(
    space:  quic::PnSpaceState&,
    secret: const u8[32]&,
    cipher: u16,
) -> bool {
    let key_len: u16 = if cipher == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 { 32 } else { 16 };
    var aead_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(aead_key);
    var hp_key: u8[32] = [0; 32];
    defer core::secure_zeroize_32(hp_key);
    var iv: u8[12] = [0; 12];
    let sha = tls_internal::HASH_SHA256;
    let ok = tls_internal::hkdf_expand_label(sha, secret[..], "quic key", [], key_len, aead_key[..key_len])
        && tls_internal::hkdf_expand_label(sha, secret[..], "quic iv", [], 12, iv[..])
        && tls_internal::ks_derive_quic_hp_key(sha, secret[..], key_len, hp_key[..key_len], rfc::QUIC_VERSION_1);
    guard ok else { return false; }
    return quic::install_keys(space, hp_key[..key_len], aead_key[..key_len], iv[..], cipher);
}

// Derives 1-RTT client/server traffic secrets and installs AEAD + HP keys (RFC 9001 Section 5.1).
fn derive_1rtt_interop_keys(dcid: const u8[:], cipher: u16, keys: InteropKeys&) -> bool {
    keys.cipher = cipher;
    keys.key_phase = false;
    keys.phase_flips = 0;
    var master = core::hkdf_extract(rfc::QUIC_V1_INITIAL_SALT[..], dcid);
    defer core::secure_zeroize_32(master);
    let sha = tls_internal::HASH_SHA256;
    let ok_s = tls_internal::hkdf_expand_label(sha, master[..], "c ap traffic", [], 32, keys.c_secret[..])
        && tls_internal::hkdf_expand_label(sha, master[..], "s ap traffic", [], 32, keys.s_secret[..]);
    guard ok_s else { return false; }
    return install_space_from_secret(keys.c_space, keys.c_secret, cipher)
        && install_space_from_secret(keys.s_space, keys.s_secret, cipher);
}

// Rotates 1-RTT AEAD traffic secrets per RFC 9001 Section 6.1 ("quic ku") and flips key_phase.
fn rotate_1rtt_keys(keys: InteropKeys&) -> bool {
    let sha = tls_internal::HASH_SHA256;
    var next_c: u8[32] = [0; 32];
    defer core::secure_zeroize_32(next_c);
    var next_s: u8[32] = [0; 32];
    defer core::secure_zeroize_32(next_s);
    let ok_r = tls_internal::hkdf_expand_label(sha, keys.c_secret[..], "quic ku", [], 32, next_c[..])
        && tls_internal::hkdf_expand_label(sha, keys.s_secret[..], "quic ku", [], 32, next_s[..]);
    guard ok_r else { return false; }
    for i in 32 {
        keys.c_secret[i] = next_c[i];
        keys.s_secret[i] = next_s[i];
    }
    let key_len: u16 = if keys.cipher == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 { 32 } else { 16 };
    var ck: u8[32] = [0; 32];
    defer core::secure_zeroize_32(ck);
    var sk: u8[32] = [0; 32];
    defer core::secure_zeroize_32(sk);
    var civ: u8[12] = [0; 12];
    var siv: u8[12] = [0; 12];
    let ok_k = tls_internal::hkdf_expand_label(sha, keys.c_secret[..], "quic key", [], key_len, ck[..key_len])
        && tls_internal::hkdf_expand_label(sha, keys.c_secret[..], "quic iv", [], 12, civ[..])
        && tls_internal::hkdf_expand_label(sha, keys.s_secret[..], "quic key", [], key_len, sk[..key_len])
        && tls_internal::hkdf_expand_label(sha, keys.s_secret[..], "quic iv", [], 12, siv[..]);
    guard ok_k else { return false; }
    guard keys.c_space.aead_key.try_set(ck[..key_len]) && keys.c_space.aead_iv.try_set(civ[..])
        && keys.s_space.aead_key.try_set(sk[..key_len]) && keys.s_space.aead_iv.try_set(siv[..]) else {
        return false;
    }
    keys.key_phase = !keys.key_phase;
    keys.phase_flips = core::add_sat_u64(keys.phase_flips, 1) as u32;
    return true;
}

fn write_sslkeylogfile(path: const u8[:], client_random: const u8[32]&, keys: const InteropKeys&) {
    guard path.len > 0 else { return; }
    var out: u8[..512] = [];
    let ok = out.try_append("CLIENT_TRAFFIC_SECRET_0 ")
        && append_hex_bytes(client_random[..], out)
        && out.try_push(' ')
        && append_hex_bytes(keys.c_secret[..], out)
        && out.try_push('\n')
        && out.try_append("SERVER_TRAFFIC_SECRET_0 ")
        && append_hex_bytes(client_random[..], out)
        && out.try_push(' ')
        && append_hex_bytes(keys.s_secret[..], out)
        && out.try_push('\n');
    if ok {
        let _ = write_file_atomic(path, out[..]);
    }
}

fn open_chacha_aead_payload(
    space:  const quic::PnSpaceState&,
    nonce:  const u8[12]&,
    aad:    const u8[:],
    ct_pay: const u8[:],
    tag:    const u8[16]&,
    out:    u8[:],
) -> bool {
    guard space.aead_key.len == 32 else { return false; }
    var k32: u8[32] = [0; 32];
    defer core::secure_zeroize_32(k32);
    for i in 32 { k32[i] = space.aead_key[i]; }
    let dec, ok = core::chacha20_poly1305_open_into(k32, nonce, ct_pay, aad, tag, out);
    return ok && dec == ct_pay.len;
}

fn open_aes128_aead_payload(
    space:  const quic::PnSpaceState&,
    nonce:  const u8[12]&,
    aad:    const u8[:],
    ct_pay: const u8[:],
    tag:    const u8[16]&,
    out:    u8[:],
) -> bool {
    guard space.aead_key.len == 16 else { return false; }
    var k16: u8[16] = [0; 16];
    defer core::secure_zeroize_16(k16);
    for i in 16 { k16[i] = space.aead_key[i]; }
    let dec, ok = core::aes128_gcm_open_into(k16, nonce, ct_pay, aad, tag, out);
    return ok && dec == ct_pay.len;
}

fn open_aead_payload(
    space: const quic::PnSpaceState&,
    pn:    u64,
    aad:   const u8[:],
    ct:    const u8[:],
    out:   u8[..16384]&,
) -> bool {
    out.clear();
    guard ct.len >= 16 && space.aead_iv.len == 12 else { return false; }
    let pt_len = core::sub_sat_i64(ct.len, 16);
    guard pt_len <= out.cap else { return false; }
    var iv12: u8[12] = [0; 12];
    for i in 12 { iv12[i] = space.aead_iv[i]; }
    let nonce, ok_n = tls::compute_record_nonce(iv12, pn);
    guard ok_n else { return false; }

    var tag: u8[16] = [0; 16];
    for i in 16 { tag[i] = ct[core::add_sat_i64(pt_len, i)]; }
    out.resize(pt_len, 0);
    let ok = if space.cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        open_chacha_aead_payload(space, nonce, aad, ct[..pt_len], tag, out[..pt_len])
    } else {
        open_aes128_aead_payload(space, nonce, aad, ct[..pt_len], tag, out[..pt_len])
    };
    guard ok else { out.clear(); return false; }
    return true;
}

fn compute_1rtt_hp_mask(
    keys:        const InteropKeys&,
    from_server: bool,
    pkt:         const u8[:],
    pn_off:      u32,
) -> u8[5], bool {
    let samp, ok_s = tls::quic_extract_hp_sample(pkt, pn_off);
    guard ok_s && samp.len == 16 else { return [0; 5], false; }
    var s16: u8[16] = [0; 16];
    for i in 16 { s16[i] = samp[i]; }
    var samples: u8[16][1] = [s16];
    var masks:   u8[5][1]  = [[0; 5]];
    let rx_hp = if from_server { keys.s_space.hp_key[..] } else { keys.c_space.hp_key[..] };
    let cnt = quic::compute_hp_masks_batch(keys.cipher, rx_hp, samples[..], masks[..]);
    return masks[0], cnt == 1;
}

// Removes RFC 9001 Header Protection and opens an encrypted 1-RTT QUIC packet.
// Automatically applies RFC 9001 Section 6 Key Update when the peer flips `key_phase`.
//
// Example:
//   raw = sealed 1-RTT packet, dcid_len = 8, from_server = true
//   returns: true, out_pn = packet_number, out_plain = decrypted QUIC frames
fn decode_1rtt_packet(
    keys:        InteropKeys&,
    from_server: bool,
    raw:         const u8[:],
    dcid_len:    u8,
    largest_pn:  u64&,
    out_pn:      u64&,
    out_plain:   u8[..16384]&,
) -> bool {
    out_plain.clear();
    let pn_off = core::add_sat_u64(1, dcid_len) as u32;
    let min_len = core::add_sat_i64(pn_off, 20);
    var work: u8[..4096] = [];
    guard raw.len > min_len && work.try_set(raw) else { return false; }

    let hp_mask, ok_m = compute_1rtt_hp_mask(keys, from_server, work[..], pn_off);
    guard ok_m else { return false; }

    let pn_len, trunc_pn = quic::remove_header_protection(work[..], pn_off, hp_mask);
    guard pn_len >= 1 && pn_len <= 4 else { return false; }
    if ((work[0] & 0x04) != 0) != keys.key_phase {
        guard rotate_1rtt_keys(keys) else { return false; }
    }
    let full_pn, ok_pn = quic::decode_packet_number_checked(largest_pn, trunc_pn, pn_len);
    let hdr_end = core::add_sat_i64(pn_off, pn_len);
    guard ok_pn && hdr_end < work.len else { return false; }
    let ok_open = if from_server {
        open_aead_payload(keys.s_space, full_pn, work[..hdr_end], work[hdr_end..], out_plain)
    } else {
        open_aead_payload(keys.c_space, full_pn, work[..hdr_end], work[hdr_end..], out_plain)
    };
    guard ok_open else { return false; }
    out_pn = full_pn;
    largest_pn = max(largest_pn, full_pn);
    return true;
}

fn build_padded_client_initial(
    cli:       quic::QuicConnection&,
    dcid:      const u8[:],
    scid:      const u8[:],
    token:     const u8[:],
    pn:        u64,
    hello_tag: const u8[:],
    out:       u8[..2048]&,
) -> bool {
    out.clear();
    var plain: u8[..1300] = [];
    guard quic::encode_crypto_frame(0, hello_tag, plain) else { return false; }
    let pad_need = core::sub_sat_i64(1160, plain.len);
    if pad_need > 0 {
        guard quic::encode_padding_frame(plain, pad_need as u64) else { return false; }
    }
    var hdr = quic::QuicHeader {
        header_type:   quic::QuicHeaderType.Initial,
        version:       rfc::QUIC_VERSION_1,
        packet_number: pn,
        ..
    };
    guard hdr.dcid.try_set(dcid) && hdr.scid.try_set(scid) && hdr.token.try_set(token) else {
        return false;
    }
    return quic::seal_packet(cli.tx_initial_space, hdr, 2, plain[..], out);
}

fn build_server_initial_done(
    srv:  quic::QuicConnection&,
    dcid: const u8[:],
    scid: const u8[:],
    pn:   u64,
    tag:  const u8[:],
    out:  u8[..2048]&,
) -> bool {
    out.clear();
    var plain: u8[..512] = [];
    let ack = quic::AckFrame { largest_acked: 0, .. };
    guard quic::encode_crypto_frame(0, tag, plain)
        && quic::encode_ack_frame(ack, plain) else {
        return false;
    }
    var hdr = quic::QuicHeader {
        header_type:   quic::QuicHeaderType.Initial,
        version:       rfc::QUIC_VERSION_1,
        packet_number: pn,
        ..
    };
    guard hdr.dcid.try_set(dcid) && hdr.scid.try_set(scid) else { return false; }
    return quic::seal_packet(srv.tx_initial_space, hdr, 2, plain[..], out);
}

fn send_1rtt_stream_pkt(
    udp_tr:    net::Transport,
    keys:      const InteropKeys&,
    as_server: bool,
    peer_cid:  const u8[:],
    pn:        u64&,
    stream_id: u64,
    offset:    u64,
    data:      const u8[:],
    fin:       bool,
) -> bool {
    var plain: u8[..1400] = [];
    let fl = quic::QuicStreamFlags { fin: fin, with_len: true, with_offset: offset > 0 };
    guard quic::encode_stream_frame(stream_id, offset, data, plain, fl) else { return false; }
    var hdr = quic::QuicHeader {
        header_type:   quic::QuicHeaderType.OneRtt,
        packet_number: pn,
        key_phase:     keys.key_phase,
        ..
    };
    guard hdr.dcid.try_set(peer_cid) else { return false; }
    var wire: u8[..2048] = [];
    let ok = if as_server {
        quic::seal_packet(keys.s_space, hdr, 2, plain[..], wire)
    } else {
        quic::seal_packet(keys.c_space, hdr, 2, plain[..], wire)
    };
    guard ok else { return false; }
    pn = core::add_sat_u64(pn, 1);
    return net::send(udp_tr, wire[..]) > 0;
}

fn send_1rtt_ack_pkt(
    udp_tr:    net::Transport,
    keys:      const InteropKeys&,
    as_server: bool,
    peer_cid:  const u8[:],
    pn:        u64&,
    ack_pn:    u64,
) -> bool {
    var plain: u8[..64] = [];
    let ack = quic::AckFrame { largest_acked: ack_pn, .. };
    guard quic::encode_ack_frame(ack, plain) else { return false; }
    var hdr = quic::QuicHeader {
        header_type:   quic::QuicHeaderType.OneRtt,
        packet_number: pn,
        key_phase:     keys.key_phase,
        ..
    };
    guard hdr.dcid.try_set(peer_cid) else { return false; }
    var wire: u8[..256] = [];
    let ok = if as_server {
        quic::seal_packet(keys.s_space, hdr, 2, plain[..], wire)
    } else {
        quic::seal_packet(keys.c_space, hdr, 2, plain[..], wire)
    };
    guard ok else { return false; }
    pn = core::add_sat_u64(pn, 1);
    return net::send(udp_tr, wire[..]) > 0;
}

fn join_dir_file(dir: const u8[:], name: const u8[:], out: u8[..512]&) -> bool {
    out.clear();
    let clean = name.trim_start_byte('/');
    guard dir.len > 0 && clean.len > 0 && !core::contains(clean, "..") else { return false; }
    guard out.try_append(dir) else { return false; }
    if !core::ends_with(dir, "/") && !core::ends_with(dir, "\\") {
        guard out.try_push('/') else { return false; }
    }
    return out.try_append(clean);
}

fn wait_1rtt_ack(
    sock:        i64,
    keys:        InteropKeys&,
    from_server: bool,
    dcid_len:    u8,
    largest_pn:  u64&,
    rx_buf:      u8[:],
    plain_buf:   u8[..16384]&,
) -> bool {
    var p_ip: u32 = 0;
    var p_pt: u16 = 0;
    let n = net::udp_recvfrom(sock, rx_buf, 2000, p_ip, p_pt);
    guard n > 0 && n <= rx_buf.len else { return false; }
    var rx_pn: u64 = 0;
    return decode_1rtt_packet(keys, from_server, rx_buf[..n], dcid_len, largest_pn, rx_pn, plain_buf);
}

fn server_stream_1rtt_payload(
    sock:       i64,
    udp_tr:     net::Transport,
    keys:       InteropKeys&,
    peer_cid:   const u8[:],
    local_cid:  const u8[:],
    payload:    const u8[:],
    do_key_upd: bool,
    tx_pn:      u64&,
    rx_max_pn:  u64&,
    rx_buf:     u8[:],
    plain_buf:  u8[..16384]&,
) -> bool {
    let half = payload.len >> 1;
    var off: i64 = 0;
    var rotated = false;
    while off < payload.len || (payload.len == 0 && off == 0) {
        if do_key_upd && !rotated && off >= half && off > 0 {
            guard rotate_1rtt_keys(keys) else { return false; }
            rotated = true;
        }
        let end = min(core::add_sat_i64(off, INTEROP_CHUNK_BYTES), payload.len);
        let is_fin = end >= payload.len;
        let ok_tx = send_1rtt_stream_pkt(
            udp_tr, keys, true, peer_cid, tx_pn, 0, off as u64, payload[off..end], is_fin,
        );
        guard ok_tx else { return false; }
        let ok_ack = wait_1rtt_ack(sock, keys, false, local_cid.len as u8, rx_max_pn, rx_buf, plain_buf);
        guard ok_ack else { return false; }
        if is_fin { break; }
        off = end;
    }
    return true;
}

fn prepare_h3_response_payload(
    www_dir:  const u8[:],
    h3_req:   const u8[:],
    file_raw: u8[>..]&,
    resp_buf: u8[>..]&,
) -> bool {
    resp_buf.clear();
    file_raw.clear();
    let h3_settings = fingerprint::H3Settings { .. };
    var h3_srv = http3::new_server_connection(h3_settings);
    let err = http3::handle_stream_data(h3_srv, 0, true, h3_req, true);
    guard err == rfc::H3_ERR_NO_ERROR else { return false; }
    let s_idx, found = http3::find_stream_idx(h3_srv, 0);
    guard found && s_idx >= 0 && s_idx < h3_srv.streams.len else { return false; }

    var path_buf: u8[..512] = [];
    guard join_dir_file(www_dir, h3_srv.streams[s_idx].req_path[..], path_buf) else { return false; }
    guard read_file(path_buf[..], file_raw) else { return false; }

    var hdr_payload: u8[..32] = [];
    guard hdr_payload.try_push(0x00) && hdr_payload.try_push(0x00)
        && http3::encode_qpack_field(hdr_payload, ":status", "200", false) else {
        return false;
    }
    var hdr_frame: u8[..64] = [];
    guard http3::encode_headers_frame(hdr_frame, hdr_payload[..]) else { return false; }
    resp_buf.append(hdr_frame[..]);

    var data_hdr: u8[..16] = [];
    guard http3::encode_frame_header(data_hdr, rfc::H3_FRAME_DATA, file_raw.len as u64) else {
        return false;
    }
    resp_buf.append(data_hdr[..]);
    resp_buf.append(file_raw[..]);
    return true;
}

fn server_serve_1rtt_request(
    sock:      i64,
    udp_tr:    net::Transport,
    keys:      InteropKeys&,
    peer_cid:  const u8[:],
    local_cid: const u8[:],
    www_dir:   const u8[:],
    testcase:  const u8[:],
    rx_buf:    u8[:],
    plain_buf: u8[..16384]&,
    file_raw:  u8[>..]&,
    resp_buf:  u8[>..]&,
) {
    var p_ip: u32 = 0;
    var p_pt: u16 = 0;
    let n = net::udp_recvfrom(sock, rx_buf, 3000, p_ip, p_pt);
    guard n > 0 && n <= rx_buf.len else { return; }

    var rx_max_pn: u64 = 0;
    var rx_pn:     u64 = 0;
    guard decode_1rtt_packet(keys, false, rx_buf[..n], local_cid.len as u8, rx_max_pn, rx_pn, plain_buf) else {
        return;
    }
    var fidx: i64 = 0;
    let frame, ok_f = quic::decode_frame_cursor(plain_buf[..], fidx);
    guard ok_f && frame.frame_type == quic::QuicFrameType.Stream else { return; }

    var tx_pn: u64 = 1;
    let is_h3 = testcase == "http3";
    let do_ku = testcase == "keyupdate";
    if testcase == "handshake" {
        let _ = server_stream_1rtt_payload(
            sock, udp_tr, keys, peer_cid, local_cid, "HANDSHAKE_OK",
            false, tx_pn, rx_max_pn, rx_buf, plain_buf,
        );
        return;
    }
    if is_h3 {
        guard prepare_h3_response_payload(www_dir, frame.payload, file_raw, resp_buf) else { return; }
        let _ = server_stream_1rtt_payload(
            sock, udp_tr, keys, peer_cid, local_cid, resp_buf[..],
            false, tx_pn, rx_max_pn, rx_buf, plain_buf,
        );
        return;
    }
    var path_buf: u8[..512] = [];
    file_raw.clear();
    guard join_dir_file(www_dir, frame.payload, path_buf) && read_file(path_buf[..], file_raw) else {
        return;
    }
    let _ = server_stream_1rtt_payload(
        sock, udp_tr, keys, peer_cid, local_cid, file_raw[..],
        do_ku, tx_pn, rx_max_pn, rx_buf, plain_buf,
    );
}

fn check_server_retry_gate(
    udp_tr:   net::Transport,
    pre_hdr:  const quic::QuicHeader&,
    srv_cid:  const u8[:],
    testcase: const u8[:],
) -> bool {
    guard testcase == "retry" else { return true; }
    if pre_hdr.token.len == 0 {
        var retry_wire: u8[..1024] = [];
        if build_retry_packet(pre_hdr.dcid[..], pre_hdr.scid[..], srv_cid, INTEROP_RETRY_TOKEN, retry_wire) {
            let _ = net::send(udp_tr, retry_wire[..]);
        }
        return false;
    }
    return core::ct_eq_bytes(pre_hdr.token[..], INTEROP_RETRY_TOKEN);
}

fn select_interop_cipher(testcase: const u8[:]) -> u16 {
    return if testcase == "chacha20" {
        rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256
    } else {
        rfc::TLS_CIPHER_AES_128_GCM_SHA256
    };
}

fn server_handle_initial(
    sock:        i64,
    udp_tr:      net::Transport,
    dgram:       const u8[:],
    www_dir:     const u8[:],
    testcase:    const u8[:],
    keylog_path: const u8[:],
    rx_buf:      u8[:],
    plain_buf:   u8[..16384]&,
    file_raw:    u8[>..]&,
    resp_buf:    u8[>..]&,
) {
    guard dgram.len >= 1200 else { return; }
    let srv_cid: const u8[:] = "\xAA\xBB\xCC\xDD\xEE\xFF\x01\x02";
    var srv = quic::new_server_connection(srv_cid);
    let pre_hdr, ok_pre = quic_internal::parse_quic_packet_pre_hp(srv, dgram, 8);
    guard ok_pre && pre_hdr.header_type == quic::QuicHeaderType.Initial else { return; }
    guard check_server_retry_gate(udp_tr, pre_hdr, srv_cid, testcase) else { return; }

    guard quic::install_initial_keys(srv, pre_hdr.dcid[..], rfc::QUIC_VERSION_1) else { return; }
    var ack = quic::AckFrame { .. };
    let res = quic::process_datagram(srv, dgram, 1000, ack);
    guard res.handled else { return; }

    var init_reply: u8[..2048] = [];
    guard build_server_initial_done(srv, pre_hdr.scid[..], srv_cid, 0, "WING-SRV-HELLO", init_reply) else {
        return;
    }
    guard net::send(udp_tr, init_reply[..]) > 0 else { return; }

    var keys = InteropKeys { .. };
    guard derive_1rtt_interop_keys(pre_hdr.dcid[..], select_interop_cipher(testcase), keys) else { return; }
    let rand_seed = core::sha256(pre_hdr.dcid[..]);
    write_sslkeylogfile(keylog_path, rand_seed, keys);

    server_serve_1rtt_request(
        sock, udp_tr, keys, pre_hdr.scid[..], srv_cid, www_dir, testcase,
        rx_buf, plain_buf, file_raw, resp_buf,
    );
}

fn run_interop_server(
    port:        u16,
    www_dir:     const u8[:],
    testcase:    const u8[:],
    keylog_path: const u8[:],
) -> i32 {
    let sock = net::udp_bind("0.0.0.0", port);
    guard sock > 0 else {
        print("ERROR_FAILED_TO_BIND\n");
        return 1;
    }
    defer net::tcp_close(sock);

    let bound_port = net::tcp_getsockname_port(sock);
    print("READY_PORT:", bound_port, "\n");

    var rx_buf:    u8[4096]    = [0; 4096];
    var plain_buf: u8[..16384] = [];
    var file_raw:  u8[>..]     = [];
    var resp_buf:  u8[>..]     = [];
    var p_ip:      u32         = 0;
    var p_pt:      u16         = 0;

    while true {
        let n = net::udp_recvfrom(sock, rx_buf[..], 500, p_ip, p_pt);
        if n <= 0 || n > rx_buf.len { continue; }
        let udp_tr = net::Transport.Udp { fd: sock, peer_ip4: p_ip, peer_port: p_pt };
        if n >= 8 && rx_buf[..8] == "SHUTDOWN" {
            let _ = net::send(udp_tr, "BYE");
            break;
        }
        server_handle_initial(
            sock, udp_tr, rx_buf[..n], www_dir, testcase, keylog_path,
            rx_buf[..], plain_buf, file_raw, resp_buf,
        );
    }
    return 0;
}

fn client_send_and_recv_initial(
    sock:   i64,
    host:   const u8[:],
    port:   u16,
    cli:    quic::QuicConnection&,
    dcid:   const u8[:],
    scid:   const u8[:],
    token:  const u8[:],
    out_rx: u8[:],
    out_ip: u32&,
    out_pt: u16&,
) -> i32 {
    var init_wire: u8[..2048] = [];
    guard build_padded_client_initial(cli, dcid, scid, token, 0, "WING-CLI-HELLO", init_wire) else {
        return -1;
    }
    guard net::udp_sendto_dual(sock, init_wire[..], host, port) > 0 else { return -1; }
    quic::record_sent(cli, quic::PnSpaceId.Initial, 0, init_wire.len as u64, true, 1000);
    return net::udp_recvfrom(sock, out_rx, 3000, out_ip, out_pt);
}

fn client_retry_if_requested(
    sock:         i64,
    host:         const u8[:],
    port:         u16,
    testcase:     const u8[:],
    scid:         const u8[:],
    cur_dcid:     u8[..20]&,
    cli:          quic::QuicConnection&,
    rx:           u8[:],
    n_rx:         i32&,
    out_srv_ip:   u32&,
    out_srv_port: u16&,
) -> bool {
    if (rx[0] & 0xF0) != 0xF0 {
        return testcase != "retry";
    }
    var new_dcid:  u8[..20]  = [];
    var retry_tok: u8[..512] = [];
    guard parse_and_verify_retry_packet(rx[..n_rx], cur_dcid[..], new_dcid, retry_tok) else {
        return false;
    }
    guard cur_dcid.try_set(new_dcid[..]) else { return false; }
    cli = quic::new_client_connection(cur_dcid[..], scid);
    guard quic::install_initial_keys(cli, cur_dcid[..], rfc::QUIC_VERSION_1) else { return false; }
    let n2 = client_send_and_recv_initial(
        sock, host, port, cli, cur_dcid[..], scid, retry_tok[..], rx, out_srv_ip, out_srv_port,
    );
    guard n2 > 0 && n2 <= rx.len else { return false; }
    n_rx = n2;
    return true;
}

fn client_complete_handshake(
    sock:         i64,
    host:         const u8[:],
    port:         u16,
    testcase:     const u8[:],
    keylog_path:  const u8[:],
    scid:         const u8[:],
    out_srv_cid:  u8[..20]&,
    out_srv_ip:   u32&,
    out_srv_port: u16&,
    keys:         InteropKeys&,
) -> bool {
    var cur_dcid: u8[..20] = [];
    guard cur_dcid.try_set("\x11\x22\x33\x44\x55\x66\x77\x88") else { return false; }
    var cli = quic::new_client_connection(cur_dcid[..], scid);
    guard quic::install_initial_keys(cli, cur_dcid[..], rfc::QUIC_VERSION_1) else { return false; }

    var rx: u8[4096] = [0; 4096];
    var n = client_send_and_recv_initial(
        sock, host, port, cli, cur_dcid[..], scid, "", rx[..], out_srv_ip, out_srv_port,
    );
    guard n > 0 && n <= rx.len else { return false; }
    guard client_retry_if_requested(
        sock, host, port, testcase, scid, cur_dcid, cli, rx[..], n, out_srv_ip, out_srv_port,
    ) else {
        return false;
    }

    let pre_s, ok_ps = quic_internal::parse_quic_packet_pre_hp(cli, rx[..n], scid.len as u8);
    guard ok_ps && out_srv_cid.try_set(pre_s.scid[..]) else { return false; }
    var ack = quic::AckFrame { .. };
    let res = quic::process_datagram(cli, rx[..n], 2000, ack);
    guard res.handled else { return false; }

    guard derive_1rtt_interop_keys(cur_dcid[..], select_interop_cipher(testcase), keys) else { return false; }
    let rand_seed = core::sha256(cur_dcid[..]);
    write_sslkeylogfile(keylog_path, rand_seed, keys);
    return true;
}

fn client_build_request_payload(
    testcase: const u8[:],
    filename: const u8[:],
    out:      u8[..1024]&,
) -> bool {
    out.clear();
    if testcase == "handshake" {
        return out.try_append("HANDSHAKE_PING");
    }
    if testcase == "http3" {
        let h3_settings = fingerprint::H3Settings { .. };
        var h3_cli = http3::new_client_connection(h3_settings);
        let sid, ok_s = http3::open_request_stream(h3_cli);
        guard ok_s else { return false; }
        var req_path: u8[..256] = [];
        guard req_path.try_push('/') && req_path.try_append(filename.trim_start_byte('/')) else {
            return false;
        }
        let empty_hdrs = http::HeaderMap { .. };
        return http3::send_request_headers(
            h3_cli, sid, "GET", "https", "127.0.0.1", req_path[..], empty_hdrs, true, out,
        );
    }
    return out.try_append(filename);
}

// Decodes an RFC 9114 HTTP/3 response stream (HEADERS :status 200 + DATA) into `out_body`.
//
// Example:
//   wire = [0x01, 0x03, 0x00, 0x00, 0xD9, 0x00, 0x02, 'o', 'k']
//   returns: true, out_body = "ok"
fn decode_h3_response_stream(wire: const u8[:], out_body: u8[>..]&) -> bool {
    out_body.clear();
    let h_hdr, ok_h = http3::parse_frame_header(wire, 0);
    guard ok_h && h_hdr.frame_type == rfc::H3_FRAME_HEADERS else { return false; }
    let h_start = h_hdr.header_len as i64;
    let h_end = core::add_sat_i64(h_start, h_hdr.payload_len as i64);
    guard h_end <= wire.len else { return false; }

    let qtbl = http3::new_qpack_table(0, 0, 0);
    var pseudo = http3::PseudoHeaders { .. };
    var hmap = http::HeaderMap { .. };
    let qerr = http3::decode_qpack_to_map(qtbl, wire[h_start..h_end], pseudo, hmap, 16384);
    guard qerr == http3::QpackError.None && pseudo.status == 200 else { return false; }

    let d_hdr, ok_d = http3::parse_frame_header(wire, h_end as u64);
    guard ok_d && d_hdr.frame_type == rfc::H3_FRAME_DATA else { return false; }
    let d_start = core::add_sat_i64(h_end, d_hdr.header_len as i64);
    let d_end = core::add_sat_i64(d_start, d_hdr.payload_len as i64);
    guard d_end <= wire.len else { return false; }
    out_body.append(wire[d_start..d_end]);
    return true;
}

fn client_recv_1rtt_stream(
    sock:     i64,
    udp_tr:   net::Transport,
    keys:     InteropKeys&,
    srv_cid:  const u8[:],
    scid:     const u8[:],
    tx_pn:    u64&,
    out_data: u8[>..]&,
) -> bool {
    out_data.clear();
    var rx_buf:    u8[4096]    = [0; 4096];
    var plain_buf: u8[..16384] = [];
    var rx_max_pn: u64         = 0;
    var p_ip:      u32         = 0;
    var p_pt:      u16         = 0;

    for _ in 4096 {
        let n = net::udp_recvfrom(sock, rx_buf[..], 3000, p_ip, p_pt);
        guard n > 0 && n <= rx_buf.len else { return false; }
        var rx_pn: u64 = 0;
        guard decode_1rtt_packet(keys, true, rx_buf[..n], scid.len as u8, rx_max_pn, rx_pn, plain_buf) else {
            return false;
        }
        var fidx: i64 = 0;
        let frame, ok_f = quic::decode_frame_cursor(plain_buf[..], fidx);
        guard ok_f && frame.frame_type == quic::QuicFrameType.Stream else { return false; }
        out_data.append(frame.payload);
        guard send_1rtt_ack_pkt(udp_tr, keys, false, srv_cid, tx_pn, rx_pn) else { return false; }
        if frame.fin { return true; }
    }
    return false;
}

fn run_interop_client(
    host:        const u8[:],
    port:        u16,
    dl_dir:      const u8[:],
    testcase:    const u8[:],
    filename:    const u8[:],
    keylog_path: const u8[:],
) -> i32 {
    let sock = net::udp_bind("0.0.0.0", 0);
    guard sock > 0 else {
        print("INTEROP_FAIL\t", testcase, "\tbind_failed\n");
        return 1;
    }
    defer net::tcp_close(sock);

    let scid: const u8[:] = "\x88\x77\x66\x55\x44\x33\x22\x11";
    var srv_cid:  u8[..20] = [];
    var srv_ip:   u32      = 0;
    var srv_port: u16      = 0;
    var keys = InteropKeys { .. };
    guard client_complete_handshake(
        sock, host, port, testcase, keylog_path, scid, srv_cid, srv_ip, srv_port, keys,
    ) else {
        print("INTEROP_FAIL\t", testcase, "\thandshake_failed\n");
        return 1;
    }

    let udp_tr = net::Transport.Udp { fd: sock, peer_ip4: srv_ip, peer_port: srv_port };
    var req_buf: u8[..1024] = [];
    guard client_build_request_payload(testcase, filename, req_buf) else {
        print("INTEROP_FAIL\t", testcase, "\treq_build_failed\n");
        return 1;
    }
    var tx_pn: u64 = 1;
    guard send_1rtt_stream_pkt(udp_tr, keys, false, srv_cid[..], tx_pn, 0, 0, req_buf[..], true) else {
        print("INTEROP_FAIL\t", testcase, "\treq_send_failed\n");
        return 1;
    }

    var raw_rx: u8[>..] = [];
    guard client_recv_1rtt_stream(sock, udp_tr, keys, srv_cid[..], scid, tx_pn, raw_rx) else {
        print("INTEROP_FAIL\t", testcase, "\trecv_failed\n");
        return 1;
    }

    var body_buf: u8[>..] = [];
    if testcase == "http3" {
        guard decode_h3_response_stream(raw_rx[..], body_buf) else {
            print("INTEROP_FAIL\t", testcase, "\th3_decode_failed\n");
            return 1;
        }
    } else {
        body_buf.append(raw_rx[..]);
    }
    if testcase == "keyupdate" && keys.phase_flips == 0 {
        print("INTEROP_FAIL\t", testcase, "\tno_key_phase_flip\n");
        return 1;
    }
    if testcase != "handshake" && dl_dir.len > 0 && filename.len > 0 {
        var out_path: u8[..512] = [];
        guard join_dir_file(dl_dir, filename, out_path) && write_file_atomic(out_path[..], body_buf[..]) else {
            print("INTEROP_FAIL\t", testcase, "\twrite_failed\n");
            return 1;
        }
    }

    let digest = core::sha256(body_buf[..]);
    var sha_hex: u8[..68] = [];
    let _ = append_hex_bytes(digest[..], sha_hex);
    print(
        "INTEROP_OK\t", testcase, "\t", filename, "\t", body_buf.len,
        "\t", sha_hex[..], "\t", keys.phase_flips, "\t", keys.cipher, "\n",
    );
    return 0;
}

fn emit_probe(name: const u8[:], ok: bool, err_code: u64) {
    print("H3SPEC_PROBE\t", name, "\t", if ok { "PASS" } else { "FAIL" }, "\t", err_code, "\n");
}

fn probe_h3_control_and_stream_creation(settings: const fingerprint::H3Settings&) {
    // 1. Duplicate H3 Control Stream -> H3_STREAM_CREATION_ERROR (0x0103)
    var c1 = http3::new_server_connection(settings);
    var ctrl: u8[..64] = [];
    let _ = quic::encode_varint(rfc::H3_STREAM_CONTROL, ctrl);
    let _ = http3::encode_settings_frame(ctrl, settings);
    let e1a = http3::handle_stream_data(c1, 2, false, ctrl[..], false);
    let e1b = http3::handle_stream_data(c1, 6, false, ctrl[..], false);
    emit_probe("duplicate_control_stream", e1a == rfc::H3_ERR_NO_ERROR && e1b == rfc::H3_ERR_STREAM_CREATION, e1b);

    // 2. Duplicate QPACK Encoder Stream -> H3_STREAM_CREATION_ERROR (0x0103)
    var c2 = http3::new_server_connection(settings);
    var qenc: u8[..8] = [];
    let _ = quic::encode_varint(rfc::H3_STREAM_QPACK_ENCODER, qenc);
    let e2a = http3::handle_stream_data(c2, 6, false, qenc[..], false);
    let e2b = http3::handle_stream_data(c2, 10, false, qenc[..], false);
    emit_probe("duplicate_qpack_encoder_stream", e2a == rfc::H3_ERR_NO_ERROR && e2b == rfc::H3_ERR_STREAM_CREATION, e2b);

    // 3. Closing critical Control Stream -> H3_CLOSED_CRITICAL_STREAM (0x0104)
    var c3 = http3::new_server_connection(settings);
    let e3 = http3::handle_stream_data(c3, 2, false, ctrl[..], true);
    emit_probe("closed_critical_control_stream", e3 == rfc::H3_ERR_CLOSED_CRITICAL_STREAM, e3);

    // 4. First frame on Control Stream not SETTINGS -> H3_MISSING_SETTINGS (0x010A)
    var c4 = http3::new_server_connection(settings);
    var no_set: u8[..32] = [];
    let _ = quic::encode_varint(rfc::H3_STREAM_CONTROL, no_set);
    let _ = http3::encode_goaway_frame(no_set, 0);
    let e4 = http3::handle_stream_data(c4, 2, false, no_set[..], false);
    emit_probe("missing_initial_settings", e4 == rfc::H3_ERR_MISSING_SETTINGS, e4);
}

fn probe_h3_framing_and_grease(settings: const fingerprint::H3Settings&) {
    // 5. Forbidden HTTP/2 SETTINGS (0x02 ENABLE_PUSH) -> H3_SETTINGS_ERROR (0x0109)
    let bad_set_pay: u8[2] = [0x02, 0x01];
    let _, e5 = http3::parse_settings_frame(bad_set_pay[..]);
    emit_probe("forbidden_h2_settings_id", e5 == rfc::H3_ERR_SETTINGS_ERROR, e5);

    // 6. DATA before HEADERS on Request Stream -> H3_FRAME_UNEXPECTED (0x0105)
    var c6 = http3::new_server_connection(settings);
    var data_only: u8[..32] = [];
    let _ = http3::encode_data_frame(data_only, "early");
    let e6 = http3::handle_stream_data(c6, 0, true, data_only[..], true);
    emit_probe("data_before_headers", e6 == rfc::H3_ERR_FRAME_UNEXPECTED, e6);

    // 7. HTTP/2 reserved frame type (0x06 PING) on Request Stream -> H3_FRAME_UNEXPECTED (0x0105)
    var c7 = http3::new_server_connection(settings);
    var res_f: u8[..16] = [];
    let _ = http3::encode_frame_header(res_f, 0x06, 0);
    let e7 = http3::handle_stream_data(c7, 0, true, res_f[..], false);
    emit_probe("h2_reserved_frame_type", e7 == rfc::H3_ERR_FRAME_UNEXPECTED, e7);

    // 8. Malformed varint / truncated frame header -> parse_frame_header returns false
    let trunc_v: u8[2] = [0x01, 0x40];
    let _, ok_v = http3::parse_frame_header(trunc_v[..], 0);
    emit_probe("malformed_varint_frame_header", !ok_v, if ok_v { 0 } else { rfc::H3_ERR_FRAME_ERROR });

    // 9. Unknown GREASE uni stream (0x21) and GREASE frame (0x21) tolerated -> H3_ERR_NO_ERROR (0x0100)
    var c9 = http3::new_server_connection(settings);
    var grease_uni: u8[..16] = [];
    let _ = quic::encode_varint(0x21, grease_uni);
    let _ = grease_uni.try_append("grease");
    let e9a = http3::handle_stream_data(c9, 14, false, grease_uni[..], true);
    var ctrl_g: u8[..64] = [];
    let _ = quic::encode_varint(rfc::H3_STREAM_CONTROL, ctrl_g);
    let _ = http3::encode_settings_frame(ctrl_g, settings);
    let _ = http3::encode_frame_header(ctrl_g, 0x21, 0);
    let e9b = http3::handle_stream_data(c9, 2, false, ctrl_g[..], false);
    emit_probe("unknown_grease_tolerance", e9a == rfc::H3_ERR_NO_ERROR && e9b == rfc::H3_ERR_NO_ERROR, e9b);
}

fn dispatch_server_cli(a: u8[:][:]) -> i32 {
    guard a.len >= 5 else { return 2; }
    let port_u, ok_p = a[2].parse_u64_dec();
    guard ok_p && port_u <= 65535 else { return 2; }
    let keylog = if a.len >= 6 { a[5] } else { "" };
    return run_interop_server(port_u as u16, a[3], a[4], keylog);
}

fn dispatch_client_cli(a: u8[:][:]) -> i32 {
    guard a.len >= 7 else { return 2; }
    let port_u, ok_p = a[3].parse_u64_dec();
    guard ok_p && port_u > 0 && port_u <= 65535 else { return 2; }
    let keylog = if a.len >= 8 { a[7] } else { "" };
    return run_interop_client(a[2], port_u as u16, a[4], a[5], a[6], keylog);
}

fn main() {
    let a = args();
    guard a.len >= 2 else {
        print("USAGE: endpoint <server|client|h3spec-probe> ...\n");
        exit(2);
    }
    if a[1] == "h3spec-probe" {
        let settings = fingerprint::H3Settings { .. };
        probe_h3_control_and_stream_creation(settings);
        probe_h3_framing_and_grease(settings);
        return;
    }
    if a[1] == "server" { exit(dispatch_server_cli(a[..])); }
    if a[1] == "client" { exit(dispatch_client_cli(a[..])); }
    print("ERR:UNKNOWN_MODE\n");
    exit(2);
}
