// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic QUIC Connection Engine, Packet Number Spaces,
// Loss Recovery Coordinator, and Path Validation Reactor (RFC 9000, RFC 9002).
namespace quic;

import std;
import core;
import .packet;
import .AckFrame;
import .bbr;
import .frames;
import .stream;
import .flow_control;
import .migration;
import .dplpmtud;
import .conn_internal;
import .conn_crypto_internal;
import .internal;
import tls.record;
import tls.types;

enum QuicConnState {
    Initial,
    Handshake,
    Established,
    Closing,
    Draining,
    Closed,
}

// Outcome of processing an inbound QUIC datagram, packet, or frame payload.
struct ProcessResult {
    handled:   bool = false,
    needs_ack: bool = false,
}

struct QuicConnection {
    role:                       QuicRole              = QuicRole.Server,
    state:                      QuicConnState         = QuicConnState.Initial,
    version:                    u32                   = rfc::QUIC_VERSION_1,
    scid:                       u8[..20]              = [],
    dcid:                       u8[..20]              = [],
    original_dcid:              u8[..20]              = [],
    initial_space:              PnSpaceState          = PnSpaceState { space_id: PnSpaceId.Initial, .. },
    handshake_space:            PnSpaceState          = PnSpaceState { space_id: PnSpaceId.Handshake, .. },
    app_space:                  PnSpaceState          = PnSpaceState { space_id: PnSpaceId.ApplicationData, .. },
    tx_initial_space:           PnSpaceState          = PnSpaceState { space_id: PnSpaceId.Initial, .. },
    tx_handshake_space:         PnSpaceState          = PnSpaceState { space_id: PnSpaceId.Handshake, .. },
    tx_app_space:               PnSpaceState          = PnSpaceState { space_id: PnSpaceId.ApplicationData, .. },
    zero_rtt_keys:              QuicZeroRttKeys       = QuicZeroRttKeys { .. },
    initial_crypto:             tls::QuicCryptoStream = tls::QuicCryptoStream { .. },
    handshake_crypto:           tls::QuicCryptoStream = tls::QuicCryptoStream { .. },
    app_crypto:                 tls::QuicCryptoStream = tls::QuicCryptoStream { .. },
    rtt:                        RttState              = RttState { .. },
    pacer:                      Pacer                 = Pacer { .. },
    bbr:                        BbrState              = BbrState { .. },
    stream_table:               QuicStreamTable       = QuicStreamTable { .. },
    flow_ctrl:                  QuicFlowControl       = QuicFlowControl { .. },
    bytes_received:             u64                   = 0,
    bytes_sent:                 u64                   = 0,
    validated_address:          bool                  = false,
    packets_rx:                 u64                   = 0,
    packets_tx:                 u64                   = 0,
    close_code:                 u64                   = 0,
    allow_grease_quic_bit:      bool                  = false,
    retry_received:             bool                  = false,
    retry_token:                u8[..512]             = [],
    aead_failed_decrypts:       u64                   = 0,
    peer_reset_tokens:          u8[16][..8]           = [],
    peer_reset_token_seqs:      u64[..8]              = [],
    peer_cids:                  u8[..20][..8]         = [],
    peer_cid_seqs:              u64[..8]              = [],
    active_peer_cid_seq:        u64                   = 0,
    active_connection_id_limit: u64                   = 8,
    peer_retire_prior_to:       u64                   = 0,
    pending_retire_cids:        u64[..256]            = [],
    alt_scids:                  u8[..20][..4]         = [],
    migration:                  QuicMigrationManager  = QuicMigrationManager { .. },
    dplpmtud:                   Dplpmtud              = Dplpmtud { .. },
}

fn new_server_connection(scid: const u8[:]) -> QuicConnection {
    var conn = QuicConnection {
        role:              QuicRole.Server,
        state:             QuicConnState.Initial,
        bbr:               BbrState { .. },
        stream_table:      new_stream_table(QuicRole.Server),
        flow_ctrl:         new_flow_control(65536, 65536),
        validated_address: false,
        ..
    };
    conn.pacer = conn.bbr.pacer;
    conn.scid.append(scid[..min(scid.len, conn.scid.cap)]);
    return conn;
}

fn new_client_connection(server_dcid: const u8[:], client_scid: const u8[:]) -> QuicConnection {
    var conn = QuicConnection {
        role:              QuicRole.Client,
        state:             QuicConnState.Initial,
        bbr:               BbrState { .. },
        stream_table:      new_stream_table(QuicRole.Client),
        flow_ctrl:         new_flow_control(65536, 65536),
        validated_address: true, // Client address validation is implicit
        ..
    };
    conn.pacer = conn.bbr.pacer;
    let dcid_slice = server_dcid[..min(server_dcid.len, conn.dcid.cap)];
    conn.dcid.append(dcid_slice);
    conn.original_dcid.append(dcid_slice);
    conn.scid.append(client_scid[..min(client_scid.len, conn.scid.cap)]);
    return conn;
}

// RFC 9000 §8.1: Server anti-amplification limit (3x bytes received) and path capacity
fn can_send(conn: const QuicConnection&, bytes: u64) -> bool {
    guard !conn.validated_address && conn.role == QuicRole.Server else {
        return can_send(conn.migration.active_path, bytes);
    }
    let limit = quic_internal::calc_amplification_limit(conn.bytes_received);
    return quic_internal::is_within_amplification_budget(conn.bytes_sent, bytes, limit);
}

// Advances the connection state machine
fn advance_state(conn: QuicConnection&, new_state: QuicConnState) {
    conn.state = new_state;
}

// Closes connection with RFC 9000 transport or application error code
fn close(conn: QuicConnection&, err_code: u64) {
    conn.close_code = err_code;
    conn.state = QuicConnState.Closing;
}

// Routes an inbound ACK frame to loss recovery, RTT estimation, and the BBRv3 state machine.
fn on_ack(
    conn:      QuicConnection&,
    ack_frame: const AckFrame&,
    now_us:    u64       = 100000,
    space_id:  PnSpaceId = PnSpaceId.ApplicationData,
) -> bool {
    if space_id == PnSpaceId.Initial {
        return quic_internal::process_space_ack(conn, conn.initial_space, ack_frame, now_us, false);
    }
    if space_id == PnSpaceId.Handshake {
        return quic_internal::process_space_ack(conn, conn.handshake_space, ack_frame, now_us, false);
    }
    return quic_internal::process_space_ack(conn, conn.app_space, ack_frame, now_us, true);
}

// Records an egress packet for loss recovery and anti-amplification tracking
fn record_sent(
    conn:          QuicConnection&,
    space_id:      PnSpaceId,
    pn:            u64,
    size_bytes:    u64,
    ack_eliciting: bool,
    now_us:        u64,
) {
    conn.bytes_sent = core::add_sat_u64(conn.bytes_sent, size_bytes);
    conn.packets_tx = conn.packets_tx + 1;

    let meta = SentPacketMeta {
        pn:            pn,
        time_sent_us:  now_us,
        size_bytes:    size_bytes,
        ack_eliciting: ack_eliciting,
        in_flight:     ack_eliciting,
    };

    match space_id {
        Initial => {
            quic_internal::record_space_sent_packet(conn.initial_space, meta);
            conn.tx_initial_space.aead_encrypted_packets = core::add_sat_u64(
                conn.tx_initial_space.aead_encrypted_packets,
                1,
            );
        },
        Handshake => {
            quic_internal::record_space_sent_packet(conn.handshake_space, meta);
            conn.tx_handshake_space.aead_encrypted_packets = core::add_sat_u64(
                conn.tx_handshake_space.aead_encrypted_packets,
                1,
            );
        },
        ApplicationData => {
            quic_internal::record_space_sent_packet(conn.app_space, meta);
            conn.tx_app_space.aead_encrypted_packets = core::add_sat_u64(
                conn.tx_app_space.aead_encrypted_packets,
                1,
            );
        },
    }
}

// RFC 9000 Section 9.1: Initiates connection migration toward new remote endpoint
fn migrate(conn: QuicConnection&, new_addr: const QuicEndpointAddr&, token: const u8[8]&) {
    start_probing(conn.migration, new_addr, token);
}

// RFC 8899 Section 5.1: Handles acknowledgement of DPLPMTUD probe packet
fn on_probe_acked(conn: QuicConnection&, acked_size: u32, now_ms: u64 = 0) -> bool {
    return on_probe_acked(conn.dplpmtud, acked_size, now_ms);
}

// RFC 8899 Section 5.1: Handles loss / timeout of DPLPMTUD probe packet
fn on_probe_lost(conn: QuicConnection&, lost_size: u32, now_ms: u64 = 0) -> bool {
    return on_probe_lost(conn.dplpmtud, lost_size, now_ms);
}

// RFC 9000 Section 12.5 (Table 3): Validates whether a frame type is permitted in a packet type.
inline fn is_frame_allowed_in_packet(ftype: QuicFrameType, htype: QuicHeaderType) -> bool {
    guard ftype != QuicFrameType.Unknown else { return false; }
    guard htype != QuicHeaderType.Retry && htype != QuicHeaderType.VersionNegotiation else {
        return false;
    }
    if htype == QuicHeaderType.Initial || htype == QuicHeaderType.Handshake {
        return ftype == QuicFrameType.Padding
            || ftype == QuicFrameType.Ping
            || ftype == QuicFrameType.Ack
            || ftype == QuicFrameType.AckEcn
            || ftype == QuicFrameType.Crypto
            || ftype == QuicFrameType.ConnectionClose;
    }
    if htype == QuicHeaderType.ZeroRtt {
        if ftype == QuicFrameType.Ack
            || ftype == QuicFrameType.AckEcn
            || ftype == QuicFrameType.Crypto
            || ftype == QuicFrameType.HandshakeDone
            || ftype == QuicFrameType.NewToken
            || ftype == QuicFrameType.PathChallenge
            || ftype == QuicFrameType.PathResponse
            || ftype == QuicFrameType.RetireConnectionId
            || ftype == QuicFrameType.ConnectionClose
            || ftype == QuicFrameType.ConnectionCloseApp
            || ftype == QuicFrameType.ImmediateAck
            || ftype == QuicFrameType.AckFrequency {
            return false;
        }
        return true;
    }
    return true;
}

fn process_payload(
    conn:    QuicConnection&,
    payload: const u8[:],
    htype:   QuicHeaderType = QuicHeaderType.OneRtt,
    now_us:  u64            = 100000,
) -> ProcessResult {
    guard !quic_internal::quic_conn_is_closing_or_closed(conn.state) else {
        return ProcessResult { handled: false, needs_ack: false };
    }
    // RFC 9000 Section 12.4: Frames and Frame Types - An endpoint MUST treat receipt of a packet containing no frames as a connection error of type PROTOCOL_VIOLATION.
    guard payload.len > 0 else {
        close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
        return ProcessResult { handled: false, needs_ack: false };
    }
    var idx: i64 = 0;
    var any_ack_el = false;

    while idx < payload.len {
        let frame, ok = decode_frame_cursor(payload, idx);
        guard ok else {
            close(conn, rfc::QUIC_ERR_FRAME_ENCODING);
            return ProcessResult { handled: false, needs_ack: false };
        }

        guard is_frame_allowed_in_packet(frame.frame_type, htype) else {
            close(conn, rfc::QUIC_ERR_PROTOCOL_VIOLATION);
            return ProcessResult { handled: false, needs_ack: false };
        }

        if frame.frame_type == QuicFrameType.Ack || frame.frame_type == QuicFrameType.AckEcn {
            guard quic_internal::dispatch_inbound_ack_frame(conn, frame, htype, now_us) else {
                return ProcessResult { handled: false, needs_ack: false };
            }
        }

        let res = quic_internal::dispatch_inbound_frame(conn, frame, htype);
        guard res.handled else { return ProcessResult { handled: false, needs_ack: false }; }
        if quic_internal::quic_conn_is_closing_or_closed(conn.state) {
            return ProcessResult { handled: true, needs_ack: false };
        }
        if res.needs_ack {
            any_ack_el = true;
        }
    }

    return ProcessResult { handled: true, needs_ack: any_ack_el };
}

fn install_initial_keys(
    conn:    QuicConnection&,
    dcid:    const u8[:],
    version: u32 = rfc::QUIC_VERSION_1,
) -> bool {
    guard quic_internal::quic_derive_initial_space_keys(
        dcid,
        version,
        conn.role,
        conn.initial_space,
        conn.tx_initial_space,
    ) else {
        return false;
    }
    conn.version = version;
    return true;
}

// Derives and installs Handshake or Application traffic keys for `conn` from a TLS 1.3-over-QUIC
// secret (RFC 9001 Section 5.1).
fn install_tls_secret(
    conn:         QuicConnection&,
    level:        tls::QuicTlsLevel,
    is_read:      bool,
    secret:       const u8[:],
    cipher_suite: u16,
) -> bool {
    if level == tls::QuicTlsLevel.Handshake {
        if is_read {
            return quic_internal::quic_derive_and_install_keys(
                conn.handshake_space, secret, cipher_suite, conn.version, false,
            );
        }
        return quic_internal::quic_derive_and_install_keys(
            conn.tx_handshake_space, secret, cipher_suite, conn.version, false,
        );
    }
    if level == tls::QuicTlsLevel.Application {
        if is_read {
            return quic_internal::quic_derive_and_install_keys(
                conn.app_space, secret, cipher_suite, conn.version, true,
            );
        }
        return quic_internal::quic_derive_and_install_keys(
            conn.tx_app_space, secret, cipher_suite, conn.version, true,
        );
    }
    return false;
}

// Zeroizes all AEAD, header protection, and traffic secrets in `space` and clears sent tracking
// (RFC 9001 Section 4.9).
fn clear_space_keys(space: PnSpaceState&) {
    core::secure_zeroize_slice(space.hp_key[..]);
    core::secure_zeroize_slice(space.aead_key[..]);
    core::secure_zeroize_slice(space.aead_iv[..]);
    core::secure_zeroize_slice(space.traffic_secret[..]);
    core::secure_zeroize_slice(space.prev_aead_key[..]);
    core::secure_zeroize_slice(space.prev_aead_iv[..]);
    core::secure_zeroize_slice(space.next_traffic_secret[..]);
    core::secure_zeroize_slice(space.next_aead_key[..]);
    core::secure_zeroize_slice(space.next_aead_iv[..]);
    space.hp_key.clear();
    space.aead_key.clear();
    space.aead_iv.clear();
    space.traffic_secret.clear();
    space.prev_aead_key.clear();
    space.prev_aead_iv.clear();
    space.next_traffic_secret.clear();
    space.next_aead_key.clear();
    space.next_aead_iv.clear();
    space.keys_installed = false;
    space.has_app_secret = false;
    space.has_prev_keys = false;
    space.has_next_keys = false;
    space.min_tracked_pn = 0;
    space.has_min_tracked_pn = false;
    space.loss_time_us = 0;
    space.sent_packets.clear();
    space.skipped_pns.clear();
}

// Zeroizes all encryption keys, secrets, reset tokens, and CRYPTO buffers owned by `conn`.
fn zeroize_connection_secrets(conn: QuicConnection&) {
    clear_space_keys(conn.initial_space);
    clear_space_keys(conn.tx_initial_space);
    clear_space_keys(conn.handshake_space);
    clear_space_keys(conn.tx_handshake_space);
    clear_space_keys(conn.app_space);
    clear_space_keys(conn.tx_app_space);

    core::secure_zeroize_slice(conn.zero_rtt_keys.hp_key[..]);
    core::secure_zeroize_slice(conn.zero_rtt_keys.aead_key[..]);
    core::secure_zeroize_slice(conn.zero_rtt_keys.aead_iv[..]);
    conn.zero_rtt_keys = QuicZeroRttKeys { .. };

    core::secure_zeroize_slice(conn.initial_crypto.buf[..]);
    core::secure_zeroize_slice(conn.initial_crypto.ooo_ring[..]);
    core::secure_zeroize_slice(conn.handshake_crypto.buf[..]);
    core::secure_zeroize_slice(conn.handshake_crypto.ooo_ring[..]);
    core::secure_zeroize_slice(conn.app_crypto.buf[..]);
    core::secure_zeroize_slice(conn.app_crypto.ooo_ring[..]);
    conn.initial_crypto = tls::QuicCryptoStream { .. };
    conn.handshake_crypto = tls::QuicCryptoStream { .. };
    conn.app_crypto = tls::QuicCryptoStream { .. };
}

// Installs separate 0-RTT receive keys on a server connection (RFC 9001 Section 5.3).
fn install_zero_rtt_keys(
    conn:         QuicConnection&,
    hp_key:       const u8[:],
    aead_key:     const u8[:],
    aead_iv:      const u8[:],
    cipher_suite: u16 = 0x1301,
) -> bool {
    guard conn.role == QuicRole.Server else { return false; }
    guard hp_key.len <= conn.zero_rtt_keys.hp_key.cap
        && aead_key.len <= conn.zero_rtt_keys.aead_key.cap
        && aead_iv.len == 12 else {
        return false;
    }
    guard conn.zero_rtt_keys.hp_key.try_set(hp_key)
        && conn.zero_rtt_keys.aead_key.try_set(aead_key)
        && conn.zero_rtt_keys.aead_iv.try_set(aead_iv) else {
        return false;
    }
    conn.zero_rtt_keys.cipher_suite = cipher_suite;
    conn.zero_rtt_keys.keys_installed = true;
    return true;
}

// Computes the 16-byte Retry Integrity Tag over the Retry Pseudo-Packet (RFC 9001 §5.8, RFC 9369 §3.3.3).
fn compute_retry_integrity_tag(
    odcid:             const u8[:],
    retry_without_tag: const u8[:],
    version:           u32 = rfc::QUIC_VERSION_1,
) -> u8[16], bool {
    guard odcid.len <= rfc::QUIC_MAX_CID_LEN && retry_without_tag.len >= 8 else {
        return [0; 16], false;
    }
    let key_slice = rfc::quic_retry_key(version);
    let nonce_slice = rfc::quic_retry_nonce(version);
    guard key_slice.len == 16 && nonce_slice.len == 12 else { return [0; 16], false; }

    var pseudo: u8[..1280] = [];
    guard pseudo.try_push(odcid.len as u8)
        && pseudo.try_append(odcid)
        && pseudo.try_append(retry_without_tag) else {
        return [0; 16], false;
    }

    var key16: u8[16] = [0; 16];
    defer core::secure_zeroize_16(key16);
    for i in 16 { key16[i] = key_slice[i]; }
    var nonce12: u8[12] = [0; 12];
    for i in 12 { nonce12[i] = nonce_slice[i]; }
    var empty_ct: u8[..1] = [];
    return core::aes128_gcm_seal_inplace(key16, nonce12, empty_ct[..], pseudo[..]);
}

// Verifies the 16-byte Retry Integrity Tag in constant time (RFC 9001 §5.8, RFC 9369 §3.3.3).
fn verify_retry_integrity_tag(
    odcid:     const u8[:],
    retry_pkt: const u8[:],
    version:   u32 = rfc::QUIC_VERSION_1,
) -> bool {
    guard retry_pkt.len >= 24 else { return false; }
    let tag_off = core::sub_sat_i64(retry_pkt.len, 16);
    let expected_tag, ok = compute_retry_integrity_tag(odcid, retry_pkt[..tag_off], version);
    guard ok else { return false; }
    return core::ct_eq_bytes(expected_tag[..], retry_pkt[tag_off..]);
}

// Advances a 1-RTT packet number space to the next RFC 9001 Section 6 Key Update phase.
fn initiate_key_update(space: PnSpaceState&, version: u32 = rfc::QUIC_VERSION_1) -> bool {
    guard space.keys_installed && space.has_app_secret else { return false; }
    return quic_internal::quic_ratchet_space_keys(space, version);
}

// Seals and applies RFC 9001 Header Protection to a QUIC packet payload in `space`.
fn seal_packet<B>(
    space:     const PnSpaceState&,
    hdr:       const QuicHeader&,
    pn_len:    u8,
    plaintext: const u8[:],
    out:       B&,
) -> bool {
    guard space.keys_installed && space.aead_iv.len == 12 else { return false; }
    guard pn_len >= 1 && pn_len <= 4 && plaintext.len > 0 else { return false; }
    // RFC 9000 Section 12.3 & RFC 9001 Section 6.6: Enforce PN ceiling and AEAD confidentiality limit.
    guard hdr.packet_number <= rfc::QUIC_MAX_PN else { return false; }
    guard space.aead_encrypted_packets < quic_internal::quic_aead_confidentiality_limit(space.cipher_suite) else {
        return false;
    }

    var hdr_wire = hdr;
    if hdr_wire.header_type == QuicHeaderType.OneRtt {
        hdr_wire.key_phase = space.key_phase;
    } else {
        hdr_wire.payload_length = (pn_len as u64) + (plaintext.len as u64) + 16;
    }

    var work_hdr: u8[..600] = [];
    guard encode_header(hdr_wire, pn_len, work_hdr) else { return false; }
    let pn_offset = (work_hdr.len - (pn_len as i64)) as u32;

    var iv12: u8[12] = [0; 12];
    for i in 12 { iv12[i] = space.aead_iv[i]; }
    let nonce, ok_nonce = tls::compute_record_nonce(iv12, hdr.packet_number);
    guard ok_nonce else { return false; }

    var ct_buf: u8[..16384] = [];
    guard ct_buf.try_append(plaintext) else { return false; }
    let tag, ok_seal = quic_internal::quic_aead_seal_payload_inplace(space, nonce, work_hdr[..], ct_buf[..]);
    guard ok_seal else { return false; }

    var full_pkt: u8[..17000] = [];
    guard full_pkt.try_append(work_hdr[..])
        && full_pkt.try_append(ct_buf[..])
        && full_pkt.try_append(tag[..]) else {
        return false;
    }

    let sample_slice, ok_samp = tls::quic_extract_hp_sample(full_pkt[..], pn_offset);
    guard ok_samp else { return false; }
    let hp_mask, ok_mask = quic_internal::quic_compute_hp_mask(space, sample_slice);
    guard ok_mask else { return false; }

    apply_header_protection(full_pkt[..], pn_offset, pn_len, hp_mask);
    return out.try_append(full_pkt[..]);
}

// Seals a packet and increments `space.aead_encrypted_packets` for RFC 9001 Section 6.6 accounting.
fn seal_packet_tracked<B>(
    space:     PnSpaceState&,
    hdr:       const QuicHeader&,
    pn_len:    u8,
    plaintext: const u8[:],
    out:       B&,
) -> bool {
    guard seal_packet(space, hdr, pn_len, plaintext, out) else { return false; }
    space.aead_encrypted_packets = core::add_sat_u64(space.aead_encrypted_packets, 1);
    return true;
}

// Processes a single QUIC packet slice inside a coalesced datagram, returning consumed bytes,
// process status, decrypted frame payload, and decoded header type.
fn process_coalesced_packet(
    conn:      QuicConnection&,
    pkt_slice: const u8[:],
    dgram_len: i64,
    now_us:    u64,
    out_ack:   AckFrame&,
    out_plain: u8[..16384]&,
    out_htype: QuicHeaderType&,
) -> i64, ProcessResult {
    return quic_internal::process_single_coalesced_packet_with_plain(
        conn, pkt_slice, dgram_len, now_us, out_ack, out_plain, out_htype, false,
    );
}

// RFC 9000 Section 12.2: Coalescing Packets - Processes an inbound UDP datagram containing one or more coalesced QUIC packets.
fn process_datagram(
    conn:   QuicConnection&,
    dgram:  const u8[:],
    now_us: u64,
    ack:    AckFrame&,
) -> ProcessResult {
    guard dgram.len > 0 else { return ProcessResult { handled: false, needs_ack: false }; }
    conn.bytes_received = core::add_sat_u64(conn.bytes_received, dgram.len as u64);

    var offset: i64 = 0;
    var any_handled = false;
    var final_needs_ack = false;

    while offset < dgram.len {
        let rem = dgram[offset..];
        let consumed, res = quic_internal::process_single_coalesced_packet(conn, rem, dgram.len, now_us, ack);
        guard res.handled && consumed > 0 else {
            return ProcessResult { handled: any_handled, needs_ack: final_needs_ack };
        }
        any_handled = true;
        if res.needs_ack {
            final_needs_ack = true;
        }
        offset += consumed;
    }

    return ProcessResult { handled: any_handled, needs_ack: final_needs_ack };
}
