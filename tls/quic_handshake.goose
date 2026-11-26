// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9001 TLS 1.3-over-QUIC CRYPTO handshake engine with 0x0039 and pre-handshake SNI.
namespace tls;

import std;
import core;
import rfc;
import .internal;
import .record;
import .key_schedule;
import .handshake;
import .handshake_internal;
import .handshake_wire_internal;
import .pem;
import .session_internal;
import .session_codec_internal;
import .session_wire_internal;
import .handshake_io_client_internal;
import .handshake_io_server_internal;
import .backend_pure_internal;
import .types;

const QUIC_TLS_MAX_TP_LEN:     i64 = 2048;
const QUIC_TLS_MAX_HS_MSG_LEN: i64 = 24576;

enum QuicSrvStage {
    WaitClientHello1,
    WaitSniCredentials,
    WaitClientHello2,
    WaitClientFinished,
    Established,
    Failed,
}

enum QuicCliStage {
    Init,
    WaitServerHello,
    WaitEE,
    WaitCert,
    WaitCV,
    WaitServerFinished,
    Established,
    Failed,
}

struct QuicTlsServerSlot {
    active:          bool                      = false,
    generation:      u64                       = 0,
    defer_sni:       bool                      = false,
    has_creds:       bool                      = false,
    hrr_cipher:      u16                       = 0,
    hrr_group:       u16                       = 0,
    cipher_suite:    u16                       = 0,
    stage:           QuicSrvStage              = QuicSrvStage.WaitClientHello1,
    last_alert:      Alert                     = Alert.CloseNotify,
    alpn_csv:        u8[..255]                 = [],
    negotiated_alpn: u8[..255]                 = [],
    client_sni:      u8[..255]                 = [],
    hrr_sni:         u8[..255]                 = [],
    hrr_alpn:        u8[..255]                 = [],
    local_tp:        u8[..2048]                = [],
    peer_tp:         u8[..2048]                = [],
    cert_der:        u8[..4096]                = [],
    extra_certs_der: u8[..4096][..3]           = [],
    priv_seed:       u8[32]                    = [0; 32],
    key_kind:        PrivateKeyKind            = PrivateKeyKind.Unknown,
    rsa_key_slot:    i32                       = -1,
    rsa_key_gen:     u32                       = 0,
    pending_ch_msg:  u8[..8192]                = [],
    rx_initial_buf:  u8[..8192]                = [],
    tx_initial_buf:  u8[..4096]                = [],
    rx_hs_buf:       u8[..1024]                = [],
    tx_hs_buf:       u8[..24576]               = [],
    ts:              Transcript                = Transcript { .. },
    ks:              tls_internal::KeySchedule = tls_internal::KeySchedule { .. },
    sec_queue:       QuicTlsSecrets[..4]       = [],
}

struct QuicTlsClientSlot {
    active:          bool                      = false,
    generation:      u64                       = 0,
    hrr_received:    bool                      = false,
    preferred_group: u16                       = rfc::GROUP_X25519,
    active_group:    u16                       = 0,
    hrr_cipher:      u16                       = 0,
    hrr_group:       u16                       = 0,
    key_share_mode:  QuicClientKeyShareMode    = QuicClientKeyShareMode.SendInitialShare,
    stage:           QuicCliStage              = QuicCliStage.Init,
    last_alert:      Alert                     = Alert.CloseNotify,
    nst_count:       u8                        = 0,
    alpn_csv:        u8[..255]                 = [],
    negotiated_alpn: u8[..255]                 = [],
    local_tp:        u8[..2048]                = [],
    peer_tp:         u8[..2048]                = [],
    client_random:   u8[32]                    = [0; 32],
    eph_priv:        u8[32]                    = [0; 32],
    eph_pub:         u8[..65]                  = [],
    ts_to_cert:      u8[..48]                  = [],
    peer_cert_body:  u8[..24576]               = [],
    rx_initial_buf:  u8[..4096]                = [],
    tx_initial_buf:  u8[..4096]                = [],
    rx_hs_buf:       u8[..24576]               = [],
    tx_hs_buf:       u8[..1024]                = [],
    rx_app_buf:      u8[..8192]                = [],
    client_cfg:      ClientHandshakeConfig     = ClientHandshakeConfig { .. },
    ts:              Transcript                = Transcript { .. },
    ks:              tls_internal::KeySchedule = tls_internal::KeySchedule { .. },
    sec_queue:       QuicTlsSecrets[..4]       = [],
}

var g_quic_tls_srv_slots:    QuicTlsServerSlot[>..] = [];
var g_quic_tls_srv_next_gen: u64                    = 0;
var g_quic_tls_cli_slots:    QuicTlsClientSlot[>..] = [];
var g_quic_tls_cli_next_gen: u64                    = 0;

fn next_quic_generation(counter: u64&) -> u64 {
    counter = counter + 1;
    if counter == 0 {
        counter = 1;
    }
    return counter;
}

fn release_quic_srv_signing_creds(slot: QuicTlsServerSlot&) {
    if slot.rsa_key_slot >= 0 {
        release_rsa_key_slot(slot.rsa_key_slot, slot.rsa_key_gen);
        slot.rsa_key_slot = -1;
        slot.rsa_key_gen = 0;
    }
    core::secure_zeroize_32(slot.priv_seed);
}

fn zeroize_quic_secrets_queue(queue: QuicTlsSecrets[..4]&) {
    queue.resize(queue.cap, QuicTlsSecrets { .. });
    for i in queue.len {
        core::secure_zeroize_48(queue[i].read_secret);
        core::secure_zeroize_48(queue[i].write_secret);
        queue[i] = QuicTlsSecrets { .. };
    }
    queue.clear();
}

fn zeroize_srv_slot(slot: QuicTlsServerSlot&) {
    release_quic_srv_signing_creds(slot);
    core::secure_zeroize_slice(slot.pending_ch_msg[..]);
    core::secure_zeroize_slice(slot.rx_initial_buf[..]);
    core::secure_zeroize_slice(slot.rx_hs_buf[..]);
    tls_internal::ks_zeroize(slot.ks);
    zeroize_quic_secrets_queue(slot.sec_queue);
    slot = QuicTlsServerSlot { .. };
}

fn zeroize_cli_slot(slot: QuicTlsClientSlot&) {
    core::secure_zeroize_32(slot.client_random);
    core::secure_zeroize_32(slot.eph_priv);
    core::secure_zeroize_slice(slot.eph_pub[..]);
    core::secure_zeroize_slice(slot.client_cfg.client_priv_seed[..]);
    core::secure_zeroize_slice(slot.rx_initial_buf[..]);
    core::secure_zeroize_slice(slot.rx_hs_buf[..]);
    core::secure_zeroize_slice(slot.rx_app_buf[..]);
    tls_internal::ks_zeroize(slot.ks);
    zeroize_quic_secrets_queue(slot.sec_queue);
    slot = QuicTlsClientSlot { .. };
}

fn lookup_live_srv_slot_idx(srv: const QuicTlsServer&) -> i64 {
    guard srv.generation != 0 && srv.slot_idx >= 0 else { return -1; }
    let idx = srv.slot_idx as i64;
    guard idx < g_quic_tls_srv_slots.len else { return -1; }
    let slot .= g_quic_tls_srv_slots[idx];
    guard slot.active && slot.generation == srv.generation else { return -1; }
    return idx;
}

fn lookup_live_cli_slot_idx(cli: const QuicTlsClient&) -> i64 {
    guard cli.generation != 0 && cli.slot_idx >= 0 else { return -1; }
    let idx = cli.slot_idx as i64;
    guard idx < g_quic_tls_cli_slots.len else { return -1; }
    let slot .= g_quic_tls_cli_slots[idx];
    guard slot.active && slot.generation == cli.generation else { return -1; }
    return idx;
}

fn quic_srv_fail(slot: QuicTlsServerSlot&, alert: Alert) -> QuicTlsStatus {
    slot.stage = QuicSrvStage.Failed;
    slot.last_alert = alert;
    release_quic_srv_signing_creds(slot);
    slot.has_creds = false;
    core::secure_zeroize_slice(slot.pending_ch_msg[..]);
    core::secure_zeroize_slice(slot.rx_initial_buf[..]);
    core::secure_zeroize_slice(slot.rx_hs_buf[..]);
    slot.pending_ch_msg.clear();
    slot.rx_initial_buf.clear();
    slot.rx_hs_buf.clear();
    slot.tx_initial_buf.clear();
    slot.tx_hs_buf.clear();
    tls_internal::ks_zeroize(slot.ks);
    zeroize_quic_secrets_queue(slot.sec_queue);
    return QuicTlsStatus.AlertError;
}

fn quic_cli_fail(slot: QuicTlsClientSlot&, alert: Alert) -> QuicTlsStatus {
    slot.stage = QuicCliStage.Failed;
    slot.last_alert = alert;
    core::secure_zeroize_32(slot.client_random);
    core::secure_zeroize_32(slot.eph_priv);
    core::secure_zeroize_slice(slot.eph_pub[..]);
    core::secure_zeroize_slice(slot.client_cfg.client_priv_seed[..]);
    core::secure_zeroize_slice(slot.peer_cert_body[..]);
    core::secure_zeroize_slice(slot.rx_initial_buf[..]);
    core::secure_zeroize_slice(slot.rx_hs_buf[..]);
    core::secure_zeroize_slice(slot.rx_app_buf[..]);
    slot.eph_pub.clear();
    slot.peer_cert_body.clear();
    slot.rx_initial_buf.clear();
    slot.rx_hs_buf.clear();
    slot.rx_app_buf.clear();
    slot.tx_initial_buf.clear();
    slot.tx_hs_buf.clear();
    tls_internal::ks_zeroize(slot.ks);
    zeroize_quic_secrets_queue(slot.sec_queue);
    return QuicTlsStatus.AlertError;
}

fn load_srv_slot_creds_pem(
    slot:     QuicTlsServerSlot&,
    cert_pem: const u8[:],
    key_pem:  const u8[:],
) -> bool {
    guard cert_pem.len > 0 && key_pem.len > 0 else { return false; }
    var cfg = ServerHandshakeConfig { .. };
    defer release_server_credentials(cfg);
    guard load_server_credentials_pem(cert_pem, key_pem, cfg) else { return false; }
    guard slot.cert_der.try_set(cfg.cert_der[..]) else { return false; }

    release_quic_srv_signing_creds(slot);
    slot.extra_certs_der = copy(cfg.extra_certs_der);
    slot.priv_seed = cfg.priv_seed;
    slot.key_kind = cfg.key_kind;
    slot.rsa_key_slot = cfg.rsa_key_slot;
    slot.rsa_key_gen = cfg.rsa_key_gen;
    slot.has_creds = true;
    cfg.rsa_key_slot = -1;
    cfg.rsa_key_gen = 0;
    return true;
}

fn enqueue_quic_secret_pair(
    queue:        QuicTlsSecrets[..4]&,
    level:        QuicTlsLevel,
    cipher_suite: u16,
    hash_len:     u8,
    read_sec:     const u8[:],
    write_sec:    const u8[:],
) -> bool {
    var entry = QuicTlsSecrets {
        level:        level,
        cipher_suite: cipher_suite,
        hash_len:     hash_len,
        ..
    };
    if read_sec.len > 0 {
        guard read_sec.len >= hash_len && hash_len <= 48 else { return false; }
        core::ct_copy_bytes(entry.read_secret[..hash_len], read_sec[..hash_len]);
        entry.has_read = true;
    }
    if write_sec.len > 0 {
        guard write_sec.len >= hash_len && hash_len <= 48 else { return false; }
        core::ct_copy_bytes(entry.write_secret[..hash_len], write_sec[..hash_len]);
        entry.has_write = true;
    }
    return queue.try_push(entry);
}

fn pop_quic_secret(queue: QuicTlsSecrets[..4]&, out_sec: QuicTlsSecrets&) -> bool {
    guard queue.len > 0 else { return false; }
    out_sec = queue[0];
    core::secure_zeroize_48(queue[0].read_secret);
    core::secure_zeroize_48(queue[0].write_secret);
    let rem = core::sub_sat_i64(queue.len, 1);
    for i in 0..rem {
        queue[i] = queue[core::add_sat_i64(i, 1)];
    }
    core::secure_zeroize_48(queue[rem].read_secret);
    core::secure_zeroize_48(queue[rem].write_secret);
    queue[rem] = QuicTlsSecrets { .. };
    queue.resize(rem);
    return true;
}

fn queue_srv_app_read_secret(slot: QuicTlsServerSlot&, c_ap: const u8[:]) -> bool {
    let hlen = slot.ks.hash_len as i64;
    for i in slot.sec_queue.len {
        let sec .= slot.sec_queue[i];
        if sec.level == QuicTlsLevel.Application && sec.has_write && !sec.has_read {
            guard c_ap.len >= hlen && hlen <= 48 else { return false; }
            core::ct_copy_bytes(sec.read_secret[..hlen], c_ap[..hlen]);
            sec.has_read = true;
            return true;
        }
    }
    return enqueue_quic_secret_pair(
        slot.sec_queue,
        QuicTlsLevel.Application,
        slot.ks.cipher_suite,
        slot.ks.hash_len,
        c_ap,
        "",
    );
}

fn emit_srv_hrr_initial(
    slot:   QuicTlsServerSlot&,
    ch_msg: const u8[:],
    choice: const tls_internal::ServerClientHelloChoice&,
) -> QuicTlsStatus {
    var ks, ok_ks = tls_internal::ks_init(choice.cipher_suite);
    guard ok_ks else { return quic_srv_fail(slot, Alert.HandshakeFailure); }
    slot.ks = ks;
    slot.cipher_suite = choice.cipher_suite;
    slot.hrr_cipher = choice.cipher_suite;
    slot.hrr_group = choice.selected_group;
    guard slot.hrr_sni.try_set(choice.client_sni[..]) &&
        slot.hrr_alpn.try_set(choice.negotiated_alpn[..]) else {
        return quic_srv_fail(slot, Alert.DecodeError);
    }
    slot.ts = Transcript { .. };
    tls_internal::transcript_update(slot.ts, ch_msg);
    guard tls_internal::transcript_replace_with_message_hash(
        slot.ts, slot.ks.hash_id, slot.ks.hash_len,
    ) else {
        return quic_srv_fail(slot, Alert.InternalError);
    }

    var hrr_pay: u8[..256] = [];
    tls_internal::build_hrr_payload(
        choice.session_id[..], choice.cipher_suite, choice.selected_group, hrr_pay,
    );
    var hrr_msg: u8[..300] = [];
    guard tls_internal::frame_handshake_msg_4k(rfc::TLS_HS_SERVER_HELLO, hrr_pay[..], hrr_msg) &&
        slot.tx_initial_buf.try_append(hrr_msg[..]) else {
        return quic_srv_fail(slot, Alert.InternalError);
    }
    tls_internal::transcript_update(slot.ts, hrr_msg[..]);
    slot.stage = QuicSrvStage.WaitClientHello2;
    return QuicTlsStatus.Ok;
}

fn emit_srv_ee_message(slot: QuicTlsServerSlot&) -> bool {
    var ee_ext: u8[..2320] = [];
    if slot.negotiated_alpn.len > 0 {
        tls_internal::encode_alpn_extension_from_csv(ee_ext, slot.negotiated_alpn[..]);
    }
    // RFC 9001 Section 8.2: QUIC Transport Parameters Extension - EncryptedExtensions MUST carry 0x0039.
    guard tls_internal::encode_quic_tp_extension(ee_ext, slot.local_tp[..]) else { return false; }

    var ee_pay: u8[..2330] = [];
    let hdr: u8[2] = [((ee_ext.len >> 8) & 0xFF) as u8, (ee_ext.len & 0xFF) as u8];
    guard ee_pay.try_append(hdr[..]) && ee_pay.try_append(ee_ext[..]) else { return false; }

    var ee_msg: u8[..2340] = [];
    guard tls_internal::frame_handshake_msg_4k(rfc::TLS_HS_ENCRYPTED_EXTENSIONS, ee_pay[..], ee_msg) &&
        slot.tx_hs_buf.try_append(ee_msg[..]) else {
        return false;
    }
    tls_internal::transcript_update(slot.ts, ee_msg[..]);
    return true;
}

fn emit_srv_cert_and_cv_messages(slot: QuicTlsServerSlot&) -> bool {
    defer core::secure_scrub_stack();
    defer release_quic_srv_signing_creds(slot);
    var cert_msg: u8[..20500] = [];
    guard tls_internal::encode_server_cert_chain_msg(
        slot.cert_der[..], slot.extra_certs_der[..], cert_msg,
    ) && slot.tx_hs_buf.try_append(cert_msg[..]) else {
        return false;
    }
    tls_internal::transcript_update(slot.ts, cert_msg[..]);

    var h_to_cert: u8[..48] = [];
    tls_internal::transcript_current_hash(slot.ts, slot.ks.hash_id, h_to_cert);
    var cv_input: u8[160] = [0; 160];
    let cv_len, ok_cv = build_certificate_verify_message(true, h_to_cert[..], cv_input[..]);
    var sig_buf: u8[..512] = [];
    defer core::secure_zeroize_slice(sig_buf[..]);
    let sig_scheme, ok_sig = tls_internal::sign_certificate_verify(
        slot.cert_der[..],
        slot.priv_seed,
        cv_input[..cv_len],
        sig_buf,
        slot.rsa_key_slot,
        slot.rsa_key_gen,
    );
    var cv_pay: u8[..1024] = [];
    var cv_msg: u8[..1024] = [];
    guard ok_cv &&
        ok_sig &&
        encode_client_certificate_verify(cv_pay, sig_scheme, sig_buf[..]) &&
        tls_internal::frame_handshake_msg_4k(rfc::TLS_HS_CERTIFICATE_VERIFY, cv_pay[..], cv_msg) &&
        slot.tx_hs_buf.try_append(cv_msg[..]) else {
        return false;
    }
    tls_internal::transcript_update(slot.ts, cv_msg[..]);
    return true;
}

fn emit_srv_finished_and_app_write(slot: QuicTlsServerSlot&) -> bool {
    var h_to_cv: u8[..48] = [];
    tls_internal::transcript_current_hash(slot.ts, slot.ks.hash_id, h_to_cv);
    var fin_vd: u8[48] = [0; 48];
    defer core::secure_zeroize_48(fin_vd);
    let hlen = slot.ks.hash_len as i64;
    guard tls_internal::ks_compute_finished_verify_data(
        slot.ks.hash_id,
        slot.ks.hash_len,
        slot.ks.server_hs_traffic[..hlen],
        h_to_cv[..],
        fin_vd[..hlen],
    ) else {
        return false;
    }

    var fin_msg: u8[..64] = [];
    guard tls_internal::frame_handshake_msg_4k(rfc::TLS_HS_FINISHED, fin_vd[..hlen], fin_msg) &&
        slot.tx_hs_buf.try_append(fin_msg[..]) else {
        return false;
    }
    tls_internal::transcript_update(slot.ts, fin_msg[..]);

    var h_to_srv_fin: u8[..48] = [];
    tls_internal::transcript_current_hash(slot.ts, slot.ks.hash_id, h_to_srv_fin);
    guard tls_internal::ks_advance_to_master(slot.ks, h_to_srv_fin[..]) else { return false; }

    // RFC 9001 Section 4.1.5: TLS Interface Summary - Export 1-RTT write secret after server Finished.
    return enqueue_quic_secret_pair(
        slot.sec_queue,
        QuicTlsLevel.Application,
        slot.ks.cipher_suite,
        slot.ks.hash_len,
        "",
        slot.ks.server_ap_traffic[..],
    );
}

fn emit_srv_full_flight(
    slot:   QuicTlsServerSlot&,
    ch_msg: const u8[:],
    choice: const tls_internal::ServerClientHelloChoice&,
) -> QuicTlsStatus {
    guard slot.negotiated_alpn.try_set(choice.negotiated_alpn[..]) else {
        return quic_srv_fail(slot, Alert.DecodeError);
    }
    if slot.stage == QuicSrvStage.WaitClientHello1 {
        var ks, ok_ks = tls_internal::ks_init(choice.cipher_suite);
        guard ok_ks else { return quic_srv_fail(slot, Alert.HandshakeFailure); }
        slot.ks = ks;
        slot.cipher_suite = choice.cipher_suite;
        slot.ts = Transcript { .. };
    }
    tls_internal::transcript_update(slot.ts, ch_msg);

    var srv_rand:  u8[32]   = [0; 32];
    var srv_share: u8[..65] = [];
    var ecdhe:     u8[32]   = [0; 32];
    defer core::secure_scrub_stack();
    defer core::secure_zeroize_32(ecdhe);
    guard tls_internal::generate_server_handshake_keys_for_group(
        choice.selected_group, choice.client_share[..], srv_rand, srv_share, ecdhe,
    ) else {
        return quic_srv_fail(slot, Alert.IllegalParameter);
    }

    var sh_pay: u8[..256] = [];
    tls_internal::build_server_hello_payload_for_group(
        srv_rand,
        choice.session_id[..],
        choice.selected_group,
        srv_share[..],
        sh_pay,
        false,
        choice.cipher_suite,
        0,
    );
    var sh_msg: u8[..300] = [];
    guard tls_internal::frame_handshake_msg_4k(rfc::TLS_HS_SERVER_HELLO, sh_pay[..], sh_msg) &&
        slot.tx_initial_buf.try_append(sh_msg[..]) else {
        return quic_srv_fail(slot, Alert.InternalError);
    }
    tls_internal::transcript_update(slot.ts, sh_msg[..]);

    var h_to_sh: u8[..48] = [];
    tls_internal::transcript_current_hash(slot.ts, slot.ks.hash_id, h_to_sh);
    guard tls_internal::ks_init_early_secret(slot.ks, "") &&
        tls_internal::ks_advance_to_handshake(slot.ks, ecdhe[..]) &&
        tls_internal::ks_derive_handshake_traffic(slot.ks, h_to_sh[..]) &&
        enqueue_quic_secret_pair(
            slot.sec_queue,
            QuicTlsLevel.Handshake,
            slot.ks.cipher_suite,
            slot.ks.hash_len,
            slot.ks.client_hs_traffic[..],
            slot.ks.server_hs_traffic[..],
        ) else {
            return quic_srv_fail(slot, Alert.InternalError);
        }

    // RFC 9001 Section 4.1.4: Encryption Level Changes - EncryptedExtensions..Finished go on Handshake level.
    guard emit_srv_ee_message(slot) &&
        emit_srv_cert_and_cv_messages(slot) &&
        emit_srv_finished_and_app_write(slot) else {
        return quic_srv_fail(slot, Alert.InternalError);
    }
    slot.stage = QuicSrvStage.WaitClientFinished;
    return QuicTlsStatus.Ok;
}

fn srv_matches_hrr_ch2(
    slot:   const QuicTlsServerSlot&,
    choice: const tls_internal::ServerClientHelloChoice&,
) -> bool {
    return choice.cipher_suite == slot.hrr_cipher &&
        choice.selected_group == slot.hrr_group &&
        choice.has_quic_tp &&
        choice.client_sni[..] == slot.hrr_sni[..] &&
        choice.negotiated_alpn[..] == slot.hrr_alpn[..];
}

fn eval_srv_ch_choice(
    slot:       const QuicTlsServerSlot&,
    ch_msg:     const u8[:],
    out_choice: tls_internal::ServerClientHelloChoice&,
) -> Alert, bool {
    var req_sig: u16 = 0;
    if slot.has_creds {
        req_sig = tls_internal::detect_cert_sig_scheme(slot.cert_der[..]);
        guard req_sig != 0 else {
            return Alert.InternalError, false;
        }
    }
    let hrr_mode = if slot.stage == QuicSrvStage.WaitClientHello2 {
        tls_internal::ServerHrrMode.Reject
    } else {
        tls_internal::ServerHrrMode.Allow
    };
    let alpn_policy = if slot.alpn_csv.len > 0 {
        tls_internal::ServerAlpnPolicy.RequireMatch
    } else {
        tls_internal::ServerAlpnPolicy.Optional
    };
    let ok_ch = tls_internal::parse_server_client_hello(
        ch_msg,
        slot.alpn_csv[..],
        req_sig,
        0,
        hrr_mode,
        out_choice,
        false,
        tls_internal::ServerPskPolicy.DisableResumption,
        alpn_policy,
        QuicExtensionMode.Quic,
    );
    guard ok_ch else {
        let fail_a = if out_choice.failure_alert != Alert.CloseNotify {
            out_choice.failure_alert
        } else {
            Alert.HandshakeFailure
        };
        return fail_a, false;
    }
    return Alert.CloseNotify, true;
}

fn process_srv_ch_msg(slot: QuicTlsServerSlot&, ch_msg: const u8[:]) -> QuicTlsStatus {
    var choice = tls_internal::ServerClientHelloChoice { .. };
    defer tls_internal::zeroize_server_ch_choice(choice);

    let fail_a, ok_ch = eval_srv_ch_choice(slot, ch_msg, choice);
    guard ok_ch else { return quic_srv_fail(slot, fail_a); }

    if slot.stage == QuicSrvStage.WaitClientHello2 {
        // RFC 9001 Section 4.7: HelloRetryRequest - CH2 MUST match CH1 cipher suite, group, SNI, ALPN.
        guard srv_matches_hrr_ch2(slot, choice) else {
            return quic_srv_fail(slot, Alert.IllegalParameter);
        }
    }
    guard slot.client_sni.try_set(choice.client_sni[..]) &&
        slot.peer_tp.try_set(choice.quic_tp[..]) else {
        return quic_srv_fail(slot, Alert.DecodeError);
    }

    if slot.stage == QuicSrvStage.WaitClientHello1 && slot.defer_sni && !slot.has_creds {
        guard slot.pending_ch_msg.try_set(ch_msg) else {
            return quic_srv_fail(slot, Alert.DecodeError);
        }
        slot.stage = QuicSrvStage.WaitSniCredentials;
        return QuicTlsStatus.NeedSniCredentials;
    }
    if choice.needs_hrr {
        return emit_srv_hrr_initial(slot, ch_msg, choice);
    }
    return emit_srv_full_flight(slot, ch_msg, choice);
}

fn process_srv_initial_crypto(slot: QuicTlsServerSlot&, data: const u8[:]) -> QuicTlsStatus {
    guard slot.rx_initial_buf.try_append(data) else {
        return quic_srv_fail(slot, Alert.DecodeError);
    }
    let msg_type, total_len, read_st = tls_internal::pure_peek_hs_msg_frame(
        slot.rx_initial_buf[..], 8192, 8192,
    );
    if read_st == tls_internal::PureHsMsgRead.NeedMore {
        return QuicTlsStatus.WantMore;
    }
    guard read_st == tls_internal::PureHsMsgRead.Ready else {
        return quic_srv_fail(slot, Alert.DecodeError);
    }
    guard msg_type == rfc::TLS_HS_CLIENT_HELLO && total_len == slot.rx_initial_buf.len else {
        return quic_srv_fail(slot, Alert.UnexpectedMessage);
    }
    var ch_msg: u8[..8192] = [];
    guard ch_msg.try_set(slot.rx_initial_buf[..total_len]) else {
        return quic_srv_fail(slot, Alert.DecodeError);
    }
    slot.rx_initial_buf.clear();
    return process_srv_ch_msg(slot, ch_msg[..]);
}

fn process_srv_hs_crypto(slot: QuicTlsServerSlot&, data: const u8[:]) -> QuicTlsStatus {
    guard slot.rx_hs_buf.try_append(data) else {
        return quic_srv_fail(slot, Alert.DecodeError);
    }
    let msg_type, total_len, read_st = tls_internal::pure_peek_hs_msg_frame(
        slot.rx_hs_buf[..], 1024, 1024,
    );
    if read_st == tls_internal::PureHsMsgRead.NeedMore {
        return QuicTlsStatus.WantMore;
    }
    guard read_st == tls_internal::PureHsMsgRead.Ready else {
        return quic_srv_fail(slot, Alert.DecodeError);
    }
    // RFC 9001 Section 8.3: Removing the EndOfEarlyData Message - Reject non-Finished on server Handshake CRYPTO.
    guard msg_type == rfc::TLS_HS_FINISHED && total_len == slot.rx_hs_buf.len else {
        return quic_srv_fail(slot, Alert.UnexpectedMessage);
    }

    let hlen = slot.ks.hash_len as i64;
    let body = slot.rx_hs_buf[4..total_len];
    guard body.len == hlen else { return quic_srv_fail(slot, Alert.DecodeError); }

    var h_to_srv_fin: u8[..48] = [];
    tls_internal::transcript_current_hash(slot.ts, slot.ks.hash_id, h_to_srv_fin);
    var expected_vd: u8[48] = [0; 48];
    defer core::secure_zeroize_48(expected_vd);
    guard tls_internal::ks_compute_finished_verify_data(
        slot.ks.hash_id,
        slot.ks.hash_len,
        slot.ks.client_hs_traffic[..hlen],
        h_to_srv_fin[..],
        expected_vd[..hlen],
    ) && core::ct_eq_bytes(expected_vd[..hlen], body) else {
        return quic_srv_fail(slot, Alert.DecryptError);
    }

    tls_internal::transcript_update(slot.ts, slot.rx_hs_buf[..total_len]);
    slot.rx_hs_buf.clear();
    var h_to_cli_fin: u8[..48] = [];
    tls_internal::transcript_current_hash(slot.ts, slot.ks.hash_id, h_to_cli_fin);

    // RFC 9001 Section 4.1.1: Handshake Complete - Expose Application read secret only after Finished verifies.
    guard tls_internal::ks_advance_to_resumption(slot.ks, h_to_cli_fin[..]) &&
        queue_srv_app_read_secret(slot, slot.ks.client_ap_traffic[..]) else {
        return quic_srv_fail(slot, Alert.InternalError);
    }
    slot.stage = QuicSrvStage.Established;
    return QuicTlsStatus.Established;
}

// Opens an RFC 9001 QUIC TLS 1.3 server context storing opaque `local_tp` (extension 0x0039).
fn quic_tls_server_open(
    alpn_wire: const u8[:],
    local_tp:  const u8[:],
    defer_sni: bool,
    cert_pem:  const u8[:] = "",
    key_pem:   const u8[:] = "",
) -> QuicTlsServer {
    guard alpn_wire.len <= 255 && local_tp.len <= QUIC_TLS_MAX_TP_LEN else {
        return QuicTlsServer { .. };
    }
    if !defer_sni {
        guard cert_pem.len > 0 && key_pem.len > 0 else { return QuicTlsServer { .. }; }
    }

    var idx: i64 = -1;
    for i in g_quic_tls_srv_slots.len {
        if !g_quic_tls_srv_slots[i].active {
            idx = i;
            break;
        }
    }
    if idx < 0 {
        idx = g_quic_tls_srv_slots.len;
        g_quic_tls_srv_slots.push(QuicTlsServerSlot { .. });
    }
    let gen = next_quic_generation(g_quic_tls_srv_next_gen);
    let slot .= g_quic_tls_srv_slots[idx];
    slot = QuicTlsServerSlot {
        active:     true,
        generation: gen,
        defer_sni:  defer_sni,
        ..
    };
    tls_internal::decode_alpn_wire_to_csv(alpn_wire, slot.alpn_csv);
    guard slot.local_tp.try_set(local_tp) else {
        zeroize_srv_slot(slot);
        return QuicTlsServer { .. };
    }
    if cert_pem.len > 0 || key_pem.len > 0 {
        guard load_srv_slot_creds_pem(slot, cert_pem, key_pem) else {
            zeroize_srv_slot(slot);
            return QuicTlsServer { .. };
        }
    }
    return QuicTlsServer { slot_idx: idx as i32, generation: gen };
}

// Closes a `QuicTlsServer`, releasing RSA key slots and wiping all key material.
fn quic_tls_server_close(srv: QuicTlsServer&) {
    let idx = lookup_live_srv_slot_idx(srv);
    srv = QuicTlsServer { .. };
    guard idx >= 0 else { return; }
    zeroize_srv_slot(g_quic_tls_srv_slots[idx]);
}

fn dispatch_srv_crypto_stage(
    slot:  QuicTlsServerSlot&,
    level: QuicTlsLevel,
    data:  const u8[:],
) -> QuicTlsStatus {
    if slot.stage == QuicSrvStage.WaitClientFinished {
        if level != QuicTlsLevel.Handshake {
            if data.len == 0 { return QuicTlsStatus.WantMore; }
            return quic_srv_fail(slot, Alert.UnexpectedMessage);
        }
        return process_srv_hs_crypto(slot, data);
    }
    if level != QuicTlsLevel.Initial {
        if data.len == 0 { return QuicTlsStatus.WantMore; }
        return quic_srv_fail(slot, Alert.UnexpectedMessage);
    }
    return process_srv_initial_crypto(slot, data);
}

// Feeds inbound QUIC CRYPTO frame bytes at `level` into the server handshake engine.
fn quic_tls_server_provide_crypto(
    srv:   QuicTlsServer&,
    level: QuicTlsLevel,
    data:  const u8[:],
) -> QuicTlsStatus {
    let idx = lookup_live_srv_slot_idx(srv);
    guard idx >= 0 else { return QuicTlsStatus.AlertError; }
    let slot .= g_quic_tls_srv_slots[idx];

    if slot.stage == QuicSrvStage.Failed { return QuicTlsStatus.AlertError; }
    if slot.stage == QuicSrvStage.Established {
        if data.len == 0 { return QuicTlsStatus.Established; }
        return quic_srv_fail(slot, Alert.UnexpectedMessage);
    }
    if slot.stage == QuicSrvStage.WaitSniCredentials {
        if data.len == 0 { return QuicTlsStatus.NeedSniCredentials; }
        return quic_srv_fail(slot, Alert.UnexpectedMessage);
    }
    return dispatch_srv_crypto_stage(slot, level, data);
}

// Returns the SNI hostname extracted from ClientHello1 when paused or active.
fn quic_tls_server_client_sni(srv: const QuicTlsServer&) -> u8[..255] {
    let idx = lookup_live_srv_slot_idx(srv);
    guard idx >= 0 else { return []; }
    return g_quic_tls_srv_slots[idx].client_sni;
}

// Returns the raw peer transport parameters received in TLS extension 0x0039.
fn quic_tls_server_peer_tp(srv: const QuicTlsServer&) -> const u8[:] {
    let idx = lookup_live_srv_slot_idx(srv);
    guard idx >= 0 else { return ""; }
    return g_quic_tls_srv_slots[idx].peer_tp[..];
}

// Returns the server-selected ALPN protocol name, if negotiated.
fn quic_tls_server_negotiated_alpn(srv: const QuicTlsServer&) -> u8[..255] {
    let idx = lookup_live_srv_slot_idx(srv);
    guard idx >= 0 else { return []; }
    return g_quic_tls_srv_slots[idx].negotiated_alpn;
}

// Loads fullchain certificate and private key PEM for a server paused in `NeedSniCredentials` and resumes CH1.
fn quic_tls_server_set_credentials_pem(
    srv:      QuicTlsServer&,
    cert_pem: const u8[:],
    key_pem:  const u8[:],
) -> QuicTlsStatus {
    let idx = lookup_live_srv_slot_idx(srv);
    guard idx >= 0 else { return QuicTlsStatus.AlertError; }
    let slot .= g_quic_tls_srv_slots[idx];
    guard slot.stage == QuicSrvStage.WaitSniCredentials && slot.pending_ch_msg.len >= 4 else {
        return quic_srv_fail(slot, Alert.InternalError);
    }
    var pending: u8[..8192] = [];
    defer {
        core::secure_zeroize_slice(pending[..]);
        core::secure_zeroize_slice(slot.pending_ch_msg[..]);
        slot.pending_ch_msg.clear();
    };
    guard pending.try_set(slot.pending_ch_msg[..]) else {
        return quic_srv_fail(slot, Alert.InternalError);
    }
    guard load_srv_slot_creds_pem(slot, cert_pem, key_pem) else {
        return quic_srv_fail(slot, Alert.HandshakeFailure);
    }
    slot.stage = QuicSrvStage.WaitClientHello1;
    return process_srv_ch_msg(slot, pending[..]);
}

// Drains outbound server CRYPTO stream bytes at `level` into `out`, returning bytes appended.
fn quic_tls_server_drain_crypto(
    srv:   QuicTlsServer&,
    level: QuicTlsLevel,
    out:   u8[>..]&,
) -> i64 {
    let idx = lookup_live_srv_slot_idx(srv);
    guard idx >= 0 else { return 0; }
    let slot .= g_quic_tls_srv_slots[idx];
    if level == QuicTlsLevel.Initial {
        let n = slot.tx_initial_buf.len;
        guard n > 0 else { return 0; }
        out.append(slot.tx_initial_buf[..]);
        slot.tx_initial_buf.clear();
        return n;
    }
    if level == QuicTlsLevel.Handshake {
        let n = slot.tx_hs_buf.len;
        guard n > 0 else { return 0; }
        out.append(slot.tx_hs_buf[..]);
        slot.tx_hs_buf.clear();
        return n;
    }
    return 0;
}

// Pops the next derived encryption-level traffic secrets from the server queue.
fn quic_tls_server_take_secrets(srv: QuicTlsServer&, out_sec: QuicTlsSecrets&) -> bool {
    out_sec = QuicTlsSecrets { .. };
    let idx = lookup_live_srv_slot_idx(srv);
    guard idx >= 0 else { return false; }
    return pop_quic_secret(g_quic_tls_srv_slots[idx].sec_queue, out_sec);
}

// Returns the fatal TLS alert code mapped by RFC 9001 Section 4.8 for CRYPTO failures.
fn quic_tls_server_last_alert(srv: const QuicTlsServer&) -> Alert {
    let idx = lookup_live_srv_slot_idx(srv);
    guard idx >= 0 else { return Alert.CloseNotify; }
    return g_quic_tls_srv_slots[idx].last_alert;
}

fn generate_cli_keypair(slot: QuicTlsClientSlot&, group: u16) -> bool {
    slot.eph_pub.clear();
    if group == rfc::GROUP_X25519 {
        guard tls_internal::random_bytes_32_checked(slot.eph_priv) else { return false; }
        let pub32 = core::x25519_base_scalarmult(slot.eph_priv);
        guard slot.eph_pub.try_set(pub32[..]) else { return false; }
        slot.active_group = rfc::GROUP_X25519;
        return true;
    }
    guard group == rfc::GROUP_SECP256R1 else { return false; }
    for _ in 16 {
        guard tls_internal::random_bytes_32_checked(slot.eph_priv) else { return false; }
        let pub65 = core::ecdsa_p256_public_key(slot.eph_priv);
        if pub65[0] == 0x04 {
            guard slot.eph_pub.try_set(pub65[..]) else { return false; }
            slot.active_group = rfc::GROUP_SECP256R1;
            return true;
        }
    }
    return false;
}

// Encodes RFC 9001 ClientHello extensions including key_share, SNI, ALPN, and 0x0039 transport params.
//
// Example:
//   server_name = "h3.example.test", alpn_csv = "h3", local_tp = [0x01, 0x01, 0x00]
//   returns: true, ext = [0x00, 0x2B, ...]
fn encode_quic_ch_extensions(
    slot:   const QuicTlsClientSlot&,
    cookie: const u8[:],
    ext:    u8[..3500]&,
) -> bool {
    let sv: u8[7] = [0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x04];
    guard ext.try_append(sv[..]) else { return false; }

    let groups: u16[2] = if slot.preferred_group == rfc::GROUP_SECP256R1 {
        [rfc::GROUP_SECP256R1, rfc::GROUP_X25519]
    } else {
        [rfc::GROUP_X25519, rfc::GROUP_SECP256R1]
    };
    tls_internal::encode_supported_groups_extension(ext, groups[..]);

    ext.append_u16_be(rfc::TLS_EXT_SIGNATURE_ALGORITHMS);
    ext.append_u16_be(10);
    ext.append_u16_be(8);
    ext.append_u16_be(rfc::SIG_SCHEME_ED25519);
    ext.append_u16_be(rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256);
    ext.append_u16_be(rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256);
    ext.append_u16_be(rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA384);

    if slot.eph_pub.len > 0 {
        var shares: u8[..128] = [];
        shares.append_u16_be(slot.active_group);
        shares.append_u16_be(slot.eph_pub.len as u16);
        guard shares.try_append(slot.eph_pub[..]) else { return false; }
        tls_internal::encode_key_share_client_extension(ext, shares[..]);
    } else {
        let empty_ks: u8[6] = [0x00, 0x33, 0x00, 0x02, 0x00, 0x00];
        guard ext.try_append(empty_ks[..]) else { return false; }
    }

    let sni = slot.client_cfg.server_name[..];
    if tls_internal::validate_sni_host_bytes(sni) {
        ext.append_u16_be(rfc::TLS_EXT_SERVER_NAME);
        let list_len = core::add_sat_i64(sni.len, 3) as u16;
        ext.append_u16_be(core::add_sat_u64(list_len, 2) as u16);
        ext.append_u16_be(list_len);
        guard ext.try_push(0) else { return false; }
        ext.append_u16_be(sni.len as u16);
        guard ext.try_append(sni) else { return false; }
    }
    if slot.alpn_csv.len > 0 {
        tls_internal::encode_alpn_extension_from_csv(ext, slot.alpn_csv[..]);
    }
    if cookie.len > 0 {
        guard tls_internal::serialize_cookie_extension(ext, cookie) else { return false; }
    }
    return tls_internal::encode_quic_tp_extension(ext, slot.local_tp[..]);
}

// Builds an RFC 9001 QUIC ClientHello handshake message with 0-byte legacy_session_id and extension 0x0039.
//
// Example:
//   server_name = "h3.example.test", alpn_csv = "h3", local_tp = [0x01, 0x01, 0x00]
//   returns: true, out_msg = [0x01, ...]
fn build_quic_client_hello_msg(
    slot:    const QuicTlsClientSlot&,
    cookie:  const u8[:],
    out_msg: u8[..4096]&,
) -> bool {
    out_msg.clear();
    var pay: u8[..3900] = [];
    pay.append_u16_be(rfc::TLS_LEGACY_VERSION_1_2);
    guard pay.try_append(slot.client_random[..]) && pay.try_push(0) else { return false; }

    pay.append_u16_be(6);
    pay.append_u16_be(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    pay.append_u16_be(rfc::TLS_CIPHER_AES_256_GCM_SHA384);
    pay.append_u16_be(rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256);
    guard pay.try_push(1) && pay.try_push(0) else { return false; }

    var ext: u8[..3500] = [];
    guard encode_quic_ch_extensions(slot, cookie, ext) else { return false; }
    pay.append_u16_be(ext.len as u16);
    guard pay.try_append(ext[..]) else { return false; }
    return tls_internal::frame_handshake_msg_4k(rfc::TLS_HS_CLIENT_HELLO, pay[..], out_msg);
}

// Parses and validates QUIC EncryptedExtensions, extracting 0x0039 peer transport parameters and ALPN.
//
// Example:
//   ee_body = [0x00, 0x07, 0x00, 0x39, 0x00, 0x03, 0x01, 0x01, 0x00], offered_alpn = ""
//   returns: out_tp = [0x01, 0x01, 0x00], Alert.CloseNotify, ok = true
fn parse_quic_encrypted_extensions(
    ee_body:          const u8[:],
    offered_alpn_csv: const u8[:],
    sni_state:        SniOfferState,
    out_alpn:         u8[..255]&,
    out_tp:           u8[..2048]&,
) -> Alert, bool {
    out_alpn.clear();
    out_tp.clear();
    var committed = false;
    defer if !committed {
        out_alpn.clear();
        out_tp.clear();
    };

    var entries: ExtensionEntry[..32] = [];
    guard parse_extensions_block(ee_body, entries) else { return Alert.DecodeError, false; }
    guard tls_internal::validate_ee_solicited_extensions(
        entries, offered_alpn_csv, sni_state, false, QuicExtensionMode.Quic,
    ) else {
        return Alert.UnsupportedExtension, false;
    }

    let tp_data, has_tp = find_extension(entries, rfc::TLS_EXT_QUIC_TRANSPORT_PARAMETERS);
    // RFC 9001 Section 8.2: QUIC Transport Parameters Extension - EncryptedExtensions MUST carry 0x0039.
    guard has_tp else { return Alert.MissingExtension, false; }
    guard out_tp.try_set(tp_data) else { return Alert.DecodeError, false; }

    let alpn_data, has_alpn = find_extension(entries, rfc::TLS_EXT_ALPN);
    if !has_alpn {
        // RFC 9001 Section 8.1: Protocol Negotiation - Require ALPN match when client offered protocols.
        guard offered_alpn_csv.len == 0 else { return Alert.NoApplicationProtocol, false; }
        committed = true;
        return Alert.CloseNotify, true;
    }
    var ac = core::cursor_from(alpn_data);
    let list_bytes, ok_l = ac.read_u16_prefixed();
    guard ok_l && ac.buf.len == 0 && list_bytes.len >= 2 else { return Alert.DecodeError, false; }
    var lc = core::cursor_from(list_bytes);
    let proto, ok_p = lc.read_u8_prefixed();
    guard ok_p && lc.buf.len == 0 && proto.len >= 1 && proto.len <= 255 else {
        return Alert.DecodeError, false;
    }
    guard tls_internal::alpn_csv_contains_proto(offered_alpn_csv, proto) && out_alpn.try_set(proto) else {
        return Alert.NoApplicationProtocol, false;
    }
    committed = true;
    return Alert.CloseNotify, true;
}

fn process_cli_hrr(
    slot:   QuicTlsClientSlot&,
    sh_msg: const u8[:],
    sh:     const ParsedServerHello&,
) -> QuicTlsStatus {
    guard !slot.hrr_received else { return quic_cli_fail(slot, Alert.UnexpectedMessage); }
    guard sh.selected_group == rfc::GROUP_X25519 || sh.selected_group == rfc::GROUP_SECP256R1 else {
        return quic_cli_fail(slot, Alert.IllegalParameter);
    }
    guard sh.selected_group != slot.active_group else {
        return quic_cli_fail(slot, Alert.IllegalParameter);
    }
    var ks, ok_ks = tls_internal::ks_init(sh.cipher_suite);
    guard ok_ks else { return quic_cli_fail(slot, Alert.IllegalParameter); }
    slot.hrr_received = true;
    slot.hrr_cipher = sh.cipher_suite;
    slot.hrr_group = sh.selected_group;

    guard tls_internal::transcript_replace_with_message_hash(slot.ts, ks.hash_id, ks.hash_len) else {
        return quic_cli_fail(slot, Alert.InternalError);
    }
    tls_internal::transcript_update(slot.ts, sh_msg);
    guard generate_cli_keypair(slot, sh.selected_group) else {
        return quic_cli_fail(slot, Alert.InternalError);
    }
    var ch2_msg: u8[..4096] = [];
    guard build_quic_client_hello_msg(slot, sh.hrr_cookie[..], ch2_msg) &&
        slot.tx_initial_buf.try_append(ch2_msg[..]) else {
        return quic_cli_fail(slot, Alert.InternalError);
    }
    tls_internal::transcript_update(slot.ts, ch2_msg[..]);
    return QuicTlsStatus.Ok;
}

fn compute_cli_ecdhe(
    slot:       QuicTlsClientSlot&,
    sh:         const ParsedServerHello&,
    out_secret: u8[32]&,
) -> bool {
    guard sh.selected_group == slot.active_group else { return false; }
    defer core::secure_scrub_stack();
    defer core::secure_zeroize_32(slot.eph_priv);
    if sh.selected_group == rfc::GROUP_X25519 {
        guard sh.server_share.len == 32 else { return false; }
        var peer32: u8[32] = [0; 32];
        core::ct_copy_bytes(peer32[..], sh.server_share[..32]);
        var ss, ok = core::x25519_shared_secret(slot.eph_priv, peer32);
        defer core::secure_zeroize_32(ss);
        guard ok else { return false; }
        out_secret = ss;
        return true;
    }
    guard sh.selected_group == rfc::GROUP_SECP256R1 && sh.server_share.len == 65 else { return false; }
    var ss, ok = core::p256_ecdh_shared_secret(slot.eph_priv, sh.server_share[..]);
    defer core::secure_zeroize_32(ss);
    guard ok else { return false; }
    out_secret = ss;
    return true;
}

fn install_cli_handshake_secrets(
    slot:   QuicTlsClientSlot&,
    sh_msg: const u8[:],
    sh:     const ParsedServerHello&,
) -> QuicTlsStatus {
    if slot.hrr_received {
        guard sh.cipher_suite == slot.hrr_cipher && sh.selected_group == slot.hrr_group else {
            return quic_cli_fail(slot, Alert.IllegalParameter);
        }
    }
    var ks, ok_ks = tls_internal::ks_init(sh.cipher_suite);
    var ecdhe: u8[32] = [0; 32];
    defer core::secure_zeroize_32(ecdhe);
    guard ok_ks && compute_cli_ecdhe(slot, sh, ecdhe) else {
        return quic_cli_fail(slot, Alert.IllegalParameter);
    }
    slot.ks = ks;
    tls_internal::transcript_update(slot.ts, sh_msg);
    var h_to_sh: u8[..48] = [];
    tls_internal::transcript_current_hash(slot.ts, slot.ks.hash_id, h_to_sh);
    guard tls_internal::ks_init_early_secret(slot.ks, "") &&
        tls_internal::ks_advance_to_handshake(slot.ks, ecdhe[..]) &&
        tls_internal::ks_derive_handshake_traffic(slot.ks, h_to_sh[..]) &&
        enqueue_quic_secret_pair(
            slot.sec_queue,
            QuicTlsLevel.Handshake,
            slot.ks.cipher_suite,
            slot.ks.hash_len,
            slot.ks.server_hs_traffic[..],
            slot.ks.client_hs_traffic[..],
        ) else {
            return quic_cli_fail(slot, Alert.InternalError);
        }
    slot.stage = QuicCliStage.WaitEE;
    return QuicTlsStatus.Ok;
}

fn process_cli_initial(slot: QuicTlsClientSlot&, data: const u8[:]) -> QuicTlsStatus {
    guard slot.rx_initial_buf.try_append(data) else {
        return quic_cli_fail(slot, Alert.DecodeError);
    }
    let msg_type, total_len, read_st = tls_internal::pure_peek_hs_msg_frame(
        slot.rx_initial_buf[..], 4096, 4096,
    );
    if read_st == tls_internal::PureHsMsgRead.NeedMore { return QuicTlsStatus.WantMore; }
    guard read_st == tls_internal::PureHsMsgRead.Ready else {
        return quic_cli_fail(slot, Alert.DecodeError);
    }
    guard msg_type == rfc::TLS_HS_SERVER_HELLO && total_len == slot.rx_initial_buf.len else {
        return quic_cli_fail(slot, Alert.UnexpectedMessage);
    }
    var sh_msg: u8[..4096] = [];
    guard sh_msg.try_set(slot.rx_initial_buf[..total_len]) else {
        return quic_cli_fail(slot, Alert.DecodeError);
    }
    slot.rx_initial_buf.clear();

    var sh = ParsedServerHello { .. };
    guard parse_live_server_hello(sh_msg[..], sh) && tls_internal::validate_quic_client_sh(sh) else {
        let a = tls_internal::classify_sh_failure_alert(sh_msg[..]);
        return quic_cli_fail(slot, a);
    }
    if sh.is_hrr {
        return process_cli_hrr(slot, sh_msg[..], sh);
    }
    return install_cli_handshake_secrets(slot, sh_msg[..], sh);
}

fn step_cli_ee_or_cert(slot: QuicTlsClientSlot&, msg_type: u8, msg_slice: const u8[:]) -> QuicTlsStatus {
    let body = msg_slice[4..];
    if slot.stage == QuicCliStage.WaitEE {
        guard msg_type == rfc::TLS_HS_ENCRYPTED_EXTENSIONS else {
            return quic_cli_fail(slot, Alert.UnexpectedMessage);
        }
        let sni_state = if slot.client_cfg.server_name.len > 0 {
            SniOfferState.Offered
        } else {
            SniOfferState.Omitted
        };
        let ee_alert, ok_ee = parse_quic_encrypted_extensions(
            body, slot.alpn_csv[..], sni_state, slot.negotiated_alpn, slot.peer_tp,
        );
        guard ok_ee else { return quic_cli_fail(slot, ee_alert); }
        tls_internal::transcript_update(slot.ts, msg_slice);
        slot.stage = QuicCliStage.WaitCert;
        return QuicTlsStatus.Ok;
    }
    guard msg_type == rfc::TLS_HS_CERTIFICATE && slot.peer_cert_body.try_set(body) else {
        let a = if msg_type != rfc::TLS_HS_CERTIFICATE {
            Alert.UnexpectedMessage
        } else {
            Alert.DecodeError
        };
        return quic_cli_fail(slot, a);
    }
    tls_internal::transcript_update(slot.ts, msg_slice);
    tls_internal::transcript_current_hash(slot.ts, slot.ks.hash_id, slot.ts_to_cert);
    slot.stage = QuicCliStage.WaitCV;
    return QuicTlsStatus.Ok;
}

fn step_cli_cv_or_fin(slot: QuicTlsClientSlot&, msg_type: u8, msg_slice: const u8[:]) -> QuicTlsStatus {
    let body = msg_slice[4..];
    if slot.stage == QuicCliStage.WaitCV {
        guard msg_type == rfc::TLS_HS_CERTIFICATE_VERIFY else {
            return quic_cli_fail(slot, Alert.UnexpectedMessage);
        }
        let ok_v = tls_internal::verify_server_cert_and_signature(
            slot.peer_cert_body[..], body, slot.ts_to_cert[..], slot.client_cfg, 0xFFFF,
        );
        if !ok_v {
            let ca = tls_internal::classify_cert_failure_alert(slot.peer_cert_body[..]);
            return quic_cli_fail(slot, ca);
        }
        core::secure_zeroize_slice(slot.peer_cert_body[..]);
        slot.peer_cert_body.clear();
        tls_internal::transcript_update(slot.ts, msg_slice);
        slot.stage = QuicCliStage.WaitServerFinished;
        return QuicTlsStatus.Ok;
    }

    guard msg_type == rfc::TLS_HS_FINISHED else {
        return quic_cli_fail(slot, Alert.UnexpectedMessage);
    }
    let hlen = slot.ks.hash_len as i64;
    guard body.len == hlen else { return quic_cli_fail(slot, Alert.DecodeError); }

    var h_to_cv: u8[..48] = [];
    tls_internal::transcript_current_hash(slot.ts, slot.ks.hash_id, h_to_cv);
    var expected_vd: u8[48] = [0; 48];
    defer core::secure_zeroize_48(expected_vd);
    guard tls_internal::ks_compute_finished_verify_data(
        slot.ks.hash_id, slot.ks.hash_len, slot.ks.server_hs_traffic[..hlen], h_to_cv[..], expected_vd[..hlen],
    ) && core::ct_eq_bytes(expected_vd[..hlen], body) else {
        return quic_cli_fail(slot, Alert.DecryptError);
    }
    tls_internal::transcript_update(slot.ts, msg_slice);

    var h_to_srv_fin: u8[..48] = [];
    tls_internal::transcript_current_hash(slot.ts, slot.ks.hash_id, h_to_srv_fin);
    var cli_vd: u8[48] = [0; 48];
    defer core::secure_zeroize_48(cli_vd);
    var fin_msg: u8[..64] = [];
    guard tls_internal::ks_advance_to_master(slot.ks, h_to_srv_fin[..]) &&
        tls_internal::ks_compute_finished_verify_data(
            slot.ks.hash_id, slot.ks.hash_len, slot.ks.client_hs_traffic[..hlen], h_to_srv_fin[..], cli_vd[..hlen],
        ) &&
        tls_internal::frame_handshake_msg_4k(rfc::TLS_HS_FINISHED, cli_vd[..hlen], fin_msg) &&
        slot.tx_hs_buf.try_append(fin_msg[..]) else {
        return quic_cli_fail(slot, Alert.InternalError);
    }

    tls_internal::transcript_update(slot.ts, fin_msg[..]);
    var h_to_cli_fin: u8[..48] = [];
    tls_internal::transcript_current_hash(slot.ts, slot.ks.hash_id, h_to_cli_fin);
    guard tls_internal::ks_advance_to_resumption(slot.ks, h_to_cli_fin[..]) &&
        enqueue_quic_secret_pair(
            slot.sec_queue,
            QuicTlsLevel.Application,
            slot.ks.cipher_suite,
            slot.ks.hash_len,
            slot.ks.server_ap_traffic[..],
            slot.ks.client_ap_traffic[..],
        ) else {
            return quic_cli_fail(slot, Alert.InternalError);
        }
    slot.stage = QuicCliStage.Established;
    return QuicTlsStatus.Established;
}

fn process_cli_hs_crypto(slot: QuicTlsClientSlot&, data: const u8[:]) -> QuicTlsStatus {
    guard slot.rx_hs_buf.try_append(data) else { return quic_cli_fail(slot, Alert.DecodeError); }
    while slot.rx_hs_buf.len > 0 {
        let msg_type, total_len, read_st = tls_internal::pure_peek_hs_msg_frame(
            slot.rx_hs_buf[..], QUIC_TLS_MAX_HS_MSG_LEN, QUIC_TLS_MAX_HS_MSG_LEN,
        );
        if read_st == tls_internal::PureHsMsgRead.NeedMore { return QuicTlsStatus.WantMore; }
        guard read_st == tls_internal::PureHsMsgRead.Ready else {
            return quic_cli_fail(slot, Alert.DecodeError);
        }
        guard slot.stage != QuicCliStage.Established else {
            return quic_cli_fail(slot, Alert.UnexpectedMessage);
        }
        let st = if slot.stage == QuicCliStage.WaitEE || slot.stage == QuicCliStage.WaitCert {
            step_cli_ee_or_cert(slot, msg_type, slot.rx_hs_buf[..total_len])
        } else {
            step_cli_cv_or_fin(slot, msg_type, slot.rx_hs_buf[..total_len])
        };
        guard st != QuicTlsStatus.AlertError else { return QuicTlsStatus.AlertError; }
        core::compact_wire_buffer(slot.rx_hs_buf, total_len);
        if st == QuicTlsStatus.Established {
            guard slot.rx_hs_buf.len == 0 else {
                return quic_cli_fail(slot, Alert.UnexpectedMessage);
            }
            return QuicTlsStatus.Established;
        }
    }
    return QuicTlsStatus.WantMore;
}

// Opens an RFC 9001 QUIC TLS 1.3 client context with SNI, ALPN, `0x0039` parameters, and trust PEM.
fn quic_tls_client_open(
    server_name:     const u8[:],
    alpn_wire:       const u8[:],
    local_tp:        const u8[:],
    trust_pem:       const u8[:]            = "",
    preferred_group: u16                    = rfc::GROUP_X25519,
    key_share_mode:  QuicClientKeyShareMode = QuicClientKeyShareMode.SendInitialShare,
    verify_mode:     QuicClientVerifyMode   = QuicClientVerifyMode.VerifyTrustAndSan,
) -> QuicTlsClient {
    guard server_name.len <= 256 && alpn_wire.len <= 255 && local_tp.len <= QUIC_TLS_MAX_TP_LEN else {
        return QuicTlsClient { .. };
    }
    guard preferred_group == rfc::GROUP_X25519 || preferred_group == rfc::GROUP_SECP256R1 else {
        return QuicTlsClient { .. };
    }

    var idx: i64 = -1;
    for i in g_quic_tls_cli_slots.len {
        if !g_quic_tls_cli_slots[i].active {
            idx = i;
            break;
        }
    }
    if idx < 0 {
        idx = g_quic_tls_cli_slots.len;
        g_quic_tls_cli_slots.push(QuicTlsClientSlot { .. });
    }
    let gen = next_quic_generation(g_quic_tls_cli_next_gen);
    let slot .= g_quic_tls_cli_slots[idx];
    slot = QuicTlsClientSlot {
        active:          true,
        generation:      gen,
        preferred_group: preferred_group,
        key_share_mode:  key_share_mode,
        ..
    };
    slot.client_cfg.use_system_roots = trust_pem.len == 0;
    slot.client_cfg.insecure_skip_verify = verify_mode == QuicClientVerifyMode.InsecureSkipVerify;
    tls_internal::decode_alpn_wire_to_csv(alpn_wire, slot.alpn_csv);

    guard slot.client_cfg.server_name.try_set(server_name) &&
        slot.client_cfg.alpn.try_set(slot.alpn_csv[..]) &&
        slot.local_tp.try_set(local_tp) else {
        zeroize_cli_slot(slot);
        return QuicTlsClient { .. };
    }
    if trust_pem.len > 0 {
        let _, ok_t = add_trust_anchors_pem(slot.client_cfg.trust_store, trust_pem);
        guard ok_t else {
            zeroize_cli_slot(slot);
            return QuicTlsClient { .. };
        }
    }
    return QuicTlsClient { slot_idx: idx as i32, generation: gen };
}

// Closes a `QuicTlsClient` handle and wipes all ephemeral, traffic, and transcript secrets.
fn quic_tls_client_close(cli: QuicTlsClient&) {
    let idx = lookup_live_cli_slot_idx(cli);
    cli = QuicTlsClient { .. };
    guard idx >= 0 else { return; }
    zeroize_cli_slot(g_quic_tls_cli_slots[idx]);
}

// Emits the initial QUIC ClientHello on `QuicTlsLevel.Initial`.
fn quic_tls_client_start(cli: QuicTlsClient&) -> QuicTlsStatus {
    let idx = lookup_live_cli_slot_idx(cli);
    guard idx >= 0 else { return QuicTlsStatus.AlertError; }
    let slot .= g_quic_tls_cli_slots[idx];
    guard slot.stage == QuicCliStage.Init else { return quic_cli_fail(slot, Alert.UnexpectedMessage); }

    guard tls_internal::random_bytes_32_checked(slot.client_random) else {
        return quic_cli_fail(slot, Alert.InternalError);
    }
    if slot.key_share_mode == QuicClientKeyShareMode.SendInitialShare {
        guard generate_cli_keypair(slot, slot.preferred_group) else {
            return quic_cli_fail(slot, Alert.InternalError);
        }
    }
    var ch1: u8[..4096] = [];
    guard build_quic_client_hello_msg(slot, "", ch1) &&
        slot.tx_initial_buf.try_append(ch1[..]) else {
        return quic_cli_fail(slot, Alert.InternalError);
    }
    slot.ts = Transcript { .. };
    tls_internal::transcript_update(slot.ts, ch1[..]);
    slot.stage = QuicCliStage.WaitServerHello;
    return QuicTlsStatus.Ok;
}

fn validate_quic_post_hs_nst(body: const u8[:]) -> bool {
    var c = core::cursor_from(body);
    var lifetime: u32 = 0;
    var age_add:  u32 = 0;
    // RFC 8446 Section 4.6.1: New Session Ticket Message - Bound lifetime <= 604800s and check extensions.
    guard c.get_u32(lifetime) && c.get_u32(age_add) && lifetime <= 604800 else { return false; }
    let nonce, ok_n = c.read_u8_prefixed();
    let ticket, ok_t = c.read_u16_prefixed();
    var ext_c, ok_e = c.read_u16_sub_cursor();
    guard ok_n && ok_t && ok_e && ticket.len >= 1 && c.buf.len == 0 else { return false; }
    var seen: u16[..16] = [];
    while ext_c.buf.len > 0 {
        let etype, ok_et = ext_c.read_u16();
        let edata, ok_ed = ext_c.read_u16_prefixed();
        guard ok_et && ok_ed else { return false; }
        for prev in seen {
            if prev == etype { return false; }
        }
        guard seen.try_push(etype) else { return false; }
        if etype == rfc::TLS_EXT_EARLY_DATA && edata.len != 4 {
            return false;
        }
    }
    return true;
}

fn process_cli_established_app_crypto(
    slot:  QuicTlsClientSlot&,
    level: QuicTlsLevel,
    data:  const u8[:],
) -> QuicTlsStatus {
    if data.len == 0 { return QuicTlsStatus.Established; }
    // RFC 9001 Section 4.5: Session Resumption - Post-handshake CRYPTO arrives only at Application level.
    guard level == QuicTlsLevel.Application else {
        return quic_cli_fail(slot, Alert.UnexpectedMessage);
    }
    guard slot.rx_app_buf.try_append(data) else {
        return quic_cli_fail(slot, Alert.RecordOverflow);
    }
    while slot.rx_app_buf.len > 0 {
        let msg_type, total_len, read_st = tls_internal::pure_peek_hs_msg_frame(
            slot.rx_app_buf[..], 8192, 8192,
        );
        if read_st == tls_internal::PureHsMsgRead.NeedMore {
            return QuicTlsStatus.Established;
        }
        guard read_st == tls_internal::PureHsMsgRead.Ready else {
            return quic_cli_fail(slot, Alert.DecodeError);
        }
        // RFC 9001 Section 6: Key Update - Reject KeyUpdate and non-ticket messages in CRYPTO frames.
        guard msg_type == rfc::TLS_HS_NEW_SESSION_TICKET else {
            return quic_cli_fail(slot, Alert.UnexpectedMessage);
        }
        guard slot.nst_count < 16 else {
            return quic_cli_fail(slot, Alert.UnexpectedMessage);
        }
        guard validate_quic_post_hs_nst(slot.rx_app_buf[4..total_len]) else {
            return quic_cli_fail(slot, Alert.DecodeError);
        }
        slot.nst_count += 1;
        core::compact_wire_buffer(slot.rx_app_buf, total_len);
    }
    return QuicTlsStatus.Established;
}

// Feeds inbound QUIC CRYPTO frame bytes at `level` into the client handshake engine.
fn quic_tls_client_provide_crypto(
    cli:   QuicTlsClient&,
    level: QuicTlsLevel,
    data:  const u8[:],
) -> QuicTlsStatus {
    let idx = lookup_live_cli_slot_idx(cli);
    guard idx >= 0 else { return QuicTlsStatus.AlertError; }
    let slot .= g_quic_tls_cli_slots[idx];

    if slot.stage == QuicCliStage.Failed { return QuicTlsStatus.AlertError; }
    if slot.stage == QuicCliStage.Established {
        return process_cli_established_app_crypto(slot, level, data);
    }
    if slot.stage == QuicCliStage.Init {
        return quic_cli_fail(slot, Alert.UnexpectedMessage);
    }
    if slot.stage == QuicCliStage.WaitServerHello {
        if level != QuicTlsLevel.Initial {
            if data.len == 0 { return QuicTlsStatus.WantMore; }
            return quic_cli_fail(slot, Alert.UnexpectedMessage);
        }
        return process_cli_initial(slot, data);
    }
    if level != QuicTlsLevel.Handshake {
        if data.len == 0 { return QuicTlsStatus.WantMore; }
        return quic_cli_fail(slot, Alert.UnexpectedMessage);
    }
    return process_cli_hs_crypto(slot, data);
}

// Drains outbound client CRYPTO stream bytes at `level` into `out`, returning bytes appended.
fn quic_tls_client_drain_crypto(
    cli:   QuicTlsClient&,
    level: QuicTlsLevel,
    out:   u8[>..]&,
) -> i64 {
    let idx = lookup_live_cli_slot_idx(cli);
    guard idx >= 0 else { return 0; }
    let slot .= g_quic_tls_cli_slots[idx];
    if level == QuicTlsLevel.Initial {
        let n = slot.tx_initial_buf.len;
        guard n > 0 else { return 0; }
        out.append(slot.tx_initial_buf[..]);
        slot.tx_initial_buf.clear();
        return n;
    }
    if level == QuicTlsLevel.Handshake {
        let n = slot.tx_hs_buf.len;
        guard n > 0 else { return 0; }
        out.append(slot.tx_hs_buf[..]);
        slot.tx_hs_buf.clear();
        return n;
    }
    return 0;
}

// Pops the next derived encryption-level traffic secrets from the client queue.
fn quic_tls_client_take_secrets(cli: QuicTlsClient&, out_sec: QuicTlsSecrets&) -> bool {
    out_sec = QuicTlsSecrets { .. };
    let idx = lookup_live_cli_slot_idx(cli);
    guard idx >= 0 else { return false; }
    return pop_quic_secret(g_quic_tls_cli_slots[idx].sec_queue, out_sec);
}

// Returns the server transport parameters received in EncryptedExtensions extension 0x0039.
fn quic_tls_client_peer_tp(cli: const QuicTlsClient&) -> const u8[:] {
    let idx = lookup_live_cli_slot_idx(cli);
    guard idx >= 0 else { return ""; }
    return g_quic_tls_cli_slots[idx].peer_tp[..];
}

// Returns the server-negotiated ALPN protocol string from EncryptedExtensions.
fn quic_tls_client_negotiated_alpn(cli: const QuicTlsClient&) -> u8[..255] {
    let idx = lookup_live_cli_slot_idx(cli);
    guard idx >= 0 else { return []; }
    return g_quic_tls_cli_slots[idx].negotiated_alpn;
}

// Returns the fatal TLS alert code recorded on client handshake failure.
fn quic_tls_client_last_alert(cli: const QuicTlsClient&) -> Alert {
    let idx = lookup_live_cli_slot_idx(cli);
    guard idx >= 0 else { return Alert.CloseNotify; }
    return g_quic_tls_cli_slots[idx].last_alert;
}
