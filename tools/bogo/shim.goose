// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// BoringSSL BoGo protocol test shim for goose-wing (`PureGoose` and `SystemOpenSsl`).
// Connects over TCP, writes the 8-byte little-endian `shim-id` header, completes TLS 1.3
// (or opt-in TLS 1.2 on OpenSSL), and runs the BoGo XOR-0xFF application echo loop.
import std;
import os;
import wing from "../..";

const BOGO_EXIT_OK:            i32 = 0;
const BOGO_EXIT_FAIL:          i32 = 1;
const BOGO_EXIT_UNIMPLEMENTED: i32 = 89;
const BOGO_XOR_MASK:           u8  = 0xFF;
const BOGO_IO_TIMEOUT_MS:      u32 = 5000;
const TLS_VERSION_1_2_WIRE:    u16 = 0x0303;
const TLS_VERSION_1_3_WIRE:    u16 = 0x0304;

extern fn bogo_err(msg: const u8[:]) = "wing_write_stderr";

struct BogoConfig {
    port:           u16                 = 0,
    shim_id:        u64                 = 0,
    is_server:      bool                = false,
    verify_peer:    bool                = false,
    fallback_scsv:  bool                = false,
    ipv6:           bool                = false,
    key_update:     bool                = false,
    writes_first:   bool                = false,
    min_version:    u16                 = 0,
    max_version:    u16                 = 0,
    expect_version: u16                 = 0,
    backend:        tls::TlsBackendKind = tls::TlsBackendKind.PureGoose,
    host_name:      u8[..256]           = [],
    cert_file:      u8[..256]           = [],
    key_file:       u8[..256]           = [],
    trust_cert:     u8[..256]           = [],
    alpn_wire:      u8[..64]            = [],
    alpn_csv:       u8[..64]            = [],
    expect_alpn:    u8[..64]            = [],
}

// Parses a decimal or 0x-prefixed hexadecimal TLS protocol version into u16.
//
// Example:
//   raw = "772" -> returns: 0x0304, true
//   raw = "0x0303" -> returns: 0x0303, true
fn parse_tls_version_arg(raw: const u8[:]) -> u16, bool {
    guard raw.len > 0 else { return 0, false; }
    let hex_body, has_hex = raw.strip_prefix_fold("0x");
    if has_hex {
        let v, ok = hex_body.parse_u64_hex();
        guard ok && v <= 0xFFFF else { return 0, false; }
        return v as u16, true;
    }
    let v, ok = raw.parse_u64_dec();
    guard ok && v <= 0xFFFF else { return 0, false; }
    return v as u16, true;
}

// Parses a BoGo shim backend token (`pure` or `openssl`) into `tls::TlsBackendKind`.
//
// Example:
//   raw = "openssl"
//   returns: tls::TlsBackendKind.SystemOpenSsl, true
fn parse_backend_arg(raw: const u8[:]) -> tls::TlsBackendKind, bool {
    if raw == "pure" { return tls::TlsBackendKind.PureGoose, true; }
    if raw == "openssl" { return tls::TlsBackendKind.SystemOpenSsl, true; }
    return tls::TlsBackendKind.PureGoose, false;
}

// Decodes RFC 7301 length-prefixed ALPN wire bytes into `out_wire` and CSV `out_csv`.
// Clears both output buffers on failure so no partial state leaks.
//
// Example:
//   raw = "\x02h2\x08http/1.1"
//   returns: true, out_csv = "h2,http/1.1"
fn decode_alpn_wire_arg(
    raw:      const u8[:],
    out_wire: u8[..64]&,
    out_csv:  u8[..64]&,
) -> bool {
    var committed = false;
    defer if !committed {
        out_wire.clear();
        out_csv.clear();
    };
    out_wire.clear();
    out_csv.clear();
    guard raw.len >= 2 && raw.len <= out_wire.cap else { return false; }

    var cur = core::cursor_from(raw);
    while cur.buf.len > 0 {
        let proto, ok_p = cur.read_u8_prefixed();
        guard ok_p && proto.len > 0 && core::is_pure_ascii(proto) else { return false; }
        if out_csv.len > 0 {
            guard out_csv.try_push(',') else { return false; }
        }
        guard out_csv.try_append(proto) else { return false; }
    }
    guard out_csv.len > 0 && out_wire.try_set(raw) else { return false; }
    committed = true;
    return true;
}

// Parses `-alpn-protos` accepting either RFC 7301 wire format or comma-separated ASCII CSV.
// Populates both `out_wire` and `out_csv`; clears both on malformed input.
//
// Example:
//   raw = "h2,http/1.1"
//   returns: true, out_wire = [2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1']
fn parse_alpn_protos_arg(
    raw:      const u8[:],
    out_wire: u8[..64]&,
    out_csv:  u8[..64]&,
) -> bool {
    if decode_alpn_wire_arg(raw, out_wire, out_csv) {
        return true;
    }
    var committed = false;
    defer if !committed {
        out_wire.clear();
        out_csv.clear();
    };
    out_wire.clear();
    out_csv.clear();
    guard raw.len > 0 else { return false; }

    var tok = core::make_byte_tokenizer(raw, ',');
    while true {
        let item, more = core::token_next(tok);
        guard more else { break; }
        let p = item.trim_lws();
        guard p.len > 0 && p.len <= 255 else { return false; }
        if out_csv.len > 0 {
            guard out_csv.try_push(',') else { return false; }
        }
        guard out_wire.try_push(p.len as u8) &&
            out_wire.try_append(p) &&
            out_csv.try_append(p) else {
            return false;
        }
    }
    guard out_wire.len > 0 else { return false; }
    committed = true;
    return true;
}

// Parses a single boolean BoGo shim flag into `cfg`.
//
// Example:
//   flag = "-is-server"
//   returns: true, cfg.is_server = true
fn parse_bogo_bool_flag(flag: const u8[:], cfg: BogoConfig&) -> bool {
    let names: (const u8[:])[11] = [
        "-is-server", "-verify-peer", "-fallback-scsv", "-ipv6",
        "-key-update", "-shim-writes-first", "-no-ssl3", "-no-tls1",
        "-no-tls11", "-no-tls12", "-expect-no-session",
    ];
    var flags: bool[6] = [
        cfg.is_server, cfg.verify_peer, cfg.fallback_scsv,
        cfg.ipv6, cfg.key_update, cfg.writes_first,
    ];
    for i in 11 {
        if flag == names[i] {
            if i < 6 { flags[i] = true; }
            cfg.is_server = flags[0];
            cfg.verify_peer = flags[1];
            cfg.fallback_scsv = flags[2];
            cfg.ipv6 = flags[3];
            cfg.key_update = flags[4];
            cfg.writes_first = flags[5];
            return true;
        }
    }
    return false;
}

// Parses a string/path BoGo shim flag and its argument into `cfg`.
// Returns 0 on match, 1 if unrecognized, or -1 on invalid value.
//
// Example:
//   flag = "-host-name", val = "localhost"
//   returns: 0, cfg.host_name = "localhost"
fn parse_bogo_path_flag(flag: const u8[:], val: const u8[:], cfg: BogoConfig&) -> i32 {
    var matched = true;
    var ok = false;
    if flag == "-host-name" {
        ok = cfg.host_name.try_set(val);
    } else if flag == "-cert-file" {
        ok = cfg.cert_file.try_set(val);
    } else if flag == "-key-file" {
        ok = cfg.key_file.try_set(val);
    } else if flag == "-trust-cert" {
        ok = cfg.trust_cert.try_set(val);
    } else if flag == "-expect-alpn" {
        ok = cfg.expect_alpn.try_set(val);
    } else if flag == "-alpn-protos" {
        ok = parse_alpn_protos_arg(val, cfg.alpn_wire, cfg.alpn_csv);
    } else {
        matched = false;
    }
    guard matched else { return 1; }
    return if ok { 0 } else { -1 };
}

// Parses a numeric or enum BoGo shim flag and its argument into `cfg`.
// Returns 0 on match, 1 if unrecognized, or -1 on invalid value.
//
// Example:
//   flag = "-port", val = "4433"
//   returns: 0, cfg.port = 4433
fn parse_bogo_num_flag(flag: const u8[:], val: const u8[:], cfg: BogoConfig&) -> i32 {
    if flag == "-port" {
        let p, ok = val.parse_u64_dec();
        guard ok && p > 0 && p <= 65535 else { return -1; }
        cfg.port = p as u16;
        return 0;
    }
    if flag == "-shim-id" {
        let id, ok = val.parse_u64_dec();
        guard ok else { return -1; }
        cfg.shim_id = id;
        return 0;
    }
    if flag == "-min-version" {
        let v, ok = parse_tls_version_arg(val);
        guard ok else { return -1; }
        cfg.min_version = v;
        return 0;
    }
    if flag == "-max-version" {
        let v, ok = parse_tls_version_arg(val);
        guard ok else { return -1; }
        cfg.max_version = v;
        return 0;
    }
    if flag == "-expect-version" {
        let v, ok = parse_tls_version_arg(val);
        guard ok else { return -1; }
        cfg.expect_version = v;
        return 0;
    }
    if flag == "-backend" {
        let bk, ok = parse_backend_arg(val);
        guard ok else { return -1; }
        cfg.backend = bk;
        return 0;
    }
    return 1;
}

// Parses full CLI argument list into `cfg`, returning exit status (0, 1, or 89).
//
// Example:
//   a = ["bogo_shim", "-port", "4433", "-shim-id", "7"]
//   returns: 0, cfg.port = 4433, cfg.shim_id = 7
fn parse_bogo_cli_args(a: u8[:][>..]&, cfg: BogoConfig&) -> i32 {
    var i: i64 = 1;
    while i < a.len {
        let flag = a[i];
        if parse_bogo_bool_flag(flag, cfg) {
            i = core::add_sat_i64(i, 1);
            continue;
        }
        let next_i = core::add_sat_i64(i, 1);
        guard next_i < a.len else { return BOGO_EXIT_UNIMPLEMENTED; }
        let val = a[next_i];
        let num_rc = parse_bogo_num_flag(flag, val, cfg);
        if num_rc == 0 {
            i = core::add_sat_i64(i, 2);
            continue;
        }
        guard num_rc == 1 else { return BOGO_EXIT_FAIL; }
        let path_rc = parse_bogo_path_flag(flag, val, cfg);
        if path_rc == 0 {
            i = core::add_sat_i64(i, 2);
            continue;
        }
        return if path_rc == 1 { BOGO_EXIT_UNIMPLEMENTED } else { BOGO_EXIT_FAIL };
    }
    return BOGO_EXIT_OK;
}

fn check_bogo_policy_support(cfg: const BogoConfig&) -> i32 {
    if cfg.fallback_scsv {
        print("BOGO_UNIMPLEMENTED: fallback-scsv unsupported\n");
        return BOGO_EXIT_UNIMPLEMENTED;
    }
    if cfg.backend == tls::TlsBackendKind.PureGoose {
        let legacy_max = cfg.max_version != 0 && cfg.max_version < TLS_VERSION_1_3_WIRE;
        let legacy_min = cfg.min_version != 0 &&
            cfg.min_version < TLS_VERSION_1_3_WIRE &&
            cfg.max_version < TLS_VERSION_1_3_WIRE;
        let legacy_exp = cfg.expect_version != 0 && cfg.expect_version < TLS_VERSION_1_3_WIRE;
        if legacy_max || legacy_min || legacy_exp {
            print("BOGO_UNIMPLEMENTED: PureGoose requires TLS 1.3\n");
            return BOGO_EXIT_UNIMPLEMENTED;
        }
        if cfg.is_server && cfg.verify_peer {
            print("BOGO_UNIMPLEMENTED: PureGoose server mTLS unsupported\n");
            return BOGO_EXIT_UNIMPLEMENTED;
        }
        return BOGO_EXIT_OK;
    }
    let below_12 = (cfg.max_version != 0 && cfg.max_version < TLS_VERSION_1_2_WIRE) ||
        (cfg.expect_version != 0 && cfg.expect_version < TLS_VERSION_1_2_WIRE);
    if below_12 {
        print("BOGO_UNIMPLEMENTED: TLS <= 1.1 unsupported\n");
        return BOGO_EXIT_UNIMPLEMENTED;
    }
    return BOGO_EXIT_OK;
}

fn write_bogo_shim_header(fd: i64, shim_id: u64) -> bool {
    var hdr: u8[8] = [0; 8];
    core::write_le_u64_at(hdr[..], 0, shim_id);
    return net::tcp_send(fd, hdr[..]) == 8;
}

fn xor_bogo_payload(buf: u8[:]) {
    for i in buf.len {
        buf[i] = buf[i] ^ BOGO_XOR_MASK;
    }
}

fn load_pure_client_mtls_creds(
    cert_path: const u8[:],
    key_path:  const u8[:],
    cli_cfg:   tls::ClientHandshakeConfig&,
) -> bool {
    guard cert_path.len > 0 && key_path.len > 0 else { return false; }
    var cert_pem: u8[>..] = [];
    var key_pem:  u8[>..] = [];
    defer core::secure_zeroize_slice(cert_pem[..]);
    defer core::secure_zeroize_slice(key_pem[..]);
    guard read_file(cert_path, cert_pem) && read_file(key_path, key_pem) else { return false; }

    var idx:   i64        = 0;
    var label: u8[..64]   = [];
    var der:   u8[..4096] = [];
    guard tls::pem_next_block(cert_pem[..], idx, label, der) && label[..] == "CERTIFICATE" else {
        return false;
    }
    guard cli_cfg.client_cert_der.try_set(der[..]) else { return false; }
    let _, ok_key = tls::parse_private_key_pem(key_pem[..], cli_cfg.client_priv_seed);
    guard ok_key else {
        cli_cfg.client_cert_der.clear();
        return false;
    }
    return true;
}

fn load_pure_server_creds(cfg: const BogoConfig&, srv_cfg: tls::ServerHandshakeConfig&) -> bool {
    if cfg.cert_file.len > 0 && cfg.key_file.len > 0 {
        var cert_pem: u8[>..] = [];
        var key_pem:  u8[>..] = [];
        defer core::secure_zeroize_slice(cert_pem[..]);
        defer core::secure_zeroize_slice(key_pem[..]);
        guard read_file(cfg.cert_file[..], cert_pem) && read_file(cfg.key_file[..], key_pem) else {
            return false;
        }
        return tls::load_server_credentials_pem(cert_pem[..], key_pem[..], srv_cfg);
    }
    let seed: u8[32] = [0x42; 32];
    var cert_der: u8[..2048] = [];
    guard tls::build_test_ed25519_cert_der(
        seed, "localhost", "localhost", "127.0.0.1", cert_der,
    ) else { return false; }
    srv_cfg.priv_seed = seed;
    return srv_cfg.cert_der.try_set(cert_der[..]);
}

fn run_pure_bogo_write_first(fd: i64, slot_idx: u16) -> i32 {
    let msg = "hello";
    guard tls::transport_send(fd, slot_idx, msg) == (msg.len as i32) else {
        bogo_err("BOGO_ERR: WRITE_FAILED\n");
        return BOGO_EXIT_FAIL;
    }
    var buf: u8[64] = [0; 64];
    let nr = tls::transport_recv_slice(fd, slot_idx, buf[..], BOGO_IO_TIMEOUT_MS);
    guard nr == (msg.len as i32) else {
        bogo_err("BOGO_ERR: RECORD_ERROR\n");
        return BOGO_EXIT_FAIL;
    }
    xor_bogo_payload(buf[..nr]);
    guard buf[..nr] == msg else {
        bogo_err("BOGO_ERR: ECHO_MISMATCH\n");
        return BOGO_EXIT_FAIL;
    }
    return BOGO_EXIT_OK;
}

fn run_pure_bogo_echo(fd: i64, slot_idx: u16) -> i32 {
    var buf: u8[16384] = [0; 16384];
    for _ in 1024 {
        let nr = tls::transport_recv_slice(fd, slot_idx, buf[..], BOGO_IO_TIMEOUT_MS);
        if nr == 0 { return BOGO_EXIT_OK; }
        guard nr > 0 && nr <= buf.len else {
            bogo_err("BOGO_ERR: RECORD_ERROR\n");
            return BOGO_EXIT_FAIL;
        }
        xor_bogo_payload(buf[..nr]);
        let ns = tls::transport_send(fd, slot_idx, buf[..nr]);
        guard ns == nr else {
            bogo_err("BOGO_ERR: WRITE_FAILED\n");
            return BOGO_EXIT_FAIL;
        }
    }
    return BOGO_EXIT_OK;
}

fn check_expected_alpn(selected: const u8[:], expected: const u8[:]) -> bool {
    guard expected.len > 0 else { return true; }
    return selected == expected;
}

fn run_pure_bogo_client(fd: i64, cfg: const BogoConfig&) -> i32 {
    var cli_cfg = tls::ClientHandshakeConfig {
        insecure_skip_verify: !cfg.verify_peer,
        use_system_roots:     cfg.trust_cert.len == 0,
        ..
    };
    defer core::secure_zeroize_32(cli_cfg.client_priv_seed);
    guard cli_cfg.server_name.try_set(cfg.host_name[..]) && cli_cfg.alpn.try_set(cfg.alpn_csv[..]) else {
        net::tcp_close(fd);
        return BOGO_EXIT_FAIL;
    }
    if cfg.trust_cert.len > 0 {
        let added, ok_ca = tls::load_trust_anchors_pem_file(cli_cfg.trust_store, cfg.trust_cert[..]);
        guard ok_ca && added > 0 else {
            net::tcp_close(fd);
            return BOGO_EXIT_FAIL;
        }
    }
    if cfg.cert_file.len > 0 || cfg.key_file.len > 0 {
        guard load_pure_client_mtls_creds(cfg.cert_file[..], cfg.key_file[..], cli_cfg) else {
            net::tcp_close(fd);
            bogo_err("BOGO_UNIMPLEMENTED: unsupported client mTLS key type\n");
            return BOGO_EXIT_UNIMPLEMENTED;
        }
    }
    let slot_idx, ok_hs = tls::client_handshake(fd, cli_cfg);
    guard ok_hs else {
        net::tcp_close(fd);
        bogo_err("BOGO_ERR: HANDSHAKE_FAILED\n");
        return BOGO_EXIT_FAIL;
    }
    defer tls::transport_close(fd, slot_idx);
    guard check_expected_alpn(tls::session_alpn(slot_idx), cfg.expect_alpn[..]) else {
        bogo_err("BOGO_ERR: ALPN_MISMATCH\n");
        return BOGO_EXIT_FAIL;
    }
    if cfg.key_update {
        guard tls::send_key_update(fd, slot_idx, rfc::KEY_UPDATE_REQUESTED) else {
            bogo_err("BOGO_ERR: KEY_UPDATE_FAILED\n");
            return BOGO_EXIT_FAIL;
        }
    }
    return if cfg.writes_first { run_pure_bogo_write_first(fd, slot_idx) } else { run_pure_bogo_echo(fd, slot_idx) };
}

fn run_pure_bogo_server(fd: i64, cfg: const BogoConfig&) -> i32 {
    var srv_cfg = tls::ServerHandshakeConfig { .. };
    defer core::secure_zeroize_32(srv_cfg.priv_seed);
    guard load_pure_server_creds(cfg, srv_cfg) && srv_cfg.alpn.try_set(cfg.alpn_csv[..]) else {
        net::tcp_close(fd);
        return BOGO_EXIT_FAIL;
    }
    let slot_idx, ok_hs = tls::server_handshake(fd, srv_cfg);
    guard ok_hs else {
        net::tcp_close(fd);
        bogo_err("BOGO_ERR: HANDSHAKE_FAILED\n");
        return BOGO_EXIT_FAIL;
    }
    defer tls::transport_close(fd, slot_idx);
    guard check_expected_alpn(tls::session_alpn(slot_idx), cfg.expect_alpn[..]) else {
        bogo_err("BOGO_ERR: ALPN_MISMATCH\n");
        return BOGO_EXIT_FAIL;
    }
    if cfg.key_update {
        guard tls::send_key_update(fd, slot_idx, rfc::KEY_UPDATE_REQUESTED) else {
            bogo_err("BOGO_ERR: KEY_UPDATE_FAILED\n");
            return BOGO_EXIT_FAIL;
        }
    }
    return if cfg.writes_first { run_pure_bogo_write_first(fd, slot_idx) } else { run_pure_bogo_echo(fd, slot_idx) };
}

fn flush_ep_wire(fd: i64, ep: tls::TlsEndpoint&) -> bool {
    var wire: u8[16384] = [0; 16384];
    for _ in 16 {
        let n, st = tls::tls_endpoint_drain_wire(ep, wire[..]);
        guard st == tls::TlsBackendStatus.Ok else { return false; }
        if n <= 0 { return true; }
        guard net::tcp_send(fd, wire[..n]) == (n as i32) else { return false; }
    }
    return true;
}

fn feed_ep_wire_once(fd: i64, ep: tls::TlsEndpoint&, rx: u8[:]) -> tls::TlsBackendStatus {
    let recvd = net::tcp_recv_slice(fd, rx, BOGO_IO_TIMEOUT_MS);
    if recvd == -2 { return tls::TlsBackendStatus.WantRead; }
    guard recvd > 0 else { return tls::TlsBackendStatus.Closed; }
    let fed, st = tls::tls_endpoint_feed_wire(ep, rx[..recvd]);
    guard st == tls::TlsBackendStatus.Ok && fed == recvd else {
        return tls::TlsBackendStatus.Error;
    }
    return tls::TlsBackendStatus.Ok;
}

fn drive_ep_handshake(fd: i64, ep: tls::TlsEndpoint&) -> tls::TlsBackendStatus {
    var rx: u8[16384] = [0; 16384];
    for _ in 64 {
        let st = tls::tls_endpoint_step_handshake(ep);
        let _ = flush_ep_wire(fd, ep);
        if st == tls::TlsBackendStatus.Ok || tls::tls_endpoint_is_established(ep) {
            return tls::TlsBackendStatus.Ok;
        }
        if st != tls::TlsBackendStatus.WantRead && st != tls::TlsBackendStatus.WantWrite {
            return st;
        }
        let rst = feed_ep_wire_once(fd, ep, rx[..]);
        if rst == tls::TlsBackendStatus.Closed {
            let fst = tls::tls_endpoint_step_handshake(ep);
            return if fst == tls::TlsBackendStatus.WantRead {
                tls::TlsBackendStatus.HandshakeError
            } else {
                fst
            };
        }
        guard rst == tls::TlsBackendStatus.Ok || rst == tls::TlsBackendStatus.WantRead else {
            return rst;
        }
    }
    return tls::TlsBackendStatus.HandshakeError;
}

fn run_ep_bogo_echo(fd: i64, ep: tls::TlsEndpoint&) -> i32 {
    var rx:  u8[16384] = [0; 16384];
    var app: u8[16384] = [0; 16384];
    for _ in 1024 {
        let nr, st = tls::tls_endpoint_read_app(ep, app[..]);
        if nr > 0 && nr <= app.len {
            xor_bogo_payload(app[..nr]);
            let nw, sw = tls::tls_endpoint_write_app(ep, app[..nr]);
            guard sw == tls::TlsBackendStatus.Ok && nw == nr && flush_ep_wire(fd, ep) else {
                bogo_err("BOGO_ERR: WRITE_FAILED\n");
                return BOGO_EXIT_FAIL;
            }
            continue;
        }
        if st == tls::TlsBackendStatus.Closed {
            let _ = tls::tls_endpoint_shutdown(ep);
            let _ = flush_ep_wire(fd, ep);
            return BOGO_EXIT_OK;
        }
        guard st == tls::TlsBackendStatus.WantRead || st == tls::TlsBackendStatus.Ok else {
            bogo_err("BOGO_ERR: RECORD_ERROR\n");
            return BOGO_EXIT_FAIL;
        }
        let _ = flush_ep_wire(fd, ep);
        let rst = feed_ep_wire_once(fd, ep, rx[..]);
        if rst == tls::TlsBackendStatus.Closed { return BOGO_EXIT_OK; }
        guard rst == tls::TlsBackendStatus.Ok else {
            bogo_err("BOGO_ERR: RECORD_ERROR\n");
            return BOGO_EXIT_FAIL;
        }
    }
    return BOGO_EXIT_OK;
}

fn build_openssl_bogo_config(cfg: const BogoConfig&, out: tls::TlsBackendConfig&) -> bool {
    let want_tls12 = (cfg.min_version > 0 && cfg.min_version <= TLS_VERSION_1_2_WIRE) ||
        (cfg.max_version > 0 && cfg.max_version <= TLS_VERSION_1_2_WIRE);
    out = tls::TlsBackendConfig {
        kind:                 tls::TlsBackendKind.SystemOpenSsl,
        min_version:          if want_tls12 { tls::TlsMinVersion.Tls12 } else { tls::TlsMinVersion.Tls13 },
        is_server:            cfg.is_server,
        insecure_skip_verify: !cfg.verify_peer,
        use_system_roots:     cfg.trust_cert.len == 0,
        ..
    };
    guard out.server_name.try_set(cfg.host_name[..]) &&
        out.alpn_wire.try_set(cfg.alpn_wire[..]) &&
        out.ca_file.try_set(cfg.trust_cert[..]) &&
        out.cert_pem_file.try_set(cfg.cert_file[..]) &&
        out.key_pem_file.try_set(cfg.key_file[..]) else {
        return false;
    }
    return true;
}

fn run_openssl_bogo_session(fd: i64, cfg: const BogoConfig&) -> i32 {
    defer net::tcp_close(fd);
    var bcfg = tls::TlsBackendConfig { .. };
    guard build_openssl_bogo_config(cfg, bcfg) else { return BOGO_EXIT_FAIL; }
    var ep, open_st = tls::tls_endpoint_open(bcfg);
    guard open_st == tls::TlsBackendStatus.Ok else {
        if open_st == tls::TlsBackendStatus.Unavailable {
            print("BOGO_UNIMPLEMENTED: SystemOpenSsl unavailable\n");
            return BOGO_EXIT_UNIMPLEMENTED;
        }
        bogo_err("BOGO_ERR: OPEN_FAILED\n");
        return BOGO_EXIT_FAIL;
    }
    defer tls::tls_endpoint_close(ep);

    let hs_st = drive_ep_handshake(fd, ep);
    guard hs_st == tls::TlsBackendStatus.Ok else {
        if hs_st == tls::TlsBackendStatus.VerifyError {
            bogo_err("BOGO_ERR: VERIFY_FAILED\n");
        } else {
            bogo_err("BOGO_ERR: HANDSHAKE_FAILED\n");
        }
        return BOGO_EXIT_FAIL;
    }
    let sel_alpn = tls::tls_endpoint_selected_alpn(ep);
    guard check_expected_alpn(sel_alpn[..], cfg.expect_alpn[..]) else {
        bogo_err("BOGO_ERR: ALPN_MISMATCH\n");
        return BOGO_EXIT_FAIL;
    }
    return run_ep_bogo_echo(fd, ep);
}

fn main() {
    let a = args();
    for arg in a {
        if arg == "-is-handshaker-supported" {
            print("No\n");
            return;
        }
    }
    var cfg = BogoConfig { .. };
    let cli_rc = parse_bogo_cli_args(a, cfg);
    if cli_rc != BOGO_EXIT_OK {
        exit(cli_rc);
    }
    let pol_rc = check_bogo_policy_support(cfg);
    if pol_rc != BOGO_EXIT_OK {
        exit(pol_rc);
    }
    guard cfg.port > 0 else {
        bogo_err("BOGO_ERR: MISSING_PORT\n");
        exit(BOGO_EXIT_FAIL);
    }

    let host = if cfg.ipv6 { "::1" } else { "127.0.0.1" };
    let fd = net::tcp_connect(host, cfg.port, BOGO_IO_TIMEOUT_MS);
    guard fd > 0 else {
        bogo_err("BOGO_ERR: CONNECT_FAILED\n");
        exit(BOGO_EXIT_FAIL);
    }
    guard write_bogo_shim_header(fd, cfg.shim_id) else {
        net::tcp_close(fd);
        bogo_err("BOGO_ERR: HEADER_WRITE_FAILED\n");
        exit(BOGO_EXIT_FAIL);
    }

    let rc = if cfg.backend == tls::TlsBackendKind.SystemOpenSsl {
        run_openssl_bogo_session(fd, cfg)
    } else if cfg.is_server {
        run_pure_bogo_server(fd, cfg)
    } else {
        run_pure_bogo_client(fd, cfg)
    };
    if rc != BOGO_EXIT_OK {
        exit(rc);
    }
}
