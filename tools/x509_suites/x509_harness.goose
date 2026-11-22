// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Stdin/stdout line-protocol X.509 PKI conformance harness for goose-wing.
// Drives RFC 5280 certificate chain validation, SAN matching, NameConstraints,
// CRL revocation checks, and RFC 6960 OCSP stapling for x509-limbo, BetterTLS, and PKITS.
import std;
import wing from "../..";

const MAX_INTERMEDIATES: i64 = 16;
const MAX_CHAIN_LEN:     i64 = 8;

enum VerifyMode {
    Build,
    Direct,
}

struct DerSpan {
    start: i64 = 0,
    len:   i64 = 0,
}

struct VerifyCmd {
    case_id:     const u8[:]             = "",
    mode:        VerifyMode              = VerifyMode.Build,
    role:        tls::CertValidationRole = tls::CertValidationRole.Server,
    now_unix:    i64                     = 0,
    peer:        const u8[:]             = "-",
    leaf_hex:    const u8[:]             = "-",
    inters_hex:  const u8[:]             = "-",
    anchors_hex: const u8[:]             = "-",
    max_depth:   i64                     = -1,
}

struct RevocationCmd {
    case_id:    const u8[:] = "",
    now_unix:   i64         = 0,
    leaf_hex:   const u8[:] = "-",
    issuer_hex: const u8[:] = "-",
    data_hex:   const u8[:] = "-",
}

struct HarnessCtx {
    store: tls::TrustAnchorStore = tls::TrustAnchorStore { .. },
    arena: u8[>..]               = [],
}

fn alert_name(a: tls::Alert) -> const u8[:] {
    return match a {
        CloseNotify => "CloseNotify",
        UnexpectedMessage => "UnexpectedMessage",
        BadRecordMac => "BadRecordMac",
        RecordOverflow => "RecordOverflow",
        HandshakeFailure => "HandshakeFailure",
        BadCertificate => "BadCertificate",
        UnsupportedCertificate => "UnsupportedCertificate",
        CertificateRevoked => "CertificateRevoked",
        CertificateExpired => "CertificateExpired",
        CertificateUnknown => "CertificateUnknown",
        IllegalParameter => "IllegalParameter",
        UnknownCa => "UnknownCa",
        AccessDenied => "AccessDenied",
        DecodeError => "DecodeError",
        DecryptError => "DecryptError",
        ProtocolVersion => "ProtocolVersion",
        InsufficientSecurity => "InsufficientSecurity",
        InternalError => "InternalError",
        InappropriateFallback => "InappropriateFallback",
        UserCanceled => "UserCanceled",
        MissingExtension => "MissingExtension",
        UnsupportedExtension => "UnsupportedExtension",
        UnrecognizedName => "UnrecognizedName",
        BadCertificateStatusResponse => "BadCertificateStatusResponse",
        UnknownPskIdentity => "UnknownPskIdentity",
        CertificateRequired => "CertificateRequired",
        NoApplicationProtocol => "NoApplicationProtocol",
    };
}

// Decodes an even-length hex string and appends bytes to `arena`.
// Rolls back `arena` on odd length or invalid hex digit.
//
// Example:
//   hex_str = "3003", arena = []
//   returns: DerSpan { start: 0, len: 2 }, ok = true
fn decode_hex_append(hex_str: const u8[:], arena: u8[>..]&) -> DerSpan, bool {
    let saved = arena.len;
    if hex_str == "-" || hex_str.len == 0 {
        return DerSpan { start: saved, len: 0 }, true;
    }
    guard (hex_str.len & 1) == 0 else { return DerSpan { .. }, false; }
    var committed = false;
    defer if !committed { arena.resize(saved); };

    var i: i64 = 0;
    while i < hex_str.len {
        let next_i = core::add_sat_i64(i, 2);
        let b, ok = core::parse_u8_hex(hex_str[i..next_i]);
        guard ok else { return DerSpan { .. }, false; }
        arena.push(b);
        i = next_i;
    }
    committed = true;
    return DerSpan { start: saved, len: core::sub_sat_i64(arena.len, saved) }, true;
}

// Decodes comma-separated hex DER blobs into `arena`, recording spans in `out_spans`.
// Rolls back `arena` and clears `out_spans` on overflow or malformed hex.
//
// Example:
//   csv = "3000,3001"
//   returns: ok = true, out_spans has 2 entries
fn decode_hex_csv_spans(
    csv:       const u8[:],
    arena:     u8[>..]&,
    out_spans: DerSpan[..16]&,
) -> bool {
    out_spans.clear();
    guard csv.len > 0 && csv != "-" else { return true; }
    let saved = arena.len;
    var committed = false;
    defer if !committed {
        arena.resize(saved);
        out_spans.clear();
    };

    var tok = core::make_byte_tokenizer(csv, ',');
    while true {
        let item, more = core::token_next(tok);
        guard more else { break; }
        let trimmed = item.trim_lws();
        guard trimmed.len > 0 else { continue; }
        let sp, ok_hex = decode_hex_append(trimmed, arena);
        guard ok_hex && out_spans.try_push(sp) else { return false; }
    }
    committed = true;
    return true;
}

// Parses a verification mode token (`BUILD` or `DIRECT`).
//
// Example:
//   tok = "DIRECT"
//   returns: VerifyMode.Direct, ok = true
fn parse_verify_mode(tok: const u8[:]) -> VerifyMode, bool {
    if tok == "BUILD" { return VerifyMode.Build, true; }
    if tok == "DIRECT" { return VerifyMode.Direct, true; }
    return VerifyMode.Build, false;
}

// Parses a certificate validation role token (`SERVER`, `CLIENT`, or `ANY`).
//
// Example:
//   tok = "CLIENT"
//   returns: tls::CertValidationRole.Client, ok = true
fn parse_role_token(tok: const u8[:]) -> tls::CertValidationRole, bool {
    if tok == "SERVER" { return tls::CertValidationRole.Server, true; }
    if tok == "CLIENT" { return tls::CertValidationRole.Client, true; }
    if tok == "ANY" { return tls::CertValidationRole.Any, true; }
    return tls::CertValidationRole.Server, false;
}

// Parses an 8-column `VERIFY` command payload into `VerifyCmd`.
//
// Example:
//   rest = "c1\tBUILD\tSERVER\t1700000000\texample.com\t30...\t-\t30..."
//   returns: VerifyCmd { case_id: "c1", mode: VerifyMode.Build, ... }, ok = true
fn parse_verify_cmd(rest: const u8[:]) -> VerifyCmd, bool {
    var out = VerifyCmd { .. };
    let c0, r0, ok0 = rest.split_once_byte('\t');
    let c1, r1, ok1 = r0.split_once_byte('\t');
    let c2, r2, ok2 = r1.split_once_byte('\t');
    let c3, r3, ok3 = r2.split_once_byte('\t');
    let c4, r4, ok4 = r3.split_once_byte('\t');
    let c5, r5, ok5 = r4.split_once_byte('\t');
    let c6, r6, ok6 = r5.split_once_byte('\t');
    guard ok0 && ok1 && ok2 && ok3 && ok4 && ok5 && ok6 else { return out, false; }
    let c7, c8, has_c8 = r6.split_once_byte('\t');
    let anchors_tok = if has_c8 { c7 } else { r6 };
    let mode, ok_m = parse_verify_mode(c1);
    let role, ok_r = parse_role_token(c2);
    let now_u, ok_t = c3.parse_i64_dec();
    guard ok_m && ok_r && ok_t else { return out, false; }
    if has_c8 {
        let md, ok_md = c8.parse_i64_dec();
        guard ok_md else { return out, false; }
        out.max_depth = md;
    }
    out.case_id = c0;
    out.mode = mode;
    out.role = role;
    out.now_unix = now_u;
    out.peer = c4;
    out.leaf_hex = c5;
    out.inters_hex = c6;
    out.anchors_hex = anchors_tok;
    return out, true;
}

// Parses a 5-column `CRL` or `OCSP` command payload into `RevocationCmd`.
//
// Example:
//   rest = "r1\t1700000000\t30...\t30...\t30..."
//   returns: RevocationCmd { case_id: "r1", now_unix: 1700000000, ... }, ok = true
fn parse_revocation_cmd(rest: const u8[:]) -> RevocationCmd, bool {
    var out = RevocationCmd { .. };
    let c0, r0, ok0 = rest.split_once_byte('\t');
    let c1, r1, ok1 = r0.split_once_byte('\t');
    let c2, r2, ok2 = r1.split_once_byte('\t');
    let c3, c4, ok3 = r2.split_once_byte('\t');
    guard ok0 && ok1 && ok2 && ok3 else { return out, false; }
    let now_u, ok_t = c1.parse_i64_dec();
    guard ok_t else { return out, false; }
    out.case_id = c0;
    out.now_unix = now_u;
    out.leaf_hex = c2;
    out.issuer_hex = c3;
    out.data_hex = c4;
    return out, true;
}

fn load_anchors(
    arena: const u8[:],
    spans: const DerSpan[..16]&,
    store: tls::TrustAnchorStore&,
) -> i64 {
    store = tls::TrustAnchorStore { .. };
    var loaded: i64 = 0;
    for i in spans.len {
        let sp = spans[i];
        let end = core::add_sat_i64(sp.start, sp.len);
        guard sp.len > 0 && end <= arena.len else { continue; }
        if tls::add_trust_anchor_cert_der(store, arena[sp.start..end]) {
            loaded = core::add_sat_i64(loaded, 1);
        }
    }
    return loaded;
}

fn verify_chain_direct(
    arena:       const u8[:],
    leaf_span:   DerSpan,
    inter_spans: const DerSpan[..16]&,
    store:       const tls::TrustAnchorStore&,
    now_unix:    i64,
    role:        tls::CertValidationRole,
    leaf_out:    tls::ParsedCert&,
) -> tls::Alert {
    let leaf_end = core::add_sat_i64(leaf_span.start, leaf_span.len);
    guard leaf_span.len > 0 && leaf_end <= arena.len else { return tls::Alert.DecodeError; }
    let leaf_raw = arena[leaf_span.start..leaf_end];
    guard tls::parse_x509_certificate(leaf_raw, leaf_out) else { return tls::Alert.DecodeError; }

    var chain: tls::ParsedCert[..8] = [];
    var raws:  const u8[:][..8]     = [];
    guard chain.try_push(leaf_out) && raws.try_push(leaf_raw) else { return tls::Alert.BadCertificate; }

    for i in inter_spans.len {
        let sp = inter_spans[i];
        let end = core::add_sat_i64(sp.start, sp.len);
        guard sp.len > 0 && end <= arena.len else { return tls::Alert.DecodeError; }
        let raw_c = arena[sp.start..end];
        var parsed_c = tls::ParsedCert { .. };
        guard tls::parse_x509_certificate(raw_c, parsed_c) else { return tls::Alert.DecodeError; }
        guard chain.try_push(parsed_c) && raws.try_push(raw_c) else { return tls::Alert.BadCertificate; }
    }
    return tls::verify_certificate_chain(chain, raws, store, now_unix, role);
}

fn is_issuer_candidate(
    cert:       const tls::ParsedCert&,
    raw_cert:   const u8[:],
    top_issuer: const u8[:],
    is_visited: bool,
) -> bool {
    guard !is_visited else { return false; }
    let cand_subj = tls::span_slice(raw_cert, cert.subject_raw);
    return cand_subj.len > 0 && cand_subj == top_issuer;
}

inline fn is_self_issued_cert(cert: const tls::ParsedCert&, raw_cert: const u8[:]) -> bool {
    let iss = tls::span_slice(raw_cert, cert.issuer_raw);
    let sub = tls::span_slice(raw_cert, cert.subject_raw);
    return iss.len > 0 && iss == sub;
}

inline fn next_non_self_issued_depth(
    cert:       const tls::ParsedCert&,
    raw_cert:   const u8[:],
    non_si_cnt: i64,
    max_depth:  i64,
) -> i64, bool {
    let next_cnt = if is_self_issued_cert(cert, raw_cert) {
        non_si_cnt
    } else {
        core::add_sat_i64(non_si_cnt, 1)
    };
    return next_cnt, max_depth < 0 || next_cnt <= max_depth;
}

recursive fn dfs_build_chain(
    pool_certs: const tls::ParsedCert[..16]&,
    pool_raws:  const u8[:][..16]&,
    chain:      tls::ParsedCert[..8]&,
    raws:       const u8[:][..8]&,
    store:      const tls::TrustAnchorStore&,
    now_unix:   i64,
    role:       tls::CertValidationRole,
    visited:    bool[16]&,
    max_depth:  i64,
    non_si_cnt: i64,
) -> tls::Alert {
    var best = tls::verify_certificate_chain(chain, raws, store, now_unix, role);
    if best == tls::Alert.CloseNotify || chain.len >= MAX_CHAIN_LEN {
        return best;
    }
    let top_idx = core::sub_sat_i64(chain.len, 1);
    let top_issuer = tls::span_slice(raws[top_idx], chain[top_idx].issuer_raw);
    let limit = min(pool_certs.len, MAX_INTERMEDIATES);
    for i in limit {
        guard is_issuer_candidate(pool_certs[i], pool_raws[i], top_issuer, visited[i]) else { continue; }
        let next_non_si, ok_depth = next_non_self_issued_depth(pool_certs[i], pool_raws[i], non_si_cnt, max_depth);
        guard ok_depth && chain.try_push(pool_certs[i]) && raws.try_push(pool_raws[i]) else { continue; }
        visited[i] = true;
        let sub = dfs_build_chain(
            pool_certs, pool_raws, chain, raws, store, now_unix, role, visited, max_depth, next_non_si,
        );
        visited[i] = false;
        chain.pop();
        raws.pop();
        if sub == tls::Alert.CloseNotify { return tls::Alert.CloseNotify; }
        if best == tls::Alert.UnknownCa && sub != tls::Alert.UnknownCa { best = sub; }
    }
    return best;
}

fn collect_intermediate_pool(
    arena:       const u8[:],
    inter_spans: const DerSpan[..16]&,
    pool_certs:  tls::ParsedCert[..16]&,
    pool_raws:   const u8[:][..16]&,
) {
    for i in inter_spans.len {
        let sp = inter_spans[i];
        let end = core::add_sat_i64(sp.start, sp.len);
        guard sp.len > 0 && end <= arena.len else { continue; }
        let raw_c = arena[sp.start..end];
        var parsed_c = tls::ParsedCert { .. };
        guard tls::parse_x509_certificate(raw_c, parsed_c) else { continue; }
        guard pool_certs.try_push(parsed_c) && pool_raws.try_push(raw_c) else { break; }
    }
}

fn verify_chain_build(
    arena:       const u8[:],
    leaf_span:   DerSpan,
    inter_spans: const DerSpan[..16]&,
    store:       const tls::TrustAnchorStore&,
    now_unix:    i64,
    role:        tls::CertValidationRole,
    max_depth:   i64,
    leaf_out:    tls::ParsedCert&,
) -> tls::Alert {
    let leaf_end = core::add_sat_i64(leaf_span.start, leaf_span.len);
    guard leaf_span.len > 0 && leaf_end <= arena.len else { return tls::Alert.DecodeError; }
    let leaf_raw = arena[leaf_span.start..leaf_end];
    guard tls::parse_x509_certificate(leaf_raw, leaf_out) else { return tls::Alert.DecodeError; }

    var pool_certs: tls::ParsedCert[..16] = [];
    var pool_raws:  const u8[:][..16]     = [];
    collect_intermediate_pool(arena, inter_spans, pool_certs, pool_raws);

    var chain:   tls::ParsedCert[..8] = [];
    var raws:    const u8[:][..8]     = [];
    var visited: bool[16]             = [false; 16];
    guard chain.try_push(leaf_out) && raws.try_push(leaf_raw) else { return tls::Alert.BadCertificate; }
    return dfs_build_chain(pool_certs, pool_raws, chain, raws, store, now_unix, role, visited, max_depth, 0);
}

fn check_peer_san(
    leaf_cert: const tls::ParsedCert&,
    leaf_raw:  const u8[:],
    peer:      const u8[:],
) -> bool {
    guard peer.len > 0 && peer != "-" else { return true; }
    return tls::match_cert_san_host(leaf_cert, leaf_raw, peer);
}

fn handle_verify_cmd(rest: const u8[:], ctx: HarnessCtx&) {
    let cmd, ok_cmd = parse_verify_cmd(rest);
    guard ok_cmd else {
        print("VERDICT\t-\tFAIL\tBadCommand");
        flush_stdout();
        return;
    }
    ctx.arena.clear();
    let leaf_sp, ok_leaf = decode_hex_append(cmd.leaf_hex, ctx.arena);
    var inter_spans:  DerSpan[..16] = [];
    var anchor_spans: DerSpan[..16] = [];
    guard ok_leaf &&
        decode_hex_csv_spans(cmd.inters_hex, ctx.arena, inter_spans) &&
        decode_hex_csv_spans(cmd.anchors_hex, ctx.arena, anchor_spans) else {
        print("VERDICT\t", cmd.case_id, "\tFAIL\tBadHex");
        flush_stdout();
        return;
    }

    let _ = load_anchors(ctx.arena[..], anchor_spans, ctx.store);
    var leaf_cert = tls::ParsedCert { .. };
    let alert = if cmd.mode == VerifyMode.Direct {
        verify_chain_direct(
            ctx.arena[..], leaf_sp, inter_spans, ctx.store, cmd.now_unix, cmd.role, leaf_cert,
        )
    } else {
        verify_chain_build(
            ctx.arena[..], leaf_sp, inter_spans, ctx.store, cmd.now_unix, cmd.role, cmd.max_depth, leaf_cert,
        )
    };
    if alert != tls::Alert.CloseNotify {
        print("VERDICT\t", cmd.case_id, "\tFAIL\t", alert_name(alert));
        flush_stdout();
        return;
    }
    let leaf_end = core::add_sat_i64(leaf_sp.start, leaf_sp.len);
    guard check_peer_san(leaf_cert, ctx.arena[leaf_sp.start..leaf_end], cmd.peer) else {
        print("VERDICT\t", cmd.case_id, "\tFAIL\tHostnameMismatch");
        flush_stdout();
        return;
    }
    print("VERDICT\t", cmd.case_id, "\tOK\tCloseNotify");
    flush_stdout();
}

fn eval_crl_status(
    leaf_raw:   const u8[:],
    issuer_raw: const u8[:],
    crl_raw:    const u8[:],
    now_unix:   i64,
) -> const u8[:], const u8[:] {
    var leaf_cert = tls::ParsedCert { .. };
    var issuer_cert = tls::ParsedCert { .. };
    guard tls::parse_x509_certificate(leaf_raw, leaf_cert) &&
        tls::parse_x509_certificate(issuer_raw, issuer_cert) else {
        return "PARSE_ERR", "DecodeError";
    }
    let leaf_iss = tls::span_slice(leaf_raw, leaf_cert.issuer_raw);
    let iss_subj = tls::span_slice(issuer_raw, issuer_cert.subject_raw);
    guard leaf_iss.len > 0 && leaf_iss == iss_subj else {
        return "DIFF_ISSUER", "CloseNotify";
    }
    let ser_u64, ok_ser = tls::parse_asn1_serial_u64(tls::span_slice(leaf_raw, leaf_cert.serial_number));
    guard ok_ser else { return "PARSE_ERR", "BadCertificate"; }
    let alert = tls::check_crl_der_revocation(crl_raw, ser_u64, issuer_cert, issuer_raw, now_unix);
    if alert == tls::Alert.CloseNotify { return "OK", "CloseNotify"; }
    if alert == tls::Alert.CertificateRevoked { return "REVOKED", "CertificateRevoked"; }
    if alert == tls::Alert.CertificateExpired { return "EXPIRED", "CertificateExpired"; }
    if alert == tls::Alert.UnknownCa { return "BAD_ISSUER", "UnknownCa"; }
    if alert == tls::Alert.BadCertificate { return "BAD_SIG", "BadCertificate"; }
    return "PARSE_ERR", alert_name(alert);
}

fn handle_crl_cmd(rest: const u8[:], ctx: HarnessCtx&) {
    let cmd, ok_cmd = parse_revocation_cmd(rest);
    guard ok_cmd else {
        print("CRL_VERDICT\t-\tPARSE_ERR\tBadCommand");
        flush_stdout();
        return;
    }
    ctx.arena.clear();
    let leaf_sp, ok_l = decode_hex_append(cmd.leaf_hex, ctx.arena);
    let iss_sp, ok_i = decode_hex_append(cmd.issuer_hex, ctx.arena);
    let crl_sp, ok_c = decode_hex_append(cmd.data_hex, ctx.arena);
    guard ok_l && ok_i && ok_c && leaf_sp.len > 0 && iss_sp.len > 0 && crl_sp.len > 0 else {
        print("CRL_VERDICT\t", cmd.case_id, "\tPARSE_ERR\tBadHex");
        flush_stdout();
        return;
    }
    let l_end = core::add_sat_i64(leaf_sp.start, leaf_sp.len);
    let i_end = core::add_sat_i64(iss_sp.start, iss_sp.len);
    let c_end = core::add_sat_i64(crl_sp.start, crl_sp.len);
    let st, reason = eval_crl_status(
        ctx.arena[leaf_sp.start..l_end],
        ctx.arena[iss_sp.start..i_end],
        ctx.arena[crl_sp.start..c_end],
        cmd.now_unix,
    );
    print("CRL_VERDICT\t", cmd.case_id, "\t", st, "\t", reason);
    flush_stdout();
}

fn handle_ocsp_cmd(rest: const u8[:], ctx: HarnessCtx&) {
    let cmd, ok_cmd = parse_revocation_cmd(rest);
    guard ok_cmd else {
        print("OCSP_VERDICT\t-\tFAIL\tBadCommand");
        flush_stdout();
        return;
    }
    ctx.arena.clear();
    let leaf_sp, ok_l = decode_hex_append(cmd.leaf_hex, ctx.arena);
    let iss_sp, ok_i = decode_hex_append(cmd.issuer_hex, ctx.arena);
    let ocsp_sp, ok_o = decode_hex_append(cmd.data_hex, ctx.arena);
    guard ok_l && ok_i && ok_o && leaf_sp.len > 0 && ocsp_sp.len > 0 else {
        print("OCSP_VERDICT\t", cmd.case_id, "\tFAIL\tBadHex");
        flush_stdout();
        return;
    }
    let leaf_raw = ctx.arena[leaf_sp.start..core::add_sat_i64(leaf_sp.start, leaf_sp.len)];
    let iss_raw = if iss_sp.len > 0 {
        ctx.arena[iss_sp.start..core::add_sat_i64(iss_sp.start, iss_sp.len)]
    } else {
        ""
    };
    let ocsp_raw = ctx.arena[ocsp_sp.start..core::add_sat_i64(ocsp_sp.start, ocsp_sp.len)];
    var leaf_cert = tls::ParsedCert { .. };
    guard tls::parse_x509_certificate(leaf_raw, leaf_cert) else {
        print("OCSP_VERDICT\t", cmd.case_id, "\tFAIL\tDecodeError");
        flush_stdout();
        return;
    }
    let alert = tls::validate_ocsp_stapling(ocsp_raw, leaf_cert, leaf_raw, cmd.now_unix, iss_raw);
    let verdict = if alert == tls::Alert.CloseNotify { "OK" } else { "FAIL" };
    print("OCSP_VERDICT\t", cmd.case_id, "\t", verdict, "\t", alert_name(alert));
    flush_stdout();
}

fn dispatch_line(raw_line: const u8[:], ctx: HarnessCtx&) -> bool {
    let line = raw_line.trim_end_byte('\r');
    guard line.len > 0 else { return true; }
    if line == "QUIT" { return false; }
    let kind, rest, ok_k = line.split_once_byte('\t');
    guard ok_k else {
        print("ERR\tBadLine");
        flush_stdout();
        return true;
    }
    if kind == "VERIFY" {
        handle_verify_cmd(rest, ctx);
    } else if kind == "CRL" {
        handle_crl_cmd(rest, ctx);
    } else if kind == "OCSP" {
        handle_ocsp_cmd(rest, ctx);
    } else {
        print("ERR\tUnknownCmd");
        flush_stdout();
    }
    return true;
}

fn main() {
    var ctx = HarnessCtx { .. };
    let a = args();
    if a.len >= 2 && a[1] != "-" {
        var batch: u8[>..] = [];
        guard read_file(a[1], batch) else {
            print("ERR:READ_FILE");
            exit(2);
        }
        var tok = core::make_byte_tokenizer(batch[..], '\n');
        while true {
            let ln, more = core::token_next(tok);
            guard more else { break; }
            guard dispatch_line(ln, ctx) else { break; }
        }
        return;
    }
    var line_buf: u8[>..] = [];
    while read_line(line_buf) {
        guard dispatch_line(line_buf[..], ctx) else { break; }
        line_buf.clear();
    }
}
