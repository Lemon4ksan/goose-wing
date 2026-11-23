// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal OCSP response (RFC 6960) DER parsing and verification helpers.
namespace tls_internal;

import std;
import core;
import .internal;
import .asn1;
import .record;
import .types;
import .pki_sig_internal;
import .pki_x509_ext_internal;

inline fn x509_parse_ocsp_status(s_val: u8, out_status: tls::OcspResponseStatus&) -> bool {
    if s_val == rfc::OCSP_STATUS_SUCCESSFUL {
        out_status = tls::OcspResponseStatus.Successful;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_MALFORMED_REQ {
        out_status = tls::OcspResponseStatus.MalformedRequest;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_INTERNAL_ERROR {
        out_status = tls::OcspResponseStatus.InternalError;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_TRY_LATER {
        out_status = tls::OcspResponseStatus.TryLater;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_SIG_REQUIRED {
        out_status = tls::OcspResponseStatus.SigRequired;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_UNAUTHORIZED {
        out_status = tls::OcspResponseStatus.Unauthorized;
        return true;
    }
    out_status = tls::OcspResponseStatus.Unknown;
    return false;
}

fn x509_parse_ocsp_cert_id(
    single_resp:     core::ByteCursor&,
    single_resp_end: i64,
    out:             tls::ParsedOcspResponse&,
) -> bool {
    var cert_id_seq = core::cursor_from(single_resp.buf[..0]);
    if !tls::get_asn1_element(single_resp, rfc::ASN1_TAG_SEQUENCE, cert_id_seq) { return false; }
    let cert_id_end = core::sub_sat_i64(single_resp_end, single_resp.cursor_len());

    var hash_alg = core::cursor_from(cert_id_seq.buf[..0]);
    if !tls::get_asn1_element(cert_id_seq, rfc::ASN1_TAG_SEQUENCE, hash_alg) { return false; }
    let hash_alg_end = core::sub_sat_i64(cert_id_end, cert_id_seq.cursor_len());
    var hash_oid = core::cursor_from(hash_alg.buf[..0]);
    guard tls::get_asn1_element(hash_alg, rfc::ASN1_TAG_OID, hash_oid) && hash_oid.buf.len > 0 else {
        return false;
    }
    out.hash_alg_oid = tls::span_from_end(hash_alg_end, hash_alg.cursor_len(), hash_oid.buf.len);
    if hash_alg.cursor_len() > 0 {
        var null_el = core::cursor_from(hash_alg.buf[..0]);
        guard tls::get_asn1_element(hash_alg, rfc::ASN1_TAG_NULL, null_el) &&
            null_el.cursor_len() == 0 && hash_alg.cursor_len() == 0 else {
            return false;
        }
    }

    var name_hash = core::cursor_from(cert_id_seq.buf[..0]);
    if !tls::get_asn1_element(cert_id_seq, rfc::ASN1_TAG_OCTET_STRING, name_hash) { return false; }
    out.issuer_name_hash = tls::span_from_end(cert_id_end, cert_id_seq.cursor_len(), name_hash.buf.len);

    var key_hash = core::cursor_from(cert_id_seq.buf[..0]);
    if !tls::get_asn1_element(cert_id_seq, rfc::ASN1_TAG_OCTET_STRING, key_hash) { return false; }
    out.issuer_key_hash = tls::span_from_end(cert_id_end, cert_id_seq.cursor_len(), key_hash.buf.len);

    var serial = core::cursor_from(cert_id_seq.buf[..0]);
    if !tls::get_asn1_element(cert_id_seq, rfc::ASN1_TAG_INTEGER, serial) { return false; }
    guard tls::validate_asn1_integer(serial.buf, true) && cert_id_seq.cursor_len() == 0 else { return false; }
    out.serial_number = tls::span_from_end(cert_id_end, cert_id_seq.cursor_len(), serial.buf.len);
    return true;
}

fn x509_parse_ocsp_revoked_info(rev_elem: core::ByteCursor&) -> bool {
    var rev_time = core::cursor_from(rev_elem.buf[..0]);
    guard tls::get_asn1_element(rev_elem, rfc::ASN1_TAG_GENERALIZED_TIME, rev_time) else { return false; }
    let _, ok_rt = tls::parse_generalized_time(rev_time.buf);
    guard ok_rt else { return false; }
    if rev_elem.cursor_len() > 0 {
        var reason_ctx = core::cursor_from(rev_elem.buf[..0]);
        var reason_enum = core::cursor_from(rev_elem.buf[..0]);
        guard tls::get_asn1_element(rev_elem, 0xA0, reason_ctx) &&
            tls::get_asn1_element(reason_ctx, rfc::ASN1_TAG_ENUMERATED, reason_enum) &&
            reason_enum.buf.len == 1 &&
            reason_ctx.cursor_len() == 0 else {
            return false;
        }
    }
    return rev_elem.cursor_len() == 0;
}

fn x509_parse_ocsp_cert_status(single_resp: core::ByteCursor&, out_status: tls::OcspCertStatus&) -> bool {
    var cert_status_tag: u8 = 0;
    var cert_status_elem = core::cursor_from(single_resp.buf[..0]);
    if !tls::get_any_asn1_element(single_resp, cert_status_tag, cert_status_elem) { return false; }
    // RFC 6960 Section 4.2.1: Exact DER tags: [0] IMPLICIT NULL (0x80), [1] IMPLICIT RevokedInfo (0xA1), [2] IMPLICIT NULL (0x82).
    if cert_status_tag == 0x80 {
        guard cert_status_elem.cursor_len() == 0 else { return false; }
        out_status = tls::OcspCertStatus.Good;
        return true;
    }
    if cert_status_tag == 0xA1 {
        guard x509_parse_ocsp_revoked_info(cert_status_elem) else { return false; }
        out_status = tls::OcspCertStatus.Revoked;
        return true;
    }
    if cert_status_tag == 0x82 {
        guard cert_status_elem.cursor_len() == 0 else { return false; }
        out_status = tls::OcspCertStatus.Unknown;
        return true;
    }
    return false;
}

fn x509_check_ocsp_ext_list(parent: core::ByteCursor&, ctx_tag: u8) -> bool {
    guard parent.cursor_len() > 0 && parent.buf[0] == ctx_tag else {
        return parent.cursor_len() == 0;
    }
    var ext_ctx = core::cursor_from(parent.buf[..0]);
    var ext_seq = core::cursor_from(parent.buf[..0]);
    guard tls::get_asn1_element(parent, ctx_tag, ext_ctx) && parent.cursor_len() == 0 else { return false; }
    guard tls::get_asn1_element(ext_ctx, rfc::ASN1_TAG_SEQUENCE, ext_seq) &&
        ext_ctx.cursor_len() == 0 && ext_seq.cursor_len() > 0 else {
        return false;
    }
    while ext_seq.cursor_len() > 0 {
        var single_ext = core::cursor_from(ext_seq.buf[..0]);
        guard tls::get_asn1_element(ext_seq, rfc::ASN1_TAG_SEQUENCE, single_ext) else { return false; }
        var oid = core::cursor_from(single_ext.buf[..0]);
        guard tls::get_asn1_element(single_ext, rfc::ASN1_TAG_OID, oid) else { return false; }
        var crit_ok = true;
        let is_crit = x509_check_ext_critical(single_ext, crit_ok);
        guard crit_ok && !is_crit else { return false; }
        var ext_val = core::cursor_from(single_ext.buf[..0]);
        guard tls::get_asn1_element(single_ext, rfc::ASN1_TAG_OCTET_STRING, ext_val) &&
            single_ext.cursor_len() == 0 else {
            return false;
        }
    }
    return true;
}

fn x509_parse_ocsp_next_update(single_resp: core::ByteCursor&, out: tls::ParsedOcspResponse&) -> bool {
    if single_resp.cursor_len() > 0 && single_resp.buf[0] == 0xA0 {
        var next_up_ctx = core::cursor_from(single_resp.buf[..0]);
        guard tls::get_asn1_element(single_resp, 0xA0, next_up_ctx) else { return false; }
        var next_up_elem = core::cursor_from(next_up_ctx.buf[..0]);
        guard tls::get_asn1_element(next_up_ctx, rfc::ASN1_TAG_GENERALIZED_TIME, next_up_elem) &&
            next_up_ctx.cursor_len() == 0 else { return false; }
        let next_time, ok_next = tls::parse_generalized_time(next_up_elem.buf);
        guard ok_next else { return false; }
        out.next_update = next_time;
        out.has_next_update = true;
    }
    return x509_check_ocsp_ext_list(single_resp, 0xA1);
}

fn x509_parse_ocsp_single_response(
    responses_seq: core::ByteCursor&,
    responses_end: i64,
    out:           tls::ParsedOcspResponse&,
) -> bool {
    guard responses_seq.cursor_len() > 0 else { return false; }
    var single_resp = core::cursor_from(responses_seq.buf[..0]);
    if !tls::get_asn1_element(responses_seq, rfc::ASN1_TAG_SEQUENCE, single_resp) { return false; }
    let single_resp_end = core::sub_sat_i64(responses_end, responses_seq.cursor_len());

    guard x509_parse_ocsp_cert_id(single_resp, single_resp_end, out) else { return false; }
    guard x509_parse_ocsp_cert_status(single_resp, out.cert_status) else { return false; }

    var this_up_elem = core::cursor_from(single_resp.buf[..0]);
    if !tls::get_asn1_element(single_resp, rfc::ASN1_TAG_GENERALIZED_TIME, this_up_elem) { return false; }
    let this_time, ok_this = tls::parse_generalized_time(this_up_elem.buf);
    guard ok_this else { return false; }
    out.this_update = this_time;

    return x509_parse_ocsp_next_update(single_resp, out);
}

inline fn ocsp_record_seen_serial(seen: (const u8[:])[..32]&, serial: const u8[:]) -> bool {
    for prev in seen {
        if prev == serial { return false; }
    }
    return seen.try_push(serial);
}

fn x509_parse_ocsp_responses_list(
    responses_seq: core::ByteCursor&,
    responses_end: i64,
    raw_ocsp:      const u8[:],
    target_serial: const u8[:],
    out:           tls::ParsedOcspResponse&,
) -> bool {
    guard responses_seq.cursor_len() > 0 else { return false; }
    var seen_serials: (const u8[:])[..32] = [];
    var selected = false;
    while responses_seq.cursor_len() > 0 {
        var cand = tls::ParsedOcspResponse {
            status:           out.status,
            responder_id_tag: out.responder_id_tag,
            responder_id:     out.responder_id,
            tbs_raw:          out.tbs_raw,
        };
        guard x509_parse_ocsp_single_response(responses_seq, responses_end, cand) else { return false; }
        let cand_serial = tls::span_slice(raw_ocsp, cand.serial_number);
        guard ocsp_record_seen_serial(seen_serials, cand_serial) else { return false; }
        let matches = if target_serial.len > 0 { cand_serial == target_serial } else { !selected };
        if matches {
            guard !selected else { return false; }
            out = cand;
            selected = true;
        }
    }
    return selected;
}

fn x509_parse_ocsp_version_and_id(
    tbs_resp_data: core::ByteCursor&,
    tbs_data_end:  i64,
    out:           tls::ParsedOcspResponse&,
) -> bool {
    if tbs_resp_data.cursor_len() > 0 && tbs_resp_data.buf[0] == 0xA0 {
        var ver_elem = core::cursor_from(tbs_resp_data.buf[..0]);
        var ver_int: i64 = -1;
        guard tls::get_asn1_element(tbs_resp_data, 0xA0, ver_elem) &&
            tls::get_asn1_integer(ver_elem, ver_int) &&
            ver_int == 0 &&
            ver_elem.cursor_len() == 0 else {
            return false;
        }
    }
    var resp_id_tag: u8 = 0;
    var resp_id = core::cursor_from(tbs_resp_data.buf[..0]);
    guard tls::get_any_asn1_element(tbs_resp_data, resp_id_tag, resp_id) && resp_id.buf.len > 0 else {
        return false;
    }
    let resp_id_end = core::sub_sat_i64(tbs_data_end, tbs_resp_data.cursor_len());
    if resp_id_tag == 0xA1 {
        out.responder_id_tag = 0xA1;
        out.responder_id = tls::span_from_end(tbs_data_end, tbs_resp_data.cursor_len(), resp_id.buf.len);
        return true;
    }
    if resp_id_tag == 0xA2 {
        var key_hash = core::cursor_from(resp_id.buf[..0]);
        guard tls::get_asn1_element(resp_id, rfc::ASN1_TAG_OCTET_STRING, key_hash) &&
            key_hash.buf.len == 20 &&
            resp_id.cursor_len() == 0 else {
            return false;
        }
        out.responder_id_tag = 0xA2;
        out.responder_id = tls::span_from_end(resp_id_end, resp_id.cursor_len(), key_hash.buf.len);
        return true;
    }
    return false;
}

fn x509_ocsp_read_optional_certs(
    basic_seq: core::ByteCursor&,
    basic_end: i64,
    out:       tls::ParsedOcspResponse&,
) -> bool {
    guard basic_seq.cursor_len() > 0 else { return true; }
    guard basic_seq.buf[0] == 0xA0 else { return false; }
    var certs_ctx = core::cursor_from(basic_seq.buf[..0]);
    guard tls::get_asn1_element(basic_seq, 0xA0, certs_ctx) && basic_seq.cursor_len() == 0 else {
        return false;
    }
    let certs_ctx_end = core::sub_sat_i64(basic_end, basic_seq.cursor_len());
    var certs_seq = core::cursor_from(certs_ctx.buf[..0]);
    guard tls::get_asn1_element(certs_ctx, rfc::ASN1_TAG_SEQUENCE, certs_seq) &&
        certs_ctx.cursor_len() == 0 &&
        certs_seq.cursor_len() > 0 else {
        return false;
    }
    let certs_seq_end = core::sub_sat_i64(certs_ctx_end, certs_ctx.cursor_len());
    var is_first = true;
    while certs_seq.cursor_len() > 0 {
        let cert_tlv_start = certs_seq.buf;
        var cert_body = core::cursor_from(certs_seq.buf[..0]);
        guard tls::get_asn1_element(certs_seq, rfc::ASN1_TAG_SEQUENCE, cert_body) else { return false; }
        if is_first {
            let cert_tlv_len = core::sub_sat_i64(cert_tlv_start.len, certs_seq.buf.len);
            out.responder_cert_der = tls::span_from_end(certs_seq_end, certs_seq.cursor_len(), cert_tlv_len);
            is_first = false;
        }
    }
    return true;
}

fn x509_ocsp_read_basic_sig(
    basic_seq: core::ByteCursor&,
    basic_end: i64,
    out:       tls::ParsedOcspResponse&,
) -> bool {
    guard basic_seq.cursor_len() > 0 else { return false; }
    var sig_alg_seq = core::cursor_from(basic_seq.buf[..0]);
    guard tls::get_asn1_element(basic_seq, rfc::ASN1_TAG_SEQUENCE, sig_alg_seq) else { return false; }
    let sig_alg_end = core::sub_sat_i64(basic_end, basic_seq.cursor_len());
    var sig_oid = core::cursor_from(sig_alg_seq.buf[..0]);
    guard tls::get_asn1_element(sig_alg_seq, rfc::ASN1_TAG_OID, sig_oid) && sig_oid.buf.len > 0 else {
        return false;
    }
    let sig_oid_span = tls::span_from_end(sig_alg_end, sig_alg_seq.cursor_len(), sig_oid.buf.len);
    guard validate_x509_sig_alg_params(sig_oid.buf, sig_alg_seq, out.pss_hash_id) else {
        return false;
    }
    out.sig_alg_oid = sig_oid_span;

    guard basic_seq.cursor_len() > 0 else { return false; }
    var sig_bits = core::cursor_from(basic_seq.buf[..0]);
    var unused_bits: u8 = 0;
    guard tls::get_asn1_bit_string(basic_seq, sig_bits, unused_bits) &&
        unused_bits == 0 && sig_bits.buf.len > 0 else { return false; }
    out.signature = tls::span_from_end(basic_end, basic_seq.cursor_len(), sig_bits.buf.len);

    // RFC 6960 Section 4.2.1: BasicOCSPResponse - Optional `certs [0] EXPLICIT SEQUENCE OF Certificate`.
    return x509_ocsp_read_optional_certs(basic_seq, basic_end, out);
}

fn x509_parse_ocsp_basic_response(
    resp_bytes_seq: core::ByteCursor&,
    resp_bytes_end: i64,
    raw_ocsp:       const u8[:],
    target_serial:  const u8[:],
    out:            tls::ParsedOcspResponse&,
) -> bool {
    var resp_type_oid = core::cursor_from(resp_bytes_seq.buf[..0]);
    if !tls::get_asn1_element(resp_bytes_seq, rfc::ASN1_TAG_OID, resp_type_oid) { return false; }
    guard resp_type_oid.buf == rfc::OID_OCSP_BASIC[..] else { return false; }

    var resp_oct = core::cursor_from(resp_bytes_seq.buf[..0]);
    if !tls::get_asn1_element(resp_bytes_seq, rfc::ASN1_TAG_OCTET_STRING, resp_oct) { return false; }
    guard resp_bytes_seq.cursor_len() == 0 else { return false; }
    let resp_oct_end = core::sub_sat_i64(resp_bytes_end, resp_bytes_seq.cursor_len());

    var basic_seq = core::cursor_from(resp_oct.buf[..0]);
    if !tls::get_asn1_element(resp_oct, rfc::ASN1_TAG_SEQUENCE, basic_seq) { return false; }
    guard resp_oct.cursor_len() == 0 else { return false; }
    let basic_end = core::sub_sat_i64(resp_oct_end, resp_oct.cursor_len());

    let tbs_raw_start = basic_seq.buf;
    var tbs_resp_data = core::cursor_from(basic_seq.buf[..0]);
    if !tls::get_asn1_element(basic_seq, rfc::ASN1_TAG_SEQUENCE, tbs_resp_data) { return false; }
    let tbs_tlv_len = core::sub_sat_i64(tbs_raw_start.len, basic_seq.buf.len);
    let tbs_data_end = core::sub_sat_i64(basic_end, basic_seq.cursor_len());
    out.tbs_raw = tls::span_from_end(basic_end, basic_seq.cursor_len(), tbs_tlv_len);

    guard x509_parse_ocsp_version_and_id(tbs_resp_data, tbs_data_end, out) else { return false; }

    var prod_time = core::cursor_from(tbs_resp_data.buf[..0]);
    if !tls::get_asn1_element(tbs_resp_data, rfc::ASN1_TAG_GENERALIZED_TIME, prod_time) { return false; }
    let _, ok_prod = tls::parse_generalized_time(prod_time.buf);
    guard ok_prod else { return false; }

    var responses_seq = core::cursor_from(tbs_resp_data.buf[..0]);
    if !tls::get_asn1_element(tbs_resp_data, rfc::ASN1_TAG_SEQUENCE, responses_seq) { return false; }
    let responses_end = core::sub_sat_i64(tbs_data_end, tbs_resp_data.cursor_len());

    guard x509_parse_ocsp_responses_list(responses_seq, responses_end, raw_ocsp, target_serial, out) else {
        return false;
    }
    guard x509_check_ocsp_ext_list(tbs_resp_data, 0xA1) else { return false; }

    return x509_ocsp_read_basic_sig(basic_seq, basic_end, out);
}

// Parses a DER-encoded OCSPResponse and selects the SingleResponse matching `target_serial` (RFC 6960 Section 4.2.1).
//
// Example:
//   raw_ocsp = 0x30 ... (DER encoded OCSPResponse), target_serial = "\x42"
//   returns: ok = true, out filled with matching cert status
fn parse_ocsp_response_for_serial(
    raw_ocsp:      const u8[:],
    target_serial: const u8[:],
    out:           tls::ParsedOcspResponse&,
) -> bool {
    out = tls::ParsedOcspResponse {};
    var committed = false;
    defer if !committed { out = tls::ParsedOcspResponse {}; };
    guard raw_ocsp.len > 0 && raw_ocsp.len <= 65535 else { return false; }

    var c = core::cursor_from(raw_ocsp);
    var ocsp_seq = core::cursor_from(raw_ocsp[..0]);
    if !tls::get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, ocsp_seq) { return false; }
    guard c.cursor_len() == 0 else { return false; }
    let ocsp_seq_end = raw_ocsp.len;

    var status_oct = core::cursor_from(ocsp_seq.buf[..0]);
    if !tls::get_asn1_element(ocsp_seq, rfc::ASN1_TAG_ENUMERATED, status_oct) { return false; }
    guard status_oct.buf.len == 1 else { return false; }

    guard x509_parse_ocsp_status(status_oct.buf[0], out.status) else { return false; }
    if out.status != tls::OcspResponseStatus.Successful {
        guard ocsp_seq.cursor_len() == 0 else { return false; }
        committed = true;
        return true;
    }

    guard ocsp_seq.cursor_len() > 0 else { return false; }
    var resp_bytes_ctx = core::cursor_from(ocsp_seq.buf[..0]);
    if !tls::get_asn1_element(ocsp_seq, 0xA0, resp_bytes_ctx) { return false; }
    guard ocsp_seq.cursor_len() == 0 else { return false; }
    let resp_bytes_ctx_end = core::sub_sat_i64(ocsp_seq_end, ocsp_seq.cursor_len());

    var resp_bytes_seq = core::cursor_from(resp_bytes_ctx.buf[..0]);
    if !tls::get_asn1_element(resp_bytes_ctx, rfc::ASN1_TAG_SEQUENCE, resp_bytes_seq) { return false; }
    guard resp_bytes_ctx.cursor_len() == 0 else { return false; }
    let resp_bytes_end = core::sub_sat_i64(resp_bytes_ctx_end, resp_bytes_ctx.cursor_len());

    guard x509_parse_ocsp_basic_response(
        resp_bytes_seq, resp_bytes_end, raw_ocsp, target_serial, out,
    ) else { return false; }
    committed = true;
    return true;
}

fn x509_validate_ocsp_temporal(resp: const tls::ParsedOcspResponse&, now_unix: i64) -> tls::Alert {
    if resp.has_next_update && resp.this_update > resp.next_update {
        return tls::Alert.BadCertificateStatusResponse;
    }
    if now_unix < resp.this_update {
        return tls::Alert.CertificateExpired;
    }
    if resp.has_next_update {
        if now_unix > resp.next_update {
            return tls::Alert.CertificateExpired;
        }
        return tls::Alert.CloseNotify;
    }
    // RFC 6960 Section 4.2.2.1: When nextUpdate is omitted, enforce finite maximum response age.
    if core::sub_sat_i64(now_unix, resp.this_update) > MAX_REVOCATION_AGE_SECS {
        return tls::Alert.CertificateExpired;
    }
    return tls::Alert.CloseNotify;
}

// RFC 6960 Section 4.1.1: ASN.1 Specification of the OCSP Request - Validates CertID hashAlgorithm OID and hash lengths.
inline fn x509_validate_ocsp_cert_id_alg(resp: const tls::ParsedOcspResponse&, raw_ocsp: const u8[:]) -> bool {
    let alg_oid = tls::span_slice(raw_ocsp, resp.hash_alg_oid);
    let ocsp_nh = tls::span_slice(raw_ocsp, resp.issuer_name_hash);
    let ocsp_kh = tls::span_slice(raw_ocsp, resp.issuer_key_hash);
    if alg_oid == OID_OCSP_SHA256[..] {
        return ocsp_nh.len == 32 && ocsp_kh.len == 32;
    }
    if alg_oid == OID_OCSP_SHA1[..] {
        return ocsp_nh.len == 20 && ocsp_kh.len == 20;
    }
    return false;
}

// Wraps inner X.509 `Name` RDNSequence bytes in their canonical DER `SEQUENCE` TLV (`0x30 <len> || body`)
// as required for RFC 6960 Section 4.1.1 `issuerNameHash` computation.
fn encode_der_name_tlv(dn_inner: const u8[:], out: u8[..1024]&) -> bool {
    out.clear();
    guard dn_inner.len > 0 && dn_inner.len <= 1020 else { return false; }
    guard out.try_push(rfc::ASN1_TAG_SEQUENCE) else { return false; }
    if dn_inner.len < 128 {
        guard out.try_push(dn_inner.len as u8) else { return false; }
    } else if dn_inner.len < 256 {
        guard out.try_push(0x81) && out.try_push(dn_inner.len as u8) else { return false; }
    } else {
        guard out.try_push(0x82) &&
            out.try_push(((dn_inner.len >> 8) & 0xFF) as u8) &&
            out.try_push((dn_inner.len & 0xFF) as u8) else {
            return false;
        }
    }
    return out.try_append(dn_inner);
}

inline fn x509_verify_ocsp_issuer_name_hash(
    alg_oid:   const u8[:],
    ocsp_nh:   const u8[:],
    issuer_dn: const u8[:],
) -> bool {
    var dn_tlv: u8[..1024] = [];
    guard encode_der_name_tlv(issuer_dn, dn_tlv) else { return false; }
    if alg_oid == OID_OCSP_SHA256[..] && ocsp_nh.len == 32 {
        let h = core::sha256(dn_tlv[..]);
        return core::ct_eq_bytes(ocsp_nh, h[..]);
    }
    if alg_oid == OID_OCSP_SHA1[..] && ocsp_nh.len == 20 {
        let h = core::sha1(dn_tlv[..]);
        return core::ct_eq_bytes(ocsp_nh, h[..]);
    }
    return false;
}

// RFC 6960 Section 4.1.1: ASN.1 Specification of the OCSP Request - Verifies hashAlgorithm, issuerNameHash, and issuerKeyHash.
fn x509_verify_ocsp_cert_id_material(
    resp:              const tls::ParsedOcspResponse&,
    raw_ocsp:          const u8[:],
    issuer_subject_dn: const u8[:],
    issuer_pubkey_val: const u8[:],
) -> bool {
    guard issuer_subject_dn.len > 0 && issuer_pubkey_val.len > 0 else { return false; }
    var dn_tlv: u8[..1024] = [];
    guard encode_der_name_tlv(issuer_subject_dn, dn_tlv) else { return false; }
    let alg_oid = tls::span_slice(raw_ocsp, resp.hash_alg_oid);
    let ocsp_nh = tls::span_slice(raw_ocsp, resp.issuer_name_hash);
    let ocsp_kh = tls::span_slice(raw_ocsp, resp.issuer_key_hash);
    if alg_oid == OID_OCSP_SHA256[..] {
        guard ocsp_nh.len == 32 && ocsp_kh.len == 32 else { return false; }
        let nh = core::sha256(dn_tlv[..]);
        let kh = core::sha256(issuer_pubkey_val);
        return core::ct_eq_bytes(ocsp_nh, nh[..]) && core::ct_eq_bytes(ocsp_kh, kh[..]);
    }
    if alg_oid == OID_OCSP_SHA1[..] {
        guard ocsp_nh.len == 20 && ocsp_kh.len == 20 else { return false; }
        let nh = core::sha1(dn_tlv[..]);
        let kh = core::sha1(issuer_pubkey_val);
        return core::ct_eq_bytes(ocsp_nh, nh[..]) && core::ct_eq_bytes(ocsp_kh, kh[..]);
    }
    return false;
}

fn x509_verify_ocsp_cert_id_with_issuer(
    resp:           const tls::ParsedOcspResponse&,
    raw_ocsp:       const u8[:],
    leaf_cert:      const tls::ParsedCert&,
    leaf_raw:       const u8[:],
    issuer_cert:    const tls::ParsedCert&,
    issuer_raw_der: const u8[:],
) -> bool {
    let issuer_subject = tls::span_slice(issuer_raw_der, issuer_cert.subject_raw);
    if leaf_cert.issuer_raw.length > 0 {
        guard issuer_subject == tls::span_slice(leaf_raw, leaf_cert.issuer_raw) else { return false; }
    }
    let pk_bits = tls::span_slice(issuer_raw_der, issuer_cert.spki_pubkey);
    guard pk_bits.len >= 2 && pk_bits[0] == 0 else { return false; }
    return x509_verify_ocsp_cert_id_material(resp, raw_ocsp, issuer_subject, pk_bits[1..]);
}

fn x509_verify_ocsp_signature_with_pubkey(
    resp:          const tls::ParsedOcspResponse&,
    raw_ocsp:      const u8[:],
    parent_pubkey: const u8[:],
) -> tls::Alert {
    guard resp.signature.length > 0 && resp.tbs_raw.length > 0 && parent_pubkey.len > 0 else {
        return tls::Alert.BadCertificateStatusResponse;
    }
    let sig_oid = tls::span_slice(raw_ocsp, resp.sig_alg_oid);
    let tbs_data = tls::span_slice(raw_ocsp, resp.tbs_raw);
    let sig_bytes = tls::span_slice(raw_ocsp, resp.signature);
    return x509_verify_signature_by_oid(
        sig_oid, tbs_data, sig_bytes, parent_pubkey, tls::Alert.BadCertificateStatusResponse, resp.pss_hash_id,
    );
}

// Checks RFC 6960 Section 4.2.2.2 ResponderID binding (`byName` or `byKey`) against `responder_cert`.
fn ocsp_responder_id_matches_cert(
    resp:           const tls::ParsedOcspResponse&,
    raw_ocsp:       const u8[:],
    responder_cert: const tls::ParsedCert&,
    responder_der:  const u8[:],
) -> bool {
    let rid = tls::span_slice(raw_ocsp, resp.responder_id);
    guard rid.len > 0 else { return false; }
    if resp.responder_id_tag == 0xA1 {
        let resp_subj = tls::span_slice(responder_der, responder_cert.subject_raw);
        guard resp_subj.len > 0 else { return false; }
        var c = core::cursor_from(rid);
        var name_seq = core::cursor_from(rid[..0]);
        if tls::get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, name_seq) && c.cursor_len() == 0 {
            return name_seq.buf == resp_subj;
        }
        return rid == resp_subj;
    }
    if resp.responder_id_tag == 0xA2 {
        guard rid.len == 20 else { return false; }
        let pk_bits = tls::span_slice(responder_der, responder_cert.spki_pubkey);
        guard pk_bits.len >= 2 && pk_bits[0] == 0 else { return false; }
        let kh = core::sha1(pk_bits[1..]);
        return core::ct_eq_bytes(rid, kh[..]);
    }
    return false;
}

// RFC 6960 Section 4.2.2.2: Authorized Responders - Verifies an embedded delegated OCSP responder cert
// issued by `(ca_subject_dn, ca_pubkey)` with `id-kp-OCSPSigning` EKU and ResponderID binding.
fn verify_delegated_ocsp_responder_with_material(
    resp:          const tls::ParsedOcspResponse&,
    raw_ocsp:      const u8[:],
    ca_subject_dn: const u8[:],
    ca_pubkey:     const u8[:],
    now_unix:      i64,
) -> tls::Alert {
    let responder_der = tls::span_slice(raw_ocsp, resp.responder_cert_der);
    guard responder_der.len > 0 else { return tls::Alert.BadCertificateStatusResponse; }

    var responder_cert = tls::ParsedCert { .. };
    guard tls::parse_x509_certificate(responder_der, responder_cert) else {
        return tls::Alert.BadCertificateStatusResponse;
    }
    guard !responder_cert.has_unsupported_critical &&
        !responder_cert.has_malformed_policy_constraints &&
        !responder_cert.is_ca &&
        x509_check_cert_spki_policy(responder_cert, responder_der) else {
        return tls::Alert.BadCertificateStatusResponse;
    }
    guard !responder_cert.has_key_usage ||
        (responder_cert.key_usage & rfc::KEY_USAGE_DIGITAL_SIGNATURE) != 0 else {
        return tls::Alert.BadCertificateStatusResponse;
    }
    guard now_unix >= responder_cert.validity_not_before &&
        now_unix <= responder_cert.validity_not_after else {
        return tls::Alert.BadCertificateStatusResponse;
    }
    guard responder_cert.has_eku && (responder_cert.eku_mask & rfc::EKU_OCSP_SIGNING) != 0 else {
        return tls::Alert.BadCertificateStatusResponse;
    }
    guard ocsp_responder_id_matches_cert(resp, raw_ocsp, responder_cert, responder_der) else {
        return tls::Alert.BadCertificateStatusResponse;
    }
    let resp_issuer_dn = tls::span_slice(responder_der, responder_cert.issuer_raw);
    guard resp_issuer_dn.len > 0 && resp_issuer_dn == ca_subject_dn else {
        return tls::Alert.BadCertificateStatusResponse;
    }
    let sig_oid = tls::span_slice(responder_der, responder_cert.sig_alg_oid);
    let tbs_data = tls::span_slice(responder_der, responder_cert.tbs_cert);
    let sig_bytes = tls::span_slice(responder_der, responder_cert.signature_value);
    let chain_alert = x509_verify_signature_by_oid(
        sig_oid, tbs_data, sig_bytes, ca_pubkey, tls::Alert.BadCertificate, responder_cert.pss_hash_id,
    );
    guard chain_alert == tls::Alert.CloseNotify else { return chain_alert; }
    return tls::x509_verify_ocsp_signature(resp, raw_ocsp, responder_cert, responder_der);
}

// RFC 6960 Section 4.2.2.2: Authorized Responders - Verifies an embedded delegated OCSP responder cert
// issued by `issuer_cert` with `id-kp-OCSPSigning` EKU and checks the BasicOCSPResponse signature.
fn verify_delegated_ocsp_responder(
    resp:        const tls::ParsedOcspResponse&,
    raw_ocsp:    const u8[:],
    issuer_cert: const tls::ParsedCert&,
    issuer_raw:  const u8[:],
    now_unix:    i64,
) -> tls::Alert {
    let ca_subject_dn = tls::span_slice(issuer_raw, issuer_cert.subject_raw);
    var ca_pubkey = tls::span_slice(issuer_raw, issuer_cert.spki_pubkey);
    if ca_pubkey.len >= 2 && ca_pubkey[0] == 0 {
        ca_pubkey = ca_pubkey[1..];
    }
    return verify_delegated_ocsp_responder_with_material(resp, raw_ocsp, ca_subject_dn, ca_pubkey, now_unix);
}
