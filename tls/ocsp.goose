// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 6066 §8 & RFC 6960 Online Certificate Status Protocol (OCSP) Stapling parser and validator.
namespace wing;

import std;
import core from "..";
import .record;
import .asn1;
import .x509;

enum OcspResponseStatus {
    Successful,
    MalformedRequest,
    InternalError,
    TryLater,
    SigRequired,
    Unauthorized,
    Unknown,
}

enum OcspCertStatus {
    Good,
    Revoked,
    Unknown,
}

struct ParsedOcspResponse {
    status:           OcspResponseStatus = OcspResponseStatus.Unknown,
    cert_status:      OcspCertStatus     = OcspCertStatus.Unknown,
    serial_number:    Span16             = Span16 { offset: 0, length: 0 },
    issuer_name_hash: Span16             = Span16 { offset: 0, length: 0 },
    issuer_key_hash:  Span16             = Span16 { offset: 0, length: 0 },
    hash_alg_oid:     Span16             = Span16 { offset: 0, length: 0 },
    tbs_raw:          Span16             = Span16 { offset: 0, length: 0 },
    sig_alg_oid:      Span16             = Span16 { offset: 0, length: 0 },
    signature:        Span16             = Span16 { offset: 0, length: 0 },
    this_update:      i64                = 0,
    next_update:      i64                = 0,
    has_next_update:  bool               = false,
}

inline fn x509_parse_ocsp_status(s_val: u8, out_status: OcspResponseStatus&) -> bool {
    if s_val == rfc::OCSP_STATUS_SUCCESSFUL {
        out_status = OcspResponseStatus.Successful;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_MALFORMED_REQ {
        out_status = OcspResponseStatus.MalformedRequest;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_INTERNAL_ERROR {
        out_status = OcspResponseStatus.InternalError;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_TRY_LATER {
        out_status = OcspResponseStatus.TryLater;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_SIG_REQUIRED {
        out_status = OcspResponseStatus.SigRequired;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_UNAUTHORIZED {
        out_status = OcspResponseStatus.Unauthorized;
        return true;
    }
    out_status = OcspResponseStatus.Unknown;
    return false;
}

fn x509_parse_ocsp_cert_id(
    single_resp: ByteCursor&,
    raw_ocsp:    const u8[:],
    out:         ParsedOcspResponse&,
) -> bool {
    var cert_id_seq = core::cursor_from(single_resp.buf[..0]);
    if !get_asn1_element(single_resp, rfc::ASN1_TAG_SEQUENCE, cert_id_seq) { return false; }

    var hash_alg = core::cursor_from(cert_id_seq.buf[..0]);
    if !get_asn1_element(cert_id_seq, rfc::ASN1_TAG_SEQUENCE, hash_alg) { return false; }
    if hash_alg.cursor_len() > 0 {
        var hash_oid = core::cursor_from(hash_alg.buf[..0]);
        if get_asn1_element(hash_alg, rfc::ASN1_TAG_OID, hash_oid) {
            out.hash_alg_oid = make_span(raw_ocsp, hash_oid.buf);
        }
    }

    var name_hash = core::cursor_from(cert_id_seq.buf[..0]);
    if !get_asn1_element(cert_id_seq, rfc::ASN1_TAG_OCTET_STRING, name_hash) { return false; }
    out.issuer_name_hash = make_span(raw_ocsp, name_hash.buf);

    var key_hash = core::cursor_from(cert_id_seq.buf[..0]);
    if !get_asn1_element(cert_id_seq, rfc::ASN1_TAG_OCTET_STRING, key_hash) { return false; }
    out.issuer_key_hash = make_span(raw_ocsp, key_hash.buf);

    var serial = core::cursor_from(cert_id_seq.buf[..0]);
    if !get_asn1_element(cert_id_seq, rfc::ASN1_TAG_INTEGER, serial) { return false; }
    if !validate_asn1_integer(serial.buf, true) { return false; }
    out.serial_number = make_span(raw_ocsp, serial.buf);
    return true;
}

fn x509_parse_ocsp_cert_status(single_resp: ByteCursor&, out_status: OcspCertStatus&) -> bool {
    var cert_status_tag: u8 = 0;
    var cert_status_elem = core::cursor_from(single_resp.buf[..0]);
    if !get_any_asn1_element(single_resp, cert_status_tag, cert_status_elem) { return false; }
    guard (cert_status_tag & 0xC0) == 0x80 else { return false; }
    let cs_num = cert_status_tag & 0x1F;
    if cs_num == 0 {
        out_status = OcspCertStatus.Good;
        return true;
    }
    if cs_num == 1 {
        out_status = OcspCertStatus.Revoked;
        return true;
    }
    if cs_num == 2 {
        out_status = OcspCertStatus.Unknown;
        return true;
    }
    return false;
}

fn x509_parse_ocsp_next_update(single_resp: ByteCursor&, out: ParsedOcspResponse&) -> bool {
    guard single_resp.cursor_len() > 0 && single_resp.buf[0] == 0xA0 else { return true; }
    var next_up_ctx = core::cursor_from(single_resp.buf[..0]);
    guard get_asn1_element(single_resp, 0xA0, next_up_ctx) else { return false; }
    var next_up_tag: u8 = 0;
    var next_up_elem = core::cursor_from(next_up_ctx.buf[..0]);
    guard get_any_asn1_element(next_up_ctx, next_up_tag, next_up_elem) else { return false; }
    let next_time, ok_next = parse_asn1_time(next_up_tag, next_up_elem.buf);
    guard ok_next else { return false; }
    out.next_update = next_time;
    out.has_next_update = true;
    return true;
}

fn x509_parse_ocsp_single_response(
    responses_seq: ByteCursor&,
    raw_ocsp:      const u8[:],
    out:           ParsedOcspResponse&,
) -> bool {
    guard responses_seq.cursor_len() > 0 else { return false; }
    var single_resp = core::cursor_from(responses_seq.buf[..0]);
    if !get_asn1_element(responses_seq, rfc::ASN1_TAG_SEQUENCE, single_resp) { return false; }

    guard x509_parse_ocsp_cert_id(single_resp, raw_ocsp, out) else { return false; }
    guard x509_parse_ocsp_cert_status(single_resp, out.cert_status) else { return false; }

    var this_up_tag: u8 = 0;
    var this_up_elem = core::cursor_from(single_resp.buf[..0]);
    if !get_any_asn1_element(single_resp, this_up_tag, this_up_elem) { return false; }
    let this_time, ok_this = parse_asn1_time(this_up_tag, this_up_elem.buf);
    guard ok_this else { return false; }
    out.this_update = this_time;

    return x509_parse_ocsp_next_update(single_resp, out);
}

fn x509_skip_ocsp_version_and_id(tbs_resp_data: ByteCursor&) -> bool {
    if tbs_resp_data.cursor_len() > 0 && tbs_resp_data.buf[0] == 0xA0 {
        var ver_elem = core::cursor_from(tbs_resp_data.buf[..0]);
        get_asn1_element(tbs_resp_data, 0xA0, ver_elem);
    }
    var resp_id_tag: u8 = 0;
    var resp_id = core::cursor_from(tbs_resp_data.buf[..0]);
    return get_any_asn1_element(tbs_resp_data, resp_id_tag, resp_id);
}

fn x509_ocsp_read_basic_sig(basic_seq: ByteCursor&, raw_ocsp: const u8[:], out: ParsedOcspResponse&) -> bool {
    guard basic_seq.cursor_len() > 0 else { return true; }
    var sig_alg_seq = core::cursor_from(basic_seq.buf[..0]);
    guard get_asn1_element(basic_seq, rfc::ASN1_TAG_SEQUENCE, sig_alg_seq) else { return false; }
    var sig_oid = core::cursor_from(sig_alg_seq.buf[..0]);
    guard get_asn1_element(sig_alg_seq, rfc::ASN1_TAG_OID, sig_oid) else { return false; }
    out.sig_alg_oid = make_span(raw_ocsp, sig_oid.buf);

    guard basic_seq.cursor_len() > 0 else { return false; }
    var sig_bits = core::cursor_from(basic_seq.buf[..0]);
    var unused_bits: u8 = 0;
    guard get_asn1_bit_string(basic_seq, sig_bits, unused_bits) &&
        unused_bits == 0 && sig_bits.buf.len > 0 else { return false; }
    out.signature = make_span(raw_ocsp, sig_bits.buf);
    return true;
}

fn x509_parse_ocsp_basic_response(
    resp_bytes_seq: ByteCursor&,
    raw_ocsp:       const u8[:],
    out:            ParsedOcspResponse&,
) -> bool {
    var resp_type_oid = core::cursor_from(resp_bytes_seq.buf[..0]);
    if !get_asn1_element(resp_bytes_seq, rfc::ASN1_TAG_OID, resp_type_oid) { return false; }
    guard resp_type_oid.buf == rfc::OID_OCSP_BASIC[..] else { return false; }

    var resp_oct = core::cursor_from(resp_bytes_seq.buf[..0]);
    if !get_asn1_element(resp_bytes_seq, rfc::ASN1_TAG_OCTET_STRING, resp_oct) { return false; }

    var basic_seq = core::cursor_from(resp_oct.buf[..0]);
    if !get_asn1_element(resp_oct, rfc::ASN1_TAG_SEQUENCE, basic_seq) { return false; }

    let tbs_raw_start = basic_seq.buf;
    var tbs_resp_data = core::cursor_from(basic_seq.buf[..0]);
    if !get_asn1_element(basic_seq, rfc::ASN1_TAG_SEQUENCE, tbs_resp_data) { return false; }
    let tbs_tlv_len = core::sub_sat_i64(tbs_raw_start.len, basic_seq.buf.len);
    out.tbs_raw = make_span(raw_ocsp, tbs_raw_start[..tbs_tlv_len]);

    guard x509_skip_ocsp_version_and_id(tbs_resp_data) else { return false; }

    var prod_time = core::cursor_from(tbs_resp_data.buf[..0]);
    if !get_asn1_element(tbs_resp_data, rfc::ASN1_TAG_GENERALIZED_TIME, prod_time) { return false; }

    var responses_seq = core::cursor_from(tbs_resp_data.buf[..0]);
    if !get_asn1_element(tbs_resp_data, rfc::ASN1_TAG_SEQUENCE, responses_seq) { return false; }

    guard x509_parse_ocsp_single_response(responses_seq, raw_ocsp, out) else { return false; }

    return x509_ocsp_read_basic_sig(basic_seq, raw_ocsp, out);
}

// Parses an OCSPResponse (RFC 6960 §4.2.1) with zero dynamic allocation.
// Example:
//   raw_ocsp = 0x30 ... (DER encoded OCSPResponse)
//   returns: ok = true, out filled with status and cert status
fn parse_ocsp_response(raw_ocsp: const u8[:], out: ParsedOcspResponse&) -> bool {
    var c = core::cursor_from(raw_ocsp);
    var ocsp_seq = core::cursor_from(raw_ocsp[..0]);
    if !get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, ocsp_seq) { return false; }
    guard c.cursor_len() == 0 else { return false; }

    var status_oct = core::cursor_from(ocsp_seq.buf[..0]);
    if !get_asn1_element(ocsp_seq, rfc::ASN1_TAG_ENUMERATED, status_oct) { return false; }
    guard status_oct.buf.len == 1 else { return false; }

    guard x509_parse_ocsp_status(status_oct.buf[0], out.status) else { return false; }
    if out.status != OcspResponseStatus.Successful {
        return true;
    }

    guard ocsp_seq.cursor_len() > 0 else { return false; }
    var resp_bytes_ctx = core::cursor_from(ocsp_seq.buf[..0]);
    if !get_asn1_element(ocsp_seq, 0xA0, resp_bytes_ctx) { return false; }

    var resp_bytes_seq = core::cursor_from(resp_bytes_ctx.buf[..0]);
    if !get_asn1_element(resp_bytes_ctx, rfc::ASN1_TAG_SEQUENCE, resp_bytes_seq) { return false; }

    return x509_parse_ocsp_basic_response(resp_bytes_seq, raw_ocsp, out);
}

fn x509_validate_ocsp_temporal(resp: const ParsedOcspResponse&, now_unix: i64) -> TlsAlert {
    if resp.has_next_update && resp.this_update > resp.next_update {
        return TlsAlert.BadCertificateStatusResponse;
    }
    if now_unix < resp.this_update {
        return TlsAlert.CertificateExpired;
    }
    if resp.has_next_update && now_unix > resp.next_update {
        return TlsAlert.CertificateExpired;
    }
    return TlsAlert.CloseNotify;
}

inline fn x509_verify_ocsp_issuer_name_hash(
    ocsp_nh:   const u8[:],
    issuer_dn: const u8[:],
) -> bool {
    if ocsp_nh.len == 32 {
        let h = core::sha256(issuer_dn);
        return core::ct_eq_bytes(ocsp_nh, h[..]);
    }
    if ocsp_nh.len == 20 {
        let h = core::sha1(issuer_dn);
        return core::ct_eq_bytes(ocsp_nh, h[..]);
    }
    return false;
}

// Validates an OCSP stapled response against the leaf certificate (RFC 6066 §8, RFC 6960).
fn validate_ocsp_stapling(
    raw_ocsp:  const u8[:],
    leaf_cert: const ParsedCert&,
    leaf_raw:  const u8[:],
    now_unix:  i64,
) -> TlsAlert {
    var resp = ParsedOcspResponse {};
    guard parse_ocsp_response(raw_ocsp, resp) && resp.status == OcspResponseStatus.Successful else {
        return TlsAlert.BadCertificateStatusResponse;
    }
    if resp.cert_status == OcspCertStatus.Revoked {
        return TlsAlert.BadCertificate;
    }
    guard resp.cert_status == OcspCertStatus.Good else {
        return TlsAlert.BadCertificateStatusResponse;
    }

    let ocsp_serial = span_slice(raw_ocsp, resp.serial_number);
    let leaf_serial = span_slice(leaf_raw, leaf_cert.serial_number);
    guard ocsp_serial.len > 0 && ocsp_serial == leaf_serial else {
        return TlsAlert.BadCertificateStatusResponse;
    }

    if leaf_cert.issuer_raw.length > 0 {
        guard resp.issuer_name_hash.length > 0 else {
            return TlsAlert.BadCertificateStatusResponse;
        }
        let ocsp_nh = span_slice(raw_ocsp, resp.issuer_name_hash);
        let issuer_dn = span_slice(leaf_raw, leaf_cert.issuer_raw);
        guard x509_verify_ocsp_issuer_name_hash(ocsp_nh, issuer_dn) else {
            return TlsAlert.BadCertificateStatusResponse;
        }
    } else if resp.issuer_name_hash.length > 0 {
        let ocsp_nh = span_slice(raw_ocsp, resp.issuer_name_hash);
        guard ocsp_nh.len == 32 || ocsp_nh.len == 20 else {
            return TlsAlert.BadCertificateStatusResponse;
        }
    }

    return x509_validate_ocsp_temporal(resp, now_unix);
}

fn x509_verify_ocsp_signature(
    resp:        const ParsedOcspResponse&,
    raw_ocsp:    const u8[:],
    issuer_cert: const ParsedCert&,
    issuer_raw:  const u8[:],
) -> TlsAlert {
    guard resp.signature.length > 0 && resp.tbs_raw.length > 0 else {
        return TlsAlert.BadCertificateStatusResponse;
    }
    let sig_oid = span_slice(raw_ocsp, resp.sig_alg_oid);
    let tbs_data = span_slice(raw_ocsp, resp.tbs_raw);
    let sig_bytes = span_slice(raw_ocsp, resp.signature);
    var parent_pubkey = span_slice(issuer_raw, issuer_cert.spki_pubkey);

    if parent_pubkey.len >= 2 && parent_pubkey[0] == 0 {
        parent_pubkey = parent_pubkey[1..];
    }

    return x509_verify_signature_by_oid(
        sig_oid, tbs_data, sig_bytes, parent_pubkey, TlsAlert.BadCertificateStatusResponse,
    );
}

// Unwraps TLS 1.3 / TLS 1.2 status_request extension wire framing (opaque OCSPResponse<1..2^24-1>).
fn unwrap_tls_ocsp_response(ext_data: const u8[:]) -> const u8[:], bool {
    var c = core::cursor_from(ext_data);
    var resp_len: u32 = 0;
    if !c.get_u24(resp_len) { return "", false; }
    guard resp_len > 0 && resp_len == c.cursor_len() else { return "", false; }
    return c.buf, true;
}
