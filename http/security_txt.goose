// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9116: A File Format to Aid in Security Vulnerability Disclosure (security.txt).
// Zero-heap parser, validator, and formatter for /.well-known/security.txt.
namespace wing;

import std;
import core from "..";

// ---- canonical locations and media type ------------------------------------

// ---- error codes -----------------------------------------------------------

const SEC_TXT_OK:                    i32 = 0;
const SEC_TXT_ERR_MISSING_CONTACT:   i32 = 1;
const SEC_TXT_ERR_MISSING_EXPIRES:   i32 = 2;
const SEC_TXT_ERR_DUPLICATE_EXPIRES: i32 = 3;
const SEC_TXT_ERR_INVALID_EXPIRES:   i32 = 4;
const SEC_TXT_ERR_EXPIRED:           i32 = 5;
const SEC_TXT_ERR_INVALID_CANONICAL: i32 = 6;
const SEC_TXT_ERR_EMPTY_VALUE:       i32 = 7;

// ---- data structures -------------------------------------------------------

struct SecurityTxt {
    contact:             u8[..256][..8] = [],
    expires:             u8[..64]       = "",
    expires_unix:        i64            = 0,
    encryption:          u8[..256][..4] = [],
    canonical:           u8[..256][..4] = [],
    acknowledgments:     u8[..256][..4] = [],
    policy:              u8[..256][..4] = [],
    hiring:              u8[..256][..4] = [],
    preferred_languages: u8[..64]       = "",
    is_valid:            bool           = false,
    has_contact:         bool           = false,
    has_expires:         bool           = false,
    is_expired:          bool           = false,
    status:              i32            = 0,
}

// Constructs a zero-initialized SecurityTxt structure.
// Returns whether the request URI path matches the RFC 9116 security.txt location.
fn is_security_txt_path(path: const u8[:]) -> bool {
    return path == rfc::SECURITY_TXT_WELL_KNOWN_PATH || path == rfc::SECURITY_TXT_LEGACY_PATH;
}

// ---- line classification helper --------------------------------------------

fn is_security_txt_comment_or_pgp(trimmed: const u8[:]) -> bool {
    guard trimmed.len > 0 else { return true; }
    guard trimmed[0] != '#' else { return true; }
    guard !trimmed.starts_with("-----") else { return true; }
    guard !trimmed.starts_with("Hash:") else { return true; }
    return false;
}

// ---- line field parser helpers ---------------------------------------------

fn apply_security_txt_contact(val: const u8[:], sec: SecurityTxt&) -> bool {
    guard sec.contact.len < 8 && val.len <= 256 else { return true; }
    sec.contact.push(val);
    sec.has_contact = true;
    return true;
}

fn apply_security_txt_expires(val: const u8[:], now_epoch: i64, sec: SecurityTxt&) -> bool {
    guard !sec.has_expires else {
        sec.status = SEC_TXT_ERR_DUPLICATE_EXPIRES;
        return false;
    }
    let parsed_time, ok = core::parse_rfc3339(val);
    guard ok && sec.expires.try_set(val) else {
        sec.status = SEC_TXT_ERR_INVALID_EXPIRES;
        return false;
    }
    sec.expires_unix = parsed_time.unix();
    sec.has_expires = true;

    guard now_epoch <= 0 || sec.expires_unix >= now_epoch else {
        sec.is_expired = true;
        sec.status = SEC_TXT_ERR_EXPIRED;
        return false;
    }
    return true;
}

fn apply_security_txt_canonical(val: const u8[:], sec: SecurityTxt&) -> bool {
    guard val.starts_with_fold("https://") && val.len <= 256 else {
        sec.status = SEC_TXT_ERR_INVALID_CANONICAL;
        return false;
    }
    guard sec.canonical.len < 4 else { return true; }
    sec.canonical.push(val);
    return true;
}

fn apply_security_txt_metadata(name: const u8[:], val: const u8[:], sec: SecurityTxt&) -> bool {
    if name.eq_ascii_fold("encryption") {
        guard val.len <= 256 else { return false; }
        guard sec.encryption.len < 4 else { return true; }
        sec.encryption.push(val);
        return true;
    }
    if name.eq_ascii_fold("acknowledgments") || name.eq_ascii_fold("acknowledgements") {
        guard val.len <= 256 else { return false; }
        guard sec.acknowledgments.len < 4 else { return true; }
        sec.acknowledgments.push(val);
        return true;
    }
    if name.eq_ascii_fold("policy") {
        guard val.len <= 256 else { return false; }
        guard sec.policy.len < 4 else { return true; }
        sec.policy.push(val);
        return true;
    }
    if name.eq_ascii_fold("hiring") {
        guard val.len <= 256 else { return false; }
        guard sec.hiring.len < 4 else { return true; }
        sec.hiring.push(val);
        return true;
    }
    if name.eq_ascii_fold("preferred-languages") {
        return sec.preferred_languages.len == 0 && val.len > 0 && sec.preferred_languages.try_append(val);
    }
    return true;
}

fn apply_security_txt_field(
    name:      const u8[:],
    val:       const u8[:],
    now_epoch: i64,
    sec:       SecurityTxt&,
) -> bool {
    guard val.len > 0 else {
        sec.status = SEC_TXT_ERR_EMPTY_VALUE;
        return false;
    }

    if name.eq_ascii_fold("contact") {
        return apply_security_txt_contact(val, sec);
    }
    if name.eq_ascii_fold("expires") {
        return apply_security_txt_expires(val, now_epoch, sec);
    }
    if name.eq_ascii_fold("canonical") {
        return apply_security_txt_canonical(val, sec);
    }

    return apply_security_txt_metadata(name, val, sec);
}

fn validate_mandatory_security_fields(sec: SecurityTxt&) -> bool {
    guard sec.has_contact else {
        sec.status = SEC_TXT_ERR_MISSING_CONTACT;
        return false;
    }
    guard sec.has_expires else {
        sec.status = SEC_TXT_ERR_MISSING_EXPIRES;
        return false;
    }
    guard !sec.is_expired else {
        sec.status = SEC_TXT_ERR_EXPIRED;
        return false;
    }
    sec.is_valid = true;
    sec.status = SEC_TXT_OK;
    return true;
}

// Parses a single line from security.txt (RFC 9116 §2.1).
//
// Example:
//   line = "Contact: mailto:sec@example.com", now_epoch = 1700000000
//   returns: true (Contact field populated)
fn parse_security_txt_line(line: const u8[:], now_epoch: i64, sec: SecurityTxt&) -> bool {
    let trimmed = line.trim_ascii_space();
    guard !is_security_txt_comment_or_pgp(trimmed) else { return true; }

    let raw_name, raw_val, has_colon = trimmed.split_once_byte(':');
    guard has_colon else { return true; }

    let name = raw_name.trim_ascii_space();
    let val = raw_val.trim_ascii_space();

    return apply_security_txt_field(name, val, now_epoch, sec);
}

// ---- parser implementation -------------------------------------------------

// Parses and validates a security.txt buffer per RFC 9116.
//
// Example:
//   content = "Contact: mailto:sec@example.com\nExpires: 2027-01-01T00:00:00Z\n"
//   returns: sec with status=SEC_TXT_OK, is_valid=true
fn parse_security_txt(content: const u8[:], now_epoch: i64 = 0) -> SecurityTxt {
    var sec = SecurityTxt { .. };
    var tok = core::make_byte_tokenizer(content, '\n');

    loop {
        let line, ok = tok.token_next();
        guard ok else { break; }

        let line_ok = parse_security_txt_line(line, now_epoch, sec);
        guard line_ok else { return sec; }
    }

    validate_mandatory_security_fields(sec);
    return sec;
}

// ---- formatter implementation ----------------------------------------------

// Formats a valid SecurityTxt object into wire text format per RFC 9116.
fn format_security_txt<B>(sec: const SecurityTxt&, out: B&) {
    for c in sec.contact {
        out.append("Contact: ");
        out.append(c[..]);
        out.append("\r\n");
    }

    if sec.expires.len > 0 {
        out.append("Expires: ");
        out.append(sec.expires[..]);
        out.append("\r\n");
    }

    for enc in sec.encryption {
        out.append("Encryption: ");
        out.append(enc[..]);
        out.append("\r\n");
    }

    for can in sec.canonical {
        out.append("Canonical: ");
        out.append(can[..]);
        out.append("\r\n");
    }

    for ack in sec.acknowledgments {
        out.append("Acknowledgments: ");
        out.append(ack[..]);
        out.append("\r\n");
    }

    for pol in sec.policy {
        out.append("Policy: ");
        out.append(pol[..]);
        out.append("\r\n");
    }

    for hir in sec.hiring {
        out.append("Hiring: ");
        out.append(hir[..]);
        out.append("\r\n");
    }

    if sec.preferred_languages.len > 0 {
        out.append("Preferred-Languages: ");
        out.append(sec.preferred_languages[..]);
        out.append("\r\n");
    }
}
