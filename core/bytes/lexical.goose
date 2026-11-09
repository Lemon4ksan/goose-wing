// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-regex RFC lexical validators (UUID, ULID, Email, Slug, Luhn, character-class slices).
namespace core;

import std;
import core.bytes.case;
import core.bytes.split;
import core.bytes.search;
import core.bytes.format;
import core.math;
import core.url.idna;

// ---- uuid (rfc 9562) --------------------------------------------------------

// Canonical hyphenated UUID string length (`8-4-4-4-12`, RFC 9562 Section 4).
const UUID_STR_LEN: i64 = 36;

// RFC 9562 Section 5.9: Nil UUID version sentinel (`00000000-0000-0000-0000-000000000000`).
const UUID_VERSION_NIL: u8 = 0;

// RFC 9562 Section 5.10: Max UUID version sentinel (`ffffffff-ffff-ffff-ffff-ffffffffffff`).
const UUID_VERSION_MAX: u8 = 15;

// RFC 9562 Section 4.1: Variant field top-two-bit pattern `0b10` for RFC 9562 UUIDs.
const UUID_VARIANT_RFC9562: u8 = 2;

const UUID_HI_NIBBLE_OFFSET: const i64[16] = [
    0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34,
];

const UUID_LO_NIBBLE_OFFSET: const i64[16] = [
    1, 3, 5, 7, 10, 12, 15, 17, 20, 22, 25, 27, 29, 31, 33, 35,
];

const HEX_HI_NIBBLE_LUT: const u8[256] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const HEX_LO_NIBBLE_LUT: const u8[256] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// 128-bit binary UUID value in network byte order (RFC 9562 Section 4).
struct Uuid {
    bytes: u8[16] = [0; 16],
}

inline fn has_uuid_hyphens(raw: const u8[:]) -> bool {
    return raw[8] == '-' && raw[13] == '-' && raw[18] == '-' && raw[23] == '-';
}

// Parses and validates a 36-byte canonical hyphenated UUID (`8-4-4-4-12`) per RFC 9562.
// Accepts versions 1..8 with variant `0b10xx`, plus Nil (all `0x00`, version `0`)
// and Max (all `0xFF`, version `15`).
//
// Example:
//   raw = "018f3e9c-6d2a-7b10-9a3f-001122334455"
//   returns: Uuid { ... }, version = 7, ok = true
fn parse_uuid(raw: const u8[:]) -> Uuid, u8, bool {
    guard raw.len == UUID_STR_LEN && has_uuid_hyphens(raw) else {
        return Uuid { .. }, 0, false;
    }

    var out = Uuid { .. };
    var bit_or:  u8 = 0x00;
    var bit_and: u8 = 0xFF;
    for byte_idx in 16 {
        let hi_ch = raw[UUID_HI_NIBBLE_OFFSET[byte_idx]];
        let lo_ch = raw[UUID_LO_NIBBLE_OFFSET[byte_idx]];
        guard core::hex_digit_to_val(hi_ch) >= 0 && core::hex_digit_to_val(lo_ch) >= 0 else {
            return Uuid { .. }, 0, false;
        }
        let b = HEX_HI_NIBBLE_LUT[hi_ch] | HEX_LO_NIBBLE_LUT[lo_ch];
        out.bytes[byte_idx] = b;
        bit_or = bit_or | b;
        bit_and = bit_and & b;
    }

    if bit_or == 0x00 { return out, UUID_VERSION_NIL, true; }
    if bit_and == 0xFF { return out, UUID_VERSION_MAX, true; }

    let ver = (out.bytes[6] >> 4) & 0x0F;
    let var_bits = (out.bytes[8] >> 6) & 0x03;
    guard ver >= 1 && ver <= 8 && var_bits == UUID_VARIANT_RFC9562 else {
        return Uuid { .. }, 0, false;
    }
    return out, ver, true;
}

inline fn try_append_uuid_chars<B>(out: B&, formatted: const u8[:]) -> bool {
    let saved_len = out.len;
    guard core::sub_sat_i64(out.cap, saved_len) >= formatted.len else {
        return false;
    }
    out.append(formatted);
    return true;
}

inline fn try_append_uuid_chars(out: u8[>..]&, formatted: const u8[:]) -> bool {
    out.append(formatted);
    return true;
}

// Formats `uuid` into canonical 36-byte lowercase `8-4-4-4-12` hex text (RFC 9562 Section 4).
// Leaves `out` unchanged and returns `false` if `out` lacks capacity for 36 bytes.
//
// Example:
//   uuid = Nil Uuid { bytes: [0; 16] }
//   writes "00000000-0000-0000-0000-000000000000", returns true
fn format_uuid<B>(uuid: const Uuid&, out: B&) -> bool {
    var tmp: u8[..36] = [];
    for byte_idx in 16 {
        if byte_idx == 4 || byte_idx == 6 || byte_idx == 8 || byte_idx == 10 {
            tmp.push('-');
        }
        core::format_u8_hex(uuid.bytes[byte_idx], tmp, false);
    }
    return try_append_uuid_chars(out, tmp[..]);
}

fn is_valid_uuid(raw: const u8[:]) -> bool {
    let _, _, ok = parse_uuid(raw);
    return ok;
}

fn is_valid_uuid_v4(raw: const u8[:]) -> bool {
    let _, ver, ok = parse_uuid(raw);
    return ok && ver == 4;
}

fn is_valid_uuid_v7(raw: const u8[:]) -> bool {
    let _, ver, ok = parse_uuid(raw);
    return ok && ver == 7;
}

// ---- ulid (crockford base32) ------------------------------------------------

// Canonical ULID encoded string length (48-bit timestamp + 80-bit randomness).
const ULID_STR_LEN: i64 = 26;

const CROCKFORD_B32_LUT: const i8[256] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, 16, 17, -1, 18, 19, -1, 20, 21, -1,
    22, 23, 24, 25, 26, -1, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, 16, 17, -1, 18, 19, -1, 20, 21, -1,
    22, 23, 24, 25, 26, -1, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
];

// Validates a 26-byte ULID in Crockford's Base32 alphabet (excluding I, L, O, U)
// with leading character in `'0'..'7'` so the 48-bit timestamp cannot overflow.
fn is_valid_ulid(raw: const u8[:]) -> bool {
    guard raw.len == ULID_STR_LEN else { return false; }
    guard raw[0] >= '0' && raw[0] <= '7' else { return false; }
    for b in raw {
        guard CROCKFORD_B32_LUT[b] >= 0 else { return false; }
    }
    return true;
}

// ---- email addr-spec (rfc 5322 section 3.4.1 / rfc 5321) --------------------

// Maximum local-part length in octets (RFC 5321 Section 4.5.3.1.1).
const MAX_EMAIL_LOCAL_OCTETS: i64 = 64;

// Maximum addr-spec length in octets (RFC 5321 Section 4.5.3.1.3 / Errata 1690).
const MAX_EMAIL_ADDR_SPEC_OCTETS: i64 = 254;

// Maximum DNS domain and label lengths in octets (RFC 1035 Section 2.3.4).
const MAX_DNS_DOMAIN_OCTETS: i64 = 253;
const MAX_DNS_LABEL_OCTETS:  i64 = 63;

// Lookup table for RFC 5322 Section 3.2.3 `atext` characters:
// ALPHA / DIGIT / "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" /
// "/" / "=" / "?" / "^" / "_" / "`" / "{" / "|" / "}" / "~"
const RFC5322_ATEXT_LUT: const u8[256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

// Validates an unquoted dot-atom email local-part (`<= 64` octets, RFC 5322 Section 3.4.1).
fn is_valid_email_local_part(local: const u8[:]) -> bool {
    guard local.len >= 1 && local.len <= MAX_EMAIL_LOCAL_OCTETS else { return false; }
    let last_idx = core::sub_sat_i64(local.len, 1);
    guard local[0] != '.' && local[last_idx] != '.' else { return false; }
    var prev_dot = false;
    for b in local {
        if b == '.' {
            guard !prev_dot else { return false; }
            prev_dot = true;
        } else {
            guard RFC5322_ATEXT_LUT[b] != 0 else { return false; }
            prev_dot = false;
        }
    }
    return true;
}

inline fn is_valid_dns_tld(label_len: i64, prev_hyphen: bool) -> bool {
    return label_len >= 2 && label_len <= MAX_DNS_LABEL_OCTETS && !prev_hyphen;
}

inline fn is_valid_email_domain_labels(domain: const u8[:]) -> bool {
    guard domain.len >= 3 && domain.len <= MAX_DNS_DOMAIN_OCTETS else { return false; }
    guard core::contains_byte(domain, '.') else { return false; }

    var label_len: i64 = 0;
    var prev_hyphen = false;
    var tld_all_digits = true;
    for b in domain {
        if b == '.' {
            guard label_len >= 1 && label_len <= MAX_DNS_LABEL_OCTETS && !prev_hyphen else {
                return false;
            }
            label_len = 0;
            prev_hyphen = false;
            tld_all_digits = true;
        } else if b == '-' {
            guard label_len > 0 else { return false; }
            label_len = core::add_sat_i64(label_len, 1);
            prev_hyphen = true;
            tld_all_digits = false;
        } else {
            guard core::is_ascii_alphanumeric(b) else { return false; }
            if !core::is_ascii_digit(b) { tld_all_digits = false; }
            label_len = core::add_sat_i64(label_len, 1);
            prev_hyphen = false;
        }
    }
    guard !tld_all_digits && is_valid_dns_tld(label_len, prev_hyphen) else { return false; }
    return core::validate_idna_domain_bounds(domain);
}

// Validates an email `addr-spec` (`<local-part>@<domain>`, `<= 254` octets)
// combining RFC 5322 Section 3.4.1 dot-atom rules with IDNA domain label bounds.
fn is_valid_email_addr_spec(raw: const u8[:]) -> bool {
    guard raw.len >= 3 && raw.len <= MAX_EMAIL_ADDR_SPEC_OCTETS else { return false; }
    let local, domain, has_at = core::rsplit_once_byte(raw, '@');
    guard has_at && is_valid_email_local_part(local) else { return false; }
    return is_valid_email_domain_labels(domain);
}

// ---- slug & luhn (iso/iec 7812-1) -------------------------------------------

inline fn is_slug_alnum(b: u8) -> bool {
    return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9');
}

// Validates URL/identifier slugs matching `^[0-9a-z]+(?:[-_][0-9a-z]+)*$`.
fn is_valid_slug(raw: const u8[:]) -> bool {
    guard raw.len > 0 else { return false; }
    let last_idx = core::sub_sat_i64(raw.len, 1);
    guard is_slug_alnum(raw[0]) && is_slug_alnum(raw[last_idx]) else { return false; }
    var prev_sep = false;
    for b in raw {
        if b == '-' || b == '_' {
            guard !prev_sep else { return false; }
            prev_sep = true;
        } else {
            guard is_slug_alnum(b) else { return false; }
            prev_sep = false;
        }
    }
    return true;
}

const LUHN_ASCII_UND_LUT: const i64[256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

const LUHN_ASCII_DBL_LUT: const i64[256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 2, 4, 6, 8, 1, 3, 5, 7, 9, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

inline fn is_luhn_separator(b: u8) -> bool {
    return b == ' ' || b == '-';
}

inline fn add_mod10(sum_mod10: i64, term: i64) -> i64 {
    let next = core::add_sat_i64(sum_mod10, term);
    return if next >= 10 { core::sub_sat_i64(next, 10) } else { next };
}

// Validates payment card or IMEI numbers using the ISO/IEC 7812-1 Luhn mod-10 check.
// Skips single `' '` or `'-'` separators in-place without allocation; requires `>= 2` digits.
fn is_valid_luhn(raw: const u8[:]) -> bool {
    guard raw.len >= 2 else { return false; }
    let last_idx = core::sub_sat_i64(raw.len, 1);
    guard !is_luhn_separator(raw[0]) && !is_luhn_separator(raw[last_idx]) else { return false; }

    var idx = raw.len;
    var double_digit = false;
    var prev_sep = false;
    var sum_mod10:   i64 = 0;
    var digit_count: u64 = 0;

    while idx > 0 {
        idx = core::sub_sat_i64(idx, 1);
        let b = raw[idx];
        if is_luhn_separator(b) {
            guard !prev_sep else { return false; }
            prev_sep = true;
            continue;
        }
        guard core::is_ascii_digit(b) else { return false; }
        prev_sep = false;
        let term = if double_digit { LUHN_ASCII_DBL_LUT[b] } else { LUHN_ASCII_UND_LUT[b] };
        sum_mod10 = add_mod10(sum_mod10, term);
        double_digit = !double_digit;
        digit_count = core::add_sat_u64(digit_count, 1);
    }
    return digit_count >= 2 && sum_mod10 == 0;
}

// ---- slice-wide character class predicates ----------------------------------

fn is_all_digits(s: const u8[:]) -> bool {
    guard s.len > 0 else { return false; }
    for b in s {
        guard core::is_ascii_digit(b) else { return false; }
    }
    return true;
}

fn is_all_hex(s: const u8[:]) -> bool {
    guard s.len > 0 else { return false; }
    for b in s {
        guard core::is_ascii_hexdigit(b) else { return false; }
    }
    return true;
}

fn is_all_alphanumeric(s: const u8[:]) -> bool {
    guard s.len > 0 else { return false; }
    for b in s {
        guard core::is_ascii_alphanumeric(b) else { return false; }
    }
    return true;
}

fn is_all_printable_ascii(s: const u8[:]) -> bool {
    guard s.len > 0 else { return false; }
    for b in s {
        guard core::is_ascii_printable(b) else { return false; }
    }
    return true;
}
