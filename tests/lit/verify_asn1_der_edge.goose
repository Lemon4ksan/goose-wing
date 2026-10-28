// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wire_kit from ".";

// Bounded ASN.1 DER length decoder enforcing ITU-T X.690 §8.1.3 invariants
fn decode_der_length(buf: const u8[:]) -> i64 {
    if buf.len <= 0 { return -1; }
    let b0 = buf[0] as i64;
    if (b0 & 128) == 0 {
        return b0;
    }
    // Indefinite length (0x80) and initial 0xFF are strictly forbidden in DER
    if b0 == 128 || b0 == 255 {
        return -2;
    }
    let num_bytes = b0 & 127;
    if num_bytes < 1 || num_bytes > 4 {
        return -2;
    }
    if buf.len < 1 + num_bytes {
        return -1; // incomplete
    }
    var total: i64 = 0;
    var i: i64 = 0;
    while i < num_bytes {
        let b = buf[1 + i] as i64;
        // Redundant leading zero in long form is strictly forbidden
        if i == 0 && b == 0 {
            return -2;
        }
        total = (total << 8) | b;
        i += 1;
    }
    // Long form must encode values >= 128
    if total < 128 {
        return -2;
    }
    return total;
}

// Validates DER integer canonical padding and RFC 5280 positive serial number rules.
fn validate_asn1_serial_number(buf: const u8[:]) -> i64 {
    if buf.len <= 0 { return -1; }
    // RFC 5280 §4.1.2.2: serial numbers longer than 20 octets are forbidden
    if buf.len > 20 { return -2; }
    let b0 = buf[0];
    // Serial numbers MUST be positive (high bit must be 0)
    if (b0 & 128) != 0 { return -2; }
    // Canonical DER padding: if b0 == 0x00 and len > 1, the next byte MUST have its high bit set
    if buf.len > 1 && b0 == 0 {
        let b1 = buf[1];
        if (b1 & 128) == 0 {
            return -2; // Redundant leading zero padding
        }
    }
    return 1; // Valid serial number
}

fn main() {
    var raw_edge: u8[>..] = [];
    assert(wire_kit::parse_hex("820100", raw_edge));
    let split_ok = wire_kit::verify_split_stream(raw_edge[..], -1, 256, decode_der_length);
    assert(split_ok);
    assert(wire_kit::fuzz_payload(raw_edge[..], 100, decode_der_length));
    print("ASN1_DER_SPLIT: OK");

    var p80: u8[>..] = []; wire_kit::parse_hex("80", p80);
    assert(decode_der_length(p80[..]) == -2);

    var p820080: u8[>..] = []; wire_kit::parse_hex("820080", p820080);
    assert(decode_der_length(p820080[..]) == -2);

    var pFF: u8[>..] = []; wire_kit::parse_hex("FF", pFF);
    assert(decode_der_length(pFF[..]) == -2);

    var p817F: u8[>..] = []; wire_kit::parse_hex("817F", p817F);
    assert(decode_der_length(p817F[..]) == -2);
    print("ASN1_LENGTH_RULES: OK");

    var s42: u8[>..] = []; wire_kit::parse_hex("42", s42);
    assert(validate_asn1_serial_number(s42[..]) == 1);

    var s0080: u8[>..] = []; wire_kit::parse_hex("0080", s0080);
    assert(validate_asn1_serial_number(s0080[..]) == 1);

    var s80: u8[>..] = []; wire_kit::parse_hex("80", s80);
    assert(validate_asn1_serial_number(s80[..]) == -2);

    var s0001: u8[>..] = []; wire_kit::parse_hex("0001", s0001);
    assert(validate_asn1_serial_number(s0001[..]) == -2);

    var s21: u8[>..] = []; wire_kit::parse_hex("0102030405060708090A0B0C0D0E0F101112131415", s21);
    assert(validate_asn1_serial_number(s21[..]) == -2);
    print("ASN1_SERIAL_RULES: OK");
}

// CHECK: ASN1_DER_SPLIT: OK
// CHECK: ASN1_LENGTH_RULES: OK
// CHECK: ASN1_SERIAL_RULES: OK
