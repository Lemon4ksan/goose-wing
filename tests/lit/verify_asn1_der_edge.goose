// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_asn1_der_edge.goose
// Verification of ITU-T X.690 length boundaries and RFC 5280 serial number rules via wing::tls.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// Wire adapter for verify_split_stream and fuzzing using wing::get_asn1_length
fn wing_decode_der_length(buf: const u8[:]) -> i64 {
    guard buf.len > 0 else { return -1; }
    var c = wing::cursor_from(buf);
    var out_len: i64 = 0;
    if wing::get_asn1_length(c, out_len) {
        return out_len;
    }
    let b0 = buf[0];
    guard (b0 & 0x80) != 0 else { return -2; }
    guard b0 != 0x80 && b0 != 0xFF else { return -2; }
    let num_bytes = (b0 & 0x7F) as i64;
    guard num_bytes >= 1 && num_bytes <= 4 else { return -2; }
    guard buf.len >= 1 + num_bytes else { return -1; }
    return -2;
}

// Validates RFC 5280 positive serial number rules and canonical padding via wing::validate_asn1_integer
fn wing_validate_asn1_serial_number(buf: const u8[:]) -> i64 {
    guard buf.len > 0 else { return -1; }
    if wing::validate_asn1_integer(buf, true) {
        return 1;
    }
    return -2;
}

fn main() {
    var raw_edge: u8[>..] = [];
    assert(wire_kit::parse_hex("820100", raw_edge));
    let split_ok = wire_kit::verify_split_stream(raw_edge[..], -1, 256, wing_decode_der_length);
    assert(split_ok);
    assert(wire_kit::fuzz_payload(raw_edge[..], 100, wing_decode_der_length));
    print("ASN1_DER_SPLIT: OK");

    var p80: u8[>..] = []; wire_kit::parse_hex("80", p80);
    assert(wing_decode_der_length(p80[..]) == -2);

    var p820080: u8[>..] = []; wire_kit::parse_hex("820080", p820080);
    assert(wing_decode_der_length(p820080[..]) == -2);

    var pFF: u8[>..] = []; wire_kit::parse_hex("FF", pFF);
    assert(wing_decode_der_length(pFF[..]) == -2);

    var p817F: u8[>..] = []; wire_kit::parse_hex("817F", p817F);
    assert(wing_decode_der_length(p817F[..]) == -2);
    print("ASN1_LENGTH_RULES: OK");

    var s42: u8[>..] = []; wire_kit::parse_hex("42", s42);
    assert(wing_validate_asn1_serial_number(s42[..]) == 1);

    var s0080: u8[>..] = []; wire_kit::parse_hex("0080", s0080);
    assert(wing_validate_asn1_serial_number(s0080[..]) == 1);

    var s80: u8[>..] = []; wire_kit::parse_hex("80", s80);
    assert(wing_validate_asn1_serial_number(s80[..]) == -2);

    var s0001: u8[>..] = []; wire_kit::parse_hex("0001", s0001);
    assert(wing_validate_asn1_serial_number(s0001[..]) == -2);

    var s21: u8[>..] = []; wire_kit::parse_hex("0102030405060708090A0B0C0D0E0F101112131415", s21);
    assert(wing_validate_asn1_serial_number(s21[..]) == -2);
    print("ASN1_SERIAL_RULES: OK");
}

// CHECK: ASN1_DER_SPLIT: OK
// CHECK: ASN1_LENGTH_RULES: OK
// CHECK: ASN1_SERIAL_RULES: OK
