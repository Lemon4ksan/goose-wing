// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_masque_dns_edge.goose
// Verification of RFC 9297 MASQUE capsules and RFC 1035 DNS compression pointers via wing::net.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// Wire adapter for verify_split_stream and fuzzing using wing's real parse_http_capsule
fn wing_validate_masque_capsule_wire(buf: const u8[:]) -> i64 {
    let cap, ok = wing::parse_http_capsule(buf);
    if ok {
        return cap.payload.len;
    }
    return -1;
}

fn wing_validate_dns_pointer_wire(buf: const u8[:], start_off: i64) -> i32 {
    var out: u8[..256] = [];
    var off = start_off;
    let ok = wing::dns_decode_name(buf, off, out);
    if ok {
        return 0;
    }
    return -2;
}

fn validate_svcb_target_wire(buf: const u8[:], start_off: i64) -> i32 {
    let len = buf.len;
    var cur = start_off;
    while cur < len {
        let b = buf[cur];
        if b == 0 { return 1; }
        if (b & 192) != 0 { return -2; }
        if b > 63 { return -3; }
        cur += 1 + b;
        if cur > len { return -1; }
    }
    return -1;
}

fn main() {
    var raw_cap: u8[>..] = [];
    assert(wire_kit::parse_hex("000568656C6C6F", raw_cap));
    assert(wire_kit::verify_split_stream(raw_cap[..], -1, 5, wing_validate_masque_capsule_wire));
    assert(wire_kit::fuzz_payload(raw_cap[..], 100, wing_validate_masque_capsule_wire));
    print("MASQUE_CAPSULE: OK");

    var ovf_cap: u8[>..] = []; wire_kit::parse_hex("00C0000000FFFFFFFF", ovf_cap);
    assert(wing_validate_masque_capsule_wire(ovf_cap[..]) == -1);
    print("MASQUE_OVF: OK");

    var dns_ok: u8[>..] = []; wire_kit::parse_hex("123481800001000100000000076578616d706c6503636f6d0000010001c00c", dns_ok);
    assert(wing_validate_dns_pointer_wire(dns_ok[..], 29) == 0);

    var dns_fwd: u8[>..] = []; wire_kit::parse_hex("123481800001000100000000076578616d706c6503636f6d0000010001c023", dns_fwd);
    assert(wing_validate_dns_pointer_wire(dns_fwd[..], 29) == -2);

    var dns_hdr: u8[>..] = []; wire_kit::parse_hex("123481800001000100000000076578616d706c6503636f6d0000010001c004", dns_hdr);
    assert(wing_validate_dns_pointer_wire(dns_hdr[..], 29) == -2);

    var dns_loop: u8[>..] = []; wire_kit::parse_hex("123481800001000100000000076578616d706c6500c015", dns_loop);
    assert(wing_validate_dns_pointer_wire(dns_loop[..], 29) == -2);
    print("DNS_POINTERS: OK");

    var svcb_ok: u8[>..] = []; wire_kit::parse_hex("076578616d706c6500", svcb_ok);
    assert(validate_svcb_target_wire(svcb_ok[..], 0) == 1);

    var svcb_bad: u8[>..] = []; wire_kit::parse_hex("c00c", svcb_bad);
    assert(validate_svcb_target_wire(svcb_bad[..], 0) == -2);
    print("SVCB_POINTERS: OK");
}

// CHECK: MASQUE_CAPSULE: OK
// CHECK: MASQUE_OVF: OK
// CHECK: DNS_POINTERS: OK
// CHECK: SVCB_POINTERS: OK
