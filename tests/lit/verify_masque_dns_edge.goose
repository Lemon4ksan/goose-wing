// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wire_kit from ".";

fn validate_masque_capsule_wire(buf: const u8[:]) -> i64 {
    let len = buf.len;
    if len <= 0 { return -1; }
    var idx: i64 = 0;

    let t0 = buf[idx];
    let tag_t = (t0 >> 6) & 3;
    var ctype_len: i64 = 1;
    if tag_t == 1 { ctype_len = 2; }
    else if tag_t == 2 { ctype_len = 4; }
    else if tag_t == 3 { ctype_len = 8; }
    if idx + ctype_len > len { return -1; }
    idx += ctype_len;

    if idx >= len { return -1; }
    let l0 = buf[idx];
    let tag_l = (l0 >> 6) & 3;
    var clen: i64 = l0 & 63;
    var len_bytes: i64 = 1;
    if tag_l == 1 {
        len_bytes = 2;
        if idx + len_bytes > len { return -1; }
        clen = (clen << 8) | buf[idx + 1];
    } else if tag_l == 2 {
        len_bytes = 4;
        if idx + len_bytes > len { return -1; }
        clen = (clen << 24) | ((buf[idx + 1] as i64) << 16) | ((buf[idx + 2] as i64) << 8) | buf[idx + 3];
    } else if tag_l == 3 {
        len_bytes = 8;
        if idx + len_bytes > len { return -1; }
        var j: i64 = 1;
        while j < 8 {
            clen = (clen << 8) | buf[idx + j];
            j += 1;
        }
    }
    idx += len_bytes;

    let total: i64 = idx + clen;
    if len < total {
        return -1;
    }
    return clen;
}

fn validate_dns_pointer_wire(buf: const u8[:], start_off: i64) -> i32 {
    let len = buf.len;
    var cur = start_off;
    var jumps: i32 = 0;
    while cur < len {
        let b = buf[cur];
        if b == 0 { return 0; }
        if (b & 192) == 192 {
            if cur + 1 >= len { return -1; }
            let ptr_off = ((b & 63) << 8) | buf[cur + 1];
            if ptr_off >= cur || ptr_off < 12 { return -2; }
            cur = ptr_off;
            jumps += 1;
            if jumps > 16 { return -3; }
            continue;
        }
        if (b & 192) != 0 || b > 63 { return -4; }
        cur += 1 + b;
        if cur > len { return -1; }
    }
    return -1;
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
    assert(wire_kit::verify_split_stream(raw_cap[..], -1, 5, validate_masque_capsule_wire));
    assert(wire_kit::fuzz_payload(raw_cap[..], 100, validate_masque_capsule_wire));
    print("MASQUE_CAPSULE: OK");

    var ovf_cap: u8[>..] = []; wire_kit::parse_hex("00C0000000FFFFFFFF", ovf_cap);
    assert(validate_masque_capsule_wire(ovf_cap[..]) == -1);
    print("MASQUE_OVF: OK");

    var dns_ok: u8[>..] = []; wire_kit::parse_hex("123481800001000100000000076578616d706c6503636f6d0000010001c00c", dns_ok);
    assert(validate_dns_pointer_wire(dns_ok[..], 29) == 0);

    var dns_fwd: u8[>..] = []; wire_kit::parse_hex("123481800001000100000000076578616d706c6503636f6d0000010001c023", dns_fwd);
    assert(validate_dns_pointer_wire(dns_fwd[..], 29) == -2);

    var dns_hdr: u8[>..] = []; wire_kit::parse_hex("123481800001000100000000076578616d706c6503636f6d0000010001c004", dns_hdr);
    assert(validate_dns_pointer_wire(dns_hdr[..], 29) == -2);

    var dns_loop: u8[>..] = []; wire_kit::parse_hex("123481800001000100000000076578616d706c6500c015", dns_loop);
    assert(validate_dns_pointer_wire(dns_loop[..], 21) == -2);
    print("DNS_POINTER_SECURITY: OK");

    var svcb_ok: u8[>..] = []; wire_kit::parse_hex("03666f6f0362617200", svcb_ok);
    assert(validate_svcb_target_wire(svcb_ok[..], 0) == 1);

    var svcb_bad: u8[>..] = []; wire_kit::parse_hex("c00c", svcb_bad);
    assert(validate_svcb_target_wire(svcb_bad[..], 0) == -2);
    print("SVCB_TARGET_SECURITY: OK");
}

// CHECK: MASQUE_CAPSULE: OK
// CHECK: MASQUE_OVF: OK
// CHECK: DNS_POINTER_SECURITY: OK
// CHECK: SVCB_TARGET_SECURITY: OK
