// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose --cc gcc %s | %FileCheck %s

import std;
import core from "../..";

fn test_uuid_validators() {
    let v4_str = "550e8400-e29b-41d4-a716-446655440000";
    let v7_str = "018f3e9c-6d2a-7b10-9a3f-001122334455";
    let nil_str = "00000000-0000-0000-0000-000000000000";
    let max_str = "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF";

    let u7, ver7, ok7 = core::parse_uuid(v7_str);
    let _, ver_nil, ok_nil = core::parse_uuid(nil_str);
    let u_max, ver_max, ok_max = core::parse_uuid(max_str);

    var fixed_buf: u8[..64] = [];
    let fmt_ok = core::format_uuid(u7, fixed_buf);

    var tiny_buf: u8[..20] = [];
    tiny_buf.append("keep");
    let fmt_tiny_ok = core::format_uuid(u7, tiny_buf);

    var dyn_buf: u8[>..] = [];
    let fmt_dyn_ok = core::format_uuid(u_max, dyn_buf);

    let _, _, bad_len = core::parse_uuid("018f3e9c-6d2a-7b10-9a3f-00112233445");
    let _, _, bad_hyph = core::parse_uuid("018f3e9c_6d2a-7b10-9a3f-001122334455");
    let _, _, bad_hex = core::parse_uuid("018f3e9c-6d2a-7b10-9a3f-00112233445g");
    let _, _, bad_ver = core::parse_uuid("018f3e9c-6d2a-9b10-9a3f-001122334455");
    let _, _, bad_var = core::parse_uuid("018f3e9c-6d2a-7b10-da3f-001122334455");

    assert(ok7 && ver7 == 7);
    assert(ok_nil && ver_nil == 0);
    assert(ok_max && ver_max == 15);
    assert(fmt_ok && fixed_buf[..] == v7_str);
    assert(!fmt_tiny_ok && tiny_buf[..] == "keep");
    assert(fmt_dyn_ok && dyn_buf[..] == "ffffffff-ffff-ffff-ffff-ffffffffffff");
    assert(!bad_len && !bad_hyph && !bad_hex && !bad_ver && !bad_var);

    assert(core::is_valid_uuid(v4_str) && v4_str.is_valid_uuid());
    assert(core::is_valid_uuid_v4(v4_str) && v4_str.is_valid_uuid_v4());
    assert(!core::is_valid_uuid_v4(v7_str) && !v7_str.is_valid_uuid_v4());
    assert(core::is_valid_uuid_v7(v7_str) && v7_str.is_valid_uuid_v7());
    assert(!core::is_valid_uuid_v7(v4_str) && !v4_str.is_valid_uuid_v7());
    print("uuid: ", ok7, " ", fmt_ok, " ", !fmt_tiny_ok);
}

fn test_ulid_and_slug_and_luhn() {
    let ulid_ok = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    let ulid_lower = "01arz3ndektsv4rrffq69g5fav";
    let ulid_overflow = "81ARZ3NDEKTSV4RRFFQ69G5FAV";
    let ulid_bad_char = "01ARZ3NDEKTSV4RRFFQ69G5FAI";
    let ulid_short = "01ARZ3NDEKTSV4RRFFQ69G5FA";

    assert(core::is_valid_ulid(ulid_ok) && ulid_ok.is_valid_ulid());
    assert(core::is_valid_ulid(ulid_lower));
    assert(!core::is_valid_ulid(ulid_overflow));
    assert(!core::is_valid_ulid(ulid_bad_char));
    assert(!core::is_valid_ulid(ulid_short));

    assert(core::is_valid_slug("goose-wing_v2") && "goose-wing_v2".is_valid_slug());
    assert(core::is_valid_slug("a0"));
    assert(!core::is_valid_slug(""));
    assert(!core::is_valid_slug("-leading"));
    assert(!core::is_valid_slug("trailing_"));
    assert(!core::is_valid_slug("double--sep"));
    assert(!core::is_valid_slug("Upper-Case"));

    assert(core::is_valid_luhn("79927398713") && "79927398713".is_valid_luhn());
    assert(core::is_valid_luhn("4532-0151-1283-0366"));
    assert(core::is_valid_luhn("4532 0151 1283 0366"));
    assert(!core::is_valid_luhn("79927398714"));
    assert(!core::is_valid_luhn("0"));
    assert(!core::is_valid_luhn("-79927398713"));
    assert(!core::is_valid_luhn("4532--0151-1283-0366"));
    assert(!core::is_valid_luhn("7992739871a"));
    print("ulid_slug_luhn: true");
}

fn test_email_and_char_classes() {
    assert(core::is_valid_email_local_part("user.name+tag=1/2"));
    assert(!core::is_valid_email_local_part(""));
    assert(!core::is_valid_email_local_part(".leading"));
    assert(!core::is_valid_email_local_part("trailing."));
    assert(!core::is_valid_email_local_part("double..dot"));
    assert(!core::is_valid_email_local_part("bad space"));

    let email_ok = "alice.smith+dev@sub.example-domain.com";
    let email_idn = "user@xn--bcher-kva.example";
    assert(core::is_valid_email_addr_spec(email_ok) && email_ok.is_valid_email_addr_spec());
    assert(core::is_valid_email_addr_spec(email_idn));
    assert(!core::is_valid_email_addr_spec("a@b"));
    assert(!core::is_valid_email_addr_spec("no-at-sign.com"));
    assert(!core::is_valid_email_addr_spec("two@@example.com"));
    assert(!core::is_valid_email_addr_spec("user@localhost"));
    assert(!core::is_valid_email_addr_spec("user@.example.com"));
    assert(!core::is_valid_email_addr_spec("user@example.com."));
    assert(!core::is_valid_email_addr_spec("user@-example.com"));
    assert(!core::is_valid_email_addr_spec("user@example-.com"));
    assert(!core::is_valid_email_addr_spec("user@example..com"));
    assert(!core::is_valid_email_addr_spec("user@bad_host.com"));
    assert(!core::is_valid_email_addr_spec("user@127.0.0.1"));

    assert(core::is_all_digits("0123456789") && "0123456789".is_all_digits());
    assert(!core::is_all_digits("") && !core::is_all_digits("123a"));

    assert(core::is_all_hex("0123deadBEEF") && "0123deadBEEF".is_all_hex());
    assert(!core::is_all_hex("") && !core::is_all_hex("0123g"));

    assert(core::is_all_alphanumeric("Az09") && "Az09".is_all_alphanumeric());
    assert(!core::is_all_alphanumeric("") && !core::is_all_alphanumeric("Az-09"));

    assert(core::is_all_printable_ascii("Hello, World! ~") && "Hello!".is_all_printable_ascii());
    assert(!core::is_all_printable_ascii("") && !core::is_all_printable_ascii("line\nbreak"));
    print("email_chars: true");
}

fn test_base64_and_ufcs_scalars() {
    assert(core::is_valid_base64("") && "".is_valid_base64());
    assert(core::is_valid_base64("Zg==") && "Zg==".is_valid_base64());
    assert(core::is_valid_base64("Zm8="));
    assert(core::is_valid_base64("Zm9v"));
    assert(!core::is_valid_base64("Zh=="));
    assert(!core::is_valid_base64("Zm9="));
    assert(!core::is_valid_base64("Zg"));
    assert(!core::is_valid_base64("Zg=A"));
    assert(!core::is_valid_base64("A==="));
    assert(!core::is_valid_base64("Zm*="));
    assert(!core::is_valid_base64("Zm8*"));

    assert(core::is_valid_base64url("") && "".is_valid_base64url());
    assert(core::is_valid_base64url("Zg") && "Zg".is_valid_base64url());
    assert(core::is_valid_base64url("Zm8"));
    assert(core::is_valid_base64url("Zm9v"));
    assert(core::is_valid_base64url("Zm-_"));
    assert(core::is_valid_base64url("Zg=="));
    assert(core::is_valid_base64url("Zm8="));
    assert(!core::is_valid_base64url("Zh"));
    assert(!core::is_valid_base64url("Zm9"));
    assert(!core::is_valid_base64url("Zh=="));
    assert(!core::is_valid_base64url("Zm9="));
    assert(!core::is_valid_base64url("A"));
    assert(!core::is_valid_base64url("Zg="));
    assert(!core::is_valid_base64url("A==="));
    assert(!core::is_valid_base64url("Zm*="));
    assert(!core::is_valid_base64url("Zm+/"));

    let i_val: i64 = 42;
    let u_val: u64 = 42;
    assert(i_val.in_range_i64(10, 50) && !i_val.in_range_i64(50, 100));
    assert(u_val.in_range_u64(10, 50) && !u_val.in_range_u64(50, 100));
    assert(i_val.clamp_i64(0, 20) == 20 && i_val.clamp_i64(50, 100) == 50);
    assert(u_val.clamp_u64(0, 20) == 20 && u_val.clamp_u64(50, 100) == 50);
    assert("hello".has_len_between(3, 8) && !"hi".has_len_between(3, 8));
    print("b64_ufcs: true");
}

fn main() {
    test_uuid_validators();
    test_ulid_and_slug_and_luhn();
    test_email_and_char_classes();
    test_base64_and_ufcs_scalars();
}

// CHECK: uuid: true true true
// CHECK-NEXT: ulid_slug_luhn: true
// CHECK-NEXT: email_chars: true
// CHECK-NEXT: b64_ufcs: true
