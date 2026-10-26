// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Tests for MIME media types, parameter parsing, unquoting, and structured fields.
import std;
import core from "..";
import wing from "..";

fn test_strict_unquote_invariants(t: core::T&) {
    t.run("Chromium HttpUtil::StrictUnquote Valid Cases") { sub =>
        var out: u8[>..] = [];
        let ok1 = wing::strict_unquote("\"simple text\"", out);
        sub.assert_true(ok1, "Simple double-quoted string unquotes");
        sub.assert_bytes_eq(out[..], "simple text", "Content matches");

        // Escaped quotes inside
        out.clear();
        let ok2 = wing::strict_unquote("\"hello \\\"world\\\"\"", out);
        sub.assert_true(ok2, "Escaped internal quotes unquote");
        sub.assert_bytes_eq(out[..], "hello \"world\"", "Internal quotes preserved");

        // Even number of backslashes before closing quote (escaped backslash)
        out.clear();
        let ok3 = wing::strict_unquote("\"path\\\\\"", out);
        sub.assert_true(ok3, "Even number of backslashes before closing quote unquotes to single backslash");
        sub.assert_bytes_eq(out[..], "path\\", "Trailing single backslash preserved");

        // Single quote inside double quotes is valid text
        out.clear();
        let ok4 = wing::strict_unquote("\"user's parameter\"", out);
        sub.assert_true(ok4, "Single quote inside double quotes is valid");
        sub.assert_bytes_eq(out[..], "user's parameter", "Single quote unquoted");
    };

    t.run("Chromium HttpUtil::StrictUnquote Rejection Invariants") { sub =>
        var out: u8[>..] = [];

        // Odd number of backslashes before closing quote escapes the delimiter -> MUST FAIL
        let bad_esc = wing::strict_unquote("\"abc\\\"", out);
        sub.assert_false(bad_esc, "Escaped closing quote must fail");

        let bad_esc2 = wing::strict_unquote("\"\\\"", out);
        sub.assert_false(bad_esc2, "Single escaped quote inside quotes must fail");

        // Single quotes are NEVER delimiters
        let single_q = wing::strict_unquote("'single-quoted'", out);
        sub.assert_false(single_q, "Single-quoted string must fail");

        let empty_single = wing::strict_unquote("''", out);
        sub.assert_false(empty_single, "Empty single quotes must fail");

        // Unquoted string
        let unquoted = wing::strict_unquote("unquoted_token", out);
        sub.assert_false(unquoted, "Unquoted string must fail");

        // Unpaired quote
        let unpaired = wing::strict_unquote("\"unclosed", out);
        sub.assert_false(unpaired, "Unclosed quote must fail");
    };
}

fn test_media_type_parser(t: core::T&) {
    t.run("Content-Type Parsing and Parameters") { sub =>
        let mt, ok = wing::parse_media_type("text/html; charset=UTF-8; boundary=\"----WebKit123\"");
        sub.assert_true(ok, "Valid Content-Type parsed");
        sub.assert_bytes_eq(mt.mime_type[..], "text/html", "Mime type normalized lowercase");
        sub.assert_bytes_eq(mt.type_name[..], "text", "Type matches");
        sub.assert_bytes_eq(mt.subtype[..], "html", "Subtype matches");

        sub.assert_bytes_eq(wing::charset(mt), "UTF-8", "Charset extracted");
        sub.assert_bytes_eq(wing::boundary(mt), "----WebKit123", "Strict unquoted boundary extracted");
        sub.assert_false(wing::is_multipart(mt), "text/html is not multipart");
    };

    t.run("Multipart Form-Data Detection") { sub =>
        let mt, ok = wing::parse_media_type("multipart/form-data; boundary=boundary_xyz_99");
        sub.assert_true(ok, "Multipart Content-Type parsed");
        sub.assert_true(wing::is_multipart(mt), "Identified as multipart");
        sub.assert_bytes_eq(wing::boundary(mt), "boundary_xyz_99", "Boundary extracted");
    };

    t.run("Malformed Media Type Rejections") { sub =>
        let mt1, ok1 = wing::parse_media_type("");
        sub.assert_false(ok1, "Empty input fails");

        let mt2, ok2 = wing::parse_media_type("notype");
        sub.assert_false(ok2, "Missing slash fails");

        let mt3, ok3 = wing::parse_media_type("type/");
        sub.assert_false(ok3, "Empty subtype fails");

        let mt4, ok4 = wing::parse_media_type("text/html; badparameter");
        sub.assert_false(ok4, "Parameter without '=' fails");
    };
}

fn test_sfv_integers_and_decimals(t: core::T&) {
    t.run("RFC 8941 Section 3.3.1 sf-integer 15-Digit Bounds") { sub =>
        var item = wing::SfvItem { .. };

        // 15 digits positive max
        let ok1 = wing::parse_sfv_item("999999999999999", item);
        sub.assert_true(ok1, "15 digits max integer parsed");
        sub.assert_eq(item.bare.kind, wing::SfvType.Integer, "Is Integer");
        sub.assert_eq(item.bare.int_val, 999999999999999, "Integer value matches");

        // 15 digits negative max
        let ok2 = wing::parse_sfv_item("-999999999999999", item);
        sub.assert_true(ok2, "15 digits min integer parsed");
        sub.assert_eq(item.bare.int_val, -999999999999999, "Negative value matches");

        // 16 digits MUST FAIL per RFC 8941 Section 3.3.1
        let ok3 = wing::parse_sfv_item("1000000000000000", item);
        sub.assert_false(ok3, "16-digit integer must be rejected");

        // Zero and negative zero
        let ok_zero = wing::parse_sfv_item("-0", item);
        sub.assert_true(ok_zero, "-0 is valid");
        sub.assert_eq(item.bare.int_val, 0, "-0 parsed as 0");
    };

    t.run("RFC 8941 Section 3.3.2 sf-decimal (12.3 Fixed-Point Milliths)") { sub =>
        var item = wing::SfvItem { .. };

        // 1.5 -> 1500 milliths
        let ok1 = wing::parse_sfv_item("1.5", item);
        sub.assert_true(ok1, "1.5 parsed as decimal");
        sub.assert_eq(item.bare.kind, wing::SfvType.Decimal, "Is Decimal");
        sub.assert_eq(item.bare.int_val, 1500, "1.5 is 1500 milliths");

        // -0.123 -> -123 milliths
        let ok2 = wing::parse_sfv_item("-0.123", item);
        sub.assert_true(ok2, "-0.123 parsed as decimal");
        sub.assert_eq(item.bare.int_val, -123, "-123 milliths");

        // Serialization
        var ser: u8[>..] = [];
        wing::serialize_sfv_decimal(item.bare.int_val, ser);
        sub.assert_bytes_eq(ser[..], "-0.123", "Serialized decimal matches");

        ser.clear();
        wing::serialize_sfv_decimal(1500, ser);
        sub.assert_bytes_eq(ser[..], "1.5", "Trailing zeros stripped in serialization");

        // Strict rejections
        let bad_dot_only = wing::parse_sfv_item("1.", item);
        sub.assert_false(bad_dot_only, "Dot without fractional digits fails");

        let bad_no_int = wing::parse_sfv_item(".5", item);
        sub.assert_false(bad_no_int, "Dot without integer digits fails");

        let bad_4_frac = wing::parse_sfv_item("1.1234", item);
        sub.assert_false(bad_4_frac, "4 fractional digits fails");
    };
}

fn test_sfv_strings_tokens_and_keys(t: core::T&) {
    t.run("RFC 8941 Section 3.3.3 sf-string Escape Invariants") { sub =>
        var item = wing::SfvItem { .. };

        let ok1 = wing::parse_sfv_item("\"hello \\\"world\\\" and \\\\ slash\"", item);
        sub.assert_true(ok1, "Valid escaped string parsed");
        sub.assert_eq(item.bare.kind, wing::SfvType.String, "Is String");
        sub.assert_bytes_eq(item.bare.text[..], "hello \"world\" and \\ slash", "Escapes decoded");

        // Illegal escape sequence (e.g. \n or \t) MUST FAIL per RFC 8941 Section 3.3.3
        let bad_esc = wing::parse_sfv_item("\"illegal \\n escape\"", item);
        sub.assert_false(bad_esc, "\\n escape sequence is forbidden in sf-string");

        // Single quotes forbidden
        let single_q = wing::parse_sfv_item("'single'", item);
        sub.assert_false(single_q, "Single-quoted string is forbidden");
    };

    t.run("RFC 8941 Section 3.1.2 Dictionary Key Lowercase Invariant") { sub =>
        var dict = wing::SfvDict { .. };

        // Valid lowercase key
        let ok_lower = wing::parse_sfv_dict("cache-control_max.age*=?1", dict);
        sub.assert_true(ok_lower, "Lowercase key is valid");
        sub.assert_eq(dict.entries.len, 1, "1 entry in dict");

        // Uppercase in key MUST CAUSE COMPLETE ATOMIC PARSE FAILURE
        let bad_upper = wing::parse_sfv_dict("SHA-256=123", dict);
        sub.assert_false(bad_upper, "Uppercase in key causes hard parse failure");
        sub.assert_false(dict.valid, "Dictionary marked invalid on uppercase key");
    };

    t.run("RFC 8941 Section 3.3.5 sf-binary Base64 Decoding") { sub =>
        var item = wing::SfvItem { .. };
        // :AQIDBA==: -> [1, 2, 3, 4]
        let ok = wing::parse_sfv_item(":AQIDBA==:", item);
        sub.assert_true(ok, "Binary parsed");
        sub.assert_eq(item.bare.kind, wing::SfvType.ByteSequence, "Is ByteSequence");
        sub.assert_eq(item.bare.text.len, 4, "4 bytes decoded");
        sub.assert_eq(item.bare.text[0], 1, "Byte 0");
        sub.assert_eq(item.bare.text[1], 2, "Byte 1");
        sub.assert_eq(item.bare.text[2], 3, "Byte 2");
        sub.assert_eq(item.bare.text[3], 4, "Byte 3");
    };
}

fn test_sfv_rfc9651_dates_and_display_strings(t: core::T&) {
    t.run("RFC 9651 Section 3.3.7 sf-date (@epoch)") { sub =>
        var item = wing::SfvItem { .. };
        let ok = wing::parse_sfv_item("@1659578233", item);
        sub.assert_true(ok, "Date parsed");
        sub.assert_eq(item.bare.kind, wing::SfvType.Date, "Is Date");
        sub.assert_eq(item.bare.int_val, 1659578233, "Timestamp matches");

        // Decimal date MUST FAIL
        let bad_dec_date = wing::parse_sfv_item("@1659578233.5", item);
        sub.assert_false(bad_dec_date, "Decimal date must fail");
    };

    t.run("RFC 9651 Section 3.3.8 sf-displaystring (%\"...\" UTF-8 and Lowercase Hex)") { sub =>
        var item = wing::SfvItem { .. };
        // %"f%c3%bcber" -> "f\xc3\xbcber" (German u, 2 bytes UTF-8) -> 6 bytes total
        let ok = wing::parse_sfv_item("%\"f%c3%bcber\"", item);
        sub.assert_true(ok, "DisplayString with percent-encoded UTF-8 parsed");
        sub.assert_eq(item.bare.kind, wing::SfvType.DisplayString, "Is DisplayString");
        sub.assert_eq(item.bare.text.len, 6, "6 bytes decoded");

        // Uppercase percent-encoded hex (%C3) MUST FAIL per RFC 9651 Section 3.3.8!
        let bad_upper = wing::parse_sfv_item("%\"f%C3%bcber\"", item);
        sub.assert_false(bad_upper, "Uppercase percent-hex is strictly forbidden");

        // Invalid UTF-8 sequence MUST FAIL
        let bad_utf8 = wing::parse_sfv_item("%\"%ff%ff\"", item);
        sub.assert_false(bad_utf8, "Invalid UTF-8 byte sequence must fail");
    };
}

fn test_sfv_lists_and_dictionaries(t: core::T&) {
    t.run("RFC 8941 Section 3.1 List with Standalone and Inner Lists") { sub =>
        var list = wing::SfvList { .. };
        // sugar, (milk tea);temp=hot, "cookies"
        let ok = wing::parse_sfv_list("sugar, (milk tea);temp=hot, \"cookies\"", list);
        sub.assert_true(ok, "Structured list parsed");
        sub.assert_eq(list.members.len, 3, "3 list members");

        // Member 0: token "sugar"
        sub.assert_false(list.members[0].is_inner_list, "Member 0 is standalone item");
        sub.assert_eq(list.members[0].item.bare.kind, wing::SfvType.Token, "Is Token");

        // Member 1: inner list (milk tea) with param temp=hot
        sub.assert_true(list.members[1].is_inner_list, "Member 1 is inner list");
        sub.assert_eq(list.members[1].inner_list.len, 2, "2 items in inner list");
        sub.assert_eq(list.members[1].inner_params.len, 1, "1 param on inner list");
        sub.assert_bytes_eq(list.members[1].inner_params[0].key[..], "temp", "Param key temp");

        // Member 2: string "cookies"
        sub.assert_false(list.members[2].is_inner_list, "Member 2 is standalone item");
        sub.assert_eq(list.members[2].item.bare.kind, wing::SfvType.String, "Is String");
    };

    t.run("RFC 8941 Section 3.2 Dictionary In-Place Duplicate Overwrite") { sub =>
        var dict = wing::SfvDict { .. };
        // a=1, b=?0, a=2
        // Duplicate key 'a' MUST overwrite previous value in-place per RFC 8941 Section 3.2!
        let ok = wing::parse_sfv_dict("a=1, b=?0, a=2", dict);
        sub.assert_true(ok, "Dictionary parsed");
        sub.assert_eq(dict.entries.len, 2, "2 unique keys (a and b)");
        sub.assert_bytes_eq(dict.entries[0].key[..], "a", "Key 0 is a");
        sub.assert_eq(dict.entries[0].member.item.bare.int_val, 2, "Key a overwritten with 2");
        sub.assert_bytes_eq(dict.entries[1].key[..], "b", "Key 1 is b");
        sub.assert_eq(dict.entries[1].member.item.bare.bool_val, false, "Key b is false");
    };
}

// ---- consolidated suite entry point ---------------------------------------

fn main() {
    var runner = core::new_runner("HTTP MIME & Structured Field Values (SFV) Verification Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Chromium HttpUtil::StrictUnquote Invariants", test_strict_unquote_invariants);
    core::run_case(runner, "2. RFC 9110 Section 8.3 MediaType & Content-Type", test_media_type_parser);
    core::run_case(runner, "3. RFC 8941 Section 3.3.1 sf-integer & Section 3.3.2 sf-decimal", test_sfv_integers_and_decimals);
    core::run_case(runner, "4. RFC 8941 Section 3.3.3 sf-string, Section 3.3.5 sf-binary & keys", test_sfv_strings_tokens_and_keys);
    core::run_case(runner, "5. RFC 9651 sf-date & sf-displaystring (UTF-8)", test_sfv_rfc9651_dates_and_display_strings);
    core::run_case(runner, "6. RFC 8941 Section 3.1 Lists & Section 3.2 Dictionaries", test_sfv_lists_and_dictionaries);

    let ok = core::finish(runner);
    assert(ok);
}
