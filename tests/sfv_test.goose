// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for RFC 8941 & RFC 9651 Structured Field Values for HTTP:
// - Primitives: boolean, integer, decimal, string, token, binary, date
// - Parameterized items
// - Structured Lists and Inner Lists
// - Structured Dictionaries and fast accessors
// - Zero-allocation serialization into output buffers
import std;
import core from "..";
import wing from "..";

fn test_sfv_primitives(t: core::T&) {
    t.run("SFV Primitives Parsing (RFC 8941 §3.1-§3.3)") { sub =>
        // 1. Boolean
        let item_bool_t, ok_b1 = wing::parse_sf_item("?1");
        sub.assert_true(ok_b1, "Parse boolean ?1");
        sub.assert_eq(item_bool_t.item.kind, wing::SfType.Boolean, "Kind boolean");
        sub.assert_true(item_bool_t.item.bool_val, "Value is true");

        let item_bool_f, ok_b2 = wing::parse_sf_item("?0");
        sub.assert_true(ok_b2, "Parse boolean ?0");
        sub.assert_false(item_bool_f.item.bool_val, "Value is false");

        // 2. Integer
        let item_int, ok_i1 = wing::parse_sf_item("42");
        sub.assert_true(ok_i1, "Parse integer 42");
        sub.assert_eq(item_int.item.kind, wing::SfType.Integer, "Kind integer");
        sub.assert_eq(item_int.item.int_val, 42, "Value is 42");

        let item_int_neg, ok_i2 = wing::parse_sf_item("-999");
        sub.assert_true(ok_i2, "Parse negative integer -999");
        sub.assert_eq(item_int_neg.item.int_val, -999, "Value is -999");

        // 3. Decimal
        let item_dec, ok_dec = wing::parse_sf_item("3.14");
        sub.assert_true(ok_dec, "Parse decimal 3.14");
        sub.assert_eq(item_dec.item.kind, wing::SfType.Decimal, "Kind decimal");
        sub.assert_gt(item_dec.item.dec_val, 3.13, "Value > 3.13");
        sub.assert_lt(item_dec.item.dec_val, 3.15, "Value < 3.15");

        // 4. String
        let item_str, ok_str = wing::parse_sf_item("\"hello world\"");
        sub.assert_true(ok_str, "Parse string");
        sub.assert_eq(item_str.item.kind, wing::SfType.String, "Kind string");
        sub.assert_eq(item_str.item.str_val, "hello world", "String contents match");

        // 5. Token
        let item_tok, ok_tok = wing::parse_sf_item("gzip");
        sub.assert_true(ok_tok, "Parse token gzip");
        sub.assert_eq(item_tok.item.kind, wing::SfType.Token, "Kind token");
        sub.assert_eq(item_tok.item.str_val, "gzip", "Token contents match");

        // 6. Binary
        let item_bin, ok_bin = wing::parse_sf_item(":aGVsbG8=:");
        sub.assert_true(ok_bin, "Parse binary");
        sub.assert_eq(item_bin.item.kind, wing::SfType.Binary, "Kind binary");
        sub.assert_eq(item_bin.item.str_val, "aGVsbG8=", "Binary base64 payload matches");

        // 7. Date
        let item_date, ok_date = wing::parse_sf_item("@1618884475");
        sub.assert_true(ok_date, "Parse date");
        sub.assert_eq(item_date.item.kind, wing::SfType.Date, "Kind date");
        sub.assert_eq(item_date.item.int_val, 1618884475, "Date timestamp matches");
    };
}

fn test_sfv_parameters(t: core::T&) {
    t.run("SFV Parameters on Items (RFC 8941 §3.1.2)") { sub =>
        let p_item, ok = wing::parse_sf_item("text/html;charset=utf-8;q=0.8");
        sub.assert_true(ok, "Parsed parameterized item");
        sub.assert_eq(p_item.item.kind, wing::SfType.Token, "Kind is token");
        sub.assert_eq(p_item.item.str_val, "text/html", "Token text/html");
        sub.assert_eq(p_item.params.len, 2, "Has 2 parameters");

        sub.assert_eq(p_item.params[0].key, "charset", "First param key charset");
        sub.assert_eq(p_item.params[0].item.kind, wing::SfType.Token, "Charset is token");
        sub.assert_eq(p_item.params[0].item.str_val, "utf-8", "Charset is utf-8");

        sub.assert_eq(p_item.params[1].key, "q", "Second param key q");
        sub.assert_eq(p_item.params[1].item.kind, wing::SfType.Decimal, "Q is decimal");
        sub.assert_gt(p_item.params[1].item.dec_val, 0.79, "Q value > 0.79");
    };
}

fn test_sfv_lists_and_dicts(t: core::T&) {
    t.run("SFV Lists and Dictionaries (RFC 8941 §3.1-§3.2)") { sub =>
        // 1. Lists
        var list_items: wing::SfParameterizedItem[..16] = [];
        var ok = wing::parse_sf_list("sugar, tea, rum", list_items);
        sub.assert_true(ok, "Parse simple list");
        sub.assert_eq(list_items.len, 3, "List has 3 items");
        sub.assert_eq(list_items[0].item.str_val, "sugar", "Item 0 sugar");
        sub.assert_eq(list_items[1].item.str_val, "tea", "Item 1 tea");
        sub.assert_eq(list_items[2].item.str_val, "rum", "Item 2 rum");

        // 2. Dictionary
        var dict_entries: wing::SfDictEntry[..16] = [];
        let raw_dict = "u=3, i=?1, mode=\"fast\", prio=10";
        ok = wing::parse_sf_dict(raw_dict, dict_entries);
        sub.assert_true(ok, "Parse dictionary");
        sub.assert_eq(dict_entries.len, 4, "Dictionary has 4 entries");

        // Fast zero-alloc accessors
        let u_val = wing::sf_dict_get_int(raw_dict, "u", 0);
        sub.assert_eq(u_val, 3, "Urgency is 3");

        let i_val = wing::sf_dict_get_bool(raw_dict, "i", false);
        sub.assert_true(i_val, "Incremental is true");

        let mode_val = wing::sf_dict_get_token(raw_dict, "mode");
        // 'mode' is a string ("fast"), sf_dict_get_token accepts String or Token
        sub.assert_eq(mode_val, "fast", "Mode value matches");

        sub.assert_true(wing::sf_dict_has_key(raw_dict, "prio"), "Has key 'prio'");
        sub.assert_false(wing::sf_dict_has_key(raw_dict, "unknown"), "No unknown key");
    };

    t.run("SFV Inner List in Dictionary") { sub =>
        var dict: wing::SfDictEntry[..16] = [];
        let ok = wing::parse_sf_dict("endpoints=(srv1 srv2);p=1", dict);
        sub.assert_true(ok, "Parsed inner list in dict");
        sub.assert_eq(dict.len, 1, "One dict entry");
        sub.assert_eq(dict[0].key, "endpoints", "Key is endpoints");
        sub.assert_true(dict[0].is_inner_list, "Is inner list");
        sub.assert_eq(dict[0].inner_items.len, 2, "2 inner items");
        sub.assert_eq(dict[0].inner_items[0].str_val, "srv1", "srv1");
        sub.assert_eq(dict[0].inner_items[1].str_val, "srv2", "srv2");
        sub.assert_eq(dict[0].params.len, 1, "Inner list has 1 parameter");
        sub.assert_eq(dict[0].params[0].key, "p", "Param key p");
        sub.assert_eq(dict[0].params[0].item.int_val, 1, "Param p value 1");
    };
}

fn test_sfv_serialization(t: core::T&) {
    t.run("SFV Serialization (RFC 8941 §4.1)") { sub =>
        var out: u8[>..] = [];

        // Serialize Integer
        var item = wing::SfItem { kind: wing::SfType.Integer, int_val: 1234, .. };
        wing::sf_serialize_item(item, out);
        sub.assert_eq(out[..], "1234", "Output matches 1234");

        // Serialize Dict Entry: u=5
        out.clear();
        var entry = wing::SfDictEntry {
            key: "u",
            item: wing::SfItem { kind: wing::SfType.Integer, int_val: 5, .. },
            ..
        };
        wing::sf_serialize_dict_entry(entry, out);
        sub.assert_eq(out[..], "u=5", "Dict entry matches u=5");

        // Serialize Boolean ?1 in Dict Entry: i (RFC 8941 omits =?1 for boolean true in dicts)
        out.clear();
        var entry_bool = wing::SfDictEntry {
            key: "i",
            item: wing::SfItem { kind: wing::SfType.Boolean, bool_val: true, .. },
            ..
        };
        wing::sf_serialize_dict_entry(entry_bool, out);
        sub.assert_eq(out[..], "i", "Dict entry matches 'i'");
    };
}

fn main() {
    var runner = core::new_runner("RFC 8941 Structured Fields Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. SFV Primitives", test_sfv_primitives);
    core::run_case(runner, "2. SFV Parameters", test_sfv_parameters);
    core::run_case(runner, "3. SFV Lists & Dicts", test_sfv_lists_and_dicts);
    core::run_case(runner, "4. SFV Serialization", test_sfv_serialization);
    let ok = core::finish(runner);
    assert(ok);
}
