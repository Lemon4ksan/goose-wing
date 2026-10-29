// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: HTTP MIME, Multipart Form-Data, and Byte Ranges Suite
import std;
import core from "..";
import wing from "..";

// --- Component: http_mime ---
// Tests for MIME media types, parameter parsing, unquoting, and structured fields.

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

// --- Component: http_multipart ---
// Tests for multipart/form-data parsing and HTTP range requests.

fn test_streaming_multipart_parsing(t: core::T&) {
    t.run("Valid Multipart Form-Data with Text and File Parts") { sub =>
        let boundary = "----GooseBoundaryXYZ";
        var body: u8[>..] = [];
        body.append("------GooseBoundaryXYZ\r\n");
        body.append("Content-Disposition: form-data; name=\"username\"\r\n\r\n");
        body.append("alice\r\n");
        body.append("------GooseBoundaryXYZ\r\n");
        body.append("Content-Disposition: form-data; name=\"upload\"; filename=\"profile.png\"\r\n");
        body.append("Content-Type: image/png\r\n\r\n");
        body.append("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\r\n");
        body.append("------GooseBoundaryXYZ--\r\n");

        let msg, err = wing::parse_multipart(body[..], boundary);
        sub.assert_eq(err, wing::MultipartError.None, "Multipart parsed cleanly");
        sub.assert_true(msg.valid, "Message marked valid");
        sub.assert_eq(msg.parts.len, 2, "Exactly 2 parts parsed");

        // Part 1: username field
        let p1 = msg.parts[0];
        sub.assert_bytes_eq(p1.name[..], "username", "Part 1 name username");
        sub.assert_bytes_eq(p1.filename[..], "", "Part 1 has no filename");
        sub.assert_bytes_eq(p1.data, "alice", "Part 1 body alice");

        // Part 2: file upload
        let p2 = msg.parts[1];
        sub.assert_bytes_eq(p2.name[..], "upload", "Part 2 name upload");
        sub.assert_bytes_eq(p2.filename[..], "profile.png", "Part 2 filename profile.png");
        sub.assert_bytes_eq(p2.content_type[..], "image/png", "Part 2 Content-Type image/png");
        sub.assert_bytes_eq(p2.data, "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", "Part 2 binary data intact");
    };

    t.run("Multipart Quotas (max_parts and max_memory)") { sub =>
        let boundary = "test_boundary";
        var body: u8[>..] = [];
        body.append("--test_boundary\r\nContent-Disposition: form-data; name=\"f1\"\r\n\r\nv1\r\n");
        body.append("--test_boundary\r\nContent-Disposition: form-data; name=\"f2\"\r\n\r\nv2\r\n");
        body.append("--test_boundary\r\nContent-Disposition: form-data; name=\"f3\"\r\n\r\nv3\r\n");
        body.append("--test_boundary--\r\n");

        // Limit to max 2 parts
        var opts = wing::default_multipart_options();
        opts.max_parts = 2;
        let msg, err = wing::parse_multipart(body[..], boundary, opts);
        sub.assert_eq(err, wing::MultipartError.ExceededMaxParts, "ExceededMaxParts triggered");
        sub.assert_false(msg.valid, "Message invalid on quota exceed");
    };
}

fn test_cve_2026_19484_boundary_and_bmh_table(t: core::T&) {
    t.run("Barrier 1: RFC 2046 Section 5.1.1 Boundary Length Cap (252-Byte Boundary Rejection)") { sub =>
        // In CVE-2026-19484 (@fastify/busboy), a 252-byte boundary caused 256-byte needle and 8-bit table overflow.
        // In naive implementations, ose, any boundary > 70 characters MUST be rejected immediately!
        var long_boundary: u8[..256] = [];
        for i in 252 {
            long_boundary.push('a');
        }

        let body = "--fake\r\n\r\ntest\r\n--fake--\r\n";
        let msg, err = wing::parse_multipart(body, long_boundary[..]);
        sub.assert_eq(err, wing::MultipartError.InvalidBoundaryLength, "252-byte boundary rejected before state allocation");
        sub.assert_false(msg.valid, "Invalid boundary makes message invalid");
    };

    t.run("Barrier 2: 16-Bit BMH Shift Table No-Wrap Invariant") { sub =>
        // Construct a synthetic 256-byte needle and build the BMH shift table directly.
        // With u8[256], default_shift = 256 wrapped to 0, causing infinite loops!
        // With u16[256], default_shift = 256, preserving strict forward progress (step >= 1).
        var big_needle: u8[>..] = [];
        for i in 256 {
            big_needle.push('x');
        }

        var table: u16[256] = [0; 256];
        wing::build_bmh_shift_table(big_needle[..], table);

        // Every byte not in the needle prefix must have shift == 256 (not 0!)
        let shift_other = table['y' as i64];
        sub.assert_eq(shift_other, 256, "BMH shift distance is 256 without 8-bit truncation");
        sub.assert_true(shift_other > 0, "Shift distance strictly positive, eliminating spinloops");
    };
}

fn test_rfc9110_range_requests(t: core::T&) {
    t.run("Three RFC 9110 Section 14.1.2 Range Specifier Forms") { sub =>
        let file_len: i64 = 10000;

        // 1. Explicit: bytes=0-499
        let rs1, err1 = wing::parse_range_header("bytes=0-499", file_len);
        sub.assert_eq(err1, wing::RangeError.None, "Explicit range parsed");
        sub.assert_eq(rs1.ranges.len, 1, "1 range");
        sub.assert_eq(rs1.ranges[0].start, 0, "Start 0");
        sub.assert_eq(rs1.ranges[0].end_pos, 499, "End 499");

        // 2. Open prefix: bytes=5000-
        let rs2, err2 = wing::parse_range_header("bytes=5000-", file_len);
        sub.assert_eq(err2, wing::RangeError.None, "Open prefix range parsed");
        sub.assert_eq(rs2.ranges.len, 1, "1 range");
        sub.assert_eq(rs2.ranges[0].start, 5000, "Start 5000");
        sub.assert_eq(rs2.ranges[0].end_pos, 9999, "End 9999 (last byte of 10000)");

        // 3. Suffix: bytes=-500 (last 500 bytes: 9500-9999)
        let rs3, err3 = wing::parse_range_header("bytes=-500", file_len);
        sub.assert_eq(err3, wing::RangeError.None, "Suffix range parsed");
        sub.assert_eq(rs3.ranges.len, 1, "1 range");
        sub.assert_eq(rs3.ranges[0].start, 9500, "Start 9500");
        sub.assert_eq(rs3.ranges[0].end_pos, 9999, "End 9999");
    };

    t.run("RFC 9110 Section 14.4 416 Range Not Satisfiable") { sub =>
        let file_len: i64 = 5000;
        let rs, err = wing::parse_range_header("bytes=60000-", file_len);
        sub.assert_eq(err, wing::RangeError.Unsatisfiable, "Unsatisfiable range returns 416 error");
        sub.assert_false(rs.is_satisfiable, "Marked unsatisfiable");

        var cr_val: u8[>..] = [];
        wing::format_content_range(-1, -1, file_len, cr_val);
        sub.assert_bytes_eq(cr_val[..], "bytes */5000", "Mandatory Content-Range bytes */5000 formatted");
    };
}

fn test_cve_2011_3192_apache_killer_and_coalescing(t: core::T&) {
    t.run("CVE-2011-3192: 16-Range Ceiling Rejection") { sub =>
        // Attacker sends 20 ranges to amplify CPU and response size
        var attack_hdr: u8[>..] = "bytes=";
        for i in 20 {
            if i > 0 { attack_hdr.append(", "); }
            format(attack_hdr, i * 10);
            attack_hdr.push('-');
            format(attack_hdr, i * 10 + 5);
        }

        let rs, err = wing::parse_range_header(attack_hdr[..], 10000);
        sub.assert_eq(err, wing::RangeError.ExceededMaxRanges, "Excessive range count rejected to defeat CVE-2011-3192");
    };

    t.run("RFC 9110 Range Coalescing (s2 <= e1 + 1)") { sub =>
        let file_len: i64 = 10000;

        // Overlapping ranges: bytes=0-500, 400-999 -> [0, 999]
        let rs_over, err_over = wing::parse_range_header("bytes=0-500, 400-999", file_len, true);
        sub.assert_eq(err_over, wing::RangeError.None, "Overlapping ranges parsed");
        sub.assert_true(rs_over.coalesced, "Coalescing occurred");
        sub.assert_eq(rs_over.ranges.len, 1, "Coalesced into 1 range");
        sub.assert_eq(rs_over.ranges[0].start, 0, "Merged start 0");
        sub.assert_eq(rs_over.ranges[0].end_pos, 999, "Merged end 999");

        // Adjacent ranges: bytes=0-100, 101-200 -> [0, 200]
        let rs_adj, err_adj = wing::parse_range_header("bytes=0-100, 101-200", file_len, true);
        sub.assert_eq(err_adj, wing::RangeError.None, "Adjacent ranges parsed");
        sub.assert_true(rs_adj.coalesced, "Coalescing occurred");
        sub.assert_eq(rs_adj.ranges.len, 1, "Coalesced into 1 range");
        sub.assert_eq(rs_adj.ranges[0].start, 0, "Merged start 0");
        sub.assert_eq(rs_adj.ranges[0].end_pos, 200, "Merged end 200");

        // Disjoint ranges: bytes=0-100, 500-600 -> 2 ranges
        let rs_dis, err_dis = wing::parse_range_header("bytes=0-100, 500-600", file_len, true);
        sub.assert_eq(err_dis, wing::RangeError.None, "Disjoint ranges parsed");
        sub.assert_eq(rs_dis.ranges.len, 2, "Keeps 2 distinct ranges");
        sub.assert_eq(rs_dis.ranges[0].start, 0, "Range 0 start");
        sub.assert_eq(rs_dis.ranges[0].end_pos, 100, "Range 0 end");
        sub.assert_eq(rs_dis.ranges[1].start, 500, "Range 1 start");
        sub.assert_eq(rs_dis.ranges[1].end_pos, 600, "Range 1 end");
    };
}

fn test_if_range_and_seconds_truncation(t: core::T&) {
    t.run("Strong ETag Matches, Weak ETag FORBIDDEN") { sub =>
        let file_time = core::unix(0);

        // Strong ETag matches
        let ok_strong = wing::evaluate_if_range("\"strong-etag-1\"", "\"strong-etag-1\"", file_time);
        sub.assert_true(ok_strong, "Strong ETag match succeeds");

        // Weak ETag MUST NEVER match in If-Range per RFC 9110 Section 13.1.5
        let bad_weak1 = wing::evaluate_if_range("W/\"strong-etag-1\"", "\"strong-etag-1\"", file_time);
        sub.assert_false(bad_weak1, "Weak ETag forbidden in If-Range");

        let bad_weak2 = wing::evaluate_if_range("w/\"strong-etag-1\"", "\"strong-etag-1\"", file_time);
        sub.assert_false(bad_weak2, "Lowercase weak ETag forbidden in If-Range");

        // Resource ETag being weak is also forbidden per RFC 9110 Section 13.1.5
        let bad_weak3 = wing::evaluate_if_range("\"strong-etag-1\"", "W/\"strong-etag-1\"", file_time);
        sub.assert_false(bad_weak3, "Weak target representation ETag forbidden in If-Range");
    };

    t.run("HTTP-Date Seconds Truncation for Filesystem Timestamps") { sub =>
        // Suppose filesystem mtime has sub-second resolution (e.g. 1700000000 sec + 450,000,000 ns)
        let exact_sec: i64 = 1700000000;
        let fs_time = core::unix(exact_sec, 450000000);

        // Client sends HTTP-Date with 1-second resolution
        var http_date_buf: u8[>..] = [];
        core::format_http(http_date_buf, core::unix(exact_sec));

        // evaluate_if_range MUST truncate fs_time to seconds before comparison!
        let is_match = wing::evaluate_if_range(http_date_buf[..], "", fs_time);
        sub.assert_true(is_match, "Filesystem sub-second mtime truncated to seconds matches HTTP-Date");
    };
}

fn test_serve_range_and_patch_validation(t: core::T&) {
    t.run("Single-Part 206 Serve via Window Reader Callback") { sub =>
        let source_data = "0123456789abcdefghijklmnopqrstuvwxyz";
        let res_len = source_data.len;

        var status: i32 = 0;
        var headers = wing::HeaderMap { .. };
        var body_out: u8[>..] = [];

        wing::serve_range_request(
            "bytes=0-9",
            "",
            "\"etag\"",
            core::unix(0),
            res_len,
            "text/plain",
            status,
            headers,
            body_out,
        ) { offset, len, out =>
            out.append(source_data[offset..offset + len]);
        };

        sub.assert_eq(status, 206, "Status 206 Partial Content");
        sub.assert_bytes_eq(wing::get_header(headers, "content-range"), "bytes 0-9/36", "Content-Range header exact");
        sub.assert_bytes_eq(wing::get_header(headers, "content-length"), "10", "Content-Length is 10");
        sub.assert_bytes_eq(body_out[..], "0123456789", "Body contains exactly first 10 bytes");
    };

    t.run("draft-wright Byte-Range PATCH Validation") { sub =>
        // Valid PATCH: Content-Range matches body length (10 bytes: 0-9)
        let s1, e1, ok1 = wing::validate_byterange_patch("bytes 0-9/1000", 10);
        sub.assert_true(ok1, "Valid PATCH Content-Range accepted");
        sub.assert_eq(s1, 0, "Start 0");
        sub.assert_eq(e1, 9, "End 9");

        // Length mismatch (body length 5 != 10)
        let s2, e2, ok2 = wing::validate_byterange_patch("bytes 0-9/1000", 5);
        sub.assert_false(ok2, "Length mismatch rejected");

        // Unsatisfied form 'bytes */1000' in PATCH is a syntax error
        let s3, e3, ok3 = wing::validate_byterange_patch("bytes */1000", 0);
        sub.assert_false(ok3, "Unsatisfied bytes */N in PATCH rejected");
    };
}

fn test_boundary_delimiter_and_disposition_invariants(t: core::T&) {
    t.run("Incomplete Final Boundary Delimiter (Missing Closing Dashes) Rejected") { sub =>
        // Truncated payload ends with intermediate delimiter --bnd\r\n without closing '--'
        let boundary = "IncompBnd";
        var body: u8[>..] = [];
        body.append("--IncompBnd\r\n");
        body.append("Content-Disposition: form-data; name=\"field\"\r\n\r\n");
        body.append("data\r\n");
        body.append("--IncompBnd\r\n");

        let msg, err = wing::parse_multipart(body[..], boundary);
        sub.assert_eq(err, wing::MultipartError.PrematureEOF, "Truncated payload without closing dashes rejected as PrematureEOF");
        sub.assert_false(msg.valid, "Message marked invalid");
    };

    t.run("Part Body Containing Boundary Collision Substring Preserved Intact") { sub =>
        // Body contains --bnd--invalid_suffix which must NOT be treated as closing delimiter
        let boundary = "SafeBnd";
        var body: u8[>..] = [];
        body.append("--SafeBnd\r\n");
        body.append("Content-Disposition: form-data; name=\"upload\"\r\n\r\n");
        body.append("pre\r\n--SafeBnd--not_close\r\npost\r\n");
        body.append("--SafeBnd--\r\n");

        let msg, err = wing::parse_multipart(body[..], boundary);
        sub.assert_eq(err, wing::MultipartError.None, "Payload with inner --bnd--collision parsed cleanly");
        sub.assert_true(msg.valid, "Message valid");
        sub.assert_eq(msg.parts.len, 1, "Exactly 1 part extracted");
        sub.assert_bytes_eq(msg.parts[0].data, "pre\r\n--SafeBnd--not_close\r\npost", "Body containing false boundary suffix preserved intact");
    };

    t.run("RFC 7578 Section 4.2 Content-Disposition form-data Enforcement") { sub =>
        let boundary = "DispBnd";
        // Part 1: disposition-type is 'attachment' instead of 'form-data'
        var bad_body: u8[>..] = [];
        bad_body.append("--DispBnd\r\n");
        bad_body.append("Content-Disposition: attachment; filename=\"file.bin\"\r\n\r\n");
        bad_body.append("bytes\r\n");
        bad_body.append("--DispBnd--\r\n");

        let msg1, err1 = wing::parse_multipart(bad_body[..], boundary);
        sub.assert_eq(err1, wing::MultipartError.InvalidPartHeaders, "Non-form-data Content-Disposition rejected");
        sub.assert_false(msg1.valid, "Message marked invalid");

        // Part 2: Malformed Content-Disposition header with unclosed quote
        var malformed_body: u8[>..] = [];
        malformed_body.append("--DispBnd\r\n");
        malformed_body.append("Content-Disposition: form-data; name=\"unclosed\r\n\r\n");
        malformed_body.append("bytes\r\n");
        malformed_body.append("--DispBnd--\r\n");

        let msg2, err2 = wing::parse_multipart(malformed_body[..], boundary);
        sub.assert_eq(err2, wing::MultipartError.InvalidPartHeaders, "Malformed Content-Disposition header rejected");
        sub.assert_false(msg2.valid, "Message marked invalid on malformed disposition");
    };
}

fn test_rfc9110_coalescing_and_nested_boundaries(t: core::T&) {
    t.run("Out-of-Order and Overlapping Range Coalescing (RFC 9110 Section 14.1.2)") { sub =>
        let file_len: i64 = 10000;

        // 1. Out-of-order disjoint: bytes=100-200, 0-50 -> sorted [0, 50], [100, 200]
        let rs_ord, err_ord = wing::parse_range_header("bytes=100-200, 0-50", file_len, true);
        sub.assert_eq(err_ord, wing::RangeError.None, "Out-of-order ranges parsed");
        sub.assert_true(rs_ord.coalesced, "Coalescing triggered");
        sub.assert_eq(rs_ord.ranges.len, 2, "Maintains 2 sorted disjoint ranges");
        sub.assert_eq(rs_ord.ranges[0].start, 0, "First range start is 0");
        sub.assert_eq(rs_ord.ranges[0].end_pos, 50, "First range end is 50");
        sub.assert_eq(rs_ord.ranges[1].start, 100, "Second range start is 100");
        sub.assert_eq(rs_ord.ranges[1].end_pos, 200, "Second range end is 200");

        // 2. Out-of-order overlapping: bytes=100-200, 0-150 -> merged [0, 200]
        let rs_over, err_over = wing::parse_range_header("bytes=100-200, 0-150", file_len, true);
        sub.assert_eq(err_over, wing::RangeError.None, "Out-of-order overlapping parsed");
        sub.assert_true(rs_over.coalesced, "Coalesced");
        sub.assert_eq(rs_over.ranges.len, 1, "Merged to 1 range");
        sub.assert_eq(rs_over.ranges[0].start, 0, "Merged start 0");
        sub.assert_eq(rs_over.ranges[0].end_pos, 200, "Merged end 200");

        // 3. Duplicate identical ranges: bytes=0-50, 0-50 -> single range [0, 50]
        let rs_dup, err_dup = wing::parse_range_header("bytes=0-50, 0-50", file_len, true);
        sub.assert_eq(err_dup, wing::RangeError.None, "Duplicate ranges parsed");
        sub.assert_true(rs_dup.coalesced, "Coalesced");
        sub.assert_eq(rs_dup.ranges.len, 1, "Duplicate coalesced to 1 range");
        sub.assert_eq(rs_dup.ranges[0].start, 0, "Range start 0");
        sub.assert_eq(rs_dup.ranges[0].end_pos, 50, "Range end 50");

        // 4. Identical start, out-of-order end: bytes=0-100, 0-50 -> merged [0, 100]
        let rs_same_s, err_same_s = wing::parse_range_header("bytes=0-100, 0-50", file_len, true);
        sub.assert_eq(err_same_s, wing::RangeError.None, "Same start parsed");
        sub.assert_true(rs_same_s.coalesced, "Coalesced");
        sub.assert_eq(rs_same_s.ranges.len, 1, "Merged into 1 range");
        sub.assert_eq(rs_same_s.ranges[0].start, 0, "Merged start 0");
        sub.assert_eq(rs_same_s.ranges[0].end_pos, 100, "Merged end 100");
    };

    t.run("Negative Suffix Range Math (RFC 9110 Section 14.1.2)") { sub =>
        let file_len: i64 = 10000;

        // bytes=-0 must be rejected with MalformedRange
        let rs_zero, err_zero = wing::parse_range_header("bytes=-0", file_len);
        sub.assert_eq(err_zero, wing::RangeError.MalformedRange, "bytes=-0 rejected as MalformedRange");

        // Suffix length exceeding resource length clamps to full resource [0, file_len - 1]
        let rs_clamp, err_clamp = wing::parse_range_header("bytes=-20000", file_len);
        sub.assert_eq(err_clamp, wing::RangeError.None, "Large suffix parsed");
        sub.assert_eq(rs_clamp.ranges.len, 1, "1 range");
        sub.assert_eq(rs_clamp.ranges[0].start, 0, "Start clamped to 0");
        sub.assert_eq(rs_clamp.ranges[0].end_pos, 9999, "End clamped to resource_len - 1");
    };

    t.run("64-Bit Integer Overflow Guard in Range Serving") { sub =>
        // Construct a synthetic RangeSet where end_pos - start + 1 would overflow signed 64-bit int
        var rs = wing::RangeSet {
            resource_length: 9223372036854775807,
            is_satisfiable: true,
            coalesced: false,
            ..
        };
        rs.ranges.push(wing::NormalizedRange {
            start: 0,
            end_pos: 9223372036854775807,
        });

        var status: i32 = 0;
        var headers = wing::HeaderMap { .. };
        var body_out: u8[>..] = [];

        wing::serve_range_set(
            rs,
            9223372036854775807,
            "application/octet-stream",
            status,
            headers,
            body_out,
        ) { offset, len, out =>
            // Callback should never be invoked for overflowing range
            out.append("overflow");
        };

        sub.assert_eq(status, 416, "Status 416 Range Not Satisfiable on i64 overflow");
        sub.assert_bytes_eq(wing::get_header(headers, "content-range"), "bytes */9223372036854775807", "416 Content-Range with resource length");
        sub.assert_bytes_eq(wing::get_header(headers, "content-length"), "0", "Content-Length is 0");
        sub.assert_eq(body_out.len, 0, "Body empty");
    };

    t.run("Nested Multipart MIME and Boundary Prefix Isolation (RFC 2046 Section 5.1)") { sub =>
        // Outer boundary is a strict prefix of inner boundary: 'Outer' and 'Outer_Inner'
        let outer_boundary = "Outer";
        let inner_boundary = "Outer_Inner";

        var body: u8[>..] = [];
        body.append("--Outer\r\n");
        body.append("Content-Disposition: form-data; name=\"upload_batch\"\r\n");
        body.append("Content-Type: multipart/form-data; boundary=Outer_Inner\r\n\r\n");

        // Inner nested payload
        body.append("--Outer_Inner\r\n");
        body.append("Content-Disposition: form-data; name=\"doc1\"; filename=\"notes.txt\"\r\n");
        body.append("Content-Type: text/plain\r\n\r\n");
        body.append("meeting notes\r\n");
        body.append("--Outer_Inner\r\n");
        body.append("Content-Disposition: form-data; name=\"doc2\"; filename=\"summary.md\"\r\n");
        body.append("Content-Type: text/markdown\r\n\r\n");
        body.append("# Project Plan\r\n");
        body.append("--Outer_Inner--\r\n");

        // Outer closing boundary
        body.append("--Outer--\r\n");

        // 1. Outer parse: should NOT prematurely terminate at --Outer_Inner
        let outer_msg, outer_err = wing::parse_multipart(body[..], outer_boundary);
        sub.assert_eq(outer_err, wing::MultipartError.None, "Outer multipart parsed cleanly");
        sub.assert_true(outer_msg.valid, "Outer message valid");
        sub.assert_eq(outer_msg.parts.len, 1, "Exactly 1 outer part extracted");
        sub.assert_bytes_eq(outer_msg.parts[0].name[..], "upload_batch", "Outer part name matched");

        // 2. Inner parse: parse outer part's data with inner boundary
        let inner_msg, inner_err = wing::parse_multipart(outer_msg.parts[0].data, inner_boundary);
        sub.assert_eq(inner_err, wing::MultipartError.None, "Inner nested multipart parsed cleanly");
        sub.assert_true(inner_msg.valid, "Inner message valid");
        sub.assert_eq(inner_msg.parts.len, 2, "Both nested parts extracted");

        let p1 = inner_msg.parts[0];
        sub.assert_bytes_eq(p1.name[..], "doc1", "Nested part 1 name");
        sub.assert_bytes_eq(p1.filename[..], "notes.txt", "Nested part 1 filename");
        sub.assert_bytes_eq(p1.data, "meeting notes", "Nested part 1 data intact");

        let p2 = inner_msg.parts[1];
        sub.assert_bytes_eq(p2.name[..], "doc2", "Nested part 2 name");
        sub.assert_bytes_eq(p2.filename[..], "summary.md", "Nested part 2 filename");
        sub.assert_bytes_eq(p2.data, "# Project Plan", "Nested part 2 data intact");
    };
}

fn test_round3_boundary_quoting_patch_and_quotas(t: core::T&) {
    t.run("RFC 7578 / RFC 2046 Quoted Boundary Unquoting and Validation") { sub =>
        // 1. Valid quoted boundary
        sub.assert_true(wing::validate_boundary_string("\"valid-quoted-bnd\""), "Standard quoted boundary accepted");

        // 2. Interior space is valid in RFC 2046 bchars
        sub.assert_true(wing::validate_boundary_string("\"valid boundary with spaces\""), "Quoted boundary with interior spaces accepted");

        // 3. Trailing space rejected per RFC 2046 Section 5.1.1
        sub.assert_false(wing::validate_boundary_string("\"boundary with trailing space \""), "Quoted boundary ending with space rejected");

        // 4. Escaped quotes inside boundary rejected (quote is not an RFC 2046 bchar)
        sub.assert_false(wing::validate_boundary_string("\"escaped\\\"quote\""), "Escaped quote inside boundary rejected");

        // 5. Escaped backslash inside boundary rejected (backslash is not an RFC 2046 bchar)
        sub.assert_false(wing::validate_boundary_string("\"escaped\\\\pair\""), "Escaped backslash inside boundary rejected");

        // 6. Unclosed quote rejected
        sub.assert_false(wing::validate_boundary_string("\"unclosed-boundary"), "Unclosed quoted boundary rejected");

        // 7. Escaped terminal quote rejected
        sub.assert_false(wing::validate_boundary_string("\"escaped-terminal\\\""), "Escaped terminal quote rejected");

        // 8. Empty quotes rejected (length 0)
        sub.assert_false(wing::validate_boundary_string("\"\""), "Empty quoted boundary rejected");

        // 9. Quoted boundary with invalid character rejected
        sub.assert_false(wing::validate_boundary_string("\"bad@boundary\""), "Quoted boundary with @ rejected");

        // 10. parse_multipart with quoted boundary parameter
        var body: u8[>..] = [];
        body.append("--QuotedBnd\r\n");
        body.append("Content-Disposition: form-data; name=\"msg\"\r\n\r\n");
        body.append("hello quoted\r\n");
        body.append("--QuotedBnd--\r\n");

        let msg, err = wing::parse_multipart(body[..], "\"QuotedBnd\"");
        sub.assert_eq(err, wing::MultipartError.None, "parse_multipart unquotes boundary and matches wire delimiters");
        sub.assert_true(msg.valid, "Message valid");
        sub.assert_eq(msg.parts.len, 1, "1 part extracted");
        sub.assert_bytes_eq(msg.parts[0].data, "hello quoted", "Part body extracted correctly");
    };

    t.run("Byte-Range PATCH Validation Syntax & Wildcards (draft-wright)") { sub =>
        // 1. Wildcard complete-length: bytes 0-9/* (accepted)
        let s_wc, e_wc, ok_wc = wing::validate_byterange_patch("bytes 0-9/*", 10);
        sub.assert_true(ok_wc, "Wildcard complete-length bytes 0-9/* accepted");
        sub.assert_eq(s_wc, 0, "Start 0");
        sub.assert_eq(e_wc, 9, "End 9");

        // 2. Wildcard range interval: bytes */* (rejected)
        let s_wc2, e_wc2, ok_wc2 = wing::validate_byterange_patch("bytes */*", 0);
        sub.assert_false(ok_wc2, "Wildcard range bytes */* rejected in PATCH");

        // 3. Inverted range interval: bytes 50-20/100 (start > end, rejected)
        let s_inv, e_inv, ok_inv = wing::validate_byterange_patch("bytes 50-20/100", 10);
        sub.assert_false(ok_inv, "Inverted range bytes 50-20/100 rejected");

        // 4. Negative offset: bytes -10-20/100 (rejected)
        let s_neg, e_neg, ok_neg = wing::validate_byterange_patch("bytes -10-20/100", 10);
        sub.assert_false(ok_neg, "Negative start offset rejected");

        // 5. Non-numeric range characters: bytes 0-abc/100 (rejected)
        let s_nan, e_nan, ok_nan = wing::validate_byterange_patch("bytes 0-abc/100", 10);
        sub.assert_false(ok_nan, "Non-numeric range characters rejected");

        // 6. Non-numeric total characters: bytes 0-9/xyz (rejected)
        let s_nan_tot, e_nan_tot, ok_nan_tot = wing::validate_byterange_patch("bytes 0-9/xyz", 10);
        sub.assert_false(ok_nan_tot, "Non-numeric total length rejected");

        // 7. Complete length <= end byte: bytes 0-9/5 (rejected)
        let s_short, e_short, ok_short = wing::validate_byterange_patch("bytes 0-9/5", 10);
        sub.assert_false(ok_short, "Complete length <= last byte rejected");

        // 8. Missing complete length: bytes 0-9/ (rejected)
        let s_miss, e_miss, ok_miss = wing::validate_byterange_patch("bytes 0-9/", 10);
        sub.assert_false(ok_miss, "Missing complete length after slash rejected");

        // 9. Negative body length: bytes 0-9/10 with body_len = -1 (rejected)
        let s_neg_len, e_neg_len, ok_neg_len = wing::validate_byterange_patch("bytes 0-9/10", -1);
        sub.assert_false(ok_neg_len, "Negative body length rejected");
    };

    t.run("Maximum Parts and Memory Accounting Boundary Conditions") { sub =>
        let boundary = "QuotaBnd";
        var body_3parts: u8[>..] = [];
        body_3parts.append("--QuotaBnd\r\nContent-Disposition: form-data; name=\"p1\"\r\n\r\nv1\r\n");
        body_3parts.append("--QuotaBnd\r\nContent-Disposition: form-data; name=\"p2\"\r\n\r\nv2\r\n");
        body_3parts.append("--QuotaBnd\r\nContent-Disposition: form-data; name=\"p3\"\r\n\r\nv3\r\n");
        body_3parts.append("--QuotaBnd--\r\n");

        // Exactly max_parts: 3 parts with max_parts = 3 succeeds
        var opts_exact = wing::default_multipart_options();
        opts_exact.max_parts = 3;
        let msg_exact, err_exact = wing::parse_multipart(body_3parts[..], boundary, opts_exact);
        sub.assert_eq(err_exact, wing::MultipartError.None, "Exactly max_parts (3 of 3) succeeds");
        sub.assert_true(msg_exact.valid, "Exact parts count valid");
        sub.assert_eq(msg_exact.parts.len, 3, "All 3 parts parsed");

        // Exceeding max_parts by 1: 3 parts with max_parts = 2 rejected
        var opts_exceed = wing::default_multipart_options();
        opts_exceed.max_parts = 2;
        let msg_exceed, err_exceed = wing::parse_multipart(body_3parts[..], boundary, opts_exceed);
        sub.assert_eq(err_exceed, wing::MultipartError.ExceededMaxParts, "max_parts + 1 rejected with ExceededMaxParts");
        sub.assert_false(msg_exceed.valid, "Exceeded parts invalid");

        // max_parts = 0 rejected immediately
        var opts_zero = wing::default_multipart_options();
        opts_zero.max_parts = 0;
        let msg_zero, err_zero = wing::parse_multipart(body_3parts[..], boundary, opts_zero);
        sub.assert_eq(err_zero, wing::MultipartError.ExceededMaxParts, "max_parts = 0 rejected with ExceededMaxParts");
        sub.assert_false(msg_zero.valid, "Zero max_parts invalid");

        // Memory quota boundary: calculate total header + body bytes of first part
        // Content-Disposition: form-data; name="p1"\r\n (45 bytes) + v1 (2 bytes) = 47 bytes
        var opts_mem = wing::default_multipart_options();
        opts_mem.max_memory_bytes = 46; // 1 byte less than part 1 requires
        let msg_mem, err_mem = wing::parse_multipart(body_3parts[..], boundary, opts_mem);
        sub.assert_eq(err_mem, wing::MultipartError.ExceededMaxMemory, "Memory quota boundary enforced with ExceededMaxMemory");
        sub.assert_false(msg_mem.valid, "Memory exceeded message invalid");
    };
}

// ---- consolidated suite entry point ---------------------------------------

// --- Component: http_multipart_range_bounds ---
// Tests for multipart form-data and HTTP range parser bounds and edge cases.

// ----------------------------------------------------------------------------
// 1. 64-Bit Integer Overflow in RFC 9110 Range Offsets & parse_i64_slice
// ----------------------------------------------------------------------------
fn test_range_offset_i64_overflow(t: core::T&) {
    t.run("parse_i64_slice Rejects Values >= 2^63 and Multi-Digit Overflows") { sub =>
        // Boundary: 2^63 - 1 (9223372036854775807) is maximum signed positive i64
        let val_max, ok_max = wing::parse_i64_slice("9223372036854775807");
        sub.assert_true(ok_max, "i64::MAX (9223372036854775807) must parse successfully");
        sub.assert_eq(val_max, 9223372036854775807, "Exact i64::MAX value preserved");

        // 2^63 (9223372036854775808): signed overflow to negative in C
        let val_ovf1, ok_ovf1 = wing::parse_i64_slice("9223372036854775808");
        sub.assert_false(ok_ovf1, "2^63 (9223372036854775808) must be rejected with ok=false");

        // 2^64 (18446744073709551616): wraps to 0 in 64-bit unsigned/signed arithmetic
        let val_ovf2, ok_ovf2 = wing::parse_i64_slice("18446744073709551616");
        sub.assert_false(ok_ovf2, "2^64 (18446744073709551616) must be rejected with ok=false");

        // Extreme 20-digit overflow (99999999999999999999)
        let val_ovf3, ok_ovf3 = wing::parse_i64_slice("99999999999999999999");
        sub.assert_false(ok_ovf3, "20-digit value (99999999999999999999) must be rejected with ok=false");

        // Multi-limb extreme digits
        let val_ovf4, ok_ovf4 = wing::parse_i64_slice("123456789012345678901234567890");
        sub.assert_false(ok_ovf4, "30-digit value must be rejected with ok=false");

        // Leading zeros on valid value
        let val_zero, ok_zero = wing::parse_i64_slice("00000000000000000042");
        sub.assert_true(ok_zero, "Leading zeros on valid value 42 must succeed");
        sub.assert_eq(val_zero, 42, "Value 42 parsed accurately despite leading zeros");
    };

    t.run("RFC 9110 parse_range_header Rejects Overflowing Range Offsets") { sub =>
        let file_len: i64 = 1000;

        // Open prefix with 2^64 (wraps to 0 without overflow guard)
        let rs_ovf1, err_ovf1 = wing::parse_range_header("bytes=18446744073709551616-", file_len);
        sub.assert_eq(err_ovf1, wing::RangeError.MalformedRange, "bytes=2^64- must return MalformedRange");

        // Open prefix with 2^63 (9223372036854775808-)
        let rs_ovf2, err_ovf2 = wing::parse_range_header("bytes=9223372036854775808-", file_len);
        sub.assert_eq(err_ovf2, wing::RangeError.MalformedRange, "bytes=2^63- must return MalformedRange");

        // Explicit interval with overflowing end offset (bytes=0-18446744073709551616)
        let rs_ovf3, err_ovf3 = wing::parse_range_header("bytes=0-18446744073709551616", file_len);
        sub.assert_eq(err_ovf3, wing::RangeError.MalformedRange, "bytes=0-2^64 must return MalformedRange");

        // Suffix interval with overflowing offset (bytes=-18446744073709551626)
        let rs_ovf4, err_ovf4 = wing::parse_range_header("bytes=-18446744073709551626", file_len);
        sub.assert_eq(err_ovf4, wing::RangeError.MalformedRange, "bytes=-(2^64+10) must return MalformedRange");

        // 20-digit overflow
        let rs_ovf5, err_ovf5 = wing::parse_range_header("bytes=99999999999999999999-", file_len);
        sub.assert_eq(err_ovf5, wing::RangeError.MalformedRange, "20-digit range offset must return MalformedRange");
    };

    t.run("draft-wright validate_byterange_patch Rejects Overflowing Offsets") { sub =>
        // 2^64 in PATCH range header
        let s_p, e_p, ok_p = wing::validate_byterange_patch("bytes 18446744073709551616-18446744073709551625/1000", 10);
        sub.assert_false(ok_p, "PATCH with 2^64 offset must be rejected");

        // Valid boundary PATCH range
        let s_ok, e_ok, ok_valid = wing::validate_byterange_patch("bytes 0-9/1000", 10);
        sub.assert_true(ok_valid, "Valid PATCH range must be accepted");
        sub.assert_eq(s_ok, 0, "Start offset 0");
        sub.assert_eq(e_ok, 9, "End offset 9");
    };
}

// ----------------------------------------------------------------------------
// 2. Multipart Delimiter Search & Line Endings (LF vs CRLF Compliance)
// ----------------------------------------------------------------------------
fn test_multipart_lf_delimiter_and_line_endings(t: core::T&) {
    t.run("LF-Only Line Endings in Multipart Form-Data") { sub =>
        // Valid RFC 7578 / RFC 2046 multipart with UNIX LF ('\n') line endings
        let boundary = "GooseLFBoundary42";
        var body: u8[>..] = [];
        body.append("--GooseLFBoundary42\n");
        body.append("Content-Disposition: form-data; name=\"user\"\n\n");
        body.append("alice\n");
        body.append("--GooseLFBoundary42\n");
        body.append("Content-Disposition: form-data; name=\"file\"; filename=\"hello.txt\"\n");
        body.append("Content-Type: text/plain\n\n");
        body.append("hello world\n");
        body.append("--GooseLFBoundary42--\n");

        let msg, err = wing::parse_multipart(body[..], boundary);
        sub.assert_eq(err, wing::MultipartError.None, "LF multipart parsed cleanly with None error");
        sub.assert_true(msg.valid, "Message marked valid for LF body");
        sub.assert_eq(msg.parts.len, 2, "Exactly 2 parts parsed from LF body");

        // Part 1 validation
        let p1 = msg.parts[0];
        sub.assert_bytes_eq(p1.name[..], "user", "Part 1 name is 'user'");
        sub.assert_bytes_eq(p1.data, "alice", "Part 1 data is 'alice' without trailing delimiter newline");

        // Part 2 validation
        let p2 = msg.parts[1];
        sub.assert_bytes_eq(p2.name[..], "file", "Part 2 name is 'file'");
        sub.assert_bytes_eq(p2.filename[..], "hello.txt", "Part 2 filename is 'hello.txt'");
        sub.assert_bytes_eq(p2.content_type[..], "text/plain", "Part 2 content-type is text/plain");
        sub.assert_bytes_eq(p2.data, "hello world", "Part 2 data is 'hello world' without trailing newline");
    };

    t.run("Mixed CRLF and LF Line Endings Across Multipart Parts") { sub =>
        // Part 1 uses CRLF; Part 2 uses LF; Closing delimiter uses CRLF
        let boundary = "GooseMixedBoundary";
        var body: u8[>..] = [];
        body.append("--GooseMixedBoundary\r\n");
        body.append("Content-Disposition: form-data; name=\"crlf_part\"\r\n\r\n");
        body.append("alpha\r\n");
        body.append("--GooseMixedBoundary\n");
        body.append("Content-Disposition: form-data; name=\"lf_part\"\n\n");
        body.append("beta\n");
        body.append("--GooseMixedBoundary--\r\n");

        let msg, err = wing::parse_multipart(body[..], boundary);
        sub.assert_eq(err, wing::MultipartError.None, "Mixed CRLF/LF multipart parsed cleanly");
        sub.assert_true(msg.valid, "Message valid with mixed line endings");
        sub.assert_eq(msg.parts.len, 2, "2 parts extracted");
        sub.assert_bytes_eq(msg.parts[0].data, "alpha", "Part 1 data exact");
        sub.assert_bytes_eq(msg.parts[1].data, "beta", "Part 2 data exact");
    };

    t.run("Initial Boundary in Preamble Requires Line Start") { sub =>
        // Preamble containing substring that looks like boundary but is not at line start
        let boundary = "TrueBnd";
        var body: u8[>..] = [];
        body.append("Random preamble containing bogus--TrueBnd text\r\n");
        body.append("--TrueBnd\r\n");
        body.append("Content-Disposition: form-data; name=\"field\"\r\n\r\n");
        body.append("value\r\n");
        body.append("--TrueBnd--\r\n");

        let msg, err = wing::parse_multipart(body[..], boundary);
        sub.assert_eq(err, wing::MultipartError.None, "Preamble with embedded boundary substring handled");
        sub.assert_true(msg.valid, "Valid message despite preamble");
        sub.assert_eq(msg.parts.len, 1, "Exactly 1 real part extracted");
        sub.assert_bytes_eq(msg.parts[0].name[..], "field", "Field name matches");
        sub.assert_bytes_eq(msg.parts[0].data, "value", "Field data matches");
    };
}

// ----------------------------------------------------------------------------
// 3. Algorithmic Limits & Range Coalescing Edge Cases
// ----------------------------------------------------------------------------
fn test_range_limits_and_coalescing(t: core::T&) {
    t.run("RFC 9110 Coalescing with Large 64-Bit Boundaries Without Overflow") { sub =>
        let res_len: i64 = 9223372036854775806;
        // Overlapping adjacent intervals at high 64-bit offsets:
        // bytes=1000-2000, 2001-3000 -> merged [1000, 3000]
        let rs, err = wing::parse_range_header("bytes=1000-2000, 2001-3000", res_len, true);
        sub.assert_eq(err, wing::RangeError.None, "High offset range parsed");
        sub.assert_true(rs.coalesced, "Coalescing flag active");
        sub.assert_eq(rs.ranges.len, 1, "Merged to 1 range");
        sub.assert_eq(rs.ranges[0].start, 1000, "Merged start 1000");
        sub.assert_eq(rs.ranges[0].end_pos, 3000, "Merged end 3000");
    };

    t.run("Algorithmic Limit on Empty Elements Defends Against Denial of Service") { sub =>
        // > 16 empty comma elements
        let rs_dos, err_dos = wing::parse_range_header("bytes=,,,,,,,,,,,,,,,,,,0-10", 100);
        sub.assert_eq(err_dos, wing::RangeError.TooManyEmptyElements, "Excessive empty elements rejected");
    };

    t.run("Range bytes=-0 Must Be Rejected as Malformed") { sub =>
        // RFC 9110: bytes=-0 requests 0 bytes from suffix, which is invalid
        let rs, err = wing::parse_range_header("bytes=-0", 1000);
        sub.assert_eq(err, wing::RangeError.MalformedRange, "bytes=-0 must return MalformedRange, not 206 with invalid Content-Range");
    };

    t.run("Case-Insensitive Bytes= Unit Accepted") { sub =>
        let rs1, err1 = wing::parse_range_header("BYTES=0-100", 1000);
        sub.assert_eq(err1, wing::RangeError.None, "Uppercase BYTES= must be accepted");
        sub.assert_eq(rs1.ranges.len, 1);

        let rs2, err2 = wing::parse_range_header("Bytes=0-100", 1000);
        sub.assert_eq(err2, wing::RangeError.None, "Mixed case Bytes= must be accepted");
    };

    t.run("Unsupported Range Unit Returns InvalidUnit") { sub =>
        let rs, err = wing::parse_range_header("items=0-10", 1000);
        sub.assert_eq(err, wing::RangeError.InvalidUnit, "Unsupported unit 'items' must return InvalidUnit");
    };
}

// ----------------------------------------------------------------------------
// 4. MIME Headers Memory Limit Bypass (#81741 / CVE-2026-94440)
// ----------------------------------------------------------------------------
fn test_mime_headers_memory_limit_bypass(t: core::T&) {
    t.run("MIME Header Memory Limit Enforced with Remaining Quota < 400 Bytes (#81741 / CVE-2026-94440)") { sub =>
        let boundary = "GooseMemBnd";
        var body: u8[>..] = [];
        body.append("--GooseMemBnd\r\n");
        body.append("Content-Disposition: form-data; name=\"p1\"\r\n\r\n");
        body.append("data-segment-1\r\n"); // 14 bytes
        body.append("--GooseMemBnd\r\n");
        body.append("Content-Disposition: form-data; name=\"p2\"\r\n\r\n");
        body.append("data-segment-2-overflowing-remaining-budget\r\n");
        body.append("--GooseMemBnd--\r\n");

        // Quota: 25 bytes total memory. Part 1 takes 14 bytes. Remaining budget is 11 bytes (< 400 bytes).
        // Part 2 has 43 bytes, which exceeds remaining 11 bytes.
        var opts = wing::default_multipart_options();
        opts.max_memory_bytes = 25;

        let msg, err = wing::parse_multipart(body[..], boundary, opts);
        sub.assert_eq(err, wing::MultipartError.ExceededMaxMemory, "Memory limit strictly enforced when remaining quota < 400 bytes");
        sub.assert_false(msg.valid, "Message marked invalid upon memory limit breach");
    };

    t.run("Oversized Part Header Exceeding max_header_bytes Rejected (#81741, #1528, #26339)") { sub =>
        let boundary = "GooseHdrBnd";
        var body: u8[>..] = [];
        body.append("--GooseHdrBnd\r\n");
        body.append("Content-Disposition: form-data; name=\"oversized\"\r\n");
        body.append("X-Custom-Exploit-Header: ");
        // Generate header line exceeding max_header_bytes (500 bytes for this test)
        for i in 600 {
            body.push('A');
        }
        body.append("\r\n\r\n");
        body.append("payload\r\n");
        body.append("--GooseHdrBnd--\r\n");

        var opts = wing::default_multipart_options();
        opts.max_header_bytes = 500; // Small limit to test bounded scan

        let msg, err = wing::parse_multipart(body[..], boundary, opts);
        sub.assert_eq(err, wing::MultipartError.InvalidPartHeaders, "Header line exceeding max_header_bytes rejected without memory bypass");
        sub.assert_false(msg.valid, "Message marked invalid on oversized header");
    };

    t.run("Zero-Memory and Strict Quotas Trap Runaway Payloads") { sub =>
        let boundary = "GooseZeroMem";
        var body: u8[>..] = [];
        body.append("--GooseZeroMem\r\n");
        body.append("Content-Disposition: form-data; name=\"val\"\r\n\r\n");
        body.append("x\r\n");
        body.append("--GooseZeroMem--\r\n");

        var opts = wing::default_multipart_options();
        opts.max_memory_bytes = 0;

        let msg, err = wing::parse_multipart(body[..], boundary, opts);
        sub.assert_eq(err, wing::MultipartError.ExceededMaxMemory, "Zero memory budget triggers ExceededMaxMemory on any part data");
        sub.assert_false(msg.valid, "Invalid message on zero budget");
    };
}

// ----------------------------------------------------------------------------
// 5. Range Header Size and Count Limits (#81858 / CVE-2026-78667)
// ----------------------------------------------------------------------------
fn test_range_header_size_and_count_limits(t: core::T&) {
    t.run("200+ Ranges Requested Rejected in O(1) Time (#81858 / CVE-2026-78667)") { sub =>
        // In , a Range header with > 200 ranges caused CPU exhaustion.
        // In naive implementations, ose, max_ranges is 16 by default. It must reject at range 17 in O(1) time.
        var attack_hdr: u8[>..] = "bytes=";
        for i in 205 {
            if i > 0 { attack_hdr.append(", "); }
            format(attack_hdr, i * 2);
            attack_hdr.push('-');
            format(attack_hdr, i * 2 + 1);
        }

        let rs, err = wing::parse_range_header(attack_hdr[..], 10000);
        sub.assert_eq(err, wing::RangeError.ExceededMaxRanges, "205-range attack rejected at range index 16 without CPU exhaustion");
        sub.assert_eq(rs.ranges.len, 0, "No ranges returned on exceeded max ranges");
    };

    t.run("500+ Extreme Ranges Rejection Stress (#81858)") { sub =>
        var big_attack: u8[>..] = "bytes=";
        for i in 500 {
            if i > 0 { big_attack.append(","); }
            format(big_attack, i);
            big_attack.push('-');
            format(big_attack, i + 1);
        }

        let rs, err = wing::parse_range_header(big_attack[..], 50000);
        sub.assert_eq(err, wing::RangeError.ExceededMaxRanges, "500-range attack rejected cleanly");
    };

    t.run("Comma Flooding and Empty Element Abuse (CVE-2011-3192 Denial of Service)") { sub =>
        // 20 empty elements
        let rs_empty, err_empty = wing::parse_range_header("bytes=,,,,,,,,,,,,,,,,,,,,0-10", 1000);
        sub.assert_eq(err_empty, wing::RangeError.TooManyEmptyElements, "Exceeding 16 empty elements rejected");

        // 16 empty elements allowed, followed by valid range
        let rs_valid, err_valid = wing::parse_range_header("bytes=,,,,,,,,,,,,,,,,0-10", 1000);
        sub.assert_eq(err_valid, wing::RangeError.None, "16 empty elements within ceiling accepted");
        sub.assert_eq(rs_valid.ranges.len, 1, "1 valid range extracted");
    };
}

// ----------------------------------------------------------------------------
// 6. Delimiter Line-Ending Desync and Transport Padding
// ----------------------------------------------------------------------------
fn test_delimiter_line_ending_desync(t: core::T&) {
    t.run("Pure Bare UNIX LF Delimiters Across All Parts") { sub =>
        let boundary = "PureLF";
        var body: u8[>..] = [];
        body.append("--PureLF\n");
        body.append("Content-Disposition: form-data; name=\"field1\"\n\n");
        body.append("value1\n");
        body.append("--PureLF\n");
        body.append("Content-Disposition: form-data; name=\"field2\"\n\n");
        body.append("value2\n");
        body.append("--PureLF--\n");

        let msg, err = wing::parse_multipart(body[..], boundary);
        sub.assert_eq(err, wing::MultipartError.None, "Pure LF delimiters parsed with None error");
        sub.assert_true(msg.valid, "Valid message");
        sub.assert_eq(msg.parts.len, 2, "2 parts extracted");
        sub.assert_bytes_eq(msg.parts[0].data, "value1", "Part 1 data value1");
        sub.assert_bytes_eq(msg.parts[1].data, "value2", "Part 2 data value2");
    };

    t.run("Part Data Ending in CR Before Delimiter Preserved Accurately") { sub =>
        // If data contains \r before \r\n--boundary, the trailing \r in "hello\r" is part of the body
        let boundary = "CrBnd";
        var body: u8[>..] = [];
        body.append("--CrBnd\r\n");
        body.append("Content-Disposition: form-data; name=\"cr_data\"\r\n\r\n");
        body.append("hello\r\r\n");
        body.append("--CrBnd--\r\n");

        let msg, err = wing::parse_multipart(body[..], boundary);
        sub.assert_eq(err, wing::MultipartError.None, "CR body parsed cleanly");
        sub.assert_true(msg.valid, "Valid message");
        sub.assert_eq(msg.parts.len, 1, "1 part extracted");
        sub.assert_bytes_eq(msg.parts[0].data, "hello\r", "Body ends with embedded carriage return");
    };

    t.run("RFC 2046 Section 5.1.1 Transport Padding on Boundaries") { sub =>
        // Boundary followed by linear whitespace (spaces and tabs) before CRLF
        let boundary = "PadBnd";
        var body: u8[>..] = [];
        body.append("--PadBnd   \r\n");
        body.append("Content-Disposition: form-data; name=\"padded\"\r\n\r\n");
        body.append("content\r\n");
        body.append("--PadBnd-- \t \r\n");

        let msg, err = wing::parse_multipart(body[..], boundary);
        sub.assert_eq(err, wing::MultipartError.None, "Transport padding on delimiters accepted per RFC 2046");
        sub.assert_true(msg.valid, "Valid message with padded boundaries");
        sub.assert_eq(msg.parts.len, 1, "1 part parsed");
        sub.assert_bytes_eq(msg.parts[0].data, "content", "Content matches");
    };
}

// ----------------------------------------------------------------------------
// 7. 10,000+ Parts Boundary Flood & Memory Limits (#59153 / CVE-2023-24536)
// ----------------------------------------------------------------------------
fn test_multipart_part_count_fuzzing(t: core::T&) {
    t.run("1,000-Part Request Aborted by Default max_parts (#59153 / CVE-2023-24536)") { sub =>
        let boundary = "FloodBnd";
        var body: u8[>..] = [];
        // Generate 1000 parts
        for i in 1000 {
            body.append("--FloodBnd\r\n");
            body.append("Content-Disposition: form-data; name=\"f\"\r\n\r\n");
            body.append("x\r\n");
        }
        body.append("--FloodBnd--\r\n");

        // Default max_parts is 64
        let msg, err = wing::parse_multipart(body[..], boundary);
        sub.assert_eq(err, wing::MultipartError.ExceededMaxParts, "1,000-part flood intercepted at max_parts quota");
        sub.assert_false(msg.valid, "Message marked invalid on part quota breach");
    };

    t.run("High Part Quota with Strict Memory Budget Traps Exhaustion (#58006 / CVE-2022-41725)") { sub =>
        let boundary = "MemFloodBnd";
        var body: u8[>..] = [];
        for i in 200 {
            body.append("--MemFloodBnd\r\n");
            body.append("Content-Disposition: form-data; name=\"f\"\r\n\r\n");
            body.append("0123456789abcdef\r\n"); // 16 bytes per part
        }
        body.append("--MemFloodBnd--\r\n");

        var opts = wing::default_multipart_options();
        opts.max_parts = 500;
        opts.max_memory_bytes = 500; // Cap memory at 500 bytes (exceeded around part 31)

        let msg, err = wing::parse_multipart(body[..], boundary, opts);
        sub.assert_eq(err, wing::MultipartError.ExceededMaxMemory, "Memory ceiling strictly terminates multi-part ingestion");
        sub.assert_false(msg.valid, "Message invalid on memory exhaustion");
    };

    t.run("Rapid Ingestion of 50 Empty Parts Without Heap Allocation") { sub =>
        let boundary = "EmptyPartsBnd";
        var body: u8[>..] = [];
        for i in 50 {
            body.append("--EmptyPartsBnd\r\n");
            body.append("Content-Disposition: form-data; name=\"empty\"\r\n\r\n");
            body.append("\r\n");
        }
        body.append("--EmptyPartsBnd--\r\n");

        var opts = wing::default_multipart_options();
        opts.max_parts = 64;

        let msg, err = wing::parse_multipart(body[..], boundary, opts);
        sub.assert_eq(err, wing::MultipartError.None, "50 empty parts parsed cleanly");
        sub.assert_true(msg.valid, "Valid message");
        sub.assert_eq(msg.parts.len, 50, "50 parts successfully extracted into zero-heap structure");
    };
}

// ----------------------------------------------------------------------------
// 8. Malformed Boundary Quoting and RFC 2046 Validation
// ----------------------------------------------------------------------------
fn test_malformed_boundary_quoting_and_lexical(t: core::T&) {
    t.run("RFC 2046 Section 5.1.1 Boundary Length Bounds (0, 70, 71 Chars)") { sub =>
        // Empty boundary: length 0
        sub.assert_false(wing::validate_boundary_string(""), "0-length boundary rejected");

        // 70-character boundary: exact upper limit
        var b70: u8[..70] = [];
        for i in 70 {
            b70.push('a');
        }
        sub.assert_true(wing::validate_boundary_string(b70[..]), "70-character boundary valid per RFC 2046");

        // 71-character boundary: rejected
        var b71: u8[..72] = [];
        for i in 71 {
            b71.push('a');
        }
        sub.assert_false(wing::validate_boundary_string(b71[..]), "71-character boundary rejected (> 70 chars)");
    };

    t.run("RFC 2046 Boundary Character Set Validation") { sub =>
        // Valid special characters: ' ( ) + _ , - . / : = ?
        sub.assert_true(wing::validate_boundary_string("abc-123_XYZ:+=?().,'/+"), "All RFC 2046 bchars accepted");

        // Invalid characters: @, [, ], {, }, <, >, ;, CTL
        sub.assert_false(wing::validate_boundary_string("bad@boundary"), "@ rejected");
        sub.assert_false(wing::validate_boundary_string("bad[boundary"), "[ rejected");
        sub.assert_false(wing::validate_boundary_string("bad]boundary"), "] rejected");
        sub.assert_false(wing::validate_boundary_string("bad{boundary"), "{ rejected");
        sub.assert_false(wing::validate_boundary_string("bad;boundary"), "; rejected");
        sub.assert_false(wing::validate_boundary_string("bad\x00boundary"), "NUL rejected");
        sub.assert_false(wing::validate_boundary_string("bad\r\nboundary"), "CRLF injection in boundary rejected");
    };

    t.run("Chromium StrictUnquote Boundary Quoting Invariants") { sub =>
        // 1. Quoted valid boundary
        var out1: u8[>..] = [];
        let ok1 = wing::strict_unquote("\"valid-boundary-123\"", out1);
        sub.assert_true(ok1, "Quoted boundary unquoted successfully");
        sub.assert_bytes_eq(out1[..], "valid-boundary-123", "Unquoted boundary string exact");

        // 2. Unclosed quote: rejected
        var out2: u8[>..] = [];
        let ok2 = wing::strict_unquote("\"unclosed-boundary", out2);
        sub.assert_false(ok2, "Unclosed quote rejected");

        // 3. Single quotes: rejected
        var out3: u8[>..] = [];
        let ok3 = wing::strict_unquote("'single-quoted'", out3);
        sub.assert_false(ok3, "Single quotes rejected by StrictUnquote");

        // 4. Escaped terminal quote: rejected
        var out4: u8[>..] = [];
        let ok4 = wing::strict_unquote("\"escaped-quote\\\"", out4);
        sub.assert_false(ok4, "Escaped terminal quote rejected");

        // 5. Escaped pairs within boundary: \\ decoded
        var out5: u8[>..] = [];
        let ok5 = wing::strict_unquote("\"escaped\\\\pair\"", out5);
        sub.assert_true(ok5, "Escaped backslash accepted");
        sub.assert_bytes_eq(out5[..], "escaped\\pair", "Decoded escaped backslash");
    };

    t.run("Content-Type Header Boundary Parameter Parsing") { sub =>
        // Boundary with semicolon inside quotes: boundary="foo;bar"
        let ct1, ok1 = wing::parse_media_type("multipart/form-data; boundary=\"foo;bar\"");
        sub.assert_true(ok1, "Content-Type with quoted semicolon in boundary parsed");
        sub.assert_bytes_eq(wing::boundary(ct1), "foo;bar", "Boundary parameter preserved with semicolon");

        // Unquoted boundary
        let ct2, ok2 = wing::parse_media_type("multipart/form-data; boundary=my-boundary-42");
        sub.assert_true(ok2, "Unquoted boundary parsed");
        sub.assert_bytes_eq(wing::boundary(ct2), "my-boundary-42", "Unquoted boundary matches");
    };
}

// ----------------------------------------------------------------------------
// 9. ReDoS Resistance and Nested Boundary Isolation (#10616, #14085)
// ----------------------------------------------------------------------------
fn test_redos_and_nested_boundaries(t: core::T&) {
    t.run("Prefix Collision: Inner Boundary Has Outer Boundary as Prefix (#10616)") { sub =>
        // outer boundary is a prefix of inner boundary
        let outer_bnd = "NextPart_12345";
        var body: u8[>..] = [];
        body.append("--NextPart_12345\r\n");
        body.append("Content-Disposition: form-data; name=\"outer_field\"\r\n\r\n");
        body.append("prefix data: --NextPart_12345_alt and inner payload\r\n");
        body.append("--NextPart_12345--\r\n");

        let msg, err = wing::parse_multipart(body[..], outer_bnd);
        sub.assert_eq(err, wing::MultipartError.None, "Prefix collision parsed without premature EOF");
        sub.assert_true(msg.valid, "Valid message");
        sub.assert_eq(msg.parts.len, 1, "Exactly 1 outer part extracted");
        sub.assert_bytes_eq(msg.parts[0].data, "prefix data: --NextPart_12345_alt and inner payload", "Inner data with boundary prefix intact");
    };

    t.run("Boundary Substring Without Preceding Newline Treated as Body Data (#14085)") { sub =>
        // part contains --boundary inside a line
        let boundary = "MidLineBnd";
        var body: u8[>..] = [];
        body.append("--MidLineBnd\r\n");
        body.append("Content-Disposition: form-data; name=\"msg\"\r\n\r\n");
        body.append("This is text containing --MidLineBnd right in the middle of a line!\r\n");
        body.append("--MidLineBnd--\r\n");

        let msg, err = wing::parse_multipart(body[..], boundary);
        sub.assert_eq(err, wing::MultipartError.None, "Mid-line boundary substring does not break parsing");
        sub.assert_true(msg.valid, "Valid message");
        sub.assert_eq(msg.parts.len, 1, "1 part extracted");
        sub.assert_bytes_eq(msg.parts[0].data, "This is text containing --MidLineBnd right in the middle of a line!", "Body text preserved intact");
    };

    t.run("Nested Multipart Document Extraction") { sub =>
        let outer_bnd = "OuterBnd";
        let inner_bnd = "InnerBnd";

        var inner_doc: u8[>..] = [];
        inner_doc.append("--InnerBnd\r\n");
        inner_doc.append("Content-Disposition: form-data; name=\"inner_f\"\r\n\r\n");
        inner_doc.append("nested-value\r\n");
        inner_doc.append("--InnerBnd--\r\n");

        var outer_doc: u8[>..] = [];
        outer_doc.append("--OuterBnd\r\n");
        outer_doc.append("Content-Type: multipart/mixed; boundary=\"InnerBnd\"\r\n\r\n");
        outer_doc.append(inner_doc[..]);
        outer_doc.append("\r\n--OuterBnd--\r\n");

        // Parse outer
        let outer_msg, outer_err = wing::parse_multipart(outer_doc[..], outer_bnd);
        sub.assert_eq(outer_err, wing::MultipartError.None, "Outer multipart parsed");
        sub.assert_true(outer_msg.valid, "Outer message valid");
        sub.assert_eq(outer_msg.parts.len, 1, "1 outer part");

        // Parse inner
        let inner_msg, inner_err = wing::parse_multipart(outer_msg.parts[0].data, inner_bnd);
        sub.assert_eq(inner_err, wing::MultipartError.None, "Inner multipart parsed cleanly from outer data");
        sub.assert_true(inner_msg.valid, "Inner message valid");
        sub.assert_eq(inner_msg.parts.len, 1, "1 inner part extracted");
        sub.assert_bytes_eq(inner_msg.parts[0].data, "nested-value", "Inner part data exact");
    };

    t.run("ReDoS Resistance: Pathological Hyphen Repetition and BMH Performance") { sub =>
        // 10,000 hyphens in haystack, boundary of 30 hyphens ending in 'X'
        var needle: u8[..32] = [];
        for i in 30 { needle.push('-'); }
        needle.push('X');

        var table: u16[256] = [0; 256];
        wing::build_bmh_shift_table(needle[..], table);

        var haystack: u8[>..] = [];
        for i in 10000 { haystack.push('-'); }
        haystack.push('X'); // Only at the very end

        let pos = wing::bmh_find(haystack[..], needle[..], table, 0);
        sub.assert_eq(pos, 9970, "BMH finds needle at exact offset in linear time without backtracking");
    };
}

// ----------------------------------------------------------------------------
// 10. Content-Disposition Filename Traversal and Edge Cases (#45789, #63629)
// ----------------------------------------------------------------------------
fn test_mime_disposition_and_filename_traversal(t: core::T&) {
    t.run("Directory Path Traversal in Multipart Filename (#45789)") { sub =>
        // filename with directory path (../../etc/shadow or C:\\Windows\\cmd.exe)
        let boundary = "TravBnd";
        var body: u8[>..] = [];
        body.append("--TravBnd\r\n");
        body.append("Content-Disposition: form-data; name=\"avatar\"; filename=\"../../etc/passwd\"\r\n");
        body.append("Content-Type: text/plain\r\n\r\n");
        body.append("root:x:0:0...\r\n");
        body.append("--TravBnd--\r\n");

        let msg, err = wing::parse_multipart(body[..], boundary);
        sub.assert_eq(err, wing::MultipartError.None, "Multipart with traversal filename parsed safely");
        sub.assert_true(msg.valid, "Valid message");
        sub.assert_eq(msg.parts.len, 1, "1 part extracted");
        sub.assert_bytes_eq(msg.parts[0].filename[..], "../../etc/passwd", "Filename extracted verbatim without unsafe filesystem execution");
    };

    t.run("Empty Field Name Part Ingestion (#63629)") { sub =>
        // parts with empty name="" must not be dropped
        let boundary = "EmptyNameBnd";
        var body: u8[>..] = [];
        body.append("--EmptyNameBnd\r\n");
        body.append("Content-Disposition: form-data; name=\"\"; filename=\"upload.bin\"\r\n\r\n");
        body.append("binary-content\r\n");
        body.append("--EmptyNameBnd--\r\n");

        let msg, err = wing::parse_multipart(body[..], boundary);
        sub.assert_eq(err, wing::MultipartError.None, "Empty name part parsed cleanly");
        sub.assert_true(msg.valid, "Valid message");
        sub.assert_eq(msg.parts.len, 1, "Part with empty name retained");
        sub.assert_bytes_eq(msg.parts[0].name[..], "", "Part name is empty string");
        sub.assert_bytes_eq(msg.parts[0].filename[..], "upload.bin", "Filename intact");
    };

    t.run("Optional Filename in Content-Disposition (#19183)") { sub =>
        // filename parameter is optional in RFC 7578
        let boundary = "OptFnBnd";
        var body: u8[>..] = [];
        body.append("--OptFnBnd\r\n");
        body.append("Content-Disposition: form-data; name=\"field_without_filename\"\r\n\r\n");
        body.append("plain-value\r\n");
        body.append("--OptFnBnd--\r\n");

        let msg, err = wing::parse_multipart(body[..], boundary);
        sub.assert_eq(err, wing::MultipartError.None, "Form field without filename parsed");
        sub.assert_true(msg.valid, "Valid message");
        sub.assert_eq(msg.parts.len, 1, "1 part");
        sub.assert_bytes_eq(msg.parts[0].name[..], "field_without_filename", "Field name extracted");
        sub.assert_bytes_eq(msg.parts[0].filename[..], "", "Filename empty when omitted");
    };
}

// ----------------------------------------------------------------------------
// Suite Entry Point
// ----------------------------------------------------------------------------

// --- Component: http_resumable_upload ---
// Verification suite for IETF draft-ietf-httpbis-resumable-upload-14:
// - Creation request formatting with Upload-Complete: ?0 and MIME application/partial-upload
// - Server 201 Created response parsing (Location, Upload-Offset)
// - Chunk append with PATCH, Upload-Offset, and final Upload-Complete: ?1
// - Interruption offset query with HEAD request (RFC 8941 Structured Fields parsing)

fn test_resumable_uploads(t: core::T&) {
    t.run("Upload Session Initialization & Creation Request") { sub =>
        var state = wing::init_resumable_upload(800000, 500000);
        sub.assert_eq(state.total_size, 800000, "Total size is 800KB");
        sub.assert_eq(state.offset, 0, "Initial offset is 0");
        sub.assert_false(state.complete, "Initial complete is false");

        var create_req = wing::Request { .. };
        let chunk1 = "FIRST_CHUNK_DATA_500000_BYTES";
        wing::format_upload_creation_request(create_req, "https://storage.cdn.com/uploads", chunk1, false);

        sub.assert_bytes_eq(create_req.method[..], "POST", "Method is POST");
        sub.assert_bytes_eq(create_req.url[..], "https://storage.cdn.com/uploads", "URL is uploads endpoint");

        sub.assert_true(create_req.has_header("Upload-Complete"), "Upload-Complete present");
        sub.assert_bytes_eq(create_req.header("Upload-Complete"), "?0", "Upload-Complete is ?0 for initial incomplete chunk");
        sub.assert_true(create_req.has_header("Content-Type"), "Content-Type present");
        sub.assert_bytes_eq(create_req.header("Content-Type"), "application/partial-upload", "Content-Type is application/partial-upload");
    };

    t.run("Creation Response Handling & Chunk Append (PATCH)") { sub =>
        var state = wing::init_resumable_upload(800000, 500000);

        // Server responds 201 Created
        var create_resp = wing::Response { status_code: 201, .. };
        create_resp.headers.push(wing::make_header("Location", "https://storage.cdn.com/uploads/session-abc1234"));
        create_resp.headers.push(wing::make_header("Upload-Offset", "500000"));
        create_resp.headers.push(wing::make_header("Upload-Complete", "?0"));

        let ok_handle = wing::handle_creation_response(create_resp, state);
        sub.assert_true(ok_handle, "Creation response handled");
        sub.assert_bytes_eq(state.upload_url[..], "https://storage.cdn.com/uploads/session-abc1234", "Session URL stored");
        sub.assert_eq(state.offset, 500000, "Server offset updated to 500000");
        sub.assert_false(state.complete, "Upload is not complete yet");

        // Format final chunk append (PATCH)
        var patch_req = wing::Request { .. };
        let final_chunk = "FINAL_CHUNK_DATA_300000_BYTES";
        wing::format_upload_chunk_request(patch_req, state, final_chunk, true);

        sub.assert_bytes_eq(patch_req.method[..], "PATCH", "Method is PATCH");
        sub.assert_bytes_eq(patch_req.url[..], "https://storage.cdn.com/uploads/session-abc1234", "PATCH URL is session URL");

        sub.assert_true(patch_req.has_header("Upload-Offset"), "Upload-Offset present");
        sub.assert_bytes_eq(patch_req.header("Upload-Offset"), "500000", "Upload-Offset matches current client state");
        sub.assert_true(patch_req.has_header("Upload-Complete"), "Upload-Complete present");
        sub.assert_bytes_eq(patch_req.header("Upload-Complete"), "?1", "Upload-Complete is ?1 on final chunk");

        // Server responds 204 No Content for PATCH
        var patch_resp = wing::Response { status_code: 204, .. };
        patch_resp.headers.push(wing::make_header("Upload-Offset", "800000"));
        patch_resp.headers.push(wing::make_header("Upload-Complete", "?1"));

        let ok_patch = wing::handle_chunk_response(patch_resp, state);
        sub.assert_true(ok_patch, "Chunk response handled");
        sub.assert_eq(state.offset, 800000, "Offset updated to 800000");
        sub.assert_true(state.complete, "State complete is now true");
    };

    t.run("Interruption Offset Query Recovery (HEAD)") { sub =>
        var state = wing::init_resumable_upload(800000, 500000);
        state.upload_url.append("https://storage.cdn.com/uploads/session-abc1234");
        state.offset = 0; // Simulated connection loss / client restart

        var head_req = wing::Request { .. };
        wing::format_upload_offset_query(head_req, state.upload_url[..]);
        sub.assert_bytes_eq(head_req.method[..], "HEAD", "Offset query is HEAD");

        // Server returns current stored offset 500000
        var head_resp = wing::Response { status_code: 204, .. };
        head_resp.headers.push(wing::make_header("Upload-Offset", "500000"));
        head_resp.headers.push(wing::make_header("Upload-Complete", "?0"));

        let ok_rec = wing::handle_offset_query_response(head_resp, state);
        sub.assert_true(ok_rec, "Offset query response parsed");
        sub.assert_eq(state.offset, 500000, "Offset successfully recovered to 500000");
        sub.assert_false(state.complete, "Complete flag correctly reflects ongoing upload");
    };
}

fn main() {
    var runner = core::new_runner("HTTP MIME, Multipart Form-Data, and Byte Ranges Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Chromium HttpUtil::StrictUnquote Invariants", test_strict_unquote_invariants);
    core::run_case(runner, "2. RFC 9110 Section 8.3 MediaType & Content-Type", test_media_type_parser);
    core::run_case(runner, "3. RFC 8941 Section 3.3.1 sf-integer & Section 3.3.2 sf-decimal", test_sfv_integers_and_decimals);
    core::run_case(runner, "4. RFC 8941 Section 3.3.3 sf-string, Section 3.3.5 sf-binary & keys", test_sfv_strings_tokens_and_keys);
    core::run_case(runner, "5. RFC 9651 sf-date & sf-displaystring (UTF-8)", test_sfv_rfc9651_dates_and_display_strings);
    core::run_case(runner, "6. RFC 8941 Section 3.1 Lists & Section 3.2 Dictionaries", test_sfv_lists_and_dictionaries);
    core::run_case(runner, "7. Streaming Multipart Parsing & Metadata", test_streaming_multipart_parsing);
    core::run_case(runner, "8. CVE-2026-19484 Boundary Cap & 16-Bit BMH", test_cve_2026_19484_boundary_and_bmh_table);
    core::run_case(runner, "9. RFC 9110 Range Request Forms & 416", test_rfc9110_range_requests);
    core::run_case(runner, "10. CVE-2011-3192 Apache Killer Defense & Coalescing", test_cve_2011_3192_apache_killer_and_coalescing);
    core::run_case(runner, "11. If-Range & Seconds Truncation", test_if_range_and_seconds_truncation);
    core::run_case(runner, "12. Window Reader serve_range & Byte-Range PATCH", test_serve_range_and_patch_validation);
    core::run_case(runner, "13. Boundary Delimiters & RFC 7578 Disposition Enforcement", test_boundary_delimiter_and_disposition_invariants);
    core::run_case(runner, "14. RFC 9110 Coalescing, Overflow Guard & Nested Boundaries", test_rfc9110_coalescing_and_nested_boundaries);
    core::run_case(runner, "15. Boundary Quoting, Byte-Range PATCH & Quotas", test_round3_boundary_quoting_patch_and_quotas);
    core::run_case(runner, "16. 64-Bit Integer Overflow in Range Offsets (CWE-190)", test_range_offset_i64_overflow);
    core::run_case(runner, "17. Multipart Delimiter & Line Endings (LF vs CRLF)", test_multipart_lf_delimiter_and_line_endings);
    core::run_case(runner, "18. Range Limits & Boundary Coalescing", test_range_limits_and_coalescing);
    core::run_case(runner, "19. MIME Headers Memory Limit Bypass (#81741 / CVE-2026-94440)", test_mime_headers_memory_limit_bypass);
    core::run_case(runner, "20. Range Header Size and Count Limits (#81858 / CVE-2026-78667)", test_range_header_size_and_count_limits);
    core::run_case(runner, "21. Delimiter Line-Ending Desync and Transport Padding", test_delimiter_line_ending_desync);
    core::run_case(runner, "22. 10,000+ Parts Boundary Flood and Memory Limits (#59153 / CVE-2023-24536)", test_multipart_part_count_fuzzing);
    core::run_case(runner, "23. Malformed Boundary Quoting and RFC 2046 Validation", test_malformed_boundary_quoting_and_lexical);
    core::run_case(runner, "24. ReDoS Resistance and Nested Boundary Isolation (#10616, #14085)", test_redos_and_nested_boundaries);
    core::run_case(runner, "25. Content-Disposition Filename Traversal and Edge Cases (#45789, #63629)", test_mime_disposition_and_filename_traversal);
    core::run_case(runner, "26. Resumable Uploads for HTTP", test_resumable_uploads);

    let ok = core::finish(runner);
    assert(ok);
}
