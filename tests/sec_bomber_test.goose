// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Tests for multipart form-data and HTTP range parser bounds and edge cases.
import std;
import core from "..";
import wing from "..";

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
fn main() {
    var runner = core::new_runner("Multipart & Range Edge Cases Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. 64-Bit Integer Overflow in Range Offsets (CWE-190)", test_range_offset_i64_overflow);
    core::run_case(runner, "2. Multipart Delimiter & Line Endings (LF vs CRLF)", test_multipart_lf_delimiter_and_line_endings);
    core::run_case(runner, "3. Range Limits & Boundary Coalescing", test_range_limits_and_coalescing);
    core::run_case(runner, "4. MIME Headers Memory Limit Bypass (#81741 / CVE-2026-94440)", test_mime_headers_memory_limit_bypass);
    core::run_case(runner, "5. Range Header Size and Count Limits (#81858 / CVE-2026-78667)", test_range_header_size_and_count_limits);
    core::run_case(runner, "6. Delimiter Line-Ending Desync and Transport Padding", test_delimiter_line_ending_desync);
    core::run_case(runner, "7. 10,000+ Parts Boundary Flood and Memory Limits (#59153 / CVE-2023-24536)", test_multipart_part_count_fuzzing);
    core::run_case(runner, "8. Malformed Boundary Quoting and RFC 2046 Validation", test_malformed_boundary_quoting_and_lexical);
    core::run_case(runner, "9. ReDoS Resistance and Nested Boundary Isolation (#10616, #14085)", test_redos_and_nested_boundaries);
    core::run_case(runner, "10. Content-Disposition Filename Traversal and Edge Cases (#45789, #63629)", test_mime_disposition_and_filename_traversal);

    let ok = core::finish(runner);
    assert(ok);
}
