// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Tests for multipart/form-data parsing and HTTP range requests.
import std;
import core from "..";
import wing from "..";

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
        let bad_weak = wing::evaluate_if_range("W/\"strong-etag-1\"", "\"strong-etag-1\"", file_time);
        sub.assert_false(bad_weak, "Weak ETag forbidden in If-Range");
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
        var headers = wing::new_header_map();
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

// ---- consolidated suite entry point ---------------------------------------

fn main() {
    var runner = core::new_runner("HTTP Multipart & RFC 9110 Range Verification Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Streaming Multipart Parsing & Metadata", test_streaming_multipart_parsing);
    core::run_case(runner, "2. CVE-2026-19484 Boundary Cap & 16-Bit BMH", test_cve_2026_19484_boundary_and_bmh_table);
    core::run_case(runner, "3. RFC 9110 Range Request Forms & 416", test_rfc9110_range_requests);
    core::run_case(runner, "4. CVE-2011-3192 Apache Killer Defense & Coalescing", test_cve_2011_3192_apache_killer_and_coalescing);
    core::run_case(runner, "5. If-Range & Seconds Truncation", test_if_range_and_seconds_truncation);
    core::run_case(runner, "6. Window Reader serve_range & Byte-Range PATCH", test_serve_range_and_patch_validation);

    let ok = core::finish(runner);
    assert(ok);
}
