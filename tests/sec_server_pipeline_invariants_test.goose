// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Security invariant tests for Server Request Pipeline & HTTP/1.1 Pipelining:
// 1. HTTP/1.1 Pipelined request buffer parsing.
// 2. RFC 9112 Section 2.2 empty line tolerance & Section 3.1 leading whitespace ban.
// 3. Request target and Host header structural security invariants.
import std;
import core from "..";
import wing from "..";

fn test_server_http1_pipelining(t: core::T&) {
    let wire: const u8[:] = "GET /first HTTP/1.1\r\nHost: example.com\r\n\r\nGET /second HTTP/1.1\r\nHost: example.com\r\n\r\n";

    var req1 = wing::Request { .. };
    let ok1, consumed1 = wing::parse_http1_wire_request(wire, req1);
    t.assert_true(ok1, "first pipelined request parsed successfully");
    t.assert_true(req1.url[..] == "/first", "first url matches");
    t.assert_true(consumed1 > 0 && consumed1 < wire.len, "consumed bytes valid");

    let rem_wire = wire[consumed1..];
    var req2 = wing::Request { .. };
    let ok2, consumed2 = wing::parse_http1_wire_request(rem_wire, req2);
    t.assert_true(ok2, "second pipelined request parsed successfully");
    t.assert_true(req2.url[..] == "/second", "second url matches");
    t.assert_eq(consumed1 + consumed2, wire.len, "entire pipelined stream consumed");
}

fn test_server_empty_line_and_whitespace_invariants(t: core::T&) {
    // 1. RFC 9112 §2.2: Single empty line (\r\n) before request-line is tolerated
    let single_crlf: const u8[:] = "\r\nGET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var req1 = wing::Request { .. };
    let ok1, _ = wing::parse_http1_wire_request(single_crlf, req1);
    t.assert_true(ok1, "single CRLF before request-line is tolerated");
    t.assert_true(req1.url[..] == "/index.html", "request url matches");

    // 2. RFC 9112 §2.2: Multiple empty lines (\r\n\r\n) before request-line MUST be rejected
    let double_crlf: const u8[:] = "\r\n\r\nGET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var req2 = wing::Request { .. };
    let ok2, _ = wing::parse_http1_wire_request(double_crlf, req2);
    t.assert_false(ok2, "more than one CRLF before request-line must be rejected");

    // 3. RFC 9112 §3.1: Whitespace before method name MUST be rejected
    let ws_method: const u8[:] = " GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var req3 = wing::Request { .. };
    let ok3, _ = wing::parse_http1_wire_request(ws_method, req3);
    t.assert_false(ok3, "space before method name must be rejected");

    let tab_method: const u8[:] = "\tGET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var req4 = wing::Request { .. };
    let ok4, _ = wing::parse_http1_wire_request(tab_method, req4);
    t.assert_false(ok4, "tab before method name must be rejected");
}

fn test_server_target_and_host_invariants(t: core::T&) {
    // 1. Reject CTL character in request target
    let bad_ctl: const u8[:] = "GET /bad\x01path HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var req1 = wing::Request { .. };
    let ok1, _ = wing::parse_http1_wire_request(bad_ctl, req1);
    t.assert_false(ok1, "CTL in request target must be rejected");

    // 2. Reject Host header with path or query delimiter
    let bad_host1: const u8[:] = "GET / HTTP/1.1\r\nHost: example.com/path\r\n\r\n";
    var req2 = wing::Request { .. };
    let ok2, _ = wing::parse_http1_wire_request(bad_host1, req2);
    t.assert_false(ok2, "Host header with path separator must be rejected");

    let bad_host2: const u8[:] = "GET / HTTP/1.1\r\nHost: example.com?query\r\n\r\n";
    var req3 = wing::Request { .. };
    let ok3, _ = wing::parse_http1_wire_request(bad_host2, req3);
    t.assert_false(ok3, "Host header with query delimiter must be rejected");

    // 3. Valid IPv6 literal host
    let ipv6_host: const u8[:] = "GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n";
    var req4 = wing::Request { .. };
    let ok4, _ = wing::parse_http1_wire_request(ipv6_host, req4);
    t.assert_true(ok4, "valid IPv6 literal host must succeed");
}

fn main() {
    var runner = core::new_runner("Server & Multiplexer Security Invariants Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. HTTP/1.1 Pipelining", test_server_http1_pipelining);
    core::run_case(runner, "2. Empty Line & Whitespace Invariants", test_server_empty_line_and_whitespace_invariants);
    core::run_case(runner, "3. Target & Host Invariants", test_server_target_and_host_invariants);
    let ok = core::finish(runner);
    assert(ok);
}
