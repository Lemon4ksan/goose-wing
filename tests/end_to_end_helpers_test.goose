// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for end-to-end convenience helpers:
// - Request priority configuration (RFC 9218 header injection)
// - Request and Response Ed25519 HTTP Message Signatures (RFC 9421)
// - Server response zero-copy transmission via IoVecArray (send_http1_response_iov)
import std;
import core from "..";
import wing from "..";

fn test_request_priority_helper(t: core::T&) {
    t.run("Request.set_priority") { sub =>
        var req = wing::Request { .. };
        wing::set_priority(req, 1, true);
        let prio_val = wing::header(req, "priority");
        sub.assert_eq(prio_val, "u=1, i", "Priority header encoded correctly with incremental");

        var req2 = wing::Request { .. };
        wing::set_priority(req2, 6);
        let prio_val2 = wing::header(req2, "priority");
        sub.assert_eq(prio_val2, "u=6", "Priority header encoded correctly without incremental");

        // Invalid urgency defaults to 3
        var req3 = wing::Request { .. };
        wing::set_priority(req3, 99);
        let prio_val3 = wing::header(req3, "priority");
        sub.assert_eq(prio_val3, "u=3", "Out-of-range urgency defaults to 3");
    };
}

fn test_ed25519_signatures_helpers(t: core::T&) {
    t.run("sign_request_ed25519 & verify_request_ed25519") { sub =>
        let seed: u8[32] = [
            0x9d, 0x61, 0xb1, 0x9c, 0x4f, 0x61, 0x97, 0xf8,
            0x9a, 0x21, 0xe1, 0xf3, 0xc2, 0x55, 0xa0, 0x45,
            0x82, 0xe2, 0x15, 0x68, 0x77, 0x11, 0x0f, 0x2e,
            0xa0, 0x21, 0x86, 0xc4, 0x2d, 0x39, 0x53, 0x4f,
        ];
        let pubkey = core::ed25519_public_key(seed);

        var req = wing::Request {
            method: "POST",
            url: "https://api.example.com/v1/orders?item=book",
            ..
        };
        wing::set_header(req, "content-type", "application/json");

        let ok_sign = wing::sign_request_ed25519(req, "ed-key-1", seed[..]);
        sub.assert_true(ok_sign, "Request signed with Ed25519");

        let ok_verify = wing::verify_request_ed25519(req, "ed-key-1", pubkey[..]);
        sub.assert_true(ok_verify, "Request signature verified with public key");

        // Tamper method
        var tampered_req = req;
        tampered_req.method.clear();
        tampered_req.method.append("GET");
        let tamper_verify = wing::verify_request_ed25519(tampered_req, "ed-key-1", pubkey[..]);
        sub.assert_false(tamper_verify, "Tampered request signature rejected");
    };

    t.run("sign_response_ed25519 & verify_response_ed25519") { sub =>
        let seed: u8[32] = [
            0x9d, 0x61, 0xb1, 0x9c, 0x4f, 0x61, 0x97, 0xf8,
            0x9a, 0x21, 0xe1, 0xf3, 0xc2, 0x55, 0xa0, 0x45,
            0x82, 0xe2, 0x15, 0x68, 0x77, 0x11, 0x0f, 0x2e,
            0xa0, 0x21, 0x86, 0xc4, 0x2d, 0x39, 0x53, 0x4f,
        ];
        let pubkey = core::ed25519_public_key(seed);

        var req = wing::Request {
            method: "GET",
            url: "https://api.example.com/v1/status",
            ..
        };

        var res = wing::Response {
            status_code: 200,
            ..
        };
        wing::set_header(res, "content-type", "application/json");

        let ok_sign = wing::sign_response_ed25519(res, req, "ed-key-1", seed[..]);
        sub.assert_true(ok_sign, "Response signed with Ed25519");

        let ok_verify = wing::verify_response_ed25519(res, req, "ed-key-1", pubkey[..]);
        sub.assert_true(ok_verify, "Response signature verified with public key");

        // Tamper status
        var tampered_res = res;
        tampered_res.status_code = 404;
        let tamper_verify = wing::verify_response_ed25519(tampered_res, req, "ed-key-1", pubkey[..]);
        sub.assert_false(tamper_verify, "Tampered response signature rejected");
    };
}

fn test_send_http1_response_iov_helper(t: core::T&) {
    t.run("send_http1_response_iov empty descriptor check") { sub =>
        var res = wing::Response {
            status_code: 200,
            ..
        };
        var iov = core::new_iovec_array();
        core::iovec_push(iov, "chunk 1\n");
        core::iovec_push(iov, "chunk 2\n");

        var wire_hdr: u8[>..] = [];
        // Closed / invalid socket returns 0 guard
        let sent = wing::send_http1_response_iov(-1, res, "goose-wing/1.0", iov, wire_hdr);
        sub.assert_eq(sent, 0, "Non-positive socket returns 0 bytes safely");
        sub.assert_gt(wire_hdr.len, 0, "Headers formatted");
    };
}

fn main() {
    var runner = core::new_runner("End-to-End Convenience Helpers Suite", core::Verbosity.Verbose);
    core::run_case(runner, "Request.set_priority helper", test_request_priority_helper);
    core::run_case(runner, "RFC 9421 Ed25519 Request & Response helpers", test_ed25519_signatures_helpers);
    core::run_case(runner, "send_http1_response_iov helper", test_send_http1_response_iov_helper);
    let ok = core::finish(runner);
    assert(ok);
}
