// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_request_response_reset.goose
// Verification of zero-allocation reset_request and reset_response.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    var req = wing::new_request("POST", "https://example.com/api");
    req.url.append("?token=xyz");
    req.timeout = 5000;
    req.body_consumed = true;
    req.is_http10 = true;
    wing::set_header(req, "X-Custom-Header", "Value123");

    assert(req.headers.entries.len == 1);
    assert(req.url.len > 0);
    assert(req.timeout == 5000);

    wing::reset_request(req);

    assert(req.method[..] == "GET");
    assert(req.url.len == 0);
    assert(req.headers.entries.len == 0);
    assert(req.trailers.entries.len == 0);
    assert(req.query_params.len == 0);
    assert(req.rewind_buf.len == 0);
    assert(req.timeout == 0);
    assert(!req.body_consumed);
    assert(!req.is_http10);

    var res = wing::Response { status_code: 404, .. };
    wing::set_header(res, "Content-Type", "application/json");

    assert(res.status_code == 404);
    assert(res.headers.entries.len == 1);

    wing::reset_response(res);

    assert(res.status_code == 200);
    assert(res.headers.entries.len == 0);
    assert(res.sent_headers.entries.len == 0);
    assert(res.body.len == 0);

    print("REQUEST_RESPONSE_RESET: OK");
}

// CHECK: REQUEST_RESPONSE_RESET: OK
