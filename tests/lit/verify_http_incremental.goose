// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_http_incremental.goose
// Verification of RFC 10036 Incremental Forwarding of HTTP Messages:
// - Boolean Item parsing (?1 / ?0)
// - Parameter ignoring rule (RFC 10036 §2)
// - Strict rejection of non-boolean types (RFC 10036 §2)
// - Intermediary Proxy-Status error signaling (incremental_refused & connection_limit_reached)
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    // 1. Valid Boolean Items
    let inc1, ok1 = wing::parse_incremental_header("?1");
    assert(ok1);
    assert(inc1);
    print("INC_TRUE: 1");
    // CHECK: INC_TRUE: 1

    let inc0, ok0 = wing::parse_incremental_header("?0");
    assert(ok0);
    assert(!inc0);
    print("INC_FALSE: 1");
    // CHECK: INC_FALSE: 1

    // 2. Parameters ignored per RFC 10036 §2
    let inc_param, ok_param = wing::parse_incremental_header("?1; param=value");
    assert(ok_param);
    assert(inc_param);
    print("INC_PARAM_IGNORED: 1");
    // CHECK: INC_PARAM_IGNORED: 1

    // 3. Non-Boolean types must be ignored (RFC 10036 §2)
    let _, ok_int = wing::parse_incremental_header("1");
    assert(!ok_int);

    let _, ok_str = wing::parse_incremental_header("\"?1\"");
    assert(!ok_str);

    let _, ok_tok = wing::parse_incremental_header("true");
    assert(!ok_tok);
    print("NON_BOOLEAN_IGNORED: 1");
    // CHECK: NON_BOOLEAN_IGNORED: 1

    // 4. HeaderMap inspection
    var headers = wing::HeaderMap { .. };
    wing::append_incremental_header(headers, true);
    assert(wing::is_incremental_requested(headers));
    print("HEADER_MAP_INCREMENTAL: 1");
    // CHECK: HEADER_MAP_INCREMENTAL: 1

    // 5. Intermediary incremental_refused Proxy-Status
    var ps_refused: u8[..128] = [];
    wing::format_incremental_refused_proxy_status(ps_refused, "edge-proxy");
    assert(core::contains(ps_refused[..], "edge-proxy"));
    assert(core::contains(ps_refused[..], "error=incremental_refused"));
    print("PROXY_STATUS_REFUSED: 1");
    // CHECK: PROXY_STATUS_REFUSED: 1

    // 6. Intermediary connection_limit_reached Proxy-Status
    var ps_limited: u8[..128] = [];
    wing::format_incremental_limit_reached_proxy_status(ps_limited, "edge-proxy");
    assert(core::contains(ps_limited[..], "edge-proxy"));
    assert(core::contains(ps_limited[..], "error=connection_limit_reached"));
    print("PROXY_STATUS_LIMITED: 1");
    // CHECK: PROXY_STATUS_LIMITED: 1

    print("RFC10036_VERIFICATION_COMPLETE");
    // CHECK: RFC10036_VERIFICATION_COMPLETE
}
