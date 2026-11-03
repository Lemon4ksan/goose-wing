// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_semantic_h3_connect_pseudo.goose
// Verification of RFC 9114 Section 4.3.1 and Section 4.4 CONNECT pseudo-header validation.
// RFC 9114 Section 4.3.1: Request Pseudo-Header Fields - All HTTP/3 requests MUST include exactly one value for the :method, :scheme, and :path pseudo-header fields, unless the request is a CONNECT request; see Section 4.4.
// RFC 9114 Section 4.4: The CONNECT Method - A CONNECT request MUST be constructed as follows: The :method pseudo-header field is set to "CONNECT", the :scheme and :path pseudo-header fields are omitted, the :authority pseudo-header field contains the host and port to connect to. A CONNECT request that does not conform to these restrictions is malformed.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    var settings = wing::H3Settings { .. };
    var conn = internal::new_h3_server_connection(settings);
    let s_idx, err_s = internal::get_or_create_bidi_stream(conn, 0);
    assert(err_s == rfc::H3_ERR_NO_ERROR);

    // 1. Valid RFC 9114 CONNECT: :method = CONNECT, :authority = host:port (omitted :scheme and :path)
    var valid_connect_fields: internal::HeaderField[>..] = [];
    var f1 = internal::HeaderField { .. };
    f1.name.append(":method");
    f1.value.append("CONNECT");
    valid_connect_fields.push(f1);

    var f2 = internal::HeaderField { .. };
    f2.name.append(":authority");
    f2.value.append("example.com:443");
    valid_connect_fields.push(f2);

    let err_valid = internal::validate_h3_headers(conn, s_idx, valid_connect_fields);
    print("VALID_CONNECT: ", err_valid == rfc::H3_ERR_NO_ERROR, "\n");

    // 2. Malformed RFC 9114 CONNECT: :scheme and :path must be omitted for CONNECT
    conn = internal::new_h3_server_connection(settings);
    let s_idx2, err_s2 = internal::get_or_create_bidi_stream(conn, 0);
    assert(err_s2 == rfc::H3_ERR_NO_ERROR);

    var malformed_connect_fields: internal::HeaderField[>..] = [];
    var m1 = internal::HeaderField { .. };
    m1.name.append(":method");
    m1.value.append("CONNECT");
    malformed_connect_fields.push(m1);

    var m2 = internal::HeaderField { .. };
    m2.name.append(":scheme");
    m2.value.append("https");
    malformed_connect_fields.push(m2);

    var m3 = internal::HeaderField { .. };
    m3.name.append(":path");
    m3.value.append("/");
    malformed_connect_fields.push(m3);

    var m4 = internal::HeaderField { .. };
    m4.name.append(":authority");
    m4.value.append("example.com:443");
    malformed_connect_fields.push(m4);

    let err_malformed = internal::validate_h3_headers(conn, s_idx2, malformed_connect_fields);
    print("MALFORMED_CONNECT_SCHEME_PATH: ", err_malformed == rfc::H3_ERR_GENERAL_PROTOCOL, "\n");

    // 3. Malformed RFC 9114 CONNECT: missing :authority
    conn = internal::new_h3_server_connection(settings);
    let s_idx3, err_s3 = internal::get_or_create_bidi_stream(conn, 0);
    assert(err_s3 == rfc::H3_ERR_NO_ERROR);

    var no_auth_fields: internal::HeaderField[>..] = [];
    var a1 = internal::HeaderField { .. };
    a1.name.append(":method");
    a1.value.append("CONNECT");
    no_auth_fields.push(a1);

    let err_no_auth = internal::validate_h3_headers(conn, s_idx3, no_auth_fields);
    print("MALFORMED_CONNECT_NO_AUTH: ", err_no_auth == rfc::H3_ERR_GENERAL_PROTOCOL, "\n");

    // 4. Standard valid GET request
    conn = internal::new_h3_server_connection(settings);
    let s_idx4, err_s4 = internal::get_or_create_bidi_stream(conn, 0);
    assert(err_s4 == rfc::H3_ERR_NO_ERROR);

    var get_fields: internal::HeaderField[>..] = [];
    var g1 = internal::HeaderField { .. };
    g1.name.append(":method");
    g1.value.append("GET");
    get_fields.push(g1);

    var g2 = internal::HeaderField { .. };
    g2.name.append(":scheme");
    g2.value.append("https");
    get_fields.push(g2);

    var g3 = internal::HeaderField { .. };
    g3.name.append(":path");
    g3.value.append("/");
    get_fields.push(g3);

    var g4 = internal::HeaderField { .. };
    g4.name.append(":authority");
    g4.value.append("example.com");
    get_fields.push(g4);

    let err_get = internal::validate_h3_headers(conn, s_idx4, get_fields);
    print("VALID_GET: ", err_get == rfc::H3_ERR_NO_ERROR, "\n");
}

// CHECK: VALID_CONNECT: true
// CHECK: MALFORMED_CONNECT_SCHEME_PATH: true
// CHECK: MALFORMED_CONNECT_NO_AUTH: true
// CHECK: VALID_GET: true
