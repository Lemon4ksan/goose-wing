// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_auth_digest_vector.goose
// RFC 7616 Section 3.9.2 SHA-512-256 Digest Authentication test vector reproduction.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    // RFC 7616 Section 3.9.2: Example with SHA-512-256, Charset, and Userhash - Truncated SHA-512 (first 256 bits) for SHA-512-256 digest calculation.
    let username = "J\xC3\xA4s\xC3\xB8n Doe";
    let realm = "api@example.org";
    let password = "Secret, or not?";
    let uri = "/doe.json";
    let method = "GET";
    let nonce = "5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK";
    let cnonce = "NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v";
    let nc = "00000001";
    let qop = "auth";
    let algo = "SHA-512-256";

    // 1. Verify Userhash (RFC 7616 Section 3.9.2)
    let userhash = wing::resolve_userhash(username, realm, algo);
    let expected_userhash = "488869477bf257147b804c45308cd62ac4e25eb717b12b298c79e62dcea254ec";
    assert(userhash[..] == expected_userhash);

    // 2. Calculate HA1 (A1 = username:realm:password)
    let ha1 = wing::calculate_digest_ha1(algo, username, realm, password, nonce, cnonce);

    // 3. Calculate HA2 (A2 = method:uri)
    let ha2 = wing::calculate_digest_ha2(algo, method, uri, false, "");

    // 4. Calculate Response
    let resp = wing::calculate_digest_response(algo, ha1[..], nonce, nc, cnonce, qop, ha2[..]);

    let expected_resp = "ae66e67d6b427bd3f120414a82e4acff38e8ecd9101d6c861229025f607a79dd";
    assert(resp[..] == expected_resp);

    print("RFC7616_SHA512_256_RESPONSE: OK\n");
}

// CHECK: RFC7616_SHA512_256_RESPONSE: OK
