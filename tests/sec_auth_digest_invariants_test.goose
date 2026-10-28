// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Hardening & Security Invariants Suite for HTTP Digest Authentication (RFC 7616):
// 1. Buffer overflow protection on algorithm and qop (> 32 bytes).
// 2. Missing '=' separator and malformed parameter syntax rejection.
// 3. Parameter injection prevention in Authorization header serialization.
// 4. CRLF injection prevention in Digest header parameters.
import std;
import core from "..";
import wing from "..";

fn test_digest_challenge_buffer_bounds(t: core::T&) {
    t.run("DIGEST-SEC-01: Algorithm Name Exceeding 32 Bytes Must Not Panic") { sub =>
        // 40-character algorithm string
        let long_algo = "Digest realm=\"api\", nonce=\"12345\", algorithm=SHA-256-SUPER-LONG-ALGORITHM-NAME-OVERFLOW";
        let chal, ok = wing::parse_digest_challenge(long_algo);
        // Must either fail or safely reject the oversize algorithm without panicking
        sub.assert_true(true, "oversize algorithm handled without capacity panic");
        if ok {
            sub.assert_true(chal.algorithm.len <= 32, "algorithm capacity not exceeded");
        }
    };

    t.run("DIGEST-SEC-02: QOP String Exceeding 32 Bytes Must Not Panic") { sub =>
        // 50-character qop string
        let long_qop = "Digest realm=\"api\", nonce=\"12345\", qop=\"auth,auth-int,super-long-unsupported-qop-value-overflow\"";
        let chal, ok = wing::parse_digest_challenge(long_qop);
        sub.assert_true(true, "oversize qop handled without capacity panic");
        if ok {
            sub.assert_true(chal.qop.len <= 32, "qop capacity not exceeded");
        }
    };

    t.run("DIGEST-SEC-03: Missing '=' Separator Must Be Rejected") { sub =>
        let missing_eq = "Digest realm \"test\", nonce=\"12345\"";
        let _, ok = wing::parse_digest_challenge(missing_eq);
        sub.assert_false(ok, "missing '=' separator between parameter key and value must be rejected");
    };

    t.run("DIGEST-SEC-04: Unclosed Quoted Parameter Must Be Rejected") { sub =>
        let unclosed = "Digest realm=\"unclosed_realm, nonce=\"12345\"";
        let _, ok = wing::parse_digest_challenge(unclosed);
        sub.assert_false(ok, "unclosed quoted string in challenge must be rejected");
    };
}

fn test_has_substr(haystack: const u8[:], needle: const u8[:]) -> bool {
    guard haystack.len >= needle.len else { return false; }
    for i in 0..(haystack.len - needle.len + 1) {
        if haystack[i..i + needle.len] == needle {
            return true;
        }
    }
    return false;
}

fn test_digest_auth_serialization_security(t: core::T&) {
    t.run("DIGEST-SEC-05: Injected Quotes in Nonce Must Be Escaped") { sub =>
        var out_hdr: u8[..512] = [];
        let ok = wing::serialize_digest_auth(
            "user", "realm", "nonce\"with\"quotes", "/api",
            "SHA-256", "0123456789abcdef", "auth",
            "00000001", "cnonce", "opaque", false,
            out_hdr,
        );
        sub.assert_true(ok, "serialization succeeds with escaped quotes");

        // Verify that quotes inside nonce were escaped as \"
        sub.assert_true(test_has_substr(out_hdr[..], "nonce=\"nonce\\\"with\\\"quotes\""), "quotes inside nonce must be escaped with backslash");
    };

    t.run("DIGEST-SEC-06: CRLF Injection in Realm or Nonce Must Be Rejected") { sub =>
        var out_hdr: u8[..512] = [];
        let ok = wing::serialize_digest_auth(
            "user", "realm\r\nEvil: true", "nonce", "/api",
            "SHA-256", "0123456789abcdef", "auth",
            "00000001", "cnonce", "opaque", false,
            out_hdr,
        );
        sub.assert_false(ok, "CRLF inside realm must cause serialization failure (header injection prevention)");
    };
}

fn main() {
    var runner = core::new_runner("HTTP Digest Authentication Security Invariants Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Digest Challenge Buffer Bounds & Syntax", test_digest_challenge_buffer_bounds);
    core::run_case(runner, "2. Digest Authorization Serialization Defenses", test_digest_auth_serialization_security);

    let ok = core::finish(runner);
    assert(ok);
}
