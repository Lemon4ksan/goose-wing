// Verification suite for RFC 9576 Privacy Pass Architecture,
// RFC 9577 PrivateToken HTTP Authentication Scheme, and RFC 9578 Blind RSA Tokens:
// - TokenChallenge binary wire serialization and deserialization (RFC 9577 §2.1.1)
// - Token binary wire serialization and deserialization (RFC 9577 §2.2.1)
// - Challenge digest SHA-256 computation (RFC 9577 §2.2.1)
// - WWW-Authenticate: PrivateToken header parsing (challenge, token-key, max-age)
// - Authorization: PrivateToken token="..." header formatting (RFC 9577 §2.2.2)
// - Sec-Private-State-Token W3C header formatting
// - PrivateTokenCache storage, expiration, and single-use redemption enforcement
// - Request header attachment and response 401 PrivateToken challenge detection
// - RFC 9577 §6.2.1 GREASE token type verification
import std;
import core from "..";
import wing from "..";

fn test_token_challenge_roundtrip(t: core::T&) {
    t.run("TokenChallenge with 32-byte Redemption Context") { sub =>
        var ch = wing::TokenChallenge {
            token_type: wing::TOKEN_TYPE_BLIND_RSA,
            ..
        };
        ch.issuer_name.append("issuer.example.com");
        for i in 32 { ch.redemption_context.push(0x42); }
        ch.origin_info.append("origin.example.com");

        var wire: u8[>..] = [];
        wing::marshal_token_challenge(ch, wire);
        sub.assert_gt(wire.len, 7, "Wire length > 7");

        var parsed = wing::TokenChallenge { .. };
        let ok = wing::unmarshal_token_challenge(wire[..], parsed);
        sub.assert_true(ok, "Unmarshal succeeded");
        sub.assert_eq(parsed.token_type, wing::TOKEN_TYPE_BLIND_RSA, "Token type matches");
        sub.assert_bytes_eq(parsed.issuer_name[..], "issuer.example.com", "Issuer name matches");
        sub.assert_eq(parsed.redemption_context.len, 32, "Redemption context is 32 bytes");
        sub.assert_bytes_eq(parsed.origin_info[..], "origin.example.com", "Origin info matches");

        // Challenge digest
        let digest = wing::compute_challenge_digest(ch);
        var zero_cnt = 0;
        for b in digest {
            if b == 0 { zero_cnt += 1; }
        }
        sub.assert_true(zero_cnt < 32, "Challenge digest is non-zero SHA-256");
    };

    t.run("TokenChallenge with Empty Context and Multiple Origins") { sub =>
        var ch = wing::TokenChallenge {
            token_type: wing::TOKEN_TYPE_PUBLICLY_VERIFIABLE,
            ..
        };
        ch.issuer_name.append("turnstile.cloudflare.com");
        ch.origin_info.append("site1.com,site2.com,site3.com");

        var wire: u8[>..] = [];
        wing::marshal_token_challenge(ch, wire);

        var parsed = wing::TokenChallenge { .. };
        let ok = wing::unmarshal_token_challenge(wire[..], parsed);
        sub.assert_true(ok, "Unmarshal succeeded");
        sub.assert_eq(parsed.token_type, wing::TOKEN_TYPE_PUBLICLY_VERIFIABLE, "Token type matches");
        sub.assert_eq(parsed.redemption_context.len, 0, "Redemption context is empty");
        sub.assert_bytes_eq(parsed.origin_info[..], "site1.com,site2.com,site3.com", "Origins preserved");
    };
}

fn test_token_wire_roundtrip(t: core::T&) {
    t.run("Token Binary Wire Codec (RFC 9577 §2.2.1)") { sub =>
        var tok = wing::Token {
            token_type: wing::TOKEN_TYPE_BLIND_RSA,
            ..
        };
        for i in 32 { tok.nonce[i] = (i + 1) as u8; }
        for i in 32 { tok.challenge_digest[i] = (i + 50) as u8; }
        for i in 32 { tok.token_key_id.push(0x01); }
        for i in 64 { tok.authenticator.push(0x99); }

        var wire: u8[>..] = [];
        wing::marshal_token(tok, wire);
        // 2 + 32 + 32 + 32 + 64 = 162 bytes
        sub.assert_eq(wire.len, 162, "Token wire is exactly 162 bytes");

        var parsed = wing::Token { .. };
        let ok = wing::unmarshal_token(wire[..], 32, 64, parsed);
        sub.assert_true(ok, "Token unmarshaled");
        sub.assert_eq(parsed.token_type, wing::TOKEN_TYPE_BLIND_RSA, "Token type matches");
        sub.assert_bytes_eq(parsed.nonce[..], tok.nonce[..], "Nonce matches");
        sub.assert_bytes_eq(parsed.challenge_digest[..], tok.challenge_digest[..], "Challenge digest matches");
        sub.assert_bytes_eq(parsed.token_key_id[..], tok.token_key_id[..], "Token key id matches");
        sub.assert_bytes_eq(parsed.authenticator[..], tok.authenticator[..], "Authenticator matches");
    };
}

fn test_privacypass_headers_and_cache(t: core::T&) {
    t.run("WWW-Authenticate PrivateToken Challenge Parsing") { sub =>
        // Construct challenge wire and base64url
        var ch = wing::TokenChallenge {
            token_type: wing::TOKEN_TYPE_BLIND_RSA,
            ..
        };
        ch.issuer_name.append("issuer.example.com");
        ch.origin_info.append("origin.example.com");

        var ch_wire: u8[>..] = [];
        wing::marshal_token_challenge(ch, ch_wire);

        var ch_b64: u8[..512] = [];
        core::base64url_encode(ch_wire[..], ch_b64);

        var header_val: u8[..1024] = [];
        header_val.append("PrivateToken challenge=\"");
        header_val.append(ch_b64[..]);
        header_val.append("\", token-key=\"AQIDBA==\", max-age=3600");

        var parsed_ch = wing::TokenChallenge { .. };
        var token_key: u8[..128] = [];
        var max_age: i64 = 0;
        let ok = wing::parse_private_token_challenge(header_val[..], parsed_ch, token_key, max_age);
        sub.assert_true(ok, "PrivateToken challenge header parsed");
        sub.assert_bytes_eq(parsed_ch.issuer_name[..], "issuer.example.com", "Issuer name parsed");
        sub.assert_bytes_eq(parsed_ch.origin_info[..], "origin.example.com", "Origin info parsed");
        sub.assert_eq(max_age, 3600, "max-age parsed as 3600 seconds");
    };

    t.run("Authorization Header Formatting") { sub =>
        let raw_token = "mock_privacy_token_bytes_xyz_12345";
        var auth_hdr: u8[..512] = [];
        wing::format_private_token_authorization(raw_token, auth_hdr);
        sub.assert_true(core::eq_ascii_fold(auth_hdr[..19], "PrivateToken token="), "Starts with PrivateToken token=");

        var sec_hdr: u8[..512] = [];
        wing::format_sec_private_state_token(raw_token, sec_hdr);
        sub.assert_gt(sec_hdr.len, 0, "Sec-Private-State-Token formatted");
    };

    t.run("PrivateTokenCache Storage and Single-Use Enforcement") { sub =>
        var cache = wing::PrivateTokenCache { .. };
        var ch = wing::TokenChallenge { .. };
        ch.issuer_name.append("issuer.example.com");
        ch.origin_info.append("example.com");

        var tok = wing::Token { .. };
        tok.token_key_id.append("key1");
        let raw = "raw_token_data_stream";

        let now_sec: i64 = 1714000000;
        let put_ok = wing::put_private_token(cache, ch, tok, raw, 3600, now_sec);
        sub.assert_true(put_ok, "Token cached");

        // Spend token 1st time (should succeed)
        var got_tok = wing::Token { .. };
        var got_raw: u8[..512] = [];
        let get1_ok = wing::get_private_token(cache, ch, now_sec + 10, got_tok, got_raw);
        sub.assert_true(get1_ok, "1st spend succeeds");
        sub.assert_bytes_eq(got_raw[..], raw, "Got matching raw token");

        // Spend token 2nd time (should FAIL - RFC 9577 single-use spend)
        var got_tok2 = wing::Token { .. };
        var got_raw2: u8[..512] = [];
        let get2_ok = wing::get_private_token(cache, ch, now_sec + 20, got_tok2, got_raw2);
        sub.assert_false(get2_ok, "2nd spend fails (token already redeemed)");
    };

    t.run("Client Response Challenge Detection and GREASE Types") { sub =>
        var resp = wing::Response { status_code: 401, .. };
        resp.headers.push(wing::make_header("WWW-Authenticate", "PrivateToken challenge=\"abc\""));
        sub.assert_true(wing::has_private_token_challenge(resp), "Detects 401 PrivateToken challenge");

        var resp_200 = wing::Response { status_code: 200, .. };
        sub.assert_false(wing::has_private_token_challenge(resp_200), "Rejects non-401 response");

        // GREASE verification (RFC 9577 §6.2.1)
        sub.assert_true(wing::is_grease_token_type(0x02AA), "0x02AA is GREASE");
        sub.assert_true(wing::is_grease_token_type(0xF057), "0xF057 is GREASE");
        sub.assert_false(wing::is_grease_token_type(0x0001), "0x0001 is NOT GREASE (Blind RSA)");
        sub.assert_false(wing::is_grease_token_type(0x0002), "0x0002 is NOT GREASE (Publicly Verifiable)");
    };
}

fn main() {
    var runner = core::new_runner("Privacy Pass Suite (RFC 9576 / RFC 9577 / RFC 9578)", core::Verbosity.Verbose);
    core::run_case(runner, "1. TokenChallenge Wire Codec", test_token_challenge_roundtrip);
    core::run_case(runner, "2. Token Binary Wire Codec", test_token_wire_roundtrip);
    core::run_case(runner, "3. Privacy Pass Headers & Cache", test_privacypass_headers_and_cache);
    let ok = core::finish(runner);
    assert(ok);
}
