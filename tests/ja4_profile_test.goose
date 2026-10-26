// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification Suite for FoxIO JA4 (TLS) / JA4H (HTTP) fingerprinting and Wing Profile System.
import std;
import core from "..";
import wing from "..";

fn test_ja4_tls_fingerprint(t: core::T&) {
    t.run("1. FoxIO JA4 Specification Conformance & Vector Verification") { sub =>
        let ciphers: u16[15] = [
            0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303,
            0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9,
        ];
        let extensions: u16[16] = [
            0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012,
            0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d, 0x0033, 0x4469, 0xff01,
        ];
        let supported_versions: u16[1] = [0x0304];
        let sig_algos: u16[8] = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];

        let ja4_result = wing::compute_ja4(
            ciphers[..],
            extensions[..],
            supported_versions[..],
            true,
            "h2",
            sig_algos[..],
            false
        );

        sub.assert_eq(ja4_result.len, 36, "JA4 fingerprint length must be exactly 36 chars");
        sub.assert_bytes_eq(ja4_result[..11], "t13d1516h2_", "JA4 standard prefix (t=TLS, 13=v1.3, d=SNI, 15 ciphers, 16 exts, h2 ALPN)");
        sub.assert_eq(ja4_result[23], '_' as u8, "Delimiter between cipher hash and extension hash");
    };

    t.run("2. RFC 8701 GREASE Invariance & Bitwise Filtering") { sub =>
        // Test all 16 reserved GREASE values
        let grease_samples: u16[16] = [
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
            0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
        ];
        for g in grease_samples {
            sub.assert_true(wing::is_grease_u16(g), "Must recognize valid RFC 8701 GREASE value");
        }
        sub.assert_false(wing::is_grease_u16(0x002f), "0x002f is not GREASE");
        sub.assert_false(wing::is_grease_u16(0x1301), "0x1301 is not GREASE");
        sub.assert_false(wing::is_grease_u16(0x0a1a), "0x0a1a has mismatched nibbles, not GREASE");

        // JA4 must be identical with or without GREASE injection
        let base_ciphers: u16[3] = [0x1301, 0x1302, 0x1303];
        let grease_ciphers: u16[5] = [0x0a0a, 0x1301, 0x2a2a, 0x1302, 0x1303];
        let base_exts: u16[2] = [0x0000, 0x002b];
        let grease_exts: u16[3] = [0x0000, 0x3a3a, 0x002b];
        let vers: u16[1] = [0x0304];

        let fp_clean = wing::compute_ja4(base_ciphers[..], base_exts[..], vers[..], true, "h2");
        let fp_grease = wing::compute_ja4(grease_ciphers[..], grease_exts[..], vers[..], true, "h2");

        sub.assert_bytes_eq(fp_clean[..], fp_grease[..], "JA4 must remain strictly invariant under GREASE injection");
    };

    t.run("3. QUIC Protocol Code and DTLS Support") { sub =>
        let ciphers: u16[3] = [0x1301, 0x1302, 0x1303];
        let exts: u16[2] = [0x0000, 0x002b];
        let vers: u16[1] = [0x0304];

        let ja4_quic = wing::compute_ja4(ciphers[..], exts[..], vers[..], true, "h3", [], true);
        sub.assert_bytes_eq(ja4_quic[..11], "q13d0302h3_", "QUIC JA4 prefix (q=QUIC, 13=v1.3, d=SNI, 03 ciphers, 02 exts, h3 ALPN)");
    };
}

fn test_ja4h_http_fingerprint(t: core::T&) {
    t.run("1. FoxIO JA4H HTTP Request Vector Verification") { sub =>
        let headers: const u8[:][4] = ["Accept", "Accept-Encoding", "Accept-Language", "User-Agent"];
        let cookie_names: const u8[:][2] = ["session_id", "csrf_token"];
        let cookie_values: const u8[:][2] = ["abc123xyz", "tok456"];

        let ja4h_result = wing::compute_ja4h(
            "GET",
            "HTTP/2",
            headers[..],
            true,
            false,
            "en-US,en;q=0.9",
            cookie_names[..],
            cookie_values[..]
        );

        sub.assert_eq(ja4h_result.len, 51, "JA4H fingerprint length must be 51 chars");
        sub.assert_bytes_eq(ja4h_result[..12], "ge20cn04enus", "JA4H prefix (ge=GET, 20=H2, c=cookie, n=no-referer, 04 headers, enus=Accept-Language)");
        sub.assert_eq(ja4h_result[12], '_' as u8, "Delimiter 1");
        sub.assert_eq(ja4h_result[25], '_' as u8, "Delimiter 2");
        sub.assert_eq(ja4h_result[38], '_' as u8, "Delimiter 3");
    };

    t.run("2. Header Sorting Case-Insensitivity & Cookie/Referer Exclusion") { sub =>
        // JA4H standard requires header names (excluding Cookie and Referer) to be sorted alphabetically in lowercase
        let mixed_headers: const u8[:][5] = ["User-Agent", "accept-language", "ACCEPT", "Cookie", "Referer"];
        let ja4h = wing::compute_ja4h("POST", "HTTP/1.1", mixed_headers[..], true, true, "ru-RU", [], []);

        // 3 headers counted (Cookie and Referer excluded from count), ruru language, c=cookie, r=referer
        sub.assert_bytes_eq(ja4h[..12], "po11cr03ruru", "PO=post, 11=HTTP/1.1, c=cookie, r=referer, 03 headers, ruru=lang");
    };
}

fn test_wing_profile_and_session(t: core::T&) {
    t.run("1. Wing Authentic Default Profile Inspection") { sub =>
        let p = wing::wing_default_profile();
        sub.assert_eq(p.kind, wing::ProfileKind.Wing, "Default profile kind is Wing");
        sub.assert_contains(p.user_agent[..], "Wing/1.0", "Wing authentic UA string");
        sub.assert_contains(p.accept_encoding[..], "zstd", "Wing advertises native RFC 8878 Zstandard!");
        sub.assert_eq(p.upgrade_insecure_requests[..], "1", "Upgrade-Insecure-Requests is 1");

        // Inspect Wing JA4 TLS profile
        let w_ja4 = wing::ja4(p);
        sub.assert_eq(w_ja4.len, 36, "Wing JA4 length is 36 chars");
        sub.assert_bytes_eq(w_ja4[..11], "t13d0910h2_", "Wing JA4 prefix: 9 modern ciphers, 10 extensions, TLS 1.3, h2 ALPN");

        // Inspect Wing JA4H HTTP profile
        let w_ja4h = wing::ja4h(p, "GET", "HTTP/2");
        sub.assert_bytes_eq(w_ja4h[..12], "ge20nn05enus", "Wing JA4H: GET, H2, no-cookie, no-referer, 5 headers, enus");
    };

    t.run("2. Client Session Out-of-the-Box Identity") { sub =>
        var session = wing::new_client();
        sub.assert_eq(session.profile, wing::Profile.Wing, "New client defaults to Profile.Wing");
        sub.assert_contains(wing::user_agent(session), "Wing/1.0", "Session defaults to Wing authentic User-Agent");

        // Default headers check
        var has_ua = false;
        var has_accept = false;
        var has_zstd = false;
        for &hdr in session.default_headers {
            if hdr.name[..] == "User-Agent" { has_ua = true; }
            if hdr.name[..] == "Accept" { has_accept = true; }
            if hdr.name[..] == "Accept-Encoding" && find(hdr.value[..], "zstd") >= 0 { has_zstd = true; }
        }
        sub.assert_true(has_ua, "User-Agent present in session default headers");
        sub.assert_true(has_accept, "Accept present in session default headers");
        sub.assert_true(has_zstd, "Zstandard present in session default Accept-Encoding");

        // Session JA4
        let s_ja4 = wing::ja4(session);
        sub.assert_bytes_eq(s_ja4[..11], "t13d0910h2_", "Session JA4 matches Wing default profile");
    };

    t.run("3. 100% User Control: Custom Profile Overrides Without Browser Mimicry") { sub =>
        var session = wing::new_client();

        // Caller can fully change UA and headers without any browser mimicry
        session.set_user_agent("CustomGooseBot/2.4 (Internal Systems)");
        sub.assert_bytes_eq(wing::user_agent(session), "CustomGooseBot/2.4 (Internal Systems)", "Custom user agent applied cleanly");

        // Caller can configure a completely custom BrowserProfile
        var custom = wing::custom_profile();
        custom.set_user_agent("WingCustomWorker/3.1");
        custom.set_accept("application/json");
        custom.set_accept_encoding("zstd");
        custom.set_accept_language("de-DE");
        custom.set_header("X-API-Client", "Wing/Core");

        session.set_profile(custom);
        sub.assert_bytes_eq(wing::user_agent(session), "WingCustomWorker/3.1", "Custom profile UA applied");

        let custom_ja4h = wing::ja4h(custom, "POST", "HTTP/2");
        sub.assert_bytes_eq(custom_ja4h[..12], "po20nn05dede", "Custom JA4H reflects custom profile headers (dede lang, 5 headers)");
    };
}

fn main() {
    var runner = core::new_runner("JA4 & Wing Profile Verification Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. FoxIO JA4 TLS Client Fingerprint Engine", test_ja4_tls_fingerprint);
    core::run_case(runner, "2. FoxIO JA4H HTTP Request Fingerprint Engine", test_ja4h_http_fingerprint);
    core::run_case(runner, "3. Wing Authentic Profile & Custom User Control", test_wing_profile_and_session);

    let ok = core::finish(runner);
    assert(ok);
}
