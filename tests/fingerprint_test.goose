// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification Suite for Client Fingerprinting: JA4/JA4H, Akamai HTTP/2, and p0f v3.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// Verification Suite for FoxIO JA4 (TLS) / JA4H (HTTP) fingerprinting and Wing Profile System.

fn test_ja4_tls_fingerprint(t: lit::T&) {
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
        let sig_algos:          u16[8] = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];

        let ja4_result = wing::compute_ja4(
            ciphers[..],
            extensions[..],
            supported_versions[..],
            true,
            "h2",
            sig_algos[..],
            false,
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
            sub.assert_true(rfc::is_grease_u16(g), "Must recognize valid RFC 8701 GREASE value");
        }
        sub.assert_false(rfc::is_grease_u16(0x002f), "0x002f is not GREASE");
        sub.assert_false(rfc::is_grease_u16(0x1301), "0x1301 is not GREASE");
        sub.assert_false(rfc::is_grease_u16(0x0a1a), "0x0a1a has mismatched nibbles, not GREASE");

        // JA4 must be identical with or without GREASE injection (ciphers, extensions, and signature algorithms)
        let base_ciphers:   u16[3] = [0x1301, 0x1302, 0x1303];
        let grease_ciphers: u16[5] = [0x0a0a, 0x1301, 0x2a2a, 0x1302, 0x1303];
        let base_exts:      u16[2] = [0x0000, 0x002b];
        let grease_exts:    u16[3] = [0x0000, 0x3a3a, 0x002b];
        let vers:           u16[1] = [0x0304];
        let base_sigs:      u16[2] = [0x0403, 0x0804];
        let grease_sigs:    u16[4] = [0x0a0a, 0x0403, 0x1a1a, 0x0804];

        let fp_clean = wing::compute_ja4(base_ciphers[..], base_exts[..], vers[..], true, "h2", base_sigs[..]);
        let fp_grease = wing::compute_ja4(grease_ciphers[..], grease_exts[..], vers[..], true, "h2", grease_sigs[..]);

        sub.assert_bytes_eq(fp_clean[..], fp_grease[..], "JA4 must remain strictly invariant under GREASE injection in ciphers, exts, and sig_algorithms");

        // Non-alphanumeric ALPN character handling
        let fp_alpn_custom = wing::compute_ja4(base_ciphers[..], base_exts[..], vers[..], true, " ", base_sigs[..]);
        sub.assert_bytes_eq(fp_alpn_custom[8..10], "20", "Non-alnum ALPN space byte (0x20) maps to '20'");
    };

    t.run("3. QUIC Protocol Code and DTLS Support") { sub =>
        let ciphers: u16[3] = [0x1301, 0x1302, 0x1303];
        let exts:    u16[2] = [0x0000, 0x002b];
        let vers:    u16[1] = [0x0304];

        let ja4_quic = wing::compute_ja4(ciphers[..], exts[..], vers[..], true, "h3", [], true);
        sub.assert_bytes_eq(ja4_quic[..11], "q13d0302h3_", "QUIC JA4 prefix (q=QUIC, 13=v1.3, d=SNI, 03 ciphers, 02 exts, h3 ALPN)");
    };
}

fn test_ja4h_http_fingerprint(t: lit::T&) {
    t.run("1. FoxIO JA4H HTTP Request Vector Verification") { sub =>
        let headers:       const u8[:][4] = ["Accept", "Accept-Encoding", "Accept-Language", "User-Agent"];
        let cookie_names:  const u8[:][2] = ["session_id", "csrf_token"];
        let cookie_values: const u8[:][2] = ["abc123xyz", "tok456"];

        let ja4h_result = wing::compute_ja4h(
            "GET",
            "HTTP/2",
            headers[..],
            wing::Ja4hFlags { has_cookie: true, has_referer: false },
            "en-US,en;q=0.9",
            cookie_names[..],
            cookie_values[..],
        );

        sub.assert_eq(ja4h_result.len, 51, "JA4H fingerprint length must be 51 chars");
        sub.assert_bytes_eq(ja4h_result[..12], "ge20cn04enus", "JA4H prefix (ge=GET, 20=H2, c=cookie, n=no-referer, 04 headers, enus=Accept-Language)");
        sub.assert_eq(ja4h_result[12], '_' as u8, "Delimiter 1");
        sub.assert_eq(ja4h_result[25], '_' as u8, "Delimiter 2");
        sub.assert_eq(ja4h_result[38], '_' as u8, "Delimiter 3");
    };

    t.run("2. Header Wire-Order & Cookie Alphabetical Sorting & Exclusion") { sub =>
        // Headers preserve wire transmission order in section b
        let h_order1: const u8[:][2] = ["Accept", "User-Agent"];
        let h_order2: const u8[:][2] = ["User-Agent", "Accept"];
        let ja4h_1 = wing::compute_ja4h("GET", "HTTP/2", h_order1[..], wing::Ja4hFlags { has_cookie: false, has_referer: false });
        let ja4h_2 = wing::compute_ja4h("GET", "HTTP/2", h_order2[..], wing::Ja4hFlags { has_cookie: false, has_referer: false });
        sub.assert_false(ja4h_1[13..25] == ja4h_2[13..25], "Different header arrival order produces distinct JA4H_b hash");

        // Cookies are sorted alphabetically in section c & d regardless of arrival order
        let c_names1: const u8[:][2] = ["zebra", "apple"];
        let c_vals1:  const u8[:][2] = ["z1", "a1"];
        let c_names2: const u8[:][2] = ["apple", "zebra"];
        let c_vals2:  const u8[:][2] = ["a1", "z1"];
        let ja4h_c1 = wing::compute_ja4h("GET", "HTTP/2", h_order1[..], wing::Ja4hFlags { has_cookie: true, has_referer: false }, "", c_names1[..], c_vals1[..]);
        let ja4h_c2 = wing::compute_ja4h("GET", "HTTP/2", h_order1[..], wing::Ja4hFlags { has_cookie: true, has_referer: false }, "", c_names2[..], c_vals2[..]);
        sub.assert_bytes_eq(ja4h_c1[26..38], ja4h_c2[26..38], "Cookie names hash JA4H_c is invariant under permutation");
        sub.assert_bytes_eq(ja4h_c1[39..51], ja4h_c2[39..51], "Cookie values hash JA4H_d is invariant under permutation");

        let mixed_headers: const u8[:][5] = ["User-Agent", "accept-language", "ACCEPT", "Cookie", "Referer"];
        let ja4h = wing::compute_ja4h("POST", "HTTP/1.1", mixed_headers[..], wing::Ja4hFlags { has_cookie: true, has_referer: true }, "ru-RU", [], []);

        // 3 headers counted (Cookie and Referer excluded from count), ruru language, c=cookie, r=referer
        sub.assert_bytes_eq(ja4h[..12], "po11cr03ruru", "PO=post, 11=HTTP/1.1, c=cookie, r=referer, 03 headers, ruru=lang");
    };
}

fn test_wing_profile_and_session(t: lit::T&) {
    t.run("1. Wing Authentic Default Profile Inspection") { sub =>
        let p = wing::wing_default_profile();
        sub.assert_eq(p.kind, wing::Profile.Wing, "Default profile kind is Wing");
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
        let has_ua = wing::has_header(session.default_headers, "User-Agent");
        let has_accept = wing::has_header(session.default_headers, "Accept");
        let has_zstd = find(wing::get_header(session.default_headers, "Accept-Encoding"), "zstd") >= 0;
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

        // set_header overrides standard headers without creating duplicates
        var prof_ovr = wing::wing_default_profile();
        wing::set_header(prof_ovr, "User-Agent", "UniqueUA/1.0");
        sub.assert_bytes_eq(prof_ovr.user_agent[..], "UniqueUA/1.0", "set_header overrides user_agent field");
        sub.assert_eq(prof_ovr.extra_headers.entries.len, 0, "No duplicate in extra_headers");
    };
}

// Verification suite for Akamai HTTP/2 Passive Fingerprinting & Active Matching Engine:
// 1. Presets formatting (Chrome, Firefox, Safari, Wing, cURL) and MD5 hash generation
// 2. Parsing and bidirectional round-trip deserialization
// 3. Signature matching and client family identification
// 4. Passive anomaly detection (Anti-Bot spoofing detection)
// 5. Binary HTTP/2 wire framing round-trip (ingress extractor & egress generator)
// 6. Pseudo-header canonical ordering
// 7. High-level BrowserProfile and Session integration

fn test_akamai_presets_and_hashes(t: lit::T&) {
    t.run("Verify standard Akamai fingerprint presets and MD5 hashes") { sub =>
        // 1. Chrome 124+ Preset
        let chrome_fp = wing::akamai_chrome_preset();
        let chrome_str = wing::akamai_fingerprint_to_string(chrome_fp);
        sub.assert_eq(chrome_str[..], "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", "Chrome fingerprint string format");

        let chrome_hash = wing::akamai_fingerprint_hash(chrome_fp);
        sub.assert_eq(chrome_hash.len, 32, "Chrome Akamai MD5 hash is 32 hex chars");

        // Verify hash determinism
        var chrome_hash2: u8[..32] = [];
        wing::compute_akamai_hash(chrome_fp, chrome_hash2);
        sub.assert_eq(chrome_hash[..], chrome_hash2[..], "Akamai hash is 100% deterministic");

        // 2. Firefox 124+ Preset
        let ff_fp = wing::akamai_firefox_preset();
        let ff_str = wing::akamai_fingerprint_to_string(ff_fp);
        sub.assert_eq(ff_str[..], "1:65536;4:131072;5:16384|12517377|0|m,p,a,s", "Firefox fingerprint string format");

        // 3. Safari 17+ Preset
        let saf_fp = wing::akamai_safari_preset();
        let saf_str = wing::akamai_fingerprint_to_string(saf_fp);
        sub.assert_eq(saf_str[..], "2:0;3:100;4:2097152|10485760|0|m,s,a,p", "Safari fingerprint string format");

        // 4. Wing Default Systems Engine Preset
        let wing_fp = wing::akamai_wing_preset();
        let wing_str = wing::akamai_fingerprint_to_string(wing_fp);
        sub.assert_eq(wing_str[..], "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p", "Wing fingerprint string format");

        // 5. cURL Preset
        let curl_fp = wing::akamai_curl_preset();
        let curl_str = wing::akamai_fingerprint_to_string(curl_fp);
        sub.assert_eq(curl_str[..], "1:4096;2:0;3:100;4:65535|0|0|m,a,p,s", "cURL fingerprint string format");
    };
}

fn test_akamai_parsing_and_roundtrip(t: lit::T&) {
    t.run("Parse raw Akamai string and verify round-trip serialization") { sub =>
        let raw = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";
        let fp, ok = wing::parse_akamai_fingerprint(raw);
        sub.assert_true(ok, "Parsed valid Akamai fingerprint");
        sub.assert_eq(fp.settings.len, 4, "Parsed 4 settings");
        sub.assert_eq(fp.settings[0].id, 1, "Setting 0 id = 1");
        sub.assert_eq(fp.settings[0].val, 65536, "Setting 0 val = 65536");
        sub.assert_eq(fp.settings[1].id, 2, "Setting 1 id = 2");
        sub.assert_eq(fp.settings[1].val, 0, "Setting 1 val = 0");
        sub.assert_eq(fp.settings[2].id, 4, "Setting 2 id = 4");
        sub.assert_eq(fp.settings[2].val, 6291456, "Setting 2 val = 6291456");
        sub.assert_eq(fp.settings[3].id, 6, "Setting 3 id = 6");
        sub.assert_eq(fp.settings[3].val, 262144, "Setting 3 val = 262144");

        sub.assert_eq(fp.window_update, 15663105, "Window update increment");
        sub.assert_eq(fp.priority_frames.len, 0, "No priority frames");
        sub.assert_eq(fp.pseudo_headers.len, 4, "4 pseudo headers");
        sub.assert_eq(fp.pseudo_headers[0], 'm', "First is 'm'");
        sub.assert_eq(fp.pseudo_headers[1], 'a', "Second is 'a'");
        sub.assert_eq(fp.pseudo_headers[2], 's', "Third is 's'");
        sub.assert_eq(fp.pseudo_headers[3], 'p', "Fourth is 'p'");

        // Roundtrip check
        let roundtrip = wing::akamai_fingerprint_to_string(fp);
        sub.assert_eq(roundtrip[..], raw, "Roundtrip serialization is identical to input");

        // Parse with priority tree
        let raw_prio = "1:65536|1048576|3:0:0:201,5:1:3:101|m,p,a,s";
        let fp2, ok2 = wing::parse_akamai_fingerprint(raw_prio);
        sub.assert_true(ok2, "Parsed priority tree");
        sub.assert_eq(fp2.priority_frames.len, 2, "Parsed 2 priority frames");
        sub.assert_eq(fp2.priority_frames[0].stream_id, 3, "Stream 3");
        sub.assert_eq(fp2.priority_frames[0].exclusive, 0, "Not exclusive");
        sub.assert_eq(fp2.priority_frames[0].dep_stream_id, 0, "Dep stream 0");
        sub.assert_eq(fp2.priority_frames[0].weight, 201, "Weight 201");

        sub.assert_eq(fp2.priority_frames[1].stream_id, 5, "Stream 5");
        sub.assert_eq(fp2.priority_frames[1].exclusive, 1, "Exclusive");
        sub.assert_eq(fp2.priority_frames[1].dep_stream_id, 3, "Dep stream 3");
        sub.assert_eq(fp2.priority_frames[1].weight, 101, "Weight 101");

        let roundtrip2 = wing::akamai_fingerprint_to_string(fp2);
        sub.assert_eq(roundtrip2[..], raw_prio, "Priority roundtrip identical");

        // Error cases
        let _, bad1 = wing::parse_akamai_fingerprint("invalid_string_without_pipes");
        sub.assert_false(bad1, "Fails on missing pipes");

        let _, bad2 = wing::parse_akamai_fingerprint("1:65536|1000|0|m,a,s,p|extra_pipe");
        sub.assert_false(bad2, "Fails on extra pipe");

        let _, bad3 = wing::parse_akamai_fingerprint("1:not_a_number|1000|0|m,a,s,p");
        sub.assert_false(bad3, "Fails on non-numeric setting value");

        let _, bad4 = wing::parse_akamai_fingerprint("1:65536|1000|3:0:0:0|m,a,s,p");
        sub.assert_false(bad4, "Fails on priority weight 0 (< 1)");

        let _, bad5 = wing::parse_akamai_fingerprint("1:65536|1000|3:0:0:257|m,a,s,p");
        sub.assert_false(bad5, "Fails on priority weight 257 (> 256)");
    };
}

fn test_akamai_matching_and_family(t: lit::T&) {
    t.run("Verify Akamai matching logic and family classification") { sub =>
        let chrome1 = wing::akamai_chrome_preset();
        let chrome2 = wing::akamai_chrome_preset();
        let ff = wing::akamai_firefox_preset();
        let saf = wing::akamai_safari_preset();
        let wing_preset = wing::akamai_wing_preset();
        let curl_preset = wing::akamai_curl_preset();

        sub.assert_true(wing::match_akamai_fingerprints(chrome1, chrome2), "Identical Chrome presets match");
        sub.assert_false(wing::match_akamai_fingerprints(chrome1, ff), "Chrome does not match Firefox");
        sub.assert_false(wing::match_akamai_fingerprints(chrome1, saf), "Chrome does not match Safari");

        // Family classification
        let f_chrome = wing::identify_akamai_family(chrome1);
        sub.assert_true(f_chrome == wing::AkamaiBrowserFamily.Chrome, "Identified Chrome");

        let f_ff = wing::identify_akamai_family(ff);
        sub.assert_true(f_ff == wing::AkamaiBrowserFamily.Firefox, "Identified Firefox");

        let f_saf = wing::identify_akamai_family(saf);
        sub.assert_true(f_saf == wing::AkamaiBrowserFamily.Safari, "Identified Safari");

        let f_wing = wing::identify_akamai_family(wing_preset);
        sub.assert_true(f_wing == wing::AkamaiBrowserFamily.Wing, "Identified Wing");

        let f_curl = wing::identify_akamai_family(curl_preset);
        sub.assert_true(f_curl == wing::AkamaiBrowserFamily.Curl, "Identified Curl");
    };
}

fn test_akamai_anomaly_detection(t: lit::T&) {
    t.run("Passive anomaly detection: detect spoofed User-Agents and bot signatures") { sub =>
        let chrome_fp = wing::akamai_chrome_preset();
        let ff_fp = wing::akamai_firefox_preset();
        let curl_fp = wing::akamai_curl_preset();

        // 1. Legitimate Chrome: UA matches HTTP/2 signature
        let ua_chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36";
        let a1, _ = wing::detect_akamai_anomaly(ua_chrome, chrome_fp);
        sub.assert_true(a1 == wing::AkamaiAnomaly.None, "Legitimate Chrome passes");

        // 2. Spoofing attempt: UA claims to be Chrome, but HTTP/2 stack sends Firefox pseudo-headers (m,p,a,s)
        let a2, _ = wing::detect_akamai_anomaly(ua_chrome, ff_fp);
        sub.assert_true(a2 == wing::AkamaiAnomaly.PseudoHeaderOrderMismatch, "Detects pseudo-header order spoofing");

        // 3. Spoofing attempt: UA claims Chrome, but client omitted WINDOW_UPDATE (e.g. curl/custom python bot)
        var bot_fp = wing::akamai_chrome_preset();
        bot_fp.window_update = 0; // Omitted window update
        let a3, _ = wing::detect_akamai_anomaly(ua_chrome, bot_fp);
        sub.assert_true(a3 == wing::AkamaiAnomaly.WindowUpdateAnomaly, "Detects omitted window update bot pattern");

        // 4. Legitimate Firefox passes
        let ua_firefox = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0";
        let a4, _ = wing::detect_akamai_anomaly(ua_firefox, ff_fp);
        sub.assert_true(a4 == wing::AkamaiAnomaly.None, "Legitimate Firefox passes");

        // 5. Firefox UA with Chrome ordering
        let a5, _ = wing::detect_akamai_anomaly(ua_firefox, chrome_fp);
        sub.assert_true(a5 == wing::AkamaiAnomaly.PseudoHeaderOrderMismatch, "Detects non-Gecko ordering for Firefox UA");

        // 6. Legitimate Curl passes
        let a6, _ = wing::detect_akamai_anomaly("curl/8.6.0", curl_fp);
        sub.assert_true(a6 == wing::AkamaiAnomaly.None, "Legitimate Curl passes");
    };
}

fn test_akamai_wire_framing_roundtrip(t: lit::T&) {
    t.run("HTTP/2 binary framing: serialize to wire bytes and parse back identically") { sub =>
        let chrome_fp = wing::akamai_chrome_preset();

        // 1. Serialize wire frames
        var wire_buf: u8[>..] = [];
        // Add HTTP/2 preface first
        wire_buf.append(rfc::H2_CLIENT_PREFACE[..]);
        // Encode handshake frames: SETTINGS + WINDOW_UPDATE
        wing::encode_akamai_handshake_frames(chrome_fp, wire_buf);

        // Verify total length: 24 (preface) + 9 (SETTINGS hdr) + 24 (4*6 payload) + 9 (WU hdr) + 4 (payload) = 70 bytes
        sub.assert_eq(wire_buf.len, 70, "70 bytes wire frame stream");

        // 2. Extract Akamai fingerprint from wire bytes
        let pseudos = "m,a,s,p";
        let extracted_fp, ok = wing::extract_akamai_from_wire(wire_buf[..], pseudos);
        sub.assert_true(ok, "Extracted fingerprint from raw HTTP/2 wire frames");

        // 3. Verify extracted fingerprint matches original Chrome preset 100%
        sub.assert_true(wing::match_akamai_fingerprints(extracted_fp, chrome_fp), "Extracted wire fingerprint matches Chrome preset exactly");
        sub.assert_eq(extracted_fp.window_update, 15663105, "Extracted window update is 15663105");
        sub.assert_eq(extracted_fp.settings.len, 4, "Extracted 4 settings");

        // 4. Reject garbage / non-HTTP/2 input (e.g. plain HTTP/1.1 request)
        let http1_req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let _, ok_bad = wing::extract_akamai_from_wire(http1_req, pseudos);
        sub.assert_false(ok_bad, "Rejects plain HTTP/1.1 stream lacking valid HTTP/2 SETTINGS frame");
    };
}

fn test_akamai_pseudo_header_ordering(t: lit::T&) {
    t.run("Order pseudo headers according to browser specification") { sub =>
        let chrome_fp = wing::akamai_chrome_preset();
        var chrome_ordered = wing::HeaderMap { .. };
        wing::order_pseudo_headers(chrome_fp, "GET", "api.example.com", "https", "/v1/data", chrome_ordered);

        sub.assert_eq(chrome_ordered.entries.len, 4, "4 ordered headers");
        sub.assert_eq(wing::entry_name(chrome_ordered, chrome_ordered.entries[0]), ":method", "Chrome 0 is :method");
        sub.assert_eq(wing::entry_name(chrome_ordered, chrome_ordered.entries[1]), ":authority", "Chrome 1 is :authority");
        sub.assert_eq(wing::entry_name(chrome_ordered, chrome_ordered.entries[2]), ":scheme", "Chrome 2 is :scheme");
        sub.assert_eq(wing::entry_name(chrome_ordered, chrome_ordered.entries[3]), ":path", "Chrome 3 is :path");

        let ff_fp = wing::akamai_firefox_preset();
        var ff_ordered = wing::HeaderMap { .. };
        wing::order_pseudo_headers(ff_fp, "GET", "api.example.com", "https", "/v1/data", ff_ordered);

        sub.assert_eq(wing::entry_name(ff_ordered, ff_ordered.entries[0]), ":method", "Firefox 0 is :method");
        sub.assert_eq(wing::entry_name(ff_ordered, ff_ordered.entries[1]), ":path", "Firefox 1 is :path");
        sub.assert_eq(wing::entry_name(ff_ordered, ff_ordered.entries[2]), ":authority", "Firefox 2 is :authority");
        sub.assert_eq(wing::entry_name(ff_ordered, ff_ordered.entries[3]), ":scheme", "Firefox 3 is :scheme");

        let saf_fp = wing::akamai_safari_preset();
        var saf_ordered = wing::HeaderMap { .. };
        wing::order_pseudo_headers(saf_fp, "GET", "api.example.com", "https", "/v1/data", saf_ordered);

        sub.assert_eq(wing::entry_name(saf_ordered, saf_ordered.entries[0]), ":method", "Safari 0 is :method");
        sub.assert_eq(wing::entry_name(saf_ordered, saf_ordered.entries[1]), ":scheme", "Safari 1 is :scheme");
        sub.assert_eq(wing::entry_name(saf_ordered, saf_ordered.entries[2]), ":authority", "Safari 2 is :authority");
        sub.assert_eq(wing::entry_name(saf_ordered, saf_ordered.entries[3]), ":path", "Safari 3 is :path");
    };
}

fn test_akamai_browser_profiles(t: lit::T&) {
    t.run("ClientProfile exports authentic Wing Akamai fingerprint") { sub =>
        let wp = wing::wing_default_profile();
        let fp_str4 = wing::akamai(wp);
        sub.assert_eq(fp_str4[..], "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p", "Wing default profile has authentic Wing Akamai fingerprint");

        // Session integration
        var session = wing::new_session();
        let sess_ak = session.akamai();
        sub.assert_eq(sess_ak[..], fp_str4[..], "Session exports authentic Akamai fingerprint");
        let sess_hash = session.akamai_hash();
        sub.assert_eq(sess_hash.len, 32, "Session exports 32-char Akamai hash");
    };
}

// Verification Suite for Passive OS Fingerprinting (p0f v3) TCP SYN Engine.

fn test_wing_authentic_p0f(t: lit::T&) {
    t.run("1. Wing Authentic TCP SYN Identity Spec") { sub =>
        let sig = wing::wing_p0f_signature();

        sub.assert_eq(sig.ip_version as i64, 0, "Dual-stack wildcard IP version ('*')");
        sub.assert_eq(sig.ttl as i64, 64, "Initial TTL 64");
        sub.assert_false(sig.has_ttl_minus, "Default profile has exact initial TTL");
        sub.assert_eq(sig.ip_opt_len as i64, 0, "No archaic IP options");
        sub.assert_eq(sig.mss as i64, -1, "Wildcard MSS ('*') discovered via Path MTU");
        sub.assert_eq(sig.window_type, wing::P0fWindowType.Mss, "Dynamic window based on MSS multiplier");
        sub.assert_eq(sig.window_size as i64, 20, "Window multiplier: mss*20");
        sub.assert_eq(sig.window_scale as i64, 10, "Window scale: 10 for multi-gigabit throughput");

        // Options layout
        sub.assert_eq(sig.options.len, 5, "5 standard RFC TCP options");
        sub.assert_eq(sig.options[0], wing::P0fTcpOption.Mss, "Option 1: MSS");
        sub.assert_eq(sig.options[1], wing::P0fTcpOption.Sok, "Option 2: SACK Permitted");
        sub.assert_eq(sig.options[2], wing::P0fTcpOption.Ts, "Option 3: Timestamps");
        sub.assert_eq(sig.options[3], wing::P0fTcpOption.Nop, "Option 4: NOP alignment");
        sub.assert_eq(sig.options[4], wing::P0fTcpOption.Ws, "Option 5: Window Scale");

        // Quirks
        sub.assert_true(sig.quirks.df, "Don't Fragment (DF) enabled for Path MTU Discovery");
        sub.assert_true(sig.quirks.id_plus, "Random IP ID generated");
        sub.assert_false(sig.quirks.ecn, "ECN not set in default SYN");

        // Canonical format
        let formatted = wing::format_p0f(sig);
        sub.assert_bytes_eq(
            formatted[..],
            "*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0",
            "Wing authentic p0f v3 wire signature matches canonical specification",
        );
    };

    t.run("2. Socket Parameter Derivation & Client Integration") { sub =>
        let sig = wing::wing_p0f_signature();
        let sock_opts = wing::p0f_to_socket_opts(sig, 1460);

        sub.assert_eq(sock_opts.ttl as i64, 64, "Socket TTL option is 64");
        sub.assert_true(sock_opts.dont_fragment, "Socket IP_DONTFRAGMENT is enabled");
        sub.assert_eq(sock_opts.receive_buffer_size as i64, 29200, "SO_RCVBUF is 1460 * 20 = 29200 bytes");

        // Profile default has wing_p0f_signature
        let profile = wing::wing_default_profile();
        let p_p0f = wing::p0f(profile);
        sub.assert_bytes_eq(
            p_p0f[..],
            "*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0",
            "Default BrowserProfile exports authentic Wing p0f signature",
        );

        // Client session exposes p0f signature
        let session = wing::new_client();
        let s_p0f = wing::p0f(session);
        sub.assert_bytes_eq(
            s_p0f[..],
            "*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0",
            "New client session default p0f reflects Wing authentic identity",
        );
    };
}

fn test_p0f_parser_and_roundtrip(t: lit::T&) {
    t.run("1. Standard p0f v3 Signatures Roundtrip") { sub =>
        // Vector 1: Wing Authentic Profile
        let raw1 = "*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0";
        let sig1, ok1 = wing::parse_p0f(raw1);
        sub.assert_true(ok1, "Must parse Wing signature");
        sub.assert_bytes_eq(wing::format_p0f(sig1)[..], raw1, "Roundtrip 1 must be exact");

        // Vector 2: MTU multiplier window with IPv4
        let raw2 = "4:64:0:1460:mtu*4,0:mss,sok:df:0";
        let sig2, ok2 = wing::parse_p0f(raw2);
        sub.assert_true(ok2, "Must parse MTU window signature");
        sub.assert_eq(sig2.ip_version as i64, 4, "IPv4");
        sub.assert_eq(sig2.mss as i64, 1460, "MSS 1460");
        sub.assert_eq(sig2.window_type, wing::P0fWindowType.Mtu, "MTU multiplier");
        sub.assert_eq(sig2.window_size as i64, 4, "Window size 4");
        sub.assert_eq(sig2.window_scale as i64, 0, "Window scale 0");
        sub.assert_bytes_eq(wing::format_p0f(sig2)[..], raw2, "Roundtrip 2 must be exact");

        // Vector 3: Exact / Normal window size with IPv6
        let raw3 = "6:128:0:1440:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0";
        let sig3, ok3 = wing::parse_p0f(raw3);
        sub.assert_true(ok3, "Must parse exact window signature");
        sub.assert_eq(sig3.ip_version as i64, 6, "IPv6");
        sub.assert_eq(sig3.ttl as i64, 128, "TTL 128");
        sub.assert_eq(sig3.window_type, wing::P0fWindowType.Normal, "Normal window");
        sub.assert_eq(sig3.window_size as i64, 65535, "Window size 65535");
        sub.assert_eq(sig3.window_scale as i64, 8, "Window scale 8");
        sub.assert_bytes_eq(wing::format_p0f(sig3)[..], raw3, "Roundtrip 3 must be exact");

        // Vector 4: Wildcard window size (*,-1)
        let raw4 = "*:64:0:*:*,-1:mss,sok,ts,nop,ws:df,id+:0";
        let sig4, ok4 = wing::parse_p0f(raw4);
        sub.assert_true(ok4, "Must parse wildcard window signature");
        sub.assert_eq(sig4.window_type, wing::P0fWindowType.Any, "Any window type");
        sub.assert_eq(sig4.window_size as i64, -1, "Wildcard window size");
        sub.assert_eq(sig4.window_scale as i64, -1, "Wildcard window scale");
        sub.assert_bytes_eq(wing::format_p0f(sig4)[..], raw4, "Roundtrip 4 must be exact");

        // Vector 5: TTL minus wildcard (64-)
        let raw5 = "*:64-:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0";
        let sig5, ok5 = wing::parse_p0f(raw5);
        sub.assert_true(ok5, "Must parse TTL minus signature");
        sub.assert_true(sig5.has_ttl_minus, "has_ttl_minus is true");
        sub.assert_eq(sig5.ttl as i64, 64, "Base TTL 64");
        sub.assert_bytes_eq(wing::format_p0f(sig5)[..], raw5, "Roundtrip 5 must be exact");
    };

    t.run("2. Strong Parsing and Error Rejection") { sub =>
        // Too few fields
        let _, err1 = wing::parse_p0f("too:few:parts");
        sub.assert_false(err1, "Rejects signature with < 8 fields");

        // Empty input
        let _, err2 = wing::parse_p0f("");
        sub.assert_false(err2, "Rejects empty input");

        // Invalid IP version
        let _, err3 = wing::parse_p0f("3:64:0:*:mss*20,10:mss:df:0");
        sub.assert_false(err3, "Rejects invalid IP version '3'");

        // Invalid TTL
        let _, err4 = wing::parse_p0f("*:invalid:0:*:mss*20,10:mss:df:0");
        sub.assert_false(err4, "Rejects non-numeric TTL");

        // Missing window scale
        let _, err5 = wing::parse_p0f("*:64:0:*:65535:mss:df:0");
        sub.assert_false(err5, "Rejects window field without comma separator");

        // Payload buffer overflow (> 8 chars)
        let _, err6 = wing::parse_p0f("*:64:0:*:65535,0:mss:df:excessive_payload_length");
        sub.assert_false(err6, "Rejects payload exceeding buffer capacity");

        // Apple Darwin/FreeBSD eol+1 TCP option parsing
        let apple_raw = "*:64:0:*:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0";
        let sig_apple, ok_apple = wing::parse_p0f(apple_raw);
        sub.assert_true(ok_apple, "Successfully parses Darwin/FreeBSD eol+1 option layout");
        sub.assert_eq(sig_apple.options.len, 8, "Darwin signature has 8 TCP options");
        sub.assert_eq(sig_apple.options[7], wing::P0fTcpOption.Eol, "eol+1 maps to P0fTcpOption.Eol");
    };
}

fn test_p0f_pattern_matching(t: lit::T&) {
    t.run("1. Exact and Self Matching") { sub =>
        let sig = wing::wing_p0f_signature();
        sub.assert_true(wing::match_p0f(sig, sig), "Signature matches itself");
    };

    t.run("2. Hop Degradation Tolerance with TTL-minus") { sub =>
        let pattern_raw = "*:64-:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0";
        let pattern, ok = wing::parse_p0f(pattern_raw);
        sub.assert_true(ok, "Parsed pattern");

        // Packet arrived with TTL degraded from 64 to 52 (12 network hops)
        var actual = wing::wing_p0f_signature();
        actual.ttl = 52;
        sub.assert_true(wing::match_p0f(actual, pattern), "Accepts TTL degraded within 35 hops");

        // Packet arrived with TTL degraded by > 35 hops (TTL 20)
        actual.ttl = 20;
        sub.assert_false(wing::match_p0f(actual, pattern), "Rejects TTL degraded beyond 35 hops");
    };

    t.run("3. Option Layout and Quirk Discrimination") { sub =>
        let base = wing::wing_p0f_signature();

        // Altered option layout (missing Timestamps)
        var altered_opts = base;
        altered_opts.options.clear();
        altered_opts.options.push(wing::P0fTcpOption.Mss);
        altered_opts.options.push(wing::P0fTcpOption.Sok);
        altered_opts.options.push(wing::P0fTcpOption.Nop);
        altered_opts.options.push(wing::P0fTcpOption.Ws);
        sub.assert_false(wing::match_p0f(altered_opts, base), "Option layout mismatch fails matching");

        // Altered quirks (DF disabled)
        var altered_quirks = base;
        altered_quirks.quirks.df = false;
        sub.assert_false(wing::match_p0f(altered_quirks, base), "Missing required DF quirk fails matching");

        // Payload mismatch
        var altered_payload = base;
        altered_payload.payload.clear();
        altered_payload.payload.append("+");
        sub.assert_false(wing::match_p0f(altered_payload, base), "Unexpected non-zero payload fails matching");
    };

    t.run("4. Custom P0f Builder and Quirk Helpers") { sub =>
        var custom = wing::custom_p0f_signature(4, 128, false, 1400, wing::P0fWindowType.Normal, 16384, 2);
        wing::p0f_push_option(custom, wing::P0fTcpOption.Mss);
        wing::p0f_push_option(custom, wing::P0fTcpOption.Ws);
        wing::p0f_set_quirk(custom, "df", true);
        wing::p0f_set_quirk(custom, "ecn", true);
        custom.payload.append("0");

        sub.assert_true(wing::p0f_has_quirk(custom, "df"), "Quirk 'df' is set");
        sub.assert_true(wing::p0f_has_quirk(custom, "ecn"), "Quirk 'ecn' is set");
        sub.assert_false(wing::p0f_has_quirk(custom, "id+"), "Quirk 'id+' is not set");

        let formatted = wing::format_p0f(custom);
        sub.assert_bytes_eq(
            formatted[..],
            "4:128:0:1400:16384,2:mss,ws:df,ecn:0",
            "Custom signature formatted correctly",
        );

        // Plug into BrowserProfile
        var profile = wing::custom_profile();
        wing::set_p0f(profile, custom);
        let prof_str = wing::p0f(profile);
        sub.assert_bytes_eq(
            prof_str[..],
            "4:128:0:1400:16384,2:mss,ws:df,ecn:0",
            "BrowserProfile successfully incorporates custom p0f signature",
        );
    };
}

fn main() {
    var runner = lit::new_runner("Client Fingerprinting Verification Suite (JA4, Akamai, p0f)", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. JA4: FoxIO JA4 TLS Client Fingerprint Engine", test_ja4_tls_fingerprint);
    lit::run_case(runner, "2. JA4: FoxIO JA4H HTTP Request Fingerprint Engine", test_ja4h_http_fingerprint);
    lit::run_case(runner, "3. JA4: Wing Authentic Profile & Custom User Control", test_wing_profile_and_session);
    lit::run_case(runner, "4. Akamai: Presets and MD5 Hash Generation", test_akamai_presets_and_hashes);
    lit::run_case(runner, "5. Akamai: Parsing and Round-trip Deserialization", test_akamai_parsing_and_roundtrip);
    lit::run_case(runner, "6. Akamai: Fingerprint Matching and Family Classification", test_akamai_matching_and_family);
    lit::run_case(runner, "7. Akamai: Passive Anomaly Detection", test_akamai_anomaly_detection);
    lit::run_case(runner, "8. Akamai: Binary HTTP/2 Wire Framing Round-trip", test_akamai_wire_framing_roundtrip);
    lit::run_case(runner, "9. Akamai: Pseudo-header Canonical Ordering", test_akamai_pseudo_header_ordering);
    lit::run_case(runner, "10. Akamai: BrowserProfile and Session Integration", test_akamai_browser_profiles);
    lit::run_case(runner, "11. p0f: Wing Authentic TCP SYN Identity", test_wing_authentic_p0f);
    lit::run_case(runner, "12. p0f: Standard p0f v3 Parser & Roundtrip", test_p0f_parser_and_roundtrip);
    lit::run_case(runner, "13. p0f: Pattern Matching & Discrimination", test_p0f_pattern_matching);

    let ok = lit::finish(runner);
    assert(ok);
}
