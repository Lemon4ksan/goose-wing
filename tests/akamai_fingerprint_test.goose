// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for Akamai HTTP/2 Passive Fingerprinting & Active Matching Engine:
// 1. Presets formatting (Chrome, Firefox, Safari, Wing, cURL) and MD5 hash generation
// 2. Parsing and bidirectional round-trip deserialization
// 3. Signature matching and client family identification
// 4. Passive anomaly detection (Anti-Bot spoofing detection)
// 5. Binary HTTP/2 wire framing round-trip (ingress extractor & egress generator)
// 6. Pseudo-header canonical ordering
// 7. High-level BrowserProfile and Session integration
import std;
import core from "..";
import wing from "..";

fn test_akamai_presets_and_hashes(t: core::T&) {
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

fn test_akamai_parsing_and_roundtrip(t: core::T&) {
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
    };
}

fn test_akamai_matching_and_family(t: core::T&) {
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

fn test_akamai_anomaly_detection(t: core::T&) {
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

fn test_akamai_wire_framing_roundtrip(t: core::T&) {
    t.run("HTTP/2 binary framing: serialize to wire bytes and parse back identically") { sub =>
        let chrome_fp = wing::akamai_chrome_preset();

        // 1. Serialize wire frames
        var wire_buf: u8[>..] = [];
        // Add HTTP/2 preface first
        wire_buf.append(wing::H2_CLIENT_PREFACE[..]);
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
    };
}

fn test_akamai_pseudo_header_ordering(t: core::T&) {
    t.run("Order pseudo headers according to browser specification") { sub =>
        let chrome_fp = wing::akamai_chrome_preset();
        var chrome_ordered: wing::HeaderItem[..4] = [];
        wing::order_pseudo_headers(chrome_fp, "GET", "api.example.com", "https", "/v1/data", chrome_ordered);

        sub.assert_eq(chrome_ordered.len, 4, "4 ordered headers");
        sub.assert_eq(chrome_ordered[0].name[..], ":method", "Chrome 0 is :method");
        sub.assert_eq(chrome_ordered[1].name[..], ":authority", "Chrome 1 is :authority");
        sub.assert_eq(chrome_ordered[2].name[..], ":scheme", "Chrome 2 is :scheme");
        sub.assert_eq(chrome_ordered[3].name[..], ":path", "Chrome 3 is :path");

        let ff_fp = wing::akamai_firefox_preset();
        var ff_ordered: wing::HeaderItem[..4] = [];
        wing::order_pseudo_headers(ff_fp, "GET", "api.example.com", "https", "/v1/data", ff_ordered);

        sub.assert_eq(ff_ordered[0].name[..], ":method", "Firefox 0 is :method");
        sub.assert_eq(ff_ordered[1].name[..], ":path", "Firefox 1 is :path");
        sub.assert_eq(ff_ordered[2].name[..], ":authority", "Firefox 2 is :authority");
        sub.assert_eq(ff_ordered[3].name[..], ":scheme", "Firefox 3 is :scheme");

        let saf_fp = wing::akamai_safari_preset();
        var saf_ordered: wing::HeaderItem[..4] = [];
        wing::order_pseudo_headers(saf_fp, "GET", "api.example.com", "https", "/v1/data", saf_ordered);

        sub.assert_eq(saf_ordered[0].name[..], ":method", "Safari 0 is :method");
        sub.assert_eq(saf_ordered[1].name[..], ":scheme", "Safari 1 is :scheme");
        sub.assert_eq(saf_ordered[2].name[..], ":authority", "Safari 2 is :authority");
        sub.assert_eq(saf_ordered[3].name[..], ":path", "Safari 3 is :path");
    };
}

fn test_akamai_browser_profiles(t: core::T&) {
    t.run("BrowserProfile presets export authentic Akamai fingerprints") { sub =>
        let cp = wing::chrome_profile();
        let fp_str = wing::profile_akamai(cp);
        sub.assert_eq(fp_str[..], "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", "Chrome profile has Chrome Akamai fingerprint");

        let ffp = wing::firefox_profile();
        let fp_str2 = wing::profile_akamai(ffp);
        sub.assert_eq(fp_str2[..], "1:65536;4:131072;5:16384|12517377|0|m,p,a,s", "Firefox profile has Firefox Akamai fingerprint");

        let sp = wing::safari_profile();
        let fp_str3 = wing::profile_akamai(sp);
        sub.assert_eq(fp_str3[..], "2:0;3:100;4:2097152|10485760|0|m,s,a,p", "Safari profile has Safari Akamai fingerprint");

        let wp = wing::wing_default_profile();
        let fp_str4 = wing::profile_akamai(wp);
        sub.assert_eq(fp_str4[..], "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p", "Wing default profile has authentic Wing Akamai fingerprint");

        // Session integration
        var session = wing::new_session();
        let sess_ak = session.akamai();
        sub.assert_eq(sess_ak[..], fp_str4[..], "Session exports authentic Akamai fingerprint");
        let sess_hash = session.akamai_hash();
        sub.assert_eq(sess_hash.len, 32, "Session exports 32-char Akamai hash");
    };
}

fn main() {
    var runner = core::new_runner("Akamai HTTP/2 Fingerprint & Anti-Bot Engine Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Presets and MD5 Hash Generation", test_akamai_presets_and_hashes);
    core::run_case(runner, "2. Parsing and Round-trip Deserialization", test_akamai_parsing_and_roundtrip);
    core::run_case(runner, "3. Fingerprint Matching and Family Classification", test_akamai_matching_and_family);
    core::run_case(runner, "4. Passive Anomaly Detection", test_akamai_anomaly_detection);
    core::run_case(runner, "5. Binary HTTP/2 Wire Framing Round-trip", test_akamai_wire_framing_roundtrip);
    core::run_case(runner, "6. Pseudo-header Canonical Ordering", test_akamai_pseudo_header_ordering);
    core::run_case(runner, "7. BrowserProfile and Session Integration", test_akamai_browser_profiles);
    let ok = core::finish(runner);
    assert(ok);
}
