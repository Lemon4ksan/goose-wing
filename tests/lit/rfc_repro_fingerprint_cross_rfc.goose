// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cross-component & RFC edge-case regression suite for `fingerprint/`.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s
// RUN: goose check %s

import std;
import core from "../..";
import wing from "../..";

fn test_akamai_regressions() {
    // F001: 514-byte max valid Akamai fingerprint formatting and hashing without capacity abort
    var max_fp = wing::AkamaiFingerprint {};
    for i in 16 {
        max_fp.settings.push(wing::AkamaiSetting { id: (65500 + i) as u16, val: 4294967295 });
    }
    max_fp.window_update = 2147483647;
    for i in 8 {
        max_fp.priority_frames.push(wing::AkamaiPriorityFrame {
            stream_id:     (2147483600 + i) as u32,
            exclusive:     1,
            dep_stream_id: (2147483500 + i) as u32,
            weight:        256,
        });
    }
    max_fp.pseudo_headers.push('m');
    max_fp.pseudo_headers.push('a');
    max_fp.pseudo_headers.push('s');
    max_fp.pseudo_headers.push('p');

    let max_str = wing::akamai_fingerprint_to_string(max_fp);
    assert(max_str.len == 514);
    var max_hash: u8[..32] = [];
    wing::compute_akamai_hash(max_fp, max_hash);
    assert(max_hash.len == 32);

    // F002 & F003: RFC 9113 stream ID, window_update, settings, priority, and pseudo-header validation
    let _, ok1 = wing::parse_akamai_fingerprint("1:65536||0|m,a,s,p");
    assert(!ok1);
    let _, ok2 = wing::parse_akamai_fingerprint("1:65536|2147483648|0|m,a,s,p");
    assert(!ok2);
    let _, ok3 = wing::parse_akamai_fingerprint("1:65536;;2:0|0|0|m,a,s,p");
    assert(!ok3);
    let _, ok4 = wing::parse_akamai_fingerprint("1:65536|0|0:0:0:16|m,a,s,p");
    assert(!ok4);
    let _, ok5 = wing::parse_akamai_fingerprint("1:65536|0|3:0:3:16|m,a,s,p");
    assert(!ok5);
    let _, ok6 = wing::parse_akamai_fingerprint("1:65536|0|2147483648:0:0:16|m,a,s,p");
    assert(!ok6);
    let _, ok7 = wing::parse_akamai_fingerprint("1:65536|0|0|m,m,a,s");
    assert(!ok7);
    let _, ok8 = wing::parse_akamai_fingerprint("1:65536|0|0|,,,");
    assert(!ok8);

    // F003: order_pseudo_headers deduplication & Safari window_update=0 anomaly
    var dup_fp = wing::akamai_chrome_preset();
    dup_fp.pseudo_headers.clear();
    dup_fp.pseudo_headers.append("mmasp");
    var hmap = wing::HeaderMap { .. };
    wing::order_pseudo_headers(dup_fp, "GET", "example.com", "https", "/index", hmap);
    assert(hmap.entries.len == 4);
    assert(wing::get_header(hmap, ":path") == "/index");

    var bad_safari = wing::akamai_safari_preset();
    bad_safari.window_update = 0;
    let anom, _ = wing::detect_akamai_anomaly("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Version/17.4 Safari/605.1.15", bad_safari);
    assert(anom == wing::AkamaiAnomaly.WindowUpdateAnomaly);
    print("AKAMAI_OK");
}

fn test_ja4_and_profile_regressions() {
    // F004 & F005: CSV ALPN ("h2,http/1.1"), DTLS versions, and draft version (0x7f1c) filtering
    let ciphers: u16[2] = [0x1301, 0x1302];
    let exts:    u16[2] = [0x0000, 0x0010];
    let vers:    u16[2] = [0x0304, 0x7f1c];
    let sigs:    u16[1] = [0x0403];

    let ja4_csv = wing::compute_ja4(ciphers[..], exts[..], vers[..], true, "h2,http/1.1", sigs[..], false);
    assert(ja4_csv[..11] == "t13d0202h2_");

    let dtls_vers: u16[2] = [0xfefd, 0xfeff];
    let ja4_dtls = wing::compute_ja4(ciphers[..], exts[..], dtls_vers[..], true, "h2", sigs[..], false);
    assert(ja4_dtls[..4] == "td2d");

    // F006 & F007: JA4H language ';' delimiter, HTTP/2 :pseudo stripping, "h2" version, and reusable buffer clear()
    let hdrs:    const u8[:][4] = [":method", ":path", "Host", "Accept-Language"];
    let cookies: const u8[:][1] = ["session_id"];
    var reusable_ja4h: u8[..64] = [];
    wing::compute_ja4h("GET", "h2", hdrs[..], wing::Ja4hFlags {}, "en;q=0.9,fr;q=0.8", cookies[..], cookies[..], reusable_ja4h);
    wing::compute_ja4h("GET", "h2", hdrs[..], wing::Ja4hFlags {}, "en;q=0.9,fr;q=0.8", cookies[..], cookies[..], reusable_ja4h);
    assert(reusable_ja4h[..12] == "ge20cn02en00");

    // F007: set_akamai syncs BrowserProfile.h2
    var prof = wing::new_client_profile(wing::Profile.Wing);
    let ff_fp = wing::akamai_firefox_preset();
    wing::set_akamai(prof, ff_fp);
    assert(prof.h2.initial_window_size == 131072);
    assert(prof.h2.max_frame_size == 16384);
    print("JA4_PROFILE_OK");
}

fn test_p0f_regressions() {
    // F008 & F009: Wildcard window scale round-trip, MTU multiplier matching, and integer bounds
    let p_any, ok_any = wing::parse_p0f("4:64:0:1460:*,8:mss,sok,ts,nop,ws:df,id+:0");
    assert(ok_any);
    let fmt_any = wing::format_p0f(p_any);
    assert(fmt_any[..] == "4:64:0:1460:*,8:mss,sok,ts,nop,ws:df,id+:0");

    let target_mtu, ok_mtu = wing::parse_p0f("4:64-:0:*:mtu*4,7:mss,sok,ts,nop,ws:df:0");
    assert(ok_mtu);
    let actual_pkt, ok_pkt = wing::parse_p0f("4:60:0:1460:6000,7:mss,sok,ts,nop,ws:df:0");
    assert(ok_pkt);
    assert(wing::match_p0f(actual_pkt, target_mtu));

    let _, ok_ovf = wing::parse_p0f("4:64:0:999999999999:65535,8:mss:df:0");
    assert(!ok_ovf);
    let _, ok_ttl0 = wing::parse_p0f("4:0:0:1460:65535,8:mss:df:0");
    assert(!ok_ttl0);
    let _, ok_bad_quirk = wing::parse_p0f("4:64:0:1460:65535,8:mss:df,unknown_quirk:0");
    assert(!ok_bad_quirk);
    let _, ok_bad_eol = wing::parse_p0f("4:64:0:1460:65535,8:mss,eol+abc:df:0");
    assert(!ok_bad_eol);
    let _, ok_empty_payload = wing::parse_p0f("4:64:0:1460:65535,8:mss:df:");
    assert(!ok_empty_payload);
    print("P0F_OK");
}

fn main() {
    test_akamai_regressions();
    test_ja4_and_profile_regressions();
    test_p0f_regressions();
}

// CHECK: AKAMAI_OK
// CHECK-NEXT: JA4_PROFILE_OK
// CHECK-NEXT: P0F_OK
