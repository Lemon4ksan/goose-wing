// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Browser Fingerprints (JA3/JA4/Akamai H2/JA4DB) and WPT (Cookies, Redirects, CORS)
// conformance harness for goose-wing.
import std;
import wing from "../..";

const EXT_SNI:            u16 = 0x0000;
const EXT_STATUS_REQ:     u16 = 0x0005;
const EXT_SUPP_GROUPS:    u16 = 0x000A;
const EXT_EC_POINT_FMTS:  u16 = 0x000B;
const EXT_SIG_ALGS:       u16 = 0x000D;
const EXT_ALPN:           u16 = 0x0010;
const EXT_SCT:            u16 = 0x0012;
const EXT_EMS:            u16 = 0x0017;
const EXT_COMPRESS_CERT:  u16 = 0x001B;
const EXT_RECORD_LIMIT:   u16 = 0x001C;
const EXT_DELEG_CREDS:    u16 = 0x0022;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_SUPP_VERSIONS:  u16 = 0x002B;
const EXT_PSK_MODES:      u16 = 0x002D;
const EXT_KEY_SHARE:      u16 = 0x0033;
const EXT_ALPS:           u16 = 0x4469;
const EXT_RENEG_INFO:     u16 = 0xFF01;
const TLS_LEGACY_VER_12:  u16 = 0x0303;
const GROUP_X25519:       u16 = 0x001D;
const GROUP_SECP256R1:    u16 = 0x0017;
const GROUP_SECP384R1:    u16 = 0x0018;
const GREASE_0A:          u16 = 0x0A0A;
const GREASE_1A:          u16 = 0x1A1A;
const GREASE_2A:          u16 = 0x2A2A;
const GREASE_3A:          u16 = 0x3A3A;
const GREASE_4A:          u16 = 0x4A4A;
const GREASE_5A:          u16 = 0x5A5A;
const GREASE_6A:          u16 = 0x6A6A;
const GREASE_7A:          u16 = 0x7A7A;

struct ProfileBundle {
    profile:    fingerprint::ClientProfile = fingerprint::ClientProfile { .. },
    groups:     u16[..8]                   = [],
    ec_formats: u8[..4]                    = [],
}

// Decodes an even-length hexadecimal ASCII string into `out`.
// Clears `out` and returns false on odd length or invalid hex digit.
//
// Example:
//   hex_str = "613d31"
//   returns: ok = true, out = "a=1"
fn decode_hex_into(hex_str: const u8[:], out: u8[>..]&) -> bool {
    out.clear();
    guard hex_str.len > 0 && hex_str != "-" else { return true; }
    guard (hex_str.len & 1) == 0 else { return false; }
    var i: i64 = 0;
    while i < hex_str.len {
        let next_i = core::add_sat_i64(i, 2);
        let b, ok = core::parse_u8_hex(hex_str[i..next_i]);
        guard ok else {
            out.clear();
            return false;
        }
        out.push(b);
        i = next_i;
    }
    return true;
}

fn encode_hex_all(data: const u8[:], out: u8[>..]&) {
    out.clear();
    if data.len == 0 {
        out.push('-');
        return;
    }
    for b in data {
        b.format_u8_hex(out, false);
    }
}

// Parses newline-delimited `Name: Value` lines into `headers`.
// Returns false on missing `:` or header map capacity overflow.
//
// Example:
//   raw = "Origin: https://app.test\nAuthorization: Bearer tok\n"
//   returns: ok = true, headers populated with 2 entries
fn parse_header_lines(raw: const u8[:], headers: http::HeaderMap&) -> bool {
    headers.clear();
    var committed = false;
    defer if !committed { headers.clear(); };
    var tok = core::make_byte_tokenizer(raw, '\n');
    while true {
        let ln, more = core::token_next(tok);
        guard more else { break; }
        let line = ln.trim_end_byte('\r').trim_lws();
        guard line.len > 0 else { continue; }
        let k, v, ok = line.split_once_byte(':');
        guard ok && http::append_header(headers, k.trim_lws(), v.trim_lws()) else { return false; }
    }
    committed = true;
    return true;
}

fn redirect_err_name(err: client::RedirectError) -> const u8[:] {
    return match err {
        None => "None",
        MissingLocation => "MissingLocation",
        MultipleLocationHeaders => "MultipleLocationHeaders",
        InvalidLocationUrl => "InvalidLocationUrl",
        ForbiddenRedirectScheme => "ForbiddenRedirectScheme",
        CorsCredentialsInRedirectUrl => "CorsCredentialsInRedirectUrl",
        SchemeDowngradeBlocked => "SchemeDowngradeBlocked",
        TooManyRedirects => "TooManyRedirects",
        RedirectBlockedByPolicy => "RedirectBlockedByPolicy",
        CannotRewindBody => "CannotRewindBody",
        SsrfBlockedUrl => "SsrfBlockedUrl",
        SsrfBlockedIp => "SsrfBlockedIp",
    };
}

fn cors_result_name(r: security::CorsResult) -> const u8[:] {
    return match r {
        NoCors => "NoCors",
        AllowedActual => "AllowedActual",
        AllowedPreflight => "AllowedPreflight",
        RejectedOrigin => "RejectedOrigin",
        RejectedPreflightMethod => "RejectedPreflightMethod",
        RejectedPreflightHeaders => "RejectedPreflightHeaders",
        InvalidConfig => "InvalidConfig",
    };
}

fn make_chrome_bundle() -> ProfileBundle {
    var b = ProfileBundle { profile: fingerprint::custom_profile(), .. };
    b.profile.set_user_agent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    );
    b.profile.set_accept("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    b.profile.set_accept_encoding("gzip, deflate, br, zstd");
    b.profile.set_accept_language("en-US,en;q=0.9");
    b.profile.tls.supported_versions = [GREASE_3A, 0x0304, 0x0303];
    b.profile.tls.ciphers = [
        GREASE_0A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
    ];
    b.profile.tls.extensions = [
        GREASE_1A, EXT_SNI, EXT_EMS, EXT_RENEG_INFO, EXT_SUPP_GROUPS, EXT_EC_POINT_FMTS,
        EXT_SESSION_TICKET, EXT_ALPN, EXT_STATUS_REQ, EXT_SIG_ALGS, EXT_SCT, EXT_KEY_SHARE,
        EXT_PSK_MODES, EXT_SUPP_VERSIONS, EXT_COMPRESS_CERT, EXT_ALPS, GREASE_2A,
    ];
    b.profile.tls.sig_algorithms = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];
    let _ = b.profile.tls.alpn.try_set("h2");
    b.groups = [GREASE_0A, GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1];
    b.ec_formats = [0];
    var ak = fingerprint::custom_akamai_fingerprint(15663105, "m,a,s,p");
    let _ = ak.push_setting(rfc::H2_SETTING_HEADER_TABLE_SIZE, 65536);
    let _ = ak.push_setting(rfc::H2_SETTING_ENABLE_PUSH, 0);
    let _ = ak.push_setting(rfc::H2_SETTING_INITIAL_WINDOW_SIZE, 6291456);
    let _ = ak.push_setting(rfc::H2_SETTING_MAX_HEADER_LIST_SIZE, 262144);
    b.profile.set_akamai(ak);
    return b;
}

fn make_firefox_bundle() -> ProfileBundle {
    var b = ProfileBundle { profile: fingerprint::custom_profile(), .. };
    b.profile.set_user_agent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    );
    b.profile.set_accept("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    b.profile.set_accept_encoding("gzip, deflate, br, zstd");
    b.profile.set_accept_language("en-US,en;q=0.5");
    b.profile.tls.supported_versions = [0x0304, 0x0303];
    b.profile.tls.ciphers = [
        0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C, 0xC030,
    ];
    b.profile.tls.extensions = [
        EXT_SNI, EXT_EMS, EXT_RENEG_INFO, EXT_SUPP_GROUPS, EXT_EC_POINT_FMTS,
        EXT_SESSION_TICKET, EXT_ALPN, EXT_STATUS_REQ, EXT_DELEG_CREDS, EXT_KEY_SHARE,
        EXT_SUPP_VERSIONS, EXT_SIG_ALGS, EXT_PSK_MODES, EXT_RECORD_LIMIT,
    ];
    b.profile.tls.sig_algorithms = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501];
    let _ = b.profile.tls.alpn.try_set("h2");
    b.groups = [GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1];
    b.ec_formats = [0];
    var ak = fingerprint::custom_akamai_fingerprint(12517377, "m,p,a,s");
    let _ = ak.push_setting(rfc::H2_SETTING_HEADER_TABLE_SIZE, 65536);
    let _ = ak.push_setting(rfc::H2_SETTING_ENABLE_PUSH, 0);
    let _ = ak.push_setting(rfc::H2_SETTING_INITIAL_WINDOW_SIZE, 131072);
    let _ = ak.push_setting(rfc::H2_SETTING_MAX_FRAME_SIZE, 16384);
    b.profile.set_akamai(ak);
    return b;
}

fn make_safari_bundle() -> ProfileBundle {
    var b = ProfileBundle { profile: fingerprint::custom_profile(), .. };
    b.profile.set_user_agent(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15",
    );
    b.profile.set_accept("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    b.profile.set_accept_encoding("gzip, deflate, br");
    b.profile.set_accept_language("en-US,en;q=0.9");
    b.profile.tls.supported_versions = [GREASE_7A, 0x0304, 0x0303];
    b.profile.tls.ciphers = [
        GREASE_4A, 0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xCCA9, 0xC030, 0xC02F, 0xCCA8,
    ];
    b.profile.tls.extensions = [
        GREASE_5A, EXT_SNI, EXT_EMS, EXT_RENEG_INFO, EXT_SUPP_GROUPS, EXT_EC_POINT_FMTS,
        EXT_ALPN, EXT_STATUS_REQ, EXT_SIG_ALGS, EXT_SCT, EXT_KEY_SHARE, EXT_PSK_MODES,
        EXT_SUPP_VERSIONS, EXT_COMPRESS_CERT, GREASE_6A,
    ];
    b.profile.tls.sig_algorithms = [0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0501, 0x0806];
    let _ = b.profile.tls.alpn.try_set("h2");
    b.groups = [GREASE_4A, GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1];
    b.ec_formats = [0];
    var ak = fingerprint::custom_akamai_fingerprint(10420225, "m,s,p,a");
    let _ = ak.push_setting(rfc::H2_SETTING_ENABLE_PUSH, 0);
    let _ = ak.push_setting(rfc::H2_SETTING_MAX_CONCURRENT_STREAMS, 100);
    let _ = ak.push_setting(rfc::H2_SETTING_INITIAL_WINDOW_SIZE, 2097152);
    let _ = ak.push_setting(9, 1);
    b.profile.set_akamai(ak);
    return b;
}

fn build_named_bundle(name: const u8[:]) -> ProfileBundle, bool {
    if name == "Chrome" { return make_chrome_bundle(), true; }
    if name == "Firefox" { return make_firefox_bundle(), true; }
    if name == "Safari" { return make_safari_bundle(), true; }
    if name == "Wing" {
        var b = ProfileBundle { profile: fingerprint::wing_default_profile(), .. };
        b.groups = [GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1];
        b.ec_formats = [0];
        return b, true;
    }
    return ProfileBundle { .. }, false;
}

fn append_u16_list_body(vals: const u16[:], out: u8[>..]&) {
    let byte_len = core::mul_sat_u64(vals.len as u64, 2) as u16;
    out.append_u16_be(byte_len);
    for v in vals {
        out.append_u16_be(v);
    }
}

fn append_ext_payload(
    ext_id: u16,
    b:      const ProfileBundle&,
    sni:    const u8[:],
    body:   u8[>..]&,
) {
    body.clear();
    if ext_id == EXT_SNI {
        let sni_len = sni.len as u64;
        body.append_u16_be(core::add_sat_u64(sni_len, 3) as u16);
        body.push(0);
        body.append_u16_be(sni_len as u16);
        body.append(sni);
    } else if ext_id == EXT_SUPP_GROUPS {
        append_u16_list_body(b.groups[..], body);
    } else if ext_id == EXT_EC_POINT_FMTS {
        body.push(b.ec_formats.len as u8);
        body.append(b.ec_formats[..]);
    } else if ext_id == EXT_SIG_ALGS {
        append_u16_list_body(b.profile.tls.sig_algorithms[..], body);
    } else if ext_id == EXT_ALPN {
        let a = b.profile.tls.alpn[..];
        let a_len = a.len as u64;
        body.append_u16_be(core::add_sat_u64(a_len, 1) as u16);
        body.push(a_len as u8);
        body.append(a);
    } else if ext_id == EXT_SUPP_VERSIONS {
        let ver_bytes = core::mul_sat_u64(b.profile.tls.supported_versions.len as u64, 2) as u8;
        body.push(ver_bytes);
        for v in b.profile.tls.supported_versions {
            body.append_u16_be(v);
        }
    } else if ext_id == EXT_PSK_MODES {
        body.push(1);
        body.push(1);
    } else if ext_id == EXT_KEY_SHARE {
        body.append_u16_be(36);
        body.append_u16_be(GROUP_X25519);
        body.append_u16_be(32);
        for i in 32 {
            body.push(0x40 | (i as u8));
        }
    } else if ext_id == EXT_RENEG_INFO {
        body.push(0);
    }
}

fn encode_profile_client_hello(
    b:        const ProfileBundle&,
    sni:      const u8[:],
    out:      u8[>..]&,
    ext_buf:  u8[>..]&,
    ext_body: u8[>..]&,
) {
    out.clear();
    ext_buf.clear();
    out.append_u16_be(TLS_LEGACY_VER_12);
    for i in 32 { out.push(0x20 | (i as u8)); }
    out.push(32);
    for i in 32 { out.push(0xA0 | (i as u8)); }
    append_u16_list_body(b.profile.tls.ciphers[..], out);
    out.push(1);
    out.push(0);
    for ext_id in b.profile.tls.extensions {
        append_ext_payload(ext_id, b, sni, ext_body);
        ext_buf.append_u16_be(ext_id);
        ext_buf.append_u16_be(ext_body.len as u16);
        ext_buf.append(ext_body[..]);
    }
    out.append_u16_be(ext_buf.len as u16);
    out.append(ext_buf[..]);
}

root struct HarnessState {
    jar:      cookie::CanonicalCookieJar = cookie::CanonicalCookieJar { .. },
    scratch:  u8[>..]                    = [],
    ch_buf:   u8[>..]                    = [],
    ext_buf:  u8[>..]                    = [],
    ext_body: u8[>..]                    = [],
    h2_wire:  u8[>..]                    = [],
    hex_a:    u8[>..]                    = [],
    hex_b:    u8[>..]                    = [],
    hex_c:    u8[>..]                    = [],
}

fn format_ordered_pseudo_csv(ph_map: const http::HeaderMap&, out: u8[..32]&) {
    out.clear();
    for i in ph_map.entries.len {
        let nm = ph_map.entry_name(ph_map.entries[i]);
        guard nm.len >= 2 && nm[0] == ':' else { continue; }
        if out.len > 0 { let _ = out.try_push(','); }
        let _ = out.try_push(nm[1]);
    }
}

fn handle_profile_cmd(name: const u8[:], st: HarnessState&) {
    let b, ok_b = build_named_bundle(name);
    guard ok_b else {
        print("PROFILE_OUT\t", name, "\tERR_UNKNOWN");
        flush_stdout();
        return;
    }
    let ja4_s = b.profile.ja4();
    let ja4h_s = b.profile.ja4h("GET", "HTTP/2");
    let ak_s = b.profile.format_akamai();
    let ak_h = b.profile.akamai_hash();

    encode_profile_client_hello(b, "tls.peet.ws", st.ch_buf, st.ext_buf, st.ext_body);
    encode_hex_all(st.ch_buf[..], st.hex_a);

    st.h2_wire.clear();
    st.h2_wire.append(rfc::H2_CLIENT_PREFACE[..]);
    let ok_h2 = fingerprint::encode_akamai_handshake_frames(b.profile.akamai, st.h2_wire);
    encode_hex_all(st.h2_wire[..], st.hex_b);

    var ph_map = http::HeaderMap { .. };
    let ok_ph = fingerprint::order_pseudo_headers(
        b.profile.akamai, "GET", "tls.peet.ws", "https", "/api/all", ph_map,
    );
    var ph_csv: u8[..32] = [];
    format_ordered_pseudo_csv(ph_map, ph_csv);

    let ext_ak, ok_ext = fingerprint::extract_akamai_from_wire(st.h2_wire[..], ph_csv[..]);
    let anom, _ = fingerprint::detect_akamai_anomaly(ext_ak, b.profile.akamai);
    let rt_ok = ok_h2 && ok_ph && ok_ext && anom == fingerprint::AkamaiAnomaly.None;

    var rand32: u8[32] = [0x11; 32];
    var pub32:  u8[32] = [0x22; 32];
    tls::build_client_hello_payload(rand32, pub32, "tls.peet.ws", "h2,http/1.1", st.ext_buf);
    encode_hex_all(st.ext_buf[..], st.hex_c);

    print(
        "PROFILE_OUT\t", name, "\t", ja4_s[..], "\t", ja4h_s[..], "\t", ak_s[..],
        "\t", ak_h[..], "\t", ph_csv[..], "\t", st.hex_a[..], "\t", st.hex_b[..],
        "\t", if rt_ok { 1 } else { 0 }, "\t", st.hex_c[..],
    );
    flush_stdout();
}

// Parses a WPT cookie request access-mode token into `cookie::AccessOptions`.
//
// Example:
//   tok = "CROSS_TOP_GET"
//   returns: AccessOptions { is_same_site: false, is_top_level_navigation: true, is_safe_method: true }, ok = true
fn parse_cookie_access(tok: const u8[:]) -> cookie::AccessOptions, bool {
    if tok == "SAME_SITE" {
        return cookie::AccessOptions {
            is_same_site: true, is_top_level_navigation: true, is_safe_method: true, ..
        }, true;
    }
    if tok == "CROSS_TOP_GET" {
        return cookie::AccessOptions {
            is_same_site: false, is_top_level_navigation: true, is_safe_method: true, ..
        }, true;
    }
    if tok == "CROSS_TOP_POST" {
        return cookie::AccessOptions {
            is_same_site: false, is_top_level_navigation: true, is_safe_method: false, ..
        }, true;
    }
    if tok == "CROSS_SUB_GET" {
        return cookie::AccessOptions {
            is_same_site: false, is_top_level_navigation: false, is_safe_method: true, ..
        }, true;
    }
    return cookie::AccessOptions { .. }, false;
}

fn format_matched_cookies(
    jar:     const cookie::CanonicalCookieJar&,
    indices: const u16[:],
    out:     u8[>..]&,
) {
    out.clear();
    for i in indices.len {
        let idx = indices[i] as i64;
        guard idx >= 0 && idx < jar.cookies.len else { continue; }
        if out.len > 0 { out.append("; "); }
        let c .= jar.cookies[idx];
        if c.name.len > 0 {
            out.append(c.name[..]);
            out.push('=');
        }
        out.append(c.value[..]);
    }
}

fn handle_cookie_set(rest: const u8[:], st: HarnessState&) {
    let cid, r0, ok0 = rest.split_once_byte('\t');
    let now_s, r1, ok1 = r0.split_once_byte('\t');
    let url, r2, ok2 = r1.split_once_byte('\t');
    let hdr_hex, r3, ok3 = r2.split_once_byte('\t');
    let api_s, part_k, ok4 = r3.split_once_byte('\t');
    let now_us, ok_t = now_s.parse_i64_dec();
    guard ok0 && ok1 && ok2 && ok3 && ok4 && ok_t && decode_hex_into(hdr_hex, st.scratch) else {
        print("COOKIE_SET_OUT\t", cid, "\tERR");
        flush_stdout();
        return;
    }
    let pk = if part_k == "-" { "" } else { part_k };
    let ok_set = st.jar.set_cookie_header(url, st.scratch[..], now_us, api_s == "HTTP", pk);
    print("COOKIE_SET_OUT\t", cid, "\t", if ok_set { 1 } else { 0 });
    flush_stdout();
}

fn handle_cookie_get(rest: const u8[:], st: HarnessState&) {
    let cid, r0, ok0 = rest.split_once_byte('\t');
    let now_s, r1, ok1 = r0.split_once_byte('\t');
    let url, r2, ok2 = r1.split_once_byte('\t');
    let api_s, r3, ok3 = r2.split_once_byte('\t');
    let part_k, acc_s, ok4 = r3.split_once_byte('\t');
    let now_us, ok_t = now_s.parse_i64_dec();
    let access, ok_a = parse_cookie_access(acc_s);
    guard ok0 && ok1 && ok2 && ok3 && ok4 && ok_t && ok_a else {
        print("COOKIE_GET_OUT\t", cid, "\tERR");
        flush_stdout();
        return;
    }
    let pk = if part_k == "-" { "" } else { part_k };
    var matched: u16[..180] = [];
    st.jar.get_canonical_cookies_for_request(url, api_s == "HTTP", pk, now_us, matched, access);
    format_matched_cookies(st.jar, matched[..], st.scratch);
    let out_s = if st.scratch.len > 0 { st.scratch[..] } else { "-" };
    print("COOKIE_GET_OUT\t", cid, "\t", out_s);
    flush_stdout();
}

struct RedirectCmd {
    cid:        const u8[:] = "",
    status:     i32         = 302,
    method:     const u8[:] = "GET",
    cur_url:    const u8[:] = "",
    location:   const u8[:] = "",
    ref_policy: const u8[:] = "strict-origin-when-cross-origin",
    cur_ref:    const u8[:] = "",
    hdrs_hex:   const u8[:] = "-",
}

// Parses an 8-column `REDIRECT` command payload into `RedirectCmd`.
//
// Example:
//   rest = "r1\t302\tPOST\thttps://a.test/1\thttps://b.test/2\tstrict-origin\t-\t-"
//   returns: RedirectCmd { cid: "r1", status: 302, ... }, ok = true
fn parse_redirect_cmd(rest: const u8[:]) -> RedirectCmd, bool {
    var out = RedirectCmd { .. };
    let c0, r0, ok0 = rest.split_once_byte('\t');
    let c1, r1, ok1 = r0.split_once_byte('\t');
    let c2, r2, ok2 = r1.split_once_byte('\t');
    let c3, r3, ok3 = r2.split_once_byte('\t');
    let c4, r4, ok4 = r3.split_once_byte('\t');
    let c5, r5, ok5 = r4.split_once_byte('\t');
    let c6, c7, ok6 = r5.split_once_byte('\t');
    let st_v, ok_s = c1.parse_i32_dec();
    guard ok0 && ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok_s else { return out, false; }
    out.cid = c0;
    out.status = st_v;
    out.method = c2;
    out.cur_url = c3;
    out.location = c4;
    out.ref_policy = c5;
    out.cur_ref = if c6 == "-" { "" } else { c6 };
    out.hdrs_hex = c7;
    return out, true;
}

fn handle_redirect_cmd(rest: const u8[:], st: HarnessState&) {
    let cmd, ok_cmd = parse_redirect_cmd(rest);
    guard ok_cmd && decode_hex_into(cmd.hdrs_hex, st.scratch) else {
        print("REDIRECT_OUT\t", cmd.cid, "\tERR");
        flush_stdout();
        return;
    }
    var hdrs = http::HeaderMap { .. };
    if st.scratch.len > 0 {
        guard parse_header_lines(st.scratch[..], hdrs) else {
            print("REDIRECT_OUT\t", cmd.cid, "\tERR_HDR");
            flush_stdout();
            return;
        }
    }
    let pol = client::parse_referrer_policy_with_fallback(
        cmd.ref_policy, client::ReferrerPolicy.StrictOriginWhenCrossOrigin,
    );
    let info = client::compute_redirect_info(
        cmd.method, cmd.status, cmd.cur_url, cmd.location, pol, cmd.cur_ref,
        client::RedirectOptions { cors_mode: true, .. },
    );
    client::sanitize_headers_on_redirect(
        hdrs, info,
        client::RedirectSanitizeOptions { cors_mode: true, enable_referer: true, .. },
    );
    let new_m = if info.new_method.len > 0 { info.new_method[..] } else { "-" };
    let new_u = if info.new_url.href.len > 0 { info.new_url.href[..] } else { "-" };
    let orig_v = hdrs.get_header("origin");
    let ref_v = hdrs.get_header("referer");
    print(
        "REDIRECT_OUT\t", cmd.cid, "\t", redirect_err_name(info.error), "\t", new_m,
        "\t", info.clear_body,
        "\t", info.is_cross_origin,
        "\t", info.is_scheme_downgrade,
        "\t", new_u,
        "\t", hdrs.get_header("authorization").len > 0,
        "\t", hdrs.get_header("cookie").len > 0,
        "\t", hdrs.get_header("dpop").len > 0,
        "\t", hdrs.get_header("content-type").len > 0,
        "\t", if orig_v.len > 0 { orig_v } else { "-" },
        "\t", if ref_v.len > 0 { ref_v } else { "-" },
    );
    flush_stdout();
}

fn populate_cors_origins(csv: const u8[:], pol: security::CorsPolicy&) {
    guard csv.len > 0 && csv != "-" else { return; }
    var tok = core::make_byte_tokenizer(csv, ',');
    while true {
        let item, more = core::token_next(tok);
        guard more else { break; }
        let _ = security::add_allowed_origin(pol, item);
    }
}

// Parses a client-side CORS verification mode token (`NORMAL`, `CREDS`, `TAINTED`, `TAINTED_CREDS`).
//
// Example:
//   tok = "CREDS"
//   returns: ClientCorsVerifyOptions { include_credentials: true, .. }, ok = true
fn parse_cors_cli_opts(tok: const u8[:]) -> security::ClientCorsVerifyOptions, bool {
    if tok == "NORMAL" {
        return security::ClientCorsVerifyOptions { tainted_origin: false, include_credentials: false }, true;
    }
    if tok == "CREDS" {
        return security::ClientCorsVerifyOptions { tainted_origin: false, include_credentials: true }, true;
    }
    if tok == "TAINTED" {
        return security::ClientCorsVerifyOptions { tainted_origin: true, include_credentials: false }, true;
    }
    if tok == "TAINTED_CREDS" {
        return security::ClientCorsVerifyOptions { tainted_origin: true, include_credentials: true }, true;
    }
    return security::ClientCorsVerifyOptions { .. }, false;
}

fn handle_cors_srv(rest: const u8[:], st: HarnessState&) {
    let cid, r0, ok0 = rest.split_once_byte('\t');
    let creds_s, r1, ok1 = r0.split_once_byte('\t');
    let orig_csv, r2, ok2 = r1.split_once_byte('\t');
    let meths_s, r3, ok3 = r2.split_once_byte('\t');
    let hdrs_s, r4, ok4 = r3.split_once_byte('\t');
    let req_m, req_hex, ok5 = r4.split_once_byte('\t');
    guard ok0 && ok1 && ok2 && ok3 && ok4 && ok5 && decode_hex_into(req_hex, st.scratch) else {
        print("CORS_SRV_OUT\t", cid, "\tERR");
        flush_stdout();
        return;
    }
    var pol = security::CorsPolicy { allow_credentials: creds_s == "1", .. };
    populate_cors_origins(orig_csv, pol);
    if meths_s != "-" { let _ = pol.allowed_methods.try_set(meths_s); }
    if hdrs_s != "-" { let _ = pol.allowed_headers.try_set(hdrs_s); }
    var req = http::new_request(req_m, "/api");
    var res = http::Response { status_code: 200, .. };
    guard parse_header_lines(st.scratch[..], req.headers) else {
        print("CORS_SRV_OUT\t", cid, "\tERR_HDR");
        flush_stdout();
        return;
    }
    let r = security::evaluate_cors(pol, req, res);
    let acao = res.headers.get_header("access-control-allow-origin");
    let acac = res.headers.get_header("access-control-allow-credentials");
    let vary = res.headers.get_header("vary");
    print(
        "CORS_SRV_OUT\t", cid, "\t", cors_result_name(r),
        "\t", if acao.len > 0 { acao } else { "-" },
        "\t", if acac.len > 0 { acac } else { "-" },
        "\t", if vary.len > 0 { vary } else { "-" },
    );
    flush_stdout();
}

fn handle_cors_cli(rest: const u8[:], st: HarnessState&) {
    let cid, r0, ok0 = rest.split_once_byte('\t');
    let req_orig, r1, ok1 = r0.split_once_byte('\t');
    let mode_s, resp_hex, ok2 = r1.split_once_byte('\t');
    let opts, ok_m = parse_cors_cli_opts(mode_s);
    guard ok0 && ok1 && ok2 && ok_m && decode_hex_into(resp_hex, st.scratch) else {
        print("CORS_CLI_OUT\t", cid, "\tERR");
        flush_stdout();
        return;
    }
    var hdrs = http::HeaderMap { .. };
    guard parse_header_lines(st.scratch[..], hdrs) else {
        print("CORS_CLI_OUT\t", cid, "\tERR_HDR");
        flush_stdout();
        return;
    }
    let ok_v = security::verify_client_cors_response(hdrs, req_orig, opts);
    print("CORS_CLI_OUT\t", cid, "\t", if ok_v { 1 } else { 0 });
    flush_stdout();
}

fn handle_live_fetch(rest: const u8[:], st: HarnessState&) {
    let prof_name, url, ok_sp = rest.split_once_byte('\t');
    guard ok_sp else {
        print("LIVE_OUT\t-\t0\t1\tBadArgs\t-");
        flush_stdout();
        return;
    }
    let b, ok_b = build_named_bundle(prof_name);
    guard ok_b else {
        print("LIVE_OUT\t", prof_name, "\t0\t1\tBadProfile\t-");
        flush_stdout();
        return;
    }
    var sess = client::new_session(client::Config {
        timeout_ms:             15000,
        tls_use_system_roots:   true,
        enable_protocol_racing: false,
        ..
    });
    defer client::close(sess);
    client::set_profile(sess, b.profile);
    let resp, err = client::get(sess, url);
    if !err.ok() {
        let stage = if err.stage.len > 0 { err.stage[..] } else { "Error" };
        print("LIVE_OUT\t", prof_name, "\t", resp.status_code, "\t", err.code, "\t", stage, "\t-");
        flush_stdout();
        return;
    }
    encode_hex_all(resp.body[..], st.hex_a);
    print("LIVE_OUT\t", prof_name, "\t", resp.status_code, "\t0\tOK\t", st.hex_a[..]);
    flush_stdout();
}

fn dispatch_line(raw_line: const u8[:], st: HarnessState&) -> bool {
    let line = raw_line.trim_end_byte('\r');
    guard line.len > 0 else { return true; }
    if line == "QUIT" { return false; }
    if line == "COOKIE_RESET" {
        st.jar = cookie::CanonicalCookieJar { .. };
        print("COOKIE_RESET_OUT\t1");
        flush_stdout();
        return true;
    }
    let kind, rest, ok_k = line.split_once_byte('\t');
    guard ok_k else {
        print("ERR\tBadLine");
        flush_stdout();
        return true;
    }
    if kind == "PROFILE" { handle_profile_cmd(rest, st); }
    else if kind == "COOKIE_SET" { handle_cookie_set(rest, st); }
    else if kind == "COOKIE_GET" { handle_cookie_get(rest, st); }
    else if kind == "REDIRECT" { handle_redirect_cmd(rest, st); }
    else if kind == "CORS_SRV" { handle_cors_srv(rest, st); }
    else if kind == "CORS_CLI" { handle_cors_cli(rest, st); }
    else if kind == "LIVE_FETCH" { handle_live_fetch(rest, st); }
    else {
        print("ERR\tUnknownCmd");
        flush_stdout();
    }
    return true;
}

fn main() {
    var st = HarnessState { .. };
    let a = args();
    if a.len >= 2 && a[1] != "-" {
        var batch: u8[>..] = [];
        guard read_file(a[1], batch) else {
            print("ERR:READ_FILE");
            exit(2);
        }
        var tok = core::make_byte_tokenizer(batch[..], '\n');
        while true {
            let ln, more = core::token_next(tok);
            guard more else { break; }
            guard dispatch_line(ln, st) else { break; }
        }
        return;
    }
    var line_buf: u8[>..] = [];
    while read_line(line_buf) {
        guard dispatch_line(line_buf[..], st) else { break; }
        line_buf.clear();
    }
}
