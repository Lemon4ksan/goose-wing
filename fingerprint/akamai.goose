// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Akamai HTTP/2 Passive Fingerprinting & Active Matching Engine.
// Models Akamai Bot Manager, Cloudflare, and Datadome passive client fingerprinting:
// Format: SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADERS
// Computes canonical Akamai fingerprint string and 32-character MD5 hash.
// Supports frame extraction, signature matching, preset profiles, and anomaly detection.
namespace wing;

import std;
import client.profile;
import core from "..";
import http2.framing;

// ---- Data Structures -----------------------------------------------------

// Single HTTP/2 parameter within the initial SETTINGS frame.
struct AkamaiSetting {
    id:  u16 = 0,
    val: u32 = 0,
}

// Stream priority dependency declared during HTTP/2 connection setup.
struct AkamaiPriorityFrame {
    stream_id:     u32 = 0,
    exclusive:     u8  = 0, // 0 or 1
    dep_stream_id: u32 = 0,
    weight:        u16 = 0, // 1 to 256
}

// Complete Akamai HTTP/2 Client Fingerprint specification.
struct AkamaiFingerprint {
    settings:        AkamaiSetting[..16]      = [],
    window_update:   u32                      = 0, // Stream 0 window increment (0 if omitted)
    priority_frames: AkamaiPriorityFrame[..8] = [],
    pseudo_headers:  u8[..8]                  = [], // Initial chars: e.g. ['m', 'a', 's', 'p']
}

// Recognized browser and client families.
enum AkamaiBrowserFamily {
    Unknown,
    Chrome,
    Firefox,
    Safari,
    Wing,
    Curl,
}

// Classification of fingerprint anomalies detected against client declarations.
enum AkamaiAnomaly {
    None,
    MissingPseudoHeaders,
    PseudoHeaderOrderMismatch,
    WindowUpdateAnomaly,
    SettingsMismatch,
    BotPattern,
}

// ---- Formatting & Serialization ------------------------------------------

// Formats SETTINGS section: `ID:Value;ID:Value;...`
fn format_akamai_settings<B>(settings: const AkamaiSetting[:], out: B&) {
    for i in settings.len {
        if i > 0 {
            out.push(';');
        }
        settings[i].id.format_u32_dec(out);
        out.push(':');
        settings[i].val.format_u32_dec(out);
    }
}

// Formats PRIORITY section: `stream:excl:dep:weight,...` or `0` if empty.
fn format_akamai_priority<B>(priority: const AkamaiPriorityFrame[:], out: B&) {
    guard priority.len > 0 else {
        out.push('0');
        return;
    }
    for i in priority.len {
        if i > 0 {
            out.push(',');
        }
        priority[i].stream_id.format_u32_dec(out);
        out.push(':');
        priority[i].exclusive.format_u32_dec(out);
        out.push(':');
        priority[i].dep_stream_id.format_u32_dec(out);
        out.push(':');
        priority[i].weight.format_u32_dec(out);
    }
}

// Formats PSEUDO_HEADERS section: `m,a,s,p`
fn format_akamai_pseudo_headers<B>(pseudos: const u8[:], out: B&) {
    for i in pseudos.len {
        if i > 0 {
            out.push(',');
        }
        out.push(pseudos[i]);
    }
}

// Formats the canonical Akamai HTTP/2 fingerprint string:
// `SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADERS`
fn format_akamai_fingerprint<B>(fp: const AkamaiFingerprint&, out: B&) {
    out.clear();
    format_akamai_settings(fp.settings[..], out);
    out.push('|');
    fp.window_update.format_u32_dec(out);
    out.push('|');
    format_akamai_priority(fp.priority_frames[..], out);
    out.push('|');
    format_akamai_pseudo_headers(fp.pseudo_headers[..], out);
}

// Formats the canonical Akamai fingerprint string returning a bounded buffer.
fn akamai_fingerprint_to_string(fp: const AkamaiFingerprint&) -> u8[..640] {
    var out: u8[..640] = [];
    format_akamai_fingerprint(fp, out);
    return out;
}

// Computes the 32-character hexadecimal MD5 hash of the Akamai fingerprint string.
fn compute_akamai_hash<B>(fp: const AkamaiFingerprint&, dst: B&) {
    var raw: u8[..640] = [];
    format_akamai_fingerprint(fp, raw);
    let digest = core::md5(raw[..]);
    dst.clear();
    for b in digest {
        b.format_u8_hex(dst, false);
    }
}

// Computes the 32-character hexadecimal MD5 hash returning a bounded buffer.
fn akamai_fingerprint_hash(fp: const AkamaiFingerprint&) -> u8[..32] {
    var out: u8[..32] = [];
    compute_akamai_hash(fp, out);
    return out;
}

// ---- Standard Presets ----------------------------------------------------

// Chrome 124+ / Chromium / Edge preset:
// Settings: 1:65536;2:0;4:6291456;6:262144
// Window Update: 15663105
// Priority: 0
// Pseudo Headers: m,a,s,p
fn akamai_chrome_preset() -> AkamaiFingerprint {
    var fp = AkamaiFingerprint {
        window_update: 15663105,
        ..
    };
    fp.settings.push(AkamaiSetting { id: 1, val: 65536 });
    fp.settings.push(AkamaiSetting { id: 2, val: 0 });
    fp.settings.push(AkamaiSetting { id: 4, val: 6291456 });
    fp.settings.push(AkamaiSetting { id: 6, val: 262144 });

    fp.pseudo_headers.push('m');
    fp.pseudo_headers.push('a');
    fp.pseudo_headers.push('s');
    fp.pseudo_headers.push('p');
    return fp;
}

// Firefox 124+ preset:
// Settings: 1:65536;4:131072;5:16384
// Window Update: 12517377
// Priority: 0
// Pseudo Headers: m,p,a,s
fn akamai_firefox_preset() -> AkamaiFingerprint {
    var fp = AkamaiFingerprint {
        window_update: 12517377,
        ..
    };
    fp.settings.push(AkamaiSetting { id: 1, val: 65536 });
    fp.settings.push(AkamaiSetting { id: 4, val: 131072 });
    fp.settings.push(AkamaiSetting { id: 5, val: 16384 });

    fp.pseudo_headers.push('m');
    fp.pseudo_headers.push('p');
    fp.pseudo_headers.push('a');
    fp.pseudo_headers.push('s');
    return fp;
}

// Safari 17+ / WebKit / iOS preset:
// Settings: 2:0;3:100;4:2097152
// Window Update: 10485760
// Priority: 0
// Pseudo Headers: m,s,a,p
fn akamai_safari_preset() -> AkamaiFingerprint {
    var fp = AkamaiFingerprint {
        window_update: 10485760,
        ..
    };
    fp.settings.push(AkamaiSetting { id: 2, val: 0 });
    fp.settings.push(AkamaiSetting { id: 3, val: 100 });
    fp.settings.push(AkamaiSetting { id: 4, val: 2097152 });

    fp.pseudo_headers.push('m');
    fp.pseudo_headers.push('s');
    fp.pseudo_headers.push('a');
    fp.pseudo_headers.push('p');
    return fp;
}

// Wing client preset:
// Settings: 1:65536;2:0;3:100;4:6291456;6:262144
// Window Update: 15663105
// Priority: 0
// Pseudo Headers: m,a,s,p
fn akamai_wing_preset() -> AkamaiFingerprint {
    var fp = AkamaiFingerprint {
        window_update: 15663105,
        ..
    };
    fp.settings.push(AkamaiSetting { id: 1, val: 65536 });
    fp.settings.push(AkamaiSetting { id: 2, val: 0 });
    fp.settings.push(AkamaiSetting { id: 3, val: 100 });
    fp.settings.push(AkamaiSetting { id: 4, val: 6291456 });
    fp.settings.push(AkamaiSetting { id: 6, val: 262144 });

    fp.pseudo_headers.push('m');
    fp.pseudo_headers.push('a');
    fp.pseudo_headers.push('s');
    fp.pseudo_headers.push('p');
    return fp;
}

// Standard curl / automated tooling preset:
// Settings: 1:4096;2:0;3:100;4:65535
// Window Update: 0
// Priority: 0
// Pseudo Headers: m,a,p,s
fn akamai_curl_preset() -> AkamaiFingerprint {
    var fp = AkamaiFingerprint {
        window_update: 0,
        ..
    };
    fp.settings.push(AkamaiSetting { id: 1, val: 4096 });
    fp.settings.push(AkamaiSetting { id: 2, val: 0 });
    fp.settings.push(AkamaiSetting { id: 3, val: 100 });
    fp.settings.push(AkamaiSetting { id: 4, val: 65535 });

    fp.pseudo_headers.push('m');
    fp.pseudo_headers.push('a');
    fp.pseudo_headers.push('p');
    fp.pseudo_headers.push('s');
    return fp;
}

// ---- Fingerprint Parsing -------------------------------------------------

const H2_MAX_STREAM_ID: u32 = 0x7FFFFFFF; // RFC 9113 §4.1 (31-bit stream identifier)

// Parses a single Akamai priority token `stream_id:exclusive:dep_stream_id:weight` (RFC 7540 §6.3).
//
// Example:
//   token = "3:0:0:201"
//   returns: AkamaiPriorityFrame { stream_id: 3, exclusive: 0, dep_stream_id: 0, weight: 201 }, ok = true
fn parse_priority_token(token: const u8[:]) -> AkamaiPriorityFrame, bool {
    var dummy = AkamaiPriorityFrame { .. };
    let s_str, rem1, ok_c1 = token.split_once_byte(':');
    guard ok_c1 else { return dummy, false; }
    let excl_str, rem2, ok_c2 = rem1.split_once_byte(':');
    guard ok_c2 else { return dummy, false; }
    let dep_str, w_str, ok_c3 = rem2.split_once_byte(':');
    guard ok_c3 else { return dummy, false; }

    let s_id, ok1 = s_str.parse_u32_dec();
    let excl, ok2 = excl_str.parse_u32_dec();
    let dep, ok3 = dep_str.parse_u32_dec();
    let w, ok4 = w_str.parse_u32_dec();
    guard ok1 && ok2 && ok3 && ok4 && excl <= 1 && w >= 1 && w <= 256 else { return dummy, false; }
    guard s_id > 0 && s_id <= H2_MAX_STREAM_ID && dep <= H2_MAX_STREAM_ID && s_id != dep else { return dummy, false; }

    return AkamaiPriorityFrame {
        stream_id:     s_id,
        exclusive:     excl as u8,
        dep_stream_id: dep,
        weight:        w as u16,
    }, true;
}

// Parses a single key-value setting pair (e.g. 1:65536) in an Akamai fingerprint.
//
// Example:
//   token = "1:65536"
//   returns: AkamaiSetting { id: 1, val: 65536 }, ok = true
fn parse_akamai_setting_token(token: const u8[:]) -> AkamaiSetting, bool {
    var dummy = AkamaiSetting { id: 0, val: 0 };
    let id_str, val_str, has_colon = token.split_once_byte(':');
    guard has_colon else { return dummy, false; }
    let id_val, ok_id = id_str.parse_u32_dec();
    let val_val, ok_val = val_str.parse_u32_dec();
    guard ok_id && ok_val && id_val <= 0xFFFF else { return dummy, false; }
    return AkamaiSetting { id: id_val as u16, val: val_val }, true;
}

// Parses semicolon-separated HTTP/2 settings in an Akamai fingerprint section.
//
// Example:
//   settings_part = "1:65536;2:0"
//   appends: parsed settings to fp.settings, returns: true
fn parse_akamai_settings(settings_part: const u8[:], fp: AkamaiFingerprint&) -> bool {
    guard settings_part.len > 0 else { return true; }
    let saved_len = fp.settings.len;
    var committed = false;
    defer if !committed { fp.settings.resize(saved_len); };

    var tok = core::make_byte_tokenizer(settings_part, ';');
    while true {
        let item, has_more = core::token_next(tok);
        guard has_more else { break; }
        let setting, ok = parse_akamai_setting_token(item);
        guard ok && fp.settings.try_push(setting) else { return false; }
    }
    committed = true;
    return true;
}

// Parses comma-separated priority stream frames in an Akamai fingerprint section.
//
// Example:
//   prio_part = "3:0:0:201,5:0:0:101"
//   appends: parsed frames to fp.priority_frames, returns: true
fn parse_akamai_priorities(prio_part: const u8[:], fp: AkamaiFingerprint&) -> bool {
    guard prio_part.len > 0 && prio_part != "0" else { return true; }
    let saved_len = fp.priority_frames.len;
    var committed = false;
    defer if !committed { fp.priority_frames.resize(saved_len); };

    var tok = core::make_byte_tokenizer(prio_part, ',');
    while true {
        let item, has_more = core::token_next(tok);
        guard has_more else { break; }
        let frame, ok = parse_priority_token(item);
        guard ok && fp.priority_frames.try_push(frame) else { return false; }
    }
    committed = true;
    return true;
}

// Parses comma-separated pseudo-header letters in an Akamai fingerprint section.
//
// Example:
//   pseudo_part = "m,a,s,p"
//   appends: ['m', 'a', 's', 'p'] to fp.pseudo_headers, returns: true
fn parse_akamai_pseudo_headers(pseudo_part: const u8[:], fp: AkamaiFingerprint&) -> bool {
    guard pseudo_part.len > 0 else { return true; }
    let saved_len = fp.pseudo_headers.len;
    var committed = false;
    defer if !committed { fp.pseudo_headers.resize(saved_len); };

    var expect_char = true;
    for b in pseudo_part {
        if b == ' ' {
            continue;
        }
        if b == ',' {
            guard !expect_char else { return false; }
            expect_char = true;
            continue;
        }
        guard expect_char && (b == 'm' || b == 'a' || b == 's' || b == 'p') else { return false; }
        for existing in fp.pseudo_headers {
            guard existing != b else { return false; }
        }
        guard fp.pseudo_headers.try_push(b) else { return false; }
        expect_char = false;
    }
    guard !expect_char else { return false; }
    committed = true;
    return true;
}

// Parses a canonical Akamai string `SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADERS` into an AkamaiFingerprint.
//
// Example:
//   raw = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
//   returns: fp = AkamaiFingerprint { .. }, ok = true
fn parse_akamai_fingerprint(raw: const u8[:]) -> AkamaiFingerprint, bool {
    var fp = AkamaiFingerprint { .. };
    guard raw.len > 0 else { return fp, false; }

    let settings_part, rem1, ok_p0 = raw.split_once_byte('|');
    guard ok_p0 else { return fp, false; }
    let wu_part, rem2, ok_p1 = rem1.split_once_byte('|');
    guard ok_p1 else { return fp, false; }
    let prio_part, pseudo_part, ok_p2 = rem2.split_once_byte('|');
    guard ok_p2 && !pseudo_part.contains_byte('|') else { return fp, false; }

    // 1. Parse Settings
    guard parse_akamai_settings(settings_part, fp) else { return AkamaiFingerprint { .. }, false; }

    // 2. Parse Window Update
    let wu_val, ok_wu = wu_part.parse_u32_dec();
    guard ok_wu && wu_val <= rfc::H2_MAX_WINDOW_SIZE else { return AkamaiFingerprint { .. }, false; }
    fp.window_update = wu_val;

    // 3. Parse Priority
    guard parse_akamai_priorities(prio_part, fp) else { return AkamaiFingerprint { .. }, false; }

    // 4. Parse Pseudo Headers
    guard parse_akamai_pseudo_headers(pseudo_part, fp) else { return AkamaiFingerprint { .. }, false; }

    return fp, true;
}

// ---- Matching & Classification -------------------------------------------

// Checks whether two Akamai fingerprints match exactly across all four vectors.
fn match_akamai_fingerprints(a: const AkamaiFingerprint&, b: const AkamaiFingerprint&) -> bool {
    // 1. Settings length & values
    if a.settings.len != b.settings.len { return false; }
    for i in a.settings.len {
        if a.settings[i].id != b.settings[i].id || a.settings[i].val != b.settings[i].val {
            return false;
        }
    }

    // 2. Window update increment
    if a.window_update != b.window_update { return false; }

    // 3. Priority frames length & values
    if a.priority_frames.len != b.priority_frames.len { return false; }
    for i in a.priority_frames.len {
        if a.priority_frames[i].stream_id != b.priority_frames[i].stream_id ||
           a.priority_frames[i].exclusive != b.priority_frames[i].exclusive ||
           a.priority_frames[i].dep_stream_id != b.priority_frames[i].dep_stream_id ||
           a.priority_frames[i].weight != b.priority_frames[i].weight {
            return false;
        }
    }

    // 4. Pseudo-headers order
    if a.pseudo_headers.len != b.pseudo_headers.len { return false; }
    for i in a.pseudo_headers.len {
        if a.pseudo_headers[i] != b.pseudo_headers[i] {
            return false;
        }
    }

    return true;
}

// Identifies the client family from an Akamai fingerprint.
fn identify_akamai_family(fp: const AkamaiFingerprint&) -> AkamaiBrowserFamily {
    let chrome = akamai_chrome_preset();
    if match_akamai_fingerprints(fp, chrome) {
        return AkamaiBrowserFamily.Chrome;
    }
    let ff = akamai_firefox_preset();
    if match_akamai_fingerprints(fp, ff) {
        return AkamaiBrowserFamily.Firefox;
    }
    let saf = akamai_safari_preset();
    if match_akamai_fingerprints(fp, saf) {
        return AkamaiBrowserFamily.Safari;
    }
    let w = akamai_wing_preset();
    if match_akamai_fingerprints(fp, w) {
        return AkamaiBrowserFamily.Wing;
    }
    let c = akamai_curl_preset();
    if match_akamai_fingerprints(fp, c) {
        return AkamaiBrowserFamily.Curl;
    }

    // Heuristic categorization based on pseudo headers and window update
    if fp.pseudo_headers.len == 4 {
        if fp.pseudo_headers[..] == "masp" {
            return AkamaiBrowserFamily.Chrome;
        }
        if fp.pseudo_headers[..] == "mpas" {
            return AkamaiBrowserFamily.Firefox;
        }
        if fp.pseudo_headers[..] == "msap" {
            return AkamaiBrowserFamily.Safari;
        }
        if fp.pseudo_headers[..] == "maps" {
            return AkamaiBrowserFamily.Curl;
        }
    }

    return AkamaiBrowserFamily.Unknown;
}

inline fn has_setting_value(settings: const AkamaiSetting[:], id: u16, val: u32) -> bool {
    for &s in settings {
        if s.id == id && s.val == val {
            return true;
        }
    }
    return false;
}

inline fn has_all_four_pseudo_headers(pseudos: const u8[:]) -> bool {
    guard pseudos.len == 4 else { return false; }
    var mask: u8 = 0;
    for b in pseudos {
        if b == 'm' { mask = mask | 1; }
        else if b == 'a' { mask = mask | 2; }
        else if b == 's' { mask = mask | 4; }
        else if b == 'p' { mask = mask | 8; }
    }
    return mask == 0x0F;
}

// Detects passive fingerprint anomalies between User-Agent declarations and HTTP/2 wire profile.
fn detect_akamai_anomaly(user_agent: const u8[:], fp: const AkamaiFingerprint&) -> AkamaiAnomaly, const u8[:] {
    guard has_all_four_pseudo_headers(fp.pseudo_headers[..]) else {
        return AkamaiAnomaly.MissingPseudoHeaders, "Missing or incomplete HTTP/2 pseudo-headers";
    }

    let is_chrome = user_agent.contains_fold("chrome")
        || user_agent.contains_fold("chromium")
        || user_agent.contains_fold("edg");
    let is_firefox = user_agent.contains_fold("firefox");
    let is_safari = user_agent.contains_fold("safari") && !is_chrome;
    let is_curl = user_agent.contains_fold("curl");

    // Chrome validation rules:
    if is_chrome {
        // Pseudo header ordering: must be m,a,s,p
        if fp.pseudo_headers[..] != "masp" {
            return AkamaiAnomaly.PseudoHeaderOrderMismatch,
                "User-Agent claims Chrome but pseudo-headers exhibit non-Chromium ordering";
        }
        // Window update: Chrome always sends window update 15663105
        if fp.window_update == 0 {
            return AkamaiAnomaly.WindowUpdateAnomaly,
                "User-Agent claims Chrome but connection WINDOW_UPDATE is omitted (bot signature)";
        }
        // Settings: Chrome requires initial window size 6291456
        if !has_setting_value(fp.settings[..], 4, 6291456) {
            return AkamaiAnomaly.SettingsMismatch,
                "User-Agent claims Chrome but SETTINGS_INITIAL_WINDOW_SIZE does not match 6291456";
        }
        return AkamaiAnomaly.None, "Authentic Chrome profile";
    }

    // Firefox validation rules:
    if is_firefox {
        if fp.pseudo_headers[..] != "mpas" {
            return AkamaiAnomaly.PseudoHeaderOrderMismatch,
                "User-Agent claims Firefox but pseudo-headers exhibit non-Gecko ordering";
        }
        if fp.window_update == 0 {
            return AkamaiAnomaly.WindowUpdateAnomaly,
                "User-Agent claims Firefox but connection WINDOW_UPDATE is omitted";
        }
        return AkamaiAnomaly.None, "Authentic Firefox profile";
    }

    // Safari validation rules:
    if is_safari {
        if fp.pseudo_headers[..] != "msap" {
            return AkamaiAnomaly.PseudoHeaderOrderMismatch,
                "User-Agent claims Safari but pseudo-headers exhibit non-WebKit ordering";
        }
        if fp.window_update == 0 {
            return AkamaiAnomaly.WindowUpdateAnomaly,
                "User-Agent claims Safari but connection WINDOW_UPDATE is omitted";
        }
        return AkamaiAnomaly.None, "Authentic Safari profile";
    }

    // Curl validation rules:
    if is_curl {
        if fp.pseudo_headers[..] != "maps" {
            return AkamaiAnomaly.PseudoHeaderOrderMismatch,
                "User-Agent claims curl but pseudo-headers exhibit non-curl ordering";
        }
        if fp.window_update != 0 {
            return AkamaiAnomaly.BotPattern, "User-Agent claims curl but connection sent browser-like WINDOW_UPDATE";
        }
        return AkamaiAnomaly.None, "Authentic Curl profile";
    }

    return AkamaiAnomaly.None, "Consistent profile";
}

// ---- Wire Framing Ingress Extractor ---------------------------------------

fn process_akamai_settings_frame(
    hdr:     const internal::FrameHeader&,
    payload: const u8[:],
    fp:      AkamaiFingerprint&,
) -> bool {
    guard (hdr.length % 6) == 0 else { return false; }
    let saved_len = fp.settings.len;
    var committed = false;
    defer if !committed { fp.settings.resize(saved_len); };

    var cur = core::cursor_from(payload);
    while cur.cursor_len() >= 6 {
        let s_id, ok_id = cur.read_u16();
        let s_val, ok_val = cur.read_u32();
        guard ok_id && ok_val && fp.settings.try_push(AkamaiSetting { id: s_id, val: s_val }) else {
            return false;
        }
    }
    committed = true;
    return true;
}

fn process_akamai_priority_frame(
    hdr:     const internal::FrameHeader&,
    payload: const u8[:],
    fp:      AkamaiFingerprint&,
) -> bool {
    var cur = core::cursor_from(payload);
    let raw_dep, ok_dep = cur.read_u32();
    let raw_weight, ok_w = cur.read_u8();
    guard ok_dep && ok_w else { return false; }
    let exclusive = ((raw_dep >> 31) & 1) as u8;
    let dep_id = raw_dep & H2_MAX_STREAM_ID;
    let weight = core::add_sat_u64(raw_weight, 1) as u16;
    guard hdr.stream_id > 0 && hdr.stream_id != dep_id else {
        return false;
    }
    return fp.priority_frames.try_push(AkamaiPriorityFrame {
        stream_id:     hdr.stream_id,
        exclusive:     exclusive,
        dep_stream_id: dep_id,
        weight:        weight,
    });
}

// Extracts an AkamaiFingerprint from binary HTTP/2 connection wire frames.
//
// Example:
//   wire_bytes = [H2_CLIENT_PREFACE, SETTINGS frame, WINDOW_UPDATE frame], pseudo_headers_order = "m,a,s,p"
//   returns: AkamaiFingerprint { ... }, ok = true
fn extract_akamai_from_wire(
    wire_bytes:           const u8[:],
    pseudo_headers_order: const u8[:],
) -> AkamaiFingerprint, bool {
    var fp = AkamaiFingerprint { .. };
    guard wire_bytes.len >= 9 else { return fp, false; }

    var rem = wire_bytes;
    // Skip 24-byte client connection preface if present
    if core::starts_with(rem, rfc::H2_CLIENT_PREFACE[..]) {
        rem = rem[24..];
    }

    var cur = core::cursor_from(rem);
    var found_settings = false;

    while cur.cursor_len() >= 9 {
        let hdr, err = internal::parse_frame_header(cur.buf);
        if err != rfc::H2_ERR_NO_ERROR || internal::validate_frame_header_rules(hdr) != rfc::H2_ERR_NO_ERROR {
            return AkamaiFingerprint { .. }, false;
        }
        let frame_total_len = core::add_sat_i64(9, hdr.length);
        guard cur.cursor_len() >= frame_total_len else { break; }

        // Connection handshake phase ends on first HEADERS or DATA frame
        if hdr.frame_type == rfc::H2_FRAME_HEADERS || hdr.frame_type == rfc::H2_FRAME_DATA {
            break;
        }

        let _, _ = cur.read_bytes(9);
        let payload, ok_pay = cur.read_bytes(hdr.length);
        guard ok_pay else { break; }

        // SETTINGS Frame (Type 0x04) on Stream 0 (non-ACK)
        if hdr.frame_type == rfc::H2_FRAME_SETTINGS && hdr.stream_id == 0 && (hdr.flags & rfc::H2_FLAG_ACK) == 0 {
            found_settings = true;
            guard process_akamai_settings_frame(hdr, payload, fp) else { return AkamaiFingerprint { .. }, false; }
        }

        // WINDOW_UPDATE Frame (Type 0x08) on Stream 0
        if hdr.frame_type == rfc::H2_FRAME_WINDOW_UPDATE && hdr.stream_id == 0 && hdr.length == 4 {
            var wu_cur = core::cursor_from(payload);
            let raw_inc, ok_inc = wu_cur.read_u32();
            let inc = raw_inc & H2_MAX_STREAM_ID;
            guard ok_inc && inc > 0 else { return AkamaiFingerprint { .. }, false; }
            fp.window_update = inc;
        }

        // PRIORITY Frame (Type 0x02)
        if hdr.frame_type == rfc::H2_FRAME_PRIORITY && hdr.length == 5 {
            guard process_akamai_priority_frame(hdr, payload, fp) else { return AkamaiFingerprint { .. }, false; }
        }
    }

    guard found_settings && parse_akamai_pseudo_headers(pseudo_headers_order, fp) else {
        return AkamaiFingerprint { .. }, false;
    }

    return fp, true;
}

// ---- Wire Framing Egress Generator ---------------------------------------

// Serializes the exact HTTP/2 wire frames corresponding to this Akamai fingerprint.
fn encode_akamai_handshake_frames<B>(fp: const AkamaiFingerprint&, out: B&) {
    // 1. SETTINGS Frame (Stream 0)
    let settings_payload_len = core::mul_sat_u64(fp.settings.len as u64, 6) as u32;
    var settings_hdr = internal::FrameHeader {
        length:     settings_payload_len,
        frame_type: rfc::H2_FRAME_SETTINGS,
        flags:      0,
        stream_id:  0,
    };
    internal::encode_frame_header_to(settings_hdr, out);

    for &s in fp.settings {
        out.append_u16_be(s.id);
        out.append_u32_be(s.val);
    }

    // 2. WINDOW_UPDATE Frame (Stream 0) if increment > 0
    if fp.window_update > 0 {
        var wu_hdr = internal::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_WINDOW_UPDATE,
            flags:      0,
            stream_id:  0,
        };
        internal::encode_frame_header_to(wu_hdr, out);

        let inc = fp.window_update & H2_MAX_STREAM_ID;
        out.append_u32_be(inc);
    }

    // 3. PRIORITY Frames (if declared)
    for &p in fp.priority_frames {
        var p_hdr = internal::FrameHeader {
            length:     5,
            frame_type: rfc::H2_FRAME_PRIORITY,
            flags:      0,
            stream_id:  p.stream_id & H2_MAX_STREAM_ID,
        };
        internal::encode_frame_header_to(p_hdr, out);

        let excl_bit = ((p.exclusive & 1) as u32) << 31;
        let dep = (p.dep_stream_id & H2_MAX_STREAM_ID) | excl_bit;
        out.append_u32_be(dep);

        let w_clamped = min(max(p.weight, 1), 256);
        let w_byte = core::sub_sat_u64(w_clamped, 1) as u8;
        out.push(w_byte);
    }
}

// ---- Pseudo-Header Ordering Helper ---------------------------------------

// Orders the 4 standard HTTP/2 pseudo-headers in the exact sequence specified by the fingerprint.
fn order_pseudo_headers(
    fp:        const AkamaiFingerprint&,
    method:    const u8[:],
    authority: const u8[:],
    scheme:    const u8[:],
    path:      const u8[:],
    out:       HeaderMap&,
) {
    out.clear();
    var seen_mask: u8 = 0;
    for b in fp.pseudo_headers {
        guard out.entries.len < 4 else { break; }
        if b == 'm' && (seen_mask & 1) == 0 {
            seen_mask = seen_mask | 1;
            let _ = append_header(out, ":method", method);
        } else if b == 'a' && (seen_mask & 2) == 0 {
            seen_mask = seen_mask | 2;
            let _ = append_header(out, ":authority", authority);
        } else if b == 's' && (seen_mask & 4) == 0 {
            seen_mask = seen_mask | 4;
            let _ = append_header(out, ":scheme", scheme);
        } else if b == 'p' && (seen_mask & 8) == 0 {
            seen_mask = seen_mask | 8;
            let _ = append_header(out, ":path", path);
        }
    }
}
