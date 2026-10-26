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

// ---- 1. Data Structures -----------------------------------------------------

// Single HTTP/2 parameter within the initial SETTINGS frame.
struct AkamaiSetting {
    id: u16 = 0,
    val: u32 = 0,
}

// Stream priority dependency declared during HTTP/2 connection setup.
struct AkamaiPriorityFrame {
    stream_id: u32 = 0,
    exclusive: u8 = 0,      // 0 or 1
    dep_stream_id: u32 = 0,
    weight: u16 = 0,        // 1 to 256
}

// Complete Akamai HTTP/2 Client Fingerprint specification.
struct AkamaiFingerprint {
    settings: AkamaiSetting[..16] = [],
    window_update: u32 = 0,                     // Stream 0 window increment (0 if omitted)
    priority_frames: AkamaiPriorityFrame[..8] = [],
    pseudo_headers: u8[..8] = [],               // Initial chars: e.g. ['m', 'a', 's', 'p']
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

// ---- 2. Formatting & Serialization ------------------------------------------

// Formats an unsigned 32-bit integer as ASCII decimal characters into out.
fn format_u32_dec<B>(val: u32, out: B&) {
    guard val > 0 else {
        out.push('0');
        return;
    }
    var digits: u8[16] = [0; 16];
    var count = 0;
    var v = val;
    while v > 0 {
        digits[count] = ('0' as u8) + ((v % 10) as u8);
        v = v / 10;
        count += 1;
    }
    for i in count {
        out.push(digits[count - 1 - i]);
    }
}

// Parses an ASCII decimal string into an unsigned 32-bit integer.
fn parse_u32_dec(str: const u8[:]) -> u32, bool {
    guard str.len > 0 else { return 0, false; }
    var result: u64 = 0;
    for b in str {
        if b < '0' || b > '9' { return 0, false; }
        result = result * 10 + (b - '0');
        if result > 0xFFFFFFFF { return 0, false; }
    }
    return (result as u32), true;
}

// Formats SETTINGS section: `ID:Value;ID:Value;...`
fn format_akamai_settings<B>(settings: const AkamaiSetting[:], out: B&) {
    for i in settings.len {
        if i > 0 {
            out.push(';');
        }
        format_u32_dec(settings[i].id as u32, out);
        out.push(':');
        format_u32_dec(settings[i].val, out);
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
        format_u32_dec(priority[i].stream_id, out);
        out.push(':');
        format_u32_dec(priority[i].exclusive as u32, out);
        out.push(':');
        format_u32_dec(priority[i].dep_stream_id, out);
        out.push(':');
        format_u32_dec(priority[i].weight as u32, out);
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
fn format_akamai_fingerprint(fp: const AkamaiFingerprint&, out: u8[..256]&) {
    out.clear();
    format_akamai_settings(fp.settings[..], out);
    out.push('|');
    format_u32_dec(fp.window_update, out);
    out.push('|');
    format_akamai_priority(fp.priority_frames[..], out);
    out.push('|');
    format_akamai_pseudo_headers(fp.pseudo_headers[..], out);
}

// Formats the canonical Akamai fingerprint string returning a bounded buffer.
fn akamai_fingerprint_to_string(fp: const AkamaiFingerprint&) -> u8[..256] {
    var out: u8[..256] = [];
    format_akamai_fingerprint(fp, out);
    return out;
}

// Computes the 32-character hexadecimal MD5 hash of the Akamai fingerprint string.
fn compute_akamai_hash<B>(fp: const AkamaiFingerprint&, out_hex: B&) {
    var raw: u8[..256] = [];
    format_akamai_fingerprint(fp, raw);
    let digest = core::md5(raw[..]);
    out_hex.clear();
    let hex_chars: const u8[16] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
    for b in digest {
        out_hex.push(hex_chars[(b >> 4) & 0x0F]);
        out_hex.push(hex_chars[b & 0x0F]);
    }
}

// Computes the 32-character hexadecimal MD5 hash returning a bounded buffer.
fn akamai_fingerprint_hash(fp: const AkamaiFingerprint&) -> u8[..32] {
    var out: u8[..32] = [];
    compute_akamai_hash(fp, out);
    return out;
}

// ---- 3. Standard Presets ----------------------------------------------------

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

// ---- 4. Fingerprint Parsing -------------------------------------------------

// Checks whether two byte slices are identical in length and content.
fn bytes_eq(a: const u8[:], b: const u8[:]) -> bool {
    guard a.len == b.len else { return false; }
    for i in a.len {
        if a[i] != b[i] { return false; }
    }
    return true;
}

// Parses a canonical Akamai string `SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADERS` into an AkamaiFingerprint.
fn parse_akamai_fingerprint(raw: const u8[:]) -> AkamaiFingerprint, bool {
    var fp = AkamaiFingerprint { .. };
    guard raw.len > 0 else { return fp, false; }

    // Find 3 pipe separators
    var pipe_indices: i64[4] = [-1; 4];
    var pipe_cnt = 0;
    for i in raw.len {
        if raw[i] == '|' {
            if pipe_cnt < 3 {
                pipe_indices[pipe_cnt] = i;
                pipe_cnt += 1;
            } else {
                return fp, false; // Extra pipe
            }
        }
    }
    guard pipe_cnt == 3 else { return fp, false; }

    let p0 = pipe_indices[0];
    let p1 = pipe_indices[1];
    let p2 = pipe_indices[2];

    let settings_part = raw[0..p0];
    let wu_part = raw[(p0 + 1)..p1];
    let prio_part = raw[(p1 + 1)..p2];
    let pseudo_part = raw[(p2 + 1)..raw.len];

    // 1. Parse Settings
    if settings_part.len > 0 {
        var start: i64 = 0;
        var idx: i64 = 0;
        while idx <= settings_part.len {
            if idx == settings_part.len || settings_part[idx] == ';' {
                if idx > start {
                    let token = settings_part[start..idx];
                    var colon_idx: i64 = -1;
                    for k in token.len {
                        if token[k] == ':' {
                            colon_idx = k;
                            break;
                        }
                    }
                    guard colon_idx > 0 else { return fp, false; }
                    let id_val, ok_id = parse_u32_dec(token[0..colon_idx]);
                    guard ok_id && id_val <= 0xFFFF else { return fp, false; }
                    let val_val, ok_val = parse_u32_dec(token[(colon_idx + 1)..token.len]);
                    guard ok_val else { return fp, false; }

                    if fp.settings.len < fp.settings.cap {
                        fp.settings.push(AkamaiSetting { id: id_val as u16, val: val_val });
                    }
                }
                start = idx + 1;
            }
            idx += 1;
        }
    }

    // 2. Parse Window Update
    if wu_part.len > 0 {
        let wu_val, ok_wu = parse_u32_dec(wu_part);
        guard ok_wu else { return fp, false; }
        fp.window_update = wu_val;
    }

    // 3. Parse Priority
    if prio_part.len > 0 && !(prio_part.len == 1 && prio_part[0] == '0') {
        var start: i64 = 0;
        var idx: i64 = 0;
        while idx <= prio_part.len {
            if idx == prio_part.len || prio_part[idx] == ',' {
                if idx > start {
                    let token = prio_part[start..idx];
                    // token format: stream_id:exclusive:dep_stream_id:weight
                    var colons: i64[4] = [-1; 4];
                    var c_cnt = 0;
                    for k in token.len {
                        if token[k] == ':' && c_cnt < 3 {
                            colons[c_cnt] = k;
                            c_cnt += 1;
                        }
                    }
                    guard c_cnt == 3 else { return fp, false; }
                    let s_id, ok1 = parse_u32_dec(token[0..colons[0]]);
                    let excl, ok2 = parse_u32_dec(token[(colons[0] + 1)..colons[1]]);
                    let dep, ok3 = parse_u32_dec(token[(colons[1] + 1)..colons[2]]);
                    let w, ok4 = parse_u32_dec(token[(colons[2] + 1)..token.len]);
                    guard ok1 && ok2 && ok3 && ok4 else { return fp, false; }

                    if fp.priority_frames.len < fp.priority_frames.cap {
                        fp.priority_frames.push(AkamaiPriorityFrame {
                            stream_id: s_id,
                            exclusive: (excl & 1) as u8,
                            dep_stream_id: dep,
                            weight: w as u16,
                        });
                    }
                }
                start = idx + 1;
            }
            idx += 1;
        }
    }

    // 4. Parse Pseudo Headers
    if pseudo_part.len > 0 {
        for b in pseudo_part {
            if b != ',' && b != ' ' {
                if fp.pseudo_headers.len < fp.pseudo_headers.cap {
                    fp.pseudo_headers.push(b);
                }
            }
        }
    }

    return fp, true;
}

// ---- 5. Matching & Classification -------------------------------------------

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
        if fp.pseudo_headers[0] == 'm' && fp.pseudo_headers[1] == 'a' && fp.pseudo_headers[2] == 's' && fp.pseudo_headers[3] == 'p' {
            return AkamaiBrowserFamily.Chrome;
        }
        if fp.pseudo_headers[0] == 'm' && fp.pseudo_headers[1] == 'p' && fp.pseudo_headers[2] == 'a' && fp.pseudo_headers[3] == 's' {
            return AkamaiBrowserFamily.Firefox;
        }
        if fp.pseudo_headers[0] == 'm' && fp.pseudo_headers[1] == 's' && fp.pseudo_headers[2] == 'a' && fp.pseudo_headers[3] == 'p' {
            return AkamaiBrowserFamily.Safari;
        }
    }

    return AkamaiBrowserFamily.Unknown;
}

// Detects passive fingerprint anomalies between User-Agent declarations and HTTP/2 wire profile.
fn detect_akamai_anomaly(user_agent: const u8[:], fp: const AkamaiFingerprint&) -> AkamaiAnomaly, const u8[:] {
    guard fp.pseudo_headers.len == 4 else {
        return AkamaiAnomaly.MissingPseudoHeaders, "Missing or incomplete HTTP/2 pseudo-headers";
    }

    let is_chrome = core::contains_fold(user_agent, "chrome") ||
                    core::contains_fold(user_agent, "chromium") ||
                    core::contains_fold(user_agent, "edg");
    let is_firefox = core::contains_fold(user_agent, "firefox");
    let is_safari = core::contains_fold(user_agent, "safari") && !is_chrome;
    let is_curl = core::contains_fold(user_agent, "curl");

    // Chrome validation rules:
    if is_chrome {
        // Pseudo header ordering: must be m,a,s,p
        if fp.pseudo_headers[0] != 'm' || fp.pseudo_headers[1] != 'a' || fp.pseudo_headers[2] != 's' || fp.pseudo_headers[3] != 'p' {
            return AkamaiAnomaly.PseudoHeaderOrderMismatch, "User-Agent claims Chrome but pseudo-headers exhibit non-Chromium ordering";
        }
        // Window update: Chrome always sends window update 15663105
        if fp.window_update == 0 {
            return AkamaiAnomaly.WindowUpdateAnomaly, "User-Agent claims Chrome but connection WINDOW_UPDATE is omitted (bot signature)";
        }
        // Settings: Chrome requires initial window size 6291456
        var has_win_setting = false;
        for &s in fp.settings {
            if s.id == 4 && s.val == 6291456 {
                has_win_setting = true;
                break;
            }
        }
        if !has_win_setting {
            return AkamaiAnomaly.SettingsMismatch, "User-Agent claims Chrome but SETTINGS_INITIAL_WINDOW_SIZE does not match 6291456";
        }
        return AkamaiAnomaly.None, "Authentic Chrome profile";
    }

    // Firefox validation rules:
    if is_firefox {
        if fp.pseudo_headers[0] != 'm' || fp.pseudo_headers[1] != 'p' || fp.pseudo_headers[2] != 'a' || fp.pseudo_headers[3] != 's' {
            return AkamaiAnomaly.PseudoHeaderOrderMismatch, "User-Agent claims Firefox but pseudo-headers exhibit non-Gecko ordering";
        }
        if fp.window_update == 0 {
            return AkamaiAnomaly.WindowUpdateAnomaly, "User-Agent claims Firefox but connection WINDOW_UPDATE is omitted";
        }
        return AkamaiAnomaly.None, "Authentic Firefox profile";
    }

    // Safari validation rules:
    if is_safari {
        if fp.pseudo_headers[0] != 'm' || fp.pseudo_headers[1] != 's' || fp.pseudo_headers[2] != 'a' || fp.pseudo_headers[3] != 'p' {
            return AkamaiAnomaly.PseudoHeaderOrderMismatch, "User-Agent claims Safari but pseudo-headers exhibit non-WebKit ordering";
        }
        return AkamaiAnomaly.None, "Authentic Safari profile";
    }

    // Curl validation rules:
    if is_curl {
        if fp.window_update != 0 {
            return AkamaiAnomaly.BotPattern, "User-Agent claims curl but connection sent browser-like WINDOW_UPDATE";
        }
        return AkamaiAnomaly.None, "Authentic Curl profile";
    }

    return AkamaiAnomaly.None, "Consistent profile";
}

// ---- 6. Wire Framing Ingress Extractor ---------------------------------------

// Extracts an AkamaiFingerprint from binary HTTP/2 connection wire frames.
fn extract_akamai_from_wire(
    wire_bytes: const u8[:],
    pseudo_headers_order: const u8[:],
) -> AkamaiFingerprint, bool {
    var fp = AkamaiFingerprint { .. };
    guard wire_bytes.len >= 9 else { return fp, false; }

    var offset: i64 = 0;
    // Skip 24-byte client connection preface if present
    if wire_bytes.len >= 24 && bytes_eq(wire_bytes[0..24], H2_CLIENT_PREFACE[..]) {
        offset = 24;
    }

    while (wire_bytes.len - offset) >= 9 {
        let hdr, err = parse_frame_header(wire_bytes[offset..wire_bytes.len]);
        if err != ERR_NO_ERROR {
            break;
        }
        let frame_total_len = 9 + (hdr.length as i64);
        guard (wire_bytes.len - offset) >= frame_total_len else { break; }

        let payload = wire_bytes[(offset + 9)..(offset + frame_total_len)];

        // SETTINGS Frame (Type 0x04) on Stream 0 (non-ACK)
        if hdr.frame_type == FRAME_SETTINGS && hdr.stream_id == 0 && (hdr.flags & FLAG_ACK) == 0 {
            let num_settings = (hdr.length / 6) as i64;
            for i in num_settings {
                let s_off = i * 6;
                let s_id = ((payload[s_off] as u16) << 8) | payload[s_off + 1];
                let s_val = ((payload[s_off + 2] as u32) << 24) |
                            ((payload[s_off + 3] as u32) << 16) |
                            ((payload[s_off + 4] as u32) << 8) |
                            payload[s_off + 5];
                if fp.settings.len < fp.settings.cap {
                    fp.settings.push(AkamaiSetting { id: s_id, val: s_val });
                }
            }
        }

        // WINDOW_UPDATE Frame (Type 0x08) on Stream 0
        if hdr.frame_type == FRAME_WINDOW_UPDATE && hdr.stream_id == 0 && hdr.length == 4 {
            let inc = (((payload[0] & 0x7F) as u32) << 24) |
                      ((payload[1] as u32) << 16) |
                      ((payload[2] as u32) << 8) |
                      payload[3];
            fp.window_update = inc;
        }

        // PRIORITY Frame (Type 0x02)
        if hdr.frame_type == FRAME_PRIORITY && hdr.length == 5 {
            let exclusive = (payload[0] >> 7) & 1;
            let dep_id = (((payload[0] & 0x7F) as u32) << 24) |
                         ((payload[1] as u32) << 16) |
                         ((payload[2] as u32) << 8) |
                         payload[3];
            let weight = (payload[4] as u16) + 1;

            if fp.priority_frames.len < fp.priority_frames.cap {
                fp.priority_frames.push(AkamaiPriorityFrame {
                    stream_id: hdr.stream_id,
                    exclusive: exclusive,
                    dep_stream_id: dep_id,
                    weight: weight,
                });
            }
        }

        offset += frame_total_len;
    }

    // Assign pseudo-headers (filtering commas and whitespace)
    for b in pseudo_headers_order {
        if b != ',' && b != ' ' {
            if fp.pseudo_headers.len < fp.pseudo_headers.cap {
                fp.pseudo_headers.push(b);
            }
        }
    }

    return fp, true;
}

// ---- 7. Wire Framing Egress Generator ---------------------------------------

// Serializes the exact HTTP/2 wire frames corresponding to this Akamai fingerprint.
fn encode_akamai_handshake_frames<B>(fp: const AkamaiFingerprint&, out: B&) {
    // 1. SETTINGS Frame (Stream 0)
    let settings_payload_len = (fp.settings.len * 6) as u32;
    var settings_hdr = FrameHeader {
        length: settings_payload_len,
        frame_type: FRAME_SETTINGS,
        flags: 0,
        stream_id: 0,
    };
    encode_frame_header_to(settings_hdr, out);

    for &s in fp.settings {
        out.push(((s.id >> 8) & 0xFF) as u8);
        out.push((s.id & 0xFF) as u8);

        out.push(((s.val >> 24) & 0xFF) as u8);
        out.push(((s.val >> 16) & 0xFF) as u8);
        out.push(((s.val >> 8) & 0xFF) as u8);
        out.push((s.val & 0xFF) as u8);
    }

    // 2. WINDOW_UPDATE Frame (Stream 0) if increment > 0
    if fp.window_update > 0 {
        var wu_hdr = FrameHeader {
            length: 4,
            frame_type: FRAME_WINDOW_UPDATE,
            flags: 0,
            stream_id: 0,
        };
        encode_frame_header_to(wu_hdr, out);

        let inc = fp.window_update & 0x7FFFFFFF;
        out.push(((inc >> 24) & 0x7F) as u8);
        out.push(((inc >> 16) & 0xFF) as u8);
        out.push(((inc >> 8) & 0xFF) as u8);
        out.push((inc & 0xFF) as u8);
    }

    // 3. PRIORITY Frames (if declared)
    for &p in fp.priority_frames {
        var p_hdr = FrameHeader {
            length: 5,
            frame_type: FRAME_PRIORITY,
            flags: 0,
            stream_id: p.stream_id,
        };
        encode_frame_header_to(p_hdr, out);

        let excl_bit = ((p.exclusive & 1) as u32) << 31;
        let dep = (p.dep_stream_id & 0x7FFFFFFF) | excl_bit;

        out.push(((dep >> 24) & 0xFF) as u8);
        out.push(((dep >> 16) & 0xFF) as u8);
        out.push(((dep >> 8) & 0xFF) as u8);
        out.push((dep & 0xFF) as u8);

        let w_byte = if p.weight > 0 { (p.weight - 1) as u8 } else { 0 };
        out.push(w_byte);
    }
}

// ---- 8. Pseudo-Header Ordering Helper ---------------------------------------

// Orders the 4 standard HTTP/2 pseudo-headers in the exact sequence specified by the fingerprint.
fn order_pseudo_headers(
    fp: const AkamaiFingerprint&,
    method: const u8[:],
    authority: const u8[:],
    scheme: const u8[:],
    path: const u8[:],
    out: HeaderItem[..4]&,
) {
    out.clear();
    for b in fp.pseudo_headers {
        if b == 'm' {
            out.push(make_header(":method", method));
        } else if b == 'a' {
            out.push(make_header(":authority", authority));
        } else if b == 's' {
            out.push(make_header(":scheme", scheme));
        } else if b == 'p' {
            out.push(make_header(":path", path));
        }
    }
}
