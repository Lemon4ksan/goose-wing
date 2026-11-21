// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Akamai HTTP/2 Passive Fingerprinting & Active Matching Engine.
// Format: SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADERS
// Computes canonical Akamai fingerprint string and 32-character MD5 hash.
// Supports frame extraction, signature matching, Wing & custom profiles, and anomaly detection.
namespace fingerprint;

import std;
import core;
import http.headers;
import http2.framing;
import .types;
import .internal;

// ---- Formatting & Serialization ------------------------------------------

// Formats the canonical Akamai HTTP/2 fingerprint string into `out`:
// `SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADERS`
fn format_akamai<B>(fp: const AkamaiFingerprint&, out: B&) {
    out.clear();
    fingerprint_internal::format_akamai_settings(fp.settings[..], out);
    out.push('|');
    fp.window_update.format_u32_dec(out);
    out.push('|');
    fingerprint_internal::format_akamai_priority(fp.priority_frames[..], out);
    out.push('|');
    fingerprint_internal::format_akamai_pseudo_headers(fp.pseudo_headers[..], out);
}

// Formats the canonical Akamai fingerprint string returning a bounded buffer.
fn format_akamai(fp: const AkamaiFingerprint&) -> u8[..640] {
    var out: u8[..640] = [];
    format_akamai(fp, out);
    return out;
}

// Computes the 32-character hexadecimal MD5 hash of the Akamai fingerprint string into `out`.
fn compute_akamai_hash<B>(fp: const AkamaiFingerprint&, out: B&) {
    var raw: u8[..640] = [];
    format_akamai(fp, raw);
    let digest = core::md5(raw[..]);
    out.clear();
    for b in digest {
        b.format_u8_hex(out, false);
    }
}

// Computes the 32-character hexadecimal MD5 hash returning a bounded buffer.
fn akamai_hash(fp: const AkamaiFingerprint&) -> u8[..32] {
    var out: u8[..32] = [];
    compute_akamai_hash(fp, out);
    return out;
}

// ---- Authentic Wing Preset & Custom Builders -----------------------------

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
    fp.settings.push(AkamaiSetting { id: rfc::H2_SETTING_HEADER_TABLE_SIZE, val: 65536 });
    fp.settings.push(AkamaiSetting { id: rfc::H2_SETTING_ENABLE_PUSH, val: 0 });
    fp.settings.push(AkamaiSetting { id: rfc::H2_SETTING_MAX_CONCURRENT_STREAMS, val: 100 });
    fp.settings.push(AkamaiSetting { id: rfc::H2_SETTING_INITIAL_WINDOW_SIZE, val: 6291456 });
    fp.settings.push(AkamaiSetting { id: rfc::H2_SETTING_MAX_HEADER_LIST_SIZE, val: 262144 });

    fp.pseudo_headers.push('m');
    fp.pseudo_headers.push('a');
    fp.pseudo_headers.push('s');
    fp.pseudo_headers.push('p');
    return fp;
}

// Constructs a custom Akamai HTTP/2 fingerprint with configurable window increment and pseudo-header order.
fn custom_akamai_fingerprint(
    window_update:  u32         = 0,
    pseudo_headers: const u8[:] = "m,a,s,p",
) -> AkamaiFingerprint {
    var fp = AkamaiFingerprint {
        window_update: window_update & fingerprint_internal::H2_MAX_STREAM_ID,
        ..
    };
    let _ = fingerprint_internal::parse_akamai_pseudo_headers(pseudo_headers, fp.pseudo_headers);
    return fp;
}

// Appends or updates an HTTP/2 SETTINGS parameter (id: val) in `fp`.
fn push_setting(fp: AkamaiFingerprint&, id: u16, val: u32) -> bool {
    for &s in fp.settings {
        if s.id == id {
            s.val = val;
            return true;
        }
    }
    return fp.settings.try_push(AkamaiSetting { id: id, val: val });
}

// Appends a validated RFC 9113 stream PRIORITY frame entry to `fp`.
fn push_priority(
    fp:            AkamaiFingerprint&,
    stream_id:     u32,
    exclusive:     u8,
    dep_stream_id: u32,
    weight:        u16,
) -> bool {
    guard stream_id > 0 && stream_id <= fingerprint_internal::H2_MAX_STREAM_ID else { return false; }
    guard dep_stream_id <= fingerprint_internal::H2_MAX_STREAM_ID && dep_stream_id != stream_id else {
        return false;
    }
    guard exclusive <= 1 && weight >= 1 && weight <= 256 else { return false; }
    return fp.priority_frames.try_push(AkamaiPriorityFrame {
        stream_id:     stream_id,
        exclusive:     exclusive,
        dep_stream_id: dep_stream_id,
        weight:        weight,
    });
}

// Sets the HTTP/2 pseudo-header ordering (e.g., "m,a,s,p" or "m,p,a,s") on `fp`.
fn set_pseudo_headers(fp: AkamaiFingerprint&, order: const u8[:]) -> bool {
    var parsed: u8[..8] = [];
    guard fingerprint_internal::parse_akamai_pseudo_headers(order, parsed) else { return false; }
    fp.pseudo_headers = parsed;
    return true;
}

// ---- Fingerprint Parsing -------------------------------------------------

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

    guard fingerprint_internal::parse_akamai_settings(settings_part, fp) else {
        return AkamaiFingerprint { .. }, false;
    }

    let wu_val, ok_wu = wu_part.parse_u32_dec();
    guard ok_wu && wu_val <= rfc::H2_MAX_WINDOW_SIZE else { return AkamaiFingerprint { .. }, false; }
    fp.window_update = wu_val;

    guard fingerprint_internal::parse_akamai_priorities(prio_part, fp) else {
        return AkamaiFingerprint { .. }, false;
    }
    guard fingerprint_internal::parse_akamai_pseudo_headers(pseudo_part, fp.pseudo_headers) else {
        return AkamaiFingerprint { .. }, false;
    }

    return fp, true;
}

// ---- Matching & Classification -------------------------------------------

// Checks whether two Akamai fingerprints match exactly across all four vectors.
fn match_akamai(a: const AkamaiFingerprint&, b: const AkamaiFingerprint&) -> bool {
    return a.window_update == b.window_update
        && a.settings[..] == b.settings[..]
        && a.priority_frames[..] == b.priority_frames[..]
        && a.pseudo_headers[..] == b.pseudo_headers[..];
}

// Detects structural or profile anomalies between an observed HTTP/2 fingerprint
// and an expected reference fingerprint.
fn detect_akamai_anomaly(
    actual:   const AkamaiFingerprint&,
    expected: const AkamaiFingerprint&,
) -> AkamaiAnomaly, const u8[:] {
    guard fingerprint_internal::has_all_four_pseudo_headers(actual.pseudo_headers[..]) else {
        return AkamaiAnomaly.MissingPseudoHeaders, "Missing or incomplete HTTP/2 pseudo-headers";
    }
    if expected.pseudo_headers.len == 4 && actual.pseudo_headers[..] != expected.pseudo_headers[..] {
        return AkamaiAnomaly.PseudoHeaderOrderMismatch,
            "HTTP/2 pseudo-header order does not match expected profile";
    }
    if actual.window_update != expected.window_update {
        return AkamaiAnomaly.WindowUpdateAnomaly,
            "HTTP/2 connection WINDOW_UPDATE does not match expected profile";
    }
    if actual.settings.len != expected.settings.len {
        return AkamaiAnomaly.SettingsMismatch,
            "HTTP/2 SETTINGS parameter count does not match expected profile";
    }
    for &s in expected.settings {
        if !fingerprint_internal::has_setting_value(actual.settings[..], s.id, s.val) {
            return AkamaiAnomaly.SettingsMismatch,
                "HTTP/2 SETTINGS parameter value does not match expected profile";
        }
    }
    return AkamaiAnomaly.None, "Consistent profile";
}

// ---- Wire Framing Ingress & Egress ---------------------------------------

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
    guard wire_bytes.len >= rfc::H2_FRAME_HEADER_LEN else { return fp, false; }

    let stripped, has_preface = wire_bytes.strip_prefix(rfc::H2_CLIENT_PREFACE[..]);
    var cur = core::cursor_from(if has_preface { stripped } else { wire_bytes });
    var found_settings = false;
    var ended_on_request_frame = false;

    while cur.cursor_len() >= rfc::H2_FRAME_HEADER_LEN {
        match fingerprint_internal::step_akamai_wire_frame(cur, fp, found_settings) {
            Continue => {},
            StopAtRequest => {
                ended_on_request_frame = true;
                break;
            },
            Invalid => { return AkamaiFingerprint { .. }, false; },
        }
    }

    guard ended_on_request_frame || cur.cursor_len() == 0 else {
        return AkamaiFingerprint { .. }, false;
    }
    guard found_settings && fingerprint_internal::parse_akamai_pseudo_headers(
        pseudo_headers_order, fp.pseudo_headers,
    ) else {
        return AkamaiFingerprint { .. }, false;
    }
    return fp, true;
}

// Serializes validated HTTP/2 wire frames corresponding to this Akamai fingerprint.
// Rolls back `out` to its entry length on capacity overflow and returns `false`.
fn encode_akamai_handshake_frames<B>(fp: const AkamaiFingerprint&, out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };

    guard fingerprint_internal::try_encode_akamai_settings_frame(fp.settings[..], out) else {
        return false;
    }

    let wu_inc = fp.window_update & fingerprint_internal::H2_MAX_STREAM_ID;
    if wu_inc > 0 {
        let wu_hdr = http2::FrameHeader {
            length:     4,
            frame_type: rfc::H2_FRAME_WINDOW_UPDATE,
            flags:      0,
            stream_id:  0,
        };
        guard fingerprint_internal::try_append_frame_header(wu_hdr, out)
            && fingerprint_internal::try_append_u32_be_buf(wu_inc, out) else {
            return false;
        }
    }

    for &p in fp.priority_frames {
        guard fingerprint_internal::try_append_priority_frame(p, out) else { return false; }
    }

    committed = true;
    return true;
}

// Orders the 4 standard HTTP/2 pseudo-headers in the exact sequence specified by `fp`.
fn order_pseudo_headers(
    fp:        const AkamaiFingerprint&,
    method:    const u8[:],
    authority: const u8[:],
    scheme:    const u8[:],
    path:      const u8[:],
    out:       http::HeaderMap&,
) -> bool {
    out.clear();
    var committed = false;
    defer if !committed { out.clear(); };

    var seen_mask: u8 = 0;
    for b in fp.pseudo_headers {
        if out.entries.len >= 4 { break; }
        let bit = fingerprint_internal::pseudo_header_bit(b);
        if bit == 0 || (seen_mask & bit) != 0 {
            continue;
        }
        seen_mask = seen_mask | bit;
        let h_name = match b {
            'm' => ":method",
            'a' => ":authority",
            's' => ":scheme",
            _ => ":path",
        };
        let h_val = match b {
            'm' => method,
            'a' => authority,
            's' => scheme,
            _ => path,
        };
        if !out.append_header(h_name, h_val) { return false; }
    }

    committed = true;
    return true;
}
