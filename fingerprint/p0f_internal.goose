// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for p0f v3 TCP SYN fingerprint parsing, formatting, and matching.
namespace fingerprint_internal;

import std;
import core;
import .types;

// ---- p0f v3 Internal Helpers -----------------------------------------------

const P0F_QUIRK_NAMES: const u8[:][17] = [
    "df", "id+", "id-", "ecn", "0+", "flow", "seq-", "ack+",
    "ack-", "uptr+", "urgf+", "pushf+", "ts1-", "ts2+", "opt+", "expt", "bad",
];

fn quirk_index(name: const u8[:]) -> i64, bool {
    for i in 17 {
        if name == P0F_QUIRK_NAMES[i] {
            return i, true;
        }
    }
    return 0, false;
}

fn quirks_flags(q: const fingerprint::P0fQuirks&) -> bool[17] {
    return [
        q.df, q.id_plus, q.id_minus, q.ecn, q.zero_plus, q.flow,
        q.seq_minus, q.ack_plus, q.ack_minus, q.uptr_plus, q.urgf_plus,
        q.pushf_plus, q.ts1_minus, q.ts2_plus, q.opt_plus, q.expt, q.bad,
    ];
}

fn append_p0f_options<B>(options: const fingerprint::P0fTcpOption[:], out: B&) {
    for idx in options.len {
        if idx > 0 { out.push(','); }
        match options[idx] {
            Eol => out.append("eol"),
            Nop => out.append("nop"),
            Mss => out.append("mss"),
            Ws => out.append("ws"),
            Sok => out.append("sok"),
            Sack => out.append("sack"),
            Ts => out.append("ts"),
            Unknown => out.append("dat"),
        }
    }
}

fn append_p0f_window<B>(sig: const fingerprint::P0fSignature&, out: B&) {
    match sig.window_type {
        Any => {
            out.append("*,");
            sig.window_scale.format_i64_dec(out);
        },
        Mss => {
            out.append("mss*");
            sig.window_size.format_i64_dec(out);
            out.push(',');
            sig.window_scale.format_i64_dec(out);
        },
        Mtu => {
            out.append("mtu*");
            sig.window_size.format_i64_dec(out);
            out.push(',');
            sig.window_scale.format_i64_dec(out);
        },
        Mod => {
            out.append("mod*");
            sig.window_size.format_i64_dec(out);
            out.push(',');
            sig.window_scale.format_i64_dec(out);
        },
        Normal => {
            sig.window_size.format_i64_dec(out);
            out.push(',');
            sig.window_scale.format_i64_dec(out);
        },
    }
}

fn append_p0f_quirks<B>(q: const fingerprint::P0fQuirks&, out: B&) {
    let flags = quirks_flags(q);
    var first = true;
    for i in 17 {
        if flags[i] {
            if !first { out.push(','); }
            out.append(P0F_QUIRK_NAMES[i]);
            first = false;
        }
    }
}

// Extracts colon delimiter offsets across an 8-field p0f signature.
//
// Example:
//   raw = "4:64:0:1460:mss*10,0:mss,sok:df:0"
//   returns: ok = true, colons = [1, 4, 6, 11, 20, 28, 31]
fn parse_p0f_colons(raw: const u8[:], colons: i64[..8]&) -> bool {
    let saved_len = colons.len;
    var committed = false;
    defer if !committed { colons.resize(saved_len); };

    for i in raw.len {
        if raw[i] == ':' {
            guard colons.try_push(i) else { return false; }
        }
    }
    guard colons.len == 7 else { return false; }
    committed = true;
    return true;
}

// Parses the TCP window size token (before ',') of a p0f v3 signature.
//
// Example:
//   ws_str = "mss*10"
//   returns: P0fWindowType.Mss, 10, true
fn parse_p0f_window_size(ws_str: const u8[:]) -> fingerprint::P0fWindowType, i32, bool {
    if ws_str == "*" {
        return fingerprint::P0fWindowType.Any, -1, true;
    }
    var wtype = fingerprint::P0fWindowType.Normal;
    var num_str = ws_str;
    var min_val: i64 = 0;

    let r_mss, is_mss = ws_str.strip_prefix("mss*");
    let r_mtu, is_mtu = ws_str.strip_prefix("mtu*");
    let r_mod, is_mod = ws_str.strip_prefix("mod*");
    let r_pct, is_pct = ws_str.strip_prefix("%");

    if is_mss {
        wtype = fingerprint::P0fWindowType.Mss;
        num_str = r_mss;
    } else if is_mtu {
        wtype = fingerprint::P0fWindowType.Mtu;
        num_str = r_mtu;
    } else if is_mod {
        wtype = fingerprint::P0fWindowType.Mod;
        num_str = r_mod;
        min_val = 1;
    } else if is_pct {
        wtype = fingerprint::P0fWindowType.Mod;
        num_str = r_pct;
        min_val = 1;
    }

    let val, ok = num_str.parse_i64_dec();
    guard ok && val >= min_val && val <= 65535 else {
        return fingerprint::P0fWindowType.Normal, 0, false;
    }
    return wtype, val as i32, true;
}

// Parses TCP window size and scale specifications (f4).
//
// Example:
//   f4 = "mss*10,0"
//   returns: ok = true, sig.window_type = Mss, sig.window_scale = 0
fn parse_p0f_window(f4: const u8[:], sig: fingerprint::P0fSignature&) -> bool {
    if f4 == "*,-1" || f4 == "*,*" {
        sig.window_type = fingerprint::P0fWindowType.Any;
        sig.window_size = -1;
        sig.window_scale = -1;
        return true;
    }
    let ws_str, scale_str, has_comma = f4.split_once_byte(',');
    guard has_comma else { return false; }

    if scale_str == "*" || scale_str == "-1" {
        sig.window_scale = -1;
    } else {
        let sc_val, sc_ok = scale_str.parse_i64_dec();
        guard sc_ok && sc_val >= -1 && sc_val <= 14 else { return false; }
        sig.window_scale = sc_val as i16;
    }

    let wtype, wsize, ok_ws = parse_p0f_window_size(ws_str);
    guard ok_ws else { return false; }
    sig.window_type = wtype;
    sig.window_size = wsize;
    return true;
}

fn push_parsed_option(sig: fingerprint::P0fSignature&, token: const u8[:]) -> bool {
    guard token.len > 0 else { return false; }
    var opt = fingerprint::P0fTcpOption.Unknown;
    let eol_pad, is_eol_pad = token.strip_prefix("eol+");
    if token == "eol" {
        opt = fingerprint::P0fTcpOption.Eol;
    } else if is_eol_pad {
        let pad_val, pad_ok = eol_pad.parse_i64_dec();
        guard pad_ok && pad_val >= 0 && pad_val <= 255 else { return false; }
        opt = fingerprint::P0fTcpOption.Eol;
    } else if token == "nop" {
        opt = fingerprint::P0fTcpOption.Nop;
    } else if token == "mss" {
        opt = fingerprint::P0fTcpOption.Mss;
    } else if token == "ws" {
        opt = fingerprint::P0fTcpOption.Ws;
    } else if token == "sok" {
        opt = fingerprint::P0fTcpOption.Sok;
    } else if token == "sack" {
        opt = fingerprint::P0fTcpOption.Sack;
    } else if token == "ts" {
        opt = fingerprint::P0fTcpOption.Ts;
    }
    return sig.options.try_push(opt);
}

// Parses comma-separated TCP options into signature option array (f5).
//
// Example:
//   f5 = "mss,sok,ts,nop,ws"
//   populates sig.options with corresponding P0fTcpOption entries
fn parse_p0f_options_field(f5: const u8[:], sig: fingerprint::P0fSignature&) -> bool {
    guard f5.len > 0 else { return true; }
    let saved_len = sig.options.len;
    var committed = false;
    defer if !committed { sig.options.resize(saved_len); };

    var tok = core::make_byte_tokenizer(f5, ',');
    while true {
        let token, has_more = core::token_next(tok);
        guard has_more else { break; }
        guard push_parsed_option(sig, token) else { return false; }
    }
    committed = true;
    return true;
}

// Parses comma-separated TCP quirks into signature quirk bitflags (f6).
//
// Example:
//   f6 = "df,id+"
//   populates sig.quirks with bitflags for df and id+
fn parse_p0f_quirks_field(f6: const u8[:], sig: fingerprint::P0fSignature&) -> bool {
    guard f6.len > 0 else { return true; }
    let saved_quirks = sig.quirks;
    var committed = false;
    defer if !committed { sig.quirks = saved_quirks; };

    var tok = core::make_byte_tokenizer(f6, ',');
    while true {
        let token, has_more = core::token_next(tok);
        guard has_more else { break; }
        guard apply_quirk(sig.quirks, token, true) else { return false; }
    }
    committed = true;
    return true;
}

fn apply_quirk(q: fingerprint::P0fQuirks&, name: const u8[:], enabled: bool) -> bool {
    let idx, ok = quirk_index(name);
    guard ok else { return false; }
    match idx {
        0 => { q.df = enabled; },
        1 => { q.id_plus = enabled; },
        2 => { q.id_minus = enabled; },
        3 => { q.ecn = enabled; },
        4 => { q.zero_plus = enabled; },
        5 => { q.flow = enabled; },
        6 => { q.seq_minus = enabled; },
        7 => { q.ack_plus = enabled; },
        8 => { q.ack_minus = enabled; },
        9 => { q.uptr_plus = enabled; },
        10 => { q.urgf_plus = enabled; },
        11 => { q.pushf_plus = enabled; },
        12 => { q.ts1_minus = enabled; },
        13 => { q.ts2_plus = enabled; },
        14 => { q.opt_plus = enabled; },
        15 => { q.expt = enabled; },
        16 => { q.bad = enabled; },
        _ => { return false; },
    }
    return true;
}

// Parses leading p0f v3 header fields (ip_version, ttl, ip_opt_len, mss).
//
// Example:
//   f0 = "4", f1 = "64-", f2 = "0", f3 = "1460"
//   populates sig.ip_version = 4, sig.ttl = 64, sig.has_ttl_minus = true, sig.mss = 1460
fn parse_p0f_header_fields(
    f0:  const u8[:],
    f1:  const u8[:],
    f2:  const u8[:],
    f3:  const u8[:],
    sig: fingerprint::P0fSignature&,
) -> bool {
    if f0 == "4" {
        sig.ip_version = 4;
    } else if f0 == "6" {
        sig.ip_version = 6;
    } else if f0 == "*" {
        sig.ip_version = 0;
    } else {
        return false;
    }

    let ttl_base, has_minus = f1.strip_suffix("-");
    sig.has_ttl_minus = has_minus;
    let ttl_slice = if has_minus { ttl_base } else { f1 };
    let ttl_val, ttl_ok = ttl_slice.parse_u32_dec();
    guard ttl_ok && ttl_val >= 1 && ttl_val <= 255 else { return false; }
    sig.ttl = ttl_val as u8;

    let olen_val, olen_ok = f2.parse_u32_dec();
    guard olen_ok && olen_val <= 255 else { return false; }
    sig.ip_opt_len = olen_val as u8;

    if f3 == "*" {
        sig.mss = -1;
        return true;
    }
    let mss_val, mss_ok = f3.parse_u32_dec();
    guard mss_ok && mss_val <= 65535 else { return false; }
    sig.mss = mss_val as i32;
    return true;
}

fn match_p0f_ttl(actual: const fingerprint::P0fSignature&, target: const fingerprint::P0fSignature&) -> bool {
    guard target.has_ttl_minus else { return actual.ttl == target.ttl; }
    let min_ttl = max(core::sub_sat_u64(target.ttl, 35), 1) as u8;
    return actual.ttl <= target.ttl && actual.ttl >= min_ttl;
}

fn match_p0f_scaled_window(
    actual: const fingerprint::P0fSignature&,
    target: const fingerprint::P0fSignature&,
) -> bool {
    if actual.window_type == target.window_type && actual.window_size == target.window_size {
        return true;
    }
    guard actual.window_type == fingerprint::P0fWindowType.Normal
        && actual.mss > 0
        && actual.window_size >= 0 else {
        return false;
    }
    let is_mtu = target.window_type == fingerprint::P0fWindowType.Mtu;
    let hdr_len: u64 = if !is_mtu { 0 } else if actual.ip_version == 6 { 60 } else { 40 };
    let unit = core::add_sat_u64(actual.mss as u64, hdr_len);
    let prod = core::mul_sat_u64(unit, max(target.window_size, 0) as u64);
    return (actual.window_size as u64) == prod;
}

fn match_p0f_window(actual: const fingerprint::P0fSignature&, target: const fingerprint::P0fSignature&) -> bool {
    match target.window_type {
        Any => { return true; },
        Mss => { return match_p0f_scaled_window(actual, target); },
        Mtu => { return match_p0f_scaled_window(actual, target); },
        Mod => {
            guard actual.window_size >= 0 && target.window_size > 0 else { return false; }
            let _, rem = core::div_rem_u64(actual.window_size as u64, target.window_size as u64);
            return rem == 0;
        },
        Normal => {
            return actual.window_type == fingerprint::P0fWindowType.Normal
                && actual.window_size == target.window_size;
        },
    }
}
