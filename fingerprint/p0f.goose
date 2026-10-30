// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Passive OS fingerprinting (p0f v3) TCP SYN parser and matcher (RFC 793, RFC 2018, RFC 7323).
// Provides signature parsing, packet matching, and a default TCP profile for wing.
namespace wing;

import std;

// Window size calculation type in p0f v3 SYN fingerprint.
enum P0fWindowType {
    Normal, // Exact window size (e.g. 65535, 8192)
    Mss,    // Window is a multiple of MSS (e.g. mss*20, mss*10)
    Mtu,    // Window is a multiple of MTU (e.g. mtu*4)
    Mod,    // Window is modulo (mod*N or %N)
    Any,    // Wildcard window size (*,-1)
}

// Canonical TCP Option identifiers in p0f layout.
enum P0fTcpOption {
    Eol,     // End of option list (0)
    Nop,     // No operation / padding (1)
    Mss,     // Maximum segment size (2)
    Ws,      // Window scale (3)
    Sok,     // SACK permitted (4)
    Sack,    // SACK block (5)
    Ts,      // Timestamps (8)
    Unknown, // Generic / other option
}

// Canonical TCP Quirks recognized in p0f v3.
struct P0fQuirks {
    df:         bool = false, // Don't Fragment bit set
    id_plus:    bool = false, // IP ID non-zero when DF set
    id_minus:   bool = false, // IP ID zero when DF NOT set
    ecn:        bool = false, // ECN flags set (ECE/CWR)
    zero_plus:  bool = false, // Reserved bits non-zero
    flow:       bool = false, // IPv6 flow label non-zero
    seq_minus:  bool = false, // Sequence number zero
    ack_plus:   bool = false, // ACK non-zero in pure SYN
    ack_minus:  bool = false, // ACK zero in SYN+ACK
    uptr_plus:  bool = false, // Urgent pointer non-zero
    urgf_plus:  bool = false, // URG flag set
    pushf_plus: bool = false, // PUSH flag set
    ts1_minus:  bool = false, // Own timestamp zero
    ts2_plus:   bool = false, // Peer timestamp non-zero in initial SYN
    opt_plus:   bool = false, // Trailing data after EOL
    expt:       bool = false, // Experimental option ID (253, 254)
    bad:        bool = false, // Malformed option
}

// Complete parsed p0f v3 TCP SYN signature structure (8 fields).
// format: ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
struct P0fSignature {
    ip_version:    u8                 = 0,     // 4, 6, or 0 (wildcard '*')
    ttl:           u8                 = 64,    // Initial TTL (e.g. 64, 128)
    has_ttl_minus: bool               = false, // TTL tolerance wildcard (e.g. '64-')
    ip_opt_len:    u8                 = 0,     // Length of IP options (usually 0)
    mss:           i32                = -1,    // MSS value or -1 for wildcard '*'
    window_type:   P0fWindowType      = P0fWindowType.Mss,
    window_size:   i32                = 20, // Value or multiplier
    window_scale:  i16                = 10, // Scale factor (0..14, or -1 for any)
    options:       P0fTcpOption[..16] = [], // Ordered TCP options
    quirks:        P0fQuirks          = P0fQuirks { .. },
    payload:       u8[..8]            = [], // "0", "+", or "*"
}

// Concrete OS socket parameters derived from a p0f signature.
struct P0fSocketOpts {
    ttl:                 u8   = 64,
    dont_fragment:       bool = true,
    receive_buffer_size: i32  = 262144,
}

// ---- authentic wing tcp syn signature --------------------------------------

// Constructs the authentic Wing TCP SYN profile.
// Does NOT mimic any browser or OS; reflects modern, high-throughput, low-latency
// systems stack parameters:
// - Wildcard dual-stack IPv4/IPv6 ('*')
// - 64 hop initial TTL
// - 0 IP option length
// - Path MTU discovered MSS ('*')
// - High-throughput window scaling: mss*20, scale 10
// - Clean RFC option layout: mss, sok, ts, nop, ws
// - Quirks: df (Path MTU Discovery RFC 1191), id+ (random IP ID)
// - Payload: 0
// Format string: "*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0"
fn wing_p0f_signature() -> P0fSignature {
    var sig = P0fSignature {
        ip_version:    0,
        ttl:           64,
        has_ttl_minus: false,
        ip_opt_len:    0,
        mss:           -1,
        window_type:   P0fWindowType.Mss,
        window_size:   20,
        window_scale:  10,
        options:       [],
        quirks: P0fQuirks {
            df:      true,
            id_plus: true,
            ..
        },
        payload: [],
    };
    sig.options.push(P0fTcpOption.Mss);
    sig.options.push(P0fTcpOption.Sok);
    sig.options.push(P0fTcpOption.Ts);
    sig.options.push(P0fTcpOption.Nop);
    sig.options.push(P0fTcpOption.Ws);
    sig.payload.append("0");
    return sig;
}

// Constructs a blank custom p0f signature for user customization.
fn custom_p0f_signature(
    ip_version:    u8            = 0,
    ttl:           u8            = 64,
    has_ttl_minus: bool          = false,
    mss:           i32           = -1,
    window_type:   P0fWindowType = P0fWindowType.Mss,
    window_size:   i32           = 20,
    window_scale:  i16           = 10,
) -> P0fSignature {
    return P0fSignature {
        ip_version:    ip_version,
        ttl:           ttl,
        has_ttl_minus: has_ttl_minus,
        ip_opt_len:    0,
        mss:           mss,
        window_type:   window_type,
        window_size:   window_size,
        window_scale:  window_scale,
        options:       [],
        quirks:        P0fQuirks { .. },
        payload:       [],
    };
}

// ---- signature formatting & serialization ----------------------------------

fn append_p0f_options<B>(options: const P0fTcpOption[:], out: B&) {
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

// Formats a p0f signature structure into the standard 8-field p0f v3 string.
fn format_p0f(sig: const P0fSignature&) -> u8[..128] {
    var out: u8[..128] = [];

    // 1. ip_version
    if sig.ip_version == 4 {
        out.push('4');
    } else if sig.ip_version == 6 {
        out.push('6');
    } else {
        out.push('*');
    }
    out.push(':');

    // 2. ttl
    format(out, sig.ttl as i64);
    if sig.has_ttl_minus {
        out.push('-');
    }
    out.push(':');

    // 3. ip_opt_len
    format(out, sig.ip_opt_len as i64);
    out.push(':');

    // 4. mss
    if sig.mss == -1 {
        out.push('*');
    } else {
        format(out, sig.mss as i64);
    }
    out.push(':');

    // 5. window_type & scale
    match sig.window_type {
        Any => {
            out.append("*,-1");
        },
        Mss => {
            out.append("mss*");
            format(out, sig.window_size as i64);
            out.push(',');
            format(out, sig.window_scale as i64);
        },
        Mtu => {
            out.append("mtu*");
            format(out, sig.window_size as i64);
            out.push(',');
            format(out, sig.window_scale as i64);
        },
        Mod => {
            out.append("mod*");
            format(out, sig.window_size as i64);
            out.push(',');
            format(out, sig.window_scale as i64);
        },
        Normal => {
            format(out, sig.window_size as i64);
            out.push(',');
            format(out, sig.window_scale as i64);
        },
    }
    out.push(':');

    // 6. options
    append_p0f_options(sig.options[..], out);
    out.push(':');

    // 7. quirks
    var first_quirk = true;
    if sig.quirks.df { if !first_quirk { out.push(','); } out.append("df"); first_quirk = false; }
    if sig.quirks.id_plus { if !first_quirk { out.push(','); } out.append("id+"); first_quirk = false; }
    if sig.quirks.id_minus { if !first_quirk { out.push(','); } out.append("id-"); first_quirk = false; }
    if sig.quirks.ecn { if !first_quirk { out.push(','); } out.append("ecn"); first_quirk = false; }
    if sig.quirks.zero_plus { if !first_quirk { out.push(','); } out.append("0+"); first_quirk = false; }
    if sig.quirks.flow { if !first_quirk { out.push(','); } out.append("flow"); first_quirk = false; }
    if sig.quirks.seq_minus { if !first_quirk { out.push(','); } out.append("seq-"); first_quirk = false; }
    if sig.quirks.ack_plus { if !first_quirk { out.push(','); } out.append("ack+"); first_quirk = false; }
    if sig.quirks.ack_minus { if !first_quirk { out.push(','); } out.append("ack-"); first_quirk = false; }
    if sig.quirks.uptr_plus { if !first_quirk { out.push(','); } out.append("uptr+"); first_quirk = false; }
    if sig.quirks.urgf_plus { if !first_quirk { out.push(','); } out.append("urgf+"); first_quirk = false; }
    if sig.quirks.pushf_plus { if !first_quirk { out.push(','); } out.append("pushf+"); first_quirk = false; }
    if sig.quirks.ts1_minus { if !first_quirk { out.push(','); } out.append("ts1-"); first_quirk = false; }
    if sig.quirks.ts2_plus { if !first_quirk { out.push(','); } out.append("ts2+"); first_quirk = false; }
    if sig.quirks.opt_plus { if !first_quirk { out.push(','); } out.append("opt+"); first_quirk = false; }
    if sig.quirks.expt { if !first_quirk { out.push(','); } out.append("expt"); first_quirk = false; }
    if sig.quirks.bad { if !first_quirk { out.push(','); } out.append("bad"); first_quirk = false; }
    out.push(':');

    // 8. payload
    out.append(sig.payload[..]);

    return out;
}

// ---- signature parsing -----------------------------------------------------

// Extracts colon delimiter offsets across a p0f signature.
//
// Example:
//   raw = "4:64:0:1460:mss*10,0:mss,sok:df:0"
//   returns: ok = true, colons = [1, 4, 6, 11, 20, 28, 31]
fn parse_p0f_colons(raw: const u8[:], colons: i64[..8]&) -> bool {
    for i in raw.len {
        if raw[i] == ':' {
            guard colons.len < colons.cap else { return false; }
            colons.push(i);
        }
    }
    return colons.len == 7;
}

// Parses TCP window size and scale specifications (f4).
//
// Example:
//   f4 = "mss*10,0"
//   returns: ok = true, sig.window_type = Mss, sig.window_scale = 0
fn parse_p0f_window(f4: const u8[:], sig: P0fSignature&) -> bool {
    if f4 == "*,-1" || f4 == "*,*" {
        sig.window_type = P0fWindowType.Any;
        sig.window_size = -1;
        sig.window_scale = -1;
        return true;
    }
    var comma_idx: i64 = -1;
    for i in f4.len {
        if f4[i] == ',' {
            comma_idx = i;
            break;
        }
    }
    guard comma_idx >= 0 else { return false; }

    let ws_str = f4[..comma_idx];
    let scale_str = f4[comma_idx + 1..];

    if scale_str == "*" || scale_str == "-1" {
        sig.window_scale = -1;
    } else {
        let sc_val, sc_ok = parse_int(scale_str);
        guard sc_ok else { return false; }
        sig.window_scale = sc_val as i16;
    }

    if starts_with(ws_str, "mss*") {
        sig.window_type = P0fWindowType.Mss;
        let m_val, m_ok = parse_int(ws_str[4..]);
        guard m_ok else { return false; }
        sig.window_size = m_val as i32;
    } else if starts_with(ws_str, "mtu*") {
        sig.window_type = P0fWindowType.Mtu;
        let m_val, m_ok = parse_int(ws_str[4..]);
        guard m_ok else { return false; }
        sig.window_size = m_val as i32;
    } else if starts_with(ws_str, "mod*") {
        sig.window_type = P0fWindowType.Mod;
        let m_val, m_ok = parse_int(ws_str[4..]);
        guard m_ok else { return false; }
        sig.window_size = m_val as i32;
    } else if starts_with(ws_str, "%") {
        sig.window_type = P0fWindowType.Mod;
        let m_val, m_ok = parse_int(ws_str[1..]);
        guard m_ok else { return false; }
        sig.window_size = m_val as i32;
    } else if ws_str == "*" {
        sig.window_type = P0fWindowType.Any;
        sig.window_size = -1;
    } else {
        sig.window_type = P0fWindowType.Normal;
        let w_val, w_ok = parse_int(ws_str);
        guard w_ok else { return false; }
        sig.window_size = w_val as i32;
    }
    return true;
}

// Parses comma-separated TCP options into signature option array (f5).
//
// Example:
//   f5 = "mss,sok,ts,nop,ws"
//   populates sig.options with corresponding P0fOption entries
fn parse_p0f_options_field(f5: const u8[:], sig: P0fSignature&) {
    guard f5.len > 0 else { return; }
    var start_idx: i64 = 0;
    for i in f5.len {
        if f5[i] == ',' {
            let token = f5[start_idx..i];
            push_parsed_option(sig, token);
            start_idx = i + 1;
        }
    }
    if start_idx < f5.len {
        let token = f5[start_idx..];
        push_parsed_option(sig, token);
    }
}

// Parses comma-separated TCP quirks into signature quirk bitflags (f6).
//
// Example:
//   f6 = "df,id+"
//   populates sig.quirks with bitflags for df and id+
fn parse_p0f_quirks_field(f6: const u8[:], sig: P0fSignature&) {
    guard f6.len > 0 else { return; }
    var start_idx: i64 = 0;
    for i in f6.len {
        if f6[i] == ',' {
            let token = f6[start_idx..i];
            apply_parsed_quirk(sig, token);
            start_idx = i + 1;
        }
    }
    if start_idx < f6.len {
        let token = f6[start_idx..];
        apply_parsed_quirk(sig, token);
    }
}

// Parses an 8-field p0f v3 signature string without dynamic heap allocations.
//
// Example:
//   raw = "4:64:0:1460:mss*10,0:mss,sok,ts,nop,ws:df,id+:0"
//   returns: sig = P0fSignature { .. }, ok = true
fn parse_p0f(raw: const u8[:]) -> P0fSignature, bool {
    var dummy = P0fSignature { .. };
    guard raw.len > 0 else { return dummy, false; }

    var colons: i64[..8] = [];
    guard parse_p0f_colons(raw, colons) else { return dummy, false; }

    let f0 = raw[..colons[0]];
    let f1 = raw[colons[0] + 1..colons[1]];
    let f2 = raw[colons[1] + 1..colons[2]];
    let f3 = raw[colons[2] + 1..colons[3]];
    let f4 = raw[colons[3] + 1..colons[4]];
    let f5 = raw[colons[4] + 1..colons[5]];
    let f6 = raw[colons[5] + 1..colons[6]];
    let f7 = raw[colons[6] + 1..];

    var sig = P0fSignature {
        ip_version:    0,
        ttl:           64,
        has_ttl_minus: false,
        ip_opt_len:    0,
        mss:           -1,
        window_type:   P0fWindowType.Normal,
        window_size:   0,
        window_scale:  0,
        options:       [],
        quirks:        P0fQuirks { .. },
        payload:       [],
    };

    // 1. IP version
    if f0 == "4" {
        sig.ip_version = 4;
    } else if f0 == "6" {
        sig.ip_version = 6;
    } else if f0 == "*" {
        sig.ip_version = 0;
    } else {
        return dummy, false;
    }

    // 2. TTL
    var ttl_slice = f1;
    if ends_with(ttl_slice, "-") {
        sig.has_ttl_minus = true;
        ttl_slice = ttl_slice[..ttl_slice.len - 1];
    }
    let ttl_val, ttl_ok = parse_int(ttl_slice);
    guard ttl_ok && ttl_val >= 0 && ttl_val <= 255 else { return dummy, false; }
    sig.ttl = ttl_val as u8;

    // 3. IP Option Length
    let olen_val, olen_ok = parse_int(f2);
    guard olen_ok && olen_val >= 0 && olen_val <= 255 else { return dummy, false; }
    sig.ip_opt_len = olen_val as u8;

    // 4. MSS
    if f3 == "*" {
        sig.mss = -1;
    } else {
        let mss_val, mss_ok = parse_int(f3);
        guard mss_ok && mss_val >= 0 else { return dummy, false; }
        sig.mss = mss_val as i32;
    }

    // 5. Window & Scale
    guard parse_p0f_window(f4, sig) else { return dummy, false; }

    // 6. Options layout
    parse_p0f_options_field(f5, sig);

    // 7. Quirks
    parse_p0f_quirks_field(f6, sig);

    // 8. Payload
    guard f7.len <= sig.payload.cap else { return dummy, false; }
    sig.payload.append(f7);

    return sig, true;
}

fn push_parsed_option(sig: P0fSignature&, token: const u8[:]) {
    guard sig.options.len < sig.options.cap else { return; }
    if token == "eol" || starts_with(token, "eol+") { sig.options.push(P0fTcpOption.Eol); }
    else if token == "nop" { sig.options.push(P0fTcpOption.Nop); }
    else if token == "mss" { sig.options.push(P0fTcpOption.Mss); }
    else if token == "ws" { sig.options.push(P0fTcpOption.Ws); }
    else if token == "sok" { sig.options.push(P0fTcpOption.Sok); }
    else if token == "sack" { sig.options.push(P0fTcpOption.Sack); }
    else if token == "ts" { sig.options.push(P0fTcpOption.Ts); }
    else { sig.options.push(P0fTcpOption.Unknown); }
}

fn apply_parsed_quirk(sig: P0fSignature&, token: const u8[:]) {
    if token == "df" { sig.quirks.df = true; }
    else if token == "id+" { sig.quirks.id_plus = true; }
    else if token == "id-" { sig.quirks.id_minus = true; }
    else if token == "ecn" { sig.quirks.ecn = true; }
    else if token == "0+" { sig.quirks.zero_plus = true; }
    else if token == "flow" { sig.quirks.flow = true; }
    else if token == "seq-" { sig.quirks.seq_minus = true; }
    else if token == "ack+" { sig.quirks.ack_plus = true; }
    else if token == "ack-" { sig.quirks.ack_minus = true; }
    else if token == "uptr+" { sig.quirks.uptr_plus = true; }
    else if token == "urgf+" { sig.quirks.urgf_plus = true; }
    else if token == "pushf+" { sig.quirks.pushf_plus = true; }
    else if token == "ts1-" { sig.quirks.ts1_minus = true; }
    else if token == "ts2+" { sig.quirks.ts2_plus = true; }
    else if token == "opt+" { sig.quirks.opt_plus = true; }
    else if token == "expt" { sig.quirks.expt = true; }
    else if token == "bad" { sig.quirks.bad = true; }
}

// ---- pattern matching ------------------------------------------------------

// Matches an observed TCP SYN signature against a target pattern signature.
// Supports wildcards ('*', '64-', '*,-1', mss/mtu multipliers).
fn match_p0f(actual: const P0fSignature&, target: const P0fSignature&) -> bool {
    // 1. IP version (wildcard 0 matches anything)
    if target.ip_version != 0 && actual.ip_version != 0 {
        guard actual.ip_version == target.ip_version else { return false; }
    }

    // 2. TTL matching
    if target.has_ttl_minus {
        let min_ttl = if target.ttl > 35 { target.ttl - 35 } else { 1 };
        guard actual.ttl <= target.ttl && actual.ttl >= min_ttl else { return false; }
    } else {
        guard actual.ttl == target.ttl else { return false; }
    }

    // 3. IP options length
    guard actual.ip_opt_len == target.ip_opt_len else { return false; }

    // 4. MSS (target.mss == -1 is wildcard)
    if target.mss != -1 {
        guard actual.mss == target.mss else { return false; }
    }

    // 5. Window & scale
    match target.window_type {
        Any => {},
        Mss => {
            if actual.window_type == P0fWindowType.Mss {
                guard actual.window_size == target.window_size else { return false; }
            } else if actual.mss > 0 {
                guard actual.window_size == (actual.mss * target.window_size) else { return false; }
            } else {
                guard actual.window_size == target.window_size else { return false; }
            }
        },
        Mtu => {
            if actual.window_type == P0fWindowType.Mtu {
                guard actual.window_size == target.window_size else { return false; }
            } else {
                guard actual.window_size == target.window_size else { return false; }
            }
        },
        Mod => {
            guard target.window_size > 0 && (actual.window_size % target.window_size) == 0 else { return false; }
        },
        Normal => {
            guard actual.window_size == target.window_size else { return false; }
        },
    }

    // Scale match (-1 is wildcard)
    if target.window_scale != -1 {
        guard actual.window_scale == target.window_scale else { return false; }
    }

    // 6. Options layout
    guard match_p0f_options(actual.options[..], target.options[..]) else { return false; }

    // 7. Quirks
    guard actual.quirks.df == target.quirks.df else { return false; }
    guard actual.quirks.id_plus == target.quirks.id_plus else { return false; }
    guard actual.quirks.id_minus == target.quirks.id_minus else { return false; }
    guard actual.quirks.ecn == target.quirks.ecn else { return false; }
    guard actual.quirks.zero_plus == target.quirks.zero_plus else { return false; }
    guard actual.quirks.flow == target.quirks.flow else { return false; }
    guard actual.quirks.seq_minus == target.quirks.seq_minus else { return false; }
    guard actual.quirks.ack_plus == target.quirks.ack_plus else { return false; }
    guard actual.quirks.ack_minus == target.quirks.ack_minus else { return false; }
    guard actual.quirks.uptr_plus == target.quirks.uptr_plus else { return false; }
    guard actual.quirks.urgf_plus == target.quirks.urgf_plus else { return false; }
    guard actual.quirks.pushf_plus == target.quirks.pushf_plus else { return false; }
    guard actual.quirks.ts1_minus == target.quirks.ts1_minus else { return false; }
    guard actual.quirks.ts2_plus == target.quirks.ts2_plus else { return false; }
    guard actual.quirks.opt_plus == target.quirks.opt_plus else { return false; }
    guard actual.quirks.expt == target.quirks.expt else { return false; }
    guard actual.quirks.bad == target.quirks.bad else { return false; }

    // 8. Payload
    if target.payload[..] != "*" {
        guard actual.payload[..] == target.payload[..] else { return false; }
    }

    return true;
}

fn match_p0f_options(actual: const P0fTcpOption[:], target: const P0fTcpOption[:]) -> bool {
    guard actual.len == target.len else { return false; }
    for i in actual.len {
        guard actual[i] == target[i] else { return false; }
    }
    return true;
}

// ---- helper builders & socket option extraction ----------------------------

// Adds a TCP option to the signature.
fn p0f_push_option(sig: P0fSignature&, opt: P0fTcpOption) {
    guard sig.options.len < sig.options.cap else { return; }
    sig.options.push(opt);
}

// Sets a quirk by token name.
fn p0f_set_quirk(sig: P0fSignature&, quirk_name: const u8[:], enabled: bool) {
    if quirk_name == "df" { sig.quirks.df = enabled; }
    else if quirk_name == "id+" { sig.quirks.id_plus = enabled; }
    else if quirk_name == "id-" { sig.quirks.id_minus = enabled; }
    else if quirk_name == "ecn" { sig.quirks.ecn = enabled; }
    else if quirk_name == "0+" { sig.quirks.zero_plus = enabled; }
    else if quirk_name == "flow" { sig.quirks.flow = enabled; }
    else if quirk_name == "seq-" { sig.quirks.seq_minus = enabled; }
    else if quirk_name == "ack+" { sig.quirks.ack_plus = enabled; }
    else if quirk_name == "ack-" { sig.quirks.ack_minus = enabled; }
    else if quirk_name == "uptr+" { sig.quirks.uptr_plus = enabled; }
    else if quirk_name == "urgf+" { sig.quirks.urgf_plus = enabled; }
    else if quirk_name == "pushf+" { sig.quirks.pushf_plus = enabled; }
    else if quirk_name == "ts1-" { sig.quirks.ts1_minus = enabled; }
    else if quirk_name == "ts2+" { sig.quirks.ts2_plus = enabled; }
    else if quirk_name == "opt+" { sig.quirks.opt_plus = enabled; }
    else if quirk_name == "expt" { sig.quirks.expt = enabled; }
    else if quirk_name == "bad" { sig.quirks.bad = enabled; }
}

// Checks whether a quirk by token name is set.
fn p0f_has_quirk(sig: const P0fSignature&, quirk_name: const u8[:]) -> bool {
    if quirk_name == "df" { let r = sig.quirks.df; return r; }
    if quirk_name == "id+" { let r = sig.quirks.id_plus; return r; }
    if quirk_name == "id-" { let r = sig.quirks.id_minus; return r; }
    if quirk_name == "ecn" { let r = sig.quirks.ecn; return r; }
    if quirk_name == "0+" { let r = sig.quirks.zero_plus; return r; }
    if quirk_name == "flow" { let r = sig.quirks.flow; return r; }
    if quirk_name == "seq-" { let r = sig.quirks.seq_minus; return r; }
    if quirk_name == "ack+" { let r = sig.quirks.ack_plus; return r; }
    if quirk_name == "ack-" { let r = sig.quirks.ack_minus; return r; }
    if quirk_name == "uptr+" { let r = sig.quirks.uptr_plus; return r; }
    if quirk_name == "urgf+" { let r = sig.quirks.urgf_plus; return r; }
    if quirk_name == "pushf+" { let r = sig.quirks.pushf_plus; return r; }
    if quirk_name == "ts1-" { let r = sig.quirks.ts1_minus; return r; }
    if quirk_name == "ts2+" { let r = sig.quirks.ts2_plus; return r; }
    if quirk_name == "opt+" { let r = sig.quirks.opt_plus; return r; }
    if quirk_name == "expt" { let r = sig.quirks.expt; return r; }
    if quirk_name == "bad" { let r = sig.quirks.bad; return r; }
    return false;
}

// Converts a p0f signature into concrete OS socket options (IP_TTL, IP_DONTFRAGMENT, SO_RCVBUF).
fn p0f_to_socket_opts(sig: const P0fSignature&, base_mss: i32 = 1460) -> P0fSocketOpts {
    var opts = P0fSocketOpts {
        ttl:                 sig.ttl,
        dont_fragment:       sig.quirks.df,
        receive_buffer_size: 262144,
    };

    match sig.window_type {
        Normal => {
            if sig.window_size > 0 {
                opts.receive_buffer_size = sig.window_size;
            }
        },
        Mss => {
            let mss = if sig.mss > 0 { sig.mss } else { base_mss };
            opts.receive_buffer_size = mss * sig.window_size;
        },
        Mtu => {
            let mtu = base_mss + 40;
            opts.receive_buffer_size = mtu * sig.window_size;
        },
        _ => {},
    }

    return opts;
}
