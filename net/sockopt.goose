// Layer 4 OS Socket Parameter Tuning & p0f SYN Real Wire Alignment.
// Configures kernel socket options (TTL, Window Size, Don't Fragment, TCP_NODELAY)
// matching target browser OS profiles for passive network inspection evasion (p0f v3).
namespace wing;

import std;
import core from "..";

// ---- 1. OS-Level Socket Constants ------------------------------------------

// Protocol Levels
const IPPROTO_IP: i32  = 0;
const IPPROTO_TCP: i32 = 6;

// Socket Level Constants
const SOL_SOCKET_WIN: i32   = 0xFFFF;
const SOL_SOCKET_POSIX: i32 = 1;

// Socket Option Names (Universal / Windows / Linux)
const SO_RCVBUF_OPT: i32    = 0x1002; // Windows SO_RCVBUF (or 8 on Linux)
const SO_SNDBUF_OPT: i32    = 0x1001; // Windows SO_SNDBUF (or 7 on Linux)
const SO_KEEPALIVE_OPT: i32 = 0x0008; // SO_KEEPALIVE
const TCP_NODELAY_OPT: i32  = 0x0001; // TCP_NODELAY

// IP Level Option Names
const IP_TTL_OPT: i32       = 4;      // IP_TTL
const IP_DONTFRAG_WIN: i32  = 14;     // Windows IP_DONTFRAGMENT
const IP_MTU_DISCOVER_LINUX: i32 = 10;// Linux IP_MTU_DISCOVER (PMTUDISC_DO = 2)

// ---- 2. Socket p0f Profile Configuration -----------------------------------

struct SocketP0fProfile {
    ttl: i32 = 64,
    window_size: i32 = 65536,
    has_dont_fragment: bool = true,
    tcp_nodelay: bool = true,
    tcp_keepalive: bool = true,
    mss: i32 = 1460,
    wscale: i32 = 8,
    os_name: u8[..32] = "Universal/POSIX",
}

// Generates the exact socket option profile corresponding to a BrowserProfile
fn p0f_socket_config(browser: const BrowserProfile&) -> SocketP0fProfile {
    var cfg = SocketP0fProfile { .. };

    if browser.kind == ProfileKind.Chrome {
        // Windows 10/11 Chrome: TTL=128, Initial Window=64240, DF=1, WScale=8
        cfg.ttl = 128;
        cfg.window_size = 64240;
        cfg.has_dont_fragment = true;
        cfg.tcp_nodelay = true;
        cfg.mss = 1460;
        cfg.wscale = 8;
        cfg.os_name.clear();
        cfg.os_name.append("Windows 10/11 (Chrome)");
    } else if browser.kind == ProfileKind.Safari {
        // macOS Sonoma Safari: TTL=64, Initial Window=65535, DF=1, WScale=6
        cfg.ttl = 64;
        cfg.window_size = 65535;
        cfg.has_dont_fragment = true;
        cfg.tcp_nodelay = true;
        cfg.mss = 1460;
        cfg.wscale = 6;
        cfg.os_name.clear();
        cfg.os_name.append("macOS Sonoma (Safari)");
    } else if browser.kind == ProfileKind.Firefox {
        // Ubuntu/Linux Firefox: TTL=64, Initial Window=65495, DF=1, WScale=7
        cfg.ttl = 64;
        cfg.window_size = 65495;
        cfg.has_dont_fragment = true;
        cfg.tcp_nodelay = true;
        cfg.mss = 1460;
        cfg.wscale = 7;
        cfg.os_name.clear();
        cfg.os_name.append("Linux/Ubuntu (Firefox)");
    } else {
        // Wing Authentic: TTL=64, Initial Window=65536, DF=1, WScale=8
        cfg.ttl = 64;
        cfg.window_size = 65536;
        cfg.has_dont_fragment = true;
        cfg.tcp_nodelay = true;
        cfg.mss = 1460;
        cfg.wscale = 8;
        cfg.os_name.clear();
        cfg.os_name.append("Wing/1.0 NetStack");
    }

    return cfg;
}

// Generates the socket option profile from a ProfileKind enum
fn p0f_socket_config(kind: ProfileKind) -> SocketP0fProfile {
    let bp = new_browser_profile(kind);
    return p0f_socket_config(bp);
}

// Generates the socket option profile from an active Profile enum
fn p0f_socket_config(p: Profile) -> SocketP0fProfile {
    var kind = ProfileKind.Wing;
    if p == Profile.Custom {
        kind = ProfileKind.Custom;
    } else if p == Profile.None {
        kind = ProfileKind.None;
    }
    let bp = new_browser_profile(kind);
    return p0f_socket_config(bp);
}

// Validates whether the socket profile parameters comply with p0f v3 invariants
fn validate_p0f_socket_invariants(cfg: const SocketP0fProfile&) -> bool {
    // TTL must be a standard IP TTL (32, 64, 128, 255)
    guard cfg.ttl == 32 || cfg.ttl == 64 || cfg.ttl == 128 || cfg.ttl == 255 else {
        return false;
    }
    // Window size must be within 16-bit TCP header window (or scaled up to 65535)
    guard cfg.window_size > 0 && cfg.window_size <= 65535 else {
        return false;
    }
    // MSS must be realistic (standard ethernet 1460 or jumboframes)
    guard cfg.mss >= 536 && cfg.mss <= 8960 else {
        return false;
    }
    // WScale must be 0..14
    guard cfg.wscale >= 0 && cfg.wscale <= 14 else {
        return false;
    }
    return true;
}

// Formats a human-readable summary of the socket configuration
fn format_socket_p0f_summary<B>(cfg: const SocketP0fProfile&, out: B&) {
    out.append("OS: ");
    out.append(cfg.os_name[..]);
    out.append(" | TTL=");
    format_int(out, cfg.ttl as i64);
    out.append(" | Window=");
    format_int(out, cfg.window_size as i64);
    out.append(" | DF=");
    out.append(if cfg.has_dont_fragment { "1" } else { "0" });
    out.append(" | WScale=");
    format_int(out, cfg.wscale as i64);
    out.append(" | TCP_NODELAY=");
    out.append(if cfg.tcp_nodelay { "1" } else { "0" });
}

fn format_int<B>(out: B&, val: i64) {
    if val == 0 {
        out.push('0' as u8);
        return;
    }
    var v = val;
    var digits: u8[..32] = [];
    while v > 0 {
        let d = (v % 10) as u8;
        digits.push(('0' as u8) + d);
        v /= 10;
    }
    var i = digits.len;
    while i > 0 {
        i -= 1;
        out.push(digits[i]);
    }
}
