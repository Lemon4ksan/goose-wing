// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 OS Socket Parameter Tuning & p0f SYN Real Wire Alignment.
// Configures kernel socket options (TTL, Window Size, Don't Fragment, TCP_NODELAY)
// matching target browser OS profiles for passive network inspection evasion (p0f v3).
namespace internal;

import std;
import core from "..";

// ---- OS-Level Socket Constants ------------------------------------------

// Protocol Levels
const IPPROTO_IP:  i32 = 0;
const IPPROTO_TCP: i32 = 6;

// Socket Level Constants
const SOL_SOCKET_WIN:   i32 = 0xFFFF;
const SOL_SOCKET_POSIX: i32 = 1;

// Socket Option Names (Universal / Windows / Linux)
const SO_RCVBUF_OPT:    i32 = 0x1002; // Windows SO_RCVBUF (or 8 on Linux)
const SO_SNDBUF_OPT:    i32 = 0x1001; // Windows SO_SNDBUF (or 7 on Linux)
const SO_KEEPALIVE_OPT: i32 = 0x0008; // SO_KEEPALIVE
const TCP_NODELAY_OPT:  i32 = 0x0001; // TCP_NODELAY
const SO_LINGER_OPT:    i32 = 0x0080; // SO_LINGER
const SO_REUSEADDR_OPT: i32 = 0x0004; // SO_REUSEADDR
const SO_REUSEPORT_OPT: i32 = 0x0200; // SO_REUSEPORT

// Channel shutdown modes
const SHUT_RD:   i32 = 0;
const SHUT_WR:   i32 = 1;
const SHUT_RDWR: i32 = 2;

// IP Level Option Names
const IP_TTL_OPT:            i32 = 4;  // IP_TTL
const IP_DONTFRAG_WIN:       i32 = 14; // Windows IP_DONTFRAGMENT
const IP_MTU_DISCOVER_LINUX: i32 = 10; // Linux IP_MTU_DISCOVER (PMTUDISC_DO = 2)

// ---- Socket p0f Profile Configuration -----------------------------------

struct SocketP0fProfile {
    ttl:               i32      = 64,
    window_size:       i32      = 65535,
    has_dont_fragment: bool     = true,
    tcp_nodelay:       bool     = true,
    tcp_keepalive:     bool     = true,
    mss:               i32      = 1460,
    wscale:            i32      = 8,
    os_name:           u8[..32] = "Universal/POSIX",
}

// Generates the socket option profile from an active Profile enum
fn p0f_socket_config(p: wing::Profile) -> SocketP0fProfile {
    var cfg = SocketP0fProfile { .. };

    if p == wing::Profile.None {
        // Minimal / raw OS socket defaults
        cfg.ttl = 64;
        cfg.window_size = 65535;
        cfg.has_dont_fragment = false;
        cfg.tcp_nodelay = false;
        cfg.mss = 1460;
        cfg.wscale = 7;
        cfg.os_name.clear();
        cfg.os_name.append("Raw/None NetStack");
    } else if p == wing::Profile.Custom {
        // User-customized L4 socket configuration
        cfg.ttl = 64;
        cfg.window_size = 65535;
        cfg.has_dont_fragment = true;
        cfg.tcp_nodelay = true;
        cfg.mss = 1460;
        cfg.wscale = 8;
        cfg.os_name.clear();
        cfg.os_name.append("Custom NetStack");
    } else {
        // Wing Authentic: TTL=64, Initial Window=65535, DF=1, WScale=8, TCP_NODELAY=1
        cfg.ttl = 64;
        cfg.window_size = 65535;
        cfg.has_dont_fragment = true;
        cfg.tcp_nodelay = true;
        cfg.mss = 1460;
        cfg.wscale = 8;
        cfg.os_name.clear();
        cfg.os_name.append("Wing/1.0 NetStack");
    }

    return cfg;
}

// Generates the socket option profile corresponding to a ClientProfile
fn p0f_socket_config(profile: const wing::ClientProfile&) -> SocketP0fProfile {
    return p0f_socket_config(profile.kind);
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
    core::format_i64_dec(cfg.ttl as i64, out);
    out.append(" | Window=");
    core::format_i64_dec(cfg.window_size as i64, out);
    out.append(" | DF=");
    out.append(if cfg.has_dont_fragment { "1" } else { "0" });
    out.append(" | WScale=");
    core::format_i64_dec(cfg.wscale as i64, out);
    out.append(" | TCP_NODELAY=");
    out.append(if cfg.tcp_nodelay { "1" } else { "0" });
}

// Configures SO_LINGER on socket (RFC 1122 Section 4.2.2.13).
fn tcp_set_linger(fd: i64, onoff: bool, timeout_sec: i32 = 0) -> bool {
    guard fd > 0 else { return false; }
    return wing::tcp_set_linger(fd, onoff, timeout_sec);
}

// Configures TCP_NODELAY (Nagle algorithm bypass) on socket.
fn tcp_set_nodelay(fd: i64, enable: bool = true) -> bool {
    guard fd > 0 else { return false; }
    return wing::tcp_set_nodelay(fd, enable);
}

// Configures SO_REUSEADDR on socket.
fn tcp_set_reuseaddr(fd: i64, enable: bool = true) -> bool {
    guard fd > 0 else { return false; }
    return wing::tcp_set_reuseaddr(fd, enable);
}

// Configures SO_REUSEPORT on socket (Linux / FreeBSD).
fn tcp_set_reuseport(fd: i64, enable: bool = true) -> bool {
    guard fd > 0 else { return false; }
    return wing::tcp_set_reuseport(fd, enable);
}

// Abruptly terminates socket with TCP RST (RFC 1122 Section 4.2.2.13).
fn tcp_abort(fd: i64) -> bool {
    guard fd > 0 else { return false; }
    return wing::tcp_abort(fd);
}
