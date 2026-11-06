// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Command-line argument structures and parser for the standalone wing CLI.
import std;
import os;
import core from "..";

enum CliMode {
    Help,
    Version,
    Client,
    Serve,
}

struct HeaderPair {
    name:  u8[..128]  = [],
    value: u8[..1024] = [],
}

struct ResolveEntry {
    host: u8[..128] = [],
    port: u16       = 0,
    ip:   u8[..64]  = [],
}

struct CliConfig {
    mode:             CliMode           = CliMode.Help,
    method:           u8[..16]          = "GET",
    has_explicit_m:   bool              = false,
    head_only:        bool              = false,
    fail_on_error:    bool              = false,
    silent:           bool              = false,
    url:              u8[..2048]        = [],
    body:             u8[..8192]        = [],
    has_body:         bool              = false,
    output_file:      u8[..512]         = [],
    remote_name:      bool              = false,
    user_agent:       u8[..256]         = [],
    cookie_header:    u8[..1024]        = [],
    write_out:        u8[..256]         = [],
    headers:          HeaderPair[..16]  = [],
    resolves:         ResolveEntry[..8] = [],
    bearer_token:     u8[..512]         = [],
    basic_user:       u8[..64]          = [],
    basic_pass:       u8[..64]          = [],
    proxy_url:        u8[..256]         = [],
    timeout_ms:       i64               = 10000,
    max_retries:      i32               = 0,
    follow_redirects: bool              = true,
    insecure_tls:     bool              = false,
    http2_prior:      bool              = false,
    show_headers:     bool              = false,
    verbose:          bool              = false,
    no_color:         bool              = false,
    raw_profile:      bool              = false,
    bind_host:        u8[..64]          = "127.0.0.1",
    port:             u16               = 8080,
    max_reqs:         u64               = 0,
    scenario_file:    u8[..512]         = [],
    inline_routes:    u8[..512][..32]   = [],
    err_msg:          u8[..256]         = [],
}

fn set_cli_error(cfg: CliConfig&, msg: const u8[:], arg: const u8[:] = "") -> bool {
    cfg.err_msg.clear();
    let _ = cfg.err_msg.try_set(msg);
    let max_len = cfg.err_msg.cap;
    if arg.len > 0 && core::add_sat_i64(core::add_sat_i64(cfg.err_msg.len, 2), arg.len) <= max_len {
        cfg.err_msg.append(": ");
        cfg.err_msg.append(arg);
    }
    return false;
}

// Parses a `-H / --header "Name: Value"` argument into `cfg.headers`.
//
// Example:
//   raw = "Accept: application/json"
//   returns: true, pushes HeaderPair { name: "Accept", value: "application/json" }
fn parse_header_flag(raw: const u8[:], cfg: CliConfig&) -> bool {
    guard cfg.headers.len < cfg.headers.cap else {
        return set_cli_error(cfg, "too many -H headers (max 16)");
    }
    let col = core::index_of_byte(raw, ':');
    guard col > 0 else {
        return set_cli_error(cfg, "invalid header format, expected 'Name: Value'", raw);
    }
    let next_idx = core::add_sat_i64(col, 1);
    let name = core::trim_lws(raw[..col]);
    let val = core::trim_lws(raw[next_idx..]);
    var pair = HeaderPair { .. };
    guard pair.name.try_set(name) && pair.value.try_set(val) else {
        return set_cli_error(cfg, "header name or value exceeds buffer capacity");
    }
    cfg.headers.push(pair);
    return true;
}

// Parses a `-u / --user "user:password"` Basic Auth argument into `cfg`.
//
// Example:
//   raw = "admin:secret123"
//   returns: true, sets cfg.basic_user = "admin", cfg.basic_pass = "secret123"
fn parse_user_flag(raw: const u8[:], cfg: CliConfig&) -> bool {
    let col = core::index_of_byte(raw, ':');
    guard col > 0 else {
        return set_cli_error(cfg, "invalid -u credentials, expected 'user:password'", raw);
    }
    let next_idx = core::add_sat_i64(col, 1);
    guard cfg.basic_user.try_set(raw[..col]) && cfg.basic_pass.try_set(raw[next_idx..]) else {
        return set_cli_error(cfg, "credentials exceed capacity");
    }
    return true;
}

// Parses curl-style `--resolve host:port:ip` entry.
//
// Example:
//   raw = "example.com:443:93.184.215.14"
//   returns: true, pushes ResolveEntry { host: "example.com", port: 443, ip: "93.184.215.14" }
fn parse_resolve_flag(raw: const u8[:], cfg: CliConfig&) -> bool {
    guard cfg.resolves.len < cfg.resolves.cap else {
        return set_cli_error(cfg, "too many --resolve entries (max 8)");
    }
    let c1 = core::index_of_byte(raw, ':');
    let next1 = core::add_sat_i64(c1, 1);
    guard c1 > 0 && next1 < raw.len else {
        return set_cli_error(cfg, "invalid --resolve format, expected 'host:port:ip'", raw);
    }
    let rest = raw[next1..];
    let c2 = core::index_of_byte(rest, ':');
    let next2 = core::add_sat_i64(c2, 1);
    guard c2 > 0 && next2 < rest.len else {
        return set_cli_error(cfg, "invalid --resolve format, expected 'host:port:ip'", raw);
    }
    let host_part = raw[..c1];
    let port_part = rest[..c2];
    let ip_part = rest[next2..];
    let port_u64, ok_p = core::parse_u64_dec(port_part);
    guard ok_p && port_u64 > 0 && port_u64 <= 65535 else {
        return set_cli_error(cfg, "invalid port in --resolve", raw);
    }
    var entry = ResolveEntry { port: port_u64 as u16, .. };
    guard entry.host.try_set(host_part) && entry.ip.try_set(ip_part) else {
        return set_cli_error(cfg, "--resolve host or IP exceeds capacity");
    }
    cfg.resolves.push(entry);
    return true;
}

fn load_data_arg(raw: const u8[:], cfg: CliConfig&) -> bool {
    if raw.len > 1 && raw[0] == '@' {
        let path = raw[1..];
        var content: u8[>..] = [];
        guard read_file(path, content) else {
            return set_cli_error(cfg, "cannot read payload file", path);
        }
        guard cfg.body.try_set(content[..]) else {
            return set_cli_error(cfg, "payload file exceeds 8 KB", path);
        }
        return true;
    }
    guard cfg.body.try_set(raw) else {
        return set_cli_error(cfg, "payload exceeds 8 KB");
    }
    return true;
}

// Extracts the trailing filename segment from a URL for `-O / --remote-name`.
//
// Example:
//   url = "https://raw.githubusercontent.com/github/gitignore/main/Go.gitignore?raw=1"
//   returns: "Go.gitignore"
fn extract_remote_filename(url: const u8[:]) -> const u8[:] {
    var clean = url;
    let q_idx = core::index_of_byte(clean, '?');
    if q_idx >= 0 { clean = clean[..q_idx]; }
    let h_idx = core::index_of_byte(clean, '#');
    if h_idx >= 0 { clean = clean[..h_idx]; }

    var last_slash: i64 = -1;
    for i in clean.len {
        if clean[i] == '/' { last_slash = i; }
    }
    let next_slash = core::add_sat_i64(last_slash, 1);
    if last_slash >= 0 && next_slash < clean.len {
        return clean[next_slash..];
    }
    return "index.html";
}

fn apply_cli_output_bool_flag(arg: const u8[:], cfg: CliConfig&) -> bool {
    if arg == "-v" || arg == "--verbose" {
        cfg.verbose = true;
        cfg.show_headers = true;
        return true;
    }
    if arg == "-i" || arg == "--include" {
        cfg.show_headers = true;
        return true;
    }
    if arg == "-I" || arg == "--head" {
        cfg.head_only = true;
        cfg.show_headers = true;
        if !cfg.has_explicit_m { let _ = cfg.method.try_set("HEAD"); }
        return true;
    }
    if arg == "-s" || arg == "--silent" || arg == "-sS" {
        cfg.silent = true;
        return true;
    }
    if arg == "--fail" || arg == "--fail-with-body" {
        cfg.fail_on_error = true;
        return true;
    }
    if arg == "--no-color" {
        cfg.no_color = true;
        return true;
    }
    return false;
}

fn apply_cli_transport_bool_flag(arg: const u8[:], cfg: CliConfig&) -> bool {
    if arg == "-k" || arg == "--insecure" {
        cfg.insecure_tls = true;
        return true;
    }
    if arg == "--h2c" || arg == "--http2-prior-knowledge" {
        cfg.http2_prior = true;
        return true;
    }
    if arg == "-L" || arg == "--location" {
        cfg.follow_redirects = true;
        return true;
    }
    if arg == "--no-follow" {
        cfg.follow_redirects = false;
        return true;
    }
    if arg == "--raw-profile" {
        cfg.raw_profile = true;
        return true;
    }
    if arg == "-O" || arg == "--remote-name" {
        cfg.remote_name = true;
        return true;
    }
    return false;
}

fn apply_cli_boolean_flag(arg: const u8[:], cfg: CliConfig&) -> bool {
    return apply_cli_output_bool_flag(arg, cfg) || apply_cli_transport_bool_flag(arg, cfg);
}

fn apply_cli_client_string_opt(arg: const u8[:], val: const u8[:], cfg: CliConfig&) -> bool, bool {
    if arg == "-o" || arg == "--output" {
        return true, cfg.output_file.try_set(val) || set_cli_error(cfg, "output path too long");
    }
    if arg == "-A" || arg == "--user-agent" {
        return true, cfg.user_agent.try_set(val) || set_cli_error(cfg, "User-Agent too long");
    }
    if arg == "-b" || arg == "--cookie" {
        return true, cfg.cookie_header.try_set(val) || set_cli_error(cfg, "cookie string too long");
    }
    if arg == "-w" || arg == "--write-out" {
        return true, cfg.write_out.try_set(val) || set_cli_error(cfg, "write-out format too long");
    }
    if arg == "--resolve" {
        return true, parse_resolve_flag(val, cfg);
    }
    if arg == "-X" || arg == "--request" {
        guard cfg.method.try_set(val) else { return true, set_cli_error(cfg, "method too long"); }
        cfg.has_explicit_m = true;
        return true, true;
    }
    return false, false;
}

fn apply_cli_auth_or_serve_string_opt(arg: const u8[:], val: const u8[:], cfg: CliConfig&) -> bool, bool {
    if arg == "-H" || arg == "--header" {
        return true, parse_header_flag(val, cfg);
    }
    if arg == "--bearer" {
        return true, cfg.bearer_token.try_set(val) || set_cli_error(cfg, "token too long");
    }
    if arg == "-u" || arg == "--user" {
        return true, parse_user_flag(val, cfg);
    }
    if arg == "-x" || arg == "--proxy" {
        return true, cfg.proxy_url.try_set(val) || set_cli_error(cfg, "proxy URL too long");
    }
    if arg == "--host" {
        return true, cfg.bind_host.try_set(val) || set_cli_error(cfg, "host too long");
    }
    if arg == "-f" || arg == "--file" {
        return true, cfg.scenario_file.try_set(val) || set_cli_error(cfg, "file path too long");
    }
    return false, false;
}

fn apply_cli_string_opt(arg: const u8[:], val: const u8[:], cfg: CliConfig&) -> bool, bool {
    let m1, ok1 = apply_cli_client_string_opt(arg, val, cfg);
    if m1 { return true, ok1; }
    return apply_cli_auth_or_serve_string_opt(arg, val, cfg);
}

fn apply_cli_payload_opt(arg: const u8[:], val: const u8[:], cfg: CliConfig&) -> bool, bool {
    if arg == "-d" || arg == "--data" || arg == "--data-raw" || arg == "--data-binary" {
        guard load_data_arg(val, cfg) else { return true, false; }
        cfg.has_body = true;
        if !cfg.has_explicit_m { let _ = cfg.method.try_set("POST"); }
        return true, true;
    }
    if arg == "--json" {
        guard load_data_arg(val, cfg) else { return true, false; }
        cfg.has_body = true;
        if !cfg.has_explicit_m { let _ = cfg.method.try_set("POST"); }
        guard parse_header_flag("Content-Type: application/json", cfg) else { return true, false; }
        guard parse_header_flag("Accept: application/json", cfg) else { return true, false; }
        return true, true;
    }
    if arg == "-r" || arg == "--route" {
        guard cfg.inline_routes.len < cfg.inline_routes.cap else {
            return true, set_cli_error(cfg, "too many --route definitions (max 32)");
        }
        var r_buf: u8[..512] = [];
        guard r_buf.try_set(val) else { return true, set_cli_error(cfg, "route rule exceeds 512 chars"); }
        cfg.inline_routes.push(r_buf);
        return true, true;
    }
    return false, false;
}

fn apply_cli_numeric_opt(arg: const u8[:], val: const u8[:], cfg: CliConfig&) -> bool, bool {
    let is_timeout = arg == "--timeout" || arg == "-m" || arg == "--max-time";
    let is_retry = arg == "--retry";
    let is_port = arg == "-p" || arg == "--port";
    let is_max = arg == "-n" || arg == "--max-reqs";
    guard is_timeout || is_retry || is_port || is_max else { return false, false; }

    let num, ok = core::parse_u64_dec(val);
    guard ok else { return true, set_cli_error(cfg, "invalid numeric option", val); }

    if is_timeout {
        guard num > 0 else { return true, set_cli_error(cfg, "invalid timeout value", val); }
        let ms_scaled = if arg == "--timeout" { num } else { core::mul_sat_u64(num, 1000) };
        cfg.timeout_ms = ms_scaled as i64;
        return true, true;
    }
    if is_retry {
        guard num <= 16 else { return true, set_cli_error(cfg, "invalid retry count (0..16)", val); }
        cfg.max_retries = num as i32;
        return true, true;
    }
    if is_port {
        guard num <= 65535 else { return true, set_cli_error(cfg, "invalid port (0..65535)", val); }
        cfg.port = num as u16;
        return true, true;
    }
    cfg.max_reqs = num;
    return true, true;
}

fn assign_positional_url(arg: const u8[:], cfg: CliConfig&) -> bool {
    guard cfg.url.len == 0 else {
        return set_cli_error(cfg, "unexpected positional argument", arg);
    }
    let has_scheme = core::starts_with(arg, "http://") || core::starts_with(arg, "https://") ||
        core::starts_with(arg, "ws://") || core::starts_with(arg, "wss://");
    if !has_scheme {
        cfg.url.append("http://");
    }
    let max_url = cfg.url.cap;
    guard core::add_sat_i64(cfg.url.len, arg.len) <= max_url else {
        return set_cli_error(cfg, "URL exceeds maximum length");
    }
    cfg.url.append(arg);
    return true;
}

// Consumes one CLI option (and its value if paired) or positional URL at `argv[idx]`, advancing `idx`.
//
// Example:
//   argv = ["wing", "-X", "POST", "https://example.com"], idx = 1
//   returns: true, idx = 3, cfg.method = "POST"
fn step_cli_arg(argv: u8[:][:], idx: i64&, cfg: CliConfig&) -> bool {
    let arg = argv[idx];
    if arg == "-h" || arg == "--help" {
        cfg.mode = CliMode.Help;
        idx = argv.len;
        return true;
    }
    if apply_cli_boolean_flag(arg, cfg) {
        idx = core::add_sat_i64(idx, 1);
        return true;
    }
    if arg.len > 0 && arg[0] == '-' {
        let next_idx = core::add_sat_i64(idx, 1);
        guard next_idx < argv.len else {
            return set_cli_error(cfg, "missing value for option", arg);
        }
        let val = argv[next_idx];
        let after_val = core::add_sat_i64(idx, 2);
        let matched_s, ok_s = apply_cli_string_opt(arg, val, cfg);
        if matched_s {
            idx = after_val;
            return ok_s;
        }
        let matched_p, ok_p = apply_cli_payload_opt(arg, val, cfg);
        if matched_p {
            idx = after_val;
            return ok_p;
        }
        let matched_n, ok_n = apply_cli_numeric_opt(arg, val, cfg);
        if matched_n {
            idx = after_val;
            return ok_n;
        }
        return set_cli_error(cfg, "unknown flag", arg);
    }
    guard assign_positional_url(arg, cfg) else { return false; }
    idx = core::add_sat_i64(idx, 1);
    return true;
}

// Parses command-line `argv` into `cfg`, selecting `Client`, `Serve`, `Help`, or `Version` mode.
//
// Example:
//   argv = ["wing", "-i", "https://api.github.com/zen"]
//   returns: true, cfg.mode = CliMode.Client, cfg.show_headers = true, cfg.url = "https://api.github.com/zen"
fn parse_cli_args(argv: u8[:][:], cfg: CliConfig&) -> bool {
    if argv.len <= 1 {
        cfg.mode = CliMode.Help;
        return true;
    }

    var idx: i64 = 1;
    let first = argv[1];
    if first == "help" || first == "-h" || first == "--help" {
        cfg.mode = CliMode.Help;
        return true;
    }
    if first == "version" || first == "--version" || first == "-V" {
        cfg.mode = CliMode.Version;
        return true;
    }
    if first == "serve" || first == "server" {
        cfg.mode = CliMode.Serve;
        idx = 2;
    } else {
        cfg.mode = CliMode.Client;
    }

    while idx < argv.len {
        guard step_cli_arg(argv, idx, cfg) else { return false; }
    }

    if cfg.mode == CliMode.Client && cfg.url.len == 0 {
        return set_cli_error(cfg, "missing target URL (try 'wing --help')");
    }
    if cfg.remote_name && cfg.output_file.len == 0 && cfg.url.len > 0 {
        let fname = extract_remote_filename(cfg.url[..]);
        let _ = cfg.output_file.try_set(fname);
    }
    return true;
}
