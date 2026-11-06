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

struct FormFieldSpec {
    name:         u8[..128]  = [],
    value:        u8[..1024] = [],
    filename:     u8[..256]  = [],
    content_type: u8[..128]  = [],
    is_file:      bool       = false,
}

struct CliConfig {
    mode:             CliMode             = CliMode.Help,
    method:           u8[..16]            = "GET",
    has_explicit_m:   bool                = false,
    get_query_mode:   bool                = false,
    head_only:        bool                = false,
    fail_on_error:    bool                = false,
    silent:           bool                = false,
    url:              u8[..2048]          = [],
    has_body:         bool                = false,
    upload_file:      u8[..512]           = [],
    output_file:      u8[..512]           = [],
    dump_header_file: u8[..512]           = [],
    remote_name:      bool                = false,
    user_agent:       u8[..256]           = [],
    referer:          u8[..512]           = [],
    range_spec:       u8[..128]           = [],
    resume_from:      i64                 = 0,
    auto_resume:      bool                = false,
    cookie_header:    u8[..1024]          = [],
    cookie_jar_in:    u8[..512]           = [],
    cookie_jar_out:   u8[..512]           = [],
    write_out:        u8[..256]           = [],
    headers:          HeaderPair[..16]    = [],
    resolves:         ResolveEntry[..8]   = [],
    form_fields:      FormFieldSpec[..16] = [],
    bearer_token:     u8[..512]           = [],
    basic_user:       u8[..64]            = [],
    basic_pass:       u8[..64]            = [],
    proxy_url:        u8[..256]           = [],
    no_proxy:         u8[..512]           = [],
    timeout_ms:       i64                 = 10000,
    max_redirects:    i64                 = 10,
    max_retries:      i32                 = 0,
    follow_redirects: bool                = true,
    insecure_tls:     bool                = false,
    http2_prior:      bool                = false,
    http1_1_only:     bool                = false,
    compressed:       bool                = true,
    show_headers:     bool                = false,
    verbose:          bool                = false,
    no_color:         bool                = false,
    raw_profile:      bool                = false,
    bind_host:        u8[..64]            = "127.0.0.1",
    port:             u16                 = 8080,
    max_reqs:         u64                 = 0,
    scenario_file:    u8[..512]           = [],
    inline_routes:    u8[..512][..32]     = [],
    err_msg:          u8[..256]           = [],
    body:             u8[>..]             = [],
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

fn load_headers_from_text(content: const u8[:], cfg: CliConfig&) -> bool {
    var cursor: i64 = 0;
    while cursor < content.len {
        let nl = core::index_of_byte(content[cursor..], '\n');
        let line_end = if nl >= 0 { core::add_sat_i64(cursor, nl) } else { content.len };
        var line = content[cursor..line_end];
        if core::ends_with(line, "\r") {
            line = line[..core::sub_sat_i64(line.len, 1)];
        }
        let trimmed = core::trim_lws(line);
        if trimmed.len > 0 && trimmed[0] != '#' {
            guard parse_header_flag(trimmed, cfg) else { return false; }
        }
        cursor = core::add_sat_i64(line_end, 1);
    }
    return true;
}

// Loads `-H @filename` header lines or a single inline `Name: Value` header.
fn apply_header_or_file_flag(raw: const u8[:], cfg: CliConfig&) -> bool {
    if raw.len > 1 && raw[0] == '@' {
        let path = raw[1..];
        var content: u8[>..] = [];
        guard read_file(path, content) else {
            return set_cli_error(cfg, "cannot read header file", path);
        }
        return load_headers_from_text(content[..], cfg);
    }
    return parse_header_flag(raw, cfg);
}

// Parses a `-u / --user "user:password"` Basic/Digest Auth argument into `cfg`.
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

fn apply_form_modifiers(modifiers: const u8[:], field: FormFieldSpec&) {
    var rem_mod = modifiers;
    while rem_mod.len > 0 {
        let s_idx = core::index_of_byte(rem_mod, ';');
        let item = if s_idx >= 0 { rem_mod[..s_idx] } else { rem_mod };
        rem_mod = if s_idx >= 0 { rem_mod[core::add_sat_i64(s_idx, 1)..] } else { rem_mod[rem_mod.len..] };
        let trimmed = core::trim_lws(item);
        if core::starts_with_fold(trimmed, "type=") {
            let _ = field.content_type.try_set(trimmed[5..]);
        } else if core::starts_with_fold(trimmed, "filename=") {
            let _ = field.filename.try_set(trimmed[9..]);
        }
    }
}

// Parses a curl-style `-F / --form` specification (`name=value` or `name=@file;type=...;filename=...`).
//
// Example:
//   raw = "avatar=@photo.png;type=image/png;filename=avatar.png"
//   returns: true, pushes FormFieldSpec { name: "avatar", value: "photo.png", is_file: true, ... }
fn parse_form_flag(raw: const u8[:], cfg: CliConfig&) -> bool {
    guard cfg.form_fields.len < cfg.form_fields.cap else {
        return set_cli_error(cfg, "too many -F form fields (max 16)");
    }
    let eq = core::index_of_byte(raw, '=');
    let next_eq = core::add_sat_i64(eq, 1);
    guard eq > 0 && next_eq <= raw.len else {
        return set_cli_error(cfg, "invalid -F form field, expected 'name=value'", raw);
    }

    var field = FormFieldSpec { .. };
    guard field.name.try_set(raw[..eq]) else {
        return set_cli_error(cfg, "-F field name too long");
    }

    var rhs = raw[next_eq..];
    let semi = core::index_of_byte(rhs, ';');
    let modifiers = if semi >= 0 { rhs[core::add_sat_i64(semi, 1)..] } else { rhs[rhs.len..] };
    if semi >= 0 {
        rhs = rhs[..semi];
    }

    if rhs.len > 1 && rhs[0] == '@' {
        field.is_file = true;
        let fpath = rhs[1..];
        guard field.value.try_set(fpath) else {
            return set_cli_error(cfg, "-F file path too long");
        }
        let base_fn = extract_remote_filename(fpath);
        let _ = field.filename.try_set(base_fn);
    } else {
        guard field.value.try_set(rhs) else {
            return set_cli_error(cfg, "-F value too long");
        }
    }

    apply_form_modifiers(modifiers, field);
    cfg.form_fields.push(field);
    if !cfg.has_explicit_m {
        let _ = cfg.method.try_set("POST");
    }
    return true;
}

fn read_source_bytes(raw: const u8[:], allow_at_file: bool, out: u8[>..]&, cfg: CliConfig&) -> bool {
    out.clear();
    if allow_at_file && raw.len > 1 && raw[0] == '@' {
        let path = raw[1..];
        if path == "-" {
            read_stdin(out);
            return true;
        }
        guard read_file(path, out) else {
            return set_cli_error(cfg, "cannot read payload file", path);
        }
        return true;
    }
    out.append(raw);
    return true;
}

fn load_data_arg(raw: const u8[:], allow_at_file: bool, cfg: CliConfig&) -> bool {
    var chunk: u8[>..] = [];
    guard read_source_bytes(raw, allow_at_file, chunk, cfg) else { return false; }
    if cfg.has_body && cfg.body.len > 0 {
        cfg.body.push('&');
    }
    cfg.body.append(chunk[..]);
    cfg.has_body = true;
    return true;
}

fn append_percent_encoded_bytes<B>(src: const u8[:], out: B&) {
    for b in src {
        if core::is_uri_unreserved(b) {
            out.push(b);
        } else {
            out.push('%');
            core::format_u8_hex(b, out, true);
        }
    }
}

// Encodes a `--data-urlencode` item (`name=val`, `=val`, `name@file`, `@file`) into `cfg.body`.
fn apply_data_urlencode_arg(raw: const u8[:], cfg: CliConfig&) -> bool {
    var prefix_name = raw[..0];
    var source_part = raw;
    var is_file_ref = false;

    let eq_idx = core::index_of_byte(raw, '=');
    let at_idx = core::index_of_byte(raw, '@');

    if eq_idx >= 0 && (at_idx < 0 || eq_idx < at_idx) {
        prefix_name = raw[..eq_idx];
        source_part = raw[core::add_sat_i64(eq_idx, 1)..];
    } else if at_idx >= 0 {
        prefix_name = raw[..at_idx];
        source_part = raw[at_idx..];
        is_file_ref = true;
    }

    var raw_bytes: u8[>..] = [];
    guard read_source_bytes(source_part, is_file_ref, raw_bytes, cfg) else { return false; }

    if cfg.has_body && cfg.body.len > 0 {
        cfg.body.push('&');
    }
    if prefix_name.len > 0 {
        cfg.body.append(prefix_name);
        cfg.body.push('=');
    }
    append_percent_encoded_bytes(raw_bytes[..], cfg.body);
    cfg.has_body = true;
    if !cfg.has_explicit_m && !cfg.get_query_mode {
        let _ = cfg.method.try_set("POST");
    }
    return true;
}

// Extracts the trailing filename segment from a URL or file path for `-O / --remote-name`.
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
        if clean[i] == '/' || clean[i] == '\\' { last_slash = i; }
    }
    let next_slash = core::add_sat_i64(last_slash, 1);
    if last_slash >= 0 && next_slash < clean.len {
        return clean[next_slash..];
    }
    return if clean.len > 0 { clean } else { "index.html" };
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
    if arg == "-s" || arg == "--silent" || arg == "-sS" || arg == "-S" || arg == "--show-error" {
        cfg.silent = (arg != "-S" && arg != "--show-error");
        return true;
    }
    if (arg == "-f" && cfg.mode == CliMode.Client) || arg == "--fail" || arg == "--fail-with-body" {
        cfg.fail_on_error = true;
        return true;
    }
    return false;
}

fn apply_cli_protocol_bool_flag(arg: const u8[:], cfg: CliConfig&) -> bool {
    if arg == "-k" || arg == "--insecure" {
        cfg.insecure_tls = true;
        return true;
    }
    if arg == "--h2c" || arg == "--http2-prior-knowledge" || arg == "--http2" {
        cfg.http2_prior = (arg != "--http2");
        return true;
    }
    if arg == "--http1.1" || arg == "-0" || arg == "--http1.0" {
        cfg.http1_1_only = true;
        return true;
    }
    if arg == "--compressed" || arg == "--no-compressed" {
        cfg.compressed = (arg == "--compressed");
        return true;
    }
    if arg == "-L" || arg == "--location" || arg == "--no-follow" || arg == "--no-location" {
        cfg.follow_redirects = (arg == "-L" || arg == "--location");
        return true;
    }
    return false;
}

fn apply_cli_behavior_bool_flag(arg: const u8[:], cfg: CliConfig&) -> bool {
    if arg == "-G" || arg == "--get" {
        cfg.get_query_mode = true;
        if !cfg.has_explicit_m { let _ = cfg.method.try_set("GET"); }
        return true;
    }
    if arg == "-O" || arg == "--remote-name" {
        cfg.remote_name = true;
        return true;
    }
    if arg == "--no-color" {
        cfg.no_color = true;
        return true;
    }
    if arg == "--raw-profile" {
        cfg.raw_profile = true;
        return true;
    }
    return false;
}

fn apply_cli_boolean_flag(arg: const u8[:], cfg: CliConfig&) -> bool {
    if apply_cli_output_bool_flag(arg, cfg) { return true; }
    if apply_cli_protocol_bool_flag(arg, cfg) { return true; }
    return apply_cli_behavior_bool_flag(arg, cfg);
}

fn apply_cookie_arg(val: const u8[:], cfg: CliConfig&) -> bool {
    if core::index_of_byte(val, '=') >= 0 {
        if cfg.cookie_header.len > 0 {
            guard cfg.cookie_header.try_append("; ") else {
                return set_cli_error(cfg, "cookie header string too long");
            }
        }
        guard cfg.cookie_header.try_append(val) else {
            return set_cli_error(cfg, "cookie header string too long");
        }
        return true;
    }
    return cfg.cookie_jar_in.try_set(val) || set_cli_error(cfg, "cookie jar path too long");
}

fn apply_cli_io_string_opt(arg: const u8[:], val: const u8[:], cfg: CliConfig&) -> bool, bool {
    if arg == "-o" || arg == "--output" {
        return true, cfg.output_file.try_set(val) || set_cli_error(cfg, "output path too long");
    }
    if arg == "-D" || arg == "--dump-header" {
        return true, cfg.dump_header_file.try_set(val) || set_cli_error(cfg, "dump-header path too long");
    }
    if arg == "-b" || arg == "--cookie" {
        return true, apply_cookie_arg(val, cfg);
    }
    if arg == "-c" || arg == "--cookie-jar" {
        return true, cfg.cookie_jar_out.try_set(val) || set_cli_error(cfg, "cookie-jar path too long");
    }
    if arg == "-w" || arg == "--write-out" {
        return true, cfg.write_out.try_set(val) || set_cli_error(cfg, "write-out format too long");
    }
    return false, false;
}

fn apply_cli_req_meta_string_opt(arg: const u8[:], val: const u8[:], cfg: CliConfig&) -> bool, bool {
    if arg == "-A" || arg == "--user-agent" {
        return true, cfg.user_agent.try_set(val) || set_cli_error(cfg, "User-Agent too long");
    }
    if arg == "-e" || arg == "--referer" {
        return true, cfg.referer.try_set(val) || set_cli_error(cfg, "Referer too long");
    }
    if (arg == "-r" && cfg.mode == CliMode.Client) || arg == "--range" {
        return true, cfg.range_spec.try_set(val) || set_cli_error(cfg, "Range spec too long");
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
        return true, apply_header_or_file_flag(val, cfg);
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
    if arg == "--noproxy" {
        return true, cfg.no_proxy.try_set(val) || set_cli_error(cfg, "noproxy list too long");
    }
    if arg == "--host" {
        return true, cfg.bind_host.try_set(val) || set_cli_error(cfg, "host too long");
    }
    if (arg == "-f" && cfg.mode == CliMode.Serve) || arg == "--file" {
        return true, cfg.scenario_file.try_set(val) || set_cli_error(cfg, "file path too long");
    }
    return false, false;
}

fn apply_cli_string_opt(arg: const u8[:], val: const u8[:], cfg: CliConfig&) -> bool, bool {
    let m1, ok1 = apply_cli_io_string_opt(arg, val, cfg);
    if m1 { return true, ok1; }
    let m2, ok2 = apply_cli_req_meta_string_opt(arg, val, cfg);
    if m2 { return true, ok2; }
    return apply_cli_auth_or_serve_string_opt(arg, val, cfg);
}

fn apply_cli_data_opt(arg: const u8[:], val: const u8[:], cfg: CliConfig&) -> bool, bool {
    let is_data = arg == "-d" || arg == "--data" || arg == "--data-ascii" || arg == "--data-binary";
    if is_data || arg == "--data-raw" {
        guard load_data_arg(val, is_data, cfg) else { return true, false; }
        if !cfg.has_explicit_m && !cfg.get_query_mode { let _ = cfg.method.try_set("POST"); }
        return true, true;
    }
    if arg == "--data-urlencode" {
        return true, apply_data_urlencode_arg(val, cfg);
    }
    if arg == "--json" {
        guard load_data_arg(val, true, cfg) else { return true, false; }
        if !cfg.has_explicit_m { let _ = cfg.method.try_set("POST"); }
        return true, parse_header_flag("Content-Type: application/json", cfg) &&
            parse_header_flag("Accept: application/json", cfg);
    }
    return false, false;
}

fn apply_cli_upload_or_route_opt(arg: const u8[:], val: const u8[:], cfg: CliConfig&) -> bool, bool {
    if arg == "-F" || arg == "--form" || arg == "--form-string" {
        return true, parse_form_flag(val, cfg);
    }
    if arg == "-T" || arg == "--upload-file" {
        guard cfg.upload_file.try_set(val) else {
            return true, set_cli_error(cfg, "upload-file path too long");
        }
        guard load_data_arg(str("@", val), true, cfg) else { return true, false; }
        if !cfg.has_explicit_m { let _ = cfg.method.try_set("PUT"); }
        return true, true;
    }
    if (arg == "-r" && cfg.mode == CliMode.Serve) || arg == "--route" {
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

fn apply_cli_payload_opt(arg: const u8[:], val: const u8[:], cfg: CliConfig&) -> bool, bool {
    let m1, ok1 = apply_cli_data_opt(arg, val, cfg);
    if m1 { return true, ok1; }
    return apply_cli_upload_or_route_opt(arg, val, cfg);
}

fn apply_continue_at_opt(val: const u8[:], cfg: CliConfig&) -> bool {
    if val == "-" {
        cfg.auto_resume = true;
        return true;
    }
    let off, ok_o = core::parse_u64_dec(val);
    guard ok_o else { return set_cli_error(cfg, "invalid -C offset", val); }
    cfg.resume_from = (off & 0x7FFFFFFFFFFFFFFF) as i64;
    return true;
}

fn apply_parsed_numeric_val(arg: const u8[:], val: const u8[:], num: u64, cfg: CliConfig&) -> bool {
    if arg == "--timeout" || arg == "-m" || arg == "--max-time" || arg == "--connect-timeout" {
        guard num > 0 else { return set_cli_error(cfg, "invalid timeout value", val); }
        let ms_scaled = if arg == "--timeout" { num } else { core::mul_sat_u64(num, 1000) };
        cfg.timeout_ms = ms_scaled as i64;
        return true;
    }
    if arg == "--retry" {
        guard num <= 16 else { return set_cli_error(cfg, "invalid retry count (0..16)", val); }
        cfg.max_retries = num as i32;
        return true;
    }
    if arg == "--max-redirs" {
        guard num <= 64 else { return set_cli_error(cfg, "invalid --max-redirs (0..64)", val); }
        cfg.max_redirects = num as i64;
        return true;
    }
    if arg == "-p" || arg == "--port" {
        guard num <= 65535 else { return set_cli_error(cfg, "invalid port (0..65535)", val); }
        cfg.port = num as u16;
        return true;
    }
    cfg.max_reqs = num;
    return true;
}

fn is_numeric_cli_flag(arg: const u8[:]) -> bool {
    if arg == "--timeout" || arg == "-m" || arg == "--max-time" || arg == "--connect-timeout" {
        return true;
    }
    if arg == "--retry" || arg == "--max-redirs" {
        return true;
    }
    return arg == "-p" || arg == "--port" || arg == "-n" || arg == "--max-reqs";
}

fn apply_cli_numeric_opt(arg: const u8[:], val: const u8[:], cfg: CliConfig&) -> bool, bool {
    if arg == "-C" || arg == "--continue-at" {
        return true, apply_continue_at_opt(val, cfg);
    }
    guard is_numeric_cli_flag(arg) else { return false, false; }
    let num, ok = core::parse_u64_dec(val);
    guard ok else { return true, set_cli_error(cfg, "invalid numeric option", val); }
    return true, apply_parsed_numeric_val(arg, val, num, cfg);
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
fn step_cli_arg<S>(argv: const S[:], idx: i64&, cfg: CliConfig&) -> bool {
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

fn finalize_get_query_mode(cfg: CliConfig&) -> bool {
    guard cfg.get_query_mode && cfg.has_body && cfg.body.len > 0 else { return true; }
    let sep: u8 = if core::index_of_byte(cfg.url[..], '?') >= 0 { '&' } else { '?' };
    let needed = core::add_sat_i64(core::add_sat_i64(cfg.url.len, 1), cfg.body.len);
    guard needed <= cfg.url.cap else {
        return set_cli_error(cfg, "URL + query string exceeds maximum length");
    }
    cfg.url.push(sep);
    cfg.url.append(cfg.body[..]);
    cfg.body.clear();
    cfg.has_body = false;
    if !cfg.has_explicit_m {
        let _ = cfg.method.try_set("GET");
    }
    return true;
}

fn finalize_cli_config(cfg: CliConfig&) -> bool {
    if cfg.mode == CliMode.Client && cfg.url.len == 0 {
        return set_cli_error(cfg, "missing target URL (try 'wing --help')");
    }
    guard finalize_get_query_mode(cfg) else { return false; }

    if cfg.remote_name && cfg.output_file.len == 0 && cfg.url.len > 0 {
        let fname = extract_remote_filename(cfg.url[..]);
        let _ = cfg.output_file.try_set(fname);
    }
    return true;
}

// Parses command-line `argv` into `cfg`, selecting `Client`, `Serve`, `Help`, or `Version` mode.
//
// Example:
//   argv = ["wing", "-i", "https://api.github.com/zen"]
//   returns: true, cfg.mode = CliMode.Client, cfg.show_headers = true, cfg.url = "https://api.github.com/zen"
fn parse_cli_args<S>(argv: const S[:], cfg: CliConfig&) -> bool {
    if argv.len <= 1 {
        cfg.mode = CliMode.Help;
        return true;
    }

    var env_nc: u8[>..] = [];
    if env("NO_COLOR", env_nc) && env_nc.len > 0 {
        cfg.no_color = true;
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
    return finalize_cli_config(cfg);
}
