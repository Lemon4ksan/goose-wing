// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Scenario rule parser and built-in httpbin endpoint engine for `wing serve`.
import std;
import core from "..";
import wing from "..";

struct RouteRule {
    method:       u8[..16]   = "GET",
    path:         u8[..256]  = "/",
    fail_status:  i32        = 503,
    fail_count:   u32        = 0,
    status_code:  i32        = 200,
    content_type: u8[..64]   = "text/plain",
    location:     u8[..256]  = [],
    set_cookie:   u8[..256]  = [],
    body:         u8[..2048] = [],
    calls:        u64        = 0,
}

struct ProgrammableServerStage {
    rules:         RouteRule[..32] = [],
    flaky_counter: u64             = 0,
    served_reqs:   u64             = 0,
    max_reqs:      u64             = 0,
    quiet:         bool            = false,
    no_color:      bool            = false,
}

// Scans the next whitespace-delimited token from `s`, advancing `pos` past it.
//
// Example:
//   s = "  GET /ping -> 200", pos = 0
//   returns: "GET", pos = 5
fn next_ws_token(s: const u8[:], pos: i64&) -> const u8[:] {
    while pos < s.len && (s[pos] == ' ' || s[pos] == '\t') {
        pos = core::add_sat_i64(pos, 1);
    }
    let start = pos;
    while pos < s.len && s[pos] != ' ' && s[pos] != '\t' {
        pos = core::add_sat_i64(pos, 1);
    }
    return s[start..pos];
}

// Parses a status specification token such as "200" or "503x2,200" or "503x2".
//
// Example:
//   tok = "503x2,", rest = "GET /flaky -> 503x2, 200 \"OK\"", pos = 20
//   returns: true, out_rule.fail_status = 503, out_rule.fail_count = 2, out_rule.status_code = 200
fn parse_status_spec(
    tok:      const u8[:],
    rest:     const u8[:],
    pos:      i64&,
    out_rule: RouteRule&,
) -> bool {
    var active = tok;
    if core::ends_with(active, ",") {
        let trim_len = core::sub_sat_i64(active.len, 1);
        active = active[..trim_len];
    }

    let x_idx = core::index_of_byte(active, 'x');
    if x_idx > 0 {
        let next_x = core::add_sat_i64(x_idx, 1);
        let f_code, ok1 = core::parse_u64_dec(active[..x_idx]);
        let f_cnt, ok2 = core::parse_u64_dec(active[next_x..]);
        guard ok1 && ok2 && f_code >= 100 && f_code <= 599 else { return false; }
        out_rule.fail_status = f_code as i32;
        out_rule.fail_count = f_cnt as u32;

        let next_tok = next_ws_token(rest, pos);
        if next_tok.len > 0 {
            let final_code, ok3 = core::parse_u64_dec(next_tok);
            if ok3 && final_code >= 100 && final_code <= 599 {
                out_rule.status_code = final_code as i32;
                return true;
            }
        }
        out_rule.status_code = 200;
        return true;
    }

    let code, ok = core::parse_u64_dec(active);
    guard ok && code >= 100 && code <= 599 else { return false; }
    out_rule.status_code = code as i32;
    return true;
}

// Consumes optional route header modifiers (`Location=`, `Cookie=`, `Type=`), advancing `pos` to the body token.
//
// Example:
//   trimmed = "GET /old -> 302 Location=/new \"Moved\"", pos = 16
//   advances pos = 29, sets out_rule.location = "/new"
fn parse_route_modifiers(trimmed: const u8[:], pos: i64&, out_rule: RouteRule&) {
    while pos < trimmed.len {
        while pos < trimmed.len && (trimmed[pos] == ' ' || trimmed[pos] == '\t') {
            pos = core::add_sat_i64(pos, 1);
        }
        guard pos < trimmed.len else { break; }
        let rem = trimmed[pos..];
        if core::starts_with_fold(rem, "location=") {
            let tok = next_ws_token(trimmed, pos);
            let _ = out_rule.location.try_set(tok[9..]);
        } else if core::starts_with_fold(rem, "cookie=") {
            let tok = next_ws_token(trimmed, pos);
            let _ = out_rule.set_cookie.try_set(tok[7..]);
        } else if core::starts_with_fold(rem, "type=") {
            let tok = next_ws_token(trimmed, pos);
            let _ = out_rule.content_type.try_set(tok[5..]);
        } else {
            break;
        }
    }
}

// Parses the trailing route response body token, stripping outer quotes or inferring JSON content-type.
//
// Example:
//   body_raw = "{\"ok\":true}"
//   sets out_rule.body = "{\"ok\":true}", out_rule.content_type = "application/json"
fn parse_route_body_spec(body_raw: const u8[:], out_rule: RouteRule&) {
    if body_raw.len >= 2 {
        let is_dquote = core::starts_with(body_raw, "\"") && core::ends_with(body_raw, "\"");
        let is_squote = core::starts_with(body_raw, "'") && core::ends_with(body_raw, "'");
        if is_dquote || is_squote {
            let end_idx = core::sub_sat_i64(body_raw.len, 1);
            let _ = out_rule.body.try_set(body_raw[1..end_idx]);
            return;
        }
    }
    if body_raw.len > 0 {
        let _ = out_rule.body.try_set(body_raw);
        if body_raw[0] == '{' || body_raw[0] == '[' {
            let _ = out_rule.content_type.try_set("application/json");
        }
    }
}

// Parses a single scenario rule line into `out_rule`.
//
// Example:
//   line = "GET /ping -> 200 \"PONG\""
//   returns: true, out_rule = { method: "GET", path: "/ping", status_code: 200, body: "PONG" }
fn parse_route_rule_line(line: const u8[:], out_rule: RouteRule&) -> bool {
    let trimmed = core::trim_lws(line);
    guard trimmed.len > 0 && trimmed[0] != '#' else { return false; }

    var pos: i64 = 0;
    let method_tok = next_ws_token(trimmed, pos);
    let path_tok = next_ws_token(trimmed, pos);
    guard method_tok.len > 0 && path_tok.len > 0 && path_tok[0] == '/' else { return false; }

    out_rule = RouteRule { .. };
    guard out_rule.method.try_set(method_tok) && out_rule.path.try_set(path_tok) else {
        return false;
    }

    let arrow_or_status = next_ws_token(trimmed, pos);
    let status_tok = if arrow_or_status == "->" || arrow_or_status == "=>" {
        next_ws_token(trimmed, pos)
    } else {
        arrow_or_status
    };
    guard status_tok.len > 0 else { return false; }
    guard parse_status_spec(status_tok, trimmed, pos, out_rule) else { return false; }

    parse_route_modifiers(trimmed, pos, out_rule);
    parse_route_body_spec(core::trim_lws(trimmed[pos..]), out_rule);
    return true;
}

fn load_scenario_text(text: const u8[:], stage: ProgrammableServerStage&) -> i64 {
    var added:  i64 = 0;
    var cursor: i64 = 0;
    while cursor < text.len {
        let nl = core::index_of_byte(text[cursor..], '\n');
        let line_end = if nl >= 0 { core::add_sat_i64(cursor, nl) } else { text.len };
        var line = text[cursor..line_end];
        if core::ends_with(line, "\r") {
            let trim_len = core::sub_sat_i64(line.len, 1);
            line = line[..trim_len];
        }
        let trimmed = core::trim_lws(line);
        if trimmed.len > 0 && trimmed[0] != '#' {
            guard stage.rules.len < stage.rules.cap else { break; }
            var r = RouteRule { .. };
            if parse_route_rule_line(trimmed, r) {
                stage.rules.push(r);
                added = core::add_sat_i64(added, 1);
            }
        }
        cursor = core::add_sat_i64(line_end, 1);
    }
    return added;
}

fn strip_query_path(url: const u8[:]) -> const u8[:] {
    let q = core::index_of_byte(url, '?');
    return if q >= 0 { url[..q] } else { url };
}

// Extracts the query component following '?' in `url`, or empty slice if absent.
//
// Example:
//   url = "/cookies/set?session=xyz&theme=dark"
//   returns: "session=xyz&theme=dark"
fn extract_query_string(url: const u8[:]) -> const u8[:] {
    let q = core::index_of_byte(url, '?');
    let next_q = core::add_sat_i64(q, 1);
    return if q >= 0 && next_q < url.len { url[next_q..] } else { "" };
}

fn append_json_escaped_bytes(src: const u8[:], out: u8[>..]&) {
    for b in src {
        if b == '"' {
            out.append("\\\"");
        } else if b == '\\' {
            out.append("\\\\");
        } else if b == '\n' {
            out.append("\\n");
        } else if b == '\r' {
            out.append("\\r");
        } else if b == '\t' {
            out.append("\\t");
        } else if b >= 0x20 && b <= 0x7E {
            out.push(b);
        }
    }
}

// Formats a request reflection payload in httpbin JSON format.
fn build_httpbin_reflection_json(req: const wing::Request&, peer_ip: const u8[:], out: u8[>..]&) {
    out.clear();
    out.append("{\n  \"method\": \"");
    out.append(req.method[..]);
    out.append("\",\n  \"url\": \"");
    out.append(req.url[..]);
    out.append("\",\n  \"origin\": \"");
    out.append(if peer_ip.len > 0 { peer_ip } else { "127.0.0.1" });
    out.append("\",\n  \"headers\": {\n");

    let n_hdrs = req.headers.entries.len;
    let last_idx = core::sub_sat_i64(n_hdrs, 1);
    for i in n_hdrs {
        let e = req.headers.entries[i];
        let h_name = wing::entry_name(req.headers, e);
        let h_val = wing::entry_value(req.headers, e);
        out.append("    \"");
        append_json_escaped_bytes(h_name, out);
        out.append("\": \"");
        append_json_escaped_bytes(h_val, out);
        out.push('"');
        if i < last_idx {
            out.push(',');
        }
        out.push('\n');
    }
    out.append("  },\n  \"data\": \"");
    append_json_escaped_bytes(req.body[..], out);
    out.append("\"\n}\n");
}

fn build_httpbin_headers_json(req: const wing::Request&, out: u8[>..]&) {
    out.clear();
    out.append("{\n  \"headers\": {\n");
    let n_hdrs = req.headers.entries.len;
    let last_idx = core::sub_sat_i64(n_hdrs, 1);
    for i in n_hdrs {
        let e = req.headers.entries[i];
        out.append("    \"");
        out.append(wing::entry_name(req.headers, e));
        out.append("\": \"");
        out.append(wing::entry_value(req.headers, e));
        out.push('"');
        if i < last_idx { out.push(','); }
        out.push('\n');
    }
    out.append("  }\n}\n");
}

fn handle_httpbin_status_or_redirect(path: const u8[:], res: wing::Response&) -> bool {
    if core::starts_with(path, "/status/") && path.len > 8 {
        let code_u64, ok = core::parse_u64_dec(path[8..]);
        guard ok && code_u64 >= 100 && code_u64 <= 599 else { return false; }
        res.status_code = code_u64 as i32;
        wing::set_header(res, "Content-Type", "text/plain");
        res.body.clear();
        if !rfc::is_empty_body_status(res.status_code) {
            res.body.append(rfc::status_phrase(res.status_code));
            res.body.push('\n');
        }
        return true;
    }

    if core::starts_with(path, "/redirect/") && path.len > 10 {
        let n_hops, ok = core::parse_u64_dec(path[10..]);
        guard ok else { return false; }
        res.status_code = 302;
        var loc: u8[..64] = [];
        if n_hops <= 1 {
            loc.append("/get");
        } else {
            loc.append("/redirect/");
            core::format_u64_dec(core::sub_sat_u64(n_hops, 1), loc);
        }
        wing::set_header(res, "Location", loc[..]);
        res.body.clear();
        res.body.append("Redirecting to ");
        res.body.append(loc[..]);
        res.body.push('\n');
        return true;
    }
    return false;
}

fn generate_synthetic_alphabet_bytes(total_len: i64, out: u8[>..]&) {
    let alphabet = "abcdefghijklmnopqrstuvwxyz";
    out.clear();
    var rem = total_len;
    while rem > 0 {
        let take = min(rem, alphabet.len);
        out.append(alphabet[..take]);
        rem = core::sub_sat_i64(rem, take);
    }
}

fn try_serve_range_slice(
    range_hdr: const u8[:],
    full_buf:  const u8[:],
    res:       wing::Response&,
) -> bool {
    let total_len = full_buf.len;
    guard range_hdr.len > 0 && total_len > 0 else { return false; }
    let rs, r_err = wing::parse_range_header(range_hdr, total_len);
    guard wing::is_ok(r_err) && rs.is_satisfiable && rs.ranges.len > 0 else { return false; }
    let r0 = rs.ranges[0];
    res.status_code = 206;
    var cr_hdr: u8[..64] = [];
    wing::format_content_range(r0.start, r0.end_pos, total_len, cr_hdr);
    wing::set_header(res, "Content-Range", cr_hdr[..]);
    wing::set_header(res, "Accept-Ranges", "bytes");
    wing::set_header(res, "Content-Type", "application/octet-stream");
    res.body.clear();
    let slice_end = min(total_len, core::add_sat_i64(r0.end_pos, 1));
    if r0.start >= 0 && r0.start < slice_end {
        res.body.append(full_buf[r0.start..slice_end]);
    }
    return true;
}

fn handle_httpbin_range_or_bytes(
    path: const u8[:],
    req:  const wing::Request&,
    res:  wing::Response&,
) -> bool {
    let is_bytes = core::starts_with(path, "/bytes/") && path.len > 7;
    let is_range = core::starts_with(path, "/range/") && path.len > 7;
    guard is_bytes || is_range else { return false; }

    let n_raw, ok = core::parse_u64_dec(path[7..]);
    guard ok && n_raw <= 65536 else { return false; }
    let total_len = n_raw as i64;

    var full_buf: u8[>..] = [];
    generate_synthetic_alphabet_bytes(total_len, full_buf);

    if try_serve_range_slice(req.header("Range"), full_buf[..], res) {
        return true;
    }

    res.status_code = 200;
    wing::set_header(res, "Accept-Ranges", "bytes");
    wing::set_header(res, "Content-Type", "application/octet-stream");
    res.body.clear();
    res.body.append(full_buf[..]);
    return true;
}

fn handle_httpbin_auth_routes(
    path: const u8[:],
    req:  const wing::Request&,
    res:  wing::Response&,
) -> bool {
    if path == "/bearer" {
        let auth = req.header("Authorization");
        if core::starts_with_fold(auth, "Bearer ") && auth.len > 7 {
            res.status_code = 200;
            wing::set_header(res, "Content-Type", "application/json");
            res.body.clear();
            res.body.append("{\"authenticated\": true, \"token\": \"");
            append_json_escaped_bytes(auth[7..], res.body);
            res.body.append("\"}\n");
            return true;
        }
        res.status_code = 401;
        wing::set_header(res, "WWW-Authenticate", "Bearer");
        res.body.clear();
        return true;
    }

    if core::starts_with(path, "/basic-auth/") && path.len > 12 {
        let creds_part = path[12..];
        let sl = core::index_of_byte(creds_part, '/');
        guard sl > 0 && core::add_sat_i64(sl, 1) < creds_part.len else { return false; }
        let exp_user = creds_part[..sl];
        let exp_pass = creds_part[core::add_sat_i64(sl, 1)..];

        var raw_up: u8[..160] = [];
        let _ = raw_up.try_append(exp_user);
        let _ = raw_up.try_push(':');
        let _ = raw_up.try_append(exp_pass);
        var exp_b64: u8[..256] = "Basic ";
        core::base64_encode(raw_up[..], exp_b64);

        let auth = req.header("Authorization");
        if auth == exp_b64[..] {
            res.status_code = 200;
            wing::set_header(res, "Content-Type", "application/json");
            res.body.clear();
            res.body.append("{\"authenticated\": true, \"user\": \"");
            append_json_escaped_bytes(exp_user, res.body);
            res.body.append("\"}\n");
            return true;
        }
        res.status_code = 401;
        wing::set_header(res, "WWW-Authenticate", "Basic realm=\"Fake Realm\"");
        res.body.clear();
        return true;
    }
    return false;
}

fn handle_httpbin_dynamic_routes(
    stage: ProgrammableServerStage&,
    path:  const u8[:],
    query: const u8[:],
    req:   const wing::Request&,
    res:   wing::Response&,
) -> bool {
    if handle_httpbin_status_or_redirect(path, res) {
        return true;
    }
    if handle_httpbin_range_or_bytes(path, req, res) {
        return true;
    }
    if handle_httpbin_auth_routes(path, req, res) {
        return true;
    }

    if path == "/cookies/set" && query.len > 0 {
        res.status_code = 302;
        var ck_hdr: u8[..256] = [];
        let _ = ck_hdr.try_set(query);
        let max_ck = ck_hdr.cap;
        if core::add_sat_i64(ck_hdr.len, 8) <= max_ck {
            ck_hdr.append("; Path=/");
        }
        wing::set_header(res, "Set-Cookie", ck_hdr[..]);
        wing::set_header(res, "Location", "/cookies");
        return true;
    }

    if core::starts_with(path, "/flaky/") && path.len > 7 {
        let fails, ok = core::parse_u64_dec(path[7..]);
        guard ok && fails > 0 && fails <= 1000 else { return false; }
        stage.flaky_counter = core::add_sat_u64(stage.flaky_counter, 1);
        let attempt = stage.flaky_counter;
        if attempt <= fails {
            res.status_code = 503;
            wing::set_header(res, "Content-Type", "text/plain");
            res.body.clear();
            res.body.append("FLAKY_TEMP_503 (attempt ");
            core::format_u64_dec(attempt, res.body);
            res.body.push('/');
            core::format_u64_dec(fails, res.body);
            res.body.append(")\n");
            return true;
        }
        stage.flaky_counter = 0;
        res.status_code = 200;
        wing::set_header(res, "Content-Type", "text/plain");
        res.body.clear();
        res.body.append("FLAKY_RECOVERED_200\n");
        return true;
    }

    return false;
}

fn handle_builtin_httpbin(
    stage:   ProgrammableServerStage&,
    req:     const wing::Request&,
    peer_ip: const u8[:],
    res:     wing::Response&,
) -> bool {
    let path = strip_query_path(req.url[..]);
    let query = extract_query_string(req.url[..]);

    if path == "/get" || path == "/post" || path == "/put" || path == "/delete" ||
       path == "/anything" || path == "/echo" {
        res.status_code = 200;
        wing::set_header(res, "Content-Type", "application/json");
        build_httpbin_reflection_json(req, peer_ip, res.body);
        return true;
    }

    if path == "/headers" {
        res.status_code = 200;
        wing::set_header(res, "Content-Type", "application/json");
        build_httpbin_headers_json(req, res.body);
        return true;
    }

    if path == "/ip" {
        res.status_code = 200;
        wing::set_header(res, "Content-Type", "application/json");
        res.body.clear();
        res.body.append("{\"origin\": \"");
        res.body.append(if peer_ip.len > 0 { peer_ip } else { "127.0.0.1" });
        res.body.append("\"}\n");
        return true;
    }

    if path == "/user-agent" {
        res.status_code = 200;
        wing::set_header(res, "Content-Type", "application/json");
        res.body.clear();
        res.body.append("{\"user-agent\": \"");
        res.body.append(req.header("User-Agent"));
        res.body.append("\"}\n");
        return true;
    }

    if path == "/cookies" {
        res.status_code = 200;
        wing::set_header(res, "Content-Type", "application/json");
        res.body.clear();
        res.body.append("{\"cookies\": \"");
        res.body.append(req.header("Cookie"));
        res.body.append("\"}\n");
        return true;
    }

    if path == "/sse" {
        res.status_code = 200;
        wing::set_header(res, "Content-Type", "text/event-stream");
        wing::set_header(res, "Cache-Control", "no-cache");
        wing::set_header(res, "Connection", "close");
        res.body.clear();
        res.body.append("id: 1\nevent: ping\ndata: {\"msg\":\"hello from wing sse\"}\n\n");
        res.body.append("id: 2\nevent: done\ndata: {\"msg\":\"stream complete\"}\n\n");
        return true;
    }

    return handle_httpbin_dynamic_routes(stage, path, query, req, res);
}
