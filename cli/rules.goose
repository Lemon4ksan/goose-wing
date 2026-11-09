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
    let active = tok.trim_end_byte(',');
    let f_code_str, f_cnt_str, has_x = active.split_once_byte('x');
    if has_x && f_code_str.len > 0 {
        let f_code, ok1 = f_code_str.parse_u64_dec();
        let f_cnt, ok2 = f_cnt_str.parse_u64_dec();
        guard ok1 && ok2 && f_code >= 100 && f_code <= 599 else { return false; }
        out_rule.fail_status = f_code as i32;
        out_rule.fail_count = f_cnt as u32;

        var peek_pos = pos;
        let next_tok = next_ws_token(rest, peek_pos);
        if next_tok.len > 0 {
            let final_code, ok3 = next_tok.parse_u64_dec();
            if ok3 && final_code >= 100 && final_code <= 599 {
                pos = peek_pos;
                out_rule.status_code = final_code as i32;
                return true;
            }
        }
        out_rule.status_code = 200;
        return true;
    }

    let code, ok = active.parse_u64_dec();
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
        if rem.starts_with_fold("location=") {
            let tok = next_ws_token(trimmed, pos);
            let _ = out_rule.location.try_set(tok[9..]);
        } else if rem.starts_with_fold("cookie=") {
            let tok = next_ws_token(trimmed, pos);
            let _ = out_rule.set_cookie.try_set(tok[7..]);
        } else if rem.starts_with_fold("type=") {
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
fn parse_route_body_spec(body_raw: const u8[:], out_rule: RouteRule&) -> bool {
    if body_raw.len >= 2 {
        let is_dquote = core::starts_with(body_raw, "\"") && core::ends_with(body_raw, "\"");
        let is_squote = core::starts_with(body_raw, "'") && core::ends_with(body_raw, "'");
        if is_dquote || is_squote {
            guard out_rule.body.try_set(body_raw[1..^1]) else { return false; }
            return true;
        }
    }
    if body_raw.len > 0 {
        guard out_rule.body.try_set(body_raw) else { return false; }
        if (body_raw[0] == '{' || body_raw[0] == '[') && out_rule.content_type == "text/plain" {
            let _ = out_rule.content_type.try_set("application/json");
        }
    }
    return true;
}

// Parses a single scenario rule line into `out_rule`.
//
// Example:
//   line = "GET /ping -> 200 \"PONG\""
//   returns: true, out_rule = { method: "GET", path: "/ping", status_code: 200, body: "PONG" }
fn parse_route_rule_line(line: const u8[:], out_rule: RouteRule&) -> bool {
    let trimmed = line.trim_lws();
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
    guard parse_route_body_spec(trimmed[pos..].trim_lws(), out_rule) else { return false; }
    return true;
}

fn load_scenario_text(text: const u8[:], stage: ProgrammableServerStage&) -> i64 {
    var added:  i64 = 0;
    var cursor: i64 = 0;
    while cursor < text.len {
        let nl = text[cursor..].index_of_byte('\n');
        let line_end = if nl >= 0 { core::add_sat_i64(cursor, nl) } else { text.len };
        let trimmed = text[cursor..line_end].trim_end_byte('\r').trim_lws();
        if trimmed.len > 0 && trimmed[0] != '#' {
            var r = RouteRule { .. };
            if parse_route_rule_line(trimmed, r) {
                guard stage.rules.try_push(r) else { break; }
                added = core::add_sat_i64(added, 1);
            }
        }
        cursor = core::add_sat_i64(line_end, 1);
    }
    return added;
}

fn strip_query_path(url: const u8[:]) -> const u8[:] {
    let path, _, _ = url.split_once_byte('?');
    return path;
}

// Extracts the query component following '?' in `url`, or empty slice if absent.
//
// Example:
//   url = "/cookies/set?session=xyz&theme=dark"
//   returns: "session=xyz&theme=dark"
fn extract_query_string(url: const u8[:]) -> const u8[:] {
    let _, query, _ = url.split_once_byte('?');
    return query;
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
        } else if b >= 0x20 && b != 0x7F {
            out.push(b);
        }
    }
}

// Formats a request reflection payload in httpbin JSON format.
fn build_httpbin_reflection_json(req: const wing::Request&, peer_ip: const u8[:], out: u8[>..]&) {
    out.clear();
    out.append("{\n  \"method\": \"");
    append_json_escaped_bytes(req.method[..], out);
    out.append("\",\n  \"url\": \"");
    append_json_escaped_bytes(req.url[..], out);
    out.append("\",\n  \"origin\": \"");
    append_json_escaped_bytes(if peer_ip.len > 0 { peer_ip } else { "127.0.0.1" }, out);
    out.append("\",\n  \"headers\": {\n");

    let n_hdrs = req.headers.entries.len;
    let last_idx = core::sub_sat_i64(n_hdrs, 1);
    for i in n_hdrs {
        let e = req.headers.entries[i];
        let h_name = req.headers.entry_name(e);
        let h_val = req.headers.entry_value(e);
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
        append_json_escaped_bytes(req.headers.entry_name(e), out);
        out.append("\": \"");
        append_json_escaped_bytes(req.headers.entry_value(e), out);
        out.push('"');
        if i < last_idx { out.push(','); }
        out.push('\n');
    }
    out.append("  }\n}\n");
}

fn handle_httpbin_status_or_redirect(path: const u8[:], res: wing::Response&) -> bool {
    if core::starts_with(path, "/status/") && path.len > 8 {
        let code_u64, ok = path[8..].parse_u64_dec();
        guard ok && code_u64 >= 100 && code_u64 <= 599 else { return false; }
        res.status_code = code_u64 as i32;
        res.set_header("Content-Type", "text/plain");
        res.body.clear();
        if !rfc::is_empty_body_status(res.status_code) {
            res.body.append(rfc::status_phrase(res.status_code));
            res.body.push('\n');
        }
        return true;
    }

    if core::starts_with(path, "/redirect/") && path.len > 10 {
        let n_hops, ok = path[10..].parse_u64_dec();
        guard ok else { return false; }
        res.status_code = 302;
        var loc: u8[..64] = [];
        if n_hops <= 1 {
            let _ = loc.try_set("/get");
        } else {
            let _ = loc.try_set("/redirect/");
            let rem_hops = core::sub_sat_u64(n_hops, 1);
            rem_hops.format_u64_dec(loc);
        }
        res.set_header("Location", loc[..]);
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
    guard range_hdr.len > 0 else { return false; }
    let rs, r_err = wing::parse_range_header(range_hdr, total_len);
    let is_bytes_unit = range_hdr.trim_lws().starts_with_fold("bytes=");
    if r_err == wing::RangeError.Unsatisfiable || (total_len == 0 && is_bytes_unit) {
        res.status_code = 416;
        var cr_416: u8[..64] = [];
        wing::format_content_range(-1, -1, total_len, cr_416);
        res.set_header("Content-Range", cr_416[..]);
        res.set_header("Accept-Ranges", "bytes");
        res.set_header("Content-Type", "application/octet-stream");
        res.body.clear();
        return true;
    }
    guard r_err.is_ok() && rs.is_satisfiable && rs.ranges.len > 0 else { return false; }
    let r0 = rs.ranges[0];
    res.status_code = 206;
    var cr_hdr: u8[..64] = [];
    wing::format_content_range(r0.start, r0.end_pos, total_len, cr_hdr);
    res.set_header("Content-Range", cr_hdr[..]);
    res.set_header("Accept-Ranges", "bytes");
    res.set_header("Content-Type", "application/octet-stream");
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

    let n_raw, ok = path[7..].parse_u64_dec();
    guard ok && n_raw <= 65536 else { return false; }
    let total_len = n_raw as i64;

    var full_buf: u8[>..] = [];
    generate_synthetic_alphabet_bytes(total_len, full_buf);

    if try_serve_range_slice(req.header("Range"), full_buf[..], res) {
        return true;
    }

    res.status_code = 200;
    res.set_header("Accept-Ranges", "bytes");
    res.set_header("Content-Type", "application/octet-stream");
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
        let tok = if auth.starts_with_fold("Bearer ") { auth[7..].trim_lws() } else { "" };
        if tok.len > 0 {
            res.status_code = 200;
            res.set_header("Content-Type", "application/json");
            res.body.clear();
            res.body.append("{\"authenticated\": true, \"token\": \"");
            append_json_escaped_bytes(tok, res.body);
            res.body.append("\"}\n");
            return true;
        }
        res.status_code = 401;
        res.set_header("WWW-Authenticate", "Bearer");
        res.body.clear();
        return true;
    }

    if core::starts_with(path, "/basic-auth/") && path.len > 12 {
        let exp_user, exp_pass, has_sl = path[12..].split_once_byte('/');
        guard has_sl && exp_user.len > 0 && exp_pass.len > 0 else { return false; }

        var raw_up: u8[..256] = [];
        guard raw_up.try_set(exp_user) && raw_up.try_push(':') && raw_up.try_append(exp_pass) else {
            return false;
        }
        var exp_b64: u8[..384] = [];
        core::base64_encode(raw_up[..], exp_b64);
        core::secure_zeroize_slice(raw_up[..]);

        let auth = req.header("Authorization");
        let b64_part = if auth.starts_with_fold("Basic ") { auth[6..].trim_lws() } else { "" };
        let matched = b64_part.len > 0 && core::ct_eq_bytes(b64_part, exp_b64[..]);
        core::secure_zeroize_slice(exp_b64[..]);

        if matched {
            res.status_code = 200;
            res.set_header("Content-Type", "application/json");
            res.body.clear();
            res.body.append("{\"authenticated\": true, \"user\": \"");
            append_json_escaped_bytes(exp_user, res.body);
            res.body.append("\"}\n");
            return true;
        }
        res.status_code = 401;
        res.set_header("WWW-Authenticate", "Basic realm=\"Fake Realm\"");
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
        let _ = ck_hdr.try_append("; Path=/");
        res.set_header("Set-Cookie", ck_hdr[..]);
        res.set_header("Location", "/cookies");
        return true;
    }

    if core::starts_with(path, "/flaky/") && path.len > 7 {
        let fails, ok = path[7..].parse_u64_dec();
        guard ok && fails > 0 && fails <= 1000 else { return false; }
        stage.flaky_counter = core::add_sat_u64(stage.flaky_counter, 1);
        let attempt = stage.flaky_counter;
        if attempt <= fails {
            res.status_code = 503;
            res.set_header("Content-Type", "text/plain");
            res.body.clear();
            res.body.append("FLAKY_TEMP_503 (attempt ");
            attempt.format_u64_dec(res.body);
            res.body.push('/');
            fails.format_u64_dec(res.body);
            res.body.append(")\n");
            return true;
        }
        stage.flaky_counter = 0;
        res.status_code = 200;
        res.set_header("Content-Type", "text/plain");
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
        res.set_header("Content-Type", "application/json");
        build_httpbin_reflection_json(req, peer_ip, res.body);
        return true;
    }

    if path == "/headers" {
        res.status_code = 200;
        res.set_header("Content-Type", "application/json");
        build_httpbin_headers_json(req, res.body);
        return true;
    }

    if path == "/ip" {
        res.status_code = 200;
        res.set_header("Content-Type", "application/json");
        res.body.clear();
        res.body.append("{\"origin\": \"");
        append_json_escaped_bytes(if peer_ip.len > 0 { peer_ip } else { "127.0.0.1" }, res.body);
        res.body.append("\"}\n");
        return true;
    }

    if path == "/user-agent" {
        res.status_code = 200;
        res.set_header("Content-Type", "application/json");
        res.body.clear();
        res.body.append("{\"user-agent\": \"");
        append_json_escaped_bytes(req.header("User-Agent"), res.body);
        res.body.append("\"}\n");
        return true;
    }

    if path == "/cookies" {
        res.status_code = 200;
        res.set_header("Content-Type", "application/json");
        res.body.clear();
        res.body.append("{\"cookies\": \"");
        append_json_escaped_bytes(req.header("Cookie"), res.body);
        res.body.append("\"}\n");
        return true;
    }

    if path == "/sse" {
        res.status_code = 200;
        res.set_header("Content-Type", "text/event-stream");
        res.set_header("Cache-Control", "no-cache");
        res.set_header("Connection", "close");
        res.body.clear();
        res.body.append("id: 1\nevent: ping\ndata: {\"msg\":\"hello from wing sse\"}\n\n");
        res.body.append("id: 2\nevent: done\ndata: {\"msg\":\"stream complete\"}\n\n");
        return true;
    }

    return handle_httpbin_dynamic_routes(stage, path, query, req, res);
}

fn apply_matched_scenario_rule(
    r:        RouteRule&,
    res:      wing::Response&,
    out_note: u8[..64]&,
) {
    r.calls = core::add_sat_u64(r.calls, 1);
    res.set_header("Content-Type", r.content_type[..]);

    if r.fail_count > 0 && r.calls <= r.fail_count {
        res.status_code = r.fail_status;
        res.body.clear();
        res.body.append("SCENARIO_FAIL_");
        r.fail_status.format_i64_dec(res.body);
        res.body.push('\n');

        let _ = out_note.try_set("flaky ");
        r.calls.format_u64_dec(out_note);
        let _ = out_note.try_push('/');
        r.fail_count.format_u64_dec(out_note);
        return;
    }

    res.status_code = r.status_code;
    if r.location.len > 0 {
        res.set_header("Location", r.location[..]);
    }
    if r.set_cookie.len > 0 {
        res.set_header("Set-Cookie", r.set_cookie[..]);
    }
    res.body.clear();
    res.body.append(r.body[..]);
    let _ = out_note.try_set("rule");
}

fn finalize_programmable_response(
    stage: ProgrammableServerStage&,
    req:   const wing::Request&,
    res:   wing::Response&,
) {
    if stage.max_reqs > 0 && stage.served_reqs >= stage.max_reqs {
        res.set_header("Connection", "close");
    }
    if req.method[..].eq_ascii_fold("HEAD") {
        if !rfc::is_empty_body_status(res.status_code) && res.header("Content-Length").len == 0 {
            var cl_buf: u8[..32] = [];
            res.body.len.format_i64_dec(cl_buf);
            res.set_header("Content-Length", cl_buf[..]);
        }
        res.body.clear();
    }
}

fn eval_programmable_server_stage(
    stage:    ProgrammableServerStage&,
    phase:    wire::ServerHookPhase,
    req:      const wing::Request&,
    res:      wing::Response&,
    out_note: u8[..64]&,
) -> wire::StageVerdict {
    out_note.clear();
    guard phase == wire::ServerHookPhase.PreRoute else {
        return wire::StageVerdict.Continue;
    }
    let req_path = strip_query_path(req.url[..]);
    if req_path == "/shutdown" {
        let _ = out_note.try_set("shutdown");
        return wire::StageVerdict.Continue;
    }

    stage.served_reqs = core::add_sat_u64(stage.served_reqs, 1);
    let is_head = req.method[..].eq_ascii_fold("HEAD");

    for &r in stage.rules {
        let is_wildcard = r.method[..] == "*" || r.method[..] == "ANY";
        let method_ok = is_wildcard ||
            r.method[..].eq_ascii_fold(req.method[..]) ||
            (is_head && r.method[..].eq_ascii_fold("GET"));
        if method_ok && r.path[..] == req_path {
            apply_matched_scenario_rule(r, res, out_note);
            finalize_programmable_response(stage, req, res);
            return wire::StageVerdict.ShortCircuit { status_code: res.status_code as u16 };
        }
    }

    if handle_builtin_httpbin(stage, req, "127.0.0.1", res) {
        let _ = out_note.try_set("httpbin");
        finalize_programmable_response(stage, req, res);
        return wire::StageVerdict.ShortCircuit { status_code: res.status_code as u16 };
    }

    let _ = out_note.try_set("not found");
    res.status_code = 404;
    res.set_header("Content-Type", "application/json");
    res.body.clear();
    res.body.append("{\"error\": \"route not found\", \"path\": \"");
    append_json_escaped_bytes(req_path, res.body);
    res.body.append("\"}\n");
    finalize_programmable_response(stage, req, res);
    return wire::StageVerdict.ShortCircuit { status_code: 404 };
}

// Parses a semicolon-delimited `Cookie` request header (`k1=v1; k2=v2`) and seeds each
// pair into `jar` for `req_url` so `STAGE_ID_CLI_IN_COOKIE_LOAD` preserves inline `-b` cookies.
//
// Example:
//   req_url = "http://example.com/api", cookie_hdr = "a=1; b=2"
//   seeds a=1 and b=2 into `jar` for host "example.com" with Path=/
fn seed_inline_cookies_to_jar(
    jar:        wing::CanonicalCookieJar&,
    req_url:    const u8[:],
    cookie_hdr: const u8[:],
    now_us:     i64,
) {
    guard cookie_hdr.len > 0 && req_url.len > 0 else { return; }
    var pos: i64 = 0;
    while pos < cookie_hdr.len {
        let rel_semi = cookie_hdr[pos..].index_of_byte(';');
        let end = if rel_semi >= 0 { core::add_sat_i64(pos, rel_semi) } else { cookie_hdr.len };
        let pair = cookie_hdr[pos..end].trim_lws();
        pos = core::add_sat_i64(end, 1);
        let key, _, has_eq = pair.split_once_byte('=');
        guard has_eq && key.len > 0 else { continue; }
        var set_str: u8[..1024] = [];
        if set_str.try_set(pair) && set_str.try_append("; Path=/") {
            let _ = jar.set_cookie_header(req_url, set_str[..], now_us, "");
        }
    }
}
