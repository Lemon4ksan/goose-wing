// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Programmable test server execution engine (`wing serve`) with scenario router & httpbin.
import std;
import os;
import core from "..";
import wing from "..";
import args;
import rules;
import term;

fn apply_matched_scenario_rule(
    r:        RouteRule&,
    res:      wing::Response&,
    out_note: u8[..64]&,
) {
    r.calls = core::add_sat_u64(r.calls, 1);
    wing::set_header(res, "Content-Type", r.content_type[..]);

    if r.fail_count > 0 && r.calls <= r.fail_count {
        res.status_code = r.fail_status;
        res.body.clear();
        res.body.append("SCENARIO_FAIL_");
        core::format_i64_dec(r.fail_status, res.body);
        res.body.push('\n');

        out_note.append("flaky ");
        core::format_u64_dec(r.calls, out_note);
        out_note.push('/');
        core::format_u64_dec(r.fail_count, out_note);
        return;
    }

    res.status_code = r.status_code;
    if r.location.len > 0 {
        wing::set_header(res, "Location", r.location[..]);
    }
    if r.set_cookie.len > 0 {
        wing::set_header(res, "Set-Cookie", r.set_cookie[..]);
    }
    res.body.clear();
    res.body.append(r.body[..]);
    out_note.append("rule");
}

fn wing::on_server_stage(
    stage: ProgrammableServerStage&,
    phase: wire::ServerHookPhase,
    _cfg:  wing::ServerPipelineConfig&,
    req:   const wing::Request&,
    _ctx:  wing::ServerStageCtx&,
    res:   wing::Response&,
) -> wire::StageVerdict {
    guard phase == wire::ServerHookPhase.PreRoute else {
        return wire::StageVerdict.Continue;
    }
    let req_path = strip_query_path(req.url[..]);
    if req_path == "/shutdown" {
        log_server_exchange(req.method[..], req.url[..], 200, "shutdown", stage.no_color);
        return wire::StageVerdict.Continue;
    }

    stage.served_reqs = core::add_sat_u64(stage.served_reqs, 1);

    // 1. Match user-defined scenario rules first
    for &r in stage.rules {
        let is_wildcard = r.method[..] == "*" || r.method[..] == "ANY";
        let method_ok = is_wildcard || core::eq_ascii_fold(r.method[..], req.method[..]);
        if method_ok && r.path[..] == req_path {
            var note: u8[..64] = [];
            apply_matched_scenario_rule(r, res, note);
            log_server_exchange(req.method[..], req.url[..], res.status_code, note[..], stage.no_color);
            return wire::StageVerdict.ShortCircuit { status_code: res.status_code as u16 };
        }
    }

    // 2. Match built-in httpbin endpoints
    if handle_builtin_httpbin(stage, req, "127.0.0.1", res) {
        log_server_exchange(req.method[..], req.url[..], res.status_code, "httpbin", stage.no_color);
        return wire::StageVerdict.ShortCircuit { status_code: res.status_code as u16 };
    }

    log_server_exchange(req.method[..], req.url[..], 404, "not found", stage.no_color);
    res.status_code = 404;
    wing::set_header(res, "Content-Type", "application/json");
    res.body.clear();
    res.body.append("{\"error\": \"route not found\", \"path\": \"");
    res.body.append(req_path);
    res.body.append("\"}\n");
    return wire::StageVerdict.ShortCircuit { status_code: 404 };
}

fn load_serve_rules(cfg: const CliConfig&, stage: ProgrammableServerStage&) -> i64 {
    if cfg.scenario_file.len > 0 {
        var file_bytes: u8[>..] = [];
        guard read_file(cfg.scenario_file[..], file_bytes) else {
            write_stderr(str("wing serve: cannot read scenario file: ", cfg.scenario_file[..], "\n"));
            return 1;
        }
        let _ = load_scenario_text(file_bytes[..], stage);
    }

    for &line in cfg.inline_routes {
        if stage.rules.len < stage.rules.cap {
            var r = RouteRule { .. };
            if parse_route_rule_line(line[..], r) {
                stage.rules.push(r);
            } else {
                write_stderr(str("wing serve: invalid --route syntax: ", line[..], "\n"));
                return 2;
            }
        }
    }
    return 0;
}

fn execute_serve_cmd(cfg: const CliConfig&) -> i64 {
    var stage = ProgrammableServerStage {
        max_reqs: cfg.max_reqs,
        no_color: cfg.no_color,
        ..
    };

    let load_rc = load_serve_rules(cfg, stage);
    if load_rc != 0 {
        return load_rc;
    }

    let listener = wing::tcp_listen(cfg.bind_host[..], cfg.port, 128);
    if listener <= 0 {
        write_stderr(str("wing serve: failed to bind ", cfg.bind_host[..], ":", cfg.port, "\n"));
        return 1;
    }
    defer wing::tcp_close(listener);

    let actual_port = wing::tcp_getsockname_port(listener);
    var server = wing::new_http_server(cfg.bind_host[..], actual_port);
    let _ = server.server_name.try_set("goose-wing-cli/1.0");
    server.pipeline.enable_csrf_guard = false;
    server.pipeline.enable_rate_limiter = false;
    wing::add_static_get_route(server, "/shutdown", "text/plain", "BYE\n", 99);

    var banner: u8[>..] = [];
    banner.append("READY_PORT:");
    core::format_u64_dec(actual_port, banner);
    banner.push('\n');
    write_stdout(banner);

    var info: u8[>..] = [];
    info.append("[serve] listening on http://");
    info.append(cfg.bind_host[..]);
    info.push(':');
    core::format_u64_dec(actual_port, info);
    info.append(" (httpbin + ");
    core::format_i64_dec(stage.rules.len, info);
    info.append(" custom rules)\n");
    write_stderr(info);

    var in_buf:      u8[..65536] = [];
    var ws_frag_buf: u8[..65536] = [];
    var out_wire:    u8[..65536] = [];

    server.is_running = true;
    while server.is_running {
        if stage.max_reqs > 0 && stage.served_reqs >= stage.max_reqs {
            break;
        }
        let conn = wing::tcp_accept(listener, 200);
        if conn <= 0 {
            continue;
        }
        let _ = wing::serve_http_connection_on_listener_buf(
            listener, conn, server, stage, in_buf, ws_frag_buf, out_wire, 500,
        );
        wing::tcp_close(conn);
    }

    return 0;
}
