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

fn wing::on_server_stage(
    stage: ProgrammableServerStage&,
    phase: wire::ServerHookPhase,
    _cfg:  wing::ServerPipelineConfig&,
    req:   const wing::Request&,
    _ctx:  wing::ServerStageCtx&,
    res:   wing::Response&,
) -> wire::StageVerdict {
    var note: u8[..64] = [];
    let verdict = eval_programmable_server_stage(stage, phase, req, res, note);
    if note.len > 0 && !stage.quiet {
        let log_code = if note[..] == "shutdown" { 200 } else { res.status_code };
        log_server_exchange(req.method[..], req.url[..], log_code, note[..], stage.no_color);
    }
    return verdict;
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
        var r = RouteRule { .. };
        guard parse_route_rule_line(line[..], r) else {
            write_stderr(str("wing serve: invalid --route syntax: ", line[..], "\n"));
            return 2;
        }
        guard stage.rules.try_push(r) else {
            write_stderr("wing serve: too many route rules (max 32)\n");
            return 2;
        }
    }
    return 0;
}

fn execute_serve_cmd(cfg: const CliConfig&) -> i64 {
    var stage = ProgrammableServerStage {
        max_reqs: cfg.max_reqs,
        quiet:    cfg.silent,
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
    server.add_static_get_route("/shutdown", "text/plain", "BYE\n", 99);

    var banner: u8[>..] = [];
    banner.append("READY_PORT:");
    actual_port.format_u64_dec(banner);
    banner.push('\n');
    write_stdout(banner);

    var info: u8[>..] = [];
    info.append("[serve] listening on http://");
    info.append(cfg.bind_host[..]);
    info.push(':');
    actual_port.format_u64_dec(info);
    info.append(" (httpbin + ");
    stage.rules.len.format_i64_dec(info);
    info.append(" custom rules)\n");
    write_stderr(info);

    var in_buf:      u8[..65536] = [];
    var ws_frag_buf: u8[..65536] = [];
    var out_wire:    u8[..65536] = [];

    server.handle_os_signals = true;
    wing::server_init_run_state(server);
    while !wing::server_should_stop(server) {
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
