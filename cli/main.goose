// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Standalone Goose-Wing CLI (`wing`): HTTP/1.1, HTTP/2, TLS 1.3 Client & Programmable Server.
import std;
import os;
import wing from "..";
import args;
import term;
import client;
import server;

const WING_CLI_VERSION: const u8[:] = "wing cli 0.1.0\n";

fn zeroize_cli_secrets(cfg: CliConfig&) {
    core::secure_zeroize_slice(cfg.bearer_token[..]);
    core::secure_zeroize_slice(cfg.basic_user[..]);
    core::secure_zeroize_slice(cfg.basic_pass[..]);
    core::secure_zeroize_slice(cfg.cookie_header[..]);
}

fn main() {
    let _ = core::disable_core_dumps();
    let argv = args();
    var cfg = CliConfig { .. };
    defer zeroize_cli_secrets(cfg);
    if !parse_cli_args(argv, cfg) {
        var err_out: u8[>..] = [];
        err_out.append("wing: ");
        sanitize_terminal_text(cfg.err_msg[..], err_out);
        err_out.push('\n');
        write_stderr(err_out);
        zeroize_cli_secrets(cfg);
        exit(2);
    }

    let code: i64 = match cfg.mode {
        Help => {
            print_help(cfg.no_color);
            0
        },
        Version => {
            write_stdout(WING_CLI_VERSION);
            0
        },
        Client => execute_client_cmd(cfg),
        Serve => execute_serve_cmd(cfg),
    };

    zeroize_cli_secrets(cfg);
    if code != 0 {
        exit(code);
    }
}
