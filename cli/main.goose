// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Standalone Goose-Wing CLI (`wing`): HTTP/1.1, HTTP/2, TLS 1.3 Client & Programmable Server.
import std;
import os;
import core from "..";
import wing from "..";
import args;
import term;
import client;
import server;

const WING_CLI_VERSION: const u8[:] = "wing cli 0.1.0\n";

fn main() {
    let argv = args();
    var cfg = CliConfig { .. };
    if !parse_cli_args(argv, cfg) {
        write_stderr(str("wing: ", cfg.err_msg[..], "\n"));
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

    if code != 0 {
        exit(code);
    }
}
