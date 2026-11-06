// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Streaming ANSI terminal formatter for HTTP status lines, headers, and server logs.
import std;
import os;
import core from "..";
import wing from "..";
import args;

const ANSI_RESET:  const u8[:] = "\x1b[0m";
const ANSI_BOLD:   const u8[:] = "\x1b[1m";
const ANSI_DIM:    const u8[:] = "\x1b[2m";
const ANSI_GREEN:  const u8[:] = "\x1b[32m";
const ANSI_YELLOW: const u8[:] = "\x1b[33m";
const ANSI_RED:    const u8[:] = "\x1b[31m";
const ANSI_CYAN:   const u8[:] = "\x1b[36m";
const ANSI_BLUE:   const u8[:] = "\x1b[34m";

fn status_color(code: i32, no_color: bool) -> const u8[:] {
    if no_color { return ""; }
    if code >= 200 && code < 300 { return ANSI_GREEN; }
    if code >= 300 && code < 400 { return ANSI_YELLOW; }
    if code >= 400 { return ANSI_RED; }
    return ANSI_CYAN;
}

fn c_seq(seq: const u8[:], no_color: bool) -> const u8[:] {
    return if no_color { "" } else { seq };
}

fn print_help(no_color: bool) {
    var out: u8[>..] = [];
    out.append(c_seq(ANSI_BOLD, no_color));
    out.append("wing");
    out.append(c_seq(ANSI_RESET, no_color));
    out.append(" - Goose-Wing HTTP/1.1, HTTP/2, TLS 1.3 Client & Programmable Test Server\n\n");

    out.append(c_seq(ANSI_CYAN, no_color));
    out.append("CLIENT USAGE (curl-compatible flags):\n");
    out.append(c_seq(ANSI_RESET, no_color));
    out.append("  wing [FLAGS] <URL>\n\n");
    out.append("  -X, --request <METHOD>     HTTP method (default: GET, POST with -d/-F, PUT with -T)\n");
    out.append("  -G, --get                  Put -d / --data-urlencode parameters into URL query string\n");
    out.append("  -I, --head                 Send HEAD request and display response headers only\n");
    out.append("  -H, --header <H: V|@FILE>  Add request header or load header lines from @file\n");
    out.append("  -A, --user-agent <UA>      Override User-Agent header\n");
    out.append("  -e, --referer <URL>        Set Referer header\n");
    out.append("  -b, --cookie <DATA|FILE>   Send Cookie string ('k=v') or load Netscape cookie jar\n");
    out.append("  -c, --cookie-jar <FILE>    Write session cookies to Netscape cookie jar file\n");
    out.append("  -d, --data <BODY|@FILE|@-> Send request body inline, from @file, or from @- (stdin)\n");
    out.append("      --data-raw <DATA>      Send request body literally without '@' file expansion\n");
    out.append("      --data-urlencode <VAL> URL-encode data parameter (name=val, =val, name@file)\n");
    out.append("  -F, --form <NAME=VAL>      Send multipart/form-data (supports @file;type=...;filename=...)\n");
    out.append("  -T, --upload-file <FILE>   PUT file contents (or @- from stdin) to target URL\n");
    out.append("      --json <JSON|@FILE>    Send JSON body with Content-Type & Accept headers\n");
    out.append("  -r, --range <RANGE>        Send byte range request (e.g. 0-499, 500-, -256)\n");
    out.append("  -C, --continue-at <OFF|->  Resume partial download at byte offset or '-' (file size)\n");
    out.append("  -o, --output <FILE>        Write response body to file instead of stdout\n");
    out.append("  -O, --remote-name          Write response body to file named after URL tail\n");
    out.append("  -D, --dump-header <FILE>   Write received HTTP response headers to file\n");
    out.append("      --bearer <TOKEN>       Set Authorization: Bearer <TOKEN>\n");
    out.append("  -u, --user <USER:PASS>     Set RFC 7616 Digest / Basic credentials\n");
    out.append("  -x, --proxy <URL>          Use HTTP CONNECT or SOCKS5/5h proxy (or HTTPS_PROXY env)\n");
    out.append("      --noproxy <HOSTS>      Comma-separated proxy bypass list (or NO_PROXY env)\n");
    out.append("      --resolve <H:P:IP>     Pin host:port to IPv4 in wing's in-memory DNS cache\n");
    out.append("  -m, --max-time <SEC>       Maximum transfer timeout in seconds (--timeout for ms)\n");
    out.append("      --max-redirs <N>       Maximum number of redirects to follow (default: 10)\n");
    out.append("      --retry <N>            Enable automatic retry on 5xx / transient errors\n");
    out.append("      --h2c                  Use HTTP/2 Prior Knowledge (RFC 9113)\n");
    out.append("      --http1.1              Force HTTP/1.1 ALPN negotiation\n");
    out.append("      --compressed           Request compressed response (zstd, br, gzip; default)\n");
    out.append("  -k, --insecure             Skip TLS certificate verification\n");
    out.append("  -L, --location             Follow redirects (default; use --no-follow to disable)\n");
    out.append("  -f, --fail                 Return exit code 22 on HTTP status >= 400\n");
    out.append("  -s, --silent               Suppress progress/error diagnostics\n");
    out.append("  -w, --write-out <FMT>      Print metadata (%{http_code}, %{size_download}, %{size_upload},\n");
    out.append("                             %{time_total}, %{url_effective}, %{redirect_url}, %{scheme})\n");
    out.append("  -i, --include              Print response status line and headers\n");
    out.append("  -v, --verbose              Print request, JA4/Akamai fingerprints, timings, and headers\n");
    out.append("      --no-color             Disable ANSI colors (or set NO_COLOR=1)\n\n");

    out.append(c_seq(ANSI_CYAN, no_color));
    out.append("SERVER USAGE (Built-in httpbin + Scenario Router):\n");
    out.append(c_seq(ANSI_RESET, no_color));
    out.append("  wing serve [FLAGS]\n\n");
    out.append("  -p, --port <PORT>          Listen port (default: 8080, use 0 for auto-port)\n");
    out.append("      --host <IP>            Bind address (default: 127.0.0.1)\n");
    out.append("  -r, --route <RULE>         Add programmable route rule (repeatable):\n");
    out.append("                               \"GET /ping -> 200 'PONG'\"\n");
    out.append("                               \"GET /flaky -> 503x2, 200 'RECOVERED'\"\n");
    out.append("                               \"GET /old -> 302 Location=/new 'Moved'\"\n");
    out.append("  -f, --file <PATH>          Load route rules from scenario file\n");
    out.append("  -n, --max-reqs <N>         Serve N requests and exit cleanly\n\n");
    out.append("  Built-in httpbin endpoints:\n");
    out.append("    /get, /post, /put, /delete, /anything, /echo, /headers, /ip, /user-agent,\n");
    out.append("    /status/:code, /redirect/:n, /flaky/:fails, /cookies, /bytes/:n, /range/:n,\n");
    out.append("    /basic-auth/:user/:pass, /bearer, /sse, /shutdown\n");
    write_stdout(out);
}

fn print_client_verbose_request(
    cfg:  const CliConfig&,
    sess: const wing::Client&,
    req:  const wing::Request&,
) {
    var out: u8[>..] = [];
    let nc = cfg.no_color;
    let ja4_fp = wing::ja4(sess);
    let ak_hash = wing::akamai_hash(sess);

    out.append(c_seq(ANSI_DIM, nc));
    out.append("* Profile: ");
    out.append(wing::profile_name(sess.profile));
    out.append(" | JA4: ");
    out.append(ja4_fp[..]);
    out.append(" | Akamai-H2: ");
    out.append(ak_hash[..]);
    out.push('\n');
    out.append("> ");
    out.append(req.method[..]);
    out.push(' ');
    out.append(req.url[..]);
    out.push('\n');
    for &e in req.headers.entries {
        out.append("> ");
        out.append(wing::entry_name(req.headers, e));
        out.append(": ");
        out.append(wing::entry_value(req.headers, e));
        out.push('\n');
    }
    out.append(c_seq(ANSI_RESET, nc));
    write_stderr(out);
}

fn append_write_out_numeric_var<B>(
    var_name:   const u8[:],
    req:        const wing::Request&,
    res:        const wing::Response&,
    elapsed_ms: u64,
    out:        B&,
) {
    if var_name == "http_code" || var_name == "response_code" {
        core::format_i64_dec(res.status_code, out);
    } else if var_name == "size_download" {
        core::format_i64_dec(res.body.len, out);
    } else if var_name == "size_upload" {
        core::format_i64_dec(req.body.len, out);
    } else if var_name == "size_header" {
        core::format_i64_dec(res.headers.raw_buf.len, out);
    } else if var_name == "num_redirects" {
        core::format_i64_dec(res.redirect_count, out);
    } else if var_name == "num_headers" {
        core::format_i64_dec(res.headers.entries.len, out);
    } else if core::starts_with(var_name, "time_") {
        core::format_u64_dec(elapsed_ms, out);
        out.append("ms");
    }
}

// Formats curl-compatible `-w / --write-out` template variables into `out`.
//
// Example:
//   fmt = "code=%{http_code} bytes=%{size_download}\n"
//   appends: "code=200 bytes=572\n"
fn append_write_out_var<B>(
    var_name:   const u8[:],
    req:        const wing::Request&,
    res:        const wing::Response&,
    elapsed_ms: u64,
    out:        B&,
) {
    append_write_out_numeric_var(var_name, req, res, elapsed_ms, out);
    if var_name == "url_effective" {
        out.append(res.effective_url[..]);
    } else if var_name == "redirect_url" {
        out.append(wing::header(res, "location"));
    } else if var_name == "http_version" {
        out.append(res.protocol[..]);
    } else if var_name == "content_type" {
        out.append(wing::header(res, "content-type"));
    } else if var_name == "scheme" {
        let pu, _ = core::parse_url(res.effective_url[..]);
        out.append(core::scheme(pu));
    }
}

fn format_write_out<B>(
    fmt:        const u8[:],
    req:        const wing::Request&,
    res:        const wing::Response&,
    elapsed_ms: u64,
    out:        B&,
) {
    var rem = fmt;
    while rem.len > 0 {
        if core::starts_with(rem, "\\n") {
            out.push('\n');
            rem = rem[2..];
            continue;
        }
        if core::starts_with(rem, "\\t") {
            out.push('\t');
            rem = rem[2..];
            continue;
        }
        if core::starts_with(rem, "%{") {
            let tail = rem[2..];
            let close_rel = core::index_of_byte(tail, '}');
            if close_rel > 0 {
                let next_idx = core::add_sat_i64(close_rel, 1);
                append_write_out_var(tail[..close_rel], req, res, elapsed_ms, out);
                rem = tail[next_idx..];
                continue;
            }
        }
        out.push(rem[0]);
        rem = rem[1..];
    }
}

fn print_client_response(
    cfg:        const CliConfig&,
    req:        const wing::Request&,
    res:        const wing::Response&,
    elapsed_ms: u64,
) {
    var out: u8[>..] = [];
    let nc = cfg.no_color;

    if cfg.show_headers {
        let sc_col = status_color(res.status_code, nc);
        out.append(c_seq(ANSI_BOLD, nc));
        out.append(res.protocol[..]);
        out.push(' ');
        out.append(sc_col);
        core::format_i64_dec(res.status_code, out);
        out.push(' ');
        out.append(rfc::status_phrase(res.status_code));
        out.append(c_seq(ANSI_RESET, nc));

        if cfg.verbose {
            out.append(c_seq(ANSI_DIM, nc));
            out.append(" (");
            core::format_u64_dec(elapsed_ms, out);
            out.append(" ms, ");
            core::format_i64_dec(res.body.len, out);
            out.append(" B");
            if res.redirect_count > 0 {
                out.append(", redirects: ");
                core::format_i64_dec(res.redirect_count, out);
            }
            out.push(')');
            out.append(c_seq(ANSI_RESET, nc));
        }
        out.push('\n');

        for &e in res.headers.entries {
            out.append(c_seq(ANSI_CYAN, nc));
            out.append(wing::entry_name(res.headers, e));
            out.append(c_seq(ANSI_RESET, nc));
            out.append(": ");
            out.append(wing::entry_value(res.headers, e));
            out.push('\n');
        }
        out.push('\n');
    }

    if cfg.output_file.len == 0 && !cfg.head_only && res.body.len > 0 {
        out.append(res.body[..]);
        if !core::ends_with(res.body[..], "\n") { out.push('\n'); }
    }

    if cfg.write_out.len > 0 { format_write_out(cfg.write_out[..], req, res, elapsed_ms, out); }
    if out.len > 0 { write_stdout(out); }
}

fn log_server_exchange(
    method:   const u8[:],
    url:      const u8[:],
    status:   i32,
    note:     const u8[:],
    no_color: bool,
) {
    var out: u8[>..] = [];
    out.append(c_seq(ANSI_DIM, no_color));
    out.append("[serve] ");
    out.append(c_seq(ANSI_RESET, no_color));
    out.append(c_seq(ANSI_BOLD, no_color));
    out.append(method);
    out.append(c_seq(ANSI_RESET, no_color));
    out.push(' ');
    out.append(url);
    out.append(" -> ");
    out.append(status_color(status, no_color));
    core::format_i64_dec(status, out);
    out.push(' ');
    out.append(rfc::status_phrase(status));
    out.append(c_seq(ANSI_RESET, no_color));
    if note.len > 0 {
        out.append(c_seq(ANSI_DIM, no_color));
        out.append(" (");
        out.append(note);
        out.push(')');
        out.append(c_seq(ANSI_RESET, no_color));
    }
    out.push('\n');
    write_stderr(out);
}
