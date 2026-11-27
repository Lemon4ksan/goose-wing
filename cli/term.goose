// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Streaming ANSI terminal formatter for HTTP status lines, headers, and server logs.
import std;
import os;
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

inline fn is_escaped_terminal_codepoint(cp: i64) -> bool {
    if cp >= 0x80 && cp <= 0x9F { return true; }
    if cp >= 0x200E && cp <= 0x200F { return true; }
    if cp >= 0x202A && cp <= 0x202E { return true; }
    if cp >= 0x2066 && cp <= 0x2069 { return true; }
    return cp >= 0xE0000 && cp <= 0xE007F;
}

inline fn append_escaped_hex_bytes<B>(bytes: const u8[:], out: B&) {
    for b in bytes {
        out.append("\\x");
        b.format_u8_hex(out, true);
    }
}

// Escapes C0 controls (except `\n` and `\t`), `DEL`, `ESC`, C1 controls (`0x80..0x9F`),
// Unicode Bidi controls (`U+200E..U+200F`, `U+202A..U+202E`, `U+2066..U+2069`), and Tag
// characters (`U+E0000..U+E007F`) as `\xHH` while keeping safe text intact.
//
// Example:
//   input = "hi\x1b]52;c;AA\x07"
//   appends: "hi\\x1B]52;c;AA\\x07"
fn sanitize_terminal_text<B>(input: const u8[:], out: B&) {
    var i: i64 = 0;
    while i < input.len {
        let b = input[i];
        if b < 0x80 {
            if b == '\n' || b == '\t' || (b >= 0x20 && b != 0x7F) {
                out.push(b);
            } else {
                out.append("\\x");
                b.format_u8_hex(out, true);
            }
            i = core::add_sat_i64(i, 1);
            continue;
        }
        let cp, size, valid = core::decode_utf8(input[i..]);
        let step = max(1, min(size, core::sub_sat_i64(input.len, i)));
        let seq = input[i..core::add_sat_i64(i, step)];
        if !valid || is_escaped_terminal_codepoint(cp) {
            append_escaped_hex_bytes(seq, out);
        } else {
            out.append(seq);
        }
        i = core::add_sat_i64(i, step);
    }
}

inline fn append_cli_text<B>(src: const u8[:], raw_output: bool, out: B&) {
    if raw_output {
        out.append(src);
    } else {
        sanitize_terminal_text(src, out);
    }
}

inline fn is_redacted_verbose_req_header(name: const u8[:]) -> bool {
    return name.eq_ascii_fold("authorization") ||
           name.eq_ascii_fold("proxy-authorization") ||
           name.eq_ascii_fold("cookie");
}

inline fn is_redacted_diag_resp_header(name: const u8[:]) -> bool {
    return name.eq_ascii_fold("set-cookie") || is_redacted_verbose_req_header(name);
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
    out.append("      --bearer-file <FILE>   Read Bearer token from file (trailing CR/LF trimmed)\n");
    out.append("  -u, --user <USER:PASS>     Set RFC 7616 Digest / Basic credentials\n");
    out.append("      --user-file <FILE>     Read USER:PASS credentials from file (CR/LF trimmed)\n");
    out.append("  -x, --proxy <URL>          Use HTTP CONNECT or SOCKS5/5h proxy (or HTTPS_PROXY env)\n");
    out.append("      --noproxy <HOSTS>      Comma-separated proxy bypass list (or NO_PROXY env)\n");
    out.append("      --resolve <H:P:IP>     Pin host:port to IPv4 in wing's in-memory DNS cache\n");
    out.append("  -m, --max-time <SEC>       Maximum transfer timeout in seconds (--timeout for ms)\n");
    out.append("      --max-redirs <N>       Maximum number of redirects to follow (default: 10)\n");
    out.append("      --retry <N>            Enable automatic retry on 5xx / transient errors\n");
    out.append("      --h2c                  Use HTTP/2 Prior Knowledge (RFC 9113)\n");
    out.append("      --http1.1              Force HTTP/1.1 ALPN negotiation\n");
    out.append("      --compressed           Request compressed response (zstd, br, gzip; default)\n");
    out.append("      --ssrf-guard           Enable SSRF guard (use --allow-loopback for localhost)\n");
    out.append("      --allow-loopback       Allow loopback targets when --ssrf-guard is enabled\n");
    out.append("  -k, --insecure             Skip TLS certificate verification\n");
    out.append("      --cacert <FILE>        CA certificate PEM file to verify peer against\n");
    out.append("  -L, --location             Follow redirects (default; use --no-follow to disable)\n");
    out.append("  -f, --fail                 Return exit code 22 on HTTP status >= 400\n");
    out.append("  -s, --silent               Suppress progress/error diagnostics\n");
    out.append("  -w, --write-out <FMT>      Print metadata (%{http_code}, %{size_download}, %{size_upload},\n");
    out.append("                             %{time_total}, %{url_effective}, %{redirect_url}, %{scheme})\n");
    out.append("  -i, --include              Print response status line and headers\n");
    out.append("  -v, --verbose              Print request, JA4/Akamai fingerprints, timings, and headers\n");
    out.append("      --raw                  Disable terminal control/Bidi escaping on output\n");
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
    sess: const client::Client&,
    req:  const http::Request&,
) {
    var out: u8[>..] = [];
    let nc = cfg.no_color;
    let ja4_fp = sess.ja4();
    let ak_hash = sess.akamai_hash();

    out.append(c_seq(ANSI_DIM, nc));
    out.append("* Profile: ");
    sanitize_terminal_text(sess.profile.name(), out);
    out.append(" | JA4: ");
    sanitize_terminal_text(ja4_fp[..], out);
    out.append(" | Akamai-H2: ");
    sanitize_terminal_text(ak_hash[..], out);
    out.push('\n');
    out.append("> ");
    sanitize_terminal_text(req.method[..], out);
    out.push(' ');
    sanitize_terminal_text(req.url[..], out);
    out.push('\n');
    for &e in req.headers.entries {
        let h_name = req.headers.entry_name(e);
        out.append("> ");
        sanitize_terminal_text(h_name, out);
        out.append(": ");
        if http::is_sensitive(e) || is_redacted_verbose_req_header(h_name) {
            out.append("<redacted>");
        } else {
            sanitize_terminal_text(req.headers.entry_value(e), out);
        }
        out.push('\n');
    }
    out.append(c_seq(ANSI_RESET, nc));
    write_stderr(out);
}

fn append_write_out_numeric_var<B>(
    var_name:   const u8[:],
    req:        const http::Request&,
    res:        const http::Response&,
    elapsed_ms: u64,
    out:        B&,
) {
    if var_name == "http_code" || var_name == "response_code" {
        res.status_code.format_i64_dec(out);
    } else if var_name == "size_download" {
        res.body.len.format_i64_dec(out);
    } else if var_name == "size_upload" {
        req.body.len.format_i64_dec(out);
    } else if var_name == "size_header" {
        res.headers.raw_buf.len.format_i64_dec(out);
    } else if var_name == "num_redirects" {
        res.redirect_count.format_i64_dec(out);
    } else if var_name == "num_headers" {
        res.headers.entries.len.format_i64_dec(out);
    } else if core::starts_with(var_name, "time_") {
        elapsed_ms.format_u64_dec(out);
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
    req:        const http::Request&,
    res:        const http::Response&,
    elapsed_ms: u64,
    raw_output: bool,
    out:        B&,
) {
    append_write_out_numeric_var(var_name, req, res, elapsed_ms, out);
    if var_name == "url_effective" {
        append_cli_text(res.effective_url[..], raw_output, out);
    } else if var_name == "redirect_url" {
        append_cli_text(res.header("location"), raw_output, out);
    } else if var_name == "http_version" {
        append_cli_text(res.protocol[..], raw_output, out);
    } else if var_name == "content_type" {
        append_cli_text(res.header("content-type"), raw_output, out);
    } else if var_name == "scheme" {
        let pu, _ = core::parse_url(res.effective_url[..]);
        append_cli_text(pu.scheme(), raw_output, out);
    }
}

fn format_write_out<B>(
    fmt:        const u8[:],
    req:        const http::Request&,
    res:        const http::Response&,
    elapsed_ms: u64,
    raw_output: bool,
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
            let var_name, after_brace, has_close = rem[2..].split_once_byte('}');
            if has_close && var_name.len > 0 {
                append_write_out_var(var_name, req, res, elapsed_ms, raw_output, out);
                rem = after_brace;
                continue;
            }
        }
        out.push(rem[0]);
        rem = rem[1..];
    }
}

fn append_client_response_headers(
    cfg:        const CliConfig&,
    res:        const http::Response&,
    elapsed_ms: u64,
    out:        u8[>..]&,
) {
    let nc = cfg.no_color;
    let sc_col = status_color(res.status_code, nc);
    out.append(c_seq(ANSI_BOLD, nc));
    append_cli_text(res.protocol[..], cfg.raw_output, out);
    out.push(' ');
    out.append(sc_col);
    res.status_code.format_i64_dec(out);
    out.push(' ');
    out.append(rfc::status_phrase(res.status_code));
    out.append(c_seq(ANSI_RESET, nc));

    if cfg.verbose {
        out.append(c_seq(ANSI_DIM, nc));
        out.append(" (");
        elapsed_ms.format_u64_dec(out);
        out.append(" ms, ");
        res.body.len.format_i64_dec(out);
        out.append(" B");
        if res.redirect_count > 0 {
            out.append(", redirects: ");
            res.redirect_count.format_i64_dec(out);
        }
        out.push(')');
        out.append(c_seq(ANSI_RESET, nc));
    }
    out.push('\n');

    for &e in res.headers.entries {
        let h_name = res.headers.entry_name(e);
        let h_val = res.headers.entry_value(e);
        out.append(c_seq(ANSI_CYAN, nc));
        append_cli_text(h_name, cfg.raw_output, out);
        out.append(c_seq(ANSI_RESET, nc));
        out.append(": ");
        if cfg.verbose && is_redacted_diag_resp_header(h_name) {
            out.append("<redacted>");
        } else {
            append_cli_text(h_val, cfg.raw_output, out);
        }
        out.push('\n');
    }
    out.push('\n');
}

fn print_client_response(
    cfg:        const CliConfig&,
    req:        const http::Request&,
    res:        const http::Response&,
    elapsed_ms: u64,
) {
    var out: u8[>..] = [];
    if cfg.show_headers {
        append_client_response_headers(cfg, res, elapsed_ms, out);
    }

    if cfg.output_file.len == 0 && !cfg.head_only && res.body.len > 0 {
        append_cli_text(res.body[..], cfg.raw_output, out);
        if out.len > 0 && out[out.len - 1] != '\n' { out.push('\n'); }
    }

    if cfg.write_out.len > 0 { format_write_out(cfg.write_out[..], req, res, elapsed_ms, cfg.raw_output, out); }
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
    sanitize_terminal_text(method, out);
    out.append(c_seq(ANSI_RESET, no_color));
    out.push(' ');
    sanitize_terminal_text(url, out);
    out.append(" -> ");
    out.append(status_color(status, no_color));
    status.format_i64_dec(out);
    out.push(' ');
    out.append(rfc::status_phrase(status));
    out.append(c_seq(ANSI_RESET, no_color));
    if note.len > 0 {
        out.append(c_seq(ANSI_DIM, no_color));
        out.append(" (");
        sanitize_terminal_text(note, out);
        out.push(')');
        out.append(c_seq(ANSI_RESET, no_color));
    }
    out.push('\n');
    write_stderr(out);
}
