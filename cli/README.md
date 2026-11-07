# Wing Command-Line Interface (`cli/`)

Command-line HTTP client and programmable test server built on `wing.goose`,
supporting curl-compatible request flags, multipart form uploads, cookie jar
persistence, DNS/proxy overrides, and scenario-driven server responses.

```goose
import wing;

var cfg = CliConfig { .. };
if parse_cli_args(os.args(), cfg) {
    let code = execute_client_cmd(cfg);
}
```

## Submodules

### Entrypoint & Mode Dispatch (`cli/main.goose`)

```goose
const WING_CLI_VERSION: const u8[:] = "wing cli 0.1.0\n"
fn main()
```

Parses command-line arguments via `parse_cli_args` into `CliConfig` and
dispatches `CliMode.Help`, `CliMode.Version`, `CliMode.Client`
(`execute_client_cmd`), or `CliMode.Serve` (`execute_serve_cmd`).

### CLI Flag Parser & Configuration State (`cli/args.goose`)

```goose
enum CliMode { Client, Serve, Help, Version }
struct HeaderPair { .. }
struct ResolveEntry { .. }
struct FormFieldSpec { .. }
struct CliConfig { .. }

fn parse_cli_args<S>(argv: const S[:], cfg: CliConfig&) -> bool
fn step_cli_arg<S>(argv: const S[:], idx: i64&, cfg: CliConfig&) -> bool
fn apply_cli_boolean_flag(arg: const u8[:], cfg: CliConfig&) -> bool
fn apply_cli_string_opt<S>(argv: const S[:], idx: i64&, arg: const u8[:], cfg: CliConfig&) -> bool
fn apply_cli_payload_opt<S>(argv: const S[:], idx: i64&, arg: const u8[:], cfg: CliConfig&) -> bool
fn apply_cli_numeric_opt<S>(argv: const S[:], idx: i64&, arg: const u8[:], cfg: CliConfig&) -> bool
fn finalize_cli_config(cfg: CliConfig&) -> bool
fn parse_header_flag(raw: const u8[:], out_pair: HeaderPair&) -> bool
fn load_headers_from_text(text: const u8[:], cfg: CliConfig&) -> bool
fn apply_header_or_file_flag(val: const u8[:], cfg: CliConfig&) -> bool
fn parse_user_flag(raw: const u8[:], cfg: CliConfig&) -> bool
fn parse_ipv4_be_u32(ip_str: const u8[:]) -> u32, bool
fn normalize_noproxy_host(host: const u8[:]) -> const u8[:]
fn is_host_bypassed_by_no_proxy(host: const u8[:], no_proxy_list: const u8[:]) -> bool
fn parse_resolve_flag(raw: const u8[:], out_entry: ResolveEntry&) -> bool
fn parse_form_flag(raw: const u8[:], out_spec: FormFieldSpec&) -> bool
fn load_data_arg(raw: const u8[:], out_buf: u8[>..]&) -> bool
fn apply_data_urlencode_arg(raw: const u8[:], out_buf: u8[>..]&) -> bool
fn extract_remote_filename(url_str: const u8[:]) -> const u8[:]
fn apply_cookie_arg(val: const u8[:], cfg: CliConfig&)
fn apply_continue_at_opt(val: const u8[:], cfg: CliConfig&) -> bool
fn assign_positional_url(arg: const u8[:], cfg: CliConfig&) -> bool
```

`CliConfig` stores the parsed target URL, HTTP method, bounded `HeaderPair`
entries for `-H` flags, `ResolveEntry` overrides for `--resolve host:port:ip`,
`FormFieldSpec` entries for `-F` multipart fields, body payload, authentication
credentials, timeouts, TLS verification options, proxy settings, cookie jar
paths, and server scenario options. On invalid flag syntax or missing option
values, `parse_cli_args` returns `false`.

### HTTP Client Execution & Multipart Builder (`cli/client.goose`)

```goose
const MULTIPART_BOUNDARY: const u8[:] = "------------------------WingCliFormBoundary7MA4YWxkTrZu0gW"

fn execute_client_cmd(cfg: const CliConfig&) -> i64
fn build_cli_request(cfg: const CliConfig&, req: wing::Request&, out_resume_off: i64&) -> bool
fn apply_basic_auth_header(cfg: const CliConfig&, req: wing::Request&)
fn apply_range_and_referer_headers(cfg: const CliConfig&, req: wing::Request&, out_resume_off: i64&) -> bool
fn build_multipart_form_body(cfg: const CliConfig&, req: wing::Request&) -> bool
fn apply_resolve_overrides(cfg: const CliConfig&, client: wing::Client&)
fn resolve_effective_proxy(cfg: const CliConfig&, target_url: const u8[:]) -> const u8[:]
fn infer_upload_mime_type(filename: const u8[:]) -> const u8[:]
fn append_multipart_field_part(spec: const FormFieldSpec&, body: u8[>..]&) -> bool
fn report_cli_error(cfg: const CliConfig&, msg: const u8[:])
fn write_cli_output_file(path: const u8[:], data: const u8[:], append_mode: bool) -> bool
fn write_dump_headers_file(path: const u8[:], resp: const wing::Response&) -> bool
fn load_and_save_cookie_jars(cfg: const CliConfig&, sess: wing::Session&, is_save: bool)
```

`execute_client_cmd` configures `wing::Client` options (redirect policy,
connect/read timeouts, TLS verification, custom CA PEM, proxy, DNS `--resolve`
overrides, and cookie jar), populates `wing::Request` via `build_cli_request`,
sends the request over a `wing::Session`, writes response output to a file or
standard output, and persists updated cookies.

### Programmable HTTP Server (`cli/server.goose`)

```goose
fn execute_serve_cmd(cfg: const CliConfig&) -> i64
fn load_serve_rules(cfg: const CliConfig&, stage: ProgrammableServerStage&) -> i64
fn wing::on_server_stage(stage: ProgrammableServerStage&, phase: wire::ServerHookPhase, _cfg: wing::ServerPipelineConfig&, req: const wing::Request&, _ctx: wing::ServerStageCtx&, res: wing::Response&) -> wire::StageVerdict
```

`execute_serve_cmd` initializes a listener with `wing::new_http_server`, loads
inline `--route` definitions and `--scenario` files via `load_serve_rules` into
`ProgrammableServerStage`, and serves connections using
`wing::serve_http_connection_on_listener_buf`. During request processing,
`wing::on_server_stage` evaluates active scenario rules and built-in `httpbin`
routes, then logs each exchange via `log_server_exchange`.

### Scenario Rule DSL & Built-in `httpbin` Routes (`cli/rules.goose`)

```goose
struct RouteRule { .. }
struct ProgrammableServerStage { .. }

fn parse_route_rule_line(line: const u8[:], out_rule: RouteRule&) -> bool
fn load_scenario_text(text: const u8[:], stage: ProgrammableServerStage&) -> i64
fn eval_programmable_server_stage(stage: ProgrammableServerStage&, req: wing::Request&, resp: wing::Response&)
fn apply_matched_scenario_rule(rule: RouteRule&, resp: wing::Response&)
fn handle_builtin_httpbin(req: wing::Request&, resp: wing::Response&) -> bool
fn handle_httpbin_status_or_redirect(path: const u8[:], resp: wing::Response&) -> bool
fn handle_httpbin_range_or_bytes(path: const u8[:], req: const wing::Request&, resp: wing::Response&) -> bool
fn handle_httpbin_auth_routes(path: const u8[:], req: const wing::Request&, resp: wing::Response&) -> bool
fn handle_httpbin_dynamic_routes(path: const u8[:], req: wing::Request&, resp: wing::Response&) -> bool
fn build_httpbin_reflection_json(req: const wing::Request&, peer_ip: const u8[:], out: u8[>..]&)
fn build_httpbin_headers_json(req: const wing::Request&, out: u8[>..]&)
fn seed_inline_cookies_to_jar(jar: wing::CanonicalCookieJar&, req_url: const u8[:], cookie_hdr: const u8[:], now_us: i64)
```

`RouteRule` represents a bounded `<METHOD> <PATH> <STATUS> [Header:Val...]
[body=<TEXT>]` rule, and `ProgrammableServerStage` tracks per-rule hit counters.
`eval_programmable_server_stage` matches incoming requests against loaded
`RouteRule` entries (`apply_matched_scenario_rule`) or falls back to
`handle_builtin_httpbin` when `--httpbin` is enabled.

### Terminal Formatting, ANSI Colors & `--write-out` (`cli/term.goose`)

```goose
const ANSI_RESET: const u8[:]
const ANSI_BOLD: const u8[:]
const ANSI_DIM: const u8[:]
const ANSI_GREEN: const u8[:]
const ANSI_YELLOW: const u8[:]
const ANSI_RED: const u8[:]
const ANSI_CYAN: const u8[:]
const ANSI_BLUE: const u8[:]

fn status_color(code: i32, no_color: bool) -> const u8[:]
fn c_seq(seq: const u8[:], no_color: bool) -> const u8[:]
fn print_help(no_color: bool)
fn print_client_verbose_request(cfg: const CliConfig&, req: const wing::Request&, out: u8[..65536]&)
fn format_write_out(fmt_str: const u8[:], resp: const wing::Response&, effective_url: const u8[:], out: u8[..65536]&)
fn print_client_response(cfg: const CliConfig&, req: const wing::Request&, resp: const wing::Response&, body_view: const u8[:])
fn log_server_exchange(req: const wing::Request&, resp: const wing::Response&, no_color: bool)
```

Formats terminal diagnostics, verbose request headers, `--write-out` template
variables into 64 KiB stack buffers (`u8[..65536]`), and colorized status lines.
