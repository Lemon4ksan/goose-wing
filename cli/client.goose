// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Client command execution engine (`wing <URL>`) over `wing::Client`.
import std;
import os;
import core from "..";
import wing from "..";
import args;
import term;

const MULTIPART_BOUNDARY: const u8[:] = "------------------------WingFormBoundary7MA4YWxkTrZu0gW";

// Parses a dotted-quad IPv4 string into a big-endian u32 for `wing::DnsCacheEntry`.
//
// Example:
//   raw = "127.0.0.1"
//   returns: 0x7F000001, true
fn parse_ipv4_be_u32(raw: const u8[:]) -> u32, bool {
    var acc: u64 = 0;
    var rem = raw;
    for part_idx in 4 {
        var part = rem;
        if part_idx < 3 {
            let dot = core::index_of_byte(rem, '.');
            guard dot > 0 else { return 0, false; }
            let next_start = core::add_sat_i64(dot, 1);
            part = rem[..dot];
            rem = rem[next_start..];
        } else {
            rem = rem[rem.len..];
        }
        let oct, ok = core::parse_u64_dec(part);
        guard ok && oct <= 255 else { return 0, false; }
        acc = (core::shl_sat_u64(acc, 8) | oct) & 0xFFFFFFFF;
    }
    return acc as u32, rem.len == 0;
}

fn apply_resolve_overrides(sess: wing::Client&, cfg: const CliConfig&) {
    let now_sec = core::as_secs(core::micros(max(0, sess.virtual_clock_us)));
    for &r in cfg.resolves {
        let ip4, ok_ip = parse_ipv4_be_u32(r.ip[..]);
        if ok_ip {
            var entry = wing::DnsCacheEntry {
                qtype:           1, // DNS_QTYPE_A
                inserted_at_sec: now_sec,
                ttl_sec:         3600,
                valid:           true,
                ..
            };
            let _ = entry.domain.try_set(r.host[..]);
            entry.ipv4_hints.push(ip4);
            wing::dns_cache_insert(sess.dns_cache, entry);
        }
    }
}

fn host_matches_noproxy_token(host: const u8[:], token: const u8[:]) -> bool {
    let clean = core::trim_lws(token);
    guard clean.len > 0 else { return false; }
    if clean == "*" { return true; }
    let dom = if clean[0] == '.' { clean[1..] } else { clean };
    if core::eq_ascii_fold(host, dom) { return true; }
    if host.len > dom.len {
        let suffix_start = core::sub_sat_i64(host.len, dom.len);
        let dot_pos = core::sub_sat_i64(suffix_start, 1);
        if host[dot_pos] == '.' && core::eq_ascii_fold(host[suffix_start..], dom) {
            return true;
        }
    }
    return false;
}

fn is_host_bypassed_by_no_proxy(host: const u8[:], no_proxy_list: const u8[:]) -> bool {
    guard host.len > 0 && no_proxy_list.len > 0 else { return false; }
    var rem = no_proxy_list;
    while rem.len > 0 {
        let c_idx = core::index_of_byte(rem, ',');
        let item = if c_idx >= 0 { rem[..c_idx] } else { rem };
        rem = if c_idx >= 0 { rem[core::add_sat_i64(c_idx, 1)..] } else { rem[rem.len..] };
        if host_matches_noproxy_token(host, item) {
            return true;
        }
    }
    return false;
}

fn resolve_effective_proxy(cfg: const CliConfig&, out_proxy: u8[..256]&) {
    out_proxy.clear();
    let parsed_u, _ = core::parse_url(cfg.url[..]);
    let host = core::hostname(parsed_u);
    let is_https = core::is_secure_scheme(parsed_u);

    var noproxy_buf: u8[>..] = [];
    if cfg.no_proxy.len > 0 {
        noproxy_buf.append(cfg.no_proxy[..]);
    } else if !env("NO_PROXY", noproxy_buf) {
        let _ = env("no_proxy", noproxy_buf);
    }

    if is_host_bypassed_by_no_proxy(host, noproxy_buf[..]) {
        return;
    }

    if cfg.proxy_url.len > 0 {
        let _ = out_proxy.try_set(cfg.proxy_url[..]);
        return;
    }

    var env_p: u8[>..] = [];
    if is_https {
        if env("HTTPS_PROXY", env_p) || env("https_proxy", env_p) {
            let _ = out_proxy.try_set(env_p[..]);
            return;
        }
    } else {
        if env("HTTP_PROXY", env_p) || env("http_proxy", env_p) {
            let _ = out_proxy.try_set(env_p[..]);
            return;
        }
    }
    env_p.clear();
    if env("ALL_PROXY", env_p) || env("all_proxy", env_p) {
        let _ = out_proxy.try_set(env_p[..]);
    }
}

fn infer_upload_mime_type(filename: const u8[:], explicit_ct: const u8[:]) -> const u8[:] {
    if explicit_ct.len > 0 { return explicit_ct; }
    if core::ends_with_fold(filename, ".json") { return "application/json"; }
    if core::ends_with_fold(filename, ".txt") || core::ends_with_fold(filename, ".md") { return "text/plain"; }
    if core::ends_with_fold(filename, ".html") || core::ends_with_fold(filename, ".htm") { return "text/html"; }
    if core::ends_with_fold(filename, ".png") { return "image/png"; }
    if core::ends_with_fold(filename, ".jpg") || core::ends_with_fold(filename, ".jpeg") { return "image/jpeg"; }
    return "application/octet-stream";
}

fn append_multipart_field_part(
    f:        const FormFieldSpec&,
    silent:   bool,
    body_out: u8[>..]&,
) -> bool {
    body_out.append("--");
    body_out.append(MULTIPART_BOUNDARY);
    body_out.append("\r\nContent-Disposition: ");
    var disp: u8[..512] = [];
    let fn_slice = if f.is_file { f.filename[..] } else { "" };
    guard wing::format_content_disposition(f.name[..], fn_slice, disp) else { return false; }
    body_out.append(disp[..]);
    body_out.append("\r\n");

    if f.is_file || f.content_type.len > 0 {
        let ct = infer_upload_mime_type(f.filename[..], f.content_type[..]);
        body_out.append("Content-Type: ");
        body_out.append(ct);
        body_out.append("\r\n");
    }
    body_out.append("\r\n");

    if f.is_file {
        var f_bytes: u8[>..] = [];
        guard read_file(f.value[..], f_bytes) else {
            if !silent {
                write_stderr(str("wing: cannot read form file: ", f.value[..], "\n"));
            }
            return false;
        }
        body_out.append(f_bytes[..]);
    } else {
        body_out.append(f.value[..]);
    }
    body_out.append("\r\n");
    return true;
}

fn build_multipart_form_body(cfg: const CliConfig&, req: wing::Request&) -> bool {
    var body_out: u8[>..] = [];
    for &f in cfg.form_fields {
        guard append_multipart_field_part(f, cfg.silent, body_out) else { return false; }
    }
    body_out.append("--");
    body_out.append(MULTIPART_BOUNDARY);
    body_out.append("--\r\n");

    var ct_hdr: u8[..128] = "multipart/form-data; boundary=";
    ct_hdr.append(MULTIPART_BOUNDARY);
    wing::set_header(req, "Content-Type", ct_hdr[..]);
    wing::set_stream_body(req, body_out[..], true);
    return true;
}

fn apply_range_and_referer_headers(cfg: const CliConfig&, req: wing::Request&, out_resume_off: i64&) {
    out_resume_off = cfg.resume_from;
    if cfg.auto_resume && cfg.output_file.len > 0 && file_exists(cfg.output_file[..]) {
        var existing: u8[>..] = [];
        if read_file(cfg.output_file[..], existing) {
            out_resume_off = existing.len;
        }
    }

    if out_resume_off > 0 {
        var r_hdr: u8[..64] = "bytes=";
        core::format_i64_dec(out_resume_off, r_hdr);
        r_hdr.push('-');
        wing::set_header(req, "Range", r_hdr[..]);
    } else if cfg.range_spec.len > 0 {
        var r_hdr: u8[..160] = [];
        if core::starts_with_fold(cfg.range_spec[..], "bytes=") {
            let _ = r_hdr.try_set(cfg.range_spec[..]);
        } else {
            r_hdr.append("bytes=");
            let _ = r_hdr.try_append(cfg.range_spec[..]);
        }
        wing::set_header(req, "Range", r_hdr[..]);
    }

    if cfg.referer.len > 0 {
        wing::set_header(req, "Referer", cfg.referer[..]);
    }
}

fn apply_basic_auth_header(cfg: const CliConfig&, req: wing::Request&) {
    var raw_cred: u8[..160] = [];
    raw_cred.append(cfg.basic_user[..]);
    raw_cred.push(':');
    raw_cred.append(cfg.basic_pass[..]);
    var b64_cred: u8[..256] = [];
    core::base64_encode(raw_cred[..], b64_cred);
    var auth_hdr: u8[..320] = "Basic ";
    auth_hdr.append(b64_cred[..]);
    wing::sensitive_header(req, "Authorization", auth_hdr[..]);
}

fn build_cli_request(cfg: const CliConfig&, req: wing::Request&, out_resume_off: i64&) -> bool {
    req = wing::new_request(cfg.method[..], cfg.url[..]);
    if cfg.bearer_token.len > 0 {
        wing::bearer(req, cfg.bearer_token[..]);
    } else if cfg.basic_user.len > 0 {
        apply_basic_auth_header(cfg, req);
    }
    if cfg.form_fields.len > 0 {
        guard build_multipart_form_body(cfg, req) else { return false; }
    } else if cfg.has_body {
        wing::text(req, cfg.body[..]);
    }
    if cfg.user_agent.len > 0 {
        wing::set_header(req, "User-Agent", cfg.user_agent[..]);
    }
    if cfg.cookie_header.len > 0 {
        wing::set_header(req, "Cookie", cfg.cookie_header[..]);
    }
    apply_range_and_referer_headers(cfg, req, out_resume_off);
    for &h in cfg.headers {
        wing::set_header(req, h.name[..], h.value[..]);
    }
    return true;
}

fn report_cli_error(cfg: const CliConfig&, err: const wing::Error&) {
    if !cfg.silent {
        var err_out: u8[>..] = [];
        err_out.append("wing: (");
        err_out.append(err.stage[..]);
        err_out.append(") ");
        err_out.append(err.message[..]);
        err_out.push('\n');
        write_stderr(err_out);
    }
}

fn write_cli_output_file(cfg: const CliConfig&, res: const wing::Response&, resume_off: i64) -> bool {
    if cfg.output_file.len == 0 {
        return true;
    }
    let ok_w = if resume_off > 0 && res.status_code == 206 {
        append_file(cfg.output_file[..], res.body[..])
    } else {
        write_file(cfg.output_file[..], res.body[..])
    };
    if ok_w {
        return true;
    }
    if !cfg.silent {
        write_stderr(str("wing: failed to write output file: ", cfg.output_file[..], "\n"));
    }
    return false;
}

fn write_dump_headers_file(cfg: const CliConfig&, res: const wing::Response&) -> bool {
    guard cfg.dump_header_file.len > 0 else { return true; }
    var dump: u8[>..] = [];
    dump.append(res.protocol[..]);
    dump.push(' ');
    core::format_i64_dec(res.status_code, dump);
    dump.push(' ');
    dump.append(rfc::status_phrase(res.status_code));
    dump.append("\r\n");
    for &e in res.headers.entries {
        dump.append(wing::entry_name(res.headers, e));
        dump.append(": ");
        dump.append(wing::entry_value(res.headers, e));
        dump.append("\r\n");
    }
    dump.append("\r\n");
    if cfg.dump_header_file[..] == "-" {
        write_stdout(dump);
        return true;
    }
    return write_file(cfg.dump_header_file[..], dump);
}

fn load_and_save_cookie_jars(sess: wing::Client&, cfg: const CliConfig&, save_phase: bool) {
    if !save_phase {
        if cfg.cookie_jar_in.len > 0 && file_exists(cfg.cookie_jar_in[..]) {
            var raw_jar: u8[>..] = [];
            if read_file(cfg.cookie_jar_in[..], raw_jar) {
                let _ = wing::import_netscape(sess.jar, raw_jar[..], sess.virtual_clock_us);
            }
        }
        return;
    }
    if cfg.cookie_jar_out.len > 0 {
        var out_jar: u8[>..] = [];
        wing::export_netscape(sess.jar, out_jar);
        if cfg.cookie_jar_out[..] == "-" {
            write_stdout(out_jar);
        } else {
            let _ = write_file(cfg.cookie_jar_out[..], out_jar);
        }
    }
}

fn execute_client_cmd(cfg: const CliConfig&) -> i64 {
    var eff_proxy: u8[..256] = [];
    resolve_effective_proxy(cfg, eff_proxy);

    var sess = wing::new_client(wing::ClientConfig {
        profile:              if cfg.raw_profile { wing::Profile.None } else { wing::Profile.Wing },
        proxy_url:            eff_proxy[..],
        timeout_ms:           cfg.timeout_ms,
        follow_redirects:     cfg.follow_redirects,
        cookie_jar:           true,
        insecure_skip_verify: cfg.insecure_tls,
        ..
    });
    defer wing::close(sess);

    sess.ssrf_guard.enabled = false;
    sess.max_redirects = cfg.max_redirects;
    if cfg.insecure_tls { sess.enable_hsts = false; }
    sess.http2_prior_knowledge = cfg.http2_prior;
    if cfg.http1_1_only {
        sess.profile_spec.tls.alpn.clear();
        sess.profile_spec.tls.alpn.append("http/1.1");
    }
    if !cfg.compressed {
        let _ = wing::remove_header(sess.default_headers, "Accept-Encoding");
        sess.profile_spec.accept_encoding.clear();
    }

    apply_resolve_overrides(sess, cfg);
    load_and_save_cookie_jars(sess, cfg, false);

    if cfg.max_retries > 0 {
        let _ = wing::add_app_retry(sess, cfg.max_retries, true);
    }
    if cfg.basic_user.len > 0 {
        wing::set_credentials(sess, cfg.basic_user[..], cfg.basic_pass[..]);
    }

    var req = wing::Request { .. };
    var resume_off: i64 = 0;
    guard build_cli_request(cfg, req, resume_off) else { return 2; }

    if cfg.verbose && !cfg.silent {
        print_client_verbose_request(cfg, sess, req);
    }

    let t0_ns = core::as_nanos(core::monotonic_now());
    let res, err = wing::do(sess, req);
    let t1_ns = core::as_nanos(core::monotonic_now());
    let delta_ns = (core::sub_sat_u64(t1_ns, t0_ns) & 0x7FFFFFFFFFFFFFFF) as i64;
    let elapsed_ms = max(0, core::as_millis(core::nanos(delta_ns))) as u64;

    if !wing::ok(err) {
        report_cli_error(cfg, err);
        return 1;
    }

    load_and_save_cookie_jars(sess, cfg, true);
    let _ = write_dump_headers_file(cfg, res);
    guard write_cli_output_file(cfg, res, resume_off) else { return 1; }

    print_client_response(cfg, req, res, elapsed_ms);

    if cfg.fail_on_error && res.status_code >= 400 {
        return 22;
    }
    return 0;
}
