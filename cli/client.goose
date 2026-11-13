// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Client command execution engine (`wing <URL>`) over `wing::Client`.
import std;
import os;
import core from "..";
import wing from "..";
import args;
import rules;
import term;

const MULTIPART_BOUNDARY: const u8[:] = "------------------------WingFormBoundary7MA4YWxkTrZu0gW";

fn apply_resolve_overrides(sess: wing::Client&, cfg: const CliConfig&) {
    let now_sec = core::micros(max(0, sess.virtual_clock_us)).as_secs();
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
            let _ = entry.ipv4_hints.try_push(ip4);
            sess.dns_cache.dns_cache_insert(entry);
        }
    }
}

fn resolve_effective_proxy(cfg: const CliConfig&) -> u8[..256] {
    var out_proxy: u8[..256] = [];
    let parsed_u, _ = core::parse_url(cfg.url[..]);
    let host = parsed_u.hostname();
    let is_https = parsed_u.is_secure_scheme();

    var noproxy_buf: u8[>..] = [];
    if cfg.no_proxy.len > 0 {
        noproxy_buf.append(cfg.no_proxy[..]);
    } else if !env("NO_PROXY", noproxy_buf) {
        let _ = env("no_proxy", noproxy_buf);
    }

    if is_host_bypassed_by_no_proxy(host, noproxy_buf[..]) {
        return out_proxy;
    }

    if cfg.proxy_url.len > 0 {
        let _ = out_proxy.try_set(cfg.proxy_url[..]);
        return out_proxy;
    }

    var env_p: u8[>..] = [];
    let found_scheme_proxy = if is_https {
        env("HTTPS_PROXY", env_p) || env("https_proxy", env_p)
    } else {
        env("HTTP_PROXY", env_p) || env("http_proxy", env_p)
    };
    if found_scheme_proxy {
        let _ = out_proxy.try_set(env_p[..]);
        return out_proxy;
    }
    env_p.clear();
    if env("ALL_PROXY", env_p) || env("all_proxy", env_p) {
        let _ = out_proxy.try_set(env_p[..]);
    }
    return out_proxy;
}

fn infer_upload_mime_type(filename: const u8[:], explicit_ct: const u8[:]) -> const u8[:] {
    if explicit_ct.len > 0 { return explicit_ct; }
    if filename.ends_with_fold(".json") { return "application/json"; }
    if filename.ends_with_fold(".txt") || filename.ends_with_fold(".md") { return "text/plain"; }
    if filename.ends_with_fold(".html") || filename.ends_with_fold(".htm") { return "text/html"; }
    if filename.ends_with_fold(".png") { return "image/png"; }
    if filename.ends_with_fold(".jpg") || filename.ends_with_fold(".jpeg") { return "image/jpeg"; }
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
    var disp: u8[..1024] = [];
    let fn_slice = if f.filename.len > 0 { f.filename[..] } else { "" };
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
        let ok_read = if f.value[..] == "-" {
            read_stdin(f_bytes);
            true
        } else {
            read_file(f.value[..], f_bytes)
        };
        guard ok_read else {
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
    let _ = ct_hdr.try_append(MULTIPART_BOUNDARY);
    req.set_header("Content-Type", ct_hdr[..]);
    req.set_stream_body(body_out[..], true);
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
        out_resume_off.format_i64_dec(r_hdr);
        let _ = r_hdr.try_push('-');
        req.set_header("Range", r_hdr[..]);
    } else if cfg.range_spec.len > 0 {
        var r_hdr: u8[..160] = [];
        if cfg.range_spec[..].starts_with_fold("bytes=") {
            let _ = r_hdr.try_set(cfg.range_spec[..]);
        } else {
            let _ = r_hdr.try_set("bytes=");
            let _ = r_hdr.try_append(cfg.range_spec[..]);
        }
        req.set_header("Range", r_hdr[..]);
    }

    if cfg.referer.len > 0 {
        req.set_header("Referer", cfg.referer[..]);
    }
}

fn apply_basic_auth_header(cfg: const CliConfig&, req: wing::Request&) {
    var raw_cred: u8[..160] = [];
    let _ = raw_cred.try_set(cfg.basic_user[..]);
    let _ = raw_cred.try_push(':');
    let _ = raw_cred.try_append(cfg.basic_pass[..]);
    var b64_cred: u8[..256] = [];
    core::base64_encode(raw_cred[..], b64_cred);
    core::secure_zeroize_slice(raw_cred[..]);
    var auth_hdr: u8[..320] = "Basic ";
    let _ = auth_hdr.try_append(b64_cred[..]);
    core::secure_zeroize_slice(b64_cred[..]);
    req.sensitive_header("Authorization", auth_hdr[..]);
    core::secure_zeroize_slice(auth_hdr[..]);
}

fn build_cli_request(cfg: const CliConfig&, req: wing::Request&, out_resume_off: i64&) -> bool {
    req = wing::new_request(cfg.method[..], cfg.url[..]);
    if cfg.bearer_token.len > 0 {
        req.bearer(cfg.bearer_token[..]);
    } else if cfg.basic_user.len > 0 {
        apply_basic_auth_header(cfg, req);
    }
    if cfg.form_fields.len > 0 {
        guard build_multipart_form_body(cfg, req) else { return false; }
    } else if cfg.has_body {
        req.text(cfg.body[..]);
    }
    if cfg.user_agent.len > 0 {
        req.set_header("User-Agent", cfg.user_agent[..]);
    }
    if cfg.cookie_header.len > 0 {
        req.set_header("Cookie", cfg.cookie_header[..]);
    }
    apply_range_and_referer_headers(cfg, req, out_resume_off);
    for &h in cfg.headers {
        req.set_header(h.name[..], h.value[..]);
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
    guard cfg.output_file.len > 0 && !(cfg.fail_on_error && res.status_code >= 400) else {
        return true;
    }
    if resume_off > 0 && res.status_code == 206 {
        if append_file(cfg.output_file[..], res.body[..]) {
            return true;
        }
        if !cfg.silent {
            write_stderr(str("wing: failed to append to output file: ", cfg.output_file[..], "\n"));
        }
        return false;
    }
    if resume_off > 0 && res.status_code != 200 {
        return res.status_code == 416 || res.status_code >= 400;
    }
    if write_file(cfg.output_file[..], res.body[..]) {
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
    res.status_code.format_i64_dec(dump);
    dump.push(' ');
    dump.append(rfc::status_phrase(res.status_code));
    dump.append("\r\n");
    for &e in res.headers.entries {
        dump.append(res.headers.entry_name(e));
        dump.append(": ");
        dump.append(res.headers.entry_value(e));
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
    if save_phase {
        guard cfg.cookie_jar_out.len > 0 else { return; }
        var out_jar: u8[>..] = [];
        sess.jar.export_netscape(out_jar);
        if cfg.cookie_jar_out[..] == "-" {
            write_stdout(out_jar);
        } else {
            let _ = write_file(cfg.cookie_jar_out[..], out_jar);
        }
        return;
    }
    if cfg.cookie_jar_in.len > 0 && file_exists(cfg.cookie_jar_in[..]) {
        var raw_jar: u8[>..] = [];
        if read_file(cfg.cookie_jar_in[..], raw_jar) {
            let _ = sess.jar.import_netscape(raw_jar[..], sess.virtual_clock_us);
        }
    }
    seed_inline_cookies_to_jar(sess.jar, cfg.url[..], cfg.cookie_header[..], sess.virtual_clock_us);
    for &h in cfg.headers {
        if h.name[..].eq_ascii_fold("Cookie") {
            seed_inline_cookies_to_jar(sess.jar, cfg.url[..], h.value[..], sess.virtual_clock_us);
        }
    }
}

fn execute_client_cmd(cfg: const CliConfig&) -> i64 {
    let eff_proxy = resolve_effective_proxy(cfg);

    var sess = wing::new_client(wing::ClientConfig {
        profile:              if cfg.raw_profile { wing::Profile.None } else { wing::Profile.Wing },
        proxy_url:            eff_proxy[..],
        timeout_ms:           cfg.timeout_ms,
        follow_redirects:     cfg.follow_redirects,
        cookie_jar:           true,
        insecure_skip_verify: cfg.insecure_tls,
        ..
    });
    defer sess.close();
    let real_now_us = core::now().unix_micro();
    if real_now_us > 0 {
        sess.virtual_clock_us = real_now_us;
    }

    sess.ssrf_guard.enabled = false;
    sess.max_redirects = cfg.max_redirects;
    if cfg.insecure_tls { sess.enable_hsts = false; }
    if cfg.cacert_file.len > 0 {
        var ca_pem: u8[>..] = [];
        guard read_file(cfg.cacert_file[..], ca_pem) else {
            write_stderr(str("wing: cannot read cacert file: ", cfg.cacert_file[..], "\n"));
            return 77;
        }
        let _, ok_ca = wing::add_trust_anchors_pem(sess.trust_store, ca_pem[..]);
        if !ok_ca {
            write_stderr(str("wing: invalid CA PEM bundle: ", cfg.cacert_file[..], "\n"));
            return 77;
        }
    }
    sess.http2_prior_knowledge = cfg.http2_prior;
    if cfg.http1_1_only {
        let _ = sess.profile_spec.tls.alpn.try_set("http/1.1");
    }
    if !cfg.compressed {
        let _ = sess.default_headers.remove_header("Accept-Encoding");
        sess.profile_spec.accept_encoding.clear();
    }

    apply_resolve_overrides(sess, cfg);
    load_and_save_cookie_jars(sess, cfg, false);

    if cfg.max_retries > 0 {
        let _ = sess.add_app_retry(cfg.max_retries, true);
    }
    if cfg.basic_user.len > 0 {
        sess.set_credentials(cfg.basic_user[..], cfg.basic_pass[..]);
    }

    var req = wing::Request { .. };
    var resume_off: i64 = 0;
    guard build_cli_request(cfg, req, resume_off) else { return 2; }

    if cfg.verbose && !cfg.silent {
        print_client_verbose_request(cfg, sess, req);
    }

    let t0_ns = core::monotonic_now().as_nanos();
    let res, err = sess.do(req);
    let t1_ns = core::monotonic_now().as_nanos();
    let delta_ns = (core::sub_sat_u64(t1_ns, t0_ns) & 0x7FFFFFFFFFFFFFFF) as i64;
    let elapsed_ms = max(0, core::nanos(delta_ns).as_millis()) as u64;

    if !err.ok() {
        report_cli_error(cfg, err);
        return 1;
    }

    load_and_save_cookie_jars(sess, cfg, true);
    if !write_dump_headers_file(cfg, res) && !cfg.silent {
        write_stderr(str("wing: failed to write dump header file: ", cfg.dump_header_file[..], "\n"));
    }
    guard write_cli_output_file(cfg, res, resume_off) else { return 1; }

    print_client_response(cfg, req, res, elapsed_ms);

    if cfg.fail_on_error && res.status_code >= 400 {
        return 22;
    }
    return 0;
}
