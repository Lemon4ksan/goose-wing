// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Client command execution engine (`wing <URL>`) over `wing::Client`.
import std;
import os;
import core from "..";
import wing from "..";
import args;
import term;

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

fn build_cli_request(cfg: const CliConfig&) -> wing::Request {
    var req = wing::new_request(cfg.method[..], cfg.url[..]);
    if cfg.bearer_token.len > 0 {
        wing::bearer(req, cfg.bearer_token[..]);
    }
    if cfg.has_body {
        wing::text(req, cfg.body[..]);
    }
    if cfg.user_agent.len > 0 {
        wing::set_header(req, "User-Agent", cfg.user_agent[..]);
    }
    if cfg.cookie_header.len > 0 {
        wing::set_header(req, "Cookie", cfg.cookie_header[..]);
    }
    for &h in cfg.headers {
        wing::set_header(req, h.name[..], h.value[..]);
    }
    return req;
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

fn write_cli_output_file(cfg: const CliConfig&, body: const u8[:]) -> bool {
    if cfg.output_file.len == 0 {
        return true;
    }
    if write_file(cfg.output_file[..], body) {
        return true;
    }
    if !cfg.silent {
        var f_err: u8[>..] = [];
        f_err.append("wing: failed to write output file: ");
        f_err.append(cfg.output_file[..]);
        f_err.push('\n');
        write_stderr(f_err);
    }
    return false;
}

fn execute_client_cmd(cfg: const CliConfig&) -> i64 {
    var sess = wing::new_client(wing::ClientConfig {
        profile:              if cfg.raw_profile { wing::Profile.None } else { wing::Profile.Wing },
        proxy_url:            cfg.proxy_url[..],
        timeout_ms:           cfg.timeout_ms,
        follow_redirects:     cfg.follow_redirects,
        cookie_jar:           true,
        insecure_skip_verify: cfg.insecure_tls,
        ..
    });
    defer wing::close(sess);

    // Allow localhost / loopback test servers in CLI tool mode
    sess.ssrf_guard.enabled = false;
    if cfg.insecure_tls {
        sess.enable_hsts = false;
    }
    sess.http2_prior_knowledge = cfg.http2_prior;

    apply_resolve_overrides(sess, cfg);

    if cfg.max_retries > 0 {
        let _ = wing::add_app_retry(sess, cfg.max_retries, true);
    }

    if cfg.basic_user.len > 0 {
        wing::set_credentials(sess, cfg.basic_user[..], cfg.basic_pass[..]);
    }

    var req = build_cli_request(cfg);

    if cfg.verbose && !cfg.silent {
        print_client_verbose_request(cfg, sess);
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

    guard write_cli_output_file(cfg, res.body[..]) else {
        return 1;
    }

    print_client_response(cfg, res, elapsed_ms);

    if cfg.fail_on_error && res.status_code >= 400 {
        return 22; // curl exit code 22 for HTTP >= 400 with --fail
    }
    return 0;
}
