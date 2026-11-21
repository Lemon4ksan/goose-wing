// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9111 / RFC 5861 / RFC 9875 HTTP Cache Conformance Harness for goose-wing.
// Drives `http::Cache` and `proxy::filter_and_forward_headers` from TSV scenarios
// in either offline virtual-clock mode or live HTTP/1.1 origin mode.
import std;
import wing from "../..";

// Decodes an even-length hexadecimal ASCII string into `out`.
// Clears `out` and returns false on odd length or invalid hex digit.
//
// Example:
//   hex_str = "6f6b"
//   returns: true, out = "ok"
fn decode_hex_bytes(hex_str: const u8[:], out: u8[>..]&) -> bool {
    out.clear();
    guard hex_str != "-" else { return true; }
    guard (hex_str.len & 1) == 0 else { return false; }
    var i: i64 = 0;
    while i < hex_str.len {
        let next_i = core::add_sat_i64(i, 2);
        let b, ok = core::parse_u8_hex(hex_str[i..next_i]);
        guard ok else {
            out.clear();
            return false;
        }
        out.push(b);
        i = next_i;
    }
    return true;
}

// Encodes up to 128 bytes of `data` as lowercase hexadecimal into `out`, or "-" when empty.
fn encode_hex_preview(data: const u8[:], out: u8[..260]&) {
    out.clear();
    if data.len == 0 {
        let _ = out.try_push('-');
        return;
    }
    let take = min(data.len, 128);
    for i in take {
        core::format_u64_hex_fixed(data[i], 2, out, false);
    }
}

// Parses newline-delimited `Name: Value` lines into `headers`.
// Returns false if any non-empty line is missing `:`.
//
// Example:
//   raw = "Cache-Control: max-age=60\nETag: \"v1\"\n"
//   returns: true, headers populated with 2 entries
fn parse_header_lines(raw: const u8[:], headers: http::HeaderMap&) -> bool {
    var tok = core::make_byte_tokenizer(raw, '\n');
    while true {
        let raw_line, has_more = core::token_next(tok);
        guard has_more else { break; }
        let line = raw_line.trim_end_byte('\r').trim_lws();
        guard line.len > 0 else { continue; }
        let k_raw, v_raw, ok = line.split_once_byte(':');
        guard ok else { return false; }
        guard http::append_header(headers, k_raw.trim_lws(), v_raw.trim_lws()) else {
            return false;
        }
    }
    return true;
}

fn lookup_kind_str(kind: http::LookupResultKind) -> const u8[:] {
    return match kind {
        Hit => "HIT",
        Revalidate => "REVALIDATE",
        Miss => "MISS",
        Fail504 => "FAIL504",
    };
}

fn resp_action_str(kind: http::ResponseDecisionKind) -> const u8[:] {
    return match kind {
        StoreAndReturn => "STORE",
        FreshenAndReturn => "FRESHEN",
        PassThrough => "PASS",
    };
}

fn or_dash(s: const u8[:]) -> const u8[:] {
    return if s.len > 0 { s } else { "-" };
}

fn verify_proxy_forwarding_hygiene(req_headers: const http::HeaderMap&, shared: bool) -> i32 {
    guard shared else { return 1; }
    var fwd = http::HeaderMap { .. };
    let cfg = proxy::Config { .. };
    let ok = proxy::filter_and_forward_headers(
        req_headers, fwd, "127.0.0.1", "http", "origin.test", cfg,
    );
    guard ok else { return 0; }
    let has_via = fwd.get_header("via").len > 0;
    let stripped_conn = fwd.get_header("connection").len == 0;
    return if has_via && stripped_conn { 1 } else { 0 };
}

fn build_origin_path(url: const u8[:], out: u8[..512]&) {
    out.clear();
    let parsed, err = core::parse_url(url);
    if err == core::UrlParseError.None && parsed.valid {
        let p = core::pathname(parsed);
        let q = core::search(parsed);
        if p.len > 0 {
            let _ = out.try_append(p);
            if q.len > 0 {
                let _ = out.try_append(q);
            }
            return;
        }
    }
    let _ = out.try_set(if url.len > 0 { url } else { "/" });
}

fn fetch_from_live_origin(
    origin_host: const u8[:],
    origin_port: u16,
    step_id:     const u8[:],
    req:         const http::Request&,
    cond_hdrs:   const http::HeaderMap&,
    out_resp:    http::Response&,
) -> bool {
    let fd = net::tcp_connect(origin_host, origin_port, 3000);
    guard fd > 0 else { return false; }
    defer net::tcp_close(fd);

    var fwd_hdrs = http::HeaderMap { .. };
    let cfg = proxy::Config { .. };
    guard proxy::filter_and_forward_headers(
        req.headers, fwd_hdrs, "127.0.0.1", "http", origin_host, cfg,
    ) else { return false; }
    let inm = cond_hdrs.get_header("if-none-match");
    if inm.len > 0 {
        let _ = http::append_header(fwd_hdrs, "If-None-Match", inm);
    }
    let ims = cond_hdrs.get_header("if-modified-since");
    if ims.len > 0 {
        let _ = http::append_header(fwd_hdrs, "If-Modified-Since", ims);
    }
    let _ = http::append_header(fwd_hdrs, "X-Cache-Step", step_id);
    let _ = http::append_header(fwd_hdrs, "Connection", "close");

    var path_buf: u8[..512] = [];
    build_origin_path(req.url[..], path_buf);
    var wire_req: u8[..8192] = [];
    guard proxy::serialize_upstream_request(req.method[..], path_buf[..], fwd_hdrs, "", wire_req) else {
        return false;
    }
    guard net::tcp_send(fd, wire_req[..]) == (wire_req.len as i32) else { return false; }

    var wire_resp: u8[..16384] = [];
    var chunk:     u8[..4096]  = [];
    while wire_resp.len < wire_resp.cap {
        chunk.clear();
        let n = net::tcp_recv(fd, chunk, 4096, 2000);
        if n <= 0 { break; }
        guard wire_resp.try_append(chunk[..n]) else { break; }
    }
    let ok_p, _ = server::parse_http1_wire_response(wire_resp[..], out_resp);
    return ok_p;
}

struct StepSpec {
    step_id:       const u8[:],
    now_sec:       i64,
    method:        const u8[:],
    url:           const u8[:],
    req_hdrs_hex:  const u8[:],
    orig_status:   i32,
    orig_hdrs_hex: const u8[:],
    orig_body_hex: const u8[:],
}

// Parses an 8-column `STEP` record into `StepSpec`.
//
// Example:
//   rest = "s1\t1000\tGET\thttps://origin.test/a\t-\t200\t-\t6f6b"
//   returns: StepSpec { step_id: "s1", now_sec: 1000, ... }, true
fn parse_step_spec(rest: const u8[:]) -> StepSpec, bool {
    var out = StepSpec {
        step_id:       "",
        now_sec:       0,
        method:        "",
        url:           "",
        req_hdrs_hex:  "-",
        orig_status:   200,
        orig_hdrs_hex: "-",
        orig_body_hex: "-",
    };
    let c0, r0, ok0 = rest.split_once_byte('\t');
    let c1, r1, ok1 = r0.split_once_byte('\t');
    let c2, r2, ok2 = r1.split_once_byte('\t');
    let c3, r3, ok3 = r2.split_once_byte('\t');
    let c4, r4, ok4 = r3.split_once_byte('\t');
    let c5, r5, ok5 = r4.split_once_byte('\t');
    let c6, c7, ok6 = r5.split_once_byte('\t');
    guard ok0 && ok1 && ok2 && ok3 && ok4 && ok5 && ok6 else { return out, false; }
    let now_v, ok_now = c1.parse_i64_dec();
    let st_v, ok_st = c5.parse_i32_dec();
    guard ok_now && ok_st else { return out, false; }
    out.step_id = c0;
    out.now_sec = now_v;
    out.method = c2;
    out.url = c3;
    out.req_hdrs_hex = c4;
    out.orig_status = st_v;
    out.orig_hdrs_hex = c6;
    out.orig_body_hex = c7;
    return out, true;
}

fn populate_inline_origin_resp(
    sp:      const StepSpec&,
    tmp_buf: u8[>..]&,
    resp:    http::Response&,
) -> bool {
    resp = http::Response { status_code: sp.orig_status, .. };
    guard decode_hex_bytes(sp.orig_hdrs_hex, tmp_buf) else { return false; }
    if tmp_buf.len > 0 {
        guard parse_header_lines(tmp_buf[..], resp.headers) else { return false; }
    }
    guard decode_hex_bytes(sp.orig_body_hex, tmp_buf) else { return false; }
    if tmp_buf.len > 0 {
        resp.body.append(tmp_buf[..]);
    }
    return true;
}

fn emit_step_result(
    case_name: const u8[:],
    step_id:   const u8[:],
    lookup_s:  const u8[:],
    action_s:  const u8[:],
    swr_bg:    i32,
    resp:      const http::Response&,
    cond:      const http::HeaderMap&,
    via_ok:    i32,
    body_hex:  u8[..260]&,
) {
    encode_hex_preview(resp.body[..], body_hex);
    let age_v = or_dash(resp.header("age"));
    let ct_v = or_dash(resp.header("content-type"));
    let tag_v = or_dash(resp.header("x-tag"));
    let inm_v = or_dash(cond.get_header("if-none-match"));
    let ims_v = or_dash(cond.get_header("if-modified-since"));
    print(
        "RESULT\t", case_name, "\t", step_id, "\t", lookup_s, "\t", action_s, "\t", swr_bg,
        "\t", resp.status_code, "\t", body_hex[..], "\t", age_v, "\t", ct_v,
        "\t", tag_v, "\t", inm_v, "\t", ims_v, "\t", via_ok,
    );
}

fn execute_cache_step(
    cache:       http::Cache&,
    case_name:   const u8[:],
    sp:          const StepSpec&,
    origin_host: const u8[:],
    origin_port: u16,
    tmp_buf:     u8[>..]&,
    body_hex:    u8[..260]&,
) {
    var req = http::new_request(sp.method, sp.url);
    guard decode_hex_bytes(sp.req_hdrs_hex, tmp_buf) else {
        print("RESULT\t", case_name, "\t", sp.step_id, "\tERR_REQ_HEX");
        return;
    }
    if tmp_buf.len > 0 {
        guard parse_header_lines(tmp_buf[..], req.headers) else {
            print("RESULT\t", case_name, "\t", sp.step_id, "\tERR_REQ_HDR");
            return;
        }
    }

    let via_ok = verify_proxy_forwarding_hygiene(req.headers, cache.options.shared);
    let dec = http::lookup(cache, req, sp.now_sec);
    let swr_bg: i32 = if dec.revalidate_in_background { 1 } else { 0 };
    if dec.kind == http::LookupResultKind.Hit {
        emit_step_result(
            case_name, sp.step_id, "HIT", "CACHE", swr_bg,
            dec.cached_response, dec.conditional_headers, via_ok, body_hex,
        );
        return;
    }
    if dec.kind == http::LookupResultKind.Fail504 {
        var r504 = http::Response { status_code: 504, .. };
        emit_step_result(
            case_name, sp.step_id, "FAIL504", "FAIL", 0,
            r504, dec.conditional_headers, via_ok, body_hex,
        );
        return;
    }

    var orig_resp = http::Response { .. };
    let ok_orig = if origin_port > 0 {
        fetch_from_live_origin(origin_host, origin_port, sp.step_id, req, dec.conditional_headers, orig_resp)
    } else {
        populate_inline_origin_resp(sp, tmp_buf, orig_resp)
    };
    guard ok_orig else {
        print("RESULT\t", case_name, "\t", sp.step_id, "\tERR_ORIGIN");
        return;
    }

    let ts = http::new_cache_timestamps(sp.now_sec, sp.now_sec, sp.now_sec);
    let rdec = http::on_response(cache, req, orig_resp, ts, dec.entry_idx);
    emit_step_result(
        case_name, sp.step_id, lookup_kind_str(dec.kind), resp_action_str(rdec.kind), swr_bg,
        rdec.response, dec.conditional_headers, via_ok, body_hex,
    );
}

fn reset_cache_for_case(cache: http::Cache&, shared: bool) {
    cache = http::Cache {
        options: http::CacheOptions {
            shared:        shared,
            cache_private: !shared,
            ..
        },
        ..
    };
}

fn dispatch_scenario_line(
    line:        const u8[:],
    cache:       http::Cache&,
    case_name:   u8[..128]&,
    origin_host: const u8[:],
    origin_port: u16,
    tmp_buf:     u8[>..]&,
    body_hex:    u8[..260]&,
) {
    let kind, rest, ok_k = line.split_once_byte('\t');
    guard ok_k else { return; }
    if kind == "CASE" {
        let cname, shared_s, ok_c = rest.split_once_byte('\t');
        guard ok_c else { return; }
        let _ = case_name.try_set(cname);
        reset_cache_for_case(cache, shared_s == "1");
        return;
    }
    guard kind == "STEP" else { return; }
    let sp, ok_sp = parse_step_spec(rest);
    guard ok_sp else {
        print("RESULT\t", case_name[..], "\tBAD_STEP\tERR");
        return;
    }
    execute_cache_step(cache, case_name[..], sp, origin_host, origin_port, tmp_buf, body_hex);
}

fn process_scenarios(
    raw_tsv:     const u8[:],
    origin_host: const u8[:],
    origin_port: u16,
) {
    var cache = http::Cache { .. };
    var case_name: u8[..128] = [];
    var tmp_buf:   u8[>..]   = [];
    var body_hex:  u8[..260] = [];

    var tok = core::make_byte_tokenizer(raw_tsv, '\n');
    while true {
        let raw_line, has_more = core::token_next(tok);
        guard has_more else { break; }
        let line = raw_line.trim_end_byte('\r');
        guard line.len > 0 else { continue; }
        dispatch_scenario_line(line, cache, case_name, origin_host, origin_port, tmp_buf, body_hex);
    }
}

fn main() {
    let a = args();
    guard a.len >= 2 else {
        print("ERR:USAGE\n");
        exit(2);
    }
    var raw_tsv: u8[>..] = [];
    guard read_file(a[1], raw_tsv) else {
        print("ERR:READ_FILE\n");
        exit(2);
    }

    var origin_host: u8[..128] = [];
    var origin_port: u16       = 0;
    if a.len >= 3 && a[2] != "-" {
        let h_s, p_s, ok_hp = a[2].split_once_byte(':');
        if ok_hp {
            let p_u, ok_p = p_s.parse_u64_dec();
            if ok_p && p_u > 0 && p_u <= 65535 {
                let _ = origin_host.try_set(h_s);
                origin_port = p_u as u16;
            }
        }
    }

    process_scenarios(raw_tsv[..], origin_host[..], origin_port);
}
