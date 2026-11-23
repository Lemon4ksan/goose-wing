// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for package client (chunked streaming, contract expansion, and client facade).
namespace client_internal;

import std;
import core;
import rfc.http;
import dns.wire;
import dns.cache;
import dns.doh;
import fingerprint.profile;
import http.headers;
import http.headers.chunked;
import http.json_codec;
import http.request;
import http.response;
import http.compression_dict;
import .stream;
import .client;
import .session.verbs;

// ---- Stream Internal Helpers -----------------------------------------------

inline fn has_chunk_buf_space<B>(buf: const B&, needed: i64) -> bool {
    return needed >= 0 && core::sub_sat_i64(buf.cap, buf.len) >= needed;
}

inline fn has_chunk_buf_space(_buf: const u8[>..]&, needed: i64) -> bool {
    return needed >= 0;
}

inline fn count_chunk_hex_digits(len_val: i64) -> i64 {
    var v = len_val;
    var digits: i64 = 0;
    while v > 0 {
        v = v >> 4;
        digits = core::add_sat_i64(digits, 1);
    }
    return max(digits, 1);
}

inline fn measure_chunked_payload_wire_len(
    body:       const u8[:],
    trailers:   const http::HeaderMap&,
    chunk_size: i64,
) -> i64 {
    let step = if chunk_size > 0 { chunk_size } else { 4096 };
    var total: i64 = 0;
    if body.len > 0 {
        var offset: i64 = 0;
        while offset < body.len {
            let end_off = min(core::add_sat_i64(offset, step), body.len);
            let c_len = core::sub_sat_i64(end_off, offset);
            let hex_digits = count_chunk_hex_digits(c_len);
            let frame_len = core::add_sat_i64(hex_digits, core::add_sat_i64(c_len, 4));
            total = core::add_sat_i64(total, frame_len);
            offset = end_off;
        }
    }
    total = core::add_sat_i64(total, 5);
    for &e in trailers.entries {
        let tname = http::entry_name(trailers, e);
        let tval = http::entry_value(trailers, e);
        if http::is_valid_header_name(tname) && http::is_valid_header_value(tval) &&
            !rfc::is_disallowed_trailer_field(tname) {
            let tr_len = core::add_sat_i64(tname.len, core::add_sat_i64(tval.len, 4));
            total = core::add_sat_i64(total, tr_len);
        }
    }
    return total;
}

fn append_trailer_item(trailers: http::HeaderMap&, name: const u8[:], val: const u8[:]) -> bool {
    guard trailers.entries.len < 16 else { return false; }
    return http::append_header(trailers, name, val);
}

fn step_chunk_size_line(dec: client::ChunkedStreamDecoder&, b: u8) -> bool {
    dec.bytes_consumed_total = core::add_sat_u64(dec.bytes_consumed_total, 1);
    if b == '\n' {
        let last_idx = core::sub_sat_i64(dec.line_buf.len, 1);
        guard dec.line_buf.len > 0 && dec.line_buf[last_idx] == '\r' else {
            dec.state = client::ChunkedStreamState.Error;
            dec.error_code = http::ChunkedDecodeError.BareLfInChunkSize;
            return false;
        }
        let size_line = dec.line_buf[..last_idx];
        let csize, parse_err = http::parse_chunk_size_hex(size_line);
        guard parse_err == http::ChunkedDecodeError.None else {
            dec.state = client::ChunkedStreamState.Error;
            dec.error_code = parse_err;
            return false;
        }
        dec.line_buf.clear();
        dec.expected_chunk_size = csize;

        if csize == 0 {
            dec.state = client::ChunkedStreamState.Trailers;
        } else {
            dec.chunk_bytes_remaining = csize;
            dec.state = client::ChunkedStreamState.ChunkData;
        }
        return true;
    }
    guard dec.line_buf.try_push(b) else {
        dec.state = client::ChunkedStreamState.Error;
        dec.error_code = http::ChunkedDecodeError.InvalidChunkExtension;
        return false;
    }
    return true;
}

fn step_chunk_data_crlf(dec: client::ChunkedStreamDecoder&, b: u8) -> bool {
    dec.bytes_consumed_total = core::add_sat_u64(dec.bytes_consumed_total, 1);
    if dec.crlf_step == 0 {
        if b == '\r' {
            dec.crlf_step = 1;
            return true;
        }
        dec.state = client::ChunkedStreamState.Error;
        dec.error_code = if b == '\n' {
            http::ChunkedDecodeError.BareLfInChunkData
        } else {
            http::ChunkedDecodeError.MalformedChunkEnding
        };
        return false;
    }
    if b == '\n' {
        dec.state = client::ChunkedStreamState.ChunkSizeLine;
        dec.crlf_step = 0;
        return true;
    }
    dec.state = client::ChunkedStreamState.Error;
    dec.error_code = http::ChunkedDecodeError.MalformedChunkEnding;
    return false;
}

fn process_trailer_line(dec: client::ChunkedStreamDecoder&) -> bool {
    let last_idx = core::sub_sat_i64(dec.line_buf.len, 1);
    guard dec.line_buf.len > 0 && dec.line_buf[last_idx] == '\r' else {
        dec.state = client::ChunkedStreamState.Error;
        dec.error_code = http::ChunkedDecodeError.BareLfInTrailer;
        return false;
    }
    let tr_line = dec.line_buf[..last_idx];

    if tr_line.len == 0 {
        dec.state = client::ChunkedStreamState.Complete;
        dec.line_buf.clear();
        return true;
    }

    let next_count_i64 = core::add_sat_i64(dec.trailer_count, 1);
    let next_bytes = core::add_sat_i64(dec.total_trailer_bytes, tr_line.len);
    let col_idx = tr_line.index_of_byte(':');
    guard next_count_i64 <= 16 && next_bytes <= 4096 && col_idx > 0 else {
        dec.state = client::ChunkedStreamState.Error;
        dec.error_code = http::ChunkedDecodeError.DisallowedTrailer;
        return false;
    }

    let hname = tr_line[..col_idx];
    let hval = tr_line[core::add_sat_i64(col_idx, 1)..].trim_lws();
    if !http::is_valid_header_name(hname) || !http::is_valid_header_value(hval) ||
        rfc::is_disallowed_trailer_field(hname) {
        dec.state = client::ChunkedStreamState.Error;
        dec.error_code = http::ChunkedDecodeError.DisallowedTrailer;
        return false;
    }

    guard append_trailer_item(dec.trailers, hname, hval) else {
        dec.state = client::ChunkedStreamState.Error;
        dec.error_code = http::ChunkedDecodeError.DisallowedTrailer;
        return false;
    }
    dec.trailer_count = next_count_i64 as i32;
    dec.total_trailer_bytes = next_bytes;
    dec.line_buf.clear();
    return true;
}

fn step_chunk_trailer(dec: client::ChunkedStreamDecoder&, b: u8) -> bool {
    dec.bytes_consumed_total = core::add_sat_u64(dec.bytes_consumed_total, 1);
    if b == '\n' {
        return process_trailer_line(dec);
    }
    guard dec.line_buf.try_push(b) else {
        dec.state = client::ChunkedStreamState.Error;
        dec.error_code = http::ChunkedDecodeError.DisallowedTrailer;
        return false;
    }
    return true;
}

fn read_chunk_chunked<B>(
    reader:    client::StreamReader&,
    max_bytes: i64,
    out:       B&,
) -> client::StreamReadStatus, bool {
    guard !client::has_error(reader.chunk_decoder) else {
        reader.finished = true;
        return client::StreamReadStatus.Error, false;
    }

    let prev_len = out.len;
    let limit = if max_bytes > 0 { max_bytes } else { -1 };
    let consumed, ok_dec = client::feed_chunked_stream(
        reader.chunk_decoder,
        reader.raw_data[reader.cursor..],
        out,
        limit,
    );
    reader.cursor = core::add_sat_i64(reader.cursor, consumed);
    guard ok_dec else {
        reader.finished = true;
        return client::StreamReadStatus.Error, false;
    }

    let emitted_i64 = max(core::sub_sat_i64(out.len, prev_len), 0);
    let emitted = emitted_i64 as u64;
    reader.bytes_read = core::add_sat_u64(reader.bytes_read, emitted);

    let is_eof = client::is_complete(reader.chunk_decoder);
    if is_eof {
        reader.finished = true;
    }
    if emitted > 0 {
        return client::StreamReadStatus.Data, is_eof;
    }
    if is_eof {
        return client::StreamReadStatus.Eof, true;
    }
    // RFC 9112 Section 7.1: Chunked Transfer Coding - Premature EOF before terminating 0-chunk is a framing error.
    reader.chunk_decoder.state = client::ChunkedStreamState.Error;
    reader.finished = true;
    return client::StreamReadStatus.Error, false;
}

fn read_chunk_identity<B>(
    reader:    client::StreamReader&,
    max_bytes: i64,
    remaining: i64,
    out:       B&,
) -> client::StreamReadStatus, bool {
    let to_read = max(if max_bytes > 0 { min(remaining, max_bytes) } else { remaining }, 0);
    let end_off = core::add_sat_i64(reader.cursor, to_read);
    out.append(reader.raw_data[reader.cursor..end_off]);
    reader.cursor = end_off;
    reader.bytes_read = core::add_sat_u64(reader.bytes_read, to_read as u64);

    let is_eof = reader.cursor >= reader.raw_data.len;
    if is_eof {
        reader.finished = true;
    }
    return client::StreamReadStatus.Data, is_eof;
}

// ---- Contract Internal Helpers ---------------------------------------------

// Formats path parameter `param_name` from `params` into `out`, rejecting empty values,
// path separators (`/`), query/fragment delimiters (`?`, `#`), and control characters.
// Rolls back `out` on failure.
fn format_path_param_segment<Params, B>(
    param_name: const u8[:],
    params:     const Params&,
    out:        B&,
) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    var seg_buf: u8[..256] = [];
    var matched = false;
    var fmt_ok = false;
    const for <Name, Acc> in fields<Params> {
        if !matched && Name == param_name {
            matched = true;
            fmt_ok = http::format_query_field_val(params.Acc, seg_buf);
        }
    }
    guard matched && fmt_ok && seg_buf.len > 0 else { return false; }
    guard seg_buf[..] != "." && seg_buf[..] != ".." else { return false; }
    for b in seg_buf[..] {
        guard b > 0x20 && b < 0x7F && b != '/' && b != '\\' && b != '?' && b != '#' && b != '%' else {
            return false;
        }
    }
    guard out.try_append(seg_buf[..]) else { return false; }
    committed = true;
    return true;
}

// Expands `:param` placeholders in `path_template` using `params` and appends the path to `out`.
// Rolls back `out` on missing parameters, unsafe characters, or capacity overflow.
fn expand_contract_path<Params, B>(
    path_template: const u8[:],
    params:        const Params&,
    out:           B&,
) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard path_template.len > 0 else { return false; }
    var idx: i64 = 0;
    while idx < path_template.len {
        let b = path_template[idx];
        if b == ':' {
            let start = core::add_sat_i64(idx, 1);
            var end = core::add_sat_i64(idx, 1);
            while end < path_template.len && path_template[end] != '/' {
                end = core::add_sat_i64(end, 1);
            }
            let param_name = path_template[start..end];
            guard param_name.len > 0 && format_path_param_segment(param_name, params, out) else {
                return false;
            }
            idx = end;
        } else {
            guard out.try_push(b) else { return false; }
            idx = core::add_sat_i64(idx, 1);
        }
    }
    committed = true;
    return true;
}

// Appends all fields of `query_dto` as query parameters on `req`.
// Rolls back `req.query_params` on capacity overflow.
fn apply_contract_query<Query>(req: http::Request&, query_dto: const Query&) -> bool {
    let saved_len = req.query_params.len;
    var committed = false;
    defer if !committed { req.query_params.resize(saved_len); };
    var all_ok = true;
    const for <Name, Acc> in fields<Query> {
        if all_ok && !http::is_omitted_query_field_val(query_dto.Acc) {
            var val_buf: u8[..256] = [];
            let ok_q = http::format_query_field_val(query_dto.Acc, val_buf) &&
                http::query(req, Name, val_buf[..]);
            all_ok = all_ok && ok_q;
        }
    }
    guard all_ok else { return false; }
    committed = true;
    return true;
}

// ---- Client Facade Internal Helpers (Profile, DoH, ECH, Dictionary) --------

fn resolve_profile_spec(kind: fingerprint::Profile) -> fingerprint::ClientProfile {
    if kind == fingerprint::Profile.None {
        return fingerprint::none_profile();
    }
    if kind == fingerprint::Profile.Custom {
        return fingerprint::custom_profile();
    }
    return fingerprint::wing_default_profile();
}

fn build_profile_headers(profile: const fingerprint::ClientProfile&) -> http::HeaderMap {
    var hdrs = http::HeaderMap { .. };
    if profile.user_agent.len > 0 {
        http::set_header(hdrs, "User-Agent", profile.user_agent[..]);
    }
    if profile.accept.len > 0 {
        http::set_header(hdrs, "Accept", profile.accept[..]);
    }
    if profile.accept_encoding.len > 0 {
        http::set_header(hdrs, "Accept-Encoding", profile.accept_encoding[..]);
    }
    if profile.accept_language.len > 0 {
        http::set_header(hdrs, "Accept-Language", profile.accept_language[..]);
    }
    if profile.upgrade_insecure_requests.len > 0 {
        http::set_header(hdrs, "Upgrade-Insecure-Requests", profile.upgrade_insecure_requests[..]);
    }
    for &e in profile.extra_headers.entries {
        let h_name = http::entry_name(profile.extra_headers, e);
        let h_val = http::entry_value(profile.extra_headers, e);
        if h_name.len > 0 {
            http::set_header(hdrs, h_name, h_val);
        }
    }
    return hdrs;
}

fn apply_profile(c: client::Client&, profile: const fingerprint::ClientProfile&) {
    c.profile = profile.kind;
    c.profile_spec = profile;
    c.default_headers = build_profile_headers(profile);
}

fn is_trusted_location_host(session: const client::Session&, host_name: const u8[:]) -> bool {
    return session.trusted_location_hosts.any() { it[..].eq_ascii_fold(host_name) };
}

// Creates an isolated `Client` copying only transport, TLS verification, SSRF policy,
// virtual clock, and mock routes so application credentials, cookies, and interceptors
// do not leak across internal sub-requests (such as RFC 8484 DoH queries).
fn clone_isolated_transport_client(session: const client::Session&) -> client::Client {
    let def_p = fingerprint::wing_default_profile();
    let def_hdrs = build_profile_headers(def_p);
    var proxy_buf: u8[..256] = [];
    let _ = proxy_buf.try_set(session.proxy_url[..]);
    return client::Client {
        profile:                    def_p.kind,
        profile_spec:               def_p,
        proxy_url:                  proxy_buf,
        timeout_ms:                 session.timeout_ms,
        https_only:                 session.https_only,
        default_headers:            def_hdrs,
        ssrf_guard:                 copy(session.ssrf_guard),
        virtual_clock_us:           session.virtual_clock_us,
        mock_routes:                copy(session.mock_routes),
        cache:                      http::Cache { .. },
        enable_cache:               false,
        altsvc:                     http::AltSvcCache { .. },
        enable_altsvc:              true,
        enable_protocol_racing:     true,
        quic_race_delay_ms:         200,
        dict_cache:                 http::DictionaryCache { .. },
        enable_compression_dict:    true,
        pipeline:                   client::InterceptorPipeline { .. },
        wire_pipeline:              wire::default_client_pipeline(),
        hsts:                       copy(session.hsts),
        enable_hsts:                session.enable_hsts,
        pool:                       net::new_stream_pool(),
        enable_cookie_jar:          true,
        trust_store:                copy(session.trust_store),
        insecure_skip_verify:       session.insecure_skip_verify,
        tls_backend:                session.tls_backend,
        tls_min_version:            session.tls_min_version,
        tls_ca_file:                copy(session.tls_ca_file),
        tls_use_system_roots:       session.tls_use_system_roots,
        tls_client_cert_file:       copy(session.tls_client_cert_file),
        tls_client_key_file:        copy(session.tls_client_key_file),
        tls_enable_pq_hybrid:       session.tls_enable_pq_hybrid,
        tls_enable_session_tickets: session.tls_enable_session_tickets,
        tls_require_ocsp_stapling:  session.tls_require_ocsp_stapling,
        tls_crl_file:               copy(session.tls_crl_file),
        tls_keylog_file:            copy(session.tls_keylog_file),
        allow_loopback_ssrf:        session.allow_loopback_ssrf,
        has_invalid_tls_config:     session.has_invalid_tls_config,
        jar:                        cookie::CanonicalCookieJar { .. },
        ..
    };
}

// Dispatches a DNS-over-HTTPS wire query using an isolated HTTP client transport
// to ensure application credentials, custom headers, and interceptors do not leak to public resolvers.
fn doh_query(
    session: client::Session&,
    domain:  const u8[:],
    qtype:   u16,
    tx_id:   u16,
) -> dns::Response, bool {
    var req = http::new_request(if session.doh.use_post { "POST" } else { "GET" }, "");

    if session.doh.use_post {
        req.url.append(session.doh.endpoint[..]);
        http::set_header(req, "content-type", "application/dns-message");
        http::set_header(req, "accept", "application/dns-message");
        var wire_query: u8[..512] = [];
        guard dns::build_query(domain, qtype, tx_id, wire_query) else { return dns::Response { .. }, false; }
        req.body.append(wire_query[..]);
    } else {
        guard dns::build_doh_get_url(session.doh.endpoint[..], domain, qtype, req.url) else {
            return dns::Response { .. }, false;
        }
        http::set_header(req, "accept", "application/dns-message");
    }

    var doh_client = clone_isolated_transport_client(session);
    let res, err = client::do(doh_client, req);
    guard http::ok(err) && res.status_code == rfc::STATUS_OK else { return dns::Response { .. }, false; }

    let parsed, ok_dns = dns::parse_response(res.body[..]);
    guard ok_dns && parsed.rcode == rfc::DNS_RCODE_NOERROR && parsed.question_count == 1 else {
        return dns::Response { .. }, false;
    }
    let expected_tx_id: u16 = if session.doh.use_post { tx_id } else { 0 };
    guard parsed.tx_id == expected_tx_id else { return dns::Response { .. }, false; }
    return parsed, true;
}

fn discover_and_cache_ech_config(
    session: client::Session&,
    domain:  const u8[:],
    now_sec: i64,
) -> u8[..512], bool {
    var ech: u8[..512] = [];
    guard session.enable_doh && session.auto_ech_discovery else { return ech, false; }

    // RFC 8484 Section 4.1: DoH clients SHOULD set DNS ID to 0 for maximum HTTP cacheability.
    let dns_resp, ok_doh = doh_query(session, domain, rfc::DNS_QTYPE_HTTPS, 0);
    guard ok_doh else { return ech, false; }

    let eff_ttl = if dns_resp.min_ttl_sec > 0 { dns_resp.min_ttl_sec } else { 300 };
    var cache_entry = dns::CacheEntry {
        qtype:           rfc::DNS_QTYPE_HTTPS,
        inserted_at_sec: now_sec,
        ttl_sec:         eff_ttl,
        valid:           true,
        ..
    };
    guard cache_entry.domain.try_set(domain) else { return ech, false; }

    var found_ech = false;
    for &rec in dns_resp.https_records {
        let _ = cache_entry.https_records.try_push(rec);
        if rec.has_ech && rec.ech_config_list.len > 0 && !found_ech {
            found_ech = ech.try_set(rec.ech_config_list[..]);
        }
    }

    session.dns_cache.insert(cache_entry);
    return ech, found_ech;
}

inline fn is_localhost_dict_authority(auth: const u8[:]) -> bool {
    let host_part, _, _ = auth.partition_byte('/');
    if host_part.starts_with_fold("localhost") {
        return host_part.len == 9 || host_part[9] == ':';
    }
    if core::starts_with(host_part, "127.0.0.1") {
        return host_part.len == 9 || host_part[9] == ':';
    }
    if core::starts_with(host_part, "[::1]") {
        return host_part.len == 5 || host_part[5] == ':';
    }
    return false;
}

inline fn is_secure_dict_origin(origin: const u8[:]) -> bool {
    guard origin.len > 0 else { return false; }
    if origin.starts_with_fold("https://") {
        return origin.len > 8;
    }
    if origin.starts_with_fold("http://") {
        return is_localhost_dict_authority(origin[7..]);
    }
    if core::contains(origin, "://") {
        return false;
    }
    guard origin[0] != ':' else { return false; }
    if core::ends_with(origin, ":80") {
        return is_localhost_dict_authority(origin);
    }
    return true;
}

inline fn is_dict_entry_usable_for_session(
    session: const client::Session&,
    entry:   const http::DictionaryEntry&,
    origin:  const u8[:],
) -> bool {
    guard entry.valid && entry.origin.len > 0 && entry.origin[..].eq_ascii_fold(origin) else {
        return false;
    }
    guard entry.ttl_sec > 0 else { return true; }
    if session.virtual_clock_us == 0 && entry.inserted_at_sec > 0 && entry.inserted_at_sec < 100000000 {
        return true;
    }
    let now_sec = div_euclid(client::effective_clock_us(session), 1000000);
    return now_sec >= entry.inserted_at_sec && core::sub_sat_i64(now_sec, entry.inserted_at_sec) < entry.ttl_sec;
}

// Verifies the RFC 9842 `dcz` or `dcb` magic header and dictionary hash, then decompresses `raw_body` into `out`.
//
// Example:
//   is_dcz = true, raw_body = <valid dcz payload>, origin = "https://example.com"
//   returns: true with decompressed bytes appended to `out`
fn decode_dict_compressed_body<B>(
    session:  const client::Session&,
    origin:   const u8[:],
    is_dcz:   bool,
    raw_body: const u8[:],
    out:      B&,
) -> bool {
    var dict_hash: u8[32] = [0; 32];
    let ok_hdr = if is_dcz {
        let _, ok_z = http::decode_dcz_header(raw_body, dict_hash);
        ok_z
    } else {
        let _, ok_b = http::decode_dcb_header(raw_body, dict_hash);
        ok_b
    };
    guard ok_hdr else { return false; }
    var dict_entry = http::DictionaryEntry { .. };
    guard http::dictionary_lookup_by_hash(session.dict_cache, dict_hash, dict_entry) else {
        return false;
    }
    guard is_dict_entry_usable_for_session(session, dict_entry, origin) else { return false; }
    let comp_payload, ok_magic = http::verify_dcz_dcb_magic(raw_body, is_dcz, dict_entry.sha256_hash);
    guard ok_magic else { return false; }
    if is_dcz {
        return http::decompress_dcz_payload(comp_payload, dict_entry.content[..], out);
    }
    return http::decompress_dcb_payload(comp_payload, dict_entry.content[..], out);
}
