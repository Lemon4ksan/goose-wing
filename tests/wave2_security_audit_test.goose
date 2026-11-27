// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Wave 2 Security & RFC Conformance Audit Regression Suite.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

struct AuditJsonModel {
    id:    i32      = 0,
    score: f64      = 0.0,
    name:  u8[..32] = [],
}

struct AuditNestedNode {
    v: i32 = 0,
}

// ----------------------------------------------------------------------------
// 1. Compression & RFC 8879 (W2_H3_C01..C07)
// ----------------------------------------------------------------------------
fn test_wave2_compression_and_rfc8879(t: lit::T&) {
    t.run("Brotli truncated bitstream & empty input fail closed with InputBufferTruncated") { sub =>
        let trunc9: u8[9] = [0xA1, 0xFF, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        var out_br: u8[..256] = [];
        let ok_t, err_t = core::brotli_decompress(trunc9[..], out_br);
        sub.assert_false(ok_t, "Truncated 9B Brotli PoC must fail");
        sub.assert_true(err_t != core::CompressError.None, "Truncated Brotli reports non-None error");

        let short_wbits: u8[1] = [0x00];
        var out_short: u8[..64] = [];
        let ok_s, err_s = core::brotli_decompress(short_wbits[..], out_short);
        sub.assert_false(ok_s, "1-byte truncated Brotli stream fails cleanly");
        sub.assert_eq(err_s, core::CompressError.InputBufferTruncated, "Short Brotli stream returns InputBufferTruncated");
    };

    t.run("Zstd enforces 8 MiB window limit and block output limit") { sub =>
        // Magic LE (28 B5 2F FD) + FHD=0x00 (Single_Segment=0, FCS=0) + WD=0xFF (window > 8 MiB)
        let huge_win_frame: u8[8] = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0xFF, 0x01, 0x00];
        var out_win: u8[..64] = [];
        let ok_win, err_win = core::zstd_decompress(huge_win_frame[..], out_win);
        sub.assert_false(ok_win, "Zstd frame with window > 8 MiB must be rejected");
        sub.assert_true(err_win != core::CompressError.None, "Excessive Zstd window returns error");

        var raw_payload: u8[..128] = [];
        for _ in 64 { raw_payload.push('A'); }
        var comp: u8[..256] = [];
        sub.require_true(core::zstd_compress(raw_payload[..], comp), "Zstd compress succeeds");
        var capped_out: u8[>..] = [];
        let ok_cap, err_cap = core::zstd_decompress_with_limit(comp[..], capped_out, 8);
        sub.assert_false(ok_cap, "Zstd decompress exceeding max_output_bytes must fail");
        sub.assert_eq(err_cap, core::CompressError.OutputBufferOverflow, "Zstd output limit enforced");
    };

    t.run("1200 concatenated empty Gzip members rejected by bounded iterative loop") { sub =>
        var gz_enc = core::new_zstream_compressor(core::ContainerFormat.Gzip, 6);
        var member: u8[..64] = [];
        sub.require_true(gz_enc.finish(member), "Empty gzip member encodes cleanly");

        var gz_bomb: u8[>..] = [];
        for _ in 1200 { gz_bomb.append(member[..]); }
        var dec = core::new_zstream_decompressor(core::ContainerFormat.Gzip);
        var out_gz: u8[>..] = [];
        let err_gz = core::zstream_decompress_write_limit(dec, gz_bomb[..], out_gz, 65536);
        sub.assert_eq(err_gz, core::CompressError.CorruptedBitstream, "1200 empty gzip members rejected without recursion overflow");
    };

    t.run("RFC 8879 decompress_incoming_certificate rejects unoffered algorithms fail-closed") { sub =>
        var raw_cert: u8[..64] = [];
        raw_cert.append("DER_CERT_PLACEHOLDER_BYTES_0123456789");
        var z_comp: u8[..256] = [];
        sub.require_true(core::zstd_compress(raw_cert[..], z_comp), "Compress dummy cert payload");

        var cert_wire: u8[..512] = [];
        // Algorithm ID 3 = Zstd (RFC 8879)
        sub.require_true(
            tls_internal::encode_compressed_certificate_payload(cert_wire, 3, raw_cert.len as u32, z_comp[..]),
            "Encoded CompressedCertificate wire payload",
        );

        var out_cert: u8[..256] = [];
        let empty_offered: u16[0] = [];
        sub.assert_false(
            tls_internal::decompress_incoming_certificate(cert_wire[..], out_cert, empty_offered[..]),
            "Empty offered_algos must fail closed instead of bypassing check",
        );
        let brotli_only: u16[1] = [2];
        sub.assert_false(
            tls_internal::decompress_incoming_certificate(cert_wire[..], out_cert, brotli_only[..]),
            "Unoffered Zstd algorithm must be rejected when only Brotli offered",
        );
    };
}

// ----------------------------------------------------------------------------
// 2. Proxy, Cookie/PSL, Cache & Web Policies (W2_H5_*)
// ----------------------------------------------------------------------------
fn test_wave2_proxy_cookie_cache_policies(t: lit::T&) {
    t.run("HttpRouteCache bypasses Cookie, Proxy-Authorization, fat GET & multi-header Cache-Control") { sub =>
        var cfg = server::new_server_pipeline_config("127.0.0.1", security::new_gcra_quota(1000, wing::secs(1), 100));
        server::cache_store(cfg.route_cache, 1000, "cached-secret-or-public", -1, "text/plain");
        let cache_mask = wire::STAGE_SRV_IN_DEFAULT_MASK | wire::STAGE_SRV_IN_CACHE_LOOKUP;
        server::add_route_pso(cfg.router, "GET", "/item", 1, cache_mask, wire::STAGE_SRV_OUT_DEFAULT_MASK);

        var req_plain = http::new_request("GET", "/item");
        http::set_header(req_plain, "Host", "127.0.0.1");
        var res_plain = http::Response { .. };
        let v_plain = server_internal::stage_server_cache_lookup(cfg.route_cache, req_plain, 1000, res_plain, 1);
        sub.assert_true(match v_plain { ShortCircuit _ => true, _ => false }, "Clean GET hits route cache");

        var req_cookie = http::new_request("GET", "/item");
        http::set_header(req_cookie, "Host", "127.0.0.1");
        http::set_header(req_cookie, "Cookie", "sid=secret");
        var res_cookie = http::Response { .. };
        let v_cookie = server_internal::stage_server_cache_lookup(cfg.route_cache, req_cookie, 1000, res_cookie, 1);
        sub.assert_true(match v_cookie { Continue => true, _ => false }, "GET with Cookie bypasses shared route cache");

        var req_pauth = http::new_request("GET", "/item");
        http::set_header(req_pauth, "Host", "127.0.0.1");
        http::set_header(req_pauth, "Proxy-Authorization", "Basic secret");
        var res_pauth = http::Response { .. };
        let v_pauth = server_internal::stage_server_cache_lookup(cfg.route_cache, req_pauth, 1000, res_pauth, 1);
        sub.assert_true(match v_pauth { Continue => true, _ => false }, "GET with Proxy-Authorization bypasses cache");

        var req_fat = http::new_request("GET", "/item");
        http::set_header(req_fat, "Host", "127.0.0.1");
        req_fat.body.append("fat-get-body");
        var res_fat = http::Response { .. };
        let v_fat = server_internal::stage_server_cache_lookup(cfg.route_cache, req_fat, 1000, res_fat, 1);
        sub.assert_true(match v_fat { Continue => true, _ => false }, "Fat GET bypasses shared route cache");

        var req_cc = http::new_request("GET", "/item");
        http::set_header(req_cc, "Host", "127.0.0.1");
        http::append_header(req_cc.headers, "Cache-Control", "max-age=600");
        http::append_header(req_cc.headers, "Cache-Control", "no-store");
        var res_cc = http::Response { .. };
        let v_cc = server_internal::stage_server_cache_lookup(cfg.route_cache, req_cc, 1000, res_cc, 1);
        sub.assert_true(match v_cc { Continue => true, _ => false }, "Second Cache-Control: no-store bypasses cache");
    };

    t.run("ReverseProxy strips X-Real-IP, True-Client-IP, underscore spoof headers & protects E2E headers from Connection") { sub =>
        var rp = proxy::new_reverse_proxy(proxy::LbPolicy.RoundRobin);
        proxy::add_upstream_target(rp.cluster, "app.internal:80", 80);

        var hdrs = http::HeaderMap { .. };
        http::append_header(hdrs, "Host", "app.example.com");
        http::append_header(hdrs, "X-Real-IP", "1.2.3.4");
        http::append_header(hdrs, "True-Client-IP", "5.6.7.8");
        http::append_header(hdrs, "X_Real_IP", "9.9.9.9");
        http::append_header(hdrs, "Authorization", "Bearer top-secret");
        http::append_header(hdrs, "Connection", "Authorization, X-Custom-Hop");
        http::append_header(hdrs, "X-Custom-Hop", "drop-me");

        var wire_req: u8[>..] = [];
        let _, ok_p = proxy::prepare_proxy_request(rp, "GET", "/api", hdrs, "203.0.113.10", "https", "", wire_req);
        sub.assert_true(ok_p, "Proxy request serialized");
        sub.assert_false(core::contains(wire_req[..], "1.2.3.4"), "Spoofed X-Real-IP stripped");
        sub.assert_false(core::contains(wire_req[..], "5.6.7.8"), "Spoofed True-Client-IP stripped");
        sub.assert_false(core::contains(wire_req[..], "9.9.9.9"), "Underscore X_Real_IP stripped");
        sub.assert_false(core::contains(wire_req[..], "drop-me"), "Custom Connection hop header stripped");
        sub.assert_true(core::contains(wire_req[..], "Bearer top-secret"), "Authorization preserved despite Connection smuggling");

        var hop_src = http::HeaderMap { .. };
        http::append_header(hop_src, "Connection", "Authorization, Cookie, Content-Security-Policy, X-Custom-Hop");
        http::append_header(hop_src, "Authorization", "Bearer a");
        http::append_header(hop_src, "Cookie", "sid=1");
        http::append_header(hop_src, "Content-Security-Policy", "default-src 'none'");
        http::append_header(hop_src, "X-Custom-Hop", "strip-val");
        var hop_dst = http::HeaderMap { .. };
        http::strip_hop_by_hop_headers(hop_src, hop_dst);
        sub.assert_true(http::has_header(hop_dst, "authorization"), "Protected Authorization preserved");
        sub.assert_true(http::has_header(hop_dst, "cookie"), "Protected Cookie preserved");
        sub.assert_true(http::has_header(hop_dst, "content-security-policy"), "Protected CSP preserved");
        sub.assert_false(http::has_header(hop_dst, "x-custom-hop"), "Unprotected custom hop header still stripped per RFC 9110 §7.6.1");
    };

    t.run("Server fails closed on untrusted loopback proxy headers and untrusted PROXY protocol peer") { sub =>
        var srv = server::new_http_server("127.0.0.1", 8080);
        srv.pipeline.enable_rate_limiter = true;
        srv.pipeline.limiter = security::new_sharded_limiter(security::new_gcra_quota(1, wing::secs(1), 0));
        server::add_route(srv.pipeline.router, "GET", "/rl", 1, 0);

        var out1: u8[..512] = [];
        var out2: u8[..512] = [];
        let o1, _ = server::handle_connection_wire(
            srv, "127.0.0.1", "GET /rl HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 1.1.1.1\r\n\r\n", 1000000000, out1,
        );
        let o2, _ = server::handle_connection_wire(
            srv, "127.0.0.1", "GET /rl HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 2.2.2.2\r\n\r\n", 1000000000, out2,
        );
        sub.assert_true(o1 == server::PipelineOutcome.Handled, "First loopback request allowed");
        sub.assert_true(o2 == server::PipelineOutcome.RateLimited, "Loopback X-Real-IP ignored when trust_proxy_headers == false");

        var srv_pp = server::new_http_server("127.0.0.1", 8080);
        srv_pp.accept_proxy_protocol = true;
        server::add_get_route(srv_pp, "/ok", 1);
        var pp_out: u8[..512] = [];
        let pp_wire = "PROXY TCP4 198.51.100.77 10.0.0.1 61234 8080\r\nGET /ok HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        let _, ok_pp = server::handle_connection_wire(srv_pp, "127.0.0.1", pp_wire, 1700000000, pp_out);
        sub.assert_false(ok_pp, "Empty proxy_protocol_trusted_cidrs fails closed");
        sub.assert_true(core::contains(pp_out[..], "400 Bad Request"), "Untrusted PROXY protocol emits 400");
    };

    t.run("Cookie Jar evicts non-Secure before Secure & PSL rejects fallback public suffixes") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        jar.max_cookies_per_domain = 4;
        jar.target_cookies_per_domain = 2;

        let now_us: i64 = 1700000000000000;
        sub.assert_true(cookie::set_cookie_header(jar, "https://example.com/", "sec1=v1; Secure; Priority=Low; Path=/", now_us));
        sub.assert_true(cookie::set_cookie_header(jar, "https://example.com/", "sec2=v2; Secure; Priority=Low; Path=/", now_us + 10));
        sub.assert_true(cookie::set_cookie_header(jar, "http://example.com/", "insec1=v3; Priority=High; Path=/", now_us + 20));
        sub.assert_true(cookie::set_cookie_header(jar, "http://example.com/", "insec2=v4; Priority=High; Path=/", now_us + 30));
        sub.assert_true(cookie::set_cookie_header(jar, "http://example.com/", "insec3=v5; Priority=High; Path=/", now_us + 40));

        sub.assert_true(cookie::get(jar, "sec1") == "v1" && cookie::get(jar, "sec2") == "v2", "Low-priority Secure cookies survive non-Secure eviction");
        sub.assert_true(cookie::is_public_suffix("co.uk"), "co.uk is public suffix");
        sub.assert_true(cookie::is_public_suffix("github.io"), "github.io is public suffix");
        sub.assert_false(cookie::is_public_suffix("example.com"), "example.com is registrable");
    };

    t.run("HttpCache blocks Set-Cookie & canonicalizes dot-segments") { sub =>
        var cache = http::Cache { options: http::CacheOptions { shared: true, .. }, .. };
        var req1 = http::new_get("https://example.com/public/../secret");
        var res1 = http::Response { status_code: 200, .. };
        http::set_header(res1, "Cache-Control", "public, max-age=60");
        res1.body.append("ok");

        let ts = http::CacheTimestamps { request_sec: 100, response_sec: 100, now_sec: 100, .. };
        let _ = cache.on_response(req1, res1, ts);

        var req_canon = http::new_get("https://example.com/secret");
        let dec = cache.lookup(req_canon, 105);
        sub.assert_true(dec.kind == http::LookupResultKind.Hit, "Canonicalized /secret hits entry cached via /public/../secret");

        var req_sc = http::new_get("https://example.com/setcookie");
        var res_sc = http::Response { status_code: 200, .. };
        http::set_header(res_sc, "Cache-Control", "max-age=60");
        http::set_header(res_sc, "Set-Cookie", "auth=secret; HttpOnly");
        res_sc.body.append("user");
        let _ = cache.on_response(req_sc, res_sc, ts);
        let dec_sc = cache.lookup(req_sc, 105);
        sub.assert_true(dec_sc.kind == http::LookupResultKind.Miss, "Shared cache refuses storing Set-Cookie response");
    };
}

// ----------------------------------------------------------------------------
// 3. Framing, Mux, HPACK/QPACK, gRPC, WS, SSE
// ----------------------------------------------------------------------------
fn test_wave2_framing_mux_realtime(t: lit::T&) {
    t.run("Unsolicited 101 rejected & valid 101 disables HTTP pool keep-alive") { sub =>
        var conn_bad = net::PooledConnection { transport: net::Transport.Mock { route_idx: 0, cursor: 0 }, .. };
        let plain_req = http::new_get("http://example.com/plain");
        var resp_bad = http::Response { status_code: 101, .. };
        let ok_bad, keep_bad = wing::pump_response_body(conn_bad, plain_req, resp_bad, "smuggled", 100);
        sub.assert_false(ok_bad || keep_bad, "Unsolicited 101 without Upgrade rejected");
    };

    t.run("H2 MadeYouReset reset_limiter triggers GOAWAY(ENHANCE_YOUR_CALM) & HPACK bomb aborts") { sub =>
        var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
        var wire_out: u8[>..] = [];
        var goaway_seen = false;
        for i in 1..1010 {
            let sid = ((i * 2) + 1) as u32;
            wire_out.clear();
            let ok_rst = server_internal::emit_rate_limited_rst_stream(sess, sid, rfc::H2_ERR_CANCEL, wire_out);
            if !ok_rst {
                goaway_seen = wire_out.len >= 9 && wire_out[3] == rfc::H2_FRAME_GOAWAY;
                break;
            }
        }
        sub.assert_true(goaway_seen, "Repeated server-initiated RST_STREAM triggers GOAWAY(ENHANCE_YOUR_CALM)");

        // Header list exceeding max_header_list_size followed by invalid opcode 0xFF must abort immediately with ENHANCE_YOUR_CALM
        var dt = http2::new_dynamic_table(4096);
        var enc_dt = http2::new_dynamic_table(4096);
        var bomb: u8[..512] = [];
        for _ in 4 {
            sub.require_true(
                http2::encode_hpack_field(
                    enc_dt, bomb, "x-pad", "01234567890123456789012345678901234567890123456789", http2::HpackIndexing.None, false,
                ),
                "Encoded HPACK bomb padding field",
            );
        }
        bomb.push(0xFF);
        var pseudo = http2::PseudoHeaders { .. };
        var hmap = http::HeaderMap { .. };
        let hpack_err = http2::decode_hpack_to_map(dt, bomb[..], pseudo, hmap, 256, false);
        sub.assert_eq(hpack_err, rfc::H2_ERR_ENHANCE_YOUR_CALM, "HPACK wireframe overflow aborts with ENHANCE_YOUR_CALM");
    };

    t.run("HPACK and QPACK encode cookie as NeverIndexed without Huffman") { sub =>
        var dt = http2::new_dynamic_table(4096);
        var hp_out: u8[..128] = [];
        let ck_val = "secret=abc123_long_cookie_value_over_20";
        let ck_idx = http2::select_hpack_indexing("cookie", ck_val, 4096);
        sub.assert_true(ck_idx == http2::HpackIndexing.NeverIndexed, "select_hpack_indexing forces NeverIndexed for all cookies");
        sub.require_true(
            http2::encode_hpack_field(dt, hp_out, "cookie", ck_val, ck_idx, true),
            "HPACK encode cookie",
        );
        // Never-Indexed indexed-name prefix is 0001xxxx (0x10..0x1F)
        sub.assert_true((hp_out[0] & 0xF0) == 0x10, "HPACK cookie forced to NeverIndexed (0x10)");
        sub.assert_true(core::contains(hp_out[..], ck_val), "HPACK cookie disables Huffman (cleartext length)");

        var qp_out: u8[..128] = [];
        sub.require_true(
            http3::encode_qpack_field(qp_out, "cookie", "secret=abc123", true, http3::QpackIndexingPolicy.Default),
            "QPACK encode cookie",
        );
        // QPACK Literal Field Line With Name Reference + Never-Indexed N=1 static T=1 => 0111xxxx (0x70..0x7F)
        sub.assert_true((qp_out[0] & 0xF0) == 0x70, "QPACK cookie forced to NeverIndexed (0x70)");
        sub.assert_true(core::contains(qp_out[..], "secret=abc123"), "QPACK cookie disables Huffman (cleartext length)");
    };

    t.run("WebSocket Origin check, gRPC trailer CRLF/CT guards, and SSE CTL/rollback invariants") { sub =>
        var policy = security::CorsPolicy { reject_non_matching_origin: true, .. };
        security::add_allowed_origin(policy, "https://trusted.example.com");
        var ws_req = http::new_get("https://api.example.com/ws");
        http::set_header(ws_req, "Host", "api.example.com");
        http::set_header(ws_req, "Upgrade", "websocket");
        http::set_header(ws_req, "Connection", "Upgrade");
        http::set_header(ws_req, "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        http::set_header(ws_req, "Sec-WebSocket-Version", "13");
        http::set_header(ws_req, "Origin", "https://evil.example.com");
        var ws_res = http::Response { .. };
        let _, ok_ws = realtime::ws_upgrade_request_with_policy(ws_req, ws_res, policy);
        sub.assert_false(ok_ws, "WS upgrade with disallowed Origin rejected");
        sub.assert_eq(ws_res.status_code, 403, "WS Origin rejection sets 403");

        var g_hdrs = http::HeaderMap { .. };
        http::append_header(g_hdrs, ":status", "200");
        http::append_header(g_hdrs, "content-type", "text/plain");
        var g_tr = http::HeaderMap { .. };
        http::append_header(g_tr, "grpc-status", "0");
        var g_resp = grpc::Response { .. };
        sub.assert_false(grpc::parse_unary_response(g_hdrs, g_tr, "", false, g_resp), "gRPC rejects non-grpc content-type");

        var g_hdrs_ok = http::HeaderMap { .. };
        http::append_header(g_hdrs_ok, "content-type", "application/grpc");
        var g_tr_dup = http::HeaderMap { .. };
        http::append_header(g_tr_dup, "grpc-status", "0");
        http::append_header(g_tr_dup, "grpc-status", "13");
        sub.assert_false(grpc::parse_unary_response(g_hdrs_ok, g_tr_dup, "", false, g_resp), "gRPC rejects duplicate grpc-status");

        var g_ctx = grpc::ServerContext { .. };
        sub.assert_false(grpc::add_response_trailer(g_ctx, "x-trace", "bad\r\ninject"), "gRPC rejects CRLF in trailer value");

        var small_sse: u8[..12] = [];
        sub.require_true(small_sse.try_set("pre:"), "Seed SSE buffer");
        sub.assert_false(realtime::sse_format_event(small_sse, "ev\r\ninjected", "payload-too-long"), "SSE overflow returns false");
        sub.assert_bytes_eq(small_sse[..], "pre:", "SSE rolls back buffer cleanly on overflow");

        var cap_idx: i64 = 0;
        let _, cap_st = net::skip_http_capsule("\x10\x03abcrest", cap_idx, 65536);
        sub.assert_true(cap_st == net::CapsuleParseStatus.Ok && cap_idx == 5, "skip_http_capsule advances past unknown capsule");
        var trunc_idx: i64 = 0;
        let _, trunc_st = net::skip_http_capsule("\x10\x05ab", trunc_idx, 65536);
        sub.assert_true(
            trunc_st == net::CapsuleParseStatus.Incomplete && trunc_idx == 0,
            "skip_http_capsule preserves idx on incomplete capsule",
        );

        net_internal::dpdk_free_mbuf(0);

        var wt_bad_req = http::new_get("https://wt.example.com/session");
        http::set_header(wt_bad_req, "Origin", "https://evil.example.com");
        sub.assert_false(realtime::validate_webtransport_origin(wt_bad_req, policy), "WebTransport rejects mismatched Origin");
        var wt_ok_req = http::new_get("https://wt.example.com/session");
        http::set_header(wt_ok_req, "Origin", "https://trusted.example.com");
        sub.assert_true(realtime::validate_webtransport_origin(wt_ok_req, policy), "WebTransport allows configured Origin");

        let wt_sess = realtime::WebTransportSession { session_id: 4, is_active: true, datagrams_enabled: true, .. };
        var wt_wire: u8[..128] = [];
        realtime::encode_webtransport_datagram(4, "ping", wt_wire);
        var wt_dgram = realtime::WebTransportDatagram { .. };
        sub.assert_true(
            realtime::accept_webtransport_datagram(wt_sess, wt_wire[..], wt_dgram) && wt_dgram.payload[..] == "ping",
            "accept_webtransport_datagram decodes valid session datagram",
        );
        sub.assert_false(
            realtime::accept_webtransport_datagram(wt_sess, wt_wire[..], wt_dgram, 2),
            "accept_webtransport_datagram enforces max_dgram_bytes quota",
        );

        var wt_demux = realtime::WebTransportDemuxer { .. };
        sub.require_true(realtime::register_webtransport_session(wt_demux, 4), "Register active WebTransport session");
        sub.assert_true(
            realtime::route_webtransport_datagram(wt_demux, wt_wire[..], wt_dgram) && wt_dgram.session_id == 4,
            "route_webtransport_datagram routes active session datagram",
        );
    };
}

// ----------------------------------------------------------------------------
// 4. Parsers (URL, DNS, JSON) & Client H3/Digest/PrivacyPass
// ----------------------------------------------------------------------------
fn test_wave2_parsers_and_client(t: lit::T&) {
    t.run("DNS parser rejects pointer compression loop and excessive jump budgets") { sub =>
        // Minimal 12-byte header (QDCOUNT=1) + pointer pointing to offset 12 (self-loop: 0xC0 0x0C)
        let loop_pkt: u8[18] = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
        ];
        let _, ok_loop = dns::parse_response(loop_pkt[..]);
        sub.assert_false(ok_loop, "DNS self-referential pointer loop rejected");
    };

    t.run("JSON parser rejects lone surrogates, duplicate keys, deep nesting, huge exponent & i32 overflow") { sub =>
        var r_sur = http::Response { status_code: 200, .. };
        r_sur.body.append("{\"id\":1,\"score\":1.0,\"name\":\"\\uD800\"}");
        let _, e_sur = http::decode_json<AuditJsonModel>(r_sur);
        sub.assert_false(http::ok(e_sur), "JSON rejects lone UTF-16 surrogate");

        var r_dup = http::Response { status_code: 200, .. };
        r_dup.body.append("{\"id\":1,\"id\":2}");
        let _, e_dup = http::decode_json<AuditJsonModel>(r_dup);
        sub.assert_false(http::ok(e_dup), "JSON rejects duplicate key");

        var r_edup = http::Response { status_code: 200, .. };
        r_edup.body.append("{\"\\u0069d\":1,\"id\":2}");
        let _, e_edup = http::decode_json<AuditJsonModel>(r_edup);
        sub.assert_false(http::ok(e_edup), "JSON rejects unicode-escaped duplicate key");

        var r_exp = http::Response { status_code: 200, .. };
        r_exp.body.append("{\"id\":1,\"score\":1e4096,\"name\":\"ok\"}");
        let _, e_exp = http::decode_json<AuditJsonModel>(r_exp);
        sub.assert_false(http::ok(e_exp), "JSON rejects non-finite 1e4096 f64 exponent");

        var r_i32 = http::Response { status_code: 200, .. };
        r_i32.body.append("{\"id\":3000000000,\"score\":1.0,\"name\":\"ok\"}");
        let _, e_i32 = http::decode_json<AuditJsonModel>(r_i32);
        sub.assert_false(http::ok(e_i32), "JSON rejects i32 overflow 3000000000");

        var r_deep = http::Response { status_code: 200, .. };
        for _ in 70 { r_deep.body.append("{\"a\":"); }
        r_deep.body.append("1");
        for _ in 70 { r_deep.body.push('}'); }
        let _, e_deep = http::decode_json<AuditNestedNode>(r_deep);
        sub.assert_false(http::ok(e_deep), "JSON rejects nesting depth > 64");
    };

    t.run("Client enforces PrivacyPass token-key/origin_info & pre-decompression Content-Digest") { sub =>
        var cli = client::new_client();
        cli.verify_content_digest = true;
        let payload = "tampered-response-body";
        var wrong_digest: u8[..128] = [];
        sub.require_true(http::format_digest_field_value("sha-256", "different-bytes", wrong_digest), "Digest formatted");
        let _ = cli.mock_route("GET", "https://edge.example.com/digest-check", 200, payload) { route =>
            route.add_mock_header("Content-Digest", wrong_digest[..]);
        };
        let _, err_cd = cli.get("https://edge.example.com/digest-check");
        sub.assert_false(http::ok(err_cd), "Pre-decompression Content-Digest mismatch aborts transfer");

        // Privacy Pass missing token-key parameter
        var chal = security::TokenChallenge { issuer_name: "issuer.example.com", .. };
        chal.origin_info.append("api.example.com");
        var raw_chal: u8[..256] = [];
        security::marshal_token_challenge(chal, raw_chal);
        var b64_chal: u8[..384] = [];
        security::encode_padded_base64url(raw_chal[..], b64_chal);

        var dummy_tok = security::Token { .. };
        let _ = security::put_private_token(cli.private_token_cache, chal, dummy_tok, "tok", 3600, 100);
        var hdr_nokey: u8[..512] = "PrivateToken challenge=\"";
        hdr_nokey.append(b64_chal[..]);
        hdr_nokey.push('"');
        cli.mock_route("GET", "https://api.example.com/no-key", 401, "need-token");
        cli.add_mock_header("WWW-Authenticate", hdr_nokey[..]);
        let r_pp, _ = cli.get("https://api.example.com/no-key");
        sub.assert_eq(http::sent_header(r_pp, "Authorization"), "", "PrivateToken 401 without token-key parameter rejected");
    };
}

// ----------------------------------------------------------------------------
// 5. Applied & Extended Crypto (BHTTP, OHTTP, PrivateJar, RFC 9421)
// ----------------------------------------------------------------------------
fn test_wave2_applied_and_extended_crypto(t: lit::T&) {
    t.run("BHTTP rejects hop-by-hop headers and mismatched content-length") { sub =>
        var breq = http::BhttpRequest { authority: "api.example.com", target: "/post", .. };
        http::append_header(breq.headers, "Connection", "close");
        var wire: u8[..8192] = [];
        let n_hop = http::bhttp_encode_request(breq, wire);
        sub.assert_lt(n_hop, 0, "BHTTP encode rejects hop-by-hop Connection header");

        var breq_cl = http::BhttpRequest { method: "POST", authority: "api.example.com", target: "/post", .. };
        http::append_header(breq_cl.headers, "Content-Length", "999");
        breq_cl.body.append("abc");
        breq_cl.body_len = 3;
        let n_cl = http::bhttp_encode_request(breq_cl, wire);
        if n_cl > 0 {
            var dec_cl = http::BhttpRequest { .. };
            sub.assert_false(http::bhttp_decode_request(wire[..n_cl], dec_cl), "BHTTP decode rejects mismatched content-length");
        } else {
            sub.assert_lt(n_cl, 0, "BHTTP encode rejects mismatched content-length");
        }
    };

    t.run("OHTTP, PrivateJar, and RFC 9421 fail closed on tampered ciphertext and signatures") { sub =>
        let gw_sk: u8[32] = [0x11; 32];
        let gw_pk = core::x25519_base_scalarmult(gw_sk);
        var cfg = http::OhttpKeyConfig {
            key_id:         1,
            kem_id:         0x0020,
            kdf_id:         0x0001,
            aead_id:        0x0001,
            public_key_len: 32,
            ..
        };
        let _ = cfg.public_key.try_set(gw_pk[..]);
        let eph_sk: u8[32] = [0x22; 32];
        var sealed:     u8[..8192] = [];
        var sealed_len: i32        = 0;
        var s_cli = http::OhttpSession { .. };
        sub.require_true(http::ohttp_seal_request(cfg, eph_sk, "inner-bhttp", sealed, sealed_len, s_cli), "OHTTP seal");
        var replay_cache = http::OhttpReplayCache { ttl_sec: 300, .. };
        var out_open:     u8[..8192] = [];
        var out_open_len: i32        = 0;
        var s_gw = http::OhttpSession { .. };
        sub.assert_true(
            http::ohttp_open_request_checked(replay_cache, gw_sk[..], sealed[..sealed_len], 1000, out_open, out_open_len, s_gw) &&
                out_open[..out_open_len] == "inner-bhttp",
            "ohttp_open_request_checked accepts fresh request",
        );
        sub.assert_false(
            http::ohttp_open_request_checked(replay_cache, gw_sk[..], sealed[..sealed_len], 1001, out_open, out_open_len, s_gw),
            "ohttp_open_request_checked rejects replayed enc",
        );
        var enc_resp:     u8[..8192] = [];
        var enc_resp_len: i32        = 0;
        sub.assert_true(
            http::ohttp_seal_response_random(s_gw, "ok-resp", enc_resp, enc_resp_len) && enc_resp_len > 16,
            "ohttp_seal_response_random seals once",
        );
        sub.assert_false(
            http::ohttp_seal_response_random(s_gw, "ok-resp", enc_resp, enc_resp_len),
            "ohttp_seal_response_random rejects second seal on same session",
        );
        http::zeroize_ohttp_session(s_gw);
        http::zeroize_ohttp_session(s_cli);
        sub.assert_true(s_gw.enc_len == 0 && !s_gw.response_sealed, "zeroize_ohttp_session clears secrets");

        if sealed_len > 10 {
            sealed[sealed_len - 1] = sealed[sealed_len - 1] ^ 0xFF;
            var s_bad_gw = http::OhttpSession { .. };
            sub.assert_false(
                http::ohttp_open_request(gw_sk[..], sealed[..sealed_len], out_open, out_open_len, s_bad_gw),
                "OHTTP open rejects tampered ciphertext tag",
            );
        }

        var ks = security::KeyStore { .. };
        let mk: u8[32] = [0x5A; 32];
        let jar_slot = security::KeySlot { key_id: 1, master_key: mk, .. };
        let _ = security::add_key(ks, jar_slot);
        let jar_a, ok_ja = security::new_private_jar_with_context(ks, false, "tenant-a");
        let jar_b, ok_jb = security::new_private_jar_with_context(ks, false, "tenant-b");
        sub.require_true(ok_ja && ok_jb, "PrivateJar context construction succeeds");
        var ctx_tok: u8[..512] = [];
        sub.require_true(jar_a.seal("sid", "secret-session", 1000, 12345, ctx_tok), "PrivateJar context seal succeeds");
        var wrong_ctx_buf: u8[..256] = [];
        sub.assert_false(jar_b.open("sid", ctx_tok[..], 1001, wrong_ctx_buf), "PrivateJar rejects cross-context open");
        let jar = security::new_private_jar(ks);
        var tok_buf: u8[..512] = [];
        sub.require_true(jar.seal("sid", "secret-session", 1000, 12345, tok_buf), "PrivateJar seal succeeds");
        var wrong_name_buf: u8[..256] = [];
        sub.assert_false(jar.open("other", tok_buf[..], 1001, wrong_name_buf), "PrivateJar rejects mismatched cookie name AAD");
        if tok_buf.len > 4 {
            tok_buf[tok_buf.len - 2] = tok_buf[tok_buf.len - 2] ^ 0x55;
            var plain_buf: u8[..256] = [];
            sub.assert_false(jar.open("sid", tok_buf[..], 1001, plain_buf), "PrivateJar open rejects tampered ciphertext");
        }

        let pq_d: u8[32] = [0x41; 32];
        let pq_z: u8[32] = [0x42; 32];
        let _, _, ok_pq = tls_internal::mlkem768_keygen_checked(pq_d, pq_z);
        sub.assert_true(ok_pq, "mlkem768_keygen_checked passes PCT");

        let ed_seed: u8[32] = [0x33; 32];
        let kp = core::ed25519_keypair(ed_seed);
        var s_req = http::new_request("POST", "https://api.example.com/pay");
        http::set_header(s_req, "Host", "api.example.com");
        s_req.body.append("amount=10");
        sub.require_true(http::sign_request_ed25519(s_req, "k1", kp.seed[..]), "Sign RFC 9421 request");
        var tampered_req = copy(s_req);
        tampered_req.method.clear();
        tampered_req.method.append("DELETE");
        sub.assert_false(
            http::verify_request_ed25519(tampered_req, "k1", kp.public_key[..]),
            "RFC 9421 Ed25519 rejects mutated request method",
        );
    };
}

fn main() {
    let _ = net::tcp_init();
    var runner = lit::new_runner("Wave 2 Security Audit Regression Suite", lit::Verbosity.Verbose);
    lit::run_case(runner, "1. Compression & RFC 8879 (W2_H3_*)", test_wave2_compression_and_rfc8879);
    lit::run_case(runner, "2. Proxy, Cookie/PSL, Cache & Web Policies (W2_H5_*)", test_wave2_proxy_cookie_cache_policies);
    lit::run_case(runner, "3. Framing, Mux, HPACK/QPACK, gRPC, WS, SSE (W2_H4_*)", test_wave2_framing_mux_realtime);
    lit::run_case(runner, "4. Parsers (URL, DNS, JSON) & Client H3/Digest/PrivacyPass (W2_H6_*, W2_H1_*)", test_wave2_parsers_and_client);
    lit::run_case(runner, "5. Applied & Extended Crypto (BHTTP, OHTTP, PrivateJar, RFC 9421)", test_wave2_applied_and_extended_crypto);
    let ok = lit::finish(runner);
    assert(ok);
}
