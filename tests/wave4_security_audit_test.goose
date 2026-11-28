// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Wave 4 Security & RFC Conformance Audit Regression Suite (0.1.1).
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn w4_dummy_grpc_handler(
    handler_id:  u16,
    ctx:         grpc::ServerContext&,
    req_payload: const u8[:],
    res_payload: u8[>..]&,
) -> grpc::Status {
    let _ = handler_id;
    let _ = ctx;
    let _ = req_payload;
    let _ = res_payload;
    return grpc::ok();
}

fn test_w4_proxy_and_forwarded_hardening(sub: lit::T&) {
    // W4-PROXY-01: RFC 7239 Forwarded injection via Host header (preserve_host=false)
    var cfg = proxy::Config {
        preserve_host:          false,
        append_forwarded:       true,
        emit_rfc7239_forwarded: true,
        ..
    };
    var in_hdrs = http::HeaderMap { .. };
    let _ = http::append_header(in_hdrs, "Host", "a,for=127.0.0.1;host=internal.corp");
    var out_hdrs = http::HeaderMap { .. };
    sub.assert_false(
        proxy::filter_and_forward_headers(in_hdrs, out_hdrs, "203.0.113.5", "http", "backend:8080", cfg, "GET"),
        "W4-PROXY-01 rejects malformed Host with RFC 7239 injection payload even when preserve_host=false",
    );

    // W4-PROXY-01b: append_quoted_node quotes/escapes non-tchar values, rejects CTLs, and rolls back on overflow
    var fwd_elem = http::ForwardedElement { .. };
    let _ = fwd_elem.for_node.try_set("203.0.113.5");
    let _ = fwd_elem.host.try_set("a,for=127.0.0.1");
    var fwd_out: u8[..256] = [];
    http::format_forwarded_element(fwd_elem, fwd_out);
    sub.assert_contains(fwd_out[..], "host=\"a,for=127.0.0.1\"", "W4-PROXY-01b quotes comma-bearing host");
    var fwd_ctl = http::ForwardedElement { .. };
    let _ = fwd_ctl.host.try_set("bad\r\nX-Injected: 1");
    var fwd_ctl_out: u8[..256] = [];
    http::format_forwarded_element(fwd_ctl, fwd_ctl_out);
    sub.assert_eq(fwd_ctl_out.len, 0, "W4-PROXY-01c rejects CRLF inside Forwarded element");
    var fwd_tiny: u8[..16] = [];
    http::format_forwarded_element(fwd_elem, fwd_tiny);
    sub.assert_eq(fwd_tiny.len, 0, "W4-PROXY-01d rolls back Forwarded element on buffer overflow (no unclosed quote)");

    // W4-PROXY-02: Via loop-detection rejects unbalanced parentheses
    var via_in = http::HeaderMap { .. };
    let _ = http::append_header(via_in, "Host", "example.com");
    let _ = http::append_header(via_in, "Via", "1.1 edge (x, 1.1 wing");
    var via_out = http::HeaderMap { .. };
    sub.assert_false(
        proxy::filter_and_forward_headers(via_in, via_out, "203.0.113.5", "http", "backend:8080", cfg, "GET"),
        "W4-PROXY-02 rejects Via with unclosed comment parenthesis",
    );

    // W4-PROXY-03: try_rewrite_upstream_url blocks protocol-relative // and /\ open redirects
    var loc_out: u8[..256] = [];
    let _, ok_slash = proxy::try_rewrite_upstream_url("http://backend:8080/evil.com", "http://backend:8080", "/", loc_out);
    sub.assert_false(ok_slash, "W4-PROXY-03 blocks //evil.com rewrite with public_url_prefix=/");
    let _, ok_bs = proxy::try_rewrite_upstream_url("http://backend:8080/\\evil.com", "http://backend:8080", "", loc_out);
    sub.assert_false(ok_bs, "W4-PROXY-03 blocks /\\evil.com WHATWG open redirect");
    let _, ok_qscheme = proxy::try_rewrite_upstream_url(
        "http://backend:8080//evil.com/?r=http://ok", "http://backend:8080", "", loc_out,
    );
    sub.assert_false(ok_qscheme, "W4-PROXY-03b blocks //evil.com/?r=http://ok query-scheme open redirect bypass");
    let rew_ok, ok_good = proxy::try_rewrite_upstream_url("http://backend:8080/app/home", "http://backend:8080", "", loc_out);
    sub.assert_true(ok_good && rew_ok == "/app/home", "W4-PROXY-03 allows clean relative path rewrite");

    // W4-PROXY-04: H2 upstream DirectHeaders rejects TE+CL and conflicting CL+CL
    var h2_sess = proxy::h2_upstream_open(proxy::H2UpstreamConfig { .. });
    defer proxy::h2_upstream_close(h2_sess);
    var bad_te_cl = http::HeaderMap { .. };
    let _ = http::append_header(bad_te_cl, "Transfer-Encoding", "chunked");
    let _ = http::append_header(bad_te_cl, "Content-Length", "5");
    let _, ok_te_cl = proxy::h2_upstream_open_stream(
        h2_sess, "POST", "https", "backend.local", "/upload", bad_te_cl, "203.0.113.5",
        proxy::H2UpstreamStreamEnd.OpenBody, proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    sub.assert_false(ok_te_cl, "W4-PROXY-04 DirectHeaders rejects TE+CL framing conflict");

    // W4-PROXY-05: H2 upstream caps consecutive 1xx HEADERS (prevents unbounded RAM amplification)
    var h2_1xx = proxy::h2_upstream_open(proxy::H2UpstreamConfig { .. });
    defer proxy::h2_upstream_close(h2_1xx);
    var ok_hdrs = http::HeaderMap { .. };
    let sid, ok_open = proxy::h2_upstream_open_stream(
        h2_1xx, "GET", "https", "backend.local", "/stream", ok_hdrs, "203.0.113.5",
        proxy::H2UpstreamStreamEnd.EndStream, proxy::H2UpstreamHeaderFilter.DirectHeaders,
    );
    sub.assert_true(ok_open && sid == 1, "H2 upstream stream 1 opens cleanly");
    var peer_wire: u8[>..] = [];
    // Server empty SETTINGS + 6 consecutive 100 Continue HEADERS frames on stream 1
    let empty_s: wire::WireSetting[0] = [];
    let _ = wire::encode_settings_frame(empty_s[..], peer_wire);
    // HPACK literal without indexing: :status (idx 8) = "100" -> [0x08, 0x03, '1', '0', '0']
    var hpack_100: u8[5] = [0x08, 0x03, '1', '0', '0'];
    for _ in 6 {
        let fh = http2::FrameHeader {
            length:     5,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  1,
        };
        http2::encode_frame_header_to(fh, peer_wire);
        peer_wire.append(hpack_100[..]);
    }
    sub.assert_false(
        proxy::h2_upstream_feed(h2_1xx, peer_wire[..]),
        "W4-PROXY-05 rejects 6th consecutive 1xx interim HEADERS frame",
    );
}

fn test_w4_security_csrf_gcra_ssrf_cors(sub: lit::T&) {
    // W4-SEC-01: CSRF //admin/webhook must NOT match exempt_paths=["/webhook"]
    let p_norm = security::extract_path_from_url("//admin/webhook?x=1");
    sub.assert_bytes_eq(p_norm, "/admin/webhook", "W4-SEC-01 preserves /admin/webhook instead of stripping //admin");
    var cfg = security::CrossOriginGuard { .. };
    let _ = security::add_exempt_path(cfg, "/webhook");
    var req = http::new_request("POST", "//admin/webhook");
    http::set_header(req, "Host", "app.example.com");
    http::set_header(req, "Sec-Fetch-Site", "cross-site");
    let dec = security::evaluate_request_csrf(cfg, req, "app.example.com");
    sub.assert_false(dec == security::CsrfDecision.AllowExempt, "W4-SEC-01 blocks CSRF bypass via //admin/webhook");

    // W4-SEC-02: GCRA 60s penalty must not be erased by clamp_clock_drift
    let gcfg = security::new_gcra_config(10, 5);
    var cell = security::GcraCell { .. };
    let t0: u64 = 10000000000;
    security::gcra_penalize(gcfg, cell, 60000000000, t0);
    let d1 = security::gcra_check(gcfg, cell, 1, t0 + 1);
    sub.assert_false(d1.allowed, "W4-SEC-02 first check after 60s penalty rejected");
    let d2 = security::gcra_check(gcfg, cell, 1, t0 + 100000001);
    sub.assert_false(d2.allowed, "W4-SEC-02 check at +100ms still blocked (60s penalty preserved)");
    var gw_rl = security::new_gateway_rate_limiter(10, 5);
    security::penalize_gateway_client(gw_rl, "abusive", 60000000000, t0);
    security::reset_gateway_rate_limiter(gw_rl);
    sub.assert_eq(gw_rl.fallback_cell.penalty_until_ns, 0, "W4-SEC-02b gateway reset clears fallback penalty_until_ns");
    let gw_dec = security::check_gateway_rate_limit(gw_rl, "fresh-client", 1, t0 + 1);
    sub.assert_true(gw_dec.allowed, "W4-SEC-02c fresh client after gateway reset is not penalized");

    // W4-SEC-03: SSRF blocks bracketed IPv6 with trailing dot, overlong >256B hex metadata, and RFC 6890 IPv6
    sub.assert_true(security::is_private_or_reserved_ip("[::1]."), "W4-SEC-03 blocks [::1].");
    sub.assert_true(security::is_forbidden_internal_host("[::1]."), "W4-SEC-03 forbidden_internal_host blocks [::1].");
    sub.assert_true(security::is_cloud_metadata_or_reserved_ip("[fd00:ec2::254]."), "W4-SEC-03 blocks [fd00:ec2::254].");
    sub.assert_true(security::is_private_or_reserved_ip("[fe80::1%25eth0]."), "W4-SEC-03 blocks [fe80::1%25eth0].");
    sub.assert_true(security::is_private_or_reserved_ip("2001:1::1"), "W4-SEC-03 blocks RFC 6890 2001::/23");
    sub.assert_true(security::is_private_or_reserved_ip("::ffff:0:8.8.8.8"), "W4-SEC-03 blocks RFC 6890 SIIT ::ffff:0:0:0/96");
    var long_hex: u8[..300] = [];
    let _ = long_hex.try_append("0x");
    for _ in 250 {
        let _ = long_hex.try_push('0');
    }
    let _ = long_hex.try_append("a9fea9fe.");
    sub.assert_true(security::is_cloud_metadata_or_reserved_ip(long_hex[..]), "W4-SEC-03 fails closed on >256B metadata IP");
    sub.assert_true(security::is_non_canonical_ipv4(long_hex[..]), "W4-SEC-03 detects trailing-dot hex IPv4");

    // W4-SEC-04: CORS verify_client_cors_response enforces exact byte-for-byte origin match
    var ch = http::HeaderMap { .. };
    let _ = http::append_header(ch, "Access-Control-Allow-Origin", "HTTPS://APP.EXAMPLE");
    let _ = http::append_header(ch, "Access-Control-Allow-Credentials", "true");
    let copts = security::ClientCorsVerifyOptions { include_credentials: true, .. };
    sub.assert_false(
        security::verify_client_cors_response(ch, "https://app.example", copts),
        "W4-SEC-04 rejects uppercase ACAO mismatch per WHATWG Fetch",
    );
}

fn test_w4_cookie_auth_url_dns(sub: lit::T&) {
    // W4-COOKIE-01: core::is_ip_address_literal validates actual IPv6 syntax
    sub.assert_false(core::is_ip_address_literal("example.com:8443"), "W4-COOKIE-01 host:port is not IP literal");
    sub.assert_false(core::is_ip_address_literal("evil..com:8080"), "W4-COOKIE-01 evil..com:8080 is not IP literal");
    sub.assert_true(core::is_ip_address_literal("::1"), "W4-COOKIE-01 ::1 is IP literal");
    sub.assert_true(core::is_ip_address_literal("[2001:db8::1]"), "W4-COOKIE-01 [2001:db8::1] is IP literal");
    sub.assert_true(core::is_ip_address_literal("127.0.0.1"), "W4-COOKIE-01 127.0.0.1 is IP literal");
    var long_url: u8[>..] = [];
    long_url.append("https://example.com:8443/api?");
    for _ in 2060 {
        long_url.push('a');
    }
    let cu = cookie::parse_canonical_cookie_url(long_url[..]);
    sub.assert_true(cu.host[..] == "example.com" && cu.port == 8443, "W4-COOKIE-01 >2048B fallback URL parses port 8443");

    // W4-COOKIE-02: Unrecognized SameSite must not overwrite Strict or bypass SameSite=None Secure check
    var jar = cookie::CanonicalCookieJar { .. };
    let ok_s = cookie::set_cookie_header(
        jar, "https://example.com/", "sid=secret; Secure; SameSite=Strict; SameSite=Invalid", 1700000000000000,
    );
    sub.assert_true(ok_s && jar.cookies.len == 1 && jar.cookies[0].same_site == cookie::SameSite.Strict, "W4-COOKIE-02 preserves Strict on invalid duplicate SameSite");
    let ok_n = cookie::set_cookie_header(
        jar, "http://example.com/", "bad=1; SameSite=None; SameSite=Invalid", 1700000000000000,
    );
    sub.assert_false(ok_n, "W4-COOKIE-02 rejects plaintext SameSite=None followed by SameSite=Invalid");

    // W4-COOKIE-03 & 04: find_cookie_value skips malformed pairs; jar.add rejects ';' injection
    let fv, ok_fv = cookie::find_cookie_value("prefs=a,b; sid=real", "sid");
    sub.assert_true(ok_fv && fv == "real", "W4-COOKIE-03 find_cookie_value skips malformed preceding pair");
    var jar2 = cookie::CanonicalCookieJar { .. };
    let _ = cookie::add(jar2, "sid", "1; role=admin");
    sub.assert_eq(jar2.cookies.len, 0, "W4-COOKIE-04 jar.add rejects semicolon injection in value");

    // W4-AUTH-01/02/03: JWT cnf escape rejection, crit standard JWS param rejection, Basic/Digest CTL rejection
    var claims = auth::JwtClaims { .. };
    sub.assert_false(
        auth::parse_jwt_claims_json("{\"sub\":\"u1\",\"exp\":2000000000,\"cnf\":{\"\\u006akt\":\"bound_jkt\"}}", claims),
        "W4-AUTH-01 rejects escaped key inside JWT cnf claim",
    );
    var jhdr = auth::JwtHeader { .. };
    sub.assert_false(
        auth::parse_jwt_header_json("{\"alg\":\"HS256\",\"jwk\":{},\"crit\":[\"jwk\"]}", jhdr),
        "W4-AUTH-02 rejects standard JWS parameter in crit",
    );
    var breq = http::new_request("GET", "/");
    sub.assert_false(http::basic_auth(breq, "alice\r\n", "pass"), "W4-AUTH-03 basic_auth rejects CTLs in user");
    sub.assert_false(http::basic_auth(breq, "alice", "pass\x07"), "W4-AUTH-03 basic_auth rejects CTLs in pass");

    // W4-URL-01: Overflowing IPv4 last label rejected instead of accepted as domain
    let _, err_ov = core::parse_url("http://127.0.0.4294967296/");
    sub.assert_true(
        err_ov != core::UrlParseError.None,
        "W4-URL-01 rejects overflowing IPv4 numeric hostname",
    );

    // W4-DNS-01/02: RFC 9460 >8 ipv4hint accepted, mandatory=no-default-alpn accepted, key 65535 rejected
    var hrec = dns::HttpsRecord { .. };
    // key=4 (ipv4hint), len=36 (9 IPv4 addresses)
    var rdata_9ip: u8[40] = [0; 40];
    rdata_9ip[0] = 0;
    rdata_9ip[1] = 4;
    rdata_9ip[2] = 0;
    rdata_9ip[3] = 36;
    for i in 9 {
        rdata_9ip[4 + i * 4] = 192;
        rdata_9ip[5 + i * 4] = 0;
        rdata_9ip[6 + i * 4] = 2;
        rdata_9ip[7 + i * 4] = (i + 1) as u8;
    }
    sub.assert_true(dns::parse_https_svc_params(hrec, rdata_9ip[..]), "W4-DNS-01 accepts >8 ipv4hint without DoS");
    sub.assert_eq(hrec.ipv4_hints.len, 8, "W4-DNS-01 stores first 8 ipv4hint slots");

    var rdata_65535: u8[4] = [0xFF, 0xFF, 0x00, 0x00];
    var hrec2 = dns::HttpsRecord { .. };
    sub.assert_false(dns::parse_https_svc_params(hrec2, rdata_65535[..]), "W4-DNS-02 rejects reserved SvcParamKey 65535");
    var mand_65535: u8[2] = [0xFF, 0xFF];
    let _, ok_m65535 = dns::parse_mandatory_svc_param(mand_65535[..]);
    sub.assert_false(ok_m65535, "W4-DNS-02b mandatory rejects reserved SvcParamKey 65535");
}

fn test_w4_grpc_wire_and_realtime(sub: lit::T&) {
    // W4-GRPC-01: Unregistered 242-byte path must return Unimplemented without buffer overflow panic
    var disp = grpc::new_server_dispatcher();
    var long_path: u8[..260] = [];
    let _ = long_path.try_push('/');
    for _ in 120 { let _ = long_path.try_push('a'); }
    let _ = long_path.try_push('/');
    for _ in 120 { let _ = long_path.try_push('b'); }
    var greq = http::new_request("POST", long_path[..]);
    http::set_header(greq, "content-type", "application/grpc");
    var gres = http::Response { .. };
    let ok_disp = grpc::dispatch_unary(disp, greq, 1000, gres, 1000, w4_dummy_grpc_handler);
    sub.assert_true(ok_disp, "W4-GRPC-01 242B unregistered path dispatches without panic");
    let st_hdr = if gres.trailer("grpc-status").len > 0 {
        gres.trailer("grpc-status")
    } else {
        gres.header("grpc-status")
    };
    sub.assert_bytes_eq(st_hdr, "12", "W4-GRPC-01 returns Unimplemented (12)");

    // W4-GRPC-02: Malformed gRPC-Web trailer frame fails closed and clears payload
    var gw_body: u8[..64] = [];
    let _ = gw_body.try_append("\x00\x00\x00\x00\x02ok\x80\x00\x00\x00\x20grpc-status: 0\r\ngrpc-status: 7\r\n");
    var gw_hdrs = http::HeaderMap { .. };
    let _ = http::append_header(gw_hdrs, "content-type", "application/grpc-web+proto");
    var gw_tr = http::HeaderMap { .. };
    var gw_resp = grpc::Response { .. };
    sub.assert_false(
        grpc::parse_unary_response(gw_hdrs, gw_tr, gw_body[..], true, gw_resp),
        "W4-GRPC-02 rejects duplicate grpc-status in gRPC-Web trailer frame",
    );
    sub.assert_eq(gw_resp.payload.len, 0, "W4-GRPC-02 clears payload on malformed trailers");

    // W4-WIRE-01: serialize_h1_request rejects Content-Length != body.len and strips IPv6 ZoneID
    let u_h1, _ = core::parse_url("http://example.com/submit");
    var sm_req = http::new_request("POST", "/submit");
    http::set_header(sm_req, "Content-Length", "5");
    sm_req.body.append("12345GET /admin HTTP/1.1\r\nHost: x\r\n\r\n");
    var wire_out: u8[..4096] = [];
    sub.assert_false(wing::serialize_h1_request(sm_req, u_h1, wire_out), "W4-WIRE-01 blocks Content-Length mismatch smuggling");

    let u_z, _ = core::parse_url("http://[fe80::1%25eth0]:8080/ping");
    var z_req = http::new_request("GET", "/ping");
    sub.assert_true(wing::serialize_h1_request(z_req, u_z, wire_out), "W4-WIRE-01 serializes link-local IPv6 request");
    sub.assert_false(core::contains(wire_out[..], "%25eth0"), "W4-WIRE-01 strips IPv6 ZoneID from Host header");
    var conn_req = http::new_request("CONNECT", "/");
    sub.assert_true(wing::serialize_h1_request(conn_req, u_z, wire_out), "W4-WIRE-01b serializes CONNECT IPv6 request");
    sub.assert_false(core::contains(wire_out[..], "%25eth0"), "W4-WIRE-01b strips IPv6 ZoneID from CONNECT target");
    var bad_url = core::Url { .. };
    sub.assert_false(wing::serialize_h1_request(z_req, bad_url, wire_out), "W4-WIRE-01c fails closed on invalid Url");

    // W4-RT-01: SSE Last-Event-ID strips ASCII CTL bytes (0x0B, 0x0C, 0x7F)
    var sse_sub = realtime::new_sse_subscription("http://example.com/events");
    var sse_evs: realtime::SseEvent[..4] = [];
    realtime::consume(sse_sub, "id: tok\x0B\x0C\x7F\ndata: hi\n\n", sse_evs);
    var sse_hdr: u8[..512] = [];
    sub.assert_true(realtime::sse_build_request_headers(sse_sub, "example.com", "/events", sse_hdr), "W4-RT-01 builds SSE reconnect headers");
    sub.assert_contains(sse_hdr[..], "Last-Event-ID: tok\r\n", "W4-RT-01 strips CTL bytes from Last-Event-ID");
    sub.assert_false(sse_hdr[..].contains_byte(0x0B), "W4-RT-01 no 0x0B in outbound header");

    // W4-RT-02: DedicatedWsCompressor separates TX and RX LZ77 sliding windows
    var ded = realtime::new_dedicated_ws_compressor(32);
    var peer_tx = realtime::new_dedicated_ws_compressor(32);
    var c1:      u8[..512] = [];
    var c2:      u8[..512] = [];
    var tx_junk: u8[..512] = [];
    var p1:      u8[..512] = [];
    var p2:      u8[..512] = [];
    let msg1 = "alpha-beta-gamma-delta-epsilon-zeta-eta-theta-0123456789";
    let msg2 = "alpha-beta-gamma-delta-epsilon-zeta-eta-theta-9876543210";
    sub.assert_true(realtime::deflate_message_dedicated(peer_tx, msg1, c1, false), "peer deflate msg1");
    sub.assert_true(realtime::deflate_message_dedicated(peer_tx, msg2, c2, false), "peer deflate msg2");
    sub.assert_true(realtime::inflate_message_dedicated(ded, c1[..], p1, 512, false) && p1[..] == msg1, "rx inflate msg1");
    // Interleave outbound TX deflate on `ded` before receiving peer msg2
    sub.assert_true(
        realtime::deflate_message_dedicated(ded, "outbound-tx-payload-that-must-not-corrupt-rx-history", tx_junk, false),
        "interleaved tx deflate",
    );
    sub.assert_true(
        realtime::inflate_message_dedicated(ded, c2[..], p2, 512, false) && p2[..] == msg2,
        "W4-RT-02 rx inflate msg2 succeeds without TX dictionary corruption",
    );

    // W4-RT-03: Unsolicited PONG flood during active fragmentation still hits WS_LIVE_MAX_CTRL_FRAMES (-2)
    var ws_conn = realtime::WsConn {
        ws:   realtime::new_websocket_session(true),
        open: true,
        ..
    };
    let frag_start: u8[2] = [0x01, 0x00]; // FIN=0, TEXT, len=0
    let pong_frame: u8[2] = [0x8A, 0x00]; // FIN=1, PONG, len=0
    ws_conn.rx_buf.append(frag_start[..]);
    for _ in 20 {
        ws_conn.rx_buf.append(pong_frame[..]);
    }
    var ws_op: u8      = 0;
    var ws_pl: u8[>..] = [];
    let ws_rc = realtime::ws_recv_frame(ws_conn, ws_op, ws_pl, 5000);
    sub.assert_eq(ws_rc, -2, "W4-RT-03 unsolicited PONG flood during fragmentation hits control-frame limit");
}

fn main() {
    let _ = net::tcp_init();
    var runner = lit::new_runner("Wave 4 Security & RFC Conformance Audit Regression Suite", lit::Verbosity.Verbose);
    lit::run_case(runner, "1. Proxy Forwarded, Via, Redirect & H2 Upstream Hardening", test_w4_proxy_and_forwarded_hardening);
    lit::run_case(runner, "2. Security CSRF, GCRA Penalty, SSRF & CORS Hardening", test_w4_security_csrf_gcra_ssrf_cors);
    lit::run_case(runner, "3. Cookie, Auth JWT/Basic, URL & DNS RFC 9460 Hardening", test_w4_cookie_auth_url_dns);
    lit::run_case(runner, "4. gRPC, Wire H1 Framing & Realtime SSE/WS Hardening", test_w4_grpc_wire_and_realtime);
    let ok = lit::finish(runner);
    assert(ok);
}
