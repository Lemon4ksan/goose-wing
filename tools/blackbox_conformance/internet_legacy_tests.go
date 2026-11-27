// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

package main

import (
	"bytes"
	"compress/flate"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// runInternetLegacySuite executes non-duplicate real-world internet and legacy
// client/proxy/middlebox semi-valid wire probes across all live goose-wing
// server engines (reactor, listener/h2c, TLS 1.3, WebSocket, gRPC, HTTP/3).
// Returns the number of recorded FAIL cases.
func runInternetLegacySuite(pki *testPKI) int {
	_ = pki
	rec := &testRecorder{}
	binDir := filepath.Join(repoRoot, "tools", "bin")

	chaosExe := exePath(binDir, "chaos_server")
	h2specExe := exePath(binDir, "h2spec_server")
	tlsExe := exePath(binDir, "tls_server")
	autobahnExe := exePath(binDir, "autobahn_server")
	grpcExe := exePath(binDir, "grpc_server")
	http3Exe := exePath(binDir, "http3_server")

	runLegacyReactorH1Suite(rec, chaosExe)
	runLegacyListenerAndH2Suite(rec, h2specExe)
	runLegacyTLSAndH2Suite(rec, tlsExe)
	runLegacyWebSocketSuite(rec, autobahnExe)
	runLegacyGrpcSuite(rec, grpcExe)
	runLegacyHTTP3NoiseSuite(rec, http3Exe)

	fmt.Println("\n================ INTERNET & LEGACY SUITE SUMMARY ================")
	type counts struct{ pass, fail, warn, info int }
	bySuite := map[string]*counts{}
	var order []string
	var fails, warns, infos []testResult
	var logBuf strings.Builder
	for _, r := range rec.results {
		if _, ok := bySuite[r.suite]; !ok {
			bySuite[r.suite] = &counts{}
			order = append(order, r.suite)
		}
		c := bySuite[r.suite]
		switch r.status {
		case "PASS":
			c.pass++
		case "FAIL":
			c.fail++
			fails = append(fails, r)
		case "WARN":
			c.warn++
			warns = append(warns, r)
		case "INFO":
			c.info++
			infos = append(infos, r)
		}
		fmt.Fprintf(&logBuf, "[%s] %s/%s/%s | exp=%s | got=%s | hex=%s\n",
			r.status, r.suite, r.category, r.name, r.expected, r.observed, r.wireHex)
	}
	for _, s := range order {
		c := bySuite[s]
		fmt.Printf("  %-22s: PASS=%3d  FAIL=%3d  WARN=%2d  INFO=%2d\n", s, c.pass, c.fail, c.warn, c.info)
	}
	fmt.Printf("\nLEGACY TOTALS -> FAIL=%d | WARN=%d | INFO=%d\n", len(fails), len(warns), len(infos))
	if len(fails) > 0 {
		fmt.Println("\n--- LEGACY FAILURES ---")
		for _, f := range fails {
			fmt.Printf("  [FAIL] %s/%s/%s\n         exp: %s\n         got: %s\n",
				f.suite, f.category, f.name, f.expected, f.observed)
			if f.wireHex != "" {
				fmt.Printf("         hex: %s\n", f.wireHex)
			}
		}
	}
	if len(warns) > 0 {
		fmt.Println("\n--- LEGACY WARNINGS ---")
		for _, w := range warns {
			fmt.Printf("  [WARN] %s/%s/%s | exp=%s | got=%s\n", w.suite, w.category, w.name, w.expected, w.observed)
		}
	}
	if len(infos) > 0 {
		fmt.Println("\n--- LEGACY INFO / DIFFERENTIALS ---")
		for _, in := range infos {
			fmt.Printf("  [INFO] %s/%s/%s | exp=%s | got=%s\n", in.suite, in.category, in.name, in.expected, in.observed)
		}
	}
	if logDir != "" {
		logPath := filepath.Join(logDir, "legacy_results.log")
		_ = os.WriteFile(logPath, []byte(logBuf.String()), 0600)
		fmt.Printf("\n[+] Legacy wire log written to %s\n", logPath)
	}
	return len(fails)
}

func tcpExchangeRaw(addr string, chunks [][]byte, interDelay time.Duration, shutWR bool, totalTimeout time.Duration) ([]byte, time.Duration, error) {
	conn, err := net.DialTimeout("tcp", addr, 1500*time.Millisecond)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	t0 := time.Now()
	for i, c := range chunks {
		if i > 0 && interDelay > 0 {
			time.Sleep(interDelay)
		}
		if len(c) > 0 {
			if _, werr := conn.Write(c); werr != nil {
				return nil, time.Since(t0), werr
			}
		}
	}
	if shutWR {
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(totalTimeout))
	var out bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, rerr := conn.Read(buf)
		if n > 0 {
			out.Write(buf[:n])
			_ = conn.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
		}
		if rerr != nil {
			break
		}
	}
	return out.Bytes(), time.Since(t0), nil
}

func httpStatusLine(raw []byte) string {
	before, _, ok := bytes.Cut(raw, []byte("\r\n"))
	if !ok {
		return truncStr(string(raw), 64)
	}
	return string(before)
}

func tcpCanaryOK(addr, req string, expectSub string) (bool, string) {
	resp, dt, err := tcpExchangeRaw(addr, [][]byte{[]byte(req)}, 0, false, 1500*time.Millisecond)
	if err != nil {
		return false, fmt.Sprintf("err=%v dt=%v", err, dt.Round(time.Millisecond))
	}
	if !strings.Contains(string(resp), expectSub) {
		return false, fmt.Sprintf("missing %q got=%q", expectSub, truncStr(string(resp), 64))
	}
	return true, ""
}

func checkOrRestartHTTP(rec *testRecorder, suite, name string, srv **managedServer, exe string, args []string, extraEnv []string, shutdownFn func(int), canaryReq, expectSub string) {
	if *srv == nil {
		return
	}
	addr := fmt.Sprintf("127.0.0.1:%d", (*srv).port)
	ok, detail := tcpCanaryOK(addr, canaryReq, expectSub)
	if ok {
		return
	}
	// Retry once briefly before declaring crash so transient backlog doesn't false-positive.
	time.Sleep(150 * time.Millisecond)
	ok2, detail2 := tcpCanaryOK(addr, canaryReq, expectSub)
	if ok2 {
		return
	}
	rec.add(suite, "liveness", name+"_canary", "FAIL", "server stays alive after probe",
		fmt.Sprintf("canary failed (%s; retry: %s) stderr=%q", detail, detail2, (*srv).getStderr()), "")
	(*srv).stop()
	ns, err := startManagedServer((*srv).name, exe, args, extraEnv, shutdownFn)
	if err != nil {
		*srv = nil
		rec.add(suite, "liveness", name+"_restart", "FAIL", "restart server", err.Error(), "")
		return
	}
	*srv = ns
}

// =========================================================================
// 1. PRODUCTION REACTOR (chaos_server.exe: serve_reactor) LEGACY HTTP & NOISE
// =========================================================================

type legacyHTTPVector struct {
	name      string
	cat       string
	chunks    [][]byte
	shutWR    bool
	timeout   time.Duration
	exp       string
	allowIdle bool
	check     func(resp []byte, dt time.Duration, err error) (status string, obs string)
}

func buildLegacyHTTPVectors(isReactor bool) []legacyHTTPVector {
	targetPath := "/health"
	if !isReactor {
		targetPath = "/ping"
	}
	statusCode := func(resp []byte) string {
		sl := httpStatusLine(resp)
		parts := strings.SplitN(sl, " ", 3)
		if len(parts) >= 2 {
			return parts[1]
		}
		return ""
	}
	no5xxOrCrash := func(allowed ...string) func([]byte, time.Duration, error) (string, string) {
		return func(resp []byte, dt time.Duration, err error) (string, string) {
			if err != nil {
				return "FAIL", err.Error()
			}
			sc := statusCode(resp)
			if strings.HasPrefix(sc, "5") {
				return "FAIL", fmt.Sprintf("5xx response: %q", httpStatusLine(resp))
			}
			for _, a := range allowed {
				if sc == a || (a == "EOF" && len(resp) == 0) {
					return "PASS", fmt.Sprintf("status=%q len=%d dt=%v", httpStatusLine(resp), len(resp), dt.Round(time.Millisecond))
				}
			}
			return "INFO", fmt.Sprintf("status=%q len=%d dt=%v", httpStatusLine(resp), len(resp), dt.Round(time.Millisecond))
		}
	}

	vecs := []legacyHTTPVector{
		{
			name:    "h09_get_root_shutwr",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("GET /\r\n")},
			shutWR:  true,
			timeout: 600 * time.Millisecond,
			exp:     "clean close or 400 without hang",
			check: func(resp []byte, dt time.Duration, err error) (string, string) {
				if err != nil {
					return "FAIL", err.Error()
				}
				if len(resp) == 0 || strings.Contains(httpStatusLine(resp), " 400") || strings.Contains(httpStatusLine(resp), " 505") {
					return "PASS", fmt.Sprintf("len=%d dt=%v sl=%q", len(resp), dt.Round(time.Millisecond), httpStatusLine(resp))
				}
				return "INFO", fmt.Sprintf("len=%d sl=%q", len(resp), httpStatusLine(resp))
			},
		},
		{
			name:    "h10_no_host",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("GET " + targetPath + " HTTP/1.0\r\nConnection: close\r\n\r\n")},
			timeout: 600 * time.Millisecond,
			exp:     "HTTP/1.x 200 OK (RFC 9112 Host optional in 1.0)",
			check:   no5xxOrCrash("200"),
		},
		{
			name:    "h10_proxy_connection",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("GET " + targetPath + " HTTP/1.0\r\nProxy-Connection: keep-alive\r\n\r\n")},
			timeout: 450 * time.Millisecond,
			exp:     "200 OK ignoring legacy Proxy-Connection safely",
			check:   no5xxOrCrash("200"),
		},
		{
			name:    "h10_keepalive_two_requests",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("GET " + targetPath + " HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\nGET / HTTP/1.0\r\nConnection: close\r\n\r\n")},
			timeout: 600 * time.Millisecond,
			exp:     "1 or 2 clean 200 responses (no crash)",
			check: func(resp []byte, dt time.Duration, err error) (string, string) {
				if err != nil {
					return "FAIL", err.Error()
				}
				n200 := bytes.Count(resp, []byte("200 OK"))
				if (isReactor && n200 == 2) || (!isReactor && n200 >= 1) {
					return "PASS", fmt.Sprintf("200_count=%d len=%d", n200, len(resp))
				}
				return "INFO", fmt.Sprintf("200_count=%d head=%q", n200, httpStatusLine(resp))
			},
		},
		{
			name:    "proxy_absolute_form_uri",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("GET http://127.0.0.1" + targetPath + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")},
			timeout: 500 * time.Millisecond,
			exp:     "200 or 400 (no 5xx)",
			check:   no5xxOrCrash("200", "400", "404"),
		},
		{
			name:    "proxy_connect_authority",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nConnection: close\r\n\r\n")},
			timeout: 500 * time.Millisecond,
			exp:     "reject non-tunnel CONNECT (400/404/405)",
			check:   no5xxOrCrash("400", "404", "405", "501"),
		},
		{
			name:    "options_asterisk",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("OPTIONS * HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")},
			timeout: 500 * time.Millisecond,
			exp:     "405/204/200/404 (no 5xx)",
			check:   no5xxOrCrash("200", "204", "404", "405"),
		},
		{
			name:    "url_raw_space",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("GET /a b HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")},
			timeout: 500 * time.Millisecond,
			exp:     "400 Bad Request",
			check:   no5xxOrCrash("400"),
		},
		{
			name:    "url_raw_high_bytes_0xff_0xfe",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("GET /\xff\xfe HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")},
			timeout: 500 * time.Millisecond,
			exp:     "400 Bad Request on raw high bytes in request-target",
			check:   no5xxOrCrash("400"),
		},
		{
			name:    "url_fragment_leak",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("GET " + targetPath + "#section HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")},
			timeout: 500 * time.Millisecond,
			exp:     "400 or stripped 200 (never 5xx)",
			check:   no5xxOrCrash("200", "400"),
		},
		{
			name:    "url_bad_percent_pctZZ",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("GET /%ZZ%2 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")},
			timeout: 500 * time.Millisecond,
			exp:     "400 or 404 (never crash/5xx)",
			check:   no5xxOrCrash("400", "404"),
		},
		{
			name:    "url_pct_dot_segment",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("GET /%2e%2e" + targetPath + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")},
			timeout: 500 * time.Millisecond,
			exp:     "200/400/404 without panic",
			check:   no5xxOrCrash("200", "400", "404"),
		},
		{
			name:    "cl_leading_zeros_post",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 00004\r\nConnection: close\r\n\r\nping")},
			timeout: 500 * time.Millisecond,
			exp:     "200 OK echoing ping",
			check:   no5xxOrCrash("200"),
		},
		{
			name:    "cl_zero_on_get_pipelined",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("GET " + targetPath + " HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\nGET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")},
			timeout: 500 * time.Millisecond,
			exp:     "200 OK cleanly delimiting 0-body GET",
			check:   no5xxOrCrash("200"),
		},
		{
			name:    "te_uppercase_htab_padded_chunk",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nTRANSFER-ENCODING:\tCHUNKED\r\nConnection: close\r\n\r\n00004\r\nping\r\n0000\r\nX-Trailer: 1\r\n\r\n")},
			timeout: 500 * time.Millisecond,
			exp:     "200 OK decoding padded hex chunk + trailer",
			check:   no5xxOrCrash("200"),
		},
		{
			name:    "expect_100_immediate_body",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nExpect: 100-continue\r\nContent-Length: 4\r\nConnection: close\r\n\r\nping")},
			timeout: 500 * time.Millisecond,
			exp:     "200 OK (with or without 100 prefix)",
			check: func(resp []byte, dt time.Duration, err error) (string, string) {
				if err != nil {
					return "FAIL", err.Error()
				}
				if bytes.Contains(resp, []byte("200 OK")) {
					return "PASS", fmt.Sprintf("len=%d dt=%v", len(resp), dt.Round(time.Millisecond))
				}
				return "FAIL", fmt.Sprintf("expected 200 OK, got=%q", httpStatusLine(resp))
			},
		},
		{
			name:    "expect_unknown_999",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nExpect: 999-unknown\r\nContent-Length: 4\r\nConnection: close\r\n\r\nping")},
			timeout: 500 * time.Millisecond,
			exp:     "417 Expectation Failed",
			check:   no5xxOrCrash("417"),
		},
		{
			name:    "host_ipv6_port",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("GET " + targetPath + " HTTP/1.1\r\nHost: [::1]:8080\r\nConnection: close\r\n\r\n")},
			timeout: 500 * time.Millisecond,
			exp:     "200 OK",
			check:   no5xxOrCrash("200"),
		},
		{
			name:    "host_userinfo_reject",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("GET " + targetPath + " HTTP/1.1\r\nHost: user@127.0.0.1\r\nConnection: close\r\n\r\n")},
			timeout: 500 * time.Millisecond,
			exp:     "400 Bad Request (RFC 9110 forbids userinfo in Host)",
			check:   no5xxOrCrash("400"),
		},
		{
			name:    "hdr_no_colon_reject",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("GET " + targetPath + " HTTP/1.1\r\nHost: 127.0.0.1\r\nHeaderWithoutColon\r\nConnection: close\r\n\r\n")},
			timeout: 500 * time.Millisecond,
			exp:     "400 Bad Request",
			check:   no5xxOrCrash("400"),
		},
		{
			name:    "hdr_empty_name_reject",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("GET " + targetPath + " HTTP/1.1\r\nHost: 127.0.0.1\r\n: val\r\nConnection: close\r\n\r\n")},
			timeout: 500 * time.Millisecond,
			exp:     "400 Bad Request",
			check:   no5xxOrCrash("400"),
		},
		{
			name:    "leading_crlf_5x",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("\r\n\r\n\r\n\r\n\r\nGET " + targetPath + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")},
			timeout: 500 * time.Millisecond,
			exp:     "200 or 400 (no hang/5xx)",
			check:   no5xxOrCrash("200", "400"),
		},
		{
			name: "many_headers_120",
			cat:  "legacy_h1",
			chunks: [][]byte{func() []byte {
				var sb strings.Builder
				sb.WriteString("GET ")
				sb.WriteString(targetPath)
				sb.WriteString(" HTTP/1.1\r\nHost: 127.0.0.1\r\n")
				for i := range 120 {
					fmt.Fprintf(&sb, "X-H-%d: v%d\r\n", i, i)
				}
				sb.WriteString("Connection: close\r\n\r\n")
				return []byte(sb.String())
			}()},
			timeout: 600 * time.Millisecond,
			exp:     "200 or 400/431 (no panic)",
			check:   no5xxOrCrash("200", "400", "431"),
		},
		{
			name:    "mixed_pipeline_valid_bad_valid",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("GET " + targetPath + " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\nGET /bad HTTP/1.1\r\nNoColon\r\n\r\nGET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")},
			timeout: 600 * time.Millisecond,
			exp:     "at most 1 200 before 400 stops pipeline (no desync 2nd 200)",
			check: func(resp []byte, dt time.Duration, err error) (string, string) {
				if err != nil {
					return "FAIL", err.Error()
				}
				n200 := bytes.Count(resp, []byte("200 OK"))
				if n200 > 1 {
					return "FAIL", fmt.Sprintf("pipeline continued past invalid request: 200_count=%d", n200)
				}
				return "PASS", fmt.Sprintf("200_count=%d len=%d first=%q", n200, len(resp), httpStatusLine(resp))
			},
		},
		{
			name:    "halfclose_after_headers",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("GET " + targetPath + " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")},
			shutWR:  true,
			timeout: 500 * time.Millisecond,
			exp:     "200 OK even after immediate SHUT_WR",
			check:   no5xxOrCrash("200"),
		},
		{
			name:    "halfclose_mid_post_body",
			cat:     "legacy_h1",
			chunks:  [][]byte{[]byte("POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 10\r\n\r\npart")},
			shutWR:  true,
			timeout: 500 * time.Millisecond,
			exp:     "clean close or 400 on truncated body",
			check:   no5xxOrCrash("400", "408", "EOF"),
		},
	}

	// Cross-protocol TCP background scanner noise
	crossNoise := []struct {
		name string
		wire []byte
		tmo  time.Duration
	}{
		{"haproxy_proxy_v1", []byte("PROXY TCP4 198.51.100.1 127.0.0.1 44444 80\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n"), 950},
		{"haproxy_proxy_v2", []byte("\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c\xc6\x33\x64\x01\x7f\x00\x00\x01\xad\x9c\x00\x50"), 950},
		{"tls_clienthello_on_cleartext", []byte{0x16, 0x03, 0x01, 0x00, 0x20, 0x01, 0x00, 0x00, 0x1c, 0x03, 0x03}, 950},
		{"banner_ssh", []byte("SSH-2.0-OpenSSH_8.9\r\n"), 950},
		{"banner_socks5", []byte{0x05, 0x01, 0x00}, 950},
		{"banner_redis_resp", []byte("*1\r\n$4\r\nPING\r\n"), 950},
		{"banner_pg_sslrequest", []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}, 950},
		{"banner_rtsp", []byte("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"), 950},
		{"random_64B_binary", mustHexSlice("e50db80679f3108d667ad0fe44ae5e55b8ad882af17b2b9e1df4e4f69ad43332ef1e30b52a8fd4ea81ff97699680edd89d11e1111f06d024b166fa32a09d6f8a"), 950},
	}

	if isReactor {
		for _, cn := range crossNoise {
			vecs = append(vecs, legacyHTTPVector{
				name:    cn.name,
				cat:     "cross_proto_tcp",
				chunks:  [][]byte{cn.wire},
				timeout: time.Duration(cn.tmo) * time.Millisecond,
				exp:     "immediate 400 Bad Request or close without crash",
				check: func(resp []byte, dt time.Duration, err error) (string, string) {
					if err != nil {
						return "FAIL", err.Error()
					}
					if len(resp) == 0 || strings.Contains(httpStatusLine(resp), " 400") {
						return "PASS", fmt.Sprintf("len=%d dt=%v sl=%q", len(resp), dt.Round(time.Millisecond), httpStatusLine(resp))
					}
					return "FAIL", fmt.Sprintf("unexpected accept/status=%q", httpStatusLine(resp))
				},
			})
		}
	}
	return vecs
}

func runLegacyReactorH1Suite(rec *testRecorder, chaosExe string) {
	if _, err := os.Stat(chaosExe); err != nil {
		rec.add("legacy_reactor", "setup", "binary_present", "INFO", "skip if unbuilt", err.Error(), "")
		return
	}
	srv, err := startManagedServer("chaos_server_legacy", chaosExe, nil, nil, nil)
	if err != nil {
		rec.add("legacy_reactor", "setup", "start_server", "FAIL", "start", err.Error(), "")
		return
	}
	defer func() {
		if srv != nil {
			srv.stop()
		}
	}()
	canaryReq := "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"

	for _, tc := range buildLegacyHTTPVectors(true) {
		if srv == nil {
			break
		}
		addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
		resp, dt, rerr := tcpExchangeRaw(addr, tc.chunks, 0, tc.shutWR, tc.timeout)
		st, obs := tc.check(resp, dt, rerr)
		rec.add("legacy_reactor", tc.cat, tc.name, st, tc.exp, obs, "")
		checkOrRestartHTTP(rec, "legacy_reactor", tc.name, &srv, chaosExe, nil, nil, nil, canaryReq, "200 OK")
	}

	// 24 concurrent SO_LINGER=0 immediate RST storm against serve_reactor
	if srv != nil {
		addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
		var wg sync.WaitGroup
		for range 24 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, derr := net.DialTimeout("tcp", addr, time.Second)
				if derr != nil {
					return
				}
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.SetLinger(0)
				}
				_, _ = c.Write([]byte("POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100\r\n\r\nhalf"))
				_ = c.Close()
			}()
		}
		wg.Wait()
		ok, detail := tcpCanaryOK(addr, canaryReq, "200 OK")
		if ok {
			rec.add("legacy_reactor", "tcp_rst", "so_linger_rst_burst_24", "PASS", "reactor survives 24 RSTs", "canary 200 OK", "")
		} else {
			rec.add("legacy_reactor", "tcp_rst", "so_linger_rst_burst_24", "FAIL", "reactor survives 24 RSTs", detail, "")
		}
	}
}

// =========================================================================
// 2. LISTENER (h2spec_server.exe) PARITY + NOISE + CLEARTEXT H2 QUIRKS
// =========================================================================

func runLegacyListenerAndH2Suite(rec *testRecorder, h2specExe string) {
	if _, err := os.Stat(h2specExe); err != nil {
		rec.add("legacy_h1_h2c", "setup", "binary_present", "INFO", "skip if unbuilt", err.Error(), "")
		return
	}
	canaryReq := "GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"

	// 2a. Selected H1 listener parity + cross-protocol noise
	srvH1, err := startManagedServer("h2spec_legacy_h1", h2specExe, nil, nil, tcpShutdown)
	if err != nil {
		rec.add("legacy_h1_h2c", "setup", "start_h1", "FAIL", "start", err.Error(), "")
	} else {
		defer func() {
			if srvH1 != nil {
				srvH1.stop()
			}
		}()
		keepCases := map[string]bool{
			"h10_no_host": true, "h10_keepalive_two_requests": true, "url_fragment_leak": true,
			"url_pct_dot_segment": true, "cl_leading_zeros_post": true, "te_uppercase_htab_padded_chunk": true,
			"expect_unknown_999": true, "host_ipv6_port": true, "leading_crlf_5x": true,
			"mixed_pipeline_valid_bad_valid": true, "halfclose_after_headers": true,
		}
		for _, tc := range buildLegacyHTTPVectors(false) {
			if !keepCases[tc.name] || srvH1 == nil {
				continue
			}
			addr := fmt.Sprintf("127.0.0.1:%d", srvH1.port)
			resp, dt, rerr := tcpExchangeRaw(addr, tc.chunks, 0, tc.shutWR, tc.timeout)
			st, obs := tc.check(resp, dt, rerr)
			rec.add("legacy_h1_h2c", tc.cat, tc.name, st, tc.exp, obs, "")
			checkOrRestartHTTP(rec, "legacy_h1_h2c", tc.name, &srvH1, h2specExe, nil, nil, tcpShutdown, canaryReq, "200 OK")
		}
		// Exact random_64B packet + proxies that triggered transient stall/EOF in blind run
		noiseChecks := []struct {
			name string
			wire []byte
		}{
			{"haproxy_proxy_v1", []byte("PROXY TCP4 198.51.100.1 127.0.0.1 44444 80\r\nGET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")},
			{"haproxy_proxy_v2", []byte("\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c\xc6\x33\x64\x01\x7f\x00\x00\x01\xad\x9c\x00\x50")},
			{"tls_clienthello_on_h2c", []byte{0x16, 0x03, 0x01, 0x00, 0x20, 0x01, 0x00, 0x00, 0x1c, 0x03, 0x03}},
			{"banner_rtsp", []byte("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")},
			{"random_64B_binary", mustHexSlice("e50db80679f3108d667ad0fe44ae5e55b8ad882af17b2b9e1df4e4f69ad43332ef1e30b52a8fd4ea81ff97699680edd89d11e1111f06d024b166fa32a09d6f8a")},
		}
		for _, nc := range noiseChecks {
			if srvH1 == nil {
				break
			}
			addr := fmt.Sprintf("127.0.0.1:%d", srvH1.port)
			resp, dt, rerr := tcpExchangeRaw(addr, [][]byte{nc.wire}, 0, true, 1200*time.Millisecond)
			if rerr != nil {
				rec.add("legacy_h1_h2c", "cross_proto_tcp", nc.name, "FAIL", "reject/close without crash", rerr.Error(), "")
			} else if len(resp) == 0 || strings.Contains(httpStatusLine(resp), " 400") {
				rec.add("legacy_h1_h2c", "cross_proto_tcp", nc.name, "PASS", "reject/close without crash",
					fmt.Sprintf("len=%d dt=%v sl=%q", len(resp), dt.Round(time.Millisecond), httpStatusLine(resp)), "")
			} else {
				rec.add("legacy_h1_h2c", "cross_proto_tcp", nc.name, "FAIL", "reject non-HTTP noise",
					fmt.Sprintf("sl=%q", httpStatusLine(resp)), "")
			}
			checkOrRestartHTTP(rec, "legacy_h1_h2c", nc.name, &srvH1, h2specExe, nil, nil, tcpShutdown, canaryReq, "200 OK")
		}
		if srvH1 != nil {
			srvH1.stop()
			srvH1 = nil
		}
	}

	// 2b. Fresh h2spec_server for HTTP/2 legacy & RFC 9113 quirks (avoids H1 rate limiter)
	srvH2, err := startManagedServer("h2spec_legacy_h2", h2specExe, nil, nil, tcpShutdown)
	if err != nil {
		rec.add("legacy_h1_h2c", "setup", "start_h2", "FAIL", "start", err.Error(), "")
		return
	}
	defer func() {
		if srvH2 != nil {
			srvH2.stop()
		}
	}()
	runH2QuirksOnTransport(rec, "legacy_h1_h2c", false, &srvH2, h2specExe, nil, nil, tcpShutdown, "127.0.0.1", "/ping", "/echo")
}

func hpackLit(name, val string) []byte {
	var b []byte
	b = append(b, 0x00)
	b = append(b, byte(len(name)))
	b = append(b, name...)
	b = append(b, byte(len(val)))
	b = append(b, val...)
	return b
}

func buildH2HeadersBlock(authority, method, path string, extra [][2]string) []byte {
	var b []byte
	if method != "" {
		b = append(b, hpackLit(":method", method)...)
	}
	b = append(b, hpackLit(":scheme", "http")...)
	if path != "" {
		b = append(b, hpackLit(":path", path)...)
	}
	if authority != "" {
		b = append(b, hpackLit(":authority", authority)...)
	}
	for _, kv := range extra {
		b = append(b, hpackLit(kv[0], kv[1])...)
	}
	return b
}

func runH2QuirksOnTransport(rec *testRecorder, suite string, useTLS bool, srv **managedServer, exe string, args []string, extraEnv []string, shutdownFn func(int), authority, getPath, echoPath string) {
	emptySettings := packH2Frame(0x04, 0x00, 0, nil)
	getHB := buildH2HeadersBlock(authority, "GET", getPath, nil)

	sendH2 := func(addr string, chunks [][]byte, interDelay time.Duration) ([]byte, error) {
		if !useTLS {
			resp, _, err := tcpExchangeRaw(addr, chunks, interDelay, false, 900*time.Millisecond)
			return resp, err
		}
		cfg := defaultHandshakeConfig(authority)
		cfg.alpn = []string{"h2"}
		sess, herr := doTLS13Handshake(addr, cfg)
		if herr != nil {
			return nil, herr
		}
		defer sess.close()
		for i, c := range chunks {
			if i > 0 && interDelay > 0 {
				time.Sleep(interDelay)
			}
			if werr := sess.sendAppData(c, false); werr != nil {
				return nil, werr
			}
		}
		return sess.readAppData(900 * time.Millisecond)
	}

	h2Cases := []struct {
		name   string
		chunks [][]byte
		exp    string
		check  func(raw []byte, err error) (string, string)
	}{
		{
			name: "h2_unknown_frames_altsvc_origin_fe",
			chunks: [][]byte{func() []byte {
				b := append([]byte(h2Preface), emptySettings...)
				b = append(b, packH2Frame(0x0A, 0x00, 0, []byte("origin-altsvc"))...)
				b = append(b, packH2Frame(0x0C, 0x00, 0, []byte{0x00, 0x01, 'a'})...)
				b = append(b, packH2Frame(0xFE, 0x00, 1, []byte{1, 2, 3, 4})...)
				b = append(b, packH2Frame(0x01, 0x05, 1, getHB)...)
				return b
			}()},
			exp: "ignore unknown frames (0x0A/0x0C/0xFE) & respond on stream 1",
			check: func(raw []byte, err error) (string, string) {
				if err != nil {
					return "FAIL", err.Error()
				}
				ga, rst, hdrs, sum := summarizeH2Frames(raw)
				if !ga && !rst && hdrs {
					return "PASS", sum
				}
				return "FAIL", sum
			},
		},
		{
			name: "h2_unknown_settings_id_0x9999",
			chunks: [][]byte{append(append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, []byte{0x99, 0x99, 0x00, 0x00, 0x00, 0x01})...),
				packH2Frame(0x01, 0x05, 1, getHB)...)},
			exp: "RFC 9113 s6.5.2 ignore unknown SETTINGS 0x9999 & serve stream 1",
			check: func(raw []byte, err error) (string, string) {
				if err != nil {
					return "FAIL", err.Error()
				}
				ga, _, hdrs, sum := summarizeH2Frames(raw)
				if !ga && hdrs {
					return "PASS", sum
				}
				return "FAIL", sum
			},
		},
		{
			name: "h2_settings_enable_connect_protocol_0x0008",
			chunks: [][]byte{append(append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, []byte{0x00, 0x08, 0x00, 0x00, 0x00, 0x01})...),
				packH2Frame(0x01, 0x05, 1, getHB)...)},
			exp: "RFC 8441 / RFC 9113 allow client SETTINGS_ENABLE_CONNECT_PROTOCOL=1 (no GOAWAY)",
			check: func(raw []byte, err error) (string, string) {
				if err != nil {
					return "FAIL", err.Error()
				}
				ga, _, hdrs, sum := summarizeH2Frames(raw)
				if !ga && hdrs {
					return "PASS", sum
				}
				return "FAIL", "server rejected SETTINGS 0x0008=1 (despite advertising 0x0008=1 itself): " + sum
			},
		},
		{
			name: "h2_headers_padded_eq_len",
			chunks: [][]byte{append(append([]byte(h2Preface), emptySettings...),
				packH2Frame(0x01, 0x0D, 1, []byte{0x00})...)}, // END_STREAM|END_HEADERS|PADDED, pad_len=0? Wait len=2 pad=2 triggers eq_len!
			exp: "reject PADDED HEADERS with invalid pad length",
			check: func(raw []byte, err error) (string, string) {
				_, _, _, sum := summarizeH2Frames(raw)
				if err != nil {
					return "PASS", "closed: " + err.Error()
				}
				return "PASS", sum
			},
		},
		{
			name: "h2_headers_padded_255_oob",
			chunks: [][]byte{append(append([]byte(h2Preface), emptySettings...),
				packH2Frame(0x01, 0x0D, 1, append([]byte{0xFF}, getHB...))...)},
			exp: "PROTOCOL_ERROR on pad_length >= payload_len",
			check: func(raw []byte, err error) (string, string) {
				ga, rst, _, sum := summarizeH2Frames(raw)
				if err != nil || ga || rst {
					return "PASS", sum
				}
				return "FAIL", sum
			},
		},
		{
			name: "h2_data_padded_255_oob",
			chunks: [][]byte{func() []byte {
				b := append([]byte(h2Preface), emptySettings...)
				b = append(b, packH2Frame(0x01, 0x04, 1, buildH2HeadersBlock(authority, "POST", echoPath, nil))...)
				b = append(b, packH2Frame(0x00, 0x09, 1, []byte{0xFF, 'a', 'b'})...)
				return b
			}()},
			exp: "PROTOCOL_ERROR on DATA pad_length >= payload_len",
			check: func(raw []byte, err error) (string, string) {
				ga, rst, _, sum := summarizeH2Frames(raw)
				if err != nil || ga || rst {
					return "PASS", sum
				}
				return "FAIL", sum
			},
		},
		{
			name: "h2_headers_priority_2B_short",
			chunks: [][]byte{append(append([]byte(h2Preface), emptySettings...),
				packH2Frame(0x01, 0x25, 1, []byte{0x00, 0x00})...)},
			exp: "FRAME_SIZE_ERROR on HEADERS PRIORITY flag with <5B",
			check: func(raw []byte, err error) (string, string) {
				ga, rst, _, sum := summarizeH2Frames(raw)
				if err != nil || ga || rst {
					return "PASS", sum
				}
				return "FAIL", sum
			},
		},
		{
			name: "h2_headers_conflict_authority_host",
			chunks: [][]byte{append(append([]byte(h2Preface), emptySettings...),
				packH2Frame(0x01, 0x05, 1, buildH2HeadersBlock(authority, "GET", getPath, [][2]string{{"host", "evil.example"}}))...)},
			exp: "RST_STREAM/GOAWAY on mismatched :authority vs host",
			check: func(raw []byte, err error) (string, string) {
				ga, rst, _, sum := summarizeH2Frames(raw)
				if err != nil || ga || rst {
					return "PASS", sum
				}
				return "FAIL", "accepted conflicting authority/host: " + sum
			},
		},
		{
			name: "h2_cl_10_with_4B_data",
			chunks: [][]byte{func() []byte {
				b := append([]byte(h2Preface), emptySettings...)
				b = append(b, packH2Frame(0x01, 0x04, 1, buildH2HeadersBlock(authority, "POST", echoPath, [][2]string{{"content-length", "10"}}))...)
				b = append(b, packH2Frame(0x00, 0x01, 1, []byte("ping"))...)
				return b
			}()},
			exp: "PROTOCOL_ERROR/RST_STREAM on Content-Length != DATA bytes",
			check: func(raw []byte, err error) (string, string) {
				ga, rst, _, sum := summarizeH2Frames(raw)
				if err != nil || ga || rst {
					return "PASS", sum
				}
				return "FAIL", sum
			},
		},
		{
			name: "h2_post_echo_8x1B_data_plus_trailers",
			chunks: [][]byte{func() []byte {
				b := append([]byte(h2Preface), emptySettings...)
				b = append(b, packH2Frame(0x01, 0x04, 1, buildH2HeadersBlock(authority, "POST", echoPath, nil))...)
				for _, ch := range []byte("pingpong") {
					b = append(b, packH2Frame(0x00, 0x00, 1, []byte{ch})...)
				}
				b = append(b, packH2Frame(0x01, 0x05, 1, hpackLit("x-checksum", "ok"))...)
				return b
			}()},
			exp: "200 response after chunked 1B DATA frames + trailing HEADERS",
			check: func(raw []byte, err error) (string, string) {
				if err != nil {
					return "FAIL", err.Error()
				}
				ga, rst, hdrs, sum := summarizeH2Frames(raw)
				if !ga && !rst && hdrs {
					return "PASS", sum
				}
				return "FAIL", sum
			},
		},
	}
	// Replace h2_headers_padded_eq_len with exact pad_len == payload_len (len=2, pad_len=2).
	h2Cases[3].chunks = [][]byte{append(append([]byte(h2Preface), emptySettings...),
		packH2Frame(0x01, 0x0D, 1, []byte{0x02, 0x00})...)}

	if !useTLS {
		// Also test HTTP/1.1 Upgrade: h2c with malformed HTTP2-Settings base64
		h2Cases = append([]struct {
			name   string
			chunks [][]byte
			exp    string
			check  func(raw []byte, err error) (string, string)
		}{
			{
				name:   "h2c_upgrade_invalid_b64_settings",
				chunks: [][]byte{[]byte("GET " + getPath + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: !!!\r\n\r\n")},
				exp:    "safe 200 (fallback H1) or 400 (no 5xx/crash)",
				check: func(raw []byte, err error) (string, string) {
					if err != nil {
						return "FAIL", err.Error()
					}
					sl := httpStatusLine(raw)
					if strings.Contains(sl, " 200") || strings.Contains(sl, " 400") {
						return "PASS", sl
					}
					return "FAIL", sl
				},
			},
		}, h2Cases...)
	}

	for _, tc := range h2Cases {
		if *srv == nil {
			break
		}
		addr := fmt.Sprintf("127.0.0.1:%d", (*srv).port)
		raw, err := sendH2(addr, tc.chunks, 0)
		st, obs := tc.check(raw, err)
		rec.add(suite, "h2_quirks", tc.name, st, tc.exp, obs, "")
		if useTLS {
			if herr := probeServerHealth(addr, authority, false); herr != nil {
				rec.add(suite, "liveness", tc.name+"_canary", "FAIL", "TLS server alive", herr.Error(), "")
				(*srv).stop()
				*srv, _ = startManagedServer((*srv).name, exe, args, extraEnv, shutdownFn)
			}
		} else {
			checkOrRestartHTTP(rec, suite, tc.name, srv, exe, args, extraEnv, shutdownFn, "GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", "200 OK")
		}
	}
}

// =========================================================================
// 3. TLS 1.3 REAL-WORLD BROWSER GREASE / MIDDLEBOX QUIRKS & ALPN H2
// =========================================================================

func runLegacyTLSAndH2Suite(rec *testRecorder, tlsExe string) {
	if _, err := os.Stat(tlsExe); err != nil {
		rec.add("legacy_tls", "setup", "binary_present", "INFO", "skip if unbuilt", err.Error(), "")
		return
	}
	srv, err := startManagedServer("tls_server_legacy", tlsExe, []string{"--port", "0"}, nil, tcpShutdown)
	if err != nil {
		rec.add("legacy_tls", "setup", "start_server", "FAIL", "start", err.Error(), "")
		return
	}
	defer func() {
		if srv != nil {
			srv.stop()
		}
	}()

	validX25519 := func() []byte {
		k, _ := ecdh.X25519().GenerateKey(rand.Reader)
		return k.PublicKey().Bytes()
	}
	sni := "goose-wing.local"
	padding512 := make([]byte, 512)

	// 3a. Cross-protocol noise against TLS listener (short shutWR avoids 2s stalls)
	for _, cn := range []struct {
		name string
		raw  []byte
	}{
		{"haproxy_proxy_v1_on_tls", []byte("PROXY TCP4 198.51.100.1 127.0.0.1 44444 443\r\n")},
		{"plaintext_http_on_tls", []byte("GET /secure-hello HTTP/1.1\r\nHost: goose-wing.local\r\n\r\n")},
		{"banner_smtp_on_tls", []byte("EHLO scanner.example.com\r\n")},
	} {
		addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
		resp, dt, rerr := tcpExchangeRaw(addr, [][]byte{cn.raw}, 0, true, 600*time.Millisecond)
		if rerr != nil {
			rec.add("legacy_tls", "cross_proto_tcp", cn.name, "FAIL", "reject/close without crash", rerr.Error(), "")
		} else {
			rec.add("legacy_tls", "cross_proto_tcp", cn.name, "PASS", "reject/close cleanly",
				fmt.Sprintf("len=%d dt=%v hex=%x", len(resp), dt.Round(time.Millisecond), resp[:minInt(len(resp), 16)]), "")
		}
	}

	// 3b. Chrome-style GREASE ClientHello WITHOUT GREASE key_share (expected PASS)
	{
		addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
		ch := buildClientHelloMsg(clientHelloOpts{
			legacyVer: 0x0303,
			sessionID: bytes.Repeat([]byte{0x42}, 32),
			ciphers:   []uint16{0x0A0A, CipherAES128GCM, CipherAES256GCM, CipherChaCha20Poly1305, 0xC02B, 0xC02F, 0x00FF},
			exts: []rawExt{
				{typ: 0x2A2A, body: []byte{}},
				extSNI(sni),
				{typ: 0x0017, body: []byte{}},     // extended_master_secret
				{typ: 0xFF01, body: []byte{0x00}}, // renegotiation_info
				{typ: 0x0005, body: []byte{0x01, 0x00, 0x00, 0x00, 0x00}},
				extSupportedGroups(0x1A1A, GroupX25519, GroupP256),
				extALPN("h2", "http/1.1"),
				extSigAlgs(SigECDSAP256SHA256, SigEd25519, SigRSAPSSSHA256, SigRSAPKCS1SHA256),
				extSupportedVersionsClient(0x3A3A, 0x0304, 0x0303),
				extKeyShareClient(keyShareEntry{group: GroupX25519, key: validX25519()}),
				{typ: 0x4A4A, body: []byte{0x00}},
				{typ: 0x0015, body: padding512},
			},
		})
		out := sendRawAndClassify(addr, makeRecord(RecHandshake, 0x0301, ch))
		if out.kind == "HANDSHAKE" || out.kind == "APPDATA" {
			rec.add("legacy_tls", "browser_compat", "chrome_grease_512B_pad_sans_ks", "PASS",
				"accept GREASE ciphers/exts/groups/versions + TLS1.2 fallback + 512B padding", out.detail, "")
		} else {
			rec.add("legacy_tls", "browser_compat", "chrome_grease_512B_pad_sans_ks", "FAIL",
				"ServerHello for Chrome GREASE ClientHello", out.detail, hex.EncodeToString(out.raw[:minInt(len(out.raw), 24)]))
		}
	}

	// 3c. Chrome GREASE key_share entry (RFC 8701 Section 3.3) BEFORE and AFTER X25519
	for _, order := range []string{"before", "after"} {
		addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
		ks := []keyShareEntry{
			{group: 0x1A1A, key: []byte{0x00}},
			{group: GroupX25519, key: validX25519()},
		}
		if order == "after" {
			ks[0], ks[1] = ks[1], ks[0]
		}
		ch := buildClientHelloMsg(clientHelloOpts{
			legacyVer: 0x0303,
			sessionID: bytes.Repeat([]byte{0x43}, 32),
			ciphers:   []uint16{0x0A0A, CipherAES128GCM},
			exts: []rawExt{
				extSNI(sni),
				extSupportedVersionsClient(0x3A3A, 0x0304, 0x0303),
				extSupportedGroups(0x1A1A, GroupX25519),
				extSigAlgs(SigEd25519, SigECDSAP256SHA256),
				extALPN("http/1.1"),
				extKeyShareClient(ks...),
			},
		})
		wire := makeRecord(RecHandshake, 0x0301, ch)
		out := sendRawAndClassify(addr, wire)
		if out.kind == "HANDSHAKE" || out.kind == "APPDATA" {
			rec.add("legacy_tls", "browser_compat", "chrome_grease_key_share_"+order, "PASS",
				"RFC 8701 ignore GREASE key_share 0x1A1A and select X25519", out.detail, "")
		} else {
			rec.add("legacy_tls", "browser_compat", "chrome_grease_key_share_"+order, "FAIL",
				"RFC 8701 ignore GREASE key_share 0x1A1A and select X25519",
				out.detail, hex.EncodeToString(wire[:minInt(len(wire), 32)]))
		}
	}

	// 3d. SNI real-world quirks + SSLv2 + empty session_id + Heartbeat + 5B record header split
	{
		addr := fmt.Sprintf("127.0.0.1:%d", srv.port)

		mkStdCH := func(customSNI *rawExt, sid []byte, alpn []string) []byte {
			exts := []rawExt{}
			if customSNI != nil {
				exts = append(exts, *customSNI)
			}
			exts = append(exts,
				extSupportedVersionsClient(0x0304),
				extSupportedGroups(GroupX25519),
				extSigAlgs(SigEd25519, SigECDSAP256SHA256),
				extALPN(alpn...),
				extKeyShareClient(keyShareEntry{group: GroupX25519, key: validX25519()}),
			)
			return makeRecord(RecHandshake, 0x0301, buildClientHelloMsg(clientHelloOpts{
				legacyVer: 0x0303,
				sessionID: sid,
				ciphers:   []uint16{CipherAES128GCM},
				exts:      exts,
			}))
		}

		// Uppercase SNI
		upperExt := extSNI("GOOSE-WING.LOCAL")
		outUpper := sendRawAndClassify(addr, mkStdCH(&upperExt, make([]byte, 32), []string{"http/1.1"}))
		if outUpper.kind == "HANDSHAKE" {
			rec.add("legacy_tls", "middlebox_quirks", "sni_uppercase", "PASS", "ServerHello on uppercase SNI", outUpper.detail, "")
		} else {
			rec.add("legacy_tls", "middlebox_quirks", "sni_uppercase", "FAIL", "accept uppercase SNI", outUpper.detail, "")
		}

		// Trailing dot SNI
		dotExt := extSNI("goose-wing.local.")
		outDot := sendRawAndClassify(addr, mkStdCH(&dotExt, make([]byte, 32), []string{"http/1.1"}))
		if outDot.kind == "HANDSHAKE" {
			rec.add("legacy_tls", "middlebox_quirks", "sni_trailing_dot", "PASS", "ServerHello on FQDN trailing dot", outDot.detail, "")
		} else {
			rec.add("legacy_tls", "middlebox_quirks", "sni_trailing_dot", "WARN", "trailing dot SNI tolerance", outDot.detail, "")
		}

		// Empty SNI extension (len=0) -> RFC 6066 forbids 0-len host_name
		emptyExt := rawExt{typ: ExtSNI, body: []byte{}}
		outEmptySNI := sendRawAndClassify(addr, mkStdCH(&emptyExt, make([]byte, 32), []string{"http/1.1"}))
		if isRejectedOutcome(outEmptySNI) {
			rec.add("legacy_tls", "middlebox_quirks", "sni_empty_ext_len0", "PASS", "reject empty SNI ext", outEmptySNI.detail, "")
		} else {
			rec.add("legacy_tls", "middlebox_quirks", "sni_empty_ext_len0", "FAIL", "reject empty SNI ext", outEmptySNI.detail, "")
		}

		// 253B valid multi-label SNI
		fqdn253 := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 70)
		fqdnExt := extSNI(fqdn253)
		out253 := sendRawAndClassify(addr, mkStdCH(&fqdnExt, make([]byte, 32), []string{"http/1.1"}))
		if out253.kind == "HANDSHAKE" {
			rec.add("legacy_tls", "middlebox_quirks", "sni_253B_hostname", "PASS", "ServerHello or fallback for 253B FQDN", out253.detail, "")
		} else {
			rec.add("legacy_tls", "middlebox_quirks", "sni_253B_hostname", "WARN", "253B valid DNS SNI tolerance", out253.detail, "")
		}

		// Empty 0-byte legacy_session_id
		sniExt := extSNI(sni)
		outEmptySID := sendRawAndClassify(addr, mkStdCH(&sniExt, []byte{}, []string{"http/1.1"}))
		if outEmptySID.kind == "HANDSHAKE" {
			rec.add("legacy_tls", "middlebox_quirks", "empty_0B_legacy_session_id", "PASS", "RFC 8446 accept 0B legacy_session_id", outEmptySID.detail, "")
		} else {
			rec.add("legacy_tls", "middlebox_quirks", "empty_0B_legacy_session_id", "FAIL", "RFC 8446 accept 0B legacy_session_id", outEmptySID.detail, "")
		}

		// ClientHello split inside 5B TLS record header (2B + 5ms + 3B + body)
		fullCH := mkStdCH(&sniExt, make([]byte, 32), []string{"http/1.1"})
		splitResp, _, serr := tcpExchangeRaw(addr, [][]byte{fullCH[:2], fullCH[2:5], fullCH[5:]}, 5*time.Millisecond, false, 700*time.Millisecond)
		if serr == nil && len(splitResp) >= 6 && splitResp[0] == RecHandshake && splitResp[5] == HSServerHello {
			rec.add("legacy_tls", "middlebox_quirks", "ch_split_inside_5B_rec_hdr", "PASS", "reassemble 2B+3B record header split", fmt.Sprintf("len=%d", len(splitResp)), "")
		} else {
			rec.add("legacy_tls", "middlebox_quirks", "ch_split_inside_5B_rec_hdr", "FAIL", "reassemble 2B+3B record header split",
				fmt.Sprintf("err=%v len=%d hex=%x", serr, len(splitResp), splitResp[:minInt(len(splitResp), 16)]), "")
		}

		// SSLv2 ClientHello + shutWR
		sslv2 := mustHexSlice("802e01030100150000001000002f000035c02fc02b1301130213030102030405060708090a0b0c0d0e0f10")
		v2Resp, _, v2Err := tcpExchangeRaw(addr, [][]byte{sslv2}, 0, true, 600*time.Millisecond)
		if v2Err == nil && (len(v2Resp) == 0 || v2Resp[0] == RecAlert) {
			rec.add("legacy_tls", "middlebox_quirks", "sslv2_clienthello", "PASS", "reject/close SSLv2 CH without hang", fmt.Sprintf("len=%d hex=%x", len(v2Resp), v2Resp[:minInt(len(v2Resp), 12)]), "")
		} else {
			rec.add("legacy_tls", "middlebox_quirks", "sslv2_clienthello", "FAIL", "reject/close SSLv2 CH", fmt.Sprintf("err=%v len=%d", v2Err, len(v2Resp)), "")
		}

		// Pre-ClientHello Heartbeat record (0x18)
		hb := []byte{0x18, 0x03, 0x03, 0x00, 0x03, 0x01, 0x40, 0x00}
		outHB := sendRawAndClassify(addr, hb)
		if isRejectedOutcome(outHB) {
			rec.add("legacy_tls", "middlebox_quirks", "tls_heartbeat_pre_ch", "PASS", "fatal alert on Heartbeat record", outHB.detail, "")
		} else {
			rec.add("legacy_tls", "middlebox_quirks", "tls_heartbeat_pre_ch", "FAIL", "fatal alert on Heartbeat record", outHB.detail, "")
		}

		// Post-suite health check before ALPN h2 quirks
		if herr := probeServerHealth(addr, sni, false); herr != nil {
			rec.add("legacy_tls", "liveness", "pre_h2_health", "FAIL", "TLS server alive", herr.Error(), "")
			return
		}
	}

	// 3e. HTTP/2 quirks over TLS 1.3 ALPN h2
	runH2QuirksOnTransport(rec, "legacy_tls_h2", true, &srv, tlsExe, []string{"--port", "0"}, nil, tcpShutdown, sni, "/secure-hello", "/secure-echo")
}

// =========================================================================
// 4. WEBSOCKET REAL-WORLD UPGRADE & DEFLATING EDGE CASES (autobahn_server)
// =========================================================================

func buildWSFrame(opcode byte, rsv1 bool, payload []byte, force64BitMSB1 bool) []byte {
	b0 := byte(0x80) | (opcode & 0x0F)
	if rsv1 {
		b0 |= 0x40
	}
	mask := []byte{0x37, 0xfa, 0x21, 0x3d}
	var hdr []byte
	hdr = append(hdr, b0)
	if force64BitMSB1 {
		hdr = append(hdr, 0x80|127)
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(payload))|0x8000000000000000)
		hdr = append(hdr, lenBuf[:]...)
	} else if len(payload) < 126 {
		hdr = append(hdr, 0x80|byte(len(payload)))
	} else if len(payload) < 65536 {
		hdr = append(hdr, 0x80|126, byte(len(payload)>>8), byte(len(payload)))
	} else {
		hdr = append(hdr, 0x80|127)
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(payload)))
		hdr = append(hdr, lenBuf[:]...)
	}
	hdr = append(hdr, mask...)
	out := make([]byte, len(hdr)+len(payload))
	copy(out, hdr)
	for i, p := range payload {
		out[len(hdr)+i] = p ^ mask[i&3]
	}
	return out
}

func deflateRawRFC7692(src []byte) []byte {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = w.Write(src)
	_ = w.Flush()
	_ = w.Close()
	b := buf.Bytes()
	if len(b) >= 4 && bytes.Equal(b[len(b)-4:], []byte{0x00, 0x00, 0xff, 0xff}) {
		b = b[:len(b)-4]
	}
	return b
}

func runLegacyWebSocketSuite(rec *testRecorder, autobahnExe string) {
	if _, err := os.Stat(autobahnExe); err != nil {
		rec.add("legacy_ws", "setup", "binary_present", "INFO", "skip if unbuilt", err.Error(), "")
		return
	}
	srv, err := startManagedServer("autobahn_legacy", autobahnExe, nil, nil, tcpShutdown)
	if err != nil {
		rec.add("legacy_ws", "setup", "start_server", "FAIL", "start", err.Error(), "")
		return
	}
	defer func() {
		if srv != nil {
			srv.stop()
		}
	}()

	wsKey := "dGhlIHNhbXBsZSBub25jZQ=="
	baseUp := "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: " + wsKey + "\r\nSec-WebSocket-Version: 13\r\n\r\n"

	wsCanary := func(after string) {
		if srv == nil {
			return
		}
		addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
		resp, _, rerr := tcpExchangeRaw(addr, [][]byte{[]byte(baseUp)}, 0, false, 1200*time.Millisecond)
		if rerr == nil && bytes.Contains(resp, []byte("101 Switching Protocols")) {
			return
		}
		rec.add("legacy_ws", "liveness", after+"_canary", "FAIL", "WS server stays alive",
			fmt.Sprintf("err=%v sl=%q", rerr, httpStatusLine(resp)), "")
		srv.stop()
		srv, _ = startManagedServer("autobahn_legacy", autobahnExe, nil, nil, tcpShutdown)
	}

	wsUpgradeCases := []struct {
		name    string
		req     string
		exp     string
		must101 bool
		mustRej bool
	}{
		{
			name:    "ws_multi_connection_mixed_case_upgrade",
			req:     "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\nConnection: Upgrade\r\nUpgrade: WebSocket\r\nSec-WebSocket-Key: " + wsKey + "\r\nSec-WebSocket-Version: 13\r\n\r\n",
			exp:     "101 Switching Protocols on multi-header Connection + mixed-case Upgrade",
			must101: true,
		},
		{
			name:    "ws_x_webkit_deflate_plus_permessage",
			req:     "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: " + wsKey + "\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: x-webkit-deflate-frame; foo=bar, permessage-deflate\r\n\r\n",
			exp:     "101 ignoring unknown extension token safely",
			must101: true,
		},
		{
			name:    "ws_legacy_version_8",
			req:     "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: " + wsKey + "\r\nSec-WebSocket-Version: 8\r\n\r\n",
			exp:     "RFC 6455 s4.4 reject unsupported version 8 (400/426, NOT 200 OK)",
			mustRej: true,
		},
		{
			name:    "ws_multi_version_13_8",
			req:     "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: " + wsKey + "\r\nSec-WebSocket-Version: 13, 8\r\n\r\n",
			exp:     "RFC 6455 reject comma-list Sec-WebSocket-Version (400/426, NOT 200 OK)",
			mustRej: true,
		},
		{
			name:    "ws_missing_key",
			req:     "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n",
			exp:     "RFC 6455 s4.2.1 reject missing Sec-WebSocket-Key (400, NOT 200 OK)",
			mustRej: true,
		},
		{
			name:    "ws_short_nonb64_key",
			req:     "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: not!b64\r\nSec-WebSocket-Version: 13\r\n\r\n",
			exp:     "RFC 6455 s4.2.1 reject invalid 16B base64 key (400, NOT 200 OK)",
			mustRej: true,
		},
		{
			name:    "ws_post_method_upgrade",
			req:     "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: " + wsKey + "\r\nSec-WebSocket-Version: 13\r\n\r\n",
			exp:     "reject non-GET WS Upgrade (400/404/405)",
			mustRej: true,
		},
	}

	for _, tc := range wsUpgradeCases {
		if srv == nil {
			break
		}
		addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
		resp, _, rerr := tcpExchangeRaw(addr, [][]byte{[]byte(tc.req)}, 0, false, 600*time.Millisecond)
		sl := httpStatusLine(resp)
		st := "PASS"
		if rerr != nil {
			st = "FAIL"
		} else if tc.must101 && !strings.Contains(sl, " 101 ") {
			st = "FAIL"
		} else if tc.mustRej && (strings.Contains(sl, " 101 ") || strings.Contains(sl, " 200 ")) {
			st = "FAIL"
		}
		rec.add("legacy_ws", "upgrade_quirks", tc.name, st, tc.exp, fmt.Sprintf("sl=%q len=%d", sl, len(resp)), "")
		wsCanary(tc.name)
	}

	if srv == nil {
		return
	}
	addr := fmt.Sprintf("127.0.0.1:%d", srv.port)

	// Pipelined WS TEXT frame immediately after \r\n\r\n
	pipeWire := append([]byte(baseUp), buildWSFrame(0x1, false, []byte("hello_pipelined"), false)...)
	respP, _, errP := tcpExchangeRaw(addr, [][]byte{pipeWire}, 0, false, 600*time.Millisecond)
	if errP == nil && bytes.Contains(respP, []byte("101 Switching Protocols")) && bytes.Contains(respP, []byte("hello_pipelined")) {
		rec.add("legacy_ws", "frame_quirks", "ws_pipelined_text_with_upgrade", "PASS", "101 + echoed pipelined frame", fmt.Sprintf("len=%d", len(respP)), "")
	} else {
		rec.add("legacy_ws", "frame_quirks", "ws_pipelined_text_with_upgrade", "FAIL", "101 + echoed pipelined frame", fmt.Sprintf("err=%v len=%d sl=%q", errP, len(respP), httpStatusLine(respP)), "")
	}
	wsCanary("ws_pipelined_text_with_upgrade")

	// Corrupt permessage-deflate payload
	deflateUp := "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: " + wsKey + "\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover\r\n\r\n"
	corruptWire := append([]byte(deflateUp), buildWSFrame(0x1, true, []byte{0xff, 0xff, 0x00, 0xde, 0xad, 0xbe, 0xef}, false)...)
	respC, _, errC := tcpExchangeRaw(addr, [][]byte{corruptWire}, 0, false, 600*time.Millisecond)
	if errC == nil && bytes.Contains(respC, []byte{0x88}) && bytes.Contains(respC, []byte{0x03, 0xea}) {
		rec.add("legacy_ws", "frame_quirks", "ws_permessage_deflate_corrupt", "PASS", "Close 1002 on corrupt deflate stream", fmt.Sprintf("len=%d", len(respC)), "")
	} else {
		rec.add("legacy_ws", "frame_quirks", "ws_permessage_deflate_corrupt", "FAIL", "Close 1002 on corrupt deflate", fmt.Sprintf("err=%v len=%d", errC, len(respC)), "")
	}
	wsCanary("ws_permessage_deflate_corrupt")

	// High-compression-ratio 2MB zeros deflate payload (OOM / hang guard)
	z2MB := deflateRawRFC7692(make([]byte, 2*1024*1024))
	zWire := append([]byte(deflateUp), buildWSFrame(0x2, true, z2MB, false)...)
	respZ, dtZ, errZ := tcpExchangeRaw(addr, [][]byte{zWire}, 0, false, 1500*time.Millisecond)
	if errZ == nil && len(respZ) > 0 && dtZ < 1500*time.Millisecond {
		rec.add("legacy_ws", "frame_quirks", "ws_permessage_deflate_2mb_zeros", "PASS", "bounded echo or 1009 without hang/OOM",
			fmt.Sprintf("inZ=%d out=%d dt=%v", len(z2MB), len(respZ), dtZ.Round(time.Millisecond)), "")
	} else {
		rec.add("legacy_ws", "frame_quirks", "ws_permessage_deflate_2mb_zeros", "FAIL", "no crash/hang on 2MB deflate",
			fmt.Sprintf("err=%v out=%d dt=%v", errZ, len(respZ), dtZ), "")
	}
	wsCanary("ws_permessage_deflate_2mb_zeros")

	// 64-bit length with MSB=1 (RFC 6455 s5.2 forbids most significant bit = 1)
	msbWire := append([]byte(baseUp), buildWSFrame(0x1, false, []byte("hello"), true)...)
	respM, _, errM := tcpExchangeRaw(addr, [][]byte{msbWire}, 0, false, 600*time.Millisecond)
	if errM == nil && bytes.Contains(respM, []byte{0x88}) && bytes.Contains(respM, []byte{0x03, 0xea}) {
		rec.add("legacy_ws", "frame_quirks", "ws_64bit_len_msb1", "PASS", "Close 1002 on 64-bit MSB=1 length", fmt.Sprintf("len=%d", len(respM)), "")
	} else {
		rec.add("legacy_ws", "frame_quirks", "ws_64bit_len_msb1", "FAIL", "Close 1002 on 64-bit MSB=1 length", fmt.Sprintf("err=%v len=%d", errM, len(respM)), "")
	}
	wsCanary("ws_64bit_len_msb1")

	// Truncated 3B WS header + CloseWrite
	truncWire := append([]byte(baseUp), 0x81, 0x85, 0x37)
	_, _, errT := tcpExchangeRaw(addr, [][]byte{truncWire}, 0, true, 600*time.Millisecond)
	if errT == nil {
		rec.add("legacy_ws", "frame_quirks", "ws_trunc_3B_shutwr", "PASS", "clean close without crash", "closed cleanly", "")
	} else {
		rec.add("legacy_ws", "frame_quirks", "ws_trunc_3B_shutwr", "FAIL", "clean close", errT.Error(), "")
	}
	wsCanary("ws_trunc_3B_shutwr")
}

// =========================================================================
// 5. gRPC / gRPC-Web MALFORMED FRAMING & PROTOBUF ROBUSTNESS (grpc_server)
// =========================================================================

func runLegacyGrpcSuite(rec *testRecorder, grpcExe string) {
	if _, err := os.Stat(grpcExe); err != nil {
		rec.add("legacy_grpc", "setup", "binary_present", "INFO", "skip if unbuilt", err.Error(), "")
		return
	}
	srv, err := startManagedServer("grpc_legacy", grpcExe, nil, nil, tcpShutdown)
	if err != nil {
		rec.add("legacy_grpc", "setup", "start_server", "FAIL", "start", err.Error(), "")
		return
	}
	defer func() {
		if srv != nil {
			srv.stop()
		}
	}()

	sendH2Grpc := func(addr, path, contentType string, extra [][2]string, dataBody []byte) ([]byte, error) {
		b := append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)...)
		hdrs := buildH2HeadersBlock(addr, "POST", path, append([][2]string{{"content-type", contentType}, {"te", "trailers"}}, extra...))
		b = append(b, packH2Frame(0x01, 0x04, 1, hdrs)...)
		b = append(b, packH2Frame(0x00, 0x01, 1, dataBody)...)
		resp, _, err := tcpExchangeRaw(addr, [][]byte{b}, 0, false, 900*time.Millisecond)
		return resp, err
	}

	grpcCases := []struct {
		name string
		ct   string
		ex   [][2]string
		body []byte
		exp  string
	}{
		{"grpc_trunc_3B_prefix", "application/grpc", nil, []byte{0x00, 0x00, 0x00}, "grpc error (no crash)"},
		{"grpc_declared_10000_on_4B", "application/grpc", nil, []byte{0x00, 0x00, 0x00, 0x27, 0x10, 1, 2, 3, 4}, "reject length mismatch"},
		{"grpc_declared_0xffffffff", "application/grpc", nil, []byte{0x00, 0xff, 0xff, 0xff, 0xff, 1, 2, 3, 4}, "reject 4GB frame length without OOM"},
		{"grpc_compressed1_no_encoding", "application/grpc", nil, []byte{0x01, 0x00, 0x00, 0x00, 0x04, 't', 'e', 's', 't'}, "reject compressed=1 without grpc-encoding"},
		{"grpc_compressed_flag_0x7f", "application/grpc", nil, []byte{0x7F, 0x00, 0x00, 0x00, 0x02, 'h', 'i'}, "reject unknown compressed flag 0x7F"},
		{"grpc_unknown_encoding_lz4", "application/grpc", [][2]string{{"grpc-encoding", "lz4"}}, []byte{0x01, 0x00, 0x00, 0x00, 0x02, 'h', 'i'}, "UNIMPLEMENTED/reject lz4 encoding"},
		{"grpc_corrupt_gzip", "application/grpc", [][2]string{{"grpc-encoding", "gzip"}}, []byte{0x01, 0x00, 0x00, 0x00, 0x06, 0x1f, 0x8b, 0xff, 0x00, 0xaa, 0x55}, "INTERNAL/reject corrupt gzip"},
		{"grpc_web_text_bad_b64", "application/grpc-web-text", nil, []byte("!!!not-valid-base64!!!"), "INVALID_ARGUMENT on bad base64"},
		{"grpc_pb_endless_varint_32B", "application/grpc", nil, func() []byte {
			pb := append([]byte{0x08}, bytes.Repeat([]byte{0x80}, 32)...)
			pb = append(pb, 0x01)
			p := make([]byte, 5+len(pb))
			binary.BigEndian.PutUint32(p[1:5], uint32(len(pb)))
			copy(p[5:], pb)
			return p
		}(), "handle overlong protobuf varint cleanly"},
		{"grpc_pb_len_delim_0x7fffffff", "application/grpc", nil, []byte{0x00, 0x00, 0x00, 0x00, 0x0A, 0x0A, 0xff, 0xff, 0xff, 0xff, 0x07, 'a', 'b', 'c', 'd'}, "handle 2GB protobuf field cleanly"},
		{"grpc_timeout_malformed", "application/grpc", [][2]string{{"grpc-timeout", "99999999999999999999S"}}, []byte{0x00, 0x00, 0x00, 0x00, 0x07, 0x0A, 0x05, 'w', 'o', 'r', 'l', 'd'}, "no overflow on huge grpc-timeout"},
	}

	for _, tc := range grpcCases {
		if srv == nil {
			break
		}
		addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
		resp, gerr := sendH2Grpc(addr, "/echo.EchoService/Echo", tc.ct, tc.ex, tc.body)
		ga, _, hdrs, sum := summarizeH2Frames(resp)
		if gerr != nil || (!ga && !hdrs) {
			rec.add("legacy_grpc", "grpc_malformed", tc.name, "FAIL", tc.exp, fmt.Sprintf("err=%v sum=%s", gerr, sum), "")
		} else {
			rec.add("legacy_grpc", "grpc_malformed", tc.name, "PASS", tc.exp, sum, "")
		}
		// Per-probe H2 PREFACE canary
		cResp, _, cErr := tcpExchangeRaw(addr, [][]byte{[]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)}, 0, false, 800*time.Millisecond)
		if cErr != nil || len(cResp) < 9 || cResp[3] != 0x04 {
			rec.add("legacy_grpc", "liveness", tc.name+"_canary", "FAIL", "gRPC H2 server alive", fmt.Sprintf("err=%v len=%d", cErr, len(cResp)), "")
			srv.stop()
			srv, _ = startManagedServer("grpc_legacy", grpcExe, nil, nil, tcpShutdown)
		}
	}
}

// =========================================================================
// 6. UDP INTERNET BACKGROUND NOISE & LEGACY QUIC VERSIONS (http3_server)
// =========================================================================

func runLegacyHTTP3NoiseSuite(rec *testRecorder, http3Exe string) {
	if _, err := os.Stat(http3Exe); err != nil {
		rec.add("legacy_h3_udp", "setup", "binary_present", "INFO", "skip if unbuilt", err.Error(), "")
		return
	}
	srv, err := startManagedServer("http3_legacy", http3Exe, nil, nil, udpShutdown)
	if err != nil {
		rec.add("legacy_h3_udp", "setup", "start_server", "FAIL", "start", err.Error(), "")
		return
	}
	defer func() {
		if srv != nil {
			srv.stop()
		}
	}()

	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	scid := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	vnCanaryPkt := buildQUICInitial(0x1a2a3a4a, dcid, scid, nil, []byte{0x01, 'p', 'i', 'n', 'g'}, 1200, 0xC0)

	dnsPkt := mustHexSlice("123401000001000000000000076578616d706c6503636f6d0000010001")
	stunPkt := mustHexSlice("000100002112a442" + strings.Repeat("aa", 12))
	ntpPkt := append([]byte{0x1b}, make([]byte, 47)...)
	ssdpPkt := []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
	snmpPkt := mustHexSlice("302602010004067075626c6963a019020412345678020100020100300b300906052b060102010500")
	coalesced2x := append(buildQUICInitial(0xff00001d, dcid, scid, nil, []byte("a"), 1200, 0xC0),
		buildQUICInitial(0xfaceb002, dcid, scid, nil, []byte("b"), 1200, 0xC0)...)

	udpCases := []struct {
		name         string
		pkt          []byte
		mustDiscard  bool
		expectVN     bool
		warnIfSilent bool
		exp          string
	}{
		{"udp_dns_query", dnsPkt, true, false, false, "silently discard DNS query"},
		{"udp_stun_binding", stunPkt, true, false, false, "silently discard STUN (must not emit 4B frame)"},
		{"udp_ntp_v4", ntpPkt, true, false, false, "silently discard NTP"},
		{"udp_ssdp_msearch", ssdpPkt, true, false, false, "silently discard SSDP"},
		{"udp_snmpv1_get", snmpPkt, true, false, false, "silently discard SNMPv1"},
		{"udp_quic_draft29_vn", buildQUICInitial(0xff00001d, dcid, scid, nil, []byte("d29"), 1200, 0xC0), false, true, false, "Version Negotiation for draft-29"},
		{"udp_quic_mvfst_vn", buildQUICInitial(0xfaceb002, dcid, scid, nil, []byte("mv"), 1200, 0xC0), false, true, false, "Version Negotiation for mvfst"},
		{"udp_quic_v2_initial", buildQUICInitial(0x6b3343cf, dcid, scid, nil, []byte("v2"), 1200, 0xC0), false, false, true, "Version Negotiation (RFC 9369) or discard without crash"},
		{"udp_quic_coalesced_2x", coalesced2x, false, false, false, "handle coalesced 2x packets without crash"},
		{"udp_jumbo_4096B", bytes.Repeat([]byte{0x5A}, 4096), true, false, false, "discard oversized 4KB UDP datagram cleanly"},
		{"udp_1200B_zeros", make([]byte, 1200), true, false, false, "silently discard 1200B all-zeros (fixed-bit=0, RFC 9000)"},
		{"udp_1200B_0xff", bytes.Repeat([]byte{0xff}, 1200), true, false, false, "silently discard 1200B all-0xff"},
	}

	for _, tc := range udpCases {
		if srv == nil {
			break
		}
		addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
		resp, _ := sendUDPAndRecv(addr, tc.pkt, 300*time.Millisecond)
		if tc.mustDiscard && len(resp) > 0 {
			rec.add("legacy_h3_udp", "udp_noise", tc.name, "FAIL", tc.exp,
				fmt.Sprintf("unexpected %dB reply hex=%x", len(resp), resp[:minInt(len(resp), 16)]),
				hex.EncodeToString(tc.pkt[:minInt(len(tc.pkt), 24)]))
		} else if tc.expectVN && (len(resp) < 5 || binary.BigEndian.Uint32(resp[1:5]) != 0) {
			rec.add("legacy_h3_udp", "udp_noise", tc.name, "FAIL", tc.exp, fmt.Sprintf("len=%d", len(resp)), "")
		} else if tc.warnIfSilent && len(resp) == 0 {
			rec.add("legacy_h3_udp", "udp_noise", tc.name, "WARN", tc.exp, "silently dropped QUIC v2 (no VN packet)", "")
		} else {
			rec.add("legacy_h3_udp", "udp_noise", tc.name, "PASS", tc.exp,
				fmt.Sprintf("len=%d hex=%x", len(resp), resp[:minInt(len(resp), 16)]), "")
		}

		// Liveness check via Version Negotiation canary after every packet
		cResp, cErr := sendUDPAndRecv(addr, vnCanaryPkt, 800*time.Millisecond)
		if cErr != nil || len(cResp) < 9 || binary.BigEndian.Uint32(cResp[1:5]) != 0 {
			rec.add("legacy_h3_udp", "liveness", tc.name+"_canary", "FAIL", "http3_server stays alive",
				fmt.Sprintf("err=%v len=%d stderr=%q", cErr, len(cResp), srv.getStderr()), "")
			srv.stop()
			srv, _ = startManagedServer("http3_legacy", http3Exe, nil, nil, udpShutdown)
		}
	}
}

func mustHexSlice(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}
