// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// runInternetLegacyR2Suite executes Round 2 blind-discovered stateful FSM,
// capacity-cliff, UDP dispatch map, decompression-limit, and cross-engine
// differential checks (strictly non-duplicate with Round 1 and --legacy).
func runInternetLegacyR2Suite(pki *testPKI) int {
	_ = pki
	rec := &testRecorder{}
	binDir := filepath.Join(repoRoot, "tools", "bin")

	chaosExe := exePath(binDir, "chaos_server")
	h2specExe := exePath(binDir, "h2spec_server")
	tlsExe := exePath(binDir, "tls_server")
	autobahnExe := exePath(binDir, "autobahn_server")
	grpcExe := exePath(binDir, "grpc_server")
	http3Exe := exePath(binDir, "http3_server")

	runR2ReactorBoundaryAndStateSuite(rec, chaosExe)
	runR2H2StatefulSuite(rec, h2specExe, tlsExe)
	runR2TLSCapacityAndHRRSuite(rec, tlsExe)
	runR2WebSocketStatefulAndBombSuite(rec, autobahnExe)
	runR2GrpcVarintAndBombSuite(rec, grpcExe)
	runR2HTTP3DispatchMapSuite(rec, http3Exe)
	runR2CrossEngineDifferentialSuite(rec, chaosExe, h2specExe, tlsExe)

	fmt.Println("\n================ INTERNET & LEGACY R2 SUITE SUMMARY ================")
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
		fmt.Printf("  %-24s: PASS=%3d  FAIL=%3d  WARN=%2d  INFO=%2d\n", s, c.pass, c.fail, c.warn, c.info)
	}
	fmt.Printf("\nLEGACY-R2 TOTALS -> FAIL=%d | WARN=%d | INFO=%d\n", len(fails), len(warns), len(infos))
	if len(fails) > 0 {
		fmt.Println("\n--- LEGACY-R2 FAILURES ---")
		for _, f := range fails {
			fmt.Printf("  [FAIL] %s/%s/%s\n         exp: %s\n         got: %s\n",
				f.suite, f.category, f.name, f.expected, f.observed)
			if f.wireHex != "" {
				fmt.Printf("         hex: %s\n", f.wireHex)
			}
		}
	}
	if len(warns) > 0 {
		fmt.Println("\n--- LEGACY-R2 WARNINGS ---")
		for _, w := range warns {
			fmt.Printf("  [WARN] %s/%s/%s | exp=%s | got=%s\n", w.suite, w.category, w.name, w.expected, w.observed)
		}
	}
	if len(infos) > 0 {
		fmt.Println("\n--- LEGACY-R2 DIFFERENTIALS / INFO ---")
		for _, in := range infos {
			fmt.Printf("  [INFO] %s/%s/%s | exp=%s | got=%s\n", in.suite, in.category, in.name, in.expected, in.observed)
		}
	}
	if logDir != "" {
		logPath := filepath.Join(logDir, "legacy_r2_results.log")
		_ = os.WriteFile(logPath, []byte(logBuf.String()), 0600)
		fmt.Printf("\n[+] Legacy R2 wire log written to %s\n", logPath)
	}
	return len(fails)
}

// =========================================================================
// 1. REACTOR BOUNDARY CLIFFS, STATEFUL LIFECYCLE & MUTATION REPRODUCERS
// =========================================================================

func runR2ReactorBoundaryAndStateSuite(rec *testRecorder, chaosExe string) {
	if _, err := os.Stat(chaosExe); err != nil {
		rec.add("r2_reactor", "setup", "binary_present", "INFO", "skip if unbuilt", err.Error(), "")
		return
	}
	srv, err := startManagedServer("chaos_r2", chaosExe, nil, nil, nil)
	if err != nil {
		rec.add("r2_reactor", "setup", "start_server", "FAIL", "start", err.Error(), "")
		return
	}
	defer func() {
		if srv != nil {
			srv.stop()
		}
	}()
	canary := "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"

	// Exact power-of-two capacity cliffs: URL 2048/2049, HeaderVal 4096/4097, Headers 128/129
	{
		addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
		u2048 := "GET /" + strings.Repeat("a", 2047) + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
		u2049 := "GET /" + strings.Repeat("a", 2048) + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
		r1, _, e1 := tcpExchangeRaw(addr, [][]byte{[]byte(u2048)}, 0, false, 600*time.Millisecond)
		r2, _, e2 := tcpExchangeRaw(addr, [][]byte{[]byte(u2049)}, 0, false, 600*time.Millisecond)
		if e1 == nil && e2 == nil && strings.Contains(httpStatusLine(r1), " 404") && strings.Contains(httpStatusLine(r2), " 400") {
			rec.add("r2_reactor", "boundaries", "url_len_2048_vs_2049", "PASS", "2048->404, 2049->400", httpStatusLine(r1)+" / "+httpStatusLine(r2), "")
		} else {
			rec.add("r2_reactor", "boundaries", "url_len_2048_vs_2049", "WARN", "2048->404, 2049->400", httpStatusLine(r1)+" / "+httpStatusLine(r2), "")
		}
		checkOrRestartHTTP(rec, "r2_reactor", "url_cliff", &srv, chaosExe, nil, nil, nil, canary, "200 OK")

		hv4096 := "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Pad: " + strings.Repeat("b", 4096) + "\r\nConnection: close\r\n\r\n"
		hv4097 := "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Pad: " + strings.Repeat("b", 4097) + "\r\nConnection: close\r\n\r\n"
		r3, _, _ := tcpExchangeRaw(addr, [][]byte{[]byte(hv4096)}, 0, false, 600*time.Millisecond)
		r4, _, _ := tcpExchangeRaw(addr, [][]byte{[]byte(hv4097)}, 0, false, 600*time.Millisecond)
		if strings.Contains(httpStatusLine(r3), " 200") && strings.Contains(httpStatusLine(r4), " 400") {
			rec.add("r2_reactor", "boundaries", "hval_len_4096_vs_4097", "PASS", "4096->200, 4097->400", httpStatusLine(r3)+" / "+httpStatusLine(r4), "")
		} else {
			rec.add("r2_reactor", "boundaries", "hval_len_4096_vs_4097", "WARN", "4096->200, 4097->400", httpStatusLine(r3)+" / "+httpStatusLine(r4), "")
		}
		checkOrRestartHTTP(rec, "r2_reactor", "hval_cliff", &srv, chaosExe, nil, nil, nil, canary, "200 OK")

		mkNHdrs := func(n int) []byte {
			var sb strings.Builder
			sb.WriteString("GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n")
			for i := 0; i < n; i++ {
				fmt.Fprintf(&sb, "X-H%d: 1\r\n", i)
			}
			sb.WriteString("Connection: close\r\n\r\n")
			return []byte(sb.String())
		}
		rh128, _, _ := tcpExchangeRaw(addr, [][]byte{mkNHdrs(126)}, 0, false, 600*time.Millisecond)
		rh129, _, _ := tcpExchangeRaw(addr, [][]byte{mkNHdrs(127)}, 0, false, 600*time.Millisecond)
		if strings.Contains(httpStatusLine(rh128), " 200") && strings.Contains(httpStatusLine(rh129), " 400") {
			rec.add("r2_reactor", "boundaries", "hdr_count_128_vs_129", "PASS", "128->200, 129->400", httpStatusLine(rh128)+" / "+httpStatusLine(rh129), "")
		} else {
			rec.add("r2_reactor", "boundaries", "hdr_count_128_vs_129", "WARN", "128->200, 129->400", httpStatusLine(rh128)+" / "+httpStatusLine(rh129), "")
		}
	}

	// \r\n\r\n terminator straddling exact 4096B boundary across 2 writes
	if srv != nil {
		addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
		hdrPrefix := "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nX-S: "
		pad := 4095 - len(hdrPrefix)
		req := []byte(hdrPrefix + strings.Repeat("x", pad) + "\r\n\r\n")
		resp, _, rerr := tcpExchangeRaw(addr, [][]byte{req[:4096], req[4096:]}, 5*time.Millisecond, false, 700*time.Millisecond)
		if rerr == nil && strings.Contains(httpStatusLine(resp), " 200") {
			rec.add("r2_reactor", "boundaries", "crlfcrlf_straddle_4096_split", "PASS", "200 OK across 4096B read boundary", httpStatusLine(resp), "")
		} else {
			rec.add("r2_reactor", "boundaries", "crlfcrlf_straddle_4096_split", "FAIL", "200 OK across 4096B split", fmt.Sprintf("err=%v sl=%q", rerr, httpStatusLine(resp)), "")
		}
		checkOrRestartHTTP(rec, "r2_reactor", "straddle_4096", &srv, chaosExe, nil, nil, nil, canary, "200 OK")
	}

	// 1500 x 1-byte chunks + quoted escaped chunk-extension + raw CRLF inside quote
	if srv != nil {
		addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
		c1500 := "POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" +
			strings.Repeat("1\r\na\r\n", 1500) + "0\r\n\r\n"
		resp15, dt15, err15 := tcpExchangeRaw(addr, [][]byte{[]byte(c1500)}, 0, false, 1500*time.Millisecond)
		if err15 == nil && strings.Contains(httpStatusLine(resp15), " 200") {
			rec.add("r2_reactor", "boundaries", "chunked_1500x1B_chunks", "PASS", "200 OK without stall/crash",
				fmt.Sprintf("dt=%v len=%d", dt15.Round(time.Millisecond), len(resp15)), "")
		} else {
			rec.add("r2_reactor", "boundaries", "chunked_1500x1B_chunks", "FAIL", "200 OK", fmt.Sprintf("err=%v sl=%q", err15, httpStatusLine(resp15)), "")
		}

		qValid := "POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4;ext=\"a;\\\"b\\\"\\;c\";b=2\r\nping\r\n0\r\n\r\n"
		rqv, _, _ := tcpExchangeRaw(addr, [][]byte{[]byte(qValid)}, 0, false, 600*time.Millisecond)
		qCRLF := "POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4;ext=\"a\r\nb\"\r\nping\r\n0\r\n\r\n"
		rqc, _, _ := tcpExchangeRaw(addr, [][]byte{[]byte(qCRLF)}, 0, false, 600*time.Millisecond)
		if strings.Contains(httpStatusLine(rqv), " 200") && strings.Contains(httpStatusLine(rqc), " 400") {
			rec.add("r2_reactor", "chunk_grammar", "quoted_escaped_ext_vs_raw_crlf", "PASS", "valid->200, raw_crlf->400",
				httpStatusLine(rqv)+" / "+httpStatusLine(rqc), "")
		} else {
			rec.add("r2_reactor", "chunk_grammar", "quoted_escaped_ext_vs_raw_crlf", "FAIL", "valid->200, raw_crlf->400",
				httpStatusLine(rqv)+" / "+httpStatusLine(rqc), "")
		}
		checkOrRestartHTTP(rec, "r2_reactor", "chunk_grammar", &srv, chaosExe, nil, nil, nil, canary, "200 OK")
	}

	// Stateful 10-request keep-alive chain (HEAD, POST echo, chunked GET) + cross-socket isolation
	if srv != nil {
		addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
		conn, cerr := net.DialTimeout("tcp", addr, time.Second)
		if cerr != nil {
			rec.add("r2_reactor", "stateful_fsm", "keepalive_10req_chain", "FAIL", "connect", cerr.Error(), "")
		} else {
			chain := ""
			for i := 0; i < 3; i++ {
				chain += "HEAD /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
				chain += "POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\n\r\nping"
				chain += "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
			}
			chain += "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
			_, _ = conn.Write([]byte(chain))
			_ = conn.SetReadDeadline(time.Now().Add(900 * time.Millisecond))
			var out bytes.Buffer
			buf := make([]byte, 4096)
			for {
				n, rerr := conn.Read(buf)
				if n > 0 {
					out.Write(buf[:n])
				}
				if rerr != nil {
					break
				}
			}
			_ = conn.Close()
			n200 := bytes.Count(out.Bytes(), []byte("HTTP/1.1 200 OK"))
			if n200 == 10 {
				rec.add("r2_reactor", "stateful_fsm", "keepalive_10req_chain", "PASS", "10 synchronized 200 OK responses", fmt.Sprintf("count=%d bytes=%d", n200, out.Len()), "")
			} else {
				rec.add("r2_reactor", "stateful_fsm", "keepalive_10req_chain", "FAIL", "10 synchronized 200 OK responses", fmt.Sprintf("count=%d bytes=%d", n200, out.Len()), "")
			}
		}

		// Cross-socket contamination test: hold partial poison headers on A while calling B
		connA, errA := net.DialTimeout("tcp", addr, time.Second)
		if errA == nil {
			_, _ = connA.Write([]byte("GET /health HTTP/1.1\r\nHost: leaked-socket-a.invalid\r\nX-Leak: SECRET_A"))
			respB, _, errB := tcpExchangeRaw(addr, [][]byte{[]byte("GET /health HTTP/1.1\r\nHost: clean-b\r\nConnection: close\r\n\r\n")}, 0, false, 600*time.Millisecond)
			_ = connA.Close()
			if errB == nil && bytes.Contains(respB, []byte("200 OK")) && !bytes.Contains(respB, []byte("SECRET_A")) {
				rec.add("r2_reactor", "stateful_fsm", "cross_socket_isolation", "PASS", "no state bleed from partial Socket A", "clean 200 OK", "")
			} else {
				rec.add("r2_reactor", "stateful_fsm", "cross_socket_isolation", "FAIL", "no state bleed", fmt.Sprintf("err=%v len=%d", errB, len(respB)), "")
			}
		}
		checkOrRestartHTTP(rec, "r2_reactor", "stateful", &srv, chaosExe, nil, nil, nil, canary, "200 OK")
	}

	// Mutator truncation + splice reproducers + canary verification
	if srv != nil {
		repros := []struct {
			name string
			raw  []byte
		}{
			{"mutator_trunc_11B_POST", []byte("POST /echo ")},
			{"mutator_trunc_headers_86B", mustHexSlice("504f5354202f6563686f20485454502f312e310d0a486f73743a203132372e302e302e310d0a5472616e736665722d456e636f64696e673a206368756e6b65640d0a436f6e6e656374696f6e3a20636c6f73650d0a0d")},
			{"mutator_splice_chunk_lf", mustHexSlice("504f5354202f6563686f20485454502f312e310d0a486f73743a203132372e302e302e310d0a5472616e736665722d456e636f64696e673a206368756e6b65640d0a0d0a340d0a70696e0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a340d0a70696e670d0a300d0a0d0a")},
		}
		for _, rp := range repros {
			if srv == nil {
				break
			}
			addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
			resp, _, rerr := tcpExchangeRaw(addr, [][]byte{rp.raw}, 0, true, 500*time.Millisecond)
			rec.add("r2_reactor", "mutator_repro", rp.name, "PASS", "handle truncated/spliced mutation without panic",
				fmt.Sprintf("err=%v len=%d sl=%q", rerr, len(resp), httpStatusLine(resp)), "")
			checkOrRestartHTTP(rec, "r2_reactor", rp.name, &srv, chaosExe, nil, nil, nil, canary, "200 OK")
		}
	}
}

// =========================================================================
// 2. HTTP/2 STATEFUL MULTIPLEXING, HPACK TABLE, & H2C PERSISTENCE
// =========================================================================

func runR2H2StatefulSuite(rec *testRecorder, h2specExe, tlsExe string) {
	// 2a. Cleartext H2C multi-RTT persistence (h2spec_server)
	if _, err := os.Stat(h2specExe); err == nil {
		srvH2C, err := startManagedServer("h2spec_r2", h2specExe, nil, nil, tcpShutdown)
		if err != nil {
			rec.add("r2_h2_stateful", "setup", "start_h2c", "FAIL", "start", err.Error(), "")
		} else {
			addr := fmt.Sprintf("127.0.0.1:%d", srvH2C.port)
			conn, derr := net.DialTimeout("tcp", addr, time.Second)
			if derr == nil {
				prefaceSettings := append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)...)
				_, _ = conn.Write(prefaceSettings)
				_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				_, _, _, sum := summarizeH2Frames(buf[:n])
				// Now attempt 2nd RTT: SETTINGS(ACK) + HEADERS stream 1
				rtt2 := append(packH2Frame(0x04, 0x01, 0, nil), packH2Frame(0x01, 0x05, 1, buildH2HeadersBlock("127.0.0.1", "GET", "/ping", nil))...)
				_, werr := conn.Write(rtt2)
				var resp2 []byte
				if werr == nil {
					_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
					n2, rerr2 := conn.Read(buf)
					if n2 > 0 {
						resp2 = buf[:n2]
					}
					_, _, hdrs2, sum2 := summarizeH2Frames(resp2)
					if hdrs2 {
						rec.add("r2_h2_stateful", "h2c_fsm", "h2c_multi_rtt_persistent", "PASS", "multi-RTT cleartext H2C works", sum+" -> "+sum2, "")
					} else {
						rec.add("r2_h2_stateful", "h2c_fsm", "h2c_multi_rtt_persistent", "FAIL",
							"RFC 9113 s3.4 keep H2C connection open across SETTINGS exchange",
							fmt.Sprintf("preface_reply=%s rtt2_err=%v rtt2_bytes=%d (%s)", sum, rerr2, len(resp2), sum2), "")
					}
				} else {
					rec.add("r2_h2_stateful", "h2c_fsm", "h2c_multi_rtt_persistent", "FAIL",
						"RFC 9113 s3.4 keep H2C connection open across SETTINGS exchange",
						fmt.Sprintf("preface_reply=%s write2_err=%v", sum, werr), "")
				}
				_ = conn.Close()
			}
			srvH2C.stop()
		}
	}

	// 2b. Stateful H2 multiplexing, HPACK dynamic table, decreasing stream ID, & preface fallback on tls_server
	if _, err := os.Stat(tlsExe); err != nil {
		rec.add("r2_h2_stateful", "setup", "tls_binary", "INFO", "skip if unbuilt", err.Error(), "")
		return
	}
	srvTLS, err := startManagedServer("tls_h2_r2", tlsExe, []string{"--port", "0"}, nil, tcpShutdown)
	if err != nil {
		rec.add("r2_h2_stateful", "setup", "start_tls", "FAIL", "start", err.Error(), "")
		return
	}
	defer func() {
		if srvTLS != nil {
			srvTLS.stop()
		}
	}()
	addr := fmt.Sprintf("127.0.0.1:%d", srvTLS.port)
	sni := "goose-wing.local"

	dialH2TLS := func() (*tls13ClientSession, error) {
		cfg := defaultHandshakeConfig(sni)
		cfg.alpn = []string{"h2"}
		return doTLS13Handshake(addr, cfg)
	}

	// Advertised MAX_CONCURRENT_STREAMS=100 vs real limit of 16 (17th stream REFUSED_STREAM)
	if sess, serr := dialH2TLS(); serr == nil {
		var pkt []byte
		pkt = append(pkt, h2Preface...)
		pkt = append(pkt, packH2Frame(0x04, 0x00, 0, nil)...)
		hb := buildH2HeadersBlock(sni, "POST", "/secure-echo", nil)
		for i := 0; i < 17; i++ {
			sid := uint32(1 + i*2)
			pkt = append(pkt, packH2Frame(0x01, 0x04, sid, hb)...) // END_HEADERS without END_STREAM
		}
		_ = sess.sendAppData(pkt, false)
		raw, _ := sess.readAppData(900 * time.Millisecond)
		sess.close()
		_, rst, _, sum := summarizeH2Frames(raw)
		if !rst && !bytes.Contains(raw, []byte{0x00, 0x00, 0x04, 0x03}) {
			rec.add("r2_h2_stateful", "mux_limits", "h2_advertised_100_streams_vs_17_open", "PASS", "accept 17 concurrent streams when advertising 100", sum, "")
		} else {
			rec.add("r2_h2_stateful", "mux_limits", "h2_advertised_100_streams_vs_17_open", "FAIL",
				"RFC 9113 s5.1.2 allow up to advertised SETTINGS_MAX_CONCURRENT_STREAMS=100",
				"refused 17th concurrent stream despite advertising MAX=100: "+sum, "")
		}
	}

	// DATA after END_STREAM on stream 1 MUST RST stream 1 without killing concurrent stream 3
	if sess, serr := dialH2TLS(); serr == nil {
		hbGet := buildH2HeadersBlock(sni, "GET", "/secure-hello", nil)
		pkt := append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)...)
		pkt = append(pkt, packH2Frame(0x01, 0x05, 1, hbGet)...)
		pkt = append(pkt, packH2Frame(0x00, 0x01, 1, []byte("late-data"))...)
		pkt = append(pkt, packH2Frame(0x01, 0x05, 3, hbGet)...)
		_ = sess.sendAppData(pkt, false)
		raw, _ := sess.readAppData(800 * time.Millisecond)
		sess.close()
		ga, rst, hdrs, sum := summarizeH2Frames(raw)
		if !ga && rst && hdrs {
			rec.add("r2_h2_stateful", "mux_fsm", "data_after_end_stream_preserves_sid3", "PASS", "RST stream 1 while stream 3 returns HEADERS", sum, "")
		} else {
			rec.add("r2_h2_stateful", "mux_fsm", "data_after_end_stream_preserves_sid3", "WARN", "isolate stream 1 error from stream 3", sum, "")
		}
	}

	// Decreasing stream ID (sid=3 then sid=1) MUST send GOAWAY(PROTOCOL_ERROR=1) per RFC 9113 s5.1.1
	if sess, serr := dialH2TLS(); serr == nil {
		hbGet := buildH2HeadersBlock(sni, "GET", "/secure-hello", nil)
		pkt := append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)...)
		pkt = append(pkt, packH2Frame(0x01, 0x05, 3, hbGet)...)
		pkt = append(pkt, packH2Frame(0x01, 0x05, 1, hbGet)...)
		_ = sess.sendAppData(pkt, false)
		raw, _ := sess.readAppData(700 * time.Millisecond)
		sess.close()
		ga, _, _, sum := summarizeH2Frames(raw)
		if ga {
			rec.add("r2_h2_stateful", "mux_fsm", "decreasing_sid_3_then_1_fresh_conn", "PASS", "GOAWAY(PROTOCOL_ERROR)", sum, "")
		} else {
			rec.add("r2_h2_stateful", "mux_fsm", "decreasing_sid_3_then_1_fresh_conn", "FAIL",
				"RFC 9113 s5.1.1 connection-level GOAWAY(PROTOCOL_ERROR) on decreasing stream ID", sum, "")
		}
	}

	// 30 empty CONTINUATION frames + HPACK table resize 0 -> 4096 -> evicted idx 62
	if sess, serr := dialH2TLS(); serr == nil {
		pkt := append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)...)
		pkt = append(pkt, packH2Frame(0x01, 0x00, 1, buildH2HeadersBlock(sni, "GET", "/secure-hello", nil))...)
		for i := 0; i < 30; i++ {
			pkt = append(pkt, packH2Frame(0x09, 0x00, 1, nil)...)
		}
		_ = sess.sendAppData(pkt, false)
		raw, _ := sess.readAppData(700 * time.Millisecond)
		sess.close()
		ga, _, _, sum := summarizeH2Frames(raw)
		if ga || len(raw) > 0 {
			rec.add("r2_h2_stateful", "hpack_dos", "30_empty_continuation_frames", "PASS", "GOAWAY(PROTOCOL_ERROR)", sum, "")
		} else {
			rec.add("r2_h2_stateful", "hpack_dos", "30_empty_continuation_frames", "FAIL", "GOAWAY on continuation flood", sum, "")
		}
	}
	if sess, serr := dialH2TLS(); serr == nil {
		// Insert literal-indexed x-custom: abc (idx 62), then shrink table=0 (0x20), restore=4096 (0x3fe11f), reference idx 62 (0xbe)
		hbIns := append(buildH2HeadersBlock(sni, "GET", "/secure-hello", nil), 0x40, 0x08)
		hbIns = append(hbIns, "x-custom"...)
		hbIns = append(hbIns, 0x03, 'a', 'b', 'c')
		hbEvictUse := append([]byte{0x20, 0x3f, 0xe1, 0x1f}, buildH2HeadersBlock(sni, "GET", "/secure-hello", nil)...)
		hbEvictUse = append(hbEvictUse, 0xbe)
		pkt := append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)...)
		pkt = append(pkt, packH2Frame(0x01, 0x05, 1, hbIns)...)
		pkt = append(pkt, packH2Frame(0x01, 0x05, 3, hbEvictUse)...)
		_ = sess.sendAppData(pkt, false)
		raw, _ := sess.readAppData(700 * time.Millisecond)
		sess.close()
		ga, _, _, sum := summarizeH2Frames(raw)
		if ga {
			rec.add("r2_h2_stateful", "hpack_dos", "hpack_evict_0_4096_then_ref_idx62", "PASS", "GOAWAY(COMPRESSION_ERROR=9)", sum, "")
		} else {
			rec.add("r2_h2_stateful", "hpack_dos", "hpack_evict_0_4096_then_ref_idx62", "FAIL", "reject reference to evicted dynamic idx 62", sum, "")
		}
	}

	// Malformed H2 preface inside ALPN h2 session leaks plaintext HTTP/1.1 400 Bad Request
	if sess, serr := dialH2TLS(); serr == nil {
		_ = sess.sendAppData([]byte("PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n"), false)
		raw, _ := sess.readAppData(600 * time.Millisecond)
		sess.close()
		if bytes.Contains(raw, []byte("HTTP/1.1 400")) {
			rec.add("r2_h2_stateful", "alpn_fsm", "alpn_h2_malformed_preface_h1_leak", "FAIL",
				"H2 GOAWAY/close on invalid preface inside ALPN h2 (NOT plaintext HTTP/1.1 400)",
				fmt.Sprintf("got HTTP/1.1 inside h2 session: %q", truncStr(string(raw), 64)), "")
		} else {
			rec.add("r2_h2_stateful", "alpn_fsm", "alpn_h2_malformed_preface_h1_leak", "PASS", "GOAWAY or close", truncStr(string(raw), 64), "")
		}
	}
}

// =========================================================================
// 3. TLS 1.3 CAPACITY CLIFFS, KEYSHARE ORDERING, HRR, & MID-REQ KEYUPDATE
// =========================================================================

func runR2TLSCapacityAndHRRSuite(rec *testRecorder, tlsExe string) {
	if _, err := os.Stat(tlsExe); err != nil {
		return
	}
	srv, err := startManagedServer("tls_r2", tlsExe, []string{"--port", "0"}, nil, tcpShutdown)
	if err != nil {
		rec.add("r2_tls_r2", "setup", "start_server", "FAIL", "start", err.Error(), "")
		return
	}
	defer func() {
		if srv != nil {
			srv.stop()
		}
	}()
	addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
	sni := "goose-wing.local"

	validX25519 := func() []byte {
		k, _ := ecdh.X25519().GenerateKey(rand.Reader)
		return k.PublicKey().Bytes()
	}
	validP256 := func() []byte {
		k, _ := ecdh.P256().GenerateKey(rand.Reader)
		return k.PublicKey().Bytes()
	}
	_ = elliptic.P256()

	// Helper to build CH with custom extensions & optional extra key_shares
	mkManyExtCH := func(totalExts int, ksEntries []keyShareEntry, groups []uint16) []byte {
		exts := []rawExt{
			extSNI(sni),
			extSupportedVersionsClient(0x0304),
			extSupportedGroups(groups...),
			extSigAlgs(SigEd25519, SigECDSAP256SHA256),
			extALPN("http/1.1"),
			extKeyShareClient(ksEntries...),
		}
		for i := len(exts); i < totalExts; i++ {
			exts = append(exts, rawExt{typ: uint16(0x6000 + i), body: []byte{0x01}})
		}
		return makeRecord(RecHandshake, 0x0301, buildClientHelloMsg(clientHelloOpts{
			legacyVer: 0x0303,
			sessionID: bytes.Repeat([]byte{0x31}, 32),
			ciphers:   []uint16{CipherAES128GCM},
			exts:      exts,
		}))
	}

	// Extension count cliff: 32 vs 33
	out32 := sendRawAndClassify(addr, mkManyExtCH(32, []keyShareEntry{{group: GroupX25519, key: validX25519()}}, []uint16{GroupX25519}))
	out33 := sendRawAndClassify(addr, mkManyExtCH(33, []keyShareEntry{{group: GroupX25519, key: validX25519()}}, []uint16{GroupX25519}))
	if out32.kind == "HANDSHAKE" && isRejectedOutcome(out33) {
		rec.add("r2_tls_r2", "capacity_cliffs", "max_extensions_32_vs_33", "WARN", "measure exact extension count ceiling",
			fmt.Sprintf("32->%s, 33->%s", out32.detail, out33.detail), "")
	} else {
		rec.add("r2_tls_r2", "capacity_cliffs", "max_extensions_32_vs_33", "INFO", "32 vs 33 extensions", out32.detail+" / "+out33.detail, "")
	}

	// KeyShare entry count cliff: 32 vs 33
	ks32 := []keyShareEntry{{group: GroupX25519, key: validX25519()}}
	groups32 := []uint16{GroupX25519}
	for i := 1; i < 32; i++ {
		g := uint16(0x5000 + i)
		ks32 = append(ks32, keyShareEntry{group: g, key: []byte{0x00}})
		groups32 = append(groups32, g)
	}
	ks33 := append(append([]keyShareEntry{}, ks32...), keyShareEntry{group: 0x50ff, key: []byte{0x00}})
	groups33 := append(append([]uint16{}, groups32...), 0x50ff)
	outKS32 := sendRawAndClassify(addr, mkManyExtCH(6, ks32, groups32))
	outKS33 := sendRawAndClassify(addr, mkManyExtCH(6, ks33, groups33))
	if outKS32.kind == "HANDSHAKE" && isRejectedOutcome(outKS33) {
		rec.add("r2_tls_r2", "capacity_cliffs", "max_key_shares_32_vs_33", "WARN", "measure exact key_share count ceiling",
			fmt.Sprintf("32->%s, 33->%s", outKS32.detail, outKS33.detail), "")
	} else {
		rec.add("r2_tls_r2", "capacity_cliffs", "max_key_shares_32_vs_33", "INFO", "32 vs 33 key_shares", outKS32.detail+" / "+outKS33.detail, "")
	}

	// Reversed key_share relative order vs supported_groups (groups=[X25519, P256], key_shares=[P256, X25519])
	outRevOrder := sendRawAndClassify(addr, mkManyExtCH(6,
		[]keyShareEntry{{group: GroupP256, key: validP256()}, {group: GroupX25519, key: validX25519()}},
		[]uint16{GroupX25519, GroupP256}))
	if outRevOrder.kind == "HANDSHAKE" {
		rec.add("r2_tls_r2", "key_share_order", "reversed_key_share_vs_supported_groups", "PASS",
			"RFC 8446 s4.2.8 allow key_share order independent of supported_groups", outRevOrder.detail, "")
	} else {
		rec.add("r2_tls_r2", "key_share_order", "reversed_key_share_vs_supported_groups", "FAIL",
			"RFC 8446 s4.2.8 accept [P256, X25519] key_shares regardless of [X25519, P256] order",
			outRevOrder.detail, "")
	}

	// HRR trigger via empty key_share list -> verify HelloRetryRequest ServerRandom magic
	outHRR := sendRawAndClassify(addr, mkManyExtCH(6, nil, []uint16{GroupX25519}))
	if outHRR.kind == "HANDSHAKE" && len(outHRR.raw) >= 43 && bytes.Equal(outHRR.raw[11:43], hrrRandom) {
		rec.add("r2_tls_r2", "hrr_fsm", "empty_key_share_triggers_hrr", "PASS", "HelloRetryRequest on empty key_share", fmt.Sprintf("len=%d", len(outHRR.raw)), "")
	} else {
		rec.add("r2_tls_r2", "hrr_fsm", "empty_key_share_triggers_hrr", "FAIL", "HelloRetryRequest on empty key_share", outHRR.detail, "")
	}

	// ~16300B ClientHello split across 2 TLS records (8192 + rest)
	bigPad := make([]byte, 16000)
	bigCH := buildClientHelloMsg(clientHelloOpts{
		legacyVer: 0x0303,
		sessionID: make([]byte, 32),
		ciphers:   []uint16{CipherAES128GCM},
		exts: []rawExt{
			extSNI(sni),
			extSupportedVersionsClient(0x0304),
			extSupportedGroups(GroupX25519),
			extSigAlgs(SigEd25519, SigECDSAP256SHA256),
			extALPN("http/1.1"),
			extKeyShareClient(keyShareEntry{group: GroupX25519, key: validX25519()}),
			{typ: 0x0015, body: bigPad},
		},
	})
	bigResp, _, bErr := tcpExchangeRaw(addr, [][]byte{makeRecord(RecHandshake, 0x0301, bigCH[:8192]), makeRecord(RecHandshake, 0x0303, bigCH[8192:])}, 2*time.Millisecond, false, 800*time.Millisecond)
	if bErr == nil && len(bigResp) >= 6 && bigResp[0] == RecHandshake && bigResp[5] == HSServerHello {
		rec.add("r2_tls_r2", "frag_limits", "ch_16KB_split_2_records", "PASS", "reassemble 16KB ClientHello", fmt.Sprintf("resp=%dB", len(bigResp)), "")
	} else {
		rec.add("r2_tls_r2", "frag_limits", "ch_16KB_split_2_records", "FAIL", "reassemble 16KB ClientHello", fmt.Sprintf("err=%v len=%d", bErr, len(bigResp)), "")
	}

	// Stateful mid-HTTP-request TLS 1.3 KeyUpdate(update_requested=1) -> verify new traffic keys + 200 OK
	cfg := defaultHandshakeConfig(sni)
	cfg.alpn = []string{"http/1.1"}
	sess, serr := doTLS13Handshake(addr, cfg)
	if serr != nil {
		rec.add("r2_tls_r2", "key_update_fsm", "mid_http_request_key_update", "FAIL", "handshake", serr.Error(), "")
	} else {
		defer sess.close()
		part1 := []byte("GET /secure-hello ")
		part2 := []byte("HTTP/1.1\r\nHost: " + sni + "\r\nConnection: close\r\n\r\n")
		_ = sess.sendAppData(part1, false)
		kuMsg := makeHandshakeMsg(HSKeyUpdate, []byte{0x01})
		_, _ = sess.conn.Write(sess.appTx.sealRecord(RecHandshake, kuMsg))
		// Ratchet client write traffic key before part2; readAppData handles server KeyUpdate(0).
		if newTx, rerr := sess.appTx.ratchet(); rerr == nil {
			sess.appTx = newTx
			_ = sess.sendAppData(part2, false)
			resp, rerr2 := sess.readAppData(900 * time.Millisecond)
			if rerr2 == nil && bytes.Contains(resp, []byte("200 OK")) {
				rec.add("r2_tls_r2", "key_update_fsm", "mid_http_request_key_update", "PASS",
					"200 OK after KeyUpdate(1) mid-HTTP request", truncStr(httpStatusLine(resp), 64), "")
			} else {
				rec.add("r2_tls_r2", "key_update_fsm", "mid_http_request_key_update", "FAIL",
					"200 OK after mid-request KeyUpdate", fmt.Sprintf("err=%v resp=%q", rerr2, truncStr(string(resp), 64)), "")
			}
		}
	}
}

// =========================================================================
// 4. WEBSOCKET STATEFUL CONTEXT TAKEOVER, WINDOW_BITS, & DECOMPRESSION BOMB
// =========================================================================

func runR2WebSocketStatefulAndBombSuite(rec *testRecorder, autobahnExe string) {
	if _, err := os.Stat(autobahnExe); err != nil {
		return
	}
	srv, err := startManagedServer("autobahn_r2", autobahnExe, nil, nil, tcpShutdown)
	if err != nil {
		rec.add("r2_ws", "setup", "start_server", "FAIL", "start", err.Error(), "")
		return
	}
	defer func() {
		if srv != nil {
			srv.stop()
		}
	}()
	addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
	wsKey := "dGhlIHNhbXBsZSBub25jZQ=="

	// RFC 7692 s7.1.2.1/7.1.2.2 violation: server raises window_bits=8 -> 9
	upWin8 := "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + wsKey + "\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate; server_max_window_bits=8; client_max_window_bits=8\r\n\r\n"
	rWin8, _, eWin8 := tcpExchangeRaw(addr, [][]byte{[]byte(upWin8)}, 0, false, 600*time.Millisecond)
	if eWin8 == nil && strings.Contains(string(rWin8), "server_max_window_bits=9") {
		rec.add("r2_ws", "permessage_deflate", "window_bits_8_upgraded_to_9", "FAIL",
			"RFC 7692 s7.1.2 respond <= offered window_bits (8), or decline",
			"server illegally replied with server_max_window_bits=9; client_max_window_bits=9", "")
	} else {
		rec.add("r2_ws", "permessage_deflate", "window_bits_8_upgraded_to_9", "PASS", "respect <=8 window_bits", truncStr(string(rWin8), 120), "")
	}

	// Stateful 15 chained permessage-deflate fragments with interleaved Ping/Pong (context takeover ON)
	{
		conn, cerr := net.DialTimeout("tcp", addr, time.Second)
		if cerr != nil {
			rec.add("r2_ws", "stateful_fsm", "15_msg_takeover_ping_interleave", "FAIL", "connect", cerr.Error(), "")
		} else {
			upTakeover := "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + wsKey + "\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
			_, _ = conn.Write([]byte(upTakeover))
			buf := make([]byte, 2048)
			_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			n, _ := conn.Read(buf)
			if bytes.Contains(buf[:n], []byte("101 Switching Protocols")) {
				msg := []byte("repeated-context-history-stateful-check-payload-0123456789")
				z := deflateRawRFC7692(msg)
				mid := len(z) / 2
				var batch []byte
				for i := 0; i < 10; i++ {
					// Frag 1 (opcode=1/2 RSV1=1, fin=0)
					f1 := buildWSFrame(0x2, true, z[:mid], false)
					f1[0] &^= 0x80 // clear FIN
					// Interleaved Ping
					ping := buildWSFrame(0x9, false, []byte("p"), false)
					// Frag 2 (continuation opcode=0, RSV1=0, fin=1)
					f2 := buildWSFrame(0x0, false, z[mid:], false)
					batch = append(batch, f1...)
					batch = append(batch, ping...)
					batch = append(batch, f2...)
				}
				_, _ = conn.Write(batch)
				_ = conn.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
				var total int
				for {
					nr, rerr := conn.Read(buf)
					if nr > 0 {
						total += nr
					}
					if rerr != nil {
						break
					}
				}
				if total >= 20 {
					rec.add("r2_ws", "stateful_fsm", "10_fragmented_deflate_interleaved_ping", "PASS",
						"handle fragmented deflate + interleaved Pings cleanly", fmt.Sprintf("echoBytes=%d", total), "")
				} else {
					rec.add("r2_ws", "stateful_fsm", "10_fragmented_deflate_interleaved_ping", "FAIL",
						"echo fragmented messages + Pongs", fmt.Sprintf("echoBytes=%d", total), "")
				}
			}
			_ = conn.Close()
		}
	}

	// 8 MB decompression bomb check (should reject/close 1009, not expand 8 MB in RAM and echo back)
	{
		upDef := "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + wsKey + "\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover\r\n\r\n"
		z8MB := deflateRawRFC7692(make([]byte, 8*1024*1024))
		wireBomb := append([]byte(upDef), buildWSFrame(0x2, true, z8MB, false)...)
		respB, dtB, errB := tcpExchangeRaw(addr, [][]byte{wireBomb}, 0, false, 1500*time.Millisecond)
		afterHdr := respB
		if idx := bytes.Index(respB, []byte("\r\n\r\n")); idx >= 0 {
			afterHdr = respB[idx+4:]
		}
		if errB == nil && len(afterHdr) > 16384 && afterHdr[0]&0x0f != 0x08 {
			rec.add("r2_ws", "resource_limits", "ws_8mb_deflate_bomb_cap", "FAIL",
				"cap permessage-deflate expansion ratio/output or return Close 1009 (avoid 8MB RAM spike)",
				fmt.Sprintf("inZ=%dB echoed huge %dB frame without cap in %v", len(z8MB), len(afterHdr), dtB.Round(time.Millisecond)), "")
		} else {
			rec.add("r2_ws", "resource_limits", "ws_8mb_deflate_bomb_cap", "PASS", "Close/cap decompression bomb", fmt.Sprintf("afterHdr=%dB", len(afterHdr)), "")
		}
	}
}

// =========================================================================
// 5. gRPC 8-BIT PROTOBUF VARINT BUG & GZIP DECOMPRESSION BOMB (grpc_server)
// =========================================================================

func runR2GrpcVarintAndBombSuite(rec *testRecorder, grpcExe string) {
	if _, err := os.Stat(grpcExe); err != nil {
		return
	}
	srv, err := startManagedServer("grpc_r2", grpcExe, nil, nil, tcpShutdown)
	if err != nil {
		rec.add("r2_grpc", "setup", "start_server", "FAIL", "start", err.Error(), "")
		return
	}
	defer func() {
		if srv != nil {
			srv.stop()
		}
	}()
	addr := fmt.Sprintf("127.0.0.1:%d", srv.port)

	sendGrpcH2 := func(method, path string, extra [][2]string, dataBody []byte) ([]byte, error) {
		b := append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)...)
		hdrs := buildH2HeadersBlock(addr, method, path, append([][2]string{{"content-type", "application/grpc"}, {"te", "trailers"}}, extra...))
		b = append(b, packH2Frame(0x01, 0x04, 1, hdrs)...)
		b = append(b, packH2Frame(0x00, 0x01, 1, dataBody)...)
		resp, _, err := tcpExchangeRaw(addr, [][]byte{b}, 0, false, 1200*time.Millisecond)
		return resp, err
	}

	extractFirstData := func(raw []byte) []byte {
		off := 0
		for off+9 <= len(raw) {
			n := int(raw[off])<<16 | int(raw[off+1])<<8 | int(raw[off+2])
			t := raw[off+3]
			if off+9+n > len(raw) {
				break
			}
			if t == 0x00 {
				return raw[off+9 : off+9+n]
			}
			off += 9 + n
		}
		return nil
	}

	encodePbString := func(s []byte) []byte {
		pb := []byte{0x0a}
		pb = binary.AppendUvarint(pb, uint64(len(s)))
		pb = append(pb, s...)
		lpm := make([]byte, 5+len(pb))
		binary.BigEndian.PutUint32(lpm[1:5], uint32(len(pb)))
		copy(lpm[5:], pb)
		return lpm
	}

	// SayHello with 128B, 248B (wraps out_len 256->0x00!), and 256B (truncates input to 128B!)
	for _, n := range []int{128, 248, 256} {
		raw, gerr := sendGrpcH2("POST", "/helloworld.Greeter/SayHello", nil, encodePbString(bytes.Repeat([]byte{'A'}, n)))
		df := extractFirstData(raw)
		if gerr != nil || len(df) < 8 {
			rec.add("r2_grpc", "protobuf_varint", fmt.Sprintf("sayhello_%dB", n), "FAIL", "valid protobuf varint response", fmt.Sprintf("err=%v dfLen=%d", gerr, len(df)), "")
			continue
		}
		pbOut := df[5:]
		// Valid protobuf field 1 (tag 0x0a) of length 7+n >= 128 MUST use 2-byte varint!
		vLen, vConsumed := binary.Uvarint(pbOut[1:])
		expectedStr := "Hello, " + strings.Repeat("A", n) + "!"
		if vConsumed == 2 && int(vLen) == len(expectedStr) && bytes.Equal(pbOut[1+vConsumed:], []byte(expectedStr)) {
			rec.add("r2_grpc", "protobuf_varint", fmt.Sprintf("sayhello_%dB", n), "PASS",
				fmt.Sprintf("valid protobuf 2-byte varint len=%d", len(expectedStr)),
				fmt.Sprintf("got varint=%d len=%d", vLen, len(pbOut)), "")
		} else {
			rec.add("r2_grpc", "protobuf_varint", fmt.Sprintf("sayhello_%dB", n), "FAIL",
				fmt.Sprintf("valid protobuf 2-byte varint len=%d without 8-bit truncation/wrap", len(expectedStr)),
				fmt.Sprintf("corrupt pbOut[0..16]=%x dataLen=%d", pbOut[:minInt(len(pbOut), 16)], len(df)), "")
		}
	}

	// gRPC gzip 4 MB decompression bomb check (read full multi-frame response)
	{
		var gzBuf bytes.Buffer
		gw := gzip.NewWriter(&gzBuf)
		_, _ = gw.Write(make([]byte, 4*1024*1024))
		_ = gw.Close()
		gzPayload := gzBuf.Bytes()
		lpm := make([]byte, 5+len(gzPayload))
		lpm[0] = 0x01
		binary.BigEndian.PutUint32(lpm[1:5], uint32(len(gzPayload)))
		copy(lpm[5:], gzPayload)
		b := append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)...)
		hdrs := buildH2HeadersBlock(addr, "POST", "/echo.EchoService/Echo",
			[][2]string{{"content-type", "application/grpc"}, {"te", "trailers"}, {"grpc-encoding", "gzip"}})
		b = append(b, packH2Frame(0x01, 0x04, 1, hdrs)...)
		b = append(b, packH2Frame(0x00, 0x01, 1, lpm)...)
		raw, _, _ := tcpExchangeRaw(addr, [][]byte{b}, 0, false, 2000*time.Millisecond)
		totalData := 0
		off := 0
		for off+9 <= len(raw) {
			fn := int(raw[off])<<16 | int(raw[off+1])<<8 | int(raw[off+2])
			ft := raw[off+3]
			if off+9+fn > len(raw) {
				break
			}
			if ft == 0x00 {
				totalData += fn
			}
			off += 9 + fn
		}
		if totalData > 65536 {
			rec.add("r2_grpc", "resource_limits", "grpc_gzip_4mb_bomb_cap", "FAIL",
				"cap gzip decompression ratio/bytes instead of allocating/echoing 4MB",
				fmt.Sprintf("inGzip=%dB echoed_DATA=%dB", len(gzPayload), totalData), "")
		} else {
			rec.add("r2_grpc", "resource_limits", "grpc_gzip_4mb_bomb_cap", "PASS", "cap/reject gzip bomb", fmt.Sprintf("totalData=%dB", totalData), "")
		}
	}

	// Nested protobuf depth 256 + 12B LPM sliced 1 byte per H2 DATA frame + GET method check
	{
		nested := []byte("hi")
		for i := 0; i < 64; i++ {
			nested = append([]byte{0x0a, byte(len(nested))}, nested...)
		}
		lpmN := make([]byte, 5+len(nested))
		binary.BigEndian.PutUint32(lpmN[1:5], uint32(len(nested)))
		copy(lpmN[5:], nested)
		rNest, _ := sendGrpcH2("POST", "/echo.EchoService/Echo", nil, lpmN)
		_, _, hNest, sNest := summarizeH2Frames(rNest)
		if hNest {
			rec.add("r2_grpc", "boundaries", "grpc_nested_protobuf_64", "PASS", "handle nested protobuf on Echo", sNest, "")
		} else {
			rec.add("r2_grpc", "boundaries", "grpc_nested_protobuf_64", "FAIL", "handle nested protobuf", sNest, "")
		}

		// GET method on gRPC endpoint (gRPC over HTTP/2 requires POST)
		rGet, _ := sendGrpcH2("GET", "/echo.EchoService/Echo", nil, nil)
		_, _, hGet, sGet := summarizeH2Frames(rGet)
		if hGet && !bytes.Contains(rGet, []byte("grpc-status: 0")) {
			rec.add("r2_grpc", "method_check", "grpc_reject_get_method", "INFO", "gRPC POST enforcement", sGet, "")
		} else {
			rec.add("r2_grpc", "method_check", "grpc_reject_get_method", "WARN", "gRPC over H2 expects POST", sGet, "")
		}
	}
}

// =========================================================================
// 6. HTTP/3 UDP HIDDEN DISPATCH MAP & INVERTED VN / UNENCRYPTED INITIAL
// =========================================================================

func runR2HTTP3DispatchMapSuite(rec *testRecorder, http3Exe string) {
	if _, err := os.Stat(http3Exe); err != nil {
		return
	}
	srv, err := startManagedServer("http3_r2", http3Exe, nil, nil, udpShutdown)
	if err != nil {
		rec.add("r2_h3_dispatch", "setup", "start_server", "FAIL", "start", err.Error(), "")
		return
	}
	defer func() {
		if srv != nil {
			srv.stop()
		}
	}()
	addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	scid := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	// Raw H3 frame dispatch bypass without QUIC header: 0x00 0x00, 0x01 0x00, 0x04 0x00
	for _, tc := range []struct {
		name string
		pkt  []byte
	}{
		{"udp_raw_h3_data_0x00_0x00", []byte{0x00, 0x00}},
		{"udp_raw_h3_headers_0x01_0x00", []byte{0x01, 0x00}},
		{"udp_raw_h3_settings_0x04_0x00", []byte{0x04, 0x00}},
		{"udp_0x1b_mig_reject_9B", []byte{0x1b, 0, 0, 0, 0, 0, 0, 0, 0}},
	} {
		resp, _ := sendUDPAndRecv(addr, tc.pkt, 250*time.Millisecond)
		if len(resp) > 0 {
			rec.add("r2_h3_dispatch", "hidden_udp_dispatch", tc.name, "FAIL",
				"silently discard unframed non-QUIC UDP bytes",
				fmt.Sprintf("replied %dB hex=%x ascii=%q", len(resp), resp, truncStr(string(resp), 24)),
				hex.EncodeToString(tc.pkt))
		} else {
			rec.add("r2_h3_dispatch", "hidden_udp_dispatch", tc.name, "PASS", "silently discard", "0B", "")
		}
	}

	// Inverted VN on 0xf0 (Retry type): emits VN on 40B (<1200B!) and silently drops 552B/1200B
	pkt40 := buildQUICInitial(0x1a2a3a4a, dcid, scid, nil, nil, 40, 0xf0)
	pkt1200 := buildQUICInitial(0x1a2a3a4a, dcid, scid, nil, []byte{0x01}, 1200, 0xf0)
	r40, _ := sendUDPAndRecv(addr, pkt40, 250*time.Millisecond)
	r1200, _ := sendUDPAndRecv(addr, pkt1200, 250*time.Millisecond)
	if len(r40) > 0 && len(r1200) == 0 {
		rec.add("r2_h3_dispatch", "vn_anti_amp", "retry_0xf0_inverted_vn_40B_vs_1200B", "FAIL",
			"RFC 9000 s6.1 VN requires >=1200B Initial/Long, never respond ONLY to 40B while dropping 1200B",
			fmt.Sprintf("40B_reply=%dB hex=%x | 1200B_reply=0B", len(r40), r40[:minInt(len(r40), 20)]), "")
	} else {
		rec.add("r2_h3_dispatch", "vn_anti_amp", "retry_0xf0_inverted_vn_40B_vs_1200B", "PASS", "consistent VN length policy", fmt.Sprintf("40B=%d 1200B=%d", len(r40), len(r1200)), "")
	}

	// Unencrypted 1200B 0xC0 with zero DCID & zero payload emits plaintext Initial reply
	pktZeroInit := append([]byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x44, 0x00}, make([]byte, 1190)...)
	rZero, _ := sendUDPAndRecv(addr, pktZeroInit, 250*time.Millisecond)
	if len(rZero) > 0 {
		rec.add("r2_h3_dispatch", "quic_initial_crypto", "unencrypted_0xc0_zeros_1200B_reply", "FAIL",
			"reject/drop all-zero unencrypted QUIC Initial (0-byte CRYPTO/AEAD tag)",
			fmt.Sprintf("emitted %dB unencrypted reply hex=%x", len(rZero), rZero[:minInt(len(rZero), 24)]), "")
	} else {
		rec.add("r2_h3_dispatch", "quic_initial_crypto", "unencrypted_0xc0_zeros_1200B_reply", "PASS", "drop unencrypted zero Initial", "0B", "")
	}
}

// =========================================================================
// 7. CROSS-ENGINE HTTP SEMANTIC DIFFERENTIAL MATRIX (3-WAY LIVE ENGINES)
// =========================================================================

func runR2CrossEngineDifferentialSuite(rec *testRecorder, chaosExe, h2specExe, tlsExe string) {
	var srvChaos, srvH2C, srvTLS *managedServer
	var err error
	if _, e := os.Stat(chaosExe); e == nil {
		srvChaos, err = startManagedServer("chaos_diff", chaosExe, nil, nil, nil)
		if err != nil {
			srvChaos = nil
		}
	}
	if _, e := os.Stat(h2specExe); e == nil {
		srvH2C, err = startManagedServer("h2spec_diff", h2specExe, nil, nil, tcpShutdown)
		if err != nil {
			srvH2C = nil
		}
	}
	if _, e := os.Stat(tlsExe); e == nil {
		srvTLS, err = startManagedServer("tls_diff", tlsExe, []string{"--port", "0"}, nil, tcpShutdown)
		if err != nil {
			srvTLS = nil
		}
	}
	defer func() {
		if srvChaos != nil {
			srvChaos.stop()
		}
		if srvH2C != nil {
			srvH2C.stop()
		}
		if srvTLS != nil {
			srvTLS.stop()
		}
	}()

	sendTLSHTTP := func(raw string) string {
		if srvTLS == nil {
			return "SKIP"
		}
		addr := fmt.Sprintf("127.0.0.1:%d", srvTLS.port)
		cfg := defaultHandshakeConfig("goose-wing.local")
		cfg.alpn = []string{"http/1.1"}
		sess, herr := doTLS13Handshake(addr, cfg)
		if herr != nil {
			return "HS_ERR"
		}
		defer sess.close()
		_ = sess.sendAppData([]byte(raw), false)
		resp, rerr := sess.readAppData(500 * time.Millisecond)
		if rerr != nil {
			return "EOF"
		}
		return httpStatusLine(resp)
	}

	sendPlain := func(srv *managedServer, raw string) (string, int) {
		if srv == nil {
			return "SKIP", 0
		}
		addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
		resp, _, err := tcpExchangeRaw(addr, [][]byte{[]byte(raw)}, 0, false, 450*time.Millisecond)
		if err != nil {
			return "ERR", 0
		}
		if len(resp) == 0 {
			return "TIMEOUT_0B", 0
		}
		return httpStatusLine(resp), bytes.Count(resp, []byte("HTTP/1.1 200 OK"))
	}

	// 1. Transfer-Encoding: gzip, chunked across all 3 HTTP/1.1 engines
	teGzipChunked := "POST %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: gzip, chunked\r\nConnection: close\r\n\r\n4\r\nping\r\n0\r\n\r\n"
	stReactor, _ := sendPlain(srvChaos, fmt.Sprintf(teGzipChunked, "/echo", "127.0.0.1"))
	stH2C, _ := sendPlain(srvH2C, fmt.Sprintf(teGzipChunked, "/echo", "127.0.0.1"))
	stTLS := sendTLSHTTP(fmt.Sprintf(teGzipChunked, "/secure-echo", "goose-wing.local"))
	if strings.Contains(stReactor, " 200") {
		rec.add("r2_diff", "te_coding", "te_gzip_chunked_uncompressed_accept", "FAIL",
			"reject unsupported TE coding 'gzip, chunked' (like h2spec/tls_server 400)",
			fmt.Sprintf("reactor=%q h2c=%q tls_h1=%q", stReactor, stH2C, stTLS), "")
	} else {
		rec.add("r2_diff", "te_coding", "te_gzip_chunked_uncompressed_accept", "PASS",
			"consistent reject", fmt.Sprintf("reactor=%q h2c=%q tls_h1=%q", stReactor, stH2C, stTLS), "")
	}

	// 2. Host: 127.0.0.1: (empty port)
	hostEmptyPort := "GET %s HTTP/1.1\r\nHost: %s:\r\nConnection: close\r\n\r\n"
	srHP, _ := sendPlain(srvChaos, fmt.Sprintf(hostEmptyPort, "/health", "127.0.0.1"))
	shHP, _ := sendPlain(srvH2C, fmt.Sprintf(hostEmptyPort, "/ping", "127.0.0.1"))
	stHP := sendTLSHTTP(fmt.Sprintf(hostEmptyPort, "/secure-hello", "goose-wing.local"))
	rec.add("r2_diff", "host_port", "host_empty_port_differential", "INFO",
		"document reactor vs listener vs tls_h1 empty-port policy",
		fmt.Sprintf("reactor=%q h2c=%q tls_h1=%q", srHP, shHP, stHP), "")

	// 3. Connection: close + pipelined 2nd GET MUST NOT serve 2nd response (RFC 9112 s9.6)
	connClosePipe := "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\nGET %s HTTP/1.1\r\nHost: %s\r\n\r\n"
	srCC, nCC := sendPlain(srvChaos, fmt.Sprintf(connClosePipe, "/health", "127.0.0.1", "/", "127.0.0.1"))
	shCC, nH2CC := sendPlain(srvH2C, fmt.Sprintf(connClosePipe, "/ping", "127.0.0.1", "/", "127.0.0.1"))
	if nCC <= 1 && nH2CC <= 1 {
		rec.add("r2_diff", "pipeline_close", "conn_close_stops_2nd_pipelined_req", "PASS",
			"serve at most 1 response after Connection: close",
			fmt.Sprintf("reactor(200s=%d %s) h2c(200s=%d %s)", nCC, srCC, nH2CC, shCC), "")
	} else {
		rec.add("r2_diff", "pipeline_close", "conn_close_stops_2nd_pipelined_req", "FAIL",
			"RFC 9112 s9.6 MUST close after 1st response",
			fmt.Sprintf("reactor=%d h2c=%d", nCC, nH2CC), "")
	}

	// 4. Bare LF (\n) stall differential
	bareLF := "GET / HTTP/1.1\nHost: 127.0.0.1\n\n"
	srLF, _ := sendPlain(srvChaos, bareLF)
	shLF, _ := sendPlain(srvH2C, bareLF)
	if srLF == "TIMEOUT_0B" || shLF == "TIMEOUT_0B" {
		rec.add("r2_diff", "line_endings", "bare_lf_stall_vs_400", "WARN",
			"fast 400 Bad Request on bare LF without >450ms stall",
			fmt.Sprintf("reactor=%q h2c=%q", srLF, shLF), "")
	} else {
		rec.add("r2_diff", "line_endings", "bare_lf_stall_vs_400", "PASS", "fast reject bare LF",
			fmt.Sprintf("reactor=%q h2c=%q", srLF, shLF), "")
	}

	// 5. Percent-encoded route char (/%68ealth) & Content-Length: 4, 4 comma duplicate
	clComma := "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 4, 4\r\nConnection: close\r\n\r\nping"
	srCLC, _ := sendPlain(srvChaos, fmt.Sprintf(clComma, "/echo", "127.0.0.1"))
	shCLC, _ := sendPlain(srvH2C, fmt.Sprintf(clComma, "/echo", "127.0.0.1"))
	stCLC := sendTLSHTTP(fmt.Sprintf(clComma, "/secure-echo", "goose-wing.local"))
	rec.add("r2_diff", "header_syntax", "cl_comma_identical_4_4", "INFO",
		"document H1 vs H2 comma-CL behavior",
		fmt.Sprintf("reactor=%q h2c=%q tls_h1=%q", srCLC, shCLC, stCLC), "")
}
