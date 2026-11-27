// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// runWave3AuditSuite executes Track 1 Wave 3 black-box security conformance suites
// across HeaderMap/Bloom, Router/PathNorm, Timer/Backpressure, HTTP Cache/Dates/X.509,
// TLS/H2 parity, QUIC/H3 transport, and CLI black-box safety.
// Returns the number of recorded FAIL cases.
func runWave3AuditSuite(pki *testPKI) int {
	rec := &testRecorder{}
	binDir := filepath.Join(repoRoot, "tools", "bin")

	chaosExe := exePath(binDir, "chaos_server")
	h2specExe := exePath(binDir, "h2spec_server")
	smugH1Exe := exePath(binDir, "smuggling_wing_h1")
	cacheExe := exePath(binDir, "cache_harness")
	x509Exe := exePath(binDir, "x509_harness")
	tlsServerExe := exePath(binDir, "tls_server")
	bogoExe := exePath(binDir, "bogo_shim")
	tlsClientExe := exePath(binDir, "tls_client")
	http3Exe := exePath(binDir, "http3_server")
	quicEndpointExe := exePath(binDir, "quic_interop_endpoint")

	runW3HeaderMapBloomSuite(rec, chaosExe, smugH1Exe, h2specExe)
	runW3RouterPathNormSuite(rec, chaosExe, smugH1Exe, h2specExe)
	runW3TimerBackpressureSuite(rec, chaosExe, h2specExe)
	runW3HTTPCacheDatesX509Suite(rec, cacheExe, x509Exe, chaosExe, smugH1Exe, h2specExe, pki)
	runW3TLSH2ParitySuite(rec, tlsServerExe, bogoExe, tlsClientExe, h2specExe, pki)
	runW3QUICH3TransportSuite(rec, http3Exe, quicEndpointExe)
	runW3CLIBlackboxSuite(rec)

	fmt.Println("\n==================== WAVE 3 AUDIT SUMMARY ====================")
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
	fmt.Printf("\nWAVE 3 TOTALS -> FAIL=%d | WARN=%d | INFO=%d\n", len(fails), len(warns), len(infos))
	if len(fails) > 0 {
		fmt.Println("\n--- WAVE 3 FAILURES ---")
		for _, f := range fails {
			fmt.Printf("  [FAIL] %s/%s/%s\n         exp: %s\n         got: %s\n",
				f.suite, f.category, f.name, f.expected, f.observed)
			if f.wireHex != "" {
				fmt.Printf("         hex: %s\n", f.wireHex)
			}
		}
	}
	if len(warns) > 0 {
		fmt.Println("\n--- WAVE 3 WARNINGS ---")
		for _, w := range warns {
			fmt.Printf("  [WARN] %s/%s/%s | exp=%s | got=%s\n", w.suite, w.category, w.name, w.expected, w.observed)
		}
	}
	if len(infos) > 0 {
		fmt.Println("\n--- WAVE 3 INFO ---")
		for _, in := range infos {
			fmt.Printf("  [INFO] %s/%s/%s | exp=%s | got=%s\n", in.suite, in.category, in.name, in.expected, in.observed)
		}
	}
	if logDir != "" {
		logPath := filepath.Join(logDir, "wave3_results.log")
		_ = os.WriteFile(logPath, []byte(logBuf.String()), 0600)
		fmt.Printf("\n[+] Wave 3 wire log written to %s\n", logPath)
	}
	return len(fails)
}

// --- Shared Wave 3 helpers ---

func w3StatusCode(resp []byte) string {
	sl := httpStatusLine(resp)
	parts := strings.SplitN(sl, " ", 3)
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

func w3HasOpenRedirectLocation(resp []byte) (string, bool) {
	hdrBlock, _, _ := bytes.Cut(resp, []byte("\r\n\r\n"))
	for line := range strings.SplitSeq(string(hdrBlock), "\r\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), "Location") {
			val := strings.TrimSpace(v)
			low := strings.ToLower(val)
			if strings.Contains(low, "evil.com") || strings.Contains(low, "attacker.example") || strings.HasPrefix(val, "//") {
				return val, true
			}
		}
	}
	return "", false
}

func w3HpackInt(firstByteMask byte, prefixBits int, val int) []byte {
	maxPrefix := (1 << prefixBits) - 1
	if val < maxPrefix {
		return []byte{firstByteMask | byte(val)}
	}
	out := []byte{firstByteMask | byte(maxPrefix)}
	val -= maxPrefix
	for val >= 128 {
		out = append(out, byte((val&0x7f)|0x80))
		val >>= 7
	}
	out = append(out, byte(val))
	return out
}

func w3HpackLitLong(name, val string) []byte {
	var b []byte
	b = append(b, 0x00)
	b = append(b, w3HpackInt(0x00, 7, len(name))...)
	b = append(b, name...)
	b = append(b, w3HpackInt(0x00, 7, len(val))...)
	b = append(b, val...)
	return b
}

func w3PackH2HeadersAndCont(streamID uint32, endStream bool, hpackBlock []byte) []byte {
	const maxFrame = 16384
	if len(hpackBlock) <= maxFrame {
		fl := byte(0x04) // END_HEADERS
		if endStream {
			fl |= 0x01
		}
		return packH2Frame(0x01, fl, streamID, hpackBlock)
	}
	var out []byte
	flFirst := byte(0x00)
	if endStream {
		flFirst |= 0x01
	}
	out = append(out, packH2Frame(0x01, flFirst, streamID, hpackBlock[:maxFrame])...)
	for off := maxFrame; off < len(hpackBlock); off += maxFrame {
		end := min(off+maxFrame, len(hpackBlock))
		fl := byte(0x00)
		if end == len(hpackBlock) {
			fl = 0x04 // END_HEADERS
		}
		out = append(out, packH2Frame(0x09, fl, streamID, hpackBlock[off:end])...)
	}
	return out
}

func w3RunSmugH1Batch(exe string, vecs map[string][]byte) (map[string][]string, error) {
	tsvPath := filepath.Join(scratchDir, fmt.Sprintf("w3_smug_%d.tsv", time.Now().UnixNano()))
	var sb strings.Builder
	for name, raw := range vecs {
		sb.WriteString(name)
		sb.WriteByte('\t')
		sb.WriteString(hex.EncodeToString(raw))
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(tsvPath, []byte(sb.String()), 0600); err != nil {
		return nil, err
	}
	defer os.Remove(tsvPath)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, exe, tsvPath).CombinedOutput()
	res := map[string][]string{}
	for line := range strings.SplitSeq(string(out), "\n") {
		cols := strings.Split(strings.TrimSpace(line), "\t")
		if len(cols) >= 2 {
			res[cols[0]] = cols
		}
	}
	if len(res) == 0 && err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return res, nil
}

// =========================================================================
// SUITE 1: W3_HeaderMap_Bloom
// =========================================================================

func runW3HeaderMapBloomSuite(rec *testRecorder, chaosExe, smugH1Exe, h2specExe string) {
	const suite = "W3_HeaderMap_Bloom"
	fmt.Printf("\n================ %s ================\n", suite)

	buildH1HeadersReq := func(path string, totalCount int, adversarial bool) []byte {
		var sb strings.Builder
		sb.WriteString("GET ")
		sb.WriteString(path)
		sb.WriteString(" HTTP/1.1\r\nHost: 127.0.0.1\r\n")
		extra := max(totalCount-2, 0) // Host + Connection = 2
		for i := range extra {
			if adversarial {
				switch i % 4 {
				case 0:
					fmt.Fprintf(&sb, "X-Bloom-%03d: v%d\r\n", i, i)
				case 1:
					fmt.Fprintf(&sb, "x-bloom-%03d-alt: v%d\r\n", i, i)
				case 2:
					fmt.Fprintf(&sb, "X-AaBbCc-%03d: v%d\r\n", i, i)
				default:
					fmt.Fprintf(&sb, "X-Hdr-Spray-%03d: v%d\r\n", i, i)
				}
			} else {
				fmt.Fprintf(&sb, "X-Hdr-%03d: v%d\r\n", i, i)
			}
		}
		sb.WriteString("Connection: close\r\n\r\n")
		return []byte(sb.String())
	}

	buildH2HeadersReq := func(path string, totalCount int, adversarial bool) []byte {
		hb := buildH2HeadersBlock("127.0.0.1", "GET", path, nil)
		for i := range totalCount {
			var name string
			if adversarial {
				if i%2 == 0 {
					name = fmt.Sprintf("x-bloom-%03d", i)
				} else {
					name = fmt.Sprintf("x-spray-alt-%03d", i)
				}
			} else {
				name = fmt.Sprintf("x-hdr-%03d", i)
			}
			hb = append(hb, w3HpackLitLong(name, "v1")...)
		}
		return append(append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)...), w3PackH2HeadersAndCont(1, true, hb)...)
	}

	counts := []int{64, 100, 128, 256, 512}

	// 1A. Live chaos_server.exe (H1 reactor)
	if _, err := os.Stat(chaosExe); err != nil {
		rec.add(suite, "setup", "chaos_server_present", "INFO", "skip if unbuilt", err.Error(), "")
	} else {
		srv, err := startManagedServer("w3_chaos_hm", chaosExe, nil, nil, nil)
		if err != nil {
			rec.add(suite, "setup", "chaos_server_start", "FAIL", "start", err.Error(), "")
		} else {
			defer func() {
				if srv != nil {
					srv.stop()
				}
			}()
			canary := "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
			for _, adv := range []bool{false, true} {
				mode := "distinct"
				if adv {
					mode = "adversarial"
				}
				for _, n := range counts {
					if srv == nil {
						break
					}
					addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
					req := buildH1HeadersReq("/health", n, adv)
					resp, dt, rerr := tcpExchangeRaw(addr, [][]byte{req}, 0, false, 1200*time.Millisecond)
					sc := w3StatusCode(resp)
					name := fmt.Sprintf("chaos_h1_%s_%d", mode, n)
					st := "PASS"
					exp := "200 or 400/431"
					if n == 64 {
						exp = "200 OK"
						if rerr != nil || sc != "200" {
							st = "FAIL"
						}
					} else if n >= 256 {
						exp = "reject (400/431/close, NOT 200)"
						if rerr == nil && sc == "200" {
							st = "FAIL"
						} else if strings.HasPrefix(sc, "5") {
							st = "FAIL"
						}
					} else {
						if rerr != nil || (sc != "200" && sc != "400" && sc != "431") {
							st = "FAIL"
						}
					}
					rec.add(suite, "header_count", name, st, exp, fmt.Sprintf("status=%q err=%v dt=%v", httpStatusLine(resp), rerr, dt.Round(time.Millisecond)), "")
					checkOrRestartHTTP(rec, suite, name, &srv, chaosExe, nil, nil, nil, canary, "200 OK")
				}
			}

			// Decoded header size limit enforcement on chaos_server
			sizeCases := []struct {
				name string
				req  []byte
			}{
				{"chaos_h1_val_8193B", []byte("GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Big: " + strings.Repeat("A", 8193) + "\r\nConnection: close\r\n\r\n")},
				{"chaos_h1_val_16385B", []byte("GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Big: " + strings.Repeat("B", 16385) + "\r\nConnection: close\r\n\r\n")},
				{"chaos_h1_block_24KB", func() []byte {
					var sb strings.Builder
					sb.WriteString("GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n")
					for i := range 16 {
						fmt.Fprintf(&sb, "X-Blk-%02d: %s\r\n", i, strings.Repeat("C", 1500))
					}
					sb.WriteString("Connection: close\r\n\r\n")
					return []byte(sb.String())
				}()},
			}
			for _, scase := range sizeCases {
				if srv == nil {
					break
				}
				addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
				resp, _, rerr := tcpExchangeRaw(addr, [][]byte{scase.req}, 0, false, 1200*time.Millisecond)
				sc := w3StatusCode(resp)
				st := "PASS"
				if rerr == nil && (sc == "200" || strings.HasPrefix(sc, "5")) {
					st = "FAIL"
				}
				rec.add(suite, "size_limit", scase.name, st, "reject oversize header (400/431/close, NOT 200)", fmt.Sprintf("status=%q err=%v", httpStatusLine(resp), rerr), "")
				checkOrRestartHTTP(rec, suite, scase.name, &srv, chaosExe, nil, nil, nil, canary, "200 OK")
			}

			// Latency amplification ratio: 512 vs 16 headers
			if srv != nil {
				addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
				req16 := buildH1HeadersReq("/health", 16, false)
				req512 := buildH1HeadersReq("/health", 512, true)
				const iters = 15
				t0 := time.Now()
				for range iters {
					_, _, _ = tcpExchangeRaw(addr, [][]byte{req16}, 0, false, 800*time.Millisecond)
				}
				d16 := time.Since(t0) / iters
				t1 := time.Now()
				for range iters {
					_, _, _ = tcpExchangeRaw(addr, [][]byte{req512}, 0, false, 800*time.Millisecond)
				}
				d512 := time.Since(t1) / iters
				ratio := float64(d512) / float64(max(d16, time.Microsecond))
				st := "PASS"
				if d512 > 150*time.Millisecond {
					st = "FAIL"
				} else if ratio > 25.0 {
					st = "WARN"
				}
				rec.add(suite, "latency_amp", "chaos_h1_512_vs_16", st, "bounded latency (avg512 < 150ms, ratio <= 25x)",
					fmt.Sprintf("avg16=%v avg512=%v ratio=%.2fx", d16.Round(time.Microsecond), d512.Round(time.Microsecond), ratio), "")
				checkOrRestartHTTP(rec, suite, "chaos_latency_amp", &srv, chaosExe, nil, nil, nil, canary, "200 OK")
			}
		}
	}

	// 1B. Offline smuggling_wing_h1.exe
	if _, err := os.Stat(smugH1Exe); err != nil {
		rec.add(suite, "setup", "smuggling_wing_h1_present", "INFO", "skip if unbuilt", err.Error(), "")
	} else {
		vecs := map[string][]byte{
			"hdr_16KB_val": []byte("GET / HTTP/1.1\r\nHost: a.com\r\nX-Big: " + strings.Repeat("Z", 16385) + "\r\n\r\n"),
			"hdr_block_24KB": func() []byte {
				var sb strings.Builder
				sb.WriteString("GET / HTTP/1.1\r\nHost: a.com\r\n")
				for i := range 16 {
					fmt.Fprintf(&sb, "X-Blk-%02d: %s\r\n", i, strings.Repeat("Y", 1500))
				}
				sb.WriteString("\r\n")
				return []byte(sb.String())
			}(),
		}
		for _, n := range counts {
			vecs[fmt.Sprintf("distinct_%d", n)] = buildH1HeadersReq("/", n, false)
			vecs[fmt.Sprintf("adv_%d", n)] = buildH1HeadersReq("/", n, true)
		}
		res, err := w3RunSmugH1Batch(smugH1Exe, vecs)
		if err != nil {
			rec.add(suite, "smug_h1", "batch_run", "FAIL", "run smuggling_wing_h1", err.Error(), "")
		} else {
			for _, mode := range []string{"distinct", "adv"} {
				for _, n := range counts {
					k := fmt.Sprintf("%s_%d", mode, n)
					cols := res[k]
					if len(cols) < 2 {
						rec.add(suite, "smug_h1", k, "FAIL", "output line", "missing", "")
						continue
					}
					verdict := cols[1]
					st := "PASS"
					exp := "ACCEPT or REJECT*"
					if n == 64 {
						exp = "ACCEPT"
						if verdict != "ACCEPT" {
							st = "FAIL"
						}
					} else if n >= 256 {
						exp = "REJECT* (>100..128 header limit)"
						if !strings.HasPrefix(verdict, "REJECT") {
							st = "FAIL"
						}
					}
					rec.add(suite, "smug_h1", k, st, exp, strings.Join(cols, "\t"), "")
				}
			}
			for _, sk := range []string{"hdr_16KB_val", "hdr_block_24KB"} {
				cols := res[sk]
				st := "PASS"
				if len(cols) < 2 || !strings.HasPrefix(cols[1], "REJECT") {
					st = "FAIL"
				}
				rec.add(suite, "smug_h1", sk, st, "REJECT* oversize header", strings.Join(cols, "\t"), "")
			}
		}
	}

	// 1C. Live h2spec_server.exe (H1 and H2)
	if _, err := os.Stat(h2specExe); err != nil {
		rec.add(suite, "setup", "h2spec_server_present", "INFO", "skip if unbuilt", err.Error(), "")
	} else {
		srv, err := startManagedServer("w3_h2spec_hm", h2specExe, nil, nil, tcpShutdown)
		if err != nil {
			rec.add(suite, "setup", "h2spec_server_start", "FAIL", "start", err.Error(), "")
		} else {
			defer func() {
				if srv != nil {
					srv.stop()
				}
			}()
			canary := "GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"

			// H1 count sweep on h2spec_server
			for _, n := range counts {
				if srv == nil {
					break
				}
				addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
				resp, dt, rerr := tcpExchangeRaw(addr, [][]byte{buildH1HeadersReq("/ping", n, true)}, 0, false, 1200*time.Millisecond)
				sc := w3StatusCode(resp)
				name := fmt.Sprintf("h2spec_h1_adv_%d", n)
				st := "PASS"
				exp := "200 or 400/431"
				if n == 64 {
					exp = "200 OK"
					if rerr != nil || sc != "200" {
						st = "FAIL"
					}
				} else if n >= 256 {
					exp = "reject (400/431/close, NOT 200)"
					if rerr == nil && sc == "200" {
						st = "FAIL"
					}
				}
				rec.add(suite, "h2spec_h1", name, st, exp, fmt.Sprintf("status=%q err=%v dt=%v", httpStatusLine(resp), rerr, dt.Round(time.Millisecond)), "")
				checkOrRestartHTTP(rec, suite, name, &srv, h2specExe, nil, nil, tcpShutdown, canary, "200 OK")
			}

			// H2 count sweep on h2spec_server
			for _, adv := range []bool{false, true} {
				mode := "distinct"
				if adv {
					mode = "adversarial"
				}
				for _, n := range counts {
					if srv == nil {
						break
					}
					addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
					pkt := buildH2HeadersReq("/ping", n, adv)
					resp, dt, rerr := tcpExchangeRaw(addr, [][]byte{pkt}, 0, false, 1200*time.Millisecond)
					ga, rst, hdrs, sum := summarizeH2Frames(resp)
					name := fmt.Sprintf("h2spec_h2_%s_%d", mode, n)
					st := "PASS"
					exp := "HEADERS or GOAWAY/RST"
					if n == 64 {
						exp = "200 HEADERS without GOAWAY/RST"
						if rerr != nil || ga || rst || !hdrs {
							st = "FAIL"
						}
					} else if n >= 256 {
						exp = "reject (>100..128 header limit: GOAWAY/RST/close without HEADERS)"
						if !ga && !rst && hdrs {
							st = "FAIL"
						}
					}
					rec.add(suite, "h2spec_h2", name, st, exp, fmt.Sprintf("frames=[%s] err=%v dt=%v", sum, rerr, dt.Round(time.Millisecond)), "")
					checkOrRestartHTTP(rec, suite, name, &srv, h2specExe, nil, nil, tcpShutdown, canary, "200 OK")
				}
			}

			// H2 decoded header size limit enforcement (16385B value and 24KB block)
			for _, sz := range []struct {
				name  string
				count int
				vlen  int
			}{
				{"h2spec_h2_val_16385B", 1, 16385},
				{"h2spec_h2_block_24KB", 16, 1500},
			} {
				if srv == nil {
					break
				}
				addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
				hb := buildH2HeadersBlock("127.0.0.1", "GET", "/ping", nil)
				for i := range sz.count {
					hb = append(hb, w3HpackLitLong(fmt.Sprintf("x-big-%02d", i), strings.Repeat("D", sz.vlen))...)
				}
				pkt := append(append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)...), w3PackH2HeadersAndCont(1, true, hb)...)
				resp, _, rerr := tcpExchangeRaw(addr, [][]byte{pkt}, 0, false, 1200*time.Millisecond)
				ga, rst, hdrs, sum := summarizeH2Frames(resp)
				st := "PASS"
				if !ga && !rst && hdrs && rerr == nil {
					st = "FAIL"
				}
				rec.add(suite, "size_limit", sz.name, st, "reject oversize decoded headers (GOAWAY/RST/close)", fmt.Sprintf("frames=[%s] err=%v", sum, rerr), "")
				checkOrRestartHTTP(rec, suite, sz.name, &srv, h2specExe, nil, nil, tcpShutdown, canary, "200 OK")
			}

			// Latency amplification ratio on h2spec_server H2 (512 vs 16)
			if srv != nil {
				addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
				p16 := buildH2HeadersReq("/ping", 16, false)
				p512 := buildH2HeadersReq("/ping", 512, true)
				const iters = 15
				t0 := time.Now()
				for range iters {
					_, _, _ = tcpExchangeRaw(addr, [][]byte{p16}, 0, false, 800*time.Millisecond)
				}
				d16 := time.Since(t0) / iters
				t1 := time.Now()
				for range iters {
					_, _, _ = tcpExchangeRaw(addr, [][]byte{p512}, 0, false, 800*time.Millisecond)
				}
				d512 := time.Since(t1) / iters
				ratio := float64(d512) / float64(max(d16, time.Microsecond))
				st := "PASS"
				if d512 > 150*time.Millisecond {
					st = "FAIL"
				} else if ratio > 25.0 {
					st = "WARN"
				}
				rec.add(suite, "latency_amp", "h2spec_h2_512_vs_16", st, "bounded latency (avg512 < 150ms, ratio <= 25x)",
					fmt.Sprintf("avg16=%v avg512=%v ratio=%.2fx", d16.Round(time.Microsecond), d512.Round(time.Microsecond), ratio), "")
			}
		}
	}
}

// =========================================================================
// SUITE 2: W3_Router_PathNorm
// =========================================================================

func runW3RouterPathNormSuite(rec *testRecorder, chaosExe, smugH1Exe, h2specExe string) {
	const suite = "W3_Router_PathNorm"
	fmt.Printf("\n================ %s ================\n", suite)

	type pathVec struct {
		name     string
		method   string
		target   string
		extraHdr string
		mustRej  bool // expect 400/404/405/508/501 (not 200)
		smugRej  bool // expect smuggling_wing_h1 REJECT
	}

	vecs := []pathVec{
		{"double_slash_health", "GET", "//health", "", false, false},
		{"pct_dotdot_health", "GET", "/%2e%2e/health", "", false, false},
		{"trailing_pct2f", "GET", "/health%2F", "", true, false},
		{"trailing_pct5c", "GET", "/health%5C", "", true, false},
		{"raw_backslash", "GET", `/health\`, "", true, true},
		{"semicolon_param", "GET", "/health;a=1", "", true, false},
		{"pct3b_param", "GET", "/health%3Ba=1", "", true, false},
		{"pct09_open_redirect", "GET", "/%09/attacker.example/x/", "", true, false},
		{"dotdot_double_slash_evil", "GET", "/..//evil.com", "", true, false},
		{"dot_double_slash_evil", "GET", "/.//evil.com", "", true, false},
		{"bad_percent_pctZZ", "GET", "/%ZZ", "", true, true},
		{"trailing_slash_health", "GET", "/health/", "", false, false},
		{"ctl_nul_in_target", "GET", "/health\x00x", "", true, true},
		{"ctl_tab_in_target", "GET", "/health\x09x", "", true, true},
		{"ctl_us_0x1f_in_target", "GET", "/health\x1fx", "", true, true},
		{"ctl_del_0x7f_in_target", "GET", "/health\x7fx", "", true, true},
		{"trace_root", "TRACE", "/", "", true, false},
		{"trace_max_forwards_0", "TRACE", "/", "Max-Forwards: 0\r\n", true, false},
		{"options_max_forwards_0", "OPTIONS", "/", "Max-Forwards: 0\r\n", false, false},
		{"via_loop_probe", "GET", "/health", "Via: 1.1 a, 1.1 wing, 1.1 b, 1.1 wing, 1.1 c\r\n", false, false},
		{"hop_by_hop_conn_smuggle", "GET", "/health", "Connection: close, X-Forwarded-For, Client-Cert\r\nX-Forwarded-For: 127.0.0.1\r\nClient-Cert: evil\r\n", false, false},
	}

	buildH1 := func(v pathVec, defaultPath string) []byte {
		t := v.target
		if defaultPath != "" && strings.Contains(t, "/health") {
			t = strings.ReplaceAll(t, "/health", defaultPath)
		}
		return []byte(v.method + " " + t + " HTTP/1.1\r\nHost: 127.0.0.1\r\n" + v.extraHdr + "Connection: close\r\n\r\n")
	}

	evalH1Live := func(engineName string, addr string, v pathVec, defaultPath string) {
		resp, _, err := tcpExchangeRaw(addr, [][]byte{buildH1(v, defaultPath)}, 0, false, 800*time.Millisecond)
		if err != nil {
			rec.add(suite, engineName, v.name, "FAIL", "clean HTTP response", "err="+err.Error(), "")
			return
		}
		sc := w3StatusCode(resp)
		loc, hasOpenRedir := w3HasOpenRedirectLocation(resp)
		if hasOpenRedir {
			rec.add(suite, engineName, v.name, "FAIL", "no open redirect Location", fmt.Sprintf("status=%s Location=%q", sc, loc), "")
			return
		}
		if strings.HasPrefix(sc, "5") && sc != "501" && sc != "508" {
			rec.add(suite, engineName, v.name, "FAIL", "no 500/502/503 error", httpStatusLine(resp), "")
			return
		}
		if v.mustRej {
			if sc == "400" || sc == "404" || sc == "405" || sc == "501" || sc == "508" {
				rec.add(suite, engineName, v.name, "PASS", "400/404/405/508 rejection", httpStatusLine(resp), "")
			} else if sc == "" && len(resp) == 0 {
				rec.add(suite, engineName, v.name, "WARN", "400/404/405/508 rejection", "empty EOF (no status line)", "")
			} else {
				rec.add(suite, engineName, v.name, "FAIL", "400/404/405/508 rejection (not "+sc+")", httpStatusLine(resp), "")
			}
			return
		}
		if v.name == "via_loop_probe" {
			rec.add(suite, engineName, v.name, "PASS", "200/400/508 without crash", httpStatusLine(resp), "")
			return
		}
		if v.name == "hop_by_hop_conn_smuggle" {
			if bytes.Contains(resp, []byte("evil")) {
				rec.add(suite, engineName, v.name, "FAIL", "do not reflect smuggled Client-Cert", truncStr(string(resp), 100), "")
			} else {
				rec.add(suite, engineName, v.name, "PASS", "clean response without Client-Cert leak", httpStatusLine(resp), "")
			}
			return
		}
		rec.add(suite, engineName, v.name, "PASS", "200/204/400/404/405 without crash", httpStatusLine(resp), "")
	}

	// 2A. chaos_server.exe
	if _, err := os.Stat(chaosExe); err == nil {
		srv, err := startManagedServer("w3_chaos_router", chaosExe, nil, nil, nil)
		if err != nil {
			rec.add(suite, "chaos", "start_server", "FAIL", "start", err.Error(), "")
		} else {
			defer func() {
				if srv != nil {
					srv.stop()
				}
			}()
			canary := "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
			for _, v := range vecs {
				if srv == nil {
					break
				}
				evalH1Live("chaos_h1", fmt.Sprintf("127.0.0.1:%d", srv.port), v, "")
				checkOrRestartHTTP(rec, suite, "chaos_"+v.name, &srv, chaosExe, nil, nil, nil, canary, "200 OK")
			}
		}
	}

	// 2B. h2spec_server.exe (H1 and H2)
	if _, err := os.Stat(h2specExe); err == nil {
		srv, err := startManagedServer("w3_h2spec_router", h2specExe, nil, nil, tcpShutdown)
		if err != nil {
			rec.add(suite, "h2spec", "start_server", "FAIL", "start", err.Error(), "")
		} else {
			defer func() {
				if srv != nil {
					srv.stop()
				}
			}()
			canary := "GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
			for _, v := range vecs {
				if srv == nil {
					break
				}
				evalH1Live("h2spec_h1", fmt.Sprintf("127.0.0.1:%d", srv.port), v, "/ping")
				checkOrRestartHTTP(rec, suite, "h2spec_h1_"+v.name, &srv, h2specExe, nil, nil, tcpShutdown, canary, "200 OK")
			}

			// Also probe path divergence vectors over HTTP/2 :path on h2spec_server
			for _, v := range vecs {
				if srv == nil {
					break
				}
				if v.name == "hop_by_hop_conn_smuggle" {
					continue // Connection header is forbidden by H2 RFC 9113 (tested in R1)
				}
				t := strings.ReplaceAll(v.target, "/health", "/ping")
				var extra [][2]string
				if v.name == "trace_max_forwards_0" || v.name == "options_max_forwards_0" {
					extra = append(extra, [2]string{"max-forwards", "0"})
				}
				if v.name == "via_loop_probe" {
					extra = append(extra, [2]string{"via", "1.1 a, 1.1 wing, 1.1 b"})
				}
				hb := buildH2HeadersBlock("127.0.0.1", v.method, t, extra)
				pkt := append(append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)...), packH2Frame(0x01, 0x05, 1, hb)...)
				resp, _, rerr := tcpExchangeRaw(fmt.Sprintf("127.0.0.1:%d", srv.port), [][]byte{pkt}, 0, false, 800*time.Millisecond)
				ga, rst, hdrs, sum := summarizeH2Frames(resp)
				if bytes.Contains(bytes.ToLower(resp), []byte("evil.com")) || bytes.Contains(bytes.ToLower(resp), []byte("attacker.example")) {
					rec.add(suite, "h2spec_h2", v.name, "FAIL", "no open redirect payload in H2 reply", sum, "")
				} else if strings.HasPrefix(v.name, "ctl_") {
					st := "PASS"
					if !ga && !rst && hdrs && rerr == nil {
						st = "FAIL"
					}
					rec.add(suite, "h2spec_h2", v.name, st, "reject control char in H2 :path (GOAWAY/RST)", sum, "")
				} else {
					rec.add(suite, "h2spec_h2", v.name, "PASS", "handled cleanly without crash/redirect", fmt.Sprintf("frames=[%s] err=%v", sum, rerr), "")
				}
				checkOrRestartHTTP(rec, suite, "h2spec_h2_"+v.name, &srv, h2specExe, nil, nil, tcpShutdown, canary, "200 OK")
			}
		}
	}

	// 2C. smuggling_wing_h1.exe
	if _, err := os.Stat(smugH1Exe); err == nil {
		sVecs := map[string][]byte{}
		for _, v := range vecs {
			sVecs[v.name] = buildH1(v, "")
		}
		res, err := w3RunSmugH1Batch(smugH1Exe, sVecs)
		if err != nil {
			rec.add(suite, "smug_h1", "batch_run", "FAIL", "run", err.Error(), "")
		} else {
			for _, v := range vecs {
				cols := res[v.name]
				if len(cols) < 2 {
					rec.add(suite, "smug_h1", v.name, "FAIL", "harness output", "missing", "")
					continue
				}
				verdict := cols[1]
				st := "PASS"
				exp := "ACCEPT or REJECT cleanly"
				if v.smugRej {
					exp = "REJECT (invalid syntax/CTL/backslash/%ZZ)"
					if verdict != "REJECT" {
						st = "FAIL"
					}
				}
				rec.add(suite, "smug_h1", v.name, st, exp, strings.Join(cols, "\t"), "")
			}
		}
	}
}

// =========================================================================
// SUITE 3: W3_Timer_Backpressure
// =========================================================================

func runW3TimerBackpressureSuite(rec *testRecorder, chaosExe, h2specExe string) {
	const suite = "W3_Timer_Backpressure"
	fmt.Printf("\n================ %s ================\n", suite)

	send1Byte := func(addr string, data []byte, readWait time.Duration) ([]byte, time.Duration, error) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			return nil, 0, err
		}
		defer conn.Close()
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		t0 := time.Now()
		for i := range data {
			if _, werr := conn.Write(data[i : i+1]); werr != nil {
				return nil, time.Since(t0), werr
			}
		}
		_ = conn.SetReadDeadline(time.Now().Add(readWait))
		var out bytes.Buffer
		buf := make([]byte, 4096)
		for {
			n, rerr := conn.Read(buf)
			if n > 0 {
				out.Write(buf[:n])
				_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			}
			if rerr != nil {
				break
			}
		}
		return out.Bytes(), time.Since(t0), nil
	}

	testH1Timers := func(tag string, srv **managedServer, exe string, shutdownFn func(int), path string) {
		if *srv == nil {
			return
		}
		canary := "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"

		// 1. 1-byte TCP fragmentation of H1 request line + headers
		{
			addr := fmt.Sprintf("127.0.0.1:%d", (*srv).port)
			req := []byte("GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Frag: one-byte\r\nConnection: close\r\n\r\n")
			resp, dt, rerr := send1Byte(addr, req, 1500*time.Millisecond)
			st := "PASS"
			if rerr != nil || w3StatusCode(resp) != "200" {
				st = "FAIL"
			}
			rec.add(suite, tag, "1byte_frag_h1", st, "200 OK", fmt.Sprintf("sl=%q dt=%v err=%v", httpStatusLine(resp), dt.Round(time.Millisecond), rerr), "")
			checkOrRestartHTTP(rec, suite, tag+"_1byte_h1", srv, exe, nil, nil, shutdownFn, canary, "200 OK")
		}

		// 2. Half-closed TCP client: post-request CloseWrite()
		if *srv != nil {
			addr := fmt.Sprintf("127.0.0.1:%d", (*srv).port)
			resp, dt, rerr := tcpExchangeRaw(addr, [][]byte{[]byte(canary)}, 0, true, 1200*time.Millisecond)
			st := "PASS"
			if rerr != nil || w3StatusCode(resp) != "200" {
				st = "FAIL"
			}
			rec.add(suite, tag, "halfclose_post_request", st, "200 OK without hang", fmt.Sprintf("sl=%q dt=%v err=%v", httpStatusLine(resp), dt.Round(time.Millisecond), rerr), "")
		}

		// 3. Half-closed TCP client: mid-request CloseWrite()
		if *srv != nil {
			addr := fmt.Sprintf("127.0.0.1:%d", (*srv).port)
			partial := []byte("GET " + path + " HTTP/1.1\r\nHost: 127.")
			resp, dt, rerr := tcpExchangeRaw(addr, [][]byte{partial}, 0, true, 1500*time.Millisecond)
			st := "PASS"
			if rerr != nil || dt > 1400*time.Millisecond {
				st = "FAIL"
			}
			rec.add(suite, tag, "halfclose_mid_request", st, "prompt release (<1.4s)", fmt.Sprintf("len=%d sl=%q dt=%v err=%v", len(resp), httpStatusLine(resp), dt.Round(time.Millisecond), rerr), "")
			checkOrRestartHTTP(rec, suite, tag+"_halfclose_mid", srv, exe, nil, nil, shutdownFn, canary, "200 OK")
		}

		// 4. Slow-read / small receive buffer stall + concurrent healthy client
		if *srv != nil {
			addr := fmt.Sprintf("127.0.0.1:%d", (*srv).port)
			var stalled []net.Conn
			bigBody := strings.Repeat("S", 32768)
			echoReq := fmt.Sprintf("POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: %d\r\n\r\n%s", len(bigBody), bigBody)
			for range 8 {
				c, cerr := net.DialTimeout("tcp", addr, time.Second)
				if cerr == nil {
					if tc, ok := c.(*net.TCPConn); ok {
						_ = tc.SetReadBuffer(1024)
					}
					_, _ = c.Write([]byte(echoReq))
					stalled = append(stalled, c)
				}
			}
			respH, dtH, errH := tcpExchangeRaw(addr, [][]byte{[]byte(canary)}, 0, false, 1000*time.Millisecond)
			for _, c := range stalled {
				_ = c.Close()
			}
			st := "PASS"
			if errH != nil || w3StatusCode(respH) != "200" || dtH > 700*time.Millisecond {
				st = "FAIL"
			}
			rec.add(suite, tag, "slow_read_stall_isolation", st, "healthy client 200 OK <700ms despite 8 stalled readers",
				fmt.Sprintf("sl=%q dt=%v stalled=%d err=%v", httpStatusLine(respH), dtH.Round(time.Millisecond), len(stalled), errH), "")
			checkOrRestartHTTP(rec, suite, tag+"_slowread", srv, exe, nil, nil, shutdownFn, canary, "200 OK")
		}
	}

	if _, err := os.Stat(chaosExe); err == nil {
		srvC, err := startManagedServer("w3_chaos_timer", chaosExe, nil, nil, nil)
		if err != nil {
			rec.add(suite, "chaos", "start_server", "FAIL", "start", err.Error(), "")
		} else {
			defer func() {
				if srvC != nil {
					srvC.stop()
				}
			}()
			testH1Timers("chaos_h1", &srvC, chaosExe, nil, "/health")
		}
	}

	if _, err := os.Stat(h2specExe); err == nil {
		srvH, err := startManagedServer("w3_h2spec_timer", h2specExe, nil, nil, tcpShutdown)
		if err != nil {
			rec.add(suite, "h2spec", "start_server", "FAIL", "start", err.Error(), "")
		} else {
			defer func() {
				if srvH != nil {
					srvH.stop()
				}
			}()
			testH1Timers("h2spec_h1", &srvH, h2specExe, tcpShutdown, "/ping")
			canaryH1 := "GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"

			// 5. H2 1-byte TCP fragmentation (preface + SETTINGS + HEADERS)
			if srvH != nil {
				addr := fmt.Sprintf("127.0.0.1:%d", srvH.port)
				pkt := append(append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)...),
					packH2Frame(0x01, 0x05, 1, buildH2HeadersBlock("127.0.0.1", "GET", "/ping", nil))...)
				resp, dt, rerr := send1Byte(addr, pkt, 1500*time.Millisecond)
				ga, rst, hdrs, sum := summarizeH2Frames(resp)
				st := "PASS"
				if rerr != nil || ga || rst || !hdrs {
					st = "FAIL"
				}
				rec.add(suite, "h2spec_h2", "1byte_frag_h2_preface_headers", st, "200 HEADERS without GOAWAY/hang",
					fmt.Sprintf("frames=[%s] dt=%v err=%v", sum, dt.Round(time.Millisecond), rerr), "")
				checkOrRestartHTTP(rec, suite, "h2_1byte", &srvH, h2specExe, nil, nil, tcpShutdown, canaryH1, "200 OK")
			}

			// 6. H2 mid-frame CloseWrite()
			if srvH != nil {
				addr := fmt.Sprintf("127.0.0.1:%d", srvH.port)
				partial := append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)...)
				partial = append(partial, 0x00, 0x00, 0x20, 0x01) // truncated 4B of 9B HEADERS header
				resp, dt, rerr := tcpExchangeRaw(addr, [][]byte{partial}, 0, true, 1500*time.Millisecond)
				st := "PASS"
				if rerr != nil || dt > 1400*time.Millisecond {
					st = "FAIL"
				}
				rec.add(suite, "h2spec_h2", "halfclose_mid_h2_frame", st, "prompt release (<1.4s)",
					fmt.Sprintf("len=%d dt=%v err=%v", len(resp), dt.Round(time.Millisecond), rerr), "")
				checkOrRestartHTTP(rec, suite, "h2_halfclose", &srvH, h2specExe, nil, nil, tcpShutdown, canaryH1, "200 OK")
			}

			// 7. H2 flow-control backpressure isolation: stall Stream 1 while Streams 3..9 complete
			if srvH != nil {
				addr := fmt.Sprintf("127.0.0.1:%d", srvH.port)
				conn, derr := net.DialTimeout("tcp", addr, 2*time.Second)
				if derr != nil {
					rec.add(suite, "h2spec_h2", "flow_control_stream_isolation", "FAIL", "connect", derr.Error(), "")
				} else {
					// Set INITIAL_WINDOW_SIZE = 1 so Stream 1 echo response stalls after 1 byte unless WINDOW_UPDATE sent!
					var pkt []byte
					pkt = append(pkt, h2Preface...)
					pkt = append(pkt, packH2Frame(0x04, 0x00, 0, []byte{0x00, 0x04, 0x00, 0x00, 0x00, 0x01})...)
					pkt = append(pkt, packH2Frame(0x04, 0x01, 0, nil)...)
					// Stream 1: POST /echo with 4096B body (leave stalled at 1B window)
					pkt = append(pkt, packH2Frame(0x01, 0x04, 1, buildH2HeadersBlock("127.0.0.1", "POST", "/echo", nil))...)
					pkt = append(pkt, packH2Frame(0x00, 0x01, 1, bytes.Repeat([]byte{'X'}, 4096))...)
					// Streams 3, 5, 7, 9: GET /ping
					hbPing := buildH2HeadersBlock("127.0.0.1", "GET", "/ping", nil)
					for _, sid := range []uint32{3, 5, 7, 9} {
						pkt = append(pkt, packH2Frame(0x01, 0x05, sid, hbPing)...)
					}
					_, _ = conn.Write(pkt)

					var raw []byte
					buf := make([]byte, 8192)
					deadline := time.Now().Add(1200 * time.Millisecond)
					for time.Now().Before(deadline) {
						_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
						n, rerr := conn.Read(buf)
						if n > 0 {
							raw = append(raw, buf[:n]...)
						}
						if rerr != nil {
							if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
								if bytes.Contains(raw, []byte{0x01}) && len(raw) > 80 {
									continue
								}
							}
							break
						}
					}
					_ = conn.Close()

					// Count distinct stream IDs that got HEADERS frames
					hdrStreams := map[uint32]bool{}
					off := 0
					for off+9 <= len(raw) {
						fn := int(raw[off])<<16 | int(raw[off+1])<<8 | int(raw[off+2])
						ft := raw[off+3]
						sid := binary.BigEndian.Uint32(raw[off+5:off+9]) & 0x7fffffff
						if off+9+fn > len(raw) {
							break
						}
						if ft == 0x01 {
							hdrStreams[sid] = true
						}
						off += 9 + fn
					}
					st := "PASS"
					if !hdrStreams[3] || !hdrStreams[5] || !hdrStreams[7] || !hdrStreams[9] {
						st = "FAIL"
					}
					_, _, _, sum := summarizeH2Frames(raw)
					rec.add(suite, "h2spec_h2", "flow_control_stream_isolation", st,
						"streams 3,5,7,9 receive HEADERS despite stalled stream 1",
						fmt.Sprintf("hdrStreams=%v summary=%s", hdrStreams, truncStr(sum, 120)), "")
					checkOrRestartHTTP(rec, suite, "h2_flow_iso", &srvH, h2specExe, nil, nil, tcpShutdown, canaryH1, "200 OK")
				}
			}

			// 8a. Rapid Reset burst (100x HEADERS + RST_STREAM)
			if srvH != nil {
				addr := fmt.Sprintf("127.0.0.1:%d", srvH.port)
				hb := buildH2HeadersBlock("127.0.0.1", "GET", "/ping", nil)
				var burst []byte
				burst = append(burst, h2Preface...)
				burst = append(burst, packH2Frame(0x04, 0x00, 0, nil)...)
				for i := range 100 {
					sid := uint32(1 + i*2)
					burst = append(burst, packH2Frame(0x01, 0x04, sid, hb)...)
					burst = append(burst, packH2Frame(0x03, 0x00, sid, []byte{0, 0, 0, 8})...) // CANCEL
				}
				resp, dt, rerr := tcpExchangeRaw(addr, [][]byte{burst}, 0, false, 1500*time.Millisecond)
				ga, _, _, sum := summarizeH2Frames(resp)
				// Verify server stays alive to subsequent healthy H2 client
				h2Canary, _, h2CErr := tcpExchangeRaw(addr, [][]byte{append(append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)...), packH2Frame(0x01, 0x05, 1, hb)...)}, 0, false, 800*time.Millisecond)
				_, _, cHdrs, _ := summarizeH2Frames(h2Canary)
				st := "PASS"
				if h2CErr != nil || !cHdrs {
					st = "FAIL"
				}
				rec.add(suite, "h2spec_h2", "rapid_reset_100_burst", st, "GOAWAY/ratelimit or survive + healthy followup",
					fmt.Sprintf("goaway=%v dt=%v err=%v followupOK=%v sum=%s", ga, dt.Round(time.Millisecond), rerr, cHdrs, truncStr(sum, 80)), "")
				checkOrRestartHTTP(rec, suite, "h2_rapid_reset", &srvH, h2specExe, nil, nil, tcpShutdown, canaryH1, "200 OK")
			}

			// 8b. MadeYouReset burst (50x HEADERS + malformed WINDOW_UPDATE=0 on each stream)
			if srvH != nil {
				addr := fmt.Sprintf("127.0.0.1:%d", srvH.port)
				hb := buildH2HeadersBlock("127.0.0.1", "GET", "/ping", nil)
				var burst []byte
				burst = append(burst, h2Preface...)
				burst = append(burst, packH2Frame(0x04, 0x00, 0, nil)...)
				for i := range 50 {
					sid := uint32(1 + i*2)
					burst = append(burst, packH2Frame(0x01, 0x04, sid, hb)...)
					burst = append(burst, packH2Frame(0x08, 0x00, sid, []byte{0, 0, 0, 0})...)
				}
				resp, dt, rerr := tcpExchangeRaw(addr, [][]byte{burst}, 0, false, 1500*time.Millisecond)
				ga, _, _, sum := summarizeH2Frames(resp)
				h2Canary, _, h2CErr := tcpExchangeRaw(addr, [][]byte{append(append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)...), packH2Frame(0x01, 0x05, 1, hb)...)}, 0, false, 800*time.Millisecond)
				_, _, cHdrs, _ := summarizeH2Frames(h2Canary)
				st := "PASS"
				if h2CErr != nil || !cHdrs {
					st = "FAIL"
				}
				rec.add(suite, "h2spec_h2", "madeyoureset_50_burst", st, "GOAWAY/ratelimit or survive + healthy followup",
					fmt.Sprintf("goaway=%v dt=%v err=%v followupOK=%v sum=%s", ga, dt.Round(time.Millisecond), rerr, cHdrs, truncStr(sum, 80)), "")
				checkOrRestartHTTP(rec, suite, "h2_madeyoureset", &srvH, h2specExe, nil, nil, tcpShutdown, canaryH1, "200 OK")
			}
		}
	}
}

// =========================================================================
// SUITE 4: W3_HTTP_Cache_Dates_X509
// =========================================================================

func runW3HTTPCacheDatesX509Suite(rec *testRecorder, cacheExe, x509Exe, chaosExe, smugH1Exe, h2specExe string, pki *testPKI) {
	const suite = "W3_HTTP_Cache_Dates_X509"
	fmt.Printf("\n================ %s ================\n", suite)

	// 4A. cache_harness.exe TSV suite
	if _, err := os.Stat(cacheExe); err != nil {
		rec.add(suite, "cache", "binary_present", "INFO", "skip if unbuilt", err.Error(), "")
	} else {
		hHex := func(s string) string {
			if s == "" {
				return ""
			}
			return hex.EncodeToString([]byte(s))
		}
		var tsv strings.Builder
		addStep := func(id string, nowSec int64, method, url, reqHdrs string, status int, respHdrs, body string) {
			fmt.Fprintf(&tsv, "STEP\t%s\t%d\t%s\t%s\t%s\t%d\t%s\t%s\n",
				id, nowSec, method, url, hHex(reqHdrs), status, hHex(respHdrs), hHex(body))
		}

		// 1. RFC 9875 Cache-Groups cross-origin isolation
		tsv.WriteString("CASE\tcg_xorigin\tSHARED\t1024\n")
		addStep("store_a", 1767225600, "GET", "http://origin-a.example/item", "", 200, "Cache-Control: max-age=120\r\nCache-Groups: \"g1\"\r\n", "okA")
		addStep("inv_b", 1767225605, "POST", "http://origin-b.example/act", "", 200, "Cache-Group-Invalidation: \"g1\"\r\n", "okB")
		addStep("check_a", 1767225610, "GET", "http://origin-a.example/item", "", 200, "", "")

		// 2. RFC 9875 Cache-Group-Invalidation ignored on safe GET/HEAD/OPTIONS
		tsv.WriteString("CASE\tcg_safe_methods\tSHARED\t1024\n")
		addStep("store", 1767225600, "GET", "http://origin-a.example/item", "", 200, "Cache-Control: max-age=120\r\nCache-Groups: \"g1\"\r\n", "ok")
		addStep("safe_get", 1767225602, "GET", "http://origin-a.example/other", "", 200, "Cache-Group-Invalidation: \"g1\"\r\n", "g")
		addStep("after_get", 1767225603, "GET", "http://origin-a.example/item", "", 200, "", "")
		addStep("safe_head", 1767225604, "HEAD", "http://origin-a.example/other", "", 200, "Cache-Group-Invalidation: \"g1\"\r\n", "")
		addStep("after_head", 1767225605, "GET", "http://origin-a.example/item", "", 200, "", "")
		addStep("safe_opt", 1767225606, "OPTIONS", "http://origin-a.example/other", "", 200, "Cache-Group-Invalidation: \"g1\"\r\n", "")
		addStep("after_opt", 1767225607, "GET", "http://origin-a.example/item", "", 200, "", "")

		// 3. RFC 9875 non-cascading invalidation
		tsv.WriteString("CASE\tcg_noncascade\tSHARED\t1024\n")
		addStep("s_r1", 1767225600, "GET", "http://origin-a.example/r1", "", 200, "Cache-Control: max-age=120\r\nCache-Groups: \"g1\", \"g2\"\r\n", "r1")
		addStep("s_r2", 1767225601, "GET", "http://origin-a.example/r2", "", 200, "Cache-Control: max-age=120\r\nCache-Groups: \"g2\"\r\n", "r2")
		addStep("inv_g1", 1767225605, "POST", "http://origin-a.example/act", "", 200, "Cache-Group-Invalidation: \"g1\"\r\n", "act")
		addStep("chk_r1", 1767225606, "GET", "http://origin-a.example/r1", "", 200, "", "")
		addStep("chk_r2", 1767225607, "GET", "http://origin-a.example/r2", "", 200, "", "")

		// 4. RFC 9875 >32 groups limit (40 groups)
		var g40 []string
		for i := 1; i <= 40; i++ {
			g40 = append(g40, fmt.Sprintf("\"g%02d\"", i))
		}
		tsv.WriteString("CASE\tcg_gt32\tSHARED\t1024\n")
		addStep("store40", 1767225600, "GET", "http://origin-a.example/r40", "", 200, "Cache-Control: max-age=120\r\nCache-Groups: "+strings.Join(g40, ", ")+"\r\n", "r40")
		addStep("inv_g40", 1767225605, "POST", "http://origin-a.example/act", "", 200, "Cache-Group-Invalidation: \"g40\"\r\n", "act")
		addStep("chk_r40", 1767225606, "GET", "http://origin-a.example/r40", "", 200, "", "")

		// 5. Weak ETag W/"v1" in If-Range vs If-None-Match
		tsv.WriteString("CASE\tweak_etag\tSHARED\t1024\n")
		addStep("store_w", 1767225600, "GET", "http://origin-a.example/w", "", 200, "Cache-Control: max-age=120\r\nETag: W/\"v1\"\r\n", "abcd")
		addStep("if_range_w", 1767225605, "GET", "http://origin-a.example/w", "Range: bytes=0-1\r\nIf-Range: W/\"v1\"\r\n", 200, "", "")
		addStep("inm_w", 1767225606, "GET", "http://origin-a.example/w", "If-None-Match: W/\"v1\"\r\n", 200, "", "")

		// 6. RFC 850 2-digit year dates (Saturday, 01-Jan-50 00:00:01 GMT) at 2026 (2050=future -> HIT) vs Sunday, 01-Jan-50 at 1990 (1950=past -> MISS/REVALIDATE)
		tsv.WriteString("CASE\trfc850_2026\tSHARED\t1024\n")
		addStep("store_50", 1767225600, "GET", "http://origin-a.example/d50", "", 200, "Date: Thu, 01 Jan 2026 00:00:00 GMT\r\nExpires: Saturday, 01-Jan-50 00:00:01 GMT\r\n", "ok50")
		addStep("chk_50", 1767225610, "GET", "http://origin-a.example/d50", "", 200, "", "")

		tsv.WriteString("CASE\trfc850_bad_wday_2026\tSHARED\t1024\n")
		addStep("store_50_sun", 1767225600, "GET", "http://origin-a.example/d50s", "", 200, "Date: Thu, 01 Jan 2026 00:00:00 GMT\r\nExpires: Sunday, 01-Jan-50 00:00:01 GMT\r\n", "ok50s")
		addStep("chk_50_sun", 1767225610, "GET", "http://origin-a.example/d50s", "", 200, "", "")

		tsv.WriteString("CASE\trfc850_1990\tSHARED\t1024\n")
		addStep("store_50_1990", 631152000, "GET", "http://origin-a.example/d50b", "", 200, "Date: Mon, 01 Jan 1990 00:00:00 GMT\r\nExpires: Sunday, 01-Jan-50 00:00:01 GMT\r\n", "ok50b")
		addStep("chk_50_1990", 631152010, "GET", "http://origin-a.example/d50b", "", 200, "", "")

		// 7. Invalid calendar dates & leap second in Expires (no Cache-Control -> invalid Expires MUST be expired -> MISS!)
		tsv.WriteString("CASE\tbad_feb29\tSHARED\t1024\n")
		addStep("s_feb29", 1767225600, "GET", "http://origin-a.example/f29", "", 200, "Date: Thu, 01 Jan 2026 00:00:00 GMT\r\nExpires: Sun, 29 Feb 2026 00:00:00 GMT\r\n", "f29")
		addStep("c_feb29", 1767225605, "GET", "http://origin-a.example/f29", "", 200, "", "")

		tsv.WriteString("CASE\tbad_apr31\tSHARED\t1024\n")
		addStep("s_apr31", 1767225600, "GET", "http://origin-a.example/a31", "", 200, "Date: Thu, 01 Jan 2026 00:00:00 GMT\r\nExpires: Thu, 31 Apr 2026 00:00:00 GMT\r\n", "a31")
		addStep("c_apr31", 1767225605, "GET", "http://origin-a.example/a31", "", 200, "", "")

		tsv.WriteString("CASE\tleap_sec\tSHARED\t1024\n")
		addStep("s_leap", 1767225590, "GET", "http://origin-a.example/leap", "", 200, "Date: Wed, 31 Dec 2025 23:59:50 GMT\r\nExpires: Wed, 31 Dec 2025 23:59:60 GMT\r\n", "ls")
		addStep("c_leap", 1767225595, "GET", "http://origin-a.example/leap", "", 200, "", "")

		// 8. Proxy header hygiene in cache_harness
		tsv.WriteString("CASE\tproxy_hyg\tSHARED\t1024\n")
		addStep("s_hyg", 1767225600, "GET", "http://origin-a.example/hyg", "Connection: X-Forwarded-For, Client-Cert\r\nX-Forwarded-For: 1.2.3.4\r\nClient-Cert: evil\r\n", 200, "Cache-Control: max-age=60\r\nConnection: X-Forwarded-For, Client-Cert\r\nX-Forwarded-For: 1.2.3.4\r\nClient-Cert: evil\r\n", "hyg")
		addStep("c_hyg", 1767225605, "GET", "http://origin-a.example/hyg", "", 200, "", "")

		tsvPath := filepath.Join(scratchDir, "w3_cache.tsv")
		_ = os.WriteFile(tsvPath, []byte(tsv.String()), 0600)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		outBytes, runErr := exec.CommandContext(ctx, cacheExe, tsvPath).CombinedOutput()
		cancel()
		_ = os.Remove(tsvPath)

		if runErr != nil && len(outBytes) == 0 {
			rec.add(suite, "cache", "run_harness", "FAIL", "execute cache_harness", runErr.Error(), "")
		} else {
			results := map[string][]string{}
			for line := range strings.SplitSeq(string(outBytes), "\n") {
				cols := strings.Split(strings.TrimSpace(line), "\t")
				if len(cols) >= 7 && cols[0] == "RESULT" {
					results[cols[1]+"/"+cols[2]] = cols
				}
			}
			checkCache := func(key, wantHitMiss, wantStatus, expNote string, infoOnly bool) {
				cols := results[key]
				if len(cols) < 7 {
					rec.add(suite, "cache", key, "FAIL", expNote, "missing RESULT line", "")
					return
				}
				gotHM := cols[3]
				gotSt := cols[6]
				st := "PASS"
				if infoOnly {
					st = "INFO"
				} else if wantHitMiss == "NOT_HIT" {
					if gotHM == "HIT" || (wantStatus != "" && gotSt != wantStatus) {
						st = "FAIL"
					}
				} else if (wantHitMiss != "" && gotHM != wantHitMiss) || (wantStatus != "" && gotSt != wantStatus) {
					st = "FAIL"
				}
				rec.add(suite, "cache", key, st, expNote, fmt.Sprintf("%s %s status=%s age=%s", cols[3], cols[4], cols[6], cols[8]), "")
			}

			checkCache("cg_xorigin/check_a", "HIT", "200", "RFC 9875 cross-origin Cache-Group-Invalidation must NOT evict origin-a (HIT)", false)
			checkCache("cg_safe_methods/after_get", "HIT", "200", "RFC 9875 ignore invalidation on GET (HIT)", false)
			checkCache("cg_safe_methods/after_head", "HIT", "200", "RFC 9875 ignore invalidation on HEAD (HIT)", false)
			checkCache("cg_safe_methods/after_opt", "HIT", "200", "RFC 9875 ignore invalidation on OPTIONS (HIT)", false)
			checkCache("cg_noncascade/chk_r1", "MISS", "200", "r1 in g1 evicted (MISS)", false)
			checkCache("cg_noncascade/chk_r2", "HIT", "200", "RFC 9875 non-cascading: r2 in g2 NOT evicted (HIT)", false)
			checkCache("cg_gt32/chk_r40", "", "200", "observe >32 groups limit (capped at 32 -> HIT, >32 -> MISS)", true)

			// If-Range weak ETag MUST NOT return 206 Partial Content
			if cols := results["weak_etag/if_range_w"]; len(cols) >= 7 {
				st := "PASS"
				if cols[6] == "206" {
					st = "FAIL"
				}
				rec.add(suite, "cache", "weak_etag/if_range_w", st, "RFC 9110 s13.1.5 weak ETag in If-Range must NOT return 206", strings.Join(cols, "|"), "")
			}
			checkCache("weak_etag/inm_w", "", "", "weak ETag in If-None-Match handled cleanly", true)

			checkCache("rfc850_2026/chk_50", "HIT", "200", "RFC 9110 s5.6.7 RFC 850 Saturday 01-Jan-50 at 2026 -> 2050 (HIT)", false)
			checkCache("rfc850_bad_wday_2026/chk_50_sun", "NOT_HIT", "200", "RFC 9110 s5.6.7 Sunday 01-Jan-50 invalid weekday for 2050 (not HIT)", false)
			checkCache("rfc850_1990/chk_50_1990", "NOT_HIT", "200", "RFC 9110 s5.6.7 RFC 850 year 50 at 1990 -> 1950 expired (MISS/REVALIDATE)", false)
			checkCache("bad_feb29/c_feb29", "NOT_HIT", "200", "RFC 9111 invalid 29 Feb 2026 Expires treated as expired (MISS/REVALIDATE)", false)
			checkCache("bad_apr31/c_apr31", "NOT_HIT", "200", "RFC 9111 invalid 31 Apr 2026 Expires treated as expired (MISS/REVALIDATE)", false)
			checkCache("leap_sec/c_leap", "", "200", "leap second 23:59:60 handled cleanly without crash", true)
			checkCache("proxy_hyg/c_hyg", "HIT", "200", "hop-by-hop Connection: X-Forwarded-For, Client-Cert handled cleanly", false)
		}
	}

	// 4B. x509_harness.exe dates, NUL, NameConstraints, DigestAlgorithm trailing elements
	if _, err := os.Stat(x509Exe); err != nil {
		rec.add(suite, "x509", "binary_present", "INFO", "skip if unbuilt", err.Error(), "")
	} else {
		h, err := startLineHarness(x509Exe)
		if err != nil {
			rec.add(suite, "x509", "start_harness", "FAIL", "start", err.Error(), "")
		} else {
			defer h.close()
			oidEcdsaSha256 := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}

			// Helper to rebuild TBS replacing validity field (5th element inside TBS SEQUENCE: [0]ver, serial, sigAlg, issuer, validity, ...)
			replaceValidity := func(certDER []byte, nbTag byte, nbVal []byte, naTag byte, naVal []byte, signer *ecdsa.PrivateKey) []byte {
				tbs, _, _, _ := extractCertParts(certDER)
				var tbsSeq asn1.RawValue
				_, _ = asn1.Unmarshal(tbs, &tbsSeq)
				rest := tbsSeq.Bytes
				var elems []asn1.RawValue
				for len(rest) > 0 {
					var el asn1.RawValue
					var uerr error
					rest, uerr = asn1.Unmarshal(rest, &el)
					if uerr != nil {
						break
					}
					elems = append(elems, el)
				}
				if len(elems) < 7 {
					return nil
				}
				newVal := derSeq(append(derTLV(nbTag, nbVal), derTLV(naTag, naVal)...))
				var newBody []byte
				for i, el := range elems {
					if i == 4 {
						newBody = append(newBody, newVal...)
					} else {
						newBody = append(newBody, el.FullBytes...)
					}
				}
				return signDERCertWithCA(derSeq(newBody), oidEcdsaSha256, signer, 0, nil, "")
			}

			// Create a long-lived Root CA (NotBefore=2025-01-01 UTCTime, NotAfter=9999-12-31 GeneralizedTime)
			longCAKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			longCATmpl := &x509.Certificate{
				SerialNumber:          big.NewInt(9001),
				Subject:               pkix.Name{CommonName: "Wave3 LongLived Root CA"},
				NotBefore:             time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:              time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC),
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
				BasicConstraintsValid: true,
				IsCA:                  true,
			}
			longCADER0, _ := x509.CreateCertificate(rand.Reader, longCATmpl, longCATmpl, &longCAKey.PublicKey, longCAKey)
			longCADER := replaceValidity(longCADER0, 0x17, []byte("250101000000Z"), 0x18, []byte("99991231235959Z"), longCAKey)
			longCACert, _ := x509.ParseCertificate(longCADER)
			longCAHex := hex.EncodeToString(longCADER)

			baseLeafTmpl := func(serial int64, dns string) *x509.Certificate {
				return &x509.Certificate{
					SerialNumber:          big.NewInt(serial),
					Subject:               pkix.Name{CommonName: dns},
					NotBefore:             time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
					NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
					KeyUsage:              x509.KeyUsageDigitalSignature,
					ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
					BasicConstraintsValid: true,
					DNSNames:              []string{dns},
				}
			}
			makeLeafValidity := func(serial int64, nbTag byte, nbVal []byte, naTag byte, naVal []byte) []byte {
				d0, _ := x509.CreateCertificate(rand.Reader, baseLeafTmpl(serial, "time.example"), longCACert, &pki.ecKey.PublicKey, longCAKey)
				return replaceValidity(d0, nbTag, nbVal, naTag, naVal, longCAKey)
			}

			verifyAt := func(name string, nowUnix int64, leaf []byte, inters [][]byte, caHex string, peer string, wantOK bool, infoOnly bool, note string) {
				interHex := "-"
				if len(inters) > 0 {
					var ps []string
					for _, in := range inters {
						ps = append(ps, hex.EncodeToString(in))
					}
					interHex = strings.Join(ps, ",")
				}
				cols, cerr := h.call("VERIFY", name, "BUILD", "SERVER", fmt.Sprintf("%d", nowUnix), peer, hex.EncodeToString(leaf), interHex, caHex, "-1")
				if cerr != nil {
					rec.add(suite, "x509", name, "FAIL", note, "harness err: "+cerr.Error(), "")
					return
				}
				gotOK := len(cols) >= 4 && cols[0] == "VERDICT" && cols[2] == "OK"
				reason := strings.Join(cols, "|")
				if len(cols) >= 4 {
					reason = cols[2] + "(" + cols[3] + ")"
				}
				st := "PASS"
				if infoOnly {
					st = "INFO"
				} else if gotOK != wantOK {
					st = "FAIL"
				}
				rec.add(suite, "x509", name, st, note, reason, "")
			}

			// 1. Y2038 UTCTime (2039-01-01 & 2049-12-31)
			t2038 := time.Date(2038, 6, 1, 0, 0, 0, 0, time.UTC).Unix()
			t2049 := time.Date(2049, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
			t2050 := time.Date(2050, 6, 1, 0, 0, 0, 0, time.UTC).Unix()
			t2026 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).Unix()

			verifyAt("y2038_utctime_2039_01_01", t2038,
				makeLeafValidity(9101, 0x17, []byte("250101000000Z"), 0x17, []byte("390101000000Z")),
				nil, longCAHex, "time.example", true, false, "Y2038 UTCTime 390101000000Z valid at 2038-06-01")
			verifyAt("y2049_utctime_2049_12_31", t2049,
				makeLeafValidity(9102, 0x17, []byte("250101000000Z"), 0x17, []byte("491231235959Z")),
				nil, longCAHex, "time.example", true, false, "UTCTime 491231235959Z valid at 2049-01-01")

			// 2. Post-2050 GeneralizedTime (2051-01-01 & 99991231235959Z)
			verifyAt("post2050_gen_2051_01_01", t2050,
				makeLeafValidity(9103, 0x17, []byte("250101000000Z"), 0x18, []byte("20510101000000Z")),
				nil, longCAHex, "time.example", true, false, "GeneralizedTime 20510101000000Z valid at 2050-06-01")
			verifyAt("post2050_gen_99991231", t2050,
				makeLeafValidity(9104, 0x17, []byte("250101000000Z"), 0x18, []byte("99991231235959Z")),
				nil, longCAHex, "time.example", true, false, "GeneralizedTime 99991231235959Z valid at 2050-06-01")

			// 3. Fractional seconds .123Z in GeneralizedTime (RFC 5280 s4.1.2.5.2 forbids)
			verifyAt("gen_fractional_seconds_dot123Z", t2026,
				makeLeafValidity(9105, 0x17, []byte("250101000000Z"), 0x18, []byte("20510101000000.123Z")),
				nil, longCAHex, "time.example", false, false, "RFC 5280 forbid fractional seconds .123Z in GeneralizedTime")

			// 4. Non-Z offset +0000
			verifyAt("gen_non_z_plus0000", t2026,
				makeLeafValidity(9106, 0x17, []byte("250101000000Z"), 0x18, []byte("20510101000000+0000")),
				nil, longCAHex, "time.example", false, false, "RFC 5280 forbid +0000 offset in GeneralizedTime")
			verifyAt("utc_non_z_plus0000", t2026,
				makeLeafValidity(9107, 0x17, []byte("250101000000Z"), 0x17, []byte("390101000000+0000")),
				nil, longCAHex, "time.example", false, false, "RFC 5280 forbid +0000 offset in UTCTime")

			// 5. UTCTime >=2050 (500101000000Z == 1950, expired in 2026) and GeneralizedTime <2050 (RFC 5280 s4.1.2.5)
			verifyAt("utctime_year50_means_1950", t2026,
				makeLeafValidity(9108, 0x17, []byte("250101000000Z"), 0x17, []byte("500101000000Z")),
				nil, longCAHex, "time.example", false, false, "RFC 5280 UTCTime 50 == 1950 (must reject at 2026)")
			verifyAt("generalizedtime_pre2050_2026", t2026,
				makeLeafValidity(9109, 0x18, []byte("20250101000000Z"), 0x18, []byte("20300101000000Z")),
				nil, longCAHex, "time.example", false, false, "RFC 5280 s4.1.2.5 MUST use UTCTime for years < 2050")

			// 6. Invalid calendar 2026-02-29 & leap second :60
			verifyAt("invalid_cal_utc_260229", t2026,
				makeLeafValidity(9110, 0x17, []byte("250101000000Z"), 0x17, []byte("260229000000Z")),
				nil, longCAHex, "time.example", false, false, "reject invalid calendar date 2026-02-29 (UTCTime)")
			verifyAt("invalid_cal_gen_20510229", t2026,
				makeLeafValidity(9111, 0x17, []byte("250101000000Z"), 0x18, []byte("20510229000000Z")),
				nil, longCAHex, "time.example", false, false, "reject invalid calendar date 2051-02-29 (GeneralizedTime)")
			verifyAt("leap_second_60_utc", t2026,
				makeLeafValidity(9112, 0x17, []byte("250101000000Z"), 0x17, []byte("260101235960Z")),
				nil, longCAHex, "time.example", false, false, "reject :60 leap second in ASN.1 time")

			// 7. Embedded NUL in DNS SAN (example.com\x00.evil.com)
			{
				sanNul := derSeq(derTLV(0x82, []byte("example.com\x00.evil.com")))
				tmpl := &x509.Certificate{
					SerialNumber: big.NewInt(9113), Subject: pkix.Name{CommonName: "example.com"},
					NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
					KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
					BasicConstraintsValid: true,
					ExtraExtensions:       []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: sanNul}},
				}
				d, _ := x509.CreateCertificate(rand.Reader, tmpl, pki.caCert, &pki.ecKey.PublicKey, pki.caKey)
				verifyAt("san_nul_example_com", time.Now().UTC().Unix(), d, nil, hex.EncodeToString(pki.caDER), "example.com", false, false, "reject NUL byte in DNS SAN")
			}

			// 8. NameConstraints bypass: Subject CN=evil.example + iPAddress / registeredID SAN under excluded evil.example
			{
				now := time.Now().UTC()
				icKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				icTmpl := &x509.Certificate{
					SerialNumber: big.NewInt(9120), Subject: pkix.Name{CommonName: "W3 NC Excl CA"},
					NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
					KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
					ExcludedDNSDomains: []string{"evil.example"},
				}
				icDER, _ := x509.CreateCertificate(rand.Reader, icTmpl, pki.caCert, &icKey.PublicKey, pki.caKey)
				icCert, _ := x509.ParseCertificate(icDER)

				mkSANLeaf := func(ser int64, san []byte) []byte {
					lt := &x509.Certificate{
						SerialNumber: big.NewInt(ser), Subject: pkix.Name{CommonName: "evil.example"},
						NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
						KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
						BasicConstraintsValid: true,
						ExtraExtensions:       []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san}},
					}
					d, _ := x509.CreateCertificate(rand.Reader, lt, icCert, &pki.ecKey.PublicKey, icKey)
					return d
				}
				leafIP := mkSANLeaf(9121, derSeq(derTLV(0x87, []byte{127, 0, 0, 1})))
				regOID, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 3, 4})
				leafReg := mkSANLeaf(9122, derSeq(derTLV(0x88, regOID[2:])))
				caHex := hex.EncodeToString(pki.caDER)
				verifyAt("nc_cn_evil_ip_san_peer_dns", now.Unix(), leafIP, [][]byte{icDER}, caHex, "evil.example", false, false, "reject CN fallback when IP SAN present")
				verifyAt("nc_cn_evil_ip_san_peer_ip", now.Unix(), leafIP, [][]byte{icDER}, caHex, "127.0.0.1", false, true, "observe CN=evil.example + IP SAN under excluded evil.example")
				verifyAt("nc_cn_evil_regid_san", now.Unix(), leafReg, [][]byte{icDER}, caHex, "evil.example", false, false, "reject CN=evil.example + registeredID SAN for peer evil.example")
			}

			// 9. Nested DigestAlgorithm (signatureAlgorithm) ASN.1 trailing elements
			{
				tbs, _, _, _ := extractCertParts(pki.ecDER)
				var tbsSeq asn1.RawValue
				_, _ = asn1.Unmarshal(tbs, &tbsSeq)
				rest := tbsSeq.Bytes
				var elems []asn1.RawValue
				for len(rest) > 0 {
					var el asn1.RawValue
					var uerr error
					rest, uerr = asn1.Unmarshal(rest, &el)
					if uerr != nil {
						break
					}
					elems = append(elems, el)
				}
				if len(elems) >= 7 {
					for _, tc := range []struct {
						name   string
						algSeq []byte
					}{
						{"sigalg_extra_null", derSeq(append(append([]byte{}, oidEcdsaSha256...), 0x05, 0x00))},
						{"sigalg_extra_octet", derSeq(append(append([]byte{}, oidEcdsaSha256...), 0x04, 0x04, 0xde, 0xad, 0xbe, 0xef))},
					} {
						var newBody []byte
						for i, el := range elems {
							if i == 2 {
								newBody = append(newBody, tc.algSeq...)
							} else {
								newBody = append(newBody, el.FullBytes...)
							}
						}
						newTBS := derSeq(newBody)
						d := sha256.Sum256(newTBS)
						sig, _ := ecdsa.SignASN1(rand.Reader, pki.caKey, d[:])
						mutCert := derSeq(append(append(append([]byte{}, newTBS...), tc.algSeq...), derTLV(0x03, append([]byte{0}, sig...))...))
						verifyAt(tc.name, time.Now().UTC().Unix(), mutCert, nil, hex.EncodeToString(pki.caDER), "localhost", false, false,
							"reject trailing/extra ASN.1 element inside signature AlgorithmIdentifier")
					}
				}
			}
		}
	}
}

// =========================================================================
// SUITE 5: W3_TLS_H2_Parity
// =========================================================================

func runW3TLSH2ParitySuite(rec *testRecorder, tlsServerExe, bogoExe, tlsClientExe, h2specExe string, pki *testPKI) {
	const suite = "W3_TLS_H2_Parity"
	fmt.Printf("\n================ %s ================\n", suite)

	// Helper: one-shot fault TLS 1.3 server for Suite 5 cases
	runFaultTLSServer := func(mode string, expectBoGoID bool) (int, <-chan string, func()) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			ch := make(chan string, 1)
			ch <- "listen_err:" + err.Error()
			return 0, ch, func() {}
		}
		port := ln.Addr().(*net.TCPAddr).Port
		done := make(chan string, 2)
		stopCh := make(chan struct{})

		go func() {
			defer ln.Close()
			maxAccepts := 1
			if !expectBoGoID {
				maxAccepts = 3 // tls_client.exe makes up to 2 connections
			}
			for range maxAccepts {
				select {
				case <-stopCh:
					return
				default:
				}
				_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
				conn, aerr := ln.Accept()
				if aerr != nil {
					done <- "accept_err:" + aerr.Error()
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(4 * time.Second))
					if expectBoGoID {
						var idb [8]byte
						if _, rerr := io.ReadFull(c, idb[:]); rerr != nil {
							done <- "id_err:" + rerr.Error()
							return
						}
					}
					rCH, rerr := readTLSRecord(c, 2*time.Second)
					if rerr != nil {
						done <- "ch_err:" + rerr.Error()
						return
					}
					ch, perr := parseClientHello(rCH.payload)
					if perr != nil {
						done <- "parse_ch_err:" + perr.Error()
						return
					}
					spec, _ := getCipherSpec(CipherAES128GCM)
					srvKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
					ksGroup := GroupX25519
					if mode == "grease_group" {
						ksGroup = 0x2A2A
					}
					ksBody := binary.BigEndian.AppendUint16(nil, ksGroup)
					ksBody = binary.BigEndian.AppendUint16(ksBody, 32)
					ksBody = append(ksBody, srvKey.PublicKey().Bytes()...)
					srvRnd := make([]byte, 32)
					_, _ = rand.Read(srvRnd)

					shCipher := CipherAES128GCM
					if mode == "grease_cipher" {
						shCipher = 0x0A0A
					}
					shVer := uint16(0x0304)
					if mode == "grease_version" {
						shVer = 0x1A1A
					}
					shExts := []rawExt{
						{typ: ExtSupportedVersions, body: []byte{byte(shVer >> 8), byte(shVer)}},
						{typ: ExtKeyShare, body: ksBody},
					}
					shMsg := buildServerHelloMsg(0x0303, srvRnd, ch.sessionID, shCipher, 0x00, shExts)
					_, _ = c.Write(makeRecord(RecHandshake, 0x0303, shMsg))

					if mode == "grease_cipher" || mode == "grease_version" || mode == "grease_group" {
						out := classifyResponse(c, nil, nil, 1200*time.Millisecond)
						done <- "after_grease_sh:" + out.detail
						return
					}

					peerPub, _ := ecdh.X25519().NewPublicKey(ch.keyShares[GroupX25519])
					shared, _ := srvKey.ECDH(peerPub)
					zeros := make([]byte, spec.hLen)
					earlySec := hkdfExtract(spec.hashFn, zeros, zeros)
					hsSec := hkdfExtract(spec.hashFn, deriveSecret(spec, earlySec, "derived", emptyHash(spec)), shared)
					thSH := hashMessages(spec, ch.raw, shMsg)
					cHsSec := deriveSecret(spec, hsSec, "c hs traffic", thSH)
					sHsSec := deriveSecret(spec, hsSec, "s hs traffic", thSH)
					hsTx, _ := newTrafficState(spec, sHsSec)
					hsRx, _ := newTrafficState(spec, cHsSec)

					var eeExts []byte
					if mode == "h2_pha" {
						eeExts = []byte{0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2'}
					}
					eeBody := append(binary.BigEndian.AppendUint16(nil, uint16(len(eeExts))), eeExts...)
					eeMsg := makeHandshakeMsg(HSEncryptedExtensions, eeBody)
					certMsg := buildCertHandshakeMsg([][]byte{pki.ecDER, pki.caDER})
					transcript := [][]byte{ch.raw, shMsg, eeMsg, certMsg}
					thCert := hashMessages(spec, transcript...)
					var content []byte
					content = append(content, bytes.Repeat([]byte{0x20}, 64)...)
					content = append(content, []byte("TLS 1.3, server CertificateVerify")...)
					content = append(content, 0x00)
					content = append(content, thCert...)
					d := sha256.Sum256(content)
					sig, _ := ecdsa.SignASN1(rand.Reader, pki.ecKey, d[:])
					cvBody := binary.BigEndian.AppendUint16(nil, SigECDSAP256SHA256)
					cvBody = binary.BigEndian.AppendUint16(cvBody, uint16(len(sig)))
					cvBody = append(cvBody, sig...)
					cvMsg := makeHandshakeMsg(HSCertificateVerify, cvBody)
					transcript = append(transcript, cvMsg)
					finMAC := computeFinishedMAC(spec, sHsSec, hashMessages(spec, transcript...))
					finMsg := makeHandshakeMsg(HSFinished, finMAC)
					transcript = append(transcript, finMsg)

					_, _ = c.Write(hsTx.sealRecord(RecHandshake, eeMsg))
					_, _ = c.Write(hsTx.sealRecord(RecHandshake, certMsg))
					_, _ = c.Write(hsTx.sealRecord(RecHandshake, cvMsg))
					_, _ = c.Write(hsTx.sealRecord(RecHandshake, finMsg))

					// Wait for client Finished
					for {
						recIn, rerr := readTLSRecord(c, 2*time.Second)
						if rerr != nil {
							done <- "wait_fin_err:" + rerr.Error()
							return
						}
						if recIn.typ == RecCCS {
							continue
						}
						it, pt, oerr := hsRx.openRecord(recIn)
						if oerr != nil {
							done <- "open_fin_err:" + oerr.Error()
							return
						}
						if it == RecHandshake && len(pt) >= 4 && pt[0] == HSFinished {
							break
						}
					}

					thSF := hashMessages(spec, transcript...)
					derived2 := deriveSecret(spec, hsSec, "derived", emptyHash(spec))
					masterSec := hkdfExtract(spec.hashFn, derived2, zeros)
					sAppSec := deriveSecret(spec, masterSec, "s ap traffic", thSF)
					cAppSec := deriveSecret(spec, masterSec, "c ap traffic", thSF)
					appTx, _ := newTrafficState(spec, sAppSec)
					appRx, _ := newTrafficState(spec, cAppSec)

					if mode == "unclean_eof_bogo" {
						// BoGo protocol: send AppData then abruptly close TCP WITHOUT close_notify alert!
						_, _ = c.Write(appTx.sealRecord(RecAppData, []byte("HELLO_BOGO_TEST!")))
						time.Sleep(50 * time.Millisecond)
						done <- "closed_without_close_notify"
						return
					}
					if mode == "unclean_eof_cli" {
						// Read H2/H1 request briefly then send partial H2 settings or H1 partial response and close without close_notify!
						_, _ = c.Read(make([]byte, 512))
						_, _ = c.Write(appTx.sealRecord(RecAppData, []byte("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhi")))
						done <- "cli_closed_without_close_notify"
						return
					}
					if mode == "unclean_eof_close_delim" {
						_, _ = c.Read(make([]byte, 512))
						_, _ = c.Write(appTx.sealRecord(RecAppData, []byte("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\npartial-body")))
						time.Sleep(30 * time.Millisecond)
						done <- "cli_close_delim_without_close_notify"
						return
					}
					if mode == "h2_pha" {
						// RFC 9113 s9.2.3: send CertificateRequest(13) after Finished over ALPN h2!
						crBody := []byte{
							0x03, 'p', 'h', 'a', // certificate_request_context
							0x00, 0x06, 0x00, 0x0d, 0x00, 0x02, 0x04, 0x03, // signature_algorithms ext
						}
						_, _ = c.Write(appTx.sealRecord(RecHandshake, makeHandshakeMsg(HSCertificateRequest, crBody)))
						out := classifyResponse(c, hsRx, appRx, 1500*time.Millisecond)
						done <- "after_h2_pha:" + out.detail
						return
					}
				}(conn)
			}
		}()
		return port, done, func() {
			close(stopCh)
			_ = ln.Close()
		}
	}

	// 5.1 Client-side tests against bogo_shim.exe and tls_client.exe
	if _, err := os.Stat(bogoExe); err == nil {
		bogoCases := []struct {
			name     string
			mode     string
			extraArg []string
			exp      string
		}{
			{"bogo_unclean_eof_no_close_notify", "unclean_eof_bogo", nil, "reject unclean TCP EOF without close_notify"},
			{"bogo_grease_server_cipher_0x0A0A", "grease_cipher", nil, "RFC 8701 s4.1 reject GREASE cipher"},
			{"bogo_grease_server_version_0x1A1A", "grease_version", nil, "RFC 8701 s4.1 reject GREASE version"},
			{"bogo_grease_server_group_0x2A2A", "grease_group", nil, "RFC 8701 s4.1 reject GREASE key_share group"},
			{"bogo_h2_post_handshake_auth_cr", "h2_pha", []string{"-alpn-protos", "h2"}, "RFC 9113 s9.2.3 reject CertificateRequest over h2"},
		}
		for i, tc := range bogoCases {
			port, done, cleanup := runFaultTLSServer(tc.mode, true)
			args := []string{"-host-name", "localhost", "-trust-cert", pki.caPEMPath, "-verify-peer"}
			args = append(args, tc.extraArg...)
			rc, shimOut := runBoGoShim(bogoExe, port, 8100+i, args...)
			var srvNote string
			select {
			case srvNote = <-done:
			case <-time.After(1500 * time.Millisecond):
				srvNote = "srv_timeout"
			}
			cleanup()
			st := "PASS"
			if rc == 0 {
				st = "FAIL"
			}
			rec.add(suite, "bogo_client", tc.name, st, tc.exp, fmt.Sprintf("rc=%d shim=%q srv=%q", rc, truncStr(shimOut, 60), truncStr(srvNote, 60)), "")
		}
	}

	if _, err := os.Stat(tlsClientExe); err == nil {
		for _, tc := range []struct {
			name string
			mode string
			exp  string
		}{
			{"tls_cli_unclean_eof", "unclean_eof_cli", "reject unclean EOF without close_notify"},
			{"tls_cli_unclean_eof_close_delim", "unclean_eof_close_delim", "reject close-delimited HTTP/1.1 body without close_notify"},
			{"tls_cli_grease_cipher", "grease_cipher", "RFC 8701 s4.1 reject GREASE cipher"},
			{"tls_cli_grease_version", "grease_version", "RFC 8701 s4.1 reject GREASE version"},
			{"tls_cli_grease_group", "grease_group", "RFC 8701 s4.1 reject GREASE group"},
		} {
			port, _, cleanup := runFaultTLSServer(tc.mode, false)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			cmd := exec.CommandContext(ctx, tlsClientExe)
			cmd.Env = append(cmd.Environ(), fmt.Sprintf("PORT=%d", port), fmt.Sprintf("WING_PORT=%d", port))
			outBytes, _ := cmd.CombinedOutput()
			cancel()
			cleanup()
			outStr := strings.TrimSpace(string(outBytes))
			st := "PASS"
			if strings.Contains(outStr, "TLS_CLI_VERIFIED_H2: PASS") {
				st = "FAIL"
			}
			rec.add(suite, "tls_client", tc.name, st, tc.exp, fmt.Sprintf("out=%q", truncStr(outStr, 90)), "")
		}
	}

	// 5.2 Server-side tests against tls_server.exe (default & --sni-map)
	if _, err := os.Stat(tlsServerExe); err == nil {
		srvDef, err := startManagedServer("w3_tls_def", tlsServerExe, []string{"--port", "0"}, nil, tcpShutdown)
		if err != nil {
			rec.add(suite, "tls_server", "start_default", "FAIL", "start", err.Error(), "")
		} else {
			defer srvDef.stop()
			addr := fmt.Sprintf("127.0.0.1:%d", srvDef.port)
			sni := "goose-wing.local"

			validX25519 := func() []byte {
				k, _ := ecdh.X25519().GenerateKey(rand.Reader)
				return k.PublicKey().Bytes()
			}

			// Duplicate GREASE extension IDs (0x0A0A twice)
			{
				ch := buildClientHelloMsg(clientHelloOpts{
					legacyVer: 0x0303,
					sessionID: make([]byte, 32),
					ciphers:   []uint16{CipherAES128GCM},
					exts: []rawExt{
						{typ: 0x0A0A, body: []byte{}},
						extSNI(sni),
						extSupportedVersionsClient(0x0304),
						extSupportedGroups(GroupX25519),
						extSigAlgs(SigEd25519, SigECDSAP256SHA256),
						extALPN("http/1.1"),
						extKeyShareClient(keyShareEntry{group: GroupX25519, key: validX25519()}),
						{typ: 0x0A0A, body: []byte{0x00}},
					},
				})
				out := sendRawAndClassify(addr, makeRecord(RecHandshake, 0x0301, ch))
				st := "PASS"
				if !isRejectedOutcome(out) {
					st = "FAIL"
				}
				rec.add(suite, "tls_server_grease", "dup_grease_ext_0x0A0A", st, "RFC 8446 s4.2 reject duplicate extension 0x0A0A", out.detail, "")
			}

			// GREASE-only cipher / version / group
			for _, gc := range []struct {
				name string
				opts clientHelloOpts
			}{
				{"grease_only_cipher", clientHelloOpts{
					legacyVer: 0x0303, ciphers: []uint16{0x0A0A},
					exts: []rawExt{extSNI(sni), extSupportedVersionsClient(0x0304), extSupportedGroups(GroupX25519), extSigAlgs(SigEd25519), extKeyShareClient(keyShareEntry{group: GroupX25519, key: validX25519()})},
				}},
				{"grease_only_version", clientHelloOpts{
					legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM},
					exts: []rawExt{extSNI(sni), extSupportedVersionsClient(0x1A1A), extSupportedGroups(GroupX25519), extSigAlgs(SigEd25519), extKeyShareClient(keyShareEntry{group: GroupX25519, key: validX25519()})},
				}},
				{"grease_only_group", clientHelloOpts{
					legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM},
					exts: []rawExt{extSNI(sni), extSupportedVersionsClient(0x0304), extSupportedGroups(0x2A2A), extSigAlgs(SigEd25519), extKeyShareClient(keyShareEntry{group: 0x2A2A, key: []byte{0x00}})},
				}},
			} {
				out := sendRawAndClassify(addr, makeRecord(RecHandshake, 0x0301, buildClientHelloMsg(gc.opts)))
				st := "PASS"
				if !isRejectedOutcome(out) {
					st = "FAIL"
				}
				rec.add(suite, "tls_server_grease", gc.name, st, "RFC 8701 reject GREASE-only negotiation", out.detail, "")
			}

			// Client unclean EOF mid-AppData (no close_notify)
			{
				cfg := defaultHandshakeConfig(sni)
				sess, herr := doTLS13Handshake(addr, cfg)
				if herr != nil {
					rec.add(suite, "tls_server_eof", "client_unclean_eof", "FAIL", "handshake", herr.Error(), "")
				} else {
					_ = sess.sendAppData([]byte("GET /secure-hello HTTP/1.1\r\nHost: "+sni+"\r\n"), false)
					sess.close()
					if err := probeServerHealth(addr, sni, false); err != nil {
						rec.add(suite, "tls_server_eof", "client_unclean_eof", "FAIL", "server cleans up and stays healthy", err.Error(), "")
					} else {
						rec.add(suite, "tls_server_eof", "client_unclean_eof", "PASS", "server cleans up and stays healthy", "ok", "")
					}
				}
			}

			// H2 :authority vs Host mismatch over TLS
			{
				cfg := defaultHandshakeConfig(sni)
				cfg.alpn = []string{"h2"}
				sess, herr := doTLS13Handshake(addr, cfg)
				if herr != nil {
					rec.add(suite, "tls_h2_parity", "h2_authority_host_mismatch", "FAIL", "handshake", herr.Error(), "")
				} else {
					hb := buildH2HeadersBlock(sni, "GET", "/secure-hello", [][2]string{{"host", "evil.example"}})
					pkt := append(append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)...), packH2Frame(0x01, 0x05, 1, hb)...)
					_ = sess.sendAppData(pkt, false)
					resp, rerr := sess.readAppData(1000 * time.Millisecond)
					sess.close()
					ga, rst, hdrs, sum := summarizeH2Frames(resp)
					st := "PASS"
					if !ga && !rst && hdrs && rerr == nil && !bytes.Contains(resp, []byte("400")) && !bytes.Contains(resp, []byte("421")) {
						st = "FAIL"
					}
					rec.add(suite, "tls_h2_parity", "h2_authority_host_mismatch", st, "reject 400/421/RST/GOAWAY", fmt.Sprintf("frames=[%s] err=%v", sum, rerr), "")
				}
			}

			// H2 Post-Handshake Auth (client sends Certificate/CertificateRequest over ALPN h2)
			for _, hsMsg := range []struct {
				name string
				msg  []byte
			}{
				{"h2_client_post_hs_cert", makeHandshakeMsg(HSCertificate, []byte{0, 0, 0, 0})},
				{"h2_client_post_hs_certreq", makeHandshakeMsg(HSCertificateRequest, []byte{0, 0, 2, 0, 0})},
			} {
				cfg := defaultHandshakeConfig(sni)
				cfg.alpn = []string{"h2"}
				sess, herr := doTLS13Handshake(addr, cfg)
				if herr != nil {
					rec.add(suite, "tls_h2_pha", hsMsg.name, "FAIL", "handshake", herr.Error(), "")
				} else {
					_, _ = sess.conn.Write(sess.appTx.sealRecord(RecHandshake, hsMsg.msg))
					out := classifyResponse(sess.conn, sess.hsRx, sess.appRx, 1000*time.Millisecond)
					sess.close()
					st := "PASS"
					if !isRejectedOutcome(out) {
						st = "FAIL"
					}
					rec.add(suite, "tls_h2_pha", hsMsg.name, st, "RFC 9113 s9.2.3 reject post-handshake auth over h2", out.detail, "")
				}
			}
			srvDef.stop()
		}

		// SNI vs :authority mismatch against --sni-map mode (test.local vs ecdsa.local)
		sniArgs := []string{
			"--port", "0",
			"--sni-map", fmt.Sprintf("test.local=%s|%s", pki.edCertPath, pki.edKeyPath),
			"--sni-map", fmt.Sprintf("ecdsa.local=%s|%s", pki.ecCertPath, pki.ecKeyPath),
		}
		srvSNI, err := startManagedServer("w3_tls_snimap", tlsServerExe, sniArgs, []string{"WING_PORT=0"}, tcpShutdown)
		if err != nil {
			rec.add(suite, "tls_sni_parity", "start_snimap", "FAIL", "start", err.Error(), "")
		} else {
			defer srvSNI.stop()
			addr := fmt.Sprintf("127.0.0.1:%d", srvSNI.port)
			cfg := defaultHandshakeConfig("test.local")
			cfg.alpn = []string{"h2", "http/1.1"}
			sess, herr := doTLS13Handshake(addr, cfg)
			if herr != nil {
				rec.add(suite, "tls_sni_parity", "sni_vs_authority_mismatch", "FAIL", "handshake", herr.Error(), "")
			} else if sess.negotiatedALPN == "h2" {
				hb := buildH2HeadersBlock("ecdsa.local", "GET", "/secure-hello", nil)
				pkt := append(append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)...), packH2Frame(0x01, 0x05, 1, hb)...)
				_ = sess.sendAppData(pkt, false)
				resp, rerr := sess.readAppData(1000 * time.Millisecond)
				sess.close()
				ga, rst, _, sum := summarizeH2Frames(resp)
				st := "INFO"
				if ga || rst || bytes.Contains(resp, []byte("421")) {
					st = "PASS"
				}
				rec.add(suite, "tls_sni_parity", "sni_vs_authority_mismatch", st, "421 Misdirected Request or rejection on SNI!=:authority",
					fmt.Sprintf("frames=[%s] ascii=%q err=%v", sum, truncStr(string(resp), 48), rerr), "")
			} else {
				// PureGoose --sni-map may negotiate http/1.1; test H1 Host vs SNI mismatch
				_ = sess.sendAppData([]byte("GET /secure-hello HTTP/1.1\r\nHost: ecdsa.local\r\nConnection: close\r\n\r\n"), false)
				resp, rerr := sess.readAppData(1000 * time.Millisecond)
				sess.close()
				rec.add(suite, "tls_sni_parity", "sni_vs_host_mismatch_h1", "INFO", "observe SNI=test.local vs Host=ecdsa.local (alpn="+sess.negotiatedALPN+")",
					fmt.Sprintf("sl=%q err=%v", httpStatusLine(resp), rerr), "")
			}
			srvSNI.stop()
		}
	}

	// Also verify h2spec_server cleartext :authority vs Host mismatch
	if _, err := os.Stat(h2specExe); err == nil {
		srvH2, err := startManagedServer("w3_h2c_parity", h2specExe, nil, nil, tcpShutdown)
		if err == nil {
			defer srvH2.stop()
			hb := buildH2HeadersBlock("127.0.0.1", "GET", "/ping", [][2]string{{"host", "evil.example"}})
			pkt := append(append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, nil)...), packH2Frame(0x01, 0x05, 1, hb)...)
			resp, _, rerr := tcpExchangeRaw(fmt.Sprintf("127.0.0.1:%d", srvH2.port), [][]byte{pkt}, 0, false, 800*time.Millisecond)
			ga, rst, hdrs, sum := summarizeH2Frames(resp)
			st := "PASS"
			if !ga && !rst && hdrs && rerr == nil {
				st = "FAIL"
			}
			rec.add(suite, "h2c_parity", "h2c_authority_vs_host_mismatch", st, "reject :authority!=host (RST/GOAWAY)", fmt.Sprintf("frames=[%s] err=%v", sum, rerr), "")
		}
	}
}

// =========================================================================
// SUITE 6: W3_QUIC_H3_Transport
// =========================================================================

func runW3QUICH3TransportSuite(rec *testRecorder, http3Exe, quicEndpointExe string) {
	const suite = "W3_QUIC_H3_Transport"
	fmt.Printf("\n================ %s ================\n", suite)

	dcidA := []byte{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}
	dcidB := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	scid := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	vnProbe := buildQUICInitial(0x5a5a5a5a, dcidA, scid, nil, []byte{0x01, 'p', 'i', 'n', 'g'}, 1200, 0xC0)

	runTarget := func(targetName, exe string, args []string, useVNProbe bool) {
		if _, err := os.Stat(exe); err != nil {
			rec.add(suite, targetName, "binary_present", "INFO", "skip if unbuilt", err.Error(), "")
			return
		}
		srv, err := startManagedServer("w3_"+targetName, exe, args, nil, udpShutdown)
		if err != nil {
			rec.add(suite, targetName, "start_server", "FAIL", "start", err.Error(), "")
			return
		}
		var exitCh chan error
		watchProc := func(s *managedServer) {
			if s == nil || useVNProbe {
				return
			}
			exitCh = make(chan error, 1)
			go func() { exitCh <- s.cmd.Wait() }()
		}
		stopSrv := func(s *managedServer) {
			if s == nil || s.stopped {
				return
			}
			if !useVNProbe && exitCh != nil {
				s.stopped = true
				if s.port > 0 {
					udpShutdown(s.port)
				}
				select {
				case <-exitCh:
				case <-time.After(1500 * time.Millisecond):
					_ = s.cmd.Process.Kill()
					<-exitCh
				}
				fmt.Printf("[*] Stopped %s (port %d)\n", s.name, s.port)
				return
			}
			s.stop()
		}
		watchProc(srv)
		defer func() {
			stopSrv(srv)
		}()

		checkLiveness := func(after string) bool {
			if srv == nil {
				return false
			}
			if !useVNProbe {
				select {
				case werr := <-exitCh:
					srv.stopped = true
					rec.add(suite, targetName, after+"_liveness", "FAIL", "process stays alive",
						fmt.Sprintf("exited unexpectedly: err=%v stderr=%q", werr, srv.getStderr()), "")
					srv, _ = startManagedServer("w3_"+targetName, exe, args, nil, udpShutdown)
					watchProc(srv)
					return false
				case <-time.After(20 * time.Millisecond):
					return true
				}
			}
			addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
			resp, err := sendUDPAndRecv(addr, vnProbe, 600*time.Millisecond)
			if err == nil && len(resp) >= 15 && binary.BigEndian.Uint32(resp[1:5]) == 0 {
				return true
			}
			rec.add(suite, targetName, after+"_liveness", "FAIL", "server alive and replies VN",
				fmt.Sprintf("err=%v len=%d stderr=%q", err, len(resp), srv.getStderr()), "")
			stopSrv(srv)
			srv, _ = startManagedServer("w3_"+targetName, exe, args, nil, udpShutdown)
			watchProc(srv)
			return false
		}

		// 1. Short UDP packets <= 42B (random + 0x40 short-header) -> NO amplification
		for _, sz := range []int{1, 16, 21, 32, 42} {
			for _, hdrMode := range []string{"rand", "short0x40"} {
				if srv == nil {
					break
				}
				pkt := make([]byte, sz)
				_, _ = rand.Read(pkt)
				if hdrMode == "short0x40" {
					pkt[0] = (pkt[0] & 0x3f) | 0x40
				}
				addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
				resp, _ := sendUDPAndRecv(addr, pkt, 200*time.Millisecond)
				name := fmt.Sprintf("short_%s_%dB", hdrMode, sz)
				if len(resp) >= len(pkt) {
					rec.add(suite, targetName, name, "FAIL", fmt.Sprintf("no amplification (resp < %dB)", sz),
						fmt.Sprintf("AMPLIFICATION/STATELESS_RESET: in=%dB out=%dB hex=%x", sz, len(resp), resp[:minInt(len(resp), 24)]), "")
				} else {
					rec.add(suite, targetName, name, "PASS", "no amplification (discarded)", fmt.Sprintf("in=%dB out=%dB", sz, len(resp)), "")
				}
				checkLiveness(name)
			}
		}

		// 2. Coalesced Initial packets with distinct DCIDs in one UDP datagram
		if srv != nil {
			init1 := buildQUICInitial(0x00000001, dcidA, scid, nil, []byte{0x01, 'a', 'b', 'c'}, 1200, 0xC0)
			init2 := buildQUICInitial(0x00000001, dcidB, scid, nil, []byte{0x01, 'd', 'e', 'f'}, 1200, 0xC0)
			coalesced := append(init1, init2...)
			addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
			resp, err := sendUDPAndRecv(addr, coalesced, 400*time.Millisecond)
			rec.add(suite, targetName, "coalesced_distinct_dcid_initials", "PASS", "no crash/hang on coalesced distinct DCIDs",
				fmt.Sprintf("out=%dB err=%v", len(resp), err), "")
			checkLiveness("coalesced_distinct_dcid")
		}

		// 3. Invalid / oversize QUIC packets & PATH_CHALLENGE flood
		if srv != nil {
			addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
			oversize := buildQUICInitial(0x00000001, dcidA, scid, nil, []byte{0x01, 'o', 'v'}, 4096, 0xC0)
			rOv, _ := sendUDPAndRecv(addr, oversize, 250*time.Millisecond)
			rec.add(suite, targetName, "oversize_4096B_initial", "PASS", "handle oversize datagram without crash", fmt.Sprintf("out=%dB", len(rOv)), "")
			checkLiveness("oversize_4096B")
		}

		if srv != nil {
			addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
			badLen := []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0x08}
			badLen = append(badLen, dcidA...)
			badLen = append(badLen, 0x08)
			badLen = append(badLen, scid...)
			badLen = append(badLen, 0x00, 0x7f, 0xff) // invalid 2-byte varint length 16383 > packet size
			badLen = append(badLen, make([]byte, 1200-len(badLen))...)
			rBL, _ := sendUDPAndRecv(addr, badLen, 250*time.Millisecond)
			st := "PASS"
			if len(rBL) > len(badLen) {
				st = "FAIL"
			}
			rec.add(suite, targetName, "invalid_initial_length_varint", st, "reject/discard invalid length without amplification", fmt.Sprintf("out=%dB", len(rBL)), "")
			checkLiveness("invalid_initial_len")
		}

		// PATH_CHALLENGE / spoofed short-header flood (64 rapid packets)
		if srv != nil {
			addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
			conn, derr := net.DialTimeout("udp", addr, time.Second)
			if derr == nil {
				for i := range 64 {
					pkt := make([]byte, 48)
					pkt[0] = 0x40
					copy(pkt[1:9], dcidA)
					pkt[9] = 0x1a // PATH_CHALLENGE frame type marker inside payload
					binary.BigEndian.PutUint64(pkt[10:18], uint64(i+1))
					_, _ = conn.Write(pkt)
				}
				_ = conn.Close()
			}
			if useVNProbe {
				resp, rerr := sendUDPAndRecv(addr, vnProbe, 800*time.Millisecond)
				if rerr == nil && len(resp) >= 15 && binary.BigEndian.Uint32(resp[1:5]) == 0 {
					rec.add(suite, targetName, "path_challenge_flood_64", "PASS", "survive flood and respond to valid probe", fmt.Sprintf("vn=%dB", len(resp)), "")
				} else {
					rec.add(suite, targetName, "path_challenge_flood_64", "FAIL", "survive flood and respond to valid probe", fmt.Sprintf("err=%v len=%d", rerr, len(resp)), "")
				}
			} else if checkLiveness("path_challenge_flood_64") {
				rec.add(suite, targetName, "path_challenge_flood_64", "PASS", "process survives 64-pkt flood without crash", "alive", "")
			}
		}
	}

	runTarget("http3_server", http3Exe, nil, true)

	wwwDir := filepath.Join(scratchDir, "quic_www")
	_ = os.MkdirAll(wwwDir, 0750)
	_ = os.WriteFile(filepath.Join(wwwDir, "index.html"), []byte("ok\n"), 0600)
	runTarget("quic_interop_endpoint", quicEndpointExe, []string{"server", "0", "handshake", wwwDir}, false)
}

// =========================================================================
// SUITE 7: W3_CLI_Blackbox
// =========================================================================

func runW3CLIBlackboxSuite(rec *testRecorder) {
	const suite = "W3_CLI_Blackbox"
	fmt.Printf("\n================ %s ================\n", suite)

	cliOut := filepath.Join(scratchDir, "wing_cli")
	if os.PathSeparator == '\\' {
		cliOut += ".exe"
	}
	ctxB, cancelB := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelB()
	buildCmd := exec.CommandContext(ctxB, "goose", "build", "-O0", "cli/main.goose", "-o", cliOut)
	buildCmd.Dir = repoRoot
	if os.PathSeparator == '\\' {
		bat := filepath.Join(repoRoot, "tools", "gcc_stack.bat")
		if _, err := os.Stat(bat); err == nil {
			buildCmd.Env = append(os.Environ(), "GOOSE_CC="+bat)
		}
	}
	buildOut, buildErr := buildCmd.CombinedOutput()
	if buildErr != nil {
		rec.add(suite, "build", "goose_build_cli", "INFO", "compile cli/main.goose (skip cleanly if toolchain/MSVC env missing)",
			fmt.Sprintf("build skipped/failed: %v | %s", buildErr, truncStr(strings.TrimSpace(string(buildOut)), 140)), "")
		return
	}
	rec.add(suite, "build", "goose_build_cli", "PASS", "compile cli/main.goose", cliOut, "")

	// Check supported flags via --help
	helpOut, _ := exec.Command(cliOut, "--help").CombinedOutput()
	helpStr := string(helpOut)

	// 1. ANSI / OSC 52 escaping test
	srvANSI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Evil", "\x1b]52;c;cHdu\x07")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("hello\x1b[31mred\x1b[0m\x1b]52;c;AAAA\x07\n"))
	}))
	defer srvANSI.Close()

	{
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, cliOut, "-i", srvANSI.URL+"/ansi").CombinedOutput()
		cancel()
		if err != nil && len(out) == 0 {
			rec.add(suite, "ansi_osc52", "cli_escape_ansi", "INFO", "CLI run on mock ANSI server", fmt.Sprintf("err=%v", err), "")
		} else if bytes.Contains(out, []byte("\x1b]52;")) {
			rec.add(suite, "ansi_osc52", "cli_escape_ansi", "FAIL", "strip/escape OSC 52 ESC sequence", truncStr(string(out), 100), "")
		} else {
			rec.add(suite, "ansi_osc52", "cli_escape_ansi", "PASS", "no raw OSC 52 escape leaked", truncStr(string(out), 100), "")
		}
	}

	// 2. Content-Disposition traversal with -J / -O in temp dir
	if strings.Contains(helpStr, "-J") || strings.Contains(helpStr, "-O") {
		cdNames := []string{
			"../../pwn.txt",
			"%2F..%2Fpwn.txt",
			`..\pwn.txt`,
			"COM¹.txt",
			"NUL.txt",
			"foo:bar::$DATA",
		}
		dlRoot := filepath.Join(scratchDir, "cli_dl_root")
		dlSub := filepath.Join(dlRoot, "sub")
		_ = os.MkdirAll(dlSub, 0750)
		for i, fn := range cdNames {
			srvCD := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fn))
				_, _ = w.Write([]byte("pwned"))
			}))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			cmd := exec.CommandContext(ctx, cliOut, "-J", "-O", srvCD.URL+"/file")
			cmd.Dir = dlSub
			out, _ := cmd.CombinedOutput()
			cancel()
			srvCD.Close()
			if _, err := os.Stat(filepath.Join(dlRoot, "pwn.txt")); err == nil {
				rec.add(suite, "cd_traversal", fmt.Sprintf("cd_%d", i), "FAIL", "no traversal outside cwd", "created pwn.txt in parent dir!", "")
				_ = os.Remove(filepath.Join(dlRoot, "pwn.txt"))
			} else {
				rec.add(suite, "cd_traversal", fmt.Sprintf("cd_%d", i), "PASS", "safe filename / no parent write", truncStr(string(out), 60), "")
			}
		}
	} else {
		rec.add(suite, "cd_traversal", "flags_check", "INFO", "check -J/-O support", "CLI --help lacks -J/-O flags", "")
	}

	// 3. Cross-origin 302 redirect credential stripping
	if strings.Contains(helpStr, "-L") {
		var mu sync.Mutex
		var leakedAuth, leakedKey string
		srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			leakedAuth = r.Header.Get("Authorization")
			leakedKey = r.Header.Get("X-API-Key")
			mu.Unlock()
			w.WriteHeader(200)
			_, _ = w.Write([]byte("dest-ok"))
		}))
		defer srvB.Close()
		srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, srvB.URL+"/dest", http.StatusFound)
		}))
		defer srvA.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, _ := exec.CommandContext(ctx, cliOut, "-L", "-H", "Authorization: Bearer secret123", "-H", "X-API-Key: key456", srvA.URL+"/start").CombinedOutput()
		cancel()
		mu.Lock()
		la, lk := leakedAuth, leakedKey
		mu.Unlock()
		if la != "" || lk != "" {
			rec.add(suite, "redirect_creds", "xorigin_302_strip", "FAIL", "strip Authorization and X-API-Key on cross-origin 302",
				fmt.Sprintf("leaked Authorization=%q X-API-Key=%q", la, lk), "")
		} else {
			rec.add(suite, "redirect_creds", "xorigin_302_strip", "PASS", "credentials stripped on cross-origin 302", truncStr(string(out), 60), "")
		}
	} else {
		rec.add(suite, "redirect_creds", "flags_check", "INFO", "check -L support", "CLI --help lacks -L flag", "")
	}
}
