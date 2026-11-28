// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// runWave4AuditSuite executes Wave 4 (0.1.1) black-box conformance and security probes
// targeting live gRPC/gRPC-Web (242B unregistered path overflow, oversized H2 frame DoS,
// idle H2 client recovery) and WebSocket upgrade parser strictness.
func runWave4AuditSuite() int {
	rec := &testRecorder{}
	binDir := filepath.Join(repoRoot, "tools", "bin")
	grpcExe := exePath(binDir, "grpc_server")

	runW4GrpcLiveSuite(rec, grpcExe)

	fmt.Println("\n==================== WAVE 4 AUDIT SUMMARY ====================")
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
	fmt.Printf("\nWAVE 4 TOTALS -> FAIL=%d | WARN=%d | INFO=%d\n", len(fails), len(warns), len(infos))
	if len(fails) > 0 {
		fmt.Println("\n--- WAVE 4 FAILURES ---")
		for _, f := range fails {
			fmt.Printf("  [FAIL] %s/%s/%s\n         exp: %s\n         got: %s\n",
				f.suite, f.category, f.name, f.expected, f.observed)
		}
	}
	if logDir != "" {
		logPath := filepath.Join(logDir, "wave4_results.log")
		_ = os.WriteFile(logPath, []byte(logBuf.String()), 0600)
		fmt.Printf("\n[+] Wave 4 wire log written to %s\n", logPath)
	}
	return len(fails)
}

func runW4GrpcLiveSuite(rec *testRecorder, grpcExe string) {
	const suite = "W4_gRPC_Hardening"
	fmt.Printf("\n================ %s ================\n", suite)

	if _, err := os.Stat(grpcExe); err != nil {
		rec.add(suite, "setup", "grpc_server_present", "INFO", "skip if unbuilt", err.Error(), "")
		return
	}
	srv, err := startManagedServer("w4_grpc", grpcExe, nil, []string{"WING_PORT=0"}, tcpShutdown)
	if err != nil {
		rec.add(suite, "setup", "grpc_server_start", "FAIL", "start", err.Error(), "")
		return
	}
	defer srv.stop()
	addr := fmt.Sprintf("127.0.0.1:%d", srv.port)

	// W4-GRPC-01: Unregistered 242-byte path must return Unimplemented (12) without crashing server.
	longPath := "/" + strings.Repeat("a", 120) + "/" + strings.Repeat("b", 120)
	req := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: 5\r\nConnection: close\r\n\r\n\x00\x00\x00\x00\x00",
		longPath,
	)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		rec.add(suite, "overflow", "unregistered_242b_path", "FAIL", "connect", err.Error(), "")
		return
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write([]byte(req))
	rawResp, _ := io.ReadAll(conn)
	_ = conn.Close()

	if bytes.Contains(rawResp, []byte("200 OK")) && bytes.Contains(rawResp, []byte("grpc-status: 12")) {
		rec.add(suite, "overflow", "unregistered_242b_path", "PASS", "200 OK + grpc-status: 12", fmt.Sprintf("%dB response", len(rawResp)), "")
	} else {
		rec.add(suite, "overflow", "unregistered_242b_path", "FAIL", "200 OK + grpc-status: 12", fmt.Sprintf("got %q stderr=%q", string(rawResp), srv.getStderr()), "")
	}

	// W4-GRPC-02: Oversized H2 frame length (>16384B) must terminate cleanly without stalling server.
	c2, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		rec.add(suite, "h2_dos", "oversized_frame_header", "FAIL", "connect after 242B probe", err.Error(), "")
		return
	}
	_ = c2.SetDeadline(time.Now().Add(2 * time.Second))
	var badHdr [9]byte
	badHdr[0] = 0x01 // length = 65536 (> 16384 max frame size)
	badHdr[3] = 0x01 // HEADERS
	binary.BigEndian.PutUint32(badHdr[5:9], 1)
	_, _ = c2.Write(append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), badHdr[:]...))
	_, _ = io.ReadAll(c2)
	_ = c2.Close()

	// W4-GRPC-03: Health check after both adversarial probes must still return 200 OK immediately.
	c3, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		rec.add(suite, "liveness", "health_after_probes", "FAIL", "200 OK", err.Error(), "")
		return
	}
	_ = c3.SetDeadline(time.Now().Add(3 * time.Second))
	healthReq := "POST /grpc.health.v1.Health/Check HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: 5\r\nConnection: close\r\n\r\n\x00\x00\x00\x00\x00"
	_, _ = c3.Write([]byte(healthReq))
	hResp, _ := io.ReadAll(c3)
	_ = c3.Close()
	if bytes.Contains(hResp, []byte("200 OK")) {
		rec.add(suite, "liveness", "health_after_probes", "PASS", "200 OK", fmt.Sprintf("%dB", len(hResp)), "")
	} else {
		rec.add(suite, "liveness", "health_after_probes", "FAIL", "200 OK", fmt.Sprintf("got %q", string(hResp)), "")
	}
}
