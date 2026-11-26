// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	repoRoot   string
	scratchDir string
	logDir     string
)

func exePath(dir, name string) string {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(dir, name)
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "wing.goose")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not locate wing.goose above current directory; pass --repo-root")
		}
		dir = parent
	}
}

type managedServer struct {
	name     string
	cmd      *exec.Cmd
	port     int
	shutdown func(port int)
	stopped  bool
	mu       sync.Mutex
	errBuf   strings.Builder
}

func (ms *managedServer) getStderr() string {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	return strings.TrimSpace(ms.errBuf.String())
}

func startManagedServer(name, exe string, args []string, extraEnv []string, shutdownFn func(int)) (*managedServer, error) {
	cmd := exec.Command(exe, args...)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), extraEnv...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	ms := &managedServer{name: name, cmd: cmd, shutdown: shutdownFn}
	portCh := make(chan int, 1)
	errCh := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			line := sc.Text()
			if _, after, ok := strings.Cut(line, "READY_PORT:"); ok {
				pStr := strings.TrimSpace(after)
				if p, err := strconv.Atoi(pStr); err == nil {
					portCh <- p
					return
				}
			}
		}
		errCh <- "stdout closed before READY_PORT"
	}()
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			ms.mu.Lock()
			if ms.errBuf.Len() < 1024 {
				ms.errBuf.WriteString(sc.Text())
				ms.errBuf.WriteByte('\n')
			}
			ms.mu.Unlock()
		}
	}()

	select {
	case p := <-portCh:
		ms.port = p
		return ms, nil
	case e := <-errCh:
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("%s failed: %s", name, e)
	case <-time.After(8 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("%s timed out waiting for READY_PORT", name)
	}
}

func (ms *managedServer) stop() {
	if ms == nil || ms.cmd == nil || ms.stopped {
		return
	}
	ms.stopped = true
	if ms.shutdown != nil && ms.port > 0 {
		ms.shutdown(ms.port)
	}
	done := make(chan error, 1)
	go func() { done <- ms.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(1500 * time.Millisecond):
		_ = ms.cmd.Process.Kill()
		<-done
	}
	fmt.Printf("[*] Stopped %s (port %d)\n", ms.name, ms.port)
}

func tcpShutdown(port int) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
	if err != nil {
		return
	}
	_, _ = c.Write([]byte("GET /shutdown HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, _ = c.Read(make([]byte, 128))
	_ = c.Close()
}

func udpShutdown(port int) {
	c, err := net.DialTimeout("udp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
	if err != nil {
		return
	}
	_, _ = c.Write([]byte("SHUTDOWN"))
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, _ = c.Read(make([]byte, 128))
	_ = c.Close()
}

func writeFileBytes(path string, data []byte) error {
	return os.WriteFile(path, data, 0600)
}

func main() {
	var (
		flagRepoRoot = flag.String("repo-root", "", "path to goose-wing repository root (auto-detected if omitted)")
		flagLogDir   = flag.String("log-dir", "", "optional directory to write results.log / round2_results.log")
		flagProbe    = flag.Bool("probe", false, "run deep diagnostic wire probes")
		flagRound2   = flag.Bool("round2", false, "run Round 2 (2025-2026 CVE matrix)")
		flagAll      = flag.Bool("all", false, "run both Round 1 and Round 2 suites")
	)
	flag.Parse()

	if *flagRepoRoot != "" {
		abs, err := filepath.Abs(*flagRepoRoot)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FATAL invalid --repo-root: %v\n", err)
			os.Exit(1)
		}
		repoRoot = abs
	} else {
		root, err := findRepoRoot()
		if err != nil {
			fmt.Fprintf(os.Stderr, "FATAL %v\n", err)
			os.Exit(1)
		}
		repoRoot = root
	}

	tmpDir, err := os.MkdirTemp("", "wing-blackbox-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL os.MkdirTemp: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)
	scratchDir = tmpDir

	if *flagLogDir != "" {
		if err := os.MkdirAll(*flagLogDir, 0750); err != nil {
			fmt.Fprintf(os.Stderr, "FATAL mkdir --log-dir: %v\n", err)
			os.Exit(1)
		}
		logDir = *flagLogDir
	}

	if err := verifyChaCha20Poly1305SelfTest(); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL ChaCha20-Poly1305 self-test failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] Pure-Go RFC 8439 ChaCha20-Poly1305 self-test PASSED")

	pki, err := generateTestPKI(scratchDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL generateTestPKI: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] Generated ephemeral PKI (CA + Ed25519 + ECDSA P-256 + RSA-2048)")

	if *flagProbe {
		runDeepProbes(pki)
		return
	}
	if *flagRound2 && !*flagAll {
		runRound2Suite(pki)
		return
	}

	binDir := filepath.Join(repoRoot, "tools", "bin")
	tlsServerExe := exePath(binDir, "tls_server")
	bogoShimExe := exePath(binDir, "bogo_shim")
	tlsClientExe := exePath(binDir, "tls_client")
	x509HarnessExe := exePath(binDir, "x509_harness")
	smugWingExe := exePath(binDir, "smuggling_wing")
	smugH1Exe := exePath(binDir, "smuggling_wing_h1")
	h2specServerExe := exePath(binDir, "h2spec_server")
	http3ServerExe := exePath(binDir, "http3_server")
	cryptoHarnessExe := exePath(filepath.Join(repoRoot, ".lit", "cache", "crypto_vectors"), "harness")

	rec := &testRecorder{}

	// 1. Live default tls_server.exe (--port 0)
	srvDef, err := startManagedServer("tls_server_default", tlsServerExe, []string{"--port", "0"}, nil, tcpShutdown)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR starting tls_server default: %v\n", err)
	} else {
		defer srvDef.stop()
		addr := fmt.Sprintf("127.0.0.1:%d", srvDef.port)
		fmt.Printf("[*] Started tls_server.exe (default) on %s\n", addr)
		runServerSuite(rec, "tls_srv_default", addr, "goose-wing.local", false, "")
		runH1OverTLSSuite(rec, addr, "goose-wing.local")
		runH2OverTLSSuite(rec, addr, "goose-wing.local")
		srvDef.stop()
		srvDef = nil
	}

	// 2. Live --sni-map PureGoose TlsEndpoint mode (Ed25519 + ECDSA P-256)
	sniArgs := []string{
		"--port", "0",
		"--sni-map", fmt.Sprintf("test.local=%s|%s", pki.edCertPath, pki.edKeyPath),
		"--sni-map", fmt.Sprintf("ecdsa.local=%s|%s", pki.ecCertPath, pki.ecKeyPath),
	}
	srvSNI, err := startManagedServer("tls_server_snimap", tlsServerExe, sniArgs, []string{"WING_PORT=0"}, tcpShutdown)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR starting tls_server --sni-map: %v\n", err)
	} else {
		defer srvSNI.stop()
		addr := fmt.Sprintf("127.0.0.1:%d", srvSNI.port)
		fmt.Printf("[*] Started tls_server.exe (--sni-map PureGoose) on %s\n", addr)
		runServerSuite(rec, "tls_srv_snimap", addr, "test.local", true, "ecdsa.local")
		srvSNI.stop()
		srvSNI = nil
	}

	// 3. Client-side fault-injecting TLS 1.3 server against bogo_shim.exe & tls_client.exe
	runClientSuite(rec, bogoShimExe, tlsClientExe, pki)

	// 4. Live cleartext h2spec_server.exe
	srvH2, err := startManagedServer("h2spec_server", h2specServerExe, nil, nil, tcpShutdown)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR starting h2spec_server: %v\n", err)
	} else {
		defer srvH2.stop()
		addr := fmt.Sprintf("127.0.0.1:%d", srvH2.port)
		fmt.Printf("[*] Started h2spec_server.exe on %s\n", addr)
		runH2SpecServerSuite(rec, addr)
		srvH2.stop()
		srvH2 = nil
	}

	// 5. Offline smuggling differential harnesses
	runSmugglingHarnessSuite(rec, smugWingExe, smugH1Exe, scratchDir)

	// 6. Live UDP http3_server.exe (with per-packet liveness check & crash bisection)
	runHTTP3ServerSuite(rec, http3ServerExe)

	// 7. Direct x509_harness.exe & crypto_vectors/harness.exe edge suites
	runX509HarnessEdgeSuite(rec, x509HarnessExe, pki)
	runCryptoHarnessEdgeSuite(rec, cryptoHarnessExe)

	// Summary table & save full log
	fmt.Println("\n==================== EXECUTION SUMMARY ====================")
	type counts struct{ pass, fail, warn, info int }
	bySuite := map[string]*counts{}
	var suiteOrder []string
	var fails []testResult
	var warns []testResult
	var infos []testResult

	var logBuf strings.Builder
	for _, r := range rec.results {
		if _, ok := bySuite[r.suite]; !ok {
			bySuite[r.suite] = &counts{}
			suiteOrder = append(suiteOrder, r.suite)
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
		fmt.Fprintf(&logBuf, "[%s] %s/%s/%s | exp=%s | got=%s | hex=%s\n", r.status, r.suite, r.category, r.name, r.expected, r.observed, r.wireHex)
	}

	for _, sName := range suiteOrder {
		c := bySuite[sName]
		fmt.Printf("  %-18s: PASS=%3d  FAIL=%3d  WARN=%2d  INFO=%2d\n", sName, c.pass, c.fail, c.warn, c.info)
	}
	fmt.Printf("\nTOTAL FAILURES: %d | WARNINGS: %d | INFO: %d\n", len(fails), len(warns), len(infos))
	if len(fails) > 0 {
		fmt.Println("\n--- ALL FAILURES ---")
		for _, f := range fails {
			fmt.Printf("  [FAIL] %s/%s/%s\n         exp: %s\n         got: %s\n", f.suite, f.category, f.name, f.expected, f.observed)
		}
	}
	if len(warns) > 0 {
		fmt.Println("\n--- ALL WARNINGS ---")
		for _, w := range warns {
			fmt.Printf("  [WARN] %s/%s/%s | exp=%s | got=%s\n", w.suite, w.category, w.name, w.expected, w.observed)
		}
	}
	if len(infos) > 0 {
		fmt.Println("\n--- ALL INFO / ORACLE OBSERVATIONS ---")
		for _, in := range infos {
			fmt.Printf("  [INFO] %s/%s/%s | exp=%s | got=%s\n", in.suite, in.category, in.name, in.expected, in.observed)
		}
	}

	if logDir != "" {
		logPath := filepath.Join(logDir, "results.log")
		_ = os.WriteFile(logPath, []byte(logBuf.String()), 0600)
		fmt.Printf("\n[+] Full wire log written to %s\n", logPath)
	}
	if *flagAll {
		runRound2Suite(pki)
	}
}
