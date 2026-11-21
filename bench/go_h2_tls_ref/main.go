// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type apiResponse struct {
	ID            string `json:"id"`
	Region        string `json:"region"`
	Authenticated bool   `json:"authenticated"`
	Engine        string `json:"engine"`
	Proto         string `json:"proto"`
}

type memStatsSnap struct {
	TotalAlloc  uint64 `json:"total_alloc"`
	Mallocs     uint64 `json:"mallocs"`
	Frees       uint64 `json:"frees"`
	HeapInuse   uint64 `json:"heap_inuse"`
	HeapObjects uint64 `json:"heap_objects"`
	Sys         uint64 `json:"sys"`
}

func makeSelfSignedCert() (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now,
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        leaf,
	}, nil
}

func runServer(port int) error {
	cert, err := makeSelfSignedCert()
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /plaintext", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("Hello, HTTP/2 over TLS 1.3!"))
	})
	mux.HandleFunc("GET /json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":200,"message":"ok","engine":"go-net-http","protocol":"h2","tls":"1.3"}`))
	})
	mux.HandleFunc("GET /api/v1/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		region := r.Header.Get("X-Client-Region")
		if region == "" {
			region = "unknown"
		}
		payload, _ := json.Marshal(apiResponse{
			ID:            r.PathValue("id"),
			Region:        region,
			Authenticated: r.Header.Get("Authorization") != "",
			Engine:        "go-net-http",
			Proto:         "h2",
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Engine", "go-net-http")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(payload)
	})
	mux.HandleFunc("GET /__memstats", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("gc") == "1" {
			runtime.GC()
		}
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(memStatsSnap{
			TotalAlloc:  ms.TotalAlloc,
			Mallocs:     ms.Mallocs,
			Frees:       ms.Frees,
			HeapInuse:   ms.HeapInuse,
			HeapObjects: ms.HeapObjects,
			Sys:         ms.Sys,
		})
	})

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	actualPort := ln.Addr().(*net.TCPAddr).Port

	srv := &http.Server{
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	fmt.Printf("SERVER_READY port=%d\n", actualPort)
	return srv.ServeTLS(ln, "", "")
}

func runHTTP1Server(port int) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("PONG"))
	})
	mux.HandleFunc("GET /api/v1/items/{id}", func(w http.ResponseWriter, r *http.Request) {
		region := r.Header.Get("X-Client-Region")
		if region == "" {
			region = "unknown"
		}
		payload, _ := json.Marshal(struct {
			ID     string `json:"id"`
			Region string `json:"region"`
			Engine string `json:"engine"`
		}{
			ID:     r.PathValue("id"),
			Region: region,
			Engine: "go-net-http",
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	})
	mux.HandleFunc("GET /__memstats", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("gc") == "1" {
			runtime.GC()
		}
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(memStatsSnap{
			TotalAlloc:  ms.TotalAlloc,
			Mallocs:     ms.Mallocs,
			Frees:       ms.Frees,
			HeapInuse:   ms.HeapInuse,
			HeapObjects: ms.HeapObjects,
			Sys:         ms.Sys,
		})
	})

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	actualPort := ln.Addr().(*net.TCPAddr).Port
	srv := &http.Server{Handler: mux}
	fmt.Printf("SERVER_READY port=%d\n", actualPort)
	return srv.Serve(ln)
}

func runGet(targetURL string) error {
	c := makeH2Client()
	resp, err := c.Get(targetURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	_, err = os.Stdout.Write(body)
	return err
}

func makeH2Client() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // benchmark loopback cert
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			NextProtos:         []string{"h2"},
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     60 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
	}
}

func runLoadgen(targetURL string, conns, streams, totalReqs, warmup int) error {
	if conns <= 0 {
		conns = 1
	}
	if streams <= 0 {
		streams = 1
	}
	clients := make([]*http.Client, conns)
	for i := 0; i < conns; i++ {
		clients[i] = makeH2Client()
	}

	doOne := func(c *http.Client) (int64, error) {
		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("X-Client-Region", "eu-central-1")
		req.Header.Set("Authorization", "Bearer bench-token-42")
		req.Header.Set("Accept", "application/json")
		t0 := time.Now()
		resp, err := c.Do(req)
		if err != nil {
			return 0, err
		}
		_, err = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return 0, err
		}
		if resp.StatusCode != 200 {
			return 0, fmt.Errorf("unexpected status %d", resp.StatusCode)
		}
		if resp.ProtoMajor != 2 {
			return 0, fmt.Errorf("expected HTTP/2, got %s", resp.Proto)
		}
		return time.Since(t0).Nanoseconds(), nil
	}

	// Warmup all C connections and M streams first
	var warmWG sync.WaitGroup
	var firstErr atomic.Value
	for c := 0; c < conns; c++ {
		warmWG.Add(1)
		go func(cl *http.Client) {
			defer warmWG.Done()
			for w := 0; w < warmup; w++ {
				if _, err := doOne(cl); err != nil {
					firstErr.CompareAndSwap(nil, err)
					return
				}
			}
		}(clients[c])
	}
	warmWG.Wait()
	if v := firstErr.Load(); v != nil {
		return v.(error)
	}

	workers := conns * streams
	latencies := make([]int64, totalReqs)
	var nextIdx atomic.Int64
	var wg sync.WaitGroup

	tStart := time.Now()
	for w := 0; w < workers; w++ {
		cl := clients[w%conns]
		wg.Add(1)
		go func(c *http.Client) {
			defer wg.Done()
			for {
				idx := int(nextIdx.Add(1) - 1)
				if idx >= totalReqs {
					return
				}
				dt, err := doOne(c)
				if err != nil {
					firstErr.CompareAndSwap(nil, err)
					return
				}
				latencies[idx] = dt
			}
		}(cl)
	}
	wg.Wait()
	elapsed := time.Since(tStart)
	if v := firstErr.Load(); v != nil {
		return v.(error)
	}

	for _, cl := range clients {
		cl.CloseIdleConnections()
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	n := len(latencies)
	pct := func(num, den int) float64 {
		idx := (n * num) / den
		if idx >= n {
			idx = n - 1
		}
		return float64(latencies[idx]) / 1e6
	}
	elapsedMs := float64(elapsed.Nanoseconds()) / 1e6
	if elapsedMs <= 0.001 {
		elapsedMs = 0.001
	}
	rps := float64(n) / elapsed.Seconds()

	fmt.Printf(
		"LOADGEN_RESULT requests=%d elapsed_ms=%.2f rps=%.0f p50_ms=%.3f p90_ms=%.3f p99_ms=%.3f p999_ms=%.3f min_ms=%.3f max_ms=%.3f\n",
		n, elapsedMs, rps,
		pct(50, 100), pct(90, 100), pct(99, 100), pct(999, 1000),
		float64(latencies[0])/1e6, float64(latencies[n-1])/1e6,
	)
	return nil
}

func main() {
	serverPort := flag.Int("server", 0, "listen port for H2+TLS server")
	http1Port := flag.Int("http1-server", 0, "listen port for plaintext HTTP/1.1 server")
	getURL := flag.String("get", "", "fetch single URL and print response body")
	loadgenURL := flag.String("loadgen", "", "target URL for H2+TLS loadgen")
	conns := flag.Int("conns", 8, "number of distinct TLS/H2 TCP connections")
	streams := flag.Int("streams", 4, "concurrent streams per connection")
	requests := flag.Int("requests", 4000, "total measured requests")
	warmup := flag.Int("warmup", 16, "warmup requests per connection")
	flag.Parse()

	if *serverPort > 0 {
		if err := runServer(*serverPort); err != nil {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *http1Port > 0 {
		if err := runHTTP1Server(*http1Port); err != nil {
			fmt.Fprintf(os.Stderr, "http1 server error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *getURL != "" {
		if err := runGet(*getURL); err != nil {
			fmt.Fprintf(os.Stderr, "get error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *loadgenURL != "" {
		if err := runLoadgen(*loadgenURL, *conns, *streams, *requests, *warmup); err != nil {
			fmt.Fprintf(os.Stderr, "loadgen error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	fmt.Fprintln(os.Stderr, "Usage: go_h2_tls_ref --server <port> | --http1-server <port> | --get <url> | --loadgen <url>")
	os.Exit(2)
}
