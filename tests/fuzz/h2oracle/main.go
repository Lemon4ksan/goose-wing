// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type ScenarioSpec struct {
	Name       string            `json:"name"`
	Target     string            `json:"target"`
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	UseCA      bool              `json:"use_ca"`
	GoVerdict  string            `json:"go_verdict"`
	GoCheckHdr map[string]string `json:"go_check_hdr,omitempty"`
}

type OracleManifest struct {
	CAPEM     string         `json:"ca_pem"`
	Ports     map[string]int `json:"ports"`
	Scenarios []ScenarioSpec `json:"scenarios"`
}

type caBundle struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func makeCA(cn string, serial int64) (*caBundle, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &caBundle{cert: cert, key: key, pem: string(pemBytes)}, nil
}

func makeLeaf(
	ca *caBundle,
	serial int64,
	cn string,
	dnsNames []string,
	ips []net.IP,
	notBefore, notAfter time.Time,
) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der, ca.cert.Raw},
		PrivateKey:  key,
	}, nil
}

func buildLargePayload(size int) []byte {
	out := make([]byte, size)
	const pat = "0123456789ABCDEF"
	for i := 0; i < size; i++ {
		out[i] = pat[i%len(pat)]
	}
	return out
}

func buildH2Handler() http.Handler {
	mux := http.NewServeMux()
	largePayload := buildLargePayload(36864)

	mux.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Oracle-Proto", r.Proto)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "hello-from-go-h2")
	})

	mux.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		if tag := r.Header.Get("X-Req-Tag"); tag != "" {
			w.Header().Set("X-Echo-Tag", tag)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "echo:%s:%s", r.Method, string(body))
	})

	mux.HandleFunc("/multi-header", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Alpha", "1")
		w.Header().Set("X-Beta", "two")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"multi":true}`)
	})

	mux.HandleFunc("/empty", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/missing", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "not-found-404")
	})

	mux.HandleFunc("/large", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(largePayload)
	})

	mux.HandleFunc("/h1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "hello-from-go-%s", r.Proto)
	})

	return mux
}

func startTLSServer(cert tls.Certificate, nextProtos []string, enableH2 bool, handler http.Handler) (int, io.Closer, error) {
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   nextProtos,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, err
	}
	protos := new(http.Protocols)
	protos.SetHTTP1(true)
	if enableH2 {
		protos.SetHTTP2(true)
	}
	srv := &http.Server{
		Handler:   handler,
		TLSConfig: tlsCfg,
		Protocols: protos,
	}
	if !enableH2 {
		srv.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	}

	go func() {
		_ = srv.ServeTLS(ln, "", "")
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	return port, srv, nil
}

func runGoProbe(sc ScenarioSpec, caPEM string) (string, map[string]string) {
	pool := x509.NewCertPool()
	if sc.UseCA {
		pool.AppendCertsFromPEM([]byte(caPEM))
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    pool,
	}
	tr := &http.Transport{
		TLSClientConfig:   tlsCfg,
		ForceAttemptHTTP2: true,
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}
	var bodyReader io.Reader
	if sc.Body != "" {
		bodyReader = bytes.NewBufferString(sc.Body)
	}
	req, err := http.NewRequest(sc.Method, sc.URL, bodyReader)
	if err != nil {
		return "ERR", nil
	}
	for k, v := range sc.Headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "ERR", nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "ERR", nil
	}
	sum := sha256.Sum256(body)
	proto := resp.Proto
	if proto == "HTTP/2.0" {
		proto = "HTTP/2"
	}
	hdrs := make(map[string]string)
	for k := range sc.GoCheckHdr {
		hdrs[strings.ToLower(k)] = resp.Header.Get(k)
	}
	return fmt.Sprintf("OK %s %d %d %s", proto, resp.StatusCode, len(body), hex.EncodeToString(sum[:])), hdrs
}

func main() {
	manifestPath := flag.String("manifest", "", "path to write JSON manifest")
	flag.Parse()
	if *manifestPath == "" {
		log.Fatal("-manifest is required")
	}

	trustedCA, err := makeCA("Wing Oracle Trusted Root", 1)
	if err != nil {
		log.Fatal(err)
	}
	untrustedCA, err := makeCA("Wing Oracle Untrusted Root", 2)
	if err != nil {
		log.Fatal(err)
	}

	now := time.Now().UTC()
	validLeaf, err := makeLeaf(
		trustedCA,
		10,
		"localhost",
		[]string{"localhost"},
		[]net.IP{net.ParseIP("127.0.0.1")},
		now.Add(-1*time.Hour),
		now.Add(24*time.Hour),
	)
	if err != nil {
		log.Fatal(err)
	}
	wrongSanLeaf, err := makeLeaf(
		trustedCA,
		11,
		"wrong.example",
		[]string{"wrong.example"},
		nil,
		now.Add(-1*time.Hour),
		now.Add(24*time.Hour),
	)
	if err != nil {
		log.Fatal(err)
	}
	expiredLeaf, err := makeLeaf(
		trustedCA,
		12,
		"localhost",
		[]string{"localhost"},
		[]net.IP{net.ParseIP("127.0.0.1")},
		now.Add(-48*time.Hour),
		now.Add(-24*time.Hour),
	)
	if err != nil {
		log.Fatal(err)
	}
	untrustedLeaf, err := makeLeaf(
		untrustedCA,
		13,
		"localhost",
		[]string{"localhost"},
		[]net.IP{net.ParseIP("127.0.0.1")},
		now.Add(-1*time.Hour),
		now.Add(24*time.Hour),
	)
	if err != nil {
		log.Fatal(err)
	}

	handler := buildH2Handler()
	h2Port, c1, err := startTLSServer(validLeaf, []string{"h2", "http/1.1"}, true, handler)
	if err != nil {
		log.Fatal(err)
	}
	defer c1.Close()

	h1Port, c2, err := startTLSServer(validLeaf, []string{"http/1.1"}, false, handler)
	if err != nil {
		log.Fatal(err)
	}
	defer c2.Close()

	wrongSanPort, c3, err := startTLSServer(wrongSanLeaf, []string{"h2", "http/1.1"}, true, handler)
	if err != nil {
		log.Fatal(err)
	}
	defer c3.Close()

	expiredPort, c4, err := startTLSServer(expiredLeaf, []string{"h2", "http/1.1"}, true, handler)
	if err != nil {
		log.Fatal(err)
	}
	defer c4.Close()

	untrustedPort, c5, err := startTLSServer(untrustedLeaf, []string{"h2", "http/1.1"}, true, handler)
	if err != nil {
		log.Fatal(err)
	}
	defer c5.Close()

	leafOnlyCert := validLeaf
	leafOnlyCert.Certificate = [][]byte{validLeaf.Certificate[0]}
	leafOnlyPort, c6, err := startTLSServer(leafOnlyCert, []string{"h2", "http/1.1"}, true, handler)
	if err != nil {
		log.Fatal(err)
	}
	defer c6.Close()

	scenarios := []ScenarioSpec{
		{
			Name:       "h2_get",
			Target:     "h2",
			Method:     "GET",
			URL:        fmt.Sprintf("https://localhost:%d/get", h2Port),
			UseCA:      true,
			GoCheckHdr: map[string]string{"content-type": "", "x-oracle-proto": ""},
		},
		{
			Name:       "h2_post_echo",
			Target:     "h2",
			Method:     "POST",
			URL:        fmt.Sprintf("https://localhost:%d/post", h2Port),
			Headers:    map[string]string{"X-Req-Tag": "alpha-99", "Content-Type": "text/plain"},
			Body:       "differential-payload-123",
			UseCA:      true,
			GoCheckHdr: map[string]string{"x-echo-tag": ""},
		},
		{
			Name:       "h2_multi_header",
			Target:     "h2",
			Method:     "GET",
			URL:        fmt.Sprintf("https://localhost:%d/multi-header", h2Port),
			UseCA:      true,
			GoCheckHdr: map[string]string{"x-alpha": "", "x-beta": "", "cache-control": ""},
		},
		{
			Name:   "h2_204_no_content",
			Target: "h2",
			Method: "GET",
			URL:    fmt.Sprintf("https://localhost:%d/empty", h2Port),
			UseCA:  true,
		},
		{
			Name:   "h2_404_not_found",
			Target: "h2",
			Method: "GET",
			URL:    fmt.Sprintf("https://localhost:%d/missing", h2Port),
			UseCA:  true,
		},
		{
			Name:   "h2_large_36k",
			Target: "h2",
			Method: "GET",
			URL:    fmt.Sprintf("https://localhost:%d/large", h2Port),
			UseCA:  true,
		},
		{
			Name:   "h1_alpn_fallback",
			Target: "h1",
			Method: "GET",
			URL:    fmt.Sprintf("https://localhost:%d/h1", h1Port),
			UseCA:  true,
		},
		{
			Name:       "h2_leaf_only_chain",
			Target:     "leaf_only",
			Method:     "GET",
			URL:        fmt.Sprintf("https://localhost:%d/get", leafOnlyPort),
			UseCA:      true,
			GoCheckHdr: map[string]string{"content-type": "", "x-oracle-proto": ""},
		},
		{
			Name:   "reject_untrusted_ca",
			Target: "untrusted",
			Method: "GET",
			URL:    fmt.Sprintf("https://localhost:%d/get", untrustedPort),
			UseCA:  true,
		},
		{
			Name:   "reject_no_ca",
			Target: "h2_noca",
			Method: "GET",
			URL:    fmt.Sprintf("https://localhost:%d/get", h2Port),
			UseCA:  false,
		},
		{
			Name:   "reject_wrong_san",
			Target: "wrong_san",
			Method: "GET",
			URL:    fmt.Sprintf("https://localhost:%d/get", wrongSanPort),
			UseCA:  true,
		},
		{
			Name:   "reject_expired_cert",
			Target: "expired",
			Method: "GET",
			URL:    fmt.Sprintf("https://localhost:%d/get", expiredPort),
			UseCA:  true,
		},
	}

	for i := range scenarios {
		verdict, hdrs := runGoProbe(scenarios[i], trustedCA.pem)
		scenarios[i].GoVerdict = verdict
		if len(hdrs) > 0 {
			scenarios[i].GoCheckHdr = hdrs
		}
	}

	manifest := OracleManifest{
		CAPEM: trustedCA.pem,
		Ports: map[string]int{
			"h2":        h2Port,
			"h1":        h1Port,
			"leaf_only": leafOnlyPort,
			"wrong_san": wrongSanPort,
			"expired":   expiredPort,
			"untrusted": untrustedPort,
		},
		Scenarios: scenarios,
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*manifestPath, raw, 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Println("READY")
	_, _ = io.Copy(io.Discard, os.Stdin)
}
