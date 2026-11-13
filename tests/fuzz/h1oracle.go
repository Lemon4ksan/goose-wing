// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/1.1 differential reference oracle backed by Go's net/http server.
// Reads one hex-encoded raw request per line from -cases and prints one
// verdict per line: "ok KIND LENGTH BODYHEX", "bodyerr KIND", "status N",
// or "noresponse".
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	cases := flag.String("cases", "", "file of hex-encoded requests, one a line")
	flag.Parse()
	if *cases == "" {
		fmt.Fprintln(os.Stderr, "h1oracle: -cases is required")
		os.Exit(2)
	}
	data, err := os.ReadFile(*cases)
	if err != nil {
		fmt.Fprintln(os.Stderr, "h1oracle:", err)
		os.Exit(1)
	}

	var addrs []string
	for i := 0; i < 16; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Fprintln(os.Stderr, "h1oracle:", err)
			os.Exit(1)
		}
		srv := &http.Server{Handler: http.HandlerFunc(handle), ReadTimeout: 5 * time.Second}
		go srv.Serve(ln)
		addrs = append(addrs, ln.Addr().String())
	}

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		req, err := hex.DecodeString(trimmed)
		if err != nil {
			fmt.Fprintln(os.Stderr, "h1oracle: bad case:", err)
			os.Exit(1)
		}
		fmt.Fprintln(out, verdict(addrs[i%len(addrs)], req))
	}
}

func handle(w http.ResponseWriter, r *http.Request) {
	kind := "none"
	if len(r.TransferEncoding) > 0 {
		kind = "chunked"
	} else if r.ContentLength > 0 {
		kind = "length"
	}
	body, err := io.ReadAll(r.Body)
	w.Header().Set("Connection", "close")
	if err != nil {
		fmt.Fprintf(w, "bodyerr %s", kind)
		return
	}
	fmt.Fprintf(w, "ok %s %d %x", kind, len(body), body)
}

func verdict(addr string, req []byte) string {
	var c net.Conn
	var err error
	for try := 0; try < 600; try++ {
		if c, err = net.Dial("tcp", addr); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "h1oracle: dial:", err)
		return "dialerr"
	}
	defer c.Close()
	if tcp, ok := c.(*net.TCPConn); ok {
		tcp.SetLinger(0)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	c.Write(req)
	if tcp, ok := c.(*net.TCPConn); ok {
		tcp.CloseWrite()
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return "noresponse"
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 200 && (strings.HasPrefix(string(b), "ok ") || strings.HasPrefix(string(b), "bodyerr ")) {
		return string(b)
	}
	return fmt.Sprintf("status %d", resp.StatusCode)
}
