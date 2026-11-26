// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func packH2Frame(frameType, flags byte, streamID uint32, payload []byte) []byte {
	n := len(payload)
	out := make([]byte, 9+n)
	out[0] = byte(n >> 16)
	out[1] = byte(n >> 8)
	out[2] = byte(n)
	out[3] = frameType
	out[4] = flags
	binary.BigEndian.PutUint32(out[5:9], streamID&0x7fffffff)
	copy(out[9:], payload)
	return out
}

const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// =========================================================================
// 9a. HTTP/1.1 OVER TLS 1.3 NEGATIVE / SMUGGLING TESTS (LIVE tls_server.exe)
// =========================================================================

func runH1OverTLSSuite(rec *testRecorder, addr, sni string) {
	fmt.Printf("\n================ HTTP/1.1 OVER TLS 1.3 NEGATIVE SUITE (%s) ================\n", addr)

	cases := []struct {
		name string
		raw  []byte
		exp  string
	}{
		{"cl_plus_te_chunked", []byte("POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"), "400 or close"},
		{"te_plus_cl", []byte("POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n"), "400 or close"},
		{"dup_conflicting_cl", []byte("POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\n1234567890"), "400 or close"},
		{"dup_identical_cl", []byte("POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n12345"), "400 or RFC 9112 reject/dedup"},
		{"space_before_colon_host", []byte("GET /secure-hello HTTP/1.1\r\nHost : " + sni + "\r\n\r\n"), "400 (RFC 9112 Section 5.1)"},
		{"space_before_colon_te", []byte("POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n"), "400"},
		{"bare_lf_request_line", []byte("GET /secure-hello HTTP/1.1\nHost: " + sni + "\r\n\r\n"), "400"},
		{"bare_lf_header", []byte("GET /secure-hello HTTP/1.1\r\nHost: " + sni + "\nX-A: 1\r\n\r\n"), "400"},
		{"bare_cr_header", []byte("GET /secure-hello HTTP/1.1\r\nHost: " + sni + "\rX-A: 1\r\n\r\n"), "400"},
		{"obs_fold_header", []byte("GET /secure-hello HTTP/1.1\r\nHost: " + sni + "\r\nX-Fold: a\r\n b\r\n\r\n"), "400 (RFC 9112 Section 5.2)"},
		{"nul_in_header_value", []byte("GET /secure-hello HTTP/1.1\r\nHost: " + sni + "\r\nX-Nul: a\x00b\r\n\r\n"), "400"},
		{"nul_in_request_target", []byte("GET /secure-hello\x00evil HTTP/1.1\r\nHost: " + sni + "\r\n\r\n"), "400"},
		{"missing_host_header", []byte("GET /secure-hello HTTP/1.1\r\nUser-Agent: test\r\n\r\n"), "400 (RFC 9112 Section 3.2)"},
		{"duplicate_host_header", []byte("GET /secure-hello HTTP/1.1\r\nHost: " + sni + "\r\nHost: evil.com\r\n\r\n"), "400 (RFC 9112 Section 3.2)"},
		{"negative_cl", []byte("POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nContent-Length: -5\r\n\r\n"), "400"},
		{"plus_sign_cl", []byte("POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nContent-Length: +5\r\n\r\n12345"), "400"},
		{"non_numeric_cl", []byte("POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nContent-Length: 5abc\r\n\r\n12345"), "400"},
		{"invalid_chunk_size_hex", []byte("POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\nhello\r\n0\r\n\r\n"), "400"},
		{"invalid_chunk_size_neg", []byte("POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\n\r\n0\r\n\r\n"), "400"},
		{"invalid_chunk_size_overflow", []byte("POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000000\r\na\r\n0\r\n\r\n"), "400"},
		{"invalid_chunk_missing_crlf", []byte("POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n"), "400"},
		{"bare_cr_in_chunk_ext", []byte("POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=a\rb\r\nhello\r\n0\r\n\r\n"), "400"},
		{"nul_in_chunk_ext", []byte("POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=a\x00b\r\nhello\r\n0\r\n\r\n"), "400"},
		{"chunk_size_0x_prefix", []byte("POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nTransfer-Encoding: chunked\r\n\r\n0x5\r\nhello\r\n0\r\n\r\n"), "400"},
		{"chunk_size_leading_sp", []byte("POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nTransfer-Encoding: chunked\r\n\r\n 5\r\nhello\r\n0\r\n\r\n"), "400"},
		{"te_unknown_xchunked", []byte("POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n"), "400/501"},
		{"te_chunked_identity", []byte("POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nTransfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n"), "400/501 (chunked not final)"},
		{"invalid_http_version_9_9", []byte("GET /secure-hello HTTP/9.9\r\nHost: " + sni + "\r\n\r\n"), "400/505"},
	}

	for _, tc := range cases {
		cfg := defaultHandshakeConfig(sni)
		cfg.alpn = []string{"http/1.1"}
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add("tls_h1", "h1_smug", tc.name, "FAIL", tc.exp, "handshake err: "+err.Error(), "")
			continue
		}
		_ = sess.sendAppData(tc.raw, false)
		resp, rerr := sess.readAppData(1500 * time.Millisecond)
		sess.close()

		if rerr != nil {
			// Closed / alert / EOF = rejected
			rec.add("tls_h1", "h1_smug", tc.name, "PASS", tc.exp, "closed/err: "+rerr.Error(), "")
			continue
		}
		respStr := string(resp)
		firstLine, _, _ := strings.Cut(respStr, "\r\n")
		is4xx5xx := strings.Contains(firstLine, " 4") || strings.Contains(firstLine, " 5")
		if tc.name == "dup_identical_cl" && strings.Contains(firstLine, " 200") {
			// RFC 9112 Section 6.3 permits collapsing identical Content-Length values.
			is4xx5xx = true
		}
		st := "PASS"
		if !is4xx5xx {
			st = "FAIL"
		}
		rec.add("tls_h1", "h1_smug", tc.name, st, tc.exp, fmt.Sprintf("resp=%q", truncStr(firstLine, 80)), "")
	}
}

// =========================================================================
// 9b. HTTP/2 NEGATIVE TESTS (OVER TLS 1.3 ALPN h2 AND CLEARTEXT h2spec_server.exe)
// =========================================================================

type h2TestCase struct {
	name      string
	send      []byte
	expectRej bool // expects GOAWAY, RST_STREAM, or close (NOT 200 OK!)
	expNote   string
}

func buildH2NegativeCases(sni string) []h2TestCase {
	validSettings := packH2Frame(0x04, 0x00, 0, nil)
	validHpackGET := func(path string) []byte {
		b := []byte{0x82, 0x87, 0x04, byte(len(path))}
		b = append(b, path...)
		b = append(b, 0x01, byte(len(sni)))
		b = append(b, sni...)
		return b
	}

	return []h2TestCase{
		{"invalid_preface", []byte("PRI * HTTP/1.1\r\n\r\nSM\r\n\r\n"), true, "GOAWAY/close on invalid preface"},
		{"headers_stream_0", append([]byte(h2Preface), append(validSettings, packH2Frame(0x01, 0x05, 0, validHpackGET("/secure-hello"))...)...), true, "PROTOCOL_ERROR (HEADERS on stream 0)"},
		{"data_stream_0", append([]byte(h2Preface), append(validSettings, packH2Frame(0x00, 0x01, 0, []byte("abc"))...)...), true, "PROTOCOL_ERROR (DATA on stream 0)"},
		{"even_stream_id_2", append([]byte(h2Preface), append(validSettings, packH2Frame(0x01, 0x05, 2, validHpackGET("/secure-hello"))...)...), true, "PROTOCOL_ERROR (even client stream ID 2)"},
		{"decreasing_stream_id_3_then_1", func() []byte {
			b := append([]byte(h2Preface), validSettings...)
			b = append(b, packH2Frame(0x01, 0x05, 3, validHpackGET("/secure-hello"))...)
			b = append(b, packH2Frame(0x01, 0x05, 1, validHpackGET("/secure-hello"))...)
			return b
		}(), true, "PROTOCOL_ERROR (decreasing stream ID)"},
		{"window_update_zero_stream_0", append([]byte(h2Preface), append(validSettings, packH2Frame(0x08, 0x00, 0, []byte{0, 0, 0, 0})...)...), true, "PROTOCOL_ERROR (WINDOW_UPDATE=0 on stream 0)"},
		{"window_update_zero_stream_1", func() []byte {
			b := append([]byte(h2Preface), validSettings...)
			b = append(b, packH2Frame(0x01, 0x04, 1, validHpackGET("/secure-hello"))...) // open stream 1
			b = append(b, packH2Frame(0x08, 0x00, 1, []byte{0, 0, 0, 0})...)
			return b
		}(), true, "PROTOCOL_ERROR/RST_STREAM (WINDOW_UPDATE=0 on stream 1)"},
		{"window_update_overflow", func() []byte {
			b := append([]byte(h2Preface), validSettings...)
			b = append(b, packH2Frame(0x08, 0x00, 0, []byte{0x7f, 0xff, 0xff, 0xff})...)
			b = append(b, packH2Frame(0x08, 0x00, 0, []byte{0x7f, 0xff, 0xff, 0xff})...)
			return b
		}(), true, "FLOW_CONTROL_ERROR (window > 2^31-1)"},
		{"continuation_interleave_ping", func() []byte {
			b := append([]byte(h2Preface), validSettings...)
			// HEADERS without END_HEADERS (flags=0x00) followed by PING!
			b = append(b, packH2Frame(0x01, 0x00, 1, []byte{0x82, 0x87})...)
			b = append(b, packH2Frame(0x06, 0x00, 0, []byte{1, 2, 3, 4, 5, 6, 7, 8})...)
			return b
		}(), true, "PROTOCOL_ERROR (interleaved frame during CONTINUATION)"},
		{"continuation_interleave_other_stream", func() []byte {
			b := append([]byte(h2Preface), validSettings...)
			b = append(b, packH2Frame(0x01, 0x00, 1, []byte{0x82, 0x87})...)
			b = append(b, packH2Frame(0x09, 0x04, 3, []byte{0x84})...)
			return b
		}(), true, "PROTOCOL_ERROR (CONTINUATION on wrong stream)"},
		{"unexpected_continuation", append([]byte(h2Preface), append(validSettings, packH2Frame(0x09, 0x04, 1, []byte{0x82})...)...), true, "PROTOCOL_ERROR (CONTINUATION without HEADERS)"},
		{"settings_nonzero_stream", append([]byte(h2Preface), packH2Frame(0x04, 0x00, 1, nil)...), true, "PROTOCOL_ERROR (SETTINGS on stream 1)"},
		{"settings_ack_nonempty", append([]byte(h2Preface), packH2Frame(0x04, 0x01, 0, []byte{0, 1, 0, 0, 0, 0})...), true, "FRAME_SIZE_ERROR (SETTINGS ACK with payload)"},
		{"settings_len_not_mult_6", append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, []byte{0, 1, 0, 0, 0})...), true, "FRAME_SIZE_ERROR (SETTINGS len=5)"},
		{"settings_max_frame_size_too_small", append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, []byte{0x00, 0x05, 0x00, 0x00, 0x3f, 0xff})...), true, "PROTOCOL_ERROR (MAX_FRAME_SIZE=16383)"},
		{"settings_max_frame_size_too_large", append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, []byte{0x00, 0x05, 0x01, 0x00, 0x00, 0x00})...), true, "PROTOCOL_ERROR (MAX_FRAME_SIZE=16777216)"},
		{"settings_enable_push_2", append([]byte(h2Preface), packH2Frame(0x04, 0x00, 0, []byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x02})...), true, "PROTOCOL_ERROR (ENABLE_PUSH=2)"},
		{"ping_nonzero_stream", append([]byte(h2Preface), append(validSettings, packH2Frame(0x06, 0x00, 1, make([]byte, 8))...)...), true, "PROTOCOL_ERROR (PING on stream 1)"},
		{"ping_bad_len_7", append([]byte(h2Preface), append(validSettings, packH2Frame(0x06, 0x00, 0, make([]byte, 7))...)...), true, "FRAME_SIZE_ERROR (PING len=7)"},
		{"rst_stream_0", append([]byte(h2Preface), append(validSettings, packH2Frame(0x03, 0x00, 0, []byte{0, 0, 0, 0})...)...), true, "PROTOCOL_ERROR (RST_STREAM on stream 0)"},
		{"priority_self_dep", append([]byte(h2Preface), append(validSettings, packH2Frame(0x02, 0x00, 1, []byte{0, 0, 0, 1, 16})...)...), true, "PROTOCOL_ERROR (PRIORITY self-dependency)"},
		{"hpack_index_0", append([]byte(h2Preface), append(validSettings, packH2Frame(0x01, 0x05, 1, []byte{0x80})...)...), true, "COMPRESSION_ERROR (HPACK index 0)"},
		{"hpack_oob_index", append([]byte(h2Preface), append(validSettings, packH2Frame(0x01, 0x05, 1, []byte{0xfe})...)...), true, "COMPRESSION_ERROR (HPACK index 126 > table)"},
		{"hpack_bad_huffman_padding", append([]byte(h2Preface), append(validSettings, packH2Frame(0x01, 0x05, 1, []byte{0x82, 0x87, 0x04, 0x81, 0x00})...)...), true, "COMPRESSION_ERROR (invalid Huffman non-1s padding)"},
		{"h2_uppercase_header_name", func() []byte {
			hb := validHpackGET("/secure-hello")
			hb = append(hb, 0x00, 0x05)
			hb = append(hb, "X-Bad"...)
			hb = append(hb, 0x01, '1')
			return append([]byte(h2Preface), append(validSettings, packH2Frame(0x01, 0x05, 1, hb)...)...)
		}(), true, "PROTOCOL_ERROR (uppercase header name in H2)"},
		{"h2_connection_header_forbidden", func() []byte {
			hb := validHpackGET("/secure-hello")
			hb = append(hb, 0x00, byte(len("connection")))
			hb = append(hb, "connection"...)
			hb = append(hb, byte(len("keep-alive")))
			hb = append(hb, "keep-alive"...)
			return append([]byte(h2Preface), append(validSettings, packH2Frame(0x01, 0x05, 1, hb)...)...)
		}(), true, "PROTOCOL_ERROR (RFC 9113 Section 8.2.2 forbids Connection header)"},
		{"h2_te_chunked_forbidden", func() []byte {
			hb := validHpackGET("/secure-hello")
			hb = append(hb, 0x00, 0x02, 't', 'e', 0x07)
			hb = append(hb, "chunked"...)
			return append([]byte(h2Preface), append(validSettings, packH2Frame(0x01, 0x05, 1, hb)...)...)
		}(), true, "PROTOCOL_ERROR (RFC 9113 Section 8.2.2 forbids TE != trailers)"},
		{"h2_duplicate_method_pseudo", func() []byte {
			hb := append([]byte{0x82, 0x82, 0x87, 0x84}, 0x01, byte(len(sni)))
			hb = append(hb, sni...)
			return append([]byte(h2Preface), append(validSettings, packH2Frame(0x01, 0x05, 1, hb)...)...)
		}(), true, "PROTOCOL_ERROR (duplicate :method pseudo-header)"},
	}
}

func summarizeH2Frames(raw []byte) (hasGoaway, hasRst, hasRespHeaders bool, summary string) {
	var parts []string
	off := 0
	for off+9 <= len(raw) {
		n := int(raw[off])<<16 | int(raw[off+1])<<8 | int(raw[off+2])
		ft := raw[off+3]
		fl := raw[off+4]
		sid := binary.BigEndian.Uint32(raw[off+5:off+9]) & 0x7fffffff
		off += 9
		if off+n > len(raw) {
			parts = append(parts, fmt.Sprintf("TRUNC(type=%d,need=%d,have=%d)", ft, n, len(raw)-off))
			break
		}
		pl := raw[off : off+n]
		off += n
		switch ft {
		case 0x04:
			parts = append(parts, fmt.Sprintf("SETTINGS(fl=%x,len=%d)", fl, n))
		case 0x07:
			hasGoaway = true
			var errCode uint32
			if len(pl) >= 8 {
				errCode = binary.BigEndian.Uint32(pl[4:8])
			}
			parts = append(parts, fmt.Sprintf("GOAWAY(err=0x%x)", errCode))
		case 0x03:
			hasRst = true
			var errCode uint32
			if len(pl) >= 4 {
				errCode = binary.BigEndian.Uint32(pl[0:4])
			}
			parts = append(parts, fmt.Sprintf("RST_STREAM(sid=%d,err=0x%x)", sid, errCode))
		case 0x01:
			hasRespHeaders = true
			parts = append(parts, fmt.Sprintf("HEADERS(sid=%d,len=%d)", sid, n))
		case 0x00:
			parts = append(parts, fmt.Sprintf("DATA(sid=%d,len=%d)", sid, n))
		case 0x06:
			parts = append(parts, fmt.Sprintf("PING(fl=%x)", fl))
		case 0x08:
			parts = append(parts, fmt.Sprintf("WIN_UPD(sid=%d)", sid))
		default:
			parts = append(parts, fmt.Sprintf("F%d(sid=%d,len=%d)", ft, sid, n))
		}
	}
	if len(parts) == 0 {
		return false, false, false, fmt.Sprintf("raw(%dB)=%x", len(raw), raw[:minInt(len(raw), 24)])
	}
	return hasGoaway, hasRst, hasRespHeaders, strings.Join(parts, "+")
}

func runH2OverTLSSuite(rec *testRecorder, addr, sni string) {
	fmt.Printf("\n================ HTTP/2 OVER TLS 1.3 NEGATIVE SUITE (%s) ================\n", addr)
	for _, tc := range buildH2NegativeCases(sni) {
		cfg := defaultHandshakeConfig(sni)
		cfg.alpn = []string{"h2"}
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add("tls_h2", "h2_neg", tc.name, "FAIL", tc.expNote, "handshake err: "+err.Error(), "")
			continue
		}
		_ = sess.sendAppData(tc.send, false)
		var all []byte
		var lastErr error
		for range 6 {
			chunk, rerr := sess.readAppData(500 * time.Millisecond)
			if len(chunk) > 0 {
				all = append(all, chunk...)
			}
			if rerr != nil {
				lastErr = rerr
				break
			}
			g, r, _, _ := summarizeH2Frames(all)
			if g || r {
				break
			}
		}
		sess.close()
		hasGoaway, hasRst, hasHdrs, sum := summarizeH2Frames(all)
		// Rejected if GOAWAY, RST_STREAM, or connection closed without serving HEADERS!
		// Special case: decreasing_stream_id sends valid stream 3 first (so stream 3 might get HEADERS), then invalid stream 1 MUST get GOAWAY/RST!
		rejected := hasGoaway || hasRst || (!hasHdrs && lastErr != nil)
		if tc.name == "decreasing_stream_id_3_then_1" {
			rejected = hasGoaway || hasRst
		}
		st := "PASS"
		if tc.expectRej && !rejected {
			st = "FAIL"
		}
		obs := fmt.Sprintf("frames=[%s] err=%v", sum, lastErr)
		rec.add("tls_h2", "h2_neg", tc.name, st, tc.expNote, obs, "")
	}
}

func runH2SpecServerSuite(rec *testRecorder, addr string) {
	fmt.Printf("\n================ CLEARTEXT h2spec_server.exe NEGATIVE SUITE (%s) ================\n", addr)
	for _, tc := range buildH2NegativeCases("127.0.0.1") {
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			rec.add("h2spec_srv", "h2_neg", tc.name, "FAIL", tc.expNote, "dial err: "+err.Error(), "")
			continue
		}
		_, _ = conn.Write(tc.send)
		var all []byte
		var lastErr error
		buf := make([]byte, 4096)
		for range 6 {
			_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			n, rerr := conn.Read(buf)
			if n > 0 {
				all = append(all, buf[:n]...)
			}
			if rerr != nil {
				lastErr = rerr
				break
			}
			g, r, _, _ := summarizeH2Frames(all)
			if g || r {
				break
			}
		}
		_ = conn.Close()
		hasGoaway, hasRst, hasHdrs, sum := summarizeH2Frames(all)
		rejected := hasGoaway || hasRst || (!hasHdrs && lastErr != nil)
		if tc.name == "decreasing_stream_id_3_then_1" {
			rejected = hasGoaway || hasRst
		}
		st := "PASS"
		if tc.expectRej && !rejected {
			st = "FAIL"
		}
		obs := fmt.Sprintf("frames=[%s] err=%v", sum, lastErr)
		rec.add("h2spec_srv", "h2_neg", tc.name, st, tc.expNote, obs, "")
	}
}

// =========================================================================
// 9c. OFFLINE HTTP/1.1 SMUGGLING HARNESSES (smuggling_wing.exe & smuggling_wing_h1.exe)
// =========================================================================

func runSmugglingHarnessSuite(rec *testRecorder, wingExe, wingH1Exe, scratchDir string) {
	fmt.Printf("\n================ SMUGGLING HARNESS DIFFERENTIAL SUITE ================\n")
	type smugVec struct {
		name         string
		raw          []byte
		expectAccept bool
	}
	vecs := []smugVec{
		{"valid_get", []byte("GET / HTTP/1.1\r\nHost: a.com\r\n\r\n"), true},
		{"valid_post_cl", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nContent-Length: 5\r\n\r\nhello"), true},
		{"valid_post_chunked", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"), true},
		{"cl_te_smug", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"), false},
		{"te_cl_smug", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n"), false},
		{"te_obf_leading_space", []byte("POST / HTTP/1.1\r\nHost: a.com\r\n Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n12345"), false},
		{"te_obf_space_before_colon", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n"), false},
		{"te_obf_tab_before_colon", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nTransfer-Encoding\t: chunked\r\n\r\n0\r\n\r\n"), false},
		{"te_obf_vtab_value", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nTransfer-Encoding: \x0bchunked\r\n\r\n0\r\n\r\n"), false},
		{"te_double_chunked", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nTransfer-Encoding: chunked, chunked\r\n\r\n0\r\n\r\n"), false},
		{"te_chunked_then_gzip", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n"), false},
		{"cl_conflict", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n123456"), false},
		{"cl_comma_conflict", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nContent-Length: 5, 6\r\n\r\n123456"), false},
		{"cl_plus_sign", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nContent-Length: +5\r\n\r\n12345"), false},
		{"cl_minus_sign", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nContent-Length: -5\r\n\r\n"), false},
		{"cl_hex_value", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nContent-Length: 0x5\r\n\r\n12345"), false},
		{"cl_trailing_tab_junk", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nContent-Length: 5 0\r\n\r\n12345"), false},
		{"bare_lf_reqline", []byte("GET / HTTP/1.1\nHost: a.com\r\n\r\n"), false},
		{"bare_lf_header", []byte("GET / HTTP/1.1\r\nHost: a.com\nX-A: b\r\n\r\n"), false},
		{"bare_cr_in_header", []byte("GET / HTTP/1.1\r\nHost: a.com\r\nX-A: b\rc\r\n\r\n"), false},
		{"bare_cr_in_chunk_ext", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=a\rb\r\nhello\r\n0\r\n\r\n"), false},
		{"nul_in_chunk_ext", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=a\x00b\r\nhello\r\n0\r\n\r\n"), false},
		{"chunk_size_0x_prefix", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nTransfer-Encoding: chunked\r\n\r\n0x5\r\nhello\r\n0\r\n\r\n"), false},
		{"chunk_size_leading_sp", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nTransfer-Encoding: chunked\r\n\r\n 5\r\nhello\r\n0\r\n\r\n"), false},
		{"chunk_size_plus", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n"), false},
		{"chunk_bare_lf_term", []byte("POST / HTTP/1.1\r\nHost: a.com\r\nTransfer-Encoding: chunked\r\n\r\n5\nhello\n0\n\n"), false},
		{"obs_fold", []byte("GET / HTTP/1.1\r\nHost: a.com\r\nX-Fold: a\r\n b\r\n\r\n"), false},
		{"missing_host", []byte("GET / HTTP/1.1\r\nX-A: 1\r\n\r\n"), false},
		{"duplicate_host", []byte("GET / HTTP/1.1\r\nHost: a.com\r\nHost: b.com\r\n\r\n"), false},
		{"ctl_del_in_header_val", []byte("GET / HTTP/1.1\r\nHost: a.com\r\nX-Del: a\x7fb\r\n\r\n"), false},
		{"nul_in_header_name", []byte("GET / HTTP/1.1\r\nHost: a.com\r\nX-\x00Bad: 1\r\n\r\n"), false},
		{"sp_in_target", []byte("GET /a b HTTP/1.1\r\nHost: a.com\r\n\r\n"), false},
	}

	tsvPath := filepath.Join(scratchDir, "smug_vectors.tsv")
	var sb strings.Builder
	for _, v := range vecs {
		sb.WriteString(v.name)
		sb.WriteByte('\t')
		sb.WriteString(hex.EncodeToString(v.raw))
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(tsvPath, []byte(sb.String()), 0600); err != nil {
		rec.add("smuggling", "setup", "write_tsv", "FAIL", "write tsv", err.Error(), "")
		return
	}

	runOne := func(exe string) map[string][]string {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, exe, tsvPath).CombinedOutput()
		res := map[string][]string{}
		if err != nil {
			fmt.Printf("smuggling harness %s err: %v out=%s\n", exe, err, string(out))
		}
		for line := range strings.SplitSeq(string(out), "\n") {
			cols := strings.Split(strings.TrimSpace(line), "\t")
			if len(cols) >= 7 {
				res[cols[0]] = cols
			}
		}
		return res
	}
	wRes := runOne(wingExe)
	hRes := runOne(wingH1Exe)

	for _, v := range vecs {
		wc := wRes[v.name]
		hc := hRes[v.name]
		if wc == nil || hc == nil {
			rec.add("smuggling", "h1_wall", v.name, "FAIL", "harness output", fmt.Sprintf("wing=%v h1=%v", wc != nil, hc != nil), "")
			continue
		}
		wAcc := wc[1] == "ACCEPT"
		hAcc := hc[1] == "ACCEPT"
		parity := wAcc == hAcc && (!wAcc || (wc[2] == hc[2] && wc[6] == hc[6]))
		ok := parity && (wAcc == v.expectAccept)
		st := "PASS"
		if !ok {
			st = "FAIL"
		}
		exp := "REJECT (both)"
		if v.expectAccept {
			exp = "ACCEPT (both)"
		}
		obs := fmt.Sprintf("wing=%s(cons=%s,body=%s) h1=%s(cons=%s,body=%s) parity=%v", wc[1], wc[2], wc[6], hc[1], hc[2], hc[6], parity)
		rec.add("smuggling", "h1_wall", v.name, st, exp, obs, "")
	}
}

// =========================================================================
// 9d. LIVE UDP http3_server.exe NEGATIVE QUIC / HTTP/3 SUITE
// =========================================================================

func buildQUICInitial(ver uint32, dcid, scid, token, payload []byte, padTo int, firstByte byte) []byte {
	var b []byte
	b = append(b, firstByte)
	b = binary.BigEndian.AppendUint32(b, ver)
	b = append(b, byte(len(dcid)))
	b = append(b, dcid...)
	b = append(b, byte(len(scid)))
	b = append(b, scid...)
	b = append(b, byte(len(token)))
	b = append(b, token...)
	b = append(b, byte(len(payload)))
	b = append(b, payload...)
	if len(b) < padTo {
		b = append(b, make([]byte, padTo-len(b))...)
	}
	return b
}

func sendUDPAndRecv(addr string, pkt []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.Write(pkt); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func runHTTP3ServerSuite(rec *testRecorder, http3Exe string) {
	srv, err := startManagedServer("http3_server", http3Exe, nil, nil, udpShutdown)
	if err != nil {
		rec.add("http3_srv", "setup", "start_server", "FAIL", "start", err.Error(), "")
		return
	}
	defer func() {
		if srv != nil {
			srv.stop()
		}
	}()
	addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
	fmt.Printf("\n================ LIVE UDP http3_server.exe NEGATIVE SUITE (%s) ================\n", addr)

	dcid := []byte{0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}
	scid := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	checkAliveOrRestart := func(afterTest string) (alive bool, deathNote string) {
		vn := buildQUICInitial(0x5a5a5a5a, dcid, scid, nil, []byte{0x01, '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}, 1200, 0xC0)
		resp, err := sendUDPAndRecv(addr, vn, 600*time.Millisecond)
		if err == nil && len(resp) >= 15 && binary.BigEndian.Uint32(resp[1:5]) == 0 {
			return true, ""
		}
		// Server died or hung!
		deathNote = fmt.Sprintf("SERVER_DIED_OR_HUNG after %s (vn_err=%v, stderr=%q)", afterTest, err, srv.getStderr())
		srv.stop()
		srv, err = startManagedServer("http3_server", http3Exe, nil, nil, udpShutdown)
		if err == nil {
			addr = fmt.Sprintf("127.0.0.1:%d", srv.port)
		}
		return false, deathNote
	}

	// Baseline 1: Version Negotiation
	{
		vn := buildQUICInitial(0x5a5a5a5a, dcid, scid, nil, []byte{0x01, '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}, 1200, 0xC0)
		resp, err := sendUDPAndRecv(addr, vn, 1500*time.Millisecond)
		if err == nil && len(resp) >= 15 && resp[0]&0x80 != 0 && binary.BigEndian.Uint32(resp[1:5]) == 0 {
			rec.add("http3_srv", "quic_base", "version_negotiation", "PASS", "VN packet (ver=0)", fmt.Sprintf("len=%d hex=%x", len(resp), resp[:minInt(len(resp), 28)]), "")
		} else {
			rec.add("http3_srv", "quic_base", "version_negotiation", "FAIL", "VN packet", fmt.Sprintf("err=%v len=%d", err, len(resp)), "")
		}
	}

	// Baseline 2: QUIC v1 Initial (1200B)
	{
		initPkt := buildQUICInitial(0x00000001, dcid, scid, nil, []byte{0x01, '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}, 1200, 0xC0)
		resp, err := sendUDPAndRecv(addr, initPkt, 1500*time.Millisecond)
		if err == nil && len(resp) >= 30 && resp[0]&0xC0 == 0xC0 && binary.BigEndian.Uint32(resp[1:5]) == 1 {
			rec.add("http3_srv", "quic_base", "quic_v1_initial_1200B", "PASS", "QUIC v1 Initial response", fmt.Sprintf("len=%d hex=%x", len(resp), resp[:minInt(len(resp), 28)]), "")
		} else {
			rec.add("http3_srv", "quic_base", "quic_v1_initial_1200B", "FAIL", "QUIC v1 Initial response", fmt.Sprintf("err=%v len=%d", err, len(resp)), "")
		}
	}

	// Negative QUIC / H3 packet matrix (checking liveness after EVERY SINGLE PACKET to pinpoint crashes!)
	negPackets := []struct {
		name          string
		pkt           []byte
		mustNotAccept bool
		expectDiscard bool
		expNote       string
	}{
		{"empty_0B_datagram", []byte{}, true, true, "ignore/discard empty datagram without crashing"},
		{"trunc_1B_long_hdr", []byte{0xC0}, true, true, "ignore 1B truncated header"},
		{"trunc_4B_long_hdr", []byte{0xC0, 0x00, 0x00, 0x00}, true, true, "ignore 4B truncated header"},
		{"trunc_6B_missing_dcid", []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0x08}, true, true, "ignore truncated DCID"},
		{"short_initial_100B", buildQUICInitial(0x00000001, dcid, scid, nil, []byte{0x01, 'a', 'b'}, 100, 0xC0), true, true, "RFC 9000 Section 14.1 MUST discard Initial < 1200B"},
		{"short_initial_1199B", buildQUICInitial(0x00000001, dcid, scid, nil, []byte{0x01, 'a', 'b'}, 1199, 0xC0), true, true, "RFC 9000 Section 14.1 MUST discard Initial == 1199B"},
		{"fixed_bit_zero_0x80", buildQUICInitial(0x00000001, dcid, scid, nil, []byte{0x01, 'a', 'b'}, 1200, 0x80), true, true, "RFC 9000 Section 17.2 fixed bit MUST be 1"},
		{"dcid_len_21_overflow", buildQUICInitial(0x00000001, bytes.Repeat([]byte{0xaa}, 21), scid, nil, []byte{0x01, 'a'}, 1200, 0xC0), true, true, "RFC 9000 Section 17.2 DCID len > 20 invalid in v1"},
		{"scid_len_21_overflow", buildQUICInitial(0x00000001, dcid, bytes.Repeat([]byte{0xbb}, 21), nil, []byte{0x01, 'a'}, 1200, 0xC0), true, true, "RFC 9000 Section 17.2 SCID len > 20 invalid in v1"},
		{"0rtt_packet_0xD0", buildQUICInitial(0x00000001, dcid, scid, nil, []byte("early-0rtt"), 1200, 0xD0), true, false, "reject/drop unsolicited 0-RTT"},
		{"handshake_pkt_before_init_0xE0", buildQUICInitial(0x00000001, dcid, scid, nil, []byte("hs-early"), 1200, 0xE0), true, false, "reject/drop Handshake before Initial"},
		{"retry_pkt_from_client_0xF0", buildQUICInitial(0x00000001, dcid, scid, nil, []byte("retry"), 1200, 0xF0), true, false, "reject/drop Retry from client"},
		{"short_hdr_bad_aead_tag", append([]byte{0x40}, bytes.Repeat([]byte{0xde}, 48)...), true, false, "reject/drop short header with invalid AEAD tag"},
		{"trunc_varint_token_len", func() []byte {
			b := []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0x08}
			b = append(b, dcid...)
			b = append(b, 0x08)
			b = append(b, scid...)
			b = append(b, 0xC0, 0x01) // 8-byte varint prefix truncated!
			return b
		}(), true, true, "reject truncated varint"},
		{"huge_varint_token_len", func() []byte {
			b := []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0x08}
			b = append(b, dcid...)
			b = append(b, 0x08)
			b = append(b, scid...)
			b = append(b, 0xBF, 0xFF, 0xFF, 0xFF) // 1GB token length!
			b = append(b, make([]byte, 1200)...)
			return b
		}(), true, true, "reject huge token length overflow"},
		{"h3_forbidden_h2_setting_0x02", []byte{0x04, 0x02, 0x02, 0x01}, true, false, "RFC 9114 Section 7.2.4 H3_SETTINGS_ERROR(0x0109)"},
		{"h3_forbidden_h2_setting_0x03", []byte{0x04, 0x02, 0x03, 0x64}, true, false, "RFC 9114 Section 7.2.4 H3_SETTINGS_ERROR(0x0109)"},
		{"h3_forbidden_h2_setting_0x04", []byte{0x04, 0x02, 0x04, 0x10}, true, false, "RFC 9114 Section 7.2.4 H3_SETTINGS_ERROR(0x0109)"},
		{"h3_forbidden_h2_setting_0x05", []byte{0x04, 0x02, 0x05, 0x10}, true, false, "RFC 9114 Section 7.2.4 H3_SETTINGS_ERROR(0x0109)"},
		{"h3_reserved_h2_frame_priority_0x02", []byte{0x02, 0x04, 0x00, 0x00, 0x00, 0x01}, true, false, "RFC 9114 Section 7.2.8 H3_FRAME_UNEXPECTED"},
		{"h3_reserved_h2_frame_ping_0x06", []byte{0x06, 0x08, 1, 2, 3, 4, 5, 6, 7, 8}, true, false, "RFC 9114 Section 7.2.8 H3_FRAME_UNEXPECTED"},
		{"h3_reserved_h2_frame_winupd_0x08", []byte{0x08, 0x04, 0, 0, 0, 1}, true, false, "RFC 9114 Section 7.2.8 H3_FRAME_UNEXPECTED"},
		{"h3_reserved_h2_frame_cont_0x09", []byte{0x09, 0x02, 0x00, 0x00}, true, false, "RFC 9114 Section 7.2.8 H3_FRAME_UNEXPECTED"},
		{"h3_duplicate_settings", []byte{0x04, 0x00, 0x04, 0x00}, true, false, "RFC 9114 Section 7.2.4 duplicate SETTINGS -> H3_FRAME_UNEXPECTED"},
		{"h3_data_before_headers", []byte{0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}, true, false, "DATA before HEADERS -> error/ignore"},
		{"h3_headers_huge_varint_len", []byte{0x01, 0xBF, 0xFF, 0xFF, 0xFF, 0x00, 0x00}, true, false, "truncated/huge H3 frame length"},
		{"h3_headers_malformed_qpack_bad_idx", []byte{0x01, 0x04, 0x00, 0x00, 0xff, 0x7f}, true, false, "malformed QPACK static index"},
		{"h3_headers_crlf_in_path", func() []byte {
			badPath := "/\r\nX-Injected: evil"
			qpack := []byte{0x00, 0x00, 0xd1, 0xd7, 0x51, byte(len(badPath))}
			qpack = append(qpack, badPath...)
			qpack = append(qpack, 0x50, 0x09)
			qpack = append(qpack, "127.0.0.1"...)
			return append([]byte{0x01, byte(len(qpack))}, qpack...)
		}(), true, false, "reject CRLF injection in H3 :path"},
	}

	for _, tc := range negPackets {
		resp, err := sendUDPAndRecv(addr, tc.pkt, 300*time.Millisecond)
		alive, deathNote := checkAliveOrRestart(tc.name)
		if !alive {
			rec.add("http3_srv", "quic_neg", tc.name, "FAIL", tc.expNote, deathNote, "")
			continue
		}
		if err != nil {
			rec.add("http3_srv", "quic_neg", tc.name, "PASS", tc.expNote, "discarded/timeout (server alive)", "")
			continue
		}
		isInitialReply := len(resp) >= 5 && (resp[0]&0xC0 == 0xC0) && binary.BigEndian.Uint32(resp[1:5]) == 1 && !bytes.Contains(resp, []byte("ERROR")) && !bytes.Contains(resp, []byte{0x1c})
		is200 := bytes.Contains(resp, []byte("200")) || (len(resp) >= 5 && resp[0] == 0x01 && bytes.Contains(resp, []byte{0xd9}))
		st := "PASS"
		if tc.expectDiscard && len(resp) > 0 {
			st = "FAIL"
		} else if tc.mustNotAccept && (isInitialReply || is200) {
			st = "FAIL"
		}
		rec.add("http3_srv", "quic_neg", tc.name, st, tc.expNote, fmt.Sprintf("resp(%dB) hex=%x ascii=%q", len(resp), resp[:minInt(len(resp), 28)], truncStr(string(resp), 40)), hex.EncodeToString(resp[:minInt(len(resp), 28)]))
	}
}

var _ = io.EOF
