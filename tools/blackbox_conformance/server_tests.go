// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

type testResult struct {
	suite    string
	category string
	name     string
	status   string // "PASS", "FAIL", "WARN", "INFO"
	expected string
	observed string
	wireHex  string
}

type testRecorder struct {
	results []testResult
}

func (r *testRecorder) add(suite, cat, name, status, exp, obs, wireHex string) {
	tr := testResult{
		suite: suite, category: cat, name: name,
		status: status, expected: exp, observed: obs, wireHex: wireHex,
	}
	r.results = append(r.results, tr)
	fmt.Printf("[%s] [%s/%s] %s | exp=%s | got=%s\n", status, suite, cat, name, exp, obs)
}

func probeServerHealth(addr, sni string, isPureGoose bool) error {
	cfg := defaultHandshakeConfig(sni)
	cfg.ciphers = []uint16{CipherAES128GCM}
	sess, err := doTLS13Handshake(addr, cfg)
	if err != nil {
		return err
	}
	defer sess.close()
	req := []byte("GET /secure-hello HTTP/1.1\r\nHost: " + sni + "\r\nConnection: close\r\n\r\n")
	if err := sess.sendAppData(req, false); err != nil {
		return err
	}
	resp, err := sess.readAppData(3 * time.Second)
	if err != nil {
		return err
	}
	if len(resp) == 0 {
		return fmt.Errorf("empty health response")
	}
	return nil
}

func sendRawAndClassify(addr string, payloads ...[]byte) wireOutcome {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return wireOutcome{kind: "DIAL_ERR", detail: err.Error()}
	}
	defer conn.Close()
	for _, p := range payloads {
		if _, err := conn.Write(p); err != nil {
			return wireOutcome{kind: "WRITE_ERR", detail: err.Error()}
		}
	}
	return classifyResponse(conn, nil, nil, 1500*time.Millisecond)
}

func isRejectedOutcome(o wireOutcome) bool {
	return o.kind == "ALERT" || o.kind == "ENC_ALERT" || o.kind == "EOF" || o.kind == "RST"
}

func runServerSuite(rec *testRecorder, suiteName, addr, sni string, isPureGoose bool, altEcdsaSNI string) {
	fmt.Printf("\n================ SERVER SUITE: %s (%s, sni=%s) ================\n", suiteName, addr, sni)

	// =========================================================================
	// 1. BASELINE TLS 1.3 CONFORMANCE
	// =========================================================================
	ciphers := []struct {
		name string
		id   uint16
	}{
		{"TLS_AES_128_GCM_SHA256", CipherAES128GCM},
		{"TLS_AES_256_GCM_SHA384", CipherAES256GCM},
		{"TLS_CHACHA20_POLY1305_SHA256", CipherChaCha20Poly1305},
	}
	for _, c := range ciphers {
		cfg := defaultHandshakeConfig(sni)
		cfg.ciphers = []uint16{c.id}
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add(suiteName, "baseline", "cipher_"+c.name, "FAIL", "handshake+app 200", err.Error(), "")
			continue
		}
		req := []byte("GET /secure-hello HTTP/1.1\r\nHost: " + sni + "\r\nConnection: close\r\n\r\n")
		err = sess.sendAppData(req, false)
		var resp []byte
		if err == nil {
			resp, err = sess.readAppData(3 * time.Second)
		}
		sess.close()
		if err != nil {
			rec.add(suiteName, "baseline", "cipher_"+c.name, "FAIL", "decrypted response", err.Error(), "")
			continue
		}
		ok := strings.Contains(string(resp), "200")
		if isPureGoose {
			ok = strings.Contains(string(resp), "EDGE_ECHO")
		}
		st := "PASS"
		if !ok {
			st = "FAIL"
		}
		rec.add(suiteName, "baseline", "cipher_"+c.name, st,
			fmt.Sprintf("cipher=0x%04x cvValid=true respOK", c.id),
			fmt.Sprintf("cipher=0x%04x cvSig=0x%04x alpn=%q resp=%q", sess.cipherID, sess.cvSigAlg, sess.negotiatedALPN, truncStr(string(resp), 80)), "")
	}

	// Test POST /secure-echo (default mode) or ECDSA SNI cert (--sni-map mode)
	if !isPureGoose {
		cfg := defaultHandshakeConfig(sni)
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add(suiteName, "baseline", "post_secure_echo", "FAIL", "200 echo", err.Error(), "")
		} else {
			req := "POST /secure-echo HTTP/1.1\r\nHost: " + sni + "\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello-world"
			_ = sess.sendAppData([]byte(req), false)
			var full []byte
			var rerr error
			for range 4 {
				chunk, err2 := sess.readAppData(1500 * time.Millisecond)
				if len(chunk) > 0 {
					full = append(full, chunk...)
				}
				if strings.Contains(string(full), "hello-world") || err2 != nil {
					rerr = err2
					break
				}
			}
			sess.close()
			if strings.Contains(string(full), "200") && (strings.Contains(string(full), "TLS_ECHO_OK") || strings.Contains(string(full), "hello-world")) {
				rec.add(suiteName, "baseline", "post_secure_echo", "PASS", "200 + TLS_ECHO_OK", truncStr(string(full), 100), "")
			} else {
				rec.add(suiteName, "baseline", "post_secure_echo", "FAIL", "200 + TLS_ECHO_OK", fmt.Sprintf("err=%v resp=%q", rerr, truncStr(string(full), 140)), "")
			}
		}
	} else if altEcdsaSNI != "" {
		cfg := defaultHandshakeConfig(altEcdsaSNI)
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add(suiteName, "baseline", "sni_ecdsa_p256_cert", "FAIL", "ECDSA P-256 cert + CV valid", err.Error(), "")
		} else {
			_ = sess.sendAppData([]byte("GET /secure-hello HTTP/1.1\r\nHost: "+altEcdsaSNI+"\r\nConnection: close\r\n\r\n"), false)
			resp, rerr := sess.readAppData(3 * time.Second)
			sess.close()
			if rerr == nil && strings.Contains(string(resp), "EDGE_ECHO") {
				rec.add(suiteName, "baseline", "sni_ecdsa_p256_cert", "PASS", "ECDSA CV valid + EDGE_ECHO", fmt.Sprintf("cvSig=0x%04x resp=%q", sess.cvSigAlg, truncStr(string(resp), 80)), "")
			} else {
				rec.add(suiteName, "baseline", "sni_ecdsa_p256_cert", "FAIL", "ECDSA EDGE_ECHO", fmt.Sprintf("err=%v resp=%q", rerr, truncStr(string(resp), 80)), "")
			}
		}
	}

	// Test P-256 key share (direct or HRR -> X25519)
	{
		cfg := defaultHandshakeConfig(sni)
		cfg.useP256KeyShare = true
		cfg.groups = []uint16{GroupP256, GroupX25519}
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add(suiteName, "baseline", "p256_keyshare_or_hrr", "INFO", "accept P-256 or HRR to X25519", err.Error(), "")
		} else {
			_ = sess.sendAppData([]byte("GET /secure-hello HTTP/1.1\r\nHost: "+sni+"\r\nConnection: close\r\n\r\n"), false)
			resp, rerr := sess.readAppData(3 * time.Second)
			sess.close()
			rec.add(suiteName, "baseline", "p256_keyshare_or_hrr", "PASS", "handshake ok", fmt.Sprintf("hrr=%v group=0x%04x err=%v respLen=%d", sess.isHRR, sess.selectedGroup, rerr, len(resp)), "")
		}
	}

	// Test valid RFC 8446 Section 5.4 trailing zero-padding on Client Finished
	{
		cfg := defaultHandshakeConfig(sni)
		cfg.customFinPad = 16
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add(suiteName, "baseline", "valid_zero_padded_finished", "FAIL", "accept 16B zero padding on Finished", err.Error(), "")
		} else {
			_ = sess.sendAppData([]byte("GET /secure-hello HTTP/1.1\r\nHost: "+sni+"\r\nConnection: close\r\n\r\n"), false)
			resp, rerr := sess.readAppData(3 * time.Second)
			sess.close()
			if rerr == nil && len(resp) > 0 {
				rec.add(suiteName, "baseline", "valid_zero_padded_finished", "PASS", "accept zero-padded Finished", fmt.Sprintf("respLen=%d", len(resp)), "")
			} else {
				rec.add(suiteName, "baseline", "valid_zero_padded_finished", "FAIL", "response after padded Finished", fmt.Sprintf("err=%v", rerr), "")
			}
		}
	}

	// Test valid 0-length encrypted ApplicationData followed by real request (RFC 8446 Section 5.1)
	{
		cfg := defaultHandshakeConfig(sni)
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add(suiteName, "baseline", "zero_len_encrypted_appdata", "FAIL", "handshake", err.Error(), "")
		} else {
			_ = sess.sendAppData([]byte{}, false)
			req := []byte("GET /secure-hello HTTP/1.1\r\nHost: " + sni + "\r\nConnection: close\r\n\r\n")
			_ = sess.sendAppData(req, false)
			resp, rerr := sess.readAppData(3 * time.Second)
			sess.close()
			if rerr == nil && len(resp) > 0 {
				rec.add(suiteName, "baseline", "zero_len_encrypted_appdata", "PASS", "allow 0-len appdata + serve next", truncStr(string(resp), 60), "")
			} else {
				rec.add(suiteName, "baseline", "zero_len_encrypted_appdata", "WARN", "RFC 8446 allows 0-len encrypted AppData", fmt.Sprintf("err=%v", rerr), "")
			}
		}
	}

	// Test valid client KeyUpdate (update_not_requested=0 and update_requested=1)
	for _, reqUpd := range []byte{0, 1} {
		cfg := defaultHandshakeConfig(sni)
		sess, err := doTLS13Handshake(addr, cfg)
		label := fmt.Sprintf("valid_key_update_req_%d", reqUpd)
		if err != nil {
			rec.add(suiteName, "baseline", label, "FAIL", "handshake", err.Error(), "")
			continue
		}
		kuMsg := makeHandshakeMsg(HSKeyUpdate, []byte{reqUpd})
		_, werr := sess.conn.Write(sess.appTx.sealRecord(RecHandshake, kuMsg))
		if werr == nil {
			sess.appTx, err = sess.appTx.ratchet()
		}
		if err == nil && werr == nil {
			req := []byte("GET /secure-hello HTTP/1.1\r\nHost: " + sni + "\r\nConnection: close\r\n\r\n")
			werr = sess.sendAppData(req, false)
		}
		resp, rerr := sess.readAppData(3 * time.Second)
		sess.close()
		if werr == nil && rerr == nil && len(resp) > 0 {
			rec.add(suiteName, "baseline", label, "PASS", "ratchet + app response", truncStr(string(resp), 60), "")
		} else {
			rec.add(suiteName, "baseline", label, "WARN", "RFC 8446 Section 4.6.3 KeyUpdate", fmt.Sprintf("werr=%v rerr=%v", werr, rerr), "")
		}
	}

	// Probe ALPN mismatch deeper: complete full handshake with unmatched ALPN to see what server negotiates!
	for _, badALPN := range []string{"h3", "unknown-proto/9.9"} {
		cfg := defaultHandshakeConfig(sni)
		cfg.alpn = []string{badALPN}
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add(suiteName, "downgrade", "alpn_mismatch_full_"+badALPN, "PASS", "reject with no_application_protocol(120)", err.Error(), "")
		} else {
			_ = sess.sendAppData([]byte("GET /secure-hello HTTP/1.1\r\nHost: "+sni+"\r\nConnection: close\r\n\r\n"), false)
			resp, rerr := sess.readAppData(2 * time.Second)
			sess.close()
			rec.add(suiteName, "downgrade", "alpn_mismatch_full_"+badALPN, "FAIL", "RFC 7301 Section 3.2 fatal no_application_protocol(120)",
				fmt.Sprintf("ACCEPTED handshake! negotiatedALPN=%q resp=%q err=%v", sess.negotiatedALPN, truncStr(string(resp), 48), rerr), "")
		}
	}

	// Test HTTP/2 over TLS 1.3 (ALPN h2) in default mode
	if !isPureGoose {
		cfg := defaultHandshakeConfig(sni)
		cfg.alpn = []string{"h2", "http/1.1"}
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add(suiteName, "baseline", "h2_over_tls13", "FAIL", "ALPN h2 + H2 response", err.Error(), "")
		} else {
			preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
			settings := packH2Frame(0x04, 0x00, 0, nil)
			// HPACK: :method GET (0x82), :scheme https (0x87), :path /secure-hello (0x04 + len + path), :authority sni (0x01 + len + sni)
			hpack := []byte{0x82, 0x87, 0x04, byte(len("/secure-hello"))}
			hpack = append(hpack, "/secure-hello"...)
			hpack = append(hpack, 0x01, byte(len(sni)))
			hpack = append(hpack, sni...)
			hdrs := packH2Frame(0x01, 0x05, 1, hpack) // END_STREAM | END_HEADERS
			_ = sess.sendAppData(append(append(preface, settings...), hdrs...), false)
			var all []byte
			for range 6 {
				chunk, rerr := sess.readAppData(1200 * time.Millisecond)
				if len(chunk) > 0 {
					all = append(all, chunk...)
				}
				if rerr != nil || bytes.Contains(all, []byte("hello")) || len(all) > 64 {
					break
				}
			}
			sess.close()
			if sess.negotiatedALPN == "h2" && len(all) >= 9 {
				rec.add(suiteName, "baseline", "h2_over_tls13", "PASS", "alpn=h2 + H2 frames", fmt.Sprintf("alpn=%q h2Bytes=%d hex=%x", sess.negotiatedALPN, len(all), all[:minInt(len(all), 32)]), "")
			} else {
				rec.add(suiteName, "baseline", "h2_over_tls13", "FAIL", "alpn=h2 + H2 frames", fmt.Sprintf("alpn=%q h2Bytes=%d", sess.negotiatedALPN, len(all)), "")
			}
		}
	}

	// =========================================================================
	// 2. DOWNGRADE ATTACKS
	// =========================================================================
	validX25519Key := func() []byte {
		k, _ := ecdh.X25519().GenerateKey(rand.Reader)
		return k.PublicKey().Bytes()
	}
	baseExts := func(overrideSNI string, overrideALPN []string, includeSV bool, svList []uint16, includeSigAlgs bool, sigAlgs []uint16) []rawExt {
		var exts []rawExt
		if overrideSNI != "-" {
			exts = append(exts, extSNI(overrideSNI))
		}
		if includeSV {
			exts = append(exts, extSupportedVersionsClient(svList...))
		}
		exts = append(exts, extSupportedGroups(GroupX25519, GroupP256))
		if includeSigAlgs {
			exts = append(exts, extSigAlgs(sigAlgs...))
		}
		if overrideALPN != nil {
			exts = append(exts, extALPN(overrideALPN...))
		}
		exts = append(exts, extKeyShareClient(keyShareEntry{group: GroupX25519, key: validX25519Key()}))
		return exts
	}

	downgradeCases := []struct {
		name    string
		recVer  uint16
		opts    clientHelloOpts
		mustRej bool
		expNote string
	}{
		{"ssl_3_0_clienthello", 0x0300, clientHelloOpts{legacyVer: 0x0300, ciphers: []uint16{0x002f}, omitExts: true}, true, "fatal alert (protocol_version/handshake_failure)"},
		{"tls_1_0_clienthello", 0x0301, clientHelloOpts{legacyVer: 0x0301, ciphers: []uint16{0x002f}, omitExts: true}, true, "fatal alert"},
		{"tls_1_1_clienthello", 0x0302, clientHelloOpts{legacyVer: 0x0302, ciphers: []uint16{0x002f}, omitExts: true}, true, "fatal alert"},
		{"tls_1_2_only_no_sv", 0x0301, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{0xc02f, CipherAES128GCM}, exts: baseExts(sni, []string{"http/1.1"}, false, nil, true, []uint16{SigEd25519, SigECDSAP256SHA256})}, true, "reject missing supported_versions"},
		{"tls_1_2_only_with_sv_0303", 0x0301, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{0xc02f, CipherAES128GCM}, exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0303}, true, []uint16{SigEd25519, SigECDSAP256SHA256})}, true, "reject TLS 1.2 supported_versions"},
		{"wrong_legacy_ver_0301_with_sv13", 0x0301, clientHelloOpts{legacyVer: 0x0301, ciphers: []uint16{CipherAES128GCM}, exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256})}, true, "reject ClientHello legacy_version != 0x0303"},
		{"wrong_legacy_ver_0304_with_sv13", 0x0301, clientHelloOpts{legacyVer: 0x0304, ciphers: []uint16{CipherAES128GCM}, exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256})}, true, "RFC 8446 Section 4.1.2 requires legacy_version==0x0303"},
		{"weak_cipher_null_0000", 0x0301, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{0x0000}, exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256})}, true, "reject NULL cipher"},
		{"weak_cipher_rc4_0004", 0x0301, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{0x0004}, exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256})}, true, "reject RC4 cipher"},
		{"weak_cipher_aes128cbc_002f", 0x0301, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{0x002f}, exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256})}, true, "reject TLS 1.2 CBC cipher"},
		{"weak_cipher_ecdhe_c02f", 0x0301, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{0xc02f}, exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256})}, true, "reject TLS 1.2 ECDHE-GCM cipher"},
		{"non_null_compression_01_00", 0x0301, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM}, compression: []byte{0x01, 0x00}, exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256})}, true, "RFC 8446 Section 4.1.2: compression must be {0x00}"},
		{"non_null_compression_01_only", 0x0301, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM}, compression: []byte{0x01}, exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256})}, true, "reject DEFLATE-only compression"},
		{"non_null_compression_00_01", 0x0301, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM}, compression: []byte{0x00, 0x01}, exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256})}, true, "RFC 8446 Section 4.1.2: len must be 1 with 0x00"},
		{"empty_compression", 0x0301, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM}, compression: []byte{}, exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256})}, true, "reject empty compression"},
		{"weak_sigalg_rsa_pkcs1_sha1", 0x0301, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM}, exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigRSAPKCS1SHA1})}, true, "reject rsa_pkcs1_sha1"},
		{"weak_sigalg_ecdsa_sha1", 0x0301, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM}, exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigECDSASHA1})}, true, "reject ecdsa_sha1"},
		{"missing_sigalg_ext", 0x0301, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM}, exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, false, nil)}, true, "RFC 8446 Section 4.2.3 requires signature_algorithms"},
		{"sni_mismatch", 0x0301, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM}, exts: baseExts("evil-unconfigured.invalid", []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256})}, isPureGoose, "unrecognized_name or fallback"},
		{"sni_nul_byte", 0x0301, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM}, exts: baseExts(sni+"\x00.evil.com", []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256})}, true, "reject NUL byte in SNI"},
		{"sni_ip_literal", 0x0301, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM}, exts: baseExts("127.0.0.1", []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256})}, true, "RFC 6066 Section 3 forbids IP literal in SNI"},
		{"alpn_mismatch", 0x0301, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM}, exts: baseExts(sni, []string{"unknown-proto/9.9"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256})}, true, "no_application_protocol(120)"},
		{"alpn_empty_entry", 0x0301, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM}, exts: append(baseExts(sni, nil, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256}), rawExt{typ: ExtALPN, body: []byte{0x00, 0x01, 0x00}})}, true, "reject 0-length ALPN entry"},
		{"record_ver_0304_on_ch", 0x0304, clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM}, exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256})}, true, "RFC 8446 Section 5.1: CH record version must be 0x0301 or 0x0303"},
	}

	for _, tc := range downgradeCases {
		ch := buildClientHelloMsg(tc.opts)
		out := sendRawAndClassify(addr, makeRecord(RecHandshake, tc.recVer, ch))
		st := "PASS"
		if tc.mustRej {
			if !isRejectedOutcome(out) {
				st = "FAIL"
			}
		} else {
			st = "INFO"
		}
		rec.add(suiteName, "downgrade", tc.name, st, tc.expNote, out.detail, hex.EncodeToString(out.raw[:minInt(len(out.raw), 24)]))
	}

	// =========================================================================
	// 3. ASYMMETRIC / SMALL-ORDER & INVALID KEY-SHARE POINTS (RFC 7748 / WYCHEPROOF)
	// =========================================================================
	x25519BadPoints := []struct {
		name string
		hex  string
		must bool
	}{
		{"x25519_loworder_1_zero", "0000000000000000000000000000000000000000000000000000000000000000", true},
		{"x25519_loworder_2_one", "0100000000000000000000000000000000000000000000000000000000000000", true},
		{"x25519_loworder_3_order8a", "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", true},
		{"x25519_loworder_4_order8b", "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", true},
		{"x25519_loworder_5_p_minus_1", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", true},
		{"x25519_loworder_6_p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", true},
		{"x25519_loworder_7_p_plus_1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", true},
		{"x25519_loworder_msb_2pow255", "0000000000000000000000000000000000000000000000000000000000000080", true},
		{"x25519_loworder_msb_one", "0100000000000000000000000000000000000000000000000000000000000080", true},
		{"x25519_loworder_msb_p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", true},
		// Non-canonical u-coordinates with valid base point (RFC 7748 allows clearing bit 255 / reducing mod p, record behavior!)
		{"x25519_noncanon_gen_msb_set", "0900000000000000000000000000000000000000000000000000000000000080", false},
		{"x25519_noncanon_p_plus_9", "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false},
		{"x25519_trunc_0B", "", true},
		{"x25519_trunc_16B", "09000000000000000000000000000000", true},
		{"x25519_trunc_31B", "09000000000000000000000000000000000000000000000000000000000000", true},
		{"x25519_oversize_33B", "090000000000000000000000000000000000000000000000000000000000000000", true},
	}
	for _, pt := range x25519BadPoints {
		kb, _ := hex.DecodeString(pt.hex)
		exts := []rawExt{
			extSNI(sni),
			extSupportedVersionsClient(0x0304),
			extSupportedGroups(GroupX25519),
			extSigAlgs(SigEd25519, SigECDSAP256SHA256),
			extALPN("http/1.1"),
			extKeyShareClient(keyShareEntry{group: GroupX25519, key: kb}),
		}
		ch := buildClientHelloMsg(clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM}, exts: exts})
		out := sendRawAndClassify(addr, makeRecord(RecHandshake, 0x0301, ch))
		st := "PASS"
		exp := "reject (fatal alert / close)"
		if !pt.must {
			st = "INFO"
			exp = "RFC 7748 masks bit 255 / reduces mod p (observe accept vs reject)"
		} else if !isRejectedOutcome(out) {
			st = "FAIL"
		}
		rec.add(suiteName, "keyshare", pt.name, st, exp, out.detail, hex.EncodeToString(out.raw[:minInt(len(out.raw), 24)]))
	}

	// Invalid P-256 points & mismatched supported_groups vs key_share
	p256Cases := []struct {
		name   string
		groups []uint16
		ks     []keyShareEntry
	}{
		{"p256_off_curve_point", []uint16{GroupP256}, []keyShareEntry{{group: GroupP256, key: append(append([]byte{0x04}, bytes.Repeat([]byte{0x01}, 32)...), bytes.Repeat([]byte{0x02}, 32)...)}}},
		{"p256_point_at_infinity_zeros", []uint16{GroupP256}, []keyShareEntry{{group: GroupP256, key: append([]byte{0x04}, make([]byte, 64)...)}}},
		{"p256_point_at_infinity_1B", []uint16{GroupP256}, []keyShareEntry{{group: GroupP256, key: []byte{0x00}}}},
		{"p256_compressed_point", []uint16{GroupP256}, []keyShareEntry{{group: GroupP256, key: append([]byte{0x02}, bytes.Repeat([]byte{0x01}, 32)...)}}},
		{"p256_coords_ge_p", []uint16{GroupP256}, []keyShareEntry{{group: GroupP256, key: append([]byte{0x04}, bytes.Repeat([]byte{0xff}, 64)...)}}},
		{"p256_trunc_64B", []uint16{GroupP256}, []keyShareEntry{{group: GroupP256, key: append([]byte{0x04}, bytes.Repeat([]byte{0x01}, 63)...)}}},
		{"p256_oversize_66B", []uint16{GroupP256}, []keyShareEntry{{group: GroupP256, key: append([]byte{0x04}, bytes.Repeat([]byte{0x01}, 65)...)}}},
		{"mismatch_groups_p256_ks_x25519", []uint16{GroupP256}, []keyShareEntry{{group: GroupX25519, key: validX25519Key()}}},
		{"duplicate_keyshare_same_group", []uint16{GroupX25519}, []keyShareEntry{{group: GroupX25519, key: validX25519Key()}, {group: GroupX25519, key: validX25519Key()}}},
	}
	for _, tc := range p256Cases {
		exts := []rawExt{
			extSNI(sni),
			extSupportedVersionsClient(0x0304),
			extSupportedGroups(tc.groups...),
			extSigAlgs(SigEd25519, SigECDSAP256SHA256),
			extALPN("http/1.1"),
			extKeyShareClient(tc.ks...),
		}
		ch := buildClientHelloMsg(clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM}, exts: exts})
		out := sendRawAndClassify(addr, makeRecord(RecHandshake, 0x0301, ch))
		st := "PASS"
		if !isRejectedOutcome(out) {
			// Note: for mismatch_groups_p256_ks_x25519, RFC 8446 Section 4.2.8 says client MUST NOT offer key_share not in supported_groups -> illegal_parameter(47).
			// If server sent HRR instead of rejecting, flag FAIL!
			st = "FAIL"
		}
		rec.add(suiteName, "keyshare", tc.name, st, "reject (illegal_parameter/handshake_failure)", out.detail, hex.EncodeToString(out.raw[:minInt(len(out.raw), 24)]))
	}

	// =========================================================================
	// 4. AEAD TAG, AAD, & PADDING TAMPERING (DOOM PRINCIPLE & RECORD LAYER)
	// =========================================================================
	// 4a. Finished record tampering
	finTamperTests := []struct {
		name  string
		build func(s *tls13ClientSession) []byte
	}{
		{"fin_tag_flip_first_byte", func(s *tls13ClientSession) []byte {
			r := s.hsTx.sealRecord(RecHandshake, s.clientFinMsg)
			r[len(r)-16] ^= 0x01
			return r
		}},
		{"fin_tag_flip_last_byte", func(s *tls13ClientSession) []byte {
			r := s.hsTx.sealRecord(RecHandshake, s.clientFinMsg)
			r[len(r)-1] ^= 0x01
			return r
		}},
		{"fin_tag_all_zeros", func(s *tls13ClientSession) []byte {
			r := s.hsTx.sealRecord(RecHandshake, s.clientFinMsg)
			for i := len(r) - 16; i < len(r); i++ {
				r[i] = 0
			}
			return r
		}},
		{"fin_ct_flip_first_byte", func(s *tls13ClientSession) []byte {
			r := s.hsTx.sealRecord(RecHandshake, s.clientFinMsg)
			r[5] ^= 0x80
			return r
		}},
		{"fin_trunc_0B", func(s *tls13ClientSession) []byte {
			return makeRecord(RecAppData, 0x0303, []byte{})
		}},
		{"fin_trunc_1B", func(s *tls13ClientSession) []byte {
			return makeRecord(RecAppData, 0x0303, []byte{0xaa})
		}},
		{"fin_trunc_15B", func(s *tls13ClientSession) []byte {
			return makeRecord(RecAppData, 0x0303, bytes.Repeat([]byte{0xaa}, 15))
		}},
		{"fin_trunc_16B_tag_only", func(s *tls13ClientSession) []byte {
			return makeRecord(RecAppData, 0x0303, bytes.Repeat([]byte{0xaa}, 16))
		}},
		{"fin_aad_tamper_ver_0304", func(s *tls13ClientSession) []byte {
			r := s.hsTx.sealRecord(RecHandshake, s.clientFinMsg)
			r[1], r[2] = 0x03, 0x04 // flipped after sealing -> AAD mismatch!
			return r
		}},
		{"fin_aad_tamper_ver_0301", func(s *tls13ClientSession) []byte {
			r := s.hsTx.sealRecord(RecHandshake, s.clientFinMsg)
			r[1], r[2] = 0x03, 0x01
			return r
		}},
		{"fin_valid_aead_wrong_recver_0304", func(s *tls13ClientSession) []byte {
			// Validly authenticated with legacy_record_version=0x0304 (RFC 8446 Section 5.1 says MUST be 0x0303)
			return s.hsTx.sealRecordWithOpts(RecHandshake, s.clientFinMsg, 0, 0x0304, nil)
		}},
		{"fin_all_zero_inner_plaintext", func(s *tls13ClientSession) []byte {
			return s.hsTx.sealRawInner(make([]byte, 16), 0x0303)
		}},
		{"fin_trailing_garbage_in_hs", func(s *tls13ClientSession) []byte {
			bad := append(append([]byte{}, s.clientFinMsg...), 0xde, 0xad, 0xbe, 0xef)
			return s.hsTx.sealRecord(RecHandshake, bad)
		}},
		{"fin_bad_verify_data_valid_aead", func(s *tls13ClientSession) []byte {
			bad := append([]byte{}, s.clientFinMsg...)
			bad[len(bad)-1] ^= 0x01
			return s.hsTx.sealRecord(RecHandshake, bad)
		}},
	}
	for _, tc := range finTamperTests {
		cfg := defaultHandshakeConfig(sni)
		cfg.stopBeforeFin = true
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add(suiteName, "aead_fin", tc.name, "FAIL", "reach Finished stage", err.Error(), "")
			continue
		}
		badRec := tc.build(sess)
		_, _ = sess.conn.Write(badRec)
		// Also try sending an HTTP request right after to verify server refuses subsequent appdata
		out := classifyResponse(sess.conn, sess.hsRx, sess.appRx, 1200*time.Millisecond)
		if out.kind == "TIMEOUT" {
			// Send valid encrypted appdata to see if server mistakenly accepted!
			_ = sess.sendAppData([]byte("GET /secure-hello HTTP/1.1\r\nHost: "+sni+"\r\n\r\n"), false)
			out2 := classifyResponse(sess.conn, sess.hsRx, sess.appRx, 1200*time.Millisecond)
			out.detail += " -> after_appdata: " + out2.detail
			out.kind = out2.kind
			out.raw = out2.raw
		}
		sess.close()
		st := "PASS"
		exp := "fatal alert / reject"
		if tc.name == "fin_valid_aead_wrong_recver_0304" {
			// RFC 8446 Section 5.1 says legacy_record_version MUST be ignored for all purposes (for compatibility) though senders MUST set 0x0303; note behavior!
			st = "INFO"
			exp = "RFC 8446 Section 5.1: legacy_record_version ignored or rejected"
		} else if !isRejectedOutcome(out) {
			st = "FAIL"
		}
		rec.add(suiteName, "aead_fin", tc.name, st, exp, out.detail, hex.EncodeToString(out.raw[:minInt(len(out.raw), 24)]))
	}

	// 4b. Post-handshake ApplicationData AEAD tampering + verify subsequent request refused!
	appTamperTests := []struct {
		name string
		run  func(s *tls13ClientSession) ([]byte, error)
	}{
		{"app_tag_flip_1bit", func(s *tls13ClientSession) ([]byte, error) {
			r := s.appTx.sealRecord(RecAppData, []byte("GET /secure-hello HTTP/1.1\r\nHost: "+sni+"\r\n\r\n"))
			r[len(r)-1] ^= 0x01
			return r, nil
		}},
		{"app_nonce_reuse_replay", func(s *tls13ClientSession) ([]byte, error) {
			// First send a valid AppData record (seq 0) and read response, then REPLAY exact seq 0 record!
			req := []byte("GET /secure-hello HTTP/1.1\r\nHost: " + sni + "\r\nConnection: keep-alive\r\n\r\n")
			r0 := s.appTx.sealRecord(RecAppData, req)
			if _, err := s.conn.Write(r0); err != nil {
				return nil, err
			}
			if _, err := s.readAppData(2 * time.Second); err != nil {
				return nil, fmt.Errorf("initial valid req failed: %w", err)
			}
			return r0, nil // exact replay of seq 0 record!
		}},
		{"app_wrong_seq_num", func(s *tls13ClientSession) ([]byte, error) {
			wrongSeq := s.appTx.seq + 5
			r := s.appTx.sealRecordWithOpts(RecAppData, []byte("GET /secure-hello HTTP/1.1\r\nHost: "+sni+"\r\n\r\n"), 0, 0x0303, &wrongSeq)
			return r, nil
		}},
		{"app_aad_tamper_ver", func(s *tls13ClientSession) ([]byte, error) {
			r := s.appTx.sealRecord(RecAppData, []byte("GET /secure-hello HTTP/1.1\r\nHost: "+sni+"\r\n\r\n"))
			r[1], r[2] = 0x03, 0x01
			return r, nil
		}},
		{"app_all_zero_inner_plaintext", func(s *tls13ClientSession) ([]byte, error) {
			return s.appTx.sealRawInner(make([]byte, 16), 0x0303), nil
		}},
		{"app_encrypted_ccs_inner_type", func(s *tls13ClientSession) ([]byte, error) {
			return s.appTx.sealRecord(RecCCS, []byte{0x01}), nil
		}},
		{"app_encrypted_invalid_inner_type_ff", func(s *tls13ClientSession) ([]byte, error) {
			return s.appTx.sealRecord(0xff, []byte("bad")), nil
		}},
		{"app_trunc_10B_ciphertext", func(s *tls13ClientSession) ([]byte, error) {
			return makeRecord(RecAppData, 0x0303, bytes.Repeat([]byte{0x42}, 10)), nil
		}},
	}
	for _, tc := range appTamperTests {
		cfg := defaultHandshakeConfig(sni)
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add(suiteName, "aead_app", tc.name, "FAIL", "valid handshake", err.Error(), "")
			continue
		}
		badRec, berr := tc.run(sess)
		if berr != nil {
			sess.close()
			rec.add(suiteName, "aead_app", tc.name, "FAIL", "prepare tampered record", berr.Error(), "")
			continue
		}
		_, _ = sess.conn.Write(badRec)
		out := classifyResponse(sess.conn, sess.hsRx, sess.appRx, 1200*time.Millisecond)
		// Verify server refuses any further valid request on same socket!
		followUpAccepted := false
		if out.kind != "EOF" && out.kind != "RST" {
			var followReq []byte
			if isPureGoose {
				followReq = []byte("AFTER_FATAL_CHECK")
			} else {
				followReq = []byte("GET /secure-hello HTTP/1.1\r\nHost: " + sni + "\r\nConnection: close\r\n\r\n")
			}
			if werr := sess.sendAppData(followReq, false); werr == nil {
				out2 := classifyResponse(sess.conn, sess.hsRx, sess.appRx, 800*time.Millisecond)
				if out2.kind == "APPDATA" {
					followUpAccepted = true
					out.detail += " [CRITICAL: FOLLOWUP ACCEPTED: " + out2.detail + "]"
				} else {
					out.detail += " [followup: " + out2.kind + "]"
				}
			}
		}
		sess.close()
		st := "PASS"
		if !isRejectedOutcome(out) || followUpAccepted {
			st = "FAIL"
		}
		rec.add(suiteName, "aead_app", tc.name, st, "fatal alert + close + refuse followup", out.detail, hex.EncodeToString(out.raw[:minInt(len(out.raw), 24)]))
	}

	// =========================================================================
	// 5. STATE MACHINE ORDERING VIOLATIONS
	// =========================================================================
	// 5a. Pre-handshake
	preHSCases := []struct {
		name string
		rec  []byte
	}{
		{"pre_appdata", makeRecord(RecAppData, 0x0303, []byte("hello world 1234567890123456"))},
		{"pre_ccs", makeRecord(RecCCS, 0x0303, []byte{0x01})},
		{"pre_serverhello", makeRecord(RecHandshake, 0x0303, makeHandshakeMsg(HSServerHello, make([]byte, 40)))},
		{"pre_finished", makeRecord(RecHandshake, 0x0303, makeHandshakeMsg(HSFinished, make([]byte, 32)))},
		{"pre_certificate", makeRecord(RecHandshake, 0x0303, makeHandshakeMsg(HSCertificate, []byte{0, 0, 0, 0}))},
		{"pre_encrypted_extensions", makeRecord(RecHandshake, 0x0303, makeHandshakeMsg(HSEncryptedExtensions, []byte{0, 0}))},
		{"pre_key_update", makeRecord(RecHandshake, 0x0303, makeHandshakeMsg(HSKeyUpdate, []byte{0}))},
		{"pre_new_session_ticket", makeRecord(RecHandshake, 0x0303, makeHandshakeMsg(HSNewSessionTicket, make([]byte, 16)))},
		{"pre_invalid_rec_type_00", makeRecord(0x00, 0x0303, []byte{0x01, 0x02})},
		{"pre_invalid_rec_type_18", makeRecord(0x18, 0x0303, []byte{0x01, 0x02})},
		{"pre_invalid_rec_type_ff", makeRecord(0xff, 0x0303, []byte{0x01, 0x02})},
		{"pre_close_notify", makeRecord(RecAlert, 0x0303, []byte{0x01, 0x00})},
	}
	for _, tc := range preHSCases {
		out := sendRawAndClassify(addr, tc.rec)
		st := "PASS"
		if !isRejectedOutcome(out) {
			st = "FAIL"
		}
		rec.add(suiteName, "fsm_pre_hs", tc.name, st, "reject (unexpected_message / close)", out.detail, hex.EncodeToString(out.raw[:minInt(len(out.raw), 24)]))
	}

	// Test pre-handshake CCS followed immediately by valid ClientHello (RFC 8446 Section 5 forbids CCS before ClientHello!)
	{
		conn, derr := net.DialTimeout("tcp", addr, 3*time.Second)
		if derr == nil {
			_, _ = conn.Write(makeRecord(RecCCS, 0x0303, []byte{0x01}))
			cfg := defaultHandshakeConfig(sni)
			sess, herr := doTLS13HandshakeOnConn(conn, cfg)
			if herr != nil {
				_ = conn.Close()
				rec.add(suiteName, "fsm_pre_hs", "pre_ccs_then_valid_ch", "PASS", "reject pre-CH CCS even when followed by valid CH", herr.Error(), "")
			} else {
				_ = sess.sendAppData([]byte("GET /secure-hello HTTP/1.1\r\nHost: "+sni+"\r\nConnection: close\r\n\r\n"), false)
				resp, rerr := sess.readAppData(2 * time.Second)
				sess.close()
				rec.add(suiteName, "fsm_pre_hs", "pre_ccs_then_valid_ch", "FAIL", "RFC 8446 Section 5 MUST reject CCS before first ClientHello",
					fmt.Sprintf("ACCEPTED pre-CH CCS + completed TLS 1.3 handshake! resp=%q err=%v", truncStr(string(resp), 64), rerr), "")
			}
		}
	}

	// 5b. Post-ServerHello (before Finished)
	postSHCases := []struct {
		name  string
		build func(s *tls13ClientSession) [][]byte
	}{
		{"post_sh_plaintext_finished", func(s *tls13ClientSession) [][]byte {
			return [][]byte{makeRecord(RecHandshake, 0x0303, s.clientFinMsg)}
		}},
		{"post_sh_enc_appdata_with_hs_key", func(s *tls13ClientSession) [][]byte {
			return [][]byte{s.hsTx.sealRecord(RecAppData, []byte("early appdata"))}
		}},
		{"post_sh_enc_appdata_with_app_key", func(s *tls13ClientSession) [][]byte {
			return [][]byte{s.appTx.sealRecord(RecAppData, []byte("early appdata"))}
		}},
		{"post_sh_dup_clienthello_plain", func(s *tls13ClientSession) [][]byte {
			return [][]byte{makeRecord(RecHandshake, 0x0303, s.transcript[0])}
		}},
		{"post_sh_dup_clienthello_enc", func(s *tls13ClientSession) [][]byte {
			return [][]byte{s.hsTx.sealRecord(RecHandshake, s.transcript[0])}
		}},
		{"post_sh_unsolicited_cert", func(s *tls13ClientSession) [][]byte {
			return [][]byte{s.hsTx.sealRecord(RecHandshake, makeHandshakeMsg(HSCertificate, []byte{0, 0, 0, 0}))}
		}},
		{"post_sh_unsolicited_certverify", func(s *tls13ClientSession) [][]byte {
			return [][]byte{s.hsTx.sealRecord(RecHandshake, makeHandshakeMsg(HSCertificateVerify, []byte{0x08, 0x07, 0x00, 0x04, 1, 2, 3, 4}))}
		}},
		{"post_sh_unsolicited_nst", func(s *tls13ClientSession) [][]byte {
			return [][]byte{s.hsTx.sealRecord(RecHandshake, makeHandshakeMsg(HSNewSessionTicket, make([]byte, 20)))}
		}},
		{"post_sh_unsolicited_keyupdate", func(s *tls13ClientSession) [][]byte {
			return [][]byte{s.hsTx.sealRecord(RecHandshake, makeHandshakeMsg(HSKeyUpdate, []byte{0}))}
		}},
		{"post_sh_unsolicited_eoed", func(s *tls13ClientSession) [][]byte {
			return [][]byte{s.hsTx.sealRecord(RecHandshake, makeHandshakeMsg(HSEndOfEarlyData, nil))}
		}},
		{"post_sh_malformed_ccs_02", func(s *tls13ClientSession) [][]byte {
			return [][]byte{makeRecord(RecCCS, 0x0303, []byte{0x02})}
		}},
		{"post_sh_malformed_ccs_empty", func(s *tls13ClientSession) [][]byte {
			return [][]byte{makeRecord(RecCCS, 0x0303, []byte{})}
		}},
		{"post_sh_malformed_ccs_2bytes", func(s *tls13ClientSession) [][]byte {
			return [][]byte{makeRecord(RecCCS, 0x0303, []byte{0x01, 0x01})}
		}},
		{"post_sh_ccs_flood_10", func(s *tls13ClientSession) [][]byte {
			var recs [][]byte
			for range 10 {
				recs = append(recs, makeRecord(RecCCS, 0x0303, []byte{0x01}))
			}
			recs = append(recs, s.hsTx.sealRecord(RecHandshake, s.clientFinMsg))
			return recs
		}},
	}
	for _, tc := range postSHCases {
		cfg := defaultHandshakeConfig(sni)
		cfg.stopBeforeFin = true
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add(suiteName, "fsm_post_sh", tc.name, "FAIL", "reach post-SH", err.Error(), "")
			continue
		}
		for _, r := range tc.build(sess) {
			_, _ = sess.conn.Write(r)
		}
		out := classifyResponse(sess.conn, sess.hsRx, sess.appRx, 1200*time.Millisecond)
		if out.kind == "TIMEOUT" {
			_ = sess.sendAppData([]byte("GET /secure-hello HTTP/1.1\r\nHost: "+sni+"\r\n\r\n"), false)
			out2 := classifyResponse(sess.conn, sess.hsRx, sess.appRx, 1000*time.Millisecond)
			out.detail += " -> after_appdata: " + out2.detail
			out.kind = out2.kind
			out.raw = out2.raw
		}
		sess.close()
		st := "PASS"
		if !isRejectedOutcome(out) {
			st = "FAIL"
		}
		rec.add(suiteName, "fsm_post_sh", tc.name, st, "reject (unexpected_message)", out.detail, hex.EncodeToString(out.raw[:minInt(len(out.raw), 24)]))
	}

	// 5c. Post-Finished
	postFinCases := []struct {
		name  string
		build func(s *tls13ClientSession) [][]byte
	}{
		{"post_fin_duplicate_finished", func(s *tls13ClientSession) [][]byte {
			return [][]byte{s.appTx.sealRecord(RecHandshake, s.clientFinMsg)}
		}},
		{"post_fin_reneg_clienthello_plain", func(s *tls13ClientSession) [][]byte {
			return [][]byte{makeRecord(RecHandshake, 0x0303, s.transcript[0])}
		}},
		{"post_fin_reneg_clienthello_enc", func(s *tls13ClientSession) [][]byte {
			return [][]byte{s.appTx.sealRecord(RecHandshake, s.transcript[0])}
		}},
		{"post_fin_client_nst", func(s *tls13ClientSession) [][]byte {
			return [][]byte{s.appTx.sealRecord(RecHandshake, makeHandshakeMsg(HSNewSessionTicket, make([]byte, 20)))}
		}},
		{"post_fin_client_serverhello", func(s *tls13ClientSession) [][]byte {
			return [][]byte{s.appTx.sealRecord(RecHandshake, makeHandshakeMsg(HSServerHello, make([]byte, 40)))}
		}},
		{"post_fin_client_ee", func(s *tls13ClientSession) [][]byte {
			return [][]byte{s.appTx.sealRecord(RecHandshake, makeHandshakeMsg(HSEncryptedExtensions, []byte{0, 0}))}
		}},
		{"post_fin_malformed_ku_val_2", func(s *tls13ClientSession) [][]byte {
			return [][]byte{s.appTx.sealRecord(RecHandshake, makeHandshakeMsg(HSKeyUpdate, []byte{0x02}))}
		}},
		{"post_fin_malformed_ku_len_0", func(s *tls13ClientSession) [][]byte {
			return [][]byte{s.appTx.sealRecord(RecHandshake, makeHandshakeMsg(HSKeyUpdate, []byte{}))}
		}},
		{"post_fin_malformed_ku_len_2", func(s *tls13ClientSession) [][]byte {
			return [][]byte{s.appTx.sealRecord(RecHandshake, makeHandshakeMsg(HSKeyUpdate, []byte{0x00, 0x00}))}
		}},
		{"post_fin_ku_coalesced_cross_boundary", func(s *tls13ClientSession) [][]byte {
			// RFC 8446 Section 5.1: KeyUpdate MUST NOT be coalesced with subsequent handshake message
			ku := makeHandshakeMsg(HSKeyUpdate, []byte{0x00})
			ku2 := makeHandshakeMsg(HSKeyUpdate, []byte{0x00})
			return [][]byte{s.appTx.sealRecord(RecHandshake, append(ku, ku2...))}
		}},
		{"post_fin_plaintext_ccs", func(s *tls13ClientSession) [][]byte {
			// RFC 8446 Section 5: CCS after handshake is unexpected_message
			return [][]byte{makeRecord(RecCCS, 0x0303, []byte{0x01})}
		}},
		{"post_fin_plaintext_handshake", func(s *tls13ClientSession) [][]byte {
			return [][]byte{makeRecord(RecHandshake, 0x0303, makeHandshakeMsg(HSKeyUpdate, []byte{0x00}))}
		}},
	}
	for _, tc := range postFinCases {
		cfg := defaultHandshakeConfig(sni)
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add(suiteName, "fsm_post_fin", tc.name, "FAIL", "valid handshake", err.Error(), "")
			continue
		}
		for _, r := range tc.build(sess) {
			_, _ = sess.conn.Write(r)
		}
		out := classifyResponse(sess.conn, sess.hsRx, sess.appRx, 1200*time.Millisecond)
		if out.kind == "TIMEOUT" {
			var probe []byte
			if isPureGoose {
				probe = []byte("AFTER_BAD_FSM")
			} else {
				probe = []byte("GET /secure-hello HTTP/1.1\r\nHost: " + sni + "\r\nConnection: close\r\n\r\n")
			}
			_ = sess.sendAppData(probe, false)
			out2 := classifyResponse(sess.conn, sess.hsRx, sess.appRx, 1000*time.Millisecond)
			out.detail += " -> after_probe: " + out2.detail
			out.kind = out2.kind
			out.raw = out2.raw
		}
		sess.close()
		st := "PASS"
		if !isRejectedOutcome(out) {
			st = "FAIL"
		}
		rec.add(suiteName, "fsm_post_fin", tc.name, st, "reject (unexpected_message/illegal_parameter/decode_error)", out.detail, hex.EncodeToString(out.raw[:minInt(len(out.raw), 24)]))
	}

	// Rapid KeyUpdate flood (25 consecutive KeyUpdates) -> observe whether rate-limited or handled cleanly without crash/hang
	{
		cfg := defaultHandshakeConfig(sni)
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add(suiteName, "fsm_post_fin", "rapid_key_update_flood_25", "FAIL", "handshake", err.Error(), "")
		} else {
			var sendErr error
			for range 25 {
				ku := makeHandshakeMsg(HSKeyUpdate, []byte{0x00})
				if _, sendErr = sess.conn.Write(sess.appTx.sealRecord(RecHandshake, ku)); sendErr != nil {
					break
				}
				sess.appTx, err = sess.appTx.ratchet()
				if err != nil {
					break
				}
			}
			out := classifyResponse(sess.conn, sess.hsRx, sess.appRx, 1000*time.Millisecond)
			sess.close()
			rec.add(suiteName, "fsm_post_fin", "rapid_key_update_flood_25", "INFO", "limit or handle cleanly without crash", fmt.Sprintf("sendErr=%v resp=%s", sendErr, out.detail), "")
		}
	}

	// =========================================================================
	// 6. FRAGMENTATION & MALFORMED FIELD LENGTHS
	// =========================================================================
	// 6a. 1-byte TCP segmentation of full TLS 1.3 handshake + HTTP request
	{
		cfg := defaultHandshakeConfig(sni)
		cfg.oneByteTCP = true
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add(suiteName, "frag", "1byte_tcp_full_handshake", "FAIL", "full handshake + response", err.Error(), "")
		} else {
			req := []byte("GET /secure-hello HTTP/1.1\r\nHost: " + sni + "\r\nConnection: close\r\n\r\n")
			_ = sess.sendAppData(req, true)
			resp, rerr := sess.readAppData(5 * time.Second)
			sess.close()
			if rerr == nil && len(resp) > 0 {
				rec.add(suiteName, "frag", "1byte_tcp_full_handshake", "PASS", "reassemble + respond", truncStr(string(resp), 64), "")
			} else {
				rec.add(suiteName, "frag", "1byte_tcp_full_handshake", "FAIL", "respond", fmt.Sprintf("err=%v", rerr), "")
			}
		}
	}

	// 6b. Multi-record ClientHello (2 and 8 records) & Client Finished (2 encrypted records)
	for _, splits := range []int{2, 8} {
		cfg := defaultHandshakeConfig(sni)
		cfg.chRecordSplits = splits
		sess, err := doTLS13Handshake(addr, cfg)
		label := fmt.Sprintf("clienthello_split_%d_records", splits)
		if err != nil {
			rec.add(suiteName, "frag", label, "FAIL", "reassemble fragmented ClientHello", err.Error(), "")
		} else {
			req := []byte("GET /secure-hello HTTP/1.1\r\nHost: " + sni + "\r\nConnection: close\r\n\r\n")
			_ = sess.sendAppData(req, false)
			resp, rerr := sess.readAppData(3 * time.Second)
			sess.close()
			if rerr == nil && len(resp) > 0 {
				rec.add(suiteName, "frag", label, "PASS", "reassemble + respond", truncStr(string(resp), 64), "")
			} else {
				rec.add(suiteName, "frag", label, "FAIL", "respond", fmt.Sprintf("err=%v", rerr), "")
			}
		}
	}
	{
		cfg := defaultHandshakeConfig(sni)
		cfg.finRecordSplits = 2
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add(suiteName, "frag", "finished_split_2_enc_records", "FAIL", "reassemble fragmented Finished", err.Error(), "")
		} else {
			req := []byte("GET /secure-hello HTTP/1.1\r\nHost: " + sni + "\r\nConnection: close\r\n\r\n")
			_ = sess.sendAppData(req, false)
			resp, rerr := sess.readAppData(3 * time.Second)
			sess.close()
			if rerr == nil && len(resp) > 0 {
				rec.add(suiteName, "frag", "finished_split_2_enc_records", "PASS", "reassemble + respond", truncStr(string(resp), 64), "")
			} else {
				rec.add(suiteName, "frag", "finished_split_2_enc_records", "FAIL", "respond", fmt.Sprintf("err=%v", rerr), "")
			}
		}
	}

	// 6c. Interleaved CCS inside fragmented ClientHello (RFC 8446 Section 5.1 forbids!)
	{
		ch := buildClientHelloMsg(clientHelloOpts{
			legacyVer: 0x0303,
			ciphers:   []uint16{CipherAES128GCM},
			exts:      baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256}),
		})
		mid := len(ch) / 2
		out := sendRawAndClassify(addr,
			makeRecord(RecHandshake, 0x0301, ch[:mid]),
			makeRecord(RecCCS, 0x0303, []byte{0x01}),
			makeRecord(RecHandshake, 0x0301, ch[mid:]),
		)
		st := "PASS"
		if !isRejectedOutcome(out) {
			st = "FAIL"
		}
		rec.add(suiteName, "frag", "interleaved_ccs_in_fragmented_ch", st, "reject interleaved CCS inside CH", out.detail, hex.EncodeToString(out.raw[:minInt(len(out.raw), 24)]))
	}

	// 6d. 0-length encrypted handshake record (RFC 8446 Section 5.1 forbids zero-length HS fragments)
	{
		cfg := defaultHandshakeConfig(sni)
		cfg.stopBeforeFin = true
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add(suiteName, "frag", "zero_len_enc_handshake_record", "FAIL", "reach post-SH", err.Error(), "")
		} else {
			_, _ = sess.conn.Write(sess.hsTx.sealRecord(RecHandshake, []byte{}))
			out := classifyResponse(sess.conn, sess.hsRx, sess.appRx, 1200*time.Millisecond)
			if out.kind == "TIMEOUT" {
				_, _ = sess.conn.Write(sess.hsTx.sealRecord(RecHandshake, s.clientFinMsgOrNil(sess)))
				_ = sess.sendAppData([]byte("GET /secure-hello HTTP/1.1\r\nHost: "+sni+"\r\n\r\n"), false)
				out2 := classifyResponse(sess.conn, sess.hsRx, sess.appRx, 1000*time.Millisecond)
				out.detail += " -> after_fin: " + out2.detail
				out.kind = out2.kind
			}
			sess.close()
			st := "PASS"
			if !isRejectedOutcome(out) {
				st = "FAIL"
			}
			rec.add(suiteName, "frag", "zero_len_enc_handshake_record", st, "RFC 8446 Section 5.1 reject 0-len HS fragment", out.detail, "")
		}
	}

	// 6e. Oversize encrypted record (16641 bytes) after handshake
	{
		cfg := defaultHandshakeConfig(sni)
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add(suiteName, "frag", "oversize_enc_record_16641B", "FAIL", "handshake", err.Error(), "")
		} else {
			_, _ = sess.conn.Write(makeRecord(RecAppData, 0x0303, make([]byte, 16641)))
			out := classifyResponse(sess.conn, sess.hsRx, sess.appRx, 1200*time.Millisecond)
			sess.close()
			st := "PASS"
			if !isRejectedOutcome(out) {
				st = "FAIL"
			}
			rec.add(suiteName, "frag", "oversize_enc_record_16641B", st, "record_overflow(22)", out.detail, hex.EncodeToString(out.raw[:minInt(len(out.raw), 24)]))
		}
	}

	// 6f. Validly sealed oversize inner plaintext (16385B inner + 1B type = 16386B > 16384+1 max plaintext!)
	{
		cfg := defaultHandshakeConfig(sni)
		sess, err := doTLS13Handshake(addr, cfg)
		if err != nil {
			rec.add(suiteName, "frag", "oversize_inner_plaintext_16385B", "FAIL", "handshake", err.Error(), "")
		} else {
			bigRec := sess.appTx.sealRecord(RecAppData, bytes.Repeat([]byte{'A'}, 16385))
			_, _ = sess.conn.Write(bigRec)
			out := classifyResponse(sess.conn, sess.hsRx, sess.appRx, 1200*time.Millisecond)
			sess.close()
			st := "PASS"
			if !isRejectedOutcome(out) {
				st = "FAIL"
			}
			rec.add(suiteName, "frag", "oversize_inner_plaintext_16385B", st, "RFC 8446 Section 5.2 record_overflow(22)", out.detail, hex.EncodeToString(out.raw[:minInt(len(out.raw), 24)]))
		}
	}

	// 6g. Malformed ClientHello records & field lengths
	malformedCHCases := []struct {
		name string
		rec  []byte
	}{
		{"zero_len_plain_hs_record", makeRecord(RecHandshake, 0x0303, []byte{})},
		{"oversize_plain_hs_16385B", makeRecord(RecHandshake, 0x0303, make([]byte, 16385))},
		{"hs_len_gt_record_payload", func() []byte {
			ch := buildClientHelloMsg(clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM}, exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256})})
			// Inflate 24-bit HS length by +20 while keeping payload short
			cur := int(ch[1])<<16 | int(ch[2])<<8 | int(ch[3])
			cur += 20
			ch[1], ch[2], ch[3] = byte(cur>>16), byte(cur>>8), byte(cur)
			return makeRecord(RecHandshake, 0x0301, ch)
		}()},
		{"hs_len_lt_record_payload_trailing_garbage", func() []byte {
			ch := buildClientHelloMsg(clientHelloOpts{legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM}, exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256})})
			return makeRecord(RecHandshake, 0x0301, append(ch, 0x99, 0x88, 0x77, 0x66))
		}()},
		{"dup_ext_sni", makeRecord(RecHandshake, 0x0301, buildClientHelloMsg(clientHelloOpts{
			legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM},
			exts: append(baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256}), extSNI(sni)),
		}))},
		{"dup_ext_supported_versions", makeRecord(RecHandshake, 0x0301, buildClientHelloMsg(clientHelloOpts{
			legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM},
			exts: append(baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256}), extSupportedVersionsClient(0x0304)),
		}))},
		{"dup_ext_key_share", makeRecord(RecHandshake, 0x0301, buildClientHelloMsg(clientHelloOpts{
			legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM},
			exts: append(baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256}), extKeyShareClient(keyShareEntry{group: GroupX25519, key: validX25519Key()})),
		}))},
		{"dup_ext_alpn", makeRecord(RecHandshake, 0x0301, buildClientHelloMsg(clientHelloOpts{
			legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM},
			exts: append(baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256}), extALPN("http/1.1")),
		}))},
		{"dup_ext_sigalgs", makeRecord(RecHandshake, 0x0301, buildClientHelloMsg(clientHelloOpts{
			legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM},
			exts: append(baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256}), extSigAlgs(SigEd25519)),
		}))},
		{"dup_ext_supported_groups", makeRecord(RecHandshake, 0x0301, buildClientHelloMsg(clientHelloOpts{
			legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM},
			exts: append(baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256}), extSupportedGroups(GroupX25519)),
		}))},
		{"trailing_bytes_after_extensions", makeRecord(RecHandshake, 0x0301, buildClientHelloMsg(clientHelloOpts{
			legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM},
			exts:     baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256}),
			trailing: []byte{0xde, 0xad, 0xbe, 0xef},
		}))},
		{"session_id_33_bytes", makeRecord(RecHandshake, 0x0301, buildClientHelloMsg(clientHelloOpts{
			legacyVer: 0x0303, sessionID: bytes.Repeat([]byte{0x41}, 33), ciphers: []uint16{CipherAES128GCM},
			exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256}),
		}))},
		{"odd_cipher_suites_len_3", makeRecord(RecHandshake, 0x0301, buildClientHelloMsg(clientHelloOpts{
			legacyVer: 0x0303, rawCiphers: []byte{0x00, 0x03, 0x13, 0x01, 0x00},
			exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256}),
		}))},
		{"empty_cipher_suites_len_0", makeRecord(RecHandshake, 0x0301, buildClientHelloMsg(clientHelloOpts{
			legacyVer: 0x0303, ciphers: []uint16{},
			exts: baseExts(sni, []string{"http/1.1"}, true, []uint16{0x0304}, true, []uint16{SigEd25519, SigECDSAP256SHA256}),
		}))},
	}
	for _, tc := range malformedCHCases {
		out := sendRawAndClassify(addr, tc.rec)
		st := "PASS"
		if tc.name == "hs_len_gt_record_payload" {
			// A server waiting for continuation records may timeout or reject on EOF; verify it doesn't send ServerHello!
			if out.kind == "HANDSHAKE" || out.kind == "APPDATA" {
				st = "FAIL"
			}
		} else if !isRejectedOutcome(out) {
			st = "FAIL"
		}
		rec.add(suiteName, "malformed", tc.name, st, "reject (decode_error/illegal_parameter)", out.detail, hex.EncodeToString(out.raw[:minInt(len(out.raw), 24)]))
	}

	// Final server health check after all negative tests
	if err := probeServerHealth(addr, sni, isPureGoose); err != nil {
		rec.add(suiteName, "health", "post_suite_health_check", "FAIL", "server still healthy", err.Error(), "")
	} else {
		rec.add(suiteName, "health", "post_suite_health_check", "PASS", "server still healthy", "valid TLS 1.3 + appdata succeeded", "")
	}
}

type helperFin struct{}

var s helperFin

func (helperFin) clientFinMsgOrNil(sess *tls13ClientSession) []byte {
	return sess.clientFinMsg
}
