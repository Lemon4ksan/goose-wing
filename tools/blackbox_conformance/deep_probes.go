// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Run targeted deep wire-level probes when invoked with -probe
func runDeepProbes(pki *testPKI) {
	binDir := filepath.Join(repoRoot, "tools", "bin")
	tlsServerExe := exePath(binDir, "tls_server")
	bogoShimExe := exePath(binDir, "bogo_shim")
	http3ServerExe := exePath(binDir, "http3_server")

	fmt.Println("================ DEEP WIRE PROBES ================")

	// 1. Default tls_server.exe: POST /secure-echo full response & ALPN mismatch variants
	srvDef, err := startManagedServer("tls_def_probe", tlsServerExe, []string{"--port", "0"}, nil, tcpShutdown)
	if err == nil {
		defer srvDef.stop()
		addr := fmt.Sprintf("127.0.0.1:%d", srvDef.port)

		// 1a. POST /secure-echo full body
		sess, err := doTLS13Handshake(addr, defaultHandshakeConfig("goose-wing.local"))
		if err == nil {
			req := "POST /secure-echo HTTP/1.1\r\nHost: goose-wing.local\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello-world"
			_ = sess.sendAppData([]byte(req), false)
			var full []byte
			for range 6 {
				ch, rerr := sess.readAppData(1500 * time.Millisecond)
				if len(ch) > 0 {
					full = append(full, ch...)
				}
				if rerr != nil {
					fmt.Printf("[PROBE 1a] POST /secure-echo read done err=%v total=%dB:\n%q\n", rerr, len(full), string(full))
					break
				}
			}
			sess.close()
		}

		// 1b. ALPN mismatch probes on default tls_server.exe
		for _, alpnList := range [][]string{{"h3"}, {"ftp"}, {"spdy/3.1"}, {"bogus-proto"}, {"http/1.0"}} {
			cfg := defaultHandshakeConfig("goose-wing.local")
			cfg.alpn = alpnList
			s, herr := doTLS13Handshake(addr, cfg)
			if herr != nil {
				fmt.Printf("[PROBE 1b] default ALPN=%v -> REJECTED: %v\n", alpnList, herr)
			} else {
				fmt.Printf("[PROBE 1b] default ALPN=%v -> ACCEPTED! negotiatedALPN=%q\n", alpnList, s.negotiatedALPN)
				s.close()
			}
		}

		// 1c. ClientHello split 2 records on default tls_server.exe: check exact split offsets (1B+rest, 4B+rest, 50B+rest)
		for _, splitAt := range []int{1, 4, 50} {
			conn, derr := net.DialTimeout("tcp", addr, 2*time.Second)
			if derr == nil {
				k, _ := ecdh.X25519().GenerateKey(rand.Reader)
				ch := buildClientHelloMsg(clientHelloOpts{
					legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM},
					exts: []rawExt{
						extSNI("goose-wing.local"),
						extSupportedVersionsClient(0x0304),
						extSupportedGroups(GroupX25519),
						extSigAlgs(SigEd25519, SigECDSAP256SHA256),
						extALPN("http/1.1"),
						extKeyShareClient(keyShareEntry{group: GroupX25519, key: k.PublicKey().Bytes()}),
					},
				})
				_, _ = conn.Write(makeRecord(RecHandshake, 0x0301, ch[:splitAt]))
				_, _ = conn.Write(makeRecord(RecHandshake, 0x0301, ch[splitAt:]))
				out := classifyResponse(conn, nil, nil, 1500*time.Millisecond)
				_ = conn.Close()
				fmt.Printf("[PROBE 1c] default CH split(%d+%dB) -> %s\n", splitAt, len(ch)-splitAt, out.detail)
			}
		}
		srvDef.stop()
	}

	// 2. --sni-map PureGoose mode probes: 1B/2B/5B/10B TCP segmentation, KeyUpdate wire trace, pre-CCS, post-fin bad AEAD alert
	sniArgs := []string{
		"--port", "0",
		"--sni-map", fmt.Sprintf("test.local=%s|%s", pki.edCertPath, pki.edKeyPath),
	}
	srvSNI, err := startManagedServer("tls_sni_probe", tlsServerExe, sniArgs, []string{"WING_PORT=0"}, tcpShutdown)
	if err == nil {
		defer srvSNI.stop()
		addr := fmt.Sprintf("127.0.0.1:%d", srvSNI.port)

		// 2a. TCP chunked write sizes (1B, 2B, 4B, 5B, 10B, 50B) of ClientHello record!
		for _, chunkSz := range []int{1, 2, 4, 5, 10, 50} {
			conn, derr := net.DialTimeout("tcp", addr, 2*time.Second)
			if derr != nil {
				continue
			}
			k, _ := ecdh.X25519().GenerateKey(rand.Reader)
			ch := buildClientHelloMsg(clientHelloOpts{
				legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM},
				exts: []rawExt{
					extSNI("test.local"),
					extSupportedVersionsClient(0x0304),
					extSupportedGroups(GroupX25519),
					extSigAlgs(SigEd25519, SigECDSAP256SHA256),
					extALPN("http/1.1"),
					extKeyShareClient(keyShareEntry{group: GroupX25519, key: k.PublicKey().Bytes()}),
				},
			})
			recBytes := makeRecord(RecHandshake, 0x0301, ch)
			written := 0
			var werr error
			for off := 0; off < len(recBytes); off += chunkSz {
				end := min(off+chunkSz, len(recBytes))
				var n int
				n, werr = conn.Write(recBytes[off:end])
				written += n
				if werr != nil {
					break
				}
				time.Sleep(2 * time.Millisecond)
			}
			out := classifyResponse(conn, nil, nil, 1000*time.Millisecond)
			_ = conn.Close()
			fmt.Printf("[PROBE 2a] snimap TCP chunkSz=%2dB written=%d/%d werr=%v resp=%s\n", chunkSz, written, len(recBytes), werr, out.detail)
		}

		// 2b. KeyUpdate(0) and KeyUpdate(1) raw wire trace on --sni-map: compare delayed vs pipelined (same TCP write)!
		for _, pipelined := range []bool{false, true} {
			for _, reqUpd := range []byte{0, 1} {
				sess, herr := doTLS13Handshake(addr, defaultHandshakeConfig("test.local"))
				if herr != nil {
					fmt.Printf("[PROBE 2b] snimap pipelined=%v KU(%d) hs err: %v\n", pipelined, reqUpd, herr)
					continue
				}
				ku := makeHandshakeMsg(HSKeyUpdate, []byte{reqUpd})
				rKU := sess.appTx.sealRecord(RecHandshake, ku)
				sess.appTx, _ = sess.appTx.ratchet()
				rApp := sess.appTx.sealRecord(RecAppData, []byte("GET /secure-hello HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n"))
				if pipelined {
					_, _ = sess.conn.Write(append(rKU, rApp...))
				} else {
					_, _ = sess.conn.Write(rKU)
					time.Sleep(100 * time.Millisecond)
					_, _ = sess.conn.Write(rApp)
				}
				gotApp := false
				var lastErr error
				for range 3 {
					rec, rerr := readTLSRecord(sess.conn, 1000*time.Millisecond)
					if rerr != nil {
						lastErr = rerr
						break
					}
					it, pt, oerr := sess.appRx.openRecord(rec)
					if oerr == nil {
						if it == RecHandshake && len(pt) >= 5 && pt[0] == HSKeyUpdate {
							sess.appRx, _ = sess.appRx.ratchet()
						} else if it == RecAppData && len(pt) > 0 {
							gotApp = true
						}
					} else {
						lastErr = oerr
						break
					}
				}
				fmt.Printf("[PROBE 2b] snimap pipelined=%v KU(%d) -> gotApp=%v lastErr=%v\n", pipelined, reqUpd, gotApp, lastErr)
				sess.close()
			}
		}

		// 2c. Post-handshake bad AEAD tag raw response bytes on --sni-map
		{
			sess, herr := doTLS13Handshake(addr, defaultHandshakeConfig("test.local"))
			if herr == nil {
				r := sess.appTx.sealRecord(RecAppData, []byte("GET / HTTP/1.1\r\nHost: test.local\r\n\r\n"))
				r[len(r)-1] ^= 0x01
				_, _ = sess.conn.Write(r)
				out := classifyResponse(sess.conn, sess.hsRx, sess.appRx, 1000*time.Millisecond)
				fmt.Printf("[PROBE 2c] snimap post-fin bad AEAD tag -> kind=%s rawLen=%d detail=%s\n", out.kind, len(out.raw), out.detail)
				sess.close()
			}
		}

		srvSNI.stop()
	}

	// 3. bogo_shim.exe -is-server probes (PureGoose server directly): pre-CCS, ALPN mismatch, 1-byte TCP frag!
	for _, testName := range []string{"pre_ccs_then_ch", "alpn_mismatch_h3", "1byte_tcp_ch"} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		port := ln.Addr().(*net.TCPAddr).Port
		resCh := make(chan string, 1)
		go func() {
			defer ln.Close()
			_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(4 * time.Second))
			c, aerr := ln.Accept()
			if aerr != nil {
				resCh <- "accept_err:" + aerr.Error()
				return
			}
			defer c.Close()
			var idb [8]byte
			_, _ = io.ReadFull(c, idb[:])
			cfg := defaultHandshakeConfig("test.local")
			switch testName {
			case "pre_ccs_then_ch":
				_, _ = c.Write(makeRecord(RecCCS, 0x0303, []byte{0x01}))
				s, herr := doTLS13HandshakeOnConn(c, cfg)
				if herr != nil {
					resCh <- "REJECTED:" + herr.Error()
				} else {
					s.close()
					resCh <- "ACCEPTED_PRE_CCS!"
				}
			case "alpn_mismatch_h3":
				cfg.alpn = []string{"h3"}
				s, herr := doTLS13HandshakeOnConn(c, cfg)
				if herr != nil {
					resCh <- "REJECTED:" + herr.Error()
				} else {
					alpn := s.negotiatedALPN
					s.close()
					resCh <- fmt.Sprintf("ACCEPTED_ALPN=%q!", alpn)
				}
			case "1byte_tcp_ch":
				cfg.oneByteTCP = true
				s, herr := doTLS13HandshakeOnConn(c, cfg)
				if herr != nil {
					resCh <- "FAILED:" + herr.Error()
				} else {
					s.close()
					resCh <- "1BYTE_OK"
				}
			}
		}()
		rc, shimOut := runBoGoShim(bogoShimExe, port, 9001, "-is-server", "-cert-file", pki.edCertPath, "-key-file", pki.edKeyPath, "-alpn-protos", "h2,http/1.1")
		peerNote := <-resCh
		fmt.Printf("[PROBE 3] bogo_shim -is-server %s -> rc=%d shim=%q peer=%s\n", testName, rc, shimOut, peerNote)
	}

	// 4. http3_server.exe: exact exit code on 0-byte UDP packet, valid 1B varint 0x03 setting, duplicate settings!
	{
		srv, err := startManagedServer("h3_exit_probe", http3ServerExe, nil, nil, udpShutdown)
		if err == nil {
			addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
			// Test valid 1-byte varint forbidden setting 0x03 (04 02 03 01)
			r03, err03 := sendUDPAndRecv(addr, []byte{0x04, 0x02, 0x03, 0x01}, 500*time.Millisecond)
			fmt.Printf("[PROBE 4a] http3 forbidden setting 0x03 (val=1) -> err=%v hex=%x\n", err03, r03)

			// Test duplicate SETTINGS (two separate frames in one packet vs two packets)
			rDup1, errDup1 := sendUDPAndRecv(addr, []byte{0x04, 0x00}, 500*time.Millisecond)
			rDup2, errDup2 := sendUDPAndRecv(addr, []byte{0x04, 0x00}, 500*time.Millisecond)
			fmt.Printf("[PROBE 4b] http3 two consecutive SETTINGS -> pkt1=(%v,%x) pkt2=(%v,%x)\n", errDup1, rDup1, errDup2, rDup2)

			// Now send 0-byte UDP datagram and wait for process exit!
			c, _ := net.DialTimeout("udp", addr, time.Second)
			_, _ = c.Write([]byte{})
			_ = c.Close()
			exitCh := make(chan error, 1)
			go func() { exitCh <- srv.cmd.Wait() }()
			select {
			case werr := <-exitCh:
				rc := 0
				if werr != nil {
					if ee, ok := werr.(*exec.ExitError); ok {
						rc = ee.ExitCode()
					} else {
						rc = -1
					}
				}
				srv.stopped = true
				fmt.Printf("[PROBE 4c] http3_server after 0-byte UDP datagram -> EXITED IMMEDIATELY! exit_code=%d err=%v stderr=%q\n", rc, werr, srv.getStderr())
			case <-time.After(1500 * time.Millisecond):
				fmt.Printf("[PROBE 4c] http3_server still running after 0-byte UDP datagram\n")
				srv.stop()
			}
		}
	}

	// 5. Check dup_identical_cl in smuggling_wing vs smuggling_wing_h1
	{
		raw := []byte("POST / HTTP/1.1\r\nHost: a.com\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n12345")
		tsv := filepath.Join(scratchDir, "dup_cl.tsv")
		_ = writePEMFile // keep ref
		_ = hex.EncodeToString
		_ = binary.BigEndian
		_ = strings.TrimSpace
		cmdW := exec.Command(exePath(binDir, "smuggling_wing"), tsv)
		cmdH := exec.Command(exePath(binDir, "smuggling_wing_h1"), tsv)
		_ = writeRawFile(tsv, "dup_identical_cl\t"+hex.EncodeToString(raw)+"\n")
		outW, _ := cmdW.CombinedOutput()
		outH, _ := cmdH.CombinedOutput()
		fmt.Printf("[PROBE 5] dup_identical_cl -> wing=%q | wing_h1=%q\n", strings.TrimSpace(string(outW)), strings.TrimSpace(string(outH)))
	}
}

func writeRawFile(path, s string) error {
	return writeFileBytes(path, []byte(s))
}
