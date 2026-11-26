// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os/exec"
	"strings"
	"time"
)

// --- Independent Fault-Injecting Go TLS 1.3 Server ---

type parsedCH struct {
	raw       []byte
	legacyVer uint16
	random    []byte
	sessionID []byte
	ciphers   []uint16
	sni       string
	alpn      []string
	groups    []uint16
	sigAlgs   []uint16
	keyShares map[uint16][]byte
}

func parseClientHello(hsMsg []byte) (*parsedCH, error) {
	if len(hsMsg) < 4 || hsMsg[0] != HSClientHello {
		return nil, fmt.Errorf("not ClientHello: type=%d", hsMsg[0])
	}
	b := hsMsg[4:]
	if len(b) < 35 {
		return nil, errors.New("CH too short")
	}
	ch := &parsedCH{raw: append([]byte{}, hsMsg...), keyShares: map[uint16][]byte{}}
	ch.legacyVer = binary.BigEndian.Uint16(b[0:2])
	ch.random = append([]byte{}, b[2:34]...)
	sidLen := int(b[34])
	off := 35
	if off+sidLen+2 > len(b) {
		return nil, errors.New("CH sid overflow")
	}
	ch.sessionID = append([]byte{}, b[off:off+sidLen]...)
	off += sidLen
	csLen := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if off+csLen+1 > len(b) {
		return nil, errors.New("CH cs overflow")
	}
	for i := 0; i < csLen; i += 2 {
		ch.ciphers = append(ch.ciphers, binary.BigEndian.Uint16(b[off+i:off+i+2]))
	}
	off += csLen
	compLen := int(b[off])
	off += 1 + compLen
	if off+2 > len(b) {
		return ch, nil
	}
	extLen := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	end := min(off+extLen, len(b))
	for off+4 <= end {
		et := binary.BigEndian.Uint16(b[off : off+2])
		el := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4
		if off+el > end {
			break
		}
		eb := b[off : off+el]
		off += el
		switch et {
		case ExtSNI:
			if len(eb) >= 5 {
				nl := int(binary.BigEndian.Uint16(eb[3:5]))
				if 5+nl <= len(eb) {
					ch.sni = string(eb[5 : 5+nl])
				}
			}
		case ExtALPN:
			if len(eb) >= 2 {
				for p := 2; p < len(eb); {
					l := int(eb[p])
					p++
					if p+l > len(eb) {
						break
					}
					ch.alpn = append(ch.alpn, string(eb[p:p+l]))
					p += l
				}
			}
		case ExtSupportedGroups:
			if len(eb) >= 2 {
				for p := 2; p+1 < len(eb); p += 2 {
					ch.groups = append(ch.groups, binary.BigEndian.Uint16(eb[p:p+2]))
				}
			}
		case ExtSigAlgs:
			if len(eb) >= 2 {
				for p := 2; p+1 < len(eb); p += 2 {
					ch.sigAlgs = append(ch.sigAlgs, binary.BigEndian.Uint16(eb[p:p+2]))
				}
			}
		case ExtKeyShare:
			if len(eb) >= 2 {
				for p := 2; p+4 <= len(eb); {
					g := binary.BigEndian.Uint16(eb[p : p+2])
					kl := int(binary.BigEndian.Uint16(eb[p+2 : p+4]))
					p += 4
					if p+kl > len(eb) {
						break
					}
					ch.keyShares[g] = append([]byte{}, eb[p:p+kl]...)
					p += kl
				}
			}
		}
	}
	return ch, nil
}

type serverFaultConfig struct {
	cipher             uint16
	certType           string // "ecdsa", "ed25519", "rsa"
	customCertChain    [][]byte
	downgradeSentinel  []byte // 8 bytes placed at ServerHello.random[24:32]
	tls12ServerHello   bool   // send TLS 1.2 SH without supported_versions
	overrideSHVersion  uint16 // override supported_versions in SH (0 => 0x0304)
	overrideSHLegacyV  uint16 // override legacy_version in SH (0 => 0x0303)
	wrongSessionIDEcho bool
	nonZeroSHComp      bool
	customServerKS     []byte // overrides X25519 server key share bytes
	customServerKSGrp  uint16
	corruptEETag       bool
	corruptCertTag     bool
	corruptCVTag       bool
	corruptFinTag      bool
	corruptFinMAC      bool
	corruptCVSigFlip   bool
	cvEd25519SgeL      bool // Ed25519 S' = S + L (or S = L)
	cvECDSAHighS       bool // ECDSA s' = n - s
	cvECDSABEROverlong bool // non-canonical BER INTEGER in ECDSA (r,s)
	cvECDSATrailing    bool // trailing byte in ECDSA sig
	cvRSAPKCS1v15      bool // use forbidden rsa_pkcs1_sha256 (0x0401) in TLS 1.3 CV
	cvSigAlgMismatch   bool // claim Ed25519 alg for ECDSA cert
	skipEECertCV       bool // SH -> Finished
	skipCertCV         bool // SH -> EE -> Finished
	skipCV             bool // SH -> EE -> Cert -> Finished
	swapEECert         bool // SH -> Cert -> EE -> CV -> Finished
	dupEE              bool // SH -> EE -> EE -> Cert -> CV -> Finished
	appDataBeforeFin   bool // send AppData before server Finished
	doubleHRR          bool // send HRR twice
	hrrSameGroup       bool // send HRR requesting X25519 when client already sent X25519
	plaintextEE        bool // send EE in plaintext handshake record
	nstBeforeFin       bool // send NewSessionTicket before Finished
	malformedKeyUpdate bool // after handshake send KeyUpdate(2)
	allZeroInnerPT     bool // send all-zero inner plaintext instead of EE
	oneByteFrag        bool
	echoAppData        bool
}

func buildServerHelloMsg(legacyVer uint16, random, sid []byte, cipher uint16, comp byte, exts []rawExt) []byte {
	var body []byte
	body = binary.BigEndian.AppendUint16(body, legacyVer)
	body = append(body, random...)
	body = append(body, byte(len(sid)))
	body = append(body, sid...)
	body = binary.BigEndian.AppendUint16(body, cipher)
	body = append(body, comp)
	var eb []byte
	for _, e := range exts {
		eb = binary.BigEndian.AppendUint16(eb, e.typ)
		eb = binary.BigEndian.AppendUint16(eb, uint16(len(e.body)))
		eb = append(eb, e.body...)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(eb)))
	body = append(body, eb...)
	return makeHandshakeMsg(HSServerHello, body)
}

func buildCertHandshakeMsg(chain [][]byte) []byte {
	var entries []byte
	for _, c := range chain {
		entries = append(entries, byte(len(c)>>16), byte(len(c)>>8), byte(len(c)))
		entries = append(entries, c...)
		entries = append(entries, 0x00, 0x00) // cert extensions len = 0
	}
	var body []byte
	body = append(body, 0x00) // request context len = 0
	body = append(body, byte(len(entries)>>16), byte(len(entries)>>8), byte(len(entries)))
	body = append(body, entries...)
	return makeHandshakeMsg(HSCertificate, body)
}

// Ed25519 curve order L = 2^252 + 27742317777372353535851937790883648493
var ed25519OrderL, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
var p256OrderN, _ = new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

func makeEd25519MalleableSig(sig []byte) []byte {
	out := append([]byte{}, sig...)
	// S is little-endian 32 bytes in sig[32:64]. Compute S + L (if < 2^256; guaranteed since S < L < 2^253).
	sBE := reverseBytes(out[32:64])
	sInt := new(big.Int).SetBytes(sBE)
	sPlusL := new(big.Int).Add(sInt, ed25519OrderL)
	be := sPlusL.Bytes()
	var sLE [32]byte
	for i := 0; i < len(be) && i < 32; i++ {
		sLE[i] = be[len(be)-1-i]
	}
	copy(out[32:64], sLE[:])
	return out
}

func makeECDSAHighS(derSig []byte) ([]byte, error) {
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(derSig, &parsed); err != nil {
		return nil, err
	}
	// If S is already high (> n/2), keep it; if low, replace with n - S (still mathematically valid ECDSA signature!)
	halfN := new(big.Int).Rsh(p256OrderN, 1)
	if parsed.S.Cmp(halfN) <= 0 {
		parsed.S = new(big.Int).Sub(p256OrderN, parsed.S)
	}
	return asn1.Marshal(parsed)
}

func makeECDSABEROverlong(derSig []byte) ([]byte, error) {
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(derSig, &parsed); err != nil {
		return nil, err
	}
	// Encode R with non-minimal extra leading 0x00 byte (BER, invalid DER!)
	rb := append([]byte{0x00, 0x00}, parsed.R.Bytes()...)
	sb := parsed.S.Bytes()
	if len(sb) > 0 && sb[0]&0x80 != 0 {
		sb = append([]byte{0x00}, sb...)
	}
	rTLV := append([]byte{0x02, byte(len(rb))}, rb...)
	sTLV := append([]byte{0x02, byte(len(sb))}, sb...)
	body := append(rTLV, sTLV...)
	// Also use overlong length 0x81 <len> for SEQUENCE if < 128
	return append([]byte{0x30, 0x81, byte(len(body))}, body...), nil
}

func runFaultServerOnce(pki *testPKI, fc serverFaultConfig, expectBoGoShimID bool, handlerDone chan<- string) (int, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		defer ln.Close()
		_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(6 * time.Second))
		conn, err := ln.Accept()
		if err != nil {
			handlerDone <- "accept_err:" + err.Error()
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		if expectBoGoShimID {
			var idBuf [8]byte
			if _, err := io.ReadFull(conn, idBuf[:]); err != nil {
				handlerDone <- "shim_id_err:" + err.Error()
				return
			}
		}

		// Read ClientHello
		rec, err := readTLSRecord(conn, 3*time.Second)
		if err != nil {
			handlerDone <- "read_ch_err:" + err.Error()
			return
		}
		ch, err := parseClientHello(rec.payload)
		if err != nil {
			handlerDone <- "parse_ch_err:" + err.Error()
			return
		}

		cipherID := fc.cipher
		if cipherID == 0 {
			cipherID = CipherAES128GCM
		}
		spec, err := getCipherSpec(cipherID)
		if err != nil {
			handlerDone <- "spec_err:" + err.Error()
			return
		}

		// HRR faults
		if fc.doubleHRR || fc.hrrSameGroup {
			hrrExts := []rawExt{
				{typ: ExtSupportedVersions, body: []byte{0x03, 0x04}},
				{typ: ExtKeyShare, body: []byte{0x00, 0x1d}}, // X25519
			}
			hrr := buildServerHelloMsg(0x0303, hrrRandom, ch.sessionID, cipherID, 0x00, hrrExts)
			_ = writeBytesOpts(conn, makeRecord(RecHandshake, 0x0303, hrr), fc.oneByteFrag)
			if fc.doubleHRR {
				// Read second CH then send a SECOND HRR!
				rec2, rerr := readTLSRecord(conn, 2*time.Second)
				if rerr != nil {
					handlerDone <- "after_hrr1:" + rerr.Error()
					return
				}
				if rec2.typ == RecAlert && len(rec2.payload) >= 2 {
					handlerDone <- fmt.Sprintf("alert_after_hrr1:%s", alertName(rec2.payload[1]))
					return
				}
				_ = writeBytesOpts(conn, makeRecord(RecHandshake, 0x0303, hrr), fc.oneByteFrag)
			}
			out := classifyResponse(conn, nil, nil, 1500*time.Millisecond)
			handlerDone <- "client_resp:" + out.detail
			return
		}

		// Key exchange setup
		srvKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
		srvPub := srvKey.PublicKey().Bytes()
		ksGroup := GroupX25519
		if fc.customServerKS != nil {
			srvPub = fc.customServerKS
		}
		if fc.customServerKSGrp != 0 {
			ksGroup = fc.customServerKSGrp
		}

		srvRnd := make([]byte, 32)
		_, _ = rand.Read(srvRnd)
		if len(fc.downgradeSentinel) == 8 {
			copy(srvRnd[24:32], fc.downgradeSentinel)
		}
		sid := append([]byte{}, ch.sessionID...)
		if fc.wrongSessionIDEcho {
			if len(sid) == 0 {
				sid = []byte{0xaa, 0xbb}
			} else {
				sid[0] ^= 0xff
			}
		}
		shLegacyVer := fc.overrideSHLegacyV
		if shLegacyVer == 0 {
			shLegacyVer = 0x0303
		}
		shComp := byte(0x00)
		if fc.nonZeroSHComp {
			shComp = 0x01
		}

		var shExts []rawExt
		if !fc.tls12ServerHello {
			sv := fc.overrideSHVersion
			if sv == 0 {
				sv = 0x0304
			}
			shExts = append(shExts, rawExt{typ: ExtSupportedVersions, body: []byte{byte(sv >> 8), byte(sv)}})
			ksBody := binary.BigEndian.AppendUint16(nil, ksGroup)
			ksBody = binary.BigEndian.AppendUint16(ksBody, uint16(len(srvPub)))
			ksBody = append(ksBody, srvPub...)
			shExts = append(shExts, rawExt{typ: ExtKeyShare, body: ksBody})
		}

		shMsg := buildServerHelloMsg(shLegacyVer, srvRnd, sid, cipherID, shComp, shExts)
		if err := writeBytesOpts(conn, makeRecord(RecHandshake, 0x0303, shMsg), fc.oneByteFrag); err != nil {
			handlerDone <- "write_sh_err:" + err.Error()
			return
		}

		// If ServerHello itself was fatally malformed (TLS 1.2 SH, bad KS, downgrade, etc.), client may fail right here;
		// still try to compute keys if possible so we can send encrypted flight if client didn't reject SH!
		var shared []byte
		if cliKS, ok := ch.keyShares[GroupX25519]; ok && len(cliKS) == 32 && fc.customServerKS == nil && !fc.tls12ServerHello {
			if peerPub, perr := ecdh.X25519().NewPublicKey(cliKS); perr == nil {
				shared, _ = srvKey.ECDH(peerPub)
			}
		}
		if len(shared) == 0 {
			// Fallback dummy shared secret so we can still observe if client continues past broken SH!
			shared = make([]byte, 32)
		}

		transcript := [][]byte{ch.raw, shMsg}
		zeros := make([]byte, spec.hLen)
		earlySec := hkdfExtract(spec.hashFn, zeros, zeros)
		derived1 := deriveSecret(spec, earlySec, "derived", emptyHash(spec))
		hsSec := hkdfExtract(spec.hashFn, derived1, shared)
		thSH := hashMessages(spec, transcript...)
		cHsSec := deriveSecret(spec, hsSec, "c hs traffic", thSH)
		sHsSec := deriveSecret(spec, hsSec, "s hs traffic", thSH)
		hsTx, _ := newTrafficState(spec, sHsSec)
		hsRx, _ := newTrafficState(spec, cHsSec)

		// Build EncryptedExtensions
		var eeExts []byte
		if len(ch.alpn) > 0 {
			proto := ch.alpn[0]
			alpnList := append([]byte{byte(len(proto))}, proto...)
			alpnBody := binary.BigEndian.AppendUint16(nil, uint16(len(alpnList)))
			alpnBody = append(alpnBody, alpnList...)
			eeExts = binary.BigEndian.AppendUint16(eeExts, ExtALPN)
			eeExts = binary.BigEndian.AppendUint16(eeExts, uint16(len(alpnBody)))
			eeExts = append(eeExts, alpnBody...)
		}
		eeBody := binary.BigEndian.AppendUint16(nil, uint16(len(eeExts)))
		eeBody = append(eeBody, eeExts...)
		eeMsg := makeHandshakeMsg(HSEncryptedExtensions, eeBody)

		// Choose certificate chain & signing key
		certType := fc.certType
		if certType == "" {
			certType = "ecdsa"
		}
		var chain [][]byte
		switch certType {
		case "ed25519":
			chain = [][]byte{pki.edDER, pki.caDER}
		case "rsa":
			chain = [][]byte{pki.rsaDER, pki.caDER}
		default:
			chain = [][]byte{pki.ecDER, pki.caDER}
		}
		if fc.customCertChain != nil {
			chain = fc.customCertChain
		}
		certMsg := buildCertHandshakeMsg(chain)

		// Build CertificateVerify
		buildCV := func(curTranscript [][]byte) []byte {
			th := hashMessages(spec, curTranscript...)
			var content []byte
			content = append(content, bytes.Repeat([]byte{0x20}, 64)...)
			content = append(content, []byte("TLS 1.3, server CertificateVerify")...)
			content = append(content, 0x00)
			content = append(content, th...)

			var sigAlg uint16
			var sig []byte
			switch certType {
			case "ed25519":
				sigAlg = SigEd25519
				sig = ed25519.Sign(pki.edKey, content)
				if fc.cvEd25519SgeL {
					sig = makeEd25519MalleableSig(sig)
				}
			case "rsa":
				d := sha256.Sum256(content)
				if fc.cvRSAPKCS1v15 {
					sigAlg = SigRSAPKCS1SHA256
					sig, _ = rsa.SignPKCS1v15(rand.Reader, pki.rsaKey, crypto.SHA256, d[:])
				} else {
					sigAlg = SigRSAPSSSHA256
					sig, _ = rsa.SignPSS(rand.Reader, pki.rsaKey, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
				}
			default:
				sigAlg = SigECDSAP256SHA256
				d := sha256.Sum256(content)
				sig, _ = ecdsa.SignASN1(rand.Reader, pki.ecKey, d[:])
				if fc.cvECDSAHighS {
					if hs, err := makeECDSAHighS(sig); err == nil {
						sig = hs
					}
				}
				if fc.cvECDSABEROverlong {
					if ber, err := makeECDSABEROverlong(sig); err == nil {
						sig = ber
					}
				}
				if fc.cvECDSATrailing {
					sig = append(sig, 0x00)
				}
			}
			if fc.cvSigAlgMismatch {
				if sigAlg == SigEd25519 {
					sigAlg = SigECDSAP256SHA256
				} else {
					sigAlg = SigEd25519
				}
			}
			if fc.corruptCVSigFlip && len(sig) > 0 {
				sig[len(sig)-1] ^= 0x01
			}
			cvBody := binary.BigEndian.AppendUint16(nil, sigAlg)
			cvBody = binary.BigEndian.AppendUint16(cvBody, uint16(len(sig)))
			cvBody = append(cvBody, sig...)
			return makeHandshakeMsg(HSCertificateVerify, cvBody)
		}

		// Helper to send an encrypted HS message with optional tag corruption
		sendHS := func(msg []byte, corruptTag bool) error {
			r := hsTx.sealRecord(RecHandshake, msg)
			if corruptTag {
				r[len(r)-1] ^= 0x01
			}
			return writeBytesOpts(conn, r, fc.oneByteFrag)
		}

		if fc.tls12ServerHello {
			// Don't send TLS 1.3 encrypted flight on TLS 1.2 SH; just read client alert/EOF
			out := classifyResponse(conn, nil, nil, 1500*time.Millisecond)
			handlerDone <- "client_resp:" + out.detail
			return
		}

		if fc.allZeroInnerPT {
			r := hsTx.sealRawInner(make([]byte, 16), 0x0303)
			_ = writeBytesOpts(conn, r, fc.oneByteFrag)
			out := classifyResponse(conn, hsRx, nil, 1500*time.Millisecond)
			handlerDone <- "client_resp:" + out.detail
			return
		}

		if fc.plaintextEE {
			_ = writeBytesOpts(conn, makeRecord(RecHandshake, 0x0303, eeMsg), fc.oneByteFrag)
			out := classifyResponse(conn, hsRx, nil, 1500*time.Millisecond)
			handlerDone <- "client_resp:" + out.detail
			return
		}

		// Construct ordered or faulted flight
		if fc.skipEECertCV {
			// SH -> Finished
			finMAC := computeFinishedMAC(spec, sHsSec, hashMessages(spec, transcript...))
			_ = sendHS(makeHandshakeMsg(HSFinished, finMAC), false)
		} else if fc.skipCertCV {
			transcript = append(transcript, eeMsg)
			_ = sendHS(eeMsg, fc.corruptEETag)
			finMAC := computeFinishedMAC(spec, sHsSec, hashMessages(spec, transcript...))
			_ = sendHS(makeHandshakeMsg(HSFinished, finMAC), false)
		} else if fc.skipCV {
			transcript = append(transcript, eeMsg, certMsg)
			_ = sendHS(eeMsg, false)
			_ = sendHS(certMsg, false)
			finMAC := computeFinishedMAC(spec, sHsSec, hashMessages(spec, transcript...))
			_ = sendHS(makeHandshakeMsg(HSFinished, finMAC), false)
		} else if fc.swapEECert {
			transcript = append(transcript, certMsg, eeMsg)
			cvMsg := buildCV(transcript)
			transcript = append(transcript, cvMsg)
			finMAC := computeFinishedMAC(spec, sHsSec, hashMessages(spec, transcript...))
			_ = sendHS(certMsg, false)
			_ = sendHS(eeMsg, false)
			_ = sendHS(cvMsg, false)
			_ = sendHS(makeHandshakeMsg(HSFinished, finMAC), false)
		} else {
			// Normal or dupEE / nstBeforeFin / appDataBeforeFin
			transcript = append(transcript, eeMsg)
			_ = sendHS(eeMsg, fc.corruptEETag)
			if fc.dupEE {
				transcript = append(transcript, eeMsg)
				_ = sendHS(eeMsg, false)
			}
			transcript = append(transcript, certMsg)
			_ = sendHS(certMsg, fc.corruptCertTag)
			cvMsg := buildCV(transcript)
			transcript = append(transcript, cvMsg)
			_ = sendHS(cvMsg, fc.corruptCVTag)
			if fc.nstBeforeFin {
				nst := makeHandshakeMsg(HSNewSessionTicket, make([]byte, 24))
				_ = sendHS(nst, false)
			}
			if fc.appDataBeforeFin {
				r := hsTx.sealRecord(RecAppData, []byte("PREMATURE_APPDATA"))
				_ = writeBytesOpts(conn, r, fc.oneByteFrag)
			}
			finMAC := computeFinishedMAC(spec, sHsSec, hashMessages(spec, transcript...))
			if fc.corruptFinMAC {
				finMAC[0] ^= 0x01
			}
			finMsg := makeHandshakeMsg(HSFinished, finMAC)
			transcript = append(transcript, finMsg)
			_ = sendHS(finMsg, fc.corruptFinTag)
		}

		// Derive app secrets to verify client Finished and optionally echo data
		thSF := hashMessages(spec, transcript...)
		derived2 := deriveSecret(spec, hsSec, "derived", emptyHash(spec))
		masterSec := hkdfExtract(spec.hashFn, derived2, zeros)
		cAppSec := deriveSecret(spec, masterSec, "c ap traffic", thSF)
		sAppSec := deriveSecret(spec, masterSec, "s ap traffic", thSF)
		appTx, _ := newTrafficState(spec, sAppSec)
		appRx, _ := newTrafficState(spec, cAppSec)

		// Read client Finished (skip optional CCS)
		gotClientFin := false
		for !gotClientFin {
			r, rerr := readTLSRecord(conn, 2*time.Second)
			if rerr != nil {
				handlerDone <- "client_after_flight:" + rerr.Error()
				return
			}
			if r.typ == RecCCS {
				continue
			}
			if r.typ == RecAlert && len(r.payload) >= 2 {
				handlerDone <- fmt.Sprintf("client_plain_alert:%s", alertName(r.payload[1]))
				return
			}
			it, pt, oerr := hsRx.openRecord(r)
			if oerr != nil {
				handlerDone <- "client_hs_decrypt_err:" + oerr.Error()
				return
			}
			if it == RecAlert && len(pt) >= 2 {
				handlerDone <- fmt.Sprintf("client_enc_alert:%s", alertName(pt[1]))
				return
			}
			if it == RecHandshake && len(pt) >= 4 && pt[0] == HSFinished {
				expCFin := computeFinishedMAC(spec, cHsSec, thSF)
				if !bytes.Equal(pt[4:], expCFin) {
					handlerDone <- "client_fin_mac_mismatch"
					return
				}
				gotClientFin = true
			}
		}

		if fc.malformedKeyUpdate {
			badKU := makeHandshakeMsg(HSKeyUpdate, []byte{0x02})
			_ = writeBytesOpts(conn, appTx.sealRecord(RecHandshake, badKU), false)
			out := classifyResponse(conn, hsRx, appRx, 1500*time.Millisecond)
			handlerDone <- "after_bad_ku:" + out.detail
			return
		}

		if fc.echoAppData {
			// BoGo echo protocol: read client encrypted AppData, echo XOR 0xff (BoGo convention) or read/write!
			// Wait: BoGo shim echoes XOR 0xff when peer writes first! Let's write "hello" and read back XOR 0xff!
			msg := []byte("HELLO_BOGO_TEST!")
			_ = writeBytesOpts(conn, appTx.sealRecord(RecAppData, msg), fc.oneByteFrag)
			r, rerr := readTLSRecord(conn, 2*time.Second)
			if rerr != nil {
				handlerDone <- "echo_read_err:" + rerr.Error()
				return
			}
			it, pt, oerr := appRx.openRecord(r)
			if oerr != nil {
				handlerDone <- "echo_open_err:" + oerr.Error()
				return
			}
			// Send close_notify cleanly
			_ = writeBytesOpts(conn, appTx.sealRecord(RecAlert, []byte{0x01, 0x00}), false)
			handlerDone <- fmt.Sprintf("HANDSHAKE_AND_ECHO_OK(inner=%d,len=%d)", it, len(pt))
			return
		}
		handlerDone <- "CLIENT_ACCEPTED_HANDSHAKE"
	}()

	return port, func() { _ = ln.Close() }
}

// --- Non-canonical DER Certificate Builders ---

func derLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append([]byte{byte(v & 0xff)}, b...)
	}
	return append([]byte{byte(0x80 | len(b))}, b...)
}

func derTLV(tag byte, body []byte) []byte {
	out := []byte{tag}
	out = append(out, derLen(len(body))...)
	return append(out, body...)
}

func derSeq(body []byte) []byte { return derTLV(0x30, body) }
func derInt(v int64) []byte {
	b := big.NewInt(v).Bytes()
	if len(b) == 0 {
		b = []byte{0}
	} else if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return derTLV(0x02, b)
}

func signDERCertWithCA(tbs []byte, outerSigAlgOID []byte, caKey *ecdsa.PrivateKey, bitStringUnused byte, trailing []byte, outerLenMutate string) []byte {
	d := sha256.Sum256(tbs)
	sig, _ := ecdsa.SignASN1(rand.Reader, caKey, d[:])
	// sigAlg SEQUENCE { OID }
	sigAlgSeq := derSeq(outerSigAlgOID)
	bitStr := derTLV(0x03, append([]byte{bitStringUnused}, sig...))
	body := append(append(append([]byte{}, tbs...), sigAlgSeq...), bitStr...)
	var cert []byte
	switch outerLenMutate {
	case "indefinite":
		cert = append([]byte{0x30, 0x80}, body...)
		cert = append(cert, 0x00, 0x00)
	case "overlong":
		// 3-byte length encoding even when 2 bytes suffice (0x83 0x00 hi lo)
		l := len(body)
		cert = append([]byte{0x30, 0x83, 0x00, byte(l >> 8), byte(l)}, body...)
	default:
		cert = derSeq(body)
	}
	return append(cert, trailing...)
}

// Extract TBS bytes from a valid DER certificate so we can craft targeted DER mutations
func extractCertParts(der []byte) (tbs, outerSigAlg, sigBitStr []byte, err error) {
	var outer asn1.RawValue
	if _, err = asn1.Unmarshal(der, &outer); err != nil {
		return
	}
	rest := outer.Bytes
	var v1, v2, v3 asn1.RawValue
	if rest, err = asn1.Unmarshal(rest, &v1); err != nil {
		return
	}
	if rest, err = asn1.Unmarshal(rest, &v2); err != nil {
		return
	}
	if _, err = asn1.Unmarshal(rest, &v3); err != nil {
		return
	}
	return v1.FullBytes, v2.FullBytes, v3.FullBytes, nil
}

// Build a DER cert with non-minimal INTEGER serial (0x02 0x02 0x00 0x01) signed by CA
func buildNonMinimalIntCert(pki *testPKI) []byte {
	tbs, _, _, err := extractCertParts(pki.ecDER)
	if err != nil {
		return nil
	}
	// Replace serial number inside TBS: TBS is SEQUENCE { [0] v3, serial INT, ... }
	var tbsSeq asn1.RawValue
	_, _ = asn1.Unmarshal(tbs, &tbsSeq)
	rest := tbsSeq.Bytes
	var verField, serField asn1.RawValue
	rest, _ = asn1.Unmarshal(rest, &verField)
	rest, _ = asn1.Unmarshal(rest, &serField)
	badSer := []byte{0x02, 0x02, 0x00, 0x01} // non-minimal positive integer 1!
	newTBSBody := append(append(append([]byte{}, verField.FullBytes...), badSer...), rest...)
	newTBS := derSeq(newTBSBody)
	oidEcdsaSha256 := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}
	return signDERCertWithCA(newTBS, oidEcdsaSha256, pki.caKey, 0, nil, "")
}

// Build a DER cert with overlong length inside an inner field (0x81 0x05 on a 5-byte field)
func buildOverlongInnerLenCert(pki *testPKI) []byte {
	tbs, _, _, err := extractCertParts(pki.ecDER)
	if err != nil {
		return nil
	}
	// Mutate serial INTEGER to use 0x81 0x01 length for 1-byte value!
	var tbsSeq asn1.RawValue
	_, _ = asn1.Unmarshal(tbs, &tbsSeq)
	rest := tbsSeq.Bytes
	var verField, serField asn1.RawValue
	rest, _ = asn1.Unmarshal(rest, &verField)
	rest, _ = asn1.Unmarshal(rest, &serField)
	badSer := []byte{0x02, 0x81, 0x01, 0x05} // overlong length 0x81 0x01!
	newTBSBody := append(append(append([]byte{}, verField.FullBytes...), badSer...), rest...)
	newTBS := derSeq(newTBSBody)
	oidEcdsaSha256 := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}
	return signDERCertWithCA(newTBS, oidEcdsaSha256, pki.caKey, 0, nil, "")
}

// Build a DER cert with NUL byte in SAN dNSName ("localhost\x00.evil.com") signed validly by CA!
func buildNulInSANCert(pki *testPKI) []byte {
	now := time.Now().UTC()
	// Encode SAN extension manually: SEQUENCE { [2] "localhost\x00.evil.com" }
	badDNS := []byte("localhost\x00.evil.com")
	sanVal := derSeq(derTLV(0x82, badDNS))
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(901),
		Subject:               pki.ecCert.Subject,
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: false, Value: sanVal},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pki.caCert, &pki.ecKey.PublicKey, pki.caKey)
	if err != nil {
		return nil
	}
	return der
}

func runBoGoShim(bogoExe string, port int, shimID int, extraArgs ...string) (int, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	args := []string{"-port", fmt.Sprintf("%d", port), "-shim-id", fmt.Sprintf("%d", shimID)}
	args = append(args, extraArgs...)
	cmd := exec.CommandContext(ctx, bogoExe, args...)
	out, err := cmd.CombinedOutput()
	rc := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			rc = ee.ExitCode()
		} else {
			rc = -1
		}
	}
	return rc, strings.TrimSpace(string(out))
}

func runClientSuite(rec *testRecorder, bogoExe, tlsClientExe string, pki *testPKI) {
	fmt.Printf("\n================ CLIENT FAULT-INJECTION SUITE (bogo_shim.exe & tls_client.exe) ================\n")

	oidEcdsaSha256 := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}
	oidEcdsaSha384 := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03}
	tbsEC, _, _, _ := extractCertParts(pki.ecDER)

	// Prepare mutated certs
	certOverlongOuter := signDERCertWithCA(tbsEC, oidEcdsaSha256, pki.caKey, 0, nil, "overlong")
	certOverlongInner := buildOverlongInnerLenCert(pki)
	certIndefinite := signDERCertWithCA(tbsEC, oidEcdsaSha256, pki.caKey, 0, nil, "indefinite")
	certNonMinInt := buildNonMinimalIntCert(pki)
	certNonZeroUnusedBits := signDERCertWithCA(tbsEC, oidEcdsaSha256, pki.caKey, 3, nil, "")
	certTrailingGarbage := signDERCertWithCA(tbsEC, oidEcdsaSha256, pki.caKey, 0, []byte{0xde, 0xad}, "")
	certOuterSigAlgMismatch := signDERCertWithCA(tbsEC, oidEcdsaSha384, pki.caKey, 0, nil, "")
	certNulInSAN := buildNulInSANCert(pki)

	// Expired cert
	now := time.Now().UTC()
	expTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(902), Subject: pki.ecCert.Subject,
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-1 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, DNSNames: []string{"localhost"},
	}
	certExpired, _ := x509.CreateCertificate(rand.Reader, expTmpl, pki.caCert, &pki.ecKey.PublicKey, pki.caKey)

	// Self-signed untrusted cert
	ssDER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(903), Subject: pki.ecCert.Subject,
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, DNSNames: []string{"localhost"},
	}, &x509.Certificate{
		SerialNumber: big.NewInt(903), Subject: pki.ecCert.Subject,
	}, &pki.ecKey.PublicKey, pki.ecKey)

	tests := []struct {
		name       string
		cat        string
		fc         serverFaultConfig
		expectPass bool // true => shim rc==0 expected; false => shim rc!=0 expected
		infoOnly   bool
		expNote    string
	}{
		// Baselines
		{"baseline_aes128_ecdsa", "client_base", serverFaultConfig{cipher: CipherAES128GCM, certType: "ecdsa", echoAppData: true}, true, false, "rc=0"},
		{"baseline_aes256_ecdsa", "client_base", serverFaultConfig{cipher: CipherAES256GCM, certType: "ecdsa", echoAppData: true}, true, false, "rc=0"},
		{"baseline_chacha20_ecdsa", "client_base", serverFaultConfig{cipher: CipherChaCha20Poly1305, certType: "ecdsa", echoAppData: true}, true, false, "rc=0"},
		{"baseline_aes128_ed25519", "client_base", serverFaultConfig{cipher: CipherAES128GCM, certType: "ed25519", echoAppData: true}, true, false, "rc=0"},
		{"baseline_aes128_rsa_pss", "client_base", serverFaultConfig{cipher: CipherAES128GCM, certType: "rsa", echoAppData: true}, true, false, "rc=0"},
		{"baseline_1byte_server_frag", "client_base", serverFaultConfig{cipher: CipherAES128GCM, certType: "ecdsa", oneByteFrag: true, echoAppData: true}, true, false, "rc=0"},

		// Downgrade sentinels & ServerHello faults
		{"downgrade_sentinel_tls12_in_tls13_sh", "client_downgrade", serverFaultConfig{downgradeSentinel: downgrade12}, false, false, "RFC 8446 Section 4.1.3 reject DOWNGRD\\x01"},
		{"downgrade_sentinel_tls11_in_tls13_sh", "client_downgrade", serverFaultConfig{downgradeSentinel: downgrade11}, false, false, "RFC 8446 Section 4.1.3 reject DOWNGRD\\x00"},
		{"downgrade_tls12_sh_with_sentinel", "client_downgrade", serverFaultConfig{tls12ServerHello: true, downgradeSentinel: downgrade12}, false, false, "reject TLS 1.2 SH + sentinel"},
		{"sh_wrong_session_id_echo", "client_downgrade", serverFaultConfig{wrongSessionIDEcho: true}, false, false, "reject mismatched legacy_session_id_echo"},
		{"sh_nonzero_compression", "client_downgrade", serverFaultConfig{nonZeroSHComp: true}, false, false, "reject non-zero SH compression"},
		{"sh_supported_ver_0303", "client_downgrade", serverFaultConfig{overrideSHVersion: 0x0303}, false, false, "reject SH supported_versions=0x0303"},
		{"sh_legacy_ver_0304", "client_downgrade", serverFaultConfig{overrideSHLegacyV: 0x0304}, false, false, "reject SH legacy_version=0x0304"},

		// Small-order server X25519 key shares (all 7 RFC 7748 low-order points + bad lengths)
		{"srv_x25519_loworder_1_zero", "client_keyshare", serverFaultConfig{customServerKS: mustHex("0000000000000000000000000000000000000000000000000000000000000000")}, false, false, "reject all-zero server X25519"},
		{"srv_x25519_loworder_2_one", "client_keyshare", serverFaultConfig{customServerKS: mustHex("0100000000000000000000000000000000000000000000000000000000000000")}, false, false, "reject u=1 low-order server X25519"},
		{"srv_x25519_loworder_3_order8a", "client_keyshare", serverFaultConfig{customServerKS: mustHex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")}, false, false, "reject order-8a server X25519"},
		{"srv_x25519_loworder_4_order8b", "client_keyshare", serverFaultConfig{customServerKS: mustHex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157")}, false, false, "reject order-8b server X25519"},
		{"srv_x25519_loworder_5_p_minus_1", "client_keyshare", serverFaultConfig{customServerKS: mustHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")}, false, false, "reject p-1 server X25519"},
		{"srv_x25519_loworder_6_p", "client_keyshare", serverFaultConfig{customServerKS: mustHex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")}, false, false, "reject p server X25519"},
		{"srv_x25519_loworder_7_p_plus_1", "client_keyshare", serverFaultConfig{customServerKS: mustHex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")}, false, false, "reject p+1 server X25519"},
		{"srv_x25519_trunc_31B", "client_keyshare", serverFaultConfig{customServerKS: make([]byte, 31)}, false, false, "reject 31B X25519 key share"},
		{"srv_x25519_oversize_33B", "client_keyshare", serverFaultConfig{customServerKS: make([]byte, 33)}, false, false, "reject 33B X25519 key share"},

		// Non-canonical DER / X.509 certificates over live TLS 1.3
		{"cert_der_overlong_outer_len", "client_x509", serverFaultConfig{customCertChain: [][]byte{certOverlongOuter, pki.caDER}}, false, false, "reject overlong outer DER length"},
		{"cert_der_overlong_inner_len", "client_x509", serverFaultConfig{customCertChain: [][]byte{certOverlongInner, pki.caDER}}, false, false, "reject overlong inner DER length (0x81 0x01)"},
		{"cert_der_indefinite_len", "client_x509", serverFaultConfig{customCertChain: [][]byte{certIndefinite, pki.caDER}}, false, false, "reject indefinite DER length (0x80)"},
		{"cert_der_nonminimal_int", "client_x509", serverFaultConfig{customCertChain: [][]byte{certNonMinInt, pki.caDER}}, false, false, "reject non-minimal INTEGER (0x00 0x01)"},
		{"cert_der_nonzero_bitstring_unused", "client_x509", serverFaultConfig{customCertChain: [][]byte{certNonZeroUnusedBits, pki.caDER}}, false, false, "reject non-zero BIT STRING unused bits"},
		{"cert_der_trailing_garbage", "client_x509", serverFaultConfig{customCertChain: [][]byte{certTrailingGarbage, pki.caDER}}, false, false, "reject trailing DER garbage"},
		{"cert_outer_vs_tbs_sigalg_mismatch", "client_x509", serverFaultConfig{customCertChain: [][]byte{certOuterSigAlgMismatch, pki.caDER}}, false, false, "reject outer vs TBS signatureAlgorithm mismatch"},
		{"cert_nul_byte_in_san", "client_x509", serverFaultConfig{customCertChain: [][]byte{certNulInSAN, pki.caDER}}, false, false, "reject NUL byte in SAN dNSName"},
		{"cert_empty_list", "client_x509", serverFaultConfig{customCertChain: [][]byte{}}, false, false, "reject empty Certificate list"},
		{"cert_expired", "client_x509", serverFaultConfig{customCertChain: [][]byte{certExpired, pki.caDER}}, false, false, "reject expired certificate"},
		{"cert_untrusted_selfsigned", "client_x509", serverFaultConfig{customCertChain: [][]byte{ssDER}}, false, false, "reject untrusted self-signed cert"},

		// Corrupted CertificateVerify signatures
		{"cv_ed25519_1bit_flip", "client_cv", serverFaultConfig{certType: "ed25519", corruptCVSigFlip: true}, false, false, "reject corrupted Ed25519 CV"},
		{"cv_ed25519_malleable_S_ge_L", "client_cv", serverFaultConfig{certType: "ed25519", cvEd25519SgeL: true}, false, false, "RFC 8032 reject Ed25519 S >= L"},
		{"cv_ecdsa_1bit_flip", "client_cv", serverFaultConfig{certType: "ecdsa", corruptCVSigFlip: true}, false, false, "reject corrupted ECDSA CV"},
		{"cv_ecdsa_high_s", "client_cv", serverFaultConfig{certType: "ecdsa", cvECDSAHighS: true, echoAppData: true}, false, true, "observe ECDSA high-s handling (valid per SEC1, rejected if low-s enforced)"},
		{"cv_ecdsa_noncanon_ber_rs", "client_cv", serverFaultConfig{certType: "ecdsa", cvECDSABEROverlong: true}, false, false, "reject non-canonical BER ECDSA (r,s)"},
		{"cv_ecdsa_trailing_byte", "client_cv", serverFaultConfig{certType: "ecdsa", cvECDSATrailing: true}, false, false, "reject trailing byte in ECDSA DER sig"},
		{"cv_rsa_pss_1bit_flip", "client_cv", serverFaultConfig{certType: "rsa", corruptCVSigFlip: true}, false, false, "reject corrupted RSA-PSS CV"},
		{"cv_rsa_pkcs1_v15_forbidden_tls13", "client_cv", serverFaultConfig{certType: "rsa", cvRSAPKCS1v15: true}, false, false, "RFC 8446 Section 4.2.3 forbid rsa_pkcs1 in TLS 1.3 CV"},
		{"cv_sigalg_key_mismatch", "client_cv", serverFaultConfig{certType: "ecdsa", cvSigAlgMismatch: true}, false, false, "reject CV sigAlg mismatch with leaf key"},

		// Corrupted AEAD tags & Finished MAC
		{"aead_corrupt_ee_tag", "client_aead", serverFaultConfig{corruptEETag: true}, false, false, "reject bad AEAD tag on EE"},
		{"aead_corrupt_cert_tag", "client_aead", serverFaultConfig{corruptCertTag: true}, false, false, "reject bad AEAD tag on Certificate"},
		{"aead_corrupt_cv_tag", "client_aead", serverFaultConfig{corruptCVTag: true}, false, false, "reject bad AEAD tag on CertificateVerify"},
		{"aead_corrupt_fin_tag", "client_aead", serverFaultConfig{corruptFinTag: true}, false, false, "reject bad AEAD tag on Finished"},
		{"fin_bad_verify_data", "client_aead", serverFaultConfig{corruptFinMAC: true}, false, false, "reject bad server Finished MAC"},
		{"aead_all_zero_inner_pt", "client_aead", serverFaultConfig{allZeroInnerPT: true}, false, false, "reject all-zero inner plaintext"},

		// Out-of-order server flights
		{"ooo_sh_to_fin_skip_ee_cert_cv", "client_fsm", serverFaultConfig{skipEECertCV: true}, false, false, "reject SH -> Finished"},
		{"ooo_sh_ee_fin_skip_cert_cv", "client_fsm", serverFaultConfig{skipCertCV: true}, false, false, "reject SH -> EE -> Finished"},
		{"ooo_sh_ee_cert_fin_skip_cv", "client_fsm", serverFaultConfig{skipCV: true}, false, false, "reject SH -> EE -> Cert -> Finished"},
		{"ooo_swap_ee_cert", "client_fsm", serverFaultConfig{swapEECert: true}, false, false, "reject SH -> Cert -> EE"},
		{"ooo_duplicate_ee", "client_fsm", serverFaultConfig{dupEE: true}, false, false, "reject duplicate EncryptedExtensions"},
		{"ooo_appdata_before_fin", "client_fsm", serverFaultConfig{appDataBeforeFin: true}, false, false, "reject AppData before Finished"},
		{"ooo_duplicate_hrr", "client_fsm", serverFaultConfig{doubleHRR: true}, false, false, "RFC 8446 Section 4.1.4 reject duplicate HRR"},
		{"ooo_hrr_same_group", "client_fsm", serverFaultConfig{hrrSameGroup: true}, false, false, "RFC 8446 Section 4.1.4 reject HRR for already-sent group"},
		{"ooo_plaintext_ee", "client_fsm", serverFaultConfig{plaintextEE: true}, false, false, "reject plaintext EncryptedExtensions"},
		{"ooo_nst_before_fin", "client_fsm", serverFaultConfig{nstBeforeFin: true}, false, false, "reject NewSessionTicket before Finished"},
		{"ooo_malformed_server_keyupdate", "client_fsm", serverFaultConfig{malformedKeyUpdate: true}, false, false, "reject server KeyUpdate(2)"},
	}

	for i, tc := range tests {
		done := make(chan string, 1)
		port, cleanup := runFaultServerOnce(pki, tc.fc, true, done)
		rc, out := runBoGoShim(bogoExe, port, 5000+i, "-host-name", "localhost", "-trust-cert", pki.caPEMPath, "-verify-peer")
		srvNote := ""
		select {
		case srvNote = <-done:
		case <-time.After(1500 * time.Millisecond):
			srvNote = "srv_timeout"
		}
		cleanup()

		st := "PASS"
		if tc.infoOnly {
			st = "INFO"
		} else if tc.expectPass && rc != 0 {
			st = "FAIL"
		} else if !tc.expectPass && rc == 0 {
			st = "FAIL"
		}
		obs := fmt.Sprintf("rc=%d shim=%q srv=%q", rc, truncStr(out, 70), truncStr(srvNote, 70))
		rec.add("bogo_shim", tc.cat, tc.name, st, tc.expNote, obs, "")
	}

	// Also drive tls_client.exe against our fault-injecting Go TLS 1.3 server!
	// tls_client.exe uses PORT & WING_PORT env vars and connects to 127.0.0.1:<port>.
	tlsClientFaults := []struct {
		name string
		fc   serverFaultConfig
		exp  string
	}{
		{"tls_client_downgrade_sentinel", serverFaultConfig{downgradeSentinel: downgrade12}, "must not pass TLS_CLI_VERIFIED_H2"},
		{"tls_client_downgrade_sentinel_11", serverFaultConfig{downgradeSentinel: downgrade11}, "must reject DOWNGRD\\x00 sentinel"},
		{"tls_client_sh_wrong_sid_echo", serverFaultConfig{wrongSessionIDEcho: true}, "must reject mismatched SH session_id_echo"},
		{"tls_client_sh_nonzero_comp", serverFaultConfig{nonZeroSHComp: true}, "must reject non-zero SH compression"},
		{"tls_client_sh_legacy_ver_0304", serverFaultConfig{overrideSHLegacyV: 0x0304}, "must reject SH legacy_version=0x0304"},
		{"tls_client_loworder_x25519_zero", serverFaultConfig{customServerKS: make([]byte, 32)}, "must reject low-order X25519"},
		{"tls_client_bad_aead_tag", serverFaultConfig{corruptEETag: true}, "must reject bad EE AEAD tag"},
		{"tls_client_ooo_sh_to_fin", serverFaultConfig{skipEECertCV: true}, "must reject SH -> Finished"},
		{"tls_client_ooo_skip_cv", serverFaultConfig{skipCV: true}, "must reject Cert -> Finished without CV"},
		{"tls_client_bad_cert_verify_sig", serverFaultConfig{corruptCVSigFlip: true}, "must reject corrupted CertificateVerify sig"},
		{"tls_client_bad_fin_mac", serverFaultConfig{corruptFinMAC: true}, "must reject bad server Finished MAC"},
		{"tls_client_untrusted_cert", serverFaultConfig{certType: "ecdsa", echoAppData: false}, "must reject untrusted cert (TLS_CLI_UNTRUSTED_REJECT: PASS)"},
		{"tls_client_expired_cert", serverFaultConfig{customCertChain: [][]byte{certExpired, pki.caDER}}, "must reject expired certificate"},
		{"tls_client_nul_in_san", serverFaultConfig{customCertChain: [][]byte{certNulInSAN, pki.caDER}}, "must reject NUL byte in SAN"},
	}
	for _, tc := range tlsClientFaults {
		// Note: tls_client.exe makes up to 2 connections (untrusted check + verified check); serve up to 3 connections per test!
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		port := ln.Addr().(*net.TCPAddr).Port
		stopCh := make(chan struct{})
		srvNotes := make(chan string, 4)
		go func() {
			defer ln.Close()
			for range 3 {
				select {
				case <-stopCh:
					return
				default:
				}
				_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
				c, aerr := ln.Accept()
				if aerr != nil {
					return
				}
				go handleSingleFaultConn(c, pki, tc.fc, srvNotes)
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		cmd := exec.CommandContext(ctx, tlsClientExe)
		cmd.Env = append(cmd.Environ(), fmt.Sprintf("PORT=%d", port), fmt.Sprintf("WING_PORT=%d", port))
		outBytes, _ := cmd.CombinedOutput()
		cancel()
		close(stopCh)
		_ = ln.Close()
		outStr := strings.TrimSpace(string(outBytes))
		st := "PASS"
		if strings.Contains(outStr, "TLS_CLI_VERIFIED_H2: PASS") {
			st = "FAIL"
		}
		rec.add("tls_client", "client_fault", tc.name, st, tc.exp, fmt.Sprintf("out=%q", truncStr(outStr, 100)), "")
	}
}

func handleSingleFaultConn(conn net.Conn, pki *testPKI, fc serverFaultConfig, notes chan<- string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	rec, err := readTLSRecord(conn, 2*time.Second)
	if err != nil {
		notes <- "ch_err:" + err.Error()
		return
	}
	ch, err := parseClientHello(rec.payload)
	if err != nil {
		notes <- "parse_ch_err"
		return
	}
	cipherID := CipherAES128GCM
	spec, _ := getCipherSpec(cipherID)
	srvKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	srvPub := srvKey.PublicKey().Bytes()
	if fc.customServerKS != nil {
		srvPub = fc.customServerKS
	}
	srvRnd := make([]byte, 32)
	_, _ = rand.Read(srvRnd)
	if len(fc.downgradeSentinel) == 8 {
		copy(srvRnd[24:32], fc.downgradeSentinel)
	}
	ksBody := binary.BigEndian.AppendUint16(nil, GroupX25519)
	ksBody = binary.BigEndian.AppendUint16(ksBody, uint16(len(srvPub)))
	ksBody = append(ksBody, srvPub...)
	legacyV := uint16(0x0303)
	if fc.overrideSHLegacyV != 0 {
		legacyV = fc.overrideSHLegacyV
	}
	shVer := uint16(0x0304)
	if fc.overrideSHVersion != 0 {
		shVer = fc.overrideSHVersion
	}
	comp := byte(0x00)
	if fc.nonZeroSHComp {
		comp = 0x01
	}
	sid := ch.sessionID
	if fc.wrongSessionIDEcho && len(sid) > 0 {
		sid = append([]byte{}, sid...)
		sid[0] ^= 0xFF
	} else if fc.wrongSessionIDEcho {
		sid = []byte{0x01, 0x02, 0x03, 0x04}
	}
	shExts := []rawExt{
		{typ: ExtSupportedVersions, body: []byte{byte(shVer >> 8), byte(shVer)}},
		{typ: ExtKeyShare, body: ksBody},
	}
	shMsg := buildServerHelloMsg(legacyV, srvRnd, sid, cipherID, comp, shExts)
	_, _ = conn.Write(makeRecord(RecHandshake, 0x0303, shMsg))

	var shared []byte
	if cliKS, ok := ch.keyShares[GroupX25519]; ok && len(cliKS) == 32 && fc.customServerKS == nil {
		if pp, perr := ecdh.X25519().NewPublicKey(cliKS); perr == nil {
			shared, _ = srvKey.ECDH(pp)
		}
	}
	if len(shared) == 0 {
		shared = make([]byte, 32)
	}
	transcript := [][]byte{ch.raw, shMsg}
	zeros := make([]byte, spec.hLen)
	earlySec := hkdfExtract(spec.hashFn, zeros, zeros)
	derived1 := deriveSecret(spec, earlySec, "derived", emptyHash(spec))
	hsSec := hkdfExtract(spec.hashFn, derived1, shared)
	thSH := hashMessages(spec, transcript...)
	sHsSec := deriveSecret(spec, hsSec, "s hs traffic", thSH)
	hsTx, _ := newTrafficState(spec, sHsSec)

	eeMsg := makeHandshakeMsg(HSEncryptedExtensions, []byte{0x00, 0x00})
	chain := [][]byte{pki.ecDER, pki.caDER}
	if fc.customCertChain != nil {
		chain = fc.customCertChain
	}
	certMsg := buildCertHandshakeMsg(chain)
	if fc.skipEECertCV {
		finMAC := computeFinishedMAC(spec, sHsSec, hashMessages(spec, transcript...))
		_, _ = conn.Write(hsTx.sealRecord(RecHandshake, makeHandshakeMsg(HSFinished, finMAC)))
		return
	}
	rEE := hsTx.sealRecord(RecHandshake, eeMsg)
	if fc.corruptEETag {
		rEE[len(rEE)-1] ^= 0x01
	}
	_, _ = conn.Write(rEE)
	transcript = append(transcript, eeMsg, certMsg)
	_, _ = conn.Write(hsTx.sealRecord(RecHandshake, certMsg))
	if !fc.skipCV {
		thCert := hashMessages(spec, transcript...)
		var content []byte
		content = append(content, bytes.Repeat([]byte{0x20}, 64)...)
		content = append(content, []byte("TLS 1.3, server CertificateVerify")...)
		content = append(content, 0x00)
		content = append(content, thCert...)
		d := sha256.Sum256(content)
		sig, _ := ecdsa.SignASN1(rand.Reader, pki.ecKey, d[:])
		if fc.corruptCVSigFlip && len(sig) > 4 {
			sig[len(sig)-1] ^= 0x01
		}
		cvBody := binary.BigEndian.AppendUint16(nil, SigECDSAP256SHA256)
		cvBody = binary.BigEndian.AppendUint16(cvBody, uint16(len(sig)))
		cvBody = append(cvBody, sig...)
		cvMsg := makeHandshakeMsg(HSCertificateVerify, cvBody)
		transcript = append(transcript, cvMsg)
		_, _ = conn.Write(hsTx.sealRecord(RecHandshake, cvMsg))
	}
	finMAC := computeFinishedMAC(spec, sHsSec, hashMessages(spec, transcript...))
	if fc.corruptFinMAC {
		finMAC[0] ^= 0x01
	}
	_, _ = conn.Write(hsTx.sealRecord(RecHandshake, makeHandshakeMsg(HSFinished, finMAC)))
	_, _ = conn.Read(make([]byte, 512))
	notes <- "done"
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
