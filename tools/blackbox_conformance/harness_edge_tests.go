// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"os/exec"
	"strings"
	"time"
)

// --- Direct Black-Box Edge Probing of x509_harness.exe & crypto_vectors harness.exe ---

type lineHarness struct {
	cmd    *exec.Cmd
	stdin  *bufio.Writer
	stdout *bufio.Reader
}

func startLineHarness(exe string) (*lineHarness, error) {
	cmd := exec.Command(exe)
	inPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &lineHarness{
		cmd:    cmd,
		stdin:  bufio.NewWriter(inPipe),
		stdout: bufio.NewReader(outPipe),
	}, nil
}

func (h *lineHarness) call(fields ...string) ([]string, error) {
	line := strings.Join(fields, "\t") + "\n"
	if _, err := h.stdin.WriteString(line); err != nil {
		return nil, err
	}
	if err := h.stdin.Flush(); err != nil {
		return nil, err
	}
	resp, err := h.stdout.ReadString('\n')
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimRight(resp, "\r\n"), "\t"), nil
}

func (h *lineHarness) close() {
	if h == nil || h.cmd == nil {
		return
	}
	_ = h.cmd.Process.Kill()
	_ = h.cmd.Wait()
}

func hexOrDash(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

func runX509HarnessEdgeSuite(rec *testRecorder, x509Exe string, pki *testPKI) {
	fmt.Printf("\n================ x509_harness.exe DIRECT EDGE SUITE ================\n")
	h, err := startLineHarness(x509Exe)
	if err != nil {
		rec.add("x509_edge", "setup", "start_harness", "FAIL", "start", err.Error(), "")
		return
	}
	defer h.close()

	nowUnix := fmt.Sprintf("%d", time.Now().UTC().Unix())
	caHex := hex.EncodeToString(pki.caDER)
	oidEcdsaSha256 := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}
	oidEcdsaSha384 := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03}
	tbsEC, _, _, _ := extractCertParts(pki.ecDER)

	verifyCase := func(name string, leafDER []byte, inters [][]byte, peer string, expectOK bool, infoOnly bool, note string) {
		interHex := "-"
		if len(inters) > 0 {
			var parts []string
			for _, in := range inters {
				parts = append(parts, hex.EncodeToString(in))
			}
			interHex = strings.Join(parts, ",")
		}
		cols, err := h.call("VERIFY", name, "BUILD", "SERVER", nowUnix, peer, hexOrDash(leafDER), interHex, caHex, "-1")
		if err != nil {
			rec.add("x509_edge", "verify", name, "FAIL", note, "harness err: "+err.Error(), "")
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
		} else if gotOK != expectOK {
			st = "FAIL"
		}
		rec.add("x509_edge", "verify", name, st, note, reason, "")
	}

	// Baseline valid ECDSA and Ed25519
	verifyCase("baseline_ecdsa_valid", pki.ecDER, nil, "localhost", true, false, "OK")
	verifyCase("baseline_ed25519_valid", pki.edDER, nil, "test.local", true, false, "OK")

	// Non-canonical DER encodings
	verifyCase("der_overlong_outer_len", signDERCertWithCA(tbsEC, oidEcdsaSha256, pki.caKey, 0, nil, "overlong"), nil, "localhost", false, false, "reject overlong outer DER length")
	verifyCase("der_overlong_inner_len", buildOverlongInnerLenCert(pki), nil, "localhost", false, false, "reject overlong inner DER length (0x81 0x01)")
	verifyCase("der_indefinite_len", signDERCertWithCA(tbsEC, oidEcdsaSha256, pki.caKey, 0, nil, "indefinite"), nil, "localhost", false, false, "reject indefinite DER length (0x80)")
	verifyCase("der_nonminimal_int_serial", buildNonMinimalIntCert(pki), nil, "localhost", false, false, "reject non-minimal INTEGER (0x00 0x01)")
	verifyCase("der_nonzero_sig_bitstring_unused", signDERCertWithCA(tbsEC, oidEcdsaSha256, pki.caKey, 3, nil, ""), nil, "localhost", false, false, "reject non-zero BIT STRING unused bits on sig")
	verifyCase("der_trailing_garbage", signDERCertWithCA(tbsEC, oidEcdsaSha256, pki.caKey, 0, []byte{0x00}, ""), nil, "localhost", false, false, "reject trailing DER byte")
	verifyCase("der_outer_vs_tbs_sigalg_mismatch", signDERCertWithCA(tbsEC, oidEcdsaSha384, pki.caKey, 0, nil, ""), nil, "localhost", false, false, "reject outer vs TBS sigAlg mismatch")

	// Negative serial number (RFC 5280 Section 4.1.2.2: serial MUST be positive integer!)
	{
		var tbsSeq asn1.RawValue
		_, _ = asn1.Unmarshal(tbsEC, &tbsSeq)
		rest := tbsSeq.Bytes
		var verF, serF asn1.RawValue
		rest, _ = asn1.Unmarshal(rest, &verF)
		rest, _ = asn1.Unmarshal(rest, &serF)
		negSer := []byte{0x02, 0x01, 0xff} // -1!
		newTBS := derSeq(append(append(append([]byte{}, verF.FullBytes...), negSer...), rest...))
		verifyCase("x509_negative_serial", signDERCertWithCA(newTBS, oidEcdsaSha256, pki.caKey, 0, nil, ""), nil, "localhost", false, true, "RFC 5280 Section 4.1.2.2 negative serial (observe)")
	}

	// Non-canonical DER BOOLEAN (0x01 instead of 0xFF) in BasicConstraints cA=TRUE on intermediate CA!
	{
		now := time.Now().UTC()
		intKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		// First create a valid intermediate so Go can parse it and sign the leaf cleanly
		goodIntTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(501), Subject: pkix.Name{CommonName: "NonCanon Bool CA"},
			NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
		}
		goodIntDER, _ := x509.CreateCertificate(rand.Reader, goodIntTmpl, pki.caCert, &intKey.PublicKey, pki.caKey)
		intCert, err := x509.ParseCertificate(goodIntDER)
		if err == nil && intCert != nil {
			leafTmpl := &x509.Certificate{
				SerialNumber: big.NewInt(502), Subject: pkix.Name{CommonName: "leaf.local"},
				NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
				KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true, DNSNames: []string{"leaf.local"},
			}
			leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, intCert, &pki.ecKey.PublicKey, intKey)
			// Mutate BasicConstraints BOOLEAN 0x01 0x01 0xff -> 0x01 0x01 0x01 inside intermediate TBS and re-sign with CA!
			intTBS, _, _, _ := extractCertParts(goodIntDER)
			mutTBS := bytes.Replace(intTBS, []byte{0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff}, []byte{0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0x01}, 1)
			badIntDER := signDERCertWithCA(mutTBS, oidEcdsaSha256, pki.caKey, 0, nil, "")
			verifyCase("der_noncanon_bool_0x01_in_bc", leafDER, [][]byte{badIntDER}, "leaf.local", false, false, "X.690 DER BOOLEAN TRUE must be 0xFF not 0x01")
		}
	}

	// NUL byte in SAN dNSName
	verifyCase("san_nul_byte_injection", buildNulInSANCert(pki), nil, "localhost", false, false, "reject NUL byte in SAN dNSName")

	// Wildcard & SAN edge cases
	makeSANCert := func(serial int64, sanRaw []byte) []byte {
		now := time.Now().UTC()
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "wc"},
			NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			ExtraExtensions:       []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: sanRaw}},
		}
		d, _ := x509.CreateCertificate(rand.Reader, tmpl, pki.caCert, &pki.ecKey.PublicKey, pki.caKey)
		return d
	}
	verifyCase("san_wildcard_bare_star", makeSANCert(601, derSeq(derTLV(0x82, []byte("*")))), nil, "example.com", false, false, "reject bare * wildcard")
	verifyCase("san_wildcard_tld_star_com", makeSANCert(602, derSeq(derTLV(0x82, []byte("*.com")))), nil, "example.com", false, true, "RFC 6125 public suffix wildcard *.com (observe)")
	verifyCase("san_wildcard_double_star", makeSANCert(603, derSeq(derTLV(0x82, []byte("*.*.example.com")))), nil, "a.b.example.com", false, false, "reject *.*.example.com")
	verifyCase("san_wildcard_partial_label", makeSANCert(604, derSeq(derTLV(0x82, []byte("f*o.example.com")))), nil, "foo.example.com", false, false, "reject partial-label wildcard f*o")
	verifyCase("san_ip_bad_len_3B", makeSANCert(605, derSeq(derTLV(0x87, []byte{127, 0, 1}))), nil, "127.0.0.1", false, false, "reject 3-byte IP SAN")
	verifyCase("san_ip_bad_len_5B", makeSANCert(606, derSeq(derTLV(0x87, []byte{127, 0, 0, 1, 0}))), nil, "127.0.0.1", false, false, "reject 5-byte IP SAN")
	verifyCase("san_ip_bad_len_15B", makeSANCert(607, derSeq(derTLV(0x87, make([]byte, 15)))), nil, "::1", false, false, "reject 15-byte IP SAN")

	// Duplicate SAN extension (RFC 5280 Section 4.2: a certificate MUST NOT include >1 instance of a particular extension)
	{
		now := time.Now().UTC()
		san1 := derSeq(derTLV(0x82, []byte("good.local")))
		san2 := derSeq(derTLV(0x82, []byte("evil.local")))
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(608), Subject: pkix.Name{CommonName: "dup-san"},
			NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			ExtraExtensions: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san1},
				{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san2},
			},
		}
		d, _ := x509.CreateCertificate(rand.Reader, tmpl, pki.caCert, &pki.ecKey.PublicKey, pki.caKey)
		verifyCase("x509_duplicate_san_extension", d, nil, "good.local", false, false, "RFC 5280 Section 4.2 reject duplicate extension OID")
	}

	// ECDSA high-s cert signature & BER non-canonical ECDSA cert signature
	{
		d := sha256.Sum256(tbsEC)
		sig, _ := ecdsa.SignASN1(rand.Reader, pki.caKey, d[:])
		highS, _ := makeECDSAHighS(sig)
		sigAlgSeq := derSeq(oidEcdsaSha256)
		certHighS := derSeq(append(append(append([]byte{}, tbsEC...), sigAlgSeq...), derTLV(0x03, append([]byte{0}, highS...))...))
		verifyCase("cert_ecdsa_high_s_sig", certHighS, nil, "localhost", true, true, "observe ECDSA high-s signature on cert")

		berSig, _ := makeECDSABEROverlong(sig)
		certBER := derSeq(append(append(append([]byte{}, tbsEC...), sigAlgSeq...), derTLV(0x03, append([]byte{0}, berSig...))...))
		verifyCase("cert_ecdsa_ber_overlong_sig", certBER, nil, "localhost", false, false, "reject BER overlong ECDSA sig in cert")
	}

	// Ed25519 CA signing leaf with malleable S >= L signature
	{
		now := time.Now().UTC()
		edCAPub, edCAPriv, _ := ed25519.GenerateKey(rand.Reader)
		edCATmpl := &x509.Certificate{
			SerialNumber: big.NewInt(700), Subject: pkix.Name{CommonName: "Ed25519 Root CA"},
			NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
		}
		edCADER, _ := x509.CreateCertificate(rand.Reader, edCATmpl, edCATmpl, edCAPub, edCAPriv)
		edCACert, _ := x509.ParseCertificate(edCADER)
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(701), Subject: pkix.Name{CommonName: "edleaf.local"},
			NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true, DNSNames: []string{"edleaf.local"},
		}
		leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, edCACert, &pki.ecKey.PublicKey, edCAPriv)
		tbsL, sigAlgL, _, _ := extractCertParts(leafDER)
		rawSig := ed25519.Sign(edCAPriv, tbsL)
		malSig := makeEd25519MalleableSig(rawSig)
		malCert := derSeq(append(append(append([]byte{}, tbsL...), sigAlgL...), derTLV(0x03, append([]byte{0}, malSig...))...))

		cols, err := h.call("VERIFY", "cert_ed25519_malleable_S_ge_L", "BUILD", "SERVER", nowUnix, "edleaf.local", hex.EncodeToString(malCert), "-", hex.EncodeToString(edCADER), "-1")
		gotOK := err == nil && len(cols) >= 4 && cols[2] == "OK"
		st := "PASS"
		if gotOK {
			st = "FAIL"
		}
		rec.add("x509_edge", "verify", "cert_ed25519_malleable_S_ge_L", st, "RFC 8032 reject Ed25519 S >= L on cert", strings.Join(cols, "|"), "")
	}
}

// --- Direct Black-Box Wycheproof / RFC Edge Probing of crypto_vectors/harness.exe ---

func rsaRawSign(priv *rsa.PrivateKey, em []byte) []byte {
	m := new(big.Int).SetBytes(em)
	s := new(big.Int).Exp(m, priv.D, priv.N)
	k := (priv.N.BitLen() + 7) / 8
	out := make([]byte, k)
	s.FillBytes(out)
	return out
}

func runCryptoHarnessEdgeSuite(rec *testRecorder, cryptoExe string) {
	fmt.Printf("\n================ crypto_vectors harness.exe DIRECT EDGE SUITE ================\n")
	h, err := startLineHarness(cryptoExe)
	if err != nil {
		rec.add("crypto_edge", "setup", "start_harness", "FAIL", "start", err.Error(), "")
		return
	}
	defer h.close()

	checkCmd := func(cat, name string, expectOK bool, infoOnly bool, note string, args ...string) {
		cols, err := h.call(args...)
		if err != nil {
			rec.add("crypto_edge", cat, name, "FAIL", note, "harness err: "+err.Error(), "")
			return
		}
		gotOK := len(cols) > 0 && cols[0] == "OK"
		st := "PASS"
		if infoOnly {
			st = "INFO"
		} else if gotOK != expectOK {
			st = "FAIL"
		}
		rec.add("crypto_edge", cat, name, st, note, truncStr(strings.Join(cols, "\t"), 90), "")
	}

	// 1. X25519 low-order & non-canonical u-coordinates
	privHex := "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	x25519Cases := []struct {
		name string
		pub  string
		exp  bool
		info bool
		note string
	}{
		{"x25519_zero", "0000000000000000000000000000000000000000000000000000000000000000", false, false, "reject all-zero shared secret"},
		{"x25519_one", "0100000000000000000000000000000000000000000000000000000000000000", false, false, "reject u=1 low-order"},
		{"x25519_order8a", "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", false, false, "reject order-8a"},
		{"x25519_order8b", "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", false, false, "reject order-8b"},
		{"x25519_p_minus_1", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false, false, "reject p-1"},
		{"x25519_p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false, false, "reject p"},
		{"x25519_p_plus_1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false, false, "reject p+1"},
		{"x25519_msb_2pow255", "0000000000000000000000000000000000000000000000000000000000000080", false, false, "reject 2^255 (0 after bit-255 mask)"},
		{"x25519_noncanon_gen_msb", "0900000000000000000000000000000000000000000000000000000000000080", true, true, "RFC 7748 clears bit 255 -> valid or reject"},
		{"x25519_noncanon_p_plus_9", "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", true, true, "RFC 7748 reduces mod p -> valid or reject"},
		{"x25519_trunc_31B", strings.Repeat("09", 31), false, false, "reject 31B"},
		{"x25519_oversize_33B", strings.Repeat("09", 33), false, false, "reject 33B"},
	}
	for _, tc := range x25519Cases {
		checkCmd("x25519", tc.name, tc.exp, tc.info, tc.note, "X25519", privHex, tc.pub)
	}

	// 2. Ed25519 RFC 8032 / ZIP-215 edge cases
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("blackbox-ed25519-edge-test")
	edSig := ed25519.Sign(edPriv, msg)
	checkCmd("ed25519", "valid_sig", true, false, "valid Ed25519", "ED25519_VERIFY", hex.EncodeToString(edPub), hex.EncodeToString(msg), hex.EncodeToString(edSig))
	checkCmd("ed25519", "malleable_S_plus_L", false, false, "RFC 8032 reject S >= L", "ED25519_VERIFY", hex.EncodeToString(edPub), hex.EncodeToString(msg), hex.EncodeToString(makeEd25519MalleableSig(edSig)))
	{
		// S = L exactly
		sEqL := append([]byte{}, edSig...)
		beL := ed25519OrderL.Bytes()
		var leL [32]byte
		for i := range beL {
			leL[i] = beL[len(beL)-1-i]
		}
		copy(sEqL[32:], leL[:])
		checkCmd("ed25519", "S_equals_L", false, false, "reject S == L", "ED25519_VERIFY", hex.EncodeToString(edPub), hex.EncodeToString(msg), hex.EncodeToString(sEqL))
	}
	// Small-order public key + small-order R with S=0 (classic Ed25519 small-order forgery!)
	// Identity point A = (0, 1) -> encoding 01 00..00; R = (0, 1) -> 01 00..00; S = 0 -> 00..00
	// Notice 8*S*B = 8*R + 8*k*A holds trivially (0 = 0 + 0) in cofactorless or naive implementations!
	idPt := "0100000000000000000000000000000000000000000000000000000000000000"
	ord2Pt := "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
	ord4Pt := "0000000000000000000000000000000000000000000000000000000000000000"
	zeroS := "0000000000000000000000000000000000000000000000000000000000000000"
	checkCmd("ed25519", "small_order_identity_A_R_S0", false, false, "reject identity torsion forgery (A=I, R=I, S=0)", "ED25519_VERIFY", idPt, hex.EncodeToString(msg), idPt+zeroS)
	checkCmd("ed25519", "small_order_ord2_A_R_S0", false, false, "reject order-2 torsion forgery", "ED25519_VERIFY", ord2Pt, hex.EncodeToString(msg), ord2Pt+zeroS)
	checkCmd("ed25519", "small_order_ord4_A_R_S0", false, false, "reject order-4 torsion forgery", "ED25519_VERIFY", ord4Pt, hex.EncodeToString(msg), ord4Pt+zeroS)
	// Non-canonical y >= p for A (ed ff..7f)
	nonCanonY := "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
	checkCmd("ed25519", "noncanon_pubkey_y_eq_p", false, false, "reject non-canonical A with y == p", "ED25519_VERIFY", nonCanonY, hex.EncodeToString(msg), hex.EncodeToString(edSig))
	checkCmd("ed25519", "trunc_sig_63B", false, false, "reject 63B sig", "ED25519_VERIFY", hex.EncodeToString(edPub), hex.EncodeToString(msg), hex.EncodeToString(edSig[:63]))

	// 3. ECDSA P-256 & P-384 DER Wycheproof edge cases
	p256Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p256Pub := make([]byte, 65)
	p256Pub[0] = 0x04
	p256Key.X.FillBytes(p256Pub[1:33])
	p256Key.Y.FillBytes(p256Pub[33:65])
	d256 := sha256.Sum256(msg)
	p256Sig, _ := ecdsa.SignASN1(rand.Reader, p256Key, d256[:])
	checkCmd("ecdsa_p256", "valid_der", true, false, "valid P-256 DER", "ECDSA_P256_VERIFY_DER", hex.EncodeToString(p256Pub), hex.EncodeToString(msg), hex.EncodeToString(p256Sig))
	highS256, _ := makeECDSAHighS(p256Sig)
	checkCmd("ecdsa_p256", "high_s", true, true, "observe ECDSA P-256 high-s", "ECDSA_P256_VERIFY_DER", hex.EncodeToString(p256Pub), hex.EncodeToString(msg), hex.EncodeToString(highS256))
	ber256, _ := makeECDSABEROverlong(p256Sig)
	checkCmd("ecdsa_p256", "ber_overlong_rs", false, false, "reject non-canonical BER (r,s)", "ECDSA_P256_VERIFY_DER", hex.EncodeToString(p256Pub), hex.EncodeToString(msg), hex.EncodeToString(ber256))
	checkCmd("ecdsa_p256", "trailing_zero_byte", false, false, "reject trailing byte", "ECDSA_P256_VERIFY_DER", hex.EncodeToString(p256Pub), hex.EncodeToString(msg), hex.EncodeToString(append(append([]byte{}, p256Sig...), 0x00)))
	// r = 0, s = 0, r = n, s = n
	rZero, _ := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(0), big.NewInt(1)})
	sZero, _ := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(1), big.NewInt(0)})
	rEqN, _ := asn1.Marshal(struct{ R, S *big.Int }{p256OrderN, big.NewInt(1)})
	sEqN, _ := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(1), p256OrderN})
	checkCmd("ecdsa_p256", "r_equals_0", false, false, "reject r=0", "ECDSA_P256_VERIFY_DER", hex.EncodeToString(p256Pub), hex.EncodeToString(msg), hex.EncodeToString(rZero))
	checkCmd("ecdsa_p256", "s_equals_0", false, false, "reject s=0", "ECDSA_P256_VERIFY_DER", hex.EncodeToString(p256Pub), hex.EncodeToString(msg), hex.EncodeToString(sZero))
	checkCmd("ecdsa_p256", "r_equals_n", false, false, "reject r=n", "ECDSA_P256_VERIFY_DER", hex.EncodeToString(p256Pub), hex.EncodeToString(msg), hex.EncodeToString(rEqN))
	checkCmd("ecdsa_p256", "s_equals_n", false, false, "reject s=n", "ECDSA_P256_VERIFY_DER", hex.EncodeToString(p256Pub), hex.EncodeToString(msg), hex.EncodeToString(sEqN))
	// Negative r (unsigned bytes with MSB=1 encoded without leading 0x00!)
	{
		var rs struct{ R, S *big.Int }
		_, _ = asn1.Unmarshal(p256Sig, &rs)
		rb := rs.R.Bytes()
		sb := rs.S.Bytes()
		// Force MSB=1 without leading 0x00 -> ASN.1 decodes as negative integer
		rbNeg := append([]byte{}, rb...)
		rbNeg[0] |= 0x80
		negSig := derSeq(append(derTLV(0x02, rbNeg), derTLV(0x02, sb)...))
		checkCmd("ecdsa_p256", "negative_r_no_lead_zero", false, false, "reject negative ASN.1 integer r", "ECDSA_P256_VERIFY_DER", hex.EncodeToString(p256Pub), hex.EncodeToString(msg), hex.EncodeToString(negSig))
	}

	// ECDSA P-384 baseline + BER overlong
	p384Key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384Pub := make([]byte, 97)
	p384Pub[0] = 0x04
	p384Key.X.FillBytes(p384Pub[1:49])
	p384Key.Y.FillBytes(p384Pub[49:97])
	d384 := sha512.Sum384(msg)
	p384Sig, _ := ecdsa.SignASN1(rand.Reader, p384Key, d384[:])
	checkCmd("ecdsa_p384", "valid_der", true, false, "valid P-384 DER", "ECDSA_P384_VERIFY_DER", hex.EncodeToString(p384Pub), hex.EncodeToString(msg), hex.EncodeToString(p384Sig))
	checkCmd("ecdsa_p384", "trailing_byte", false, false, "reject P-384 trailing byte", "ECDSA_P384_VERIFY_DER", hex.EncodeToString(p384Pub), hex.EncodeToString(msg), hex.EncodeToString(append(append([]byte{}, p384Sig...), 0x00)))

	// 4. RSA PKCS#1 v1.5 SHA-256 Bleichenbacher / DigestInfo padding oracle attacks (using exact m^d mod N!)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaPubDER := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)
	rsaPubHex := hex.EncodeToString(rsaPubDER)
	kLen := 256
	// Standard SHA-256 DigestInfo prefix (RFC 8017 Section 9.2): 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
	sha256Prefix := mustHex("3031300d060960864801650304020105000420")
	digestInfoValid := append(append([]byte{}, sha256Prefix...), d256[:]...)

	buildPKCS1EM := func(prefix []byte, psByte byte, psLen int, sep byte, body []byte, tail []byte) []byte {
		var em []byte
		em = append(em, prefix...)
		em = append(em, bytes.Repeat([]byte{psByte}, psLen)...)
		em = append(em, sep)
		em = append(em, body...)
		em = append(em, tail...)
		return em
	}

	validEM := buildPKCS1EM([]byte{0x00, 0x01}, 0xff, kLen-3-len(digestInfoValid), 0x00, digestInfoValid, nil)
	checkCmd("rsa_pkcs1", "valid_sha256", true, false, "valid RSA PKCS#1 v1.5", "RSA_PKCS1_SHA256_VERIFY_DER", rsaPubHex, hex.EncodeToString(msg), hex.EncodeToString(rsaRawSign(rsaKey, validEM)))

	// Bleichenbacher-style: extra trailing bytes after DigestInfo (reduced PS to fit)
	trailEM := buildPKCS1EM([]byte{0x00, 0x01}, 0xff, kLen-3-len(digestInfoValid)-4, 0x00, digestInfoValid, []byte{0xde, 0xad, 0xbe, 0xef})
	checkCmd("rsa_pkcs1", "bleichenbacher_trailing_garbage", false, false, "reject trailing bytes after DigestInfo", "RSA_PKCS1_SHA256_VERIFY_DER", rsaPubHex, hex.EncodeToString(msg), hex.EncodeToString(rsaRawSign(rsaKey, trailEM)))

	// Missing NULL parameter in AlgorithmIdentifier (RFC 8017 Section 9.2 requires NULL; Wycheproof flags missing NULL as invalid/legacy)
	noNullPrefix := mustHex("302f300b06096086480165030402010420")
	diNoNull := append(append([]byte{}, noNullPrefix...), d256[:]...)
	noNullEM := buildPKCS1EM([]byte{0x00, 0x01}, 0xff, kLen-3-len(diNoNull), 0x00, diNoNull, nil)
	checkCmd("rsa_pkcs1", "digestinfo_missing_null_param", false, true, "RFC 8017 missing NULL in DigestInfo (observe)", "RSA_PKCS1_SHA256_VERIFY_DER", rsaPubHex, hex.EncodeToString(msg), hex.EncodeToString(rsaRawSign(rsaKey, noNullEM)))

	// Non-canonical BER DigestInfo (overlong length 0x81 0x31)
	berPrefix := mustHex("308131300d060960864801650304020105000420")
	diBER := append(append([]byte{}, berPrefix...), d256[:]...)
	berEM := buildPKCS1EM([]byte{0x00, 0x01}, 0xff, kLen-3-len(diBER), 0x00, diBER, nil)
	checkCmd("rsa_pkcs1", "digestinfo_ber_overlong_len", false, false, "reject BER overlong length in DigestInfo", "RSA_PKCS1_SHA256_VERIFY_DER", rsaPubHex, hex.EncodeToString(msg), hex.EncodeToString(rsaRawSign(rsaKey, berEM)))

	// Wrong padding byte in PS (0xFE instead of 0xFF)
	badPSEM := append([]byte{}, validEM...)
	badPSEM[10] = 0xfe
	checkCmd("rsa_pkcs1", "bad_ps_byte_0xfe", false, false, "reject non-0xFF byte in PS", "RSA_PKCS1_SHA256_VERIFY_DER", rsaPubHex, hex.EncodeToString(msg), hex.EncodeToString(rsaRawSign(rsaKey, badPSEM)))

	// Wrong block type (0x00 0x02 instead of 0x00 0x01)
	bt2EM := append([]byte{}, validEM...)
	bt2EM[1] = 0x02
	checkCmd("rsa_pkcs1", "wrong_block_type_02", false, false, "reject block type 0x02", "RSA_PKCS1_SHA256_VERIFY_DER", rsaPubHex, hex.EncodeToString(msg), hex.EncodeToString(rsaRawSign(rsaKey, bt2EM)))

	// Signature >= N (add N to valid sig? No, s >= N exceeds kLen or fails mod N; construct s = N + 1!)
	sigGeN := new(big.Int).Add(rsaKey.N, big.NewInt(1)).Bytes()
	checkCmd("rsa_pkcs1", "sig_ge_modulus_N", false, false, "reject signature >= N", "RSA_PKCS1_SHA256_VERIFY_DER", rsaPubHex, hex.EncodeToString(msg), hex.EncodeToString(sigGeN))

	// 5. RSA-PSS SHA-256 edge cases
	pssSig, _ := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, d256[:], &rsa.PSSOptions{SaltLength: 32})
	checkCmd("rsa_pss", "valid_sha256_salt32", true, false, "valid RSA-PSS SHA-256", "RSA_PSS_SHA256_VERIFY_DER", rsaPubHex, hex.EncodeToString(msg), hex.EncodeToString(pssSig))
	pssFlip := append([]byte{}, pssSig...)
	pssFlip[len(pssFlip)-1] ^= 0x01
	checkCmd("rsa_pss", "sig_1bit_flip", false, false, "reject flipped RSA-PSS", "RSA_PSS_SHA256_VERIFY_DER", rsaPubHex, hex.EncodeToString(msg), hex.EncodeToString(pssFlip))
	pssZeroSalt, _ := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, d256[:], &rsa.PSSOptions{SaltLength: 0})
	checkCmd("rsa_pss", "wrong_salt_len_0", false, false, "reject salt_len=0 when sLen=32 expected", "RSA_PSS_SHA256_VERIFY_DER", rsaPubHex, hex.EncodeToString(msg), hex.EncodeToString(pssZeroSalt))

	// 6. AEAD edge cases (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)
	k16 := bytes.Repeat([]byte{0x11}, 16)
	k32 := bytes.Repeat([]byte{0x22}, 32)
	iv12 := bytes.Repeat([]byte{0x33}, 12)
	aad := []byte("aad-edge")
	pt := []byte("plaintext-edge")

	b16, _ := aes.NewCipher(k16)
	g16, _ := cipher.NewGCM(b16)
	out16 := g16.Seal(nil, iv12, pt, aad)
	ct16, tag16 := out16[:len(pt)], out16[len(pt):]
	badTag16 := append([]byte{}, tag16...)
	badTag16[15] ^= 0x01
	checkCmd("aead", "aes128_gcm_valid", true, false, "valid AES-128-GCM", "AES128_GCM_OPEN", hex.EncodeToString(k16), hex.EncodeToString(iv12), hex.EncodeToString(aad), hex.EncodeToString(ct16), hex.EncodeToString(tag16))
	checkCmd("aead", "aes128_gcm_tag_flip", false, false, "reject tag flip", "AES128_GCM_OPEN", hex.EncodeToString(k16), hex.EncodeToString(iv12), hex.EncodeToString(aad), hex.EncodeToString(ct16), hex.EncodeToString(badTag16))
	checkCmd("aead", "aes128_gcm_wrong_iv_11B", false, false, "reject 11B IV", "AES128_GCM_OPEN", hex.EncodeToString(k16), hex.EncodeToString(iv12[:11]), hex.EncodeToString(aad), hex.EncodeToString(ct16), hex.EncodeToString(tag16))
	checkCmd("aead", "aes128_gcm_wrong_tag_15B", false, false, "reject 15B tag", "AES128_GCM_OPEN", hex.EncodeToString(k16), hex.EncodeToString(iv12), hex.EncodeToString(aad), hex.EncodeToString(ct16), hex.EncodeToString(tag16[:15]))

	cc, _ := newChaCha20Poly1305(k32)
	outCC := cc.Seal(nil, iv12, pt, aad)
	ctCC, tagCC := outCC[:len(pt)], outCC[len(pt):]
	badTagCC := append([]byte{}, tagCC...)
	badTagCC[0] ^= 0x80
	checkCmd("aead", "chacha20_poly1305_valid", true, false, "valid ChaCha20-Poly1305", "CHACHA20_POLY1305_OPEN", hex.EncodeToString(k32), hex.EncodeToString(iv12), hex.EncodeToString(aad), hex.EncodeToString(ctCC), hex.EncodeToString(tagCC))
	checkCmd("aead", "chacha20_poly1305_tag_flip", false, false, "reject tag flip", "CHACHA20_POLY1305_OPEN", hex.EncodeToString(k32), hex.EncodeToString(iv12), hex.EncodeToString(aad), hex.EncodeToString(ctCC), hex.EncodeToString(badTagCC))
	checkCmd("aead", "chacha20_poly1305_wrong_iv_13B", false, false, "reject 13B IV", "CHACHA20_POLY1305_OPEN", hex.EncodeToString(k32), hex.EncodeToString(append(iv12, 0)), hex.EncodeToString(aad), hex.EncodeToString(ctCC), hex.EncodeToString(tagCC))

	// 7. ML-KEM-768 non-canonical modulus & implicit rejection
	dSeed := strings.Repeat("aa", 32)
	zSeed := strings.Repeat("bb", 32)
	mSeed := strings.Repeat("cc", 32)
	kgCols, err := h.call("MLKEM768_KEYGEN", dSeed, zSeed)
	if err == nil && len(kgCols) >= 3 && kgCols[0] == "OK" {
		ekHex, dkHex := kgCols[1], kgCols[2]
		encCols, _ := h.call("MLKEM768_ENCAPS", ekHex, mSeed)
		if len(encCols) >= 3 && encCols[0] == "OK" {
			ctHex, ssHex := encCols[1], encCols[2]
			decCols, _ := h.call("MLKEM768_DECAPS", ctHex, dkHex)
			st := "PASS"
			if len(decCols) < 2 || decCols[0] != "OK" || decCols[1] != ssHex {
				st = "FAIL"
			}
			rec.add("crypto_edge", "mlkem768", "roundtrip_keygen_encaps_decaps", st, "ss match", fmt.Sprintf("ok=%v", st == "PASS"), "")

			// Non-canonical ek: set first 12-bit coefficient = 3329 (0x0D01 -> bytes 0x01, 0x0D in 12-bit LE packing!)
			badEK, _ := hex.DecodeString(ekHex)
			badEK[0] = 0x01
			badEK[1] = (badEK[1] & 0xf0) | 0x0d
			checkCmd("mlkem768", "noncanon_ek_coeff_3329", false, false, "FIPS 203 Section 7.2 reject ek coeff >= 3329", "MLKEM768_ENCAPS", hex.EncodeToString(badEK), mSeed)

			// Truncated ek
			checkCmd("mlkem768", "trunc_ek", false, false, "reject truncated ek", "MLKEM768_ENCAPS", hex.EncodeToString(badEK[:len(badEK)-1]), mSeed)

			// Implicit rejection on corrupted ciphertext: must succeed with deterministic pseudorandom key != ssHex!
			badCT, _ := hex.DecodeString(ctHex)
			badCT[0] ^= 0x01
			decBad1, _ := h.call("MLKEM768_DECAPS", hex.EncodeToString(badCT), dkHex)
			decBad2, _ := h.call("MLKEM768_DECAPS", hex.EncodeToString(badCT), dkHex)
			irOK := len(decBad1) >= 2 && decBad1[0] == "OK" && decBad1[1] != ssHex && len(decBad2) >= 2 && decBad1[1] == decBad2[1]
			stIR := "PASS"
			if !irOK {
				stIR = "FAIL"
			}
			rec.add("crypto_edge", "mlkem768", "implicit_rejection_on_corrupt_ct", stIR, "deterministic ss != real ss", fmt.Sprintf("got1=%v", decBad1), "")
		}
	}
}
