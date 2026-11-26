// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
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
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// =========================================================================
// ROUND 2: 2025-2026 CRYPTOGRAPHIC BYPASS & CVE BLACK-BOX MATRIX
// =========================================================================

func runRound2Suite(pki *testPKI) {
	rec := &testRecorder{}
	binDir := filepath.Join(repoRoot, "tools", "bin")
	tlsServerExe := exePath(binDir, "tls_server")
	bogoShimExe := exePath(binDir, "bogo_shim")
	x509HarnessExe := exePath(binDir, "x509_harness")
	cryptoHarnessExe := exePath(filepath.Join(repoRoot, ".lit", "cache", "crypto_vectors"), "harness")

	// 1. ML-KEM-768 exhaustive byte-by-byte ciphertext mutation & EK boundary checks
	runRound2MLKEM(rec, cryptoHarnessExe)

	// 2. AEAD differential ref vs goose-wing across 2048B threshold + truncated IV/tag
	runRound2AEAD(rec, cryptoHarnessExe)

	// 3. Asymmetric 2024-2026 matrix (Ed25519, ECDSA P-256/P-384, RSA PKCS#1 e=3 / DigestInfo)
	runRound2Asymmetric(rec, cryptoHarnessExe)

	// 4. X.509 / ASN.1 2026 CVE matrix against x509_harness.exe
	runRound2X509(rec, x509HarnessExe, pki)

	// 5. TLS 1.3 2025-2026 live wire CVEs against tls_server.exe (default & --sni-map) and bogo_shim.exe
	runRound2TLSWire(rec, tlsServerExe, bogoShimExe, pki)

	// Print summary and write round2_results.log
	fmt.Println("\n==================== ROUND 2 SUMMARY ====================")
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
		logBuf.WriteString(fmt.Sprintf("[%s] %s/%s/%s | exp=%s | got=%s | hex=%s\n", r.status, r.suite, r.category, r.name, r.expected, r.observed, r.wireHex))
	}
	for _, s := range order {
		c := bySuite[s]
		fmt.Printf("  %-20s: PASS=%3d  FAIL=%3d  WARN=%2d  INFO=%2d\n", s, c.pass, c.fail, c.warn, c.info)
	}
	fmt.Printf("\nROUND 2 TOTALS -> FAIL=%d | WARN=%d | INFO=%d\n", len(fails), len(warns), len(infos))
	if len(fails) > 0 {
		fmt.Println("\n--- ROUND 2 FAILURES ---")
		for _, f := range fails {
			fmt.Printf("  [FAIL] %s/%s/%s\n         exp: %s\n         got: %s\n", f.suite, f.category, f.name, f.expected, f.observed)
		}
	}
	if len(warns) > 0 {
		fmt.Println("\n--- ROUND 2 WARNINGS ---")
		for _, w := range warns {
			fmt.Printf("  [WARN] %s/%s/%s | exp=%s | got=%s\n", w.suite, w.category, w.name, w.expected, w.observed)
		}
	}
	if len(infos) > 0 {
		fmt.Println("\n--- ROUND 2 INFO ---")
		for _, in := range infos {
			fmt.Printf("  [INFO] %s/%s/%s | exp=%s | got=%s\n", in.suite, in.category, in.name, in.expected, in.observed)
		}
	}
	if logDir != "" {
		logPath := filepath.Join(logDir, "round2_results.log")
		_ = os.WriteFile(logPath, []byte(logBuf.String()), 0600)
		fmt.Printf("\n[+] Round 2 wire log written to %s\n", logPath)
	}
}

// =========================================================================
// 1. ML-KEM-768 EXHAUSTIVE BYTE-BY-BYTE CIPHERTEXT MUTATION & EK CHECKS
// =========================================================================

func setMLKEM12BitCoeff(ek []byte, coeffIdx int, val uint16) {
	pair := coeffIdx / 2
	off := pair * 3
	if coeffIdx%2 == 0 {
		ek[off] = byte(val & 0xff)
		ek[off+1] = (ek[off+1] & 0xf0) | byte((val>>8)&0x0f)
	} else {
		ek[off+1] = (ek[off+1] & 0x0f) | byte((val&0x0f)<<4)
		ek[off+2] = byte((val >> 4) & 0xff)
	}
}

func runRound2MLKEM(rec *testRecorder, cryptoExe string) {
	fmt.Println("\n================ ROUND 2.1: ML-KEM-768 EXHAUSTIVE MUTATION MATRIX ================")
	h, err := startLineHarness(cryptoExe)
	if err != nil {
		rec.add("r2_mlkem", "setup", "start_harness", "FAIL", "start", err.Error(), "")
		return
	}
	defer h.close()

	dSeed := strings.Repeat("42", 32)
	zSeed := strings.Repeat("99", 32)
	mSeed := strings.Repeat("17", 32)

	kg, err := h.call("MLKEM768_KEYGEN", dSeed, zSeed)
	if err != nil || len(kg) < 3 || kg[0] != "OK" {
		rec.add("r2_mlkem", "base", "keygen", "FAIL", "OK", fmt.Sprintf("err=%v cols=%v", err, kg), "")
		return
	}
	ekHex, dkHex := kg[1], kg[2]
	ekBytes, _ := hex.DecodeString(ekHex)

	enc, err := h.call("MLKEM768_ENCAPS", ekHex, mSeed)
	if err != nil || len(enc) < 3 || enc[0] != "OK" {
		rec.add("r2_mlkem", "base", "encaps", "FAIL", "OK", fmt.Sprintf("err=%v cols=%v", err, enc), "")
		return
	}
	ctHex, ssValid := enc[1], enc[2]
	ctBytes, _ := hex.DecodeString(ctHex)

	dec0, err := h.call("MLKEM768_DECAPS", ctHex, dkHex)
	if err != nil || len(dec0) < 2 || dec0[0] != "OK" || dec0[1] != ssValid {
		rec.add("r2_mlkem", "base", "decaps_valid", "FAIL", ssValid, fmt.Sprintf("err=%v cols=%v", err, dec0), "")
		return
	}
	rec.add("r2_mlkem", "base", "keygen_encaps_decaps_1088B", "PASS", "ek=1184B ct=1088B ss=32B match", fmt.Sprintf("ek=%dB ct=%dB ss=%s", len(ekBytes), len(ctBytes), ssValid[:16]+"..."), "")

	// Record natural 0x00 byte offsets in ct for strcmp verification
	var zeroPos []int
	for i, b := range ctBytes {
		if b == 0x00 {
			zeroPos = append(zeroPos, i)
		}
	}

	// Exhaustive 1088 byte-position XOR 0x01 mutations!
	seenSS := map[string]int{}
	var failPositions []int
	var validMatchPositions []int
	var dupPositions []string
	var badLenPositions []int
	detSamples := map[int]string{}
	sampleIdxs := map[int]bool{0: true, 1: true, 31: true, 32: true, 543: true, 544: true, 1055: true, 1056: true, 1087: true}

	for i := range ctBytes {
		mut := append([]byte{}, ctBytes...)
		mut[i] ^= 0x01
		cols, derr := h.call("MLKEM768_DECAPS", hex.EncodeToString(mut), dkHex)
		if derr != nil || len(cols) < 2 || cols[0] != "OK" {
			failPositions = append(failPositions, i)
			continue
		}
		ss := cols[1]
		if len(ss) != 64 {
			badLenPositions = append(badLenPositions, i)
		}
		if ss == ssValid {
			validMatchPositions = append(validMatchPositions, i)
		}
		if prev, exists := seenSS[ss]; exists {
			dupPositions = append(dupPositions, fmt.Sprintf("%d==%d", prev, i))
		} else {
			seenSS[ss] = i
		}
		if sampleIdxs[i] {
			detSamples[i] = ss
		}
	}

	if len(failPositions) == 0 && len(validMatchPositions) == 0 && len(dupPositions) == 0 && len(badLenPositions) == 0 {
		rec.add("r2_mlkem", "ct_mutate", "all_1088_bytes_xor01_implicit_reject", "PASS",
			"1088/1088 OK, 32B ss!=ss_valid, 1088 distinct ss",
			fmt.Sprintf("1088/1088 distinct implicit rejections (natural 0x00 in ct at %v)", zeroPos[:minInt(len(zeroPos), 6)]), "")
	} else {
		rec.add("r2_mlkem", "ct_mutate", "all_1088_bytes_xor01_implicit_reject", "FAIL",
			"1088/1088 distinct implicit rejections",
			fmt.Sprintf("fails=%v validLeak=%v dups=%v badLen=%v", failPositions[:minInt(len(failPositions), 10)], validMatchPositions[:minInt(len(validMatchPositions), 10)], dupPositions[:minInt(len(dupPositions), 10)], badLenPositions[:minInt(len(badLenPositions), 10)]), "")
	}

	// Re-run sample indices for FO determinism check
	detFail := 0
	for idx, wantSS := range detSamples {
		mut := append([]byte{}, ctBytes...)
		mut[idx] ^= 0x01
		cols, derr := h.call("MLKEM768_DECAPS", hex.EncodeToString(mut), dkHex)
		if derr != nil || len(cols) < 2 || cols[0] != "OK" || cols[1] != wantSS {
			detFail++
		}
	}
	stDet := "PASS"
	if detFail > 0 {
		stDet = "FAIL"
	}
	rec.add("r2_mlkem", "ct_mutate", "fo_implicit_reject_determinism", stDet, "identical ss_rej on repeat", fmt.Sprintf("checked=%d mismatches=%d", len(detSamples), detFail), "")

	// Explicit 0x00 / strcmp-truncation checks: set ct[i]=0x00 across early/mid/last-32B + paired (ct[0]=0x00, ct[1087]^=1)
	zeroIdxs := []int{0, 1, 2, 15, 31, 32, 63, 64, 511, 512, 544, 1055, 1056, 1060, 1072, 1086, 1087}
	zeroFails := []string{}
	zeroSS := map[string]bool{}
	for _, idx := range zeroIdxs {
		mut := append([]byte{}, ctBytes...)
		if mut[idx] == 0x00 {
			mut[idx] = 0x01 // ensure actual mutation if originally 0x00
		} else {
			mut[idx] = 0x00
		}
		cols, derr := h.call("MLKEM768_DECAPS", hex.EncodeToString(mut), dkHex)
		if derr != nil || len(cols) < 2 || cols[0] != "OK" || len(cols[1]) != 64 || cols[1] == ssValid {
			zeroFails = append(zeroFails, fmt.Sprintf("idx=%d:%v", idx, cols))
		} else {
			zeroSS[cols[1]] = true
		}
	}
	// Pair check: force ct[0]=0x00 vs ct[0]=0x00 + ct[1087]^=1 (would collide if strcmp truncates at byte 0!)
	mutPairA := append([]byte{}, ctBytes...)
	mutPairA[0] = 0x00
	if ctBytes[0] == 0x00 {
		mutPairA[1] = 0x00
	}
	mutPairB := append([]byte{}, mutPairA...)
	mutPairB[1087] ^= 0x01
	colA, _ := h.call("MLKEM768_DECAPS", hex.EncodeToString(mutPairA), dkHex)
	colB, _ := h.call("MLKEM768_DECAPS", hex.EncodeToString(mutPairB), dkHex)
	pairOK := len(colA) >= 2 && colA[0] == "OK" && len(colB) >= 2 && colB[0] == "OK" && colA[1] != colB[1] && colA[1] != ssValid && colB[1] != ssValid
	if len(zeroFails) == 0 && len(zeroSS) == len(zeroIdxs) && pairOK {
		rec.add("r2_mlkem", "ct_mutate", "strcmp_0x00_truncation_vectors", "PASS",
			"all 17 0x00 mutations + (0x00@0, flip@1087) distinct & != ss_valid",
			fmt.Sprintf("%d/17 distinct, pairA!=pairB=%v", len(zeroSS), pairOK), "")
	} else {
		rec.add("r2_mlkem", "ct_mutate", "strcmp_0x00_truncation_vectors", "FAIL",
			"no strcmp/0x00 truncation",
			fmt.Sprintf("zeroFails=%v distinct=%d/%d pairOK=%v", zeroFails, len(zeroSS), len(zeroIdxs), pairOK), "")
	}

	// Probe whether harness supports MLKEM768_EK_CHECK command directly; test both EK_CHECK (if present) and ENCAPS!
	ekCheckCmd := "MLKEM768_EK_CHECK"
	probeEK, perr := h.call(ekCheckCmd, ekHex)
	hasEKCheck := perr == nil && len(probeEK) > 0 && probeEK[0] == "OK"
	rec.add("r2_mlkem", "ek_check", "command_support_probe", "INFO", "check MLKEM768_EK_CHECK availability", fmt.Sprintf("supported=%v resp=%v", hasEKCheck, probeEK), "")

	// Test boundary coefficients 3328 (valid), 3329 (invalid), 4095 (invalid) in first (0,1), middle (384,385), final (766,767)
	coeffPositions := []struct {
		label string
		idx   int
	}{
		{"first_even_0", 0},
		{"first_odd_1", 1},
		{"mid_even_384", 384},
		{"mid_odd_385", 385},
		{"final_even_766", 766},
		{"final_odd_767", 767},
	}
	coeffVals := []struct {
		val    uint16
		wantOK bool
	}{
		{3328, true},
		{3329, false},
		{4095, false},
	}
	for _, pos := range coeffPositions {
		for _, cv := range coeffVals {
			mutEK := append([]byte{}, ekBytes...)
			setMLKEM12BitCoeff(mutEK, pos.idx, cv.val)
			mutHex := hex.EncodeToString(mutEK)
			name := fmt.Sprintf("coeff_%s_val_%d", pos.label, cv.val)

			// Test via MLKEM768_ENCAPS (always present)
			encRes, eerr := h.call("MLKEM768_ENCAPS", mutHex, mSeed)
			encOK := eerr == nil && len(encRes) > 0 && encRes[0] == "OK"
			allOK := encOK == cv.wantOK
			detail := fmt.Sprintf("encaps=%v", encRes[0])
			if hasEKCheck {
				chkRes, cerr := h.call(ekCheckCmd, mutHex)
				chkOK := cerr == nil && len(chkRes) > 0 && chkRes[0] == "OK"
				allOK = allOK && (chkOK == cv.wantOK)
				detail += fmt.Sprintf(" ek_check=%v", chkRes[0])
			}
			st := "PASS"
			if !allOK {
				st = "FAIL"
			}
			exp := "FAIL (coeff >= 3329)"
			if cv.wantOK {
				exp = "OK (coeff == 3328 <= q-1)"
			}
			rec.add("r2_mlkem", "ek_check", name, st, exp, detail, "")
		}
	}
}

// =========================================================================
// 2. AEAD DIFFERENTIAL REF VS GOOSE-WING ACROSS 2048B THRESHOLD + IV/TAG
// =========================================================================

func runRound2AEAD(rec *testRecorder, cryptoExe string) {
	fmt.Println("\n================ ROUND 2.2: AEAD 2048B DIFFERENTIAL & IV/TAG MATRIX ================")
	h, err := startLineHarness(cryptoExe)
	if err != nil {
		rec.add("r2_aead", "setup", "start_harness", "FAIL", "start", err.Error(), "")
		return
	}
	defer h.close()

	type aeadAlg struct {
		name    string
		sealCmd string
		openCmd string
		keyLen  int
		newAEAD func(key []byte) (cipher.AEAD, error)
	}
	algs := []aeadAlg{
		{"aes128_gcm", "AES128_GCM_SEAL", "AES128_GCM_OPEN", 16, func(k []byte) (cipher.AEAD, error) {
			b, err := aes.NewCipher(k)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(b)
		}},
		{"aes256_gcm", "AES256_GCM_SEAL", "AES256_GCM_OPEN", 32, func(k []byte) (cipher.AEAD, error) {
			b, err := aes.NewCipher(k)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(b)
		}},
		{"chacha20_poly1305", "CHACHA20_POLY1305_SEAL", "CHACHA20_POLY1305_OPEN", 32, newChaCha20Poly1305},
	}

	lengths := []int{0, 1, 15, 16, 63, 64, 1024, 2047, 2048, 2049, 2064, 4096, 8192, 16384}
	tamperLens := map[int]bool{2047: true, 2049: true, 4096: true}
	aad := []byte("round2-aead-aad-verify-2026!")
	iv := mustHex("070000004041424344454647")

	for _, alg := range algs {
		key := make([]byte, alg.keyLen)
		for i := range key {
			key[i] = byte(0x80 + i)
		}
		refAEAD, _ := alg.newAEAD(key)
		keyHex := hex.EncodeToString(key)
		ivHex := hex.EncodeToString(iv)
		aadHex := hex.EncodeToString(aad)

		// Length differential sweep
		for _, ptLen := range lengths {
			pt := make([]byte, ptLen)
			for i := range pt {
				pt[i] = byte((i*31 + 7) & 0xff)
			}
			sealed := refAEAD.Seal(nil, iv, pt, aad)
			refCT := sealed[:ptLen]
			refTag := sealed[ptLen:]

			sealCols, serr := h.call(alg.sealCmd, keyHex, ivHex, aadHex, hexOrDash(pt))
			sealMatch := serr == nil && len(sealCols) >= 3 && sealCols[0] == "OK" && sealCols[1] == hexOrDash(refCT) && sealCols[2] == hex.EncodeToString(refTag)

			openCols, oerr := h.call(alg.openCmd, keyHex, ivHex, aadHex, hexOrDash(refCT), hex.EncodeToString(refTag))
			openMatch := oerr == nil && len(openCols) >= 2 && openCols[0] == "OK" && openCols[1] == hexOrDash(pt)

			st := "PASS"
			if !sealMatch || !openMatch {
				st = "FAIL"
			}
			obs := fmt.Sprintf("sealOK=%v openOK=%v", sealMatch, openMatch)
			if !sealMatch {
				obs += fmt.Sprintf(" sealErr=%v sealCol0=%v", serr, firstCol(sealCols))
			}
			if !openMatch {
				obs += fmt.Sprintf(" openErr=%v openCol0=%v", oerr, firstCol(openCols))
			}
			rec.add("r2_aead", alg.name, fmt.Sprintf("len_%d_parity", ptLen), st, "byte-for-byte Seal+Open parity", obs, "")

			// Tamper checks at 2047, 2049, 4096
			if tamperLens[ptLen] {
				tampers := []struct {
					tname string
					mAAD  []byte
					mCT   []byte
					mTag  []byte
				}{
					{"ct_flip_first", aad, flipAt(refCT, 0), refTag},
					{"ct_flip_mid", aad, flipAt(refCT, ptLen/2), refTag},
					{"ct_flip_last", aad, flipAt(refCT, ptLen-1), refTag},
					{"aad_flip_first", flipAt(aad, 0), refCT, refTag},
					{"aad_flip_last", flipAt(aad, len(aad)-1), refCT, refTag},
					{"tag_flip_first", aad, refCT, flipAt(refTag, 0)},
					{"tag_flip_last", aad, refCT, flipAt(refTag, 15)},
				}
				var accepted []string
				for _, t := range tampers {
					oc, err2 := h.call(alg.openCmd, keyHex, ivHex, hexOrDash(t.mAAD), hexOrDash(t.mCT), hex.EncodeToString(t.mTag))
					if err2 != nil || len(oc) == 0 || oc[0] != "FAIL" {
						accepted = append(accepted, fmt.Sprintf("%s=%v(err=%v)", t.tname, firstCol(oc), err2))
					}
				}
				tst := "PASS"
				if len(accepted) > 0 {
					tst = "FAIL"
				}
				rec.add("r2_aead", alg.name, fmt.Sprintf("len_%d_tamper_7x", ptLen), tst, "7/7 tampers FAIL", fmt.Sprintf("anomalies=%v", accepted), "")
			}
		}

		// Invalid IV lengths (0, 1, 11, 13, 16) on BOTH SEAL and OPEN
		ptSmall := []byte("iv-tag-edge-test")
		sealedSmall := refAEAD.Seal(nil, iv, ptSmall, aad)
		ctSmall, tagSmall := sealedSmall[:len(ptSmall)], sealedSmall[len(ptSmall):]

		badIVLens := []int{0, 1, 11, 13, 16}
		var badIVAnom []string
		for _, ivl := range badIVLens {
			badIV := bytes.Repeat([]byte{0x42}, ivl)
			sc, serr := h.call(alg.sealCmd, keyHex, hexOrDash(badIV), aadHex, hex.EncodeToString(ptSmall))
			oc, oerr := h.call(alg.openCmd, keyHex, hexOrDash(badIV), aadHex, hex.EncodeToString(ctSmall), hex.EncodeToString(tagSmall))
			if serr != nil || len(sc) == 0 || sc[0] != "FAIL" {
				badIVAnom = append(badIVAnom, fmt.Sprintf("SEAL_iv%d=%v", ivl, firstCol(sc)))
			}
			if oerr != nil || len(oc) == 0 || oc[0] != "FAIL" {
				badIVAnom = append(badIVAnom, fmt.Sprintf("OPEN_iv%d=%v", ivl, firstCol(oc)))
			}
		}
		ivSt := "PASS"
		if len(badIVAnom) > 0 {
			ivSt = "FAIL"
		}
		rec.add("r2_aead", alg.name, "invalid_iv_lens_0_1_11_13_16", ivSt, "all SEAL+OPEN FAIL", fmt.Sprintf("anomalies=%v", badIVAnom), "")

		// Truncated & oversized tags (0, 1, 4, 8, 12, 15, 17, 32) on OPEN
		badTagLens := []int{0, 1, 4, 8, 12, 15, 17, 32}
		var badTagAnom []string
		for _, tl := range badTagLens {
			var bt []byte
			if tl <= 16 {
				bt = tagSmall[:tl]
			} else {
				bt = append(append([]byte{}, tagSmall...), make([]byte, tl-16)...)
			}
			oc, oerr := h.call(alg.openCmd, keyHex, ivHex, aadHex, hex.EncodeToString(ctSmall), hexOrDash(bt))
			if oerr != nil || len(oc) == 0 || oc[0] != "FAIL" {
				badTagAnom = append(badTagAnom, fmt.Sprintf("OPEN_tag%d=%v", tl, firstCol(oc)))
			}
		}
		tagSt := "PASS"
		if len(badTagAnom) > 0 {
			tagSt = "FAIL"
		}
		rec.add("r2_aead", alg.name, "invalid_tag_lens_0_1_4_8_12_15_17_32", tagSt, "all OPEN FAIL", fmt.Sprintf("anomalies=%v", badTagAnom), "")
	}
}

func flipAt(b []byte, idx int) []byte {
	out := append([]byte{}, b...)
	out[idx] ^= 0x01
	return out
}

func firstCol(cols []string) string {
	if len(cols) == 0 {
		return "<empty>"
	}
	return cols[0]
}

// =========================================================================
// 3. ASYMMETRIC 2024-2026 MATRIX (Ed25519, ECDSA P-256/P-384, RSA PKCS#1 e=3)
// =========================================================================

// Pure-Go Edwards25519 big.Int arithmetic to construct exact mixed-order points (A+T, R+T)
var (
	edP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edD = func() *big.Int {
		// d = -121665 * inv(121666) mod p
		inv := new(big.Int).ModInverse(big.NewInt(121666), edP)
		d := new(big.Int).Mul(big.NewInt(-121665), inv)
		return d.Mod(d, edP)
	}()
	edBy = func() *big.Int {
		inv := new(big.Int).ModInverse(big.NewInt(5), edP)
		y := new(big.Int).Mul(big.NewInt(4), inv)
		return y.Mod(y, edP)
	}()
	edBx, _ = new(big.Int).SetString("15112221349535400772501151409588531511454012693041857206046113283949847762202", 10)
)

type edPt struct{ x, y *big.Int }

func edAdd(p1, p2 edPt) edPt {
	// x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
	// y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2)
	x1y2 := new(big.Int).Mul(p1.x, p2.y)
	y1x2 := new(big.Int).Mul(p1.y, p2.x)
	y1y2 := new(big.Int).Mul(p1.y, p2.y)
	x1x2 := new(big.Int).Mul(p1.x, p2.x)

	dxxyy := new(big.Int).Mul(edD, new(big.Int).Mul(x1x2, y1y2))
	dxxyy.Mod(dxxyy, edP)

	denX := new(big.Int).Add(big.NewInt(1), dxxyy)
	denX.Mod(denX, edP)
	denY := new(big.Int).Sub(big.NewInt(1), dxxyy)
	denY.Mod(denY, edP)

	invX := new(big.Int).ModInverse(denX, edP)
	invY := new(big.Int).ModInverse(denY, edP)

	x3 := new(big.Int).Mul(new(big.Int).Add(x1y2, y1x2), invX)
	x3.Mod(x3, edP)
	y3 := new(big.Int).Mul(new(big.Int).Add(y1y2, x1x2), invY)
	y3.Mod(y3, edP)
	return edPt{x: x3, y: y3}
}

func edScalarMul(k *big.Int, pt edPt) edPt {
	res := edPt{x: big.NewInt(0), y: big.NewInt(1)}
	base := pt
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			res = edAdd(res, base)
		}
		base = edAdd(base, base)
	}
	return res
}

func edEncode(pt edPt) []byte {
	be := pt.y.Bytes()
	var out [32]byte
	for i := 0; i < len(be) && i < 32; i++ {
		out[i] = be[len(be)-1-i]
	}
	if pt.x.Bit(0) == 1 {
		out[31] |= 0x80
	}
	return out[:]
}

func edDecode(b []byte) (edPt, bool) {
	yBytes := append([]byte{}, b...)
	sign := (yBytes[31] >> 7) & 1
	yBytes[31] &= 0x7f
	y := new(big.Int).SetBytes(reverseBytes(yBytes))
	if y.Cmp(edP) >= 0 {
		return edPt{}, false
	}
	// x^2 = (y^2 - 1) / (d*y^2 + 1) mod p
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, edP)
	num := new(big.Int).Sub(y2, big.NewInt(1))
	num.Mod(num, edP)
	den := new(big.Int).Add(new(big.Int).Mul(edD, y2), big.NewInt(1))
	den.Mod(den, edP)
	x2 := new(big.Int).Mul(num, new(big.Int).ModInverse(den, edP))
	x2.Mod(x2, edP)
	x := new(big.Int).ModSqrt(x2, edP)
	if x == nil {
		return edPt{}, false
	}
	if uint(x.Bit(0)) != uint(sign) {
		x = new(big.Int).Sub(edP, x)
		x.Mod(x, edP)
	}
	return edPt{x: x, y: y}, true
}

func leBytesToBig(b []byte) *big.Int {
	return new(big.Int).SetBytes(reverseBytes(b))
}

func bigToLE32(v *big.Int) []byte {
	be := v.Bytes()
	var out [32]byte
	for i := 0; i < len(be) && i < 32; i++ {
		out[i] = be[len(be)-1-i]
	}
	return out[:]
}

// Generate an actual 2048-bit RSA key with e = 3 for authentic Bleichenbacher e=3 tests!
func generateRSAKeyE3() (*rsa.PrivateKey, error) {
	three := big.NewInt(3)
	one := big.NewInt(1)
	two := big.NewInt(2)
	var p, q *big.Int
	for {
		c, err := rand.Prime(rand.Reader, 1024)
		if err != nil {
			return nil, err
		}
		if new(big.Int).Mod(c, three).Cmp(two) == 0 {
			if p == nil {
				p = c
			} else if c.Cmp(p) != 0 {
				q = c
				break
			}
		}
	}
	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	d := new(big.Int).ModInverse(three, phi)
	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: 3},
		D:         d,
		Primes:    []*big.Int{p, q},
	}, nil
}

// Integer cube root floor(cbrt(x)) for Bleichenbacher e=3 forgery construction
func bigCbrt(x *big.Int) *big.Int {
	lo := big.NewInt(0)
	hi := new(big.Int).Lsh(big.NewInt(1), uint((x.BitLen()+2)/3+1))
	three := big.NewInt(3)
	one := big.NewInt(1)
	for lo.Cmp(hi) < 0 {
		mid := new(big.Int).Add(lo, hi)
		mid.Add(mid, one)
		mid.Rsh(mid, 1)
		cube := new(big.Int).Exp(mid, three, nil)
		if cube.Cmp(x) <= 0 {
			lo = mid
		} else {
			hi = new(big.Int).Sub(mid, one)
		}
	}
	return lo
}

var p384OrderN, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)

func runRound2Asymmetric(rec *testRecorder, cryptoExe string) {
	fmt.Println("\n================ ROUND 2.3: ASYMMETRIC 2024-2026 MATRIX ================")
	h, err := startLineHarness(cryptoExe)
	if err != nil {
		rec.add("r2_asym", "setup", "start_harness", "FAIL", "start", err.Error(), "")
		return
	}
	defer h.close()

	check := func(cat, name string, wantOK, infoOnly bool, exp string, args ...string) {
		cols, derr := h.call(args...)
		if derr != nil {
			rec.add("r2_asym", cat, name, "FAIL", exp, "err: "+derr.Error(), "")
			return
		}
		gotOK := len(cols) > 0 && cols[0] == "OK"
		st := "PASS"
		if infoOnly {
			st = "INFO"
		} else if gotOK != wantOK {
			st = "FAIL"
		}
		rec.add("r2_asym", cat, name, st, exp, strings.Join(cols, "\t"), "")
	}

	msg := []byte("round2-asymmetric-cve-vector")
	msgHex := hex.EncodeToString(msg)

	// --- 3A. Ed25519 Taming the Many EdDSAs ---
	smallOrderPts := []struct {
		name string
		hex  string
	}{
		{"ord1_identity", "0100000000000000000000000000000000000000000000000000000000000000"},
		{"ord2", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{"ord4a", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"ord4b", "0000000000000000000000000000000000000000000000000000000000000080"},
		{"ord8a", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"},
		{"ord8b", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"},
		{"ord8c", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"},
		{"ord8d", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"},
	}

	// Base scalar r = 12345 -> R_valid = r*B, S_valid = r (passes cofactored 8SB = 8R + 8kA for ANY small-order A!)
	rScalar := big.NewInt(12345)
	B := edPt{x: edBx, y: edBy}
	RvalidBytes := edEncode(edScalarMul(rScalar, B))
	SvalidBytes := bigToLE32(rScalar)
	zero32Hex := strings.Repeat("00", 32)

	for _, pt := range smallOrderPts {
		// Vector 1: A = T, R = T, S = 0 (8*0*B == 8*T + 8*k*T == 0!)
		check("ed25519", "small_order_A_R_S0_"+pt.name, false, false, "reject small-order A=R=T, S=0",
			"ED25519_VERIFY", pt.hex, msgHex, pt.hex+zero32Hex)
		// Vector 2: A = T, R = r*B, S = r (8*S*B == 8*R + 8*k*T == 8*r*B!)
		check("ed25519", "small_order_A_validR_"+pt.name, false, false, "reject small-order A with R=rB, S=r",
			"ED25519_VERIFY", pt.hex, msgHex, hex.EncodeToString(RvalidBytes)+hex.EncodeToString(SvalidBytes))
	}

	// Mixed-order A' = A + T_2 and R' = R + T_2 (Taming the Many EdDSAs #4/#5)
	aScalar := big.NewInt(777777)
	Apt := edScalarMul(aScalar, B)
	T2, _ := edDecode(mustHex(smallOrderPts[1].hex)) // order-2 point (0, -1)
	Amixed := edAdd(Apt, T2)
	AmixedBytes := edEncode(Amixed)

	// Find message M where k = H(R || A_mixed || M) mod L is ODD (so k*T2 != O -> cofactorless rejects, cofactored accepts!)
	var mixedMsg []byte
	var mixedSig []byte
	for ctr := range 64 {
		cand := fmt.Appendf(nil, "mixed-order-msg-%d", ctr)
		h512 := sha512.New()
		h512.Write(RvalidBytes)
		h512.Write(AmixedBytes)
		h512.Write(cand)
		k := new(big.Int).Mod(leBytesToBig(h512.Sum(nil)), ed25519OrderL)
		if k.Bit(0) == 1 {
			// S = (r + k*a) mod L => S*B = R + k*A, while R + k*(A+T2) = R + k*A + T2 != S*B, YET 8*S*B == 8*(R + k*A')!
			S := new(big.Int).Add(rScalar, new(big.Int).Mul(k, aScalar))
			S.Mod(S, ed25519OrderL)
			mixedMsg = cand
			mixedSig = append(append([]byte{}, RvalidBytes...), bigToLE32(S)...)
			break
		}
	}
	check("ed25519", "mixed_order_A_plus_T2_odd_k", false, true, "observe cofactorless (FAIL) vs cofactored (OK) on mixed-order A+T2",
		"ED25519_VERIFY", hex.EncodeToString(AmixedBytes), hex.EncodeToString(mixedMsg), hex.EncodeToString(mixedSig))

	// Mixed-order R' = R + T2 with valid A: S = (r + k*a) mod L => S*B = R + k*A != (R+T2) + k*A, YET 8*S*B == 8*(R'+k*A)!
	RmixedBytes := edEncode(edAdd(edScalarMul(rScalar, B), T2))
	Abytes := edEncode(Apt)
	{
		h512 := sha512.New()
		h512.Write(RmixedBytes)
		h512.Write(Abytes)
		h512.Write(msg)
		k := new(big.Int).Mod(leBytesToBig(h512.Sum(nil)), ed25519OrderL)
		S := new(big.Int).Add(rScalar, new(big.Int).Mul(k, aScalar))
		S.Mod(S, ed25519OrderL)
		sigRmix := append(append([]byte{}, RmixedBytes...), bigToLE32(S)...)
		check("ed25519", "mixed_order_R_plus_T2", false, true, "observe cofactorless (FAIL) vs cofactored (OK) on mixed-order R+T2",
			"ED25519_VERIFY", hex.EncodeToString(Abytes), msgHex, hex.EncodeToString(sigRmix))
	}

	// Non-canonical A and R encodings (y >= p, y=1 with sign=1 for x=0, y=p-1 with sign=1 for x=0)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edSig := ed25519.Sign(edPriv, msg)
	nonCanonEncs := []struct {
		name string
		hex  string
	}{
		{"y_eq_p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{"y_eq_p_plus_1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{"y_eq_2pow255_minus_1", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{"x0_y1_neg_sign", "0100000000000000000000000000000000000000000000000000000000000080"},
		{"x0_yminus1_neg_sign", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
	}
	for _, nc := range nonCanonEncs {
		check("ed25519", "noncanon_A_"+nc.name, false, false, "reject non-canonical A",
			"ED25519_VERIFY", nc.hex, msgHex, hex.EncodeToString(edSig))
		check("ed25519", "noncanon_R_"+nc.name, false, false, "reject non-canonical R",
			"ED25519_VERIFY", hex.EncodeToString(edPub), msgHex, nc.hex+hex.EncodeToString(edSig[32:]))
	}
	// S >= L, S = L, S = 0, 63B, 65B with trailing 0x00
	check("ed25519", "S_plus_L", false, false, "reject S >= L",
		"ED25519_VERIFY", hex.EncodeToString(edPub), msgHex, hex.EncodeToString(makeEd25519MalleableSig(edSig)))
	check("ed25519", "S_eq_L", false, false, "reject S == L",
		"ED25519_VERIFY", hex.EncodeToString(edPub), msgHex, hex.EncodeToString(edSig[:32])+hex.EncodeToString(bigToLE32(ed25519OrderL)))
	check("ed25519", "S_eq_0", false, false, "reject S == 0 on real A/R",
		"ED25519_VERIFY", hex.EncodeToString(edPub), msgHex, hex.EncodeToString(edSig[:32])+zero32Hex)
	check("ed25519", "sig_trunc_63B", false, false, "reject 63B sig",
		"ED25519_VERIFY", hex.EncodeToString(edPub), msgHex, hex.EncodeToString(edSig[:63]))
	check("ed25519", "sig_extended_65B_trailing_00", false, false, "reject 65B sig with trailing 0x00",
		"ED25519_VERIFY", hex.EncodeToString(edPub), msgHex, hex.EncodeToString(append(append([]byte{}, edSig...), 0x00)))

	// --- 3B. ECDSA P-256 and P-384 (CVE-2022-21449 Psychic Signatures + DER malleability) ---
	testECDSA := func(curveName, cmd string, curve elliptic.Curve, orderN *big.Int, coordLen int, use384 bool) {
		k, _ := ecdsa.GenerateKey(curve, rand.Reader)
		pub := make([]byte, 1+2*coordLen)
		pub[0] = 0x04
		k.X.FillBytes(pub[1 : 1+coordLen])
		k.Y.FillBytes(pub[1+coordLen:])
		pubHex := hex.EncodeToString(pub)
		var sig []byte
		if use384 {
			d := sha512.Sum384(msg)
			sig, _ = ecdsa.SignASN1(rand.Reader, k, d[:])
		} else {
			d := sha256.Sum256(msg)
			sig, _ = ecdsa.SignASN1(rand.Reader, k, d[:])
		}
		var rs struct{ R, S *big.Int }
		_, _ = asn1.Unmarshal(sig, &rs)

		check(curveName, "valid", true, false, "valid", cmd, pubHex, msgHex, hex.EncodeToString(sig))

		psychic, _ := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(0), big.NewInt(0)})
		r0s1, _ := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(0), big.NewInt(1)})
		r1s0, _ := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(1), big.NewInt(0)})
		rn, _ := asn1.Marshal(struct{ R, S *big.Int }{orderN, big.NewInt(1)})
		sn, _ := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(1), orderN})
		check(curveName, "psychic_r0_s0_CVE_2022_21449", false, false, "reject (0,0)", cmd, pubHex, msgHex, hex.EncodeToString(psychic))
		check(curveName, "r_eq_0", false, false, "reject r=0", cmd, pubHex, msgHex, hex.EncodeToString(r0s1))
		check(curveName, "s_eq_0", false, false, "reject s=0", cmd, pubHex, msgHex, hex.EncodeToString(r1s0))
		check(curveName, "r_eq_n", false, false, "reject r=n", cmd, pubHex, msgHex, hex.EncodeToString(rn))
		check(curveName, "s_eq_n", false, false, "reject s=n", cmd, pubHex, msgHex, hex.EncodeToString(sn))

		// Negative DER r and negative DER s (MSB=1 without leading 0x00)
		rb := rs.R.Bytes()
		sb := rs.S.Bytes()
		rNeg := append([]byte{}, rb...)
		rNeg[0] |= 0x80
		sNeg := append([]byte{}, sb...)
		sNeg[0] |= 0x80
		canonEnc := func(b []byte) []byte {
			if len(b) > 0 && b[0]&0x80 != 0 {
				return append([]byte{0x00}, b...)
			}
			return b
		}
		check(curveName, "neg_der_r", false, false, "reject negative DER r", cmd, pubHex, msgHex, hex.EncodeToString(derSeq(append(derTLV(0x02, rNeg), derTLV(0x02, canonEnc(sb))...))))
		check(curveName, "neg_der_s", false, false, "reject negative DER s", cmd, pubHex, msgHex, hex.EncodeToString(derSeq(append(derTLV(0x02, canonEnc(rb)), derTLV(0x02, sNeg)...))))

		// Unnecessary leading 0x00 on r (when MSB=0, i.e., 0x00 0x00 ... or 0x00 <byte<0x80>)
		rLeadZero := append([]byte{0x00}, canonEnc(rb)...)
		if rLeadZero[1]&0x80 != 0 {
			rLeadZero = append([]byte{0x00}, rLeadZero...)
		}
		check(curveName, "unnecessary_lead_zero_r", false, false, "reject non-minimal DER INT r", cmd, pubHex, msgHex, hex.EncodeToString(derSeq(append(derTLV(0x02, rLeadZero), derTLV(0x02, canonEnc(sb))...))))

		// Overlong BER SEQUENCE length (0x30 0x81 <len>)
		body := append(derTLV(0x02, canonEnc(rb)), derTLV(0x02, canonEnc(sb))...)
		overlongSeq := append([]byte{0x30, 0x81, byte(len(body))}, body...)
		check(curveName, "overlong_ber_seq_len", false, false, "reject overlong BER SEQUENCE len", cmd, pubHex, msgHex, hex.EncodeToString(overlongSeq))

		// Trailing byte after SEQUENCE
		check(curveName, "trailing_byte_after_seq", false, false, "reject trailing byte", cmd, pubHex, msgHex, hex.EncodeToString(append(append([]byte{}, sig...), 0x00)))
	}
	testECDSA("ecdsa_p256", "ECDSA_P256_VERIFY_DER", elliptic.P256(), p256OrderN, 32, false)
	testECDSA("ecdsa_p384", "ECDSA_P384_VERIFY_DER", elliptic.P384(), p384OrderN, 48, true)

	// --- 3C. RSA PKCS#1 v1.5 e=3 Bleichenbacher & DigestAlgorithm Nested Garbage (CVE-2026-33894 / CVE-2026-85393) ---
	rsaE3, err := generateRSAKeyE3()
	if err != nil {
		rec.add("r2_asym", "rsa_e3", "keygen_e3", "FAIL", "generate e=3 key", err.Error(), "")
		return
	}
	pubE3Hex := hex.EncodeToString(x509.MarshalPKCS1PublicKey(&rsaE3.PublicKey))
	d256 := sha256.Sum256(msg)
	kLen := (rsaE3.N.BitLen() + 7) / 8 // 256 bytes

	sha256Prefix := mustHex("3031300d060960864801650304020105000420")
	validDI := append(append([]byte{}, sha256Prefix...), d256[:]...)
	buildEM := func(b1 byte, psLen int, body, tail []byte) []byte {
		em := make([]byte, 0, kLen)
		em = append(em, 0x00, b1)
		em = append(em, bytes.Repeat([]byte{0xff}, psLen)...)
		em = append(em, 0x00)
		em = append(em, body...)
		em = append(em, tail...)
		return em
	}

	// Baseline valid e=3 signature
	validEM := buildEM(0x01, kLen-3-len(validDI), validDI, nil)
	check("rsa_e3", "valid_pkcs1_e3", true, false, "valid e=3 PKCS#1 v1.5",
		"RSA_PKCS1_SHA256_VERIFY_DER", pubE3Hex, msgHex, hex.EncodeToString(rsaRawSign(rsaE3, validEM)))

	// 1. Authentic Bleichenbacher e=3 cube-root forgery (no private key used!):
	// Target EM = 0x00 || 0x01 || 0xFF*8 || 0x00 || validDI || 0xFF*(remaining)
	// Cube root s = cbrt(target) => s^3 starts with exact 0x00 0x01 FF*8 0x00 validDI followed by low-byte cube-root garbage!
	bleichTarget := buildEM(0x01, 8, validDI, bytes.Repeat([]byte{0xff}, kLen-3-8-len(validDI)))
	sCube := bigCbrt(new(big.Int).SetBytes(bleichTarget))
	// Verify our cube-root forgery actually cubes to the prefix 00 01 FF*8 00 <validDI>
	cubeBytes := make([]byte, kLen)
	new(big.Int).Exp(sCube, big.NewInt(3), rsaE3.N).FillBytes(cubeBytes)
	sCubeBytes := make([]byte, kLen)
	sCube.FillBytes(sCubeBytes)
	prefixMatched := bytes.HasPrefix(cubeBytes, bleichTarget[:3+8+len(validDI)])
	check("rsa_e3", "bleichenbacher_cuberoot_CVE_2026_33894", false, false,
		fmt.Sprintf("reject e=3 cube-root forgery (prefixExact=%v)", prefixMatched),
		"RSA_PKCS1_SHA256_VERIFY_DER", pubE3Hex, msgHex, hex.EncodeToString(sCubeBytes))

	// 2. Exact m^d mod N trailing garbage after DigestInfo
	emTrail := buildEM(0x01, kLen-3-len(validDI)-4, validDI, []byte{0xde, 0xad, 0xbe, 0xef})
	check("rsa_e3", "trailing_garbage_after_digestinfo", false, false, "reject trailing garbage after DigestInfo",
		"RSA_PKCS1_SHA256_VERIFY_DER", pubE3Hex, msgHex, hex.EncodeToString(rsaRawSign(rsaE3, emTrail)))

	// 3. Nested garbage inside DigestAlgorithm: extra NULL (CVE-2026-85393)
	// AlgorithmIdentifier = SEQUENCE { OID(sha256), NULL, NULL }
	sha256OID := mustHex("0609608648016503040201")
	diExtraNull := derSeq(append(derSeq(append(append([]byte{}, sha256OID...), 0x05, 0x00, 0x05, 0x00)), derTLV(0x04, d256[:])...))
	emExtraNull := buildEM(0x01, kLen-3-len(diExtraNull), diExtraNull, nil)
	check("rsa_e3", "nested_extra_null_in_algid_CVE_2026_85393", false, false, "reject extra NULL inside DigestAlgorithm",
		"RSA_PKCS1_SHA256_VERIFY_DER", pubE3Hex, msgHex, hex.EncodeToString(rsaRawSign(rsaE3, emExtraNull)))

	// 4. Nested garbage inside DigestAlgorithm: extra OCTET STRING (CVE-2026-85393)
	diExtraOctet := derSeq(append(derSeq(append(append([]byte{}, sha256OID...), 0x05, 0x00, 0x04, 0x04, 0xde, 0xad, 0xbe, 0xef)), derTLV(0x04, d256[:])...))
	emExtraOctet := buildEM(0x01, kLen-3-len(diExtraOctet), diExtraOctet, nil)
	check("rsa_e3", "nested_extra_octet_in_algid_CVE_2026_85393", false, false, "reject extra OCTET STRING inside DigestAlgorithm",
		"RSA_PKCS1_SHA256_VERIFY_DER", pubE3Hex, msgHex, hex.EncodeToString(rsaRawSign(rsaE3, emExtraOctet)))

	// 5. Missing NULL parameter in AlgorithmIdentifier
	diNoNull := derSeq(append(derSeq(sha256OID), derTLV(0x04, d256[:])...))
	emNoNull := buildEM(0x01, kLen-3-len(diNoNull), diNoNull, nil)
	check("rsa_e3", "missing_null_in_algid", false, false, "reject missing NULL param in DigestAlgorithm",
		"RSA_PKCS1_SHA256_VERIFY_DER", pubE3Hex, msgHex, hex.EncodeToString(rsaRawSign(rsaE3, emNoNull)))

	// 6. Short PS padding (< 8 bytes of 0xFF: exactly 7 bytes of 0xFF, padded with trailing bytes to 256B)
	emShortPS := buildEM(0x01, 7, validDI, bytes.Repeat([]byte{0x00}, kLen-3-7-len(validDI)))
	check("rsa_e3", "short_ps_7_bytes_ff", false, false, "reject PS < 8 bytes (7 bytes 0xFF)",
		"RSA_PKCS1_SHA256_VERIFY_DER", pubE3Hex, msgHex, hex.EncodeToString(rsaRawSign(rsaE3, emShortPS)))

	// 7. Wrong block type 0x00 0x02
	emBT2 := buildEM(0x02, kLen-3-len(validDI), validDI, nil)
	check("rsa_e3", "wrong_block_type_0x02", false, false, "reject block type 0x02",
		"RSA_PKCS1_SHA256_VERIFY_DER", pubE3Hex, msgHex, hex.EncodeToString(rsaRawSign(rsaE3, emBT2)))

	// 8. sig >= N (N itself and N + 1)
	nBytes := make([]byte, kLen)
	rsaE3.N.FillBytes(nBytes)
	nPlus1 := new(big.Int).Add(rsaE3.N, big.NewInt(1)).Bytes()
	check("rsa_e3", "sig_eq_N", false, false, "reject sig == N", "RSA_PKCS1_SHA256_VERIFY_DER", pubE3Hex, msgHex, hex.EncodeToString(nBytes))
	check("rsa_e3", "sig_gt_N", false, false, "reject sig == N+1", "RSA_PKCS1_SHA256_VERIFY_DER", pubE3Hex, msgHex, hex.EncodeToString(nPlus1))
}

// =========================================================================
// 4. X.509 / ASN.1 2026 CVE MATRIX AGAINST x509_harness.exe
// =========================================================================

func buildRawX509Extensions(exts []pkix.Extension) []byte {
	var body []byte
	for _, e := range exts {
		oidBytes, _ := asn1.Marshal(e.Id)
		var eb []byte
		eb = append(eb, oidBytes...)
		if e.Critical {
			eb = append(eb, 0x01, 0x01, 0xff)
		}
		eb = append(eb, derTLV(0x04, e.Value)...)
		body = append(body, derSeq(eb)...)
	}
	return derSeq(body)
}

func makeNameConstraintsExt(permitted, excluded [][]byte) pkix.Extension {
	var body []byte
	if len(permitted) > 0 {
		var sub []byte
		for _, g := range permitted {
			sub = append(sub, derSeq(g)...) // GeneralSubtree ::= SEQUENCE { base GeneralName }
		}
		body = append(body, derTLV(0xa0, sub)...)
	}
	if len(excluded) > 0 {
		var sub []byte
		for _, g := range excluded {
			sub = append(sub, derSeq(g)...)
		}
		body = append(body, derTLV(0xa1, sub)...)
	}
	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 30},
		Critical: true,
		Value:    derSeq(body),
	}
}

func runRound2X509(rec *testRecorder, x509Exe string, pki *testPKI) {
	fmt.Println("\n================ ROUND 2.4: X.509 / ASN.1 2026 CVE MATRIX ================")
	h, err := startLineHarness(x509Exe)
	if err != nil {
		rec.add("r2_x509", "setup", "start_harness", "FAIL", "start", err.Error(), "")
		return
	}
	defer h.close()

	now := time.Now().UTC()
	nowUnix := fmt.Sprintf("%d", now.Unix())
	caHex := hex.EncodeToString(pki.caDER)
	oidEcdsaSha256 := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}

	verify := func(cat, name string, leaf []byte, inters [][]byte, peer string, wantOK, infoOnly bool, note string) {
		interHex := "-"
		if len(inters) > 0 {
			var parts []string
			for _, in := range inters {
				parts = append(parts, hex.EncodeToString(in))
			}
			interHex = strings.Join(parts, ",")
		}
		cols, derr := h.call("VERIFY", name, "BUILD", "SERVER", nowUnix, peer, hex.EncodeToString(leaf), interHex, caHex, "-1")
		if derr != nil {
			rec.add("r2_x509", cat, name, "FAIL", note, "harness err: "+derr.Error(), "")
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
		} else if gotOK != wantOK {
			st = "FAIL"
		}
		rec.add("r2_x509", cat, name, st, note, reason, "")
	}

	makeLeaf := func(serial int64, cn string, issuer *x509.Certificate, signer *ecdsa.PrivateKey, extraExts ...pkix.Extension) []byte {
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             now.Add(-24 * time.Hour),
			NotAfter:              now.Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			ExtraExtensions:       extraExts,
		}
		d, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &pki.ecKey.PublicKey, signer)
		if err != nil {
			panic(err)
		}
		return d
	}

	// Helper: create a valid intermediate CA cert, then replace its [3] extensions block in TBS and re-sign with CA
	makeCustomExtInter := func(serial int64, cn string, exts []pkix.Extension) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		// Base template for signing leaf certs validly
		baseTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             now.Add(-24 * time.Hour),
			NotAfter:              now.Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		baseDER, _ := x509.CreateCertificate(rand.Reader, baseTmpl, pki.caCert, &k.PublicKey, pki.caKey)
		parsed, _ := x509.ParseCertificate(baseDER)

		// Rebuild TBS replacing the [3] extensions field with our exact custom extensions!
		tbs, _, _, _ := extractCertParts(baseDER)
		var tbsSeq asn1.RawValue
		_, _ = asn1.Unmarshal(tbs, &tbsSeq)
		rest := tbsSeq.Bytes
		var newTBSBody []byte
		for len(rest) > 0 {
			var elem asn1.RawValue
			var err error
			rest, err = asn1.Unmarshal(rest, &elem)
			if err != nil {
				break
			}
			if elem.Class == asn1.ClassContextSpecific && elem.Tag == 3 {
				continue // strip original [3] extensions
			}
			newTBSBody = append(newTBSBody, elem.FullBytes...)
		}
		extCtx := derTLV(0xa3, buildRawX509Extensions(exts))
		newTBS := derSeq(append(newTBSBody, extCtx...))
		mutDER := signDERCertWithCA(newTBS, oidEcdsaSha256, pki.caKey, 0, nil, "")
		return parsed, k, mutDER
	}

	kuCertSignExt := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []byte{0x03, 0x02, 0x01, 0x06}} // keyCertSign | cRLSign
	bcTrueVal := derSeq([]byte{0x01, 0x01, 0xff})
	bcFalseVal := derSeq([]byte{0x01, 0x01, 0x00})
	sanExt := func(items ...[]byte) pkix.Extension {
		var b []byte
		for _, it := range items {
			b = append(b, it...)
		}
		return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: derSeq(b)}
	}

	// 4.1 Legacy basicConstraints OIDs 2.5.29.10 & 2.5.29.13 (node-forge GHSA-5x38-2vff-x55p)
	for _, legacy := range []struct {
		name string
		oid  asn1.ObjectIdentifier
	}{
		{"legacy_bc_2_5_29_10_before_19_false", asn1.ObjectIdentifier{2, 5, 29, 10}},
		{"legacy_bc_2_5_29_13_before_19_false", asn1.ObjectIdentifier{2, 5, 29, 13}},
	} {
		interCert, interKey, interDER := makeCustomExtInter(2001, "Legacy BC CA "+legacy.name, []pkix.Extension{
			kuCertSignExt,
			{Id: legacy.oid, Critical: false, Value: bcTrueVal},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: bcFalseVal},
		})
		leaf := makeLeaf(2002, "target.example", interCert, interKey, sanExt(derTLV(0x82, []byte("target.example"))))
		verify("bc_cve", legacy.name, leaf, [][]byte{interDER}, "target.example", false, false, "GHSA-5x38-2vff-x55p MUST reject non-CA")
	}

	// Legacy OID 2.5.29.10 ONLY (no 2.5.29.19 at all)
	{
		interCert, interKey, interDER := makeCustomExtInter(2003, "Legacy BC Only CA", []pkix.Extension{
			kuCertSignExt,
			{Id: asn1.ObjectIdentifier{2, 5, 29, 10}, Critical: false, Value: bcTrueVal},
		})
		leaf := makeLeaf(2004, "target.example", interCert, interKey, sanExt(derTLV(0x82, []byte("target.example"))))
		verify("bc_cve", "legacy_bc_2_5_29_10_without_19", leaf, [][]byte{interDER}, "target.example", false, false, "MUST reject CA lacking 2.5.29.19")
	}

	// 4.2 Truncated basicConstraints SEQUENCE overflowing OCTET STRING (Mbed TLS CVE-2026-49300)
	{
		// OCTET STRING wraps 3 bytes: 30 05 01 (SEQUENCE claims len 5 inside 3B OCTET STRING!)
		interCert, interKey, interDER := makeCustomExtInter(2005, "Trunc BC CA", []pkix.Extension{
			kuCertSignExt,
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x05, 0x01}},
		})
		leaf := makeLeaf(2006, "target.example", interCert, interKey, sanExt(derTLV(0x82, []byte("target.example"))))
		verify("bc_cve", "truncated_bc_seq_overflow_CVE_2026_49300", leaf, [][]byte{interDER}, "target.example", false, false, "CVE-2026-49300 MUST reject truncated BC")
	}

	// 4.3 INTEGER 1 instead of BOOLEAN TRUE as cA in basicConstraints (Mbed TLS CVE-2026-49300)
	{
		interCert, interKey, interDER := makeCustomExtInter(2007, "Int1 BC CA", []pkix.Extension{
			kuCertSignExt,
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: derSeq([]byte{0x02, 0x01, 0x01})},
		})
		leaf := makeLeaf(2008, "target.example", interCert, interKey, sanExt(derTLV(0x82, []byte("target.example"))))
		verify("bc_cve", "integer_1_as_ca_CVE_2026_49300", leaf, [][]byte{interDER}, "target.example", false, false, "CVE-2026-49300 MUST reject INTEGER 1 as cA")
	}

	// 4.4 Oct 2026 CERT/CC NameConstraints wave
	// Helper for valid constrained intermediate CA
	makeNCInter := func(serial int64, cn string, perm, excl [][]byte) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		return makeCustomExtInter(serial, cn, []pkix.Extension{
			kuCertSignExt,
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: bcTrueVal},
			makeNameConstraintsExt(perm, excl),
		})
	}

	// 4.4a Mixed-case DNS against excludedSubtrees (CVE-2026-3833 / CVE-2026-33810)
	{
		ic, ik, ider := makeNCInter(2101, "NC Excl Lower", nil, [][]byte{derTLV(0x82, []byte("allowed.example"))})
		leafUpper := makeLeaf(2102, "ALLOWED.EXAMPLE", ic, ik, sanExt(derTLV(0x82, []byte("ALLOWED.EXAMPLE"))))
		verify("nc_2026", "mixed_case_dns_upper_vs_excl_lower", leafUpper, [][]byte{ider}, "allowed.example", false, false, "CVE-2026-3833 MUST reject ALLOWED.EXAMPLE under excluded allowed.example")

		ic2, ik2, ider2 := makeNCInter(2103, "NC Excl Upper", nil, [][]byte{derTLV(0x82, []byte("ALLOWED.EXAMPLE"))})
		leafLower := makeLeaf(2104, "sub.allowed.example", ic2, ik2, sanExt(derTLV(0x82, []byte("sub.allowed.example"))))
		verify("nc_2026", "mixed_case_dns_lower_vs_excl_upper", leafLower, [][]byte{ider2}, "sub.allowed.example", false, false, "CVE-2026-3833 MUST reject sub.allowed.example under excluded ALLOWED.EXAMPLE")

		ic3, ik3, ider3 := makeNCInter(2105, "NC Perm Lower", [][]byte{derTLV(0x82, []byte("allowed.example"))}, nil)
		leafPermUpper := makeLeaf(2106, "SUB.ALLOWED.EXAMPLE", ic3, ik3, sanExt(derTLV(0x82, []byte("SUB.ALLOWED.EXAMPLE"))))
		verify("nc_2026", "mixed_case_dns_upper_vs_perm_lower", leafPermUpper, [][]byte{ider3}, "sub.allowed.example", true, false, "RFC 5280 DNS NameConstraints case-insensitive match")
	}

	// 4.4b Mixed-case rfc822Name against excludedSubtrees (CVE-2026-3833 / 33810) + positive control
	{
		ic, ik, ider := makeNCInter(2110, "NC Excl Email Lower", nil, [][]byte{derTLV(0x81, []byte("evil.example"))})
		leafEmail := makeLeaf(2111, "ok.example", ic, ik, sanExt(derTLV(0x82, []byte("ok.example")), derTLV(0x81, []byte("User@EVIL.EXAMPLE"))))
		verify("nc_2026", "mixed_case_rfc822_upper_vs_excl_lower", leafEmail, [][]byte{ider}, "ok.example", false, false, "CVE-2026-3833 MUST reject User@EVIL.EXAMPLE under excluded rfc822 evil.example")

		leafEmailOK := makeLeaf(2114, "ok.example", ic, ik, sanExt(derTLV(0x82, []byte("ok.example")), derTLV(0x81, []byte("user@good.example"))))
		verify("nc_2026", "rfc822_good_control", leafEmailOK, [][]byte{ider}, "ok.example", true, false, "control: user@good.example under excluded evil.example MUST pass")

		ic2, ik2, ider2 := makeNCInter(2112, "NC Excl Email Upper", nil, [][]byte{derTLV(0x81, []byte("EVIL.EXAMPLE"))})
		leafEmail2 := makeLeaf(2113, "ok.example", ic2, ik2, sanExt(derTLV(0x82, []byte("ok.example")), derTLV(0x81, []byte("user@evil.example"))))
		verify("nc_2026", "mixed_case_rfc822_lower_vs_excl_upper", leafEmail2, [][]byte{ider2}, "ok.example", false, false, "CVE-2026-3833 MUST reject user@evil.example under excluded rfc822 EVIL.EXAMPLE")
	}

	// 4.4c Wildcard *.evil.example & trailing dot evil.example. against excludedSubtrees (BoringSSL VU#410595)
	{
		ic, ik, ider := makeNCInter(2120, "NC Excl Evil", nil, [][]byte{derTLV(0x82, []byte("evil.example"))})
		leafWild := makeLeaf(2121, "*.evil.example", ic, ik, sanExt(derTLV(0x82, []byte("*.evil.example"))))
		verify("nc_2026", "wildcard_star_evil_vs_excl_evil", leafWild, [][]byte{ider}, "a.evil.example", false, false, "VU#410595 MUST reject *.evil.example under excluded evil.example")

		leafDot := makeLeaf(2122, "evil.example.", ic, ik, sanExt(derTLV(0x82, []byte("evil.example."))))
		verify("nc_2026", "trailing_dot_evil_vs_excl_evil_peer_dash", leafDot, [][]byte{ider}, "-", false, false, "VU#410595 MUST reject evil.example. under excluded evil.example")
		verify("nc_2026", "trailing_dot_evil_vs_excl_evil_peer_dot", leafDot, [][]byte{ider}, "evil.example.", false, false, "VU#410595 MUST reject evil.example. with peer=evil.example.")
	}

	// 4.4d Leaf with Subject CN=evil.example and ONLY iPAddress or registeredID SAN (wolfSSL CVE-2026-89134)
	{
		ic, ik, ider := makeNCInter(2130, "NC Excl Evil CN", nil, [][]byte{derTLV(0x82, []byte("evil.example"))})
		leafIPOnly := makeLeaf(2131, "evil.example", ic, ik, sanExt(derTLV(0x87, []byte{127, 0, 0, 1})))
		verify("nc_2026", "cn_evil_with_only_ip_san_peer_ip", leafIPOnly, [][]byte{ider}, "127.0.0.1", false, true, "CVE-2026-89134 observe CN=evil.example + IP-only SAN under excluded evil.example (RFC 5280 vs CN fallback)")
		verify("nc_2026", "cn_evil_with_only_ip_san_peer_dns", leafIPOnly, [][]byte{ider}, "evil.example", false, false, "MUST reject CN fallback when SAN present")

		regIDOID, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 3, 4})
		// registeredID is [8] IMPLICIT OBJECT IDENTIFIER (tag 0x88 + OID content bytes!)
		leafRegIDOnly := makeLeaf(2132, "evil.example", ic, ik, sanExt(derTLV(0x88, regIDOID[2:])))
		verify("nc_2026", "cn_evil_with_only_regid_san_peer_dash", leafRegIDOnly, [][]byte{ider}, "-", false, true, "CVE-2026-89134 observe CN=evil.example + registeredID-only SAN under excluded evil.example")
	}

	// 4.4e URI SAN with @ after /, ?, # and backslash (OpenSSL PR #30319) + positive controls
	{
		icExcl, ikExcl, iderExcl := makeNCInter(2140, "NC Excl URI Allowed", nil, [][]byte{derTLV(0x86, []byte("allowed.example"))})
		leafURIOK := makeLeaf(2147, "ok.example", icExcl, ikExcl, sanExt(derTLV(0x82, []byte("ok.example")), derTLV(0x86, []byte("https://other.example/safe"))))
		verify("nc_2026", "uri_excl_good_control", leafURIOK, [][]byte{iderExcl}, "ok.example", true, false, "control: https://other.example/safe under excluded allowed.example MUST pass")

		leafURISlash := makeLeaf(2141, "ok.example", icExcl, ikExcl, sanExt(derTLV(0x82, []byte("ok.example")), derTLV(0x86, []byte("https://allowed.example/@evil.example"))))
		verify("nc_2026", "uri_at_after_slash_excl_allowed", leafURISlash, [][]byte{iderExcl}, "ok.example", false, false, "OpenSSL PR#30319 MUST extract host=allowed.example & reject")

		leafURIQuery := makeLeaf(2142, "ok.example", icExcl, ikExcl, sanExt(derTLV(0x82, []byte("ok.example")), derTLV(0x86, []byte("https://allowed.example/?q=@evil.example"))))
		verify("nc_2026", "uri_at_after_query_excl_allowed", leafURIQuery, [][]byte{iderExcl}, "ok.example", false, false, "OpenSSL PR#30319 MUST extract host=allowed.example & reject")

		leafURIFrag := makeLeaf(2143, "ok.example", icExcl, ikExcl, sanExt(derTLV(0x82, []byte("ok.example")), derTLV(0x86, []byte("https://allowed.example/#@evil.example"))))
		verify("nc_2026", "uri_at_after_frag_excl_allowed", leafURIFrag, [][]byte{iderExcl}, "ok.example", false, false, "OpenSSL PR#30319 MUST extract host=allowed.example & reject")

		icPerm, ikPerm, iderPerm := makeNCInter(2144, "NC Perm URI Allowed", [][]byte{derTLV(0x86, []byte("allowed.example"))}, nil)
		leafURIPermOK := makeLeaf(2148, "ok.example", icPerm, ikPerm, sanExt(derTLV(0x82, []byte("ok.example")), derTLV(0x86, []byte("https://allowed.example/ok"))))
		verify("nc_2026", "uri_perm_good_control", leafURIPermOK, [][]byte{iderPerm}, "ok.example", true, false, "control: https://allowed.example/ok under permitted allowed.example MUST pass")

		leafURIUserInfo := makeLeaf(2145, "ok.example", icPerm, ikPerm, sanExt(derTLV(0x82, []byte("ok.example")), derTLV(0x86, []byte("https://evil.example@allowed.example/path"))))
		verify("nc_2026", "uri_userinfo_evil_at_allowed_perm_allowed", leafURIUserInfo, [][]byte{iderPerm}, "ok.example", true, true, "observe https://evil.example@allowed.example under permitted allowed.example (host is allowed.example or rejected for userinfo)")

		leafURIBackslash := makeLeaf(2146, "ok.example", icPerm, ikPerm, sanExt(derTLV(0x82, []byte("ok.example")), derTLV(0x86, []byte(`https://evil.example\.allowed.example/x`))))
		verify("nc_2026", "uri_backslash_authority_perm_allowed", leafURIBackslash, [][]byte{iderPerm}, "ok.example", false, false, "MUST reject URI SAN with backslash authority confusion")
	}

	// 4.4f 3-cert chain: Root -> Constrained CA1 -> Unconstrained CA2 -> Leaf (wolfSSL CVE-2026-89133)
	// Test BOTH ".allowed.example" (leading dot) AND "allowed.example" (RFC 5280 canonical) + unconstrained 3-cert baseline!
	for _, tc3 := range []struct {
		label      string
		constraint string
	}{
		{"leading_dot", ".allowed.example"},
		{"no_leading_dot", "allowed.example"},
	} {
		ca1Cert, ca1Key, ca1DER := makeNCInter(2150, "Constrained CA1 "+tc3.label, [][]byte{derTLV(0x82, []byte(tc3.constraint))}, nil)
		ca2Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ca2Tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2151), Subject: pkix.Name{CommonName: "Unconstrained CA2 " + tc3.label},
			NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
			KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
		}
		ca2DER, _ := x509.CreateCertificate(rand.Reader, ca2Tmpl, ca1Cert, &ca2Key.PublicKey, ca1Key)
		ca2Cert, _ := x509.ParseCertificate(ca2DER)

		leafEvil := makeLeaf(2152, "evil.example", ca2Cert, ca2Key, sanExt(derTLV(0x82, []byte("evil.example"))))
		leafGood := makeLeaf(2153, "sub.allowed.example", ca2Cert, ca2Key, sanExt(derTLV(0x82, []byte("sub.allowed.example"))))
		verify("nc_2026", "3cert_"+tc3.label+"_evil_CVE_2026_89133", leafEvil, [][]byte{ca2DER, ca1DER}, "evil.example", false, false, "CVE-2026-89133 MUST NOT reset CA1 constraints at CA2")
		verify("nc_2026", "3cert_"+tc3.label+"_good_control", leafGood, [][]byte{ca2DER, ca1DER}, "sub.allowed.example", true, tc3.label == "leading_dot", "control: sub.allowed.example (leading dot strictly forbidden by RFC 5280 §4.2.1.10)")
	}

	// 4.5 Explicit ECC curve parameters in SubjectPublicKeyInfo (CurveBall CVE-2020-0601)
	{
		// Build minimal explicit ECParameters SEQUENCE { INTEGER 1, fieldID, curve, base, order, cofactor }
		// Replace the namedCurve OID (06 08 2a8648ce3d030107) inside leaf TBS SPKI with explicit ECParameters SEQUENCE!
		namedP256OID := mustHex("06082a8648ce3d030107")
		primeFieldOID := mustHex("06072a8648ce3d0101") // 1.2.840.10045.1.1 prime-field
		p256P, _ := new(big.Int).SetString("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
		p256A := new(big.Int).Sub(p256P, big.NewInt(3))
		p256B, _ := new(big.Int).SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
		gBytes := make([]byte, 65)
		gBytes[0] = 0x04
		elliptic.P256().Params().Gx.FillBytes(gBytes[1:33])
		elliptic.P256().Params().Gy.FillBytes(gBytes[33:65])
		bigDERInt := func(v *big.Int) []byte {
			b := v.Bytes()
			if len(b) > 0 && b[0]&0x80 != 0 {
				b = append([]byte{0x00}, b...)
			}
			return derTLV(0x02, b)
		}
		fieldID := derSeq(append(primeFieldOID, bigDERInt(p256P)...))
		curveSeq := derSeq(append(derTLV(0x04, p256A.Bytes()), derTLV(0x04, p256B.Bytes())...))
		explicitParams := derSeq(bytes.Join([][]byte{
			derInt(1), fieldID, curveSeq, derTLV(0x04, gBytes), bigDERInt(p256OrderN), derInt(1),
		}, nil))

		ecPubBytes := make([]byte, 65)
		ecPubBytes[0] = 0x04
		pki.ecKey.X.FillBytes(ecPubBytes[1:33])
		pki.ecKey.Y.FillBytes(ecPubBytes[33:65])
		ecPubKeyOID := mustHex("06072a8648ce3d0201") // 1.2.840.10045.2.1 id-ecPublicKey
		explicitSPKI := derSeq(append(derSeq(append(ecPubKeyOID, explicitParams...)), derTLV(0x03, append([]byte{0x00}, ecPubBytes...))...))

		// Replace SPKI inside pki.ecDER TBS and re-sign with CA
		tbsEC, _, _, _ := extractCertParts(pki.ecDER)
		var tbsSeq asn1.RawValue
		_, _ = asn1.Unmarshal(tbsEC, &tbsSeq)
		rest := tbsSeq.Bytes
		var newTBSBody []byte
		replaced := false
		for len(rest) > 0 {
			var elem asn1.RawValue
			var uerr error
			rest, uerr = asn1.Unmarshal(rest, &elem)
			if uerr != nil {
				break
			}
			if !replaced && bytes.Contains(elem.FullBytes, namedP256OID) {
				newTBSBody = append(newTBSBody, explicitSPKI...)
				replaced = true
			} else {
				newTBSBody = append(newTBSBody, elem.FullBytes...)
			}
		}
		curveballDER := signDERCertWithCA(derSeq(newTBSBody), oidEcdsaSha256, pki.caKey, 0, nil, "")
		verify("curveball", "explicit_ecc_params_spki_CVE_2020_0601", curveballDER, nil, "localhost", false, false,
			fmt.Sprintf("CVE-2020-0601 MUST reject explicit ECParameters (replaced=%v)", replaced))
	}
}

// =========================================================================
// 5. TLS 1.3 2025-2026 LIVE WIRE CVES (tls_server.exe & bogo_shim.exe)
// =========================================================================

func runRound2TLSWire(rec *testRecorder, tlsServerExe, bogoShimExe string, pki *testPKI) {
	fmt.Println("\n================ ROUND 2.5: TLS 1.3 2025-2026 LIVE WIRE CVES ================")

	// 5.1 Server-side fault -> bogo_shim.exe:
	//   a) Coalesced ServerHello + plaintext EncryptedExtensions in ONE TLSPlaintext record (CVE-2025-61730 / CVE-2026-123613)
	//   b) Unsolicited server_certificate_type=RawPublicKey(2) in EncryptedExtensions (CVE-2026-89136 / CVE-2024-12797)
	runRound2BoGoClientFaults(rec, bogoShimExe, pki)

	// 5.2 Live tls_server.exe (BOTH default mode AND --sni-map PureGoose mode):
	//   a) Coalesced ClientHello + trailing Finished in ONE TLSPlaintext record
	//   b) Coalesced encrypted Finished + trailing KeyUpdate / ClientHello in ONE handshake record
	//   c) KeyUpdate + 0-byte AppData DoS bypass (CVE-2026-32283): 40 rounds
	//   d) UserCanceled warning alert flood: 10 + 35 consecutive records
	modes := []struct {
		name string
		args []string
		env  []string
		sni  string
	}{
		{"r2_tls_default", []string{"--port", "0"}, nil, "goose-wing.local"},
		{"r2_tls_snimap", []string{"--port", "0", "--sni-map", fmt.Sprintf("test.local=%s|%s", pki.edCertPath, pki.edKeyPath)}, []string{"WING_PORT=0"}, "test.local"},
	}

	for _, m := range modes {
		srv, err := startManagedServer(m.name, tlsServerExe, m.args, m.env, tcpShutdown)
		if err != nil {
			rec.add(m.name, "setup", "start_server", "FAIL", "start", err.Error(), "")
			continue
		}
		addr := fmt.Sprintf("127.0.0.1:%d", srv.port)
		fmt.Printf("\n--- %s (%s, sni=%s) ---\n", m.name, addr, m.sni)

		// 5.2a Coalesced ClientHello + trailing Finished in ONE TLSPlaintext record
		{
			k, _ := ecdh.X25519().GenerateKey(rand.Reader)
			ch := buildClientHelloMsg(clientHelloOpts{
				legacyVer: 0x0303, ciphers: []uint16{CipherAES128GCM},
				exts: []rawExt{
					extSNI(m.sni), extSupportedVersionsClient(0x0304),
					extSupportedGroups(GroupX25519), extSigAlgs(SigEd25519, SigECDSAP256SHA256),
					extALPN("http/1.1"), extKeyShareClient(keyShareEntry{group: GroupX25519, key: k.PublicKey().Bytes()}),
				},
			})
			dummyFin := makeHandshakeMsg(HSFinished, make([]byte, 32))
			out := sendRawAndClassify(addr, makeRecord(RecHandshake, 0x0301, append(ch, dummyFin...)))
			st := "PASS"
			if !isRejectedOutcome(out) {
				st = "FAIL"
			}
			rec.add(m.name, "rec_boundary", "coalesced_ch_plus_finished_one_record", st,
				"RFC 8446 Section 5.1 / CVE-2025-61730 reject", out.detail, hex.EncodeToString(out.raw[:minInt(len(out.raw), 24)]))
		}

		// 5.2b Coalesced encrypted Finished + trailing KeyUpdate in ONE handshake record (crosses hs->app key boundary!)
		for _, secondMsg := range []struct {
			label string
			msg   []byte
		}{
			{"coalesced_fin_plus_keyupdate_one_hs_record", makeHandshakeMsg(HSKeyUpdate, []byte{0x00})},
			{"coalesced_fin_plus_ch_one_hs_record", makeHandshakeMsg(HSClientHello, make([]byte, 40))},
		} {
			cfg := defaultHandshakeConfig(m.sni)
			cfg.stopBeforeFin = true
			sess, herr := doTLS13Handshake(addr, cfg)
			if herr != nil {
				rec.add(m.name, "rec_boundary", secondMsg.label, "FAIL", "reach post-SH", herr.Error(), "")
				continue
			}
			coalesced := append(append([]byte{}, sess.clientFinMsg...), secondMsg.msg...)
			_, _ = sess.conn.Write(sess.hsTx.sealRecord(RecHandshake, coalesced))
			out := classifyResponse(sess.conn, sess.hsRx, sess.appRx, 1000*time.Millisecond)
			if out.kind == "TIMEOUT" {
				// Probe with appdata to see if server silently accepted the handshake!
				_ = sess.sendAppData([]byte("GET /secure-hello HTTP/1.1\r\nHost: "+m.sni+"\r\nConnection: close\r\n\r\n"), false)
				out2 := classifyResponse(sess.conn, sess.hsRx, sess.appRx, 1000*time.Millisecond)
				out.detail += " -> after_appdata: " + out2.detail
				out.kind = out2.kind
			}
			sess.close()
			st := "PASS"
			if !isRejectedOutcome(out) {
				st = "FAIL"
			}
			rec.add(m.name, "rec_boundary", secondMsg.label, st,
				"RFC 8446 Section 5.1 reject HS spanning key change", out.detail, "")
		}

		// 5.2c KeyUpdate + 0-byte AppData DoS bypass (CVE-2026-32283): 40 rounds with req_update=1 AND req_update=0
		for _, reqUpd := range []byte{1, 0} {
			cfg := defaultHandshakeConfig(m.sni)
			sess, herr := doTLS13Handshake(addr, cfg)
			label := fmt.Sprintf("keyupdate_zero_appdata_40x_req%d_CVE_2026_32283", reqUpd)
			if herr != nil {
				rec.add(m.name, "dos_cap", label, "FAIL", "handshake", herr.Error(), "")
				continue
			}
			completedRounds := 0
			stopReason := "all_40_accepted"
			for round := 1; round <= 40; round++ {
				kuRec := sess.appTx.sealRecord(RecHandshake, makeHandshakeMsg(HSKeyUpdate, []byte{reqUpd}))
				if _, werr := sess.conn.Write(kuRec); werr != nil {
					stopReason = fmt.Sprintf("write_ku_err@%d: %v", round, werr)
					break
				}
				sess.appTx, _ = sess.appTx.ratchet()

				// Drain any server KeyUpdate reply or fatal alert
				if reqUpd == 1 {
					recIn, rerr := readTLSRecord(sess.conn, 300*time.Millisecond)
					if rerr != nil {
						if ne, ok := rerr.(net.Error); !ok || !ne.Timeout() {
							stopReason = fmt.Sprintf("read_after_ku@%d: %v", round, rerr)
							break
						}
					} else {
						it, pt, oerr := sess.appRx.openRecord(recIn)
						if oerr != nil {
							stopReason = fmt.Sprintf("open_after_ku@%d: %v", round, oerr)
							break
						}
						if it == RecAlert && len(pt) >= 2 {
							stopReason = fmt.Sprintf("alert@%d: level=%d desc=%s", round, pt[0], alertName(pt[1]))
							break
						}
						if it == RecHandshake && len(pt) >= 5 && pt[0] == HSKeyUpdate {
							sess.appRx, _ = sess.appRx.ratchet()
						}
					}
				} else {
					time.Sleep(15 * time.Millisecond)
				}

				// Send 0-byte encrypted AppData (CVE-2026-32283 reset trick!)
				zeroApp := sess.appTx.sealRecord(RecAppData, []byte{})
				if _, werr := sess.conn.Write(zeroApp); werr != nil {
					stopReason = fmt.Sprintf("write_0app_err@%d: %v", round, werr)
					break
				}
				time.Sleep(15 * time.Millisecond)
				completedRounds = round
			}
			// If all 40 writes finished, test whether connection is still alive by sending a real GET!
			appAfter40 := false
			if completedRounds == 40 {
				_ = sess.sendAppData([]byte("GET /secure-hello HTTP/1.1\r\nHost: "+m.sni+"\r\nConnection: close\r\n\r\n"), false)
				resp, rerr := sess.readAppData(1500 * time.Millisecond)
				if rerr == nil && len(resp) > 0 {
					appAfter40 = true
					stopReason = fmt.Sprintf("ALL_40_ACCEPTED_AND_SERVED_APP(%dB)", len(resp))
				} else {
					stopReason = fmt.Sprintf("after_40_app_err=%v", rerr)
				}
			}
			sess.close()
			st := "PASS"
			if appAfter40 {
				st = "FAIL"
			}
			rec.add(m.name, "dos_cap", label, st, "cap/reject KeyUpdate+0B-AppData flood before 40 rounds",
				fmt.Sprintf("rounds=%d detail=%s", completedRounds, stopReason), "")
		}

		// 5.2d UserCanceled warning alert flood (10 rounds, then up to 35 rounds + real HTTP GET)
		{
			cfg := defaultHandshakeConfig(m.sni)
			sess, herr := doTLS13Handshake(addr, cfg)
			if herr != nil {
				rec.add(m.name, "dos_cap", "user_canceled_warning_flood_10_to_35", "FAIL", "handshake", herr.Error(), "")
			} else {
				sentOK := 0
				stopReason := ""
				for i := 1; i <= 35; i++ {
					// Alert(warning=1, user_canceled=90)
					alRec := sess.appTx.sealRecord(RecAlert, []byte{0x01, 90})
					if _, werr := sess.conn.Write(alRec); werr != nil {
						stopReason = fmt.Sprintf("write_err@%d: %v", i, werr)
						break
					}
					// Check immediately (short 40ms poll) if server sent a fatal alert or closed
					recIn, rerr := readTLSRecord(sess.conn, 40*time.Millisecond)
					if rerr == nil {
						if recIn.typ == RecAlert && len(recIn.payload) >= 2 {
							stopReason = fmt.Sprintf("plain_alert@%d: %s", i, alertName(recIn.payload[1]))
							break
						}
						if it, pt, oerr := sess.appRx.openRecord(recIn); oerr == nil && it == RecAlert && len(pt) >= 2 {
							stopReason = fmt.Sprintf("enc_alert@%d: level=%d desc=%s", i, pt[0], alertName(pt[1]))
							break
						}
					} else if ne, ok := rerr.(net.Error); !ok || !ne.Timeout() {
						stopReason = fmt.Sprintf("closed@%d: %v", i, rerr)
						break
					}
					sentOK = i
				}
				appAfter := false
				if stopReason == "" {
					_ = sess.sendAppData([]byte("GET /secure-hello HTTP/1.1\r\nHost: "+m.sni+"\r\nConnection: close\r\n\r\n"), false)
					resp, rerr := sess.readAppData(1200 * time.Millisecond)
					if rerr == nil && len(resp) > 0 {
						appAfter = true
						stopReason = fmt.Sprintf("ALL_35_ACCEPTED_AND_SERVED_APP(%dB)", len(resp))
					} else {
						stopReason = fmt.Sprintf("after_35_app_err=%v", rerr)
					}
				}
				sess.close()
				st := "PASS"
				if appAfter {
					st = "FAIL"
				}
				rec.add(m.name, "dos_cap", "user_canceled_warning_flood_10_to_35", st,
					"cap/reject warning alert flood", fmt.Sprintf("sent=%d detail=%s", sentOK, stopReason), "")
			}
		}

		// Health check after all Round 2 tests on this server
		if herr := probeServerHealth(addr, m.sni, m.name == "r2_tls_snimap"); herr != nil {
			rec.add(m.name, "health", "post_round2_health", "FAIL", "server healthy", herr.Error(), "")
		} else {
			rec.add(m.name, "health", "post_round2_health", "PASS", "server healthy", "ok", "")
		}
		srv.stop()
	}
}

func runRound2BoGoClientFaults(rec *testRecorder, bogoShimExe string, pki *testPKI) {
	type customSrvTest struct {
		name string
		mode string // "coalesce_sh_ee", "unsolicited_rpk_ext", "unsolicited_rpk_ext_and_raw_spki"
		exp  string
	}
	cases := []customSrvTest{
		{"coalesced_sh_plus_plain_ee_one_record_CVE_2025_61730", "coalesce_sh_ee", "RFC 8446 Section 5.1 / CVE-2025-61730 reject"},
		{"unsolicited_server_cert_type_rpk_CVE_2026_89136", "unsolicited_rpk_ext", "RFC 8446 Section 4.2 / CVE-2026-89136 reject ext 0x0014=[0x02]"},
		{"unsolicited_server_cert_type_rpk_with_spki_CVE_2024_12797", "unsolicited_rpk_ext_and_raw_spki", "CVE-2024-12797 reject RPK ext + raw SPKI Certificate"},
		{"unsolicited_early_data_in_ee_H2_C09", "unsolicited_early_data_ee", "RFC 8446 Section 4.2 reject unsolicited early_data(42) in EE"},
		{"unsolicited_ech_in_ee_H2_C09", "unsolicited_ech_ee", "RFC 8446 Section 4.2 reject unsolicited ech(0xfe0d) in EE"},
		{"unsolicited_psk_in_sh_H2_C09", "unsolicited_psk_sh", "RFC 8446 Section 4.2 reject unsolicited pre_shared_key(41) in SH"},
		{"duplicate_alpn_in_ee", "dup_ee_alpn", "RFC 8446 Section 4.2 reject duplicate ALPN extension in EE"},
		{"excessive_nst_lifetime_over_7d_H2_C11", "excessive_nst_lifetime", "RFC 8446 Section 4.6.1 reject NST lifetime > 604800s"},
	}

	for idx, tc := range cases {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		port := ln.Addr().(*net.TCPAddr).Port
		done := make(chan string, 1)

		go func(mode string) {
			defer ln.Close()
			_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
			conn, aerr := ln.Accept()
			if aerr != nil {
				done <- "accept_err:" + aerr.Error()
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
			var idb [8]byte
			if _, rerr := io.ReadFull(conn, idb[:]); rerr != nil {
				done <- "id_err"
				return
			}
			rCH, rerr := readTLSRecord(conn, 2*time.Second)
			if rerr != nil {
				done <- "ch_err"
				return
			}
			ch, perr := parseClientHello(rCH.payload)
			if perr != nil {
				done <- "parse_ch_err"
				return
			}
			spec, _ := getCipherSpec(CipherAES128GCM)
			srvKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
			ksBody := binary.BigEndian.AppendUint16(nil, GroupX25519)
			ksBody = binary.BigEndian.AppendUint16(ksBody, 32)
			ksBody = append(ksBody, srvKey.PublicKey().Bytes()...)
			srvRnd := make([]byte, 32)
			_, _ = rand.Read(srvRnd)
			shExts := []rawExt{
				{typ: ExtSupportedVersions, body: []byte{0x03, 0x04}},
				{typ: ExtKeyShare, body: ksBody},
			}
			if mode == "unsolicited_psk_sh" {
				shExts = append(shExts, rawExt{typ: 0x0029, body: []byte{0x00, 0x00}})
			}
			shMsg := buildServerHelloMsg(0x0303, srvRnd, ch.sessionID, CipherAES128GCM, 0x00, shExts)

			peerPub, _ := ecdh.X25519().NewPublicKey(ch.keyShares[GroupX25519])
			shared, _ := srvKey.ECDH(peerPub)
			zeros := make([]byte, spec.hLen)
			earlySec := hkdfExtract(spec.hashFn, zeros, zeros)
			hsSec := hkdfExtract(spec.hashFn, deriveSecret(spec, earlySec, "derived", emptyHash(spec)), shared)
			thSH := hashMessages(spec, ch.raw, shMsg)
			cHsSec := deriveSecret(spec, hsSec, "c hs traffic", thSH)
			sHsSec := deriveSecret(spec, hsSec, "s hs traffic", thSH)
			hsTx, _ := newTrafficState(spec, sHsSec)
			hsRx, _ := newTrafficState(spec, cHsSec)

			if mode == "unsolicited_psk_sh" {
				_, _ = conn.Write(makeRecord(RecHandshake, 0x0303, shMsg))
				out := classifyResponse(conn, hsRx, nil, 1500*time.Millisecond)
				done <- "client_resp:" + out.detail
				return
			}

			if mode == "coalesce_sh_ee" {
				eePlain := makeHandshakeMsg(HSEncryptedExtensions, []byte{0x00, 0x00})
				_, _ = conn.Write(makeRecord(RecHandshake, 0x0303, append(shMsg, eePlain...)))
				out := classifyResponse(conn, hsRx, nil, 1500*time.Millisecond)
				done <- "client_resp:" + out.detail
				return
			}

			_, _ = conn.Write(makeRecord(RecHandshake, 0x0303, shMsg))
			var eeExts []byte
			switch mode {
			case "unsolicited_early_data_ee":
				eeExts = []byte{0x00, 0x2a, 0x00, 0x00}
			case "unsolicited_ech_ee":
				eeExts = []byte{0xfe, 0x0d, 0x00, 0x02, 0x00, 0x00}
			case "dup_ee_alpn":
				eeExts = []byte{
					0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2',
					0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2',
				}
			default:
				// Unsolicited server_certificate_type (0x0014) = RawPublicKey (2) in EncryptedExtensions
				eeExts = []byte{0x00, 0x14, 0x00, 0x01, 0x02}
			}
			if mode == "excessive_nst_lifetime" {
				eeExts = nil
			}
			eeBody := append(binary.BigEndian.AppendUint16(nil, uint16(len(eeExts))), eeExts...)
			eeMsg := makeHandshakeMsg(HSEncryptedExtensions, eeBody)

			var certChain [][]byte
			if mode == "unsolicited_rpk_ext_and_raw_spki" {
				spkiDER, _ := x509.MarshalPKIXPublicKey(&pki.ecKey.PublicKey)
				certChain = [][]byte{spkiDER}
			} else {
				certChain = [][]byte{pki.ecDER, pki.caDER}
			}
			certMsg := buildCertHandshakeMsg(certChain)
			transcript := [][]byte{ch.raw, shMsg, eeMsg, certMsg}
			thCert := hashMessages(spec, transcript...)
			var content []byte
			content = append(content, bytes.Repeat([]byte{0x20}, 64)...)
			content = append(content, []byte("TLS 1.3, server CertificateVerify")...)
			content = append(content, 0x00)
			content = append(content, thCert...)
			d := sha256.Sum256(content)
			sig, _ := ecdsa.SignASN1(rand.Reader, pki.ecKey, d[:])
			cvBody := binary.BigEndian.AppendUint16(nil, SigECDSAP256SHA256)
			cvBody = binary.BigEndian.AppendUint16(cvBody, uint16(len(sig)))
			cvBody = append(cvBody, sig...)
			cvMsg := makeHandshakeMsg(HSCertificateVerify, cvBody)
			transcript = append(transcript, cvMsg)
			finMAC := computeFinishedMAC(spec, sHsSec, hashMessages(spec, transcript...))
			finMsg := makeHandshakeMsg(HSFinished, finMAC)

			_, _ = conn.Write(hsTx.sealRecord(RecHandshake, eeMsg))
			_, _ = conn.Write(hsTx.sealRecord(RecHandshake, certMsg))
			_, _ = conn.Write(hsTx.sealRecord(RecHandshake, cvMsg))
			_, _ = conn.Write(hsTx.sealRecord(RecHandshake, finMsg))
			if mode == "excessive_nst_lifetime" {
				transcript = append(transcript, finMsg)
				thFin := hashMessages(spec, transcript...)
				derivedHS := deriveSecret(spec, hsSec, "derived", emptyHash(spec))
				masterSec := hkdfExtract(spec.hashFn, derivedHS, zeros)
				sApSec := deriveSecret(spec, masterSec, "s ap traffic", thFin)
				cApSec := deriveSecret(spec, masterSec, "c ap traffic", thFin)
				apTx, _ := newTrafficState(spec, sApSec)
				apRx, _ := newTrafficState(spec, cApSec)
				var nst []byte
				nst = binary.BigEndian.AppendUint32(nst, 604801) // > 7 days (RFC 8446 Section 4.6.1)
				nst = binary.BigEndian.AppendUint32(nst, 0x11223344)
				nst = append(nst, 0x01, 0xaa)                   // nonce
				nst = append(nst, 0x00, 0x04, 'T', 'K', 'T', '1') // ticket
				nst = append(nst, 0x00, 0x00)                   // extensions
				nstMsg := makeHandshakeMsg(HSNewSessionTicket, nst)
				_, _ = conn.Write(apTx.sealRecord(RecHandshake, nstMsg))
				out := classifyResponse(conn, apRx, nil, 1500*time.Millisecond)
				done <- "client_resp:" + out.detail
				return
			}
			out := classifyResponse(conn, hsRx, nil, 1500*time.Millisecond)
			done <- "client_resp:" + out.detail
		}(tc.mode)

		rc, shimOut := runBoGoShim(bogoShimExe, port, 7000+idx, "-host-name", "localhost", "-trust-cert", pki.caPEMPath, "-verify-peer")
		srvNote := ""
		select {
		case srvNote = <-done:
		case <-time.After(1500 * time.Millisecond):
			srvNote = "srv_timeout"
		}
		_ = ln.Close()
		st := "PASS"
		if rc == 0 {
			st = "FAIL"
		}
		rec.add("r2_bogo_client", "tls_cve", tc.name, st, tc.exp, fmt.Sprintf("rc=%d shim=%q srv=%q", rc, truncStr(shimOut, 60), truncStr(srvNote, 80)), "")
	}
}
