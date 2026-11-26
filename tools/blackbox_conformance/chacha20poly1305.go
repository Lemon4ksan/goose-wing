// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

package main

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
)

// Pure-Go RFC 8439 ChaCha20-Poly1305 AEAD implementation using only Go stdlib.

type chacha20Poly1305 struct {
	key [32]byte
}

func newChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("chacha20poly1305: bad key length")
	}
	a := &chacha20Poly1305{}
	copy(a.key[:], key)
	return a, nil
}

func (c *chacha20Poly1305) NonceSize() int { return 12 }
func (c *chacha20Poly1305) Overhead() int  { return 16 }

func quarterRound(s *[16]uint32, a, b, c, d int) {
	s[a] += s[b]
	s[d] = bits.RotateLeft32(s[d]^s[a], 16)
	s[c] += s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], 12)
	s[a] += s[b]
	s[d] = bits.RotateLeft32(s[d]^s[a], 8)
	s[c] += s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], 7)
}

func chacha20Block(key [32]byte, counter uint32, nonce []byte) [64]byte {
	var initState [16]uint32
	initState[0] = 0x61707865
	initState[1] = 0x3320646e
	initState[2] = 0x79622d32
	initState[3] = 0x6b206574
	for i := range 8 {
		initState[4+i] = binary.LittleEndian.Uint32(key[4*i : 4*i+4])
	}
	initState[12] = counter
	initState[13] = binary.LittleEndian.Uint32(nonce[0:4])
	initState[14] = binary.LittleEndian.Uint32(nonce[4:8])
	initState[15] = binary.LittleEndian.Uint32(nonce[8:12])

	s := initState
	for range 10 {
		quarterRound(&s, 0, 4, 8, 12)
		quarterRound(&s, 1, 5, 9, 13)
		quarterRound(&s, 2, 6, 10, 14)
		quarterRound(&s, 3, 7, 11, 15)
		quarterRound(&s, 0, 5, 10, 15)
		quarterRound(&s, 1, 6, 11, 12)
		quarterRound(&s, 2, 7, 8, 13)
		quarterRound(&s, 3, 4, 9, 14)
	}
	var out [64]byte
	for i := range 16 {
		binary.LittleEndian.PutUint32(out[4*i:4*i+4], s[i]+initState[i])
	}
	return out
}

func chacha20XOR(key [32]byte, counter uint32, nonce, in []byte) []byte {
	out := make([]byte, len(in))
	for off := 0; off < len(in); off += 64 {
		blk := chacha20Block(key, counter, nonce)
		counter++
		n := min(len(in)-off, 64)
		for i := range n {
			out[off+i] = in[off+i] ^ blk[i]
		}
	}
	return out
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

func poly1305MAC(msg []byte, otk [32]byte) [16]byte {
	var rBytes [16]byte
	copy(rBytes[:], otk[0:16])
	// Clamp r per RFC 8439 Section 2.5
	rBytes[3] &= 15
	rBytes[7] &= 15
	rBytes[11] &= 15
	rBytes[15] &= 15
	rBytes[4] &= 252
	rBytes[8] &= 252
	rBytes[12] &= 252

	r := new(big.Int).SetBytes(reverseBytes(rBytes[:]))
	s := new(big.Int).SetBytes(reverseBytes(otk[16:32]))
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 130), big.NewInt(5))
	acc := big.NewInt(0)

	for off := 0; off < len(msg); off += 16 {
		end := min(off+16, len(msg))
		chunk := make([]byte, end-off+1)
		copy(chunk, msg[off:end])
		chunk[len(chunk)-1] = 0x01
		n := new(big.Int).SetBytes(reverseBytes(chunk))
		acc.Add(acc, n)
		acc.Mul(acc, r)
		acc.Mod(acc, p)
	}
	acc.Add(acc, s)
	mod128 := new(big.Int).Lsh(big.NewInt(1), 128)
	acc.Mod(acc, mod128)
	be := acc.Bytes()
	var tag [16]byte
	for i := 0; i < len(be) && i < 16; i++ {
		tag[i] = be[len(be)-1-i]
	}
	return tag
}

func buildPoly1305Input(aad, ct []byte) []byte {
	pad16 := func(n int) int {
		if n%16 == 0 {
			return 0
		}
		return 16 - (n % 16)
	}
	aadPad := pad16(len(aad))
	ctPad := pad16(len(ct))
	buf := make([]byte, 0, len(aad)+aadPad+len(ct)+ctPad+16)
	buf = append(buf, aad...)
	buf = append(buf, make([]byte, aadPad)...)
	buf = append(buf, ct...)
	buf = append(buf, make([]byte, ctPad)...)
	var lens [16]byte
	binary.LittleEndian.PutUint64(lens[0:8], uint64(len(aad)))
	binary.LittleEndian.PutUint64(lens[8:16], uint64(len(ct)))
	buf = append(buf, lens[:]...)
	return buf
}

func (c *chacha20Poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != 12 {
		panic("chacha20poly1305: bad nonce length")
	}
	blk0 := chacha20Block(c.key, 0, nonce)
	var otk [32]byte
	copy(otk[:], blk0[:32])
	ct := chacha20XOR(c.key, 1, nonce, plaintext)
	macIn := buildPoly1305Input(additionalData, ct)
	tag := poly1305MAC(macIn, otk)
	dst = append(dst, ct...)
	dst = append(dst, tag[:]...)
	return dst
}

func (c *chacha20Poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, errors.New("chacha20poly1305: bad nonce length")
	}
	if len(ciphertext) < 16 {
		return nil, errors.New("chacha20poly1305: message authentication failed")
	}
	ct := ciphertext[:len(ciphertext)-16]
	recvTag := ciphertext[len(ciphertext)-16:]
	blk0 := chacha20Block(c.key, 0, nonce)
	var otk [32]byte
	copy(otk[:], blk0[:32])
	macIn := buildPoly1305Input(additionalData, ct)
	expTag := poly1305MAC(macIn, otk)
	if subtle.ConstantTimeCompare(recvTag, expTag[:]) != 1 {
		return nil, errors.New("chacha20poly1305: message authentication failed")
	}
	pt := chacha20XOR(c.key, 1, nonce, ct)
	return append(dst, pt...), nil
}

// Self-verify against RFC 8439 Section 2.8.2 test vector.
func verifyChaCha20Poly1305SelfTest() error {
	key, _ := hex.DecodeString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce, _ := hex.DecodeString("070000004041424344454647")
	aad, _ := hex.DecodeString("50515253c0c1c2c3c4c5c6c7")
	pt := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	expCT, _ := hex.DecodeString(
		"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
			"3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
			"92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
			"3ff4def08e4b7a9de576d26586cec64b6116")
	expTag, _ := hex.DecodeString("1ae10b594f09e26a7e902ecbd0600691")

	aead, err := newChaCha20Poly1305(key)
	if err != nil {
		return err
	}
	out := aead.Seal(nil, nonce, pt, aad)
	want := append(append([]byte{}, expCT...), expTag...)
	if hex.EncodeToString(out) != hex.EncodeToString(want) {
		return fmt.Errorf("RFC 8439 seal mismatch:\ngot:  %x\nwant: %x", out, want)
	}
	gotPT, err := aead.Open(nil, nonce, out, aad)
	if err != nil || string(gotPT) != string(pt) {
		return fmt.Errorf("RFC 8439 open mismatch: err=%v", err)
	}
	return nil
}
