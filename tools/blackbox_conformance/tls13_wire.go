// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"os"
	"time"
)

// TLS 1.3 constants (RFC 8446)
const (
	RecCCS       byte = 20 // 0x14
	RecAlert     byte = 21 // 0x15
	RecHandshake byte = 22 // 0x16
	RecAppData   byte = 23 // 0x17

	HSClientHello         byte = 1
	HSServerHello         byte = 2
	HSNewSessionTicket    byte = 4
	HSEndOfEarlyData      byte = 5
	HSEncryptedExtensions byte = 8
	HSCertificate         byte = 11
	HSCertificateRequest  byte = 13
	HSCertificateVerify   byte = 15
	HSFinished            byte = 20
	HSKeyUpdate           byte = 24

	CipherAES128GCM        uint16 = 0x1301
	CipherAES256GCM        uint16 = 0x1302
	CipherChaCha20Poly1305 uint16 = 0x1303

	GroupP256   uint16 = 0x0017
	GroupP384   uint16 = 0x0018
	GroupX25519 uint16 = 0x001d

	SigECDSAP256SHA256 uint16 = 0x0403
	SigECDSAP384SHA384 uint16 = 0x0503
	SigRSAPSSSHA256    uint16 = 0x0804
	SigEd25519         uint16 = 0x0807
	SigRSAPKCS1SHA256  uint16 = 0x0401
	SigRSAPKCS1SHA1    uint16 = 0x0201
	SigECDSASHA1       uint16 = 0x0203

	ExtSNI               uint16 = 0x0000
	ExtSupportedGroups   uint16 = 0x000a
	ExtSigAlgs           uint16 = 0x000d
	ExtALPN              uint16 = 0x0010
	ExtSupportedVersions uint16 = 0x002b
	ExtKeyShare          uint16 = 0x0033
)

var (
	hrrRandom, _ = hex.DecodeString("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
	downgrade12  = []byte{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01}
	downgrade11  = []byte{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00}
)

var alertNames = map[byte]string{
	0:   "close_notify",
	10:  "unexpected_message",
	20:  "bad_record_mac",
	22:  "record_overflow",
	40:  "handshake_failure",
	42:  "bad_certificate",
	43:  "unsupported_certificate",
	44:  "certificate_revoked",
	45:  "certificate_expired",
	46:  "certificate_unknown",
	47:  "illegal_parameter",
	48:  "unknown_ca",
	50:  "decode_error",
	51:  "decrypt_error",
	70:  "protocol_version",
	71:  "insufficient_security",
	80:  "internal_error",
	86:  "inappropriate_fallback",
	109: "missing_extension",
	110: "unsupported_extension",
	112: "unrecognized_name",
	116: "certificate_required",
	120: "no_application_protocol",
}

func alertName(desc byte) string {
	if s, ok := alertNames[desc]; ok {
		return fmt.Sprintf("%s(%d)", s, desc)
	}
	return fmt.Sprintf("unknown(%d)", desc)
}

// --- HKDF & TLS 1.3 Key Schedule ---

type cipherSpec struct {
	id     uint16
	hashFn func() hash.Hash
	hLen   int
	keyLen int
	ivLen  int
}

func getCipherSpec(id uint16) (cipherSpec, error) {
	switch id {
	case CipherAES128GCM:
		return cipherSpec{id: id, hashFn: sha256.New, hLen: 32, keyLen: 16, ivLen: 12}, nil
	case CipherAES256GCM:
		return cipherSpec{id: id, hashFn: sha512.New384, hLen: 48, keyLen: 32, ivLen: 12}, nil
	case CipherChaCha20Poly1305:
		return cipherSpec{id: id, hashFn: sha256.New, hLen: 32, keyLen: 32, ivLen: 12}, nil
	default:
		return cipherSpec{}, fmt.Errorf("unsupported cipher 0x%04x", id)
	}
}

func hkdfExtract(h func() hash.Hash, salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, h().Size())
	}
	m := hmac.New(h, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

func hkdfExpand(h func() hash.Hash, prk, info []byte, length int) []byte {
	var out []byte
	var prev []byte
	for c := byte(1); len(out) < length; c++ {
		m := hmac.New(h, prk)
		m.Write(prev)
		m.Write(info)
		m.Write([]byte{c})
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

func hkdfExpandLabel(h func() hash.Hash, secret []byte, label string, ctx []byte, length int) []byte {
	fullLabel := "tls13 " + label
	info := make([]byte, 0, 2+1+len(fullLabel)+1+len(ctx))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, byte(len(ctx)))
	info = append(info, ctx...)
	return hkdfExpand(h, secret, info, length)
}

func deriveSecret(spec cipherSpec, secret []byte, label string, transcriptHash []byte) []byte {
	return hkdfExpandLabel(spec.hashFn, secret, label, transcriptHash, spec.hLen)
}

func emptyHash(spec cipherSpec) []byte {
	h := spec.hashFn()
	return h.Sum(nil)
}

func hashMessages(spec cipherSpec, msgs ...[]byte) []byte {
	h := spec.hashFn()
	for _, m := range msgs {
		h.Write(m)
	}
	return h.Sum(nil)
}

func computeFinishedMAC(spec cipherSpec, baseSecret, transcriptHash []byte) []byte {
	fk := hkdfExpandLabel(spec.hashFn, baseSecret, "finished", nil, spec.hLen)
	m := hmac.New(spec.hashFn, fk)
	m.Write(transcriptHash)
	return m.Sum(nil)
}

// --- AEAD Record State ---

type trafficState struct {
	spec   cipherSpec
	secret []byte
	key    []byte
	iv     []byte
	seq    uint64
	aead   cipher.AEAD
}

func newTrafficState(spec cipherSpec, secret []byte) (*trafficState, error) {
	key := hkdfExpandLabel(spec.hashFn, secret, "key", nil, spec.keyLen)
	iv := hkdfExpandLabel(spec.hashFn, secret, "iv", nil, spec.ivLen)
	var aead cipher.AEAD
	var err error
	if spec.id == CipherChaCha20Poly1305 {
		aead, err = newChaCha20Poly1305(key)
	} else {
		var blk cipher.Block
		blk, err = aes.NewCipher(key)
		if err == nil {
			aead, err = cipher.NewGCM(blk)
		}
	}
	if err != nil {
		return nil, err
	}
	return &trafficState{spec: spec, secret: append([]byte{}, secret...), key: key, iv: iv, aead: aead}, nil
}

func (ts *trafficState) nonceForSeq(seq uint64) []byte {
	n := make([]byte, len(ts.iv))
	copy(n, ts.iv)
	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], seq)
	for i := range 8 {
		n[len(n)-8+i] ^= seqBytes[i]
	}
	return n
}

func (ts *trafficState) sealRecordWithOpts(innerType byte, payload []byte, padZeros int, recVer uint16, seqOverride *uint64) []byte {
	inner := make([]byte, 0, len(payload)+1+padZeros)
	inner = append(inner, payload...)
	if innerType != 0 || len(payload) > 0 || padZeros == 0 {
		inner = append(inner, innerType)
	}
	if padZeros > 0 {
		inner = append(inner, make([]byte, padZeros)...)
	}
	ctLen := len(inner) + ts.aead.Overhead()
	aad := []byte{RecAppData, byte(recVer >> 8), byte(recVer), byte(ctLen >> 8), byte(ctLen)}
	seq := ts.seq
	if seqOverride != nil {
		seq = *seqOverride
	} else {
		ts.seq++
	}
	nonce := ts.nonceForSeq(seq)
	ct := ts.aead.Seal(nil, nonce, inner, aad)
	return append(aad, ct...)
}

func (ts *trafficState) sealRawInner(inner []byte, recVer uint16) []byte {
	ctLen := len(inner) + ts.aead.Overhead()
	aad := []byte{RecAppData, byte(recVer >> 8), byte(recVer), byte(ctLen >> 8), byte(ctLen)}
	nonce := ts.nonceForSeq(ts.seq)
	ts.seq++
	ct := ts.aead.Seal(nil, nonce, inner, aad)
	return append(aad, ct...)
}

func (ts *trafficState) sealRecord(innerType byte, payload []byte) []byte {
	return ts.sealRecordWithOpts(innerType, payload, 0, 0x0303, nil)
}

func (ts *trafficState) openRecord(rec tlsRecord) (byte, []byte, error) {
	if rec.typ != RecAppData {
		return 0, nil, fmt.Errorf("expected appdata record (23), got %d", rec.typ)
	}
	aad := []byte{rec.typ, byte(rec.ver >> 8), byte(rec.ver), byte(len(rec.payload) >> 8), byte(len(rec.payload))}
	nonce := ts.nonceForSeq(ts.seq)
	pt, err := ts.aead.Open(nil, nonce, rec.payload, aad)
	if err != nil {
		return 0, nil, err
	}
	ts.seq++
	// Strip trailing zero padding per RFC 8446 Section 5.4
	i := len(pt) - 1
	for i >= 0 && pt[i] == 0 {
		i--
	}
	if i < 0 {
		return 0, nil, errors.New("all-zero inner plaintext")
	}
	return pt[i], pt[:i], nil
}

func (ts *trafficState) ratchet() (*trafficState, error) {
	nextSec := hkdfExpandLabel(ts.spec.hashFn, ts.secret, "traffic upd", nil, ts.spec.hLen)
	return newTrafficState(ts.spec, nextSec)
}

// --- Raw Record Framing ---

type tlsRecord struct {
	typ     byte
	ver     uint16
	payload []byte
}

func makeRecord(typ byte, ver uint16, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = typ
	out[1] = byte(ver >> 8)
	out[2] = byte(ver)
	binary.BigEndian.PutUint16(out[3:5], uint16(len(payload)))
	copy(out[5:], payload)
	return out
}

func makeHandshakeMsg(hsType byte, body []byte) []byte {
	out := make([]byte, 4+len(body))
	out[0] = hsType
	out[1] = byte(len(body) >> 16)
	out[2] = byte(len(body) >> 8)
	out[3] = byte(len(body))
	copy(out[4:], body)
	return out
}

func readTLSRecord(conn net.Conn, timeout time.Duration) (tlsRecord, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var hdr [5]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return tlsRecord{}, err
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n > 20000 {
		return tlsRecord{typ: hdr[0], ver: binary.BigEndian.Uint16(hdr[1:3])}, fmt.Errorf("record too big: %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return tlsRecord{typ: hdr[0], ver: binary.BigEndian.Uint16(hdr[1:3]), payload: payload}, err
	}
	return tlsRecord{
		typ:     hdr[0],
		ver:     binary.BigEndian.Uint16(hdr[1:3]),
		payload: payload,
	}, nil
}

// Drain raw response bytes and classify into alert / EOF / RST / timeout / handshake / data.
type wireOutcome struct {
	raw        []byte
	kind       string // "ALERT", "ENC_ALERT", "EOF", "RST", "TIMEOUT", "HANDSHAKE", "APPDATA", "OTHER"
	alertLevel byte
	alertDesc  byte
	detail     string
}

func classifyResponse(conn net.Conn, hsRx *trafficState, appRx *trafficState, timeout time.Duration) wireOutcome {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if n == 0 {
		if err == nil {
			return wireOutcome{kind: "EOF", detail: "clean EOF (0 bytes)"}
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return wireOutcome{kind: "TIMEOUT", detail: "read timeout (no response/close)"}
		}
		if errors.Is(err, io.EOF) {
			return wireOutcome{kind: "EOF", detail: "clean EOF"}
		}
		return wireOutcome{kind: "RST", detail: fmt.Sprintf("read error: %v", err)}
	}
	raw := buf[:n]
	// Parse first record if possible
	if len(raw) >= 5 {
		recTyp := raw[0]
		recVer := binary.BigEndian.Uint16(raw[1:3])
		recLen := int(binary.BigEndian.Uint16(raw[3:5]))
		// Read rest of record if partial
		for len(raw) < 5+recLen && recLen <= 18432 {
			_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			more := make([]byte, 5+recLen-len(raw))
			m, rerr := conn.Read(more)
			if m > 0 {
				raw = append(raw, more[:m]...)
			}
			if rerr != nil {
				break
			}
		}
		if recTyp == RecAlert && recLen >= 2 && len(raw) >= 7 {
			return wireOutcome{
				raw:        raw,
				kind:       "ALERT",
				alertLevel: raw[5],
				alertDesc:  raw[6],
				detail:     fmt.Sprintf("plain Alert(level=%d, desc=%s) hex=%x", raw[5], alertName(raw[6]), raw[:minInt(len(raw), 16)]),
			}
		}
		if recTyp == RecAppData && len(raw) >= 5+recLen {
			rec := tlsRecord{typ: recTyp, ver: recVer, payload: raw[5 : 5+recLen]}
			if appRx != nil {
				if it, pt, oerr := appRx.openRecord(rec); oerr == nil {
					if it == RecAlert && len(pt) >= 2 {
						return wireOutcome{
							raw:        raw,
							kind:       "ENC_ALERT",
							alertLevel: pt[0],
							alertDesc:  pt[1],
							detail:     fmt.Sprintf("enc(app) Alert(level=%d, desc=%s)", pt[0], alertName(pt[1])),
						}
					}
					return wireOutcome{
						raw:    raw,
						kind:   "APPDATA",
						detail: fmt.Sprintf("enc(app) innerType=%d len=%d preview=%q", it, len(pt), truncStr(string(pt), 60)),
					}
				}
			}
			if hsRx != nil {
				if it, pt, oerr := hsRx.openRecord(rec); oerr == nil {
					if it == RecAlert && len(pt) >= 2 {
						return wireOutcome{
							raw:        raw,
							kind:       "ENC_ALERT",
							alertLevel: pt[0],
							alertDesc:  pt[1],
							detail:     fmt.Sprintf("enc(hs) Alert(level=%d, desc=%s)", pt[0], alertName(pt[1])),
						}
					}
					return wireOutcome{
						raw:    raw,
						kind:   "APPDATA",
						detail: fmt.Sprintf("enc(hs) innerType=%d len=%d", it, len(pt)),
					}
				}
			}
			return wireOutcome{
				raw:    raw,
				kind:   "APPDATA",
				detail: fmt.Sprintf("opaque AppData record len=%d hex=%x", recLen, raw[:minInt(len(raw), 24)]),
			}
		}
		if recTyp == RecHandshake {
			hsType := byte(0xff)
			if len(raw) >= 6 {
				hsType = raw[5]
			}
			return wireOutcome{
				raw:    raw,
				kind:   "HANDSHAKE",
				detail: fmt.Sprintf("Handshake(type=%d) recLen=%d total=%d hex=%x", hsType, recLen, len(raw), raw[:minInt(len(raw), 24)]),
			}
		}
	}
	return wireOutcome{
		raw:    raw,
		kind:   "OTHER",
		detail: fmt.Sprintf("raw(%dB) hex=%x", len(raw), raw[:minInt(len(raw), 32)]),
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// --- ClientHello Builder ---

type rawExt struct {
	typ  uint16
	body []byte
}

func extSNI(host string) rawExt {
	b := make([]byte, 0, 5+len(host))
	b = binary.BigEndian.AppendUint16(b, uint16(3+len(host)))
	b = append(b, 0x00) // host_name
	b = binary.BigEndian.AppendUint16(b, uint16(len(host)))
	b = append(b, host...)
	return rawExt{typ: ExtSNI, body: b}
}

func extSupportedVersionsClient(vers ...uint16) rawExt {
	b := make([]byte, 0, 1+2*len(vers))
	b = append(b, byte(2*len(vers)))
	for _, v := range vers {
		b = binary.BigEndian.AppendUint16(b, v)
	}
	return rawExt{typ: ExtSupportedVersions, body: b}
}

func extSupportedGroups(groups ...uint16) rawExt {
	b := make([]byte, 0, 2+2*len(groups))
	b = binary.BigEndian.AppendUint16(b, uint16(2*len(groups)))
	for _, g := range groups {
		b = binary.BigEndian.AppendUint16(b, g)
	}
	return rawExt{typ: ExtSupportedGroups, body: b}
}

func extSigAlgs(algs ...uint16) rawExt {
	b := make([]byte, 0, 2+2*len(algs))
	b = binary.BigEndian.AppendUint16(b, uint16(2*len(algs)))
	for _, a := range algs {
		b = binary.BigEndian.AppendUint16(b, a)
	}
	return rawExt{typ: ExtSigAlgs, body: b}
}

func extALPN(protos ...string) rawExt {
	var list []byte
	for _, p := range protos {
		list = append(list, byte(len(p)))
		list = append(list, p...)
	}
	b := binary.BigEndian.AppendUint16(nil, uint16(len(list)))
	b = append(b, list...)
	return rawExt{typ: ExtALPN, body: b}
}

type keyShareEntry struct {
	group uint16
	key   []byte
}

func extKeyShareClient(entries ...keyShareEntry) rawExt {
	var list []byte
	for _, e := range entries {
		list = binary.BigEndian.AppendUint16(list, e.group)
		list = binary.BigEndian.AppendUint16(list, uint16(len(e.key)))
		list = append(list, e.key...)
	}
	b := binary.BigEndian.AppendUint16(nil, uint16(len(list)))
	b = append(b, list...)
	return rawExt{typ: ExtKeyShare, body: b}
}

type clientHelloOpts struct {
	legacyVer   uint16
	random      []byte // nil => 32 crypto/rand bytes
	sessionID   []byte
	ciphers     []uint16
	rawCiphers  []byte // overrides ciphers if non-nil
	compression []byte // nil => {0x00}
	omitComp    bool
	exts        []rawExt
	omitExts    bool
	trailing    []byte
}

func buildClientHelloMsg(o clientHelloOpts) []byte {
	lv := o.legacyVer
	if lv == 0 {
		lv = 0x0303
	}
	rnd := o.random
	if rnd == nil {
		rnd = make([]byte, 32)
		_, _ = rand.Read(rnd)
	}
	var body []byte
	body = binary.BigEndian.AppendUint16(body, lv)
	body = append(body, rnd...)
	body = append(body, byte(len(o.sessionID)))
	body = append(body, o.sessionID...)
	if o.rawCiphers != nil {
		body = append(body, o.rawCiphers...)
	} else {
		body = binary.BigEndian.AppendUint16(body, uint16(2*len(o.ciphers)))
		for _, c := range o.ciphers {
			body = binary.BigEndian.AppendUint16(body, c)
		}
	}
	if !o.omitComp {
		comp := o.compression
		if comp == nil {
			comp = []byte{0x00}
		}
		body = append(body, byte(len(comp)))
		body = append(body, comp...)
	}
	if !o.omitExts {
		var eb []byte
		for _, e := range o.exts {
			eb = binary.BigEndian.AppendUint16(eb, e.typ)
			eb = binary.BigEndian.AppendUint16(eb, uint16(len(e.body)))
			eb = append(eb, e.body...)
		}
		body = binary.BigEndian.AppendUint16(body, uint16(len(eb)))
		body = append(body, eb...)
	}
	body = append(body, o.trailing...)
	return makeHandshakeMsg(HSClientHello, body)
}

// --- Full Raw-Wire TLS 1.3 Client Handshake Engine ---

type tls13ClientSession struct {
	conn           net.Conn
	spec           cipherSpec
	cipherID       uint16
	serverRandom   []byte
	sessionIDEcho  []byte
	isHRR          bool
	selectedGroup  uint16
	serverKeyShare []byte
	negotiatedALPN string
	certs          []*x509.Certificate
	rawCerts       [][]byte
	cvSigAlg       uint16
	cvSig          []byte
	cvValid        bool
	hsTx           *trafficState
	hsRx           *trafficState
	appTx          *trafficState
	appRx          *trafficState
	masterSecret   []byte
	transcript     [][]byte
	clientFinMsg   []byte
	hsRxBuf        []byte
	serverALPN     string
}

type handshakeConfig struct {
	sni             string
	alpn            []string
	ciphers         []uint16
	groups          []uint16
	useP256KeyShare bool
	sigAlgs         []uint16
	oneByteTCP      bool
	chRecordSplits  int // >1 splits ClientHello across N TLS records
	finRecordSplits int // >1 splits Client Finished across N encrypted TLS records
	sendCCS         bool
	stopBeforeFin   bool
	customFinPad    int
	sessionID       []byte
}

func defaultHandshakeConfig(sni string) handshakeConfig {
	return handshakeConfig{
		sni:     sni,
		alpn:    []string{"http/1.1"},
		ciphers: []uint16{CipherAES128GCM, CipherAES256GCM, CipherChaCha20Poly1305},
		groups:  []uint16{GroupX25519, GroupP256},
		sigAlgs: []uint16{SigEd25519, SigECDSAP256SHA256, SigECDSAP384SHA384, SigRSAPSSSHA256},
	}
}

func writeBytesOpts(conn net.Conn, data []byte, oneByte bool) error {
	if !oneByte {
		_, err := conn.Write(data)
		return err
	}
	for i := range data {
		if _, err := conn.Write(data[i : i+1]); err != nil {
			return err
		}
	}
	return nil
}

func writeFragmentedRecord(conn net.Conn, typ byte, ver uint16, payload []byte, splits int, oneByte bool) error {
	if splits <= 1 || len(payload) < splits {
		return writeBytesOpts(conn, makeRecord(typ, ver, payload), oneByte)
	}
	step := max(len(payload)/splits, 1)
	for off := 0; off < len(payload); {
		end := off + step
		if end > len(payload) || (off+step*2 > len(payload) && splits > 1 && end < len(payload) && (len(payload)-off) < step) {
			end = len(payload)
		}
		if err := writeBytesOpts(conn, makeRecord(typ, ver, payload[off:end]), oneByte); err != nil {
			return err
		}
		off = end
	}
	return nil
}

type parsedSH struct {
	legacyVer     uint16
	random        []byte
	sessionIDEcho []byte
	cipher        uint16
	compression   byte
	isHRR         bool
	selectedVer   uint16
	ksGroup       uint16
	ksKey         []byte
	hrrGroup      uint16
	exts          map[uint16][]byte
}

func parseServerHello(hsMsg []byte) (*parsedSH, error) {
	if len(hsMsg) < 4 || hsMsg[0] != HSServerHello {
		return nil, fmt.Errorf("not ServerHello (type=%d len=%d)", hsMsg[0], len(hsMsg))
	}
	bodyLen := int(hsMsg[1])<<16 | int(hsMsg[2])<<8 | int(hsMsg[3])
	if len(hsMsg) != 4+bodyLen {
		return nil, fmt.Errorf("ServerHello length mismatch: hdr=%d actual=%d", bodyLen, len(hsMsg)-4)
	}
	b := hsMsg[4:]
	if len(b) < 2+32+1+2+1+2 {
		return nil, errors.New("ServerHello too short")
	}
	sh := &parsedSH{exts: map[uint16][]byte{}}
	sh.legacyVer = binary.BigEndian.Uint16(b[0:2])
	sh.random = append([]byte{}, b[2:34]...)
	sh.isHRR = bytes.Equal(sh.random, hrrRandom)
	sidLen := int(b[34])
	off := 35
	if off+sidLen+3 > len(b) {
		return nil, errors.New("ServerHello sid overflow")
	}
	sh.sessionIDEcho = append([]byte{}, b[off:off+sidLen]...)
	off += sidLen
	sh.cipher = binary.BigEndian.Uint16(b[off : off+2])
	sh.compression = b[off+2]
	off += 3
	if off+2 > len(b) {
		return nil, errors.New("ServerHello missing exts")
	}
	extLen := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if off+extLen != len(b) {
		return nil, fmt.Errorf("ServerHello extLen mismatch: %d vs %d", extLen, len(b)-off)
	}
	end := off + extLen
	for off < end {
		if off+4 > end {
			return nil, errors.New("ServerHello truncated ext header")
		}
		et := binary.BigEndian.Uint16(b[off : off+2])
		el := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4
		if off+el > end {
			return nil, errors.New("ServerHello truncated ext body")
		}
		eb := b[off : off+el]
		sh.exts[et] = eb
		off += el
		switch et {
		case ExtSupportedVersions:
			if len(eb) == 2 {
				sh.selectedVer = binary.BigEndian.Uint16(eb)
			}
		case ExtKeyShare:
			if sh.isHRR && len(eb) == 2 {
				sh.hrrGroup = binary.BigEndian.Uint16(eb)
			} else if len(eb) >= 4 {
				sh.ksGroup = binary.BigEndian.Uint16(eb[0:2])
				kl := int(binary.BigEndian.Uint16(eb[2:4]))
				if 4+kl == len(eb) {
					sh.ksKey = append([]byte{}, eb[4:]...)
				}
			}
		}
	}
	return sh, nil
}

func doTLS13Handshake(addr string, cfg handshakeConfig) (*tls13ClientSession, error) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	sess, err := doTLS13HandshakeOnConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return sess, nil
}

func doTLS13HandshakeOnConn(conn net.Conn, cfg handshakeConfig) (*tls13ClientSession, error) {
	var ecdhKey *ecdh.PrivateKey
	var ksGroup uint16
	var err error
	if cfg.useP256KeyShare {
		ecdhKey, err = ecdh.P256().GenerateKey(rand.Reader)
		ksGroup = GroupP256
	} else {
		ecdhKey, err = ecdh.X25519().GenerateKey(rand.Reader)
		ksGroup = GroupX25519
	}
	if err != nil {
		return nil, err
	}

	var exts []rawExt
	if cfg.sni != "" {
		exts = append(exts, extSNI(cfg.sni))
	}
	exts = append(exts, extSupportedVersionsClient(0x0304))
	exts = append(exts, extSupportedGroups(cfg.groups...))
	exts = append(exts, extSigAlgs(cfg.sigAlgs...))
	if len(cfg.alpn) > 0 {
		exts = append(exts, extALPN(cfg.alpn...))
	}
	exts = append(exts, extKeyShareClient(keyShareEntry{group: ksGroup, key: ecdhKey.PublicKey().Bytes()}))

	sid := cfg.sessionID
	if sid == nil {
		sid = make([]byte, 32)
		_, _ = rand.Read(sid)
	}
	chMsg := buildClientHelloMsg(clientHelloOpts{
		legacyVer: 0x0303,
		sessionID: sid,
		ciphers:   cfg.ciphers,
		exts:      exts,
	})

	if err := writeFragmentedRecord(conn, RecHandshake, 0x0301, chMsg, cfg.chRecordSplits, cfg.oneByteTCP); err != nil {
		return nil, fmt.Errorf("write CH: %w", err)
	}

	sess := &tls13ClientSession{conn: conn, transcript: [][]byte{chMsg}}

	// Read ServerHello (possibly fragmented across handshake records)
	var shRaw []byte
	for {
		rec, err := readTLSRecord(conn, 5*time.Second)
		if err != nil {
			return nil, fmt.Errorf("read SH: %w", err)
		}
		if rec.typ == RecAlert && len(rec.payload) >= 2 {
			return nil, fmt.Errorf("server alert before SH: level=%d desc=%s", rec.payload[0], alertName(rec.payload[1]))
		}
		if rec.typ != RecHandshake {
			return nil, fmt.Errorf("expected handshake before SH, got %d", rec.typ)
		}
		shRaw = append(shRaw, rec.payload...)
		if len(shRaw) >= 4 {
			need := 4 + (int(shRaw[1])<<16 | int(shRaw[2])<<8 | int(shRaw[3]))
			if len(shRaw) >= need {
				shRaw = shRaw[:need]
				break
			}
		}
	}

	sh, err := parseServerHello(shRaw)
	if err != nil {
		return nil, err
	}
	if sh.isHRR {
		sess.isHRR = true
		spec, err := getCipherSpec(sh.cipher)
		if err != nil {
			return nil, err
		}
		// RFC 8446 Section 4.4.1 synthetic message_hash
		chHash := hashMessages(spec, chMsg)
		msgHash := makeHandshakeMsg(254, chHash)
		sess.transcript = [][]byte{msgHash, shRaw}

		// Generate requested key share
		switch sh.hrrGroup {
		case GroupX25519:
			ecdhKey, err = ecdh.X25519().GenerateKey(rand.Reader)
			ksGroup = GroupX25519
		case GroupP256:
			ecdhKey, err = ecdh.P256().GenerateKey(rand.Reader)
			ksGroup = GroupP256
		default:
			return nil, fmt.Errorf("HRR requested unsupported group 0x%04x", sh.hrrGroup)
		}
		if err != nil {
			return nil, err
		}
		var exts2 []rawExt
		if cfg.sni != "" {
			exts2 = append(exts2, extSNI(cfg.sni))
		}
		exts2 = append(exts2, extSupportedVersionsClient(0x0304))
		exts2 = append(exts2, extSupportedGroups(cfg.groups...))
		exts2 = append(exts2, extSigAlgs(cfg.sigAlgs...))
		if len(cfg.alpn) > 0 {
			exts2 = append(exts2, extALPN(cfg.alpn...))
		}
		exts2 = append(exts2, extKeyShareClient(keyShareEntry{group: ksGroup, key: ecdhKey.PublicKey().Bytes()}))
		ch2 := buildClientHelloMsg(clientHelloOpts{
			legacyVer: 0x0303,
			sessionID: sid,
			ciphers:   cfg.ciphers,
			exts:      exts2,
		})
		if err := writeBytesOpts(conn, makeRecord(RecHandshake, 0x0303, ch2), cfg.oneByteTCP); err != nil {
			return nil, fmt.Errorf("write CH2: %w", err)
		}
		sess.transcript = append(sess.transcript, ch2)

		// Read real ServerHello (skipping optional CCS)
		shRaw = nil
		for {
			rec, err := readTLSRecord(conn, 5*time.Second)
			if err != nil {
				return nil, fmt.Errorf("read SH2: %w", err)
			}
			if rec.typ == RecCCS {
				continue
			}
			if rec.typ == RecAlert && len(rec.payload) >= 2 {
				return nil, fmt.Errorf("server alert after CH2: level=%d desc=%s", rec.payload[0], alertName(rec.payload[1]))
			}
			if rec.typ != RecHandshake {
				return nil, fmt.Errorf("expected SH2, got rec %d", rec.typ)
			}
			shRaw = append(shRaw, rec.payload...)
			if len(shRaw) >= 4 {
				need := 4 + (int(shRaw[1])<<16 | int(shRaw[2])<<8 | int(shRaw[3]))
				if len(shRaw) >= need {
					shRaw = shRaw[:need]
					break
				}
			}
		}
		sh, err = parseServerHello(shRaw)
		if err != nil {
			return nil, err
		}
	}

	// Check RFC 8446 Section 4.1.3 downgrade sentinels
	if bytes.Equal(sh.random[24:], downgrade12) || bytes.Equal(sh.random[24:], downgrade11) {
		return nil, fmt.Errorf("ServerHello.random contains downgrade sentinel: %x", sh.random[24:])
	}
	if sh.selectedVer != 0x0304 {
		return nil, fmt.Errorf("ServerHello selected version 0x%04x != 0x0304", sh.selectedVer)
	}
	if !bytes.Equal(sh.sessionIDEcho, sid) {
		return nil, fmt.Errorf("ServerHello session_id_echo mismatch: got %x want %x", sh.sessionIDEcho, sid)
	}
	spec, err := getCipherSpec(sh.cipher)
	if err != nil {
		return nil, err
	}
	sess.spec = spec
	sess.cipherID = sh.cipher
	sess.serverRandom = sh.random
	sess.sessionIDEcho = sh.sessionIDEcho
	sess.selectedGroup = sh.ksGroup
	sess.serverKeyShare = sh.ksKey
	sess.transcript = append(sess.transcript, shRaw)

	// Compute ECDHE shared secret
	var peerPub *ecdh.PublicKey
	switch sh.ksGroup {
	case GroupX25519:
		peerPub, err = ecdh.X25519().NewPublicKey(sh.ksKey)
	case GroupP256:
		peerPub, err = ecdh.P256().NewPublicKey(sh.ksKey)
	default:
		return nil, fmt.Errorf("unexpected server key_share group 0x%04x", sh.ksGroup)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid server key_share: %w", err)
	}
	shared, err := ecdhKey.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Key schedule: early -> handshake
	zeros := make([]byte, spec.hLen)
	earlySecret := hkdfExtract(spec.hashFn, zeros, zeros)
	derived1 := deriveSecret(spec, earlySecret, "derived", emptyHash(spec))
	hsSecret := hkdfExtract(spec.hashFn, derived1, shared)
	thSH := hashMessages(spec, sess.transcript...)
	cHsSecret := deriveSecret(spec, hsSecret, "c hs traffic", thSH)
	sHsSecret := deriveSecret(spec, hsSecret, "s hs traffic", thSH)
	sess.hsTx, err = newTrafficState(spec, cHsSecret)
	if err != nil {
		return nil, err
	}
	sess.hsRx, err = newTrafficState(spec, sHsSecret)
	if err != nil {
		return nil, err
	}

	// Read server encrypted handshake flight: EE, Certificate, CertificateVerify, Finished
	var gotEE, gotCert, gotCV, gotFin bool
	var certTranscriptHash []byte
	for !gotFin {
		for len(sess.hsRxBuf) < 4 {
			rec, err := readTLSRecord(conn, 5*time.Second)
			if err != nil {
				return nil, fmt.Errorf("read server flight: %w", err)
			}
			if rec.typ == RecCCS {
				continue
			}
			if rec.typ == RecAlert && len(rec.payload) >= 2 {
				return nil, fmt.Errorf("plain server alert in flight: level=%d desc=%s", rec.payload[0], alertName(rec.payload[1]))
			}
			it, pt, err := sess.hsRx.openRecord(rec)
			if err != nil {
				return nil, fmt.Errorf("decrypt server flight record: %w", err)
			}
			if it == RecAlert && len(pt) >= 2 {
				return nil, fmt.Errorf("encrypted server alert in flight: level=%d desc=%s", pt[0], alertName(pt[1]))
			}
			if it != RecHandshake {
				return nil, fmt.Errorf("unexpected inner content type %d during handshake", it)
			}
			sess.hsRxBuf = append(sess.hsRxBuf, pt...)
		}
		hsLen := int(sess.hsRxBuf[1])<<16 | int(sess.hsRxBuf[2])<<8 | int(sess.hsRxBuf[3])
		for len(sess.hsRxBuf) < 4+hsLen {
			rec, err := readTLSRecord(conn, 5*time.Second)
			if err != nil {
				return nil, fmt.Errorf("read server flight cont: %w", err)
			}
			if rec.typ == RecCCS {
				continue
			}
			it, pt, err := sess.hsRx.openRecord(rec)
			if err != nil {
				return nil, fmt.Errorf("decrypt server flight cont: %w", err)
			}
			if it != RecHandshake {
				return nil, fmt.Errorf("unexpected inner type %d in flight cont", it)
			}
			sess.hsRxBuf = append(sess.hsRxBuf, pt...)
		}
		msg := append([]byte{}, sess.hsRxBuf[:4+hsLen]...)
		sess.hsRxBuf = sess.hsRxBuf[4+hsLen:]

		switch msg[0] {
		case HSEncryptedExtensions:
			gotEE = true
			// Parse ALPN if present
			if len(msg) >= 6 {
				eb := msg[6:]
				for off := 0; off+4 <= len(eb); {
					et := binary.BigEndian.Uint16(eb[off : off+2])
					el := int(binary.BigEndian.Uint16(eb[off+2 : off+4]))
					off += 4
					if off+el > len(eb) {
						break
					}
					if et == ExtALPN && el >= 3 {
						pl := int(eb[off+2])
						if 3+pl <= el {
							sess.negotiatedALPN = string(eb[off+3 : off+3+pl])
						}
					}
					off += el
				}
			}
			sess.transcript = append(sess.transcript, msg)
		case HSCertificate:
			gotCert = true
			if err := parseCertMsg(msg, sess); err != nil {
				return nil, fmt.Errorf("parse Certificate: %w", err)
			}
			sess.transcript = append(sess.transcript, msg)
			certTranscriptHash = hashMessages(spec, sess.transcript...)
		case HSCertificateVerify:
			gotCV = true
			if err := verifyCertVerifyMsg(msg, sess, certTranscriptHash); err != nil {
				return nil, fmt.Errorf("verify CertificateVerify: %w", err)
			}
			sess.cvValid = true
			sess.transcript = append(sess.transcript, msg)
		case HSFinished:
			gotFin = true
			thBeforeFin := hashMessages(spec, sess.transcript...)
			expFin := computeFinishedMAC(spec, sHsSecret, thBeforeFin)
			if !bytes.Equal(msg[4:], expFin) {
				return nil, fmt.Errorf("server Finished MAC mismatch:\ngot:  %x\nwant: %x", msg[4:], expFin)
			}
			sess.transcript = append(sess.transcript, msg)
		default:
			return nil, fmt.Errorf("unexpected server handshake msg type %d", msg[0])
		}
	}
	if !gotEE || !gotCert || !gotCV || !gotFin {
		return nil, fmt.Errorf("incomplete server flight: EE=%v Cert=%v CV=%v Fin=%v", gotEE, gotCert, gotCV, gotFin)
	}

	// Derive application traffic secrets
	thSF := hashMessages(spec, sess.transcript...)
	derived2 := deriveSecret(spec, hsSecret, "derived", emptyHash(spec))
	sess.masterSecret = hkdfExtract(spec.hashFn, derived2, zeros)
	cAppSecret := deriveSecret(spec, sess.masterSecret, "c ap traffic", thSF)
	sAppSecret := deriveSecret(spec, sess.masterSecret, "s ap traffic", thSF)
	sess.appTx, err = newTrafficState(spec, cAppSecret)
	if err != nil {
		return nil, err
	}
	sess.appRx, err = newTrafficState(spec, sAppSecret)
	if err != nil {
		return nil, err
	}

	cFinMAC := computeFinishedMAC(spec, cHsSecret, thSF)
	sess.clientFinMsg = makeHandshakeMsg(HSFinished, cFinMAC)

	if cfg.stopBeforeFin {
		return sess, nil
	}

	if cfg.sendCCS {
		if err := writeBytesOpts(conn, makeRecord(RecCCS, 0x0303, []byte{0x01}), cfg.oneByteTCP); err != nil {
			return nil, err
		}
	}

	if cfg.finRecordSplits > 1 && len(sess.clientFinMsg) >= cfg.finRecordSplits {
		mid := len(sess.clientFinMsg) / 2
		r1 := sess.hsTx.sealRecordWithOpts(RecHandshake, sess.clientFinMsg[:mid], cfg.customFinPad, 0x0303, nil)
		r2 := sess.hsTx.sealRecordWithOpts(RecHandshake, sess.clientFinMsg[mid:], cfg.customFinPad, 0x0303, nil)
		if err := writeBytesOpts(conn, r1, cfg.oneByteTCP); err != nil {
			return nil, err
		}
		if err := writeBytesOpts(conn, r2, cfg.oneByteTCP); err != nil {
			return nil, err
		}
	} else {
		finRec := sess.hsTx.sealRecordWithOpts(RecHandshake, sess.clientFinMsg, cfg.customFinPad, 0x0303, nil)
		if err := writeBytesOpts(conn, finRec, cfg.oneByteTCP); err != nil {
			return nil, err
		}
	}
	sess.transcript = append(sess.transcript, sess.clientFinMsg)
	return sess, nil
}

func parseCertMsg(msg []byte, sess *tls13ClientSession) error {
	b := msg[4:]
	if len(b) < 4 {
		return errors.New("certificate msg too short")
	}
	ctxLen := int(b[0])
	off := 1 + ctxLen
	if off+3 > len(b) {
		return errors.New("certificate list len missing")
	}
	listLen := int(b[off])<<16 | int(b[off+1])<<8 | int(b[off+2])
	off += 3
	if off+listLen != len(b) {
		return fmt.Errorf("certificate list len mismatch: %d vs %d", listLen, len(b)-off)
	}
	end := off + listLen
	for off < end {
		if off+3 > end {
			return errors.New("cert entry len truncated")
		}
		cl := int(b[off])<<16 | int(b[off+1])<<8 | int(b[off+2])
		off += 3
		if off+cl+2 > end {
			return errors.New("cert entry truncated")
		}
		der := append([]byte{}, b[off:off+cl]...)
		off += cl
		extLen := int(binary.BigEndian.Uint16(b[off : off+2]))
		off += 2
		if off+extLen > end {
			return errors.New("cert ext truncated")
		}
		off += extLen
		sess.rawCerts = append(sess.rawCerts, der)
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("x509.ParseCertificate: %w", err)
		}
		sess.certs = append(sess.certs, c)
	}
	if len(sess.certs) == 0 {
		return errors.New("empty certificate list")
	}
	return nil
}

func verifyCertVerifyMsg(msg []byte, sess *tls13ClientSession, transcriptHash []byte) error {
	b := msg[4:]
	if len(b) < 4 {
		return errors.New("CertificateVerify too short")
	}
	sigAlg := binary.BigEndian.Uint16(b[0:2])
	sigLen := int(binary.BigEndian.Uint16(b[2:4]))
	if 4+sigLen != len(b) {
		return errors.New("CertificateVerify sig length mismatch")
	}
	sig := b[4:]
	sess.cvSigAlg = sigAlg
	sess.cvSig = append([]byte{}, sig...)

	var content []byte
	content = append(content, bytes.Repeat([]byte{0x20}, 64)...)
	content = append(content, []byte("TLS 1.3, server CertificateVerify")...)
	content = append(content, 0x00)
	content = append(content, transcriptHash...)

	pub := sess.certs[0].PublicKey
	switch sigAlg {
	case SigEd25519:
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("CV sigAlg=Ed25519 but leaf key is %T", pub)
		}
		if !ed25519.Verify(edPub, content, sig) {
			return errors.New("Ed25519 CertificateVerify signature invalid")
		}
		return nil
	case SigECDSAP256SHA256:
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("CV sigAlg=ECDSA-P256 but leaf key is %T", pub)
		}
		digest := sha256.Sum256(content)
		if !ecdsa.VerifyASN1(ecPub, digest[:], sig) {
			return errors.New("ECDSA-P256 CertificateVerify signature invalid")
		}
		return nil
	case SigECDSAP384SHA384:
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("CV sigAlg=ECDSA-P384 but leaf key is %T", pub)
		}
		digest := sha512.Sum384(content)
		if !ecdsa.VerifyASN1(ecPub, digest[:], sig) {
			return errors.New("ECDSA-P384 CertificateVerify signature invalid")
		}
		return nil
	case SigRSAPSSSHA256:
		rPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("CV sigAlg=RSA-PSS-SHA256 but leaf key is %T", pub)
		}
		digest := sha256.Sum256(content)
		if err := rsa.VerifyPSS(rPub, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
			return fmt.Errorf("RSA-PSS CertificateVerify invalid: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported CV sigAlg 0x%04x", sigAlg)
	}
}

func (s *tls13ClientSession) sendAppData(data []byte, oneByte bool) error {
	rec := s.appTx.sealRecord(RecAppData, data)
	return writeBytesOpts(s.conn, rec, oneByte)
}

func (s *tls13ClientSession) readAppData(timeout time.Duration) ([]byte, error) {
	for {
		rec, err := readTLSRecord(s.conn, timeout)
		if err != nil {
			return nil, err
		}
		if rec.typ == RecCCS {
			continue
		}
		if rec.typ == RecAlert && len(rec.payload) >= 2 {
			return nil, fmt.Errorf("plain alert: level=%d desc=%s", rec.payload[0], alertName(rec.payload[1]))
		}
		it, pt, err := s.appRx.openRecord(rec)
		if err != nil {
			return nil, fmt.Errorf("openRecord: %w", err)
		}
		switch it {
		case RecAppData:
			if len(pt) == 0 {
				continue
			}
			return pt, nil
		case RecHandshake:
			// Ignore NewSessionTicket or handle KeyUpdate
			if len(pt) >= 5 && pt[0] == HSKeyUpdate {
				s.appRx, err = s.appRx.ratchet()
				if err != nil {
					return nil, err
				}
			}
			continue
		case RecAlert:
			if len(pt) >= 2 {
				return nil, fmt.Errorf("enc alert: level=%d desc=%s", pt[0], alertName(pt[1]))
			}
			return nil, errors.New("malformed enc alert")
		default:
			return nil, fmt.Errorf("unexpected inner type %d", it)
		}
	}
}

func (s *tls13ClientSession) close() {
	if s != nil && s.conn != nil {
		_ = s.conn.Close()
	}
}

// --- Self-signed / CA Certificate Generation for Testing ---

type testPKI struct {
	caCert      *x509.Certificate
	caDER       []byte
	caPEMPath   string
	caKey       *ecdsa.PrivateKey
	edCert      *x509.Certificate
	edDER       []byte
	edKey       ed25519.PrivateKey
	edCertPath  string
	edKeyPath   string
	ecCert      *x509.Certificate
	ecDER       []byte
	ecKey       *ecdsa.PrivateKey
	ecCertPath  string
	ecKeyPath   string
	rsaCert     *x509.Certificate
	rsaDER      []byte
	rsaKey      *rsa.PrivateKey
	rsaCertPath string
	rsaKeyPath  string
}

func generateTestPKI(dir string) (*testPKI, error) {
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Blackbox Test Root CA"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		SubjectKeyId:          []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	caPEMPath := dir + `\ca.pem`
	if err := writePEMFile(caPEMPath, "CERTIFICATE", caDER); err != nil {
		return nil, err
	}

	// Ed25519 leaf signed by CA (and also self-signed? No, CA-signed works for both --sni-map and bogo_shim!)
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	leafTmpl := func(serial int64, cn string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             now.Add(-24 * time.Hour),
			NotAfter:              now.Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			DNSNames:              []string{"test.local", "localhost", "goose-wing.local"},
			IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		}
	}
	edDER, err := x509.CreateCertificate(rand.Reader, leafTmpl(201, "test.local"), caCert, edPub, caKey)
	if err != nil {
		return nil, err
	}
	edCert, err := x509.ParseCertificate(edDER)
	if err != nil {
		return nil, err
	}
	edKeyDER, err := x509.MarshalPKCS8PrivateKey(edPriv)
	if err != nil {
		return nil, err
	}
	edCertPath := dir + `\leaf_ed25519.pem`
	edKeyPath := dir + `\leaf_ed25519.key`
	if err := writePEMChainFile(edCertPath, edDER, caDER); err != nil {
		return nil, err
	}
	if err := writePEMFile(edKeyPath, "PRIVATE KEY", edKeyDER); err != nil {
		return nil, err
	}

	// ECDSA P-256 leaf
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ecDER, err := x509.CreateCertificate(rand.Reader, leafTmpl(202, "ecdsa.local"), caCert, &ecKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ecCert, err := x509.ParseCertificate(ecDER)
	if err != nil {
		return nil, err
	}
	ecKeyDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		return nil, err
	}
	ecCertPath := dir + `\leaf_ecdsa.pem`
	ecKeyPath := dir + `\leaf_ecdsa.key`
	if err := writePEMChainFile(ecCertPath, ecDER, caDER); err != nil {
		return nil, err
	}
	if err := writePEMFile(ecKeyPath, "PRIVATE KEY", ecKeyDER); err != nil {
		return nil, err
	}

	// RSA 2048 leaf
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	rsaDER, err := x509.CreateCertificate(rand.Reader, leafTmpl(203, "rsa.local"), caCert, &rsaKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	rsaCert, err := x509.ParseCertificate(rsaDER)
	if err != nil {
		return nil, err
	}
	rsaKeyDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		return nil, err
	}
	rsaCertPath := dir + `\leaf_rsa.pem`
	rsaKeyPath := dir + `\leaf_rsa.key`
	if err := writePEMChainFile(rsaCertPath, rsaDER, caDER); err != nil {
		return nil, err
	}
	if err := writePEMFile(rsaKeyPath, "PRIVATE KEY", rsaKeyDER); err != nil {
		return nil, err
	}

	return &testPKI{
		caCert: caCert, caDER: caDER, caPEMPath: caPEMPath, caKey: caKey,
		edCert: edCert, edDER: edDER, edKey: edPriv, edCertPath: edCertPath, edKeyPath: edKeyPath,
		ecCert: ecCert, ecDER: ecDER, ecKey: ecKey, ecCertPath: ecCertPath, ecKeyPath: ecKeyPath,
		rsaCert: rsaCert, rsaDER: rsaDER, rsaKey: rsaKey, rsaCertPath: rsaCertPath, rsaKeyPath: rsaKeyPath,
	}, nil
}

func writePEMFile(path, typ string, der []byte) error {
	b := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	return os.WriteFile(path, b, 0600)
}

func writePEMChainFile(path string, ders ...[]byte) error {
	var buf bytes.Buffer
	for _, d := range ders {
		buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}))
	}
	return os.WriteFile(path, buf.Bytes(), 0600)
}
