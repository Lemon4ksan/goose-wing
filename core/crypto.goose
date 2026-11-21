// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cryptographic subsystem for the Goose Core Systems Library.
// Provides zero-allocation, branchless constant-time cryptographic primitives:
// - ct: Constant-time byte comparisons, KeySlot secrecy pattern, Dudect Welch t-test verifier.
// - csprng: OS-backed cryptographically secure random byte generation.
// - sha: SHA-256, SHA-384, SHA-512 (FIPS 180-4), SHA-1 (RFC 3174), HMAC, HKDF extract/expand.
// - md5: MD5 message-digest algorithm (RFC 1321).
// - aes: AES-128, AES-256 block ciphers and AES-GCM AEAD (NIST SP 800-38D).
// - chacha: ChaCha20, HChaCha20, Poly1305, and ChaCha20-Poly1305 / XChaCha20-Poly1305 AEAD (RFC 8439).
// - x25519: Montgomery ladder Diffie-Hellman key exchange over Curve25519 (RFC 7748).
// - ed25519: Edwards-curve Digital Signature Algorithm (Ed25519) (RFC 8032).
// - base64: Standard Base64 and URL-safe Base64 codecs (RFC 4648).
namespace core;

import std;

import core.crypto.ct;
import core.crypto.csprng;
import core.crypto.sha;
import core.crypto.md5;
import core.crypto.aes;
import core.crypto.chacha;
import core.crypto.x25519;
import core.crypto.ed25519;
import core.crypto.ecdsa;
import core.crypto.rsa;
import core.crypto.base64;
