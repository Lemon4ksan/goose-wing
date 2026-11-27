// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Core Cryptography (Hashes, HMAC/HKDF, Base64, CT/CSPRNG,
// AES-GCM, ChaCha20/Poly1305/XChaCha20, X25519, Ed25519, ECDSA P-256/P-384, RSA-2048/2049).
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// ---- Test Helpers ----------------------------------------------------------

fn hex_eq(sub: lit::T&, actual: const u8[:], expected_hex: const u8[:], msg: const u8[:]) {
    sub.assert_eq(actual.len * 2, expected_hex.len, msg);
    var buf: u8[..256] = [];
    for b in actual {
        core::format_u8_hex(b, buf, false);
    }
    sub.assert_bytes_eq(buf[..], expected_hex, msg);
}

// ---- RSA-2048 (e = 65537), RSA-2049 (n[0] == 0x01), RSA-2042 (n[0] == 0x03) -

const RSA2048_N: const u8[256] = [
    0xBA, 0x01, 0x1F, 0x1D, 0x6E, 0xF1, 0xA8, 0x09, 0x6F, 0x85, 0x31, 0x54, 0x48, 0x19, 0xE6, 0x51,
    0x75, 0x7C, 0x31, 0x5C, 0xF9, 0x97, 0x75, 0x21, 0x10, 0x25, 0x87, 0xC6, 0x6C, 0x41, 0xFA, 0x7C,
    0x42, 0xC0, 0xBA, 0x03, 0x39, 0xB9, 0xD7, 0x3F, 0xA4, 0xC2, 0x98, 0x07, 0x39, 0xF0, 0x96, 0x27,
    0xB2, 0x40, 0x28, 0x52, 0x7F, 0x50, 0x06, 0x88, 0x01, 0x98, 0x92, 0xC7, 0x3A, 0xC9, 0xC1, 0x5B,
    0xBA, 0x11, 0xBE, 0x38, 0x68, 0x39, 0x43, 0xBA, 0x2D, 0x1A, 0x7D, 0x3F, 0x64, 0x4F, 0xD6, 0x46,
    0x80, 0xF8, 0xBD, 0xBD, 0xE8, 0x9F, 0x7C, 0xDD, 0x9B, 0xA2, 0x23, 0x68, 0x32, 0x52, 0xAA, 0x32,
    0x68, 0x8E, 0xE5, 0x0A, 0xFA, 0x69, 0xE1, 0xE4, 0x82, 0xB1, 0x95, 0xDE, 0x7E, 0x93, 0x65, 0xAC,
    0xA2, 0x10, 0x91, 0x95, 0x1A, 0xD1, 0x71, 0xA5, 0xB7, 0x52, 0x0F, 0x26, 0xE2, 0xCA, 0x55, 0x63,
    0x85, 0x57, 0x96, 0x45, 0x5B, 0x0E, 0xB8, 0x8D, 0xEF, 0x9B, 0xD4, 0x81, 0x2D, 0x9A, 0x26, 0x0D,
    0x0A, 0xAE, 0x4D, 0xEC, 0x27, 0x15, 0x5A, 0xA3, 0x35, 0x0E, 0x80, 0xCC, 0x5D, 0xF8, 0x35, 0x01,
    0x61, 0xA9, 0xAA, 0xBC, 0x03, 0xA7, 0xDE, 0x5E, 0x11, 0xE9, 0x79, 0xF1, 0xFE, 0x92, 0x60, 0x47,
    0xF4, 0xA8, 0x33, 0x13, 0x25, 0x77, 0x65, 0x84, 0x69, 0xAE, 0x8A, 0xF0, 0xDF, 0x4F, 0x44, 0xF7,
    0x88, 0xAA, 0x0B, 0x7E, 0x12, 0xF8, 0xD5, 0x74, 0x4B, 0x31, 0xDC, 0x77, 0xAC, 0xA1, 0xEF, 0x56,
    0xA1, 0xEF, 0xF9, 0x2A, 0x44, 0xEA, 0xB8, 0x49, 0x18, 0xD4, 0x9B, 0x98, 0x32, 0xAB, 0x25, 0x26,
    0x08, 0x23, 0xAF, 0x91, 0xFA, 0x36, 0xEE, 0x77, 0x02, 0x1E, 0xF6, 0x14, 0x92, 0x92, 0x16, 0xC8,
    0x93, 0xCB, 0x8C, 0x2C, 0xEE, 0x88, 0x86, 0x3B, 0xB6, 0x3E, 0x4E, 0x50, 0xC5, 0x4A, 0x5A, 0x0F,
];

const RSA2048_E: const u8[3] = [0x01, 0x00, 0x01];

const RSA2048_D: const u8[256] = [
    0x1C, 0x0E, 0xDB, 0x40, 0xB7, 0x61, 0xA0, 0xB5, 0x7B, 0xAB, 0x1D, 0xDB, 0xD6, 0xDC, 0x81, 0x4F,
    0xBC, 0x67, 0x35, 0x93, 0x0E, 0xDB, 0x78, 0x01, 0xBA, 0xCB, 0xCE, 0x85, 0x72, 0x03, 0x29, 0xE3,
    0xE0, 0xB5, 0xED, 0xD9, 0x5A, 0xB5, 0xDB, 0xF0, 0x6F, 0xCC, 0x22, 0xDE, 0xC4, 0x30, 0xB4, 0x95,
    0xDC, 0x5F, 0xAD, 0x35, 0x74, 0x9A, 0xFF, 0xC1, 0x38, 0x6C, 0x69, 0x87, 0xC0, 0x28, 0x7B, 0x10,
    0x79, 0x2B, 0x00, 0x04, 0xC6, 0x44, 0x0D, 0x21, 0x62, 0x78, 0x62, 0x78, 0x53, 0x8B, 0x6F, 0x89,
    0x47, 0x1F, 0x3E, 0x90, 0x0D, 0x2D, 0x31, 0xCA, 0xC4, 0x15, 0x5B, 0x3D, 0xF6, 0x89, 0x5D, 0xBF,
    0x28, 0xE2, 0x95, 0x4E, 0x68, 0xA3, 0xDC, 0x3D, 0x7A, 0x31, 0x8B, 0xA7, 0xFA, 0x74, 0x05, 0x9C,
    0x5A, 0xFE, 0x20, 0xD7, 0xDB, 0x29, 0xC8, 0xF8, 0xF4, 0x84, 0x5E, 0x60, 0xC1, 0x49, 0x40, 0x43,
    0xF6, 0xF9, 0x20, 0x2B, 0x12, 0xA5, 0x8E, 0x94, 0x12, 0xBF, 0xB6, 0x76, 0x49, 0x74, 0xAA, 0xDE,
    0xE7, 0x8D, 0x17, 0x1B, 0x3A, 0xCC, 0xE4, 0xDD, 0x1B, 0xF1, 0xD5, 0x98, 0x86, 0x9F, 0xE3, 0xE2,
    0xC7, 0x4B, 0xBB, 0x53, 0xA6, 0x3C, 0xC5, 0xB9, 0x68, 0x40, 0x5F, 0x23, 0x6B, 0xA6, 0x2B, 0x54,
    0xEA, 0x89, 0x9A, 0x61, 0xB1, 0x02, 0x12, 0x48, 0xEB, 0x28, 0x71, 0xF2, 0x31, 0x51, 0x94, 0x4C,
    0x85, 0x1E, 0x5D, 0xEE, 0x19, 0x1A, 0xA1, 0xDC, 0x23, 0xCB, 0xAE, 0x0B, 0x16, 0x0B, 0x7E, 0xB7,
    0x7E, 0xD8, 0xB9, 0x56, 0x15, 0x78, 0xA9, 0xDC, 0xC1, 0x59, 0x78, 0xE3, 0xAB, 0x73, 0x2E, 0x82,
    0x64, 0xCB, 0x21, 0x36, 0xB4, 0x81, 0xC9, 0xDF, 0x94, 0x1D, 0x98, 0x2B, 0xB9, 0xC1, 0xAC, 0x5D,
    0x82, 0x5E, 0x10, 0xB0, 0xE3, 0xC8, 0xA5, 0x08, 0x2F, 0x10, 0x3E, 0x8E, 0x6D, 0xF9, 0x6C, 0x61,
];

const TEST_SIG_PKCS1_SHA384: const u8[256] = [
    0x2d, 0xce, 0x02, 0xb6, 0x89, 0xb5, 0x68, 0xfe, 0x88, 0xf9, 0x43, 0xae, 0x86, 0x36, 0x4f, 0xad,
    0x2f, 0x08, 0x2f, 0xbf, 0xc2, 0x22, 0x8e, 0xe1, 0x8c, 0xab, 0xce, 0x65, 0x04, 0x6c, 0x1a, 0x69,
    0x7b, 0xa6, 0xac, 0x2b, 0x9f, 0x44, 0x52, 0xec, 0x19, 0x02, 0x26, 0x3e, 0xc2, 0x28, 0x1f, 0xe2,
    0xcc, 0x8b, 0xc5, 0xb7, 0x77, 0x16, 0xbd, 0x17, 0x43, 0xd4, 0x09, 0xad, 0x9f, 0x01, 0xf8, 0xa3,
    0x9e, 0x9d, 0x9b, 0x36, 0xf7, 0x8a, 0x7e, 0x3d, 0x7d, 0xb1, 0x2c, 0x50, 0xfa, 0xf8, 0x83, 0x7b,
    0xe3, 0x3a, 0x80, 0xde, 0x57, 0x27, 0x21, 0x3b, 0xd6, 0xaa, 0xb1, 0x5f, 0xf6, 0x1d, 0x78, 0x5e,
    0xa2, 0x80, 0x43, 0x69, 0x03, 0xcb, 0x89, 0x78, 0x6c, 0x85, 0xeb, 0x95, 0x1a, 0xad, 0x3b, 0x61,
    0x7e, 0xf0, 0xf2, 0x80, 0x27, 0x42, 0x31, 0xf9, 0x98, 0xfe, 0xc5, 0x79, 0x1e, 0x8e, 0x24, 0x6f,
    0xcb, 0x48, 0xad, 0x1d, 0x8a, 0x5b, 0x19, 0xe8, 0x2d, 0xef, 0x8a, 0x4a, 0xdc, 0x06, 0x56, 0x5c,
    0xd8, 0x3f, 0x86, 0x1c, 0xe2, 0xb9, 0x7b, 0x57, 0x05, 0x64, 0x73, 0x52, 0x93, 0x4c, 0xa4, 0x14,
    0xe8, 0xb3, 0x03, 0x45, 0x59, 0x93, 0x7d, 0xbd, 0x3a, 0x22, 0x25, 0x47, 0x3d, 0x0f, 0x12, 0xf8,
    0xa6, 0x00, 0xf7, 0x9b, 0x1c, 0x49, 0xd8, 0x74, 0x9a, 0xbd, 0x4a, 0xf2, 0x6d, 0x47, 0xcd, 0x27,
    0x14, 0x48, 0x60, 0xf3, 0x5c, 0x02, 0x8e, 0x3d, 0x07, 0xf8, 0x28, 0x50, 0xcb, 0xb0, 0x5a, 0x2c,
    0x01, 0x5e, 0xde, 0x1a, 0x7b, 0x87, 0x84, 0xc6, 0x23, 0x4f, 0xb5, 0x0f, 0x70, 0xc1, 0xe9, 0xd6,
    0x96, 0x4e, 0x8b, 0x56, 0x75, 0x5f, 0xdd, 0xb4, 0x49, 0x4c, 0x3d, 0xe7, 0x38, 0x7c, 0xa7, 0x3f,
    0x09, 0xb7, 0xcc, 0x6b, 0xc4, 0x05, 0x24, 0xf7, 0x29, 0x85, 0x54, 0x7e, 0x29, 0x06, 0xf1, 0x92,
];

const TEST_SIG_PSS_SHA384: const u8[256] = [
    0x10, 0x22, 0x9e, 0x87, 0x5a, 0x67, 0x6c, 0x3a, 0xbf, 0xf7, 0xcd, 0x7f, 0x57, 0xc7, 0x85, 0xd0,
    0xad, 0x51, 0xb4, 0x10, 0x81, 0x4f, 0x54, 0x49, 0x1f, 0x42, 0x20, 0x02, 0x2b, 0x24, 0x0d, 0xae,
    0x9f, 0xe2, 0x06, 0xeb, 0x5e, 0xc0, 0xd6, 0x24, 0x6c, 0x95, 0xd4, 0x01, 0xfb, 0xfc, 0xae, 0xc7,
    0x4d, 0x8a, 0x6c, 0xdb, 0x17, 0xe2, 0xa0, 0x50, 0xc8, 0x21, 0x7d, 0x82, 0x0e, 0xc6, 0x8f, 0xe6,
    0x28, 0x37, 0x57, 0x3f, 0x58, 0x57, 0xea, 0x7b, 0x83, 0xa4, 0x7a, 0xee, 0xdc, 0xa1, 0x5b, 0xe7,
    0x7f, 0x9f, 0xae, 0x58, 0xb5, 0xb8, 0xed, 0x78, 0xbe, 0x3e, 0xd7, 0x45, 0x25, 0xd3, 0xe7, 0x0e,
    0x15, 0x5a, 0x5c, 0x6a, 0xe6, 0x48, 0xf0, 0x40, 0xcd, 0x8e, 0xd8, 0x10, 0x5e, 0x62, 0x14, 0x1d,
    0xea, 0x89, 0x5b, 0x78, 0xe3, 0x2c, 0x59, 0x3d, 0x5b, 0x34, 0x9e, 0xa8, 0xd9, 0xbe, 0x50, 0xb3,
    0x90, 0xbe, 0x6d, 0x1e, 0x6d, 0x38, 0x3a, 0xa2, 0x12, 0x5b, 0x3f, 0xe4, 0x93, 0x4c, 0x51, 0x68,
    0x13, 0x35, 0x91, 0xe2, 0x27, 0x0a, 0xff, 0xc5, 0xad, 0xa5, 0x12, 0xfe, 0x0f, 0xa5, 0x04, 0xcb,
    0xb6, 0xd6, 0x50, 0x20, 0x9a, 0x06, 0xcb, 0x5d, 0xac, 0x24, 0x9c, 0x67, 0x04, 0xf8, 0x1c, 0xd3,
    0x7c, 0x36, 0xa8, 0x08, 0x55, 0x51, 0xe3, 0x10, 0xd0, 0x4a, 0x74, 0x6c, 0x5f, 0x72, 0x59, 0x08,
    0x49, 0x24, 0x75, 0x55, 0x94, 0xf5, 0x20, 0x93, 0xd0, 0x18, 0xb2, 0xf7, 0xd7, 0xe0, 0xf5, 0xb0,
    0x69, 0x64, 0xc2, 0xb0, 0x47, 0xec, 0xfa, 0xce, 0x59, 0xda, 0xff, 0x6e, 0x7c, 0x95, 0xa4, 0xea,
    0xc3, 0x4a, 0xe6, 0x74, 0x56, 0xd2, 0x08, 0xa8, 0x7f, 0x93, 0x61, 0x04, 0x7b, 0x21, 0x4e, 0xf7,
    0x7b, 0x8c, 0x86, 0x07, 0xe8, 0xe5, 0x63, 0xdf, 0x07, 0x64, 0x25, 0x0a, 0xa4, 0x96, 0x33, 0x95,
];

const RSA2049_N: const u8[257] = [
    0x01, 0x90, 0x6f, 0x50, 0x67, 0xc3, 0xa6, 0x33, 0x43, 0x35, 0xa1, 0x54, 0xd7, 0x67, 0xcb, 0x41,
    0x6a, 0x4c, 0xf8, 0x40, 0xe5, 0x79, 0x20, 0x7d, 0xb4, 0x41, 0x08, 0x16, 0xa3, 0xb8, 0x36, 0xf3,
    0x28, 0x92, 0xfb, 0x5d, 0x85, 0x2d, 0x33, 0xaa, 0x9d, 0x2a, 0xb3, 0x1a, 0xe8, 0x36, 0x02, 0xd7,
    0x84, 0x09, 0x93, 0xcf, 0xdd, 0x40, 0xe1, 0x95, 0x85, 0x84, 0x55, 0x06, 0xb2, 0x8d, 0xba, 0x8d,
    0x06, 0x17, 0xd8, 0x6c, 0xb7, 0x5d, 0x29, 0x4d, 0x92, 0x0e, 0x15, 0x81, 0x26, 0xfb, 0x6a, 0xa1,
    0x23, 0x19, 0xd3, 0xe9, 0xba, 0xe1, 0x5d, 0xa7, 0x45, 0xda, 0x8e, 0xe0, 0x87, 0xca, 0x69, 0x4b,
    0x63, 0xf7, 0xf5, 0x5c, 0x37, 0x26, 0xd1, 0xcb, 0xba, 0xfb, 0x77, 0x1c, 0x59, 0xe8, 0xc8, 0x9b,
    0xf8, 0xd3, 0x10, 0xfd, 0xb9, 0xf8, 0x8d, 0xb4, 0x1d, 0x19, 0xd2, 0x60, 0x00, 0xad, 0xfb, 0x81,
    0x20, 0x79, 0x70, 0xee, 0x04, 0x44, 0x05, 0xdd, 0xa3, 0xfb, 0x1d, 0x87, 0xc7, 0x91, 0x14, 0x1d,
    0x0b, 0x47, 0xc8, 0xe0, 0xcf, 0xf1, 0xc6, 0x59, 0x4e, 0x45, 0xd5, 0x52, 0x7c, 0x40, 0xc9, 0x3b,
    0x5b, 0xf2, 0x1d, 0x37, 0xca, 0x64, 0x64, 0xe6, 0x38, 0x3f, 0xcf, 0x69, 0xea, 0x5e, 0xca, 0x1a,
    0x78, 0x4c, 0xf1, 0xf2, 0x32, 0xd1, 0xde, 0x74, 0xfd, 0xcb, 0x05, 0xbc, 0x31, 0xe7, 0x61, 0x09,
    0x2f, 0xe6, 0xee, 0xf5, 0xa9, 0xbe, 0x93, 0xf5, 0xf4, 0x4f, 0xed, 0x14, 0x09, 0xab, 0x91, 0xf4,
    0x58, 0xeb, 0xee, 0x67, 0x8c, 0x22, 0xf7, 0xef, 0x28, 0x3f, 0x8b, 0x11, 0x97, 0x49, 0xc0, 0xa8,
    0xa1, 0x8b, 0xf8, 0xcd, 0x9c, 0x81, 0x56, 0x92, 0xc3, 0xb6, 0x11, 0x05, 0x6e, 0x62, 0x56, 0x1a,
    0x87, 0x45, 0x7a, 0xd5, 0x37, 0xe1, 0x2b, 0x19, 0x5a, 0xf5, 0x93, 0xb5, 0xc5, 0xe5, 0x35, 0xce,
    0x25,
];

const RSA2049_D: const u8[257] = [
    0x01, 0x77, 0x8d, 0xfe, 0xb2, 0x22, 0xdb, 0xc8, 0x6e, 0x3b, 0x69, 0x40, 0xe1, 0xf9, 0x75, 0xb6,
    0xb7, 0x54, 0xd2, 0xec, 0x42, 0x8b, 0xb4, 0xbe, 0x50, 0x85, 0x41, 0x69, 0xc2, 0x48, 0xee, 0x38,
    0x65, 0x90, 0x5c, 0x71, 0xdc, 0x8a, 0x85, 0x4f, 0x79, 0xb1, 0xe7, 0x62, 0xcf, 0xf0, 0x7f, 0xff,
    0xd2, 0xd5, 0x0c, 0xad, 0x42, 0x0c, 0x2c, 0xc6, 0x08, 0x00, 0x11, 0xa2, 0x83, 0x69, 0xcb, 0x51,
    0xa2, 0x2a, 0x51, 0x0f, 0xbd, 0x75, 0x81, 0x5c, 0x40, 0x24, 0x37, 0x64, 0xf6, 0xc3, 0x8b, 0xc0,
    0xee, 0xe3, 0xb5, 0x4d, 0x1b, 0xb9, 0x6c, 0x15, 0x8a, 0xbd, 0x2d, 0x8d, 0x45, 0xad, 0xbf, 0xcd,
    0x36, 0x48, 0x02, 0xf5, 0x66, 0xc0, 0x60, 0xb9, 0x1b, 0x77, 0xe6, 0xc1, 0x4f, 0x4d, 0xb4, 0x80,
    0x1c, 0x01, 0x10, 0x89, 0x76, 0x96, 0xb7, 0x87, 0xfa, 0x57, 0x12, 0x68, 0x79, 0x9a, 0xb3, 0x2b,
    0xe8, 0x5f, 0xeb, 0x56, 0x1d, 0x40, 0xfa, 0x9a, 0xbb, 0x6c, 0x17, 0x04, 0x2e, 0x97, 0x28, 0x19,
    0xdf, 0x69, 0x00, 0x7b, 0x87, 0xce, 0x26, 0xff, 0xf6, 0xf0, 0x93, 0x3d, 0x70, 0x75, 0x1b, 0x1a,
    0x0e, 0xde, 0x60, 0x12, 0xa9, 0xaa, 0xdf, 0x29, 0x37, 0x12, 0xda, 0xb9, 0xb2, 0x42, 0xa4, 0x47,
    0x4f, 0x9a, 0x6b, 0x0e, 0x0c, 0xe0, 0x74, 0x04, 0xfc, 0x30, 0x74, 0x8a, 0x47, 0x70, 0x3a, 0xf0,
    0x44, 0xba, 0x7d, 0x4d, 0xe5, 0x6e, 0x49, 0x1c, 0x92, 0x1e, 0xe6, 0xa6, 0x16, 0x6a, 0x79, 0xd9,
    0x38, 0x2c, 0xdd, 0x33, 0x72, 0x06, 0x5a, 0x75, 0xd6, 0x3f, 0xfa, 0x5e, 0xde, 0x6f, 0xfb, 0x7b,
    0x56, 0xe6, 0x92, 0x09, 0xbf, 0x2e, 0xc8, 0x28, 0x18, 0xf1, 0xcf, 0x1f, 0xd5, 0xad, 0xdd, 0xf4,
    0xd2, 0xf8, 0xc2, 0xe5, 0x76, 0x99, 0x9e, 0x24, 0x45, 0xcf, 0x25, 0xf5, 0x0d, 0xd7, 0xaa, 0xe8,
    0xcd,
];

const RSA2042_N: const u8[256] = [
    0x03, 0x16, 0xfd, 0x0b, 0x08, 0x0a, 0x1b, 0xe2, 0x4b, 0x52, 0xdc, 0x6a, 0x72, 0x9f, 0x01, 0x86,
    0xff, 0xf7, 0xad, 0x02, 0x9e, 0x21, 0xce, 0x52, 0x9e, 0xa4, 0xbf, 0xc4, 0x54, 0x84, 0x24, 0x26,
    0xf5, 0x3e, 0x82, 0x40, 0x08, 0x67, 0x89, 0xac, 0x20, 0x67, 0x7e, 0xfe, 0xe0, 0xb2, 0x53, 0xa1,
    0xf6, 0xb8, 0xdb, 0x0c, 0x54, 0x9d, 0x76, 0xe2, 0x8f, 0x5e, 0xfc, 0xc2, 0x19, 0xb4, 0x66, 0xbf,
    0x6e, 0x70, 0x7e, 0x7e, 0x70, 0x06, 0xfe, 0xde, 0x05, 0xbe, 0xf8, 0x81, 0xba, 0xed, 0x09, 0x29,
    0x16, 0x9f, 0xa6, 0xdd, 0x73, 0xf2, 0x2a, 0x8a, 0xdb, 0xd0, 0xd4, 0xae, 0x43, 0xd9, 0xb1, 0xc5,
    0xa5, 0xde, 0xf5, 0xdf, 0x9a, 0x67, 0xa2, 0x6f, 0x7c, 0x16, 0x7f, 0x3a, 0xae, 0x24, 0xb9, 0xfb,
    0xa1, 0xa3, 0x19, 0x2a, 0x11, 0x7d, 0x6c, 0x3d, 0x94, 0x35, 0xf3, 0xef, 0xeb, 0x94, 0x6f, 0x38,
    0x4b, 0x50, 0xd8, 0x49, 0xd2, 0xd7, 0x7b, 0x52, 0xcb, 0x9e, 0x0b, 0x1a, 0xde, 0x4b, 0x3f, 0x34,
    0x12, 0x3e, 0xec, 0x76, 0x7a, 0x79, 0x88, 0x4a, 0xa0, 0x4f, 0xdc, 0xe2, 0xf2, 0x63, 0x9a, 0x9c,
    0xfc, 0x62, 0xa1, 0xd3, 0xab, 0x0c, 0x40, 0x08, 0xfd, 0xc1, 0x54, 0x09, 0xd1, 0x96, 0xbf, 0xc0,
    0xde, 0x2d, 0x9a, 0xb3, 0xc6, 0xe7, 0xb5, 0x7c, 0x38, 0x03, 0x13, 0xee, 0x5f, 0x6b, 0x01, 0x0f,
    0x47, 0x21, 0x7d, 0x40, 0x0f, 0xd8, 0xa8, 0xcb, 0x64, 0x7a, 0x80, 0x22, 0xb2, 0x0b, 0x6d, 0x43,
    0xea, 0x47, 0x8d, 0x7f, 0xa9, 0x57, 0x14, 0xf9, 0x75, 0x38, 0x93, 0x96, 0xcf, 0x22, 0x2f, 0x28,
    0x64, 0xb4, 0xa9, 0x74, 0xcf, 0x7a, 0x63, 0x46, 0x40, 0xa2, 0xf4, 0x4c, 0xe2, 0x7b, 0x74, 0x85,
    0xcf, 0xa3, 0xe6, 0x54, 0xef, 0xd5, 0x5f, 0xb6, 0x7f, 0xbb, 0x29, 0x2c, 0x8b, 0x44, 0x57, 0x81,
];

const RSA2042_D: const u8[256] = [
    0x02, 0x8a, 0xb4, 0xdc, 0x90, 0x5e, 0x90, 0x95, 0xd7, 0x55, 0x71, 0x52, 0x78, 0xbc, 0xea, 0x2a,
    0xbf, 0x04, 0x67, 0xe5, 0xd1, 0x65, 0x0a, 0x30, 0xd9, 0xa5, 0xba, 0xc4, 0xae, 0xaa, 0x8e, 0x7b,
    0x26, 0x21, 0xa8, 0x51, 0x39, 0x18, 0xc4, 0x1f, 0x40, 0x01, 0x24, 0x6e, 0x55, 0x37, 0x1e, 0xaa,
    0x0d, 0x28, 0x01, 0xbb, 0xe1, 0x18, 0x31, 0x27, 0x2c, 0xbe, 0xfd, 0xbc, 0x48, 0x1d, 0x2a, 0xb1,
    0xad, 0x0f, 0x0a, 0x60, 0xc5, 0x94, 0x5b, 0xb3, 0x16, 0x93, 0x06, 0x28, 0xe3, 0x38, 0x00, 0xe3,
    0x36, 0x63, 0x5c, 0x88, 0xad, 0xcb, 0xb8, 0xc7, 0xc7, 0x11, 0xc3, 0x05, 0x21, 0x78, 0x43, 0x50,
    0xcf, 0xa5, 0xde, 0x2b, 0x77, 0x00, 0x6e, 0x96, 0xbc, 0x44, 0x5d, 0xa2, 0x4e, 0x84, 0x94, 0x23,
    0xb7, 0xd3, 0x4e, 0xee, 0x56, 0xb9, 0x11, 0x84, 0x8f, 0x1a, 0xdb, 0x74, 0xb2, 0x1e, 0xc8, 0x68,
    0x1e, 0xeb, 0xeb, 0x0a, 0x90, 0x60, 0x16, 0xe8, 0x8c, 0xa6, 0x22, 0xeb, 0xe6, 0xe0, 0x3d, 0xcd,
    0xa0, 0x18, 0x5c, 0xbc, 0xb1, 0xfe, 0x5d, 0xd7, 0x09, 0x56, 0xca, 0x7e, 0x5a, 0x38, 0x40, 0xad,
    0x4d, 0x74, 0x2b, 0xba, 0x54, 0xba, 0xb6, 0xa3, 0xe7, 0xbf, 0xac, 0x94, 0xe1, 0xe5, 0x9b, 0xf3,
    0x89, 0x81, 0xef, 0x46, 0xbf, 0x53, 0x06, 0xa6, 0x28, 0x8a, 0x01, 0xb3, 0x38, 0x3c, 0x7a, 0x2f,
    0xe1, 0xd5, 0x19, 0x08, 0x2f, 0x75, 0xc1, 0x50, 0x08, 0xd3, 0x57, 0xed, 0xd9, 0x97, 0xb1, 0xb8,
    0xdc, 0x14, 0xcf, 0x1f, 0x73, 0xe6, 0xa9, 0xbc, 0xd4, 0x60, 0x32, 0xc9, 0x01, 0x36, 0xf1, 0x4f,
    0x2e, 0x51, 0x5a, 0xa4, 0xa9, 0xb7, 0x9c, 0xdb, 0x4a, 0x74, 0x13, 0x2d, 0x17, 0x8e, 0x0a, 0x29,
    0xde, 0xdb, 0xcd, 0x31, 0x7f, 0xaf, 0x8d, 0xe1, 0xb6, 0x36, 0x95, 0xab, 0xbe, 0x92, 0xe0, 0x89,
];

// ---- 1. CSPRNG & Constant-Time Primitives --------------------------------

fn test_csprng_and_ct(t: lit::T&) {
    t.run("CSPRNG fill, empty guard, DST sim_rng, and csprng_u64") { sub =>
        var empty_buf: u8[0] = [];
        sub.assert_false(core::csprng_fill(empty_buf[..]), "empty slice fails closed");

        var r1: u8[32] = [0; 32];
        sub.assert_true(core::csprng_fill(r1[..]), "OS CSPRNG fill succeeds");
        var acc: u8 = 0;
        for b in r1 { acc |= b; }
        sub.assert_true(acc != 0, "CSPRNG produces non-zero entropy");

        let v1, ok1 = core::csprng_u64();
        let v2, ok2 = core::csprng_u64();
        sub.assert_true(ok1 && ok2 && v1 != v2, "csprng_u64 produces distinct values");

        core::sim_rng_enable(0xCAFEBABEDEADBEEF);
        var s1: u8[16] = [0; 16];
        var s2: u8[16] = [0; 16];
        sub.assert_true(core::csprng_fill(s1[..]), "sim_rng csprng_fill succeeds");
        core::sim_rng_enable(0xCAFEBABEDEADBEEF);
        sub.assert_true(core::csprng_fill(s2[..]), "sim_rng deterministic repeat");
        sub.assert_eq(s1[..], s2[..], "sim_rng output matches");
        core::sim_rng_disable();
    };

    t.run("CT equality, selection, and zeroization") { sub =>
        sub.assert_eq(core::ct_select_u8(1, 0xAA, 0x55), 0xAA, "ct_select_u8 true");
        sub.assert_eq(core::ct_select_u8(0, 0xAA, 0x55), 0x55, "ct_select_u8 false");

        let a19 = "0123456789abcdefXYZ";
        let b19 = "0123456789abcdefXYW";
        sub.assert_true(core::ct_eq_bytes(a19, a19), "ct_eq_bytes >16B equal");
        sub.assert_false(core::ct_eq_bytes(a19, b19), "ct_eq_bytes tail mismatch");
        sub.assert_false(core::ct_eq_bytes(a19, "short"), "ct_eq_bytes length mismatch");
        sub.assert_true(core::ct_eq_bytes("", ""), "ct_eq_bytes empty");

        let t16a: u8[16] = [0x11; 16];
        var t16b = t16a;
        sub.assert_true(core::ct_eq_tag16(t16a, t16b), "ct_eq_tag16 equal");
        t16b[15] ^= 1;
        sub.assert_false(core::ct_eq_tag16(t16a, t16b), "ct_eq_tag16 diff");

        let t32a: u8[32] = [0x22; 32];
        var t32b = t32a;
        sub.assert_true(core::ct_eq_tag32(t32a, t32b), "ct_eq_tag32 equal");
        t32b[31] ^= 1;
        sub.assert_false(core::ct_eq_tag32(t32a, t32b), "ct_eq_tag32 diff");

        let t48a: u8[48] = [0x33; 48];
        var t48b = t48a;
        sub.assert_true(core::ct_eq_tag48(t48a, t48b), "ct_eq_tag48 equal");
        t48b[47] ^= 1;
        sub.assert_false(core::ct_eq_tag48(t48a, t48b), "ct_eq_tag48 diff");

        var dst_empty: u8[0] = [];
        core::ct_copy_bytes(dst_empty[..], "");
        var z16:  u8[16] = [0xAA; 16];
        var z48:  u8[48] = [0xBB; 48];
        var z64:  u8[64] = [0xCC; 64];
        var zu16: u16[4] = [1, 2, 3, 4];
        var zu32: u32[4] = [1, 2, 3, 4];
        var zu64: u64[4] = [1, 2, 3, 4];
        var zi32: i32[4] = [1, 2, 3, 4];
        core::secure_zeroize_16(z16);
        core::secure_zeroize_48(z48);
        core::secure_zeroize_64(z64);
        core::secure_zeroize_u16_slice(zu16[..]);
        core::secure_zeroize_u32_slice(zu32[..]);
        core::secure_zeroize_u64_slice(zu64[..]);
        core::secure_zeroize_i32_slice(zi32[..]);
        core::ct_declassify_slice("");
        core::ct_declassify_slice(z16[..]);
        sub.assert_eq(z16[0] | z48[0] | z64[0], 0, "fixed buffers zeroized");
        sub.assert_eq(zu16[3], 0, "u16 slice zeroized");
        sub.assert_eq(zu32[3], 0, "u32 slice zeroized");
        sub.assert_eq(zu64[3], 0, "u64 slice zeroized");
        sub.assert_eq(zi32[3], 0, "i32 slice zeroized");
    };
}

// ---- 2. Base64 & Base64URL (RFC 4648) ------------------------------------

fn test_base64_and_base64url(t: lit::T&) {
    t.run("RFC 4648 Section 10 Standard Base64 & Validation") { sub =>
        let inputs:   const u8[:][7] = ["", "f", "fo", "foo", "foob", "fooba", "foobar"];
        let expected: const u8[:][7] = ["", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"];
        for idx in 7 {
            var enc: u8[..32] = [];
            core::base64_encode(inputs[idx], enc);
            sub.assert_bytes_eq(enc[..], expected[idx], "base64_encode RFC 4648");
            sub.assert_true(core::is_valid_base64(enc[..]), "is_valid_base64 valid");

            var dec: u8[..32] = [];
            sub.assert_true(core::base64_decode(enc[..], dec), "base64_decode RFC 4648");
            sub.assert_bytes_eq(dec[..], inputs[idx], "base64 roundtrip");
        }

        // Dynamic buffer target for base64_decode
        var dyn_dec: u8[>..] = [];
        sub.assert_true(core::base64_decode("Zm9vYmFy", dyn_dec));
        sub.assert_bytes_eq(dyn_dec[..], "foobar", "dyn base64_decode");

        // Overflow rollback & zeroization
        var tiny: u8[..2] = [];
        sub.assert_false(core::base64_decode("Zm9vYmFy", tiny), "tiny fixed buffer fails");
        sub.assert_eq(tiny.len, 0, "failed base64_decode clears output");

        // Invalid encodings (bad len, bad char, bad pad count, non-zero pad bits, trailing non-=)
        let bad_b64: const u8[:][10] = [
            "abc", "Zg=", "Zg=a", "Z===", "===a", "Zh==", "Zm9=", "A===", "Zm9?", "Zm?v",
        ];
        for b in bad_b64 {
            var out: u8[..32] = [];
            sub.assert_false(core::base64_decode(b, out), "reject invalid base64");
            sub.assert_false(core::is_valid_base64(b), "is_valid_base64 rejects invalid");
        }
        sub.assert_false(core::is_valid_base64("Z==="), "bad pad position rejected");
    };

    t.run("RFC 4648 Section 5 Base64URL Encode/Decode & Validation") { sub =>
        let raw: u8[5] = [0xFB, 0xEF, 0xFF, 0x00, 0x10];
        var enc: u8[..32] = [];
        core::base64url_encode(raw[..], enc);
        sub.assert_bytes_eq(enc[..], "--__ABA", "base64url uses - and _ unpadded");

        // Rem = 0, 1, 2
        var e0: u8[..16] = [];
        var e1: u8[..16] = [];
        var e2: u8[..16] = [];
        core::base64url_encode("abc", e0);
        core::base64url_encode("a", e1);
        core::base64url_encode("ab", e2);
        sub.assert_bytes_eq(e0[..], "YWJj");
        sub.assert_bytes_eq(e1[..], "YQ");
        sub.assert_bytes_eq(e2[..], "YWI");

        var d1:      u8[..16] = [];
        var d2:      u8[..16] = [];
        var d_pad:   u8[..16] = [];
        var d_empty: u8[..16] = [];
        sub.assert_true(core::base64url_decode("", d_empty) && d_empty.len == 0);
        sub.assert_true(core::base64url_decode("YQ", d1) && d1[..] == "a");
        sub.assert_true(core::base64url_decode("YWI", d2) && d2[..] == "ab");
        sub.assert_true(core::base64url_decode("YQ==", d_pad) && d_pad[..] == "a");
        d_pad.clear();
        sub.assert_true(core::base64url_decode("YWI=", d_pad) && d_pad[..] == "ab");

        var tiny: u8[..2] = [];
        sub.assert_false(core::base64url_decode("--__ABA", tiny), "fixed buffer overflow fails");
        sub.assert_eq(tiny.len, 0);

        let bad_b64u: const u8[:][12] = [
            "A", "YR", "YWJ", "Y===", "YQ=a", "YR==", "YWJ=", "YQ===", "Y+Jj", "Y/Jj", "aa*=", "aa*a",
        ];
        for b in bad_b64u {
            var out: u8[..32] = [];
            sub.assert_false(core::base64url_decode(b, out), "reject invalid base64url");
            sub.assert_false(core::is_valid_base64url(b), "is_valid_base64url rejects invalid");
        }
        var b64_bad: u8[..32] = [];
        sub.assert_false(core::base64_decode("YWI=aaaa", b64_bad), "base64_decode rejects extra after pad");
        sub.assert_true(core::is_valid_base64url(""), "empty base64url valid");
        sub.assert_true(core::is_valid_base64url("YQ=="), "padded 2-eq valid");
        sub.assert_true(core::is_valid_base64url("YWI="), "padded 1-eq valid");
        sub.assert_true(core::is_valid_base64url("aaaa"), "padded rem0 char-check valid");
        sub.assert_true(core::is_valid_base64url("YWJj"), "unpadded rem0 valid");
        sub.assert_true(core::is_valid_base64url("YQ"), "unpadded rem2 valid");
        sub.assert_true(core::is_valid_base64url("YWI"), "unpadded rem3 valid");
        sub.assert_true(core::is_valid_padded_base64url(""), "empty padded valid");
        sub.assert_true(core::is_valid_padded_base64url("YWI="), "1-eq padded valid");
        sub.assert_true(core::is_valid_padded_base64url("YWJj"), "no-eq padded valid");
        sub.assert_false(core::is_valid_padded_base64url("aa*a"), "bad c2 without =");
        sub.assert_false(core::is_valid_padded_base64url("YQ=a"), "bad trailing pad rejected");
    };
}

// ---- 3. MD5, SHA-1, SHA-256/384/512/512-256, HMAC, HKDF -------------------

fn test_hashes_hmac_hkdf(t: lit::T&) {
    t.run("MD5 (RFC 1321) including >=56B and multi-block") { sub =>
        hex_eq(sub, core::md5("")[..], "d41d8cd98f00b204e9800998ecf8427e", "MD5 empty");
        hex_eq(sub, core::md5("abc")[..], "900150983cd24fb0d6963f7d28e17f72", "MD5 abc");
        var b56: u8[56] = ['a'; 56];
        hex_eq(sub, core::md5(b56[..])[..], "3b0c8ac703f828b04c6c197006d17218", "MD5 56B");
        var b128: u8[128] = ['a'; 128];
        hex_eq(sub, core::md5(b128[..])[..], "e510683b3f5ffe4093d021808bc6ff70", "MD5 128B");
    };

    t.run("SHA-1 (RFC 3174) including >=56B and multi-block") { sub =>
        hex_eq(sub, core::sha1("")[..], "da39a3ee5e6b4b0d3255bfef95601890afd80709", "SHA-1 empty");
        hex_eq(sub, core::sha1("abc")[..], "a9993e364706816aba3e25717850c26c9cd0d89d", "SHA-1 abc");
        var b56: u8[56] = ['a'; 56];
        hex_eq(sub, core::sha1(b56[..])[..], "c2db330f6083854c99d4b5bfb6e8f29f201be699", "SHA-1 56B");
        var b120: u8[120] = ['b'; 120];
        hex_eq(sub, core::sha1(b120[..])[..], "84b5ae0b71226716cf26b778e00a1d0c0da78cf1", "SHA-1 120B");
    };

    t.run("SHA-256, SHA-384, SHA-512, SHA-512/256 boundary & streaming") { sub =>
        var b56: u8[56] = ['a'; 56];
        let s256 = core::sha256(b56[..]);
        var ctx256 = core::Sha256Ctx { .. };
        core::sha256_update(ctx256, "");
        core::sha256_update(ctx256, b56[..30]);
        core::sha256_update(ctx256, b56[30..]);
        sub.assert_eq(core::sha256_final(ctx256)[..], s256[..], "SHA-256 streaming matches 56B");

        var b112: u8[112] = ['c'; 112];
        hex_eq(
            sub, core::sha384(b112[..])[..],
            "2f4396d8a08aa20908f102b110f5895325c27e87b7f2cc60fb80e191762f4557aa6edc8ce5877bb67541c6628c664892",
            "SHA-384 112B",
        );
        hex_eq(
            sub, core::sha512(b112[..])[..],
            "059c1d8b62b418815a520e62302b26cc7f297c90d4f674fbdc30a13ad9c39603ca79c46501559c71c82f755fd3831ce1360cf518b0f0bee628ad67be5ad39ddd",
            "SHA-512 112B",
        );
        hex_eq(
            sub, core::sha512_256(b112[..])[..],
            "42ccb2ac8fffb31300631178da474f18a0a8b6bea249efc882bbf3e56a4b18d9",
            "SHA-512/256 112B",
        );

        var ctx384 = core::Sha384Ctx { .. };
        core::sha384_update(ctx384, "");
        core::sha384_update(ctx384, b112[..]);
        sub.assert_eq(core::sha384_final(ctx384)[..], core::sha384(b112[..])[..], "SHA-384 streaming");
        core::zeroize_sha384_ctx(ctx384);

        var ctx512 = core::Sha512Ctx { .. };
        core::sha512_update(ctx512, "");
        core::sha512_update(ctx512, b112[..]);
        sub.assert_eq(core::sha512_final(ctx512)[..], core::sha512(b112[..])[..], "SHA-512 streaming");

        var ctx512_256 = core::Sha512_256Ctx { .. };
        var b135: u8[135] = ['d'; 135];
        core::sha512_256_update(ctx512_256, "");
        core::sha512_256_update(ctx512_256, b135[..]);
        sub.assert_eq(
            core::sha512_256_final(ctx512_256)[..], core::sha512_256(b135[..])[..],
            "SHA-512/256 multi-block streaming",
        );
    };

    t.run("RFC 4231 HMAC-SHA256/384/512 & RFC 5869 HKDF multi-block") { sub =>
        let k131: u8[131] = [0xAA; 131];
        let d6 = "Test Using Larger Than Block-Size Key - Hash Key First";
        hex_eq(
            sub, core::hmac_sha256(k131[..], d6)[..],
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            "HMAC-SHA256 >64B key",
        );
        hex_eq(
            sub, core::hmac_sha256_parts(k131[..], d6[..20], d6[20..], "")[..],
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            "HMAC-SHA256_parts >64B key",
        );
        let h256_nop2 = core::hmac_sha256_parts("k", "ab", "", "");
        sub.assert_eq(h256_nop2[..], core::hmac_sha256("k", "ab")[..]);
        hex_eq(
            sub, core::hmac_sha384(k131[..], d6)[..],
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
            "HMAC-SHA384 >128B key",
        );
        hex_eq(
            sub, core::hmac_sha384_parts(k131[..], d6[..15], d6[15..35], d6[35..])[..],
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
            "HMAC-SHA384_parts >128B key",
        );
        let empty_p: const u8[:] = "";
        let hmac384_short = core::hmac_sha384("key", "msg");
        let hmac384_parts_empty = core::hmac_sha384_parts("key", empty_p, empty_p, "msg");
        sub.assert_eq(hmac384_parts_empty[..], hmac384_short[..], "HMAC-SHA384_parts empty p1/p2");
        hex_eq(
            sub, core::hmac_sha512(k131[..], d6)[..],
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
            "HMAC-SHA512 >128B key",
        );
        sub.assert_eq(
            core::hmac_sha512("shortkey", "data")[..].len, 64, "HMAC-SHA512 short key",
        );

        // RFC 5869 Test Case 2 (80B IKM, salt, info; 82B OKM)
        var ikm2:  u8[80] = [0; 80];
        var salt2: u8[80] = [0; 80];
        var info2: u8[80] = [0; 80];
        for i in 80 {
            ikm2[i] = i as u8;
            salt2[i] = (0x60 + i) as u8;
            info2[i] = (0xb0 + i) as u8;
        }
        let prk256 = core::hkdf_extract(salt2[..], ikm2[..]);
        hex_eq(sub, prk256[..], "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244", "HKDF-256 TC2 PRK");
        let empty_salt: const u8[:] = "";
        let prk_nosalt = core::hkdf_extract(empty_salt, ikm2[..]);
        sub.assert_eq(prk_nosalt[..].len, 32, "HKDF-256 empty salt");
        var okm256: u8[82] = [0; 82];
        sub.assert_true(core::hkdf_expand_bytes_256(prk256[..], info2[..], 82, okm256[..]));
        hex_eq(
            sub, okm256[..],
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
            "HKDF-256 TC2 OKM",
        );

        let prk384 = core::hkdf_extract_384(salt2[..], ikm2[..]);
        hex_eq(
            sub, prk384[..],
            "b319f6831dff9314efb643baa29263b30e4a8d779fe31e9c901efd7de737c85b62e676d4dc87b0895c6a7dc97b52cebb",
            "HKDF-384 TC2 PRK",
        );
        var okm384: u8[82] = [0; 82];
        sub.assert_true(core::hkdf_expand_bytes_384(prk384[..], info2[..], 82, okm384[..]));
        hex_eq(
            sub, okm384[..],
            "484ca052b8cc724fd1c4ec64d57b4e818c7e25a8e0f4569ed72a6a05fe0649eebf69f8d5c832856bf4e4fbc17967d54975324a94987f7f41835817d8994fdbd6f4c09c5500dca24a56222fea53d8967a8b2e",
            "HKDF-384 TC2 OKM",
        );
        sub.assert_eq(core::hkdf_extract_384("", ikm2[..])[..].len, 48, "HKDF-384 empty salt");
        sub.assert_false(core::hkdf_expand_bytes_256(prk256[..], "", 8161, okm256[..]), "255*32 limit");
        sub.assert_false(core::hkdf_expand_bytes_384(prk384[..], "", 12241, okm384[..]), "255*48 limit");
    };
}

// ---- 4. AES-GCM & ChaCha20 / HChaCha20 / Poly1305 / XChaCha20-Poly1305 ------

fn test_aes_and_chacha_extended(t: lit::T&) {
    t.run("AES-GCM short dst, partial overlap, prepared errors, >2048B HKDF & open") { sub =>
        let k16: u8[16] = [0x11; 16];
        let k32: u8[32] = [0x22; 32];
        let s32: u8[32] = [0x33; 32];
        let iv:  u8[12] = [0x44; 12];
        var small_dst: u8[4] = [0; 4];

        let _, _, ok_s1 = core::aes128_gcm_seal(k16, iv, "12345", "", small_dst[..]);
        let _, ok_o1 = core::aes128_gcm_open_into(k16, iv, "12345", "", k16, small_dst[..]);
        let _, ok_o2 = core::aes256_gcm_open_into(k32, iv, "12345", "", k16, small_dst[..]);
        sub.assert_false(ok_s1 || ok_o1 || ok_o2, "short dst rejected");

        // Partial slice overlap triggers C-shim fail-closed guard
        var ov: u8[32] = [0xAA; 32];
        let _, _, ok_ov_seal = core::aes128_gcm_seal(k16, iv, ov[0..16], "", ov[1..17]);
        let _, ok_ov_open = core::aes128_gcm_open_into(k16, iv, ov[0..16], "", k16, ov[1..17]);
        sub.assert_false(ok_ov_seal || ok_ov_open, "partial overlap rejected");

        // Prepared key negative paths
        var ctx = core::AesGcmKey { .. };
        var dst16: u8[16] = [0; 16];
        let _, ok_unprep_open = core::aes_gcm_open_prepared_into(ctx, iv, ov[..16], "", k16, dst16[..]);
        let _, _, ok_unprep_ip = core::aes_gcm_seal_prepared_inplace(ctx, iv, ov[..16], "");
        sub.assert_false(ok_unprep_open || ok_unprep_ip, "unprepared ctx rejected");
        sub.assert_true(core::aes_gcm_prepare_key(k16[..], ctx));
        let _, ok_short_prep = core::aes_gcm_open_prepared_into(ctx, iv, ov[..16], "", k16, small_dst[..]);
        let _, _, ok_ov_prep = core::aes_gcm_seal_prepared(ctx, iv, ov[0..16], "", ov[1..17]);
        sub.assert_false(ok_short_prep || ok_ov_prep, "prepared short dst / overlap rejected");

        // >2048B pure-Goose aes128/256_gcm_open + hkdf_aes256_gcm_open + fixed buffer overflow
        var pt_big: u8[2065] = [0; 2065];
        for i in 2065 { pt_big[i] = ((i * 13 + 7) & 0xFF) as u8; }
        var ct_big: u8[2065] = [0; 2065];
        let tag_h, _, ok_hs = core::hkdf_aes256_gcm_seal(k32, s32, iv, pt_big[..], "aad", ct_big[..]);
        sub.assert_true(ok_hs);
        var out_big: u8[>..] = [];
        sub.assert_true(core::hkdf_aes256_gcm_open(k32, s32, iv, ct_big[..], "aad", tag_h, out_big));
        sub.assert_eq(out_big[..], pt_big[..], "hkdf_aes256_gcm_open >2048B matches");

        var tiny_big: u8[..2050] = [];
        sub.assert_false(core::aes256_gcm_open(k32, iv, ct_big[..], "aad", tag_h, tiny_big));
        sub.assert_eq(tiny_big.len, 0, "aes256_gcm_open >2048B overflow clears out");

        let tag128, _, ok_128s = core::aes128_gcm_seal(k16, iv, pt_big[..], "aad", ct_big[..]);
        sub.assert_true(ok_128s);
        var bad_t = tag128;
        bad_t[0] ^= 1;
        sub.assert_false(core::aes128_gcm_open(k16, iv, ct_big[..], "aad", bad_t, tiny_big));
        sub.assert_false(core::aes128_gcm_open(k16, iv, ct_big[..], "aad", tag128, tiny_big));
        sub.assert_eq(tiny_big.len, 0, "aes128_gcm_open >2048B overflow clears out");

        // <=2048B aes128/256_gcm_open paths (aes_gcm_open_small) + aes256_decrypt_block + fusion
        var ct32: u8[32] = [0; 32];
        let pt32 = "0123456789abcdef0123456789abcdef";
        let tag32_256, _, _ = core::aes256_gcm_seal(k32, iv, pt32, "aad", ct32[..]);
        var dec32_ok: u8[..64] = [];
        var dec32_sm: u8[..8]  = [];
        sub.assert_true(core::aes256_gcm_open(k32, iv, ct32[..], "aad", tag32_256, dec32_ok));
        sub.assert_bytes_eq(dec32_ok[..], pt32);
        sub.assert_false(core::aes256_gcm_open(k32, iv, ct32[..], "aad", tag32_256, dec32_sm));
        let tag32_128, _, _ = core::aes128_gcm_seal(k16, iv, pt32, "aad", ct32[..]);
        dec32_ok.clear();
        sub.assert_true(core::aes128_gcm_open(k16, iv, ct32[..], "aad", tag32_128, dec32_ok));
        sub.assert_bytes_eq(dec32_ok[..], pt32);

        let ks256 = core::aes256_key_schedule(k32);
        let blk16: u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let dec_blk = core::aes256_decrypt_block(ks256, blk16);
        sub.assert_eq(dec_blk[..].len, 16, "aes256_decrypt_block");
    };

    t.run("RFC 8439 ChaCha20 / Poly1305 & draft HChaCha20 / XChaCha20-Poly1305") { sub =>
        // RFC 8439 Section 2.3.2 ChaCha20 Block
        var k_rfc: u8[32] = [0; 32];
        for i in 32 { k_rfc[i] = i as u8; }
        let n_rfc: u8[12] = [0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00];
        let blk = core::chacha20_block(k_rfc, 1, n_rfc);
        sub.assert_eq(blk[0], 0x10);
        sub.assert_eq(blk[1], 0xf1);
        sub.assert_eq(blk[62], 0x3c);
        sub.assert_eq(blk[63], 0x4e);

        // chacha20_xor empty + counter overflow + buffer overflow
        var xor_out: u8[..80] = [];
        sub.assert_true(core::chacha20_xor(k_rfc, 1, n_rfc, "", xor_out));
        var pt80: u8[80] = [0x41; 80];
        sub.assert_false(core::chacha20_xor(k_rfc, 0xFFFFFFFF, n_rfc, pt80[..], xor_out), "counter overflow");
        var tiny_xor: u8[..10] = [];
        sub.assert_false(core::chacha20_xor(k_rfc, 1, n_rfc, pt80[..], tiny_xor), "dst overflow");

        // draft-irtf-cfrg-xchacha Section 2.2.1 HChaCha20
        let hn: u8[16] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59, 0x27,
        ];
        hex_eq(
            sub, core::hchacha20(k_rfc, hn)[..],
            "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc",
            "HChaCha20 vector",
        );

        // XChaCha20-Poly1305: empty PT, >16B AAD, >16B CT, overflow rollback
        var n24: u8[24]   = [0x55; 24];
        var xct: u8[..64] = [];
        let xtag0, ok_xs0 = core::xchacha20_poly1305_seal(k_rfc, n24, "", "aad_longer_than_16_bytes!", xct);
        sub.assert_true(ok_xs0 && xct.len == 0);
        var xpt0: u8[..64] = [];
        sub.assert_true(core::xchacha20_poly1305_open(k_rfc, n24, xct[..], "aad_longer_than_16_bytes!", xtag0, xpt0));

        var tiny_x: u8[..4] = [];
        tiny_x.append("keep");
        let _, ok_x_tiny = core::xchacha20_poly1305_seal(k_rfc, n24, "0123456789", "", tiny_x);
        sub.assert_false(ok_x_tiny && tiny_x.len != 4, "xchacha seal capacity check");
        var xct_big: u8[..128] = [];
        let xtag_b, ok_xsb = core::xchacha20_poly1305_seal(k_rfc, n24, pt80[..], "1234567890abcdef", xct_big);
        sub.assert_true(ok_xsb);
        sub.assert_false(core::xchacha20_poly1305_open(k_rfc, n24, xct_big[..], "1234567890abcdef", xtag_b, tiny_x));

        // ChaCha20-Poly1305 >2048B pure-Goose open + error guards
        var pt_2100: u8[2100] = [0; 2100];
        for i in 2100 { pt_2100[i] = (i & 0xFF) as u8; }
        var ct_2100: u8[2100] = [0; 2100];
        let tag_2100, n_c21, ok_c21 = core::chacha20_poly1305_seal(
            k_rfc, n_rfc, pt_2100[..], "0123456789abcdef1234", ct_2100[..],
        );
        sub.assert_true(ok_c21 && n_c21 == 2100);
        var out_2100: u8[>..] = [];
        sub.assert_true(core::chacha20_poly1305_open(
            k_rfc, n_rfc, ct_2100[..], "0123456789abcdef1234", tag_2100, out_2100,
        ));
        sub.assert_eq(out_2100[..], pt_2100[..], "chacha20_poly1305_open >2048B matches");

        var bad_ctag = tag_2100;
        bad_ctag[0] ^= 1;
        var out_small: u8[..100] = [];
        sub.assert_false(core::chacha20_poly1305_open(k_rfc, n_rfc, ct_2100[..], "0123456789abcdef1234", bad_ctag, out_small));
        sub.assert_false(core::chacha20_poly1305_open(k_rfc, n_rfc, ct_2100[..], "0123456789abcdef1234", tag_2100, out_small));

        // Short dst & partial overlap on ChaCha20-Poly1305
        var ov: u8[32] = [0; 32];
        let _, _, ok_cs = core::chacha20_poly1305_seal(k_rfc, n_rfc, "12345", "", ov[..4]);
        let _, ok_co = core::chacha20_poly1305_open_into(k_rfc, n_rfc, "12345", "", tag_2100, ov[..4]);
        let _, _, ok_cov = core::chacha20_poly1305_seal(k_rfc, n_rfc, ov[0..16], "", ov[1..17]);
        let _, ok_coov = core::chacha20_poly1305_open_into(k_rfc, n_rfc, ov[0..16], "", tag_2100, ov[1..17]);
        sub.assert_false(ok_cs || ok_co || ok_cov || ok_coov, "chacha short dst / overlap rejected");

        // <=2048B chacha20_poly1305_open (small path + short buf) & XChaCha20 wrong tag & poly1305_mac
        var c32: u8[32] = [0; 32];
        let t32, _, _ = core::chacha20_poly1305_seal(k_rfc, n_rfc, "0123456789abcdef0123456789abcdef", "aad", c32[..]);
        var d32:    u8[..64] = [];
        var d32_sm: u8[..4]  = [];
        sub.assert_true(core::chacha20_poly1305_open(k_rfc, n_rfc, c32[..], "aad", t32, d32));
        sub.assert_false(core::chacha20_poly1305_open(k_rfc, n_rfc, c32[..], "aad", t32, d32_sm));
        var bad_xt = xtag_b;
        bad_xt[0] ^= 1;
        sub.assert_false(core::xchacha20_poly1305_open(k_rfc, n24, xct_big[..], "1234567890abcdef", bad_xt, d32));
        let mac16 = core::poly1305_mac(k_rfc, "Cryptographic Forum Research Group");
        sub.assert_eq(mac16[..].len, 16, "poly1305_mac");
    };
}

// ---- 5. X25519 (RFC 7748) & Ed25519 (RFC 8032) -----------------------------

fn test_x25519_and_ed25519(t: lit::T&) {
    t.run("RFC 7748 X25519 base_scalarmult & low-order point rejection") { sub =>
        let alice_sk: u8[32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let alice_pk = core::x25519_base_scalarmult(alice_sk);
        hex_eq(
            sub, alice_pk[..],
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            "RFC 7748 Alice public key",
        );

        let low_order_zero: u8[32] = [0; 32];
        let _, ok_low = core::x25519_shared_secret(alice_sk, low_order_zero);
        sub.assert_false(ok_low, "X25519 rejects all-zero shared secret");
        let bob_sk: u8[32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
            0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
            0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
            0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
        ];
        let bob_pk = core::x25519_base_scalarmult(bob_sk);
        let ss_x, ok_x = core::x25519_shared_secret(alice_sk, bob_pk);
        sub.assert_true(ok_x);
        hex_eq(sub, ss_x[..], "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", "RFC 7748 SS");
    };

    t.run("RFC 8032 Ed25519 vectors, keypair, and canonical/torsion rejections") { sub =>
        // RFC 8032 §7.1 Test 1 (empty) & Test 2 (0x72)
        let seed1: u8[32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
            0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
            0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
            0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
        ];
        let kp1 = core::ed25519_keypair(seed1);
        hex_eq(sub, kp1.public_key[..], "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "RFC 8032 pub1");
        let sig1 = core::ed25519_sign(seed1, "");
        sub.assert_true(core::ed25519_verify(kp1.public_key, "", sig1), "RFC 8032 Test 1");
        sub.assert_false(core::ed25519_verify(kp1.public_key, "x", sig1), "tampered msg rejected");

        // Malleable S >= L rejection
        var bad_sig_s = sig1;
        bad_sig_s[63] = 0x10;
        for i in 32 { bad_sig_s[32 + i] = core::ED25519_L_BYTES[i]; }
        sub.assert_false(core::ed25519_verify(kp1.public_key, "", bad_sig_s), "S == L rejected");
        bad_sig_s[32] = 0xEE;
        sub.assert_false(core::ed25519_verify(kp1.public_key, "", bad_sig_s), "S > L rejected");

        // Decompress edge cases: y >= p, non-square y=2, sqrt(-1) y=3, x==0 with sign=1, torsion points
        var y_ge_p: u8[32] = [0xFF; 32];
        y_ge_p[0] = 0xED;
        y_ge_p[31] = 0x7F;
        sub.assert_false(core::ed25519_verify(y_ge_p, "", sig1), "y == p rejected");

        var y_non_sq: u8[32] = [0; 32];
        y_non_sq[0] = 2;
        sub.assert_false(core::ed25519_verify(y_non_sq, "", sig1), "non-square u/v rejected");

        var y_sqrt_m1: u8[32] = [0; 32];
        y_sqrt_m1[0] = 3;
        var pt_m1 = core::EdPoint { .. };
        sub.assert_true(core::ed25519_point_decompress(y_sqrt_m1, pt_m1), "sqrt(-1) decompress branch");

        var x0_neg: u8[32] = [0; 32];
        x0_neg[0] = 1;
        x0_neg[31] = 0x80;
        sub.assert_false(core::ed25519_verify(x0_neg, "", sig1), "x==0 with sign=1 rejected");

        var id_pt: u8[32] = [0; 32];
        id_pt[0] = 1;
        sub.assert_false(core::ed25519_verify(id_pt, "", sig1), "small-order identity pubkey rejected");

        var sig_small_r = sig1;
        for i in 32 { sig_small_r[i] = id_pt[i]; }
        sub.assert_false(core::ed25519_verify(kp1.public_key, "", sig_small_r), "small-order R rejected");

        var bad_r_pt = sig1;
        bad_r_pt[0] = 2;
        for i in 1..32 { bad_r_pt[i] = 0; }
        sub.assert_false(core::ed25519_verify(kp1.public_key, "", bad_r_pt), "invalid R point rejected");

        // Exercise both x-parity branches in ed25519_point_compress and y_bytes[31-i]<0xFF loop
        for s_byte: u8 in 4 {
            var s_var: u8[32] = [s_byte; 32];
            let kp_s = core::ed25519_keypair(s_var);
            let sig_s = core::ed25519_sign(s_var, "parity");
            sub.assert_true(core::ed25519_verify(kp_s.public_key, "parity", sig_s));
        }
        var y_mid: u8[32] = [0xFF; 32];
        y_mid[30] = 0xFE;
        y_mid[31] = 0x7F;
        var pt_mid = core::EdPoint { .. };
        let _ = core::ed25519_point_decompress(y_mid, pt_mid);
    };
}

// ---- 6. ECDSA P-256 & P-384 + ECDH -----------------------------------------

fn test_ecdsa_and_ecdh(t: lit::T&) {
    t.run("ECDSA P-256 & ECDH edge cases and malformed DER") { sub =>
        let zero32: u8[32] = [0; 32];
        sub.assert_eq(core::ecdsa_p256_public_key(zero32)[0], 0, "P-256 zero priv returns zeros");
        sub.assert_eq(core::ecdsa_p256_sign(zero32, "hi")[0], 0, "P-256 zero priv sign returns zeros");

        var priv_a: u8[32] = [0; 32];
        var priv_b: u8[32] = [0; 32];
        priv_a[31] = 7;
        priv_b[31] = 11;
        let pub_a = core::ecdsa_p256_public_key(priv_a);
        let pub_b = core::ecdsa_p256_public_key(priv_b);
        let ss1, ok1 = core::p256_ecdh_shared_secret(priv_a, pub_b[..]);
        let ss2, ok2 = core::p256_ecdh_shared_secret(priv_b, pub_a[..]);
        sub.assert_true(ok1 && ok2 && ss1[..] == ss2[..], "P-256 ECDH symmetric");

        let _, ok_bad_k = core::p256_ecdh_shared_secret(zero32, pub_b[..]);
        var bad_pub = pub_b;
        bad_pub[64] ^= 1;
        let _, ok_bad_pt = core::p256_ecdh_shared_secret(priv_a, bad_pub[..]);
        sub.assert_false(ok_bad_k || ok_bad_pt, "P-256 ECDH rejects zero scalar & off-curve");

        // Encode DER with leading zero bytes & high-bit 0x80 padding
        var raw_pad: u8[64] = [0; 64];
        raw_pad[3] = 0x80;
        raw_pad[35] = 0x80;
        var der_pad: u8[..72] = [];
        sub.assert_true(core::ecdsa_p256_encode_der_sig(raw_pad, der_pad));
        var dec_pad: u8[64] = [0; 64];
        sub.assert_true(core::ecdsa_p256_decode_der_sig(der_pad[..], dec_pad));
        sub.assert_eq(dec_pad[..], raw_pad[..], "DER roundtrip strips/restores leading zeros");

        // Malformed DER signatures
        var out64: u8[64] = [0; 64];
        let bad_der_neg: u8[8] = [0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01];
        let bad_der_r0:  u8[8] = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01];
        let bad_der_tr:  u8[9] = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00];
        let bad_der_big: u8[8] = [0x30, 0x06, 0x02, 0x22, 0x01, 0x01, 0x02, 0x01];
        sub.assert_false(core::ecdsa_p256_decode_der_sig(bad_der_neg[..], out64));
        sub.assert_false(core::ecdsa_p256_decode_der_sig(bad_der_r0[..], out64));
        sub.assert_false(core::ecdsa_p256_decode_der_sig(bad_der_tr[..], out64));
        sub.assert_false(core::ecdsa_p256_decode_der_sig(bad_der_big[..], out64));
        sub.assert_false(core::ecdsa_p256_verify(bad_pub[..], "m", out64[..]), "bad raw sig rejected");

        // P-256 negative & edge checks: s_pad=false, bad prefix/len, off-curve/infinity, raw_pt guards, custom u256_mul_mod
        var raw_nopad: u8[64] = [0; 64];
        raw_nopad[31] = 5;
        raw_nopad[63] = 7;
        var der_nopad: u8[..72] = [];
        sub.assert_true(core::ecdsa_p256_encode_der_sig(raw_nopad, der_nopad));
        sub.assert_false(core::ecdsa_p256_decode_der_sig("123", out64));
        let bad_der_s2:       u8[8] = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00];
        let bad_der_s3:       u8[8] = [0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x01];
        let bad_der_short_s:  u8[6] = [0x30, 0x04, 0x02, 0x01, 0x01, 0x02];
        let bad_der_exact_tr: u8[9] = [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00];
        var bad_der_r33: u8[41] = [0; 41];
        bad_der_r33[0] = 0x30; bad_der_r33[1] = 39;
        bad_der_r33[2] = 0x02; bad_der_r33[3] = 33; bad_der_r33[4] = 0x01;
        bad_der_r33[37] = 0x02; bad_der_r33[38] = 1; bad_der_r33[39] = 1;
        sub.assert_false(core::ecdsa_p256_decode_der_sig(bad_der_s2[..], out64));
        sub.assert_false(core::ecdsa_p256_decode_der_sig(bad_der_s3[..], out64));
        sub.assert_false(core::ecdsa_p256_decode_der_sig(bad_der_short_s[..], out64));
        sub.assert_false(core::ecdsa_p256_decode_der_sig(bad_der_exact_tr[..], out64));
        sub.assert_false(core::ecdsa_p256_decode_der_sig(bad_der_r33[..], out64));
        let sig_ok256 = core::ecdsa_p256_sign(priv_a, "ok256");
        var der_ok256: u8[..72] = [];
        sub.assert_true(core::ecdsa_p256_encode_der_sig(sig_ok256, der_ok256));
        sub.assert_true(core::ecdsa_p256_verify(pub_a[..], "ok256", der_ok256[..]));

        var ord256_be: u8[32] = [0; 32];
        for wi in 8 {
            let w = core::P256_ORDER[7 - wi];
            ord256_be[wi * 4] = ((w >> 24) & 0xFF) as u8;
            ord256_be[wi * 4 + 1] = ((w >> 16) & 0xFF) as u8;
            ord256_be[wi * 4 + 2] = ((w >> 8) & 0xFF) as u8;
            ord256_be[wi * 4 + 3] = (w & 0xFF) as u8;
        }
        let _, ok_inf256 = core::p256_ecdh_shared_secret(ord256_be, pub_b[..]);
        sub.assert_false(ok_inf256, "P-256 scalar == N yields infinity rejected");
        sub.assert_false(core::ecdsa_p256_verify_der(bad_pub[..], "m", der_nopad[..]));
        sub.assert_false(core::ecdsa_p256_verify_p1363(pub_a[..], "m", "short"));
        sub.assert_false(core::ecdsa_p256_verify_p1363(bad_pub[..], "m", raw_nopad[..]));
        sub.assert_false(core::ecdsa_p256_verify(bad_pub[..50], "m", der_nopad[..]));

        let g256 = core::P256Point { x: core::U256 { v: core::P256_GX }, y: core::U256 { v: core::P256_GY }, infinity: false };
        sub.assert_false(core::p256_is_on_curve(core::P256Point { infinity: true, .. }));
        let over_mod = core::P256Point { x: core::U256 { v: core::P256_MOD }, y: core::U256 { v: core::P256_GY }, infinity: false };
        sub.assert_false(core::p256_is_on_curve(over_mod));
        var bad_r0: u8[64] = [0; 64];
        bad_r0[63] = 1;
        sub.assert_false(core::ecdsa_p256_verify_raw_pt(g256, core::U256 { v: [1, 0, 0, 0, 0, 0, 0, 0] }, bad_r0));
        var bad_s0: u8[64] = [0; 64];
        bad_s0[31] = 1;
        sub.assert_false(core::ecdsa_p256_verify_raw_pt(g256, core::U256 { v: [1, 0, 0, 0, 0, 0, 0, 0] }, bad_s0));
        // u1 = P256_ORDER - 1, u2 = 1 => u1*G + u2*G = P256_ORDER*G = infinity
        var inf_z = core::P256_ORDER;
        inf_z[0] -= 1;
        var inf_rs: u8[64] = [0; 64];
        inf_rs[31] = 1;
        inf_rs[63] = 1;
        sub.assert_false(core::ecdsa_p256_verify_raw_pt(g256, core::U256 { v: inf_z }, inf_rs));

        let c_m256: u32[8] = [101, 0, 0, 0, 0, 0, 0, 0];
        let c_r256 = core::u256_mul_mod(core::U256 { v: [2, 0, 0, 0, 0, 0, 0, 0] }, core::U256 { v: [70, 0, 0, 0, 0, 0, 0, 0] }, c_m256);
        sub.assert_eq(c_r256.v[0], 39);
    };

    t.run("ECDSA P-384 & ECDH + DER verification") { sub =>
        let zero48: u8[48] = [0; 48];
        let _, ok_z = core::p384_ecdh_public_key(zero48);
        sub.assert_false(ok_z, "P-384 ECDH rejects zero priv");
        sub.assert_eq(core::ecdsa_p384_public_key(zero48)[0], 0, "P-384 zero priv returns zeros");
        sub.assert_eq(core::ecdsa_p384_sign(zero48, "hi")[0], 0, "P-384 zero priv sign returns zeros");

        var priv_a: u8[48] = [0; 48];
        var priv_b: u8[48] = [0; 48];
        priv_a[47] = 9;
        priv_b[47] = 13;
        let pub_a, ok_pa = core::p384_ecdh_public_key(priv_a);
        let pub_b, ok_pb = core::p384_ecdh_public_key(priv_b);
        sub.assert_true(ok_pa && ok_pb);
        let ss1, ok_s1 = core::p384_ecdh_shared_secret(priv_a, pub_b[..]);
        let ss2, ok_s2 = core::p384_ecdh_shared_secret(priv_b, pub_a[..]);
        sub.assert_true(ok_s1 && ok_s2 && ss1[..] == ss2[..], "P-384 ECDH symmetric");

        // Sign and verify via DER encoding
        let sig96 = core::ecdsa_p384_sign(priv_a, "p384-der-message");
        var der96: u8[..110] = [];
        der96.push(0x30);
        der96.push(0x00);
        for side in 2 {
            let off = side * 48;
            let need_pad = (sig96[off] & 0x80) != 0;
            der96.push(0x02);
            der96.push((48 + (if need_pad { 1 } else { 0 })) as u8);
            if need_pad { der96.push(0x00); }
            der96.append(sig96[off..off + 48]);
        }
        der96[1] = (der96.len - 2) as u8;
        sub.assert_true(core::ecdsa_p384_verify_der(pub_a[..], "p384-der-message", der96[..]), "P-384 DER verify");
        sub.assert_true(core::ecdsa_p384_verify(pub_a[..], "p384-der-message", der96[..]), "P-384 auto DER");
        sub.assert_false(core::ecdsa_p384_verify_der(pub_a[..], "tampered", der96[..]), "P-384 DER tamper");

        // P-384 ECDH/DER/raw_pt negative & edge paths
        var bad_pub384 = pub_b;
        bad_pub384[96] ^= 1;
        let _, ok_384_bp = core::p384_ecdh_shared_secret(priv_a, bad_pub384[..]);
        let _, ok_384_zk = core::p384_ecdh_shared_secret(zero48, pub_b[..]);
        let _, ok_384_bl = core::p384_ecdh_shared_secret(priv_a, bad_pub384[..10]);
        sub.assert_false(ok_384_bp || ok_384_zk || ok_384_bl);

        var out96: u8[96] = [0; 96];
        let bad_384_s0:       u8[9] = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00];
        let bad_384_badlen:   u8[8] = [0x30, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        let bad_384_r:        u8[8] = [0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x01];
        let bad_384_s:        u8[8] = [0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x01];
        let bad_384_tr_exact: u8[9] = [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00];
        sub.assert_false(core::ecdsa_p384_decode_der_sig("123", out96));
        sub.assert_false(core::ecdsa_p384_decode_der_sig(bad_384_badlen[..], out96));
        sub.assert_false(core::ecdsa_p384_decode_der_sig(bad_384_s0[..], out96));
        sub.assert_false(core::ecdsa_p384_decode_der_sig(bad_384_r[..], out96));
        sub.assert_false(core::ecdsa_p384_decode_der_sig(bad_384_s[..], out96));
        sub.assert_false(core::ecdsa_p384_decode_der_sig(bad_384_tr_exact[..], out96));

        var ord384_be: u8[48] = [0; 48];
        for wi in 12 {
            let w = core::P384_ORDER[11 - wi];
            ord384_be[wi * 4] = ((w >> 24) & 0xFF) as u8;
            ord384_be[wi * 4 + 1] = ((w >> 16) & 0xFF) as u8;
            ord384_be[wi * 4 + 2] = ((w >> 8) & 0xFF) as u8;
            ord384_be[wi * 4 + 3] = (w & 0xFF) as u8;
        }
        let _, ok_inf384 = core::p384_ecdh_shared_secret(ord384_be, pub_b[..]);
        sub.assert_false(ok_inf384, "P-384 scalar == N yields infinity rejected");

        sub.assert_false(core::ecdsa_p384_verify_der(bad_pub384[..], "p384-der-message", der96[..]));
        sub.assert_false(core::ecdsa_p384_verify_p1363(pub_a[..], "m", "short"));
        sub.assert_false(core::ecdsa_p384_verify_p1363(bad_pub384[..], "m", sig96[..]));
        sub.assert_false(core::p384_is_on_curve(core::P384Point { infinity: true, .. }));
        sub.assert_false(core::p384_is_on_curve(core::P384Point { x: core::U384 { v: core::P384_MOD }, y: core::U384 { v: core::P384_GY }, infinity: false }));

        let g384 = core::P384Point { x: core::U384 { v: core::P384_GX }, y: core::U384 { v: core::P384_GY }, infinity: false };
        var inf384_z = core::P384_ORDER;
        inf384_z[0] -= 1;
        var inf384_rs: u8[96] = [0; 96];
        inf384_rs[47] = 1;
        sub.assert_false(core::ecdsa_p384_verify_raw_pt(g384, core::U384 { v: inf384_z }, inf384_rs));
        inf384_rs[47] = 0;
        inf384_rs[95] = 1;
        sub.assert_false(core::ecdsa_p384_verify_raw_pt(g384, core::U384 { v: inf384_z }, inf384_rs));
        inf384_rs[47] = 1;
        sub.assert_false(core::ecdsa_p384_verify_raw_pt(g384, core::U384 { v: inf384_z }, inf384_rs));

        let c_m384: u32[12] = [101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let c_r384 = core::u384_mul_mod(core::U384 { v: [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }, core::U384 { v: [70, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }, c_m384);
        sub.assert_eq(c_r384.v[0], 39);
    };
}

// ---- 7. RSA PKCS#1 v1.5, PSS (SHA-256/384/512), DER, ModExp & Blinding -----

fn build_rsa_spki_der(n_be: const u8[:], e_be: const u8[:], out: u8[..600]&) {
    var body: u8[..600] = [];
    // N INTEGER
    body.push(0x02);
    let n_pad = (n_be[0] & 0x80) != 0;
    let n_len = n_be.len + (if n_pad { 1 } else { 0 });
    if n_len >= 256 {
        body.push(0x82);
        body.push(((n_len >> 8) & 0xFF) as u8);
        body.push((n_len & 0xFF) as u8);
    } else {
        body.push(0x81);
        body.push(n_len as u8);
    }
    if n_pad { body.push(0x00); }
    body.append(n_be);
    // E INTEGER
    body.push(0x02);
    body.push(e_be.len as u8);
    body.append(e_be);
    // Outer SEQUENCE
    out.clear();
    out.push(0x30);
    if body.len >= 256 {
        out.push(0x82);
        out.push(((body.len >> 8) & 0xFF) as u8);
        out.push((body.len & 0xFF) as u8);
    } else {
        out.push(0x81);
        out.push(body.len as u8);
    }
    out.append(body[..]);
}

fn test_rsa_full_suite(t: lit::T&) {
    t.run("RSA DER parsing, exponent rules, PKCS#1 v1.5 & PSS SHA-256/384/512") { sub =>
        var der2048: u8[..600] = [];
        build_rsa_spki_der(RSA2048_N[..], RSA2048_E[..], der2048);

        var sig_pkcs1: u8[..512] = [];
        sub.assert_true(core::rsa_pkcs1_sha256_sign_blinded(
            RSA2048_N[..], RSA2048_D[..], RSA2048_E[..], "rsa-der-msg", sig_pkcs1,
        ));
        sub.assert_true(core::rsa_pkcs1_sha256_verify_der(der2048[..], "rsa-der-msg", sig_pkcs1[..]));
        sub.assert_false(core::rsa_pkcs1_sha256_verify_der(der2048[..], "bad-msg", sig_pkcs1[..]));

        sub.assert_true(core::rsa_pkcs1_sha384_verify(
            RSA2048_N[..], RSA2048_E[..], "wing-rsa-sha384-vector", TEST_SIG_PKCS1_SHA384[..],
        ));
        sub.assert_false(core::rsa_pkcs1_sha384_verify(
            RSA2048_N[..], RSA2048_E[..], "wrong", TEST_SIG_PKCS1_SHA384[..],
        ));

        let salt32: u8[32] = [0x77; 32];
        var sig_pss256: u8[..512] = [];
        sub.assert_true(core::rsa_pss_sha256_sign_blinded(
            RSA2048_N[..], RSA2048_D[..], RSA2048_E[..], salt32[..], "pss256-der", sig_pss256,
        ));
        sub.assert_true(core::rsa_pss_sha256_verify_der(der2048[..], "pss256-der", sig_pss256[..]));

        sub.assert_true(core::rsa_pss_sha384_verify_der(
            der2048[..], "wing-rsa-sha384-vector", TEST_SIG_PSS_SHA384[..],
        ));
        sub.assert_false(core::rsa_pss_sha384_verify_der(
            der2048[..], "tampered", TEST_SIG_PSS_SHA384[..],
        ));

        let salt64: u8[64] = [0x99; 64];
        var sig_pss512: u8[..512] = [];
        sub.assert_true(core::rsa_pss_sha512_sign(
            RSA2048_N[..], RSA2048_D[..], salt64[..], "pss512-der", sig_pss512,
        ));
        sub.assert_true(core::rsa_pss_sha512_verify_der(der2048[..], "pss512-der", sig_pss512[..]));
    };

    t.run("RSA-2049 (n[0] == 0x01) & RSA-2042 (n[0] == 0x03) PSS top-bit masking") { sub =>
        let salt32: u8[32] = [0x12; 32];
        var sig2049: u8[..512] = [];
        sub.assert_true(core::rsa_pss_sha256_sign_blinded(
            RSA2049_N[..], RSA2049_D[..], RSA2048_E[..], salt32[..], "n-2049-bit", sig2049,
        ));
        sub.assert_true(core::rsa_pss_sha256_verify(RSA2049_N[..], RSA2048_E[..], "n-2049-bit", sig2049[..]));
        sub.assert_false(core::rsa_pss_sha256_verify(RSA2049_N[..], RSA2048_E[..], "tamper", sig2049[..]));

        var der2049: u8[..600] = [];
        build_rsa_spki_der(RSA2049_N[..], RSA2048_E[..], der2049);
        sub.assert_true(core::rsa_pss_sha256_verify_der(der2049[..], "n-2049-bit", sig2049[..]));

        var sig2042: u8[..512] = [];
        sub.assert_true(core::rsa_pss_sha256_sign_blinded(
            RSA2042_N[..], RSA2042_D[..], RSA2048_E[..], salt32[..], "n-2042-bit", sig2042,
        ));
        sub.assert_true(core::rsa_pss_sha256_verify(RSA2042_N[..], RSA2048_E[..], "n-2042-bit", sig2042[..]));
    };

    t.run("RSA negative DER, ModExp, Blinding, MGF1 & PSS validation guards") { sub =>
        // Negative DER cases for parse_rsa_public_key_der
        let bad_empty: u8[0] = [];
        let bad_tag:   u8[4] = [0x02, 0x02, 0x01, 0x01];
        let bad_nlen:  u8[4] = [0x30, 0x83, 0x01, 0x00];
        let _, _, ok_e = core::parse_rsa_public_key_der(bad_empty[..]);
        let _, _, ok_t = core::parse_rsa_public_key_der(bad_tag[..]);
        let _, _, ok_nl = core::parse_rsa_public_key_der(bad_nlen[..]);
        sub.assert_false(ok_e || ok_t || ok_nl, "malformed DER headers rejected");

        // Exponent with leading zero & invalid exponents
        let e_padded: u8[4] = [0x00, 0x01, 0x00, 0x01];
        let e_even:   u8[1] = [0x04];
        let e_eq_n = RSA2048_N;
        sub.assert_true(core::is_valid_rsa_public_exponent(e_padded[..], RSA2048_N[..]));
        sub.assert_false(core::is_valid_rsa_public_exponent(e_even[..], RSA2048_N[..]));
        sub.assert_false(core::is_valid_rsa_public_exponent(e_eq_n[..], RSA2048_N[..]));

        // Blinded & unblinded mod_exp guards
        var out_m: u8[..512] = [];
        sub.assert_false(core::rsa_mod_exp(RSA2048_N[..], RSA2048_E[..], RSA2048_N[..], out_m), "base==m");
        var zero_exp: u8[4]   = [0; 4];
        var base1:    u8[256] = [0; 256];
        base1[255] = 2;
        sub.assert_false(core::rsa_mod_exp(base1[..], zero_exp[..], RSA2048_N[..], out_m), "exp==0");
        sub.assert_false(core::rsa_mod_exp_blinded(
            RSA2048_N[..], RSA2048_D[..], RSA2048_E[..], RSA2048_N[..], out_m,
        ), "blinded base>=m");
        sub.assert_false(core::rsa_mod_exp_exp_blinded(
            base1[..], e_even[..], RSA2048_N[..], out_m,
        ), "exp_blinded short exp");

        // Leading 0x00 byte(s) in exponent must still succeed reliably in rsa_mod_exp_exp_blinded
        var d_prefixed: u8[258] = [0; 258];
        for i in 256 { d_prefixed[i + 2] = RSA2048_D[i]; }
        var msg_rep: u8[256] = [0; 256];
        msg_rep[255] = 42;
        var out_b1: u8[..512] = [];
        var out_b2: u8[..512] = [];
        sub.assert_true(core::rsa_mod_exp(msg_rep[..], RSA2048_D[..], RSA2048_N[..], out_b1));
        for _ in 4 {
            out_b2.clear();
            sub.assert_true(
                core::rsa_mod_exp_exp_blinded(msg_rep[..], d_prefixed[..], RSA2048_N[..], out_b2),
                "leading 0x00 exponent blinding succeeds",
            );
            sub.assert_eq(out_b2[..], out_b1[..], "leading 0x00 blinded equals unblinded");
        }
        let exp_only_zeros_one: u8[3] = [0x00, 0x00, 0x01];
        sub.assert_false(
            core::rsa_mod_exp_exp_blinded(msg_rep[..], exp_only_zeros_one[..], RSA2048_N[..], out_b2),
            "trimmed 1-byte exponent rejected",
        );

        // verify_emsa_pss / encode_emsa_pss negative guards
        let h256 = core::sha256("msg");
        var em_bad: u8[256] = [0; 256];
        em_bad[255] = 0x00;
        sub.assert_false(core::verify_emsa_pss(em_bad[..], h256[..], 0x80), "PSS bad trailer");
        em_bad[255] = 0xBC;
        em_bad[0] = 0x80;
        sub.assert_false(core::verify_emsa_pss(em_bad[..], h256[..], 0x80), "PSS top bits nonzero");
        em_bad[0] = 0x00;
        sub.assert_false(core::verify_emsa_pss(em_bad[..], h256[..], 0xFF), "PSS zero-pad/sep fail");
        var em_out: u8[..512] = [];
        sub.assert_false(core::encode_emsa_pss(h256[..16], h256[..], 256, 0x80, em_out), "PSS bad h_len");

        // Unblinded PKCS#1 sign + verify + bad DER/sig/exponent + PSS SHA-384/512 negative + RSA2049 em[0]!=0
        var sig_p1_unb: u8[..512] = [];
        sub.assert_true(core::rsa_pkcs1_sha256_sign(RSA2048_N[..], RSA2048_D[..], "unblinded-p1", sig_p1_unb));
        sub.assert_true(core::rsa_pkcs1_sha256_verify(RSA2048_N[..], RSA2048_E[..], "unblinded-p1", sig_p1_unb[..]));
        sub.assert_false(core::rsa_pkcs1_sha256_verify(RSA2048_N[..], RSA2048_E[..], "unblinded-p1", RSA2048_N[..]), "p1 sig==n");
        sub.assert_false(core::rsa_pkcs1_sha256_verify_der(bad_empty[..], "unblinded-p1", sig_p1_unb[..]), "p1 bad der");
        sub.assert_false(core::rsa_pkcs1_sha384_verify(RSA2048_N[..], e_even[..], "x", TEST_SIG_PKCS1_SHA384[..]), "p1-384 bad e");
        sub.assert_false(core::rsa_pkcs1_sha384_verify(RSA2048_N[..], RSA2048_E[..], "x", RSA2048_N[..]), "p1-384 sig==n");

        let salt32_b: u8[32] = [0x33; 32];
        var sig_pss_unb: u8[..512] = [];
        sub.assert_true(core::rsa_pss_sha256_sign(RSA2048_N[..], RSA2048_D[..], salt32_b[..], "unblinded-pss", sig_pss_unb));
        sub.assert_true(core::rsa_pss_sha256_verify(RSA2048_N[..], RSA2048_E[..], "unblinded-pss", sig_pss_unb[..]));
        sub.assert_false(core::rsa_pss_sha256_verify(RSA2048_N[..], RSA2048_E[..], "x", RSA2048_N[..]), "pss256 sig==n");
        sub.assert_false(core::rsa_pss_sha256_verify_der(bad_empty[..], "x", sig_pss_unb[..]), "pss256 bad der");
        sub.assert_false(core::rsa_pss_sha384_verify(RSA2048_N[..], e_even[..], "x", TEST_SIG_PSS_SHA384[..]), "pss384 bad e");
        sub.assert_false(core::rsa_pss_sha384_verify(RSA2048_N[..], RSA2048_E[..], "x", RSA2048_N[..]), "pss384 sig==n");
        sub.assert_false(core::rsa_pss_sha384_verify_der(bad_empty[..], "x", TEST_SIG_PSS_SHA384[..]), "pss384 bad der");
        sub.assert_false(core::rsa_pss_sha512_verify(RSA2048_N[..], e_even[..], "x", sig_pss_unb[..]), "pss512 bad e");
        sub.assert_false(core::rsa_pss_sha512_verify(RSA2048_N[..], RSA2048_E[..], "x", RSA2048_N[..]), "pss512 sig==n");
        sub.assert_false(core::rsa_pss_sha512_verify_der(bad_empty[..], "x", sig_pss_unb[..]), "pss512 bad der");
        sub.assert_false(core::rsa_pss_sha256_sign(RSA2048_N[..], RSA2048_D[..], h256[..16], "x", sig_pss_unb), "pss256 bad salt");
        sub.assert_false(core::rsa_pss_sha256_sign_blinded(RSA2048_N[..], RSA2048_D[..], RSA2048_E[..], h256[..16], "x", sig_pss_unb), "pss256b bad salt");
        sub.assert_false(core::rsa_pss_sha512_sign(RSA2048_N[..], RSA2048_D[..], h256[..], "x", sig_pss_unb), "pss512 bad salt");

        // RSA2049 em[0] != 0 rejection for PSS SHA-256/384/512
        var em_bad_top: u8[257] = [0; 257];
        em_bad_top[0] = 0x01;
        em_bad_top[1] = 0x00;
        em_bad_top[256] = 0xBC;
        var sig_bad_top: u8[..512] = [];
        if core::rsa_be_cmp(em_bad_top[..], RSA2049_N[..]) < 0 {
            sub.assert_true(core::rsa_mod_exp(em_bad_top[..], RSA2049_D[..], RSA2049_N[..], sig_bad_top));
            sub.assert_false(core::rsa_pss_sha256_verify(RSA2049_N[..], RSA2048_E[..], "x", sig_bad_top[..]), "2049 pss256 top!=0");
            sub.assert_false(core::rsa_pss_sha384_verify(RSA2049_N[..], RSA2048_E[..], "x", sig_bad_top[..]), "2049 pss384 top!=0");
            sub.assert_false(core::rsa_pss_sha512_verify(RSA2049_N[..], RSA2048_E[..], "x", sig_bad_top[..]), "2049 pss512 top!=0");
        }

        // encode_emsa_pss h_len==48 + RSA2049 + low-level limb/exp/DER guards
        let h384 = core::sha384("pss-384");
        var salt48: u8[48]    = [0x22; 48];
        var em48:   u8[..512] = [];
        sub.assert_true(core::encode_pss_for_modulus(h384[..], salt48[..], RSA2049_N[..], em48));
        sub.assert_eq(em48[0], 0x00);

        var e_big = RSA2048_N;
        e_big[255] += 2;
        var e_lt = RSA2048_N;
        e_lt[255] -= 2;
        let e_one: u8[1] = [0x01];
        var e_huge: u8[260] = [0; 260];
        e_huge[0] = 1;
        e_huge[259] = 3;
        sub.assert_false(core::is_valid_rsa_public_exponent("", RSA2048_N[..]), "exp empty");
        sub.assert_false(core::is_valid_rsa_public_exponent(e_one[..], RSA2048_N[..]), "exp 1");
        sub.assert_false(core::is_valid_rsa_public_exponent(e_big[..], RSA2048_N[..]), "exp > n");
        sub.assert_true(core::is_valid_rsa_public_exponent(e_lt[..], RSA2048_N[..]), "exp == n - 2");
        sub.assert_false(core::is_valid_rsa_public_exponent(e_huge[..], RSA2048_N[..]), "exp huge");
        sub.assert_false(core::rsa_mod_exp(bad_empty[..], e_one[..], RSA2048_N[..], out_m), "mod_exp bad base");
        var even_m = RSA2048_N;
        even_m[255] &= 0xFE;
        sub.assert_false(core::rsa_mod_exp(base1[..], RSA2048_E[..], even_m[..], out_m), "mod_exp even m");
        sub.assert_false(core::rsa_mod_exp_blinded(bad_empty[..], RSA2048_D[..], RSA2048_E[..], RSA2048_N[..], out_m), "blinded bad base");
        sub.assert_false(core::rsa_mod_exp_blinded(base1[..], RSA2048_D[..], e_even[..], RSA2048_N[..], out_m), "blinded bad pub_exp");
        core::rsa_be_mul_mod(base1[..10], base1[..10], RSA2048_N[..], out_m);
        sub.assert_eq(out_m.len, 0);

        // RSA 128B (RSA_MIN_MODULUS_BYTES) DER negative tests: neg N, redundant 0x00 N, short N after strip, bad E tag/sign/pad/val, truncated TLV
        var der_trunc: u8[5] = [0x30, 0x81, 0x90, 0x02, 0x01];
        let _, _, ok_tr = core::parse_rsa_public_key_der(der_trunc[..]);
        sub.assert_false(ok_tr, "truncated TLV rejected");

        var n128: u8[128] = [0; 128];
        n128[0] = 0x80;
        n128[127] = 1;
        var der128: u8[..200] = [];
        der128.push(0x30); der128.push(0x81); der128.push(134);
        der128.push(0x02); der128.push(0x81); der128.push(128);
        der128.append(n128[..]);
        der128.push(0x02); der128.push(1); der128.push(3);
        let _, _, ok_neg_n = core::parse_rsa_public_key_der(der128[..]);
        sub.assert_false(ok_neg_n, "DER negative modulus rejected");

        n128[0] = 0x00;
        n128[1] = 0x01;
        let _, _, ok_red_n = core::parse_rsa_public_key_der(der128[..]);
        sub.assert_false(ok_red_n, "DER redundant 0x00 modulus rejected");

        var der_127: u8[..200] = [];
        der_127.push(0x30); der_127.push(0x81); der_127.push(134);
        der_127.push(0x02); der_127.push(0x81); der_127.push(128);
        der_127.push(0x00); der_127.push(0x80);
        for _ in 125 { der_127.push(0x00); }
        der_127.push(0x01);
        der_127.push(0x02); der_127.push(1); der_127.push(3);
        let _, _, ok_127 = core::parse_rsa_public_key_der(der_127[..]);
        sub.assert_false(ok_127, "DER 127B stripped modulus rejected");

        var valid_n128: u8[128] = [0; 128];
        valid_n128[0] = 0x80;
        valid_n128[127] = 1;
        // Negative E (0x80), redundant 0x00 E ([0x00, 0x03]), bad E value (1), bad E tag (0x03)
        var der_e_neg: u8[..200] = [0x30, 0x81, 135, 0x02, 0x81, 129, 0x00];
        der_e_neg.append(valid_n128[..]);
        der_e_neg.push(0x02); der_e_neg.push(1); der_e_neg.push(0x80);
        let _, _, ok_eneg = core::parse_rsa_public_key_der(der_e_neg[..]);
        sub.assert_false(ok_eneg, "DER neg E rejected");
        der_e_neg[der_e_neg.len - 1] = 1;
        let _, _, ok_e1 = core::parse_rsa_public_key_der(der_e_neg[..]);
        sub.assert_false(ok_e1, "DER E=1 rejected");
        der_e_neg[der_e_neg.len - 3] = 0x03;
        let _, _, ok_etag = core::parse_rsa_public_key_der(der_e_neg[..]);
        sub.assert_false(ok_etag, "DER bad E tag rejected");
        var der_e_red: u8[..200] = [0x30, 0x81, 136, 0x02, 0x81, 129, 0x00];
        der_e_red.append(valid_n128[..]);
        der_e_red.push(0x02); der_e_red.push(2); der_e_red.push(0x00); der_e_red.push(0x03);
        let _, _, ok_ered = core::parse_rsa_public_key_der(der_e_red[..]);
        sub.assert_false(ok_ered, "DER redundant 0x00 E rejected");

        // verify_emsa_pss & rsa_mgf1_xor edge guards
        sub.assert_false(core::verify_emsa_pss(h256[..], h256[..], 0x80), "PSS short em_len");
        sub.assert_false(core::verify_emsa_pss(em_bad[..], h256[..], 0x00), "PSS mod_first_byte == 0");
        core::rsa_mgf1_xor(h256[..], 16, em_out[..]);

        var empty_l: u32[0]     = [];
        var zero_l:  u32[2]     = [0, 0];
        var m_l:     u32[2]     = [15, 0];
        var inv_l:   u32[..128] = [];
        sub.assert_false(core::rsa_limbs_is_one(empty_l[..]), "limbs_is_one empty");
        sub.assert_false(core::rsa_limbs_mod_inv(zero_l[..], m_l[..], inv_l), "mod_inv zero r");
        sub.assert_false(core::rsa_limbs_mod_inv(m_l[..], m_l[..], inv_l), "non-coprime mod_inv rejected");
        sub.assert_false(core::rsa_limbs_mod_inv(m_l[..], zero_l[..], inv_l), "mod_inv zero m");
        core::rsa_limbs_to_be(m_l[..], 16, out_m);
        sub.assert_eq(out_m.len, 16);
    };
}

fn main() {
    let runner = lit::new_runner("Core Cryptography Verification Suite");
    lit::run_case(runner, "1. CSPRNG & Constant-Time Primitives", test_csprng_and_ct);
    lit::run_case(runner, "2. Base64 & Base64URL", test_base64_and_base64url);
    lit::run_case(runner, "3. MD5, SHA Family, HMAC & HKDF", test_hashes_hmac_hkdf);
    lit::run_case(runner, "4. AES-GCM & ChaCha20/XChaCha20 Extended", test_aes_and_chacha_extended);
    lit::run_case(runner, "5. X25519 & Ed25519", test_x25519_and_ed25519);
    lit::run_case(runner, "6. ECDSA P-256/P-384 & ECDH", test_ecdsa_and_ecdh);
    lit::run_case(runner, "7. RSA PKCS#1, PSS, DER & Blinding", test_rsa_full_suite);
    assert(lit::finish(runner));
}
