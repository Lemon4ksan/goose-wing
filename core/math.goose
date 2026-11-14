// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Mathematical, bitwise, statistical, and non-cryptographic hashing primitives.
// Zero-heap, branchless constant-time arithmetic, Jacobson EWMA (RFC 6298 / RFC 9002 Errata 7539),
// WyRand v4.2, xoroshiro64**, Lemire fast-range, and Happy Eyeballs (RFC 8305) pacing.
namespace core;

import std;

import core.math.ct;
import core.math.bits;
import core.math.arithmetic;
import core.math.random;
import core.math.hash;
import core.math.network;
import core.math.flat_index;
import core.math.bitmask;
