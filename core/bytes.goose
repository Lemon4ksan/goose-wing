// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Goose Core Byte String and Zero-Heap Slice Operations Module.
// Provides zero-heap, compile-time inlined abstractions for byte slices:
// - case: ASCII character predicates, case folding, and case conversions.
// - trim: Zero-copy linear whitespace, ASCII whitespace, and byte set trimming.
// - search: Prefix, suffix, subslice scanning, and byte occurrence counting.
// - split: Single-byte and subslice split_once, rsplit, and ByteTokenizer.
// - parse: Strict bounds-checked decimal and hexadecimal integer parsers.
// - format: Zero-heap decimal and hexadecimal integer formatting into appendable buffers.
namespace core;

import std;

import core.bytes.case;
import core.bytes.trim;
import core.bytes.search;
import core.bytes.split;
import core.bytes.parse;
import core.bytes.format;
import core.bytes.utf8;
