// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build -O0 -o %t.exe cli/main.goose
// RUN: %t.exe --help | %FileCheck %s

import std;

fn main() {}

// CHECK: -F, --form <NAME=VAL>
// CHECK: -C, --continue-at <OFF|->
