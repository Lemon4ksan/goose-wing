:: SPDX-License-Identifier: Apache-2.0
:: Copyright (c) 2026 Lemon4ksan

@echo off
gcc %* -O2 -mno-avx --param ggc-min-expand=20 --param ggc-min-heapsize=32768 -Wl,--stack,33554432
