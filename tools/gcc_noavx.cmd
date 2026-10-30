:: SPDX-License-Identifier: Apache-2.0
:: Copyright (c) 2026 Lemon4ksan

@echo off
gcc %* -O3 -mno-avx -fno-ipa-cp-clone --param inline-unit-growth=15 --param max-inline-insns-auto=15 --param max-inline-insns-single=30 --param ggc-min-expand=20 --param ggc-min-heapsize=32768 -Wl,--stack,33554432 -Wl,--allow-multiple-definition
