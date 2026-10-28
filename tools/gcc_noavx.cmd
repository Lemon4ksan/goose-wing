:: SPDX-License-Identifier: Apache-2.0
:: Copyright (c) 2026 Lemon4ksan

@echo off
gcc %* -mno-avx -Wl,--stack,33554432
