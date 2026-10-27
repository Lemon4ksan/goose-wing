@echo off
gcc %* -mno-avx -Wl,--stack,33554432
