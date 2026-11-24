# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    valgrind \
    binutils \
    curl \
    ca-certificates \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN curl -sSL --retry 5 --retry-delay 2 --retry-connrefused \
    https://github.com/aardappel/goose/releases/download/v2026.3/goose-v2026.3-linux-x64.tar.gz \
    | tar -xz -C /opt && \
    ln -s /opt/goose-v2026.3-linux-x64/goose /usr/local/bin/goose

COPY . /app

RUN mkdir -p /app/.lit/cache/ctgrind && \
    goose --standalone --header /app/.lit/cache/ctgrind/ctgrind_target.h \
        -o /app/.lit/cache/ctgrind/ctgrind_target.c tools/ctgrind/ctgrind_target.goose && \
    gcc -O2 -g -DUSE_VALGRIND=1 -fno-store-merging -mstackrealign -Wall -Wextra -Werror \
        -c tools/ctgrind/ctgrind_harness.c -o /app/.lit/cache/ctgrind/ctgrind_harness.o && \
    gcc -O2 -g -fno-store-merging -mstackrealign \
        -c /app/.lit/cache/ctgrind/ctgrind_target.c -o /app/.lit/cache/ctgrind/ctgrind_target.o && \
    gcc -O2 -g -fno-store-merging -mstackrealign \
        /app/.lit/cache/ctgrind/ctgrind_target.o /app/.lit/cache/ctgrind/ctgrind_harness.o \
        shim/rio.c shim/uring.c shim/kqueue.c shim/simd.c shim/tcp.c \
        shim/af_xdp.c shim/dpdk.c shim/smartnic.c shim/page_ring.c \
        shim/page_mem.c shim/spsc.c shim/tls_backend.c \
        -lpthread -lm -ldl -o /app/.lit/cache/ctgrind/ctgrind_harness

ENTRYPOINT ["valgrind", "--error-exitcode=42", "--track-origins=yes", "/app/.lit/cache/ctgrind/ctgrind_harness"]
