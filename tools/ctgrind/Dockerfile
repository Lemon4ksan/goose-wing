# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    gcc \
    g++ \
    git \
    valgrind \
    binutils \
    curl \
    ca-certificates \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN git clone --depth 1 https://github.com/aardappel/goose.git /opt/goose && \
    cmake -S /opt/goose -B /opt/goose/build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build /opt/goose/build -j 1 && \
    ln -s /opt/goose/build/goose /usr/local/bin/goose

COPY . /app

RUN mkdir -p /app/.lit/cache/ctgrind && \
    goose --standalone --header /app/.lit/cache/ctgrind/ctgrind_target.h \
        -o /app/.lit/cache/ctgrind/ctgrind_target.c tools/ctgrind/ctgrind_target.goose && \
    gcc -O2 -g -DUSE_VALGRIND=1 -DWING_CTGRIND_VALGRIND=1 -fno-store-merging -mstackrealign -Wall -Wextra -Werror \
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
