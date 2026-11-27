# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    curl \
    ca-certificates \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN curl -sSL --retry 5 --retry-delay 2 --retry-connrefused \
    https://github.com/aardappel/goose/releases/download/v2026.4/goose-v2026.4-linux-x64.tar.gz \
    | tar -xz -C /opt && \
    ln -s /opt/goose-v2026.4-linux-x64/goose /usr/local/bin/goose

COPY . /app

RUN mkdir -p /app/.lit/cache/crypto_vectors && \
    goose build -O2 -o /app/.lit/cache/crypto_vectors/harness tools/crypto_vectors/harness.goose

ENTRYPOINT ["python3", "/app/tools/crypto_vectors/runner.py"]
