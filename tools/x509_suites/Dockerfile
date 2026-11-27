# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

FROM golang:1.23-bookworm AS bettertls-builder
RUN go install github.com/Netflix/bettertls/test-suites/cmd/bettertls@latest

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    curl \
    ca-certificates \
    openssl \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN curl -sSL --retry 5 --retry-delay 2 --retry-connrefused \
    https://github.com/aardappel/goose/releases/download/v2026.4/goose-v2026.4-linux-x64.tar.gz \
    | tar -xz -C /opt && \
    ln -s /opt/goose-v2026.4-linux-x64/goose /usr/local/bin/goose

COPY --from=bettertls-builder /go/bin/bettertls /usr/local/bin/bettertls
COPY . /app

RUN mkdir -p /app/tools/bin && \
    goose build -O2 -o /app/tools/bin/x509_harness tools/x509_suites/x509_harness.goose

ENTRYPOINT ["python3", "/app/tools/x509_suites/runner.py"]
