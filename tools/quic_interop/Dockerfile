# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

# Official marten-seemann/quic-interop-runner Docker endpoint for goose-wing.
# For official QNS network simulator runs, override BASE_IMAGE:
#   docker build --build-arg BASE_IMAGE=martenseemann/quic-network-simulator-endpoint:latest \
#     -f tools/quic_interop/Dockerfile -t goose-wing-quic-interop .
ARG BASE_IMAGE=ubuntu:24.04

FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN curl -sSL --retry 5 --retry-delay 2 --retry-connrefused \
    https://github.com/aardappel/goose/releases/download/v2026.3/goose-v2026.3-linux-x64.tar.gz \
    | tar -xz -C /opt && \
    ln -s /opt/goose-v2026.3-linux-x64/goose /usr/local/bin/goose

COPY . /app

RUN mkdir -p /app/tools/bin && \
    goose build -O2 -o /app/tools/bin/quic_interop_endpoint tools/quic_interop/endpoint.goose

FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive
ENV ENDPOINT_BIN=/app/tools/bin/quic_interop_endpoint

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    iproute2 \
    python3 \
    && rm -rf /var/lib/apt/lists/* && \
    mkdir -p /app/tools/bin /app/tools/quic_interop /www /downloads /logs /certs

COPY --from=builder /app/tools/bin/quic_interop_endpoint /app/tools/bin/quic_interop_endpoint
COPY tools/quic_interop/run_endpoint.sh /app/tools/quic_interop/run_endpoint.sh
COPY tools/quic_interop/runner.py /app/tools/quic_interop/runner.py

RUN sed -i 's/\r$//' /app/tools/quic_interop/run_endpoint.sh && \
    chmod +x /app/tools/quic_interop/run_endpoint.sh

EXPOSE 443/udp

ENTRYPOINT ["/app/tools/quic_interop/run_endpoint.sh"]
