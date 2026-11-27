# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

# Linux kernel tc netem (iproute2) + Google packetdrill testbed for goose-wing.
# Requires --cap-add=NET_ADMIN when executing kernel tc qdisc or TUN packetdrill.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    bison \
    flex \
    git \
    curl \
    ca-certificates \
    iproute2 \
    iptables \
    tcpdump \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Build Google packetdrill from upstream source
RUN git clone --depth 1 https://github.com/google/packetdrill.git /opt/packetdrill && \
    cd /opt/packetdrill/gtests/net/packetdrill && \
    ./configure && \
    make -j"$(nproc)" && \
    cp packetdrill /usr/local/bin/packetdrill && \
    rm -rf /opt/packetdrill

WORKDIR /app

RUN curl -sSL --retry 5 --retry-delay 2 --retry-connrefused \
    https://github.com/aardappel/goose/releases/download/v2026.4/goose-v2026.4-linux-x64.tar.gz \
    | tar -xz -C /opt && \
    ln -s /opt/goose-v2026.4-linux-x64/goose /usr/local/bin/goose

COPY . /app

RUN mkdir -p /app/tools/bin && \
    goose build -O2 -o /app/tools/bin/http3_server tools/http3/server.goose && \
    goose build -O2 -o /app/tools/bin/http3_client tools/http3/client.goose && \
    sed -i 's/\r$//' /app/tools/netem_packetdrill/netem_quic_test.sh && \
    chmod +x /app/tools/netem_packetdrill/netem_quic_test.sh

ENTRYPOINT ["/app/tools/netem_packetdrill/netem_quic_test.sh"]
