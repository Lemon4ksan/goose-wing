# syntax=docker/dockerfile:1
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    curl \
    git \
    ca-certificates \
    openssl \
    libssl3t64 \
    python3 \
    python3-pip \
    python3-venv \
    bsdmainutils \
    dnsutils \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN curl -sSL --retry 5 --retry-delay 2 --retry-connrefused \
    https://github.com/aardappel/goose/releases/download/v2026.4/goose-v2026.4-linux-x64.tar.gz | \
    tar -xz -C /opt && \
    ln -s /opt/goose-v2026.4-linux-x64/goose /usr/local/bin/goose

RUN python3 -m venv /opt/audit-venv && \
    /opt/audit-venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/audit-venv/bin/pip install --no-cache-dir tlslite-ng && \
    git clone --depth 1 https://github.com/tlsfuzzer/tlsfuzzer.git /opt/tlsfuzzer

COPY . /app

RUN mkdir -p /app/tools/bin && \
    goose build -O2 -o /app/tools/bin/tls_server tools/tls/server.goose

EXPOSE 8443

ENTRYPOINT ["/app/tools/bin/tls_server"]
