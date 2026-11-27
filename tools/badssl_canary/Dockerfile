# syntax=docker/dockerfile:1
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    curl \
    ca-certificates \
    openssl \
    libssl3t64 \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN curl -sSL --retry 5 --retry-delay 2 --retry-connrefused https://github.com/aardappel/goose/releases/download/v2026.4/goose-v2026.4-linux-x64.tar.gz | tar -xz -C /opt && \
    ln -s /opt/goose-v2026.4-linux-x64/goose /usr/local/bin/goose

COPY . /app

RUN mkdir -p /app/tools/bin && \
    goose build -O2 -o /app/tools/bin/badssl_canary tools/badssl_canary/canary.goose

ENTRYPOINT ["python3", "/app/tools/badssl_canary/runner.py"]
