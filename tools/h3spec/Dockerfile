# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

# Multi-stage image building kazu-yamamoto/h3spec alongside goose-wing's
# HTTP/3 server (`tools/http3/server.goose`) and conformance probe runner.
FROM haskell:9.6-slim AS h3spec-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    pkg-config \
    libgmp-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 https://github.com/kazu-yamamoto/h3spec.git /src/h3spec && \
    cd /src/h3spec && \
    cabal update && \
    cabal install exe:h3spec --install-method=copy --installdir=/usr/local/bin

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    curl \
    ca-certificates \
    libgmp10 \
    zlib1g \
    python3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=h3spec-builder /usr/local/bin/h3spec /usr/local/bin/h3spec

WORKDIR /app

RUN curl -sSL --retry 5 --retry-delay 2 --retry-connrefused \
    https://github.com/aardappel/goose/releases/download/v2026.3/goose-v2026.3-linux-x64.tar.gz \
    | tar -xz -C /opt && \
    ln -s /opt/goose-v2026.3-linux-x64/goose /usr/local/bin/goose

COPY . /app

RUN mkdir -p /app/tools/bin && \
    goose build -O2 -o /app/tools/bin/http3_server tools/http3/server.goose && \
    goose build -O2 -o /app/tools/bin/quic_interop_endpoint tools/quic_interop/endpoint.goose

ENTRYPOINT ["python3", "/app/tools/h3spec/runner.py"]
CMD ["--local"]
