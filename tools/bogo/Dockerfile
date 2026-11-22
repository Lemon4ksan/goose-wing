# syntax=docker/dockerfile:1
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    curl \
    git \
    golang-go \
    ca-certificates \
    openssl \
    libssl3t64 \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN curl -sSL --retry 5 --retry-delay 2 --retry-connrefused \
    https://github.com/aardappel/goose/releases/download/v2026.3/goose-v2026.3-linux-x64.tar.gz | \
    tar -xz -C /opt && \
    ln -s /opt/goose-v2026.3-linux-x64/goose /usr/local/bin/goose

RUN git clone --depth 1 https://boringssl.googlesource.com/boringssl /opt/boringssl && \
    cd /opt/boringssl/ssl/test/runner && \
    go test -c -o /opt/bogo_runner .

COPY . /app

RUN mkdir -p /app/tools/bin && \
    goose build -O2 -o /app/tools/bin/bogo_shim tools/bogo/shim.goose

ENTRYPOINT ["/opt/bogo_runner"]
CMD [ \
    "-shim-path", "/app/tools/bin/bogo_shim", \
    "-shim-config", "/app/tools/bogo/bogo_config.json", \
    "-allow-unimplemented", \
    "-test", "Basic-Client-TLS13;Basic-Server-TLS13;TLS13-*" \
]
