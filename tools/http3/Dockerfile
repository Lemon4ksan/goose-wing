# syntax=docker/dockerfile:1
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# 1. Install toolchains, iproute2 (for tc netem), Python 3, and curl
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    curl \
    ca-certificates \
    iproute2 \
    python3 \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 2. Install official Goose compiler (v2026.3)
RUN curl -sSL --retry 5 --retry-delay 2 --retry-connrefused https://github.com/aardappel/goose/releases/download/v2026.3/goose-v2026.3-linux-x64.tar.gz | tar -xz -C /opt && \
    ln -s /opt/goose-v2026.3-linux-x64/goose /usr/local/bin/goose

# 3. Copy repository tree
COPY . /app

# 4. Compile native HTTP/3 & QUIC server and client with Goose & GCC -O2
RUN mkdir -p /app/tools/bin && \
    goose build tools/http3/server.goose -o /app/tools/bin/http3_server -O2 && \
    goose build tools/http3/client.goose -o /app/tools/bin/http3_client -O2

# 5. Normalize line endings and permissions for entrypoint
RUN sed -i 's/\r$//' /app/tools/http3/entrypoint.sh && \
    chmod +x /app/tools/http3/entrypoint.sh

EXPOSE 4433/udp

ENTRYPOINT ["/app/tools/http3/entrypoint.sh"]
