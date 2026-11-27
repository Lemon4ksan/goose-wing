# syntax=docker/dockerfile:1
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# 1. Install toolchains, Python 3, and curl
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    curl \
    ca-certificates \
    python3 \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 2. Install official Goose compiler (v2026.4)
RUN curl -sSL --retry 5 --retry-delay 2 --retry-connrefused https://github.com/aardappel/goose/releases/download/v2026.4/goose-v2026.4-linux-x64.tar.gz | tar -xz -C /opt && \
    ln -s /opt/goose-v2026.4-linux-x64/goose /usr/local/bin/goose

# 3. Copy repository tree
COPY . /app

# 4. Compile native Autobahn WebSocket server with Goose & GCC -O2
RUN mkdir -p /app/tools/bin && \
    goose build tools/autobahn/server.goose -o /app/tools/bin/autobahn_server -O2

# 5. Normalize line endings and permissions for entrypoint
RUN sed -i 's/\r$//' /app/tools/autobahn/entrypoint.sh && \
    chmod +x /app/tools/autobahn/entrypoint.sh

EXPOSE 9001

ENTRYPOINT ["/app/tools/autobahn/entrypoint.sh"]
