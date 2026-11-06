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

# 2. Install official Goose compiler (v2026.3)
RUN curl -sSL --retry 5 --retry-delay 2 --retry-connrefused https://github.com/aardappel/goose/releases/download/v2026.3/goose-v2026.3-linux-x64.tar.gz | tar -xz -C /opt && \
    ln -s /opt/goose-v2026.3-linux-x64/goose /usr/local/bin/goose

# 3. Download official Shopify Toxiproxy server & cli (v2.13.0)
RUN curl -sSL --retry 5 -o /usr/local/bin/toxiproxy-server https://github.com/Shopify/toxiproxy/releases/download/v2.13.0/toxiproxy-server-linux-amd64 && \
    chmod +x /usr/local/bin/toxiproxy-server && \
    curl -sSL --retry 5 -o /usr/local/bin/toxiproxy-cli https://github.com/Shopify/toxiproxy/releases/download/v2.13.0/toxiproxy-cli-linux-amd64 && \
    chmod +x /usr/local/bin/toxiproxy-cli

# 4. Copy repository sources
COPY . /app

# 5. Compile standalone goose_chaos_server and goose_chaos_client
RUN mkdir -p /app/tools/bin && \
    goose build tools/toxiproxy/goose_chaos_server.goose -o /app/tools/bin/goose_chaos_server -O2 && \
    goose build tools/toxiproxy/goose_chaos_client.goose -o /app/tools/bin/goose_chaos_client -O2 && \
    ln -s /usr/local/bin/toxiproxy-server /app/tools/bin/toxiproxy-server && \
    ln -s /usr/local/bin/toxiproxy-cli /app/tools/bin/toxiproxy-cli

# 6. Normalize line endings and permissions for entrypoint
RUN sed -i 's/\r$//' /app/tools/toxiproxy/entrypoint.sh && \
    chmod +x /app/tools/toxiproxy/entrypoint.sh

EXPOSE 8474 8080 8475-8500

ENTRYPOINT ["/app/tools/toxiproxy/entrypoint.sh"]
