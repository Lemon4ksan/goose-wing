# syntax=docker/dockerfile:1
FROM ubuntu:24.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install compiler toolchains, git, curl, and python
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    make \
    git \
    curl \
    ca-certificates \
    zlib1g-dev \
    python3 \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1. Fetch & Install official Goose compiler (v2026.3)
RUN curl -sSL https://github.com/aardappel/goose/releases/download/v2026.3/goose-v2026.3-linux-x64.tar.gz | tar -xz -C /opt && \
    ln -s /opt/goose-v2026.3-linux-x64/goose /usr/local/bin/goose

# 2. Fetch & Build official uWebSockets C++ library
RUN git clone --depth 1 --recursive https://github.com/uNetworking/uWebSockets.git /opt/uWebSockets && \
    cd /opt/uWebSockets/uSockets && \
    make WITH_OPENSSL=0 && \
    cd /app

# 3. Copy repository tree for Goose compilation, benchmark suite, and root shim
COPY . /build/repo
COPY tools/bench-vs-uwebsockets /app
COPY shim /app/shim

# Create output binary directory
RUN mkdir -p /app/bin

# 4. Compile uWebSockets C++ Server with GCC -O3 and Link Time Optimization (LTO)
RUN g++ -O3 -flto -std=c++17 \
    -I/opt/uWebSockets/src -I/opt/uWebSockets/uSockets/src \
    /app/server_uwebsockets.cpp /opt/uWebSockets/uSockets/*.o \
    -lz -lpthread \
    -o /app/bin/server_uwebsockets

# 5. Generate server_goose_wing.c on-the-fly from .goose source, then compile with GCC -O3
RUN goose -o /tmp/server_goose_wing.c /build/repo/tools/bench-vs-uwebsockets/server_goose_wing.goose --standalone && \
    gcc -O3 -std=c11 -D_GNU_SOURCE \
        -I/app -I/app/shim \
        /tmp/server_goose_wing.c /app/shim/tcp.c /app/shim/simd.c \
        -lpthread \
        -o /app/bin/server_goose_wing && \
    rm -f /tmp/server_goose_wing.c && \
    rm -rf /build

# Normalize line endings and make entrypoint executable
RUN sed -i 's/\r$//' /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Expose Web Orchestrator (8080), goose-wing (3001), uWebSockets (3002)
EXPOSE 8080 3001 3002

ENTRYPOINT ["/app/entrypoint.sh"]
