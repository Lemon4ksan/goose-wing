# syntax=docker/dockerfile:1
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    g++ \
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

RUN git clone --depth 1 https://github.com/aardappel/goose.git /opt/goose && \
    cmake -S /opt/goose -B /opt/goose/build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build /opt/goose/build -j 1 && \
    ln -s /opt/goose/build/goose /usr/local/bin/goose

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
    "-test", "Basic-Client-TLS13;Basic-Server-TLS13;TLS13-*;*-TLS13*" \
]
