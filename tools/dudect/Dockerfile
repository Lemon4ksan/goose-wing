# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    gcc \
    g++ \
    git \
    curl \
    ca-certificates \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN git clone --depth 1 https://github.com/aardappel/goose.git /opt/goose && \
    cmake -S /opt/goose -B /opt/goose/build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build /opt/goose/build -j 1 && \
    ln -s /opt/goose/build/goose /usr/local/bin/goose

COPY . /app

RUN python3 /app/tools/dudect/runner.py --local --samples 200 --rebuild

ENTRYPOINT ["python3", "/app/tools/dudect/runner.py"]
