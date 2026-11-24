// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Declarative multi-source DTO field wrappers (`Path`, `Query`, `Header`, `Cookie`, `Bearer`, `ClientIp`).
// Placed in `namespace dto` so receiver-namespace UFCS avoids generic fallback ambiguity in `namespace http`.
namespace dto;

import std;

struct Path<T> {
    val: T = default<T>(),
}

struct Query<T> {
    val: T = default<T>(),
}

struct Header<T> {
    val: T = default<T>(),
}

struct Cookie<T> {
    val: T = default<T>(),
}

struct Bearer<B> {
    val: B = default<B>(),
}

struct ClientIp {
    val: u8[..48] = [],
}
