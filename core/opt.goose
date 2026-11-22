// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Optional value wrapper for declarative REST query, JSON, and partial PATCH DTOs.
namespace core;

struct Opt<T> {
    present: bool = false,
    value:   T    = default<T>(),
}

// Wraps `val` in a present `Opt<T>`.
fn opt_some<T>(val: T) -> Opt<T> {
    return Opt<T> { present: true, value: val };
}
