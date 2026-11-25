// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Declarative multi-source DTO extractors and validators (`Path`, `Query`, `Header`, `Cookie`,
// `Bearer`, `ClientIp`, `NonEmpty`, `Positive`) in `namespace dto` to avoid `http` UFCS ambiguity.
namespace dto;

import std;

// Extracts a URI template segment matched by `RadixRouter` using the struct field name.
struct Path<T> {
    val: T = default<T>(),
}

// Extracts a URL query parameter from the request target string via `parse_query_field_val`.
struct Query<T> {
    val: T = default<T>(),
}

// Extracts an HTTP request header matched case-insensitively by struct field name.
struct Header<T> {
    val: T = default<T>(),
}

// Extracts a named cookie value from the HTTP `Cookie` request header.
struct Cookie<T> {
    val: T = default<T>(),
}

// Extracts an `Authorization: Bearer` token into buffer `B` (requires capacity >= 4096 bytes).
struct Bearer<B> {
    val: B = default<B>(),
}

// Binds the transport-supplied peer IP address into a fixed 48-byte buffer.
struct ClientIp {
    val: u8[..48] = [],
}

// Validates that bounded buffer `B` is non-empty (`val.len > 0`) on decode and DTO validation.
struct NonEmpty<B> {
    val: B = default<B>(),
}

// Validates that numeric field `T` is strictly greater than zero on decode and DTO validation.
struct Positive<T> {
    val: T = default<T>(),
}
