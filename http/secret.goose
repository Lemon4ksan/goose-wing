// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP JSON/query redaction, decoding, and struct zeroization hooks for `core::Secret<B>`.
namespace http;

import std;
import core;
import json;
import .json_codec;

// Fallback no-op used by `zeroize_struct_secrets` on non-secret DTO fields.
fn zeroize_if_secret<T>(_v: T&) {
}

// Dispatches field zeroization via receiver-namespace UFCS (`core::Secret`, `core::Opt`, `dto::*`).
fn zeroize_field_val<T>(v: T&) {
    v.zeroize_if_secret();
}

// Zeroizes a `core::Secret<B>` field in place when sweeping a DTO struct.
fn core::zeroize_if_secret<B>(v: core::Secret<B>&) {
    core::zeroize(v);
}

// Recursively sweeps optional DTO values for nested secrets.
fn core::zeroize_if_secret<T>(v: core::Opt<T>&) {
    http::zeroize_field_val(v.value);
}

// Sweeps every field of struct `obj` via `const for`, wiping all `Secret<B>` members.
fn zeroize_struct_secrets<T>(obj: T&) {
    const for <Name, Acc> in fields<T> {
        zeroize_field_val(obj.Acc);
    }
}

// Marks `core::Secret<B>` as non-omitted in JSON/query struct serialization (serialized as `"******"`).
fn core::is_omitted_json_field<B>(_v: const core::Secret<B>&) -> bool {
    return false;
}

fn core::is_omitted_query_field<B>(_v: const core::Secret<B>&) -> bool {
    return false;
}

// Serializes `core::Secret<B>` as literal `"******"` so responses, logs, and diagnostics never leak secrets.
fn core::json_encode<B>(_s: const core::Secret<B>&, out: u8[>..]&) {
    out.append("\"******\"");
}

// Fallback unredacted field encoder delegating to normal JSON encoding for non-secret fields.
fn encode_json_field_unredacted<T>(v: const T&, out: u8[>..]&) {
    v.json_encode(out);
}

// Dispatches unredacted JSON field encoding via receiver-namespace UFCS.
fn encode_field_unredacted_val<T>(v: const T&, out: u8[>..]&) {
    v.encode_json_field_unredacted(out);
}

// Encodes raw `core::Secret<B>` bytes into outbound JSON for explicit `json_secret` client bodies.
fn core::encode_json_field_unredacted<B>(v: const core::Secret<B>&, out: u8[>..]&) {
    json::format_string(out, v.val[..]);
}

// Encodes optional DTO fields cleanly inside unredacted secret request bodies.
fn core::encode_json_field_unredacted<T>(v: const core::Opt<T>&, out: u8[>..]&) {
    if !v.present {
        out.append("null");
        return;
    }
    http::encode_field_unredacted_val(v.value, out);
}

// Serializes struct `obj` into outbound JSON while preserving `core::Secret<B>` values on `json_secret` requests.
//
// Example:
//   obj = LoginReq { password: core::Secret { val: "s3cr3t" } }
//   out = {"password":"s3cr3t"}
fn encode_json_struct_unredacted<T>(obj: const T&, out: u8[>..]&) {
    out.push('{');
    var first = true;
    const for <Name, Acc> in fields<T> {
        if !obj.Acc.is_omitted_json_field() {
            if !first { out.push(','); }
            first = false;
            json::format_key(out, Name);
            encode_field_unredacted_val(obj.Acc, out);
        }
    }
    out.push('}');
}

// Redacts `core::Secret<S>` in URL query serialization so credentials never appear unmasked in URLs.
fn core::query_format<S, B>(_s: const core::Secret<S>&, out: B&) -> bool {
    return out.try_append("******");
}

// Decodes a JSON string directly into `dst.val`, wiping any partial secret bytes on parse or capacity error.
//
// Example:
//   r positioned at `"topsecret"`, dst = core::Secret<u8[..32]> -> dst.val = "topsecret"
fn core::json_decode<B>(dst: core::Secret<B>&, r: json::Reader&) {
    let ok = core::read_json_string_into(r, dst.val);
    if !ok || r.error.len > 0 {
        core::zeroize(dst);
        if r.error.len == 0 {
            json::fail(r, "secret exceeds capacity");
        }
    }
}

// Copies a raw header, path, or query token into `dst.val`, wiping on capacity overflow.
//
// Example:
//   raw = "tok123", dst = core::Secret<u8[..64]> -> returns true, dst.val = "tok123"
fn core::query_parse<B>(dst: core::Secret<B>&, raw: const u8[:]) -> bool {
    guard dst.val.try_set(raw) else {
        core::zeroize(dst);
        return false;
    }
    return true;
}
