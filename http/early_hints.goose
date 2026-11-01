// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP 103 Early Hints (RFC 8297) and Link Preload / Preconnect Engine.
// Zero-heap parser for informational 103 responses:
// - Extracts `Link: <uri>; rel=preload; as=...` and `Link: <origin>; rel=preconnect`
// - Enables client-side speculative connection pre-warming and asset prefetching
//   before the final 200 OK response arrives.
namespace wing;

import std;
import core from "..";

// ---- Early Hints Models -------------------------------------------------

const STATUS_EARLY_HINTS: u16 = 103;

struct EarlyHintLink {
    uri:         u8[..256] = [],
    rel:         u8[..32]  = [], // "preload", "preconnect", "dns-prefetch"
    as_type:     u8[..32]  = [], // "style", "script", "font", "image", "fetch"
    crossorigin: bool      = false,
}

struct EarlyHintsResponse {
    links:    EarlyHintLink[..8] = [],
    is_valid: bool               = false,
}

// ---- RFC 8288 / RFC 8297 Link Header Parser -----------------------------

// Parses single Link parameter: e.g. `rel=preload` or `as=style` (RFC 8288 §3).
//
// Example:
//   param_str = "rel=preload"
//   mutates link.rel to "preload"
fn parse_link_param(param_str: const u8[:], link: EarlyHintLink&) {
    let p_name_raw, p_val_raw, has_eq = param_str.split_once_byte('=');
    if !has_eq {
        let p_name = param_str.trim_lws();
        if eq_ascii_fold(p_name, "crossorigin") {
            link.crossorigin = true;
        }
        return;
    }

    let p_name = p_name_raw.trim_lws();
    var p_val = p_val_raw.trim_lws().trim_byte('"');

    if eq_ascii_fold(p_name, "rel") {
        guard p_val.len <= link.rel.cap else { return; }
        link.rel.clear();
        link.rel.append(p_val);
    } else if eq_ascii_fold(p_name, "as") {
        guard p_val.len <= link.as_type.cap else { return; }
        link.as_type.clear();
        link.as_type.append(p_val);
    } else if eq_ascii_fold(p_name, "crossorigin") {
        link.crossorigin = true;
    }
}

fn find_link_entry_end(s: const u8[:]) -> i64 {
    var in_quotes = false;
    var in_angle = false;
    for i in s.len {
        let b = s[i];
        if b == '"' && !in_angle {
            in_quotes = !in_quotes;
        } else if b == '<' && !in_quotes {
            in_angle = true;
        } else if b == '>' && !in_quotes {
            in_angle = false;
        } else if !in_quotes && !in_angle && b == ',' {
            return i;
        }
    }
    return s.len;
}

// Parses a single Link element enclosed in angle brackets with parameters.
//
// Example:
//   entry_str = "</style.css>; rel=preload; as=style"
//   returns: true, link populated with uri="/style.css", rel="preload", as_type="style"
fn parse_single_link(entry_str: const u8[:], link: EarlyHintLink&) -> bool {
    guard entry_str.len > 2 && entry_str[0] == '<' else { return false; }
    let rel_close = core::index_of_byte(entry_str[1..], '>');
    guard rel_close >= 0 else { return false; }
    let close_idx = 1 + rel_close;
    let uri_slice = entry_str[1..close_idx];
    // Reject empty URI (<>) and enforce capacity
    guard uri_slice.len > 0 && uri_slice.len <= link.uri.cap else { return false; }
    link.uri.append(uri_slice);

    let after_uri = entry_str[close_idx + 1..].trim_lws_start();
    if after_uri.len > 0 {
        guard after_uri[0] == ';' else { return false; }
    }

    var p_tok = make_byte_tokenizer(after_uri, ';');
    while true {
        let param_token, tok_ok = p_tok.token_next();
        guard tok_ok else { break; }
        let p_trim = param_token.trim_lws();
        if p_trim.len > 0 {
            parse_link_param(p_trim, link);
        }
    }
    return true;
}

// Parses RFC 8288 `Link` header: `<uri>; rel=...; as=...`
//
// Example:
//   raw = "</style.css>; rel=preload, </app.js>; rel=preload"
//   returns: true, out_links has 2 entries
fn parse_link_header<E>(raw: const u8[:], out_links: E&) -> bool {
    var rem = raw;
    while rem.len > 0 {
        rem = rem.trim_start_bytes(" \t,");
        guard rem.len > 0 else { break; }

        let entry_len = find_link_entry_end(rem);
        let entry_str = rem[..entry_len].trim_lws();
        rem = if entry_len < rem.len { rem[entry_len + 1..] } else { rem[entry_len..] };

        var link = EarlyHintLink { .. };
        guard parse_single_link(entry_str, link) else { return false; }
        guard out_links.len < out_links.cap else { return false; }
        out_links.push(link);
    }
    return true;
}

// Parses a 103 Early Hints informational block (RFC 8297 §2).
//
// Example:
//   status = 103, raw_link_header = "</style.css>; rel=preload"
//   returns: resp with 1 link, ok = true
fn parse_early_hints(status: u16, raw_link_header: const u8[:]) -> EarlyHintsResponse, bool {
    var resp = EarlyHintsResponse { .. };
    guard status == STATUS_EARLY_HINTS else { return resp, false; }

    guard parse_link_header(raw_link_header, resp.links) else { return resp, false; }
    resp.is_valid = true;
    return resp, true;
}

// Checks if link requests a preconnect action
fn early_hint_is_preconnect(link: const EarlyHintLink&) -> bool {
    return link.rel[..] == "preconnect" || link.rel[..] == "dns-prefetch";
}

// Checks if link requests asset preloading
fn early_hint_is_preload(link: const EarlyHintLink&) -> bool {
    return link.rel[..] == "preload";
}
