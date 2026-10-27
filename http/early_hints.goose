// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP 103 Early Hints (RFC 8297) and Link Preload / Preconnect Engine.
// Zero-heap parser for informational 103 responses:
// - Extracts `Link: <uri>; rel=preload; as=...` and `Link: <origin>; rel=preconnect`
// - Enables client-side speculative connection pre-warming and asset prefetching
//   before the final 200 OK response arrives.
namespace wing;

import std;
import http.headers;

// ---- 1. Early Hints Models -------------------------------------------------

const STATUS_EARLY_HINTS: u16 = 103;

struct EarlyHintLink {
    uri: u8[..256] = [],
    rel: u8[..32] = [],          // "preload", "preconnect", "dns-prefetch"
    as_type: u8[..32] = [],      // "style", "script", "font", "image", "fetch"
    crossorigin: bool = false,
}

struct EarlyHintsResponse {
    links: EarlyHintLink[..8] = [],
    is_valid: bool = false,
}

// ---- 2. RFC 8288 / RFC 8297 Link Header Parser -----------------------------

// Parses single Link parameter: e.g. `rel=preload` or `as=style`
fn parse_link_param(param_str: const u8[:], link: EarlyHintLink&) {
    let p_name_raw, p_val_raw, has_eq = param_str.split_once_byte('=');
    if !has_eq {
        let p_name = param_str.trim_lws();
        if p_name == "crossorigin" {
            link.crossorigin = true;
        }
        return;
    }

    let p_name = p_name_raw.trim_lws();
    var p_val = p_val_raw.trim_lws().trim_byte('"');

    if p_name == "rel" {
        guard p_val.len <= link.rel.cap else { return; }
        link.rel.clear();
        link.rel.append(p_val);
    } else if p_name == "as" {
        guard p_val.len <= link.as_type.cap else { return; }
        link.as_type.clear();
        link.as_type.append(p_val);
    } else if p_name == "crossorigin" {
        link.crossorigin = true;
    }
}

// Parses RFC 8288 `Link` header: `<uri>; rel=...; as=...`
fn parse_link_header<E>(raw: const u8[:], out_links: E&) -> bool {
    var cursor: i64 = 0;
    while cursor < raw.len {
        while cursor < raw.len && (raw[cursor] == ' ' || raw[cursor] == '\t' || raw[cursor] == ',') {
            cursor++;
        }
        if cursor == raw.len { break; }

        guard raw[cursor] == '<' else { return false; }
        cursor++; // skip '<'

        var close_angle: i64 = -1;
        for i in cursor..raw.len {
            if raw[i] == '>' {
                close_angle = i;
                break;
            }
        }
        guard close_angle > cursor else { return false; }

        let uri_slice = raw[cursor..close_angle];
        cursor = close_angle + 1;

        guard uri_slice.len <= 256 else { return false; }
        var link = EarlyHintLink { .. };
        link.uri.append(uri_slice);

        // Find parameters until next comma or end of header
        var in_quotes = false;
        var end_entry = raw.len;
        var i = cursor;
        while i < raw.len {
            let b = raw[i];
            if b == '"' {
                in_quotes = !in_quotes;
            } else if b == ',' && !in_quotes {
                end_entry = i;
                break;
            }
            i++;
        }

        let params_part = raw[cursor..end_entry];
        cursor = if end_entry < raw.len { end_entry + 1 } else { raw.len };

        var p_tok = make_byte_tokenizer(params_part, ';');
        while true {
            let param_token, tok_ok = p_tok.token_next();
            guard tok_ok else { break; }
            let p_trim = param_token.trim_lws();
            if p_trim.len > 0 {
                parse_link_param(p_trim, link);
            }
        }

        guard out_links.len < out_links.cap else { return false; }
        out_links.push(link);
    }
    return true;
}

// Parses a 103 Early Hints informational block
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
