# RFC Coverage Matrix — Engine-Level API (Vulkan-Style) Design

**Date:** 2026-11-01
**Status:** Approved for execution (approach 2: parallel file-owned tracks)
**Spec corpus:** `.gemini/rfc/` (rfc9875, rfc9440, rfc9369, rfc9458, rfc8555, rfc9849, rfc9292, rfc9651, rfc9180)

## Intent and why

`goose-wing` covers IETF specs as low-level engine primitives in the Vulkan/DPDK
style defined in `README.md`: caller-owned memory, zero heap allocation on packet
paths, explicit cursors and error returns, no ergonomic wrappers (those belong in
separate libraries). The RFC audit found six unimplemented (or mis-cited)
specifications that must be covered at the engine layer — parsers, serializers,
state tables and sanitizers integrated into existing engine structs — each proven
by tests in the subsystem suite files.

## Goals

1. **RFC 9875** — HTTP Cache Groups: parse/serialize `Cache-Groups` and
   `Cache-Group-Invalidation` (SFV List of Strings), group-tag cache entries,
   invalidate by group in `http/cache/`.
2. **RFC 9440** — Client-Cert: SFV Byte-Sequence codec, mandatory stripping of
   spoofed `Client-Cert`/`Client-Cert-Chain` at the proxy trust boundary, optional
   injection toward upstream.
3. **RFC 9369** — QUIC Version 2: version constant `0x6b3343cf`, v2 Initial salt,
   v2 HKDF labels, v2 long-header type remap, version-aware dispatch in `quic/` and
   `tls/key_schedule.goose`.
4. **RFC 9458** — Oblivious HTTP: `application/ohttp-keys` key-config parser,
   request/response HPKE seal/open over RFC 9292 known-length binary HTTP messages
   (new minimal `bhttp` codec), using the existing `tls/hpke.goose` (RFC 9180).
5. **RFC 8555** — ACME HTTP-01: key-authorization computation, challenge path
   construction and matching, token validation, server-side responder helper.
6. **RFC 9849** — TLS ECH citation refresh: `tls/ech.goose` cites
   `draft-ietf-tls-esni`; ECH is now RFC 9849. Rename constant, refresh citations,
   verify wire values unchanged.

## Non-goals

- High-level/ergonomic APIs (explicitly out of engine scope per README).
- Full ACME client automation (order polling, renewal daemon, DNS-01) — only the
  HTTP-01 engine primitives.
- QUIC v2 retry-integrity interop matrix beyond the RFC 9369 §3.3.3 constants and
  label dispatch.
- Changes to `tools/` (excluded from the build) or `bench/`.
- OHTTP relay/gateway service wiring beyond the codec primitives.

## Anti-goals

- Any heap allocation (`[>..]`) on parse/serialize paths.
- Artificial cursor wrapper structs (`SliceReader` etc.) — banned by AGENTS.md.
- Magic numbers without named RFC constants.
- Unverified RFC section numbers in comments (anti-hallucination citation contract).

## Constraints (binding)

- Zero-allocation engine model: `const u8[:]` inputs, `u8[..N]` caller buffers,
  `(value, bool)` or `(len, ok)` returns (ARCHITECTURE.md).
- AGENTS.md invariants: named RFC constants with section refs; RFC Appendix test
  vectors verified byte-for-byte where they exist; 100-col soft / 120-col hard;
  SPDX Apache-2.0 headers; no trivial getters; G-CRAP complexity gate.
- Test framework: `goose-lit`, cases in existing suites
  (`tests/http_cache_test.goose`, `tests/net_proxy_test.goose`,
  `tests/quic_test.goose`, `tests/tls_test.goose` / `tls_advanced_test.goose`,
  `tests/auth_test.goose`).
- Citations validated against `.gemini/rfc/` texts only.
- Track file ownership is disjoint (see below); parallel agents never touch a file
  outside their track.

## Approaches considered

1. **All six RFCs in one parallel dispatch** — fastest wall-clock, but collisions on
   `server/`, `tls/` and shared docs; conflicts with the workflow rule against
   parallel implementers in one worktree. Rejected.
2. **Parallel file-owned tracks, one worktree+branch per track** (chosen). Tracks:
   `http/cache` (9875), `quic` (9369), `http/client_cert` + `proxy` (9440),
   `http/bhttp` + `http/ohttp` (9458), `auth/acme` + `server` helper (8555),
   `tls/ech` citations (9849). API contracts pinned up front in the plan so
   independent implementers cannot drift. Shared docs (README tables,
   `docs/rfc_conformance.md`) as one serialized post-merge task. Merge into `main`
   via rebase or patch after per-track tests + independent review.
3. **One template RFC (9875) first, then parallel** — safer stylistic convergence,
   but a full serial step; redundant once the plan pins signatures and the existing
   modules (`http/sfv.goose`, `http/cache/engine.goose`, `tls/hpke.goose`) serve as
   style anchors. Rejected as slower with little gain.

## The how (decided)

- Each track = one git worktree + branch (`feat/rfc-<num>-<slug>`) off `main`.
- Each task: implementer subagent writes tests + implementation, commits on its
  branch, runs the subsystem suite; an independent reviewer subagent checks spec
  compliance and code quality against the diff; fixes loop until clean.
- Engine API shape follows existing modules: `parse_*`/`encode_*` leaf functions on
  slices, state embedded in existing structs (`HttpCache`, `ProxyConfig`), named
  constants like `QUIC_VERSION_2: u32 = 0x6b3343cf; // RFC 9369 §3.1`.
- SFV handling reuses `http/sfv.goose` / `http/mime.goose` primitives
  (`parse_sfv_list`, `parse_sfv_item`, `parse_sfv_binary`).
- OHTTP builds on `tls/hpke.goose` (`HPKE_KEM_DHKEM_X25519_HKDF_SHA256`,
  `HPKE_KDF_HKDF_SHA256`, `HPKE_AEAD_AES_128_GCM` / `CHACHA20_POLY1305`).

## Track ownership

| Track | RFC | Files owned | Suite |
|---|---|---|---|
| A | 9875 | `http/cache/cache_groups.goose` (new), `http/cache/engine.goose` | `tests/http_cache_test.goose` |
| B | 9440 | `http/client_cert.goose` (new), `proxy/reverse_proxy.goose` | `tests/net_proxy_test.goose` |
| C | 9369 | `quic/packet.goose`, `tls/key_schedule.goose` | `tests/quic_test.goose` |
| D | 9458 | `http/bhttp.goose` (new), `http/ohttp.goose` (new) | `tests/http_ohttp_test.goose` (new) |
| E | 8555 | `auth/acme.goose` (new), `server/` helper | `tests/auth_test.goose` |
| F | 9849 | `tls/ech.goose`, `tls/ech` tests refs | `tests/tls_advanced_test.goose` |
| G | all | `README.md`, `docs/rfc_conformance.md` (post-merge, serialized) | — |

## Left to the builder

Exact function signatures, constants, test vectors and step sequences live in
`docs/superpowers/plans/2026-11-01-rfc-matrix-engine-api.md`. Module registration
in `wing.goose` follows the existing `import http.sfv;` pattern; each track adds
its own import/export lines within its subsystem section.
