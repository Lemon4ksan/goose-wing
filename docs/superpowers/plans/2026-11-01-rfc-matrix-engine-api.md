# RFC Coverage Matrix — Engine-Level API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cover six IETF specifications (RFC 9875, 9440, 9369, 9458, 8555, 9849) as zero-allocation engine primitives in the Vulkan/DPDK style, each proven by tests in its subsystem suite.

**Architecture:** Six independent file-owned tracks; one git worktree + branch per track under `.worktrees/`, parallel implementers with per-track independent review; merge into `main` via rebase (patch fallback). Shared docs (README, rfc_conformance) are one serialized post-merge task.

**Tech Stack:** Goose language; `goose-lit` test framework; existing `http/sfv.goose` + `http/mime.goose` SFV primitives; `tls/hpke.goose` (RFC 9180); `core/crypto/base64.goose` base64url; `auth/jwks.goose` JWK thumbprint.

**Spec:** `docs/superpowers/specs/2026-11-01-rfc-matrix-engine-api-design.md`
**RFC corpus (source of truth for all wire values):** `.gemini/rfc/` — `rfc9875.txt`, `rfc9440.txt`, `rfc9369.txt`, `rfc9458.txt`, `rfc9292.txt`, `rfc8555.txt`, `rfc9849.txt`, `rfc9651.txt`, `rfc9180.txt`

## Global Constraints

- Zero heap allocation on parse/serialize paths. Inputs are `const u8[:]`; outputs are caller-owned `u8[..N]` buffers or `(value, bool)` / `(len, ok)` returns. No `[>..]` on packet paths (ARCHITECTURE.md).
- Named RFC constants with section references; never magic numbers (`const QUIC_VERSION_2: u32 = 0x6b3343cf; // RFC 9369 §3.1`).
- No artificial cursor wrapper structs. Parsers take `raw: const u8[:]` + `idx: i64&`, or return `(consumed_len, bool)`.
- All RFC section citations must be verified against the local corpus in `.gemini/rfc/` before writing them (anti-hallucination citation contract, AGENTS.md).
- RFC Appendix test vectors, where present in the corpus, must be verified byte-for-byte (AGENTS.md).
- 100-column soft / 120-column hard limit (excluding long test-vector strings).
- SPDX Apache-2.0 license header on every new file.
- Enterprise-scale buffer limits for certificates, tokens and headers — never miniature RFC-example buffers (AGENTS.md invariant 17): cert DER ≤ 4096 B, SFV tags ≤ 64 B, challenge tokens ≤ 64 B.
- Tests register via `lit::run_case(runner, "<N>. <Name>", test_fn)` in the named suite file only; a task never edits another track's suite file.
- `just check` (typecheck) and `just lint-invariants` must pass before commit; per-task suite must pass via `goose-lit tests/<file>`.
- Every task commits only on its own branch `feat/rfc-<num>-<slug>` inside its own worktree.

## Review Focus

1. **SFV header corruption:** malformed `Cache-Groups` / `Cache-Group-Invalidation` values must fail closed (entry untouched, no partial group application) — pin with a test asserting a truncated list leaves the cached entry's group set unchanged.
2. **Client-Cert spoofing:** an incoming `Client-Cert` / `Client-Cert-Chain` from an untrusted client must be stripped even with odd casing or duplicates, and never forwarded upstream — pin with a test asserting `filter_and_forward_headers` drops it in every casing.
3. **QUIC v2 key separation:** v2 salt/labels must never be selected for v1 packets and vice versa; v2 long-header type decode must be version-aware (v2 Initial codepoint ≠ v1 Initial) — pin with a test asserting v1 and v2 Initial salts/labels differ and type decode follows the version parameter.
4. **OHTTP silent garbage:** a wrong `info` string or hdr layout yields AEAD-valid but meaningless plaintext only if key schedule is wrong; tampered ciphertext must fail open — pin with seal/open round-trip, tamper-reject, and (per RFC 9458 §3.2) whole-collection discard on any malformed key config element.
5. **ACME token traversal:** `keyAuthorization` and HTTP-01 path matching must reject non-base64url tokens (`..`, `/`, `%`) before use — pin with a test asserting `acme_validate_token` rejects `../etc/passwd` and `acme_match_http01` never matches a traversal path.

---

### Task 1: RFC 9875 HTTP Cache Groups

**Files:**
- Create: `http/cache/cache_groups.goose`
- Modify: `http/cache/engine.goose` (CachedEntry fields ~L33; store path ~L529; `check_invalidation` L746)
- Modify: `wing.goose` (add `import http.cache.cache_groups;` after the `http.cache.engine` import ~L123)
- Test: `tests/http_cache_test.goose`

**Interfaces:**
- Consumes: `parse_sfv_list` (`http/mime.goose`), `HttpCache` / `CachedEntry` / `check_invalidation` (`http/cache/engine.goose`), `HeaderMap.header` for reading `Cache-Groups` / `Cache-Group-Invalidation`.
- Produces:
  - `struct CacheGroupTag { len: i32 = 0, name: u8[..64] = [] }`
  - `fn parse_cache_group_list(raw: const u8[:], out_tags: CacheGroupTag[..8]&, out_count: i32&) -> bool`
  - `fn serialize_cache_group_list(tags: const CacheGroupTag[..8]&, count: i32, out: u8[..512]&) -> i32` (bytes written, or -1 on overflow)
  - `fn entry_has_group(entry: const CachedEntry&, group: const u8[:]) -> bool`
  - `fn invalidate_group(cache: HttpCache&, group: const u8[:]) -> i64` (entries invalidated)
  - `CachedEntry` gains `group_count: i32 = 0` and `groups: CacheGroupTag[..8] = []`

- [ ] **Step 1: Write the failing tests** in `tests/http_cache_test.goose`

Add `fn test_cache_groups(t: lit::T&)` and register `"N. RFC 9875 Cache Groups"` (N = next free case number). Assertions with exact values:
- `parse_cache_group_list("\"scripts\", \"fonts\"", tags, count)` → `ok == true`, `count == 2`, `tags[0].name[..] == "scripts"`, `tags[1].name[..] == "fonts"`.
- `parse_cache_group_list("\"eurovision-results\", \"australia\"", ...)` → `count == 2` (RFC 9875 §3 example).
- Malformed: `parse_cache_group_list("\"a\", \"b", ...)` (unterminated quote) → `ok == false`, `count == 0` (fail closed).
- Round-trip: `serialize_cache_group_list` of the two tags → output equals `"scripts", "fonts"` when re-parsed.
- Store path: a stored response with `Cache-Groups: "scripts"` yields `entry.group_count == 1` and `entry_has_group(entry, "scripts") == true`.
- Invalidation: two entries tagged `"catalog"`, one tagged `"user-42"`; `invalidate_group(cache, "catalog")` returns `2`, the `"user-42"` entry remains valid; `check_invalidation` on a response with `Cache-Group-Invalidation: "catalog"` performs the same purge (RFC 9875 §3).

- [ ] **Step 2: Run the suite to verify it fails**

Run: `goose-lit tests/http_cache_test.goose`
Expected: FAIL — `parse_cache_group_list` / `CacheGroupTag` not defined.

- [ ] **Step 3: Implement `http/cache/cache_groups.goose`**

Constants: `const CACHE_GROUP_TAG_MAX: i32 = 64;` `const CACHE_GROUP_MAX_PER_ENTRY: i32 = 8;` (both cited RFC 9875 §2/§3). `parse_cache_group_list` walks the SFV list with `parse_sfv_list`-style items, copies each string item into `out_tags[i].name` (rejecting `len > 64` and `count > 8` with `ok == false` and `out_count == 0`). `serialize_cache_group_list` writes quoted items joined by `", "`. `entry_has_group` case-sensitive compare (RFC 9875 group names are case-sensitive strings). `invalidate_group` scans `cache.entries`, for each `is_valid` entry whose groups contain `group`, zeroes `is_valid` and increments a returned count (reuse the entry-reset helper used by `invalidate_matching_url`).

- [ ] **Step 4: Wire into `http/cache/engine.goose` and `wing.goose`**

Add the two fields to `CachedEntry`. In the store path (`engine.goose` ~L529), read `resp.header("Cache-Groups")` and populate `entry.groups` via `parse_cache_group_list` (ignore on parse failure — no partial tags). In `check_invalidation` (L746), after the existing URL cascade, read `resp.header("Cache-Group-Invalidation")`, parse it, and call `invalidate_group` for each tag (MUST be ignored on requests — only act on responses, RFC 9875 §3). Add `import http.cache.cache_groups;` to `wing.goose` after the `http.cache.engine` import.

- [ ] **Step 5: Run the suite to verify it passes**

Run: `goose-lit tests/http_cache_test.goose`
Expected: PASS (all cases including pre-existing).

- [ ] **Step 6: Typecheck, lint, commit**

Run: `just check && just lint-invariants --target-file http/cache/cache_groups.goose`
Then commit on branch `feat/rfc-9875-cache-groups`:
```bash
git add http/cache/cache_groups.goose http/cache/engine.goose tests/http_cache_test.goose
git commit -m "feat(rfc9875): HTTP Cache Groups parse/serialize and group invalidation"
```

---

### Task 2: RFC 9440 Client-Cert Header

**Files:**
- Create: `http/client_cert.goose`
- Modify: `proxy/reverse_proxy.goose` (`is_forwarded_metadata_header` L53; `should_forward_header` L68; `filter_and_forward_headers` L209; `ProxyConfig` L18)
- Modify: `wing.goose` (add `import http.client_cert;` immediately after `import http.trace;` ~L88 — anchor chosen so Task 2 and Task 4 import insertions stay 12+ lines apart and merge cleanly)
- Test: `tests/net_proxy_test.goose`

**Interfaces:**
- Consumes: `parse_sfv_binary` / `parse_sfv_list` (`http/mime.goose`), `base64url`-style DER encoding via SFV Byte Sequence form (`:base64:`), `HeaderMap` append/remove, `is_forwarded_metadata_header` strip list.
- Produces:
  - `fn parse_client_cert(raw: const u8[:], out_der: u8[..4096]&, out_len: i32&) -> bool`
  - `fn encode_client_cert(der: const u8[:], out: u8[..8192]&) -> i32` (bytes written, -1 on overflow)
  - `fn parse_client_cert_chain(raw: const u8[:], out_certs: u8[..4096][..4]&, out_lens: i32[..4]&, out_count: i32&) -> bool`
  - `ProxyConfig` gains `forward_client_cert: bool = false` and `client_cert_der: u8[..4096] = []`

- [ ] **Step 1: Write the failing tests** in `tests/net_proxy_test.goose`

Add `fn test_client_cert_header(t: lit::T&)` and register `"N. RFC 9440 Client-Cert"`. Assertions with exact values:
- `parse_client_cert(":MIIB...:", ...)` round-trips through `encode_client_cert` byte-for-byte on a fixed 64-byte DER fixture (use a synthetic byte string; SFV Byte Sequence is base64 of the DER).
- `parse_client_cert_chain(":a, :b,", ...)` → `count == 2`.
- Spoofing strip: `is_forwarded_metadata_header("client-cert") == true`, `("Client-Cert-Chain") == true`, `("CLIENT-CERT") == true` (case-folded).
- `filter_and_forward_headers` on a request carrying incoming `Client-Cert: :spoof:` with `config.forward_client_cert == false` → output headers contain no `Client-Cert`.
- Injection: with `config.forward_client_cert == true` and `client_cert_der` set, output headers contain exactly one `Client-Cert` whose value equals `encode_client_cert(config.client_cert_der, ...)`.

- [ ] **Step 2: Run the suite to verify it fails**

Run: `goose-lit tests/net_proxy_test.goose`
Expected: FAIL — `parse_client_cert` not defined.

- [ ] **Step 3: Implement `http/client_cert.goose`**

`parse_client_cert` accepts exactly one SFV Byte Sequence (`:<base64>:`), decodes it into `out_der` (reject `len > 4096`, reject trailing content after the closing colon → `ok == false`). `encode_client_cert` writes `:` + base64(DER) + `:`. `parse_client_cert_chain` parses an SFV List of Byte Sequences, up to 4 items, each ≤ 4096 B; any malformed item rejects the whole field (`ok == false`, `out_count == 0`) per RFC 9440 §2.3. Cite RFC 9440 §2.2 / §2.3 in comments.

- [ ] **Step 4: Wire into `proxy/reverse_proxy.goose` and `wing.goose`**

Add `"client-cert"` and `"client-cert-chain"` to `is_forwarded_metadata_header` (RFC 9440: proxies MUST remove incoming `Client-Cert*` from untrusted clients). In `filter_and_forward_headers`, after `copy_filtered_headers`, if `config.forward_client_cert && config.client_cert_der_len > 0`, append one `Client-Cert` header via `encode_client_cert`. (Store DER length in `ProxyConfig` as `client_cert_der_len: i32 = 0` alongside the buffer.) Add `import http.client_cert;` to `wing.goose` in the http import block.

- [ ] **Step 5: Run the suite to verify it passes**

Run: `goose-lit tests/net_proxy_test.goose`
Expected: PASS.

- [ ] **Step 6: Typecheck, lint, commit**

Run: `just check && just lint-invariants --target-file http/client_cert.goose`
Then commit on branch `feat/rfc-9440-client-cert`:
```bash
git add http/client_cert.goose proxy/reverse_proxy.goose tests/net_proxy_test.goose
git commit -m "feat(rfc9440): Client-Cert/Client-Cert-Chain codec and proxy sanitization"
```

---

### Task 3: RFC 9369 QUIC Version 2

**Files:**
- Modify: `quic/packet.goose` (version consts L14-16; long-header type decode ~L250; VN handling ~L268)
- Modify: `tls/key_schedule.goose` (`ks_derive_quic_hp_key` L426; initial-key derivation entry points — locate `hkdf_expand_label(..., "quic hp"/"quic key"/"quic iv", ...)` call sites)
- Test: `tests/quic_test.goose`

**Interfaces:**
- Consumes: `hkdf_expand_label` (`tls/key_schedule.goose`), `QUIC_VERSION_1` / `QUIC_VERSION_NEGOTIATION` (`quic/packet.goose`), existing initial-salt constant (locate the v1 salt 20-byte array in `quic/` or `tls/` — grep `0x38762cf7`).
- Produces:
  - `const QUIC_VERSION_2: u32 = 0x6b3343cf; // RFC 9369 §3.1`
  - `const QUIC_V2_INITIAL_SALT: u8[..20] = [0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9]; // RFC 9369 §3.3.1`
  - `fn quic_initial_salt(version: u32) -> const u8[:]` (v1 salt for `QUIC_VERSION_1`, v2 salt for `QUIC_VERSION_2`, empty slice otherwise)
  - `fn quic_hkdf_label_prefix(version: u32) -> const u8[:]` (`"quic "` for v1, `"quicv2 "` for v2 — RFC 9369 §3.3.2)
  - `fn quic_long_header_type(version: u32, two_bits: u8) -> QuicHeaderType, bool` (v1: 0=Initial,1=0-RTT,2=Handshake,3=Retry; v2: 1=Initial,2=0-RTT,3=Handshake,0=Retry — RFC 9369 §3.2)
  - `ks_derive_quic_hp_key` and the initial key/iv derivation gain a trailing `version: u32` parameter selecting `quic_hkdf_label_prefix`

- [ ] **Step 1: Write the failing tests** in `tests/quic_test.goose`

Add `fn test_quic_version2(t: lit::T&)` and register `"N. RFC 9369 QUIC v2"`. Assertions with exact values:
- `QUIC_VERSION_2 == 0x6b3343cf`.
- `quic_initial_salt(QUIC_VERSION_2)[..] == [0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9]` and differs from `quic_initial_salt(QUIC_VERSION_1)`.
- `quic_hkdf_label_prefix(QUIC_VERSION_2) == "quicv2 "`, `quic_hkdf_label_prefix(QUIC_VERSION_1) == "quic "`; derived HPKE/hp key bytes for the same secret differ between versions.
- `quic_long_header_type(QUIC_VERSION_2, 0b01) == QuicHeaderType.Initial`; `quic_long_header_type(QUIC_VERSION_1, 0b00) == QuicHeaderType.Initial`; `quic_long_header_type(QUIC_VERSION_2, 0b00) == QuicHeaderType.Retry`.
- Version negotiation packet for a v2-only peer lists `0x6b3343cf`.

- [ ] **Step 2: Run the suite to verify it fails**

Run: `goose-lit tests/quic_test.goose`
Expected: FAIL — `QUIC_VERSION_2` not defined.

- [ ] **Step 3: Implement version constants and salt/label dispatch in `quic/packet.goose`**

Add `QUIC_VERSION_2` and `QUIC_V2_INITIAL_SALT` (exact bytes above, cited RFC 9369 §3.1/§3.3.1). Implement `quic_initial_salt`, `quic_hkdf_label_prefix`, `quic_long_header_type` as pure functions on `(version, bits)` with `bool` false for unknown versions/illegal bit patterns. Replace the v1-only type decode at ~L250 with `quic_long_header_type(hdr.version, two_bits)`.

- [ ] **Step 4: Thread `version` through key derivation in `tls/key_schedule.goose`**

Locate every initial/header-protection derivation that hardcodes `"quic key"` / `"quic iv"` / `"quic hp"` / `"quic ku"` (grep `"quic `). Replace the literal label with `quic_hkdf_label_prefix(version)` concatenated with `key`/`iv`/`hp`/`ku`, and select salt via `quic_initial_salt(version)`. Keep v1 behavior byte-identical (existing tests must pass unchanged).

- [ ] **Step 5: Run the suite to verify it passes**

Run: `goose-lit tests/quic_test.goose && goose-lit tests/http3_test.goose`
Expected: PASS (v1 vectors unchanged, v2 cases green).

- [ ] **Step 6: Typecheck, lint, commit**

Run: `just check && just lint-invariants --target-file quic/packet.goose`
Then commit on branch `feat/rfc-9369-quic-v2`:
```bash
git add quic/packet.goose tls/key_schedule.goose tests/quic_test.goose
git commit -m "feat(rfc9369): QUIC v2 version, initial salt, HKDF labels, header type remap"
```

---

### Task 4: RFC 9292 bhttp + RFC 9458 Oblivious HTTP

**Files:**
- Create: `http/bhttp.goose`
- Create: `http/ohttp.goose`
- Create: `tests/http_ohttp_test.goose`
- Modify: `tls/hpke.goose` (add `hpke_export`; add `kem_id`/`kdf_id` to `HpkeContext`; fix L4 citation `RFC 9460` → `RFC 9849`)
- Modify: `wing.goose` (add `import http.bhttp;` and `import http.ohttp;` immediately after `import http.h2_framer;` ~L100 — anchor chosen so Task 2 and Task 4 import insertions stay 12+ lines apart and merge cleanly)

**Interfaces:**
- Consumes: `hpke_setup_base_s` / `hpke_setup_base_r` / `hpke_seal` / `hpke_open` and `HPKE_KEM_DHKEM_X25519_HKDF_SHA256`, `HPKE_KDF_HKDF_SHA256`, `HPKE_AEAD_AES_128_GCM` (`tls/hpke.goose`); `HeaderMap`; bhttp framing indicator values from `.gemini/rfc/rfc9292.txt` §3.3 (0=request known-length, 1=response known-length, 2/3=indeterminate — other values invalid).
- Produces:
  - `const BHTTP_FRAME_KNOWN_LEN_REQUEST: u8 = 0;` `const BHTTP_FRAME_KNOWN_LEN_RESPONSE: u8 = 1;` (RFC 9292 §3.3)
  - `struct BhttpRequest { method: u8[..16] = "GET", target: u8[..2048] = [], headers: HeaderMap = HeaderMap { .. }, body: u8[..4096] = [], body_len: i32 = 0 }`
  - `struct BhttpResponse { status: i32 = 200, headers: HeaderMap = HeaderMap { .. }, body: u8[..4096] = [], body_len: i32 = 0 }`
  - `fn bhttp_encode_request(req: const BhttpRequest&, out: u8[..8192]&) -> i32` (bytes written, -1 on overflow/invalid)
  - `fn bhttp_decode_request(raw: const u8[:], out: BhttpRequest&) -> bool` (reject unknown framing indicator per RFC 9292 §4)
  - `fn bhttp_encode_response(res: const BhttpResponse&, out: u8[..8192]&) -> i32`
  - `fn bhttp_decode_response(raw: const u8[:], out: BhttpResponse&) -> bool`
  - `struct OhttpKeyConfig { key_id: u8 = 0, kem_id: u16 = HPKE_KEM_DHKEM_X25519_HKDF_SHA256, kdf_id: u16 = HPKE_KDF_HKDF_SHA256, aead_id: u16 = HPKE_AEAD_AES_128_GCM, public_key: u8[..32] = [], public_key_len: i32 = 0 }`
  - `fn parse_ohttp_key_config(raw: const u8[:], out: OhttpKeyConfig&) -> bool` (RFC 9458 §3.1 layout — read `.gemini/rfc/rfc9458.txt` §3.1 for exact field order/lengths before implementing)
  - `fn parse_ohttp_key_configs(raw: const u8[:], out: OhttpKeyConfig[..4]&, out_count: i32&) -> bool` (`application/ohttp-keys` = concatenation of `u16be length || key config`, RFC 9458 §3.2; ANY malformed element → discard whole collection, `ok == false`)
  - `struct OhttpSession { ctx: HpkeContext = HpkeContext { .. }, enc: u8[..32] = [], enc_len: i32 = 0 }` (retained per-exchange state: HPKE context + `enc` from `enc_request`, needed as response salt — RFC 9458 §4.3 step 4, §4.4 step 3)
  - `fn hpke_export(ctx: const HpkeContext&, exporter_context: const u8[:], out: u8[:]) -> bool` — added to `tls/hpke.goose`; implements RFC 9180 §5.3 `Context.Export = LabeledExpand(exporter_secret, "sec", exporter_context, L)` reusing `hpke_labeled_expand`; add `kem_id: u16` and `kdf_id: u16` fields to `HpkeContext` (set in `hpke_setup_base_s`/`hpke_setup_base_r`) so `suite_id` is recoverable at export time
  - `fn ohttp_seal_request(cfg: const OhttpKeyConfig&, inner_bhttp: const u8[:], out: u8[..8192]&, out_len: i32&, session: OhttpSession&) -> bool` — `hdr = key_id || kem_id || kdf_id || aead_id` (8+16+16+16 bits, network order, 7 bytes); `info = "message/bhttp request" || 0x00 || hdr`; `enc_request = hdr || enc || ct` (RFC 9458 §4.1); fills `session` with sender context + `enc`
  - `fn ohttp_open_request(skR: const u8[:], enc_request: const u8[:], out: u8[..8192]&, out_len: i32&, session: OhttpSession&) -> bool` (gateway: SetupBaseR + Open; fills `session` with receiver context + `enc` so the response can be sealed — RFC 9458 §4.3)
  - `fn ohttp_seal_response(session: const OhttpSession&, response_nonce: const u8[:], response: const u8[:], out: u8[..8192]&, out_len: i32&) -> bool` — RFC 9458 §4.4: `secret = hpke_export(session.ctx, "message/bhttp response", max(Nn,Nk))`; `prk = hkdf_extract(salt = session.enc || response_nonce, ikm = secret)`; `aead_key = hkdf_expand(prk, "key", Nk)`; `aead_nonce = hkdf_expand(prk, "nonce", Nn)`; `ct = AEAD.Seal(...)`; `enc_response = response_nonce || ct`. `response_nonce` is caller-supplied (length must equal `max(Nn,Nk)`; engine does not own entropy). Use raw `hkdf_extract` / `hkdf_expand_bytes_256` from `core/crypto/sha.goose` — NOT TLS-style `hkdf_expand_label`
  - `fn ohttp_open_response(session: const OhttpSession&, enc_response: const u8[:], out: u8[..8192]&, out_len: i32&) -> bool` — client side; same derivation using `session.ctx` (sender context) as `context`, per §4.4

- [ ] **Step 1: Write the failing tests** in `tests/http_ohttp_test.goose` (new file; register the suite the same way sibling suites do)

Assertions with exact values:
- bhttp: encode a known-length request (`GET /index.html`, one header, body `"hi"`) → first byte `0x00`; decode round-trips method/target/headers/body. Encode a known-length response → first byte `0x01`. Decode of framing indicator `0x04` → `ok == false` (RFC 9292 §4).
- OHTTP: `parse_ohttp_key_configs` on a two-config collection with second element's length prefix lying → `ok == false`, `out_count == 0` (RFC 9458 §3.2 MUST discard).
- Seal/open round-trip: `ohttp_seal_request` then `ohttp_open_request` with the same keypair returns the original bhttp bytes; output layout starts with the 7-byte hdr (`key_id, kem_id, kdf_id, aead_id` = `0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01` for key_id=1, X25519/HKDF-SHA256/AES-128-GCM).
- Tamper: flip one ciphertext byte → `ohttp_open_request` returns `false`.
- Response round-trip (RFC 9458 §4.4): `ohttp_seal_request` → gateway `ohttp_open_request` → `ohttp_seal_response` with a fixed 16-byte `response_nonce` → client `ohttp_open_response` returns the original response bhttp; flipping one byte of `enc_response` makes `ohttp_open_response` return `false`.
- `hpke_export`: on a context from `hpke_setup_base_s`, `hpke_export(ctx, "message/bhttp response", out[16])` is deterministic for fixed inputs and differs when `exporter_context` differs.
- If `.gemini/rfc/rfc9458.txt` contains an Appendix vector for encapsulated request/response, verify `ohttp_seal_*` output matches it byte-for-byte; if absent, the round-trip cases above are the conformance proof (note this in the test comment).

- [ ] **Step 2: Run the suite to verify it fails**

Run: `goose-lit tests/http_ohttp_test.goose`
Expected: FAIL — `bhttp_encode_request` not defined.

- [ ] **Step 3: Implement `http/bhttp.goose`**

Known-length framing only (indeterminate-length is out of scope — non-goal). Control data, field section and content encodings follow `.gemini/rfc/rfc9292.txt` §3.4–§3.6 exactly; read those sections in the corpus before writing encoders. Zero-heap: all decode outputs land in the struct's fixed buffers; overflow → `ok == false`.

- [ ] **Step 4: Implement `http/ohttp.goose` and extend `tls/hpke.goose`**

First extend `tls/hpke.goose`: add `kem_id: u16` / `kdf_id: u16` to `HpkeContext` (populated in `hpke_setup_base_s`/`hpke_setup_base_r`) and add `hpke_export` per RFC 9180 §5.3; fix the L4 citation to RFC 9849. Then implement OHTTP: key-config layout from RFC 9458 §3.1 (read corpus: Key Identifier 8-bit, KEM ID 16-bit, Public Key Npk bytes, Symmetric Algorithms Length 16-bit = 4..65532, then repeated 4-byte KDF+AEAD pairs). Collection parser per §3.2 with all-or-nothing discard. Request seal/open via `hpke_setup_base_s`/`hpke_setup_base_r` + `hpke_seal`/`hpke_open` with the exact `info` strings; response seal/open per §4.4 (Export + HKDF re-derivation — see Interfaces). Suite selection restricted to X25519/HKDF-SHA256 + AES-128-GCM or ChaCha20-Poly1305 (matching `tls/hpke.goose` capabilities) — reject other suites with `ok == false`.

- [ ] **Step 5: Register imports in `wing.goose`**

Add `import http.bhttp;` and `import http.ohttp;` inside the existing http import block (L36-45) only — do not touch other blocks.

- [ ] **Step 6: Run the suite to verify it passes**

Run: `goose-lit tests/http_ohttp_test.goose && goose-lit tests/http1_test.goose`
Expected: PASS.

- [ ] **Step 7: Typecheck, lint, commit**

Run: `just check && just lint-invariants --target-file http/ohttp.goose`
Then commit on branch `feat/rfc-9458-ohttp`:
```bash
git add http/bhttp.goose http/ohttp.goose tests/http_ohttp_test.goose tls/hpke.goose wing.goose
git commit -m "feat(rfc9458): binary HTTP codec and Oblivious HTTP seal/open over HPKE"
```

---

### Task 5: RFC 8555 ACME HTTP-01 Primitives

**Files:**
- Create: `auth/acme.goose`
- Modify: `auth/README.md` (one-line API entry — this file is Task 5's only shared-doc touch; root README is Task 7)
- Modify: `wing.goose` (add `import auth.acme;` after the `auth.jwks` import ~L140)
- Test: `tests/auth_test.goose`

**Interfaces:**
- Consumes: `base64url_encode` (`core/crypto/base64.goose` L20), `compute_jwk_thumbprint` (`auth/jwks.goose` L148), `hash` (SHA-256, `core/crypto/`).
- Produces:
  - `const ACME_HTTP01_PREFIX: u8[..28] = "/.well-known/acme-challenge/"; // RFC 8555 §8.3`
  - `fn acme_validate_token(token: const u8[:]) -> bool` (base64url charset `[A-Za-z0-9_-]`, length 1..=64, no `/`, `.`, `%` — RFC 8555 §8.1/§8.3)
  - `fn acme_key_authorization(token: const u8[:], thumbprint_b64url: const u8[:], out: u8[..256]&) -> i32` — body = `token || '.' || thumbprint_b64url` (RFC 8555 §8.1)
  - `fn acme_http01_path(token: const u8[:], out: u8[..128]&) -> i32` — `ACME_HTTP01_PREFIX || token`
  - `fn acme_match_http01(path: const u8[:], token: const u8[:]) -> bool` (prefix + exact token equality; constant-time-ish compare of the token suffix)
  - `struct AcmeChallenge { token: u8[..64] = [], key_auth: u8[..256] = [], key_auth_len: i32 = 0 }`
  - `fn acme_find_challenge(table: const AcmeChallenge[..8]&, path: const u8[:], out_body: u8[..256]&, out_len: i32&) -> bool` (HTTP-01 responder helper: matches path, copies stored key authorization)

- [ ] **Step 1: Write the failing tests** in `tests/auth_test.goose`

Add `fn test_acme_http01(t: lit::T&)` and register `"N. RFC 8555 ACME HTTP-01"`. Assertions with exact values:
- `acme_validate_token("LoqXcYV8vQa8jxAjEuX0")` → `true` (RFC 8555 §8.3 example token); `acme_validate_token("../etc/passwd")` → `false`; `acme_validate_token("a/b")` → `false`; `acme_validate_token("")` → `false`.
- `acme_key_authorization("tok", "TP", out)` → body equals `"tok.TP"` (exact §8.1 formula: `token || '.' || base64url(Thumbprint(accountKey))`).
- `acme_http01_path("tok", out)` → `"/.well-known/acme-challenge/tok"` (exact §8.3 prefix).
- `acme_match_http01("/.well-known/acme-challenge/tok", "tok")` → `true`; `acme_match_http01("/.well-known/acme-challenge/other", "tok")` → `false`; `acme_match_http01("/.well-known/acme-challenge/../tok", "tok")` → `false`.
- Responder: table with one `AcmeChallenge{token: "tok", key_auth: "tok.TP"}`; `acme_find_challenge(table, "/.well-known/acme-challenge/tok", body, len)` → `true`, `body == "tok.TP"`; unknown path → `false`.

- [ ] **Step 2: Run the suite to verify it fails**

Run: `goose-lit tests/auth_test.goose`
Expected: FAIL — `acme_validate_token` not defined.

- [ ] **Step 3: Implement `auth/acme.goose`**

All functions zero-alloc on caller buffers. `acme_validate_token` rejects any byte outside `[A-Za-z0-9_-]` and lengths outside `1..=64`. `acme_key_authorization` appends `token`, `'.'`, `thumbprint_b64url` (caller supplies the RFC 7638 thumbprint already base64url-encoded via `base64url_encode` + `compute_jwk_thumbprint` — compose, do not re-encode). `acme_match_http01` compares prefix then token byte-by-byte. `acme_find_challenge` linear-scans ≤ 8 slots. Cite RFC 8555 §8.1 / §8.3 (verified in `.gemini/rfc/rfc8555.txt` L3453, L3563).

- [ ] **Step 4: Run the suite to verify it passes**

Run: `goose-lit tests/auth_test.goose`
Expected: PASS.

- [ ] **Step 4b: Register the module in `wing.goose`**

Add `import auth.acme;` after the `auth.jwks` import. Re-run `just check` to confirm the export resolves.

- [ ] **Step 5: Typecheck, lint, commit**

Run: `just check && just lint-invariants --target-file auth/acme.goose`
Then commit on branch `feat/rfc-8555-acme`:
```bash
git add auth/acme.goose auth/README.md tests/auth_test.goose
git commit -m "feat(rfc8555): ACME HTTP-01 key authorization and challenge responder primitives"
```

---

### Task 6: RFC 9849 ECH Citation Refresh

**Files:**
- Modify: `tls/ech.goose` (header comment L4; `EXT_ENCRYPTED_CLIENT_HELLO` L15; `ECH_VERSION_DRAFT13` L21 and all references L31, L146, L181, L228; padding comment L246)
- Test: `tests/tls_advanced_test.goose`

**Interfaces:**
- Consumes: `.gemini/rfc/rfc9849.txt` (wire values: ECH extension/version `0xFE0D`, HpkeKemId/HpkeKdfId/HpkeAeadId fields — verify L278-280 region of the corpus before editing).
- Produces:
  - `const ECH_VERSION_RFC9849: u16 = 0xFE0D;` (renamed from `ECH_VERSION_DRAFT13`, value unchanged — RFC 9849)
  - All `tls/ech.goose` comments cite RFC 9849 (no `draft-ietf-tls-esni`, no `RFC 9460` for ECH itself; RFC 9460 may remain only where DNS HTTPS RR configuration is the subject)
  - Test case `"N. RFC 9849 ECH constants"` asserting `ECH_VERSION_RFC9849 == 0xFE0D` and `EXT_ENCRYPTED_CLIENT_HELLO == 0xFE0D`, matching `rfc9849.txt`
  - Note: the `tls/hpke.goose` L4 citation fix (`RFC 9460` → `RFC 9849`) is owned by Task 4, which already modifies that file — do not touch `tls/hpke.goose` here.

- [ ] **Step 1: Write the failing test** in `tests/tls_advanced_test.goose`

Add `fn test_ech_rfc9849_citations(t: lit::T&)` asserting `wing::ECH_VERSION_RFC9849 == 0xFE0D` and `wing::EXT_ENCRYPTED_CLIENT_HELLO == 0xFE0D` (compile will fail first because the constant does not exist yet — that is the failing test).

- [ ] **Step 2: Run the suite to verify it fails**

Run: `goose-lit tests/tls_advanced_test.goose`
Expected: FAIL — `ECH_VERSION_RFC9849` not defined.

- [ ] **Step 3: Rename and re-cite in `tls/ech.goose`**

Rename `ECH_VERSION_DRAFT13` → `ECH_VERSION_RFC9849` (all references). Rewrite header comments to cite RFC 9849 (verified against `.gemini/rfc/rfc9849.txt`; keep `0xFE0D` values — they match the final RFC). Do not touch `tls/hpke.goose` (owned by Task 4). No behavioral change: every existing ECH test must pass byte-identically.

- [ ] **Step 4: Run the suites to verify they pass**

Run: `goose-lit tests/tls_advanced_test.goose && goose-lit tests/tls_test.goose`
Expected: PASS (all ECH wire tests unchanged).

- [ ] **Step 5: Typecheck, lint, commit**

Run: `just check && just lint-invariants --target-file tls/ech.goose`
Then commit on branch `feat/rfc-9849-ech-refresh`:
```bash
git add tls/ech.goose tests/tls_advanced_test.goose
git commit -m "docs(rfc9849): refresh ECH citations from draft-ietf-tls-esni to RFC 9849"
```

---

### Task 7: Shared Documentation Sweep (post-merge, serialized)

**Files:**
- Modify: `README.md` (subsystems table — add rows for Cache Groups, Client-Cert, QUIC v2, OHTTP, ACME HTTP-01)
- Modify: `docs/rfc_conformance.md` (add/refresh entries for RFC 9875, 9440, 9369, 9458, 9292, 8555, 9849 with exact status)
- Test: none (documentation only; `just check` must still pass)

**Interfaces:**
- Consumes: merged state of Tasks 1-6 (final API names as committed).
- Produces: none beyond docs.

- [ ] **Step 1: Update `README.md` subsystems table**

One row per new capability, matching existing table style and column widths.

- [ ] **Step 2: Update `docs/rfc_conformance.md`**

Entries cite RFC number + title + implemented-symbols summary; section numbers verified against `.gemini/rfc/`.

- [ ] **Step 3: Verify and commit**

Run: `just check`
Commit on branch `docs/rfc-matrix` (or directly on `main` after all track merges):
```bash
git add README.md docs/rfc_conformance.md
git commit -m "docs: record RFC 9875/9440/9369/9458/8555/9849 coverage in README and conformance table"
```

---

## Execution Notes (controller)

- Tracks 1-6 run in parallel: one worktree each (`.worktrees/rfc-<num>-<slug>`), one branch each (`feat/rfc-<num>-<slug>`), disjoint file ownership — no two tracks edit the same file except `wing.goose` import lines (Track 4 only) and `auth/README.md` (Track 5 only).
- Merge order into `main`: any order via `git rebase main` per branch then fast-forward; if rebase conflicts (expected only in `wing.goose` import block across tracks — Track 4 is the only one touching it, so conflicts are unlikely), fall back to `git format-patch main..branch` + `git am`.
- Task 7 runs only after Tasks 1-6 are merged.
- Each implementer gets: its task brief (extracted via `task-brief`), the Global Constraints block, its worktree path, suite command, report path/contract, and the no-subagents rule. Reviewers get brief + report + review package + the Global Constraints block.
