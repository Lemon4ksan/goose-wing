# Cryptography, Wire Protocols, & Specification Compliance Playbook

Load this reference when auditing `.goose` modules that implement cryptography, authentication (JWT, JWKS, OAuth, Digest, DPoP, mTLS), binary/text wire framing (HTTP/1.1, HTTP/2, HTTP/3, QUIC, WebSocket, gRPC, TLS, DNS), or RFC/specification contracts.

---

## 1. Constant-Time Execution & Secret Zeroization

### 1.1 Constant-Time Byte Comparison (`ct_eq_bytes`)
- **Rule**: Never compare cryptographic digests, HMAC tags, AEAD tags, PKCE challenges, Digest `response` hashes, or bearer/session tokens using `==`, `!=`, or early-exit byte loops (`eq_bytes`).
- **Required Primitive**: Always verify that `core::ct_eq_bytes(actual, expected)` (or bitwise XOR accumulation `(a[i] ^ b[i])` across the full fixed length) is used.
- **Length Leak Check**: Check whether `ct_eq_bytes` is preceded by an asymmetric length guard that leaks secret length rather than expected public tag length.

### 1.2 Secret Zeroization Across All Return Paths
- **Rule**: Goose has **no destructors (`Drop`) and no `defer`**. Any local stack array (`var secret: u8[32]`, `var shared_key: u8[..64]`, `var key_material: u8[..128]`) or session struct holding private keys, shared secrets, or plaintext passwords must be zeroized on **every** exit path.
- **Audit Checklist**:
  1. Locate every `var` holding key material or intermediate HMAC/HKDF state.
  2. Trace every `guard ... else { return ...; }` and `if ... { return ...; }` between the secret's population and the end of the function.
  3. Flag any early return path that exits before calling `zeroize*` on the secret buffer.

### 1.3 Secret-Dependent Branching, Indexing, & Division
- In cryptographic primitives (Ed25519, X25519, ChaCha20, Poly1305, AES, SHA/HKDF):
  - Check for hardware division (`/` or `%`) or variable-count shifts on secret scalars.
  - Check for table lookups indexed by secret bytes (`table[secret_byte]`).

---

## 2. Cryptographic & Protocol Order-of-Operations (Doom Principle)

### 2.1 Verify Before Parsing or Mutating State
- **JWT / DPoP / JWS**:
  - The header `alg` and `typ` must be validated against an explicit allowlist (`alg != "none"`, no symmetric/asymmetric `HMAC` vs `Ed25519` confusion) and the cryptographic signature verified **before** trusting payload claims (`iss`, `sub`, `exp`, `jti`) or inserting `jti` into a replay cache.
- **AEAD / TLS Record / QUIC Packet Decryption**:
  - Never increment sequence numbers (`read_seq += 1`), update anti-replay bitmasks, or evict connection table entries **before** AEAD tag verification succeeds. If decryption fails, all connection state and cursors must remain unchanged.
- **Dynamic Table / Cache Eviction (`HPACK`, `QPACK`, `JWKS`, `SessionCache`)**:
  - When inserting a replacement key or oversized entry into a bounded table: verify that the new entry satisfies `entry.size <= max_table_capacity` **before** evicting existing entries or deleting an existing key with the same name.

---

## 3. Wire Framing, Normalization, & Smuggling Disagreements

### 3.1 Dual-Header & Framing Ambiguities
- **HTTP/1.1 vs. HTTP/2 / Reverse Proxy**:
  - Reject messages containing both `Transfer-Encoding` and `Content-Length`, or multiple `Content-Length` headers with differing values.
  - Reject header field names containing whitespace (` `, `\t`) before the colon or control characters (`0x00..0x1F`, `0x7F`).
  - Ensure chunked transfer-coding parsers reject trailing non-hex characters in chunk-size lines unless explicitly parsed as valid `;chunk-ext` per RFC 9112.

### 3.2 Canonicalization Before Security Checks (SSRF / Path / Host)
- Whenever a function checks a hostname, IP address, URI path, or scheme against a security policy:
  1. **Trailing Dots & Case**: Does `"localhost."` or `"METADATA.GOOGLE.INTERNAL."` bypass `eq_bytes(host, "localhost")`?
  2. **IPv6 & IPv4-Mapped IPv6**: Does `[::1]`, `[0:0:0:0:0:0:0:1]`, or `[::ffff:127.0.0.1]` bypass an IPv4-only loopback/RFC1918 check (`127.0.0.1`, `10.0.0.0/8`, `169.254.169.254`)?
  3. **Alternative Integer IP Encodings**: If downstream resolvers accept decimal/octal/shortened IPv4 (`2130706433`, `0177.0.0.1`, `127.1`), does the validator reject non-canonical IPv4 literals?
  4. **Structured Readers Over Substring Search**: Ensure JSON, URL query strings, and HTTP headers are parsed with streaming tokenizers rather than naive `index_of_slice` / `contains` (which are trivially bypassed by escaped quotes `\"` or duplicate keys).

---

## 4. Spec-to-Code Atomic Compliance Auditing

When a `.goose` module cites an RFC section (`// RFC <NUM> Section <X.Y>: ...`), a design doc, or a `README.md` contract:

1. **Extract Atomic Claims**: Break each normative requirement (`MUST`, `MUST NOT`, `REQUIRED`, or documented function invariant) into an atomic testable rule:
   - *Input condition* -> *Required state transition / return value / error code*.
2. **Trace Exact Implementation**: Locate the exact lines in the `.goose` function handling that condition.
3. **Classify Alignment**:
   - `IMPLEMENTED`: Matches specification across all boundary values (`0`, `1`, `cap - 1`, `cap`, `cap + 1`).
   - `PARTIAL`: Handles the happy path but misses a required error code, close frame, or delimiter variation (e.g., comma-separated lists `qop="auth-int, auth"` with varying whitespace).
   - `CONTRADICTED`: Code does the opposite of the spec or comment (e.g., doc comment says "returns `false` on overflow" while code silently clamps or returns `true`).
   - `ABSENT`: Requirement is cited in comments/docs but completely unimplemented in code (`GOOSE-BUG-1`).
