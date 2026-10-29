# RFC conformance matrix

This matrix documents protocol specification conformance in `goose-wing` and maps relevant RFC sections to native LIT verification test suites (`tests/lit/*.goose`).

Every suite executes wire verification, prefix slicing (`wire_kit::verify_split_stream`), mutation fuzzing (`wire_kit::fuzz_payload`), and hardware complexity gate checks (`goose-lit gate <suite> 25`).

## Core HTTP specifications

| Specification | Title | Verified sections | LIT verification test suite |
| :--- | :--- | :--- | :--- |
| **RFC 9110** | HTTP Semantics | §5.6.2 (Tokens), §7.6 (Range header bounds), §7.6.1 (Hop-by-hop header removal, Connection tokens), §7.6.3 (Via header), §8.6 (Content-Length syntax), §12.5 (Content negotiation) | [verify_server_pipeline_edge.goose](tests/lit/verify_server_pipeline_edge.goose), [verify_protocol_invariants.goose](tests/lit/verify_protocol_invariants.goose), [verify_historical_cves.goose](tests/lit/verify_historical_cves.goose), [verify_reverse_proxy.goose](tests/lit/verify_reverse_proxy.goose) |
| **RFC 9112** | HTTP/1.1 | §3.2 (Request target validation), §6.3 (TE.CL / CL.TE desync rejection), §7.1 (Chunk size parsing, hex overflow), §7.2 (Chunk extensions), §7.3 (Trailers) | [verify_http1_chunked.goose](tests/lit/verify_http1_chunked.goose), [verify_smuggling_desync.goose](tests/lit/verify_smuggling_desync.goose) |
| **RFC 9113** | HTTP/2 | §4.1 (Frame format), §4.2 (Frame size bounds), §5.1 (Stream state machine), §6.2 (CONTINUATION FSM lock), §6.5 (SETTINGS negotiation), §6.9 (Flow control window updates) | [verify_h2_spec.goose](tests/lit/verify_h2_spec.goose), [verify_h2_continuation_fsm.goose](tests/lit/verify_h2_continuation_fsm.goose), [verify_h2_control_frames.goose](tests/lit/verify_h2_control_frames.goose) |
| **RFC 7541** | HPACK | §5.1 (Integer representation, 7-bit / 5-bit prefixes), §5.2 (String literals), §6 (Dynamic table size management) | [verify_hpack_edge.goose](tests/lit/verify_hpack_edge.goose), [verify_hpack_qpack.goose](tests/lit/verify_hpack_qpack.goose) |
| **RFC 9114** | HTTP/3 | §4.1 (Frame layout), §6.2 (Unidirectional streams), §7.1 (SETTINGS parameter encoding), §10.5 (Header Accordion mitigations) | [verify_http3_framing.goose](tests/lit/verify_http3_framing.goose) |
| **RFC 9204** | QPACK | §2.1.2 (Blocked streams state machine), §3.2 (Dynamic table insertion), §4.1 (Encoder stream instructions), §4.2 (Decoder stream instructions) | [verify_qpack_blocked_streams.goose](tests/lit/verify_qpack_blocked_streams.goose), [verify_hpack_qpack.goose](tests/lit/verify_hpack_qpack.goose) |

## Transport security and QUIC

| Specification | Title | Verified sections | LIT verification test suite |
| :--- | :--- | :--- | :--- |
| **RFC 8446** | TLS 1.3 | §4 (Handshake client state machine), §4.1.3 (HelloRetryRequest detection), §4.2.10 (0-RTT Early Data replay defense, strike register), §4.4.1 (Certificate verify), §4.6.1 (NewSessionTicket codec), §5.1 (Record layer length <= 16384 bytes, protocol version enforcement) | [verify_tls_handshake_wire.goose](tests/lit/verify_tls_handshake_wire.goose), [verify_tls_resumption_0rtt.goose](tests/lit/verify_tls_resumption_0rtt.goose), [verify_wire_framing.goose](tests/lit/verify_wire_framing.goose) |
| **RFC 5280** | X.509 PKI & DER | §4.1.2.2 (Serial number ASN.1 DER rules), §4.1.2.5 (Validity), §5.3.1 (Name constraints, embedded NUL rejection) | [verify_asn1_der.goose](tests/lit/verify_asn1_der.goose), [verify_asn1_der_edge.goose](tests/lit/verify_asn1_der_edge.goose), [verify_historical_cves.goose](tests/lit/verify_historical_cves.goose) |
| **RFC 9000** | QUIC Transport | §5 (Connection state machine), §8.1 (Server anti-amplification 3x limit), §12.4 (Frames and packet numbers), §17.2 (Long packet headers), §19.3 (ACK frame intervals, ACK_ECN format) | [verify_quic_engine.goose](tests/lit/verify_quic_engine.goose), [verify_quic_ack_edge.goose](tests/lit/verify_quic_ack_edge.goose), [verify_zstd_and_quic_edge.goose](tests/lit/verify_zstd_and_quic_edge.goose) |
| **RFC 9002** | QUIC Loss Detection | §5.3 (RTT estimators: smoothed_rtt, min_rtt, rttvar), §6.1.1 (kPacketThreshold loss), §6.1.2 (kTimeThreshold loss), §6.2.1 (Probe timeout backoff), Optimistic ACK validation | [verify_quic_loss_recovery.goose](tests/lit/verify_quic_loss_recovery.goose) |

## Realtime and WebSocket protocols

| Specification | Title | Verified sections | LIT verification test suite |
| :--- | :--- | :--- | :--- |
| **RFC 6455** | WebSocket Protocol | §5.1 (Client/server masking enforcement), §5.2 (Base framing header), §5.3 (Payload masking bitwise SWAR/SIMD), §5.4 (Fragmentation FSM), §5.5 (Control frames), §7.4 (Close status codes), Categories 1-7 Autobahn invariants | [verify_ws_autobahn.goose](tests/lit/verify_ws_autobahn.goose), [verify_ws_autobahn_exhaustive.goose](tests/lit/verify_ws_autobahn_exhaustive.goose), [verify_ws_masking_simd.goose](tests/lit/verify_ws_masking_simd.goose), [verify_ws_streaming_utf8.goose](tests/lit/verify_ws_streaming_utf8.goose) |
| **RFC 8441** | WebSocket over HTTP/2 | §3 (Extended CONNECT method, :protocol pseudo-header negotiation, payload stream demuxing) | [verify_ws_h2_rfc8441.goose](tests/lit/verify_ws_h2_rfc8441.goose) |
| **W3C SSE** | Server-Sent Events | Field parsing (`data:`, `event:`, `id:`, `retry:`), CRLF/CR/LF normalization, UTF-8 BOM stripping | [verify_sse_wire.goose](tests/lit/verify_sse_wire.goose) |

## Modern extensions and security standards

| Specification | Title | Verified sections | LIT verification test suite |
| :--- | :--- | :--- | :--- |
| **RFC 9421** | HTTP Message Signatures | Component signature base serialization, `Signature-Input` formatting, Ed25519 / HMAC verification | [verify_http_extensions_edge.goose](tests/lit/verify_http_extensions_edge.goose) |
| **RFC 9530** | Digest Fields | `Repr-Digest` and `Content-Digest` multi-algorithm parsing (sha-256, sha-512), colon-delimited byte sequences | [verify_http_extensions_edge.goose](tests/lit/verify_http_extensions_edge.goose) |
| **RFC 9116** | security.txt | Directive parsing (`Contact:`, `Expires:`, `Encryption:`), RFC 3339 date validation, canonical formatter | [verify_http_extensions_edge.goose](tests/lit/verify_http_extensions_edge.goose) |
| **RFC 7636** | PKCE | Code challenge derivation (`S256` SHA-256 base64url), code verifier entropy enforcement (43..128 chars) | [verify_protocol_invariants.goose](tests/lit/verify_protocol_invariants.goose) |
| **RFC 7616** | HTTP Digest Auth | Challenge parsing, `realm`, `nonce`, `qop`, `opaque` extraction, quoted parameter handling | [verify_auth_digest_edge.goose](tests/lit/verify_auth_digest_edge.goose) |
| **RFC 9460** | SVCB and HTTPS RR | Service parameter key-value decoding, ALPN wire parsing, IPv4/IPv6 hint extraction | [verify_dns_https_svcb.goose](tests/lit/verify_dns_https_svcb.goose) |
| **RFC 9298** | MASQUE UDP Proxying | Capsule protocol framing, Datagram capsule handling, stream context IDs | [verify_masque_dns_edge.goose](tests/lit/verify_masque_dns_edge.goose) |

## Performance and zero-allocation budgets

| Focus | Targets | Target budget | LIT verification test suite |
| :--- | :--- | :--- | :--- |
| **Wire parsing** | AVX2/SWAR `fast_find_crlfcrlf`, TLS record header parser, gRPC LPM slice decoder, chunked FSM | Latency <= 500 ns/op, zero heap allocations | [verify_wire_benchmarks.goose](tests/lit/verify_wire_benchmarks.goose) |
| **Stream robustness** | Prefix fragmentation and mutation fuzzing across all framing decoders | 100% pass rate, zero crashes or memory corruption | [verify_chaos_fuzzing.goose](tests/lit/verify_chaos_fuzzing.goose), [verify_chaos_slicer.goose](tests/lit/verify_chaos_slicer.goose) |
