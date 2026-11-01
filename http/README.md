# `http`

Comprehensive, zero-allocation HTTP engine supporting HTTP/1.1 framing, Structured Fields (RFC 8941/RFC 9651), Message Signatures (RFC 9421), Digest Fields (RFC 9530), Problem Details (RFC 9457), Multipart form-data, and protocol extensions.

## Public API

### Header Map & HTTP/1.1 Header Processing (`headers.goose`)

- **`struct HeaderMap`**: Zero-heap HTTP header collection backed by inline slots and a bounded contiguous byte buffer.
- **`fn append_header(map: HeaderMap&, name: const u8[:], value: const u8[:]) -> bool`**: Appends a header without overwriting existing entries.
- **`fn set_header(map: HeaderMap&, name: const u8[:], value: const u8[:]) -> bool`**: Inserts or replaces an existing header.
- **`fn get_header(map: const HeaderMap&, name: const u8[:]) -> const u8[:]`**: Retrieves the first value for the specified header name.
- **`fn has_header(map: const HeaderMap&, name: const u8[:]) -> bool`**: Checks if a header is present.
- **`fn get_combined<B>(map: const HeaderMap&, name: const u8[:], out: B&) -> bool`**: Combines multiple header lines with commas (RFC 9110 §5.3), strictly rejecting `Set-Cookie` folding.
- **`fn remove_header(map: HeaderMap&, name: const u8[:]) -> bool`**: Removes all occurrences of a header name.
- **`fn clear_headers(map: HeaderMap&)`**: Clears all headers and resets the raw storage buffer.
- **`fn serialize_headers(map: const HeaderMap&, out: u8[>..]&)`**: Serializes all headers to wire format (`Header: Value\r\n`).
- **`fn parse_headers(raw: const u8[:], out_map: HeaderMap&) -> i64, bool`**: Zero-allocation streaming parser for HTTP/1.1 header blocks.

### Structured Field Values (`sfv.goose`, RFC 8941 / RFC 9651)

- **`enum SfType`**: Value classification (`Integer`, `Decimal`, `String`, `Token`, `Binary`, `Boolean`, `Date`, `DisplayString`).
- **`struct SfItem`**: Typed structured field item holding numeric, boolean, or byte slice values.
- **`struct SfParameter`**: Key-value parameter attached to an item or inner list.
- **`struct SfDictEntry`**: Dictionary member associating a key with an `SfItem` or inner list.
- **`fn parse_sf_item(raw: const u8[:], out: SfItem&) -> bool`**: Parses a standalone structured field item.
- **`fn parse_sf_list(raw: const u8[:], out_items: SfItem[..16]&) -> bool`**: Parses an RFC 8941 List.
- **`fn parse_sf_dict(raw: const u8[:], out_entries: SfDictEntry[..16]&) -> bool`**: Parses an RFC 8941 Dictionary.
- **`fn serialize_sf_item<B>(item: const SfItem&, out: B&) -> bool`**: Serializes an `SfItem` to canonical wire text.

### HTTP Message Signatures (`signatures.goose`, RFC 9421)

- **`struct HttpSignatureParams`**: Signature parameters including key ID, algorithm, timestamp invariants, and covered components.
- **`fn sign_http_request(req: Request&, label: const u8[:], params: const HttpSignatureParams&, secret_key: const u8[:]) -> bool`**: Computes and attaches RFC 9421 signature to a request.
- **`fn verify_http_signature(req: const Request&, label: const u8[:], params: const HttpSignatureParams&, key_bytes: const u8[:], now_sec: i64) -> bool`**: Verifies request signature against public key or shared secret.
- **`fn sign_http_response(res: Response&, req: const Request&, label: const u8[:], params: const HttpSignatureParams&, secret_key: const u8[:]) -> bool`**: Computes and attaches response signature.
- **`fn verify_http_response_signature(res: const Response&, req: const Request&, label: const u8[:], params: const HttpSignatureParams&, key_bytes: const u8[:], now_sec: i64) -> bool`**: Verifies response signature.
- **`fn sign_request_ed25519(req: Request&, label: const u8[:], params: const HttpSignatureParams&, private_key: const u8[32]) -> bool`**: Signs a request using asymmetric Ed25519.
- **`fn verify_request_ed25519(req: const Request&, label: const u8[:], params: const HttpSignatureParams&, public_key: const u8[32], now_sec: i64) -> bool`**: Verifies an Ed25519 request signature.

### Digest Fields (`digest_fields.goose`, RFC 9530)

- **`fn set_content_digest(req: Request&, alg: const u8[:] = "sha-256") -> bool`**: Computes and attaches `Content-Digest` to a request.
- **`fn set_repr_digest(req: Request&, alg: const u8[:] = "sha-256") -> bool`**: Computes and attaches `Repr-Digest` to a request.
- **`fn set_response_content_digest(res: Response&, alg: const u8[:] = "sha-256") -> bool`**: Computes and attaches `Content-Digest` to a response.
- **`fn set_response_repr_digest(res: Response&, alg: const u8[:] = "sha-256") -> bool`**: Computes and attaches `Repr-Digest` to a response.
- **`fn verify_request_content_digest(req: const Request&) -> bool`**: Verifies request `Content-Digest` matches payload.
- **`fn verify_request_repr_digest(req: const Request&) -> bool`**: Verifies request `Repr-Digest` matches payload.
- **`fn verify_response_content_digest(res: const Response&) -> bool`**: Verifies response `Content-Digest` matches payload.
- **`fn verify_response_repr_digest(res: const Response&) -> bool`**: Verifies response `Repr-Digest` matches payload.

### Problem Details for HTTP APIs (`problem.goose`, RFC 9457)

- **`struct ProblemDetails`**: Typed RFC 9457 problem details document (type, title, status, detail, instance).
- **`fn parse_problem_details(json_src: const u8[:], out: ProblemDetails&) -> bool`**: Parses JSON problem details payload.
- **`fn serialize_problem_details<B>(problem: const ProblemDetails&, out: B&)`**: Serializes `ProblemDetails` to UTF-8 JSON.
- **`fn new_problem_response(problem: const ProblemDetails&) -> Response`**: Generates a standard `application/problem+json` Response.

### MIME Media Types & Multipart Form-Data (`mime.goose`, `multipart.goose`)

- **`struct MediaType`**: Parsed type, subtype, and parameters.
- **`fn parse_media_type(raw: const u8[:], out: MediaType&) -> bool`**: Parses Content-Type media type with parameters (RFC 9110 §8.3).
- **`struct ByteRange`**: HTTP byte range bounds (start, end, suffix).
- **`fn parse_range_header(raw: const u8[:], out_ranges: ByteRange[..16]&) -> bool`**: Parses RFC 9110 §14.1.2 byte ranges.
- **`struct MultipartPart`**: Individual part holding headers and byte payload view.
- **`struct MultipartReader`**: Streaming parser for multipart MIME bodies defending against CVE-2023-24536 boundary flooding.

### Protocol Extensions & Metadata

- **`http/altsvc.goose` (RFC 7838)**: Alternative Services header parser (`parse_altsvc_header`).
- **`http/hsts.goose` (RFC 6797)**: Strict-Transport-Security policy evaluator (`parse_hsts_header`).
- **`http/forwarded.goose` (RFC 7239)**: Reverse proxy `Forwarded` element extractor (`parse_forwarded_header`).
- **`http/priority.goose` (RFC 9218)**: Extensible HTTP Priority parser (`parse_priority_header`).
- **`http/status_diagnostics.goose`**: RFC 9211 `Cache-Status` and RFC 9209 `Proxy-Status` reporting.
- **`http/trace.goose`**: W3C Trace Context (`traceparent`, `tracestate`) generation and propagation.
