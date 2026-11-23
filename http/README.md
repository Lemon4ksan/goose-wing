# `http`

Zero-allocation HTTP engine supporting HTTP/1.1 framing, Structured Fields (RFC
8941 / RFC 9651), Binary HTTP (RFC 9292), Oblivious HTTP (RFC 9458), Message
Signatures (RFC 9421), Digest Fields (RFC 9530), Problem Details (RFC 9457),
Compression Dictionaries (RFC 9842), Multipart form-data, and protocol
extensions.

## Public API

### Header Map & HTTP/1.1 Header Processing (`headers.goose`)

```goose
enum HeaderParseError {
    None, LineTooLong, MalformedStatusLine, MalformedHeaderLine,
    InvalidHeaderName, InvalidHeaderValue, ObsFoldRejected,
    DuplicateContentLength, InvalidContentLength, SmugglingConflict,
    TooManyHeaders, ArenaExhausted,
}
enum WellKnownHeader
struct HeaderEntry
struct HeaderMap
root struct OverflowArena

fn append_header(map: HeaderMap&, name: const u8[:], value: const u8[:]) -> bool
fn set_header(map: HeaderMap&, name: const u8[:], value: const u8[:], is_sensitive: bool = false)
fn set_or_replace(map: HeaderMap&, name: const u8[:], value: const u8[:], is_sensitive: bool = false) -> bool
fn get_header(map: const HeaderMap&, name: const u8[:]) -> const u8[:]
fn has_header(map: const HeaderMap&, name: const u8[:]) -> bool
fn get_combined<B>(map: const HeaderMap&, name: const u8[:], out: B&, max_out_len: i64 = 8192) -> bool
fn remove_header(map: HeaderMap&, name: const u8[:]) -> bool
fn clear(map: HeaderMap&)
fn reset_for_keep_alive(map: HeaderMap&)
fn serialize_headers(map: const HeaderMap&, out: u8[>..]&)
fn parse_headers(raw_input: const u8[:], map: HeaderMap&, allow_obs_fold: bool = false, mode: H1ResponseParseMode = H1ResponseParseMode.Strict) -> HeaderParseError
fn parse_request_headers(raw_input: const u8[:], map: HeaderMap&, allow_obs_fold: bool = false) -> HeaderParseError
fn parse_response_headers(raw_input: const u8[:], map: HeaderMap&, allow_obs_fold: bool = false) -> HeaderParseError
fn strip_hop_by_hop_headers(src: const HeaderMap&, dst: HeaderMap&)
```

`HeaderMap` stores HTTP headers in fixed inline slots (`HeaderEntry`) backed by
a contiguous byte buffer without heap allocation. `WellKnownHeader` provides
O(1) slot indexing for common headers, while `OverflowArena` supports oversized
header blocks. `get_combined` joins duplicate header fields with commas per RFC
9110 §5.3 while refusing to fold `Set-Cookie`. `parse_headers`,
`parse_request_headers`, and `parse_response_headers` reject `obs-fold` line
continuations by default and detect `Content-Length` / `Transfer-Encoding`
request smuggling conflicts. `strip_hop_by_hop_headers` removes RFC 9110 §7.6.1
hop-by-hop fields and any tokens nominated by `Connection`.

```goose
var headers = http::HeaderMap { .. };
let err = http::parse_request_headers(raw_wire, headers);
if err == http::HeaderParseError.None {
    let host = headers.get_header("Host");
}
```

### Structured Field Values (`sfv.goose`, RFC 8941 / RFC 9651)

```goose
enum SfType
struct SfItem
struct SfParameter
struct SfParameterizedItem
struct SfDictEntry

fn parse_sf_item(input: const u8[:]) -> SfParameterizedItem, bool
fn parse_sf_list(input: const u8[:], out_items: SfParameterizedItem[..16]&) -> bool
fn parse_sf_dict(input: const u8[:], out_entries: SfDictEntry[..16]&) -> bool
fn sf_decode_display_string<B>(raw: const u8[:], out: B&) -> bool
fn sf_serialize_item<B>(item: const SfItem&, out: B&)
fn sf_serialize_parameters<B>(params: const SfParameter[:], out: B&)
fn sf_serialize_dict_entry<B>(entry: const SfDictEntry&, out: B&)
```

Structured Field parsers decode RFC 9651 Items, Lists
(`SfParameterizedItem[..16]`), and Dictionaries (`SfDictEntry[..16]`) classified
by `SfType` (`Integer`, `Decimal`, `String`, `Token`, `Binary`, `Boolean`,
`Date`, `DisplayString`). Each `SfParameterizedItem` pairs a bare `SfItem` with
up to 8 `SfParameter` key-value pairs, and each `SfDictEntry` holds a single
item or an inner list of up to 16 `SfItem` elements
(`inner_items: SfItem[..16]`). `sf_decode_display_string` decodes and validates
percent-encoded UTF-8 Display Strings (`%"..."` per RFC 9651 §3.3.8).

### Binary HTTP & Oblivious HTTP (`bhttp.goose`, `ohttp.goose`, RFC 9292 / RFC 9458)

```goose
struct BhttpRequest
struct BhttpResponse
struct OhttpKeyConfig
struct OhttpSession

fn bhttp_encode_request(req: const BhttpRequest&, out: u8[..8192]&) -> i32
fn bhttp_decode_request(raw: const u8[:], out: BhttpRequest&) -> bool
fn bhttp_encode_response(res: const BhttpResponse&, out: u8[..8192]&) -> i32
fn bhttp_decode_response(raw: const u8[:], out: BhttpResponse&) -> bool
fn parse_ohttp_key_config(raw: const u8[:], out: OhttpKeyConfig&) -> bool
fn parse_ohttp_key_configs(raw: const u8[:], out: OhttpKeyConfig[..4]&, out_count: i32&) -> bool
fn ohttp_seal_request(cfg: const OhttpKeyConfig&, ephemeral_sk: const u8[32]&, inner_bhttp: const u8[:], out: u8[..8192]&, out_len: i32&, session: OhttpSession&) -> bool
fn ohttp_open_request(skR: const u8[:], enc_request: const u8[:], out: u8[..8192]&, out_len: i32&, session: OhttpSession&) -> bool
fn ohttp_seal_response(session: const OhttpSession&, response_nonce: const u8[:], response: const u8[:], out: u8[..8192]&, out_len: i32&) -> bool
fn ohttp_open_response(session: const OhttpSession&, enc_response: const u8[:], out: u8[..8192]&, out_len: i32&) -> bool
```

`BhttpRequest` and `BhttpResponse` represent known-length Binary HTTP messages
(RFC 9292 §3.2 and §3.3) that encode into `u8[..8192]` buffers and return the
written byte count (`i32`) or `-1` on capacity overflow. `OhttpKeyConfig`
describes RFC 9458 §3 HPKE key configurations (key ID, KEM, KDF, and AEAD
identifiers) parsed individually or from an `application/ohttp-keys` directory
of up to 4 entries (`OhttpKeyConfig[..4]`). `OhttpSession` keeps the HPKE
context across `application/ohttp-req` request encapsulation and
`application/ohttp-res` response decryption.

### HTTP Message Signatures (`signatures.goose`, RFC 9421)

```goose
struct SignatureParams

fn sign_request(req: Request&, params: const SignatureParams&, secret_key: const u8[:]) -> bool
fn verify_signature(req: const Request&, label: const u8[:], params: const SignatureParams&, key_bytes: const u8[:], now_sec: i64 = 0) -> bool
fn sign_response(res: Response&, req: const Request&, params: const SignatureParams&, secret_key: const u8[:]) -> bool
fn verify_response_signature(res: const Response&, req: const Request&, label: const u8[:], params: const SignatureParams&, key_bytes: const u8[:], now_sec: i64 = 0) -> bool
fn sign_request_ed25519(req: Request&, key_id: const u8[:], private_key: const u8[:]) -> bool
fn verify_request_ed25519(req: const Request&, key_id: const u8[:], public_key: const u8[:], now_sec: i64 = 0) -> bool
fn sign_response_ed25519(res: Response&, req: const Request&, key_id: const u8[:], private_key: const u8[:]) -> bool
fn verify_response_ed25519(res: const Response&, req: const Request&, key_id: const u8[:], public_key: const u8[:], now_sec: i64 = 0) -> bool
```

`SignatureParams` configures the key identifier, signature algorithm,
creation/expiration timestamps, and covered message components for RFC 9421
`Signature-Input` and `Signature` headers. Response signing and verification
functions bind the response signature base to the initiating `Request` via the
`;req` parameter when requested. When `now_sec > 0`, verification enforces
`created` and `expires` timestamp bounds.

### Digest Fields (`digest_fields.goose`, RFC 9530)

```goose
fn set_content_digest(req: Request&, alg: const u8[:] = "sha-256") -> bool
fn set_repr_digest(req: Request&, alg: const u8[:] = "sha-256") -> bool
fn set_want_content_digest(req: Request&, want_algorithms: const u8[:] = "sha-256=10")
fn set_want_repr_digest(req: Request&, want_algorithms: const u8[:] = "sha-256=10")
fn set_response_content_digest(res: Response&, alg: const u8[:] = "sha-256") -> bool
fn apply_response_digest_if_wanted(req: const Request&, res: Response&) -> bool
fn verify_request_content_digest(req: const Request&) -> bool
fn verify_request_repr_digest(req: const Request&) -> bool
fn verify_response_content_digest(res: const Response&) -> bool
fn verify_response_repr_digest(res: const Response&) -> bool
```

Computes, formats, and verifies RFC 9530 `Content-Digest`, `Repr-Digest`,
`Want-Content-Digest`, and `Want-Repr-Digest` Structured Field byte sequence
dictionaries (`sha-256=:<base64>:`, `sha-512=:<base64>:`) over request and
response payloads.

### Problem Details for HTTP APIs (`problem.goose`, RFC 9457)

```goose
struct ProblemDetails

fn parse_problem_details(json_src: const u8[:], out: ProblemDetails&) -> bool
fn serialize_problem_details<B>(problem: const ProblemDetails&, out: B&)
fn new_problem_response(problem: const ProblemDetails&) -> Response
fn write_problem_response(res: Response&, problem: const ProblemDetails&)
fn respond_problem(res: Response&, status_code: i32, title: const u8[:], detail: const u8[:] = "", type_uri: const u8[:] = "")
```

`ProblemDetails` models RFC 9457 machine-readable error documents (`type_uri`,
`title`, `status`, `detail`, `instance`, and extension fields) serialized with
content type `application/problem+json`.

### MIME Media Types, Multipart Form-Data & Byte Ranges (`mime.goose`, `multipart.goose`)

```goose
struct MediaType
enum MultipartError {
    None, InvalidBoundary, MissingInitialBoundary, MalformedPartHeader,
    MissingClosingBoundary, TooManyParts, PartTooLarge, HeaderTooLarge,
    TotalSizeExceeded,
}
struct MultipartOptions
struct MultipartPart
struct MultipartMessage
struct MultipartWriter
struct RangeSpec
struct NormalizedRange
struct RangeSet

fn parse_media_type(raw: const u8[:]) -> MediaType, bool
fn parse_content_disposition(raw: const u8[:]) -> MediaType, bool
fn parse_multipart(body: const u8[:], boundary: const u8[:], options: MultipartOptions = MultipartOptions { .. }) -> MultipartMessage, MultipartError
fn new_multipart_writer(boundary: const u8[:] = "") -> MultipartWriter, bool
fn multipart_content_type(w: const MultipartWriter&) -> u8[..128]
fn write_field(w: MultipartWriter&, name: const u8[:], value: const u8[:]) -> bool
fn write_file(w: MultipartWriter&, field_name: const u8[:], filename: const u8[:], content_type: const u8[:], data: const u8[:]) -> bool
fn finish(w: MultipartWriter&) -> bool
fn multipart(req: Request&, w: MultipartWriter&) -> bool
fn parse_range_header(header_val: const u8[:], resource_len: i64, with_coalesce: bool = true, max_ranges: i32 = 16) -> RangeSet, RangeError
fn evaluate_if_range(if_range_header: const u8[:], etag: const u8[:], mod_unix_sec: i64) -> bool
```

`MediaType` stores a parsed type, subtype, and up to 16 parameters
(`params: MediaTypeParam[..16]`) for RFC 9110 §8.3 `Content-Type` and RFC 6266
`Content-Disposition` headers. `parse_multipart` scans boundaries with
Boyer-Moore-Horspool (`bmh_find`) while enforcing `MultipartOptions` ceilings on
part count, per-part size, header size, and total memory budget (mitigating
CVE-2023-24536). `MultipartWriter` builds RFC 7578 `multipart/form-data`
payloads for client uploads (`write_field`, `write_file`, `finish`, and
`req.multipart(w)`) with CSPRNG boundary generation and CRLF/NUL injection
rejection. `parse_range_header` validates and coalesces RFC 9110 §14.1.2 byte
`Range` intervals (`RangeSpec`, `NormalizedRange`, `RangeSet`), and
`evaluate_if_range` checks RFC 9110 §13.1.5 `If-Range` validators.

### Compression Dictionary Transport (`compression_dict.goose`, RFC 9842)

```goose
struct DictionaryParams
struct DictionaryEntry
struct DictionaryCache

fn parse_use_as_dictionary_header(header_val: const u8[:]) -> DictionaryParams, bool
fn encode_dcz_frame<B>(out: B&, dict_hash: const u8[32]&, compressed_payload: const u8[:]) -> bool
fn encode_dcb_frame<B>(out: B&, dict_hash: const u8[32]&, compressed_payload: const u8[:]) -> bool
fn decode_dcz_header(wire: const u8[:], out_hash: u8[32]&) -> const u8[:], bool
fn decode_dcb_header(wire: const u8[:], out_hash: u8[32]&) -> const u8[:], bool
fn dictionary_cache_insert(cache: DictionaryCache&, origin: const u8[:], match_pattern: const u8[:], id_str: const u8[:], body: const u8[:], ttl_sec: u32, now_sec: i64) -> bool
fn dictionary_lookup_for_request(cache: const DictionaryCache&, origin: const u8[:], url_path: const u8[:], now_sec: i64) -> u8[..64], bool
```

Implements RFC 9842 Compression Dictionary Transport. `DictionaryParams` holds
parsed `Use-As-Dictionary` parameters (`match_pattern`, `match_dest`, `id_str`,
`dict_type`, `ttl_sec`). `encode_dcz_frame` and `decode_dcz_header` handle the
40-byte Zstandard `dcz` magic header and 32-byte SHA-256 dictionary hash;
`encode_dcb_frame` and `decode_dcb_header` handle the 36-byte Brotli `dcb`
header. `DictionaryCache` stores per-origin `DictionaryEntry` records and
returns the longest-matching SFV `Available-Dictionary` hash (`u8[..64], bool`).

### Early Hints & CASPER Golomb-Coded Sets (`early_hints.goose`, RFC 8297)

```goose
struct EarlyHintLink
struct EarlyHintsResponse
struct CasperSet

fn parse_link_header<E>(raw: const u8[:], out_links: E&) -> bool
fn parse_early_hints(status: u16, raw_link_header: const u8[:]) -> EarlyHintsResponse, bool
fn format_early_hints_http1<B>(hints: const EarlyHintsResponse&, req_no_early_hints: const u8[:], out: B&) -> bool
fn casper_lookup_and_insert(set: CasperSet&, path: const u8[:], etag: const u8[:]) -> bool
fn encode_casper_cookie<B>(set: const CasperSet&, out_cookie: B&) -> bool
fn decode_casper_cookie(cookie: const u8[:], set: CasperSet&) -> bool
```

`EarlyHintsResponse` stores up to 16 `EarlyHintLink` entries (`target_uri`,
`rel`, `as_attr`, `crossorigin`, `fetchpriority`, `mime_type`) parsed from RFC
8288 `Link` headers on `103 Early Hints` responses. `format_early_hints_http1`
emits the HTTP/1.1 `103 Early Hints` block unless suppressed by
`No-Early-Hints: 1`. `CasperSet` maintains a Golomb-coded set ($P = 64$) of
browser-cached assets encoded in the Base64url `x-casper` cookie to skip
redundant preload hints.

### Client-Cert Header, Resumable Uploads & Security Metadata (`client_cert.goose`, `resumable_upload.goose`, `security_txt.goose`)

```goose
struct ResumableUploadState
struct SecurityTxt

fn parse_client_cert(raw: const u8[:], out_der: u8[..4096]&) -> bool
fn encode_client_cert<B>(der: const u8[:], out: B&) -> bool
fn parse_client_cert_chain(raw: const u8[:], out_certs: u8[..4096][..4]&) -> bool
fn init_resumable_upload(total_size: i64, chunk_size: i64 = 65536) -> ResumableUploadState
fn format_upload_creation_request(req: Request&, endpoint: const u8[:], first_chunk: const u8[:], is_complete: bool)
fn format_upload_chunk_request(req: Request&, state: const ResumableUploadState&, chunk: const u8[:], is_complete: bool)
fn parse_security_txt(content: const u8[:], now_epoch: i64 = 0) -> SecurityTxt
fn format_security_txt<B>(sec: const SecurityTxt&, out: B&)
```

`client_cert.goose` encodes and decodes RFC 9440 `Client-Cert` (`u8[..4096]`)
and `Client-Cert-Chain` (`u8[..4096][..4]`) Structured Field byte sequences for
reverse-proxy mTLS termination. `resumable_upload.goose` implements
`draft-ietf-httpbis-resumable-upload` state tracking (`ResumableUploadState`)
and formats `Upload-Draft-Interop-Version`, `Upload-Complete`, `Upload-Length`,
and `application/partial-upload` `PATCH` chunk headers. `security_txt.goose`
parses and serializes RFC 9116 `/.well-known/security.txt` policies
(`SecurityTxt`), validating mandatory `Contact`, `Expires`, and `Canonical`
fields.

### Caching Extensions, Priority & Protocol Metadata (`altsvc.goose`, `forwarded.goose`, `hsts.goose`, `incremental.goose`, `novarysearch.goose`, `priority.goose`, `status_diagnostics.goose`, `targeted_cache.goose`, `trace.goose`)

```goose
// http/altsvc.goose (RFC 7838)
struct AltSvcEndpoint
struct AltSvcCache
fn parse_altsvc_header<E>(raw: const u8[:], out_endpoints: E&) -> bool, bool
fn lookup_h3(cache: const AltSvcCache&, origin: const u8[:], now_sec: i64, out_ep: AltSvcEndpoint&) -> bool
fn format_altsvc_header<B>(out: B&, proto: const u8[:], port:        u16, max_age_sec: u32 = 86400, persist: bool = true)

// http/hsts.goose (RFC 6797)
struct HstsDirective
struct HstsCache
fn parse_hsts_header(raw: const u8[:]) -> HstsDirective, bool
fn is_hsts_host(cache: const HstsCache&, hostname: const u8[:], now_sec: i64) -> bool
fn hsts_cache_update(cache: HstsCache&, hostname: const u8[:], raw_header: const u8[:], now_sec: i64) -> bool
fn hsts_upgrade_url<B>(cache: const HstsCache&, raw_url: const u8[:], now_sec: i64, out_url: B&) -> bool

// http/forwarded.goose (RFC 7239)
struct ForwardedElement
fn parse_forwarded_header(raw: const u8[:], out_elements: ForwardedElement[..8]&) -> i64
fn format_forwarded_element<B>(elem: const ForwardedElement&, out: B&)
fn append_forwarded_header(out_headers: HeaderMap&, elem: const ForwardedElement&) -> bool

// http/priority.goose (RFC 9218)
struct PriorityParam
fn parse_priority(raw: const u8[:], default_incremental: bool = false) -> PriorityParam, bool
fn serialize_priority<B>(p: const PriorityParam&, out: B&)

// http/incremental.goose (RFC 9849)
fn parse_incremental_header(val: const u8[:]) -> bool, bool
fn is_incremental_requested(headers: const HeaderMap&) -> bool
fn append_incremental_header(out_headers: HeaderMap&, incremental: bool) -> bool
fn format_incremental_refused_proxy_status<B>(out: B&, proxy_name: const u8[:])

// http/novarysearch.goose (RFC 9847)
struct NoVarySearch
fn parse_no_vary_search(raw: const u8[:]) -> NoVarySearch, bool
fn is_param_ignored(nvs: const NoVarySearch&, key: const u8[:]) -> bool
fn normalize_query_for_cache<B>(raw_query: const u8[:], nvs: const NoVarySearch&, out: B&)

// http/targeted_cache.goose (RFC 9213)
fn parse_targeted_cache_control_headers(map: const HeaderMap&, target_name: const u8[:] = "", opts: CacheControlParseOptions = CacheControlParseOptions { .. }) -> CacheControl
fn check_target_cache_control(map: const HeaderMap&, target_name: const u8[:], cc: CacheControl&, ignore_cargo_cult: bool) -> bool

// http/status_diagnostics.goose (RFC 9211 / RFC 9209)
struct CacheStatusEntry
struct ProxyStatusEntry
fn parse_cache_status_header(raw: const u8[:], out_entries: CacheStatusEntry[..8]&) -> i64
fn format_cache_status<B>(entry: const CacheStatusEntry&, out: B&)
fn parse_proxy_status_header(raw: const u8[:], out_entries: ProxyStatusEntry[..8]&) -> i64
fn format_proxy_status<B>(entry: const ProxyStatusEntry&, out: B&)

// http/trace.goose (W3C Trace Context)
struct Traceparent
struct Tracestate
fn parse_traceparent(raw: const u8[:]) -> Traceparent, bool
fn format_traceparent<B>(tp: const Traceparent&, out: B&)
fn parse_tracestate(raw: const u8[:]) -> Tracestate, bool
fn format_tracestate<B>(ts: const Tracestate&, out: B&)
```

These extension modules handle origin service discovery, transport security,
intermediary forwarding, priority scheduling, cache key normalization, and
distributed tracing:

| Module | Specification | Purpose and Bounded Capacities |
| :--- | :--- | :--- |
| `http/altsvc.goose` | RFC 7838 | Parses `Alt-Svc` headers and caches up to 16 origins (`AltSvcOriginEntry[..16]`) with exponential failure backoff for HTTP/3 (`h3`) endpoint promotion. |
| `http/hsts.goose` | RFC 6797 | Parses `Strict-Transport-Security`, maintains a 128-entry dynamic `HstsCache` plus static preload list, and upgrades `http://` URLs to `https://`. |
| `http/forwarded.goose` | RFC 7239 | Parses and formats up to 8 `Forwarded` proxy hops (`ForwardedElement[..8]`) with `by`, `for`, `host`, and `proto` attributes. |
| `http/priority.goose` | RFC 9218 | Parses and serializes extensible HTTP `Priority` dictionaries (`urgency` in `0..7` and `incremental` boolean flag). |
| `http/incremental.goose` | RFC 9849 | Parses and formats `Incremental: ?1` headers and `incremental_refused` `Proxy-Status` diagnostics. |
| `http/novarysearch.goose` | RFC 9847 | Normalizes URL query strings for cache lookup by stripping ignored query parameters (`params`, `except`, `key-order`). |
| `http/targeted_cache.goose` | RFC 9213 | Evaluates `<target>-Cache-Control` and `CDN-Cache-Control` headers with precedence over `Cache-Control`. |
| `http/status_diagnostics.goose` | RFC 9211 / RFC 9209 | Parses and formats up to 8 `Cache-Status` (`CacheStatusEntry[..8]`) and `Proxy-Status` (`ProxyStatusEntry[..8]`) intermediary diagnostic entries. |
| `http/trace.goose` | W3C Trace Context | Validates and formats 55-byte `traceparent` headers and up to 32 `tracestate` vendor pairs (`TracestateMember[..32]`). |
