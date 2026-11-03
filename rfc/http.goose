// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Standardized HTTP semantics, status codes, methods, headers, and media types.
// Conforms to RFC 9110, RFC 9111, RFC 9112, RFC 9209, RFC 9211, RFC 9457, and RFC 10008.
namespace rfc;

import std;

// ---- HTTP Status Codes (RFC 9110 Section 15) -----------------------------

// RFC 9110 Section 15.2: Informational 1xx
const STATUS_CONTINUE:            i32 = 100;
const STATUS_SWITCHING_PROTOCOLS: i32 = 101;
const STATUS_EARLY_HINTS:         i32 = 103; // RFC 8297 Section 2
const STATUS_RESUMABLE_SUPPORTED: i32 = 104; // IETF Resumable Uploads draft-14

// RFC 9110 Section 15.3: Successful 2xx
const STATUS_OK:              i32 = 200;
const STATUS_CREATED:         i32 = 201;
const STATUS_ACCEPTED:        i32 = 202;
const STATUS_NO_CONTENT:      i32 = 204;
const STATUS_PARTIAL_CONTENT: i32 = 206;

// RFC 9110 Section 15.4: Redirection 3xx
const STATUS_MOVED_PERMANENTLY:  i32 = 301;
const STATUS_FOUND:              i32 = 302;
const STATUS_SEE_OTHER:          i32 = 303;
const STATUS_NOT_MODIFIED:       i32 = 304;
const STATUS_TEMPORARY_REDIRECT: i32 = 307;
const STATUS_PERMANENT_REDIRECT: i32 = 308;

// RFC 9110 Section 15.5: Client Error 4xx
const STATUS_BAD_REQUEST:                     i32 = 400;
const STATUS_UNAUTHORIZED:                    i32 = 401;
const STATUS_FORBIDDEN:                       i32 = 403;
const STATUS_NOT_FOUND:                       i32 = 404;
const STATUS_METHOD_NOT_ALLOWED:              i32 = 405;
const STATUS_REQUEST_TIMEOUT:                 i32 = 408;
const STATUS_CONFLICT:                        i32 = 409;
const STATUS_GONE:                            i32 = 410;
const STATUS_LENGTH_REQUIRED:                 i32 = 411;
const STATUS_PRECONDITION_FAILED:             i32 = 412;
const STATUS_CONTENT_TOO_LARGE:               i32 = 413;
const STATUS_URI_TOO_LONG:                    i32 = 414;
const STATUS_UNSUPPORTED_MEDIA_TYPE:          i32 = 415;
const STATUS_RANGE_NOT_SATISFIABLE:           i32 = 416;
const STATUS_EXPECTATION_FAILED:              i32 = 417;
const STATUS_MISDIRECTED_REQUEST:             i32 = 421;
const STATUS_UNPROCESSABLE_CONTENT:           i32 = 422;
const STATUS_TOO_EARLY:                       i32 = 425; // RFC 8470 Section 5.2
const STATUS_UPGRADE_REQUIRED:                i32 = 426;
const STATUS_PRECONDITION_REQUIRED:           i32 = 428; // RFC 6585 Section 3
const STATUS_TOO_MANY_REQUESTS:               i32 = 429; // RFC 6585 Section 4
const STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE: i32 = 431; // RFC 6585 Section 5
const STATUS_UNAVAILABLE_FOR_LEGAL_REASONS:   i32 = 451; // RFC 7725 Section 3

// RFC 9110 Section 15.6: Server Error 5xx
const STATUS_INTERNAL_SERVER_ERROR:           i32 = 500;
const STATUS_NOT_IMPLEMENTED:                 i32 = 501;
const STATUS_BAD_GATEWAY:                     i32 = 502;
const STATUS_SERVICE_UNAVAILABLE:             i32 = 503;
const STATUS_GATEWAY_TIMEOUT:                 i32 = 504;
const STATUS_HTTP_VERSION_NOT_SUPPORTED:      i32 = 505;
const STATUS_NETWORK_AUTHENTICATION_REQUIRED: i32 = 511; // RFC 6585 Section 6

// ---- Pre-formatted HTTP/1.1 Status Lines (RFC 9112 Section 4) ------------

const HTTP1_STATUS_100: const u8[:] = "HTTP/1.1 100 Continue\r\n";
const HTTP1_STATUS_101: const u8[:] = "HTTP/1.1 101 Switching Protocols\r\n";
const HTTP1_STATUS_103: const u8[:] = "HTTP/1.1 103 Early Hints\r\n";
const HTTP1_STATUS_200: const u8[:] = "HTTP/1.1 200 OK\r\n";
const HTTP1_STATUS_201: const u8[:] = "HTTP/1.1 201 Created\r\n";
const HTTP1_STATUS_202: const u8[:] = "HTTP/1.1 202 Accepted\r\n";
const HTTP1_STATUS_204: const u8[:] = "HTTP/1.1 204 No Content\r\n";
const HTTP1_STATUS_206: const u8[:] = "HTTP/1.1 206 Partial Content\r\n";
const HTTP1_STATUS_301: const u8[:] = "HTTP/1.1 301 Moved Permanently\r\n";
const HTTP1_STATUS_302: const u8[:] = "HTTP/1.1 302 Found\r\n";
const HTTP1_STATUS_303: const u8[:] = "HTTP/1.1 303 See Other\r\n";
const HTTP1_STATUS_304: const u8[:] = "HTTP/1.1 304 Not Modified\r\n";
const HTTP1_STATUS_307: const u8[:] = "HTTP/1.1 307 Temporary Redirect\r\n";
const HTTP1_STATUS_308: const u8[:] = "HTTP/1.1 308 Permanent Redirect\r\n";
const HTTP1_STATUS_400: const u8[:] = "HTTP/1.1 400 Bad Request\r\n";
const HTTP1_STATUS_401: const u8[:] = "HTTP/1.1 401 Unauthorized\r\n";
const HTTP1_STATUS_403: const u8[:] = "HTTP/1.1 403 Forbidden\r\n";
const HTTP1_STATUS_404: const u8[:] = "HTTP/1.1 404 Not Found\r\n";
const HTTP1_STATUS_405: const u8[:] = "HTTP/1.1 405 Method Not Allowed\r\n";
const HTTP1_STATUS_408: const u8[:] = "HTTP/1.1 408 Request Timeout\r\n";
const HTTP1_STATUS_413: const u8[:] = "HTTP/1.1 413 Content Too Large\r\n";
const HTTP1_STATUS_422: const u8[:] = "HTTP/1.1 422 Unprocessable Content\r\n";
const HTTP1_STATUS_429: const u8[:] = "HTTP/1.1 429 Too Many Requests\r\n";
const HTTP1_STATUS_431: const u8[:] = "HTTP/1.1 431 Request Header Fields Too Large\r\n";
const HTTP1_STATUS_500: const u8[:] = "HTTP/1.1 500 Internal Server Error\r\n";
const HTTP1_STATUS_501: const u8[:] = "HTTP/1.1 501 Not Implemented\r\n";
const HTTP1_STATUS_502: const u8[:] = "HTTP/1.1 502 Bad Gateway\r\n";
const HTTP1_STATUS_503: const u8[:] = "HTTP/1.1 503 Service Unavailable\r\n";
const HTTP1_STATUS_504: const u8[:] = "HTTP/1.1 504 Gateway Timeout\r\n";

// ---- Zero-Allocation Status Helpers (RFC 9110 Section 15) ----------------

inline fn status_phrase_1xx_2xx(code: i32) -> const u8[:] {
    return match code {
        100 => "Continue",
        101 => "Switching Protocols",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        _ => "Unknown",
    };
}

inline fn status_phrase_3xx(code: i32) -> const u8[:] {
    return match code {
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        _ => "Unknown",
    };
}

inline fn status_phrase_4xx_low(code: i32) -> const u8[:] {
    return match code {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        _ => "Unknown",
    };
}

inline fn status_phrase_4xx_high(code: i32) -> const u8[:] {
    return match code {
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        _ => "Unknown",
    };
}

inline fn status_phrase_5xx(code: i32) -> const u8[:] {
    return match code {
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        511 => "Network Authentication Required",
        _ => "Unknown",
    };
}

// Returns the standard IANA / RFC 9110 reason phrase for an HTTP status code.
fn status_phrase(code: i32) -> const u8[:] {
    if code < 300 {
        return status_phrase_1xx_2xx(code);
    }
    if code < 400 {
        return status_phrase_3xx(code);
    }
    if code <= 412 {
        return status_phrase_4xx_low(code);
    }
    if code < 500 {
        return status_phrase_4xx_high(code);
    }
    return status_phrase_5xx(code);
}

inline fn status_line_h1_1xx_2xx(code: i32) -> const u8[:] {
    return match code {
        200 => HTTP1_STATUS_200,
        204 => HTTP1_STATUS_204,
        201 => HTTP1_STATUS_201,
        202 => HTTP1_STATUS_202,
        206 => HTTP1_STATUS_206,
        101 => HTTP1_STATUS_101,
        100 => HTTP1_STATUS_100,
        103 => HTTP1_STATUS_103,
        _ => "",
    };
}

inline fn status_line_h1_3xx(code: i32) -> const u8[:] {
    return match code {
        304 => HTTP1_STATUS_304,
        301 => HTTP1_STATUS_301,
        302 => HTTP1_STATUS_302,
        303 => HTTP1_STATUS_303,
        307 => HTTP1_STATUS_307,
        308 => HTTP1_STATUS_308,
        _ => "",
    };
}

inline fn status_line_h1_4xx(code: i32) -> const u8[:] {
    return match code {
        404 => HTTP1_STATUS_404,
        400 => HTTP1_STATUS_400,
        401 => HTTP1_STATUS_401,
        403 => HTTP1_STATUS_403,
        405 => HTTP1_STATUS_405,
        408 => HTTP1_STATUS_408,
        413 => HTTP1_STATUS_413,
        422 => HTTP1_STATUS_422,
        429 => HTTP1_STATUS_429,
        431 => HTTP1_STATUS_431,
        _ => "",
    };
}

inline fn status_line_h1_5xx(code: i32) -> const u8[:] {
    return match code {
        500 => HTTP1_STATUS_500,
        502 => HTTP1_STATUS_502,
        503 => HTTP1_STATUS_503,
        501 => HTTP1_STATUS_501,
        504 => HTTP1_STATUS_504,
        _ => "",
    };
}

// Returns a pre-formatted HTTP/1.1 status line slice (including CRLF), or "" if not pre-baked.
fn status_line_h1(code: i32) -> const u8[:] {
    if code < 300 {
        return status_line_h1_1xx_2xx(code);
    }
    if code < 400 {
        return status_line_h1_3xx(code);
    }
    if code < 500 {
        return status_line_h1_4xx(code);
    }
    return status_line_h1_5xx(code);
}

// RFC 9110 Section 15: Status Codes - Responses with 1xx, 204, or 304 status MUST NOT contain a message body.
inline fn is_empty_body_status(code: i32) -> bool {
    return (code >= 100 && code < 200) || code == STATUS_NO_CONTENT || code == STATUS_NOT_MODIFIED;
}

// RFC 9110 Section 15.4: Redirection 3xx - Checks whether `code` is a followable redirect status.
inline fn is_redirect_status(code: i32) -> bool {
    return code == STATUS_MOVED_PERMANENTLY ||
           code == STATUS_FOUND ||
           code == STATUS_SEE_OTHER ||
           code == STATUS_TEMPORARY_REDIRECT ||
           code == STATUS_PERMANENT_REDIRECT;
}

// ---- HTTP Methods & SWAR Word Constants (RFC 9110 Section 9, RFC 9112) ---

const METHOD_GET:     const u8[:] = "GET";
const METHOD_HEAD:    const u8[:] = "HEAD";
const METHOD_POST:    const u8[:] = "POST";
const METHOD_PUT:     const u8[:] = "PUT";
const METHOD_DELETE:  const u8[:] = "DELETE";
const METHOD_CONNECT: const u8[:] = "CONNECT";
const METHOD_OPTIONS: const u8[:] = "OPTIONS";
const METHOD_TRACE:   const u8[:] = "TRACE";
const METHOD_PATCH:   const u8[:] = "PATCH";
const METHOD_QUERY:   const u8[:] = "QUERY"; // RFC 10008 Section 2

// Little-endian SWAR word constants for HTTP/1.1 request-line parsing (RFC 9112 Section 3)
const METHOD_GET_U32:     u32 = 0x20544547;         // "GET "
const METHOD_PUT_U32:     u32 = 0x20545550;         // "PUT "
const METHOD_POST_U64:    u64 = 0x2054534F50;       // "POST "
const METHOD_HEAD_U64:    u64 = 0x2044414548;       // "HEAD "
const METHOD_DELETE_U64:  u64 = 0x00204554454C4544; // "DELETE "
const METHOD_OPTIONS_U64: u64 = 0x20534E4F4954504F; // "OPTIONS "
const METHOD_CONNECT_U64: u64 = 0x205443454E4E4F43; // "CONNECT "
const METHOD_PATCH_U64:   u64 = 0x204843544150;     // "PATCH "
const METHOD_TRACE_U64:   u64 = 0x204543415254;     // "TRACE "

const HTTP_VERSION_1_1_U64: u64 = 0x312E312F50545448; // RFC 9112 Section 2.3 ("HTTP/1.1")
const HTTP_VERSION_1_0_U64: u64 = 0x302E312F50545448; // RFC 9112 Section 2.3 ("HTTP/1.0")

// ---- Standard HTTP Header Field Names & Media Types ----------------------

const HEADER_HOST:                const u8[:] = "Host";                // RFC 9110 Section 7.2
const HEADER_CONTENT_TYPE:        const u8[:] = "Content-Type";        // RFC 9110 Section 8.3
const HEADER_CONTENT_LENGTH:      const u8[:] = "Content-Length";      // RFC 9110 Section 8.6
const HEADER_TRANSFER_ENCODING:   const u8[:] = "Transfer-Encoding";   // RFC 9112 Section 6.1
const HEADER_CONNECTION:          const u8[:] = "Connection";          // RFC 9110 Section 7.6.1
const HEADER_DATE:                const u8[:] = "Date";                // RFC 9110 Section 6.6.1
const HEADER_SERVER:              const u8[:] = "Server";              // RFC 9110 Section 10.2.4
const HEADER_USER_AGENT:          const u8[:] = "User-Agent";          // RFC 9110 Section 10.1.5
const HEADER_ACCEPT:              const u8[:] = "Accept";              // RFC 9110 Section 12.5.1
const HEADER_AUTHORIZATION:       const u8[:] = "Authorization";       // RFC 9110 Section 11.6.2
const HEADER_COOKIE:              const u8[:] = "Cookie";              // RFC 6265 Section 5.4
const HEADER_SET_COOKIE:          const u8[:] = "Set-Cookie";          // RFC 6265 Section 4.1
const HEADER_LOCATION:            const u8[:] = "Location";            // RFC 9110 Section 10.2.2
const HEADER_UPGRADE:             const u8[:] = "Upgrade";             // RFC 9110 Section 7.8
const HEADER_ALT_SVC:             const u8[:] = "Alt-Svc";             // RFC 7838 Section 3
const HEADER_PRIORITY:            const u8[:] = "Priority";            // RFC 9218 Section 5
const HEADER_CACHE_STATUS:        const u8[:] = "Cache-Status";        // RFC 9211 Section 2
const HEADER_PROXY_STATUS:        const u8[:] = "Proxy-Status";        // RFC 9209 Section 2
const HEADER_ACCEPT_QUERY:        const u8[:] = "Accept-Query";        // RFC 10008 Section 3
const HEADER_FORWARDED:           const u8[:] = "Forwarded";           // RFC 7239 Section 4
const HEADER_EARLY_DATA:          const u8[:] = "Early-Data";          // RFC 8470 Section 5.1
const HEADER_CONTENT_DISPOSITION: const u8[:] = "Content-Disposition"; // RFC 6266 Section 4

const MIME_TEXT_PLAIN:               const u8[:] = "text/plain";
const MIME_TEXT_HTML:                const u8[:] = "text/html";
const MIME_APPLICATION_JSON:         const u8[:] = "application/json";
const MIME_APPLICATION_OCTET_STREAM: const u8[:] = "application/octet-stream";
const MIME_PROBLEM_JSON:             const u8[:] = "application/problem+json"; // RFC 9457 Section 3
const MIME_PROBLEM_XML:              const u8[:] = "application/problem+xml";  // RFC 9457 Section 3
const MIME_MULTIPART_FORM_DATA:      const u8[:] = "multipart/form-data";      // RFC 7578 Section 4
const MIME_FORM_URLENCODED:          const u8[:] = "application/x-www-form-urlencoded";
const MIME_PARTIAL_UPLOAD:           const u8[:] = "application/partial-upload";

// ---- Binary HTTP & Oblivious HTTP (RFC 9292, RFC 9458) -------------------

const BHTTP_FRAME_KNOWN_LEN_REQUEST:  u8 = 0; // RFC 9292 Section 3.3
const BHTTP_FRAME_KNOWN_LEN_RESPONSE: u8 = 1; // RFC 9292 Section 3.3

const OHTTP_INFO_REQUEST:       const u8[:] = "message/bhttp request";  // RFC 9458 Section 4.1
const OHTTP_INFO_RESPONSE:      const u8[:] = "message/bhttp response"; // RFC 9458 Section 4.4
const OHTTP_HDR_LEN:            i64         = 7;                        // RFC 9458 Section 4.1
const OHTTP_NENC:               i64         = 32;                       // RFC 9458 Section 4.1
const OHTTP_AEAD_TAG_LEN:       i64         = 16;                       // RFC 9458 Section 4.1
const OHTTP_MIN_KEY_CONFIG_LEN: i64         = 41;                       // RFC 9458 Section 3.1

// ---- Compression Dictionary Transport (RFC 9842) -------------------------

const DCZ_MAGIC_BYTE0: u8 = 0xFF; // RFC 9842 Section 5
const DCZ_MAGIC_BYTE1: u8 = 0x44; // 'D'
const DCZ_MAGIC_BYTE2: u8 = 0x43; // 'C'
const DCZ_MAGIC_BYTE3: u8 = 0x5A; // 'Z'

const DCB_MAGIC_BYTE0: u8 = 0xFF; // RFC 9842 Section 4
const DCB_MAGIC_BYTE1: u8 = 0x44; // 'D'
const DCB_MAGIC_BYTE2: u8 = 0x43; // 'C'
const DCB_MAGIC_BYTE3: u8 = 0x42; // 'B'

const HEADER_USE_AS_DICTIONARY:    const u8[:] = "use-as-dictionary";    // RFC 9842 Section 2.1
const HEADER_AVAILABLE_DICTIONARY: const u8[:] = "available-dictionary"; // RFC 9842 Section 2.2
const HEADER_DICTIONARY_ID:        const u8[:] = "dictionary-id";        // RFC 9842 Section 2.3
const ENCODING_DCZ:                const u8[:] = "dcz";                  // RFC 9842 Section 5
const ENCODING_DCB:                const u8[:] = "dcb";                  // RFC 9842 Section 4

// ---- Digest Fields & HTTP Message Signatures (RFC 9530, RFC 9421) --------

const HEADER_CONTENT_DIGEST:      const u8[:] = "Content-Digest";      // RFC 9530 Section 2
const HEADER_REPR_DIGEST:         const u8[:] = "Repr-Digest";         // RFC 9530 Section 3
const HEADER_WANT_CONTENT_DIGEST: const u8[:] = "Want-Content-Digest"; // RFC 9530 Section 4
const HEADER_WANT_REPR_DIGEST:    const u8[:] = "Want-Repr-Digest";    // RFC 9530 Section 4
const DIGEST_ALG_SHA256:          const u8[:] = "sha-256";             // RFC 9530 Section 5
const DIGEST_ALG_SHA512:          const u8[:] = "sha-512";             // RFC 9530 Section 5

const HEADER_SIGNATURE_INPUT: const u8[:] = "Signature-Input"; // RFC 9421 Section 4.1
const HEADER_SIGNATURE:       const u8[:] = "Signature";       // RFC 9421 Section 4.2
const SIG_ALG_HMAC_SHA256:    const u8[:] = "hmac-sha256";     // RFC 9421 Section 3.3.3
const SIG_ALG_ED25519:        const u8[:] = "ed25519";         // RFC 9421 Section 3.3.6

// ---- Incremental HTTP, Extensible Priority & Resumable Uploads -----------

const HEADER_INCREMENTAL:                   const u8[:] = "Incremental";              // RFC 10036 Section 2
const PROXY_ERROR_INCREMENTAL_REFUSED:      const u8[:] = "incremental_refused";      // RFC 10036 Section 3
const PROXY_ERROR_CONNECTION_LIMIT_REACHED: const u8[:] = "connection_limit_reached"; // RFC 9209 Section 2.3

const PRIORITY_URGENCY_HIGHEST: u8 = 0; // RFC 9218 Section 4
const PRIORITY_URGENCY_HIGH:    u8 = 1; // RFC 9218 Section 4
const PRIORITY_URGENCY_DEFAULT: u8 = 3; // RFC 9218 Section 4
const PRIORITY_URGENCY_LOW:     u8 = 5; // RFC 9218 Section 4
const PRIORITY_URGENCY_LOWEST:  u8 = 7; // RFC 9218 Section 4

const HEADER_UPLOAD_OFFSET:   const u8[:] = "Upload-Offset";
const HEADER_UPLOAD_COMPLETE: const u8[:] = "Upload-Complete";

const MAX_DELTA_SECONDS: i32 = 2147483647; // RFC 9111 Section 1.2.2 (2^31 - 1)

// ---- Security.txt, ACME, Digest Auth, DPoP, PKCE & Privacy Pass ----------

const SECURITY_TXT_WELL_KNOWN_PATH: const u8[:] = "/.well-known/security.txt";   // RFC 9116 Section 3
const SECURITY_TXT_LEGACY_PATH:     const u8[:] = "/security.txt";               // RFC 9116 Section 3
const SECURITY_TXT_CONTENT_TYPE:    const u8[:] = "text/plain; charset=utf-8";   // RFC 9116 Section 3

const ACME_HTTP01_PREFIX: const u8[..28] = "/.well-known/acme-challenge/";       // RFC 8555 Section 8.3

const DIGEST_ALGO_MD5:             const u8[:] = "MD5";          // RFC 7616 Section 3.4
const DIGEST_ALGO_MD5_SESS:        const u8[:] = "MD5-sess";     // RFC 7616 Section 3.4
const DIGEST_ALGO_SHA256:          const u8[:] = "SHA-256";      // RFC 7616 Section 3.4
const DIGEST_ALGO_SHA256_SESS:     const u8[:] = "SHA-256-sess"; // RFC 7616 Section 3.4
const DIGEST_ALGO_SHA512_256:      const u8[:] = "SHA-512-256";  // RFC 7616 Section 3.4
const DIGEST_ALGO_SHA512_256_SESS: const u8[:] = "SHA-512-256-sess";
const DIGEST_QOP_AUTH:             const u8[:] = "auth";        // RFC 7616 Section 3.4
const DIGEST_QOP_AUTH_INT:         const u8[:] = "auth-int";    // RFC 7616 Section 3.4

const DPOP_HEADER:            const u8[:] = "DPoP";               // RFC 9449 Section 4.1
const DPOP_NONCE_HEADER:      const u8[:] = "DPoP-Nonce";         // RFC 9449 Section 8
const DPOP_AUTH_SCHEME:       const u8[:] = "DPoP";               // RFC 9449 Section 7.1
const DPOP_JWT_TYP:           const u8[:] = "dpop+jwt";           // RFC 9449 Section 4.2
const DPOP_ERR_INVALID_PROOF: const u8[:] = "invalid_dpop_proof"; // RFC 9449 Section 5
const DPOP_ERR_INVALID_TOKEN: const u8[:] = "invalid_token";      // RFC 9449 Section 7.1
const DPOP_ERR_USE_NONCE:     const u8[:] = "use_dpop_nonce";     // RFC 9449 Section 8

const PKCE_METHOD_S256:      const u8[:] = "S256";  // RFC 7636 Section 4.2
const PKCE_METHOD_PLAIN:     const u8[:] = "plain"; // RFC 7636 Section 4.2
const PKCE_MIN_VERIFIER_LEN: i64         = 43;      // RFC 7636 Section 4.1
const PKCE_MAX_VERIFIER_LEN: i64         = 128;     // RFC 7636 Section 4.1

const ED25519_KEY_LEN:     i64 = 32; // RFC 8032 Section 5.1.5
const ED25519_SIG_LEN:     i64 = 64; // RFC 8032 Section 5.1.6
const HMAC_SHA256_MAC_LEN: i64 = 32; // RFC 7518 Section 3.2
const HMAC_SHA384_MAC_LEN: i64 = 48; // RFC 7518 Section 3.2
const HMAC_SHA512_MAC_LEN: i64 = 64; // RFC 7518 Section 3.2

const SCHEME_PRIVATE_TOKEN:           const u8[:] = "PrivateToken";            // RFC 9577 Section 2
const HEADER_SEC_PRIVATE_STATE_TOKEN: const u8[:] = "Sec-Private-State-Token";
const TOKEN_TYPE_BLIND_RSA:           u16         = 0x0001;                    // RFC 9578 Section 5
const TOKEN_TYPE_PUBLICLY_VERIFIABLE: u16         = 0x0002;                    // RFC 9578 Section 6
