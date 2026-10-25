// AWS Signature Version 4 (SigV4) Request Signing.
// Compliant with AWS SigV4 specification for S3, DynamoDB, API Gateway, SQS, etc.
// Automatically derives HMAC-SHA256 cascade signing keys and injects Authorization, x-amz-date & x-amz-content-sha256.
namespace wing;

import std;
import core from "..";

struct AwsCredentials {
    access_key_id: u8[..64] = [],
    secret_access_key: u8[..128] = [],
    session_token: u8[..256] = [],
    region: u8[..32] = "us-east-1",
    service: u8[..32] = "s3",
}

fn new_aws_credentials(
    access_key: const u8[:],
    secret_key: const u8[:],
    region: const u8[:] = "us-east-1",
    service: const u8[:] = "s3"
) -> AwsCredentials {
    var creds = AwsCredentials { .. };
    creds.access_key_id.append(access_key);
    creds.secret_access_key.append(secret_key);
    creds.region.clear();
    creds.region.append(region);
    creds.service.clear();
    creds.service.append(service);
    return creds;
}

// Derives AWS SigV4 32-byte signing key using HMAC-SHA256 4-step cascade
fn derive_aws_signing_key(
    secret_key: const u8[:],
    date_stamp: const u8[:], // "YYYYMMDD"
    region: const u8[:],
    service: const u8[:]
) -> u8[32] {
    var k_secret: u8[..140] = [];
    k_secret.append("AWS4");
    k_secret.append(secret_key);

    let k_date = core::hmac_sha256(k_secret[..], date_stamp);
    let k_region = core::hmac_sha256(k_date[..], region);
    let k_service = core::hmac_sha256(k_region[..], service);
    let k_signing = core::hmac_sha256(k_service[..], "aws4_request");
    return k_signing;
}

// Signs a Request with AWS SigV4 headers
fn sign_aws_sigv4<R>(
    req: R&,
    creds: const AwsCredentials&,
    datetime_iso: const u8[:] // e.g. "20130524T000000Z"
) -> bool {
    guard creds.access_key_id.len > 0 && creds.secret_access_key.len > 0 else { return false; }
    guard datetime_iso.len >= 16 else { return false; }

    let date_stamp = datetime_iso[..8]; // "YYYYMMDD"

    // 1. Calculate payload hash
    var payload_sha_hex: u8[..64] = [];
    let p_hash = core::sha256(req.body[..]);
    for b in p_hash {
        core::format_u8_hex(b, payload_sha_hex);
    }

    // 2. Inject x-amz-date & x-amz-content-sha256 if not present
    if !req.has_header("x-amz-date") {
        req.headers.push(make_header("x-amz-date", datetime_iso));
    }
    if !req.has_header("x-amz-content-sha256") {
        req.headers.push(make_header("x-amz-content-sha256", payload_sha_hex[..]));
    }
    if creds.session_token.len > 0 {
        req.headers.push(make_header("x-amz-security-token", creds.session_token[..]));
    }

    // 3. Build Canonical Request
    // URI path
    var canon_uri: u8[..256] = [];
    let parsed, err = core::parse_url(req.url[..]);
    if parsed.valid {
        let p = core::pathname(parsed);
        if p.len > 0 {
            canon_uri.append(p);
        } else {
            canon_uri.append("/");
        }
    } else {
        canon_uri.append("/");
    }

    // Canonical Query String
    var canon_query: u8[..256] = [];
    if parsed.valid {
        let q = core::search(parsed);
        if q.len > 1 {
            canon_query.append(q[1..]); // omit '?'
        }
    }

    // Canonical Headers & Signed Headers
    // AWS requires lowercase header names in sorted order
    var canon_headers: u8[>..] = [];
    var signed_headers: u8[..128] = [];

    // Include host
    if parsed.valid {
        let h = core::hostname(parsed);
        canon_headers.append("host:");
        canon_headers.append(h);
        canon_headers.push('\n');
        signed_headers.append("host");
    }

    canon_headers.append("x-amz-content-sha256:");
    canon_headers.append(payload_sha_hex[..]);
    canon_headers.push('\n');
    if signed_headers.len > 0 { signed_headers.push(';'); }
    signed_headers.append("x-amz-content-sha256");

    canon_headers.append("x-amz-date:");
    canon_headers.append(datetime_iso);
    canon_headers.push('\n');
    if signed_headers.len > 0 { signed_headers.push(';'); }
    signed_headers.append("x-amz-date");

    // Canonical Request string
    var canon_req: u8[>..] = [];
    canon_req.append(req.method[..]);
    canon_req.push('\n');
    canon_req.append(canon_uri[..]);
    canon_req.push('\n');
    canon_req.append(canon_query[..]);
    canon_req.push('\n');
    canon_req.append(canon_headers[..]);
    canon_req.push('\n');
    canon_req.append(signed_headers[..]);
    canon_req.push('\n');
    canon_req.append(payload_sha_hex[..]);

    let canon_req_hash = core::sha256(canon_req[..]);
    var canon_req_hash_hex: u8[..64] = [];
    for b in canon_req_hash {
        core::format_u8_hex(b, canon_req_hash_hex);
    }

    // 4. Build StringToSign
    // "AWS4-HMAC-SHA256\n<RequestDateTime>\n<CredentialScope>\n<HashedCanonicalRequest>"
    var credential_scope: u8[..128] = [];
    credential_scope.append(date_stamp);
    credential_scope.push('/');
    credential_scope.append(creds.region[..]);
    credential_scope.push('/');
    credential_scope.append(creds.service[..]);
    credential_scope.append("/aws4_request");

    var string_to_sign: u8[>..] = [];
    string_to_sign.append("AWS4-HMAC-SHA256\n");
    string_to_sign.append(datetime_iso);
    string_to_sign.push('\n');
    string_to_sign.append(credential_scope[..]);
    string_to_sign.push('\n');
    string_to_sign.append(canon_req_hash_hex[..]);

    // 5. Compute Signature = HMAC-SHA256(SigningKey, StringToSign)
    let signing_key = derive_aws_signing_key(creds.secret_access_key[..], date_stamp, creds.region[..], creds.service[..]);
    let sig_bytes = core::hmac_sha256(signing_key[..], string_to_sign[..]);
    var sig_hex: u8[..64] = [];
    for b in sig_bytes {
        core::format_u8_hex(b, sig_hex);
    }

    // 6. Build Authorization Header
    // "AWS4-HMAC-SHA256 Credential=<AccessKey>/<CredentialScope>, SignedHeaders=<SignedHeaders>, Signature=<Signature>"
    var auth_val: u8[..512] = [];
    auth_val.append("AWS4-HMAC-SHA256 Credential=");
    auth_val.append(creds.access_key_id[..]);
    auth_val.push('/');
    auth_val.append(credential_scope[..]);
    auth_val.append(", SignedHeaders=");
    auth_val.append(signed_headers[..]);
    auth_val.append(", Signature=");
    auth_val.append(sig_hex[..]);

    req.headers.push(make_header("Authorization", auth_val[..]));
    return true;
}
