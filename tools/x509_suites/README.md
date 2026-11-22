# goose-wing X.509 PKI conformance suites

X.509 PKI and revocation conformance testbed driving
`tls::parse_x509_certificate`, `tls::add_trust_anchor_cert_der`,
`tls::verify_certificate_chain`, `tls::get_cert_san_extension`,
`tls::match_any_san`, `tls::parse_x509_crl`, `tls::x509_verify_crl_signature`,
`tls::crl_is_revoked`, and `tls::validate_ocsp_stapling` via
[x509_harness.goose](x509_harness.goose).

## Quick start

### Local offline matrix (58 vectors across all three suites)

```bash
python tools/x509_suites.py --local --suite all
```

### Run an individual suite or external corpus

```bash
python tools/x509_suites.py --local --suite limbo
python tools/x509_suites.py --local --suite bettertls
python tools/x509_suites.py --local --suite pkits
python tools/x509_suites.py --limbo-json /path/to/limbo.json
python tools/x509_suites.py --fetch --suite limbo
python tools/x509_suites.py --pkits-dir /path/to/PKITS_data --suite pkits
```

### Docker mode (with official Netflix/bettertls)

```bash
python tools/x509_suites.py --docker
```

## Verified conformance coverage

| Suite | Local vectors | Verified rules |
| :--- | :--- | :--- |
| `x509-limbo` | 24 | Real C2SP `limbo.json` PEM/DER schema, OpenSSL RSA-2048 interop, wildcard SAN rules (leftmost, apex, multi-level, non-leftmost), IPv4/IPv6 SANs, CN-without-SAN rejection, weak RSA-1024 rejection, EKU `serverAuth`/`clientAuth` role enforcement, critical unknown extensions, untrusted self-signed leaves, `pathLenConstraint=0`, validity bounds, `basicConstraints cA=false`, chain cycles, mismatched inner/outer `signatureAlgorithm`, trailing DER garbage, and forbidden SHA-1 signatures. |
| `BetterTLS` | 14 | Intermediate DNS and IPv4 permitted/excluded `NameConstraints`, TrustAnchor root `NameConstraints`, end-entity `NameConstraints` prohibition, out-of-order intermediate path building, cross-signed alternate trust paths, and unrelated decoy intermediates. |
| `NIST PKITS` | 20 | RFC 5280 signature validation, validity periods, missing or false `basicConstraints`, `keyUsage` `keyCertSign`, `pathLenConstraint=0`, self-issued intermediate rollover exemption, CRL signature/expiry/revocation checks, and RFC 6960 OCSP stapling (`good`, `revoked`, bad signature, mismatched serial). |
