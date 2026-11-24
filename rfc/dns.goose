// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Wire-level DNS, HTTPS/SVCB resource record, and DoH constants (RFC 1035, 8484, 9460).
namespace rfc;

// ---- DNS Record Types & Classes (RFC 1035, 8484, 9460) -------------------

// RFC 1035 Section 3.2.2: TYPE values - host address record.
const DNS_QTYPE_A: u16 = 1;
// RFC 1035 Section 3.2.2: TYPE values - canonical name for an alias.
const DNS_QTYPE_CNAME: u16 = 5;
// RFC 8484 Section 4.1: The HTTP Request - IPv6 address record type.
const DNS_QTYPE_AAAA: u16 = 28;
// RFC 9460 Section 14.1: SVCB RR Type - Service Binding record type.
const DNS_QTYPE_SVCB: u16 = 64;
// RFC 9460 Section 14.2: HTTPS RR Type - HTTPS Service Binding record type.
const DNS_QTYPE_HTTPS: u16 = 65;
// RFC 1035 Section 3.2.4: CLASS values - Internet class.
const DNS_QCLASS_IN: u16 = 1;

// ---- DNS Header, RCODEs & Message Compression (RFC 1035) -----------------

// RFC 1035 Section 4.1.1: Header section format - fixed 12-octet DNS header length.
const DNS_HEADER_LEN: i64 = 12;
// RFC 1035 Section 4.1.1: Header section format - Recursion Desired (RD) flag bit.
const DNS_FLAG_RD: u16 = 0x0100;
// RFC 1035 Section 4.1.4: Message compression - two high-order pointer bits.
const DNS_POINTER_TAG: u8 = 0xC0;

// RFC 1035 Section 4.1.1: Header section format - no error condition.
const DNS_RCODE_NOERROR: u8 = 0;
// RFC 1035 Section 4.1.1: Header section format - format error.
const DNS_RCODE_FORMERR: u8 = 1;
// RFC 1035 Section 4.1.1: Header section format - server failure.
const DNS_RCODE_SERVFAIL: u8 = 2;
// RFC 1035 Section 4.1.1: Header section format - non-existent domain.
const DNS_RCODE_NXDOMAIN: u8 = 3;

// ---- SVCB/HTTPS SvcParamKeys (RFC 9460) ----------------------------------

// RFC 9460 Section 14.3.2: Initial Contents - mandatory keys list.
const SVC_PARAM_MANDATORY: u16 = 0;
// RFC 9460 Section 14.3.2: Initial Contents - application layer protocols.
const SVC_PARAM_ALPN: u16 = 1;
// RFC 9460 Section 14.3.2: Initial Contents - no fallback to default ALPN.
const SVC_PARAM_NO_DEFAULT_ALPN: u16 = 2;
// RFC 9460 Section 14.3.2: Initial Contents - target port override.
const SVC_PARAM_PORT: u16 = 3;
// RFC 9460 Section 14.3.2: Initial Contents - IPv4 address hints.
const SVC_PARAM_IPV4HINT: u16 = 4;
// RFC 9460 Section 14.3.2: Initial Contents - Encrypted ClientHello configuration.
const SVC_PARAM_ECH: u16 = 5;
// RFC 9460 Section 14.3.2: Initial Contents - IPv6 address hints.
const SVC_PARAM_IPV6HINT: u16 = 6;

// ---- DNS over HTTPS (DoH, RFC 8484) --------------------------------------

// RFC 8484 Section 6: Definition of the "application/dns-message" Media Type - 65535-octet limit.
const DOH_MAX_MESSAGE_OCTETS: i64 = 65535;
// RFC 8484 Section 6: Definition of the "application/dns-message" Media Type - wire MIME type.
const DOH_CONTENT_TYPE: const u8[:] = "application/dns-message";
