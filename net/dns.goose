// net/dns.goose
// Deterministic zero-allocation DNS engine with RFC 9460 HTTPS/SVCB Resource Records (Type 65).
// Supports wire message decoding, name compression pointer resolution, ALPN extraction,
// IPv4/IPv6 hints, and raw ECHConfigList extraction for Encrypted Client Hello (RFC 9460 Key 5).
namespace wing;

import std;
import security.ct;

// ---- 1. DNS Wire Constants & Record Types -----------------------------------

const DNS_QTYPE_A: u16 = 1;
const DNS_QTYPE_AAAA: u16 = 28;
const DNS_QTYPE_SVCB: u16 = 64;  // RFC 9460
const DNS_QTYPE_HTTPS: u16 = 65; // RFC 9460

const DNS_QCLASS_IN: u16 = 1;

const DNS_RCODE_NOERROR: u8 = 0;
const DNS_RCODE_FORMERR: u8 = 1;
const DNS_RCODE_SERVFAIL: u8 = 2;
const DNS_RCODE_NXDOMAIN: u8 = 3;

// RFC 9460 SvcParamKey Registrations (Section 14.3)
const SVC_PARAM_MANDATORY: u16       = 0;
const SVC_PARAM_ALPN: u16            = 1;
const SVC_PARAM_NO_DEFAULT_ALPN: u16 = 2;
const SVC_PARAM_PORT: u16            = 3;
const SVC_PARAM_IPV4HINT: u16        = 4;
const SVC_PARAM_ECH: u16             = 5; // Encrypted Client Hello ECHConfigList
const SVC_PARAM_IPV6HINT: u16        = 6;

// ---- 2. Data Structures ----------------------------------------------------

struct HttpsRecord {
    priority: u16 = 0,               // 0 = AliasMode, >0 = ServiceMode
    target_name: u8[..255] = [],
    alpns: u8[..16][..8] = [],
    port: u16 = 443,
    no_default_alpn: bool = false,
    ipv4_hints: u32[..8] = [],
    ipv6_hints: u8[16][..8] = [],
    ech_config_list: u8[..512] = [], // Raw wire bytes of ECHConfigList
    has_ech: bool = false,
}

struct DnsResponse {
    tx_id: u16 = 0,
    rcode: u8 = DNS_RCODE_NOERROR,
    is_response: bool = false,
    question_count: u16 = 0,
    answer_count: u16 = 0,
    a_records: u32[..8] = [],
    aaaa_records: u8[16][..8] = [],
    https_records: HttpsRecord[..4] = [],
}

// ---- 3. DNS Name Encoding and Compression Decoding (RFC 1035) --------------

// Encodes a human-readable domain name (e.g. "example.com") into DNS label wire format.
fn dns_encode_name<B>(domain: const u8[:], out: B&) -> bool {
    guard domain.len > 0 && domain.len <= 253 else { return false; }

    var start = 0;
    while start < domain.len {
        var dot_pos = domain.len;
        for i in start..domain.len {
            if domain[i] == '.' {
                dot_pos = i;
                break;
            }
        }

        let label_len = dot_pos - start;
        guard label_len > 0 && label_len <= 63 else { return false; }

        out.push(label_len as u8);
        for i in start..dot_pos {
            out.push(domain[i]);
        }

        start = dot_pos + 1;
    }

    out.push(0); // Zero root label
    return true;
}

// Decodes a DNS domain name from raw wire format, resolving compression pointers (0xC0).
fn dns_decode_name<B>(raw: const u8[:], offset: i64&, out: B&) -> bool {
    var jumps = 0;
    var current_off = offset;
    var advanced_original = false;

    while current_off < raw.len {
        let b = raw[current_off];
        if b == 0 {
            if !advanced_original {
                offset = current_off + 1;
            }
            return true;
        }

        // Pointer flag 0xC0
        if (b & 0xC0) == 0xC0 {
            guard current_off + 1 < raw.len else { return false; }
            let ptr_off = (((b & 0x3F) as i64) << 8) | (raw[current_off + 1] as i64);
            guard ptr_off < raw.len else { return false; }

            if !advanced_original {
                offset = current_off + 2;
                advanced_original = true;
            }

            current_off = ptr_off;
            jumps += 1;
            guard jumps <= 16 else { return false; } // Prevent pointer loops
            continue;
        }

        let label_len = b;
        current_off += 1;
        guard current_off + label_len <= raw.len else { return false; }

        if out.len > 0 {
            out.push('.');
        }
        for i in current_off..current_off + label_len {
            out.push(raw[i]);
        }
        current_off += label_len;

        if !advanced_original {
            offset = current_off;
        }
    }
    return false;
}

// ---- 4. Query Builder ------------------------------------------------------

// Builds a standard 12-byte header + question DNS query.
fn build_dns_query(domain: const u8[:], qtype: u16, tx_id: u16, out: u8[>..]&) -> bool {
    // 1. Transaction ID
    out.push(((tx_id >> 8) & 0xFF) as u8);
    out.push((tx_id & 0xFF) as u8);

    // 2. Flags: Standard query, Recursion Desired (RD = 1) -> 0x0100
    out.push(0x01);
    out.push(0x00);

    // 3. QDCOUNT = 1
    out.push(0x00);
    out.push(0x01);

    // 4. ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
    out.push(0x00); out.push(0x00);
    out.push(0x00); out.push(0x00);
    out.push(0x00); out.push(0x00);

    // 5. Question Section
    guard dns_encode_name(domain, out) else { return false; }

    // QTYPE
    out.push(((qtype >> 8) & 0xFF) as u8);
    out.push((qtype & 0xFF) as u8);

    // QCLASS (IN = 1)
    out.push(0x00);
    out.push(0x01);

    return true;
}

// ---- 5. RFC 9460 HTTPS/SVCB RDATA Parser -----------------------------------

// Parses SvcParams list from HTTPS/SVCB RDATA according to RFC 9460 Section 2.1.
fn parse_https_svc_params(rdata: const u8[:], rec: HttpsRecord&) -> bool {
    var off: i64 = 0;
    while off + 4 <= rdata.len {
        let key = ((rdata[off] as u16) << 8) | rdata[off + 1];
        let val_len = (((rdata[off + 2] as u16) << 8) | rdata[off + 3]) as i64;
        off += 4;
        guard off + val_len <= rdata.len else { return false; }

        let val = rdata[off..off + val_len];
        off += val_len;

        if key == SVC_PARAM_ALPN {
            var alpn_off: i64 = 0;
            while alpn_off < val.len && rec.alpns.len < rec.alpns.cap {
                let slen = val[alpn_off] as i64;
                alpn_off += 1;
                guard alpn_off + slen <= val.len else { return false; }
                let s = val[alpn_off..alpn_off + slen];
                var entry: u8[..16] = [];
                for i in s.len {
                    if entry.len < entry.cap { entry.push(s[i]); }
                }
                rec.alpns.push(entry);
                alpn_off += slen;
            }
        } else if key == SVC_PARAM_NO_DEFAULT_ALPN {
            rec.no_default_alpn = true;
        } else if key == SVC_PARAM_PORT {
            if val.len == 2 {
                rec.port = ((val[0] as u16) << 8) | val[1];
            }
        } else if key == SVC_PARAM_IPV4HINT {
            var ip_off: i64 = 0;
            while ip_off + 4 <= val.len && rec.ipv4_hints.len < rec.ipv4_hints.cap {
                let ip = ((val[ip_off] as u32) << 24) |
                         ((val[ip_off + 1] as u32) << 16) |
                         ((val[ip_off + 2] as u32) << 8) |
                         val[ip_off + 3];
                rec.ipv4_hints.push(ip);
                ip_off += 4;
            }
        } else if key == SVC_PARAM_IPV6HINT {
            var ip_off: i64 = 0;
            while ip_off + 16 <= val.len && rec.ipv6_hints.len < rec.ipv6_hints.cap {
                var ip6: u8[16] = [0; 16];
                for i in 16 { ip6[i] = val[ip_off + i]; }
                rec.ipv6_hints.push(ip6);
                ip_off += 16;
            }
        } else if key == SVC_PARAM_ECH {
            // Raw wire bytes of ECHConfigList (RFC 9460 Section 5)
            rec.has_ech = true;
            for i in val.len {
                if rec.ech_config_list.len < rec.ech_config_list.cap {
                    rec.ech_config_list.push(val[i]);
                }
            }
        }
    }
    return true;
}

// ---- 6. Response Parser ----------------------------------------------------

// Parses a complete DNS response wire message.
fn parse_dns_response(raw: const u8[:], out: DnsResponse&) -> bool {
    guard raw.len >= 12 else { return false; }

    out.tx_id = ((raw[0] as u16) << 8) | raw[1];
    let flags = ((raw[2] as u16) << 8) | raw[3];
    out.is_response = ((flags >> 15) & 1) == 1;
    out.rcode = (flags & 0x0F) as u8;

    out.question_count = ((raw[4] as u16) << 8) | raw[5];
    out.answer_count = ((raw[6] as u16) << 8) | raw[7];

    guard out.rcode == DNS_RCODE_NOERROR else { return true; }

    var off: i64 = 12;

    // Skip question section
    for q in out.question_count {
        var qname: u8[>..] = [];
        guard dns_decode_name(raw, off, qname) else { return false; }
        guard off + 4 <= raw.len else { return false; }
        off += 4; // Skip QTYPE and QCLASS
    }

    // Parse answer section
    for a in out.answer_count {
        var aname: u8[>..] = [];
        guard dns_decode_name(raw, off, aname) else { return false; }
        guard off + 10 <= raw.len else { return false; }

        let rtype = ((raw[off] as u16) << 8) | raw[off + 1];
        let rclass = ((raw[off + 2] as u16) << 8) | raw[off + 3];
        let ttl = ((raw[off + 4] as u32) << 24) | ((raw[off + 5] as u32) << 16) |
                  ((raw[off + 6] as u32) << 8) | raw[off + 7];
        let rdlength = (((raw[off + 8] as u16) << 8) | raw[off + 9]) as i64;
        off += 10;
        guard off + rdlength <= raw.len else { return false; }

        let rdata_start = off;
        let rdata = raw[off..off + rdlength];
        off += rdlength;

        if rtype == DNS_QTYPE_A && rdlength == 4 {
            if out.a_records.len < out.a_records.cap {
                let ip4 = ((rdata[0] as u32) << 24) | ((rdata[1] as u32) << 16) |
                          ((rdata[2] as u32) << 8) | rdata[3];
                out.a_records.push(ip4);
            }
        } else if rtype == DNS_QTYPE_AAAA && rdlength == 16 {
            if out.aaaa_records.len < out.aaaa_records.cap {
                var ip6: u8[16] = [0; 16];
                for i in 16 { ip6[i] = rdata[i]; }
                out.aaaa_records.push(ip6);
            }
        } else if rtype == DNS_QTYPE_HTTPS || rtype == DNS_QTYPE_SVCB {
            guard rdlength >= 3 else { continue; }
            if out.https_records.len < out.https_records.cap {
                var rec = HttpsRecord { .. };
                rec.priority = ((rdata[0] as u16) << 8) | rdata[1];
                var target_off = rdata_start + 2;
                guard dns_decode_name(raw, target_off, rec.target_name) else { return false; }

                let rdata_end = rdata_start + rdlength;
                if target_off < rdata_end {
                    let svc_params = raw[target_off..rdata_end];
                    guard parse_https_svc_params(svc_params, rec) else { return false; }
                }
                out.https_records.push(rec);
            }
        }
    }

    return true;
}

// ---- 7. DNS over HTTPS (DoH RFC 8484) Wire Helpers --------------------------

// Formats a DoH POST application/dns-message body for querying `domain` with `qtype`.
fn build_doh_post_body(domain: const u8[:], qtype: u16, tx_id: u16, out_body: u8[>..]&) -> bool {
    return build_dns_query(domain, qtype, tx_id, out_body);
}

// Formats base64url query parameter for DoH GET request (RFC 8484 Section 4.1).
fn build_doh_get_url(server_url: const u8[:], domain: const u8[:], qtype: u16, out_url: u8[>..]&) -> bool {
    var raw_query: u8[>..] = [];
    guard build_dns_query(domain, qtype, 0, raw_query) else { return false; }

    out_url.append(server_url);
    out_url.append("?dns=");
    base64url_encode(raw_query[..], out_url);
    return true;
}
