// Deterministic zero-allocation HAProxy PROXY Protocol v1 (text) and v2 (binary) parser & serializer.
// Conforms to the official HAProxy PROXY Protocol specification (Versions 1 and 2),
// supporting IPv4, IPv6, UNIX domain, and Type-Length-Value (TLV) metadata (ALPN, SNI, Unique ID, SSL/TLS).
namespace wing;

import std;
import core from "..";

// ---- 1. Constants and Normative Definitions ---------------------------------

// PROXY protocol version 1 prefix: "PROXY "
const PROXY_V1_PREFIX: const u8[6] = ['P', 'R', 'O', 'X', 'Y', ' '];
const PROXY_V1_MAX_LEN: i64 = 107; // RFC / HAProxy specification maximum v1 line length

// PROXY protocol version 2 12-byte constant preamble:
// \x0D \x0A \x0D \x0A \x00 \x0D \x0A \x51 \x55 \x49 \x54 \x0A ("\r\n\r\n\0\r\nQUIT\n")
const PROXY_V2_PREAMBLE: const u8[12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
];

// Protocol Commands (v2 nibble 0..3)
const PP2_CMD_LOCAL: u8 = 0x00; // Connection initiated by proxy (health check / discard address)
const PP2_CMD_PROXY: u8 = 0x01; // Forwarded connection (contains original address)

// Address Families (v2 upper nibble)
const PP2_FAM_UNSPEC: u8 = 0x00;
const PP2_FAM_INET4:  u8 = 0x01; // IPv4 (12 bytes: 4B src + 4B dst + 2B sport + 2B dport)
const PP2_FAM_INET6:  u8 = 0x02; // IPv6 (36 bytes: 16B src + 16B dst + 2B sport + 2B dport)
const PP2_FAM_UNIX:   u8 = 0x03; // Unix (216 bytes: 108B src + 108B dst)

// Transport Protocols (v2 lower nibble)
const PP2_TRANS_UNSPEC: u8 = 0x00;
const PP2_TRANS_STREAM: u8 = 0x01; // TCP
const PP2_TRANS_DGRAM:  u8 = 0x02; // UDP

// Type-Length-Value (TLV) Types
const PP2_TYPE_ALPN:      u8 = 0x01; // Application-Layer Protocol Negotiation (e.g. "h2")
const PP2_TYPE_AUTHORITY: u8 = 0x02; // Host name passed by the client (SNI / Host)
const PP2_TYPE_CRC32C:    u8 = 0x03; // CRC32c checksum
const PP2_TYPE_NOOP:      u8 = 0x04; // Ignored padding
const PP2_TYPE_UNIQUE_ID: u8 = 0x05; // Unique connection ID for tracing
const PP2_TYPE_SSL:       u8 = 0x20; // SSL/TLS client information
const PP2_TYPE_NETNS:     u8 = 0x30; // Network namespace name

// SSL Sub-TLV Types
const PP2_SUBTYPE_SSL_VERSION: u8 = 0x21; // TLS version string (e.g. "TLSv1.3")
const PP2_SUBTYPE_SSL_CN:      u8 = 0x22; // Client Common Name
const PP2_SUBTYPE_SSL_CIPHER:  u8 = 0x23; // Cipher name (e.g. "ECDHE-RSA-AES128-GCM-SHA256")
const PP2_SUBTYPE_SSL_SIG_ALG: u8 = 0x24; // Signature algorithm
const PP2_SUBTYPE_SSL_KEY_ALG: u8 = 0x25; // Key exchange algorithm

// SSL Client Bitmask Flags
const PP2_CLIENT_SSL:       u8 = 0x01; // Connection was over TLS
const PP2_CLIENT_CERT_CONN: u8 = 0x02; // Client provided a certificate in this connection
const PP2_CLIENT_CERT_SESS: u8 = 0x04; // Client provided a certificate in this session

// ---- 2. Data Structures -----------------------------------------------------

enum ProxyProtocolVersion {
    None,
    V1,
    V2,
}

enum ProxyCommand {
    Local,
    Proxy,
}

enum ProxyAddressFamily {
    Unspec,
    Inet4,
    Inet6,
    Unix,
}

enum ProxyTransportProtocol {
    Unspec,
    Stream,
    Datagram,
}

struct ProxySslInfo {
    has_ssl: bool = false,
    client_flags: u8 = 0,
    verify_result: u32 = 0,
    version: u8[..16] = [],
    cipher: u8[..64] = [],
    client_cn: u8[..128] = [],
    sig_alg: u8[..32] = [],
    key_alg: u8[..32] = [],
}

struct ProxyHeader {
    version: ProxyProtocolVersion = ProxyProtocolVersion.None,
    command: ProxyCommand = ProxyCommand.Proxy,
    family: ProxyAddressFamily = ProxyAddressFamily.Unspec,
    transport: ProxyTransportProtocol = ProxyTransportProtocol.Stream,
    src_ip_str: u8[..64] = [],
    dst_ip_str: u8[..64] = [],
    src_ipv4: u8[4] = [0; 4],
    dst_ipv4: u8[4] = [0; 4],
    src_ipv6: u8[16] = [0; 16],
    dst_ipv6: u8[16] = [0; 16],
    src_port: u16 = 0,
    dst_port: u16 = 0,
    alpn: u8[..32] = [],
    authority: u8[..128] = [],
    unique_id: u8[..64] = [],
    netns: u8[..64] = [],
    ssl: ProxySslInfo = ProxySslInfo { .. },
}

// ---- 3. Helper Codecs -------------------------------------------------------

inline fn read_u16_be(bytes: const u8[:], offset: i64) -> u16 {
    return ((bytes[offset] as u16) << 8) | bytes[offset + 1];
}

inline fn read_u32_be(bytes: const u8[:], offset: i64) -> u32 {
    return ((bytes[offset] as u32) << 24) |
           ((bytes[offset + 1] as u32) << 16) |
           ((bytes[offset + 2] as u32) << 8) |
           bytes[offset + 3];
}

fn write_u16_be<B>(out: B&, val: u16) {
    out.push(((val >> 8) & 0xFF) as u8);
    out.push((val & 0xFF) as u8);
}

fn write_u32_be<B>(out: B&, val: u32) {
    out.push(((val >> 24) & 0xFF) as u8);
    out.push(((val >> 16) & 0xFF) as u8);
    out.push(((val >> 8) & 0xFF) as u8);
    out.push((val & 0xFF) as u8);
}

// Formats an IPv4 address into dotted decimal string notation (e.g. "192.168.0.1")
fn format_ipv4<B>(ip: const u8[4]&, out: B&) {
    format(out, ip[0] as i64);
    out.push('.');
    format(out, ip[1] as i64);
    out.push('.');
    format(out, ip[2] as i64);
    out.push('.');
    format(out, ip[3] as i64);
}

// Formats an IPv6 address into hex notation
fn format_ipv6<B>(ip: const u8[16]&, out: B&) {
    let hex: const u8[16] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
    for i in 8 {
        if i > 0 { out.push(':'); }
        let hi = ip[i * 2];
        let lo = ip[i * 2 + 1];
        let val = ((hi as u16) << 8) | lo;
        if val == 0 {
            out.push('0');
        } else {
            var shift: i32 = 12;
            var started = false;
            while shift >= 0 {
                let nibble = ((val >> shift) & 0x0F) as i64;
                if nibble != 0 || started || shift == 0 {
                    out.push(hex[nibble]);
                    started = true;
                }
                shift -= 4;
            }
        }
    }
}

// Parses decimal u16 port (0..65535)
fn parse_port_decimal(str: const u8[:], out_port: u16&) -> bool {
    guard str.len > 0 && str.len <= 5 else { return false; }
    var acc: u32 = 0;
    for b in str {
        guard b >= '0' && b <= '9' else { return false; }
        acc = acc * 10 + (b - '0');
        guard acc <= 65535 else { return false; }
    }
    out_port = acc as u16;
    return true;
}

// Parses decimal IPv4 octets into u8[4]
fn parse_ipv4_decimal(str: const u8[:], out_ip: u8[4]&) -> bool {
    var octet_idx: i64 = 0;
    var current: u32 = 0;
    var digits: i64 = 0;

    for i in str.len {
        let b = str[i];
        if b == '.' {
            guard digits > 0 && current <= 255 && octet_idx < 3 else { return false; }
            out_ip[octet_idx] = current as u8;
            octet_idx++;
            current = 0;
            digits = 0;
        } else if b >= '0' && b <= '9' {
            current = current * 10 + (b - '0');
            digits++;
            guard digits <= 3 && current <= 255 else { return false; }
        } else {
            return false;
        }
    }

    guard digits > 0 && current <= 255 && octet_idx == 3 else { return false; }
    out_ip[3] = current as u8;
    return true;
}

// ---- 4. PROXY Protocol v1 Parser & Serializer (Text) ------------------------

// Parses an incoming PROXY v1 line:
// PROXY <INET_PROTOCOL> <SRC_IP> <DST_IP> <SRC_PORT> <DST_PORT>\r\n
// Returns (ProxyHeader, bytes_consumed, success)
fn parse_proxy_v1(wire: const u8[:]) -> ProxyHeader, i64, bool {
    var hdr = ProxyHeader { version: ProxyProtocolVersion.V1, .. };
    guard wire.len >= 8 else { return hdr, 0, false; }

    // Must start with "PROXY "
    for i in 6 {
        guard wire[i] == PROXY_V1_PREFIX[i] else { return hdr, 0, false; }
    }

    // Locate CRLF terminator within maximum allowed length (107 bytes)
    var crlf_idx: i64 = -1;
    let scan_limit = if wire.len < PROXY_V1_MAX_LEN { wire.len } else { PROXY_V1_MAX_LEN };
    for i in 6 .. scan_limit {
        if wire[i] == '\r' && i + 1 < wire.len && wire[i + 1] == '\n' {
            crlf_idx = i;
            break;
        }
    }
    guard crlf_idx >= 6 else { return hdr, 0, false; }
    let line = wire[6..crlf_idx];
    let consumed = crlf_idx + 2;

    // Check for "UNKNOWN" protocol
    if line.len >= 7 && line[..7] == "UNKNOWN" {
        hdr.command = ProxyCommand.Local;
        hdr.family = ProxyAddressFamily.Unspec;
        hdr.transport = ProxyTransportProtocol.Unspec;
        return hdr, consumed, true;
    }

    // Tokenize space-separated tokens: PROTO SRC_IP DST_IP SRC_PORT DST_PORT
    var tokens: Span16[..8] = [];
    var tok_start: i64 = 0;
    var in_tok = false;

    for i in line.len {
        if line[i] == ' ' {
            if in_tok {
                tokens.push(Span16 { offset: tok_start as u16, length: (i - tok_start) as u16 });
                in_tok = false;
            }
        } else {
            if !in_tok {
                tok_start = i;
                in_tok = true;
            }
        }
    }
    if in_tok {
        tokens.push(Span16 { offset: tok_start as u16, length: (line.len - tok_start) as u16 });
    }

    // Must have exactly 5 tokens for TCP4 / TCP6
    guard tokens.len == 5 else { return hdr, 0, false; }

    let proto_str = span_slice(line, tokens[0]);
    let src_ip_str = span_slice(line, tokens[1]);
    let dst_ip_str = span_slice(line, tokens[2]);
    let src_port_str = span_slice(line, tokens[3]);
    let dst_port_str = span_slice(line, tokens[4]);

    if proto_str == "TCP4" {
        hdr.family = ProxyAddressFamily.Inet4;
        hdr.transport = ProxyTransportProtocol.Stream;
        guard parse_ipv4_decimal(src_ip_str, hdr.src_ipv4) else { return hdr, 0, false; }
        guard parse_ipv4_decimal(dst_ip_str, hdr.dst_ipv4) else { return hdr, 0, false; }
    } else if proto_str == "TCP6" {
        hdr.family = ProxyAddressFamily.Inet6;
        hdr.transport = ProxyTransportProtocol.Stream;
    } else {
        return hdr, 0, false;
    }

    hdr.src_ip_str.append(src_ip_str);
    hdr.dst_ip_str.append(dst_ip_str);

    guard parse_port_decimal(src_port_str, hdr.src_port) else { return hdr, 0, false; }
    guard parse_port_decimal(dst_port_str, hdr.dst_port) else { return hdr, 0, false; }

    return hdr, consumed, true;
}

// Formats a PROXY protocol v1 text header
fn format_proxy_v1<B>(hdr: const ProxyHeader&, out: B&) -> bool {
    out.append("PROXY ");

    if hdr.command == ProxyCommand.Local || hdr.family == ProxyAddressFamily.Unspec {
        out.append("UNKNOWN\r\n");
        return true;
    }

    if hdr.family == ProxyAddressFamily.Inet4 {
        out.append("TCP4 ");
        if hdr.src_ip_str.len > 0 {
            out.append(hdr.src_ip_str[..]);
        } else {
            format_ipv4(hdr.src_ipv4, out);
        }
        out.push(' ');
        if hdr.dst_ip_str.len > 0 {
            out.append(hdr.dst_ip_str[..]);
        } else {
            format_ipv4(hdr.dst_ipv4, out);
        }
        out.push(' ');
        format(out, hdr.src_port as i64);
        out.push(' ');
        format(out, hdr.dst_port as i64);
        out.append("\r\n");
        return true;
    }

    if hdr.family == ProxyAddressFamily.Inet6 {
        out.append("TCP6 ");
        if hdr.src_ip_str.len > 0 {
            out.append(hdr.src_ip_str[..]);
        } else {
            format_ipv6(hdr.src_ipv6, out);
        }
        out.push(' ');
        if hdr.dst_ip_str.len > 0 {
            out.append(hdr.dst_ip_str[..]);
        } else {
            format_ipv6(hdr.dst_ipv6, out);
        }
        out.push(' ');
        format(out, hdr.src_port as i64);
        out.push(' ');
        format(out, hdr.dst_port as i64);
        out.append("\r\n");
        return true;
    }

    return false;
}

// ---- 5. PROXY Protocol v2 Parser & Serializer (Binary) ----------------------

// Parses an incoming PROXY v2 binary header:
// 12-byte preamble + ver_cmd(1B) + fam_trans(1B) + len(2B) + addr_block + TLVs
// Returns (ProxyHeader, bytes_consumed, success)
fn parse_proxy_v2(wire: const u8[:]) -> ProxyHeader, i64, bool {
    var hdr = ProxyHeader { version: ProxyProtocolVersion.V2, .. };
    guard wire.len >= 16 else { return hdr, 0, false; }

    // 1. Verify 12-byte constant preamble
    for i in 12 {
        guard wire[i] == PROXY_V2_PREAMBLE[i] else { return hdr, 0, false; }
    }

    // 2. Version and Command byte (index 12)
    let ver_cmd = wire[12];
    let ver = (ver_cmd >> 4) & 0x0F;
    guard ver == 0x2 else { return hdr, 0, false; } // MUST be version 2

    let cmd = ver_cmd & 0x0F;
    if cmd == PP2_CMD_LOCAL {
        hdr.command = ProxyCommand.Local;
    } else if cmd == PP2_CMD_PROXY {
        hdr.command = ProxyCommand.Proxy;
    } else {
        return hdr, 0, false; // Unknown command
    }

    // 3. Address Family and Transport Protocol byte (index 13)
    let fam_trans = wire[13];
    let fam = (fam_trans >> 4) & 0x0F;
    let trans = fam_trans & 0x0F;

    if fam == PP2_FAM_UNSPEC {
        hdr.family = ProxyAddressFamily.Unspec;
    } else if fam == PP2_FAM_INET4 {
        hdr.family = ProxyAddressFamily.Inet4;
    } else if fam == PP2_FAM_INET6 {
        hdr.family = ProxyAddressFamily.Inet6;
    } else if fam == PP2_FAM_UNIX {
        hdr.family = ProxyAddressFamily.Unix;
    } else {
        return hdr, 0, false; // Unsupported family
    }

    if trans == PP2_TRANS_UNSPEC {
        hdr.transport = ProxyTransportProtocol.Unspec;
    } else if trans == PP2_TRANS_STREAM {
        hdr.transport = ProxyTransportProtocol.Stream;
    } else if trans == PP2_TRANS_DGRAM {
        hdr.transport = ProxyTransportProtocol.Datagram;
    } else {
        return hdr, 0, false; // Unsupported transport
    }

    // 4. Payload Length (indices 14-15)
    let payload_len = read_u16_be(wire, 14) as i64;
    let total_required = 16 + payload_len;
    guard wire.len >= total_required else { return hdr, 0, false; }

    // 5. Parse Address Block based on family
    var addr_len: i64 = 0;
    if hdr.family == ProxyAddressFamily.Inet4 {
        guard payload_len >= 12 else { return hdr, 0, false; }
        for i in 4 {
            hdr.src_ipv4[i] = wire[16 + i];
            hdr.dst_ipv4[i] = wire[20 + i];
        }
        hdr.src_port = read_u16_be(wire, 24);
        hdr.dst_port = read_u16_be(wire, 26);
        format_ipv4(hdr.src_ipv4, hdr.src_ip_str);
        format_ipv4(hdr.dst_ipv4, hdr.dst_ip_str);
        addr_len = 12;
    } else if hdr.family == ProxyAddressFamily.Inet6 {
        guard payload_len >= 36 else { return hdr, 0, false; }
        for i in 16 {
            hdr.src_ipv6[i] = wire[16 + i];
            hdr.dst_ipv6[i] = wire[32 + i];
        }
        hdr.src_port = read_u16_be(wire, 48);
        hdr.dst_port = read_u16_be(wire, 50);
        format_ipv6(hdr.src_ipv6, hdr.src_ip_str);
        format_ipv6(hdr.dst_ipv6, hdr.dst_ip_str);
        addr_len = 36;
    } else if hdr.family == ProxyAddressFamily.Unix {
        guard payload_len >= 216 else { return hdr, 0, false; }
        addr_len = 216;
    } else {
        addr_len = 0;
    }

    // 6. Parse Type-Length-Value (TLV) Vectors
    var tlv_offset = 16 + addr_len;
    let tlv_limit = 16 + payload_len;

    while tlv_offset + 3 <= tlv_limit {
        let tlv_type = wire[tlv_offset];
        let tlv_len = read_u16_be(wire, tlv_offset + 1) as i64;
        let val_start = tlv_offset + 3;
        let val_end = val_start + tlv_len;
        guard val_end <= tlv_limit else { return hdr, 0, false; }

        let val = wire[val_start..val_end];

        if tlv_type == PP2_TYPE_ALPN {
            hdr.alpn.clear();
            hdr.alpn.append(val);
        } else if tlv_type == PP2_TYPE_AUTHORITY {
            hdr.authority.clear();
            hdr.authority.append(val);
        } else if tlv_type == PP2_TYPE_UNIQUE_ID {
            hdr.unique_id.clear();
            hdr.unique_id.append(val);
        } else if tlv_type == PP2_TYPE_NETNS {
            hdr.netns.clear();
            hdr.netns.append(val);
        } else if tlv_type == PP2_TYPE_SSL {
            guard val.len >= 5 else { return hdr, 0, false; }
            hdr.ssl.has_ssl = true;
            hdr.ssl.client_flags = val[0];
            hdr.ssl.verify_result = read_u32_be(val, 1);

            // Parse SSL Sub-TLVs
            var sub_offset: i64 = 5;
            while sub_offset + 3 <= val.len {
                let sub_type = val[sub_offset];
                let sub_len = read_u16_be(val, sub_offset + 1) as i64;
                let sub_start = sub_offset + 3;
                let sub_end = sub_start + sub_len;
                guard sub_end <= val.len else { break; }

                let sub_val = val[sub_start..sub_end];
                if sub_type == PP2_SUBTYPE_SSL_VERSION {
                    hdr.ssl.version.clear();
                    hdr.ssl.version.append(sub_val);
                } else if sub_type == PP2_SUBTYPE_SSL_CN {
                    hdr.ssl.client_cn.clear();
                    hdr.ssl.client_cn.append(sub_val);
                } else if sub_type == PP2_SUBTYPE_SSL_CIPHER {
                    hdr.ssl.cipher.clear();
                    hdr.ssl.cipher.append(sub_val);
                } else if sub_type == PP2_SUBTYPE_SSL_SIG_ALG {
                    hdr.ssl.sig_alg.clear();
                    hdr.ssl.sig_alg.append(sub_val);
                } else if sub_type == PP2_SUBTYPE_SSL_KEY_ALG {
                    hdr.ssl.key_alg.clear();
                    hdr.ssl.key_alg.append(sub_val);
                }
                sub_offset = sub_end;
            }
        }

        tlv_offset = val_end;
    }

    return hdr, total_required, true;
}

// Formats a PROXY protocol v2 binary header
fn format_proxy_v2<B>(hdr: const ProxyHeader&, out: B&) -> bool {
    // 1. Preamble (12 bytes)
    for b in PROXY_V2_PREAMBLE { out.push(b); }

    // 2. Version (0x2) and Command
    let cmd_nibble: u8 = if hdr.command == ProxyCommand.Local { PP2_CMD_LOCAL } else { PP2_CMD_PROXY };
    out.push(0x20 | cmd_nibble);

    // 3. Address Family and Transport Protocol
    var fam_nibble: u8 = PP2_FAM_UNSPEC;
    if hdr.family == ProxyAddressFamily.Inet4 {
        fam_nibble = PP2_FAM_INET4;
    } else if hdr.family == ProxyAddressFamily.Inet6 {
        fam_nibble = PP2_FAM_INET6;
    } else if hdr.family == ProxyAddressFamily.Unix {
        fam_nibble = PP2_FAM_UNIX;
    }

    var trans_nibble: u8 = PP2_TRANS_UNSPEC;
    if hdr.transport == ProxyTransportProtocol.Stream {
        trans_nibble = PP2_TRANS_STREAM;
    } else if hdr.transport == ProxyTransportProtocol.Datagram {
        trans_nibble = PP2_TRANS_DGRAM;
    }

    out.push((fam_nibble << 4) | trans_nibble);

    // 4. Reserve 2 bytes for payload length
    let len_offset = out.len;
    out.push(0);
    out.push(0);

    let payload_start = out.len;

    // 5. Write Address Block
    if hdr.family == ProxyAddressFamily.Inet4 {
        for b in hdr.src_ipv4 { out.push(b); }
        for b in hdr.dst_ipv4 { out.push(b); }
        write_u16_be(out, hdr.src_port);
        write_u16_be(out, hdr.dst_port);
    } else if hdr.family == ProxyAddressFamily.Inet6 {
        for b in hdr.src_ipv6 { out.push(b); }
        for b in hdr.dst_ipv6 { out.push(b); }
        write_u16_be(out, hdr.src_port);
        write_u16_be(out, hdr.dst_port);
    }

    // 6. Write TLVs
    if hdr.alpn.len > 0 {
        out.push(PP2_TYPE_ALPN);
        write_u16_be(out, hdr.alpn.len as u16);
        out.append(hdr.alpn[..]);
    }

    if hdr.authority.len > 0 {
        out.push(PP2_TYPE_AUTHORITY);
        write_u16_be(out, hdr.authority.len as u16);
        out.append(hdr.authority[..]);
    }

    if hdr.unique_id.len > 0 {
        out.push(PP2_TYPE_UNIQUE_ID);
        write_u16_be(out, hdr.unique_id.len as u16);
        out.append(hdr.unique_id[..]);
    }

    if hdr.ssl.has_ssl {
        out.push(PP2_TYPE_SSL);

        // Compute SSL sub-payload length
        var sub_len = 5; // client_flags(1B) + verify_result(4B)
        if hdr.ssl.version.len > 0 { sub_len += 3 + hdr.ssl.version.len; }
        if hdr.ssl.cipher.len > 0 { sub_len += 3 + hdr.ssl.cipher.len; }
        if hdr.ssl.client_cn.len > 0 { sub_len += 3 + hdr.ssl.client_cn.len; }

        write_u16_be(out, sub_len as u16);
        out.push(hdr.ssl.client_flags);
        write_u32_be(out, hdr.ssl.verify_result);

        if hdr.ssl.version.len > 0 {
            out.push(PP2_SUBTYPE_SSL_VERSION);
            write_u16_be(out, hdr.ssl.version.len as u16);
            out.append(hdr.ssl.version[..]);
        }
        if hdr.ssl.cipher.len > 0 {
            out.push(PP2_SUBTYPE_SSL_CIPHER);
            write_u16_be(out, hdr.ssl.cipher.len as u16);
            out.append(hdr.ssl.cipher[..]);
        }
        if hdr.ssl.client_cn.len > 0 {
            out.push(PP2_SUBTYPE_SSL_CN);
            write_u16_be(out, hdr.ssl.client_cn.len as u16);
            out.append(hdr.ssl.client_cn[..]);
        }
    }

    // 7. Patch payload length
    let total_payload = (out.len - payload_start) as u16;
    out[len_offset] = ((total_payload >> 8) & 0xFF) as u8;
    out[len_offset + 1] = (total_payload & 0xFF) as u8;

    return true;
}

// ---- 6. Auto-Detection and Stream Stripping ----------------------------------

// Detects whether an incoming wire buffer starts with a PROXY protocol header
fn detect_proxy_protocol(wire: const u8[:]) -> ProxyProtocolVersion {
    if wire.len >= 12 {
        var is_v2 = true;
        for i in 12 {
            if wire[i] != PROXY_V2_PREAMBLE[i] {
                is_v2 = false;
                break;
            }
        }
        if is_v2 { return ProxyProtocolVersion.V2; }
    }

    if wire.len >= 6 && wire[..6] == PROXY_V1_PREFIX[..] {
        return ProxyProtocolVersion.V1;
    }

    return ProxyProtocolVersion.None;
}

// Parses an incoming wire stream, automatically determining if it is PROXY v1 or v2.
// Returns (ProxyHeader, bytes_consumed, success)
fn parse_proxy_header(wire: const u8[:]) -> ProxyHeader, i64, bool {
    let ver = detect_proxy_protocol(wire);
    if ver == ProxyProtocolVersion.V2 {
        return parse_proxy_v2(wire);
    } else if ver == ProxyProtocolVersion.V1 {
        return parse_proxy_v1(wire);
    }
    var none_hdr = ProxyHeader { .. };
    return none_hdr, 0, false;
}

// Transparently strips a PROXY protocol header if present, returning the rest of the stream.
// If no PROXY header is detected, returns (original_wire, false).
fn detect_and_strip_proxy_header(wire: const u8[:], out_hdr: ProxyHeader&) -> const u8[:], bool {
    let hdr, consumed, ok = parse_proxy_header(wire);
    if ok && consumed > 0 && consumed <= wire.len {
        out_hdr = hdr;
        return wire[consumed..], true;
    }
    return wire, false;
}
