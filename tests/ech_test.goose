// tests/ech_test.goose
// Verification test suite for DNS Engine, RFC 9460 HTTPS RR (Type 65), and Encrypted Client Hello (ECH).
import std;
import core from "..";
import wing from "..";

// ============================================================================
// 1. DNS Wire Format & RFC 9460 HTTPS/SVCB Resource Records (Type 65)
// ============================================================================
fn test_dns_and_https_rr(t: core::T&) {
    t.run("DNS-01: Query Encoding and Name Compression Decoding") { sub =>
        var query: u8[>..] = [];
        let ok_q = wing::build_dns_query("cloudflare.com", wing::DNS_QTYPE_HTTPS, 0x1234, query);
        sub.assert_true(ok_q, "build_dns_query succeeds");
        sub.assert_gt(query.len, 12, "query has header and question");
        sub.assert_eq(query[0], 0x12, "tx_id hi matches");
        sub.assert_eq(query[1], 0x34, "tx_id lo matches");

        // Question: 10 'cloudflare' 3 'com' 0
        // QTYPE = 65 (0x0041), QCLASS = 1 (0x0001)
        let qlen = query.len;
        sub.assert_eq(query[qlen - 4], 0x00, "qtype hi is 0x00");
        sub.assert_eq(query[qlen - 3], 65, "qtype lo is 65 (HTTPS)");
        sub.assert_eq(query[qlen - 2], 0x00, "qclass hi is 0x00");
        sub.assert_eq(query[qlen - 1], 0x01, "qclass lo is 0x01 (IN)");
    };

    t.run("DNS-02: RFC 9460 HTTPS Resource Record Parser with ALPN, Hints & ECH") { sub =>
        // Construct a synthetic DNS response containing a Type 65 HTTPS RR:
        // Header: ID=0xABCD, Flags=0x8180 (Response, RD, RA, NoError), QD=1, AN=1, NS=0, AR=0
        var resp: u8[>..] = [];
        // Header (12B)
        resp.push(0xAB); resp.push(0xCD);
        resp.push(0x81); resp.push(0x80);
        resp.push(0x00); resp.push(0x01); // QDCOUNT=1
        resp.push(0x00); resp.push(0x01); // ANCOUNT=1
        resp.push(0x00); resp.push(0x00);
        resp.push(0x00); resp.push(0x00);

        // Question section: cloudflare.com HTTPS IN
        guard wing::dns_encode_name("cloudflare.com", resp) else { return; }
        resp.push(0x00); resp.push(65); // QTYPE=HTTPS
        resp.push(0x00); resp.push(0x01); // QCLASS=IN

        // Answer section: Name ptr to question (0xC00C), Type=65, Class=1, TTL=300
        resp.push(0xC0); resp.push(0x0C); // Pointer to 12 (offset of domain name)
        resp.push(0x00); resp.push(65);   // TYPE=65
        resp.push(0x00); resp.push(0x01); // CLASS=1
        resp.push(0x00); resp.push(0x00); resp.push(0x01); resp.push(0x2C); // TTL=300

        // RDATA:
        // Priority = 1 (ServiceMode)
        // TargetName = root ("\x00")
        // SvcParams:
        //   - Key 1 (ALPN): len=6, val="\x02h2\x02h3"
        //   - Key 3 (port): len=2, val=0x01BB (443)
        //   - Key 4 (ipv4hint): len=4, val=192.0.2.1
        //   - Key 5 (ech): len=8, val=0xFE0D0004...
        var rdata: u8[>..] = [];
        rdata.push(0x00); rdata.push(0x01); // Priority = 1
        rdata.push(0x00);                   // Target = "." (root)

        // Key 1 (ALPN)
        rdata.push(0x00); rdata.push(wing::SVC_PARAM_ALPN as u8);
        rdata.push(0x00); rdata.push(0x06); // len = 6
        rdata.push(0x02); rdata.append("h2");
        rdata.push(0x02); rdata.append("h3");

        // Key 3 (port)
        rdata.push(0x00); rdata.push(wing::SVC_PARAM_PORT as u8);
        rdata.push(0x00); rdata.push(0x02);
        rdata.push(0x01); rdata.push(0xBB); // 443

        // Key 4 (ipv4hint)
        rdata.push(0x00); rdata.push(wing::SVC_PARAM_IPV4HINT as u8);
        rdata.push(0x00); rdata.push(0x04);
        rdata.push(192); rdata.push(0); rdata.push(2); rdata.push(1);

        // Key 5 (ech)
        rdata.push(0x00); rdata.push(wing::SVC_PARAM_ECH as u8);
        rdata.push(0x00); rdata.push(0x04);
        rdata.push(0xFE); rdata.push(0x0D); rdata.push(0xAA); rdata.push(0xBB);

        // Append RDLENGTH and RDATA
        let rdlen = rdata.len;
        resp.push(((rdlen >> 8) & 0xFF) as u8);
        resp.push((rdlen & 0xFF) as u8);
        resp.append(rdata[..]);

        // Parse DNS response
        var dns_parsed = wing::DnsResponse { .. };
        let ok_parse = wing::parse_dns_response(resp[..], dns_parsed);
        sub.assert_true(ok_parse, "parse_dns_response succeeds");
        sub.assert_eq(dns_parsed.tx_id, 0xABCD, "tx_id matches");
        sub.assert_true(dns_parsed.is_response, "is_response is true");
        sub.assert_eq(dns_parsed.https_records.len, 1, "found 1 HTTPS record");

        let rec = dns_parsed.https_records[0];
        sub.assert_eq(rec.priority, 1, "priority is 1");
        sub.assert_eq(rec.port, 443, "port is 443");
        sub.assert_eq(rec.alpns.len, 2, "2 ALPN protocols parsed");
        sub.assert_eq(rec.ipv4_hints.len, 1, "1 ipv4 hint parsed");
        sub.assert_eq(rec.ipv4_hints[0], 0xC0000201, "ipv4 is 192.0.2.1");
        sub.assert_true(rec.has_ech, "ECH parameter detected");
        sub.assert_eq(rec.ech_config_list.len, 4, "ECH config wire bytes extracted");
        sub.assert_eq(rec.ech_config_list[0], 0xFE, "ECH byte 0 matches");
        sub.assert_eq(rec.ech_config_list[1], 0x0D, "ECH byte 1 matches");
    };
}

// ============================================================================
// 2. Encrypted Client Hello (ECH) Wire Formats & HPKE Privacy Handshake
// ============================================================================
fn test_ech_protocol(t: core::T&) {
    t.run("ECH-01: ECHConfig & ECHConfigList Parsing") { sub =>
        // Construct a realistic synthetic ECHConfig wire buffer:
        // version: 0xFE0D (draft-13)
        // length: u16
        // KeyConfig:
        //   config_id: 42
        //   kem_id: 0x0020 (DHKEM(X25519, HKDF-SHA256))
        //   pk_len: 32 || pk (32 bytes from Bob)
        //   cs_len: 4 || kdf=0x0001, aead=0x0001 (AES-128-GCM)
        // maximum_name_length: 64
        // public_name: len=18 || "cloudflare-ech.com"
        // extensions: len=0
        let bob_sk: u8[32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
            0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
            0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
            0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
        ];
        let bob_pk = core::x25519_base_scalarmult(bob_sk);

        var contents: u8[>..] = [];
        contents.push(42);                  // config_id
        contents.push(0x00); contents.push(0x20); // kem_id = 0x0020
        // public key (length-prefixed 32 bytes)
        contents.push(0x00); contents.push(32);
        contents.append(bob_pk[..]);
        // cipher suites: len=4, kdf=1, aead=1
        contents.push(0x00); contents.push(4);
        contents.push(0x00); contents.push(0x01); // KDF HKDF-SHA256
        contents.push(0x00); contents.push(0x01); // AEAD AES-128-GCM
        // maximum_name_length = 64
        contents.push(64);
        // public_name = "cloudflare-ech.com" (18 bytes)
        let pub_name = "cloudflare-ech.com";
        contents.push(pub_name.len as u8);
        contents.append(pub_name);
        // extensions: len=0
        contents.push(0x00); contents.push(0x00);

        // Build single ECHConfig
        var raw_cfg: u8[>..] = [];
        raw_cfg.push(0xFE); raw_cfg.push(0x0D); // version 0xFE0D
        let clen = contents.len;
        raw_cfg.push(((clen >> 8) & 0xFF) as u8);
        raw_cfg.push((clen & 0xFF) as u8);
        raw_cfg.append(contents[..]);

        // Build ECHConfigList: u16 total_len || ECHConfig...
        var raw_list: u8[>..] = [];
        let list_payload_len = raw_cfg.len;
        raw_list.push(((list_payload_len >> 8) & 0xFF) as u8);
        raw_list.push((list_payload_len & 0xFF) as u8);
        raw_list.append(raw_cfg[..]);

        // Parse list
        var cfg_list = wing::EchConfigList { .. };
        let ok_list = wing::parse_ech_config_list(raw_list[..], cfg_list);
        sub.assert_true(ok_list, "parse_ech_config_list succeeds");
        sub.assert_eq(cfg_list.configs.len, 1, "1 config parsed from list");

        var selected_cfg = wing::EchConfig { .. };
        var selected_cs = wing::EchCipherSuite { .. };
        let ok_sel = wing::select_ech_config(cfg_list, selected_cfg, selected_cs);
        sub.assert_true(ok_sel, "select_ech_config succeeds");
        sub.assert_eq(selected_cfg.config_id, 42, "config_id is 42");
        sub.assert_eq(selected_cfg.maximum_name_length, 64, "max_name_len is 64");
        sub.assert_eq(selected_cs.kdf_id, wing::HPKE_KDF_HKDF_SHA256, "kdf is SHA256");
        sub.assert_eq(selected_cs.aead_id, wing::HPKE_AEAD_AES_128_GCM, "aead is AES-128-GCM");

        // Verify public key extracted matches Bob's PK
        for i in 32 {
            sub.assert_eq(selected_cfg.public_key[i], bob_pk[i], "public key matches");
        }
    };

    t.run("ECH-02: Padding, Outer AAD Binding & End-to-End Privacy Handshake") { sub =>
        let server_sk: u8[32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
            0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
            0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
            0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
        ];
        let server_pk = core::x25519_base_scalarmult(server_sk);

        var config = wing::EchConfig { .. };
        config.version = wing::ECH_VERSION_DRAFT13;
        config.config_id = 7;
        config.kem_id = wing::HPKE_KEM_DHKEM_X25519_HKDF_SHA256;
        config.maximum_name_length = 64;
        for i in 32 { config.public_key[i] = server_pk[i]; }
        config.raw_bytes.append("synthetic-ech-config-raw-bytes");

        let cs = wing::EchCipherSuite {
            kdf_id: wing::HPKE_KDF_HKDF_SHA256,
            aead_id: wing::HPKE_AEAD_AES_128_GCM,
        };

        // Real hidden SNI: "secret.crypto.internal"
        let real_sni = "secret.crypto.internal";
        var inner_hello: u8[>..] = [];
        inner_hello.append("ClientHelloInner:sni=");
        inner_hello.append(real_sni);
        inner_hello.append(";alpn=h2;keyshare=x25519");

        // Pad inner hello to hide length
        var inner_padded: u8[>..] = [];
        let ok_pad = wing::pad_ech_inner(inner_hello[..], config.maximum_name_length, real_sni.len, inner_padded);
        sub.assert_true(ok_pad, "pad_ech_inner succeeds");
        sub.assert_gt(inner_padded.len, inner_hello.len, "padding added");
        sub.assert_eq(inner_padded.len % 32, 0, "padded length aligned to 32 bytes");

        // Outer AAD binds the ClientHelloOuter
        let outer_aad = "ClientHelloOuter:sni=cloudflare-ech.com;ech_outer_placeholder";

        let client_ephemeral_sk: u8[32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];

        var enc: u8[32] = [0; 32];
        var ciphertext: u8[>..] = [];
        let ok_seal = wing::seal_ech_inner(
            config,
            cs,
            outer_aad,
            inner_padded[..],
            client_ephemeral_sk,
            enc,
            ciphertext
        );
        sub.assert_true(ok_seal, "seal_ech_inner succeeds");
        sub.assert_eq(ciphertext.len, inner_padded.len + 16, "ciphertext len = padded len + 16B tag");

        // Format outer ECH extension
        var outer_ext_bytes: u8[>..] = [];
        let ok_ext = wing::build_ech_outer_extension(config.config_id, cs, enc, ciphertext[..], outer_ext_bytes);
        sub.assert_true(ok_ext, "build_ech_outer_extension succeeds");
        sub.assert_eq(outer_ext_bytes[0], wing::ECH_CLIENT_OUTER, "outer flag is 0x00");
        sub.assert_eq(outer_ext_bytes[5], 7, "config_id is 7");

        // Format inner ECH extension (must be 1 byte: 0x01)
        var inner_ext_bytes: u8[>..] = [];
        wing::build_ech_inner_extension(inner_ext_bytes);
        sub.assert_eq(inner_ext_bytes.len, 1, "inner extension is 1 byte");
        sub.assert_eq(inner_ext_bytes[0], wing::ECH_CLIENT_INNER, "inner flag is 0x01");

        // Server decrypts ciphertext using server_sk:
        var info: u8[..600] = [];
        info.append("tls ech");
        info.push(0x00);
        for i in config.raw_bytes.len { info.push(config.raw_bytes[i]); }

        var decrypted: u8[>..] = [];
        let ok_open = wing::hpke_open_base(
            enc,
            server_sk,
            info[..],
            outer_aad,
            ciphertext[..],
            cs.aead_id,
            decrypted
        );
        sub.assert_true(ok_open, "server decrypts ECH ciphertext successfully");
        sub.assert_eq(decrypted.len, inner_padded.len, "decrypted length matches padded inner");

        // Verify inner plaintext contains original secret SNI
        var decrypted_sni_matches = true;
        for i in inner_hello.len {
            if decrypted[i] != inner_hello[i] {
                decrypted_sni_matches = false;
                break;
            }
        }
        sub.assert_true(decrypted_sni_matches, "recovered inner ClientHello matches authentic payload");
    };
}

// ============================================================================
// 3. DNS-over-HTTPS (RFC 8484) & Automated ECH Discovery (RFC 9460)
// ============================================================================
fn test_doh_and_automated_ech_discovery(t: core::T&) {
    t.run("DoH-01: Wire Format Query Construction & URL Formatter") { sub =>
        // POST body
        var post_body: u8[>..] = [];
        let ok_post = wing::build_doh_post_body("cloudflare.com", wing::DNS_QTYPE_HTTPS, 0x1122, post_body);
        sub.assert_true(ok_post, "build_doh_post_body succeeds");
        sub.assert_gt(post_body.len, 12, "DoH post body contains DNS header + question");

        // GET URL
        var get_url: u8[..512] = [];
        let ok_get = wing::build_doh_get_url("https://cloudflare-dns.com/dns-query", "cloudflare.com", wing::DNS_QTYPE_HTTPS, get_url);
        sub.assert_true(ok_get, "build_doh_get_url succeeds");
        let prefix = "https://cloudflare-dns.com/dns-query?dns=";
        sub.assert_true(get_url.len >= prefix.len, "GET URL length sufficient");
        sub.assert_bytes_eq(get_url[..prefix.len], prefix, "GET URL starts with query param");
    };

    t.run("DoH-02: Automated ECH Discovery and DNS Cache Integration") { sub =>
        var client = wing::new_client();
        wing::enable_doh(client, "https://mock-dns.local/dns-query", true);
        wing::enable_ech(client, true);

        sub.assert_true(client.enable_doh, "DoH enabled");
        sub.assert_true(client.enable_ech, "ECH enabled");
        sub.assert_true(client.auto_ech_discovery, "Auto ECH discovery enabled");

        // Construct synthetic DNS response containing Type 65 HTTPS RR with Key 5 (ECH)
        var dns_resp_wire: u8[>..] = [];
        dns_resp_wire.push(0x12); dns_resp_wire.push(0x34); // ID 0x1234
        dns_resp_wire.push(0x81); dns_resp_wire.push(0x80); // Flags: standard response
        dns_resp_wire.push(0x00); dns_resp_wire.push(0x01); // QDCOUNT=1
        dns_resp_wire.push(0x00); dns_resp_wire.push(0x01); // ANCOUNT=1
        dns_resp_wire.push(0x00); dns_resp_wire.push(0x00);
        dns_resp_wire.push(0x00); dns_resp_wire.push(0x00);

        // Question: crypto.example.com HTTPS IN
        guard wing::dns_encode_name("crypto.example.com", dns_resp_wire) else { return; }
        dns_resp_wire.push(0x00); dns_resp_wire.push(65); // QTYPE=HTTPS
        dns_resp_wire.push(0x00); dns_resp_wire.push(0x01); // QCLASS=IN

        // Answer
        dns_resp_wire.push(0xC0); dns_resp_wire.push(0x0C); // Ptr to question name
        dns_resp_wire.push(0x00); dns_resp_wire.push(65);   // Type 65
        dns_resp_wire.push(0x00); dns_resp_wire.push(0x01); // Class IN
        dns_resp_wire.push(0x00); dns_resp_wire.push(0x00); dns_resp_wire.push(0x01); dns_resp_wire.push(0x2C); // TTL 300

        // RDATA
        var rdata: u8[>..] = [];
        rdata.push(0x00); rdata.push(0x01); // Priority 1
        rdata.push(0x00);                   // Target "."
        // Key 5 (ECH)
        rdata.push(0x00); rdata.push(wing::SVC_PARAM_ECH as u8);
        rdata.push(0x00); rdata.push(0x08); // 8 bytes
        rdata.push(0xFE); rdata.push(0x0D);
        rdata.push(0x00); rdata.push(0x04);
        rdata.push(0xCA); rdata.push(0xFE); rdata.push(0xBA); rdata.push(0xBE);

        let rdlen = rdata.len;
        dns_resp_wire.push(((rdlen >> 8) & 0xFF) as u8);
        dns_resp_wire.push((rdlen & 0xFF) as u8);
        dns_resp_wire.append(rdata[..]);

        // Register mock DoH endpoint
        var mock = wing::MockExchange {
            pattern_url: "https://mock-dns.local/dns-query",
            method: "POST",
            status_code: 200,
            ..
        };
        mock.headers.push(wing::make_header("content-type", "application/dns-message"));
        mock.body.append(dns_resp_wire[..]);
        client.mock_routes.push(mock);

        // 1st call: Performs DoH query and populates cache
        var discovered_ech: u8[..512] = [];
        let now = 1700000000;
        let ok_disc = wing::resolve_ech_config(client, "crypto.example.com", now, discovered_ech);

        sub.assert_true(ok_disc, "ECH config discovered via DoH");
        sub.assert_eq(discovered_ech.len, 8, "Extracted 8 bytes ECHConfigList");
        sub.assert_eq(discovered_ech[0], 0xFE, "ECH header byte 0 is 0xFE");
        sub.assert_eq(discovered_ech[1], 0x0D, "ECH header byte 1 is 0x0D");
        sub.assert_eq(discovered_ech[4], 0xCA, "ECH payload matches 0xCA");
        sub.assert_eq(discovered_ech[5], 0xFE, "ECH payload matches 0xFE");

        // 2nd call: Resolves from DnsCache directly without DoH request
        client.mock_routes.clear(); // Clear mock routes so any network hop would fail
        var cached_ech: u8[..512] = [];
        let ok_cache = wing::resolve_ech_config(client, "crypto.example.com", now + 60, cached_ech);

        sub.assert_true(ok_cache, "ECH resolved from DNS cache without network hop");
        sub.assert_bytes_eq(cached_ech[..], discovered_ech[..], "Cached ECH matches discovered ECH");
    };
}

// ============================================================================
// Main ECH & DNS Verification Runner
// ============================================================================
fn main() {
    var runner = core::new_runner("DNS Engine (RFC 1035), HTTPS RR (RFC 9460) & ECH Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. DNS Wire Format & RFC 9460 HTTPS Resource Records", test_dns_and_https_rr);
    core::run_case(runner, "2. Encrypted Client Hello (ECH) Wire & HPKE Handshake", test_ech_protocol);
    core::run_case(runner, "3. DNS-over-HTTPS (DoH RFC 8484) & Automated ECH Discovery", test_doh_and_automated_ech_discovery);
    let ok = core::finish(runner);
    assert(ok);
}
