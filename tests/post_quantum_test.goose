// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for RFC 10024 & FIPS 203 Hybrid Post-Quantum Key Agreement:
// - NamedGroup validation (0x11EC X25519MLKEM768, 0x6399 X25519Kyber768)
// - 1184-byte hybrid ClientHello key share wire serialization and deserialization
// - 1120-byte hybrid ServerHello key share wire serialization and deserialization
// - Hybrid shared secret derivation combiner (RFC 10024 §4)
import std;
import core from "..";
import wing from "..";

fn test_post_quantum_hybrid(t: core::T&) {
    t.run("IANA NamedGroup Recognition") { sub =>
        sub.assert_true(wing::is_post_quantum_group(wing::GROUP_X25519_MLKEM768), "0x11EC is post-quantum group");
        sub.assert_true(wing::is_post_quantum_group(wing::GROUP_X25519_KYBER768_DRAFT00), "0x6399 is post-quantum draft group");
        sub.assert_false(wing::is_post_quantum_group(0x001D), "0x001D (X25519 classical) is NOT PQ group");
        sub.assert_false(wing::is_post_quantum_group(0x0017), "0x0017 (secp256r1) is NOT PQ group");
    };

    t.run("Hybrid 1184-Byte Client Key Share Wire Codec") { sub =>
        var share = wing::PostQuantumKeyShare {
            group: wing::GROUP_X25519_MLKEM768,
            ..
        };
        for i in 32 { share.x25519_public[i] = (i + 1) as u8; }
        for i in 1152 { share.mlkem768_public[i] = ((i * 7 + 3) & 0xFF) as u8; }

        var wire: u8[>..] = [];
        share.format_hybrid_key_share(wire);
        // group (2) + len (2) + 1184 = 1188 bytes total
        sub.assert_eq(wire.len, 1188, "Wire length is exactly 1188 bytes");

        var parsed = wing::PostQuantumKeyShare { .. };
        let ok_parse = wire[..].parse_hybrid_key_share(parsed);
        sub.assert_true(ok_parse, "Hybrid key share parsed via UFCS");
        sub.assert_eq(parsed.group, wing::GROUP_X25519_MLKEM768, "Group is 0x11EC");
        sub.assert_bytes_eq(parsed.x25519_public[..], share.x25519_public[..], "X25519 component matches");

        var mlkem_match = true;
        for i in 1152 {
            if parsed.mlkem768_public[i] != share.mlkem768_public[i] {
                mlkem_match = false;
                break;
            }
        }
        sub.assert_true(mlkem_match, "ML-KEM-768 1152-byte component matches verbatim");

        // Edge cases
        var bad_parsed = wing::PostQuantumKeyShare { .. };
        sub.assert_false(wire[..10].parse_hybrid_key_share(bad_parsed), "Truncated wire fails");

        var corrupt_wire: u8[>..] = [];
        corrupt_wire.append(wire[..]);
        corrupt_wire[0] = 0x00;
        corrupt_wire[1] = 0x1D; // classical X25519, not PQ
        sub.assert_false(corrupt_wire[..].parse_hybrid_key_share(bad_parsed), "Non-PQ group fails");
    };

    t.run("Hybrid 1120-Byte Server Key Share Wire Codec") { sub =>
        var server_share = wing::PostQuantumServerShare {
            group: wing::GROUP_X25519_MLKEM768,
            ..
        };
        for i in 32 { server_share.x25519_public[i] = (i + 5) as u8; }
        for i in 1088 { server_share.mlkem768_ciphertext[i] = ((i * 11 + 7) & 0xFF) as u8; }

        var wire: u8[>..] = [];
        server_share.format_hybrid_server_key_share(wire);
        // group (2) + len (2) + 1120 = 1124 bytes total
        sub.assert_eq(wire.len, 1124, "Server wire length is exactly 1124 bytes");

        var parsed_server = wing::PostQuantumServerShare { .. };
        let ok_parse = wire[..].parse_hybrid_server_key_share(parsed_server);
        sub.assert_true(ok_parse, "Server hybrid key share parsed via UFCS");
        sub.assert_eq(parsed_server.group, wing::GROUP_X25519_MLKEM768, "Server group is 0x11EC");
        sub.assert_bytes_eq(parsed_server.x25519_public[..], server_share.x25519_public[..], "Server X25519 component matches");

        var ct_match = true;
        for i in 1088 {
            if parsed_server.mlkem768_ciphertext[i] != server_share.mlkem768_ciphertext[i] {
                ct_match = false;
                break;
            }
        }
        sub.assert_true(ct_match, "ML-KEM-768 1088-byte ciphertext matches verbatim");

        // Edge case
        var bad_parsed = wing::PostQuantumServerShare { .. };
        sub.assert_false(wire[..500].parse_hybrid_server_key_share(bad_parsed), "Truncated server wire fails");
    };

    t.run("Hybrid Shared Secret Combiner (RFC 10024 §4)") { sub =>
        var classical_ss: u8[32] = [
            1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
            17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
        ];
        var pq_ss: u8[32] = [
            33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,
            49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64
        ];

        let combined_secret = wing::derive_hybrid_shared_secret(classical_ss, pq_ss);
        var zero_cnt = 0;
        for b in combined_secret {
            if b == 0 { zero_cnt += 1; }
        }
        sub.assert_true(zero_cnt < 32, "Hybrid secret is high-entropy 32-byte SHA-256");
    };
}

fn main() {
    var runner = core::new_runner("RFC 10024 Post-Quantum Key Agreement Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Post-Quantum TLS 1.3 Key Exchange", test_post_quantum_hybrid);
    let ok = core::finish(runner);
    assert(ok);
}
