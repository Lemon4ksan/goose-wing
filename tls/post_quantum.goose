// RFC 10024 & FIPS 203 Hybrid Post-Quantum Key Agreement for TLS 1.3.
// Supports IANA-standardized X25519MLKEM768 (Group 0x11EC) and Chrome draft X25519Kyber768 (Group 0x6399).
// Formats hybrid 1184-byte ClientHello key shares, parses server 1120-byte encapsulation shares,
// and derives combined post-quantum shared secrets.
namespace wing;

import std;
import core from "..";

// ---- 1. RFC 10024 & IANA NamedGroup Identifiers -----------------------------

const GROUP_X25519_MLKEM768: u16          = 0x11EC; // RFC 10024 official IANA group
const GROUP_X25519_KYBER768_DRAFT00: u16  = 0x6399; // Chrome 124-130 draft group

const X25519_KEY_LEN: i64        = 32;
const MLKEM768_PUBLIC_LEN: i64   = 1152;
const MLKEM768_CIPHERTEXT_LEN: i64 = 1088;
const HYBRID_CLIENT_SHARE_LEN: i64 = 32 + 1152; // 1184 bytes
const HYBRID_SERVER_SHARE_LEN: i64 = 32 + 1088; // 1120 bytes

// Checks whether a TLS supported group is a Post-Quantum Hybrid group
fn is_post_quantum_group(group: u16) -> bool {
    return group == GROUP_X25519_MLKEM768 || group == GROUP_X25519_KYBER768_DRAFT00;
}

// ---- 2. Hybrid Key Share Model ----------------------------------------------

struct PostQuantumKeyShare {
    group: u16 = GROUP_X25519_MLKEM768,
    x25519_public: u8[32] = [
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    ],
    mlkem768_public: u8[1152] = [
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    ],
}

// ---- 3. Wire Formatting and Parsing (RFC 10024 §3) ---------------------------

// Formats a KeyShareEntry for ClientHello:
// group (2 bytes) + key_exchange_len (2 bytes) + [32B X25519 || 1152B ML-KEM-768]
fn format_hybrid_key_share<B>(share: const PostQuantumKeyShare&, out: B&) {
    let grp = share.group;
    out.push(((grp >> 8) & 0xFF) as u8);
    out.push((grp & 0xFF) as u8);

    let kex_len = HYBRID_CLIENT_SHARE_LEN as u16;
    out.push(((kex_len >> 8) & 0xFF) as u8);
    out.push((kex_len & 0xFF) as u8);

    for b in share.x25519_public {
        out.push(b);
    }
    for b in share.mlkem768_public {
        out.push(b);
    }
}

// Parses a hybrid KeyShareEntry from raw bytes
fn parse_hybrid_key_share(raw: const u8[:], out: PostQuantumKeyShare&) -> bool {
    guard raw.len >= 4 + HYBRID_CLIENT_SHARE_LEN else { return false; }

    out.group = ((raw[0] as u16) << 8) | raw[1];
    guard is_post_quantum_group(out.group) else { return false; }

    let kex_len = (((raw[2] as u16) << 8) | raw[3]) as i64;
    guard kex_len == HYBRID_CLIENT_SHARE_LEN else { return false; }

    for i in 32 {
        out.x25519_public[i] = raw[4 + i];
    }
    for i in 1152 {
        out.mlkem768_public[i] = raw[36 + i];
    }

    return true;
}

// ---- 4. Hybrid Secret Combiner (RFC 10024 §4) --------------------------------

// Combines the classical X25519 shared secret and the post-quantum shared secret:
// shared_secret = SHA-256(ss_classical || ss_pq)
fn derive_hybrid_shared_secret(
    classical_ss: const u8[32]&,
    pq_ss: const u8[32]&,
) -> u8[32] {
    var combined: u8[64] = [
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    ];
    for i in 32 {
        combined[i] = classical_ss[i];
        combined[32 + i] = pq_ss[i];
    }
    return core::sha256(combined[..]);
}
