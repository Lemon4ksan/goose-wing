// Constant-time primitives, key zeroization, SHA-256/HMAC/HKDF, and cryptographic codecs.
namespace wing;

import std;

// ---- constant-time branchless primitives -----------------------------------

// Returns 1 if a == b, 0 otherwise, using purely branchless bitwise arithmetic.
inline fn ct_eq_u8(a: u8, b: u8) -> u8 {
    let diff = (a ^ b) as u32;
    let non_zero = (diff | (0 - diff)) >> 31;
    return (1 - non_zero) as u8;
}


// Branchless conditional selection: returns if_true when bit == 1, if_false when bit == 0.
inline fn ct_select_u8(bit: u8, if_true: u8, if_false: u8) -> u8 {
    let mask = 0 - (bit & 1);
    return (if_false & (~mask)) | (if_true & mask);
}

// Constant-time slice equality check: only branches on public length before reading secret bytes.
fn ct_eq_bytes(bytes_a: const u8[:], bytes_b: const u8[:]) -> bool {
    guard bytes_a.len == bytes_b.len else { return false; }
    var diff_accum: u64 = 0;
    var idx = 0;
    while idx + 8 <= bytes_a.len {
        diff_accum |= core::read_le_u64(bytes_a, idx) ^ core::read_le_u64(bytes_b, idx);
        idx += 8;
    }
    var tail_accum: u8 = 0;
    while idx < bytes_a.len {
        tail_accum |= bytes_a[idx] ^ bytes_b[idx];
        idx += 1;
    }
    let total_diff = diff_accum | tail_accum;
    let non_zero = (total_diff | (0 - total_diff)) >> 63;
    return non_zero == 0;
}

// Constant-time 16-byte authentication tag comparison (Poly1305 / AES-GCM).
fn ct_eq_tag16(tag_a: const u8[16]&, tag_b: const u8[16]&) -> bool {
    let diff0 = core::read_le_u64(tag_a[..], 0) ^ core::read_le_u64(tag_b[..], 0);
    let diff1 = core::read_le_u64(tag_a[..], 8) ^ core::read_le_u64(tag_b[..], 8);
    let diff = diff0 | diff1;
    let non_zero = (diff | (0 - diff)) >> 63;
    return non_zero == 0;
}

// Constant-time 32-byte MAC comparison (HMAC-SHA256).
fn ct_eq_tag32(tag_a: const u8[32]&, tag_b: const u8[32]&) -> bool {
    let diff0 = core::read_le_u64(tag_a[..], 0) ^ core::read_le_u64(tag_b[..], 0);
    let diff1 = core::read_le_u64(tag_a[..], 8) ^ core::read_le_u64(tag_b[..], 8);
    let diff2 = core::read_le_u64(tag_a[..], 16) ^ core::read_le_u64(tag_b[..], 16);
    let diff3 = core::read_le_u64(tag_a[..], 24) ^ core::read_le_u64(tag_b[..], 24);
    let diff = diff0 | diff1 | diff2 | diff3;
    let non_zero = (diff | (0 - diff)) >> 63;
    return non_zero == 0;
}

// Constant-time 48-byte MAC comparison (HMAC-SHA384).
fn ct_eq_tag48(tag_a: const u8[48]&, tag_b: const u8[48]&) -> bool {
    var diff: u64 = 0;
    for i in 6 {
        let off = i * 8;
        diff |= core::read_le_u64(tag_a[..], off) ^ core::read_le_u64(tag_b[..], off);
    }
    let non_zero = (diff | (0 - diff)) >> 63;
    return non_zero == 0;
}

fn ct_copy_bytes(dst: u8[:], src: const u8[:]) {
    let len = if dst.len < src.len { dst.len } else { src.len };
    for i in len { dst[i] = src[i]; }
}

// ---- secret memory zeroization & KeySlot (secrecy pattern) -----------------

fn secure_zeroize_16(buf: u8[16]&) {
    for idx in 16 { buf[idx] = 0; }
}

fn secure_zeroize_24(buf: u8[24]&) {
    for idx in 24 { buf[idx] = 0; }
}

fn secure_zeroize_32(buf: u8[32]&) {
    for idx in 32 { buf[idx] = 0; }
}

fn secure_zeroize_48(buf: u8[48]&) {
    for idx in 48 { buf[idx] = 0; }
}

fn secure_zeroize_64(buf: u8[64]&) {
    for idx in 64 { buf[idx] = 0; }
}

fn secure_zeroize_vec(buf: u8[>..]&) {
    for idx in buf.len {
        buf[idx] = 0;
    }
    buf.clear();
}

// KeySlot encapsulates a 256-bit cryptographic master key with rotation metadata.
struct KeySlot {
    key_id: u32 = 0,
    master_key: u8[32] = [0; 32],
    created_at_sec: i64 = 0,
    expires_at_sec: i64 = 0,
    revoked: bool = false,
}

fn new_key_slot(key_id: u32, raw_key: const u8[:], created_at_sec: i64 = 0, expires_at_sec: i64 = 0) -> KeySlot {
    var slot = KeySlot {
        key_id: key_id,
        master_key: [0; 32],
        created_at_sec: created_at_sec,
        expires_at_sec: expires_at_sec,
        revoked: false,
    };
    let copy_len = if raw_key.len < 32 { raw_key.len } else { 32 };
    for idx in copy_len {
        slot.master_key[idx] = raw_key[idx];
    }
    return slot;
}

fn zeroize_key_slot(slot: KeySlot&) {
    secure_zeroize_32(slot.master_key);
    slot.revoked = true;
}

// Redacted format hook preventing accidental leakage of secret key bytes into logs.
fn format<B>(out: B&, slot: const KeySlot&) {
    out.append("KeySlot { key_id: ");
    format(out, slot.key_id);
    out.append(", master_key: [REDACTED], revoked: ");
    format(out, slot.revoked);
    out.append(" }");
}

fn display_redacted<B>(slot: const KeySlot&, out: B&) {
    format(out, slot);
}

// ---- dudect statistical constant-time verifier (Welch's t-test) ------------

// Online Welford accumulator for two timing classes with OS preemption outlier cropping.
struct DudectContext {
    crop_threshold_ns: f64 = 2000.0,
    n0: i64 = 0,
    n1: i64 = 0,
    mean0: f64 = 0.0,
    mean1: f64 = 0.0,
    m2_0: f64 = 0.0,
    m2_1: f64 = 0.0,
    cropped_outliers: i64 = 0,
}

fn new_dudect_context(crop_threshold_ns: f64 = 2000.0) -> DudectContext {
    return DudectContext { crop_threshold_ns: crop_threshold_ns, .. };
}

// Records a timing sample (in nanoseconds) for class 0 or class 1.
// Samples exceeding crop_threshold_ns are discarded (cropped), never clamped,
// preserving unbiased sample means per hardware-rust-crypto methodology.
fn dudect_push_sample(ctx: DudectContext&, class_idx: i32, elapsed_ns: f64) -> bool {
    if elapsed_ns < 0.0 || (ctx.crop_threshold_ns > 0.0 && elapsed_ns > ctx.crop_threshold_ns) {
        ctx.cropped_outliers += 1;
        return false;
    }
    if class_idx == 0 {
        ctx.n0 += 1;
        let delta = elapsed_ns - ctx.mean0;
        ctx.mean0 += delta / ctx.n0;
        let delta2 = elapsed_ns - ctx.mean0;
        ctx.m2_0 += delta * delta2;
    } else {
        ctx.n1 += 1;
        let delta = elapsed_ns - ctx.mean1;
        ctx.mean1 += delta / ctx.n1;
        let delta2 = elapsed_ns - ctx.mean1;
        ctx.m2_1 += delta * delta2;
    }
    return true;
}

// Approximate Newton-Raphson square root for Welch's t-statistic denominator.
fn approx_sqrt(val: f64) -> f64 {
    if val <= 0.0 { return 0.0; }
    var x = val;
    for iter in 20 {
        x = 0.5 * (x + val / x);
    }
    return x;
}

// Computes absolute Welch's |t| statistic between Class 0 and Class 1.
fn dudect_abs_t(ctx: const DudectContext&) -> f64 {
    if ctx.n0 < 2 || ctx.n1 < 2 { return 0.0; }
    let var0 = ctx.m2_0 / (ctx.n0 - 1);
    let var1 = ctx.m2_1 / (ctx.n1 - 1);
    let denom_sq = (var0 / ctx.n0) + (var1 / ctx.n1);
    if denom_sq <= 0.000000000001 { return 0.0; }
    let diff = ctx.mean0 - ctx.mean1;
    let abs_diff = if diff < 0.0 { -diff } else { diff };
    return abs_diff / approx_sqrt(denom_sq);
}

// Verifies that |t| is strictly below threshold (default 4.5 for 99.999% confidence, or 1.5 for lockstep).
fn dudect_is_constant_time(ctx: const DudectContext&, max_t: f64 = 4.5) -> bool {
    return dudect_abs_t(ctx) <= max_t;
}

// ---- sha-256 (fips 180-4 / rfc 6234) ---------------------------------------

let SHA256_K: const u32[64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];


struct Sha256Ctx {
    h: u32[8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
    buf: u8[64] = [0; 64],
    buf_len: i64 = 0,
    total_len: u64 = 0,
}

fn sha256_init() -> Sha256Ctx {
    return Sha256Ctx { .. };
}

fn sha256_transform(ctx: Sha256Ctx&, chunk: const u8[:]) {
    var w: u32[64] = [0; 64];
    for i in 16 {
        let off = i * 4;
        w[i] = ((chunk[off] as u32) << 24) |
               ((chunk[off + 1] as u32) << 16) |
               ((chunk[off + 2] as u32) << 8) |
               chunk[off + 3];
    }
    for i in 16..64 {
        let s0 = core::rotr32(w[i - 15], 7) ^ core::rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        let s1 = core::rotr32(w[i - 2], 17) ^ core::rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    var a = ctx.h[0];
    var b = ctx.h[1];
    var c = ctx.h[2];
    var d = ctx.h[3];
    var e = ctx.h[4];
    var f = ctx.h[5];
    var g = ctx.h[6];
    var h = ctx.h[7];

    for i in 64 {
        let s1 = core::rotr32(e, 6) ^ core::rotr32(e, 11) ^ core::rotr32(e, 25);
        let ch = (e & f) ^ ((~e) & g);
        let temp1 = h + s1 + ch + SHA256_K[i] + w[i];
        let s0 = core::rotr32(a, 2) ^ core::rotr32(a, 13) ^ core::rotr32(a, 22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx.h[0] += a;
    ctx.h[1] += b;
    ctx.h[2] += c;
    ctx.h[3] += d;
    ctx.h[4] += e;
    ctx.h[5] += f;
    ctx.h[6] += g;
    ctx.h[7] += h;
}

fn sha256_update(ctx: Sha256Ctx&, data: const u8[:]) {
    guard data.len > 0 else { return; }
    ctx.total_len += (data.len as u64) * 8;
    var offset = 0;
    while offset < data.len {
        let needed = 64 - ctx.buf_len;
        let available = data.len - offset;
        let to_copy = if available < needed { available } else { needed };
        for i in to_copy {
            ctx.buf[ctx.buf_len + i] = data[offset + i];
        }
        ctx.buf_len += to_copy;
        offset += to_copy;

        if ctx.buf_len == 64 {
            sha256_transform(ctx, ctx.buf[..]);
            ctx.buf_len = 0;
        }
    }
}

fn sha256_final(ctx: Sha256Ctx&) -> u8[32] {
    ctx.buf[ctx.buf_len] = 0x80;
    ctx.buf_len += 1;

    if ctx.buf_len > 56 {
        for i in (64 - ctx.buf_len) {
            ctx.buf[ctx.buf_len + i] = 0;
        }
        sha256_transform(ctx, ctx.buf[..]);
        ctx.buf_len = 0;
    }

    for i in (56 - ctx.buf_len) {
        ctx.buf[ctx.buf_len + i] = 0;
    }

    for i in 8 {
        ctx.buf[56 + i] = ((ctx.total_len >> ((7 - i) * 8)) & 0xFF) as u8;
    }
    sha256_transform(ctx, ctx.buf[..]);

    var out: u8[32] = [0; 32];
    for i in 8 {
        out[i * 4] = (ctx.h[i] >> 24) as u8;
        out[i * 4 + 1] = (ctx.h[i] >> 16) as u8;
        out[i * 4 + 2] = (ctx.h[i] >> 8) as u8;
        out[i * 4 + 3] = ctx.h[i] as u8;
    }
    return out;
}

fn sha256(data: const u8[:]) -> u8[32] {
    var ctx = sha256_init();
    sha256_update(ctx, data);
    return sha256_final(ctx);
}

// ---- hmac-sha256 (rfc 2104 / rfc 4231) -------------------------------------

fn hmac_sha256(key: const u8[:], message: const u8[:]) -> u8[32] {
    var key_block: u8[64] = [0; 64];
    if key.len > 64 {
        let hashed_key = sha256(key);
        for i in 32 { key_block[i] = hashed_key[i]; }
    } else {
        for i in key.len { key_block[i] = key[i]; }
    }

    var ipad: u8[64] = [0; 64];
    var opad: u8[64] = [0; 64];
    for i in 64 {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    var inner_ctx = sha256_init();
    sha256_update(inner_ctx, ipad[..]);
    sha256_update(inner_ctx, message);
    let inner_hash = sha256_final(inner_ctx);

    var outer_ctx = sha256_init();
    sha256_update(outer_ctx, opad[..]);
    sha256_update(outer_ctx, inner_hash[..]);
    return sha256_final(outer_ctx);
}

// ---- hkdf-sha256 (rfc 5869) ------------------------------------------------

fn hkdf_extract(salt: const u8[:], ikm: const u8[:]) -> u8[32] {
    let zero_salt: u8[32] = [0; 32];
    let actual_salt = if salt.len == 0 {
        zero_salt[..]
    } else {
        salt
    };
    return hmac_sha256(actual_salt, ikm);
}

fn hkdf_expand_32(prk: const u8[32]&, info: const u8[:]) -> u8[32] {
    var msg: u8[>..] = [];
    msg.append(info);
    msg.push(0x01);
    return hmac_sha256(prk[..], msg[..]);
}

fn hkdf_sha256_32(ikm: const u8[32]&, salt: const u8[:], info: const u8[:]) -> u8[32] {
    let prk = hkdf_extract(salt, ikm[..]);
    return hkdf_expand_32(prk, info);
}

// ---- sha-384 (fips 180-4) --------------------------------------------------

let SHA512_K: const u64[80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47867871, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

struct Sha384Ctx {
    h: u64[8] = [
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
        0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
    ],
    buf: u8[128] = [0; 128],
    buf_len: i64 = 0,
    total_len: u64 = 0,
}

fn sha384_init() -> Sha384Ctx {
    return Sha384Ctx { .. };
}

fn sha512_transform(h_state: u64[8]&, chunk: const u8[:]) {
    var w: u64[80] = [0; 80];
    for i in 16 {
        let off = i * 8;
        w[i] = ((chunk[off] as u64) << 56) |
               ((chunk[off + 1] as u64) << 48) |
               ((chunk[off + 2] as u64) << 40) |
               ((chunk[off + 3] as u64) << 32) |
               ((chunk[off + 4] as u64) << 24) |
               ((chunk[off + 5] as u64) << 16) |
               ((chunk[off + 6] as u64) << 8) |
               chunk[off + 7];
    }
    for i in 16..80 {
        let s0 = core::rotr64(w[i - 15], 1) ^ core::rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        let s1 = core::rotr64(w[i - 2], 19) ^ core::rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    var a = h_state[0];
    var b = h_state[1];
    var c = h_state[2];
    var d = h_state[3];
    var e = h_state[4];
    var f = h_state[5];
    var g = h_state[6];
    var h = h_state[7];

    for i in 80 {
        let s1 = core::rotr64(e, 14) ^ core::rotr64(e, 18) ^ core::rotr64(e, 41);
        let ch = (e & f) ^ ((~e) & g);
        let temp1 = h + s1 + ch + SHA512_K[i] + w[i];
        let s0 = core::rotr64(a, 28) ^ core::rotr64(a, 34) ^ core::rotr64(a, 39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    h_state[0] += a;
    h_state[1] += b;
    h_state[2] += c;
    h_state[3] += d;
    h_state[4] += e;
    h_state[5] += f;
    h_state[6] += g;
    h_state[7] += h;
}

fn sha384_update(ctx: Sha384Ctx&, data: const u8[:]) {
    guard data.len > 0 else { return; }
    ctx.total_len += (data.len as u64) * 8;
    var offset = 0;
    while offset < data.len {
        let needed = 128 - ctx.buf_len;
        let available = data.len - offset;
        let to_copy = if available < needed { available } else { needed };
        for i in to_copy {
            ctx.buf[ctx.buf_len + i] = data[offset + i];
        }
        ctx.buf_len += to_copy;
        offset += to_copy;

        if ctx.buf_len == 128 {
            sha512_transform(ctx.h, ctx.buf[..]);
            ctx.buf_len = 0;
        }
    }
}

fn sha384_final(ctx: Sha384Ctx&) -> u8[48] {
    ctx.buf[ctx.buf_len] = 0x80;
    ctx.buf_len += 1;

    if ctx.buf_len > 112 {
        for i in (128 - ctx.buf_len) {
            ctx.buf[ctx.buf_len + i] = 0;
        }
        sha512_transform(ctx.h, ctx.buf[..]);
        ctx.buf_len = 0;
    }

    for i in (112 - ctx.buf_len) {
        ctx.buf[ctx.buf_len + i] = 0;
    }

    for i in 8 {
        ctx.buf[112 + i] = 0;
    }
    for i in 8 {
        ctx.buf[120 + i] = ((ctx.total_len >> ((7 - i) * 8)) & 0xFF) as u8;
    }
    sha512_transform(ctx.h, ctx.buf[..]);

    var out: u8[48] = [0; 48];
    for i in 6 {
        for j in 8 {
            out[i * 8 + j] = ((ctx.h[i] >> ((7 - j) * 8)) & 0xFF) as u8;
        }
    }
    return out;
}

fn sha384(data: const u8[:]) -> u8[48] {
    var ctx = sha384_init();
    sha384_update(ctx, data);
    return sha384_final(ctx);
}

// ---- hmac-sha384 (rfc 2104 / rfc 4231) -------------------------------------

fn hmac_sha384(key: const u8[:], message: const u8[:]) -> u8[48] {
    var key_block: u8[128] = [0; 128];
    if key.len > 128 {
        let hashed_key = sha384(key);
        for i in 48 { key_block[i] = hashed_key[i]; }
    } else {
        for i in key.len { key_block[i] = key[i]; }
    }

    var ipad: u8[128] = [0; 128];
    var opad: u8[128] = [0; 128];
    for i in 128 {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    var inner_ctx = sha384_init();
    sha384_update(inner_ctx, ipad[..]);
    sha384_update(inner_ctx, message);
    let inner_hash = sha384_final(inner_ctx);

    var outer_ctx = sha384_init();
    sha384_update(outer_ctx, opad[..]);
    sha384_update(outer_ctx, inner_hash[..]);
    return sha384_final(outer_ctx);
}

// ---- hkdf-sha384 (rfc 5869) ------------------------------------------------

fn hkdf_extract_384(salt: const u8[:], ikm: const u8[:]) -> u8[48] {
    let zero_salt: u8[48] = [0; 48];
    let actual_salt = if salt.len == 0 {
        zero_salt[..]
    } else {
        salt
    };
    return hmac_sha384(actual_salt, ikm);
}

fn hkdf_expand_bytes_256(prk: const u8[:], info: const u8[:], length: u16, out: u8[:]) -> bool {
    var n: i64 = (length + 31) / 32;
    guard n <= 255 && out.len >= length else { return false; }
    var t: u8[32] = [0; 32];
    var out_off: i64 = 0;

    for i in 1..n + 1 {
        var msg: u8[>..] = [];
        if i > 1 {
            msg.append(t[..]);
        }
        msg.append(info);
        msg.push(i as u8);
        t = hmac_sha256(prk, msg[..]);
        let to_copy = if length - out_off < 32 { length - out_off } else { 32 };
        for j in to_copy {
            out[out_off + j] = t[j];
        }
        out_off += to_copy;
    }
    return true;
}

fn hkdf_expand_bytes_384(prk: const u8[:], info: const u8[:], length: u16, out: u8[:]) -> bool {
    var n: i64 = (length + 47) / 48;
    guard n <= 255 && out.len >= length else { return false; }
    var t: u8[48] = [0; 48];
    var out_off: i64 = 0;

    for i in 1..n + 1 {
        var msg: u8[>..] = [];
        if i > 1 {
            msg.append(t[..]);
        }
        msg.append(info);
        msg.push(i as u8);
        t = hmac_sha384(prk, msg[..]);
        let to_copy = if length - out_off < 48 { length - out_off } else { 48 };
        for j in to_copy {
            out[out_off + j] = t[j];
        }
        out_off += to_copy;
    }
    return true;
}

// ---- chacha20, hchacha20 & poly1305 (rfc 8439 / draft-irtf-cfrg-xchacha) ---

inline fn chacha_qr(a: u32&, b: u32&, c: u32&, d: u32&) {
    a += b; d ^= a; d = core::rotl32(d, 16);
    c += d; b ^= c; b = core::rotl32(b, 12);
    a += b; d ^= a; d = core::rotl32(d, 8);
    c += d; b ^= c; b = core::rotl32(b, 7);
}

fn load_u32_le(bytes: const u8[:], offset: i64) -> u32 {
    return bytes[offset] |
           ((bytes[offset + 1] as u32) << 8) |
           ((bytes[offset + 2] as u32) << 16) |
           ((bytes[offset + 3] as u32) << 24);
}

fn store_u32_le(bytes: u8[:], offset: i64, val: u32) {
    bytes[offset] = (val & 0xFF) as u8;
    bytes[offset + 1] = ((val >> 8) & 0xFF) as u8;
    bytes[offset + 2] = ((val >> 16) & 0xFF) as u8;
    bytes[offset + 3] = ((val >> 24) & 0xFF) as u8;
}

fn hchacha20(key: const u8[32]&, nonce16: const u8[16]&) -> u8[32] {
    var s: u32[16] = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        load_u32_le(key[..], 0), load_u32_le(key[..], 4), load_u32_le(key[..], 8), load_u32_le(key[..], 12),
        load_u32_le(key[..], 16), load_u32_le(key[..], 20), load_u32_le(key[..], 24), load_u32_le(key[..], 28),
        load_u32_le(nonce16[..], 0), load_u32_le(nonce16[..], 4), load_u32_le(nonce16[..], 8), load_u32_le(nonce16[..], 12),
    ];

    for r in 10 {
        chacha_qr(s[0], s[4], s[8], s[12]);
        chacha_qr(s[1], s[5], s[9], s[13]);
        chacha_qr(s[2], s[6], s[10], s[14]);
        chacha_qr(s[3], s[7], s[11], s[15]);
        chacha_qr(s[0], s[5], s[10], s[15]);
        chacha_qr(s[1], s[6], s[11], s[12]);
        chacha_qr(s[2], s[7], s[8], s[13]);
        chacha_qr(s[3], s[4], s[9], s[14]);
    }

    var out: u8[32] = [0; 32];
    store_u32_le(out[..], 0, s[0]);
    store_u32_le(out[..], 4, s[1]);
    store_u32_le(out[..], 8, s[2]);
    store_u32_le(out[..], 12, s[3]);
    store_u32_le(out[..], 16, s[12]);
    store_u32_le(out[..], 20, s[13]);
    store_u32_le(out[..], 24, s[14]);
    store_u32_le(out[..], 28, s[15]);
    return out;
}

fn chacha20_block(key: const u8[32]&, counter: u32, nonce12: const u8[12]&) -> u8[64] {
    var orig: u32[16] = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        load_u32_le(key[..], 0), load_u32_le(key[..], 4), load_u32_le(key[..], 8), load_u32_le(key[..], 12),
        load_u32_le(key[..], 16), load_u32_le(key[..], 20), load_u32_le(key[..], 24), load_u32_le(key[..], 28),
        counter,
        load_u32_le(nonce12[..], 0), load_u32_le(nonce12[..], 4), load_u32_le(nonce12[..], 8),
    ];
    var s = orig;
    for r in 10 {
        chacha_qr(s[0], s[4], s[8], s[12]);
        chacha_qr(s[1], s[5], s[9], s[13]);
        chacha_qr(s[2], s[6], s[10], s[14]);
        chacha_qr(s[3], s[7], s[11], s[15]);
        chacha_qr(s[0], s[5], s[10], s[15]);
        chacha_qr(s[1], s[6], s[11], s[12]);
        chacha_qr(s[2], s[7], s[8], s[13]);
        chacha_qr(s[3], s[4], s[9], s[14]);
    }

    var blk: u8[64] = [0; 64];
    for i in 16 {
        store_u32_le(blk[..], i * 4, s[i] + orig[i]);
    }
    return blk;
}

fn chacha20_xor(key: const u8[32]&, counter: u32, nonce12: const u8[12]&, input: const u8[:], out: u8[>..]&) {
    var cur_ctr = counter;
    var offset = 0;
    while offset < input.len {
        let blk = chacha20_block(key, cur_ctr, nonce12);
        cur_ctr += 1;
        let rem = input.len - offset;
        let take = if rem < 64 { rem } else { 64 };
        for i in take {
            out.push(input[offset + i] ^ blk[i]);
        }
        offset += take;
    }
}

// Poly1305 one-time MAC over GF(2^130 - 5) using 26-bit limbs for pure 64-bit arithmetic.
fn poly1305_process_block(
    m: const u8[17]&,
    r0: u64, r1: u64, r2: u64, r3: u64, r4: u64,
    s1: u64, s2: u64, s3: u64, s4: u64,
    h0: u64&, h1: u64&, h2: u64&, h3: u64&, h4: u64&
) {
    let m0: u64 = (load_u32_le(m[..], 0) as u64) & 0x3FFFFFF;
    let m1: u64 = ((load_u32_le(m[..], 3) >> 2) as u64) & 0x3FFFFFF;
    let m2: u64 = ((load_u32_le(m[..], 6) >> 4) as u64) & 0x3FFFFFF;
    let m3: u64 = ((load_u32_le(m[..], 9) >> 6) as u64) & 0x3FFFFFF;
    let m4: u64 = load_u32_le(m[..], 12) >> 8;

    h0 += m0; h1 += m1; h2 += m2; h3 += m3; h4 += m4;

    let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
    let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
    let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
    let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
    let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

    var c: u64 = d0 >> 26; h0 = d0 & 0x3FFFFFF;
    let td1 = d1 + c; c = td1 >> 26; h1 = td1 & 0x3FFFFFF;
    let td2 = d2 + c; c = td2 >> 26; h2 = td2 & 0x3FFFFFF;
    let td3 = d3 + c; c = td3 >> 26; h3 = td3 & 0x3FFFFFF;
    let td4 = d4 + c; c = td4 >> 26; h4 = td4 & 0x3FFFFFF;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3FFFFFF; h1 += c;
}

fn poly1305_finalize(
    key32: const u8[32]&,
    h0_in: u64, h1_in: u64, h2_in: u64, h3_in: u64, h4_in: u64
) -> u8[16] {
    var h0 = h0_in;
    var h1 = h1_in;
    var h2 = h2_in;
    var h3 = h3_in;
    var h4 = h4_in;

    var c: u64 = h0 >> 26; h0 &= 0x3FFFFFF;
    h1 += c; c = h1 >> 26; h1 &= 0x3FFFFFF;
    h2 += c; c = h2 >> 26; h2 &= 0x3FFFFFF;
    h3 += c; c = h3 >> 26; h3 &= 0x3FFFFFF;
    h4 += c; c = h4 >> 26; h4 &= 0x3FFFFFF;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3FFFFFF;
    h1 += c;

    var g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3FFFFFF;
    var g1 = h1 + c; c = g1 >> 26; g1 &= 0x3FFFFFF;
    var g2 = h2 + c; c = g2 >> 26; g2 &= 0x3FFFFFF;
    var g3 = h3 + c; c = g3 >> 26; g3 &= 0x3FFFFFF;
    var g4 = h4 + c - (1 << 26);

    let mask = (g4 >> 63) - 1;
    let nmask = ~mask;
    h0 = (h0 & nmask) | (g0 & mask);
    h1 = (h1 & nmask) | (g1 & mask);
    h2 = (h2 & nmask) | (g2 & mask);
    h3 = (h3 & nmask) | (g3 & mask);
    h4 = (h4 & nmask) | (g4 & mask);

    let f0 = ((h0 | (h1 << 26)) & 0xFFFFFFFF) + load_u32_le(key32[..], 16);
    c = f0 >> 32;
    let f1 = (((h1 >> 6) | (h2 << 20)) & 0xFFFFFFFF) + load_u32_le(key32[..], 20) + c;
    c = f1 >> 32;
    let f2 = (((h2 >> 12) | (h3 << 14)) & 0xFFFFFFFF) + load_u32_le(key32[..], 24) + c;
    c = f2 >> 32;
    let f3 = (((h3 >> 18) | (h4 << 8)) & 0xFFFFFFFF) + load_u32_le(key32[..], 28) + c;

    var out: u8[16] = [0; 16];
    store_u32_le(out[..], 0, f0 as u32);
    store_u32_le(out[..], 4, f1 as u32);
    store_u32_le(out[..], 8, f2 as u32);
    store_u32_le(out[..], 12, f3 as u32);
    return out;
}

fn poly1305_mac(key32: const u8[32]&, msg: const u8[:]) -> u8[16] {
    let r0: u64 = (load_u32_le(key32[..], 0) as u64) & 0x3FFFFFF;
    let r1: u64 = ((load_u32_le(key32[..], 3) >> 2) as u64) & 0x3FFFF03;
    let r2: u64 = ((load_u32_le(key32[..], 6) >> 4) as u64) & 0x3FFC0FF;
    let r3: u64 = ((load_u32_le(key32[..], 9) >> 6) as u64) & 0x3F03FFF;
    let r4: u64 = ((load_u32_le(key32[..], 12) >> 8) as u64) & 0x00FFFFF;

    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    var h0: u64 = 0;
    var h1: u64 = 0;
    var h2: u64 = 0;
    var h3: u64 = 0;
    var h4: u64 = 0;

    var offset = 0;
    while offset < msg.len {
        var m: u8[17] = [0; 17];
        let rem = msg.len - offset;
        let take = if rem < 16 { rem } else { 16 };
        for i in take { m[i] = msg[offset + i]; }
        m[take] = 1; // Pad byte 0x01

        poly1305_process_block(m, r0, r1, r2, r3, r4, s1, s2, s3, s4, h0, h1, h2, h3, h4);
        offset += take;
    }

    return poly1305_finalize(key32, h0, h1, h2, h3, h4);
}

// XChaCha20-Poly1305 AEAD (24-byte nonce)
fn xchacha20_poly1305_seal(
    key: const u8[32]&,
    nonce24: const u8[24]&,
    plaintext: const u8[:],
    aad: const u8[:],
    out_ciphertext: u8[>..]&,
) -> u8[16] {
    var nonce16: u8[16] = [0; 16];
    for i in 16 { nonce16[i] = nonce24[i]; }
    let subkey = hchacha20(key, nonce16);

    var subnonce: u8[12] = [0; 12];
    for i in 8 { subnonce[4 + i] = nonce24[16 + i]; }

    let ot_block = chacha20_block(subkey, 0, subnonce);
    var otk: u8[32] = [0; 32];
    for i in 32 { otk[i] = ot_block[i]; }

    let ct_start = out_ciphertext.len;
    chacha20_xor(subkey, 1, subnonce, plaintext, out_ciphertext);
    let ciphertext_slice = out_ciphertext[ct_start..];

    var auth_data: u8[>..] = [];
    auth_data.append(aad);
    if (aad.len % 16) != 0 {
        for p in (16 - (aad.len % 16)) { auth_data.push(0); }
    }
    auth_data.append(ciphertext_slice);
    if (ciphertext_slice.len % 16) != 0 {
        for p in (16 - (ciphertext_slice.len % 16)) { auth_data.push(0); }
    }
    for b in 8 { auth_data.push(((aad.len as u64) >> (b * 8)) as u8); }
    for b in 8 { auth_data.push(((ciphertext_slice.len as u64) >> (b * 8)) as u8); }

    return poly1305_mac(otk, auth_data[..]);
}

fn xchacha20_poly1305_open(
    key: const u8[32]&,
    nonce24: const u8[24]&,
    ciphertext: const u8[:],
    aad: const u8[:],
    tag: const u8[16]&,
    out_plaintext: u8[>..]&,
) -> bool {
    var nonce16: u8[16] = [0; 16];
    for i in 16 { nonce16[i] = nonce24[i]; }
    let subkey = hchacha20(key, nonce16);

    var subnonce: u8[12] = [0; 12];
    for i in 8 { subnonce[4 + i] = nonce24[16 + i]; }

    let ot_block = chacha20_block(subkey, 0, subnonce);
    var otk: u8[32] = [0; 32];
    for i in 32 { otk[i] = ot_block[i]; }

    var auth_data: u8[>..] = [];
    auth_data.append(aad);
    if (aad.len % 16) != 0 {
        for p in (16 - (aad.len % 16)) { auth_data.push(0); }
    }
    auth_data.append(ciphertext);
    if (ciphertext.len % 16) != 0 {
        for p in (16 - (ciphertext.len % 16)) { auth_data.push(0); }
    }
    for b in 8 { auth_data.push(((aad.len as u64) >> (b * 8)) as u8); }
    for b in 8 { auth_data.push(((ciphertext.len as u64) >> (b * 8)) as u8); }

    let computed_tag = poly1305_mac(otk, auth_data[..]);
    guard ct_eq_tag16(computed_tag, tag) else {
        return false;
    }

    chacha20_xor(subkey, 1, subnonce, ciphertext, out_plaintext);
    return true;
}

// ---- aes-256-gcm (nist sp 800-38d) -----------------------------------------

let AES_SBOX: const u8[256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

let AES_RCON: const u32[10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
];

inline fn aes_sub_word(w: u32) -> u32 {
    return ((AES_SBOX[(w >> 24) & 0xFF] as u32) << 24) |
           ((AES_SBOX[(w >> 16) & 0xFF] as u32) << 16) |
           ((AES_SBOX[(w >> 8) & 0xFF] as u32) << 8) |
           AES_SBOX[w & 0xFF];
}

inline fn aes_rot_word(w: u32) -> u32 {
    return (w << 8) | (w >> 24);
}

struct Aes256KeySchedule {
    round_keys: u32[60] = [0; 60],
}

fn aes256_key_schedule(key: const u8[32]&) -> Aes256KeySchedule {
    var ks = Aes256KeySchedule { .. };
    for i in 8 {
        let off = i * 4;
        ks.round_keys[i] = ((key[off] as u32) << 24) |
                           ((key[off + 1] as u32) << 16) |
                           ((key[off + 2] as u32) << 8) |
                           key[off + 3];
    }
    for i in 8..60 {
        var temp = ks.round_keys[i - 1];
        if (i % 8) == 0 {
            temp = aes_sub_word(aes_rot_word(temp)) ^ AES_RCON[(i / 8) - 1];
        } else if (i % 8) == 4 {
            temp = aes_sub_word(temp);
        }
        ks.round_keys[i] = ks.round_keys[i - 8] ^ temp;
    }
    return ks;
}

inline fn xtime(b: u8) -> u8 {
    return if (b & 0x80) != 0 { ((b << 1) ^ 0x1b) } else { (b << 1) };
}

fn aes_encrypt_block(ks: const Aes256KeySchedule&, input: const u8[16]&) -> u8[16] {
    var state: u8[16] = [0; 16];
    for i in 16 { state[i] = input[i]; }

    // Initial round key addition
    for i in 4 {
        let rk = ks.round_keys[i];
        state[i * 4] ^= ((rk >> 24) & 0xFF) as u8;
        state[i * 4 + 1] ^= ((rk >> 16) & 0xFF) as u8;
        state[i * 4 + 2] ^= ((rk >> 8) & 0xFF) as u8;
        state[i * 4 + 3] ^= (rk & 0xFF) as u8;
    }

    // 13 main rounds
    for round in 1..14 {
        // SubBytes
        for i in 16 { state[i] = AES_SBOX[state[i]]; }
        // ShiftRows
        let t1 = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t1;
        let t2 = state[2]; state[2] = state[10]; state[10] = t2;
        let t6 = state[6]; state[6] = state[14]; state[14] = t6;
        let t3 = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t3;
        // MixColumns
        for c in 4 {
            let col = c * 4;
            let a0 = state[col]; let a1 = state[col + 1];
            let a2 = state[col + 2]; let a3 = state[col + 3];
            state[col] = xtime(a0 ^ a1) ^ a1 ^ a2 ^ a3;
            state[col + 1] = xtime(a1 ^ a2) ^ a2 ^ a3 ^ a0;
            state[col + 2] = xtime(a2 ^ a3) ^ a3 ^ a0 ^ a1;
            state[col + 3] = xtime(a3 ^ a0) ^ a0 ^ a1 ^ a2;
        }
        // AddRoundKey
        let rk_base = round * 4;
        for i in 4 {
            let rk = ks.round_keys[rk_base + i];
            state[i * 4] ^= ((rk >> 24) & 0xFF) as u8;
            state[i * 4 + 1] ^= ((rk >> 16) & 0xFF) as u8;
            state[i * 4 + 2] ^= ((rk >> 8) & 0xFF) as u8;
            state[i * 4 + 3] ^= (rk & 0xFF) as u8;
        }
    }

    // Final round (no MixColumns)
    for i in 16 { state[i] = AES_SBOX[state[i]]; }
    let t1 = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t1;
    let t2 = state[2]; state[2] = state[10]; state[10] = t2;
    let t6 = state[6]; state[6] = state[14]; state[14] = t6;
    let t3 = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t3;

    for i in 4 {
        let rk = ks.round_keys[56 + i];
        state[i * 4] ^= ((rk >> 24) & 0xFF) as u8;
        state[i * 4 + 1] ^= ((rk >> 16) & 0xFF) as u8;
        state[i * 4 + 2] ^= ((rk >> 8) & 0xFF) as u8;
        state[i * 4 + 3] ^= (rk & 0xFF) as u8;
    }
    return state;
}

// GHASH in GF(2^128)
fn ghash_mul(x: const u8[16]&, y: const u8[16]&) -> u8[16] {
    var v: u64[2] = [
        ((load_u32_le(y[..], 12) as u64) << 32) | load_u32_le(y[..], 8),
        ((load_u32_le(y[..], 4) as u64) << 32) | load_u32_le(y[..], 0)
    ];
    // swap to big endian for bit shifts
    var v_hi = ((y[0] as u64) << 56) | ((y[1] as u64) << 48) | ((y[2] as u64) << 40) | ((y[3] as u64) << 32) |
               ((y[4] as u64) << 24) | ((y[5] as u64) << 16) | ((y[6] as u64) << 8) | y[7];
    var v_lo = ((y[8] as u64) << 56) | ((y[9] as u64) << 48) | ((y[10] as u64) << 40) | ((y[11] as u64) << 32) |
               ((y[12] as u64) << 24) | ((y[13] as u64) << 16) | ((y[14] as u64) << 8) | y[15];

    var z_hi: u64 = 0;
    var z_lo: u64 = 0;

    for i in 16 {
        let b = x[i];
        for j in 8 {
            if ((b >> (7 - j)) & 1) != 0 {
                z_hi ^= v_hi;
                z_lo ^= v_lo;
            }
            let lsb = v_lo & 1;
            v_lo = (v_lo >> 1) | ((v_hi & 1) << 63);
            v_hi = v_hi >> 1;
            if lsb != 0 {
                v_hi ^= 0xe100000000000000;
            }
        }
    }

    var res: u8[16] = [0; 16];
    for i in 8 {
        res[i] = ((z_hi >> ((7 - i) * 8)) & 0xFF) as u8;
        res[8 + i] = ((z_lo >> ((7 - i) * 8)) & 0xFF) as u8;
    }
    return res;
}

fn ghash_update(h: const u8[16]&, y: u8[16]&, data: const u8[:]) {
    var offset = 0;
    while offset < data.len {
        var gblk: u8[16] = [0; 16];
        let rem = data.len - offset;
        let take = if rem < 16 { rem } else { 16 };
        for i in take { gblk[i] = data[offset + i]; }
        for i in 16 { y[i] ^= gblk[i]; }
        y = ghash_mul(y, h);
        offset += take;
    }
}

fn aes256_gcm_seal(
    key: const u8[32]&,
    nonce12: const u8[12]&,
    plaintext: const u8[:],
    aad: const u8[:],
    out_ciphertext: u8[>..]&,
) -> u8[16] {
    let ks = aes256_key_schedule(key);
    let zero_block: u8[16] = [0; 16];
    let h = aes_encrypt_block(ks, zero_block);

    var j0: u8[16] = [0; 16];
    for i in 12 { j0[i] = nonce12[i]; }
    j0[15] = 1;

    let ct_start = out_ciphertext.len;
    var ctr = j0;
    var offset = 0;
    while offset < plaintext.len {
        // increment 32-bit counter in j0
        var val = ((ctr[12] as u32) << 24) | ((ctr[13] as u32) << 16) | ((ctr[14] as u32) << 8) | ctr[15];
        val += 1;
        ctr[12] = ((val >> 24) & 0xFF) as u8;
        ctr[13] = ((val >> 16) & 0xFF) as u8;
        ctr[14] = ((val >> 8) & 0xFF) as u8;
        ctr[15] = (val & 0xFF) as u8;

        let enc_ctr = aes_encrypt_block(ks, ctr);
        let rem = plaintext.len - offset;
        let take = if rem < 16 { rem } else { 16 };
        for i in take {
            out_ciphertext.push(plaintext[offset + i] ^ enc_ctr[i]);
        }
        offset += take;
    }

    let ct_slice = out_ciphertext[ct_start..];
    var ghash_acc: u8[16] = [0; 16];
    ghash_update(h, ghash_acc, aad);
    ghash_update(h, ghash_acc, ct_slice);

    var len_block: u8[16] = [0; 16];
    let aad_bits = (aad.len as u64) * 8;
    let ct_bits = (ct_slice.len as u64) * 8;
    for i in 8 {
        len_block[i] = ((aad_bits >> ((7 - i) * 8)) & 0xFF) as u8;
        len_block[8 + i] = ((ct_bits >> ((7 - i) * 8)) & 0xFF) as u8;
    }
    for i in 16 { ghash_acc[i] ^= len_block[i]; }
    ghash_acc = ghash_mul(ghash_acc, h);

    let enc_j0 = aes_encrypt_block(ks, j0);
    var tag: u8[16] = [0; 16];
    for i in 16 { tag[i] = ghash_acc[i] ^ enc_j0[i]; }
    return tag;
}

fn aes256_gcm_open(
    key: const u8[32]&,
    nonce12: const u8[12]&,
    ciphertext: const u8[:],
    aad: const u8[:],
    tag: const u8[16]&,
    out_plaintext: u8[>..]&,
) -> bool {
    let ks = aes256_key_schedule(key);
    let zero_block: u8[16] = [0; 16];
    let h = aes_encrypt_block(ks, zero_block);

    var j0: u8[16] = [0; 16];
    for i in 12 { j0[i] = nonce12[i]; }
    j0[15] = 1;

    var ghash_acc: u8[16] = [0; 16];
    ghash_update(h, ghash_acc, aad);
    ghash_update(h, ghash_acc, ciphertext);

    var len_block: u8[16] = [0; 16];
    let aad_bits = (aad.len as u64) * 8;
    let ct_bits = (ciphertext.len as u64) * 8;
    for i in 8 {
        len_block[i] = ((aad_bits >> ((7 - i) * 8)) & 0xFF) as u8;
        len_block[8 + i] = ((ct_bits >> ((7 - i) * 8)) & 0xFF) as u8;
    }
    for i in 16 { ghash_acc[i] ^= len_block[i]; }
    ghash_acc = ghash_mul(ghash_acc, h);

    let enc_j0 = aes_encrypt_block(ks, j0);
    var computed_tag: u8[16] = [0; 16];
    for i in 16 { computed_tag[i] = ghash_acc[i] ^ enc_j0[i]; }

    guard ct_eq_tag16(computed_tag, tag) else {
        return false;
    }

    var ctr = j0;
    var offset = 0;
    while offset < ciphertext.len {
        var val = ((ctr[12] as u32) << 24) | ((ctr[13] as u32) << 16) | ((ctr[14] as u32) << 8) | ctr[15];
        val += 1;
        ctr[12] = ((val >> 24) & 0xFF) as u8;
        ctr[13] = ((val >> 16) & 0xFF) as u8;
        ctr[14] = ((val >> 8) & 0xFF) as u8;
        ctr[15] = (val & 0xFF) as u8;

        let enc_ctr = aes_encrypt_block(ks, ctr);
        let rem = ciphertext.len - offset;
        let take = if rem < 16 { rem } else { 16 };
        for i in take {
            out_plaintext.push(ciphertext[offset + i] ^ enc_ctr[i]);
        }
        offset += take;
    }
    return true;
}

// HKDF-SHA256 + AES-256-GCM scheme (32-byte salt + 12-byte nonce)
fn hkdf_aes256_gcm_seal(
    master_key: const u8[32]&,
    salt32: const u8[32]&,
    nonce12: const u8[12]&,
    plaintext: const u8[:],
    aad: const u8[:],
    out_ciphertext: u8[>..]&,
) -> u8[16] {
    let derived_key = hkdf_sha256_32(master_key, salt32[..], "aes-256-gcm-cookie");
    return aes256_gcm_seal(derived_key, nonce12, plaintext, aad, out_ciphertext);
}

fn hkdf_aes256_gcm_open(
    master_key: const u8[32]&,
    salt32: const u8[32]&,
    nonce12: const u8[12]&,
    ciphertext: const u8[:],
    aad: const u8[:],
    tag: const u8[16]&,
    out_plaintext: u8[>..]&,
) -> bool {
    let derived_key = hkdf_sha256_32(master_key, salt32[..], "aes-256-gcm-cookie");
    return aes256_gcm_open(derived_key, nonce12, ciphertext, aad, tag, out_plaintext);
}

// ---- base64url codec (rfc 4648 section 5, unpadded) ------------------------

let BASE64URL_CHARS: const u8[64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
];

fn base64url_encode<B>(data: const u8[:], out: B&) {
    var i = 0;
    while i + 3 <= data.len {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(BASE64URL_CHARS[(n >> 18) & 63]);
        out.push(BASE64URL_CHARS[(n >> 12) & 63]);
        out.push(BASE64URL_CHARS[(n >> 6) & 63]);
        out.push(BASE64URL_CHARS[n & 63]);
        i += 3;
    }
    let rem = data.len - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        out.push(BASE64URL_CHARS[(n >> 18) & 63]);
        out.push(BASE64URL_CHARS[(n >> 12) & 63]);
    } else if rem == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(BASE64URL_CHARS[(n >> 18) & 63]);
        out.push(BASE64URL_CHARS[(n >> 12) & 63]);
        out.push(BASE64URL_CHARS[(n >> 6) & 63]);
    }
}

inline fn base64url_val(ch: u8) -> i32 {
    if ch >= 'A' && ch <= 'Z' { return ch - 'A'; }
    if ch >= 'a' && ch <= 'z' { return ch - 'a' + 26; }
    if ch >= '0' && ch <= '9' { return ch - '0' + 52; }
    if ch == '-' { return 62; }
    if ch == '_' { return 63; }
    return -1;
}

fn base64url_decode(encoded: const u8[:], out: u8[>..]&) -> bool {
    guard encoded.len > 0 else { return true; }
    var buf: u32 = 0;
    var bits = 0;

    for idx in encoded.len {
        let ch = encoded[idx];
        if ch == '=' { break; } // stop on padding if present
        let v = base64url_val(ch);
        guard v >= 0 else { return false; }
        buf = (buf << 6) | (v as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    return true;
}
