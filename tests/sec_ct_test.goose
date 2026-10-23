// Constant-Time Primitives, Pure-Goose Cryptography & CryptoJar Verification Suite
import std;
import wing from "..";

fn hex_to_bytes(hex: const u8[:], out: u8[>..]&) {
    var i = 0;
    while i + 1 < hex.len {
        let hi = hex_nibble(hex[i]);
        let lo = hex_nibble(hex[i + 1]);
        out.push((hi << 4) | lo);
        i += 2;
    }
}

inline fn hex_nibble(ch: u8) -> u8 {
    if ch >= '0' && ch <= '9' { return ch - '0'; }
    if ch >= 'a' && ch <= 'f' { return ch - 'a' + 10; }
    if ch >= 'A' && ch <= 'F' { return ch - 'A' + 10; }
    return 0;
}

fn bytes_to_hex(bytes: const u8[:], out: u8[>..]&) {
    let hex_chars: const u8[16] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
    for b in bytes {
        out.push(hex_chars[(b >> 4) & 0x0F]);
        out.push(hex_chars[b & 0x0F]);
    }
}

// ----------------------------------------------------------------------------
// 1. Constant-Time Primitives & KeySlot Redaction
// ----------------------------------------------------------------------------
fn test_constant_time_primitives(t: wing::T&) {
    t.run("Branchless Equality and Select") { sub =>
        sub.assert_eq(wing::ct_eq_u8(0x42, 0x42), 1, "ct_eq_u8 match");
        sub.assert_eq(wing::ct_eq_u8(0x42, 0x43), 0, "ct_eq_u8 mismatch");
        sub.assert_eq(wing::ct_eq_u8(0x00, 0x00), 1, "ct_eq_u8 zero match");
        sub.assert_eq(wing::ct_eq_u8(0xFF, 0x00), 0, "ct_eq_u8 boundary");

        sub.assert_eq(wing::ct_select_u8(1, 0xAA, 0xBB), 0xAA, "ct_select_u8 true");
        sub.assert_eq(wing::ct_select_u8(0, 0xAA, 0xBB), 0xBB, "ct_select_u8 false");
    };

    t.run("Constant-Time Slice Equality and Copy") { sub =>
        let a: const u8[4] = [1, 2, 3, 4];
        let b: const u8[4] = [1, 2, 3, 4];
        let c: const u8[4] = [1, 2, 3, 5];
        let d: const u8[3] = [1, 2, 3];

        sub.assert_true(wing::ct_eq_bytes(a[..], b[..]), "identical slices match");
        sub.assert_false(wing::ct_eq_bytes(a[..], c[..]), "last byte difference fails");
        sub.assert_false(wing::ct_eq_bytes(a[..], d[..]), "length difference fails");

        var dst: u8[4] = [0, 0, 0, 0];
        wing::ct_copy_bytes(dst[..], a[..]);
        sub.assert_true(wing::ct_eq_bytes(dst[..], a[..]), "ct_copy_bytes copied identical bytes");
    };

    t.run("KeySlot Redaction and Zeroization") { sub =>
        var raw_key: u8[32] = [0x5A; 32];
        var slot = wing::new_key_slot(1001, raw_key[..], 1700000000);
        sub.assert_eq(slot.key_id, 1001, "key id matches");
        sub.assert_false(slot.revoked, "slot starts non-revoked");

        // Display redacted string must hide raw key
        var red_buf: u8[..64] = [];
        wing::display_redacted(slot, red_buf);
        sub.assert_contains(red_buf[..], "[REDACTED]", "secrecy redaction format");
        sub.assert_contains(red_buf[..], "1001", "key id preserved");

        // Revoke and zeroize
        wing::zeroize_key_slot(slot);
        sub.assert_true(slot.revoked, "slot revoked after zeroize");
        sub.assert_eq(slot.master_key[0], 0, "first key byte zeroized");
        sub.assert_eq(slot.master_key[31], 0, "last key byte zeroized");
    };
}

// ----------------------------------------------------------------------------
// 2. Dudect Statistical Welch's t-test Simulation
// ----------------------------------------------------------------------------
fn test_dudect_context_and_filtering(t: wing::T&) {
    t.run("Outlier Cropping & Statistical Lockstep") { sub =>
        var ctx = wing::new_dudect_context();

        // Feed normal samples (around 100 ns)
        for i in 100 {
            sub.assert_true(wing::dudect_push_sample(ctx, 0, 100.0 + (i as f64) * 0.1), "normal sample class 0 accepted");
            sub.assert_true(wing::dudect_push_sample(ctx, 1, 100.0 + (i as f64) * 0.1), "normal sample class 1 accepted");
        }

        // Outlier sample (> 2000 ns) must be discarded
        sub.assert_false(wing::dudect_push_sample(ctx, 0, 2500.0), "outlier > 2000 ns rejected");
        sub.assert_false(wing::dudect_push_sample(ctx, 1, 3000.0), "outlier > 2000 ns rejected");

        // Verify t-statistic is near 0 for identical distributions
        let t_stat = wing::dudect_abs_t(ctx);
        sub.assert_true(t_stat < 1.0, "Welch t-stat < 1.0 for symmetric distributions");
        sub.assert_true(wing::dudect_is_constant_time(ctx, 4.5), "Passes 99.999% confidence CT threshold");
    };
}

// ----------------------------------------------------------------------------
// 3. NIST / RFC Cryptographic Primitives
// ----------------------------------------------------------------------------
fn test_pure_goose_crypto_primitives(t: wing::T&) {
    t.run("SHA-256 NIST Vectors") { sub =>
        // Vector 1: Empty string
        let h_empty = wing::sha256("");
        var hex_empty: u8[>..] = [];
        bytes_to_hex(h_empty[..], hex_empty);
        sub.assert_eq(hex_empty[..], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256 empty");

        // Vector 2: "abc"
        let h_abc = wing::sha256("abc");
        var hex_abc: u8[>..] = [];
        bytes_to_hex(h_abc[..], hex_abc);
        sub.assert_eq(hex_abc[..], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 'abc'");

        // Vector 3: 56-byte multi-block
        let h_56 = wing::sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        var hex_56: u8[>..] = [];
        bytes_to_hex(h_56[..], hex_56);
        sub.assert_eq(hex_56[..], "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "SHA-256 56-byte");
    };

    t.run("HMAC-SHA256 RFC 4231 Vector 2") { sub =>
        // Key: "Jefe", Data: "what do ya want for nothing?"
        let hmac = wing::hmac_sha256("Jefe", "what do ya want for nothing?");
        var hex_hmac: u8[>..] = [];
        bytes_to_hex(hmac[..], hex_hmac);
        sub.assert_eq(hex_hmac[..], "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "HMAC-SHA256 RFC 4231 #2");
    };

    t.run("HKDF-SHA256 RFC 5869 Vector 1") { sub =>
        var ikm: u8[>..] = [];
        hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", ikm);
        var salt: u8[>..] = [];
        hex_to_bytes("000102030405060708090a0b0c", salt);
        var info: u8[>..] = [];
        hex_to_bytes("f0f1f2f3f4f5f6f7f8f9", info);

        let prk = wing::hkdf_extract(salt[..], ikm[..]);
        var hex_prk: u8[>..] = [];
        bytes_to_hex(prk[..], hex_prk);
        sub.assert_eq(hex_prk[..], "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "HKDF PRK");

        let okm32 = wing::hkdf_expand_32(prk, info[..]);
        var hex_okm: u8[>..] = [];
        bytes_to_hex(okm32[..], hex_okm);
        // First 32 bytes of RFC 5869 Test Case 1 OKM
        sub.assert_eq(hex_okm[..], "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf", "HKDF OKM first 32 bytes");
    };

    t.run("AES-256 Block Cipher FIPS 197") { sub =>
        var key: u8[>..] = [];
        hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key);
        var pt: u8[>..] = [];
        hex_to_bytes("00112233445566778899aabbccddeeff", pt);

        var key32: u8[32] = [0; 32];
        for i in 32 { key32[i] = key[i]; }
        var pt16: u8[16] = [0; 16];
        for i in 16 { pt16[i] = pt[i]; }

        let ks = wing::aes256_key_schedule(key32);
        let ct16 = wing::aes_encrypt_block(ks, pt16);

        var hex_ct: u8[>..] = [];
        bytes_to_hex(ct16[..], hex_ct);
        sub.assert_eq(hex_ct[..], "8ea2b7ca516745bfeafc49904b496089", "AES-256 FIPS 197 C.3 vector");
    };

    t.run("Base64URL RFC 4648 Codec") { sub =>
        var out_enc: u8[>..] = [];
        wing::base64url_encode("foobar", out_enc);
        sub.assert_eq(out_enc[..], "Zm9vYmFy", "foobar encoded without padding");

        var out_dec: u8[>..] = [];
        sub.assert_true(wing::base64url_decode(out_enc[..], out_dec), "decode foobar");
        sub.assert_eq(out_dec[..], "foobar", "foobar round-trip match");

        // Test with URL-safe characters '-' and '_'
        var special_in: u8[>..] = [];
        special_in.push(0xFB); // 11111011 -> '+' in standard, '-' in url
        special_in.push(0xFF); // 11111111 -> '/' in standard, '_' in url
        var enc_spec: u8[>..] = [];
        wing::base64url_encode(special_in[..], enc_spec);
        sub.assert_true(enc_spec[0] == '-' || enc_spec[1] == '-' || enc_spec[2] == '_', "uses url-safe chars");

        var dec_spec: u8[>..] = [];
        sub.assert_true(wing::base64url_decode(enc_spec[..], dec_spec), "decodes url-safe chars");
        sub.assert_true(wing::ct_eq_bytes(special_in[..], dec_spec[..]), "binary round trip match");
    };
}

// ----------------------------------------------------------------------------
// 4. AEAD Authenticated Encryption: XChaCha20-Poly1305 & AES-256-GCM
// ----------------------------------------------------------------------------
fn test_aead_ciphers(t: wing::T&) {
    t.run("XChaCha20-Poly1305 Round-Trip & Tamper Resistance") { sub =>
        var key: u8[32] = [0x42; 32];
        var nonce: u8[24] = [0x19; 24];
        let aad = "cookie_name=session_id";
        let plaintext = "user_id=12345&role=admin";

        var ciphertext: u8[>..] = [];
        let tag = wing::xchacha20_poly1305_seal(key, nonce, plaintext, aad, ciphertext);
        sub.assert_eq(ciphertext.len, plaintext.len, "ciphertext length equals plaintext length");

        // Authentic decryption
        var decrypted: u8[>..] = [];
        let ok_auth = wing::xchacha20_poly1305_open(key, nonce, ciphertext[..], aad, tag, decrypted);
        sub.assert_true(ok_auth, "authentic ciphertext opens successfully");
        sub.assert_eq(decrypted[..], plaintext, "decrypted plaintext matches original");

        // Tampered ciphertext bit must be rejected
        ciphertext[0] ^= 0x01;
        var dec_tampered: u8[>..] = [];
        let ok_ct_tamper = wing::xchacha20_poly1305_open(key, nonce, ciphertext[..], aad, tag, dec_tampered);
        sub.assert_false(ok_ct_tamper, "tampered ciphertext rejected by Poly1305 tag");
        ciphertext[0] ^= 0x01; // restore

        // Tampered AAD must be rejected
        let ok_aad_tamper = wing::xchacha20_poly1305_open(key, nonce, ciphertext[..], "cookie_name=tampered", tag, dec_tampered);
        sub.assert_false(ok_aad_tamper, "tampered AAD context rejected");
    };

    t.run("AES-256-GCM Round-Trip & Tamper Resistance") { sub =>
        var key: u8[32] = [0x77; 32];
        var iv: u8[12] = [0x12; 12];
        let aad = "cookie_name=auth_token";
        let plaintext = "secret_session_token_xyz987";

        var ciphertext: u8[>..] = [];
        let tag = wing::aes256_gcm_seal(key, iv, plaintext, aad, ciphertext);
        sub.assert_eq(ciphertext.len, plaintext.len, "ciphertext length matches");

        // Authentic decryption
        var decrypted: u8[>..] = [];
        let ok_auth = wing::aes256_gcm_open(key, iv, ciphertext[..], aad, tag, decrypted);
        sub.assert_true(ok_auth, "AES-256-GCM authentic decryption succeeds");
        sub.assert_eq(decrypted[..], plaintext, "decrypted plaintext matches original");

        // Tampered tag must be rejected
        var bad_tag = tag;
        bad_tag[15] ^= 0x80;
        var dec_bad: u8[>..] = [];
        let ok_tag_tamper = wing::aes256_gcm_open(key, iv, ciphertext[..], aad, bad_tag, dec_bad);
        sub.assert_false(ok_tag_tamper, "tampered GHASH tag rejected");
    };
}

// ----------------------------------------------------------------------------
// 5. CryptoJar Container: PrivateJar & SignedJar with Key Rotation
// ----------------------------------------------------------------------------
fn test_crypto_jar_container(t: wing::T&) {
    t.run("PrivateJar XChaCha20-Poly1305 (53B Overhead) & AAD Binding") { sub =>
        var store = wing::new_key_store();
        var raw_key: u8[32] = [0x33; 32];
        let slot = wing::new_key_slot(1, raw_key[..], 1700000000);
        wing::add_key(store, slot);

        var jar = wing::new_private_jar(store, false);

        var sealed_cookie: u8[>..] = [];
        let ok_seal = wing::private_jar_seal_binary(jar, "session_jwt", "payload_data_123", 1700000010, 0x123456789ABCDEF0, sealed_cookie);
        sub.assert_true(ok_seal, "private jar binary seal succeeds");
        sub.assert_eq(sealed_cookie.len, 53 + "payload_data_123".len, "exact 53B wire overhead");

        // Authentic open
        var opened: u8[>..] = [];
        let ok_open = wing::private_jar_open_binary(jar, "session_jwt", sealed_cookie[..], 1700000020, opened);
        sub.assert_true(ok_open, "private jar opens authentic cookie");
        sub.assert_eq(opened[..], "payload_data_123", "cookie payload verified");

        // AAD Binding: Trying to open with different cookie name must fail!
        var opened_bad: u8[>..] = [];
        let ok_bad_name = wing::private_jar_open_binary(jar, "other_cookie", sealed_cookie[..], 1700000020, opened_bad);
        sub.assert_false(ok_bad_name, "AAD cookie name alteration rejected");

        // Expired cookie timestamp rejection
        let ok_expired = wing::private_jar_open_binary(jar, "session_jwt", sealed_cookie[..], 1700000010 + 2592001, opened_bad);
        sub.assert_false(ok_expired, "expired session cookie rejected");
    };

    t.run("PrivateJar HKDF-AES-GCM (65B Overhead)") { sub =>
        var store = wing::new_key_store();
        var raw_key: u8[32] = [0x44; 32];
        let slot = wing::new_key_slot(2, raw_key[..], 1700000000);
        wing::add_key(store, slot);

        var jar = wing::new_private_jar(store, true);

        var sealed_cookie: u8[>..] = [];
        let ok_seal = wing::private_jar_seal_binary(jar, "secure_sess", "secret_info", 1700000010, 0xFEDCBA9876543210, sealed_cookie);
        sub.assert_true(ok_seal, "HKDF AES-GCM seal succeeds");
        sub.assert_eq(sealed_cookie.len, 65 + "secret_info".len, "exact 65B wire overhead");

        var opened: u8[>..] = [];
        let ok_open = wing::private_jar_open_binary(jar, "secure_sess", sealed_cookie[..], 1700000020, opened);
        sub.assert_true(ok_open, "HKDF AES-GCM authentic cookie opens");
        sub.assert_eq(opened[..], "secret_info", "payload matches");
    };

    t.run("SignedJar HMAC-SHA256 (45B Overhead) & Forgery Resistance") { sub =>
        var store = wing::new_key_store();
        var raw_key: u8[32] = [0x88; 32];
        let slot = wing::new_key_slot(7, raw_key[..], 1700000000);
        wing::add_key(store, slot);

        var jar = wing::new_signed_jar(store);

        var signed_cookie: u8[>..] = [];
        let ok_sign = wing::signed_jar_seal_binary(jar, "pref_cookie", "dark_mode=true", 1700000010, signed_cookie);
        sub.assert_true(ok_sign, "signed jar seal succeeds");
        sub.assert_eq(signed_cookie.len, 45 + "dark_mode=true".len, "exact 45B wire overhead");

        var verified_val: u8[>..] = [];
        let ok_verify = wing::signed_jar_open_binary(jar, "pref_cookie", signed_cookie[..], 1700000020, verified_val);
        sub.assert_true(ok_verify, "authentic signed cookie verified");
        sub.assert_eq(verified_val[..], "dark_mode=true", "verified payload matches");

        // Tamper with value byte
        signed_cookie[13] ^= 0x01;
        var bad_val: u8[>..] = [];
        let ok_tamper = wing::signed_jar_open_binary(jar, "pref_cookie", signed_cookie[..], 1700000020, bad_val);
        sub.assert_false(ok_tamper, "forged signature rejected");
    };

    t.run("KeyStore Proactive Key Rotation") { sub =>
        var store = wing::new_key_store();
        var k1: u8[32] = [0x11; 32];
        var k2: u8[32] = [0x22; 32];
        wing::add_key(store, wing::new_key_slot(10, k1[..], 1700000000));
        wing::add_key(store, wing::new_key_slot(20, k2[..], 1700086400)); // 24h later

        // Rotate active key to key 20
        sub.assert_true(wing::set_active_key_id(store, 20), "rotated active key to id 20");

        var jar = wing::new_signed_jar(store);
        var cookie_k2: u8[>..] = [];
        wing::signed_jar_seal_binary(jar, "sess", "user=alice", 1700086410, cookie_k2);

        // Header must use key_id 20
        sub.assert_eq(cookie_k2[4], 20, "signed with new active key 20");

        // Old key 10 can still verify existing cookies before revocation
        var cookie_k1: u8[>..] = [];
        jar.store.active_idx = 0; // temporarily sign with old key 10
        wing::signed_jar_seal_binary(jar, "sess", "user=bob", 1700086410, cookie_k1);
        jar.store.active_idx = 1; // restore active key 20

        var out_bob: u8[>..] = [];
        let ok_old = wing::signed_jar_open_binary(jar, "sess", cookie_k1[..], 1700086420, out_bob);
        sub.assert_true(ok_old, "old key 10 still verifies historical session");

        // Revoke key 10 directly on jar.store
        sub.assert_true(wing::revoke_key(jar.store, 10), "revoked key 10");
        let ok_after_revocation = wing::signed_jar_open_binary(jar, "sess", cookie_k1[..], 1700086420, out_bob);
        sub.assert_false(ok_after_revocation, "cookie signed with revoked key 10 is now rejected");
    };
}

// ----------------------------------------------------------------------------
// Suite Runner
// ----------------------------------------------------------------------------
fn main() {
    var runner = wing::new_runner("Constant-Time Primitives, Pure Crypto & CryptoJar Suite", wing::Verbosity.Verbose);

    wing::run_case(runner, "1. Constant-Time Primitives & KeySlot Redaction", test_constant_time_primitives);
    wing::run_case(runner, "2. Dudect Statistical Welch's t-test Simulation", test_dudect_context_and_filtering);
    wing::run_case(runner, "3. NIST / RFC Cryptographic Primitives", test_pure_goose_crypto_primitives);
    wing::run_case(runner, "4. AEAD Authenticated Encryption: XChaCha20 & AES-GCM", test_aead_ciphers);
    wing::run_case(runner, "5. CryptoJar Container: PrivateJar, SignedJar & Rotation", test_crypto_jar_container);

    let ok = wing::finish(runner);
    assert(ok);
}
