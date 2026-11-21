// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of RFC 8448 Section 3 Simple 1-RTT TLS 1.3 handshake byte-for-byte:
// X25519 key agreement, HKDF key schedule, Finished verify data, AEAD record
// sealing/decryption, NewSessionTicket resumption PSK, and replay rejection.
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

fn must_unhex(hex_str: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    assert(wire_kit::parse_hex(hex_str, out));
    return out;
}

fn push_hex(out: u8[>..]&, chunk: const u8[:]) {
    assert(wire_kit::parse_hex(chunk, out));
}

fn copy_32(src: const u8[:]) -> u8[32] {
    assert(src.len == 32);
    var out: u8[32] = [0; 32];
    for i in 32 { out[i] = src[i]; }
    return out;
}

fn check_record_roundtrip(
    key:        const u8[16]&,
    iv:         const u8[12]&,
    seq:        u64,
    ctype:      u8,
    plain:      const u8[:],
    expected:   const u8[:],
    check_hmac: bool = true,
) {
    var sealed: u8[>..] = [];
    for _ in plain.len + 22 { sealed.push(0); }
    let sealed_len, alert_s, ok_s = tls::record_seal_aes128_gcm_into(
        key, iv, seq, ctype, plain, sealed[..],
    );
    assert(ok_s && alert_s == tls::Alert.CloseNotify);
    assert(sealed_len == expected.len);
    assert(core::ct_eq_bytes(sealed[..sealed_len], expected));

    var dec: u8[>..] = [];
    for _ in sealed_len { dec.push(0); }
    let dec_len, dec_type, alert_d, ok_d = tls::record_decrypt_aes128_gcm_into(
        key, iv, seq, expected[..5], expected[5..], dec[..],
    );
    assert(ok_d && alert_d == tls::Alert.CloseNotify);
    assert(dec_type == ctype && dec_len == plain.len);
    assert(core::ct_eq_bytes(dec[..dec_len], plain));

    if check_hmac {
        var tampered: u8[>..] = [];
        tampered.append(expected);
        tampered[tampered.len / 2] ^= 1;
        let _, _, alert_bad, ok_bad = tls::record_decrypt_aes128_gcm_into(
            key, iv, seq, tampered[..5], tampered[5..], dec[..],
        );
        assert(!ok_bad && alert_bad == tls::Alert.BadRecordMac);
    }
}

fn build_rfc8448_ch_and_sh(ch: u8[>..]&, sh: u8[>..]&) {
    push_hex(ch, "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef");
    push_hex(ch, "6283024dece7000006130113031302010000910000000b000900000673657276");
    push_hex(ch, "6572ff01000100000a00140012001d0017001800190100010101020103010400");
    push_hex(ch, "230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e");
    push_hex(ch, "51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603");
    push_hex(ch, "020308040805080604010501060102010402050206020202002d00020101001c");
    push_hex(ch, "00024001");

    push_hex(sh, "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155");
    push_hex(sh, "772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdb");
    push_hex(sh, "f7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304");
}

fn build_rfc8448_server_cert(cert: u8[>..]&, cv: u8[>..]&) {
    push_hex(cert, "0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a");
    push_hex(cert, "864886f70d01010b0500300e310c300a06035504031303727361301e170d3136");
    push_hex(cert, "303733303031323335395a170d3236303733303031323335395a300e310c300a");
    push_hex(cert, "0603550403130372736130819f300d06092a864886f70d010101050003818d00");
    push_hex(cert, "30818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826");
    push_hex(cert, "d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced4312");
    push_hex(cert, "0998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda4308467480");
    push_hex(cert, "30530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a");
    push_hex(cert, "8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b060355");
    push_hex(cert, "1d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5");
    push_hex(cert, "b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a5");
    push_hex(cert, "8c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102");
    push_hex(cert, "702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0");
    push_hex(cert, "a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000");

    push_hex(cv, "0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145a");
    push_hex(cv, "b3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248ee");
    push_hex(cv, "aaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c");
    push_hex(cv, "9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea2");
    push_hex(cv, "0d53dfacd42f74f3");
}

fn build_rfc8448_records(flt_rec: u8[>..]&, nst: u8[>..]&, nst_rec: u8[>..]&) {
    push_hex(flt_rec, "17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35e");
    push_hex(flt_rec, "df7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78");
    push_hex(flt_rec, "b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13b");
    push_hex(flt_rec, "d9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9");
    push_hex(flt_rec, "d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2e");
    push_hex(flt_rec, "d65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd61092");
    push_hex(flt_rec, "8d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead68694");
    push_hex(flt_rec, "5ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b368");
    push_hex(flt_rec, "4596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f");
    push_hex(flt_rec, "4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26");
    push_hex(flt_rec, "f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b65962224531");
    push_hex(flt_rec, "7b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e");
    push_hex(flt_rec, "1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da");
    push_hex(flt_rec, "8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d4");
    push_hex(flt_rec, "61e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe");
    push_hex(flt_rec, "5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb");
    push_hex(flt_rec, "992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c859");
    push_hex(flt_rec, "77b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038");
    push_hex(flt_rec, "ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b84");
    push_hex(flt_rec, "5e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5");
    push_hex(flt_rec, "d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e");
    push_hex(flt_rec, "750edc53370d2b");

    push_hex(nst, "040000c90000001efad6aac502000000b22c035d829359ee5ff7af4ec9000000");
    push_hex(nst, "00262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785a");
    push_hex(nst, "bc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827");
    push_hex(nst, "db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529");
    push_hex(nst, "513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea61764");
    push_hex(nst, "6fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934a");
    push_hex(nst, "e4d3570008002a000400000400");

    push_hex(nst_rec, "17030300de3a6b8f90414a97d6959c3487680de5134a2b240e6cffac116e95d4");
    push_hex(nst_rec, "1d6af8f6b580dcf3d11d63c758db289a015940252f55713e061dc13e078891a3");
    push_hex(nst_rec, "8efbcf5753ad8ef170ad3c7353d16d9da773b9ca7f2b9fa1b6c0d4a3d03f75e0");
    push_hex(nst_rec, "9c30ba1e62972ac46f75f7b981be63439b2999ce13064615139891d5e4c5b406");
    push_hex(nst_rec, "f16e3fc181a77ca475840025db2f0a77f81b5ab05b94c01346755f69232c8651");
    push_hex(nst_rec, "9d86cbeeac87aac347d143f9605d64f650db4d023e70e952ca49fe5137121c74");
    push_hex(nst_rec, "bc2697687e248746d6df353005f3bce18696129c8153556b3b6c6779b37bf159");
    push_hex(nst_rec, "85684f");
}

fn check_rfc8448_key_exchange() -> u8[32] {
    let c_sk = copy_32(must_unhex("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005")[..]);
    let c_pk = copy_32(must_unhex("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c")[..]);
    let s_sk = copy_32(must_unhex("b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e")[..]);
    let s_pk = copy_32(must_unhex("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f")[..]);

    let c_pk_calc = core::x25519_base_scalarmult(c_sk);
    let s_pk_calc = core::x25519_base_scalarmult(s_sk);
    assert(core::ct_eq_bytes(c_pk_calc[..], c_pk[..]));
    assert(core::ct_eq_bytes(s_pk_calc[..], s_pk[..]));

    let ss_c, ok_c = core::x25519_shared_secret(c_sk, s_pk);
    let ss_s, ok_s = core::x25519_shared_secret(s_sk, c_pk);
    let exp_ss = must_unhex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    assert(ok_c && ok_s);
    assert(core::ct_eq_bytes(ss_c[..], exp_ss[..]) && core::ct_eq_bytes(ss_s[..], exp_ss[..]));
    return ss_c;
}

fn check_rfc8448_trace() {
    let shared = check_rfc8448_key_exchange();
    var ch: u8[>..] = [];
    var sh: u8[>..] = [];
    build_rfc8448_ch_and_sh(ch, sh);

    var ks, ok_ks = tls_internal::ks_init(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    assert(ok_ks && tls_internal::ks_init_early_secret(ks, []));
    assert(core::ct_eq_bytes(
        ks.current_secret[..32],
        must_unhex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")[..],
    ));

    var transcript: u8[>..] = [];
    transcript.append(ch[..]);
    transcript.append(sh[..]);
    let th_hello = core::sha256(transcript[..]);
    assert(core::ct_eq_bytes(
        th_hello[..],
        must_unhex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")[..],
    ));

    assert(tls_internal::ks_advance_to_handshake(ks, shared[..]));
    assert(core::ct_eq_bytes(
        ks.current_secret[..32],
        must_unhex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")[..],
    ));
    assert(tls_internal::ks_derive_handshake_traffic(ks, th_hello[..]));
    assert(core::ct_eq_bytes(
        ks.client_hs_traffic[..32],
        must_unhex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")[..],
    ));
    assert(core::ct_eq_bytes(
        ks.server_hs_traffic[..32],
        must_unhex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")[..],
    ));

    var s_hs_key: u8[16] = [0; 16];
    var s_hs_iv:  u8[12] = [0; 12];
    var c_hs_key: u8[16] = [0; 16];
    var c_hs_iv:  u8[12] = [0; 12];
    assert(tls_internal::ks_derive_key_iv(
        tls_internal::HASH_SHA256, ks.server_hs_traffic[..32], 16, s_hs_key[..], s_hs_iv,
    ));
    assert(tls_internal::ks_derive_key_iv(
        tls_internal::HASH_SHA256, ks.client_hs_traffic[..32], 16, c_hs_key[..], c_hs_iv,
    ));
    assert(core::ct_eq_bytes(s_hs_key[..], must_unhex("3fce516009c21727d0f2e4e86ee403bc")[..]));
    assert(core::ct_eq_bytes(s_hs_iv[..], must_unhex("5d313eb2671276ee13000b30")[..]));
    assert(core::ct_eq_bytes(c_hs_key[..], must_unhex("dbfaa693d1762c5b666af5d950258d01")[..]));
    assert(core::ct_eq_bytes(c_hs_iv[..], must_unhex("5bd3c71b836e0b76bb73265f")[..]));

    let ee = must_unhex("080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000");
    var cert: u8[>..] = [];
    var cv:   u8[>..] = [];
    build_rfc8448_server_cert(cert, cv);
    var flt_rec: u8[>..] = [];
    var nst:     u8[>..] = [];
    var nst_rec: u8[>..] = [];
    build_rfc8448_records(flt_rec, nst, nst_rec);

    transcript.append(ee[..]);
    transcript.append(cert[..]);
    transcript.append(cv[..]);
    let th_cv = core::sha256(transcript[..]);
    var s_fin: u8[32] = [0; 32];
    assert(tls_internal::ks_compute_finished_verify_data(
        tls_internal::HASH_SHA256, 32, ks.server_hs_traffic[..32], th_cv[..], s_fin[..],
    ));
    assert(core::ct_eq_bytes(
        s_fin[..],
        must_unhex("9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718")[..],
    ));

    var s_fin_msg: u8[>..] = [];
    s_fin_msg.append([0x14, 0x00, 0x00, 0x20]);
    s_fin_msg.append(s_fin[..]);
    var flight: u8[>..] = [];
    flight.append(ee[..]);
    flight.append(cert[..]);
    flight.append(cv[..]);
    flight.append(s_fin_msg[..]);
    check_record_roundtrip(s_hs_key, s_hs_iv, 0, rfc::TLS_CONTENT_HANDSHAKE, flight[..], flt_rec[..]);

    transcript.append(s_fin_msg[..]);
    let th_sf = core::sha256(transcript[..]);
    assert(core::ct_eq_bytes(
        th_sf[..],
        must_unhex("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13")[..],
    ));
    assert(tls_internal::ks_advance_to_master(ks, th_sf[..]));
    assert(core::ct_eq_bytes(
        ks.current_secret[..32],
        must_unhex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")[..],
    ));
    assert(core::ct_eq_bytes(
        ks.client_ap_traffic[..32],
        must_unhex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")[..],
    ));
    assert(core::ct_eq_bytes(
        ks.server_ap_traffic[..32],
        must_unhex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")[..],
    ));
    assert(core::ct_eq_bytes(
        ks.exporter_secret[..32],
        must_unhex("fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50")[..],
    ));

    var c_fin: u8[32] = [0; 32];
    assert(tls_internal::ks_compute_finished_verify_data(
        tls_internal::HASH_SHA256, 32, ks.client_hs_traffic[..32], th_sf[..], c_fin[..],
    ));
    var c_fin_msg: u8[>..] = [];
    c_fin_msg.append([0x14, 0x00, 0x00, 0x20]);
    c_fin_msg.append(c_fin[..]);
    var c_fin_rec: u8[>..] = [];
    push_hex(c_fin_rec, "170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc");
    push_hex(c_fin_rec, "44d87f38f80338ac98fc46deb384bd1caeacab6867d726c40546");
    check_record_roundtrip(
        c_hs_key, c_hs_iv, 0, rfc::TLS_CONTENT_HANDSHAKE, c_fin_msg[..], c_fin_rec[..],
    );

    transcript.append(c_fin_msg[..]);
    let th_cf = core::sha256(transcript[..]);
    assert(tls_internal::ks_advance_to_resumption(ks, th_cf[..]));
    assert(core::ct_eq_bytes(
        ks.resumption_secret[..32],
        must_unhex("7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c")[..],
    ));
    var res_psk: u8[32] = [0; 32];
    let nonce0: u8[2] = [0, 0];
    assert(tls_internal::ks_derive_resumption_psk(ks, nonce0[..], res_psk[..]));
    assert(core::ct_eq_bytes(
        res_psk[..],
        must_unhex("4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3")[..],
    ));

    var s_ap_key: u8[16] = [0; 16];
    var s_ap_iv:  u8[12] = [0; 12];
    var c_ap_key: u8[16] = [0; 16];
    var c_ap_iv:  u8[12] = [0; 12];
    assert(tls_internal::ks_derive_key_iv(
        tls_internal::HASH_SHA256, ks.server_ap_traffic[..32], 16, s_ap_key[..], s_ap_iv,
    ));
    assert(tls_internal::ks_derive_key_iv(
        tls_internal::HASH_SHA256, ks.client_ap_traffic[..32], 16, c_ap_key[..], c_ap_iv,
    ));
    assert(core::ct_eq_bytes(s_ap_key[..], must_unhex("9f02283b6c9c07efc26bb9f2ac92e356")[..]));
    assert(core::ct_eq_bytes(s_ap_iv[..], must_unhex("cf782b88dd83549aadf1e984")[..]));
    assert(core::ct_eq_bytes(c_ap_key[..], must_unhex("17422dda596ed5d9acd890e3c63f5051")[..]));
    assert(core::ct_eq_bytes(c_ap_iv[..], must_unhex("5b78923dee08579033e523d9")[..]));

    check_record_roundtrip(s_ap_key, s_ap_iv, 0, rfc::TLS_CONTENT_HANDSHAKE, nst[..], nst_rec[..]);

    var app_plain: u8[>..] = [];
    push_hex(app_plain, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    push_hex(app_plain, "202122232425262728292a2b2c2d2e2f3031");
    var c_app_rec: u8[>..] = [];
    push_hex(c_app_rec, "1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f");
    push_hex(c_app_rec, "2b9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae6");
    push_hex(c_app_rec, "3aeebb21694915e4");
    var s_app_rec: u8[>..] = [];
    push_hex(s_app_rec, "17030300432e937e11ef4ac740e538ad36005fc4a46932fc3225d05f82aa1b36");
    push_hex(s_app_rec, "e30efaf97d90e6dffc602dcb501a59a8fcc49c4bf2e5f0a21c0047c2abf33254");
    push_hex(s_app_rec, "0dd032e167c2955d");
    check_record_roundtrip(
        c_ap_key, c_ap_iv, 0, rfc::TLS_CONTENT_APPLICATION_DATA, app_plain[..], c_app_rec[..],
    );
    check_record_roundtrip(
        s_ap_key, s_ap_iv, 1, rfc::TLS_CONTENT_APPLICATION_DATA, app_plain[..], s_app_rec[..],
    );

    let close_plain = must_unhex("0100");
    let c_alert_rec = must_unhex("1703030013c9872760655666b74d7ff1153efd6db6d0b0e3");
    let s_alert_rec = must_unhex("1703030013b58fd67166ebf599d24720cfbe7efa7a8864a9");
    check_record_roundtrip(
        c_ap_key, c_ap_iv, 1, rfc::TLS_CONTENT_ALERT, close_plain[..], c_alert_rec[..],
    );
    check_record_roundtrip(
        s_ap_key, s_ap_iv, 2, rfc::TLS_CONTENT_ALERT, close_plain[..], s_alert_rec[..],
    );

    // Wrong sequence number (replay) must fail with BadRecordMac.
    var replay_buf: u8[128] = [0; 128];
    let _, _, replay_alert, replay_ok = tls::record_decrypt_aes128_gcm_into(
        s_ap_key, s_ap_iv, 0, s_app_rec[..5], s_app_rec[5..], replay_buf[..],
    );
    assert(!replay_ok && replay_alert == tls::Alert.BadRecordMac);
}

fn main() {
    check_rfc8448_trace();
    // CHECK: OK RFC 8448 Section 3 TLS 1.3 trace verified
    print("OK RFC 8448 Section 3 TLS 1.3 trace verified");
}
