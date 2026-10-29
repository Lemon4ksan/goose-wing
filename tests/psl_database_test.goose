// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Comprehensive verification suite for Mozilla Public Suffix List (PSL) Engine
// and RFC 6265 Cookie Scoping (Normal, Wildcard, Exception, Private, and eTLD+1).
import std;
import core from "..";
import wing from "..";

fn test_psl_rule_types_and_precedence(t: core::T&) {
    let db = wing::new_psl_database();

    t.run("Case 1: Normal ICANN Suffixes") { sub =>
        // com
        var s1: u8[..64] = [];
        let ok1, icann1 = wing::find_public_suffix(db, "example.com", s1);
        sub.assert_true(ok1, "example.com has public suffix");
        sub.assert_true(icann1, "example.com suffix is ICANN");
        sub.assert_bytes_eq(s1[..], "com", "suffix is com");
        sub.assert_false(wing::is_public_suffix(db, "example.com"), "example.com is not public suffix");
        sub.assert_true(wing::is_public_suffix(db, "com"), "com is public suffix");

        // co.uk (2-level)
        var s2: u8[..64] = [];
        let ok2, icann2 = wing::find_public_suffix(db, "service.co.uk", s2);
        sub.assert_true(ok2, "service.co.uk has public suffix");
        sub.assert_true(icann2, "co.uk suffix is ICANN");
        sub.assert_bytes_eq(s2[..], "co.uk", "suffix is co.uk");
        sub.assert_true(wing::is_public_suffix(db, "co.uk"), "co.uk is public suffix");

        // deep subdomain
        var s3: u8[..64] = [];
        let ok3, _ = wing::find_public_suffix(db, "a.b.c.service.co.uk", s3);
        sub.assert_true(ok3, "deep subdomain matched");
        sub.assert_bytes_eq(s3[..], "co.uk", "suffix remains co.uk");
    };

    t.run("Case 2: Wildcard Rules (*.ck, *.kawasaki.jp)") { sub =>
        // *.ck -> any label under ck is a public suffix
        // bar.ck -> public suffix is bar.ck
        var s1: u8[..64] = [];
        let ok1, _ = wing::find_public_suffix(db, "bar.ck", s1);
        sub.assert_true(ok1, "bar.ck matched wildcard *.ck");
        sub.assert_bytes_eq(s1[..], "bar.ck", "suffix is bar.ck");
        sub.assert_true(wing::is_public_suffix(db, "bar.ck"), "bar.ck is public suffix due to wildcard");

        // sub.bar.ck -> suffix is bar.ck, eTLD+1 is sub.bar.ck
        var s2: u8[..64] = [];
        let ok2, _ = wing::find_public_suffix(db, "sub.bar.ck", s2);
        sub.assert_true(ok2, "sub.bar.ck matched");
        sub.assert_bytes_eq(s2[..], "bar.ck", "suffix is bar.ck");

        var etld2: u8[..64] = [];
        wing::extract_etld_plus_one(db, "sub.bar.ck", etld2);
        sub.assert_bytes_eq(etld2[..], "sub.bar.ck", "eTLD+1 is sub.bar.ck");
    };

    t.run("Case 3: Exception Rules (!www.ck, !city.kawasaki.jp)") { sub =>
        // !www.ck -> exception rule overrides wildcard *.ck. Suffix is 'ck', so www.ck is registrable!
        var s1: u8[..64] = [];
        let ok1, _ = wing::find_public_suffix(db, "www.ck", s1);
        sub.assert_true(ok1, "www.ck matched exception rule");
        sub.assert_bytes_eq(s1[..], "ck", "exception rule stripped leftmost label to ck");
        sub.assert_false(wing::is_public_suffix(db, "www.ck"), "www.ck is NOT a public suffix");

        var etld1: u8[..64] = [];
        wing::extract_etld_plus_one(db, "www.ck", etld1);
        sub.assert_bytes_eq(etld1[..], "www.ck", "www.ck is eTLD+1");

        // sub.www.ck -> suffix is still 'ck', eTLD+1 is www.ck
        var s2: u8[..64] = [];
        let ok2, _ = wing::find_public_suffix(db, "sub.www.ck", s2);
        sub.assert_true(ok2, "sub.www.ck matched");
        sub.assert_bytes_eq(s2[..], "ck", "suffix is ck");

        var etld2: u8[..64] = [];
        wing::extract_etld_plus_one(db, "sub.www.ck", etld2);
        sub.assert_bytes_eq(etld2[..], "www.ck", "eTLD+1 is www.ck");
    };

    t.run("Case 4: Private Section and Tenant Isolation") { sub =>
        // github.io is Private section
        var s1: u8[..64] = [];
        let ok1, icann1 = wing::find_public_suffix(db, "alice.github.io", s1);
        sub.assert_true(ok1, "alice.github.io parsed");
        sub.assert_false(icann1, "github.io is Private section (not ICANN)");
        sub.assert_bytes_eq(s1[..], "github.io", "suffix is github.io");

        var etld_alice: u8[..64] = [];
        wing::extract_etld_plus_one(db, "alice.github.io", etld_alice);
        sub.assert_bytes_eq(etld_alice[..], "alice.github.io", "alice.github.io is isolated tenant eTLD+1");

        // Cloudfront & Pages.dev
        var s2: u8[..64] = [];
        let ok2, icann2 = wing::find_public_suffix(db, "my-site.pages.dev", s2);
        sub.assert_true(ok2, "pages.dev parsed");
        sub.assert_false(icann2, "pages.dev is Private");
        sub.assert_bytes_eq(s2[..], "pages.dev", "suffix is pages.dev");
    };

    t.run("Case 5: Default Rule (*) on Unlisted TLD") { sub =>
        var s1: u8[..64] = [];
        let ok1, icann1 = wing::find_public_suffix(db, "app.customprivatetld", s1);
        sub.assert_true(ok1, "fallback matched");
        sub.assert_true(icann1, "fallback treated as ICANN");
        sub.assert_bytes_eq(s1[..], "customprivatetld", "fallback suffix is highest label");

        var etld1: u8[..64] = [];
        wing::extract_etld_plus_one(db, "sub.app.customprivatetld", etld1);
        sub.assert_bytes_eq(etld1[..], "app.customprivatetld", "eTLD+1 for unlisted TLD");
    };
}

fn test_psl_dynamic_update_and_scoping(t: core::T&) {
    t.run("Case 1: Dynamic update_with_list parsing") { sub =>
        var db = wing::PslDatabase { rules: [] };
        let initial_count = wing::count_rules(db);
        sub.assert_eq(initial_count, 0, "empty db initially");

        let psl_text = "// ===BEGIN ICANN DOMAINS===\ncom\nco.uk\n*.sch.uk\n!special.sch.uk\n\n// ===BEGIN PRIVATE DOMAINS===\ninternal.corp\n";

        wing::update_with_list(db, psl_text);
        sub.assert_eq(wing::count_rules(db), 5, "5 rules parsed");

        // Verify normal
        sub.assert_true(wing::is_public_suffix(db, "com"), "com is public suffix");
        sub.assert_true(wing::is_public_suffix(db, "co.uk"), "co.uk is public suffix");

        // Verify wildcard *.sch.uk
        var s_sch: u8[..64] = [];
        let ok_sch, _ = wing::find_public_suffix(db, "grammar.sch.uk", s_sch);
        sub.assert_true(ok_sch, "grammar.sch.uk matched wildcard");
        sub.assert_bytes_eq(s_sch[..], "grammar.sch.uk", "suffix is grammar.sch.uk");

        // Verify exception !special.sch.uk
        var s_sp: u8[..64] = [];
        let ok_sp, _ = wing::find_public_suffix(db, "special.sch.uk", s_sp);
        sub.assert_true(ok_sp, "special.sch.uk matched exception");
        sub.assert_bytes_eq(s_sp[..], "sch.uk", "exception stripped leftmost label to sch.uk");

        // Verify private
        var s_corp: u8[..64] = [];
        let ok_corp, icann_corp = wing::find_public_suffix(db, "node.internal.corp", s_corp);
        sub.assert_true(ok_corp, "internal.corp matched");
        sub.assert_false(icann_corp, "internal.corp is Private");
        sub.assert_bytes_eq(s_corp[..], "internal.corp", "suffix is internal.corp");
    };

    t.run("Case 2: RFC 6265 Cookie Domain Match with PSL Rejection") { sub =>
        let db = wing::new_psl_database();

        // Valid domain matches
        sub.assert_true(wing::cookie_domain_match(db, "app.example.com", "example.com"), "subdomain matches parent domain");
        sub.assert_true(wing::cookie_domain_match(db, "example.com", "example.com"), "exact host matches domain");

        // Rejection: cookie domain is public suffix
        sub.assert_false(wing::cookie_domain_match(db, "app.example.com", "com"), "reject cookie domain 'com' (public suffix)");
        sub.assert_false(wing::cookie_domain_match(db, "app.example.co.uk", "co.uk"), "reject cookie domain 'co.uk' (public suffix)");
        sub.assert_false(wing::cookie_domain_match(db, "alice.github.io", "github.io"), "reject cookie domain 'github.io' (private suffix)");

        // Suffix collision
        sub.assert_false(wing::cookie_domain_match(db, "badexample.com", "example.com"), "reject suffix collision without dot boundary");
    };

    t.run("Case 3: Case-insensitivity and edge dots normalization") { sub =>
        let db = wing::new_psl_database();

        var s1: u8[..64] = [];
        let ok1, _ = wing::find_public_suffix(db, ".EXAMPLE.COM.", s1);
        sub.assert_true(ok1, "domain with leading and trailing dot parsed");
        sub.assert_bytes_eq(s1[..], "com", "suffix normalized to com");

        var etld1: u8[..64] = [];
        wing::extract_etld_plus_one(db, ".SUB.EXAMPLE.CO.UK.", etld1);
        sub.assert_bytes_eq(etld1[..], "example.co.uk", "eTLD+1 normalized to example.co.uk");
    };
}

fn main() {
    var runner = core::new_runner("Mozilla Public Suffix List (PSL) Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. PSL Rule Types and Precedence (Normal, Wildcard, Exception, Private)", test_psl_rule_types_and_precedence);
    core::run_case(runner, "2. PSL Dynamic Update and RFC 6265 Scoping", test_psl_dynamic_update_and_scoping);
    let ok = core::finish(runner);
    assert(ok);
}
