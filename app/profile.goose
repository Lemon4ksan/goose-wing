// Browser fingerprint profiles and header presets for goose-wing.
namespace wing;

import std;

enum Profile {
    None,
    Chrome131,
    Firefox133,
    Safari18,
}

struct HeaderItem {
    name: u8[..64] = [],
    value: u8[..256] = [],
}

fn make_header(name: const u8[:], value: const u8[:]) -> HeaderItem {
    var h = HeaderItem { .. };
    h.name.append(name);
    h.value.append(value);
    return h;
}

fn eq_ascii_fold(a: const u8[:], b: const u8[:]) -> bool {
    guard a.len == b.len else { return false; }
    for i in a.len {
        let ca = if a[i] >= 'A' && a[i] <= 'Z' { a[i] + 32 } else { a[i] };
        let cb = if b[i] >= 'A' && b[i] <= 'Z' { b[i] + 32 } else { b[i] };
        if ca != cb { return false; }
    }
    return true;
}

fn profile_user_agent(p: Profile) -> const u8[:] {
    return match p {
        None => "goose-wing/0.1",
        Chrome131 => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        Firefox133 => "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
        Safari18 => "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    };
}

fn profile_name(p: Profile) -> const u8[:] {
    return match p {
        None => "None",
        Chrome131 => "Chrome131",
        Firefox133 => "Firefox133",
        Safari18 => "Safari18",
    };
}
