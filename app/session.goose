// Session state, configuration, and execution pipeline for goose-wing.
namespace wing;

import std;

struct SessionConfig {
    base_url: const u8[:] = "",
    profile: Profile = Profile.None,
    proxy_url: const u8[:] = "",
    timeout_ms: i64 = 15000,
    follow_redirects: bool = true,
    cookie_jar: bool = true,
}

struct Session {
    base_url: u8[..256] = [],
    profile: Profile = Profile.None,
    proxy_url: u8[..256] = [],
    timeout_ms: i64 = 15000,
    follow_redirects: bool = true,
    default_headers: HeaderItem[..16] = [],
    jar: CookieJar = CookieJar { .. },
}

// --- Session Factories ---

fn new_session() -> Session {
    return Session { .. };
}

fn new_session(cfg: SessionConfig) -> Session {
    var s = Session {
        profile: cfg.profile,
        timeout_ms: cfg.timeout_ms,
        follow_redirects: cfg.follow_redirects,
        ..
    };
    s.base_url.append(cfg.base_url);
    s.proxy_url.append(cfg.proxy_url);
    s.jar.enabled = cfg.cookie_jar;
    return s;
}

fn new_session(base_url: const u8[:]) -> Session {
    var s = Session { .. };
    s.base_url.append(base_url);
    return s;
}

fn new_session<F: fn(Session&)>(base_url: const u8[:]) -> Session {
    var s = new_session(base_url);
    F(&s);
    return s;
}

fn new_session<F: fn(Session&)>() -> Session {
    var s = new_session();
    F(&s);
    return s;
}

// --- UFCS Session Mutators & Accessors ---

fn set_base_url(s: Session&, url: const u8[:]) {
    s.base_url.clear();
    s.base_url.append(url);
}

fn set_profile(s: Session&, p: Profile) {
    s.profile = p;
}

fn set_proxy(s: Session&, proxy_url: const u8[:]) {
    s.proxy_url.clear();
    s.proxy_url.append(proxy_url);
}

fn set_timeout_ms(s: Session&, ms: i64) {
    s.timeout_ms = ms;
}

fn set_cookie(s: Session&, name: const u8[:], value: const u8[:]) {
    var domain: u8[..128] = [];
    var path: u8[..256] = "/";
    if s.base_url.len > 0 {
        let u = parse_cookie_url(s.base_url[..]);
        domain.append(u.host[..]);
        if u.path.len > 0 { path.clear(); path.append(u.path[..]); }
    }
    set(s.jar, name, value, domain[..], path[..]);
}

fn cookie(s: const Session&, name: const u8[:]) -> const u8[:] {
    return get(s.jar, s.base_url[..], name);
}

fn default_header(s: Session&, name: const u8[:], value: const u8[:]) {
    if s.default_headers.len < 16 {
        s.default_headers.push(make_header(name, value));
    }
}

// --- URL Resolution Helper ---

fn build_effective_url(base_url: const u8[:], req_url: const u8[:], query_params: const QueryItem[:], out: u8[..512]&) {
    out.clear();
    if req_url.len >= 7 && (req_url[..7] == "http://" || (req_url.len >= 8 && req_url[..8] == "https://")) {
        out.append(req_url);
    } else {
        out.append(base_url);
        if base_url.len > 0 && base_url[base_url.len - 1] != '/' && (req_url.len == 0 || req_url[0] != '/') {
            out.push('/');
        }
        out.append(req_url);
    }

    if query_params.len > 0 {
        var has_q = false;
        for c in out {
            if c == '?' { has_q = true; break; }
        }
        for &q, idx in query_params {
            if idx == 0 && !has_q {
                out.push('?');
            } else {
                out.push('&');
            }
            out.append(q.key[..]);
            out.push('=');
            out.append(q.value[..]);
        }
    }
}

// --- Core Execution Pipeline (`session.do` & Express Verbs) ---

fn do(session: Session&, req: const Request&) -> Response, Error {
    var resp = Response { status_code: 200, .. };
    build_effective_url(session.base_url[..], req.url[..], req.query_params[..], resp.effective_url);

    let effective_timeout = if req.timeout > 0 { req.timeout } else { session.timeout_ms };

    print("[wing] ", req.method, " ", resp.effective_url);
    print("       profile=", profile_name(session.profile), " timeout=", effective_timeout, "ms");
    if session.proxy_url.len > 0 {
        print("       proxy=", session.proxy_url);
    }
    print("       User-Agent: ", profile_user_agent(session.profile));

    if session.jar.enabled && session.jar.items.len > 0 {
        var cookie_hdr: u8[..256] = [];
        build_cookie_header(session.jar, resp.effective_url[..], cookie_hdr);
        if cookie_hdr.len > 0 {
            print("       Cookie: ", cookie_hdr);
        }
    }

    for &dh in session.default_headers {
        print("       ", dh.name, ": ", dh.value);
    }
    for &h in req.headers {
        print("       ", h.name, ": ", h.value);
    }
    if req.body.len > 0 {
        print("       Body (", req.body.len, " bytes): ", req.body);
    }

    resp.headers.push(make_header("Content-Type", "application/json"));
    resp.headers.push(make_header("Server", "goose-wing-mock/0.1"));
    resp.body.append("{\"id\":1042,\"status\":\"confirmed\",\"ok\":true}");

    return resp, no_error();
}

// Last-mile closure overload: clones `req`, applies `F(&copy_req)`, and dispatches
fn do<F: fn(Request&)>(session: Session&, req: const Request&) -> Response, Error {
    var modified = copy(req);
    F(&modified);
    return do(session, modified);
}

// Express GET (plain)
fn get(session: Session&, url: const u8[:]) -> Response, Error {
    let req = new_request("GET", url);
    return do(session, req);
}

// Express GET (with trailing closure)
fn get<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("GET", url);
    F(&req);
    return do(session, req);
}

// Express POST (with trailing closure)
fn post<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("POST", url);
    F(&req);
    return do(session, req);
}

// Express POST JSON (one-liner)
fn post_json<T>(session: Session&, url: const u8[:], payload: const T&) -> Response, Error {
    var req = new_request("POST", url);
    json(req, payload);
    return do(session, req);
}

// Express PUT (with trailing closure)
fn put<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("PUT", url);
    F(&req);
    return do(session, req);
}

// Express PUT JSON (one-liner)
fn put_json<T>(session: Session&, url: const u8[:], payload: const T&) -> Response, Error {
    var req = new_request("PUT", url);
    json(req, payload);
    return do(session, req);
}

// Express DELETE (plain & trailing closure)
fn delete(session: Session&, url: const u8[:]) -> Response, Error {
    let req = new_request("DELETE", url);
    return do(session, req);
}

fn delete<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("DELETE", url);
    F(&req);
    return do(session, req);
}
