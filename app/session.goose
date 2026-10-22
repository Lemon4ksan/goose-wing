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

// ---- session factories ----

fn new_session() -> Session {
    return Session { .. };
}

fn new_session(cfg: SessionConfig) -> Session {
    var session = Session {
        profile: cfg.profile,
        timeout_ms: cfg.timeout_ms,
        follow_redirects: cfg.follow_redirects,
        ..
    };
    session.base_url.append(cfg.base_url);
    session.proxy_url.append(cfg.proxy_url);
    session.jar.enabled = cfg.cookie_jar;
    return session;
}

fn new_session(base_url: const u8[:]) -> Session {
    var session = Session { .. };
    session.base_url.append(base_url);
    return session;
}

fn new_session<F: fn(Session&)>(base_url: const u8[:]) -> Session {
    var session = new_session(base_url);
    F(&session);
    return session;
}

fn new_session<F: fn(Session&)>() -> Session {
    var session = new_session();
    F(&session);
    return session;
}

// ---- ufcs session mutators & accessors ----

fn set_base_url(session: Session&, url: const u8[:]) {
    session.base_url.clear();
    session.base_url.append(url);
}

fn set_profile(session: Session&, profile: Profile) {
    session.profile = profile;
}

fn set_proxy(session: Session&, proxy_url: const u8[:]) {
    session.proxy_url.clear();
    session.proxy_url.append(proxy_url);
}

fn set_timeout_ms(session: Session&, ms: i64) {
    session.timeout_ms = ms;
}

fn set_cookie(session: Session&, name: const u8[:], value: const u8[:]) {
    var domain: u8[..128] = [];
    var path: u8[..256] = "/";
    if session.base_url.len > 0 {
        let parsed_url = parse_cookie_url(session.base_url[..]);
        domain.append(parsed_url.host[..]);
        if parsed_url.path.len > 0 { path.clear(); path.append(parsed_url.path[..]); }
    }
    set(session.jar, name, value, domain[..], path[..]);
}

fn cookie(session: const Session&, name: const u8[:]) -> const u8[:] {
    return get(session.jar, session.base_url[..], name);
}

fn default_header(session: Session&, name: const u8[:], value: const u8[:]) {
    if session.default_headers.len < 16 {
        session.default_headers.push(make_header(name, value));
    }
}

// ---- url resolution helper ----

fn build_effective_url(
    base_url: const u8[:],
    req_url: const u8[:],
    query_params: const QueryItem[:],
    out: u8[..512]&
) {
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
        var has_query_mark = false;
        for char_byte in out {
            if char_byte == '?' { has_query_mark = true; break; }
        }
        for &query_item, param_idx in query_params {
            if param_idx == 0 && !has_query_mark {
                out.push('?');
            } else {
                out.push('&');
            }
            out.append(query_item.key[..]);
            out.push('=');
            out.append(query_item.value[..]);
        }
    }
}

// ---- core execution pipeline ----

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

    for &default_header_entry in session.default_headers {
        print("       ", default_header_entry.name, ": ", default_header_entry.value);
    }
    for &header_entry in req.headers {
        print("       ", header_entry.name, ": ", header_entry.value);
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

// ---- express verbs ----

fn get(session: Session&, url: const u8[:]) -> Response, Error {
    let req = new_request("GET", url);
    return do(session, req);
}

fn get<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("GET", url);
    F(&req);
    return do(session, req);
}

fn post<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("POST", url);
    F(&req);
    return do(session, req);
}

fn post_json<T>(session: Session&, url: const u8[:], payload: const T&) -> Response, Error {
    var req = new_request("POST", url);
    json(req, payload);
    return do(session, req);
}

fn put<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("PUT", url);
    F(&req);
    return do(session, req);
}

fn put_json<T>(session: Session&, url: const u8[:], payload: const T&) -> Response, Error {
    var req = new_request("PUT", url);
    json(req, payload);
    return do(session, req);
}

fn delete(session: Session&, url: const u8[:]) -> Response, Error {
    let req = new_request("DELETE", url);
    return do(session, req);
}

fn delete<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("DELETE", url);
    F(&req);
    return do(session, req);
}
