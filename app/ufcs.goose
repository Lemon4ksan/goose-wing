// Global UFCS bridges so callers outside `namespace wing` can invoke
// `req.header(...)`, `session.post(...) { req => ... }`, and `res.is_success()`
// using natural method-call syntax (`val.f(arg)` -> `::f(val, arg)`).
namespace wing;

// --- Session UFCS bridges ---

fn ::set_base_url(session: wing::Session&, url: const u8[:]) { wing::set_base_url(session, url); }
fn ::set_profile(session: wing::Session&, profile: wing::Profile) { wing::set_profile(session, profile); }
fn ::set_proxy(session: wing::Session&, proxy_url: const u8[:]) { wing::set_proxy(session, proxy_url); }
fn ::set_timeout_ms(session: wing::Session&, timeout_millis: i64) { wing::set_timeout_ms(session, timeout_millis); }
fn ::set_cookie(session: wing::Session&, name: const u8[:], value: const u8[:]) { wing::set_cookie(session, name, value); }
fn ::cookie(session: const wing::Session&, name: const u8[:]) -> const u8[:] { return wing::cookie(session, name); }
fn ::default_header(session: wing::Session&, name: const u8[:], value: const u8[:]) { wing::default_header(session, name, value); }

fn ::do(session: wing::Session&, req: const wing::Request&) -> wing::Response, wing::Error {
    return wing::do(session, req);
}

fn ::do<BuilderFn: fn(wing::Request&)>(session: wing::Session&, req: const wing::Request&) -> wing::Response, wing::Error {
    return wing::do(session, req, BuilderFn);
}

fn ::get(session: wing::Session&, url: const u8[:]) -> wing::Response, wing::Error {
    return wing::get(session, url);
}

fn ::get<BuilderFn: fn(wing::Request&)>(session: wing::Session&, url: const u8[:]) -> wing::Response, wing::Error {
    return wing::get(session, url, BuilderFn);
}

fn ::post<BuilderFn: fn(wing::Request&)>(session: wing::Session&, url: const u8[:]) -> wing::Response, wing::Error {
    return wing::post(session, url, BuilderFn);
}

fn ::post_json<T>(session: wing::Session&, url: const u8[:], payload: const T&) -> wing::Response, wing::Error {
    return wing::post_json(session, url, payload);
}

fn ::put<BuilderFn: fn(wing::Request&)>(session: wing::Session&, url: const u8[:]) -> wing::Response, wing::Error {
    return wing::put(session, url, BuilderFn);
}

fn ::put_json<T>(session: wing::Session&, url: const u8[:], payload: const T&) -> wing::Response, wing::Error {
    return wing::put_json(session, url, payload);
}

fn ::delete(session: wing::Session&, url: const u8[:]) -> wing::Response, wing::Error {
    return wing::delete(session, url);
}

fn ::delete<BuilderFn: fn(wing::Request&)>(session: wing::Session&, url: const u8[:]) -> wing::Response, wing::Error {
    return wing::delete(session, url, BuilderFn);
}

// --- Request UFCS bridges ---

fn ::header(req: wing::Request&, name: const u8[:], value: const u8[:]) { wing::header(req, name, value); }
fn ::set_header(req: wing::Request&, name: const u8[:], value: const u8[:]) { wing::set_header(req, name, value); }
fn ::bearer(req: wing::Request&, token: const u8[:]) { wing::bearer(req, token); }
fn ::set_bearer(req: wing::Request&, token: const u8[:]) { wing::set_bearer(req, token); }
fn ::query(req: wing::Request&, key: const u8[:], value: const u8[:]) { wing::query(req, key, value); }
fn ::set_query(req: wing::Request&, key: const u8[:], value: const u8[:]) { wing::set_query(req, key, value); }
fn ::timeout_ms(req: wing::Request&, timeout_millis: i64) { wing::timeout_ms(req, timeout_millis); }
fn ::set_timeout_ms(req: wing::Request&, timeout_millis: i64) { wing::set_timeout_ms(req, timeout_millis); }
fn ::text(req: wing::Request&, body_str: const u8[:]) { wing::text(req, body_str); }
fn ::raw_json(req: wing::Request&, json_str: const u8[:]) { wing::raw_json(req, json_str); }
fn ::json<T>(req: wing::Request&, payload: const T&) { wing::json(req, payload); }
fn ::set_json<T>(req: wing::Request&, payload: const T&) { wing::set_json(req, payload); }

// --- Response & Error UFCS bridges ---

fn ::ok(err: const wing::Error&) -> bool { return wing::ok(err); }
fn ::is_success(res: const wing::Response&) -> bool { return wing::is_success(res); }
fn ::is_redirect(res: const wing::Response&) -> bool { return wing::is_redirect(res); }
fn ::header(res: const wing::Response&, name: const u8[:]) -> const u8[:] { return wing::header(res, name); }
fn ::text(res: const wing::Response&) -> const u8[:] { return wing::text(res); }
fn ::json<T>(res: const wing::Response&, out: T&) -> wing::Error { return wing::json(res, out); }
fn ::decode_json<T>(res: const wing::Response&) -> T, wing::Error { return wing::decode_json<T>(res); }

// --- CookieJar UFCS bridges ---

fn ::set(jar: wing::CookieJar&, name: const u8[:], value: const u8[:], domain: const u8[:], path: const u8[:]) {
    wing::set(jar, name, value, domain, path);
}
fn ::get(jar: const wing::CookieJar&, req_url: const u8[:], name: const u8[:]) -> const u8[:] {
    return wing::get(jar, req_url, name);
}
fn ::get(jar: const wing::CookieJar&, name: const u8[:]) -> const u8[:] {
    return wing::get(jar, name);
}
fn ::set_cookie_header(jar: wing::CookieJar&, req_url: const u8[:], set_cookie_raw: const u8[:]) -> bool {
    return wing::set_cookie_header(jar, req_url, set_cookie_raw);
}
fn ::build_cookie_header<B>(jar: wing::CookieJar&, req_url: const u8[:], out: B&) {
    wing::build_cookie_header(jar, req_url, out);
}
fn ::count(jar: const wing::CookieJar&) -> i64 {
    return wing::count(jar);
}
fn ::clear(jar: wing::CookieJar&) {
    wing::clear(jar);
}
fn ::clear_session_cookies(jar: wing::CookieJar&) {
    wing::clear_session_cookies(jar);
}
fn ::set_partition_key(jar: wing::CookieJar&, key: const u8[:]) {
    wing::set_partition_key(jar, key);
}
fn ::set_proxy_key(jar: wing::CookieJar&, key: const u8[:]) {
    wing::set_proxy_key(jar, key);
}
fn ::add_public_suffix(jar: wing::CookieJar&, suffix: const u8[:]) {
    wing::add_public_suffix(jar, suffix);
}
fn ::mirror(jar: wing::CookieJar&, source_url: const u8[:], target_url: const u8[:], cookie_names: const u8[:][:]) {
    wing::mirror(jar, source_url, target_url, cookie_names);
}
fn ::export_netscape<B>(jar: wing::CookieJar&, req_url: const u8[:], out: B&) {
    wing::export_netscape(jar, req_url, out);
}
fn ::export_json(jar: wing::CookieJar&, req_url: const u8[:], out: u8[>..]&) {
    wing::export_json(jar, req_url, out);
}
fn ::import_json(jar: wing::CookieJar&, target_url: const u8[:], json_text: const u8[:]) -> i64 {
    return wing::import_json(jar, target_url, json_text);
}

// --- Time & Duration UFCS bridges ---

fn ::as_nanos(dur: wing::Duration) -> i64 { return wing::as_nanos(dur); }
fn ::as_micros(dur: wing::Duration) -> i64 { return wing::as_micros(dur); }
fn ::as_millis(dur: wing::Duration) -> i64 { return wing::as_millis(dur); }
fn ::as_secs(dur: wing::Duration) -> i64 { return wing::as_secs(dur); }
fn ::as_mins(dur: wing::Duration) -> i64 { return wing::as_mins(dur); }
fn ::as_hours(dur: wing::Duration) -> i64 { return wing::as_hours(dur); }
fn ::as_days(dur: wing::Duration) -> i64 { return wing::as_days(dur); }
fn ::as_secs_f64(dur: wing::Duration) -> f64 { return wing::as_secs_f64(dur); }
fn ::as_mins_f64(dur: wing::Duration) -> f64 { return wing::as_mins_f64(dur); }
fn ::as_hours_f64(dur: wing::Duration) -> f64 { return wing::as_hours_f64(dur); }

fn ::nanoseconds(dur: wing::Duration) -> i64 { return wing::nanoseconds(dur); }
fn ::microseconds(dur: wing::Duration) -> i64 { return wing::microseconds(dur); }
fn ::milliseconds(dur: wing::Duration) -> i64 { return wing::milliseconds(dur); }
fn ::seconds(dur: wing::Duration) -> f64 { return wing::seconds(dur); }
fn ::minutes(dur: wing::Duration) -> f64 { return wing::minutes(dur); }
fn ::hours(dur: wing::Duration) -> f64 { return wing::hours(dur); }

fn ::add(dur1: wing::Duration, dur2: wing::Duration) -> wing::Duration { return wing::add(dur1, dur2); }
fn ::sub(dur1: wing::Duration, dur2: wing::Duration) -> wing::Duration { return wing::sub(dur1, dur2); }
fn ::mul(dur: wing::Duration, factor: i64) -> wing::Duration { return wing::mul(dur, factor); }
fn ::div(dur: wing::Duration, factor: i64) -> wing::Duration { return wing::div(dur, factor); }
fn ::abs(dur: wing::Duration) -> wing::Duration { return wing::abs(dur); }

// Goose stdlib naming conventions (no is_ prefix) and compatibility aliases

fn ::zero(dur: wing::Duration) -> bool { return wing::zero(dur); }
fn ::is_zero(dur: wing::Duration) -> bool { return wing::is_zero(dur); }
fn ::negative(dur: wing::Duration) -> bool { return wing::negative(dur); }
fn ::is_negative(dur: wing::Duration) -> bool { return wing::is_negative(dur); }
fn ::positive(dur: wing::Duration) -> bool { return wing::positive(dur); }
fn ::is_positive(dur: wing::Duration) -> bool { return wing::is_positive(dur); }

fn ::truncate(dur: wing::Duration, step_dur: wing::Duration) -> wing::Duration { return wing::truncate(dur, step_dur); }
fn ::round(dur: wing::Duration, step_dur: wing::Duration) -> wing::Duration { return wing::round(dur, step_dur); }
fn ::format<B>(out: B&, dur: wing::Duration) { wing::format(out, dur); }

// Time inspectors

fn ::year(time_val: wing::Time) -> i64 { return wing::year(time_val); }
fn ::month(time_val: wing::Time) -> wing::Month { return wing::month(time_val); }
fn ::month_number(time_val: wing::Time) -> i64 { return wing::month_number(time_val); }
fn ::day(time_val: wing::Time) -> i64 { return wing::day(time_val); }
fn ::weekday(time_val: wing::Time) -> wing::Weekday { return wing::weekday(time_val); }
fn ::clock(time_val: wing::Time) -> i64, i64, i64 { return wing::clock(time_val); }
fn ::hour(time_val: wing::Time) -> i64 { return wing::hour(time_val); }
fn ::minute(time_val: wing::Time) -> i64 { return wing::minute(time_val); }
fn ::second(time_val: wing::Time) -> i64 { return wing::second(time_val); }
fn ::nanosecond(time_val: wing::Time) -> i64 { return wing::nanosecond(time_val); }
fn ::unix(time_val: wing::Time) -> i64 { return wing::unix(time_val); }
fn ::unix_milli(time_val: wing::Time) -> i64 { return wing::unix_milli(time_val); }
fn ::unix_micro(time_val: wing::Time) -> i64 { return wing::unix_micro(time_val); }
fn ::unix_nano(time_val: wing::Time) -> i64 { return wing::unix_nano(time_val); }
fn ::zero(time_val: wing::Time) -> bool { return wing::zero(time_val); }
fn ::is_zero(time_val: wing::Time) -> bool { return wing::is_zero(time_val); }

// Time arithmetic

fn ::add(time_val: wing::Time, dur: wing::Duration) -> wing::Time { return wing::add(time_val, dur); }
fn ::sub(time_val: wing::Time, other_time: wing::Time) -> wing::Duration { return wing::sub(time_val, other_time); }
fn ::sub(time_val: wing::Time, dur: wing::Duration) -> wing::Time { return wing::sub(time_val, dur); }
fn ::sub_duration(time_val: wing::Time, dur: wing::Duration) -> wing::Time { return wing::sub_duration(time_val, dur); }
fn ::since(time_val: wing::Time) -> wing::Duration { return wing::since(time_val); }
fn ::until(time_val: wing::Time) -> wing::Duration { return wing::until(time_val); }
fn ::equal(time_val: wing::Time, other_time: wing::Time) -> bool { return wing::equal(time_val, other_time); }
fn ::before(time_val: wing::Time, other_time: wing::Time) -> bool { return wing::before(time_val, other_time); }
fn ::after(time_val: wing::Time, other_time: wing::Time) -> bool { return wing::after(time_val, other_time); }
fn ::compare(time_val: wing::Time, other_time: wing::Time) -> i64 { return wing::compare(time_val, other_time); }
fn ::truncate(time_val: wing::Time, dur: wing::Duration) -> wing::Time { return wing::truncate(time_val, dur); }
fn ::round(time_val: wing::Time, dur: wing::Duration) -> wing::Time { return wing::round(time_val, dur); }

// Timezones

fn ::utc(time_val: wing::Time) -> wing::Time { return wing::utc(time_val); }
fn ::in_offset(time_val: wing::Time, tz_offset_seconds: i32) -> wing::Time { return wing::in_offset(time_val, tz_offset_seconds); }
fn ::in_tz(time_val: wing::Time, hours_offset: i64, minutes_offset: i64 = 0) -> wing::Time { return wing::in_tz(time_val, hours_offset, minutes_offset); }
fn ::tz_offset(time_val: wing::Time) -> i32 { return wing::tz_offset(time_val); }

// Calendar Math & Navigation

fn ::add_months_clamped(time_val: wing::Time, months_count: i64) -> wing::Time { return wing::add_months_clamped(time_val, months_count); }
fn ::add_years_clamped(time_val: wing::Time, years_count: i64) -> wing::Time { return wing::add_years_clamped(time_val, years_count); }
fn ::days_in_month(time_val: wing::Time) -> i64 { return wing::days_in_month(time_val); }
fn ::days_in_year(time_val: wing::Time) -> i64 { return wing::days_in_year(time_val); }
fn ::leap_year(time_val: wing::Time) -> bool { return wing::leap_year(time_val); }
fn ::is_leap_year(time_val: wing::Time) -> bool { return wing::is_leap_year(time_val); }

fn ::start_of_day(time_val: wing::Time) -> wing::Time { return wing::start_of_day(time_val); }
fn ::end_of_day(time_val: wing::Time) -> wing::Time { return wing::end_of_day(time_val); }
fn ::start_of_month(time_val: wing::Time) -> wing::Time { return wing::start_of_month(time_val); }
fn ::end_of_month(time_val: wing::Time) -> wing::Time { return wing::end_of_month(time_val); }
fn ::start_of_year(time_val: wing::Time) -> wing::Time { return wing::start_of_year(time_val); }
fn ::end_of_year(time_val: wing::Time) -> wing::Time { return wing::end_of_year(time_val); }

// Formatting

fn ::format_rfc3339<B>(out: B&, time_val: wing::Time) { wing::format_rfc3339(out, time_val); }
fn ::format_rfc3339_nano<B>(out: B&, time_val: wing::Time) { wing::format_rfc3339_nano(out, time_val); }
fn ::format_http<B>(out: B&, time_val: wing::Time) { wing::format_http(out, time_val); }

// Stopwatch

fn ::elapsed(watch: const wing::Stopwatch&) -> wing::Duration { return wing::elapsed(watch); }
fn ::restart(watch: wing::Stopwatch&) -> wing::Duration { return wing::restart(watch); }

// Deadline Primitives

fn ::expired(deadline_val: const wing::Deadline&) -> bool { return wing::expired(deadline_val); }
fn ::is_expired(deadline_val: const wing::Deadline&) -> bool { return wing::is_expired(deadline_val); }
fn ::remaining(deadline_val: const wing::Deadline&) -> wing::Duration { return wing::remaining(deadline_val); }

// Policy Bridges (Backoff & RateLimiter)

fn ::delay(backoff: const wing::Backoff&, attempt: i64) -> wing::Duration { return wing::delay(backoff, attempt); }
fn ::allow(limiter: wing::RateLimiter&) -> bool { return wing::allow(limiter); }

// --- CanonicalCookie & CanonicalCookieJar UFCS bridges ---

fn ::add(jar: wing::CanonicalCookieJar&, name: const u8[:], val: const u8[:]) -> wing::CanonicalCookie& {
    return wing::add(jar, name, val);
}

fn ::with_value(cookie_val: wing::CanonicalCookie&, val: const u8[:]) -> wing::CanonicalCookie& {
    return wing::with_value(cookie_val, val);
}

fn ::with_domain(cookie_val: wing::CanonicalCookie&, domain_val: const u8[:], host_only: bool = false) -> wing::CanonicalCookie& {
    return wing::with_domain(cookie_val, domain_val, host_only);
}

fn ::with_host(cookie_val: wing::CanonicalCookie&, host_val: const u8[:]) -> wing::CanonicalCookie& {
    return wing::with_host(cookie_val, host_val);
}

fn ::with_path(cookie_val: wing::CanonicalCookie&, path_val: const u8[:]) -> wing::CanonicalCookie& {
    return wing::with_path(cookie_val, path_val);
}

fn ::with_secure(cookie_val: wing::CanonicalCookie&, secure_flag: bool = true) -> wing::CanonicalCookie& {
    return wing::with_secure(cookie_val, secure_flag);
}

fn ::with_http_only(cookie_val: wing::CanonicalCookie&, http_only_flag: bool = true) -> wing::CanonicalCookie& {
    return wing::with_http_only(cookie_val, http_only_flag);
}

fn ::with_same_site(cookie_val: wing::CanonicalCookie&, same_site_mode: wing::CookieSameSite) -> wing::CanonicalCookie& {
    return wing::with_same_site(cookie_val, same_site_mode);
}

fn ::with_priority(cookie_val: wing::CanonicalCookie&, priority_level: wing::CookiePriority) -> wing::CanonicalCookie& {
    return wing::with_priority(cookie_val, priority_level);
}

fn ::with_partition_key(cookie_val: wing::CanonicalCookie&, key: const u8[:]) -> wing::CanonicalCookie& {
    return wing::with_partition_key(cookie_val, key);
}

fn ::with_max_age_seconds(cookie_val: wing::CanonicalCookie&, seconds: i64, now_us: i64) -> wing::CanonicalCookie& {
    return wing::with_max_age_seconds(cookie_val, seconds, now_us);
}

fn ::with_expires_utc(cookie_val: wing::CanonicalCookie&, expires_us: i64) -> wing::CanonicalCookie& {
    return wing::with_expires_utc(cookie_val, expires_us);
}

fn ::with_source(cookie_val: wing::CanonicalCookie&, scheme: wing::CookieSourceScheme, port: i32) -> wing::CanonicalCookie& {
    return wing::with_source(cookie_val, scheme, port);
}

fn ::purge_expired(jar: wing::CanonicalCookieJar&, now_us: i64) -> i64 {
    return wing::purge_expired(jar, now_us);
}

fn ::build_cookie_header<B>(
    jar: wing::CanonicalCookieJar&,
    out: B&,
    host: const u8[:],
    path: const u8[:],
    is_secure: bool,
    now_us: i64
) {
    wing::build_cookie_header(jar, out, host, path, is_secure, now_us);
}

fn ::build_cookie_header<B>(
    jar: wing::CanonicalCookieJar&,
    req_url: const u8[:],
    out: B&,
    now_us: i64,
    partition_key: const u8[:] = ""
) {
    wing::build_cookie_header(jar, req_url, out, now_us, partition_key);
}

fn ::set_cookie_header(
    jar: wing::CanonicalCookieJar&,
    req_url: const u8[:],
    set_cookie_raw: const u8[:],
    now_us: i64,
    is_http_api: bool = true,
    partition_key: const u8[:] = ""
) -> bool {
    return wing::set_cookie_header(jar, req_url, set_cookie_raw, now_us, is_http_api, partition_key);
}

fn ::new_canonical_cookie(name: const u8[:], val: const u8[:]) -> wing::CanonicalCookie {
    return wing::new_canonical_cookie(name, val);
}

fn ::set(jar: wing::CanonicalCookieJar&, cookie_val: wing::CanonicalCookie, now_us: i64) -> bool {
    return wing::set(jar, cookie_val, now_us);
}

fn ::insert(jar: wing::CanonicalCookieJar&, cookie_val: wing::CanonicalCookie, now_us: i64) -> bool {
    return wing::insert(jar, cookie_val, now_us);
}

fn ::get(
    jar: wing::CanonicalCookieJar&,
    req_url: const u8[:],
    name: const u8[:],
    now_us: i64,
    is_same_site: bool = true,
    is_top_level_navigation: bool = true,
    is_safe_method: bool = true,
    partition_key: const u8[:] = ""
) -> const u8[:] {
    return wing::get(jar, req_url, name, now_us, is_same_site, is_top_level_navigation, is_safe_method, partition_key);
}

fn ::get(jar: const wing::CanonicalCookieJar&, name: const u8[:]) -> const u8[:] {
    return wing::get(jar, name);
}

fn ::export_netscape<B>(jar: const wing::CanonicalCookieJar&, out: B&) {
    wing::export_canonical_netscape(jar, out);
}

fn ::import_netscape(jar: wing::CanonicalCookieJar&, content: const u8[:], now_us: i64) -> i64 {
    return wing::import_canonical_netscape(jar, content, now_us);
}

fn ::export_json<B>(jar: const wing::CanonicalCookieJar&, out: B&) {
    wing::export_canonical_json(jar, out);
}

fn ::import_json(jar: wing::CanonicalCookieJar&, json_text: const u8[:], now_us: i64) -> i64 {
    return wing::import_canonical_json(jar, json_text, now_us);
}

// --- URL & Origin UFCS Bridges ---

fn ::scheme(u: const wing::Url&) -> const u8[:] { return wing::scheme(u); }
fn ::host(u: const wing::Url&) -> const u8[:] { return wing::host(u); }
fn ::port(u: const wing::Url&) -> i32 { return wing::effective_port(u); }
fn ::effective_port(u: const wing::Url&) -> i32 { return wing::effective_port(u); }
fn ::pathname(u: const wing::Url&) -> const u8[:] { return wing::pathname(u); }
fn ::path(u: const wing::Url&) -> const u8[:] { return wing::pathname(u); }
fn ::search(u: const wing::Url&) -> const u8[:] { return wing::search(u); }
fn ::origin(u: const wing::Url&) -> wing::Origin { return wing::origin_from_url(u); }
fn ::is_special(u: const wing::Url&) -> bool { return wing::is_special(u); }

fn ::is_opaque(o: const wing::Origin&) -> bool { return o.kind == wing::OriginKind.Opaque; }
fn ::is_same_origin(o1: const wing::Origin&, o2: const wing::Origin&) -> bool { return wing::is_same_origin(o1, o2); }
fn ::serialize<B>(o: const wing::Origin&, out: B&) { wing::serialize_origin(o, out); }

// --- File & Path UFCS Bridges ---

fn ::is_file_url(u: const wing::Url&) -> bool { return wing::is_file_url(u); }
fn ::file_path<B>(u: const wing::Url&, out: B&) -> bool { return wing::file_path(u, out); }
fn ::last_path_component(u: const wing::Url&) -> const u8[:] { return wing::last_path_component(u); }
fn ::path_extension(u: const wing::Url&) -> const u8[:] { return wing::path_extension(u); }
fn ::deleting_path_extension(u: wing::Url) -> wing::Url { return wing::deleting_path_extension(u); }
fn ::deleting_last_path_component(u: wing::Url) -> wing::Url { return wing::deleting_last_path_component(u); }
fn ::appending_path_component(u: wing::Url, component: const u8[:]) -> wing::Url { return wing::appending_path_component(u, component); }
fn ::appending(u: wing::Url, component: const u8[:]) -> wing::Url { return wing::appending_path_component(u, component); }
fn ::appending_path(u: wing::Url, subpath: const u8[:]) -> wing::Url { return wing::appending_path(u, subpath); }
fn ::appending_path_extension(u: wing::Url, ext: const u8[:]) -> wing::Url { return wing::appending_path_extension(u, ext); }

// --- SiteForCookies UFCS Bridges ---

fn ::is_null(sfc: const wing::SiteForCookies&) -> bool { return sfc.is_null; }
fn ::is_first_party(sfc: const wing::SiteForCookies&, url_str: const u8[:], compute_schemefully: bool = true) -> bool {
    return wing::is_first_party(sfc, url_str, compute_schemefully);
}
fn ::format_site_for_cookies<B>(out: B&, sfc: const wing::SiteForCookies&) { wing::format_site_for_cookies(out, sfc); }

// --- Request, Response, Session UFCS Bridges ---

fn ::initiator(req: wing::Request&, origin_val: const wing::Origin&) { wing::set_initiator(req, origin_val); }
fn ::set_initiator(req: wing::Request&, origin_val: const wing::Origin&) { wing::set_initiator(req, origin_val); }
fn ::site_for_cookies(req: wing::Request&, sfc: const wing::SiteForCookies&) { wing::set_site_for_cookies(req, sfc); }
fn ::set_site_for_cookies(req: wing::Request&, sfc: const wing::SiteForCookies&) { wing::set_site_for_cookies(req, sfc); }
fn ::first_party_policy(req: wing::Request&, policy: wing::FirstPartyURLPolicy) { wing::set_first_party_policy(req, policy); }
fn ::set_first_party_policy(req: wing::Request&, policy: wing::FirstPartyURLPolicy) { wing::set_first_party_policy(req, policy); }
fn ::sensitive_header(req: wing::Request&, name: const u8[:], value: const u8[:]) { wing::sensitive_header(req, name, value); }
fn ::set_stream_body(req: wing::Request&, body_bytes: const u8[:], rewindable: bool = false) { wing::set_stream_body(req, body_bytes, rewindable); }

fn ::redirect_count(res: const wing::Response&) -> i64 { return res.redirect_count; }
fn ::final_method(res: const wing::Response&) -> const u8[:] { return res.final_method[..]; }
fn ::sent_header(res: const wing::Response&, name: const u8[:]) -> const u8[:] { return wing::sent_header(res, name); }

fn ::set_redirect_mode(session: wing::Session&, mode: wing::RedirectMode) {
    wing::set_redirect_mode(session, mode);
}
fn ::set_max_redirects(session: wing::Session&, count: i64) {
    wing::set_max_redirects(session, count);
}
fn ::set_referrer_policy(session: wing::Session&, policy: wing::ReferrerPolicy) {
    wing::set_referrer_policy(session, policy);
}
fn ::set_clock_us(session: wing::Session&, clock_us: i64) {
    wing::set_clock_us(session, clock_us);
}
fn ::enable_ssrf_guard(session: wing::Session&, deny_local_network: bool = true) {
    wing::enable_ssrf_guard(session, deny_local_network);
}
fn ::mock_route(
    session: wing::Session&,
    method: const u8[:],
    url: const u8[:],
    status: i32,
    body: const u8[:]
) -> wing::MockExchange& {
    return wing::mock_route(session, method, url, status, body);
}
fn ::mock_route(
    session: wing::Session&,
    url: const u8[:],
    status: i32,
    body: const u8[:]
) -> wing::MockExchange& {
    return wing::mock_route(session, "", url, status, body);
}
fn ::execute_request(session: wing::Session&, req: const wing::Request&) -> wing::Response, wing::Error {
    return wing::execute_request(session, req);
}

fn ::add_mock_header(session: wing::Session&, name: const u8[:], value: const u8[:]) {
    wing::add_mock_header(session, name, value);
}
fn ::add_mock_set_cookie(session: wing::Session&, set_cookie_raw: const u8[:]) {
    wing::add_mock_set_cookie(session, set_cookie_raw);
}
fn ::add_mock_resolved_ip(session: wing::Session&, ip_str: const u8[:]) {
    wing::add_mock_resolved_ip(session, ip_str);
}
