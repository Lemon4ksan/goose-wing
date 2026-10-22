// Global UFCS bridges so callers outside `namespace wing` can invoke
// `req.header(...)`, `session.post(...) { req => ... }`, and `res.is_success()`
// using natural method-call syntax (`x.f(a)` -> `::f(x, a)`).
namespace wing;

// --- Session UFCS bridges ---
fn ::set_base_url(s: wing::Session&, url: const u8[:]) { wing::set_base_url(s, url); }
fn ::set_profile(s: wing::Session&, p: wing::Profile) { wing::set_profile(s, p); }
fn ::set_proxy(s: wing::Session&, proxy_url: const u8[:]) { wing::set_proxy(s, proxy_url); }
fn ::set_timeout_ms(s: wing::Session&, ms: i64) { wing::set_timeout_ms(s, ms); }
fn ::set_cookie(s: wing::Session&, name: const u8[:], value: const u8[:]) { wing::set_cookie(s, name, value); }
fn ::cookie(s: const wing::Session&, name: const u8[:]) -> const u8[:] { return wing::cookie(s, name); }
fn ::default_header(s: wing::Session&, name: const u8[:], value: const u8[:]) { wing::default_header(s, name, value); }

fn ::do(session: wing::Session&, req: const wing::Request&) -> wing::Response, wing::Error {
    return wing::do(session, req);
}

fn ::do<F: fn(wing::Request&)>(session: wing::Session&, req: const wing::Request&) -> wing::Response, wing::Error {
    return wing::do(session, req, F);
}

fn ::get(session: wing::Session&, url: const u8[:]) -> wing::Response, wing::Error {
    return wing::get(session, url);
}

fn ::get<F: fn(wing::Request&)>(session: wing::Session&, url: const u8[:]) -> wing::Response, wing::Error {
    return wing::get(session, url, F);
}

fn ::post<F: fn(wing::Request&)>(session: wing::Session&, url: const u8[:]) -> wing::Response, wing::Error {
    return wing::post(session, url, F);
}

fn ::post_json<T>(session: wing::Session&, url: const u8[:], payload: const T&) -> wing::Response, wing::Error {
    return wing::post_json(session, url, payload);
}

fn ::put<F: fn(wing::Request&)>(session: wing::Session&, url: const u8[:]) -> wing::Response, wing::Error {
    return wing::put(session, url, F);
}

fn ::put_json<T>(session: wing::Session&, url: const u8[:], payload: const T&) -> wing::Response, wing::Error {
    return wing::put_json(session, url, payload);
}

fn ::delete(session: wing::Session&, url: const u8[:]) -> wing::Response, wing::Error {
    return wing::delete(session, url);
}

fn ::delete<F: fn(wing::Request&)>(session: wing::Session&, url: const u8[:]) -> wing::Response, wing::Error {
    return wing::delete(session, url, F);
}

// --- Request UFCS bridges ---
fn ::header(req: wing::Request&, name: const u8[:], value: const u8[:]) { wing::header(req, name, value); }
fn ::set_header(req: wing::Request&, name: const u8[:], value: const u8[:]) { wing::set_header(req, name, value); }
fn ::bearer(req: wing::Request&, token: const u8[:]) { wing::bearer(req, token); }
fn ::set_bearer(req: wing::Request&, token: const u8[:]) { wing::set_bearer(req, token); }
fn ::query(req: wing::Request&, key: const u8[:], value: const u8[:]) { wing::query(req, key, value); }
fn ::set_query(req: wing::Request&, key: const u8[:], value: const u8[:]) { wing::set_query(req, key, value); }
fn ::timeout_ms(req: wing::Request&, ms: i64) { wing::timeout_ms(req, ms); }
fn ::set_timeout_ms(req: wing::Request&, ms: i64) { wing::set_timeout_ms(req, ms); }
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
fn ::as_nanos(d: wing::Duration) -> i64 { return wing::as_nanos(d); }
fn ::as_micros(d: wing::Duration) -> i64 { return wing::as_micros(d); }
fn ::as_millis(d: wing::Duration) -> i64 { return wing::as_millis(d); }
fn ::as_secs(d: wing::Duration) -> i64 { return wing::as_secs(d); }
fn ::as_mins(d: wing::Duration) -> i64 { return wing::as_mins(d); }
fn ::as_hours(d: wing::Duration) -> i64 { return wing::as_hours(d); }
fn ::as_days(d: wing::Duration) -> i64 { return wing::as_days(d); }
fn ::as_secs_f64(d: wing::Duration) -> f64 { return wing::as_secs_f64(d); }
fn ::as_mins_f64(d: wing::Duration) -> f64 { return wing::as_mins_f64(d); }
fn ::as_hours_f64(d: wing::Duration) -> f64 { return wing::as_hours_f64(d); }

fn ::nanoseconds(d: wing::Duration) -> i64 { return wing::nanoseconds(d); }
fn ::microseconds(d: wing::Duration) -> i64 { return wing::microseconds(d); }
fn ::milliseconds(d: wing::Duration) -> i64 { return wing::milliseconds(d); }
fn ::seconds(d: wing::Duration) -> f64 { return wing::seconds(d); }
fn ::minutes(d: wing::Duration) -> f64 { return wing::minutes(d); }
fn ::hours(d: wing::Duration) -> f64 { return wing::hours(d); }

fn ::add(d1: wing::Duration, d2: wing::Duration) -> wing::Duration { return wing::add(d1, d2); }
fn ::sub(d1: wing::Duration, d2: wing::Duration) -> wing::Duration { return wing::sub(d1, d2); }
fn ::mul(d: wing::Duration, factor: i64) -> wing::Duration { return wing::mul(d, factor); }
fn ::div(d: wing::Duration, factor: i64) -> wing::Duration { return wing::div(d, factor); }
fn ::abs(d: wing::Duration) -> wing::Duration { return wing::abs(d); }
fn ::is_zero(d: wing::Duration) -> bool { return wing::is_zero(d); }
fn ::is_negative(d: wing::Duration) -> bool { return wing::is_negative(d); }
fn ::is_positive(d: wing::Duration) -> bool { return wing::is_positive(d); }
fn ::truncate(d: wing::Duration, m: wing::Duration) -> wing::Duration { return wing::truncate(d, m); }
fn ::round(d: wing::Duration, m: wing::Duration) -> wing::Duration { return wing::round(d, m); }
fn ::format<B>(out: B&, d: wing::Duration) { wing::format(out, d); }

// Time inspectors
fn ::year(t: wing::Time) -> i64 { return wing::year(t); }
fn ::month(t: wing::Time) -> wing::Month { return wing::month(t); }
fn ::month_number(t: wing::Time) -> i64 { return wing::month_number(t); }
fn ::day(t: wing::Time) -> i64 { return wing::day(t); }
fn ::weekday(t: wing::Time) -> wing::Weekday { return wing::weekday(t); }
fn ::clock(t: wing::Time) -> i64, i64, i64 { return wing::clock(t); }
fn ::hour(t: wing::Time) -> i64 { return wing::hour(t); }
fn ::minute(t: wing::Time) -> i64 { return wing::minute(t); }
fn ::second(t: wing::Time) -> i64 { return wing::second(t); }
fn ::nanosecond(t: wing::Time) -> i64 { return wing::nanosecond(t); }
fn ::unix(t: wing::Time) -> i64 { return wing::unix(t); }
fn ::unix_milli(t: wing::Time) -> i64 { return wing::unix_milli(t); }
fn ::unix_micro(t: wing::Time) -> i64 { return wing::unix_micro(t); }
fn ::unix_nano(t: wing::Time) -> i64 { return wing::unix_nano(t); }
fn ::is_zero(t: wing::Time) -> bool { return wing::is_zero(t); }

// Time arithmetic
fn ::add(t: wing::Time, d: wing::Duration) -> wing::Time { return wing::add(t, d); }
fn ::sub(t: wing::Time, u: wing::Time) -> wing::Duration { return wing::sub(t, u); }
fn ::sub(t: wing::Time, d: wing::Duration) -> wing::Time { return wing::sub(t, d); }
fn ::sub_duration(t: wing::Time, d: wing::Duration) -> wing::Time { return wing::sub_duration(t, d); }
fn ::since(t: wing::Time) -> wing::Duration { return wing::since(t); }
fn ::until(t: wing::Time) -> wing::Duration { return wing::until(t); }
fn ::equal(t: wing::Time, u: wing::Time) -> bool { return wing::equal(t, u); }
fn ::before(t: wing::Time, u: wing::Time) -> bool { return wing::before(t, u); }
fn ::after(t: wing::Time, u: wing::Time) -> bool { return wing::after(t, u); }
fn ::compare(t: wing::Time, u: wing::Time) -> i64 { return wing::compare(t, u); }
fn ::truncate(t: wing::Time, d: wing::Duration) -> wing::Time { return wing::truncate(t, d); }
fn ::round(t: wing::Time, d: wing::Duration) -> wing::Time { return wing::round(t, d); }

// Timezones
fn ::utc(t: wing::Time) -> wing::Time { return wing::utc(t); }
fn ::in_offset(t: wing::Time, tz_offset: i32) -> wing::Time { return wing::in_offset(t, tz_offset); }
fn ::in_tz(t: wing::Time, hours: i64, minutes: i64 = 0) -> wing::Time { return wing::in_tz(t, hours, minutes); }
fn ::tz_offset(t: wing::Time) -> i32 { return wing::tz_offset(t); }

// Calendar Math & Navigation
fn ::add_months_clamped(t: wing::Time, months: i64) -> wing::Time { return wing::add_months_clamped(t, months); }
fn ::add_years_clamped(t: wing::Time, years: i64) -> wing::Time { return wing::add_years_clamped(t, years); }
fn ::days_in_month(t: wing::Time) -> i64 { return wing::days_in_month(t); }
fn ::days_in_year(t: wing::Time) -> i64 { return wing::days_in_year(t); }
fn ::is_leap_year(t: wing::Time) -> bool { return wing::is_leap_year(t); }

fn ::start_of_day(t: wing::Time) -> wing::Time { return wing::start_of_day(t); }
fn ::end_of_day(t: wing::Time) -> wing::Time { return wing::end_of_day(t); }
fn ::start_of_month(t: wing::Time) -> wing::Time { return wing::start_of_month(t); }
fn ::end_of_month(t: wing::Time) -> wing::Time { return wing::end_of_month(t); }
fn ::start_of_year(t: wing::Time) -> wing::Time { return wing::start_of_year(t); }
fn ::end_of_year(t: wing::Time) -> wing::Time { return wing::end_of_year(t); }

// Formatting
fn ::format_rfc3339<B>(out: B&, t: wing::Time) { wing::format_rfc3339(out, t); }
fn ::format_rfc3339_nano<B>(out: B&, t: wing::Time) { wing::format_rfc3339_nano(out, t); }
fn ::format_http<B>(out: B&, t: wing::Time) { wing::format_http(out, t); }

// Stopwatch
fn ::elapsed(sw: const wing::Stopwatch&) -> wing::Duration { return wing::elapsed(sw); }
fn ::restart(sw: wing::Stopwatch&) -> wing::Duration { return wing::restart(sw); }

// Deadline Primitives
fn ::is_expired(dl: const wing::Deadline&) -> bool { return wing::is_expired(dl); }
fn ::remaining(dl: const wing::Deadline&) -> wing::Duration { return wing::remaining(dl); }

// Policy Bridges (Backoff & RateLimiter)
fn ::delay(b: const wing::Backoff&, attempt: i64) -> wing::Duration { return wing::delay(b, attempt); }
fn ::allow(rl: wing::RateLimiter&) -> bool { return wing::allow(rl); }
