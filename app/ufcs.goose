// Global UFCS bridges for method-call syntax across namespaces.
namespace wing;

// ---- session ufcs bridges --------------------------------------------------

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

// ---- request ufcs bridges --------------------------------------------------

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

// ---- response & error ufcs bridges -----------------------------------------

fn ::ok(err: const wing::Error&) -> bool { return wing::ok(err); }
fn ::is_success(res: const wing::Response&) -> bool { return wing::is_success(res); }
fn ::is_redirect(res: const wing::Response&) -> bool { return wing::is_redirect(res); }
fn ::header(res: const wing::Response&, name: const u8[:]) -> const u8[:] { return wing::header(res, name); }
fn ::text(res: const wing::Response&) -> const u8[:] { return wing::text(res); }
fn ::decode_body(res: wing::Response&) -> bool { return wing::decode_body(res); }
fn ::json<T>(res: const wing::Response&, out: T&) -> wing::Error { return wing::json(res, out); }
fn ::decode_json<T>(res: const wing::Response&) -> T, wing::Error { return wing::decode_json<T>(res); }

// ---- time & duration ufcs bridges ------------------------------------------

fn ::as_nanos(dur: core::Duration) -> i64 { return core::as_nanos(dur); }
fn ::as_micros(dur: core::Duration) -> i64 { return core::as_micros(dur); }
fn ::as_millis(dur: core::Duration) -> i64 { return core::as_millis(dur); }
fn ::as_secs(dur: core::Duration) -> i64 { return core::as_secs(dur); }
fn ::as_mins(dur: core::Duration) -> i64 { return core::as_mins(dur); }
fn ::as_hours(dur: core::Duration) -> i64 { return core::as_hours(dur); }
fn ::as_days(dur: core::Duration) -> i64 { return core::as_days(dur); }
fn ::as_secs_f64(dur: core::Duration) -> f64 { return core::as_secs_f64(dur); }
fn ::as_mins_f64(dur: core::Duration) -> f64 { return core::as_mins_f64(dur); }
fn ::as_hours_f64(dur: core::Duration) -> f64 { return core::as_hours_f64(dur); }

fn ::nanoseconds(dur: core::Duration) -> i64 { return core::nanoseconds(dur); }
fn ::microseconds(dur: core::Duration) -> i64 { return core::microseconds(dur); }
fn ::milliseconds(dur: core::Duration) -> i64 { return core::milliseconds(dur); }
fn ::seconds(dur: core::Duration) -> f64 { return core::seconds(dur); }
fn ::minutes(dur: core::Duration) -> f64 { return core::minutes(dur); }
fn ::hours(dur: core::Duration) -> f64 { return core::hours(dur); }

fn ::add(dur1: core::Duration, dur2: core::Duration) -> core::Duration { return core::add(dur1, dur2); }
fn ::sub(dur1: core::Duration, dur2: core::Duration) -> core::Duration { return core::sub(dur1, dur2); }
fn ::mul(dur: core::Duration, factor: i64) -> core::Duration { return core::mul(dur, factor); }
fn ::div(dur: core::Duration, factor: i64) -> core::Duration { return core::div(dur, factor); }
fn ::abs(dur: core::Duration) -> core::Duration { return core::abs(dur); }

// Duration predicates

fn ::is_zero(dur: core::Duration) -> bool { return core::is_zero(dur); }
fn ::is_negative(dur: core::Duration) -> bool { return core::is_negative(dur); }
fn ::is_positive(dur: core::Duration) -> bool { return core::is_positive(dur); }

fn ::truncate(dur: core::Duration, step_dur: core::Duration) -> core::Duration { return core::truncate(dur, step_dur); }
fn ::round(dur: core::Duration, step_dur: core::Duration) -> core::Duration { return core::round(dur, step_dur); }
fn ::format<B>(out: B&, dur: core::Duration) { core::format(out, dur); }

// Time inspectors

fn ::year(time_val: core::Time) -> i64 { return core::year(time_val); }
fn ::month(time_val: core::Time) -> core::Month { return core::month(time_val); }
fn ::month_number(time_val: core::Time) -> i64 { return core::month_number(time_val); }
fn ::day(time_val: core::Time) -> i64 { return core::day(time_val); }
fn ::weekday(time_val: core::Time) -> core::Weekday { return core::weekday(time_val); }
fn ::clock(time_val: core::Time) -> i64, i64, i64 { return core::clock(time_val); }
fn ::hour(time_val: core::Time) -> i64 { return core::hour(time_val); }
fn ::minute(time_val: core::Time) -> i64 { return core::minute(time_val); }
fn ::second(time_val: core::Time) -> i64 { return core::second(time_val); }
fn ::nanosecond(time_val: core::Time) -> i64 { return core::nanosecond(time_val); }
fn ::unix(time_val: core::Time) -> i64 { return core::unix(time_val); }
fn ::unix_milli(time_val: core::Time) -> i64 { return core::unix_milli(time_val); }
fn ::unix_micro(time_val: core::Time) -> i64 { return core::unix_micro(time_val); }
fn ::unix_nano(time_val: core::Time) -> i64 { return core::unix_nano(time_val); }
fn ::is_zero(time_val: core::Time) -> bool { return core::is_zero(time_val); }

// Time arithmetic

fn ::add(time_val: core::Time, dur: core::Duration) -> core::Time { return core::add(time_val, dur); }
fn ::sub(time_val: core::Time, other_time: core::Time) -> core::Duration { return core::sub(time_val, other_time); }
fn ::sub(time_val: core::Time, dur: core::Duration) -> core::Time { return core::sub(time_val, dur); }
fn ::sub_duration(time_val: core::Time, dur: core::Duration) -> core::Time { return core::sub_duration(time_val, dur); }
fn ::since(time_val: core::Time) -> core::Duration { return core::since(time_val); }
fn ::until(time_val: core::Time) -> core::Duration { return core::until(time_val); }
fn ::equal(time_val: core::Time, other_time: core::Time) -> bool { return core::equal(time_val, other_time); }
fn ::before(time_val: core::Time, other_time: core::Time) -> bool { return core::before(time_val, other_time); }
fn ::after(time_val: core::Time, other_time: core::Time) -> bool { return core::after(time_val, other_time); }
fn ::compare(time_val: core::Time, other_time: core::Time) -> i64 { return core::compare(time_val, other_time); }
fn ::truncate(time_val: core::Time, dur: core::Duration) -> core::Time { return core::truncate(time_val, dur); }
fn ::round(time_val: core::Time, dur: core::Duration) -> core::Time { return core::round(time_val, dur); }

// Timezones

fn ::utc(time_val: core::Time) -> core::Time { return core::utc(time_val); }
fn ::in_offset(time_val: core::Time, tz_offset_seconds: i32) -> core::Time { return core::in_offset(time_val, tz_offset_seconds); }
fn ::in_tz(time_val: core::Time, hours_offset: i64, minutes_offset: i64 = 0) -> core::Time { return core::in_tz(time_val, hours_offset, minutes_offset); }
fn ::tz_offset(time_val: core::Time) -> i32 { return core::tz_offset(time_val); }

// Calendar Math & Navigation

fn ::add_months_clamped(time_val: core::Time, months_count: i64) -> core::Time { return core::add_months_clamped(time_val, months_count); }
fn ::add_years_clamped(time_val: core::Time, years_count: i64) -> core::Time { return core::add_years_clamped(time_val, years_count); }
fn ::days_in_month(time_val: core::Time) -> i64 { return core::days_in_month(time_val); }
fn ::days_in_month(year_val: i64, month_val: i64) -> i64 { return core::days_in_month(year_val, month_val); }
fn ::days_in_year(time_val: core::Time) -> i64 { return core::days_in_year(time_val); }
fn ::is_leap_year(time_val: core::Time) -> bool { return core::is_leap_year(time_val); }
fn ::is_leap_year(year_val: i64) -> bool { return core::is_leap_year(year_val); }

fn ::start_of_day(time_val: core::Time) -> core::Time { return core::start_of_day(time_val); }
fn ::end_of_day(time_val: core::Time) -> core::Time { return core::end_of_day(time_val); }
fn ::start_of_month(time_val: core::Time) -> core::Time { return core::start_of_month(time_val); }
fn ::end_of_month(time_val: core::Time) -> core::Time { return core::end_of_month(time_val); }
fn ::start_of_year(time_val: core::Time) -> core::Time { return core::start_of_year(time_val); }
fn ::end_of_year(time_val: core::Time) -> core::Time { return core::end_of_year(time_val); }

// Formatting

fn ::format_rfc3339<B>(out: B&, time_val: core::Time) { core::format_rfc3339(out, time_val); }
fn ::format_rfc3339_nano<B>(out: B&, time_val: core::Time) { core::format_rfc3339_nano(out, time_val); }
fn ::format_http<B>(out: B&, time_val: core::Time) { core::format_http(out, time_val); }

// Stopwatch

fn ::elapsed(watch: const core::Stopwatch&) -> core::Duration { return core::elapsed(watch); }
fn ::restart(watch: core::Stopwatch&) -> core::Duration { return core::restart(watch); }

// Deadline Primitives

fn ::is_expired(deadline_val: const core::Deadline&) -> bool { return core::is_expired(deadline_val); }
fn ::remaining(deadline_val: const core::Deadline&) -> core::Duration { return core::remaining(deadline_val); }

// Policy Bridges (Backoff & RateLimiter)

fn ::delay(backoff: const wing::Backoff&, attempt: i64) -> wing::Duration { return wing::delay(backoff, attempt); }
fn ::allow(limiter: wing::RateLimiter&) -> bool { return wing::allow(limiter); }

// ---- cookie & cookie jar ufcs bridges --------------------------------------

fn ::add(jar: wing::CanonicalCookieJar&, name: const u8[:], val: const u8[:]) -> wing::CanonicalCookie& {
    return wing::add(jar, name, val);
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

fn ::with_max_age_seconds(cookie_val: wing::CanonicalCookie&, seconds: i64, now_us: i64) -> wing::CanonicalCookie& {
    return wing::with_max_age_seconds(cookie_val, seconds, now_us);
}

fn ::with_expires_utc(cookie_val: wing::CanonicalCookie&, expires_us: i64) -> wing::CanonicalCookie& {
    return wing::with_expires_utc(cookie_val, expires_us);
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

fn ::set(jar: wing::CanonicalCookieJar&, cookie_val: wing::CanonicalCookie, now_us: i64) -> bool {
    return wing::set(jar, cookie_val, now_us);
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

// ---- url & origin ufcs bridges ---------------------------------------------

fn ::href(url_val: const core::Url&) -> const u8[:] { return core::href(url_val); }
fn ::scheme(url_val: const core::Url&) -> const u8[:] { return core::scheme(url_val); }
fn ::host(url_val: const core::Url&) -> const u8[:] { return core::host(url_val); }
fn ::hostname(url_val: const core::Url&) -> const u8[:] { return core::hostname(url_val); }
fn ::port(url_val: const core::Url&) -> i32 { return core::effective_port(url_val); }
fn ::effective_port(url_val: const core::Url&) -> i32 { return core::effective_port(url_val); }
fn ::pathname(url_val: const core::Url&) -> const u8[:] { return core::pathname(url_val); }
fn ::path(url_val: const core::Url&) -> const u8[:] { return core::pathname(url_val); }
fn ::search(url_val: const core::Url&) -> const u8[:] { return core::search(url_val); }
fn ::hash(url_val: const core::Url&) -> const u8[:] { return core::hash(url_val); }
fn ::origin(url_val: const core::Url&) -> core::Origin { return core::origin_from_url(url_val); }
fn ::is_special(url_val: const core::Url&) -> bool { return core::is_special(url_val); }
fn ::is_secure_scheme(url_val: const core::Url&) -> bool { return core::is_secure_scheme(url_val); }

// ---- file & path ufcs bridges -----------------------------------------------

fn ::is_file_url(url_val: const core::Url&) -> bool { return core::is_file_url(url_val); }
fn ::file_path<B>(url_val: const core::Url&, out: B&) -> bool { return core::file_path(url_val, out); }
fn ::last_path_component(url_val: const core::Url&) -> const u8[:] { return core::last_path_component(url_val); }
fn ::path_extension(url_val: const core::Url&) -> const u8[:] { return core::path_extension(url_val); }
fn ::deleting_path_extension(url_val: core::Url) -> core::Url { return core::deleting_path_extension(url_val); }
fn ::deleting_last_path_component(url_val: core::Url) -> core::Url { return core::deleting_last_path_component(url_val); }
fn ::appending_path_component(url_val: core::Url, component: const u8[:]) -> core::Url { return core::appending_path_component(url_val, component); }
fn ::appending(url_val: core::Url, component: const u8[:]) -> core::Url { return core::appending_path_component(url_val, component); }
fn ::appending_path(url_val: core::Url, subpath: const u8[:]) -> core::Url { return core::appending_path(url_val, subpath); }
fn ::appending_path_extension(url_val: core::Url, ext: const u8[:]) -> core::Url { return core::appending_path_extension(url_val, ext); }

// ---- dual-mode resolution ufcs bridges -------------------------------------

fn ::resolve_reference(base_url: const core::Url&, relative_ref: const u8[:]) -> core::Url { return core::resolve_reference(base_url, relative_ref); }
fn ::resolve_endpoint(base_url: const core::Url&, endpoint: const u8[:]) -> core::Url { return core::resolve_endpoint(base_url, endpoint); }
fn ::join_endpoint(base_url: const core::Url&, endpoint: const u8[:]) -> core::Url { return core::join_endpoint(base_url, endpoint); }

// ---- url view ufcs bridges -------------------------------------------------

fn ::parse_url_view(raw_input: const u8[:]) -> core::UrlView, core::UrlParseError { return core::parse_url_view(raw_input); }
fn ::new_url_view(raw_input: const u8[:]) -> core::UrlView { return core::new_url_view(raw_input); }
fn ::href(view: const core::UrlView&) -> const u8[:] { return core::href(view); }
fn ::scheme(view: const core::UrlView&) -> const u8[:] { return core::scheme(view); }
fn ::host(view: const core::UrlView&) -> const u8[:] { return core::host(view); }
fn ::hostname(view: const core::UrlView&) -> const u8[:] { return core::hostname(view); }
fn ::pathname(view: const core::UrlView&) -> const u8[:] { return core::pathname(view); }
fn ::search(view: const core::UrlView&) -> const u8[:] { return core::search(view); }
fn ::hash(view: const core::UrlView&) -> const u8[:] { return core::hash(view); }
fn ::port(view: const core::UrlView&) -> i32 { return core::port(view); }
fn ::is_valid(view: const core::UrlView&) -> bool { return core::is_valid(view); }

// ---- concurrency & sync ufcs bridges ---------------------------------------

fn ::add_worker(wg: core::WaitGroup&, worker_id: i64) -> bool { return core::add_worker(wg, worker_id); }
fn ::worker_count(wg: const core::WaitGroup&) -> i64 { return core::worker_count(wg); }
fn ::wait_all(wg: core::WaitGroup&) -> bool { return core::wait_all(wg); }
fn ::wait_all(wg: core::WaitGroup&, out_diagnostics: u8[>..]&) -> bool { return core::wait_all(wg, out_diagnostics); }
fn ::failed_count(wg: const core::WaitGroup&) -> i64 { return core::failed_count(wg); }

fn ::acquire(sem: core::Semaphore&) -> core::SemPermit { return core::acquire(sem); }
fn ::try_acquire(sem: core::Semaphore&) -> core::SemPermit, bool { return core::try_acquire(sem); }
fn ::release(sem: core::Semaphore&, permit: core::SemPermit) -> bool { return core::release(sem, permit); }

fn ::count_down(latch: core::CountDownLatch&) -> bool { return core::count_down(latch); }
fn ::latch_wait(latch: core::CountDownLatch&) { core::latch_wait(latch); }

fn ::push_unordered(r: core::Reassembler&, item: core::ReassemblerItem) { core::push_unordered(r, item); }
fn ::pop_next_in_order(r: core::Reassembler&) -> core::ReassemblerItem, bool { return core::pop_next_in_order(r); }
fn ::pending_count(r: const core::Reassembler&) -> i64 { return core::pending_count(r); }

fn ::stash(sb: core::StashBuffer&, env: core::StashedEnvelope) { core::stash(sb, env); }
fn ::unstash_all(sb: core::StashBuffer&, out_pending: core::StashedEnvelope[>..]&) -> i64 { return core::unstash_all(sb, out_pending); }
fn ::stash_count(sb: const core::StashBuffer&) -> i64 { return core::stash_count(sb); }
fn ::is_empty(sb: const core::StashBuffer&) -> bool { return core::is_empty(sb); }

fn ::push(mb: core::PriorityMailbox&, priority: u32, payload_type: u16, val: i64) { core::push(mb, priority, payload_type, val); }
fn ::pop(mb: core::PriorityMailbox&) -> core::PriorityItem, bool { return core::pop(mb); }
fn ::count(mb: const core::PriorityMailbox&) -> i64 { return core::count(mb); }

fn ::add_worker(sup: core::Supervisor&, worker_id: i64) -> bool { return core::add_worker(sup, worker_id); }
fn ::add_child(sup: core::Supervisor&, spec: core::ChildSpec, worker_id: i64) -> bool { return core::add_child(sup, spec, worker_id); }
fn ::child_count(sup: const core::Supervisor&) -> i64 { return core::child_count(sup); }
fn ::wait_all(sup: core::Supervisor&) -> bool { return core::wait_all(sup); }
fn ::wait_all(sup: core::Supervisor&, out_diagnostics: u8[>..]&) -> bool { return core::wait_all(sup, out_diagnostics); }
fn ::failed_count(sup: const core::Supervisor&) -> i64 { return core::failed_count(sup); }
fn ::success_count(sup: const core::Supervisor&) -> i64 { return core::success_count(sup); }
fn ::is_auto_shutdown(sup: const core::Supervisor&) -> bool { return core::is_auto_shutdown(sup); }
fn ::should_restart_child(sup: const core::Supervisor&, child_idx: i64, reason: const core::ExitReason&) -> bool { return core::should_restart_child(sup, child_idx, reason); }
fn ::record_failure(sup: core::Supervisor&, child_idx: i64, current_time_s: i64) -> bool { return core::record_failure(sup, child_idx, current_time_s); }

// ---- http headers, mime, and multipart ufcs bridges -----------------------

fn ::has_header(map: const wing::HeaderMap&, name: const u8[:]) -> bool { return wing::has_header(map, name); }
fn ::get_header(map: const wing::HeaderMap&, name: const u8[:]) -> const u8[:] { return wing::get_header(map, name); }
fn ::header(map: const wing::HeaderMap&, name: const u8[:]) -> const u8[:] { return wing::get_header(map, name); }
fn ::get_inline(map: const wing::HeaderMap&, id: wing::WellKnownHeader) -> const u8[:] { return wing::get_inline(map, id); }
fn ::set_inline(map: wing::HeaderMap&, id: wing::WellKnownHeader, value: const u8[:]) -> bool { return wing::set_inline(map, id, value); }
fn ::insert_header(map: wing::HeaderMap&, name: const u8[:], value: const u8[:]) -> bool { return wing::insert_header(map, name, value); }
fn ::append_header(map: wing::HeaderMap&, name: const u8[:], value: const u8[:]) -> bool { return wing::append_header(map, name, value); }
fn ::remove_header(map: wing::HeaderMap&, name: const u8[:]) -> bool { return wing::remove_header(map, name); }
fn ::reset_for_keep_alive(map: wing::HeaderMap&) { wing::reset_for_keep_alive(map); }
fn ::get_combined(map: const wing::HeaderMap&, name: const u8[:], out: u8[>..]&) -> bool { return wing::get_combined(map, name, out); }
fn ::get_all_values(map: const wing::HeaderMap&, name: const u8[:], out_values: u8[..256][>..]&) { wing::get_all_values(map, name, out_values); }
fn ::get_set_cookie(map: const wing::HeaderMap&, out_cookies: u8[..1024][>..]&) { wing::get_set_cookie(map, out_cookies); }
fn ::raw_headers(map: const wing::HeaderMap&, out: u8[>..]&) { wing::raw_headers(map, out); }
fn ::serialize_headers(map: const wing::HeaderMap&, out: u8[>..]&) { wing::serialize_headers(map, out); }
fn ::merge_with_headers_304(cached: wing::HeaderMap&, response_304: const wing::HeaderMap&) { wing::merge_with_headers_304(cached, response_304); }
fn ::persist_headers(src: const wing::HeaderMap&, dst: wing::HeaderMap&, flags: u32) { wing::persist_headers(src, dst, flags); }

fn ::param(mt: const wing::MediaType&, key: const u8[:]) -> const u8[:] { return wing::param(mt, key); }
fn ::has_param(mt: const wing::MediaType&, key: const u8[:]) -> bool { return wing::has_param(mt, key); }
fn ::is_multipart(mt: const wing::MediaType&) -> bool { return wing::is_multipart(mt); }
fn ::boundary(mt: const wing::MediaType&) -> const u8[:] { return wing::boundary(mt); }
fn ::charset(mt: const wing::MediaType&) -> const u8[:] { return wing::charset(mt); }
fn ::parse_content_disposition(raw: const u8[:]) -> wing::MediaType, bool { return wing::parse_content_disposition(raw); }

// ---- security & server ufcs bridges ----------------------------------------

fn ::add_key(store: wing::KeyStore&, slot: wing::KeySlot) -> bool { return wing::add_key(store, slot); }
fn ::active_key(store: const wing::KeyStore&) -> wing::KeySlot, bool { return wing::active_key(store); }
fn ::find_key(store: const wing::KeyStore&, key_id: u32) -> wing::KeySlot, bool { return wing::find_key(store, key_id); }
fn ::revoke_key(store: wing::KeyStore&, key_id: u32) -> bool { return wing::revoke_key(store, key_id); }

fn ::add_trusted_origin(guard_cfg: wing::CrossOriginGuard&, origin_str: const u8[:]) -> bool { return wing::add_trusted_origin(guard_cfg, origin_str); }
fn ::add_exempt_path(guard_cfg: wing::CrossOriginGuard&, path_str: const u8[:]) -> bool { return wing::add_exempt_path(guard_cfg, path_str); }

fn ::add_allowed_origin(policy: wing::CorsPolicy&, origin_pattern: const u8[:]) -> bool { return wing::add_allowed_origin(policy, origin_pattern); }

fn ::add_route(router: wing::RadixRouter&, method: const u8[:], path: const u8[:], handler_id: i32, entries_mask: u32 = 0) -> bool {
    return wing::add_route(router, method, path, handler_id, entries_mask);
}
fn ::match_route(router: const wing::RadixRouter&, method: const u8[:], path: const u8[:], params: wing::ZeroAllocParams&) -> wing::RouteMatchResult {
    return wing::match_route(router, method, path, params);
}

fn ::acquire_header_map(pool: wing::HeaderMapPool&) -> i32 { return wing::acquire_header_map(pool); }
fn ::release_header_map(pool: wing::HeaderMapPool&, idx: i32) { wing::release_header_map(pool, idx); }
fn ::acquire_extensions(pool: wing::ExtensionsPool&) -> i32 { return wing::acquire_extensions(pool); }
fn ::release_extensions(pool: wing::ExtensionsPool&, idx: i32) { wing::release_extensions(pool, idx); }
fn ::check_connection_tick(timer: wing::ConnectionTimer&, now_ns: u64) -> bool { return wing::check_connection_tick(timer, now_ns); }

// ---- http cache ufcs bridges -----------------------------------------------

fn ::is_no_store(cc: const wing::CacheControl&) -> bool { return wing::is_no_store(cc); }
fn ::is_no_cache(cc: const wing::CacheControl&) -> bool { return wing::is_no_cache(cc); }
fn ::is_must_revalidate(cc: const wing::CacheControl&) -> bool { return wing::is_must_revalidate(cc); }
fn ::is_proxy_revalidate(cc: const wing::CacheControl&) -> bool { return wing::is_proxy_revalidate(cc); }
fn ::is_must_understand(cc: const wing::CacheControl&) -> bool { return wing::is_must_understand(cc); }
fn ::is_private(cc: const wing::CacheControl&) -> bool { return wing::is_private(cc); }
fn ::is_public(cc: const wing::CacheControl&) -> bool { return wing::is_public(cc); }
fn ::is_immutable(cc: const wing::CacheControl&) -> bool { return wing::is_immutable(cc); }
fn ::is_only_if_cached(cc: const wing::CacheControl&) -> bool { return wing::is_only_if_cached(cc); }
fn ::weak_eq(a: const wing::EntityTag&, b: const wing::EntityTag&) -> bool { return wing::weak_eq(a, b); }
fn ::strong_eq(a: const wing::EntityTag&, b: const wing::EntityTag&) -> bool { return wing::strong_eq(a, b); }
fn ::matches_vary(snap: const wing::VarySnapshot&, incoming_req_headers: const wing::HeaderMap&) -> bool { return wing::matches_vary(snap, incoming_req_headers); }
fn ::lookup(cache: wing::HttpCache&, req: const wing::Request&, cur_now: wing::Time, cur_mono: wing::MonotonicInstant = wing::MonotonicInstant { .. }) -> wing::LookupDecision {
    return wing::lookup(cache, req, cur_now, cur_mono);
}
fn ::on_response(cache: wing::HttpCache&, req: const wing::Request&, resp: const wing::Response&, ts: const wing::CacheTimestamps&, revalidate_entry_idx: i64 = -1) -> wing::ResponseDecision {
    return wing::on_response(cache, req, resp, ts, revalidate_entry_idx);
}
fn ::check_invalidation(cache: wing::HttpCache&, req: const wing::Request&, resp: const wing::Response&) -> i64 {
    return wing::check_invalidation(cache, req, resp);
}

// ---- resilient networking & transport ufcs bridges -------------------------

fn ::acquire_pooled_connection(pool: wing::StreamPool&, key: const wing::PoolKey&, target_resolved_ip: const u8[:], now_ns: i64, do_extensive_checks: bool = false) -> i32, bool {
    return wing::acquire_pooled_connection(pool, key, target_resolved_ip, now_ns, do_extensive_checks);
}

fn ::register_connection(pool: wing::StreamPool&, key: const wing::PoolKey&, proto: wing::NegotiatedProtocol, resolved_ip: const u8[:], max_streams: i32, now_ns: i64, respect_limits: wing::RespectLimits = wing::RespectLimits.Enabled) -> i32 {
    return wing::register_connection(pool, key, proto, resolved_ip, max_streams, now_ns, respect_limits);
}

fn ::release_connection(pool: wing::StreamPool&, conn_id: i32, now_ns: i64) -> bool {
    return wing::release_connection(pool, conn_id, now_ns);
}

fn ::is_connection_healthy(conn: wing::PooledConnection&, now_ns: i64, do_extensive_checks: bool = false, healthy_threshold_ns: i64 = wing::IDLE_CONNECTION_HEALTHY_NS) -> bool {
    return wing::is_connection_healthy(conn, now_ns, do_extensive_checks, healthy_threshold_ns);
}

fn ::push_want(q: wing::WantQueue&, item: wing::WantConn) -> bool {
    return wing::push_want(q, item);
}

fn ::pop_want(q: wing::WantQueue&) -> wing::WantConn, bool {
    return wing::pop_want(q);
}

fn ::cancel_want(q: wing::WantQueue&, req_id: u64) -> bool {
    return wing::cancel_want(q, req_id);
}

fn ::compute_effective_cad_ms(observed_rtt_ms: i64, rtt_known: bool, min_cad_ms: i64 = wing::HE_MIN_CAD_MS, max_cad_ms: i64 = wing::HE_MAX_CAD_MS) -> i64 {
    return wing::compute_effective_cad_ms(observed_rtt_ms, rtt_known, min_cad_ms, max_cad_ms);
}

fn ::start_attempt_race(manager: wing::AttemptManager&, candidates: const wing::DnsCandidate[:], now_ms: i64) {
    wing::start_attempt_race(manager, candidates, now_ms);
}

fn ::tick_attempt_manager(manager: wing::AttemptManager&, now_ms: i64) -> bool {
    return wing::tick_attempt_manager(manager, now_ms);
}

fn ::bind_winner_attempt(manager: wing::AttemptManager&, winner_id: i32, is_alternative_h3: bool = false) -> bool {
    return wing::bind_winner_attempt(manager, winner_id, is_alternative_h3);
}

fn ::verify_connect_tunnel_response(raw_response: const u8[:], sink_buffered_bytes: i64 = 0) -> wing::ConnectTunnelError {
    return wing::verify_connect_tunnel_response(raw_response, sink_buffered_bytes);
}

fn ::feed_header_bytes(reader: wing::HeaderReader&, chunk: const u8[:], now_mono_ns: i64) -> wing::SlowlorisViolation {
    return wing::feed_header_bytes(reader, chunk, now_mono_ns);
}

fn ::should_retry_tier1_stale_socket(reused_connection: bool, headers_received: bool, req: const wing::Request&) -> bool {
    return wing::should_retry_tier1_stale_socket(reused_connection, headers_received, req);
}

fn ::evaluate_tier1_retry(err_code: i32, reused_connection: bool, headers_received: bool, req: const wing::Request&) -> wing::Tier1Decision {
    return wing::evaluate_tier1_retry(err_code, reused_connection, headers_received, req);
}

fn ::compute_backoff_jitter_ms(cfg: const wing::BackoffConfig&, attempt: i64, prev_sleep_ms: i64&, rng_seed: u64&) -> i64 {
    return wing::compute_backoff_jitter_ms(cfg, attempt, prev_sleep_ms, rng_seed);
}

fn ::parse_retry_after_ms(header_raw: const u8[:], now_unix_ms: i64) -> i64, bool {
    return wing::parse_retry_after_ms(header_raw, now_unix_ms);
}

fn ::trip_circuit_breaker_if_exceeded(breaker: wing::HostCircuitBreaker&, host_str: const u8[:], retry_after_ms: i64, now_mono_ns: i64) -> bool {
    return wing::trip_circuit_breaker_if_exceeded(breaker, host_str, retry_after_ms, now_mono_ns);
}

fn ::is_host_circuit_broken(breaker: wing::HostCircuitBreaker&, host_str: const u8[:], now_mono_ns: i64) -> bool {
    return wing::is_host_circuit_broken(breaker, host_str, now_mono_ns);
}

fn ::record_primary_request(budget: wing::AdaptiveRetryBudget&, now_mono_ns: i64) {
    wing::record_primary_request(budget, now_mono_ns);
}

fn ::allow_retry_budget(budget: wing::AdaptiveRetryBudget&, now_mono_ns: i64) -> bool {
    return wing::allow_retry_budget(budget, now_mono_ns);
}

// ---- math & rtt estimator ufcs bridges -------------------------------------

fn ::next_u64(rng: core::WyRand&) -> u64 { return core::next_u64(rng); }
fn ::next_u32(rng: core::WyRand&) -> u32 { return core::next_u32(rng); }
fn ::next_u32(rng: core::Xoroshiro64StarStar&) -> u32 { return core::next_u32(rng); }

fn ::on_rtt_sample(
    est: core::JacobsonRttEstimator&,
    latest_rtt_us: u64,
    ack_delay_us: u64 = 0,
    max_ack_delay_us: u64 = 25000,
    handshake_confirmed: bool = false
) {
    core::on_rtt_sample(est, latest_rtt_us, ack_delay_us, max_ack_delay_us, handshake_confirmed);
}
fn ::smoothed_rtt_us(est: const core::JacobsonRttEstimator&) -> u64 { return core::smoothed_rtt_us(est); }
fn ::rttvar_us(est: const core::JacobsonRttEstimator&) -> u64 { return core::rttvar_us(est); }
fn ::probe_timeout_us(est: const core::JacobsonRttEstimator&, max_ack_delay_us: u64 = 0) -> u64 {
    return core::probe_timeout_us(est, max_ack_delay_us);
}
fn ::loss_time_threshold_us(est: const core::JacobsonRttEstimator&) -> u64 { return core::loss_time_threshold_us(est); }
