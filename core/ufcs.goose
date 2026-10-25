// Universal Function Call Syntax (UFCS) method bridges for core types.
namespace core;

import std;
import core.math;
import core.time;
import core.url;
import core.sync;
import core.bytes;

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
fn ::registrable_site(url_val: const core::Url&) -> core::RegistrableSite { return core::registrable_site_from_url(url_val); }
fn ::is_same_origin(origin_a: core::Origin, origin_b: core::Origin) -> bool { return core::is_same_origin(origin_a, origin_b); }
fn ::is_same_origin_url(url_a: const core::Url&, url_b: const core::Url&) -> bool { return core::is_same_origin_url(url_a, url_b); }
fn ::serialize_origin<B>(origin_val: core::Origin, out: B&) { core::serialize_origin(origin_val, out); }
fn ::extract_etld_plus_one<B>(host: const u8[:], out: B&) { core::extract_etld_plus_one(host, out); }
fn ::compute_public_suffix<B>(clean_domain: const u8[:], out: B&) -> bool { return core::compute_public_suffix(clean_domain, out); }
fn ::public_suffix_with_icann<B>(domain: const u8[:], out_suffix: B&) -> bool { return core::public_suffix_with_icann(domain, out_suffix); }
fn ::is_ip_address_literal(host: const u8[:]) -> bool { return core::is_ip_address_literal(host); }
fn ::is_schemeful_same_site_urls(url_a: const core::Url&, url_b: const core::Url&) -> bool { return core::is_schemeful_same_site_urls(url_a, url_b); }
fn ::is_same_site_origin_url(origin_val: const core::Origin&, url_val: const core::Url&) -> bool { return core::is_same_site_origin_url(origin_val, url_val); }

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

// ---- singleflight group ufcs bridges ---------------------------------------

fn ::start_or_join(g: core::SingleflightGroup&, key_str: const u8[:]) -> bool, i64, bool { return core::start_or_join(g, key_str); }
fn ::finish_call(g: core::SingleflightGroup&, key_str: const u8[:], val: i64, ok: bool = true) -> bool, i32 { return core::finish_call(g, key_str, val, ok); }
fn ::forget(g: core::SingleflightGroup&, key_str: const u8[:]) -> bool { return core::forget(g, key_str); }
fn ::forget_unshared(g: core::SingleflightGroup&, key_str: const u8[:]) -> bool { return core::forget_unshared(g, key_str); }
fn ::is_in_flight(g: const core::SingleflightGroup&, key_str: const u8[:]) -> bool { return core::is_in_flight(g, key_str); }
fn ::waiter_count(g: const core::SingleflightGroup&, key_str: const u8[:]) -> i32 { return core::waiter_count(g, key_str); }
fn ::is_shared(g: const core::SingleflightGroup&, key_str: const u8[:]) -> bool { return core::is_shared(g, key_str); }
fn ::result_value(g: const core::SingleflightGroup&, key_str: const u8[:]) -> i64, bool { return core::result_value(g, key_str); }

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

// ---- io stream ufcs bridges ------------------------------------------------

fn ::remaining(r: const core::SliceReader&) -> i64 { return core::remaining(r); }
fn ::is_eof(r: const core::SliceReader&) -> bool { return core::is_eof(r); }
fn ::read(r: core::SliceReader&, dst: u8[:]) -> i64, core::IoError { return core::read(r, dst); }
fn ::read_exact(r: core::SliceReader&, dst: u8[:]) -> core::IoError { return core::read_exact(r, dst); }
fn ::read_slice(r: core::SliceReader&, count: i64) -> const u8[:], core::IoError { return core::read_slice(r, count); }
fn ::read_u8(r: core::SliceReader&) -> u8, core::IoError { return core::read_u8(r); }
fn ::read_u16_be(r: core::SliceReader&) -> u16, core::IoError { return core::read_u16_be(r); }
fn ::read_u16_le(r: core::SliceReader&) -> u16, core::IoError { return core::read_u16_le(r); }
fn ::read_u24_be(r: core::SliceReader&) -> u32, core::IoError { return core::read_u24_be(r); }
fn ::read_u24_le(r: core::SliceReader&) -> u32, core::IoError { return core::read_u24_le(r); }
fn ::read_u32_be(r: core::SliceReader&) -> u32, core::IoError { return core::read_u32_be(r); }
fn ::read_u32_le(r: core::SliceReader&) -> u32, core::IoError { return core::read_u32_le(r); }
fn ::read_u64_be(r: core::SliceReader&) -> u64, core::IoError { return core::read_u64_be(r); }
fn ::read_u64_le(r: core::SliceReader&) -> u64, core::IoError { return core::read_u64_le(r); }
fn ::skip(r: core::SliceReader&, count: i64) -> core::IoError { return core::skip(r, count); }
fn ::peek(r: const core::SliceReader&) -> u8, bool { return core::peek(r); }

fn ::available(w: const core::SliceWriter&) -> i64 { return core::available(w); }
fn ::written(w: const core::SliceWriter&) -> i64 { return core::written(w); }
fn ::write(w: core::SliceWriter&, src: const u8[:]) -> i64, core::IoError { return core::write(w, src); }
fn ::write_exact(w: core::SliceWriter&, src: const u8[:]) -> core::IoError { return core::write_exact(w, src); }
fn ::write_u8(w: core::SliceWriter&, b: u8) -> core::IoError { return core::write_u8(w, b); }
fn ::write_u16_be(w: core::SliceWriter&, v: u16) -> core::IoError { return core::write_u16_be(w, v); }
fn ::write_u24_be(w: core::SliceWriter&, v: u32) -> core::IoError { return core::write_u24_be(w, v); }
fn ::write_u24_le(w: core::SliceWriter&, v: u32) -> core::IoError { return core::write_u24_le(w, v); }
fn ::write_u32_be(w: core::SliceWriter&, v: u32) -> core::IoError { return core::write_u32_be(w, v); }
fn ::write_u64_be(w: core::SliceWriter&, v: u64) -> core::IoError { return core::write_u64_be(w, v); }
fn ::as_written_slice(w: const core::SliceWriter&) -> const u8[:] { return core::as_written_slice(w); }

fn ::append_u16_be<B>(out: B&, v: u16) { core::append_u16_be(out, v); }
fn ::append_u24_be<B>(out: B&, v: u32) { core::append_u24_be(out, v); }
fn ::append_u32_be<B>(out: B&, v: u32) { core::append_u32_be(out, v); }
fn ::append_u64_be<B>(out: B&, v: u64) { core::append_u64_be(out, v); }

fn ::remaining(lr: const core::LimitReader&) -> i64 { return core::remaining(lr); }
fn ::is_eof(lr: const core::LimitReader&) -> bool { return core::is_eof(lr); }
fn ::is_exhausted(lr: const core::LimitReader&) -> bool { return core::is_exhausted(lr); }
fn ::read(lr: core::LimitReader&, dst: u8[:]) -> i64, core::IoError { return core::read(lr, dst); }
fn ::read_slice(lr: core::LimitReader&, count: i64) -> const u8[:], core::IoError { return core::read_slice(lr, count); }

fn ::len(rb: const core::RingBuffer&) -> i64 { return core::len(rb); }
fn ::cap(rb: const core::RingBuffer&) -> i64 { return core::cap(rb); }
fn ::available(rb: const core::RingBuffer&) -> i64 { return core::available(rb); }
fn ::is_empty(rb: const core::RingBuffer&) -> bool { return core::is_empty(rb); }
fn ::is_full(rb: const core::RingBuffer&) -> bool { return core::is_full(rb); }
fn ::write(rb: core::RingBuffer&, src: const u8[:]) -> i64, core::IoError { return core::write(rb, src); }
fn ::read(rb: core::RingBuffer&, dst: u8[:]) -> i64, core::IoError { return core::read(rb, dst); }
fn ::peek(rb: const core::RingBuffer&, dst: u8[:]) -> i64 { return core::peek(rb, dst); }
fn ::discard(rb: core::RingBuffer&, count: i64) -> i64 { return core::discard(rb, count); }
fn ::clear(rb: core::RingBuffer&) { core::clear(rb); }

// ---- pipe & cork buffer ufcs bridges ---------------------------------------

fn ::readable_slice(p: const core::PipeBuffer&) -> const u8[:] { return core::readable_slice(p); }
fn ::unexamined_slice(p: const core::PipeBuffer&) -> const u8[:] { return core::unexamined_slice(p); }
fn ::readable_len(p: const core::PipeBuffer&) -> i64 { return core::readable_len(p); }
fn ::unexamined_len(p: const core::PipeBuffer&) -> i64 { return core::unexamined_len(p); }
fn ::write_space(p: const core::PipeBuffer&) -> i64 { return core::write_space(p); }
fn ::total_available(p: const core::PipeBuffer&) -> i64 { return core::total_available(p); }
fn ::advance_to(p: core::PipeBuffer&, consumed_delta: i64, examined_delta: i64) -> core::IoError { return core::advance_to(p, consumed_delta, examined_delta); }
fn ::get_write_span(p: core::PipeBuffer&, min_size: i64 = 1) -> u8[:], core::IoError { return core::get_write_span(p, min_size); }
fn ::commit_write(p: core::PipeBuffer&, bytes_written: i64) -> core::IoError { return core::commit_write(p, bytes_written); }
fn ::write(p: core::PipeBuffer&, src: const u8[:]) -> i64, core::IoError { return core::write(p, src); }
fn ::complete_pipe(p: core::PipeBuffer&) { core::complete_pipe(p); }
fn ::reset(p: core::PipeBuffer&) { core::reset(p); }

fn ::cork_pending(cb: const core::CorkBuffer&) -> i64 { return core::cork_pending(cb); }
fn ::cork_available(cb: const core::CorkBuffer&) -> i64 { return core::cork_available(cb); }
fn ::cork_is_empty(cb: const core::CorkBuffer&) -> bool { return core::cork_is_empty(cb); }
fn ::cork_is_full(cb: const core::CorkBuffer&) -> bool { return core::cork_is_full(cb); }
fn ::cork_as_slice(cb: const core::CorkBuffer&) -> const u8[:] { return core::cork_as_slice(cb); }
fn ::cork_write(cb: core::CorkBuffer&, src: const u8[:]) -> i64, core::IoError { return core::cork_write(cb, src); }
fn ::cork_write_exact(cb: core::CorkBuffer&, src: const u8[:]) -> core::IoError { return core::cork_write_exact(cb, src); }
fn ::cork_write_u8(cb: core::CorkBuffer&, b: u8) -> core::IoError { return core::cork_write_u8(cb, b); }
fn ::cork_write_u16_be(cb: core::CorkBuffer&, v: u16) -> core::IoError { return core::cork_write_u16_be(cb, v); }
fn ::cork_write_u24_be(cb: core::CorkBuffer&, v: u32) -> core::IoError { return core::cork_write_u24_be(cb, v); }
fn ::cork_write_u32_be(cb: core::CorkBuffer&, v: u32) -> core::IoError { return core::cork_write_u32_be(cb, v); }
fn ::cork_write_u64_be(cb: core::CorkBuffer&, v: u64) -> core::IoError { return core::cork_write_u64_be(cb, v); }
fn ::cork_consume(cb: core::CorkBuffer&, n: i64) { core::cork_consume(cb, n); }
fn ::cork_reset(cb: core::CorkBuffer&) { core::cork_reset(cb); }

// ---- bytes & stringview ufcs bridges ----------------------------------------

fn ::eq_ascii_fold(a: const u8[:], b: const u8[:]) -> bool { return core::eq_ascii_fold(a, b); }
fn ::starts_with_fold(s: const u8[:], prefix: const u8[:]) -> bool { return core::starts_with_fold(s, prefix); }
fn ::ends_with_fold(s: const u8[:], suffix: const u8[:]) -> bool { return core::ends_with_fold(s, suffix); }
fn ::contains_fold(haystack: const u8[:], needle: const u8[:]) -> bool { return core::contains_fold(haystack, needle); }
fn ::index_of_fold(haystack: const u8[:], needle: const u8[:]) -> i64 { return core::index_of_fold(haystack, needle); }

fn ::trim_lws(s: const u8[:]) -> const u8[:] { return core::trim_lws(s); }
fn ::trim_lws_start(s: const u8[:]) -> const u8[:] { return core::trim_lws_start(s); }
fn ::trim_lws_end(s: const u8[:]) -> const u8[:] { return core::trim_lws_end(s); }
fn ::trim_ascii_space(s: const u8[:]) -> const u8[:] { return core::trim_ascii_space(s); }
fn ::trim_ascii_space_start(s: const u8[:]) -> const u8[:] { return core::trim_ascii_space_start(s); }
fn ::trim_ascii_space_end(s: const u8[:]) -> const u8[:] { return core::trim_ascii_space_end(s); }
fn ::trim_byte(s: const u8[:], b: u8) -> const u8[:] { return core::trim_byte(s, b); }
fn ::trim_start_byte(s: const u8[:], b: u8) -> const u8[:] { return core::trim_start_byte(s, b); }
fn ::trim_end_byte(s: const u8[:], b: u8) -> const u8[:] { return core::trim_end_byte(s, b); }
fn ::trim_bytes(s: const u8[:], set: const u8[:]) -> const u8[:] { return core::trim_bytes(s, set); }
fn ::trim_start_bytes(s: const u8[:], set: const u8[:]) -> const u8[:] { return core::trim_start_bytes(s, set); }
fn ::trim_end_bytes(s: const u8[:], set: const u8[:]) -> const u8[:] { return core::trim_end_bytes(s, set); }

fn ::contains_byte(s: const u8[:], b: u8) -> bool { return core::contains_byte(s, b); }
fn ::index_of_byte(s: const u8[:], b: u8) -> i64 { return core::index_of_byte(s, b); }
fn ::last_index_of_byte(s: const u8[:], b: u8) -> i64 { return core::last_index_of_byte(s, b); }
fn ::index_of_slice(haystack: const u8[:], needle: const u8[:]) -> i64 { return core::index_of_slice(haystack, needle); }
fn ::count_byte(s: const u8[:], b: u8) -> i64 { return core::count_byte(s, b); }

fn ::split_once_byte(s: const u8[:], delim: u8) -> const u8[:], const u8[:], bool { return core::split_once_byte(s, delim); }
fn ::rsplit_once_byte(s: const u8[:], delim: u8) -> const u8[:], const u8[:], bool { return core::rsplit_once_byte(s, delim); }
fn ::split_once(s: const u8[:], delim: const u8[:]) -> const u8[:], const u8[:], bool { return core::split_once(s, delim); }
fn ::split_once_fold(s: const u8[:], delim: const u8[:]) -> const u8[:], const u8[:], bool { return core::split_once_fold(s, delim); }
fn ::make_byte_tokenizer(src: const u8[:], delim: u8) -> core::ByteTokenizer { return core::make_byte_tokenizer(src, delim); }
fn ::token_next(tok: core::ByteTokenizer&) -> const u8[:], bool { return core::token_next(tok); }

fn ::parse_u64_dec(s: const u8[:]) -> u64, bool { return core::parse_u64_dec(s); }
fn ::parse_i64_dec(s: const u8[:]) -> i64, bool { return core::parse_i64_dec(s); }
fn ::parse_u32_dec(s: const u8[:]) -> u32, bool { return core::parse_u32_dec(s); }
fn ::parse_i32_dec(s: const u8[:]) -> i32, bool { return core::parse_i32_dec(s); }
fn ::parse_u64_hex(s: const u8[:]) -> u64, bool { return core::parse_u64_hex(s); }
fn ::parse_u32_hex(s: const u8[:]) -> u32, bool { return core::parse_u32_hex(s); }
fn ::parse_u8_hex(s: const u8[:]) -> u8, bool { return core::parse_u8_hex(s); }

fn ::to_lower_ascii<B>(src: const u8[:], out: B&) { core::to_lower_ascii(src, out); }
fn ::to_upper_ascii<B>(src: const u8[:], out: B&) { core::to_upper_ascii(src, out); }
fn ::format_u64_dec<B>(val: u64, out: B&) { core::format_u64_dec(val, out); }
fn ::format_i64_dec<B>(val: i64, out: B&) { core::format_i64_dec(val, out); }
fn ::format_u64_hex<B>(val: u64, out: B&, uppercase: bool = false) { core::format_u64_hex(val, out, uppercase); }
fn ::format_u32_hex<B>(val: u32, out: B&, uppercase: bool = false) { core::format_u32_hex(val, out, uppercase); }
fn ::format_u8_hex<B>(val: u8, out: B&, uppercase: bool = false) { core::format_u8_hex(val, out, uppercase); }

