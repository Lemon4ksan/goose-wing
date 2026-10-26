// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Supervision trees, worker failure containment, and OTP-style restart policies.
namespace core;

import std;
import os;

enum ExitReason {
    Normal,
    Shutdown,
    ShutdownWith { code: i32, info: u8[..64] },
    Abnormal { error_code: i32, details: u8[..64] },
}

enum Strategy {
    OneForOne,
    OneForAll,
    RestForOne,
    SimpleOneForOne,
}

enum RestartType {
    Permanent,
    Transient,
    Temporary,
}

enum AutoShutdown {
    Never,
    AnySignificant,
    AllSignificant,
}

struct ChildSpec {
    id: i64 = 0,
    restart_type: RestartType = RestartType.Permanent,
    significant: bool = false,
    worker_id: i64 = 0,
    restarts_count: i32 = 0,
}

struct SupervisorSpec {
    strategy: Strategy = Strategy.OneForOne,
    max_restarts: i32 = 3,
    max_seconds: i32 = 5,
    auto_shutdown: AutoShutdown = AutoShutdown.Never,
}

// Represents the terminal execution status and specification of a supervised worker.
struct WorkerStatus {
    worker_id: i64 = 0,
    ok: bool = false,
    reason: ExitReason = ExitReason.Normal,
    restart_type: RestartType = RestartType.Permanent,
    significant: bool = false,
    restarts_count: i32 = 0,
}

// Supervisor monitors background workers, containing crashes and enforcing restart policies.
struct Supervisor {
    spec: SupervisorSpec = SupervisorSpec { .. },
    failed_count_val: i64 = 0,
    success_count_val: i64 = 0,
    is_auto_shutdown_val: bool = false,
    restart_history_times_s: i64[..32] = [],
    statuses: WorkerStatus[>..] = [],
}

fn new_supervisor() -> Supervisor {
    return Supervisor { .. };
}

fn new_supervisor(spec: SupervisorSpec) -> Supervisor {
    return Supervisor { spec: spec, .. };
}

fn add_worker(sup: Supervisor&, worker_id: i64) -> bool {
    sup.statuses.push(WorkerStatus { worker_id: worker_id, .. });
    return true;
}

fn add_child(sup: Supervisor&, spec: ChildSpec, worker_id: i64) -> bool {
    if sup.spec.auto_shutdown == AutoShutdown.Never && spec.significant {
        return false; // OTP rule: significant prohibited if auto_shutdown is Never
    }
    if spec.restart_type == RestartType.Permanent && spec.significant {
        return false; // OTP rule: permanent processes cannot be marked significant
    }
    sup.statuses.push(WorkerStatus {
        worker_id: worker_id,
        restart_type: spec.restart_type,
        significant: spec.significant,
        restarts_count: spec.restarts_count,
        ..
    });
    return true;
}

fn child_count(sup: const Supervisor&) -> i64 {
    return sup.statuses.len;
}

fn failed_count(sup: const Supervisor&) -> i64 {
    return sup.failed_count_val;
}

fn success_count(sup: const Supervisor&) -> i64 {
    return sup.success_count_val;
}

fn is_auto_shutdown(sup: const Supervisor&) -> bool {
    return sup.is_auto_shutdown_val;
}

fn should_restart_child(sup: const Supervisor&, child_idx: i64, reason: const ExitReason&) -> bool {
    guard child_idx >= 0 && child_idx < sup.statuses.len else { return false; }
    let rtype = sup.statuses[child_idx].restart_type;
    if rtype == RestartType.Permanent {
        return true;
    }
    if rtype == RestartType.Temporary {
        return false;
    }
    // Transient: only restart on Abnormal failure
    return match reason {
        Abnormal a => true,
        _ => false,
    };
}

fn record_failure(sup: Supervisor&, child_idx: i64, current_time_s: i64) -> bool {
    guard child_idx >= 0 && child_idx < sup.statuses.len else { return false; }
    let cutoff = current_time_s - sup.spec.max_seconds;
    var count_in_window: i64 = 0;
    for t in sup.restart_history_times_s {
        if t >= cutoff {
            count_in_window++;
        }
    }
    guard count_in_window < sup.spec.max_restarts else {
        return false; // Intensity threshold exceeded!
    }
    if sup.restart_history_times_s.len < sup.restart_history_times_s.cap {
        sup.restart_history_times_s.push(current_time_s);
    }
    sup.statuses[child_idx].restarts_count++;
    return true;
}

fn evaluate_auto_shutdown(sup: Supervisor&) {
    guard sup.spec.auto_shutdown != AutoShutdown.Never else { return; }
    var significant_count = 0;
    var terminated_significant_count = 0;
    for &st in sup.statuses {
        if st.significant {
            significant_count++;
            if !st.ok {
                terminated_significant_count++;
            }
        }
    }
    if sup.spec.auto_shutdown == AutoShutdown.AnySignificant && terminated_significant_count > 0 {
        sup.is_auto_shutdown_val = true;
    } else if sup.spec.auto_shutdown == AutoShutdown.AllSignificant &&
               significant_count > 0 &&
               terminated_significant_count == significant_count {
        sup.is_auto_shutdown_val = true;
    }
}

// Blocks until all supervised workers terminate, capturing execution status and crash diagnostics.
// Returns true if all workers succeeded, false if any worker aborted.
fn wait_all(sup: Supervisor&, out_diagnostics: u8[>..]&) -> bool {
    var all_ok = true;
    sup.failed_count_val = 0;
    sup.success_count_val = 0;
    var err: u8[>..] = [];
    for i in sup.statuses.len {
        err.clear();
        let ok = thread_wait(sup.statuses[i].worker_id, err);
        sup.statuses[i].ok = ok;
        if ok {
            sup.statuses[i].reason = ExitReason.Normal;
            sup.success_count_val++;
        } else {
            all_ok = false;
            var details_buf: u8[..64] = [];
            if err.len > 0 {
                let copy_len = min(err.len, 64);
                details_buf.append(err[..copy_len]);
                out_diagnostics.append(err);
                out_diagnostics.push('\n');
            }
            sup.statuses[i].reason = ExitReason.Abnormal { error_code: 1, details: details_buf };
            sup.failed_count_val++;
        }
    }
    evaluate_auto_shutdown(sup);
    return all_ok;
}

// Blocks until all supervised workers terminate. Returns true if all finished without aborting.
fn wait_all(sup: Supervisor&) -> bool {
    var dummy: u8[>..] = [];
    return wait_all(sup, dummy);
}
