// Concurrency primitives, actor message passing, CSP channels, supervisor trees, and singleflight call suppression.
namespace wing;

import std;
import os;

// ---- runtime primitives, channels & parallelism ---------------------------

// Returns the number of physical hardware execution threads available.
fn available_parallelism() -> i64 {
    return max(1, hardware_threads());
}

// Sets queue capacity backpressure limit for type T. Past this limit, send_msg returns false.
// Returns false if limit <= 0 without invoking qlimit, preventing unrecoverable runtime aborts.
fn set_channel_limit<T>(limit: i64) -> bool {
    if limit <= 0 {
        return false;
    }
    qlimit<T>(limit);
    return true;
}

// Sends a flat message to the queue for type T. Returns false if bounded queue is full.
fn send_msg<T>(msg: T) -> bool {
    return qput(msg);
}

// Sends a flat message to the queue for type T, waiting at most timeout_ms if bounded queue is full.
fn send_msg_timeout<T>(msg: T, timeout_ms: i64) -> bool {
    if qput(msg) { return true; }
    if timeout_ms <= 0 { return false; }
    let start_ns = clock_ns();
    let timeout_ns = timeout_ms * 1000000;
    while clock_ns() - start_ns < timeout_ns {
        sleep_ms(1);
        if qput(msg) { return true; }
    }
    return false;
}

// Receives a message from the queue for type T, blocking indefinitely until available.
fn recv_msg<T>() -> T {
    return qget<T>();
}

// Receives a message from the queue for type T, waiting at most timeout_ms milliseconds.
// Negative timeout_ms represents an expired deadline and returns zero value + false immediately.
fn recv_msg_timeout<T>(timeout_ms: i64) -> T, bool {
    if timeout_ms < 0 {
        return default<T>(), false;
    }
    return qget<T>(timeout_ms);
}

// Non-blocking poll for a message of type T. Returns zero value and false if empty.
fn try_recv_msg<T>() -> T, bool {
    return qpoll<T>();
}

// Drains up to max_items available messages from queue T into a buffer.
// Returns the number of messages successfully drained.
fn drain_channel<T, B>(max_items: i64, out: B&) -> i64 {
    if max_items <= 0 { return 0; }
    var count = 0;
    while count < max_items {
        let item, ok = qpoll<T>();
        if !ok { break; }
        out.push(item);
        count++;
    }
    return count;
}

// ---- baton mutex: ownership token passing ---------------------------------

// Flat container holding the single mutable instance of T.
struct Baton<T> {
    data: T,
}

// Initializes a BatonMutex queue of capacity 1 with the initial protected state.
fn new_baton_mutex<T>(initial_val: T) {
    qlimit<Baton<T>>(1);
    qput(Baton<T> { data: initial_val });
}

// Blocks until ownership of the protected value T is acquired into the local stack frame.
fn baton_lock<T>() -> T {
    let b = qget<Baton<T>>();
    return b.data;
}

// Non-blocking attempt to acquire ownership. Returns data and true if available, false if busy.
fn baton_try_lock<T>() -> T, bool {
    let b, ok = qpoll<Baton<T>>();
    if ok {
        return b.data, true;
    }
    return default<T>(), false;
}

// Releases ownership of updated value T back into the Baton queue.
fn baton_unlock<T>(val: T) -> bool {
    return qput(Baton<T> { data: val });
}

// Struct-encapsulated BatonMutex wrapper.
struct BatonMutex<T> {
    is_active: bool = false,
}

fn new_baton<T>(initial_val: T) -> BatonMutex<T> {
    new_baton_mutex(initial_val);
    return BatonMutex<T> { is_active: true };
}

fn lock<T>(bm: BatonMutex<T>&) -> T {
    return baton_lock<T>();
}

fn try_lock<T>(bm: BatonMutex<T>&) -> T, bool {
    return baton_try_lock<T>();
}

fn unlock<T>(bm: BatonMutex<T>&, val: T) -> bool {
    return baton_unlock<T>(val);
}

// ---- counting semaphore & permit pool (bulkhead) --------------------------

// Flat ticket token representing an active execution slot in a concurrency quota.
struct SemPermit {
    epoch: u32 = 1,
    slot_id: u16 = 0,
}

// Initializes a global typed counting semaphore with K tickets.
fn sem_init(k: u16) {
    qlimit<SemPermit>(k as i64);
    for i: u16 in k {
        qput(SemPermit { epoch: 1, slot_id: i });
    }
}

// Blocks until an execution permit is acquired from the pool.
fn sem_acquire() -> SemPermit {
    return qget<SemPermit>();
}

// Non-blocking attempt to acquire a permit. Fails immediately if pool is saturated.
fn sem_try_acquire() -> SemPermit, bool {
    return qpoll<SemPermit>();
}

// Returns an execution permit back to the pool.
fn sem_release(permit: SemPermit) -> bool {
    return qput(permit);
}

// Explicit transfer of permit ownership into a nested recursive job without exhausting quotas.
fn sem_transfer(permit: SemPermit) -> SemPermit {
    return permit;
}

// Semaphore object wrapper.
struct Semaphore {
    capacity: i64 = 0,
}

fn new_semaphore(capacity: i64) -> Semaphore {
    if capacity > 0 {
        sem_init(capacity as u16);
    }
    return Semaphore { capacity: capacity };
}

fn acquire(sem: Semaphore&) -> SemPermit {
    return sem_acquire();
}

fn try_acquire(sem: Semaphore&) -> SemPermit, bool {
    return sem_try_acquire();
}

fn release(sem: Semaphore&, permit: SemPermit) -> bool {
    return sem_release(permit);
}

// ---- wait group & count down latch ----------------------------------------

// WaitGroup coordinates and waits for a collection of worker threads to finish.
struct WaitGroup {
    failed_count_val: i64 = 0,
    worker_ids: i64[>..] = [],
}

fn new_wait_group() -> WaitGroup {
    return WaitGroup { .. };
}

fn add_worker(wg: WaitGroup&, worker_id: i64) -> bool {
    wg.worker_ids.push(worker_id);
    return true;
}

// Returns the number of workers registered in the wait group.
fn worker_count(wg: const WaitGroup&) -> i64 {
    return wg.worker_ids.len;
}

// Returns the count of failed/aborted workers from the last wait_all.
fn failed_count(wg: const WaitGroup&) -> i64 {
    return wg.failed_count_val;
}

// Blocks until all registered workers terminate, capturing failure diagnostics.
// Returns true if all finished without aborting, false otherwise.
fn wait_all(wg: WaitGroup&, out_diagnostics: u8[>..]&) -> bool {
    var all_ok = true;
    wg.failed_count_val = 0;
    for id in wg.worker_ids {
        var err: u8[>..] = [];
        let ok = thread_wait(id, err);
        if !ok {
            all_ok = false;
            wg.failed_count_val++;
            if err.len > 0 {
                out_diagnostics.append(err);
                out_diagnostics.push('\n');
            }
        }
    }
    wg.worker_ids.clear();
    return all_ok;
}

// Blocks until all registered workers terminate. Returns true if all finished without aborting.
fn wait_all(wg: WaitGroup&) -> bool {
    var dummy: u8[>..] = [];
    return wait_all(wg, dummy);
}

// One-shot synchronization latch for K ticking workers and M awaiting threads.
struct LatchTick {
    step: i32 = 1,
}

struct LatchOpen {
    marker: u8 = 1,
}

struct CountDownLatch {
    expected: i64 = 0,
}

fn new_count_down_latch(expected: i64) -> CountDownLatch {
    return CountDownLatch { expected: expected };
}

fn count_down(latch: CountDownLatch&) -> bool {
    return qput(LatchTick { step: 1 });
}

fn latch_tick() -> bool {
    return qput(LatchTick { step: 1 });
}

fn latch_open(waiter_count: i64) {
    for i in waiter_count {
        qput(LatchOpen { marker: 1 });
    }
}

fn latch_wait(latch: CountDownLatch&) {
    let open = qget<LatchOpen>();
}

fn latch_wait() {
    let open = qget<LatchOpen>();
}

// ---- cyclic barrier: two-phase generation turnstile -----------------------

struct BarrierArrive {
    worker_id: i32 = 0,
    epoch: u64 = 0,
}

struct BarrierRelease {
    epoch: u64 = 0,
}

struct BarrierDepart {
    worker_id: i32 = 0,
    epoch: u64 = 0,
}

struct BarrierDepartAck {
    epoch: u64 = 0,
}

// Coordinator process implementing a mathematically safe two-phase turnstile cyclic barrier.
thread_fn barrier_coordinator(n_participants: i32) {
    var current_epoch: u64 = 0;

    loop {
        // Phase 1: Wait for all N participants to arrive at current_epoch
        var arrived_count: i32 = 0;
        while arrived_count < n_participants {
            let msg = qget<BarrierArrive>();
            if msg.epoch == 0xFFFFFFFFFFFFFFFF {
                return; // Shutdown signal
            }
            if msg.epoch == current_epoch {
                arrived_count++;
            }
        }

        // Release Turnstile 1
        for i in n_participants {
            qput(BarrierRelease { epoch: current_epoch });
        }

        // Phase 2: Wait for all N participants to depart Turnstile 1
        var departed_count: i32 = 0;
        while departed_count < n_participants {
            let dep = qget<BarrierDepart>();
            if dep.epoch == current_epoch {
                departed_count++;
            }
        }

        // Release Turnstile 2: All participants can now safely advance
        for i in n_participants {
            qput(BarrierDepartAck { epoch: current_epoch });
        }

        current_epoch++;
    }
}

// Spawns a background barrier coordinator for N participants.
fn barrier_start(n_participants: i32) -> i64 {
    return thread_spawn(barrier_coordinator, n_participants);
}

// Synchronizes participant on the cyclic barrier. Returns the incremented local epoch.
fn barrier_sync(worker_id: i32, local_epoch: u64) -> u64 {
    qput(BarrierArrive { worker_id: worker_id, epoch: local_epoch });
    let rel = qget<BarrierRelease>();
    qput(BarrierDepart { worker_id: worker_id, epoch: local_epoch });
    let ack = qget<BarrierDepartAck>();
    return local_epoch + 1;
}

// Signals the barrier coordinator to terminate cleanly.
fn barrier_stop() {
    qput(BarrierArrive { worker_id: -1, epoch: 0xFFFFFFFFFFFFFFFF });
}

// ---- csp channels, rendezvous & in-order reassembler ----------------------

// Static typed channel envelope. Generates an isolated physical queue per (Tag, T).
struct Envelope<Tag, T> {
    payload: T,
}

fn chan_send<Tag, T>(msg: T) -> bool {
    return qput(Envelope<Tag, T> { payload: msg });
}

fn chan_recv<Tag, T>() -> T {
    let env = qget<Envelope<Tag, T>>();
    return env.payload;
}

fn chan_try_recv<Tag, T>() -> T, bool {
    let env, ok = qpoll<Envelope<Tag, T>>();
    if ok {
        return env.payload, true;
    }
    return default<T>(), false;
}

fn chan_recv_timeout<Tag, T>(timeout_ms: i64) -> T, bool {
    if timeout_ms < 0 {
        return default<T>(), false;
    }
    let env, ok = qget<Envelope<Tag, T>>(timeout_ms);
    if ok {
        return env.payload, true;
    }
    return default<T>(), false;
}

// Bidirectional synchronous rendezvous acknowledgment token.
struct Ack<Tag> {
    status_ok: bool = true,
}

fn chan_rendezvous<Tag, Req>(req: Req) -> bool {
    qput(Envelope<Tag, Req> { payload: req });
    let ack = qget<Ack<Tag>>();
    return ack.status_ok;
}

fn chan_rendezvous_reply<Tag>(ok: bool = true) -> bool {
    return qput(Ack<Tag> { status_ok: ok });
}

// Variable-mode ADT multiplexing event enum.
enum MuxEvent {
    DataPacket { stream_id: u16, bytes: u8[..256] },
    ControlCmd { code: u8 },
    TimerTick  { timestamp_ns: u64 },
    Shutdown,
}

// Generic in-order reassembler item.
struct ReassemblerItem {
    seq_id: i64 = 0,
    data: u8[..256] = [],
}

// In-Order stream reassembly buffer for Fan-Out parallel worker pipelines.
struct Reassembler {
    next_expected_seq: i64 = 0,
    stash: ReassemblerItem[>..<] = [],
}

fn new_reassembler(initial_seq: i64 = 0) -> Reassembler {
    return Reassembler { next_expected_seq: initial_seq, .. };
}

fn push_unordered(r: Reassembler&, item: ReassemblerItem) {
    r.stash.push(item);
}

fn pop_next_in_order(r: Reassembler&) -> ReassemblerItem, bool {
    for idx in r.stash.len {
        if r.stash[idx].seq_id == r.next_expected_seq {
            let found = r.stash[idx];
            r.stash[idx] = r.stash[r.stash.len - 1];
            r.stash.pop();
            r.next_expected_seq++;
            return found, true;
        }
    }
    return ReassemblerItem { .. }, false;
}

fn pending_count(r: const Reassembler&) -> i64 {
    return r.stash.len;
}

// ---- actor addressing, stash buffer & priority mailboxes ------------------

// 16-byte flat position-independent actor handle without heap references or pointers.
struct ActorRef {
    actor_id: u32 = 0,
    generation: u32 = 0,
    node_id: u32 = 0,
    mailbox_tag: u32 = 0,
}

fn new_actor_ref(actor_id: u32, generation: u32 = 1, node_id: u32 = 0, mailbox_tag: u32 = 0) -> ActorRef {
    return ActorRef {
        actor_id: actor_id,
        generation: generation,
        node_id: node_id,
        mailbox_tag: mailbox_tag,
    };
}

fn eq_actor_ref(a: const ActorRef&, b: const ActorRef&) -> bool {
    return a.actor_id == b.actor_id &&
           a.generation == b.generation &&
           a.node_id == b.node_id &&
           a.mailbox_tag == b.mailbox_tag;
}

// Deferred envelope stored on bump-pointer data stacks during state transitions.
struct StashedEnvelope {
    priority: u32 = 0,
    seq: u32 = 0,
    payload_type: u16 = 0,
    data: u8[..256] = [],
}

struct StashBuffer {
    messages: StashedEnvelope[>..] = [],
}

fn new_stash_buffer() -> StashBuffer {
    return StashBuffer { .. };
}

fn stash(sb: StashBuffer&, env: StashedEnvelope) {
    sb.messages.push(env);
}

fn unstash_all(sb: StashBuffer&, out_pending: StashedEnvelope[>..]&) -> i64 {
    let count = sb.messages.len;
    for msg in sb.messages {
        out_pending.push(msg);
    }
    sb.messages.clear();
    return count;
}

fn stash_count(sb: const StashBuffer&) -> i64 {
    return sb.messages.len;
}

fn is_empty(sb: const StashBuffer&) -> bool {
    return sb.messages.len == 0;
}

// Stable priority queue item for binary heap mailboxes.
struct PriorityItem {
    sort_key: u64 = 0, // (priority_u32 << 32) | (seq_counter_u32 & 0xFFFFFFFF)
    payload_type: u16 = 0,
    payload_val: i64 = 0,
}

// Zero-allocation binary min-heap priority mailbox on grow-shrink data stacks.
struct PriorityMailbox {
    seq_counter: u32 = 0,
    heap: PriorityItem[>..<] = [],
}

fn new_priority_mailbox() -> PriorityMailbox {
    return PriorityMailbox { .. };
}

fn push(mb: PriorityMailbox&, priority: u32, payload_type: u16, val: i64) {
    let key = ((priority as u64) << 32) | ((mb.seq_counter as u64) & 0xFFFFFFFF);
    mb.seq_counter++;
    mb.heap.heap_push(PriorityItem {
        sort_key: key,
        payload_type: payload_type,
        payload_val: val,
    }) { a, b => a.sort_key < b.sort_key };
}

fn pop(mb: PriorityMailbox&) -> PriorityItem, bool {
    if mb.heap.len == 0 {
        return PriorityItem { .. }, false;
    }
    let item = mb.heap.heap_pop() { a, b => a.sort_key < b.sort_key };
    return item, true;
}

fn count(mb: const PriorityMailbox&) -> i64 {
    return mb.heap.len;
}

// ---- supervision trees, fault tolerance & restart policies ----------------

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
    sup.statuses.push(WorkerStatus {
        worker_id: worker_id,
        ok: false,
        reason: ExitReason.Normal,
        restart_type: RestartType.Permanent,
        significant: false,
        restarts_count: 0,
    });
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
        ok: false,
        reason: ExitReason.Normal,
        restart_type: spec.restart_type,
        significant: spec.significant,
        restarts_count: spec.restarts_count,
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
    if child_idx < 0 || child_idx >= sup.statuses.len {
        return false;
    }
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
    if child_idx < 0 || child_idx >= sup.statuses.len {
        return false;
    }
    let cutoff = current_time_s - sup.spec.max_seconds;
    var count_in_window: i64 = 0;
    for t in sup.restart_history_times_s {
        if t >= cutoff {
            count_in_window++;
        }
    }
    if count_in_window >= sup.spec.max_restarts {
        return false; // Intensity threshold exceeded!
    }
    if sup.restart_history_times_s.len < 32 {
        sup.restart_history_times_s.push(current_time_s);
    }
    sup.statuses[child_idx].restarts_count++;
    return true;
}

fn evaluate_auto_shutdown(sup: Supervisor&) {
    if sup.spec.auto_shutdown == AutoShutdown.Never {
        return;
    }
    var significant_count = 0;
    var terminated_significant_count = 0;
    for i in sup.statuses.len {
        if sup.statuses[i].significant {
            significant_count++;
            if !sup.statuses[i].ok {
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
    for i in sup.statuses.len {
        var err: u8[>..] = [];
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

// ---- singleflight: duplicate call suppression -----------------------------
// Suppresses duplicate concurrent executions for the same key.

struct FlightEntry {
    key: u8[..64] = [],
    is_in_flight: bool = false,
    is_done: bool = false,
    has_failed: bool = false,
    val: i64 = 0,
    waiter_count: i32 = 0,
    shared: bool = false,
}

struct SingleflightGroup {
    entries: FlightEntry[..32] = [],
    total_leader_calls: i64 = 0,
    total_shared_calls: i64 = 0,
}

fn new_singleflight_group() -> SingleflightGroup {
    return SingleflightGroup { .. };
}

// Registers or joins an execution for key_str.
// Returns (is_leader, val, shared).
// If is_leader is true, the caller executes the operation and calls finish_call.
// If is_leader is false and execution is in-flight, returns (false, 0, true).
// If already completed, returns the cached result.
fn start_or_join(g: SingleflightGroup&, key_str: const u8[:]) -> bool, i64, bool {
    for idx in g.entries.len {
        if g.entries[idx].key[..] == key_str {
            if g.entries[idx].is_in_flight {
                g.entries[idx].waiter_count++;
                g.entries[idx].shared = true;
                g.total_shared_calls++;
                return false, 0, true; // Follower
            }
            if g.entries[idx].is_done {
                return false, g.entries[idx].val, g.entries[idx].shared; // Cached completion
            }
        }
    }

    if g.entries.len < g.entries.cap {
        var new_entry = FlightEntry {
            is_in_flight: true,
            is_done: false,
            has_failed: false,
            val: 0,
            waiter_count: 0,
            shared: false,
            ..
        };
        new_entry.key.append(key_str);
        g.entries.push(new_entry);
        g.total_leader_calls++;
        return true, 0, false; // Leader
    }

    // Capacity overflow fallback: execute unshared
    g.total_leader_calls++;
    return true, 0, false;
}

// Marks the in-flight key execution as finished with val and success status.
// Returns (true, waiter_count) if the key was found in-flight.
fn finish_call(g: SingleflightGroup&, key_str: const u8[:], val: i64, ok: bool = true) -> bool, i32 {
    for idx in g.entries.len {
        if g.entries[idx].key[..] == key_str && g.entries[idx].is_in_flight {
            g.entries[idx].is_in_flight = false;
            g.entries[idx].is_done = true;
            g.entries[idx].has_failed = !ok;
            g.entries[idx].val = val;
            let waiters = g.entries[idx].waiter_count;
            return true, waiters;
        }
    }
    return false, 0;
}

// forget evicts key_str from the group immediately, allowing the next caller to execute as leader.
// Returns true if the key was found and removed, false otherwise.
fn forget(g: SingleflightGroup&, key_str: const u8[:]) -> bool {
    for idx in g.entries.len {
        if g.entries[idx].key[..] == key_str {
            g.entries[idx] = g.entries[g.entries.len - 1];
            g.entries.pop();
            return true;
        }
    }
    return false;
}

// Removes key_str only if it was not shared with any concurrent caller (waiter_count == 0).
// Returns true if removed, false if preserved.
fn forget_unshared(g: SingleflightGroup&, key_str: const u8[:]) -> bool {
    for idx in g.entries.len {
        if g.entries[idx].key[..] == key_str {
            if g.entries[idx].waiter_count == 0 {
                g.entries[idx] = g.entries[g.entries.len - 1];
                g.entries.pop();
                return true;
            }
            return false;
        }
    }
    return false;
}

// Queries whether key is currently executing in-flight.
fn is_in_flight(g: const SingleflightGroup&, key_str: const u8[:]) -> bool {
    for idx in g.entries.len {
        if g.entries[idx].key[..] == key_str && g.entries[idx].is_in_flight {
            return true;
        }
    }
    return false;
}

// Returns the count of concurrent waiters for key.
fn waiter_count(g: const SingleflightGroup&, key_str: const u8[:]) -> i32 {
    for idx in g.entries.len {
        if g.entries[idx].key[..] == key_str {
            return g.entries[idx].waiter_count;
        }
    }
    return 0;
}

// Returns whether the call for key was shared across multiple callers.
fn is_shared(g: const SingleflightGroup&, key_str: const u8[:]) -> bool {
    for idx in g.entries.len {
        if g.entries[idx].key[..] == key_str {
            return g.entries[idx].shared;
        }
    }
    return false;
}

// Retrieves the result value and completion status of a finished call.
fn result_value(g: const SingleflightGroup&, key_str: const u8[:]) -> i64, bool {
    for idx in g.entries.len {
        if g.entries[idx].key[..] == key_str && g.entries[idx].is_done {
            return g.entries[idx].val, !g.entries[idx].has_failed;
        }
    }
    return 0, false;
}
