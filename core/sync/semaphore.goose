// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Counting semaphore & permit pool (bulkhead pattern) for bounded concurrency.
namespace core;

import std;

// Flat ticket token representing an active execution slot in a concurrency quota.
struct SemPermit {
    epoch:   u32 = 1,
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
    guard permit.epoch > 0 else { return false; }
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

// Creates a new semaphore with given capacity.
fn new_semaphore(capacity: i64) -> Semaphore {
    if capacity > 0 {
        sem_init(capacity as u16);
    }
    return Semaphore { capacity: capacity };
}

// Blocks until a permit is acquired from the semaphore.
fn acquire(sem: Semaphore&) -> SemPermit {
    return sem_acquire();
}

// Non-blocking attempt to acquire a permit from the semaphore.
fn try_acquire(sem: Semaphore&) -> SemPermit, bool {
    return sem_try_acquire();
}

// Releases an execution permit back to the semaphore.
fn release(sem: Semaphore&, permit: SemPermit) -> bool {
    return sem_release(permit);
}
