// Baton Mutex: Zero-overhead ownership token passing over channel queues.
namespace core;

import std;

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

// Creates a new BatonMutex holding initial_val.
fn new_baton<T>(initial_val: T) -> BatonMutex<T> {
    new_baton_mutex(initial_val);
    return BatonMutex<T> { is_active: true };
}

// Blocks until ownership of the protected value is acquired.
fn lock<T>(bm: BatonMutex<T>&) -> T {
    return baton_lock<T>();
}

// Non-blocking attempt to acquire protected value ownership.
fn try_lock<T>(bm: BatonMutex<T>&) -> T, bool {
    return baton_try_lock<T>();
}

// Releases ownership of protected value back to BatonMutex.
fn unlock<T>(bm: BatonMutex<T>&, val: T) -> bool {
    return baton_unlock<T>(val);
}
