// Semantic strong type aliases for network descriptors, streams, and time units.
// Eliminates unit ambiguity and primitive obsession across the Layer 4-7 stack.
namespace wing;

import std;

// System descriptor and identifier types
type SocketFd     = i32; // OS socket descriptor (-1 for invalid/unassigned)
type StreamId     = u32; // HTTP/2 or HTTP/3 stream identifier (1, 3, 5... for client-initiated)
type ConnectionId = u64; // High-resolution connection pool tracking tag
type EventTag     = u64; // EventLoop / Poller user data tag
type TimerId      = u64; // Monotonic timer wheel registration ID
type Port         = u16; // TCP/UDP port number (0..65535)

// Time unit representations
type Nanoseconds  = u64; // Monotonic clock nanoseconds
type Milliseconds = u64; // Timeout and delay intervals in milliseconds
type Microseconds = u64; // High-precision RTT and metrics in microseconds
type UnixSeconds  = i64; // Wall-clock UTC timestamp in seconds since UNIX epoch
