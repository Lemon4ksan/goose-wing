// Layer 4 Transport Driver Architecture & Zero-Copy Engine.
// Provides selectable high-performance L4 transport drivers:
// 1. Standard: Cross-platform zero-dependency sockets (POSIX / WinSock2 stream).
// 2. IoUring: Linux 6.1+ kernel submission/completion (SQ/CQ) ring queues.
// 3. WindowsRIO: Windows Registered I/O (RIO zero-copy, page-locked memory buffers, mswsock.dll).
// 4. Kqueue: macOS / Darwin kevent event multiplexing with exact buffer metrics.
namespace internal;

import std;

import net.driver.types;
import net.driver.rio;
import net.driver.uring;
import net.driver.kqueue;
import net.driver.af_xdp;
import net.driver.dpdk;
import net.driver.smartnic;
import net.driver.manager;
