// tests/poller_event_loop_test.goose
// Verification suite for Non-blocking Poller & Event Loop over L4 Transport Drivers.
// 1. Poller Creation & Lifecycle across L4 Driver Backends
// 2. Socket Registration, Interest Modification, and Readiness Multiplexing
// 3. High-Resolution Timer Wheel (One-shot, Periodic, Cancellation)
// 4. Non-blocking EventLoop I/O (Read/Write Buffers & Dispatching)
// 5. Bidirectional Client-Server Mock Cycle over EventLoop
import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. Poller Creation & Lifecycle across L4 Driver Backends
// ----------------------------------------------------------------------------
fn test_poller_creation_and_lifecycle(t: core::T&) {
    t.run("Standard Driver Poller Lifecycle") { sub =>
        var cfg = wing::auto_transport_driver_config();
        cfg.active_kind = wing::TransportDriverKind.Standard;

        var poller = wing::new_poller(cfg);
        sub.assert_true(poller.is_open, "Poller is open");
        sub.assert_eq(poller.active_fd_count, 0, "No active fds initially");
        sub.assert_eq(poller.active_timer_count, 0, "No active timers initially");

        wing::close_poller(poller);
        sub.assert_false(poller.is_open, "Poller closed cleanly");
    };

    t.run("Windows RIO / io_uring / kqueue Probed Poller Creation") { sub =>
        let plat = wing::detect_target_platform();
        var cfg = wing::auto_transport_driver_config();

        var poller = wing::new_poller(cfg);
        sub.assert_true(poller.is_open, "Poller created successfully with auto-selected driver");

        if plat == wing::TargetPlatform.Windows && cfg.active_kind == wing::TransportDriverKind.WindowsRIO {
            sub.assert_true(poller.rio_cq_id != 0, "Windows RIO completion queue initialized");
        }

        wing::close_poller(poller);
        sub.assert_false(poller.is_open, "Poller closed");
    };
}

// ----------------------------------------------------------------------------
// 2. Socket Registration & Readiness Multiplexing
// ----------------------------------------------------------------------------
fn test_poller_registration_and_readiness(t: core::T&) {
    var cfg = wing::auto_transport_driver_config();
    var poller = wing::new_poller(cfg);

    t.run("Registration Table: Add, Duplicate Guard, Modify, Deregister") { sub =>
        // Register fd 10
        let ok_reg = wing::register_socket(poller, 10, 1001, wing::PollInterest.Read, wing::PollTrigger.Level);
        sub.assert_true(ok_reg, "Socket 10 registered");
        sub.assert_eq(poller.active_fd_count, 1, "1 active fd");

        // Duplicate registration rejected
        let dup_reg = wing::register_socket(poller, 10, 1002, wing::PollInterest.Write, wing::PollTrigger.Level);
        sub.assert_false(dup_reg, "Duplicate fd 10 registration rejected");

        // Modify interest to ReadWrite
        let ok_mod = wing::modify_socket(poller, 10, 1001, wing::PollInterest.ReadWrite, wing::PollTrigger.Edge);
        sub.assert_true(ok_mod, "Socket 10 modified");

        let idx = wing::find_registration(poller, 10);
        sub.assert_true(idx >= 0, "Socket 10 found");
        sub.assert_eq(poller.registrations[idx].interest, wing::PollInterest.ReadWrite, "Interest is ReadWrite");
        sub.assert_eq(poller.registrations[idx].trigger, wing::PollTrigger.Edge, "Trigger is Edge");

        // Deregister
        let ok_dereg = wing::deregister_socket(poller, 10);
        sub.assert_true(ok_dereg, "Socket 10 deregistered");
        sub.assert_eq(poller.active_fd_count, 0, "0 active fds");
        sub.assert_eq(wing::find_registration(poller, 10), -1, "Socket 10 no longer found");
    };

    t.run("Readiness Multiplexing: Read, Write, Error, Hangup") { sub =>
        wing::register_socket(poller, 20, 2001, wing::PollInterest.Read, wing::PollTrigger.Level);
        wing::register_socket(poller, 21, 2002, wing::PollInterest.Write, wing::PollTrigger.Level);
        wing::register_socket(poller, 22, 2003, wing::PollInterest.ReadWrite, wing::PollTrigger.Level);

        // Simulate events
        wing::simulate_read_ready(poller, 20, 512); // fd 20 has 512 bytes unread
        wing::simulate_write_ready(poller, 21);      // fd 21 ready to write
        wing::simulate_hangup(poller, 22);           // fd 22 hangup/EOF

        var events: wing::PollReadyEvent[..64] = [];
        let count = wing::poll_events(poller, 0, 1000000000, events);

        sub.assert_eq(count, 3, "3 readiness events harvested");

        // Validate fd 20 event
        var found_20 = false;
        var found_21 = false;
        var found_22 = false;

        for i in events.len {
            if events[i].tag == 2001 {
                found_20 = true;
                sub.assert_eq(events[i].fd, 20, "fd is 20");
                sub.assert_true((events[i].events & wing::POLL_READ) != 0, "Event has POLL_READ");
                sub.assert_eq(events[i].bytes_available, 512, "Reported 512 bytes available");
                sub.assert_false(events[i].is_eof, "Not EOF");
            } else if events[i].tag == 2002 {
                found_21 = true;
                sub.assert_eq(events[i].fd, 21, "fd is 21");
                sub.assert_true((events[i].events & wing::POLL_WRITE) != 0, "Event has POLL_WRITE");
            } else if events[i].tag == 2003 {
                found_22 = true;
                sub.assert_eq(events[i].fd, 22, "fd is 22");
                sub.assert_true((events[i].events & wing::POLL_HANGUP) != 0, "Event has POLL_HANGUP");
                sub.assert_true(events[i].is_eof, "Event is EOF");
            }
        }

        sub.assert_true(found_20, "fd 20 event processed");
        sub.assert_true(found_21, "fd 21 event processed");
        sub.assert_true(found_22, "fd 22 event processed");

        wing::deregister_socket(poller, 20);
        wing::deregister_socket(poller, 21);
        wing::deregister_socket(poller, 22);
    };

    wing::close_poller(poller);
}

// ----------------------------------------------------------------------------
// 3. High-Resolution Timer Wheel
// ----------------------------------------------------------------------------
fn test_poller_timer_wheel(t: core::T&) {
    var cfg = wing::auto_transport_driver_config();
    var poller = wing::new_poller(cfg);

    t.run("One-shot Timer Expiration") { sub =>
        let now_ns: u64 = 1000000000; // 1.0s
        // Schedule one-shot timer for 50ms (deadline 1.05s)
        let ok_add = wing::add_timer(poller, 101, 50, 9101, false, now_ns);
        sub.assert_true(ok_add, "Timer 101 added");
        sub.assert_eq(poller.active_timer_count, 1, "1 active timer");

        // Poll at 1.04s (40ms elapsed) -> timer should NOT fire
        var events40: wing::PollReadyEvent[..64] = [];
        let c40 = wing::poll_events(poller, 0, now_ns + 40000000, events40);
        sub.assert_eq(c40, 0, "Timer not yet expired at 40ms");

        // Poll at 1.06s (60ms elapsed) -> timer should fire!
        var events60: wing::PollReadyEvent[..64] = [];
        let c60 = wing::poll_events(poller, 0, now_ns + 60000000, events60);
        sub.assert_eq(c60, 1, "Timer fired at 60ms");
        sub.assert_eq(events60[0].tag, 9101, "Timer tag matches");
        sub.assert_true(events60[0].is_timer, "is_timer flag is true");
        sub.assert_true((events60[0].events & wing::POLL_TIMER) != 0, "POLL_TIMER flag set");

        // One-shot timer is now deactivated
        sub.assert_eq(poller.active_timer_count, 0, "0 active timers left");

        // Subsequent poll should not fire
        var events70: wing::PollReadyEvent[..64] = [];
        let c70 = wing::poll_events(poller, 0, now_ns + 70000000, events70);
        sub.assert_eq(c70, 0, "No duplicate timer triggers");
    };

    t.run("Periodic Timer & Cancellation") { sub =>
        let now_ns: u64 = 1000000000;
        // Schedule periodic timer every 100ms
        wing::add_timer(poller, 202, 100, 9202, true, now_ns);

        // 1st tick at 110ms
        var ev1: wing::PollReadyEvent[..64] = [];
        let c1 = wing::poll_events(poller, 0, now_ns + 110000000, ev1);
        sub.assert_eq(c1, 1, "1st tick fired");
        sub.assert_eq(ev1[0].tag, 9202, "Tag matches");

        // Timer still active (periodic)
        sub.assert_eq(poller.active_timer_count, 1, "Timer still active");

        // 2nd tick at 220ms
        var ev2: wing::PollReadyEvent[..64] = [];
        let c2 = wing::poll_events(poller, 0, now_ns + 220000000, ev2);
        sub.assert_eq(c2, 1, "2nd tick fired");

        // Cancel timer
        let ok_cancel = wing::cancel_timer(poller, 202);
        sub.assert_true(ok_cancel, "Timer cancelled");
        sub.assert_eq(poller.active_timer_count, 0, "0 active timers");

        // 3rd tick should NOT fire after cancellation
        var ev3: wing::PollReadyEvent[..64] = [];
        let c3 = wing::poll_events(poller, 0, now_ns + 330000000, ev3);
        sub.assert_eq(c3, 0, "No tick after cancellation");
    };

    wing::close_poller(poller);
}

// ----------------------------------------------------------------------------
// 4. Non-blocking EventLoop I/O
// ----------------------------------------------------------------------------
fn dummy_event_handler(tag: u64, ev: const wing::PollReadyEvent&, el: wing::EventLoop&) {
    if tag == 5001 {
        if (ev.events & wing::POLL_READ) != 0 {
            var msg_buf: u8[>..] = [];
            wing::consume_read(el, tag, msg_buf);
            // Echo back with prefix "ACK:"
            var reply: u8[..64] = "ACK:";
            reply.append(msg_buf[..]);
            wing::queue_write(el, tag, reply[..]);
        }
    }
}

fn test_event_loop_io(t: core::T&) {
    var cfg = wing::auto_transport_driver_config();
    var el = wing::new_event_loop(cfg);

    t.run("Bind Connection, Queue Write, Feed Read & Consume") { sub =>
        let ok_bind = wing::bind_connection(el, 30, 5001, wing::PollInterest.ReadWrite);
        sub.assert_true(ok_bind, "Connection 5001 bound");

        // Feed incoming data
        let ok_feed = wing::feed_read(el, 5001, "REQUEST_DATA_01");
        sub.assert_true(ok_feed, "Data fed into read buffer");

        // Run event loop once
        let dispatched = wing::run_loop_once(el, 0, 1000000000, dummy_event_handler);
        sub.assert_eq(dispatched, 1, "1 event dispatched in loop");
        sub.assert_eq(el.iteration_count, 1, "Iteration count is 1");
        sub.assert_eq(el.events_dispatched_total, 1, "1 total dispatched event");

        // The handler consumed the read and queued an "ACK:REQUEST_DATA_01" response
        let b_idx = wing::find_connection_buffer(el, 5001);
        sub.assert_true(b_idx >= 0, "Buffer found");
        sub.assert_bytes_eq(el.buffers[b_idx].write_buf[..], "ACK:REQUEST_DATA_01", "Outbound reply queued");

        // Flush writes
        let flushed = wing::flush_writes(el, 5001);
        sub.assert_eq(flushed, 19, "Flushed 19 bytes");
        sub.assert_eq(el.buffers[b_idx].write_buf.len, 0, "Write buffer cleared");

        // Unbind
        sub.assert_true(wing::unbind_connection(el, 5001), "Unbound");
    };

    wing::close_event_loop(el);
}

// ----------------------------------------------------------------------------
// 5. Bidirectional Client-Server Mock Cycle over EventLoop
// ----------------------------------------------------------------------------
var g_server_received: u8[..64] = [];
var g_client_received: u8[..64] = [];

fn bidi_network_handler(tag: u64, ev: const wing::PollReadyEvent&, el: wing::EventLoop&) {
    if tag == 6001 { // Server connection
        if (ev.events & wing::POLL_READ) != 0 {
            var buf: u8[>..] = [];
            wing::consume_read(el, tag, buf);
            g_server_received.clear();
            g_server_received.append(buf[..]);

            // Server responds
            wing::queue_write(el, tag, "SERVER_OK");
        }
    } else if tag == 6002 { // Client connection
        if (ev.events & wing::POLL_READ) != 0 {
            var buf: u8[>..] = [];
            wing::consume_read(el, tag, buf);
            g_client_received.clear();
            g_client_received.append(buf[..]);
        }
    }
}

fn test_bidi_client_server_cycle(t: core::T&) {
    var cfg = wing::auto_transport_driver_config();
    var el = wing::new_event_loop(cfg);

    t.run("Complete Non-blocking Bidi Request-Response Roundtrip") { sub =>
        g_server_received.clear();
        g_client_received.clear();

        wing::bind_connection(el, 40, 6001, wing::PollInterest.ReadWrite); // Server
        wing::bind_connection(el, 41, 6002, wing::PollInterest.ReadWrite); // Client

        // 1. Client sends request to Server
        wing::feed_read(el, 6001, "PING_FROM_CLIENT");

        // 2. EventLoop Step 1: Server receives request and queues response
        wing::run_loop_once(el, 0, 1000000000, bidi_network_handler);

        sub.assert_bytes_eq(g_server_received[..], "PING_FROM_CLIENT", "Server processed request");

        // 3. Network forwards Server's outbound response to Client's inbound buffer
        let s_idx = wing::find_connection_buffer(el, 6001);
        let s_out = el.buffers[s_idx].write_buf[..];
        sub.assert_bytes_eq(s_out, "SERVER_OK", "Server queued reply");
        wing::feed_read(el, 6002, s_out);
        wing::flush_writes(el, 6001);

        // 4. EventLoop Step 2: Client receives Server's response
        wing::run_loop_once(el, 0, 1000001000, bidi_network_handler);

        sub.assert_bytes_eq(g_client_received[..], "SERVER_OK", "Client received server reply");

        wing::unbind_connection(el, 6001);
        wing::unbind_connection(el, 6002);
    };

    wing::close_event_loop(el);
}

// ----------------------------------------------------------------------------
// Suite Runner
// ----------------------------------------------------------------------------
fn main() {
    var runner = core::new_runner("L4 Non-blocking Poller & Event Loop Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Poller Creation & Lifecycle across L4 Driver Backends", test_poller_creation_and_lifecycle);
    core::run_case(runner, "2. Socket Registration & Readiness Multiplexing", test_poller_registration_and_readiness);
    core::run_case(runner, "3. High-Resolution Timer Wheel", test_poller_timer_wheel);
    core::run_case(runner, "4. Non-blocking EventLoop I/O", test_event_loop_io);
    core::run_case(runner, "5. Bidirectional Client-Server Mock Cycle", test_bidi_client_server_cycle);

    let ok = core::finish(runner);
    assert(ok);
}
