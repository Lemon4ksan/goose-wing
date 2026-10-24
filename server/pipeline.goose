// Server request execution pipeline with rate limiting, CORS/CSRF evaluation, routing, and pooling.
namespace wing;

import std;
import client.request;
import client.response;
import security.crypto_jar;
import security.csrf;
import security.cors;
import security.rate_limiter;
import server.router;
import server.pool;

struct ServerPipelineConfig {
    limiter: ShardedGcraLimiter = ShardedGcraLimiter { .. },
    csrf_guard: CrossOriginGuard = CrossOriginGuard { .. },
    cors_policy: CorsPolicy = CorsPolicy { .. },
    router: RadixRouter = RadixRouter { .. },
    private_jar: PrivateJar = PrivateJar { .. },
    header_pool: HeaderMapPool = HeaderMapPool { .. },
    ext_pool: ExtensionsPool = ExtensionsPool { .. },
    target_host: u8[..128] = "example.com",
    deadline_ns: u64 = 30000000000, // 30s
}

fn new_server_pipeline_config(target_host: const u8[:], quota: GcraQuota) -> ServerPipelineConfig {
    var cfg = ServerPipelineConfig {
        limiter: new_sharded_limiter(quota),
        csrf_guard: new_cross_origin_guard(),
        cors_policy: new_cors_policy(),
        router: new_radix_router(),
        private_jar: new_private_jar(new_key_store()),
        header_pool: new_header_map_pool(),
        ext_pool: new_extensions_pool(),
        target_host: [],
        deadline_ns: 30000000000,
    };
    cfg.target_host.append(target_host);
    return cfg;
}

enum PipelineOutcome {
    Handled,
    RateLimited,
    CsrfRejected,
    CorsPreflight,
    MethodNotAllowed,
    RouteNotFound,
    SlowlorisClosed,
    ExpectationFailed,
}

// Validates Expect header compliance per RFC 9110 Section 10.1.1.
// Returns true if valid or absent; false if unsupported expectation requested.
fn validate_pipeline_expect_header(req: const Request&) -> bool {
    for &hdr in req.headers {
        if eq_ascii_fold(hdr.name[..], "expect") {
            let exp_val = hdr.value[..];
            if !eq_ascii_fold(exp_val, "100-continue") {
                return false;
            }
        }
    }
    return true;
}

// Evaluates CORS policies and Sec-Fetch-* cross-origin isolation metadata.
// Returns (outcome, is_terminal): if is_terminal is true, the request must not proceed further.
fn evaluate_pipeline_cors_and_csrf(
    cfg: ServerPipelineConfig&,
    req: const Request&,
    res: Response&,
) -> PipelineOutcome, bool {
    let cors_res = evaluate_cors(cfg.cors_policy, req, res);
    if cors_res == CorsResult.AllowedPreflight {
        return PipelineOutcome.CorsPreflight, true;
    }

    let fetch_ctx = extract_fetch_context(req, cfg.target_host[..]);
    let csrf_res = evaluate_fetch_metadata(cfg.csrf_guard, fetch_ctx);
    apply_isolation_headers(res);

    match csrf_res {
        RejectForbidden _ => {
            res.status_code = 403; // Forbidden
            return PipelineOutcome.CsrfRejected, true;
        },
        _ => {},
    };

    return PipelineOutcome.Handled, false;
}

// Decrypts encrypted session cookie from request headers into private jar if enabled.
fn decrypt_pipeline_session_cookie(
    cfg: ServerPipelineConfig&,
    req: const Request&,
    now_ns: u64,
) {
    for idx in req.headers.len {
        if eq_ascii_fold(req.headers[idx].name[..], "Cookie") {
            var plain_cookie: u8[>..] = [];
            let now_sec = (now_ns / 1000000000) as i64;
            private_jar_open(cfg.private_jar, "session", req.headers[idx].value[..], now_sec, plain_cookie);
            break;
        }
    }
}

// Executes an incoming request through the configured pipeline stages.
//
// Pipeline stages:
// 1. Connection liveliness / timeout check (Slowloris defense)
// 2. Expect header validation (RFC 9110 Section 10.1.1)
// 3. GCRA rate limiter check & header application
// 4. CORS preflight and Fetch Metadata CSRF isolation
// 5. Radix trie route matching & extension acquisition
// 6. Authenticated session cookie decryption & inline handler dispatch
fn execute_pipeline(
    cfg: ServerPipelineConfig&,
    conn_timer: ConnectionTimer&,
    client_ip: const u8[:],
    req: const Request&,
    now_ns: u64,
    res: Response&,
    out_future: InlineHandlerFuture&,
) -> PipelineOutcome {
    notify_request_start(conn_timer);

    // Stage 1: Connection liveliness / timeout check
    guard check_connection_tick(conn_timer, now_ns) else {
        notify_request_end(conn_timer);
        res.status_code = 408; // Request Timeout
        return PipelineOutcome.SlowlorisClosed;
    }

    // Stage 2: Expect header validation (RFC 9110 Section 10.1.1)
    guard validate_pipeline_expect_header(req) else {
        notify_request_end(conn_timer);
        res.status_code = 417; // Expectation Failed
        return PipelineOutcome.ExpectationFailed;
    }

    // Stage 3: Rate limiter check
    let rl_decision = check_keyed_rate_limit(cfg.limiter, client_ip, 1, now_ns);
    apply_rate_limit_headers(res, cfg.limiter.quota, rl_decision);
    if !is_allowed(rl_decision) {
        notify_request_end(conn_timer);
        return PipelineOutcome.RateLimited;
    }

    // Stage 4: CORS and Fetch Metadata isolation check
    let security_outcome, is_terminal = evaluate_pipeline_cors_and_csrf(cfg, req, res);
    if is_terminal {
        notify_request_end(conn_timer);
        return security_outcome;
    }

    // Stage 5: Radix trie route matching
    let ext_slot_idx = acquire_extensions(cfg.ext_pool);
    let e_idx = ext_slot_idx as i64;
    cfg.ext_pool.slots[e_idx].peer_ip.append(client_ip);

    let match_res = match_route(cfg.router, req.method[..], req.url[..], cfg.ext_pool.slots[e_idx].params);

    match match_res {
        NotFound => {
            release_extensions(cfg.ext_pool, ext_slot_idx);
            notify_request_end(conn_timer);
            res.status_code = 404; // Not Found
            return PipelineOutcome.RouteNotFound;
        },
        MethodNotAllowed mna => {
            res.status_code = 405; // Method Not Allowed
            res.headers.push(make_header("Allow", mna.allow_header[..]));
            release_extensions(cfg.ext_pool, ext_slot_idx);
            notify_request_end(conn_timer);
            return PipelineOutcome.MethodNotAllowed;
        },
        Found f => {
            // Stage 6: Cookie decryption & handler dispatch
            if (f.entries_mask & ENTRY_COOKIES) != 0 {
                decrypt_pipeline_session_cookie(cfg, req, now_ns);
            }

            out_future = new_inline_handler_future(f.handler_id as u16);
            poll_future(out_future);

            res.status_code = 200;
            release_extensions(cfg.ext_pool, ext_slot_idx);
            notify_request_end(conn_timer);
            return PipelineOutcome.Handled;
        },
    };
}
