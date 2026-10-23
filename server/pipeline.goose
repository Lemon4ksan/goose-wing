// Server request execution pipeline with rate limiting, CORS/CSRF evaluation, routing, and pooling.
namespace wing;

import std;
import core.time;
import app.profile;
import app.request;
import app.response;
import security.ct;
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

// Executes an incoming request through the configured pipeline stages.
fn execute_pipeline(
    cfg: ServerPipelineConfig&,
    conn_timer: ConnectionTimer&,
    client_ip: const u8[:],
    req: const Request&,
    now_ns: u64,
    res: Response&,
    out_future: InlineHandlerFuture&,
) -> PipelineOutcome {
    // Connection liveliness / timeout check
    notify_request_start(conn_timer);
    guard check_connection_tick(conn_timer, now_ns) else {
        notify_request_end(conn_timer);
        res.status_code = 408; // Request Timeout
        return PipelineOutcome.SlowlorisClosed;
    }

    // Expect header validation (RFC 9110 §10.1.1: reject unknown expectations with 417)
    for &hdr in req.headers {
        if eq_ascii_fold(hdr.name[..], "expect") {
            let exp_val = hdr.value[..];
            if !eq_ascii_fold(exp_val, "100-continue") {
                notify_request_end(conn_timer);
                res.status_code = 417; // Expectation Failed
                return PipelineOutcome.ExpectationFailed;
            }
        }
    }

    // Rate limiter check
    let rl_decision = check_keyed_rate_limit(cfg.limiter, client_ip, 1, now_ns);
    apply_rate_limit_headers(res, cfg.limiter.quota, rl_decision);
    if !is_allowed(rl_decision) {
        notify_request_end(conn_timer);
        return PipelineOutcome.RateLimited;
    }

    // CORS and Fetch Metadata isolation check
    let cors_res = evaluate_cors(cfg.cors_policy, req, res);
    if cors_res == CorsResult.AllowedPreflight {
        notify_request_end(conn_timer);
        return PipelineOutcome.CorsPreflight;
    }

    let fetch_ctx = extract_fetch_context(req, cfg.target_host[..]);
    let csrf_res = evaluate_fetch_metadata(cfg.csrf_guard, fetch_ctx);
    apply_isolation_headers(res);

    match csrf_res {
        RejectForbidden rej => {
            notify_request_end(conn_timer);
            res.status_code = 403; // Forbidden
            return PipelineOutcome.CsrfRejected;
        },
        _ => {},
    };

    // Radix trie route matching
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
            // Cookie decryption
            if (f.entries_mask & ENTRY_COOKIES) != 0 {
                // Decrypt session cookie if present
                for idx in req.headers.len {
                    if eq_ascii_fold(req.headers[idx].name[..], "Cookie") {
                        // Ingest encrypted cookie via PrivateJar
                        var plain_cookie: u8[>..] = [];
                        let now_sec = (now_ns / 1000000000) as i64;
                        private_jar_open(cfg.private_jar, "session", req.headers[idx].value[..], now_sec, plain_cookie);
                        break;
                    }
                }
            }

            // Handler dispatch
            out_future = new_inline_handler_future(f.handler_id as u16);
            poll_future(out_future);

            res.status_code = 200;
            release_extensions(cfg.ext_pool, ext_slot_idx);
            notify_request_end(conn_timer);
            return PipelineOutcome.Handled;
        },
    };
}
