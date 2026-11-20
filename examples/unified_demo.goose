// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Demonstration of the goose-wing Unified App-Layer API (Variant 2 + Variant 3 synthesis).
import std;
import core from "..";
import wing from "..";

struct CreateOrderReq {
    symbol:   const u8[:] = "",
    side:     const u8[:] = "BUY",
    quantity: i64         = 1,
    urgent:   bool        = false,
}

struct OrderConfirmation {
    id:     i64      = 0,
    status: u8[..64] = [],
    ok:     bool     = false,
}

fn main() {
    var session = wing::new_session("https://api.exchange.io") { sess =>
        sess.set_profile(fingerprint::Profile.Wing);
        sess.set_proxy("socks5://127.0.0.1:1080");
        sess.set_timeout_ms(10000);
        sess.set_cookie("session_id", "sid_998877aabb");
        sess.default_header("Accept", "application/json");
    };

    let order_payload = CreateOrderReq {
        symbol:   "BTC-USDT",
        side:     "BUY",
        quantity: 5,
        urgent:   true,
    };

    let res1, err1 = session.post("/v1/orders") { req =>
        req.bearer("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        req.query("dry_run", "false");
        if order_payload.urgent {
            req.set_header("X-Priority-Lane", "ultra-low-latency");
        }
        req.json(order_payload);
    };
    guard err1.ok() && res1.is_success() else {
        print("Request 1 failed: ", err1.message);
        return;
    }

    var conf1 = OrderConfirmation { .. };
    let jerr1 = res1.json(conf1);
    if jerr1.ok() {
        print("id=", conf1.id, " status=", conf1.status, " ok=", conf1.ok);
    }

    var req2 = wing::new_request("POST", "/v2/settlement") { req =>
        req.bearer(session.cookie("session_id"));
        req.timeout_ms(5000);
        req.json(order_payload);
    };

    wing::enrich_tracing(req2, "trace-7741-wing");
    wing::sign_hmac_sha256(req2, "sk_live_secret_key");

    let res2, err2 = session.do(req2);
    guard err2.ok() else { return; }
    print("Status: ", res2.status_code, " Server: ", res2.header("server"));

    let res3, err3 = session.do(req2) { req =>
        req.set_header("X-Retry-Attempt", "2");
        req.query("replay", "true");
    };
    guard err3.ok() else { return; }
    print("Response body: ", res3.text());
}
