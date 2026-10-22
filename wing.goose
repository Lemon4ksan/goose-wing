// goose-wing: monolithic networking and application-layer HTTP/TLS stack for Goose.
namespace wing;

import std;
import json;

// L4-L5: Core primitives (Time & Duration, StopWatch, Layout Engine)
import core.time;

// L6-L7: Application-layer DX (Profiles, CookieJar, Unified Request/Response/Session)
import cookie.constants;
import cookie.canonical;
import app.profile;
import app.cookie;
import app.request;
import app.response;
import app.session;
import app.policy;
import app.ufcs;
