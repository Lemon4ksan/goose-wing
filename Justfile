# Task runner recipes for goose-wing

set windows-shell := ["powershell.exe", "-NoLogo", "-ExecutionPolicy", "Bypass", "-Command"]

# List available recipes
default:
    @just --list

# Typecheck core libraries, examples, and all test suites
check target=".":
    goose-lit check "{{ target }}"

# Run test suites matching a pattern (defaults to all tests) via goose-lit
test pattern="tests":
    goose-lit "{{ pattern }}"

# Run native Goose LIT test suites matching a pattern
lit pattern="tests":
    goose-lit "{{ pattern }}"

# Collect real source-to-source branch coverage (.gcrap-cov and LCOV)
cov target="." tests_path="tests":
    goose-lit cov "{{ target }}" --tests "{{ tests_path }}" -j 2 --out .lit/cache/cov/merged.gcrap-cov --lcov .lit/cache/cov/merged.info

# Enforce unified quality gate on a file (format, check, G-CRAP, optional LIT test)
gate target max_gcrap="25":
    goose-lit verify "{{ target }}" --max-gcrap {{ max_gcrap }}

# Run Goose-Evolve analysis, verification gate, and Pareto evolution loop
evolve *args:
    python scripts/goose_evolve.py {{ args }}

# Verify G-CRAP regression ratchet against baseline
ratchet:
    goose-lit crap . --baseline .lit/baseline --delta 5.0

# Run static G-CRAP complexity radar
crap target="." threshold="25.0":
    goose-lit crap "{{ target }}" --threshold {{ threshold }}

# Run static cycles-vs-SLOC scan with Goose compiler smells breakdown
sloc target=".":
    goose-lit sloc "{{ target }}" --smells

# Enforce local SLOC, anti-packing, and compiler-smell ratchet against .lit/sloc-baseline
sloc-ratchet:
    goose-lit sloc . --baseline .lit/sloc-baseline --check-packing --check-smells --sloc-delta 0

# Run live RDTSC cycle correlation against .lit/sloc-map and .lit/sloc-baseline
sloc-profile target="." benchtime="10":
    goose-lit sloc "{{ target }}" --map .lit/sloc-map --run-profile --benchtime {{ benchtime }} --baseline .lit/sloc-baseline --check-packing

# Save static SLOC baseline (preserves existing local RDTSC scope cycles)
sloc-save:
    goose-lit sloc . --check-packing --save-baseline .lit/sloc-baseline

# Capture live RDTSC cycles and save full .lit/sloc-baseline
sloc-save-profile benchtime="10":
    goose-lit sloc . --map .lit/sloc-map --run-profile --benchtime {{ benchtime }} --check-packing --save-baseline .lit/sloc-baseline

# Enforce strict code clarity and anti-bloat invariants
lint-invariants target="":
    python scripts/lint_invariants.py {{ if target == "" { "--staged" } else { "--target-file " + target } }} --strict-examples

# Format all Goose source files
fmt:
    goose format .

# Verify Goose source formatting without modifying files
fmt-check:
    goose format --check .

# Check SPDX Apache-2.0 license headers
license-check:
    python tools/licensing.py --check

# Apply missing SPDX Apache-2.0 license headers
license-fix:
    python tools/licensing.py --fix

# Lint Python tooling with Ruff
lint:
    ruff check tools/ scripts/

# Lint Markdown documentation with goosemarklint (ASD-STE100, LLM tells, and markdownlint)
md-lint *paths=".":
    goosemarklint check {{ paths }}

# Format Markdown documentation with goosemarklint
md-fmt *paths=".":
    goosemarklint fmt {{ paths }}

# Verify Markdown formatting without modifying files
md-fmt-check *paths=".":
    goosemarklint fmt --check {{ paths }}

# Configure git to use repository pre-commit hooks
install-hooks:
    git config core.hooksPath .githooks

# Run Autobahn WebSocket conformance testsuite
autobahn *args:
    python tools/autobahn.py {{ args }}

# Run performance benchmark matrix
bench scenario="pipelined" duration="5":
    python tools/bench-vs-uwebsockets/run_cli.py --scenario {{ scenario }} --duration {{ duration }}

# Run native stage profiler and benchmark CLI via goose-lit
profile *args:
    goose-lit profile {{ args }}

# Run native stateful protocol fuzzer via goose-lit
fuzz *args:
    goose-lit fuzz {{ args }}

# Format all C shims with clang-format
[unix]
c-fmt:
    clang-format --style=file:shim/.clang-format -i shim/*.c

[windows]
c-fmt:
    Get-ChildItem shim\*.c | ForEach-Object { clang-format --style=file:shim/.clang-format -i $_.FullName }

# Verify C shim formatting without modifying files
[unix]
c-fmt-check:
    clang-format --style=file:shim/.clang-format --dry-run --Werror shim/*.c

[windows]
c-fmt-check:
    Get-ChildItem shim\*.c | ForEach-Object { clang-format --style=file:shim/.clang-format --dry-run --Werror $_.FullName; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }

# Compile C acceleration shims with strict warning flags
[unix]
shims:
    gcc -Wall -Wextra -Werror -c shim/rio.c shim/uring.c shim/kqueue.c shim/simd.c shim/tcp.c shim/af_xdp.c shim/dpdk.c shim/smartnic.c shim/tls_backend.c
    rm -f *.o

[windows]
shims:
    gcc -Wall -Wextra -Werror -c shim/rio.c shim/uring.c shim/kqueue.c shim/simd.c shim/tcp.c shim/af_xdp.c shim/dpdk.c shim/smartnic.c shim/tls_backend.c
    Remove-Item -Force -ErrorAction SilentlyContinue *.o

# Run Docker-based gRPC end-to-end verification
e2e-grpc:
    python tools/grpc.py --docker

# Run Docker-based TLS 1.3 end-to-end verification
e2e-tls:
    python tools/tls.py --docker

# Run Docker-based HTTP/3 and QUIC end-to-end verification
e2e-http3:
    python tools/http3.py --docker

# Run Toxiproxy chaos verification suite
e2e-chaos:
    python tools/toxiproxy.py --docker

# Run BoGo TLS conformance shim and local/Docker runner
bogo *args="--local":
    python tools/bogo.py {{ args }}

# Run TLS audit suites (tlsfuzzer, TLS-Anvil, TLS-Attacker, testssl.sh)
tls-audit *args="--local --suite all":
    python tools/tls_audit.py {{ args }}

# Run badssl.com canary and offline local CA matrix
badssl *args="--offline":
    python tools/badssl_canary.py {{ args }}

# Run Wycheproof, C2SP/CCTV, and NIST ACVP cryptographic vector suites
crypto-vectors *args="--local --suite all":
    python tools/crypto_vectors.py {{ args }}

# Run dudect Welch's t-test constant-time statistical timing suite
dudect *args="--local":
    python tools/dudect.py {{ args }}

# Run ctgrind / TIMECOP taint-analysis and binary constant-time audit
ctgrind *args="--local":
    python tools/ctgrind.py {{ args }}

# Run x509-limbo, BetterTLS, and NIST PKITS certificate validation suites
x509-suites *args="--local --suite all":
    python tools/x509_suites.py {{ args }}

# Run JA3/JA4/Akamai H2 fingerprint parity and WPT cookies/redirects/CORS suite
fingerprint-wpt *args="--local":
    python tools/fingerprint_wpt.py {{ args }}

# Run HTTP/1.1 smuggling differential wall and HTTP Garden adapter
smuggling *args="--local":
    python tools/smuggling.py {{ args }}

# Run HTTP Garden origin-echo differential self-test
http-garden:
    python tools/smuggling/http_garden_adapter.py --self-test

# Run RFC 9111/5861/9875 HTTP cache conformance suite (http-tests style)
cache-conformance *args="--local":
    python tools/cache_conformance.py {{ args }}

# Run http2jp/hpack-test-case and quicwg/qpack interop suites
hpack-qpack *args="--local --suite all":
    python tools/hpack_qpack.py {{ args }}

# Run h3spec QUIC and HTTP/3 error conformance suite
h3spec *args="--local":
    python tools/h3spec.py {{ args }}

# Run quic-interop-runner self-interop / cross-stack suite
quic-interop *args="--local":
    python tools/quic_interop.py {{ args }}

# Run tc netem UDP/QUIC chaos and packetdrill TCP edge suite
netem-packetdrill *args="--local":
    python tools/netem_packetdrill.py {{ args }}

# Run all local/offline conformance, crypto, PKI, HTTP, and QUIC testbeds
testbeds-local: bogo tls-audit badssl crypto-vectors dudect ctgrind x509-suites fingerprint-wpt smuggling http-garden cache-conformance hpack-qpack h3spec quic-interop netem-packetdrill

# Run Go black-box wire & CVE conformance suite against compiled tools/bin harnesses
[unix]
blackbox-conformance *args="--all":
    cd tools/blackbox_conformance && go run . {{ args }}

[windows]
blackbox-conformance *args="--all":
    Push-Location tools/blackbox_conformance; try { go run . {{ args }} } finally { Pop-Location }

# Run cryptographic, compression, and framing differential fuzzing suite
diff-fuzz:
    python scripts/diff_fuzz.py

# Run HTTP/1.1 anti-smuggling differential harness against Go net/http
diff-h1 n="1000":
    python scripts/h1_differential.py --random {{ n }}

# Run URL parsing differential harness against Go net/url
diff-url n="1000":
    python scripts/url_differential.py --random {{ n }}

# Run stateful HPACK differential harness against Go x/net/http2/hpack
diff-hpack conns="500":
    python scripts/hpack_differential.py --conns {{ conns }}

# Run live TLS 1.3 and HTTP/2 differential harness against Go crypto/tls + net/http
diff-h2-tls:
    python scripts/h2_tls_differential.py -v

# Run all differential verification harnesses sequentially
diff-all: diff-fuzz diff-h1 diff-url diff-hpack diff-h2-tls

# Build the goose2rfc specification compiler into tools/bin/goose2rfc
[unix]
build-goose2rfc:
    mkdir -p tools/bin
    cd tools/goose2rfc && goose build -O2 -o ../bin/goose2rfc src/main.goose

[windows]
build-goose2rfc:
    New-Item -ItemType Directory -Force -Path tools/bin | Out-Null
    $env:GOOSE_CC = (Resolve-Path tools/gcc_noavx.cmd).Path; Push-Location tools/goose2rfc; try { goose build -O2 -o ../bin/goose2rfc.exe src/main.goose } finally { Pop-Location }

# Generate ASD-STE100 .sm.md state-machine specifications via goose2rfc
rfc-specs *targets="--all":
    python scripts/gen_rfc_specs.py {{ targets }}

# Run goose2rfc LIT verification suite
test-goose2rfc:
    goose-lit tools/goose2rfc/tests/lit
