# Task runner recipes for goose-wing

set windows-shell := ["powershell.exe", "-NoLogo", "-ExecutionPolicy", "Bypass", "-Command"]

# List available recipes
default:
    @just --list

# Typecheck core libraries, examples, and all test suites
check:
    python tools/test_runner.py --check-only

# Run test suites matching a pattern (defaults to all tests) via goose-lit
test pattern="tests":
    goose-lit "{{ pattern }}"

# Run native Goose LIT test suites matching a pattern
lit pattern="tests":
    goose-lit "{{ pattern }}"

# Enforce hardware complexity gate on a file
gate target max_gcrap="25":
    python scripts/verify_wing_gate.py "{{ target }}" --max-gcrap {{ max_gcrap }}

# Verify G-CRAP regression ratchet against baseline
ratchet:
    python scripts/ratchet.py

# Run static G-CRAP complexity radar
crap target="." threshold="25.0":
    goose-lit crap "{{ target }}" --threshold {{ threshold }}

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

# Run stage profiler and benchmark CLI
profile *args:
    python tools/profile.py {{ args }}

# Compile C acceleration shims with strict warning flags
[unix]
shims:
    gcc -Wall -Wextra -Werror -c shim/rio.c shim/uring.c shim/kqueue.c shim/simd.c shim/tcp.c shim/af_xdp.c shim/dpdk.c shim/smartnic.c shim/profiler.c
    rm -f *.o

[windows]
shims:
    gcc -Wall -Wextra -Werror -c shim/rio.c shim/uring.c shim/kqueue.c shim/simd.c shim/tcp.c shim/af_xdp.c shim/dpdk.c shim/smartnic.c shim/profiler.c
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
