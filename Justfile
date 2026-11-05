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
    goose-lit "{{pattern}}"

# Run native Goose LIT test suites matching a pattern
lit pattern="tests":
    goose-lit "{{pattern}}"

# Enforce hardware complexity gate on a file
gate target max_gcrap="25":
    python scripts/verify_wing_gate.py "{{target}}" --max-gcrap {{max_gcrap}}

# Verify G-CRAP regression ratchet against baseline
ratchet:
    python scripts/ratchet.py

# Run static G-CRAP complexity radar
crap target="." threshold="25.0":
    goose-lit crap "{{target}}" --threshold {{threshold}}

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

# Configure git to use repository pre-commit hooks
install-hooks:
    git config core.hooksPath .githooks

# Run Autobahn WebSocket conformance testsuite
autobahn *args:
    python tools/autobahn.py {{args}}

# Run performance benchmark matrix
bench scenario="pipelined" duration="5":
    python tools/bench-vs-uwebsockets/run_cli.py --scenario {{scenario}} --duration {{duration}}

# Compile C acceleration shims with strict warning flags
[unix]
shims:
    gcc -Wall -Wextra -Werror -c shim/rio.c shim/uring.c shim/kqueue.c shim/simd.c shim/tcp.c shim/af_xdp.c shim/dpdk.c shim/smartnic.c
    rm -f *.o

[windows]
shims:
    gcc -Wall -Wextra -Werror -c shim/rio.c shim/uring.c shim/kqueue.c shim/simd.c shim/tcp.c shim/af_xdp.c shim/dpdk.c shim/smartnic.c
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
