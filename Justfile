# Task runner recipes for goose-wing

set windows-shell := ["powershell.exe", "-NoLogo", "-ExecutionPolicy", "Bypass", "-Command"]

# List available recipes
default:
    @just --list

# Typecheck core libraries, examples, and all test suites
check:
    python tools/test_runner.py --check-only

# Run test suites matching a pattern (defaults to all)
test pattern="*":
    python tools/test_runner.py --pattern "{{pattern}}"

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
    ruff check tools/

# Compile C acceleration shims with strict warning flags
[unix]
shims:
    gcc -Wall -Wextra -Werror -c shim/rio.c shim/uring.c shim/kqueue.c shim/simd.c shim/tcp.c shim/af_xdp.c shim/smartnic.c
    rm -f *.o

[windows]
shims:
    gcc -Wall -Wextra -Werror -c shim/rio.c shim/uring.c shim/kqueue.c shim/simd.c shim/tcp.c shim/af_xdp.c shim/smartnic.c
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
