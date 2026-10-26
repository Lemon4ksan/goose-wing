# h2spec HTTP/2 Conformance Test Suite for goose-wing

Automated verification harness running [h2spec](https://github.com/summerwind/h2spec) against `goose-wing`'s zero-allocation HTTP/2 server engine (conforming to RFC 9113, RFC 7540, and RFC 7541 HPACK).

## Features

- **Automated Lifecycle**: Automatically compiles and launches the native Goose HTTP/2 server (`h2spec_server.exe`), detects free ephemeral ports, executes `h2spec.exe`, and tears down cleanly.
- **Section Selection**: Run generic tests, specific RFC sections (`http2/3.5`, `http2/4.1`, `http2/6.1`, `http2/8.1`, `hpack`), or full test runs.
- **Zero Configuration**: Bundled `h2spec.exe` in `tools/bin/` requires zero external Go dependencies at runtime.

## Quick Start

### 1. Run Generic Suite (44 Tests)

From repository root:
```powershell
python tools/h2spec.py generic
```
Or via Windows batch:
```cmd
.\tools\run_h2spec.bat generic
```

### 2. Run Specific RFC Sections

```powershell
# Starting HTTP/2 & Connection Preface
python tools/h2spec.py http2/3.5

# Frame Formats & Undefined Flags
python tools/h2spec.py http2/4.1

# HPACK Compression
python tools/h2spec.py hpack
```

### 3. Rebuild Server Binary

```powershell
python tools/h2spec.py --rebuild
```
