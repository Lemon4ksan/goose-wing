# h2spec HTTP/2 conformance test suite for goose-wing

Automated verification harness running
[h2spec](https://github.com/summerwind/h2spec) and supplemental RFC 9113 Section
6.9 `WINDOW_UPDATE` backpressure checks against the `goose-wing` HTTP/2 server
engine (RFC 9113, RFC 7540, and RFC 7541 HPACK).

## Coverage

| Component | Verification details |
| :--- | :--- |
| Automated lifecycle | Compiles and launches `h2spec_server`, selects an ephemeral port, executes `h2spec`, and shuts down cleanly. |
| Zero-skip enforcement | Parses the `h2spec` summary line and fails the run if any test case is skipped. |
| Section selection | Runs `generic`, specific RFC sections (`http2/3.5`, `http2/4.1`, `http2/6.1`, `http2/8.1`, `hpack`), or `all` (`-S` for strict mode). |
| `WINDOW_UPDATE` backpressure | Verifies ingress streaming `POST /echo` replenishment above 8 KiB, connection window overflow `FLOW_CONTROL_ERROR` (`0x03`), and egress `SETTINGS_INITIAL_WINDOW_SIZE` clamping. |

## Quick start

### Run full strict suite and backpressure checks

From the repository root:

```powershell
python tools/h2spec.py -S all
```

### Run generic suite (44 tests)

```powershell
python tools/h2spec.py generic
```

Or via Windows batch:

```cmd
.\tools\run_h2spec.bat generic
```

### Run specific RFC sections

```powershell
# Starting HTTP/2 and connection preface
python tools/h2spec.py http2/3.5

# Frame formats and undefined flags
python tools/h2spec.py http2/4.1

# HPACK compression
python tools/h2spec.py hpack
```

### Rebuild server binary or skip backpressure probe

```powershell
python tools/h2spec.py --rebuild -S all
python tools/h2spec.py generic --no-backpressure
```
