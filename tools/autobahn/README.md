# Autobahn WebSocket Conformance Testsuite for goose-wing

Automated verification suite validating 100% compliance with **RFC 6455** using the official [Autobahn|Testsuite](https://github.com/crossbario/autobahn-testsuite) test specifications via native runner (`kosoku` / `wstest`).

## Verification Scope (301 RFC 6455 Cases)

| Category | Suite Name | Description & Invariant Validations |
| :---: | :--- | :--- |
| **1** | **Framing Basics** | Small (0..125B), medium 16-bit (126..65535B), and large 64-bit (64KB, 1MB) frames for both text and binary opcodes. |
| **2** | **Pings & Pongs** | Unsolicited pongs, echo payload matching, heartbeats during data streams. |
| **3** | **Reserved Bits** | RSV1, RSV2, RSV3 non-zero fail-closed rejection with protocol error (Close 1002). |
| **4** | **Opcodes** | Reserved control (0xB..0xF) and data (0x3..0x7) opcodes rejection with protocol error (Close 1002). |
| **5** | **Fragmentation** | Reassembly of multi-frame messages, interleaved control frames (ping/pong during fragmented text), premature FIN/continuation invariants. |
| **6** | **UTF-8 Validation** | Full RFC 3629 / Unicode standard vectors: 1-byte, 2-byte, 3-byte, 4-byte boundaries, overlong rejection, surrogate halves rejection, and multi-byte sequence splits across frame boundaries. |
| **7** | **Close Handshake** | Clean bidirectional close handshakes, forbidden wire status codes (1004, 1005, 1006, 1015, 1016..2999) rejection, and clean TCP FIN termination without RST. |
| **9** | **High Throughput & Limits** | High-volume 64KB..1MB rapid streaming frame validation. |
| **10** | **Reporting** | Automated JSON / HTML compliance report generation. |

## Quick Start

### 1. Run Complete RFC 6455 Suite (301 Cases)

From repository root:
```powershell
python tools/autobahn.py
```
Or via the Windows batch script:
```cmd
.\tools\run_autobahn.bat
```

### 2. Run Specific Categories or Cases

```powershell
# Run only category 1 (Framing)
python tools/autobahn.py -i "1.*"

# Run only category 6 (UTF-8)
python tools/autobahn.py -i "6.*"

# Run a specific subcase
python tools/autobahn.py -i "5.19"
```

### 3. Run in Docker (Docker Compose)

Run the entire Autobahn testsuite in isolated Docker containers (native `goose-wing` WebSocket server + official `crossbario/autobahn-testsuite`):
```powershell
docker compose -f tools/autobahn/docker-compose.yml up --build --abort-on-container-exit
```
Or via the Python runner:
```powershell
python tools/autobahn.py --compose
```

### 4. Rebuild Server Executable

If you modify `tools/autobahn/server.goose`, rebuild locally with:
```powershell
python tools/autobahn.py --rebuild
```

Reports are automatically saved in `reports/autobahn/index.html` and `reports/autobahn/index.json`.
