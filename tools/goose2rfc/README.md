# goose2rfc

`goose2rfc` compiles Goose protocol source code into ASD-STE100 Markdown
specifications and JSON `Spec-IR` files.

## Build

Build the `goose2rfc` binary into `tools/bin/` with the Goose compiler:

```sh
cd tools/goose2rfc
goose build -O2 -o ../bin/goose2rfc src/main.goose
../bin/goose2rfc --version
```

Or run `just build-goose2rfc` from the repository root.

## Commands

Run `goose2rfc` directly or through `scripts/gen_rfc_specs.py`:

```sh
python scripts/gen_rfc_specs.py auth http2
./tools/bin/goose2rfc compile quic/frames.goose --root wing.goose --format sm.md -o out/quic_frames.sm.md
./tools/bin/goose2rfc check quic/frames.goose --config tools/goose2rfc/goose2rfc.json --strict
./tools/bin/goose2rfc --version
```

| Command | Action |
| --- | --- |
| `compile <files...>` | Parses target `.goose` modules, resolves constants and inlined helpers, and writes `.sm.md` or `.json` specifications. |
| `check <files...>` | Runs syntax and semantic analysis without output files and reports `[UNRESOLVED_AST_HAZARD]` or `DIRTY_EXPOSED` findings. |
| `--version` | Prints `goose2rfc 0.1.0` to standard output and exits. |

### Command flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--config <path>` | `goose2rfc.json` | Reads scope globs, inline limits, and output settings from a JSON file. |
| `--root <path>` | `wing.goose`, `core.goose` | Adds a root manifest file to the import graph walker. |
| `--fn <glob>` | `decode_*`, `encode_*`, `parse_*`, `validate_*` | Selects function names that match the glob pattern. |
| `--max-inline-depth <n>` | `3` | Sets the maximum call depth for predicate and pure helper expansion. |
| `--format <fmt>` | `sm.md` | Selects `sm.md`, `md`, or `json` output format. |
| `-o <path>` | `out/spec` | Writes the emitted specification to `<path>`. |
| `--strict` | `true` | Fails with exit code `1` when analysis finds an unresolved hazard or exposed mutation. |
| `--diagnostics <mode>` | `text` | Prints diagnostics as `file:line:col: rule: message` (`text`) or JSON lines (`json`). |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Compilation or verification completed with zero strictness errors. |
| `1` | Strict verification found `unanalyzed_statements > 0`, `[UNRESOLVED_AST_HAZARD]`, or `DIRTY_EXPOSED`. |
| `2` | The command line had invalid flags, or the tool could not read an input or configuration file. |

## Configuration

`goose2rfc.json` configures module roots, symbol filters, inliner limits, and
enabled output sections:

```json
{
  "roots": ["wing.goose", "core.goose"],
  "include": ["quic/*", "tls/*", "http/*"],
  "exclude": ["core/bytes/swar_*", "*::bloom_*"],
  "functions": ["decode_*", "encode_*", "parse_*", "validate_*"],
  "max_inline_depth": 3,
  "inline_max_nodes": 24,
  "max_fsm_rows": 128,
  "fold_lookup_tables": true,
  "formats": ["sm.md", "json"],
  "out_dir": "out/spec",
  "strict": true,
  "sections": [
    "manifest",
    "structures",
    "signature",
    "entry_context",
    "wire_ops",
    "requirements",
    "unchecked_surface",
    "error_side_effects",
    "machines"
  ],
  "intrinsics_manifest": "data/intrinsics.tsv"
}
```

## Intrinsics and templates

`data/intrinsics.tsv` maps low-level cursor, slice, buffer, and saturating math
primitives to `READ`, `WRITE`, `ROLLBACK`, and `SAT_OP` semantics. Each row
defines seven tab-separated columns:

```text
# symbol                  kind  target_arg  payload_arg  encoding  domain                   rollback_on_false
quic_decode_varint_cursor READ  1           -1           varint62  0..0x3fff_ffff_ffff_ffff true
quic_encode_varint        WRITE 0           1            varint62  0..0x3fff_ffff_ffff_ffff true
```

`data/ste_templates.tsv` defines the fixed ASD-STE100 sentence patterns for
entry context, guard requirements, unchecked surface notes, and rollback
effects.
