# ANF interpreter parity-driver protocol

Every per-SDK driver in this directory is a small CLI that reads a single JSON
input file, calls the SDK's `computeNewStateAndDataOutputs` ANF interpreter
entry point in lenient mode, and prints a single JSON output object on stdout.
The cross-interpreter parity test (`../cross-interpreter.test.ts`) spawns each
driver and compares its output to the TS-pinned golden via vitest's
`expect(actual).toEqual(expected)` (structural deep equality — key ordering
within objects does not need to match).

## Invocation

```
<driver-binary-or-script> <input-json-file>
```

Exit code: 0 on success, non-zero on any error. Driver MUST NOT print partial
output on error — print full output on stdout only after a successful run.

## Input JSON

```json
{
  "case": "arithmetic",
  "methodName": "publish",
  "currentState": { "count": "0n" },
  "args": { "payload": "deadbeef" },
  "constructorArgs": []
}
```

- `case` — conformance fixture name; the driver resolves the ANF IR at
  `<repo-root>/conformance/tests/<case>/expected-ir.json`. The driver SHOULD
  walk up from its own location until it finds a directory named `conformance`
  to anchor the lookup, so it works no matter which working directory the
  caller is in. (`anfPath` is also accepted as a fully-qualified absolute path
  alternative — drivers that support both can be invoked either way.)
- `methodName` — public method name to execute
- `currentState` — map of property name → value
- `args` — map of param name → value
- `constructorArgs` — list of constructor arg values (positional)

## Bigint encoding

Strings whose entire value matches `^-?\d+n$` represent bigints.
Example: `"42n"` decodes to integer 42.

Drivers MUST decode `"Xn"` → bigint when reading currentState/args/constructorArgs,
and MUST encode bigints back as `"Xn"` strings when writing state/dataOutputs
satoshis fields.

## Output JSON (stdout)

```json
{
  "state": { "count": "1n" },
  "dataOutputs": [
    { "satoshis": "42n", "script": "0001020304" }
  ],
  "rawOutputs": [
    { "satoshis": "1000n", "script": "76a91488ac" }
  ]
}
```

- `state` — full updated state map (current + delta), bigint-encoded
- `dataOutputs` — list of `{ satoshis, script }` records in declaration order
  resolved from `this.addDataOutput(satoshis, scriptBytes)` calls.
  `satoshis` is bigint-encoded, `script` is the hex payload.
- `rawOutputs` — list of `{ satoshis, script }` records in declaration order
  resolved from `this.addRawOutput(satoshis, scriptBytes)` calls. The
  simulator does NOT introspect these script bytes (they are caller-supplied
  raw locking-script bytes); the field is surfaced so an off-chain transaction
  builder can splice them at the correct output index. Encoded identically
  to `dataOutputs`. MUST be present (as `[]` if empty) — every driver and
  every golden file in `expected/` and `expected-strict/` carries this key.

### Strict-mode failure shape (cross-interpreter-strict.test.ts only)

When invoked with `--mode=strict` and the contract method body fires an
`assert(...)` that evaluates to false, drivers print:

```json
{
  "error": "AssertionFailureError",
  "methodName": "<method>",
  "bindingName": "<binding-id>"
}
```

instead of the success envelope above. Exit code stays 0; only real driver
errors (missing IR, malformed input) exit non-zero with a stderr message.

The TS reference implementation lives at
`packages/runar-sdk/src/anf-interpreter.ts::computeNewStateAndDataOutputs`. The
`normalizeResult` helper in `cross-interpreter.test.ts` round-trips its output
through the same protocol.

## Building each driver

The cross-interpreter test detects each driver by the presence of its built
binary or script. Local devs need:

| Driver | Build / setup | Discovered by |
|---|---|---|
| python | nothing — script `python/driver.py` runs in-place; needs `python3` on PATH | `existsSync('python/driver.py')` |
| ruby | nothing — script `ruby/driver.rb` runs in-place; needs `ruby` on PATH | `existsSync('ruby/driver.rb')` |
| go | nothing — `go run go/driver.go` builds on demand from `go.work` | `existsSync('go/driver.go')` + `go` on PATH |
| rust | `cd rust && cargo build --release` → `rust/target/release/runar-anf-driver-rust` | binary path |
| java | `cd java && gradle fatJar --no-daemon` → `java/build/libs/runar-anf-driver.jar` | jar path |
| zig | `cd zig && zig build -Doptimize=ReleaseSafe` → `zig/zig-out/bin/runar-anf-driver-zig` | binary path |

CI runs the matrix in the dedicated `conformance-anf-parity` job
(`.github/workflows/ci.yml`). That job installs every toolchain (Node / Go /
Rust / Python / Zig / Ruby / Java), builds the three compiled drivers (Rust /
Java / Zig), and runs `pnpm run conformance:anf-parity` with
`RUNAR_ANF_DRIVERS_STRICT=1` so a missing driver hard-fails instead of
silently skipping. Locally, `pnpm run conformance:anf-parity` runs the same
suite — drivers that are not built yet skip per the table above. Set
`RUNAR_ANF_DRIVERS_STRICT=1` locally to mirror CI's strict mode.
