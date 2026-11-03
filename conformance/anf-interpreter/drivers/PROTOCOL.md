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
  caller is in.
- `anfPath` — alternative to `case`, and PREFERRED by every driver when both
  are present: a path to the ANF IR, resolved against the process working
  directory (the parity tests spawn drivers with cwd = repo root, so the
  checked-in inputs use repo-root-relative paths; an absolute path also works).
  Use it for a case whose program is not a conformance fixture — e.g. the
  `num2bin-*` cases, whose program lives in `../programs/` because no fixture
  routes a `num2bin` result anywhere the lenient envelope can observe it.
  Exactly one of `case` / `anfPath` must be present.
- `methodName` — public method name to execute
- `currentState` — map of property name → value
- `args` — map of param name → value, keyed by the SOURCE (ABI) name.
  Interpreters bind args to the ANF method's `params` BY NAME, never by
  position. One rename applies (N-360): a property-named public param that
  the method reassigns appears in the ANF's `params` under its slot name
  `<name>@local`, and every interpreter binds that slot from `args[<name>]`
  (an exact `args["<name>@local"]` entry, if present, wins). Positional
  binding is not used because the ANF and ABI param lists do not align
  1:1 — a FixedArray param is one ABI entry but several ANF params.
- `constructorArgs` — list of constructor arg values (positional)

## Bigint encoding

Strings whose entire value matches `^-?\d+n$` represent bigints.
Example: `"42n"` decodes to integer 42.

Drivers MUST decode `"Xn"` → bigint when reading currentState/args/constructorArgs,
and MUST encode bigints back as `"Xn"` strings when writing state/dataOutputs
satoshis fields.

A value outside a tier's native integer width (e.g. Rust's and Zig's `i64`,
N-163) MUST still round-trip byte-identically as its `"Xn"` string — carried
through state unchanged even though the tier refuses to compute with it
(design B: refuse on use, pass through otherwise).

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

### Strict-mode and on-chain-mode failure shape

When invoked with `--mode=strict` or `--mode=on-chain` and the contract
method body fires an `assert(...)` that evaluates to false, drivers print:

```json
{
  "error": "AssertionFailureError",
  "methodName": "<method>",
  "bindingName": "<binding-id>"
}
```

instead of the success envelope above. Exit code stays 0; only real driver
errors (missing IR, malformed input, missing `sighash` for on-chain) exit
non-zero with a stderr message.

### Mode flag (`--mode=lenient|strict|on-chain`)

- **lenient** (default): asserts skipped, crypto built-ins mocked
  (`checkSig` / `checkMultiSig` / `checkPreimage` always return true).
  Used for state-transition simulation.
- **strict**: asserts enforced (raises `AssertionFailureError` on first
  falsy predicate); crypto built-ins still mocked. Used for pre-broadcast
  guard checks. This also covers the compiler's own auto-injected
  stateful-method prologue (the `checkPreimage` call and the sighash-type
  check every public `StatefulSmartContract` method starts with): both are
  mocked exactly like `checkSig`/`checkMultiSig`/`checkPreimage`, detected
  by the prologue's fixed structural shape rather than by binding name, so
  a developer-written `assert(...)` anywhere else in the method body is
  still fully enforced (F-164).
- **on-chain**: asserts enforced AND crypto built-ins perform real
  verification against the supplied `sighash`:
  - `checkSig(sig, pk)` → ECDSA-verify(sighash, sig, pk) using SEC1
    secp256k1. The signature is in checksig format, DER followed by one
    sighash type byte (stripped); bare DER with no sighash byte aborts, as in
    `Spend` (N-255). Verification is against the raw 32-byte sighash (no extra
    SHA-256), matching the on-chain `OP_CHECKSIG` semantic. An EMPTY
    signature that does not verify yields `false`. A NON-EMPTY, well-formed
    signature that does not verify aborts (N-198): a node rejects it under
    NULLFAIL (BIP146), so the arm of `checkSig(a, A) || checkSig(b, B)` that
    must fail takes an empty signature (`EMPTY_SIG`). `@bsv/sdk` `Spend` has no
    NULLFAIL and pushes false there. A
    MALFORMED encoding aborts too, as `OP_CHECKSIG` does on `@bsv/sdk`
    `Spend` (N-197): a non-empty signature that is not strict DER or has a
    high S, or a public key that is not 0x02/0x03 + 33 bytes or 0x04 + 65
    bytes on the curve. Each tier raises it through its OP_SPLIT-abort
    channel — a plain error carrying `OP_CHECKSIG aborts` (TS / Go / Python /
    Ruby / Java: non-zero exit + stderr), `error.ScriptNumberError` (Zig), or
    an `AssertionFailureError` at the `checkSig` call binding (Rust). Pinned
    by `../checksig-encoding-abort.test.ts` over `../checksig-encoding/vectors.json`
    (the NULLFAIL abort uses the same channels; `../cross-interpreter-real-crypto.test.ts`
    normalises them to `{ "error": "ScriptAbort", "methodName": "<m>" }`).
  - `checkMultiSig(sigs, pks)` → `OP_CHECKMULTISIG` as `Spend` runs it
    (N-259), over the lists an `array_literal` binding builds: the last
    signature against the last key first, walking both lists toward the
    first; a verifying signature consumes its key, a key is consumed either
    way, and the check fails once fewer keys remain than signatures. Each
    EXAMINED pair passes the `checkSig` encoding gates and aborts on a
    malformed one; N > M aborts; a failing check with any non-empty signature
    aborts under NULLFAIL (`Spend` pushes false there). Aborts use the
    `checkSig` channels, with `OP_CHECKMULTISIG aborts` in the message (Rust:
    an `AssertionFailureError` at the `checkMultiSig` call binding). Pinned by
    `../checkmultisig-onchain.test.ts` over `../checkmultisig-onchain/vectors.json`.
  - `checkPreimage(preimage)` → `hash256(preimage) == sighash`
    byte-equal.

  Required input field: `sighash` (32-byte hex string). Drivers exit
  non-zero with stderr if it's missing or malformed.

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
