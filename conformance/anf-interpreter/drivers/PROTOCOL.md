# ANF interpreter parity-driver protocol

Every per-SDK driver in this directory is a small CLI that reads a single JSON
input file, calls the SDK's `computeNewStateAndDataOutputs` ANF interpreter
entry point in lenient mode, and prints a single JSON output object on stdout.
The cross-interpreter parity test spawns each driver and compares outputs
byte-for-byte.

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
  ]
}
```

- `state` — full updated state map (current + delta), bigint-encoded
- `dataOutputs` — list of `{ satoshis, script }` records in declaration order;
  `satoshis` is bigint-encoded, `script` is hex string

The TS reference implementation lives at
`packages/runar-sdk/src/anf-interpreter.ts::computeNewStateAndDataOutputs`. The
`normalizeResult` helper in `cross-interpreter.test.ts` round-trips its output
through the same protocol.
