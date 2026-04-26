# ANF Interpreter Behavior Contract

This document captures the **current behaviour** of the three SDK ANF
interpreters: TypeScript (`packages/runar-sdk`), Zig (`packages/runar-zig`),
and Java (`packages/runar-java`). It is descriptive, not normative — each row
cites a `file:line` so the document fails loudly when an implementation drifts.

The Lean Eval workstream (`runar-verification/`) is the future canonical
reference for ANF semantics. Until that lands, the three interpreters listed
here are the working ground truth for off-chain state simulation. They share
intentional gaps; this document records them so future code changes do not
silently widen the divergence.

A separate `conformance/anf-interpreter/` parity test asserts that the three
interpreters produce byte-identical `{state, dataOutputs}` for a curated set of
ANF goldens, so any drift is caught immediately.

---

## Interpreters

| Interpreter | Entry point | IR consumed |
|---|---|---|
| TS SDK   | `packages/runar-sdk/src/anf-interpreter.ts:137` (`evalValue`) | ANF JSON loaded as `ANFProgram` |
| Java SDK | `packages/runar-java/src/main/java/runar/lang/sdk/AnfInterpreter.java:248` (`evalValue`) — two modes: `computeNewState` (line 74) and `executeStrict` (line 112) | ANF JSON loaded as `Map<String, Object>` |
| Zig SDK  | `packages/runar-zig/src/sdk_anf_interpreter.zig:145` (`computeNewState`) | ANF JSON loaded as `ANFProgram` |

A fourth interpreter, `packages/runar-testing/src/interpreter/interpreter.ts`,
operates on the **AST** (pre-ANF) and has stricter coverage (real ECDSA, real
WOTS+/SLH-DSA verification). It is not part of this contract — it predates ANF
and serves test-driven contract development.

---

## Per-kind behaviour matrix

The 18 ANF value kinds defined in `packages/runar-ir-schema/src/anf-ir.ts` and
how each interpreter handles them. Cells cite the most relevant `file:line` in
each implementation.

| ANF kind | TS SDK | Zig SDK | Java SDK |
|---|---|---|---|
| `load_param` | env lookup (`anf-interpreter.ts:145`) | env lookup (`sdk_anf_interpreter.zig:145`+) | env lookup (`AnfInterpreter.java:259`) |
| `load_prop` | env lookup (`anf-interpreter.ts:148`) | env lookup | env lookup (`AnfInterpreter.java:260`) |
| `load_const` | returns value, resolves `@ref:` aliases (`anf-interpreter.ts:151-158`) | returns value | returns value (`AnfInterpreter.java:263-269`) |
| `bin_op` | concrete (`anf-interpreter.ts:160-166` → `evalBinOp:270`) | concrete | concrete (`AnfInterpreter.java:270-276` → `evalBinOp:429`) |
| `unary_op` | concrete (`anf-interpreter.ts:168-169`) | concrete | concrete (`AnfInterpreter.java:277-282`) |
| `call` | dispatched to `evalCall` (`anf-interpreter.ts:171-172` → `:348`) | dispatched | dispatched to `evalCall` (`AnfInterpreter.java:283-289` → `:486`) |
| `method_call` | concrete with private-method body inline (`anf-interpreter.ts:174-182`) | concrete | concrete (`AnfInterpreter.java:290-296` → `evalMethodCall:376`) |
| `if` | concrete branch eval (`anf-interpreter.ts:184-197`) | concrete | concrete (`AnfInterpreter.java:297-309`) |
| `loop` | concrete bounded loop with iterVar binding (`anf-interpreter.ts:199-213`) | concrete | concrete (`AnfInterpreter.java:310-325`) |
| `assert` | **skipped** — `return undefined` (`anf-interpreter.ts:215-218`) | **skipped** | **skipped by default**; throws `AssertionFailureException` in `executeStrict` mode (`AnfInterpreter.java:326-337`) |
| `update_prop` | mutates `env` + `stateDelta` (`anf-interpreter.ts:220-225`) | mutates state map | mutates `env` + `stateDelta` (`AnfInterpreter.java:338-344`) |
| `add_output` | extracts state values into `stateDelta` (`anf-interpreter.ts:227-241`) | extracts | extracts (`AnfInterpreter.java:345-360`) |
| `add_data_output` | records to `dataOutputs[]` (`anf-interpreter.ts:243-252`) | records | records (`AnfInterpreter.java:361-369`) |
| `add_raw_output` | **skipped** — `return undefined` (`anf-interpreter.ts:254-259`) | **skipped** | **skipped** — listed in `CHAIN_ONLY_KINDS` (`AnfInterpreter.java:56-59`) |
| `check_preimage` | **skipped** (`anf-interpreter.ts:255`) | **skipped** | **skipped** (`AnfInterpreter.java:56`) |
| `deserialize_state` | **skipped** (`anf-interpreter.ts:256`) | **skipped** | **skipped** (`AnfInterpreter.java:57`) |
| `get_state_script` | **skipped** (`anf-interpreter.ts:257`) | **skipped** | **skipped** (`AnfInterpreter.java:57`) |
| `array_literal` | **default-undefined** — no explicit case in the switch; falls through to `default: return undefined` (`anf-interpreter.ts:261-262`) | **default-undefined** | **default-undefined** (`AnfInterpreter.java:370-372`) |

### Summary of intentional skips

- **On-chain-only kinds** (`check_preimage`, `deserialize_state`, `get_state_script`, `add_raw_output`): all three interpreters return `undefined`/`null`/no-op. These are simulation-only interpreters; on-chain enforcement happens in compiled Bitcoin Script, not here.
- **`assert`**: TS and Zig always skip. Java skips by default but enforces in `executeStrict` mode.
- **`array_literal`**: silently falls through to default. There is no dedicated case in any of the three interpreters today — methods that pass arrays to `checkMultiSig` rely on the next-step `call` returning `true` rather than the elements actually being resolved.

## Builtin function call behaviour

`evalCall` handles ~110 user-callable built-ins. Highlights that are part of the contract:

| Function | TS SDK | Java SDK | Zig SDK |
|---|---|---|---|
| `checkSig`, `checkMultiSig`, `checkPreimage` | mocked → `true` (`anf-interpreter.ts:351-353`) | mocked → `true` (`AnfInterpreter.java:486-488`) | mocked → `true` |
| `sha256`, `hash256`, `hash160`, `ripemd160` | real, deterministic (`anf-interpreter.ts:356-359` → `hashFn`) | real, deterministic via `MockCrypto` (`AnfInterpreter.java:493-494` and `:608-609`) | real, deterministic |
| `assert` (as a `call.func`) | skipped (`anf-interpreter.ts:362`) | skipped | skipped |
| EC ops (`ecAdd`, `ecMul`, …) | not implemented in this layer | not implemented | not implemented |
| WOTS+ / SLH-DSA verifiers | not implemented | not implemented | not implemented |
| Math/byte ops (`abs`, `min`, `max`, `cat`, `substr`, `len`, …) | concrete | concrete | concrete |

Any built-in not handled by `evalCall` falls through to a default that returns `undefined`. The three interpreters agree on this default. Cross-implementation parity is asserted by `conformance/anf-interpreter/cross-interpreter.test.ts` over the curated case list.

## Output contract

All three interpreters produce a tuple of:

1. **`state` / `newState`** — a map of property name → resolved value, accumulating every `update_prop` and `add_output` `stateValues` extraction in evaluation order.
2. **`dataOutputs`** — an ordered list of `{satoshis: bigint, script: string}` records, one per `add_data_output` binding executed.

`add_raw_output` is **not** recorded — neither as a state change nor as a data output. This is a documented gap. Off-chain consumers that need raw-output simulation must extend the interpreters explicitly.

`get_state_script` returns nothing — simulation does not synthesize the
continuation locking script. The on-chain runtime handles that via
`OP_CODESEPARATOR` and the stateful continuation pattern.

## Known divergences (caught by the parity test)

- **`assert` strictness**: Java's `executeStrict` mode raises on falsy asserts; TS and Zig always swallow them. The parity test runs Java in non-strict mode by default so all three behave identically.
- **`array_literal` is silently undefined** in all three, but ANF goldens that include `array_literal` bindings still produce identical `{state, dataOutputs}` outputs because the consumer of the array is `call(checkMultiSig)` which returns `true` regardless. Curated parity-test cases avoid `array_literal` altogether to keep the assertion sharp.

## Future directions

- The Lean Eval reference (`runar-verification/`) will define the canonical semantics. When it lands, this document should be re-derived from Lean rather than from the three implementations.
- Real signature verification, `add_raw_output` recording, and `array_literal` element resolution are deferred to that effort and are explicitly out of scope for these three SDK interpreters.
