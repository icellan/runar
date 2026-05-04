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
| TS SDK   | `packages/runar-sdk/src/anf-interpreter.ts` — three modes: `computeNewState` / `computeNewStateAndDataOutputs` (lenient), `executeStrict` (throws `AssertionFailureError`), and `executeOnChainAuthoritative(..., { sighash })` (strict + real ECDSA + real preimage) | ANF JSON loaded as `ANFProgram` |
| Java SDK | `packages/runar-java/src/main/java/runar/lang/sdk/AnfInterpreter.java` — three modes: `computeNewState`, `executeStrict` (throws `AssertionFailureException`), and `executeOnChainAuthoritative(..., new OnChainCryptoContext(sighash))` (strict + real ECDSA + real preimage) | ANF JSON loaded as `Map<String, Object>` |
| Zig SDK  | `packages/runar-zig/src/sdk_anf_interpreter.zig` — three modes: `computeNewState` / `computeNewStateAndDataOutputs` (lenient), `executeStrict` (returns `error.AssertionFailure`), and `executeOnChainAuthoritative(..., .{ .sighash = digest })` (strict + real ECDSA + real preimage) | ANF JSON loaded as `ANFProgram` |

A fourth interpreter, `packages/runar-testing/src/interpreter/interpreter.ts`,
operates on the **AST** (pre-ANF) and has stricter coverage (real ECDSA, real
WOTS+/SLH-DSA verification). It is not part of this contract — it predates ANF
and serves test-driven contract development.

### When to use which mode

- **Lenient** (`computeNewState` / `computeNewStateAndDataOutputs`) — fast
  iteration on state-transition logic. The canonical pre-call helper used
  by `RunarContract.call(...)` to derive the next state. Skips asserts so
  that a method's post-state is always computable, even when the supplied
  args wouldn't actually pass the on-chain script. **Crypto built-ins are
  mocked.**
- **Strict** (`executeStrict`) — pre-broadcast smoke check that explicit
  `assert(...)` predicates hold. Faster than the on-chain VM and surfaces
  assertion failures with a binding name + method name so the developer
  can pinpoint the failing guard. **Crypto built-ins are still mocked** —
  use this when you trust the signing path but want to validate the
  business-logic guards.
- **On-chain authoritative** (`executeOnChainAuthoritative`) — the
  authoritative pre-broadcast check. Strict assert enforcement PLUS real
  ECDSA verification of `checkSig` / `checkMultiSig` against the supplied
  sighash, PLUS real `SHA256(SHA256(preimage)) == sighash` enforcement of
  `checkPreimage`. Requires a `sighash` parameter, so it is impossible to
  call by accident without supplying the cryptographic inputs the
  verification needs. Use this to validate the exact transaction the
  caller intends to broadcast — a passing run guarantees the on-chain VM
  will accept the call (modulo VM-only intrinsics like
  `extractAmount` / `extractOutputHash`, which still return placeholders).

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
| `assert` | **skipped by default**; in `executeStrict` mode throws `AssertionFailureError` on the first falsy predicate (`anf-interpreter.ts:298-307`) | **skipped by default**; in `executeStrict` mode returns `error.AssertionFailure` on the first falsy predicate (`sdk_anf_interpreter.zig:444-456`) | **skipped by default**; throws `AssertionFailureException` in `executeStrict` mode (`AnfInterpreter.java:326-337`) |
| `update_prop` | mutates `env` + `stateDelta` (`anf-interpreter.ts:220-225`) | mutates state map | mutates `env` + `stateDelta` (`AnfInterpreter.java:338-344`) |
| `add_output` | extracts state values into `stateDelta` (`anf-interpreter.ts:227-241`) | extracts | extracts (`AnfInterpreter.java:345-360`) |
| `add_data_output` | records to `dataOutputs[]` (`anf-interpreter.ts:243-252`) | records | records (`AnfInterpreter.java:361-369`) |
| `add_raw_output` | **skipped** — `return undefined` (`anf-interpreter.ts:254-259`) | **skipped** | **skipped** — listed in `CHAIN_ONLY_KINDS` (`AnfInterpreter.java:56-59`) |
| `check_preimage` | **skipped** (`anf-interpreter.ts:255`) | **skipped** | **skipped** (`AnfInterpreter.java:56`) |
| `deserialize_state` | **skipped** (`anf-interpreter.ts:256`) | **skipped** | **skipped** (`AnfInterpreter.java:57`) |
| `get_state_script` | **skipped** (`anf-interpreter.ts:257`) | **skipped** | **skipped** (`AnfInterpreter.java:57`) |
| `array_literal` | **default-undefined** — no explicit case in the switch; falls through to `default: return undefined` (`anf-interpreter.ts:261-262`) | **default-undefined** | **default-undefined** (`AnfInterpreter.java:370-372`) |

### Summary of intentional skips

- **On-chain-only kinds** (`check_preimage`, `deserialize_state`, `get_state_script`, `add_raw_output`): the dedicated `check_preimage` ANF kind is still skipped (returns `undefined`/`null`/no-op) — it is a no-op marker on the binding side. The actual `checkPreimage(preimage)` call (which lowers to a `call` ANF kind, not `check_preimage`) IS verified in real-crypto mode. `deserialize_state`, `get_state_script`, `add_raw_output` remain unconditional skips: they are simulation-only intrinsics; on-chain enforcement happens in compiled Bitcoin Script, not here.
- **`assert`**: all three SDKs skip by default and enforce in `executeStrict` / `executeOnChainAuthoritative` — TS throws `AssertionFailureError`, Zig returns `error.AssertionFailure`, Java throws `AssertionFailureException`. The two strict modes both enforce explicit `assert(...)` predicates; only `executeOnChainAuthoritative` additionally verifies `checkSig` / `checkMultiSig` / `checkPreimage` against the caller-supplied sighash.
- **`array_literal`**: silently falls through to default. There is no dedicated case in any of the three interpreters today — methods that pass arrays to `checkMultiSig` rely on the next-step `call` resolving the array via `args` (Java + TS support `List<?>`/`Array.isArray(...)` in `verifyMultiSigReal`; the Zig path returns `false` in real-crypto mode because its ANFValue surface doesn't model arrays yet).

## Builtin function call behaviour

`evalCall` handles ~110 user-callable built-ins. Highlights that are part of the contract:

| Function | TS SDK | Java SDK | Zig SDK |
|---|---|---|---|
| `checkSig` (lenient + strict) | mocked → `true` | mocked → `true` | mocked → `true` |
| `checkSig` (real-crypto) | real ECDSA via `@bsv/sdk` `PublicKey.verify(sighash, sig)` (`anf-interpreter.ts` → `verifyEcdsa`) | real ECDSA via BouncyCastle `ECDSASigner.verifySignature(sighash, r, s)` (`AnfInterpreter.java` → `verifyEcdsaReal`) | real ECDSA via `bsvz.crypto.verifyDigest256RelaxedSec1(pk, sighash, der)` (`sdk_anf_interpreter.zig` → `verifyEcdsaReal`) |
| `checkMultiSig` (lenient + strict) | mocked → `true` | mocked → `true` | mocked → `true` |
| `checkMultiSig` (real-crypto) | real iterative ECDSA over `List<Sig>` × `List<PubKey>` (`verifyMultiSig`) | real iterative ECDSA over `List<Sig>` × `List<PubKey>` (`verifyMultiSigReal`) | returns `false` — array-of-bytes ANFValue surface not modelled yet |
| `checkPreimage` (lenient + strict) | mocked → `true` | mocked → `true` | mocked → `true` |
| `checkPreimage` (real-crypto) | `hash256(preimage) == sighash` byte-eq (`verifyPreimage`) | `hash256(preimage) == sighash` byte-eq (`verifyPreimageReal`) | `hash256(preimage) == sighash` byte-eq (`verifyPreimageReal`) |
| `sha256`, `hash256`, `hash160`, `ripemd160` | real, deterministic (`hashFn`) | real, deterministic via `MockCrypto` | real, deterministic via `bsvz.crypto.hash` |
| `assert` (as a `call.func`) | skipped lenient; enforced strict + real-crypto | skipped lenient; enforced strict + real-crypto | skipped lenient; enforced strict + real-crypto |
| EC ops (`ecAdd`, `ecMul`, …) | not implemented in this layer | not implemented | not implemented |
| WOTS+ / SLH-DSA verifiers | not implemented | not implemented | not implemented |
| Math/byte ops (`abs`, `min`, `max`, `cat`, `substr`, `len`, …) | concrete | concrete | concrete |

Any built-in not handled by `evalCall` falls through to a default that returns `undefined`. The three interpreters agree on this default. Cross-implementation parity is asserted by `conformance/anf-interpreter/cross-interpreter.test.ts` over the curated case list (lenient mode only — strict + real-crypto are exercised by per-SDK unit tests in `packages/runar-sdk/src/__tests__/anf-interpreter-{strict,real-crypto}.spec.ts`, the Zig `executeOnChainAuthoritative — *` tests in `packages/runar-zig/src/sdk_anf_interpreter.zig`, and `AnfInterpreterRealCryptoTest` in `packages/runar-java/src/test/java/runar/lang/sdk/`).

## Output contract

All three interpreters produce a tuple of:

1. **`state` / `newState`** — a map of property name → resolved value, accumulating every `update_prop` and `add_output` `stateValues` extraction in evaluation order.
2. **`dataOutputs`** — an ordered list of `{satoshis: bigint, script: string}` records, one per `add_data_output` binding executed.

`add_raw_output` is **not** recorded — neither as a state change nor as a data output. This is a documented gap. Off-chain consumers that need raw-output simulation must extend the interpreters explicitly.

`get_state_script` returns nothing — simulation does not synthesize the
continuation locking script. The on-chain runtime handles that via
`OP_CODESEPARATOR` and the stateful continuation pattern.

## Known divergences (caught by the parity test)

- **`assert` strictness**: all three SDKs default to lenient (asserts skipped) and opt in to strict via a separate entry point — TS `executeStrict` (throws `AssertionFailureError`), Zig `executeStrict` (returns `error.AssertionFailure`), Java `executeStrict` (throws `AssertionFailureException`). The parity test runs all three in lenient mode by default so they behave identically; strict-mode parity is exercised by per-SDK unit tests rather than the cross-interpreter golden suite.
- **Real-crypto coverage parity**: `executeOnChainAuthoritative` lands real ECDSA + real preimage verification on TS / Zig / Java. The Zig interpreter's real-crypto `checkMultiSig` returns `false` rather than iterating because its `ANFValue` surface doesn't model arrays yet; TS + Java iterate over `Array.isArray` / `List<?>` arg shapes. ANF goldens that exercise real multisig should run the TS or Java path until Zig grows array-of-bytes support.
- **`array_literal` is silently undefined** in all three, but ANF goldens that include `array_literal` bindings still produce identical `{state, dataOutputs}` outputs in lenient + strict mode because the consumer of the array is `call(checkMultiSig)` which returns `true` regardless. Curated parity-test cases avoid `array_literal` altogether to keep the assertion sharp.

## Future directions

- The Lean Eval reference (`runar-verification/`) will define the canonical semantics. When it lands, this document should be re-derived from Lean rather than from the three implementations.
- `add_raw_output` recording, `array_literal` element resolution in Zig, and a TS/Java/Zig real-crypto cross-parity golden suite are deferred to that effort.
