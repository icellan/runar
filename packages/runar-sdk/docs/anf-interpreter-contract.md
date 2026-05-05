# ANF Interpreter Behavior Contract

This document captures the **current behaviour** of all seven SDK ANF
interpreters: TypeScript (`packages/runar-sdk`), Java (`packages/runar-java`),
Zig (`packages/runar-zig`), Go (`packages/runar-go`), Rust (`packages/runar-rs`),
Python (`packages/runar-py`), and Ruby (`packages/runar-rb`). It is descriptive,
not normative — each row cites a `file:line` so the document fails loudly when
an implementation drifts.

The Lean Eval workstream (`runar-verification/`) is the future canonical
reference for ANF semantics. Until that lands, the seven interpreters listed
here are the working ground truth for off-chain state simulation. They share
intentional gaps; this document records them so future code changes do not
silently widen the divergence.

The `conformance/anf-interpreter/` parity test asserts that all seven
interpreters produce byte-identical `{state, dataOutputs}` for a curated set
of ANF goldens (lenient mode), so any drift is caught immediately. Each
non-TS SDK is exercised through a small CLI driver under
`conformance/anf-interpreter/drivers/<lang>/`; see
`conformance/anf-interpreter/drivers/PROTOCOL.md` for the wire spec.

---

## Interpreters

| Interpreter | Entry point | IR consumed |
|---|---|---|
| TS SDK   | `packages/runar-sdk/src/anf-interpreter.ts` — three modes: `computeNewState` / `computeNewStateAndDataOutputs` (lenient), `executeStrict` (throws `AssertionFailureError`), and `executeOnChainAuthoritative(..., { sighash })` (strict + real ECDSA + real preimage) | ANF JSON loaded as `ANFProgram` |
| Java SDK | `packages/runar-java/src/main/java/runar/lang/sdk/AnfInterpreter.java` — three modes: `computeNewState`, `executeStrict` (throws `AssertionFailureException`), and `executeOnChainAuthoritative(..., new OnChainCryptoContext(sighash))` (strict + real ECDSA + real preimage) | ANF JSON loaded as `Map<String, Object>` |
| Zig SDK  | `packages/runar-zig/src/sdk_anf_interpreter.zig` — three modes: `computeNewState` / `computeNewStateAndDataOutputs` (lenient), `executeStrict` (returns `error.AssertionFailure`), and `executeOnChainAuthoritative(..., .{ .sighash = digest })` (strict + real ECDSA + real preimage) | ANF JSON loaded as `ANFProgram` |
| Go SDK   | `packages/runar-go/anf_interpreter.go` — two modes: `ComputeNewState` / `ComputeNewStateAndDataOutputs` (lenient) and `ExecuteStrict` (strict — returns `*AssertionFailureError`). Real-crypto mode is not yet ported (cross-tier strict parity is enforced; real-crypto cross-parity is exercised by per-SDK unit tests on the TS / Java / Zig SDKs only) | ANF JSON loaded as `*ANFProgram` |
| Rust SDK | `packages/runar-rs/src/sdk/anf_interpreter.rs` — two modes: `compute_new_state` / `compute_new_state_and_data_outputs` (lenient) and `execute_strict` (strict — returns `Result<_, AssertionFailureError>`). Real-crypto mode not yet ported | ANF JSON loaded as `ANFProgram` |
| Python SDK | `packages/runar-py/runar/sdk/anf_interpreter.py` — two modes: `compute_new_state` / `compute_new_state_and_data_outputs` (lenient) and `execute_strict` (strict — raises `AssertionFailureError`). Real-crypto mode not yet ported | ANF JSON loaded as `dict` |
| Ruby SDK | `packages/runar-rb/lib/runar/sdk/anf_interpreter.rb` — two modes: `Runar::SDK::ANFInterpreter.compute_new_state` / `compute_new_state_and_data_outputs` (lenient) and `execute_strict` (strict — raises `Runar::SDK::AssertionFailureError`). Real-crypto mode not yet ported | ANF JSON loaded as `Hash` |

A fourth interpreter, `packages/runar-testing/src/interpreter/interpreter.ts`,
operates on the **AST** (pre-ANF) and has stricter coverage (real ECDSA, real
WOTS+/SLH-DSA verification). It is not part of this contract — it predates ANF
and serves test-driven contract development.

### Tiering — what is and is not in scope

The seven SDKs split into two tiers for the third (real-crypto) mode:

- **Tier 1 — TS / Java / Zig**: ship `executeOnChainAuthoritative`, the
  strict + real-ECDSA + real-preimage entry point. Real-crypto behaviour is
  exercised by per-SDK unit tests
  (`packages/runar-sdk/src/__tests__/anf-interpreter-real-crypto.spec.ts`,
  `AnfInterpreterRealCryptoTest`, and the corresponding Zig tests).
- **Tier 2 — Go / Rust / Python / Ruby**: lenient + strict only by design.
  These SDKs ship the same lenient + strict semantics (cross-tier parity
  for both is enforced by `cross-interpreter.test.ts` and
  `cross-interpreter-strict.test.ts`), but **do not** carry a real-crypto
  pre-broadcast simulator. Consumers needing a real-crypto pre-broadcast
  check on a Tier-2 stack should either:
    1. Run the same call through the TS / Java / Zig SDK in real-crypto
       mode (the ANF + sighash inputs are language-agnostic), or
    2. Submit the transaction to a regtest node — the on-chain VM is the
       authoritative real-crypto verifier.

A cross-interpreter real-crypto golden suite (which would require the four
Tier-2 SDKs to grow `executeOnChainAuthoritative`) is **explicitly out of
scope**. It is deferred to the post-Lean-Eval phase: the Lean reference
will pin canonical real-crypto semantics, and any cross-tier real-crypto
fixtures should be derived from there rather than from the working ground
truth captured in the three current implementations.

### `add_raw_output` simulation — out of scope

`this.addRawOutput(satoshis, scriptBytes)` emits a Bitcoin output whose
locking script is supplied by the caller as raw bytes. None of the seven
ANF interpreters simulate this kind, and none of them surface raw outputs
in the result envelope. This is **deliberate**, not a gap: raw outputs
have arbitrary script bytes that the simulator cannot introspect without
re-implementing the Bitcoin Script VM. On-chain enforcement happens via
`OP_PUSH_TX` / `extractOutputHash`, which the on-chain VM verifies
authoritatively.

Off-chain consumers that need raw-output simulation must extend the
interpreter explicitly. Doing so requires:

1. Extending the result type from `{state, dataOutputs}` to
   `{state, dataOutputs, rawOutputs}` across all seven SDKs.
2. Updating the cross-interpreter parity goldens to include a
   `rawOutputs[]` field.
3. Bumping the wire protocol in
   `conformance/anf-interpreter/drivers/PROTOCOL.md` and every driver.

This is a breaking change to the public ANF-interpreter API and is not
on the roadmap. Track the scope decision against this contract document
rather than re-deriving it from the per-SDK source.

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
| `array_literal` | **default-undefined** — no explicit case in the switch; consumers receive arrays through `args` instead (`anf-interpreter.ts:261-262`) | **handled** — collects the env-resolved values for each `elements` ref into an `ANFValue.array` (`sdk_anf_interpreter.zig:550+`); enables real-crypto `checkMultiSig` | **default-undefined** — `array_literal` is listed in `CHAIN_ONLY_KINDS` and falls through to the no-op skip (`AnfInterpreter.java:370-372`) |

### Per-kind behaviour for the four ANF-only SDKs

The Go, Rust, Python, and Ruby SDKs implement the lenient AND strict modes
of the contract with the same per-kind contract as the TS / Zig / Java
reference: `assert` (the dedicated kind) and `call(assert, ...)` (the call
lowering) both raise `AssertionFailureError` on a falsy predicate when the
strict entry point is invoked. Cross-tier strict parity is enforced by
`conformance/anf-interpreter/cross-interpreter-strict.test.ts`; each
non-TS SDK ships a strict-mode driver under
`conformance/anf-interpreter/drivers/<lang>/` that the harness invokes with
`--mode=strict`. Real-crypto mode (`executeOnChainAuthoritative`) is still
TS-, Java-, and Zig-only; cross-tier real-crypto parity is exercised
per-SDK in unit tests, not in the cross-interpreter golden suite.

| Kind | Go (`anf_interpreter.go`) | Rust (`anf_interpreter.rs`) | Python (`anf_interpreter.py`) | Ruby (`anf_interpreter.rb`) |
|---|---|---|---|---|
| `load_param` / `load_prop` | 186 / 190 | 293 / 298 | 145 / 148 | 143 (combined) |
| `load_const` | 194 | 303 | 151 | 146 |
| `bin_op` | 202 | 314 | 158 | 151 |
| `unary_op` | 209 | 324 | 166 | 159 |
| `call` | 215 | 332 | 173 | 166 |
| `method_call` | 224 | 341 | 177 | 170 |
| `if` | 268 | 380 | 181 | 174 |
| `loop` | 293 | 406 | 191 | 182 |
| `assert` (skipped lenient) | 314 | 431 | 205 | 201 |
| `update_prop` | 318 | 433 | 208 | 204 |
| `add_output` | 326 | 442 | 215 | 210 |
| `add_data_output` | 350 | 460 | 230 | 228 |
| on-chain-only kinds (skipped) | 367 | 471 | 241 | 239 |
| `array_literal` | default (undefined) | default (undefined) | default (undefined) | default (undefined) |

These four SDKs ship both lenient and strict modes; the strict entry
point (`ExecuteStrict` / `execute_strict`) raises `AssertionFailureError`
on the first falsy `assert(...)` predicate (carrying `methodName` plus the
ANF binding name). Real-crypto mode (`executeOnChainAuthoritative`) is
still TS / Java / Zig only; when it lands, this matrix should grow
`checkSig` / `checkMultiSig` / `checkPreimage` real-crypto rows for each.

### Summary of intentional skips

- **On-chain-only kinds** (`check_preimage`, `deserialize_state`, `get_state_script`, `add_raw_output`): the dedicated `check_preimage` ANF kind is still skipped (returns `undefined`/`null`/no-op) — it is a no-op marker on the binding side. The actual `checkPreimage(preimage)` call (which lowers to a `call` ANF kind, not `check_preimage`) IS verified in real-crypto mode. `deserialize_state`, `get_state_script`, `add_raw_output` remain unconditional skips: they are simulation-only intrinsics; on-chain enforcement happens in compiled Bitcoin Script, not here.
- **`assert`**: all three SDKs skip by default and enforce in `executeStrict` / `executeOnChainAuthoritative` — TS throws `AssertionFailureError`, Zig returns `error.AssertionFailure`, Java throws `AssertionFailureException`. The two strict modes both enforce explicit `assert(...)` predicates; only `executeOnChainAuthoritative` additionally verifies `checkSig` / `checkMultiSig` / `checkPreimage` against the caller-supplied sighash.
- **`array_literal`**: TS + Java still rely on the next-step `call` resolving the array via `args` (`Array.isArray(...)` / `List<?>` checks in `verifyMultiSigReal`); the Zig SDK now has an explicit case that materializes an `ANFValue.array` from the binding's `elements` refs, so a contract that builds its multisig sigs/pks lists in the body via `array_literal` works under real-crypto on Zig.

## Builtin function call behaviour

`evalCall` handles ~110 user-callable built-ins. Highlights that are part of the contract:

| Function | TS SDK | Java SDK | Zig SDK |
|---|---|---|---|
| `checkSig` (lenient + strict) | mocked → `true` | mocked → `true` | mocked → `true` |
| `checkSig` (real-crypto) | real ECDSA via `@bsv/sdk` `PublicKey.verify(sighash, sig)` (`anf-interpreter.ts` → `verifyEcdsa`) | real ECDSA via BouncyCastle `ECDSASigner.verifySignature(sighash, r, s)` (`AnfInterpreter.java` → `verifyEcdsaReal`) | real ECDSA via `bsvz.crypto.verifyDigest256RelaxedSec1(pk, sighash, der)` (`sdk_anf_interpreter.zig` → `verifyEcdsaReal`) |
| `checkMultiSig` (lenient + strict) | mocked → `true` | mocked → `true` | mocked → `true` |
| `checkMultiSig` (real-crypto) | real iterative ECDSA over `List<Sig>` × `List<PubKey>` (`verifyMultiSig`) | real iterative ECDSA over `List<Sig>` × `List<PubKey>` (`verifyMultiSigReal`) | real iterative ECDSA over `ANFValue.array` of `bytes` (`verifyMultiSigReal` in `sdk_anf_interpreter.zig`) |
| `checkPreimage` (lenient + strict) | mocked → `true` | mocked → `true` | mocked → `true` |
| `checkPreimage` (real-crypto) | `hash256(preimage) == sighash` byte-eq (`verifyPreimage`) | `hash256(preimage) == sighash` byte-eq (`verifyPreimageReal`) | `hash256(preimage) == sighash` byte-eq (`verifyPreimageReal`) |
| `sha256`, `hash256`, `hash160`, `ripemd160` | real, deterministic (`hashFn`) | real, deterministic via `MockCrypto` | real, deterministic via `bsvz.crypto.hash` |
| `assert` (as a `call.func`) | skipped lenient; enforced strict + real-crypto | skipped lenient; enforced strict + real-crypto | skipped lenient; enforced strict + real-crypto |
| EC ops (`ecAdd`, `ecMul`, …) | not implemented in this layer | not implemented | not implemented |
| WOTS+ / SLH-DSA verifiers | not implemented | not implemented | not implemented |
| Math/byte ops (`abs`, `min`, `max`, `cat`, `substr`, `len`, …) | concrete | concrete | concrete |

Any built-in not handled by `evalCall` falls through to a default that returns `undefined`. All seven interpreters agree on this default. Cross-implementation parity is asserted by `conformance/anf-interpreter/cross-interpreter.test.ts` over the curated case list — every fixture is run through TS in-process plus the Java / Zig / Go / Rust / Python / Ruby driver subprocesses (see `conformance/anf-interpreter/drivers/`), and every output must equal the TS-pinned golden byte-for-byte. Strict + real-crypto modes are exercised by per-SDK unit tests in `packages/runar-sdk/src/__tests__/anf-interpreter-{strict,real-crypto}.spec.ts`, the Zig `executeOnChainAuthoritative — *` tests in `packages/runar-zig/src/sdk_anf_interpreter.zig`, and `AnfInterpreterRealCryptoTest` in `packages/runar-java/src/test/java/runar/lang/sdk/`.

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
- **Real-crypto coverage parity**: `executeOnChainAuthoritative` lands real ECDSA + real preimage verification on TS / Zig / Java with matching shapes. Zig's `checkMultiSig` now iterates over an `ANFValue.array` of `bytes` (sigs and pks) using the same left-to-right consume + greedy-pubkey-match loop as TS / Java; see the multisig tests in `packages/runar-zig/src/sdk_anf_interpreter.zig` ("checkMultiSig 1-of-2 passes when sig matches second pk", "1-of-2 fails when sig matches no pk", "rejects non-array sig arg"). Real-crypto multisig parity is exercised per-SDK in unit tests; the cross-interpreter parity test still runs lenient mode only.
- **`array_literal`**: TS + Java leave it default-undefined (consumers read arrays from `args`); Zig materializes an `ANFValue.array`. ANF goldens that exercise `array_literal` bindings produce identical `{state, dataOutputs}` outputs across all three because the consumer of the array is either `call(checkMultiSig)` (which returns `true` in lenient mode regardless) or a downstream `call` whose semantics don't depend on per-element identity.

## Future directions

- The Lean Eval reference (`runar-verification/`) will define the canonical
  semantics. When it lands, this document should be re-derived from Lean
  rather than from the seven implementations.
- All seven SDKs ship lenient + strict modes; both are exercised by
  `cross-interpreter.test.ts` and `cross-interpreter-strict.test.ts` (each
  is 7 SDKs × 6 fixtures = 42 tests). Real-crypto mode is Tier-1 only
  (TS / Java / Zig) — see "Tiering" above. The decision to leave Tier-2
  Go / Rust / Python / Ruby without a real-crypto entry point is documented
  there, and is upheld by per-SDK unit tests on the Tier-1 stacks plus
  on-chain verification for any production pre-broadcast check on Tier-2.
- `add_raw_output` simulation is explicitly out of scope across all seven
  SDKs (see "out of scope" section above).
- (`array_literal` element resolution in Zig has landed — see the per-kind
  matrix and the multisig tests.)
