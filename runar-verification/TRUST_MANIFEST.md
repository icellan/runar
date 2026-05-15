# Trust Manifest

This document is the authoritative inventory of the assumptions that the
Runar Lean verification currently relies on. It intentionally separates
proved facts, explicit assumptions, and executable defaults.

The drift gate in `scripts/check-tcb-drift.sh` enforces these headline
counts:

| Item | Count | Meaning |
|---|---:|---|
| Project axioms | 71 | Named assumptions in Lean code |
| Opaque executable defaults | 0 | No executable bodies hidden from proofs |
| Opaque defaults with bodies | 0 | No opaque declarations carry defaults |
| `partial def` | 0 | No partial definitions under `RunarVerification/` |

## Axiom Inventory

| File | Count | Role |
|---|---:|---|
| `RunarVerification/ANF/Eval.lean` | 45 | Crypto and builtin primitive symbols, including external hash, preimage, and auth backends |
| `RunarVerification/Crypto/Spec.lean` | 26 | EC laws, auxiliary key functions, EUF-CMA-style companions |
| `RunarVerification/Stack/TxContext.lean` | 0 | Concrete BIP-143 context/preimage model; no companion assumptions |

These axioms are permitted by the current policy, but every theorem or
status claim that depends on them must say so. They are not hidden by
the top-level theorem names.

## External Hash Backend

`Crypto.HashBackend` supplies SHA-256 and RIPEMD-160 to the Lean model.
Lean does not prove or implement those algorithms; proofs quantify over
the backend. `Crypto.hash160` and `Crypto.hash256` remain concrete
definitions over that backend, so their linking lemmas are `rfl`.
Lean code generation uses a fail-fast backend via `implemented_by`; if a
Lean executable reaches these hashes without an external backend model,
it aborts instead of producing a placeholder digest.

Runtime confidence for the Runar implementations is handled outside
Lean: `conformance/runtime-vectors/hashes.json` carries fixed vectors
for `sha256`, `ripemd160`, `hash160`, and `hash256`, and
`packages/runar-testing/src/__tests__/runtime-vectors.test.ts` checks
those vectors against Node.js `crypto` plus the Runar runtime.

## External Auth Backend

`Crypto.AuthBackend` supplies `checkSig`, `checkMultiSig`, and the
legacy single-payload `checkMultiSigStack` fallback used by existing
peephole abstractions. Lean does not implement ECDSA or multisig
verification here; proofs quantify over the backend. Lean code
generation uses a fail-fast backend via `implemented_by`, so
authentication execution aborts unless a real backend model is supplied.

## External Preimage Backend

`Crypto.PreimageBackend` supplies `checkPreimage`. The BIP-143 byte
layout and field extraction are concrete in Lean, but deciding whether a
candidate preimage is valid for the implicit spending transaction remains
environment-provided. Lean code generation uses a fail-fast backend via
`implemented_by`, so execution aborts instead of accepting the previous
unconditional success behavior.

## Opaque Executable Defaults

There are no opaque executable defaults under `RunarVerification/`.
Executable crypto/auth placeholders must be explicit backend
assumptions with fail-fast codegen, not hidden `opaque := ...` bodies.

## Proven Or Empirical Anchors

* `goldenLoad`: parses every conformance ANF file and checks `WF.ANF`.
  Currently 49/50 — the 50th, `conformance/tests/asm-raw-script`, is an
  unrelated concurrent fixture added outside `runar-verification/` that
  uses a `raw_script` ANF kind the Lean loader does not yet recognize.
  The Lean proof gate (`scripts/lean-verify.sh` +
  `scripts/check-tcb-drift.sh`) is unaffected.
* `roundtrip`: round-trips every ANF file through the Lean JSON model.
  Same 49/50 caveat as `goldenLoad` for the same reason.
* `pipelineGolden`: default gate currently reports 49/49 byte-exact
  (34 baseline + 15 stored crypto-pending constants); the
  `asm-raw-script` JSON-parse failure means that fixture is silently
  dropped from the discovery loop, so the gate's pass count is honest
  for the 49 fixtures the Lean ANF loader does recognise.
* Peephole proofs cover the proved rewrite substrate; remaining
  composition obligations must match the exact passes used by
  `Pipeline.peepholeProgram`.
* `Stack.Peephole.peepholePostFold_runOps_eq` proves the post-fold
  phase preserves `runOps` under `noIfOp`, and
  `Stack.Peephole.peepholeChainFold_runOps_eq` proves the chain-fold
  phase preserves `runOps` under `noIfOp` plus `wellTypedRun`.
  `Pipeline.peephole_post_chain_roll_runOps_eq` composes those facts
  with a caller-supplied first-pass proof and an explicit roll/pick-fold
  equality. `Stack.Peephole.peepholeRollPickFold_runOps_eq_of_noIfOp_flatNoop`
  proves the roll/pick fold is identity on the no-IF subset with none of
  the low-depth fold heads, and
  `Pipeline.peephole_post_chain_roll_runOps_eq_of_rollPick_noop` uses
  that theorem to discharge the final fold equality for that subset.
  `Stack.Peephole.peepholePassAll_runOps_eq_of_flat_sound` and
  `Pipeline.peephole_program_ops_runOps_eq_of_flat_first_pass_rollPick_noop`
  bridge no-IF `peepholePassAll` callers through a flat first-pass proof.
  `Stack.Peephole.peepholePostFold_preserves_noIfOp`,
  `Stack.Peephole.peepholeChainFold_preserves_noIfOp`, and
  `Stack.Peephole.peepholeRollPickFold_preserves_noIfOp` show the later
  peephole phases preserve the no-IF invariant. The fired low-depth
  roll/pick rewrites have local runtime-equality slices for their
  TS-shaped depth-push sources, plus a concrete counterexample showing
  why bare `.roll 1` is not runtime-equal under bytecode-style `ROLL`.
* `Pipeline.compileSafe` rejects sentinel `OP_RUNAR_*` opcodes and
  unknown emitter opcodes before byte emission.
* `Stack.Eval` uses concrete Script-number and bytewise semantics for
  `OP_BIN2NUM`, `OP_NUM2BIN`, `OP_SPLIT`, `OP_INVERT`, `OP_AND`,
  `OP_OR`, and `OP_XOR`, and named `OP_PICK` / `OP_ROLL` dispatch is
  concrete via the bytecode-style depth-pop helpers. Executable sample
  theorems pin representative success and error paths.
* `ANF.Eval` uses the same Script-number helper for source-level
  `bin2num`, `num2bin`, `int2str`, `pack`, and `unpack`, and concrete
  bytewise/slicing semantics for `&`, `|`, `^`, `~`, `substr`, `left`,
  `right`, `split`, `reverseBytes`, and `toByteString`. It also has
  concrete numeric-helper semantics for `abs`, `min`, `max`, and
  `within`.
* `TxContext` builds concrete BIP-143 preimages, models
  `OP_CODESEPARATOR` coverage with `afterCodeSeparator`, and carries
  executable sample theorems showing that the concrete ANF extractors
  recover the serialized fields.
* `Stack.Eval.runOpsPc` threads an executable instruction counter,
  records the last executed `OP_CODESEPARATOR`, and makes
  `pushCodesepIndex` push that index. `OP_CHECKMULTISIG` and
  `OP_CHECKMULTISIGVERIFY` parse full count-framed multisig stacks when
  present, falling back to the legacy single-payload adapter only when
  the top stack item is not a count.
* `Script.Emit.emitWithCodeSepPatches` and
  `Pipeline.compileSafeWithCodeSepPatches` compute constructor slot
  offsets and replace `pushCodesepIndex` with the script-number encoding
  of the unique latest emitted `OP_CODESEPARATOR` byte offset. IF
  branches and method-dispatch alternatives are analyzed as runtime
  alternatives, and ambiguous joins fail closed.
* `Stack.Agrees` bridges binding-list witnesses to `Lower.lower` method
  execution for unique public methods selected by method name, including
  the proved const-only and copied-reference fragments. It also has
  consume-mode witnesses for depth-0 through depth-2 `loadParam` and
  depth-0 through depth-2 copied `loadConst .refAlias`, plus Stage C
  operational witnesses for the common integer/arithmetic/comparison/
  logical/shift binOps at depth pairs `(1,0)`, `(0,1)`, `(>=2,0)`, and
  `(0,>=2)`. It also has bytewise INVERT at unary depths 0/1/>=2, byte
  equality/inequality, and bytewise AND/OR/XOR success paths at binary
  depth pairs `(1,0)`, `(0,1)`, `(>=2,0)`, and `(0,>=2)`,
  plus bounded builtin-call witnesses for `toByteString` byte inputs,
  `abs`, `len`, and `bin2num` at depths 0/1/>=2, `cat`, `num2bin`, and
  `min`/`max` at depth pairs `(1,0)`, `(0,1)`, `(>=2,0)`, and
  `(0,>=2)`, and `within` at depth tuple `(2,1,0)`. `split(data, index)`
  has exact lowered VM stack-shape theorems at depth pairs `(1,0)`,
  `(0,1)`, `(>=2,0)`, and `(0,>=2)` and retained-prefix agreement bridges; this
  remains proof infrastructure separate from `simpleStepRel` because
  `OP_SPLIT` leaves an unnamed prefix below the named suffix.
  Stage D post-processing preservation covers cleanup tails made only of
  `OP_NIP`, `OP_DROP`, and `OP_VERIFY`. The output-construction families
  have explicit conditional preservation wrappers, and `Stack.OutputTrace`
  supplies the event/trace bridge for output appends while preserving
  agreement, including wrapper-shape bridges for lowered `addOutput`,
  `addRawOutput`, and `addDataOutput`, plus named-trace composition for
  multiple output events. The remaining output obligation is deriving
  those events from actual lowered verification code.
  Deeper consume-mode reference loads now have the current lowerer-shape
  theorem and a depth >= 3 witness when callers supply the required
  bytecode-style depth push before `ROLL`, either in the producer shape
  or as the initial stack prefix for the current bare `[.roll d]` shape;
  the unresolved piece is the producer/evaluator shape mismatch for the
  current emitted sequence.
* `Script.Parse`, `Script.EmitCorrect`, and `Pipeline` connect
  emit/parse round-trip facts to `Stack.Eval.runOps` for the current
  `RunarEmittable` subset, recursive `RunarEmittableWithIf` lists, and
  a normalized push predicate that parses emitted bytes to
  `normalizeOps`. `Pipeline` connects those predicates to
  single-public-method `compileSafe` results. Exact push inversion is
  intentionally not claimed: Script encodings normalize bools, small
  byte payloads, and small ints, and pushes immediately before
  `OP_PICK`/`OP_ROLL` are reconstructed structurally. The small-int
  normalized push family for `-1` and `0..16` is proved, along with a
  concrete non-small `17` and `128` pushdata cases, the empty-byte
  payload case, and a concrete multi-byte `aa bb` payload.
* `tests/PipelineGolden.lean` now guards the full 49-fixture bucket
  inventory, default/full/regen fixture modes, stale stored constants,
  and sharded full-mode crypto pending checks. `scripts/differential.sh`
  and `scripts/full-verification.sh` refuse report/artifact paths inside
  tracked fixture/test trees. `scripts/differential.sh` can consume a BSV
  reference through `RUNAR_BSV_REFERENCE_CMD` or a prebuilt
  `RUNAR_BSV_REFERENCE_JSON`.
* `Pipeline.compileSafeWithCodeSepPatches_single_public_observational_correct`
  threads the slot-aware emitted bytes into the single-public-method
  observational statement. **M4:** the patched-byte soundness hypothesis
  is gone — the theorem now takes `Parse.AreRunarEmittableWithIf
  stackM.ops` directly as a structural precondition and proves the
  patched-emit round-trip internally via `patched_bytes_sound_with_if`,
  which composes
  `Script.Emit.emitOpsWithCodeSepPatches_no_patch_sites_bytes_eq_emitOps`,
  `Script.Emit.emitWithCodeSepPatches_single_public_bytes_eq_emit_with_if`,
  and `Script.EmitCorrect.opsHaveNoPatchSites_of_AreRunarEmittableWithIf`.
  The legacy companion
  `compileSafeWithCodeSepPatches_single_public_observational_correct_of_emitFast_bytes`
  remains as a backwards-compatible re-export with a now-redundant
  `hBytes` hypothesis.
* **M2 (lowering, structural-const fragment).**
  `Pipeline.lower_observational_correct` discharges `successAgrees`
  unconditionally between the ANF evaluator and `runMethod (Lower.lower
  p)` for the structural-const fragment. Both `.isSome` directions are
  proved outright:
  `Agrees.evalBindings_structuralConstBody_isSome` on the ANF side and
  `Agrees.runMethod_lower_public_unique_no_post_structuralConst_isSome`
  on the Stack-VM side, with supporting lemmas
  `Agrees.evalValue_structuralConstValue_ok`,
  `Agrees.runOps_lowerValue_structuralConstValue_ok`, and
  `Agrees.runOps_lowerBindings_structuralConstBody_isSome`. The old
  `lower_observational_correct_skeleton` is kept only for bodies outside
  the discharged fragment.
* **M3 (peephole composition).**
  `Pipeline.peephole_observational_correct_modulo_runMethod_eq` proves
  the live `peepholeProgram` pipeline (`peepholeRollPickFold ∘
  peepholeChainFold ∘ peepholePostFold ∘ peepholePassAll`) is
  `runMethod`-preserving from genuine structural preconditions
  (`Peephole.noIfOp`, `Peephole.peepholePassAllFlat_preconditions`,
  `Peephole.wellTypedRun`, `Peephole.rollPickDepthOK`); the caller no
  longer supplies "this fold preserves runOps" hypotheses. Supporting
  composition: `Pipeline.peephole_post_chain_runOps_eq`,
  `Pipeline.peephole_post_chain_roll_runOps_eq` and `_of_rollPick_noop`
  variant, `Pipeline.peepholeMethodOps_runOps_eq` and
  `_of_rollPick_noop` variant,
  `Pipeline.peephole_program_ops_runOps_eq_of_flat_first_pass_rollPick_noop`,
  and `Stack.Peephole.peepholePassAllFlat_runOps_eq` /
  `Stack.Peephole.peepholePassAllFlat_preconditions`.
* **M5 (capstone).**
  `Pipeline.compileSafe_single_public_observational_correct_unconditional`
  composes M2 + M3 + M4 into the citable end-to-end theorem for
  single-public-method `compileSafe` on the structural-const fragment.
  All hypotheses are genuine domain or structural predicates; none
  restate the conclusion. Fragment and hypothesis details are in the
  "End-to-End Capstone (M5)" section below.

## End-to-End Capstone (M5)

`Pipeline.compileSafe_single_public_observational_correct_unconditional`
composes M2 + M3 + M4 into the citable end-to-end theorem for
single-public-method `compileSafe` over the **structural-const
fragment**. Its hypotheses are all genuine domain or structural
predicates — none restate the conclusion:

* `WF.ANF p` and `compileSafe p = .ok bytes` (handle into the deployed
  bytes).
* Single-public-method shape: `Emit.publicMethodsOf (peepholeProgram
  (Lower.lower p)) = [stackM]` and `(peepholeProgram (Lower.lower
  p)).bodyOf anfM.name = stackM.ops`, with `anfM ∈ p.methods`,
  `anfM.isPublic = true`, and public-name uniqueness.
* M2 fragment predicates: no `checkPreimage`, no `codePart`, no terminal
  `OP_VERIFY`, no `deserializeState`, and
  `Agrees.structuralConstBody anfM.body` — every binding is a literal
  load (`.loadConst (.int _)` / `.loadConst (.bool _)` / `.loadConst
  (.bytes _)`).
* M3 structural preconditions on the lowered body: `Peephole.noIfOp`,
  `Peephole.peepholePassAllFlat_preconditions`,
  `Peephole.wellTypedRun` on the post-fold list, and
  `Peephole.rollPickDepthOK` on the chain-fold list.
* M4 round-trip precondition: `Parse.AreRunarEmittable stackM.ops`.

The fragment boundary is the literal-load substrate. Bodies that use
`binOp`, `unaryOp`, `assert`, reference loads (`loadParam` / `loadProp`
/ `refAlias`), `methodCall`, crypto intrinsics, `ifVal`, `loop`, or
output construction are **outside** the discharged fragment. The
deprecated skeleton aliases `compile_observational_correct_skeleton` and
`compile_observational_correct_bytes_skeleton` remain as
`@[deprecated compileSafe_single_public_observational_correct_unconditional]`
re-exports for backwards compatibility.

## Not Yet Proven

These are active proof obligations, not historical notes:

* Widening `lower_observational_correct` past the structural-const
  fragment. The copied-reference fragment (`Agrees.structuralCopyBody`)
  is supported by Stage C `agreesTagged` / `ChainRel` witnesses and
  `stageD_public_unique_no_post_structuralCopy_bridge`, but those have
  not yet been lifted into an unconditional `successAgrees` form on the
  ANF evaluator's failure paths the way M2 does for literal loads.
  Bodies using `binOp`, `unaryOp`, `assert`, `methodCall`, crypto,
  `ifVal`, `loop`, or output construction remain outside the discharged
  fragment; the `_skeleton` form is retained for those as a documented
  hypothesis.
* Full lowering simulation from all supported ANF constructors and
  consume-depth combinations to Stack VM execution. Remaining work
  includes deriving output events for output-construction call families,
  builtin-call depth tuples beyond the landed unary/binary edge cases,
  method post-processing, and the stronger producer-shape semantics
  needed because `.roll d` is bytecode-style in `Stack.Eval`.
* Flat first-pass peephole rule preconditions and roll/pick-fold
  obligations outside the current no-op subset for the full
  `Pipeline.peepholeProgram` chain.
* Broader emit/parse/runOps coverage beyond the current recursive
  `RunarEmittableWithIf` and normalized-push predicates, especially
  additional concrete `NormalizedPushEmittable` proof families and
  push-before-`OP_PICK`/`OP_ROLL` cases if callers need them.
* Live or stored-Lean-constant verification for the 15 crypto-heavy
  fixtures currently outside the default byte-exact count. Regen mode
  now emits per-fixture hex files and a generated Lean match-table
  snippet, but the constants themselves are intentionally unpopulated
  until a full regen run supplies Lean-produced hex.

## Policy

New assumptions must be added as named axioms with a short soundness
story in this file and a matching `check-tcb-drift.sh` update. New
opaque executable defaults are not allowed unless they are explicitly
accepted as part of this manifest and counted by the drift gate.
