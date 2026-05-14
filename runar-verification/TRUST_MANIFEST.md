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

* `goldenLoad`: all 49 conformance ANF files parse and satisfy `WF.ANF`.
* `roundtrip`: all 49 ANF files round-trip through the Lean JSON model.
* `pipelineGolden`: default gate checks 34 live byte-exact fixtures.
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
  logical/shift binOps, bytewise INVERT at unary depths 0/1/>=2, byte
  equality/inequality, and bytewise AND/OR/XOR success paths at binary
  depth pair `(1,0)`, plus bounded builtin-call witnesses for
  `toByteString` byte inputs, `abs`, `len`, `bin2num`, `cat`,
  `num2bin`, `min`, `max`, and `within`.
* `Script.Parse`, `Script.EmitCorrect`, and `Pipeline` connect
  emit/parse round-trip facts to `Stack.Eval.runOps` for the current
  `RunarEmittable` subset, plus `RunarEmittableWithIf` lists that mix
  flat emitted ops with single-level structural IF frames whose branch
  bodies are already `AreRunarEmittable`. `Pipeline` connects both
  predicates to single-public-method `compileSafe` results. General
  pushes remain outside the main predicate; standalone theorems cover
  terminal singleton pushes for the small-int fast path covering -1 and
  0 through 16, explicit terminal bool collisions, bounded terminal
  byte-push samples, and one concrete nested no-else IF parser smoke
  case.
* `tests/PipelineGolden.lean` now guards the full 49-fixture bucket
  inventory, default/full/regen fixture modes, stale stored constants,
  and sharded full-mode crypto pending checks. `scripts/differential.sh`
  and `scripts/full-verification.sh` refuse report/artifact paths inside
  tracked fixture/test trees.

## Not Yet Proven

These are active proof obligations, not historical notes:

* End-to-end `compileSafe` soundness from ANF evaluation to parsed Script
  execution for deployed bytes.
* Full discharge of `lower_observational_correct_skeleton`; the current
  theorem still requires the caller to supply the ANF/Stack success
  relation.
* Full lowering simulation from all supported ANF constructors and
  consume-depth combinations to Stack VM execution. Remaining work
  includes broader binary depth pairs, output-construction call families,
  method post-processing, deeper consume-mode reference loads, and the
  stronger producer-shape semantics needed because `.roll d` is
  bytecode-style in `Stack.Eval`.
* Exact first-pass and roll/pick-fold peephole obligations outside the
  current no-op subset for the full `Pipeline.peepholeProgram` chain.
* Emit/parse/runOps round-trip beyond the current `RunarEmittableWithIf`
  subset, including the general nested IF predicate and nonterminal or
  general push cases still outside `Parse.lean`'s main predicate.
* Threading the slot-aware emit result through the final deployed-byte
  theorem using the checked branch-sensitive code-separator patching
  relation.
* Live or stored-Lean-constant verification for the 15 crypto-heavy
  fixtures currently outside the default byte-exact count.

## Policy

New assumptions must be added as named axioms with a short soundness
story in this file and a matching `check-tcb-drift.sh` update. New
opaque executable defaults are not allowed unless they are explicitly
accepted as part of this manifest and counted by the drift gate.
