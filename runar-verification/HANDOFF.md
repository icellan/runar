# Runar Verification Handoff

This is the active implementation roadmap. Historical exploration,
analysis, and audit Markdown files were removed after their live
findings were folded into `README.md`, `TRUST_MANIFEST.md`, and this
handoff.

The unimported `RunarVerification/Pipeline/SimpleSoundness.lean` proof
sketch was also removed. It no longer built as a standalone module; the
remaining active proof obligations live in `Pipeline.lean`,
`Stack/Agrees.lean`, and `TRUST_MANIFEST.md`.

## Current Baseline

* Lean toolchain: `leanprover/lean4:v4.29.1`.
* No `sorry`, no `admit`, and no `partial def` under
  `RunarVerification/`.
* `scripts/lean-verify.sh` builds every tracked Lean module, not only
  the default import closure. It is the local gate for keeping proof
  modules from rotting outside the import graph.
* `goldenLoad` and `roundtrip` cover 49/49 conformance fixtures.
* Default `pipelineGolden` is honest: 34/49 live byte-exact fixtures.
* The remaining 15 fixtures are the crypto-heavy pending-assumption
  bucket. They need full-mode live verification or stored Lean-produced
  constants before they can count in default CI.
* `Pipeline.compileSafe` is the proof-facing compiler entrypoint and
  rejects sentinel or unknown opcodes before byte emission.
* `Stack.Eval.runOpcode` now executes named `OP_PICK` and `OP_ROLL`
  through the same bytecode-style depth-pop helpers used by structured
  `.pick` / `.roll`, so raw opcode lowering paths no longer fall through
  to `unsupported`. It also has concrete Script-number and bytewise
  semantics for `OP_BIN2NUM`, `OP_NUM2BIN`, `OP_SPLIT`, `OP_INVERT`,
  `OP_AND`, `OP_OR`, and `OP_XOR`, with executable sample coverage for
  representative success/error paths.
* `Stack.Agrees` now has method-level bridge lemmas from binding-list
  execution witnesses to any unique public method selected by public
  method name, not only the public head method, for the
  no-implicit/no-postprocessing fragments proved so far.
* `lowerBindingsP = lowerBindings` is proved for the const-only
  fragment and for copied reference loads (`loadParam`, stack-backed
  `loadProp`, and copied `loadConst .refAlias`) under explicit copy-mode
  hypotheses.
* `Stack.Agrees` has operational consume-mode witnesses for depth-0
  through depth-2 `loadParam` and depth-0 through depth-2 copied
  `loadConst .refAlias`; deeper consume cases remain open.
* `Stack.Peephole` proves `peepholePostFold_runOps_eq` and
  `peepholeChainFold_runOps_eq`, and `Pipeline` composes those with a
  caller-supplied pass proof plus an explicit roll/pick-fold equality.
  It also proves the roll/pick fold is identity, and therefore
  runOps-preserving, for no-IF lists that contain none of the
  low-depth fold heads; `Pipeline` has a companion composition theorem
  that uses this no-op subset proof directly.
* `Script.Parse` / `Script.EmitCorrect` provide parser-backed
  emit/runOps lemmas for the current `RunarEmittable` subset and for
  the integrated `RunarEmittableWithIf` subset: flat emitted ops mixed
  with single-level structural IF frames whose branch bodies are already
  `AreRunarEmittable`. `Pipeline` connects both predicates to
  single-public-method `compileSafe` results. `Script.Parse` also has
  terminal singleton push round-trip lemmas for the small-int fast path
  covering -1 and 0 through 16, plus explicit terminal bool-push parser
  facts documenting the unavoidable `false -> bigint 0` and
  `true -> bigint 1` byte collisions through the fast emitter and
  `compileSafe`; list-level terminal byte-push facts cover the empty,
  `0x81`, and one non-small literal-byte cases. A concrete nested
  no-else IF smoke case is also proved through `parseScript`,
  `emitOpsFast`, and the single-public `compileSafe` parser bridge while
  the general recursive IF predicate remains open.
* `Stack.Agrees` now exposes Stage C `simpleStepRel` operational
  witnesses for common integer `binOp`s in depth pair `(left depth 1,
  right depth 0)`: ADD/SUB/MUL/DIV/MOD, comparisons, NUMEQUAL/
  NUMNOTEQUAL, BOOLAND/BOOLOR, and LSHIFT/RSHIFT. DIV/MOD carry the
  expected nonzero-divisor precondition. The same depth pair is also
  covered for byte equality/inequality and bytewise AND/OR/XOR success
  paths; bytewise INVERT is covered at unary depths 0/1/>=2. Bounded
  builtin-call witnesses cover byte-valued `toByteString` at depths
  0/1/>=2, `abs`, `len`, and `bin2num` at depth 0, `cat`, `num2bin`,
  and `min`/`max` at depth pair `(1,0)`, and `within` at depth tuple
  `(2,1,0)`. `Stack.Sim` also has byte-exact lowering identities for
  those builtin calls and the common binOp opcode table.
* Fixture gates now include a complete 49-fixture bucket inventory,
  default/full/regen mode checks, stored-constant drift reporting,
  sharded full-mode guards for the 15 crypto pending fixtures, and
  differential report path guards that refuse tracked fixture/test
  outputs.

## Finish Order

1. **Proof-facing execution model**
   * Keep the hash and authentication backends explicit and fail-fast;
     no opaque executable defaults remain. `checkPreimage` is now also
     routed through an explicit fail-fast backend instead of an
     unconditional evaluator branch.
   * Stack VM Script-number and bytewise semantics are concrete for
     `OP_BIN2NUM`, `OP_NUM2BIN`, `OP_SPLIT`, `OP_INVERT`, `OP_AND`,
     `OP_OR`, and `OP_XOR`, and named `OP_PICK` / `OP_ROLL` dispatch is
     wired to the bytecode-style stack helpers.
   * ANF evaluation now reuses the same Script-number conversion helper
     for `bin2num`, `num2bin`, `int2str`, `pack`, and `unpack`, and has
     concrete bytewise/slicing semantics for `&`, `|`, `^`, `~`,
     `substr`, `left`, `right`, `split`, `reverseBytes`,
     `toByteString`, and concrete numeric helper semantics for `abs`,
     `min`, `max`, and `within`.
   * Tx context and BIP-143 preimage construction are concrete; the old
     11 TxContext companion axioms have been removed, and
     `afterCodeSeparator` models the script suffix covered after
     `OP_CODESEPARATOR`.
   * Stack VM now has a PC-aware runner (`runOpsPc`) that records the
     last executed `OP_CODESEPARATOR` and makes `pushCodesepIndex`
     executable; legacy `runOps` remains stable for existing peephole
     proofs.
   * Slot-aware emit now has `Script.Emit.emitWithCodeSepPatches` and
     `Pipeline.compileSafeWithCodeSepPatches`, which keep constructor
     slot offsets and emit each `pushCodesepIndex` from the unique latest
     emitted `OP_CODESEPARATOR` byte offset. IF branches and multi-method
     dispatch alternatives start from the correct incoming separator
     state; ambiguous joins are rejected.
   * `OP_CHECKMULTISIG` / `OP_CHECKMULTISIGVERIFY` parse full
     count-framed multisig stacks when the top item is a count, with the
     old single-payload auth adapter kept only as a fallback for proved
     peephole abstractions.

2. **Lowering simulation**
   * Discharge `lower_observational_correct_skeleton` without a
     hypothesis that restates the ANF/Stack success relation.
   * Extend consume-mode liveness beyond the current depth-0 through
     depth-2 `loadParam` and depth-0 through depth-2 copied `refAlias`
     witnesses. Depths 3 and above need stronger producer-shape
     semantics because `.roll d` is bytecode-style in `Stack.Eval`,
     not a direct arbitrary-depth stack extraction primitive.
     Structural equality with `lowerBindings` is false by design once
     `ROLL`, `SWAP`, or `ROT` consumes tracked slots, so the remaining
     proofs should keep using execution witnesses instead of copy-mode
     equality lemmas.
   * Prove lowering simulation for the remaining supported ANF
     constructors and depth combinations. Landed coverage includes
     literal loads, copied reference loads, NEGATE/NOT/assert at
     depths 0/1/>=2, bytewise INVERT at depths 0/1/>=2, and the common
     integer/arithmetic/comparison/logical/shift binOps plus byte
     equality/inequality and bytewise AND/OR/XOR success paths for depth
     pair `(1,0)`;
     landed builtin-call coverage includes `toByteString` for byte inputs
     at depths 0/1/>=2, `abs`, `len`, and `bin2num` at depth 0, `cat`,
     `num2bin`, and `min`/`max` at depth pair `(1,0)`, and `within` at
     depth tuple `(2,1,0)`. Remaining work is broader binary depth pairs,
     output-construction call families such as `addOutput`, method
     post-processing, and consuming reference-load cases.
   * Thread the slot-aware emit result through the final deployed-byte
     theorem, using the checked branch-sensitive code-separator patching
     relation.
   * Keep unsupported constructs routed through `compileSafe` errors,
     never through emitted sentinel bytes.

3. **Peephole and emit composition**
   * Finish soundness for exactly the pass chain used by
     `Pipeline.peepholeProgram`: first-pass obligations, the exact
     roll/pick-fold equality outside the no-op subset, and the currently
     external preconditions for the rules that need stronger
     post-rewrite facts.
   * Extend the parser-backed emit/runOps theorem beyond the current
     `RunarEmittableWithIf` subset. List-level single-level IF
     integration is landed. Terminal bigint pushes, terminal bool
     collision facts, bounded terminal byte-push samples, and one
     concrete nested no-else IF smoke case are explicit, but the general
     nested IF predicate and nonterminal or general push cases remain
     active parser work.

4. **Fixture gates**
   * Populate `cryptoAxiomPendingExpected` only with Lean-produced hex
     from regen/full mode.
   * Keep default CI at 34/49 until those constants exist or full mode is
     fast enough to gate.
   * Wire the existing `scripts/full-verification.sh` hook into
     scheduled/manual CI when the project is ready to spend the runtime.

5. **Differential assurance**
   * Run the Lean parser/VM against an external BSV reference.
   * Keep differential reports as artifacts or temp files; the current
     scripts already guard against tracked fixture/test report paths.
   * Treat differential agreement as assurance alongside formal proofs,
     not as a substitute for theorem obligations.

## Acceptance Criteria

The implementation is finished when:

* the public theorem for `compileSafe` no longer relies on hypotheses
  that restate its conclusion;
* every remaining assumption is listed in `TRUST_MANIFEST.md` and counted
  by `check-tcb-drift.sh`;
* default CI, full/manual CI, and README status numbers agree exactly;
* no active code path silently emits empty bytes for unknown opcodes; and
* obsolete analysis documents and references to them are absent.
