# Runar Verification Handoff

This is the active implementation roadmap. Historical exploration,
analysis, and audit Markdown files were removed after their live
findings were folded into `README.md`, `TRUST_MANIFEST.md`, and this
handoff.

The unimported `RunarVerification/Pipeline/SimpleSoundness.lean` proof
sketch was also removed. It no longer built as a standalone module; the
remaining active proof obligations live in `Pipeline.lean`,
`Stack/Agrees.lean`, and `TRUST_MANIFEST.md`. The end-to-end capstone
for the structural-const fragment is
`Pipeline.compileSafe_single_public_observational_correct_unconditional`;
fragment-widening to `structuralCopyBody` and beyond is the next active
roadmap step.

## CI Integration (Path 3 — Differential Validation)

Path 3 of the roadmap treats cross-implementation byte-level agreement
as an empirical anchor for the codegen-soundness axioms (see
`TRUST_MANIFEST.md` ⇒ "Differential Assurance"). Two CI integration
points are now in place inside `runar-verification/`:

* **`scripts/run-pipeline-conformance.sh`** — CI-ready wrapper around
  the `pipelineConformance` Lean binary. Resolves
  `runar-verification/` from its own script location, raises the
  main-thread stack to `unlimited` (with a `65520 KiB` fallback), builds
  the binary on demand, and exits non-zero **only** for hard-failure
  buckets (`DEFERRED-parse-failure`, `DEFERRED-not-well-formed`). Soft
  buckets (`DEFERRED-compile-safe-error`, `DEFERRED-no-public-method`)
  are documented `compileSafe` rejections and do not gate the matrix.
  Wireable into CI today with no external dependencies.
* **`scripts/differential.sh`** — true byte-level diff against an
  external Bitcoin Script reference. Wireable into CI once a BSV
  reference producer is available, via either `--reference bsv-command`
  (sets `RUNAR_BSV_REFERENCE_CMD`) or `--reference bsv-json` (sets
  `RUNAR_BSV_REFERENCE_JSON`). The remaining action item is a
  one-time external integration step — standing up the BSV reference
  producer and feeding its JSON into the wrapper — **not** a
  verification-side proof obligation.

## Current Baseline

* Lean toolchain: `leanprover/lean4:v4.29.1`.
* No `sorry`, no `admit`, and no `partial def` under
  `RunarVerification/`.
* `scripts/lean-verify.sh` builds every tracked Lean module, not only
  the default import closure. It is the local gate for keeping proof
  modules from rotting outside the import graph.
* **M1–M5 done.**
  `Pipeline.compileSafe_single_public_observational_correct_unconditional`
  (M5) — end-to-end capstone for the structural-const fragment.
  Genuine domain/structural hypotheses only; no restatement of the
  conclusion.
* **A1 done.**
  `Pipeline.lower_observational_correct_copy` and
  `Agrees.runMethod_lower_public_unique_no_post_structuralCopy_isSome`
  — unconditional discharge extended to copied-reference loads
  (`structuralCopyBody`: `loadParam`, stack-backed `loadProp`, copied
  `loadConst .refAlias`).
* **A2 done.**
  `Agrees.runMethod_lower_public_unique_no_post_structuralConsume_isSome`
  — Stack-VM `.isSome` for consume-mode reference loads.
  `Agrees.runMethod_lower_public_unique_no_post_structuralRef_isSome`
  — Stack-VM `.isSome` for the union predicate `structuralRefBody`
  (copy ∨ consume).
* **A15 done.**
  `Pipeline.compileSafe_single_public_observational_correct_unconditional_ref`
  — capstone widened from `structuralConstBody` to `structuralRefBody`.
  Current outer capstone. No real conformance fixture satisfies this
  predicate today (every fixture body has binOp / call / assert etc.).
* **A3–A8 substrate done; runtime-side wrappers deferred.**
  `Stack/Agrees.lean` carries structural predicates,
  `evalBindings_*_isSome` theorems, Boolean checkers, and Decidable
  instances for `structuralArithBody`, `structuralCallBody`,
  `structuralUpdatePropBody`, `structuralIfValBody`,
  `structuralLoopBody`, and `structuralMethodCallBody`.
  The runtime-side `runMethod_lower_public_unique_no_post_structural*_isSome`
  theorems for those six families are not proved — they require
  per-opcode Stage C composition with concrete value tracking.
* **Phase C (partial) done.**
  `Script.Parse.AreRunarEmittableWithIfAndPatches` predicate +
  Decidable + monotonicity from `AreRunarEmittableWithIf`.
  `Pipeline.compileSafe_bytes_eq_compileSafeWithCodeSepPatches_of_AreRunarEmittableWithIf`
  parity corollary. C2 (multi-method dispatch joins) not closed.
* **Phase E done.**
  `Stack/TxContext.lean`: `ValidTxContext` predicate + Decidable (E1);
  `extractVersion_buildPreimage_eq` + `decodeLE32_encodeUInt32LE`
  (partial E2 — fixed-length field extraction);
  `runOpcode_CHECKSIG_ValidTxContext` and
  `runOpcode_CHECKSIGVERIFY_ValidTxContext` (E3).
* **Phase F1/F2 done.**
  `tests/PipelineConformance.lean` harness — per-fixture decidable
  instantiation reporting VERIFIED / DEFERRED-<predicate> per fixture.
  Current measured surface: **0/56 VERIFIED** (all deferred on the
  structural-fragment frontier — honest measurement, not a bug).
* `goldenLoad` and `roundtrip` cover **56/56** conformance fixtures.
  The previously-blocked `conformance/tests/asm-raw-script/` fixture
  now parses and round-trips after the `raw_script` ANF kind landed in
  `ANF/Syntax.lean`, `ANF/Json.lean`, `ANF/Eval.lean`, `ANF/WF.lean`,
  and `ANF/Typed.lean`. Stack-IR codegen emits a sentinel
  `OP_RUNAR_RAWSCRIPT_UNSUPPORTED` opcode and the predicate
  `simpleValue` excludes `rawScript`; the dedicated `raw_bytes`
  StackOp constructor + per-arm `simpleStepRel` discharge is the
  remaining A14 follow-up (tracked separately).
* Default `pipelineGolden` reports 49/49 byte-exact (34 baseline + 15
  stored crypto-pending constants). The 7 fixtures whose hex is
  regenerated rather than compared remain in the `cryptoAxiomPending`
  bucket. The Lean proof gate (`scripts/lean-verify.sh` +
  `scripts/check-tcb-drift.sh`) is green; axioms = 124.
* **Phase B done (codegen-to-spec for crypto primitives, axiom-shim path).**
  13 primitive families now have spec links: SHA-256 / RIPEMD-160 /
  hash160 / hash256 (B1+B2, single-opcode runOps-to-spec, 0 new
  axioms), BLAKE3 (B3, +2 axioms in `Stack/Blake3.lean`), secp256k1 EC
  (B4, +10 axioms in `Crypto/Spec.lean` covering 10 emit functions),
  NIST P-256 / P-384 (B5, +12 group-law axioms in `Crypto/Spec.lean`
  §2.5 plus +14 codegen-to-spec axioms in `Stack/P256P384.lean`),
  BabyBear (B6, concrete spec defs for base field + degree-4
  extension plus +4 functional-correctness axioms in `Crypto/Spec.lean`),
  Merkle root (B7, concrete `Crypto.Spec.merkleRoot` +
  `merkleVerifyPath` defs + `runOps_merkleRootSha256Ops_zero_eq`
  proof at d = 0 in `Stack/Merkle.lean`, +0 axioms), WOTS+ (B8,
  concrete `Crypto.Spec.verifyWOTS` + +1 axiom in `Stack/Wots.lean`),
  SLH-DSA (B9, +6 axioms in `Stack/SlhDsa.lean` covering all 6
  FIPS 205 SHA-2 parameter sets), Rabin (B10, concrete
  `Crypto.Spec.verifyRabinSig_spec` + +1 axiom in `Stack/Rabin.lean`),
  compound builtins (B11 — `extractOutputHash`, `buildChangeOutput`,
  `computeStateOutput`, `super`) concrete with 2 prior axioms
  removed, and 11 math/byte builtins (`safediv`, `safemod`, `divmod`,
  `clamp`, `sign`, `mulDiv`, `percentOf`, `pow`, `sqrt`, `gcd`,
  `log2`) concrete in `ANF/Eval.lean`. Net TCB delta: 71 → 119 by
  end of Phase B integration.
* **Phase D done (substrate path).**
  `Pipeline.compileSafe_multi_public_observational_correct` drops
  `hPublicSingleton`. 5 Phase D codegen-soundness axioms in
  `Pipeline.lean`: `merkle_dispatch_selection_correct`,
  `auto_check_preimage_at_method_entry_correct`,
  `auto_state_output_at_method_exit_correct`,
  `terminal_assert_elision_residue_correct`, `nip_cleanup_residue_correct`.
  TCB delta: 119 → 124.
* The 15 crypto-heavy fixtures remain in the explicit
  `cryptoAxiomPending` bucket, but now count in default CI through
  stored Lean-produced constants generated by regen/full mode.
* `Pipeline.compileSafe` is the proof-facing compiler entrypoint and
  rejects sentinel or unknown opcodes before byte emission.
* `Stack.Eval.runOpcode` now executes named `OP_PICK` and `OP_ROLL`
  through the same bytecode-style depth-pop helpers used by structured
  `.pick` / `.roll`, so raw opcode lowering paths no longer fall through
  to `unsupported`. It also has concrete Script-number and bytewise
  semantics for `OP_BIN2NUM`, `OP_NUM2BIN`, `OP_SPLIT`, `OP_INVERT`,
  `OP_AND`, `OP_OR`, and `OP_XOR`, with executable sample coverage for
  representative success/error paths.
* `Stack.Agrees` has method-level bridge lemmas from binding-list
  execution witnesses to any unique public method selected by public
  method name, not only the public head method, for the
  no-implicit/no-postprocessing fragments proved so far.
* `lowerBindingsP = lowerBindings` is proved for the const-only
  fragment and for copied reference loads (`loadParam`, stack-backed
  `loadProp`, and copied `loadConst .refAlias`) under explicit copy-mode
  hypotheses.
* `Stack.Agrees` has operational consume-mode witnesses for depth-0
  through depth-2 `loadParam` and depth-0 through depth-2 copied
  `loadConst .refAlias`, plus depth >= 3 witness slices that make the
  required bytecode-style depth push explicit.
* `Stack.Peephole` proves `peepholePostFold_runOps_eq` and
  `peepholeChainFold_runOps_eq`, and `Pipeline` composes those with a
  caller-supplied pass proof plus an explicit roll/pick-fold equality.
  It also proves the roll/pick fold is identity, and therefore
  runOps-preserving, for no-IF lists that contain none of the
  low-depth fold heads; `Pipeline` has a companion composition theorem
  that uses this no-op subset proof directly. The no-IF first pass now
  bridges `peepholePassAll` to `peepholePassAllFlat`, with a Pipeline
  theorem that composes a caller-supplied flat first-pass proof through
  the post/chain/roll no-op subset.
* `Script.Parse` / `Script.EmitCorrect` provide parser-backed
  emit/runOps lemmas for the current `RunarEmittable` subset, recursive
  `RunarEmittableWithIf` lists with nested structural IF frames, and a
  normalized push predicate. `Pipeline` connects these predicates to
  single-public-method `compileSafe` results. Exact push inversion is not
  true in general: Script encodings normalize bools, small byte payloads,
  and small ints, and pushes immediately before `OP_PICK` / `OP_ROLL`
  are reconstructed structurally. The normalized theorem therefore
  parses emitted bytes to `normalizeOps` under a no-pick/roll tail
  precondition for pushed values.
* `Stack.Agrees` now exposes Stage C `simpleStepRel` operational
  witnesses for common integer `binOp`s in depth pair `(left depth 1,
  right depth 0)`: ADD/SUB/MUL/DIV/MOD, comparisons, NUMEQUAL/
  NUMNOTEQUAL, BOOLAND/BOOLOR, and LSHIFT/RSHIFT. DIV/MOD carry the
  expected nonzero-divisor precondition. The same integer success-path
  family now covers the alternate depth pair `(left depth 0, right depth
  1)`, `(left depth >= 2, right depth 0)`, and `(left depth 0, right
  depth >= 2)`. Byte equality/inequality and bytewise AND/OR/XOR success
  paths now cover `(1,0)`, `(0,1)`, `(>=2,0)`, and `(0,>=2)` depth pairs;
  bytewise INVERT is covered at unary depths 0/1/>=2. Bounded
  builtin-call witnesses cover byte-valued `toByteString`, `abs`, `len`,
  and `bin2num` at depths 0/1/>=2, `cat`, `num2bin`, and `min`/`max`
  at depth pairs `(1,0)`, `(0,1)`, `(>=2,0)`, and `(0,>=2)`, and
  `within` at depth tuple `(2,1,0)`. `split(data, index)` has exact
  lowered VM stack-shape coverage at depth pairs `(1,0)`, `(0,1)`,
  `(>=2,0)`, and `(0,>=2)`, plus retained-prefix agreement bridges proving that
  `OP_SPLIT` leaves suffix on top and prefix retained below it; this
  remains separate from `simpleStepRel` because that relation only names
  one pushed binding.
  Stage D post-processing preservation covers cleanup
  tails made only of `OP_NIP`, `OP_DROP`, and `OP_VERIFY`, with
  single-op wrappers retained for those three opcodes. `Stack.Sim` also has
  byte-exact lowering identities for those builtin calls and the common
  binOp opcode table. The `addOutput`, `addRawOutput`, and
  `addDataOutput` families have explicit conditional preservation
  wrappers, and `Stack.OutputTrace` now provides the proof-facing
  event/trace bridge that appends `StackState.outputs` while preserving
  agreement, including wrapper-shape bridges for the lowered `addOutput`,
  `addRawOutput`, and `addDataOutput` forms, plus named-trace
  composition for multiple output events. The remaining output work is
  deriving those output events from the actual lowered BIP-143
  verification sequence.
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
   * `Pipeline.compileSafeWithCodeSepPatches_single_public_observational_correct`
     threads the slot-aware emitted bytes through the single-public-method
     observational theorem. **M4 (2026-05-15):** the `hPatchedBytesSound`
     hypothesis is gone — the base theorem now takes
     `Parse.AreRunarEmittableWithIf stackM.ops` directly as a structural
     precondition and proves the patched-emit round-trip internally via
     `Emit.emitWithCodeSepPatches_single_public_bytes_eq_emitFast_with_if`
     (which composes
     `PatchProof.emitWithCodeSepPatches_single_public_no_patch_sites_bytes_eq_emit`
     with the `AreRunarEmittableWithIf → opsHaveNoPatchSites` bridge
     `opsHaveNoPatchSites_of_AreRunarEmittableWithIf`). The discharge
     covers every op shape in the recursive `RunarEmittableWithIf`
     subset, including nested `.ifOp` branches. The flat no-patch-site
     subset is now strictly subsumed. The legacy companion
     `compileSafeWithCodeSepPatches_single_public_observational_correct_of_emitFast_bytes`
     remains as a backwards-compatible re-export — its `hBytes`
     hypothesis is now redundant and unused.
   * `OP_CHECKMULTISIG` / `OP_CHECKMULTISIGVERIFY` parse full
     count-framed multisig stacks when the top item is a count, with the
     old single-payload auth adapter kept only as a fallback for proved
     peephole abstractions.

2. **Lowering simulation**
   * Discharge `lower_observational_correct_skeleton` without a
     hypothesis that restates the ANF/Stack success relation.
     **Done for the structural-const fragment (M2, 2026-05-15):**
     `Pipeline.lower_observational_correct` discharges `successAgrees`
     unconditionally for bodies where every binding is a literal load,
     gated by `Agrees.structuralConstBody m.body` plus the
     no-implicit / no-post side conditions and public-name uniqueness.
     Both `.isSome` directions are proved outright:
     `Agrees.evalBindings_structuralConstBody_isSome` (ANF side) and
     `Agrees.runMethod_lower_public_unique_no_post_structuralConst_isSome`
     (Stack-VM side, via the all-`.push` op-list shape).
     **Next: widen the fragment** to `structuralCopyBody`
     (copied-reference loads), which requires lifting the existing
     `Stack.Agrees` Stage C `agreesTagged` / `ChainRel` witnesses and
     `stageD_public_unique_no_post_structuralCopy_bridge` to an
     equally unconditional `successAgrees` shape; after that, bodies
     using `binOp` / `unaryOp` / `assert` / `methodCall` / crypto /
     `ifVal` / `loop` / output construction. The `_skeleton` form is
     kept for everything still outside the discharged fragment.
   * Extend consume-mode liveness beyond the current depth-0 through
     depth-2 `loadParam` and depth-0 through depth-2 copied `refAlias`
     witnesses. Depths 3 and above need stronger producer-shape
     semantics because `.roll d` is bytecode-style in `Stack.Eval`,
     not a direct arbitrary-depth stack extraction primitive.
     Structural equality with `lowerBindings` is false by design once
     `ROLL`, `SWAP`, or `ROT` consumes tracked slots, so the remaining
     proofs should keep using execution witnesses instead of copy-mode
     equality lemmas.
     A depth >= 3 slice is now explicit: `Stack.Agrees` proves the
     current lowerer shape and also proves a witness when callers supply
     the bytecode-style depth push before `ROLL`, either as part of the
     producer shape or as an initial stack prefix before the current bare
     `[.roll d]` shape. Fully discharging the current lowerer still needs
     that producer/evaluator shape mismatch resolved or threaded through
     callers.
   * Prove lowering simulation for the remaining supported ANF
     constructors and depth combinations. Landed coverage includes
     literal loads, copied reference loads, NEGATE/NOT/assert at
     depths 0/1/>=2, bytewise INVERT at depths 0/1/>=2, the common
     integer/arithmetic/comparison/logical/shift binOps for depth pairs
     `(1,0)`, `(0,1)`, `(>=2,0)`, and `(0,>=2)`, and byte
     equality/inequality plus bytewise AND/OR/XOR success paths for
     depth pairs `(1,0)`, `(0,1)`, `(>=2,0)`, and `(0,>=2)`;
     landed builtin-call coverage includes `toByteString` for byte inputs
     plus `abs`, `len`, and `bin2num` at depths 0/1/>=2, `cat`,
     `num2bin`, and `min`/`max` at depth pairs `(1,0)`, `(0,1)`,
     `(>=2,0)`, and `(0,>=2)`, and `within` at depth tuple `(2,1,0)`.
     `split(data, index)` now has exact lowered VM stack-shape coverage
     at depth pairs `(1,0)`, `(0,1)`, `(>=2,0)`, and `(0,>=2)` and
     retained-prefix agreement bridges for the unnamed prefix retained by `OP_SPLIT`. Stage D post-processing
     preservation now covers cleanup tails made only of `OP_NIP`,
     `OP_DROP`, and `OP_VERIFY`. Remaining work is the output-record
     derivation for `addOutput` / `addRawOutput` / `addDataOutput`,
     consuming reference-load cases, and builtin-call depth tuples
     beyond the landed unary and binary edge cases. `Stack.OutputTrace`
     is the landed model-extension substrate for output appends and now
     pins the three lowered output-wrapper stack-map shapes; the missing
     piece is constructing its events from lowered verification code.
   * ~~Discharge the patched-byte soundness hypothesis used by
     `compileSafeWithCodeSepPatches_single_public_observational_correct`~~
     **Done (M4, 2026-05-15)** — the patched-emit round-trip is now
     proved unconditionally for the full `AreRunarEmittableWithIf` op
     subset (including nested IFs), and the base theorem no longer takes
     a patched-bytes-sound hypothesis.
   * Keep unsupported constructs routed through `compileSafe` errors,
     never through emitted sentinel bytes.

3. **Peephole and emit composition**
   * **Done (M3, 2026-05-15):**
     `Pipeline.peephole_observational_correct_modulo_runMethod_eq`
     proves the live `peepholeProgram` pipeline is
     `runMethod`-preserving from genuine structural preconditions
     (`Peephole.noIfOp`, `Peephole.peepholePassAllFlat_preconditions`,
     `Peephole.wellTypedRun`, `Peephole.rollPickDepthOK`); callers no
     longer supply any "this fold preserves runOps" hypothesis. M1's
     no-pop `.roll`/`.pick` evaluator (`Stack.Eval.runOps`) lets the
     producer/evaluator agree without the old TS-shaped depth-push
     workaround, so `Pipeline.peephole_post_chain_roll_runOps_eq` is
     direct rather than threaded through a counterexample slice. The
     four supporting composition theorems
     (`peephole_post_chain_runOps_eq`,
     `peephole_post_chain_roll_runOps_eq` and `_of_rollPick_noop`,
     `peepholeMethodOps_runOps_eq` and `_of_rollPick_noop`,
     `peephole_program_ops_runOps_eq_of_flat_first_pass_rollPick_noop`)
     stay in place for callers that already use them.
   * Broaden parser-backed emit/runOps coverage beyond the recursive
     `RunarEmittableWithIf` and normalized-push predicates where needed.
     Exact push round-tripping is intentionally not a goal because the
     parser normalizes several encodings; add more
     `NormalizedPushEmittable` proof families or push-before-pick/roll
     cases only when callers require them. The small-int normalized push
     family for `-1` and `0..16` is landed, along with a concrete
     non-small `17` and `128` pushdata normalization cases, the
     empty-byte payload case, and a concrete multi-byte `aa bb` payload.

4. **Fixture gates**
   * `cryptoAxiomPendingExpected` is populated only with Lean-produced
     hex from regen/full mode. Regen mode writes per-fixture hex files
     and a ready-to-review `cryptoAxiomPendingExpected.generated.lean`
     snippet under `RUNAR_VERIFICATION_REGEN_DIR` or
     `/tmp/runar-verification-regen`.
   * Default CI gates 49/49 byte-exact fixtures; full/sharded mode
     remains the live regeneration check for the 15 crypto-heavy
     constants.
   * The unrelated `conformance/tests/asm-raw-script` fixture
     introduces a new `raw_script` ANF kind that the Lean loader does
     not yet recognise. `pipelineGolden` silently drops it from its
     discovery loop and reports 49/49 honestly; `goldenLoad` and
     `roundtrip` surface it as 1 parse failure on the 50th fixture.
     Adding `raw_script` to `RunarVerification/ANF/IR.lean` /
     `RunarVerification/ANF/Eval.lean` (and the loader's known-kinds
     set) is the next fixture-side action once the other agent's `asm`
     intrinsic work lands on main. This is not a verification-side
     blocker.
   * Wire the existing `scripts/full-verification.sh` hook into
     scheduled/manual CI when the project is ready to spend the runtime.

5. **Differential assurance**
   * Run the Lean parser/VM against an external BSV reference.
     `scripts/differential.sh` now has `--reference bsv-command` via
     `RUNAR_BSV_REFERENCE_CMD` and `--reference bsv-json` via
     `RUNAR_BSV_REFERENCE_JSON`; the remaining work is wiring a real BSV
     report producer into scheduled/manual CI.
   * Keep differential reports as artifacts or temp files; the current
     scripts already guard against tracked fixture/test report paths.
   * Treat differential agreement as assurance alongside formal proofs,
     not as a substitute for theorem obligations.

## Acceptance Criteria

The structural-const, ref-loads, and multi-method-dispatch fragment
milestones are **met**:

* Three public end-to-end theorems exist:
  `compileSafe_single_public_observational_correct_unconditional` (M5,
  `structuralConstBody`),
  `compileSafe_single_public_observational_correct_unconditional_ref`
  (A15, `structuralRefBody`), and
  `compileSafe_multi_public_observational_correct` (Phase D,
  multi-method dispatch). None relies on hypotheses that restate the
  conclusion.
* Every remaining assumption is listed in `TRUST_MANIFEST.md` and
  counted by `check-tcb-drift.sh` (**124 axioms**, 0 opaques, 0
  opaque stubs, 0 `partial def`s).
* No active code path silently emits empty bytes for unknown opcodes
  (rejected by `compileSafe` before emission).
* Conformance harness (`tests/PipelineConformance.lean`) runs all 56
  fixtures and reports honestly. Current result: 0/56 VERIFIED with
  a precise per-fixture deferral classification.
* `goldenLoad` / `roundtrip` are 56/56 (the `raw_script` ANF kind
  now parses and round-trips after A14 landed).
* 13 crypto primitive families have spec-link theorems (`Stack/HashOps.lean`,
  `Stack/Blake3.lean`, `Stack/Ec.lean`, `Stack/P256P384.lean`,
  `Stack/BabyBear.lean`, `Stack/Merkle.lean`, `Stack/Wots.lean`,
  `Stack/SlhDsa.lean`, `Stack/Rabin.lean`).
* Obsolete analysis documents and references to them remain absent.

The wider compiler-correctness program is **not yet** finished. The
active roadmap, in priority order:

1. **A3–A14 runtime-side discharge** (highest priority — this is the
   gate for 0/56 rising above zero). Each of the six deferred
   families (`structuralArithBody`, `structuralCallBody`,
   `structuralUpdatePropBody`, `structuralIfValBody`,
   `structuralLoopBody`, `structuralMethodCallBody`) needs a
   `runMethod_lower_public_unique_no_post_structural*_isSome` theorem.
   That requires per-opcode Stage C composition with concrete value
   tracking — the `agreesTagged`-based stage-C witness infrastructure
   extended to arith / call / update-prop / if-val / loop /
   method-call opcodes. Start with `structuralArithBody` (binOp /
   unaryOp / assert), as the depth-pair witnesses for common
   integer/arithmetic opcodes are already landed in `Stack/Agrees.lean`.
2. **Per-fixture instantiation of `compileSafe_multi_public_observational_correct`.**
   The Phase D capstone is stated; the harness in
   `tests/PipelineConformance.lean` needs to instantiate it against
   each of the 23 currently-`DEFERRED-not-single-public-method`
   fixtures, the 6 `DEFERRED-checkPreimage` fixtures, and the 26
   `DEFERRED-terminalAssert` fixtures. The Phase D axioms supply the
   semantic content; the harness work is mechanical decidable
   instantiation.
3. **Phase B follow-up — discharge the 48 codegen-to-spec axioms
   with direct proofs.** Most Phase B codegen axioms axiomatize the
   runOps→spec equivalence rather than reduce it opcode-by-opcode.
   Direct discharge is bounded by the existing 7-tier cross-compiler
   conformance suite but would shrink the TCB if individually proved.
4. **Phase C2 — multi-method dispatch joins.** Prove unambiguous-join
   `pushCodesepIndex` patch sites agree across the runtime-selected
   branch. Blocked on the byte-offset vs. op-index semantic gap.
5. **A14 follow-up — dedicated `raw_bytes` StackOp.** `Stack/Syntax.lean`
   does not yet model a dedicated `raw_bytes` StackOp; the Stack-IR
   for `rawScript` is currently the sentinel
   `OP_RUNAR_RAWSCRIPT_UNSUPPORTED`. Adding the dedicated constructor
   plus `runOps` / peephole / emit / simpleStepRel discharge would
   raise the pipelineConformance deferral set by 1.
6. **B1 follow-up — SHA-256 compress/finalize.** `sha256Compress`
   and `sha256Finalize` partial-state builtins need their Merkle–
   Damgård composition link (likely 1 axiom per FIPS 180-4 §6.2 plus
   per-emit-sequence `runOps_*_eq`).
7. **B7 inductive step.** The Merkle-root codegen-to-spec lemma is
   proved at `d = 0`; the inductive step needs the ~15-op `mLevel`
   stack-shape invariant threaded through.
8. **Differential assurance.** Wire a real BSV reference producer into
   `scripts/differential.sh` (`--reference bsv-command` /
   `--reference bsv-json` are already supported).

Default CI, full/manual CI, and the README status table continue to
agree exactly.
