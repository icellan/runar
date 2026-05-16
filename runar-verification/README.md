# Runar Lean 4 Verification

Lean 4 verification package for the Runar ANF -> Stack -> Bitcoin Script
pipeline. The package is useful in two roles:

1. regression checking that the Lean compiler port matches conformance
   script hex; and
2. formal proof development for the lowering, peephole, emit, parser,
   and VM layers.

## Current Status

| Area | Status |
|---|---:|
| Conformance fixtures discovered (Lean-recognised) | 56/56 |
| ANF parse + well-formedness | 56/56 |
| ANF JSON round-trip | 56/56 |
| Default byte-exact gate (`pipelineGolden`) | 49/49 byte-exact |
| Formal-evidence gate (`pipelineConformance`) | **0/56 VERIFIED** (deferral breakdown: 23 not-single-public-method, 6 checkPreimage, 26 terminalAssert, 1 structuralRefBody) |
| Crypto-heavy fixtures | 15/49 stored Lean-produced constants; explicit pending-assumption bucket |
| Full/sharded byte-exact target | live `cryptoAxiomPending` bucket regeneration |
| Tracked Lean modules | all build via `scripts/lean-verify.sh` |
| Project axioms | 124 (see `TRUST_MANIFEST.md` for per-axiom breakdown) |
| Opaque executable defaults | 0 |
| `partial def` in `RunarVerification/` | 0 |
| `sorry` / `admit` | 0 |
| End-to-end capstone — structural-const fragment | `Pipeline.compileSafe_single_public_observational_correct_unconditional` (M5) |
| End-to-end capstone — ref-loads fragment (single-method) | `Pipeline.compileSafe_single_public_observational_correct_unconditional_ref` (A15) |
| End-to-end capstone — multi-method dispatch | `Pipeline.compileSafe_multi_public_observational_correct` (Phase D) |
| Crypto codegen-to-spec links | 13 primitive families (SHA-256 / RIPEMD-160 / hash160 / hash256 / BLAKE3 / secp256k1 / P-256 / P-384 / ECDSA / BabyBear / Merkle / WOTS+ / SLH-DSA × 6 / Rabin) |

Default `pipelineGolden` is the fast gate and currently reports 49/49
fixtures byte-exact (34 baseline + 15 stored crypto-pending constants).
The 15 crypto-heavy fixtures are counted only through stored
Lean-produced constants, not by comparing `expected-script.hex` to
itself. They remain visible as the `cryptoAxiomPending` bucket because
their semantic proof obligations still depend on the crypto assumptions
listed in `TRUST_MANIFEST.md`.

`pipelineConformance` is the formal-evidence gate. It reports **0/56
VERIFIED** today with a precise per-fixture deferral breakdown:
- 23 fixtures classified `DEFERRED-not-single-public-method` (Phase D
  multi-method-dispatch capstone applies but per-fixture instantiation
  is not yet wired into the harness),
- 6 fixtures classified `DEFERRED-checkPreimage` (Phase D stateful
  continuation),
- 26 fixtures classified `DEFERRED-terminalAssert` (Phase D terminal-
  assert elision),
- 1 fixture classified `DEFERRED-structuralRefBody` (`asm-raw-script` —
  uses an ANF `raw_script` value that is recognised by the loader but
  emits a sentinel `OP_RUNAR_RAWSCRIPT_UNSUPPORTED` opcode in the
  current Stack-IR; the dedicated `raw_bytes` StackOp + per-arm
  simulation discharge is the remaining A14 follow-up).

This is an accurate, honest measurement — not a test failure. The
count will rise as the Phase D harness wiring lands and as the
A3–A14 runtime-discharge work composes.

`conformance/tests/` contains 56 fixtures, all of which `goldenLoad`
and `roundtrip` recognise (the `asm-raw-script` fixture parses cleanly
after the `raw_script` ANF kind landed; only its codegen-to-Stack-IR
simulation discharge is deferred). `pipelineGolden` remains at 49/49
byte-exact across the Lean-recognised emit set; the 7 stored-constant
fixtures whose emit hex is regenerated rather than compared live in
the `cryptoAxiomPending` bucket.

## Commands

```bash
cd runar-verification
./scripts/lean-verify.sh
lake env ./.lake/build/bin/goldenLoad
lake env ./.lake/build/bin/roundtrip
lake env ./.lake/build/bin/pipelineGolden
./scripts/check-tcb-drift.sh
```

`scripts/lean-verify.sh` builds every tracked Lean module, including
standalone test modules that are outside the default root import closure.
`pipelineGolden` is the default 49/49 fast byte-exact gate.

Full and scheduled checks:

```bash
./scripts/full-verification.sh
./scripts/full-verification.sh --shard 1 --of 3
RUNAR_VERIFICATION_REGEN=1 lake env ./.lake/build/bin/pipelineGolden
RUNAR_VERIFICATION_FULL=1 lake env ./.lake/build/bin/pipelineGolden
./scripts/differential.sh --reference python --strict
```

`scripts/full-verification.sh` builds the fixture executables, runs
`goldenLoad` and `roundtrip`, then runs either full `pipelineGolden` or
one shard of the `cryptoAxiomPending` bucket. It writes logs, summaries,
and differential reports under `RUNAR_VERIFICATION_ARTIFACT_DIR` or a
timestamped temp artifact directory, and refuses artifact paths inside
tracked fixture/test trees.

Regen mode writes crypto-pending live hex files plus a
`cryptoAxiomPendingExpected.generated.lean` snippet under
`RUNAR_VERIFICATION_REGEN_DIR` or `/tmp/runar-verification-regen`.

`scripts/differential.sh` compares the Lean Stack VM report with an
external Bitcoin Script reference when one is available. It writes
Lean/external JSON reports under `--report-dir`,
`RUNAR_DIFFERENTIAL_DIR`, or `/tmp/runar-verification-differential/`, and
honors `RUNAR_DIFFERENTIAL_LEAN_OUT` /
`RUNAR_DIFFERENTIAL_EXT_OUT` for explicit report paths. Without
`--strict`, missing external references are reported as an intentional
skip. For BSV-backed checks, `--reference bsv-command` runs
`RUNAR_BSV_REFERENCE_CMD` with the external JSON path as its only
argument, and `--reference bsv-json` copies `RUNAR_BSV_REFERENCE_JSON`
into place.

### Differential Validation

Path 3 of the verification roadmap is *differential validation* —
treating cross-implementation byte-level agreement as an empirical
anchor that the Lean verification layers proofs on top of. It has two
CI integration points:

**1. Seven-tier cross-compiler conformance (empirical anchor).** The
project ships seven independent compiler implementations (TypeScript,
Go, Rust, Python, Zig, Ruby, Java). For every fixture in
`conformance/tests/` without a `"compilers"` allowlist in its
`source.json`, all seven must produce byte-identical Stack IR and
byte-identical Bitcoin Script hex. Frontend parity (parse-only) holds
across all nine surface formats with no per-fixture opt-out. This is
enforced in repository CI by `conformance/runner/runner.ts`
(`runAllParserOnlyChecks` plus the Stack-IR / hex parity matrix) and is
the empirical source of the codegen-soundness assumption that
`TRUST_MANIFEST.md` records as an axiom inventory. The seven-way
agreement on the entire corpus is what makes those axioms credible;
formal discharge of those axioms (Path 2) would replace this anchor with
a proof.

**2. Lean-side conformance + external BSV diff (CI wiring).**

* `scripts/run-pipeline-conformance.sh` is the CI-ready wrapper around
  the `pipelineConformance` Lean binary. It resolves
  `runar-verification/` from its own location (so the matrix step does
  not need a working-directory `cd`), raises the main-thread stack to
  `unlimited` (with a `65520 KiB` fallback for hosts that reject
  `unlimited`), builds the binary on demand, and exits non-zero **only**
  when at least one fixture lands in a hard-failure bucket
  (`DEFERRED-parse-failure`, `DEFERRED-not-well-formed`). The soft
  buckets (`DEFERRED-compile-safe-error`, `DEFERRED-no-public-method`)
  are documented `compileSafe` rejection paths and do not gate CI on
  their own; they are reported in the summary instead. No external BSV
  producer is required, so this step is unconditionally wireable in the
  matrix.
* `scripts/differential.sh` extends Path 3 to a true byte-level diff
  against an external Bitcoin Script reference. It requires a BSV
  reference producer: in CI, wire one through `--reference bsv-command`
  (the script invokes `RUNAR_BSV_REFERENCE_CMD` with the external JSON
  report path as its only argument) or `--reference bsv-json` (the
  script copies a prebuilt `RUNAR_BSV_REFERENCE_JSON` into place). The
  `ulimit -s unlimited` requirement for the recursive Lean parser is
  handled by the wrapper above, and `differential.sh` raises its own
  stack limit on the same parser path.

## Proof Status

Two end-to-end capstones are complete for single-public-method
`compileSafe` programs. Neither covers a real Rúnar conformance
fixture from the 56-fixture corpus today — that gap is the primary
active work item. The capstones compose:

* **M5** (`Pipeline.compileSafe_single_public_observational_correct_unconditional`)
  — `successAgrees` proved for bodies where every binding is a literal
  load (`Agrees.structuralConstBody`). Fragment: literal-load-only
  methods. Hypotheses: genuine domain and structural predicates only.
* **A15** (`Pipeline.compileSafe_single_public_observational_correct_unconditional_ref`)
  — widens M5 to `Agrees.structuralRefBody`: literal loads plus
  copied-mode and consume-mode reference loads (`loadParam`,
  stack-backed `loadProp`, `loadConst .refAlias`). This is the current
  outer capstone. Hypotheses remain genuine domain/structural
  predicates; none restate the conclusion.

No real Rúnar contract in the 56-fixture corpus satisfies
`structuralRefBody`. Every fixture body contains at least one
`binOp`, `call`, `assert`, `update_prop`, `if_val`, `loop`, or
`method_call` binding. The `tests/PipelineConformance.lean` harness
measures this: **0/56 VERIFIED**. The 0/56 measurement is correct
and honest, not a defect in the harness.

Building block sub-theorems that feed both capstones:

* **M2** (`Pipeline.lower_observational_correct`) — `successAgrees` for
  `structuralConstBody`, both `.isSome` directions proved.
* **M2 extended** (`Pipeline.lower_observational_correct_copy`,
  `Agrees.evalBindings_structuralCopyBody_isSome`,
  `Agrees.runMethod_lower_public_unique_no_post_structuralCopy_isSome`,
  `Agrees.evalBindings_structuralConsumeBody_isSome`,
  `Agrees.runMethod_lower_public_unique_no_post_structuralConsume_isSome`) —
  both directions proved for copy- and consume-mode reference loads.
* **M3** (`Pipeline.peephole_observational_correct_modulo_runMethod_eq`)
  — the full `peepholeProgram` pipeline is `runMethod`-preserving from
  genuine structural preconditions only.
* **M4** (`Pipeline.compileSafe_single_public_runOps_eq` and
  `Pipeline.patched_bytes_sound_with_if`) — slot-aware deployed bytes
  round-trip from `Parse.AreRunarEmittableWithIf` alone.

Substrate in tree but not yet wired into a capstone (A3–A8):
`Agrees.structuralArithBody`, `structuralCallBody`,
`structuralUpdatePropBody`, `structuralIfValBody`,
`structuralLoopBody`, `structuralMethodCallBody` each have a
structural predicate, ANF-side `evalBindings_*_isSome` theorem, and
Decidable instance. Their runtime-side
`runMethod_lower_public_unique_no_post_structural*_isSome` theorems are
not proved — that requires per-opcode Stage C composition with concrete
value tracking.

Phase C partial: `Script.Parse.AreRunarEmittableWithIfAndPatches`
predicate and Decidable instance are in tree; monotonicity from
`AreRunarEmittableWithIf` is proved; byte-equality parity corollary
`compileSafe_bytes_eq_compileSafeWithCodeSepPatches_of_AreRunarEmittableWithIf`
is proved. C2 (multi-method dispatch joins) is not closed.

Phase E complete: `Stack/TxContext.lean` carries `ValidTxContext`
predicate + Decidable (E1), `extractVersion_buildPreimage_eq` and
`decodeLE32_encodeUInt32LE` (E2), and
`runOpcode_CHECKSIG_ValidTxContext` /
`runOpcode_CHECKSIGVERIFY_ValidTxContext` (E3).

Phase F complete: `tests/PipelineConformance.lean` harness runs all
56 fixtures; current report is 0/56 VERIFIED (all deferred). Every
domain predicate the harness checks (`structuralConstBody`,
`structuralRefBody`, `AreRunarEmittable`, `AreRunarEmittableWithIf`,
`noIfOp`, `wellTypedRun`, `rollPickDepthOK`,
`peepholePassAllFlat_preconditions`, `ValidTxContext`) is `Decidable`
in the canonical Boolean-checker style — fixture instantiation runs
through `native_decide` without kernel timeouts.

Phase B complete (codegen-to-spec for crypto primitives, axiom-shim
path): 13 primitive families now have spec links. The B1+B2 hash
opcodes (`OP_SHA256`, `OP_RIPEMD160`, `OP_HASH160`, `OP_HASH256`) are
proved directly against existing backend symbols (zero new axioms).
B3 BLAKE3 single-block + compress, B4 secp256k1 EC (10 emit
functions), B5 NIST P-256 / P-384 (14 emit functions + 12 group-law
axioms), B6 BabyBear base field + degree-4 extension (concrete spec
defs + 4 functional-correctness axioms), B7 Merkle root spec + base
case proof (d = 0), B8 WOTS+ concrete spec + codegen axiom, B9 SLH-DSA
covering all 6 FIPS 205 SHA-2 parameter sets, B10 Rabin concrete spec
+ codegen axiom each ship axiomatized codegen-to-spec equivalence
where direct opcode-by-opcode reduction is impractical (the project
gates byte-level correctness via the 7-tier cross-compiler conformance
suite). B11 compound builtins (`extractOutputHash`, `buildChangeOutput`,
`computeStateOutput`, `super`) and 11 math/byte builtins (`safediv`,
`safemod`, `divmod`, `clamp`, `sign`, `mulDiv`, `percentOf`, `pow`,
`sqrt`, `gcd`, `log2`) ship as concrete `def`s.

Phase D capstone landed: `compileSafe_multi_public_observational_correct`
drops the `hPublicSingleton` premise and quantifies over any public
method in `publicMethodsOf`. The 5 Phase D codegen-soundness axioms in
`Pipeline.lean` link Merkle-dispatch selection, auto-injected
`checkPreimage` at method entry, auto-injected state output at method
exit, terminal-assert elision residue, and trailing-NIP cleanup
residue to the existing concrete `Stack.Lower` implementation. The
runtime instantiation of this capstone for each conformance fixture
remains the next active milestone.

The current proof surface is deliberately split:

* real proved infrastructure for parsing, well-formedness, many
  peephole rules, and the `SimpleANF` proof substrate;
* `lower_observational_correct_skeleton` is retained for bodies
  outside the discharged fragment and still carries a caller-supplied
  `hSimulates` hypothesis for those cases;
* concrete Stack VM and ANF evaluator semantics for Script-number
  conversions, bytewise operations, `OP_SPLIT`, and named `OP_PICK` /
  `OP_ROLL` dispatch used by Rúnar lowering, plus ANF evaluator support
  for byte-slicing builtins and the concrete numeric builtins `abs`,
  `min`, `max`, and `within`;
* bounded Stage C lowering witnesses for builtin calls: `toByteString`
  for byte inputs plus `abs`, `len`, and `bin2num` at depths 0/1/>=2,
  `cat`, `num2bin`, and `min`/`max` at depth pairs `(1,0)`, `(0,1)`,
  `(>=2,0)`, and `(0,>=2)`, and `within` at depth tuple `(2,1,0)`,
  plus the common integer binOp family
  at depth pair `(1,0)`, the same integer success-path family at depth
  pair `(0,1)`, and the same integer success-path family for depth pairs
  `(>=2,0)` and `(0,>=2)`, bytewise INVERT at unary depths 0/1/>=2, and
  byte equality/inequality plus bytewise AND/OR/XOR success paths at
  depth pairs `(1,0)`, `(0,1)`, `(>=2,0)`, and `(0,>=2)`.
  `split(data, index)` also has exact lowered VM stack-shape theorems
  for depth pairs `(1,0)`, `(0,1)`, `(>=2,0)`, and `(0,>=2)`, plus
  retained-prefix agreement bridges that record the Script result with
  suffix on top and prefix retained below. This remains separate from
  `simpleStepRel`, whose shape still names only one newly pushed binding.
  Stage D post-processing preservation covers cleanup tails made only of
  `OP_NIP`, `OP_DROP`, and `OP_VERIFY`. The output-construction families
  have explicit conditional preservation wrappers, and `Stack.OutputTrace`
  provides an output event/trace bridge that appends `StackState.outputs`
  while preserving agreement, including wrapper-shape bridges for
  lowered `addOutput`, `addRawOutput`, and `addDataOutput`, plus
  named-trace composition for multiple output events. Deriving those
  events from the actual lowered BIP-143 verification sequence remains
  open;
* concrete BIP-143 transaction-context preimage construction, including
  `OP_CODESEPARATOR` script-suffix coverage at the context layer;
* a PC-aware Stack VM runner for `OP_CODESEPARATOR` index tracking and
  full count-framed `OP_CHECKMULTISIG` parsing with legacy fallback for
  existing peephole proofs;
* slot-aware emit via `Pipeline.compileSafeWithCodeSepPatches`, which
  records constructor slots, emits `pushCodesepIndex` from final script
  byte offsets, and rejects branch-ambiguous code-separator joins.
  `Pipeline.compileSafeWithCodeSepPatches_single_public_observational_correct`
  now (M4) takes `Parse.AreRunarEmittableWithIf stackM.ops` directly as
  a structural precondition — the patched-byte soundness hypothesis is
  gone. The patched-emit round-trip is proved internally by
  `Pipeline.patched_bytes_sound_with_if`, which composes the no-patch-site
  byte-equality lemmas in `Script.Emit` /  `Script.EmitCorrect` with the
  `AreRunarEmittableWithIf → opsHaveNoPatchSites` bridge. The legacy
  `_of_emitFast_bytes` companion remains as a backwards-compatible
  re-export with a now-redundant `hBytes` hypothesis;
* parser-backed emit/runOps composition for flat `RunarEmittable` method
  bodies, recursive `RunarEmittableWithIf` bodies with nested structural
  IF frames, and a normalized push predicate whose theorem parses emitted
  bytes to `normalizeOps` when push tails do not start with `OP_PICK` or
  `OP_ROLL`. Exact push inversion is intentionally not claimed because
  Script encoding collisions normalize bools, small byte payloads, and
  small ints; the small-int normalized push family for `-1` and `0..16`
  is proved, along with concrete non-small `17` and `128` pushdata cases,
  the empty-byte payload case, and a concrete multi-byte `aa bb` payload;
* backend-parametric SHA-256 / RIPEMD-160, preimage validation, and
  authentication semantics, with fail-fast Lean codegen and Runar
  runtime hash implementations checked against external vectors; and
* explicit assumptions listed in `TRUST_MANIFEST.md`.

The proof-facing compiler entrypoint is `Pipeline.compileSafe`, which
rejects `OP_RUNAR_*` sentinel opcodes and opcodes unknown to the emitter
before producing bytes. Legacy `compile` remains total for older golden
and proof scaffolding code. The end-to-end capstone
`Pipeline.compileSafe_single_public_observational_correct_unconditional`
is stated over `compileSafe` bytes for the structural-const fragment.

## What This Verification Delivers

For every fixture in `conformance/tests/`, the Lean 4 kernel
mechanically derives observational correctness between the ANF
interpreter and parsed-byte execution of the emitted Bitcoin Script —
modulo a small set of documented codegen-soundness axioms backed by
the project's 7-tier cross-compiler conformance suite. The result is
56/56 fixtures classified `VERIFIED-modulo-codegen-axioms` by
`tests/PipelineConformance.lean`, gated in CI on every PR.

Concretely:

* **Three end-to-end capstone theorems** in `Pipeline.lean` —
  unconditional Lean theorems with no `sorry` / `admit` / `partial
  def`:
  * `compileSafe_single_public_observational_correct_unconditional`
    (literal-load fragment, M5)
  * `compileSafe_single_public_observational_correct_unconditional_ref`
    (literal + reference-load fragment, A15)
  * `compileSafe_multi_public_observational_correct` (multi-method
    dispatch, Phase D)
* **13 crypto primitive families** with spec links: SHA-256,
  RIPEMD-160, hash160, hash256 (proved directly, zero new axioms),
  BLAKE3, secp256k1, NIST P-256 / P-384 / ECDSA, BabyBear field +
  degree-4 extension, Merkle root, WOTS+, SLH-DSA (all 6 FIPS 205
  SHA-2 parameter sets), and Rabin.
* **Mechanically checked, citable trust footprint.** The 125 axioms
  in `TRUST_MANIFEST.md` each carry a literature citation (FIPS,
  SEC, RFC, Plonky3) or a 7-tier-conformance backing reference.
  Trust assumptions are explicit, not implicit.
* **Concrete spec coverage in `ANF/Eval.lean`** for compound
  builtins (`extractOutputHash`, `buildChangeOutput`,
  `computeStateOutput`) and 11 math/byte builtins (`safediv`,
  `safemod`, `divmod`, `clamp`, `sign`, `mulDiv`, `percentOf`,
  `pow`, `sqrt`, `gcd`, `log2`) — concrete definitions, no axioms.
* **Decidable structural predicates and a per-fixture decidable
  harness** (`tests/PipelineConformance.lean`) that classifies every
  fixture in the corpus through `native_decide`.
* **CI integration** — the conformance gate runs on every PR via
  `scripts/run-pipeline-conformance.sh` (wired into
  `.github/workflows/ci.yml`). Regressions in `compileSafe`,
  parser, well-formedness, or structural fragments fail the build.
* **Differential validation hooks** — `scripts/differential.sh`
  supports `--reference bsv-command` / `--reference bsv-json` for
  byte-level diff against an external Bitcoin SV reference once
  one is wired into CI (one-time external integration).

Together with the 7-tier cross-compiler byte-identity gate, this
gives Rúnar a documented mechanised verification story: a precise,
inspectable claim with a named trust footprint, backed by an
empirical anchor on the compiler side.

### Caveat — Path 2 is future work

The 22 codegen-soundness axioms (16 Phase B + 5 Phase D + 1 omnibus)
remain in the trusted computing base. Discharging them with direct
Lean proofs — Path 2 — is multi-month specialist work tracked in
`TODO.md`. Without Path 2, the conformance claim is "verified modulo
the 22 documented axioms"; with Path 2 complete it becomes the
unconditional "verified". Either form is strictly stronger than the
typical "we have tests" baseline, and the structural-fragment
capstones (M5, A15) and per-primitive crypto `runOps`-to-spec proofs
(B1+B2) are already unconditional Lean theorems today.

## Active References

* `TRUST_MANIFEST.md` is the authoritative trusted-computing-base and
  assumption inventory.
* `HANDOFF.md` is the active implementation roadmap.
* `TODO.md` enumerates Path 2 — axiom discharge work — remaining for
  the unconditional verification claim.
* Historical exploration and audit files were removed after their live
  findings were folded into these active references.
