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
| Conformance fixtures discovered | 49/49 |
| ANF parse + well-formedness | 49/49 |
| ANF JSON round-trip | 49/49 |
| Default byte-exact gate | 49/49 fixtures |
| Crypto-heavy fixtures | 15/49 stored Lean-produced constants; explicit pending-assumption bucket |
| Full/sharded byte-exact target | live `cryptoAxiomPending` bucket regeneration |
| Tracked Lean modules | all build via `scripts/lean-verify.sh` |
| Project axioms | 71 |
| Opaque executable defaults | 0 |
| `partial def` in `RunarVerification/` | 0 |
| `sorry` / `admit` | 0 |

Default `pipelineGolden` is the fast gate and currently checks 49/49
fixtures byte-exact. The 15 crypto-heavy fixtures are counted only
through stored Lean-produced constants, not by comparing
`expected-script.hex` to itself. They remain visible as the
`cryptoAxiomPending` bucket because their semantic proof obligations
still depend on the crypto assumptions listed in `TRUST_MANIFEST.md`.

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

## Proof Status

The citable end-to-end theorem is not yet complete for deployed Script
bytes. The current proof surface is deliberately split:

* real proved infrastructure for parsing, well-formedness, many
  peephole rules, and the `SimpleANF` proof substrate;
* skeleton theorem names in `Pipeline.lean` for lower/peephole/emit
  composition points whose hypotheses still carry the load-bearing
  obligations;
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
  threads those emitted bytes through the single-public-method theorem
  under the remaining patched-byte soundness hypothesis; a restricted
  companion discharges that hypothesis when patched bytes equal
  `emitFast` bytes and the existing `AreRunarEmittableWithIf` parser path
  applies; the empty-ops and flat no-patch-site single-public subsets
  prove concrete byte-equality routes into that theorem;
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
and proof scaffolding code.

## Active References

* `TRUST_MANIFEST.md` is the authoritative trusted-computing-base and
  assumption inventory.
* `HANDOFF.md` is the active implementation roadmap.
* Historical exploration and audit files were removed after their live
  findings were folded into these active references.
