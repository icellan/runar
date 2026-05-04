# Rúnar Lean 4 Verification

A Lean 4 (toolchain `leanprover/lean4:v4.29.1`) port of Rúnar's
TypeScript-to-Bitcoin-Script compiler, providing a verified
`compile : ANFProgram → ByteArray` pipeline plus a regression-gated
byte-exact comparison against the TS reference.

## Status

| Metric                                    |   Count |
|-------------------------------------------|--------:|
| Conformance fixtures                      |   49/49 |
| Parse + WF (golden)                       |   49/49 |
| ANF JSON round-trip                       |   49/49 |
| Byte-exact match vs. TS reference         | **33/49** |
| Open axioms (verification)                |  62¹    |
| `sorry` / `admit` (whole codebase)        |     0   |

¹ 61 crypto/builtin axioms in `ANF/Eval.lean` (deterministic-byte-string
semantics; see `TRUST_MANIFEST.md` §3) plus 1 linking axiom
`hash256_eq_double_sha256` in `Stack/Peephole.lean`. The capstone
simulation theorem `Pipeline.lower_observational_correct` is no longer
an axiom (Phase 6 closeout) — it carries an explicit `hSimulates`
hypothesis matching the established `peephole_observational_correct`
pattern.

## Running locally

```bash
cd runar-verification
lake build                                      # 24 jobs OK

# Tests (linux: native exe; macOS: use `lake env lean --run` form)
lake env ./.lake/build/bin/goldenLoad           # 49/49 WF
lake env ./.lake/build/bin/roundtrip            # 49/49 round-trip
lake env ./.lake/build/bin/pipelineGolden       # 33/49 byte-exact + gates
```

The `pipelineGolden` binary enforces three regression gates and exits
nonzero on any:

1. **Total byte-exact count** must not drop below
   `expectedByteExact = 33` (locked in `tests/PipelineGolden.lean`).
2. **Per-fixture baseline** preservation: every fixture in
   `baselineMatches` (33 names) must still produce byte-identical hex.
   Catches silent swaps where a new fixture passes while a baseline
   fixture regresses.
3. **Promotion notices** (non-fatal): emits a warning if any fixture
   from the pending-triage buckets (`goOnlyFixtures`,
   `cryptoAxiomPending`, `mathBuiltinsPending`,
   `lowerDivergencePending`) flips to byte-exact, prompting promotion
   into `baselineMatches`.

### Optional full-mode run

The 11 `cryptoAxiomPending` fixtures (EC × 5, P-256 × 2, P-384 × 2,
SLH-DSA × 2) are skipped by default because Lean's runtime takes
hours to evaluate the multi-MB script outputs. To opt in:

```bash
RUNAR_VERIFICATION_FULL=1 lake env ./.lake/build/bin/pipelineGolden
```

Expect >1 hour wall time. Out of scope for CI.

## What's verified (and what isn't)

**Verified end-to-end (33 fixtures):** the pipeline
`compile = emitFast ∘ peepholeProgram ∘ Lower.lower` produces
byte-identical output to the TS reference.

**Not verified empirically (16 fixtures):**
* **4 Go-only by policy:** `babybear`, `babybear-ext4`, `merkle-proof`,
  `state-covenant`. These exercise crypto codegen modules that ship
  only in the Go reference compiler (per `CLAUDE.md` "Go-first
  development approach"); they are explicitly out of scope for the
  Lean port.
* **11 crypto-axiom-pending:** secp256k1 EC, NIST P-256/P-384, SLH-DSA
  parameter sets. Stack.Lower codegen has been ported (`Stack/Ec.lean`,
  `Stack/P256P384.lean`, `Stack/SlhDsa.lean`); per-primitive crypto
  soundness axioms (group laws, FIPS 205 verification correctness)
  remain to be discharged.
* **1 lowering-divergence pending:** `if-without-else-multi-temp`
  (Phase 5 carryover; nested shadow-rebind shape needs `lowerIf`
  extension).

## Architecture

```
RunarVerification/
  ANF/                — ANF IR + JSON round-trip + WF predicate + Eval interpreter
  Stack/              — Stack IR + Lower (ANF→Stack) + Eval VM + per-rule peephole
                        + crypto codegen modules (Blake3, Ec, P256P384, SlhDsa, Wots)
                        + Sim (lowering identities + per-opcode operational lemmas)
                        + Agrees (simulation predicate + Stage A-D scaffolding)
  Script/             — Bitcoin Script syntax + byte-level Emit + EmitCorrect identities
  Pipeline.lean       — End-to-end compile + soundness theorems
                        (lower_observational_correct, peephole_observational_correct,
                         emit_observational_correct, compile_observational_correct)
tests/
  GoldenLoad.lean     — load all 49 expected-ir.json + verify WF
  Roundtrip.lean      — load → re-emit → re-parse equality
  PipelineGolden.lean — full pipeline + 3-gate regression check
```

## Trust surface

See `TRUST_MANIFEST.md` for a complete inventory of the 62 open
axioms + 5 `opaque` defs, what each asserts, and what discharging
each would require.

## Phase history

See `HANDOFF.md` for the multi-phase development log
(Phase 1/2 bootstrap → Phase 3 byte-exact pipeline → Phase 4 crypto
codegen ports → Phase 5 cryptoAxiomPending opt-in → Phase 6 capstone
discharge).
