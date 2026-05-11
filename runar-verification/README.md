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
| Default byte-exact gate | 34/49 live fixtures |
| Crypto-heavy fixtures | 15/49 explicit pending-assumption bucket |
| Tracked Lean modules | all build via `scripts/lean-verify.sh` |
| Project axioms | 82 |
| Opaque executable defaults | 2 |
| `partial def` in `RunarVerification/` | 0 |
| `sorry` / `admit` | 0 |

Default `pipelineGolden` no longer counts a crypto-heavy fixture by
comparing `expected-script.hex` to itself. A crypto-heavy fixture counts
in default mode only after `tests/PipelineGolden.lean` contains a stored
Lean-produced constant for that fixture. Until then, the 15 fixtures are
visible as unpopulated pending-assumption fixtures.

## Commands

```bash
cd runar-verification
lake build
lake env ./.lake/build/bin/goldenLoad
lake env ./.lake/build/bin/roundtrip
lake env ./.lake/build/bin/pipelineGolden
./scripts/check-tcb-drift.sh
```

Long-running checks:

```bash
RUNAR_VERIFICATION_REGEN=1 lake env ./.lake/build/bin/pipelineGolden
RUNAR_VERIFICATION_FULL=1 lake env ./.lake/build/bin/pipelineGolden
bash scripts/differential.sh --reference python --strict
```

The differential wrapper raises the process stack limit before parsing
large scripts. The Lean-side report writes to `RUNAR_DIFFERENTIAL_OUT`
when set, otherwise under `/tmp/runar-verification-differential/`.

## Proof Status

The citable end-to-end theorem is not yet complete for deployed Script
bytes. The current proof surface is deliberately split:

* real proved infrastructure for parsing, well-formedness, many
  peephole rules, and the `SimpleANF` proof substrate;
* skeleton theorem names in `Pipeline.lean` for lower/peephole/emit
  composition points whose hypotheses still carry the load-bearing
  obligations;
* backend-parametric SHA-256 / RIPEMD-160 semantics, with fail-fast Lean
  codegen and Runar runtime implementations checked against external
  vectors; and
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
