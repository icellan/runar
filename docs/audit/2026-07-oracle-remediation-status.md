# Correctness-oracle remediation — status (2026-07)

Durable record that every finding from the 2026-07-04 correctness-oracle audit
now maps to a landed, CI-gated oracle or test. The central asymmetry the audit
flagged — nothing executed the **fold-ON deployed bytes** against an independent
script engine — is closed: the differential, fuzzer-execution, fold-equivalence,
boundary, and Go script-execution oracles all execute or compare fold-ON bytes.

## Finding → gate → CI job

| Finding | Sev | Gate(s) / test(s) that now cover it | CI job |
|---|---|---|---|
| **TS-DOC-002** (stale fixture count) | LOW | `conformance/README.md` restamped to the authoritative `find tests -name source.json \| wc -l` count | — (doc) |
| **TS-DOC-001** (false "interpreter-vs-VM" fuzzer claim) | MED | `docs/testing-guide.md` corrected: fuzzer is a cross-tier **parity** oracle; the source-vs-script **execution** oracle is named separately | — (doc) |
| **TS-GAP-003** (spend-execution suite un-gated) | HIGH | `conformance/script_execution_test.go` — compiles each contract to fold-ON bytes, executes real spends + adversarial near-miss witnesses through the go-sdk Bitcoin Script engine | `script-execution` (Script Execution Oracle) |
| **TS-BUG-001** (Go integration skipped fold + EC) | MED | `integration/go/helpers/compiler.go` routed through fold + EC passes; `compiler_pipeline_test.go` asserts integration hex == Go-CLI hex | `integration` |
| **TS-GAP-004** (no per-golden spend witnesses) | HIGH | `conformance/witnesses/*.json` per-fixture accept + near-miss witnesses; `witnesses/differential.test.ts`; `witnesses/completeness.test.ts` (no silent gaps) | `conformance` (`npx vitest run witnesses/`) |
| **TS-GAP-001** (source-vs-script differential missing) | BLOCKER | fixed half: `packages/runar-testing/src/oracle/differential-execution.ts` via `witnesses/differential.test.ts`; randomized half: fuzzer `--execute` (`conformance/fuzzer/execute-differential.ts`) | `conformance` + `fuzz` (`--execute`) |
| **TS-GAP-005** (fuzzer had no execution oracle) | HIGH | fuzzer `--execute`: ANF interpreter vs `ScriptVM` on generated fold-ON scripts, accept/reject agreement | `fuzz` (nightly + PR, fixed seed) |
| **TS-GAP-002** (no fold-ON translation validation) | HIGH | `witnesses/fold-equivalence.test.ts` — fold-OFF ≡ fold-ON execution per witnessed fixture (`packages/runar-testing/src/oracle/fold-equivalence.ts`) | `conformance` (`npx vitest run witnesses/`) |
| **TS-GAP-010** (no boundary/encoding corpus) | MED | `packages/runar-compiler/src/__tests__/element-size-guard.test.ts` + push/CScriptNum boundary corpus | `ts-compiler` (`pnpm run test`) |
| **TS-GAP-011** (verifier-side sig not adversarially tested) | LOW | verifier-side dual-oracle tests in `packages/runar-testing/src/__tests__/` (e.g. `post-quantum-dual-oracle.test.ts`, `sighash-pinning.test.ts`) | `ts-compiler` (`pnpm run test`) |
| **TS-GAP-008** (peephole not exhaustively verified) | MED | `packages/runar-compiler/src/__tests__/peephole-exhaustive.test.ts` — every rule's `pattern` ≡ `replacement` stack effect over the CScriptNum edge domain | `ts-compiler` (`pnpm run test`) |
| **TS-GAP-009** (no metamorphic/EMI testing) | MED | `conformance/fuzzer/metamorphic-fuzz.ts` — semantics-preserving transforms must not change the executed accept/reject verdict | `fuzz-metamorphic` (nightly) |
| **TS-GAP-007** (no contract-level fuzz gate + reducer) | MED | contract-level IR fuzz gate + delta-debugging reducer (`conformance/fuzzer/reduce.ts`) | `fuzz` (contract-level IR, fixed seed) |
| **TS-GAP-006** (safety-net detection power unmeasured) | MED | `conformance/mutation/` — curated compiler-bug corpus + scoring harness (`run-mutation.ts`), baseline + nightly survivor-regression gate | `mutation-score` (nightly) |

All 14 findings are covered. TS-GAP-001 is counted once (fixed + randomized halves).

## Residual caps (honest limits — not silenced)

- **Crypto / stateful contracts are excluded from the in-process execution
  oracle.** `differential-witness` and the fuzzer `--execute` oracle cover
  stateless, non-crypto contracts (pure arithmetic / boolean / if). Contracts
  requiring real ECDSA / EC / PQ / hash-preimage crypto are covered instead by
  the Go `script_execution_test.go` real-crypto path and are listed with reasons
  in `conformance/witnesses/crypto-exempt.json`. The TS `ScriptVM` uses a mock
  always-true `checkSig`, so signature accept/reject is not exercised in-process.
- **Peephole bounded-exhaustive sweep is bounded to arity ≤ 3** and to a
  CScriptNum numeric/boolean/bytes edge domain. Rules whose operands need real
  signature / tx-sighash context are documented `skip`s (logged, never silent)
  and are covered by the go-sdk real-crypto path instead.
- **The mutation corpus is curated and TS-only, not exhaustive.** 16 hand-picked
  mutants across four bug classes × four stages. Go / other-tier mutants are a
  documented future extension (they need a native build per mutant). The corpus
  measures the *fast* gates' detection power, not the whole net's.

## Live sub-findings surfaced during remediation

Two observations were surfaced (and are recorded, not silenced) while
building the oracles. On investigation, the first is **not a defect on the
target consensus** — it is correct behavior:

1. **Oversized `ByteString` literal → single >520-byte element is CORRECT for
   the Chronicle target (resolved — not a bug).** The pre-Genesis
   `MAX_SCRIPT_ELEMENT_SIZE = 520` single-element cap does **not** apply on
   Chronicle (the post-Genesis BSV node variant this repo compiles for — see
   `conformance/script_execution_test.go`, whose spends run under
   `interpreter.WithAfterChronicle()`, which raises the element cap to
   MaxInt32; the TS `ScriptVM` enforces no element cap either). So the compiler
   correctly emits an oversized literal as a single push element with no guard —
   adding a 520-byte rejection would break legitimate large-literal contracts
   that spend fine on Chronicle. `element-size-guard.test.ts` was corrected to
   assert this **intended** behavior (previously it mischaracterized it as a
   "gap"). It also serves as the tripwire that would fire if a pre-Genesis
   target were ever adopted (which would then require a guard or multi-push
   lowering). The strict pre-Genesis 520/1000/4-byte limits are themselves
   exercised adversarially by `conformance/boundary_test.go` under the
   before-genesis engine config, so both regimes are covered.

2. **`OP_NOT, OP_NOT → []` is boolean-idempotence, not numeric identity.**
   The peephole rule is sound **only** under the compiler's precondition that it
   emits `OP_NOT` for `!` / `!==` on bool-typed operands. On a non-canonical
   operand (e.g. `5`), `OP_NOT OP_NOT` normalises to `1` while the empty
   replacement leaves `5`. `peephole-exhaustive.test.ts` sweeps this rule over
   the boolean edge domain `{0,1}` (its actual precondition) and separately
   asserts the numeric divergence, so the precondition is documented, not hidden.

## Mutation-score reference

The mutation scorecard (`conformance/mutation/`) reports **caught 16/16**
mutants that must be caught, with **0 survivors**. The former
`constantfold-add-to-sub` survivor — a genuine measured hole where the ANF
constant-fold arithmetic evaluator was not executed by any witness — has been
**closed** by `conformance/witnesses/fold-execution.test.ts`, whose
accept/reject verdict depends on a folded constant (`2n + 3n`) and is checked by
both the source-vs-script differential oracle and the fold-OFF/fold-ON oracle.
The scorer wires it as the `fold-execution` gate and `baseline.json` records the
mutant as caught. (This is the mutation harness working as intended: it found a
real hole in the net, which was then closed with targeted coverage.)
