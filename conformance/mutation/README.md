# Mutation scoring — measuring the safety net's detection power (TS-GAP-006)

The audit finding TS-GAP-006 observed that the *detection power of the whole
test net is unmeasured*: dozens of gates exist, but nothing proves they would
actually catch a compiler regression. This harness measures that power directly.

Rather than a generic mutation tool, it applies a **curated corpus of
representative compiler bugs** (`mutants.json`) — one targeted find/replace per
mutant into a real line of a TypeScript compiler source file — runs the mapped
fast in-process gate(s), and records **caught vs survived**. A mutant that
*should* be caught but **survives** is a measured hole in the net.

## Why no rebuild is needed (src alias, not dist)

The gates resolve `runar-compiler` / `runar-testing` through the **root
`vitest.config.ts` src alias** (`runar-compiler` → `packages/runar-compiler/src/index.ts`).
`conformance/` has no nearer vitest config, so `cd conformance && npx vitest run …`
inherits the same aliases. Mutating a file under `packages/runar-compiler/src/`
is therefore observed by the gates **without `pnpm run build`** — apply, run the
gate, revert. Fast and correct. (If the gates ever move to built `dist`, this
harness would need a per-mutant rebuild; they do not today.)

## Gates

| gate name | command | catches |
|---|---|---|
| `differential-witness` | `cd conformance && npx vitest run witnesses/differential.test.ts` | source-semantics (ANF interpreter) vs script-semantics (`@bsv/sdk` `ScriptVM`) disagreement on any fold-ON deployed contract, over declared accept + near-miss witnesses |
| `fold-equivalence` | `cd conformance && npx vitest run witnesses/fold-equivalence.test.ts` | fold-OFF vs fold-ON execution divergence per witnessed fixture |
| `peephole-exhaustive` | `cd packages/runar-compiler && npx vitest run src/__tests__/peephole-exhaustive.test.ts` | any peephole rule whose `pattern` ≠ `replacement` in stack effect over the CScriptNum edge domain |

`execute-fuzz` (`cd conformance && npx tsx fuzzer/index.ts --execute …`) is a
slower randomized oracle and is **not** wired into per-mutant scoring here.

## Corpus shape

`mutants.json` covers the four audit bug classes — **off-by-one stack index**,
**swapped operands**, **dropped OP_VERIFY**, **if-without-else regression** —
across the **stack-lower**, **emit**, **constant-fold**, and **peephole**
stages. 15 mutants carry an `expectCaughtBy` set (they MUST be caught); 1 is a
**documented survivor** (see below).

Note on the peephole stage: `peephole-rules.ts` is the declarative mirror the
bounded-exhaustive sweep executes rule-by-rule, so corrupting a rule's
`replacement` into an unsound one is exactly what `peephole-exhaustive` exists
to catch — a faithful test of that gate's detection power.

## Documented survivor (a real, honest hole — not hidden)

`constantfold-add-to-sub` flips `evalBinOp('+')` in the ANF constant-fold pass.
It **survives** both `differential-witness` and `fold-equivalence`, because no
witnessed conformance fixture executes an all-constant subexpression through the
fold pass (the one fixture that folds — `if-without-else-multi-temp`, folding
`8n + 1n` — skips that path under its reject witness). Its `expectCaughtBy` is
empty and its `finding` records the gap. This is left visible per the TS-GAP-006
no-silence rule; do not delete it without adding a fixture whose verdict depends
on a folded constant.

## Running

```bash
cd conformance && npx tsx mutation/run-mutation.ts     # or: npm run mutation:score
```

Prints a scorecard (`caught N/M`, survivors listed with class + stage) and exits
**non-zero if any mutant with a non-empty `expectCaughtBy` survives** — i.e. the
net weakened. `baseline.json` is the stamped reference; the nightly CI job
(`.github/workflows/fuzzer-nightly.yml`) fails if a previously-caught mutant
becomes a survivor.

The scorer **always reverts** every mutant (try/finally, snapshot restore), so
the working tree is left clean; a mutated compiler source is never committed.

## Future extension

The corpus is TS-only. Go / Rust / other-tier mutants (mutating
`compilers/go/**`, etc. and scoring against that tier's suites) are a documented
future extension — they would require a native build per mutant and are out of
scope for this first increment.
