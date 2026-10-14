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
| `fold-execution` | `cd conformance && npx vitest run witnesses/fold-execution.test.ts` | accept/reject verdict that depends on a folded all-constant subexpression (closes the `constantfold-add-to-sub` hole — see below) |
| `peephole-exhaustive` | `cd packages/runar-compiler && npx vitest run src/__tests__/peephole-exhaustive.test.ts` | any peephole rule whose `pattern` ≠ `replacement` in stack effect over the CScriptNum edge domain |
| `branch-merged-locals-vm` | `npx vitest run packages/runar-testing/src/__tests__/branch-merged-locals-vm.test.ts` | branch-merged locals (≥2, or asymmetric arms) deployed and called through the real `@bsv/sdk` `Spend`, asserting `expectedState` — not just accept/reject (PALMER-1, `23ef2d2b`) |
| `branch-result-depth-invariant` | `npx vitest run packages/runar-compiler/src/__tests__/branch-result-depth-invariant.test.ts` | Layer C of `lowerIf` (`7b888035`): the parent `stackMap` must describe the physical stack after `OP_ENDIF`. Registered so the branch-merge mutants can **measure** whether it fires — for a depth-preserving, name-corrupting defect it does **not** |
| `real-crypto-branch-merged-locals` | `cd conformance && npx vitest run witnesses/real-crypto-execution.test.ts -t branch-merged-locals` | the `branch-merged-locals` witness replayed through the real `@bsv/sdk` `Spend` (2 accepts + 1 tamper-reject), not the interpreter |
| `real-crypto-private-helper-outputs` | `cd conformance && npx vitest run witnesses/real-crypto-execution.test.ts -t private-helper-outputs` | the `private-helper-outputs` witness (side-effect-summary.ts's regression fixture: public methods delegate output/mutation effects to private helpers) replayed through the real `@bsv/sdk` `Spend`, not the interpreter (N-287) |
| `side-effect-summary-unit` | `npx vitest run packages/runar-compiler/src/__tests__/side-effect-summary.test.ts` | direct unit pins on `collectStmt`'s call-graph walk, including a private helper whose only mutation is reachable solely through an else branch (N-298) |
| `state-push-framing-vm` | `npx vitest run packages/runar-testing/src/__tests__/state-push-framing-vm.test.ts` | state-section `<len><data>` framing through a deployed continuation and the real Script VM, over the full 1-byte value-class matrix (PALMER-2, `23ef2d2b`) |
| `c28-state-strict` | `npx vitest run packages/runar-sdk/src/__tests__/c28-state-strict.test.ts` | `deserializeState` strictness unit pins, including a direct malformed-input case (`deserializeState(fields, '55')` must throw `/is not a push opcode/`) — the gate that actually detects a *decoder*-only OP_N regression (see Phase E1 below) |
| `sdk-vertical-constructor-slots` | `cd conformance && npx tsx sdk-vertical/runner/vertical-runner.ts --tiers typescript --filter bigint-0` | TS SDK's constructor-slot splice (`buildCodeScript()` in `contract.ts`) against the independently-derived code part in `conformance/sdk-vertical` (Phase C3 / TG-016) |
| `sdk-vertical-codeseparator` | `cd conformance && npx tsx sdk-vertical/runner/vertical-runner.ts --tiers typescript --filter codesep-tag-zero` | TS SDK's `codeSepIndexSlots` resolution (`_resolvedCodeSepSlotValues()` in `contract.ts`) against the independently-derived code part for the `CodeSepMatrix` fixture (Phase C4 / TG-016) |
| `stack-frame-mutation-pins` | `npx vitest run packages/runar-testing/src/__tests__/stack-frame-mutation-pins.test.ts` | byte pins for `05-stack-lower.ts` paths the 71-fixture golden corpus never reaches: `StackMap.dup`'s name bookkeeping, the branch-private residue drain's depth-1 special case, the empty-else reconcile predicate, and the `sinkBelow` DISTANCE (2026-08-17 frame-offset family) |

`execute-fuzz` (`cd conformance && npx tsx fuzzer/index.ts --execute …`) is a
slower randomized oracle and is **not** wired into per-mutant scoring here.

The two `sdk-vertical-*` gates are scoped to the **TypeScript tier only**
(`--tiers typescript`), consistent with this corpus's existing TS-only scope,
and to a single currently-green case each (`--filter`) for speed and
determinism — `conformance/sdk-vertical` is a large fixture set (39 cases ×
7 SDK tools) built out by a parallel work stream; do not widen the filter or
drop `--tiers typescript` without first confirming the whole case set is
green, or these gates will "catch" every mutant for a reason unrelated to the
mutation. (The two cases previously called out as missing goldens —
`bigint-neg1`, `multi-slot-mixed-a` — have had theirs since 2026-08-06.)

## Corpus shape

`mutants.json` has 33 mutants across four groups:

- 16 covering the four original audit bug classes — **off-by-one stack
  index**, **swapped operands**, **dropped OP_VERIFY**, **if-without-else
  regression** — across the **stack-lower**, **emit**, **constant-fold**, and
  **peephole** stages. All 16 carry a non-empty `expectCaughtBy`.
- 6 **Phase E1 / TG-007** (2026-08) Palmer-class additions — see below.
- 6 **2026-08-17 frame-offset family** additions (`ef753a8f6`), closing holes
  the mechanical 1169-mutant sweep over `05-stack-lower.ts` found and the
  curated 22 did not cover: `StackMap.dup`'s name bookkeeping (two mutants),
  the branch-private residue drain's depth-1 special case, the empty-else
  reconcile predicate (two mutants), and the `sinkBelow` DISTANCE. All 6 are
  caught by `stack-frame-mutation-pins` (see Gates above).
- 5 **N-287** additions closing a gap in the corpus itself: every prior
  peephole mutant patches the *declarative mirror* `peephole-rules.ts`, never
  the real engine in `peephole.ts` (its N-264 bottom-up if-arm walk and
  F-392's opcode-string-form rule matching), and nothing patched
  `side-effect-summary.ts`'s private-method call-graph walk at all. See
  below.

Note on the peephole stage: `peephole-rules.ts` is the declarative mirror the
bounded-exhaustive sweep executes rule-by-rule, so corrupting a rule's
`replacement` into an unsound one is exactly what `peephole-exhaustive` exists
to catch — a faithful test of that gate's detection power. It does **not**
exercise `peephole.ts`'s own walk/emission code (`optimizeStackIR`,
`withOptimizedArms`, `applyOnePass`) at all — `optimizeStackIR` never imports
or consults `peephole-rules.ts` (see that file's own header comment) — which
is the gap the N-287 group below measures.

## N-287 additions — peephole.ts walk/emission + side-effect-summary.ts (2026-10)

Five mutants probed with a broad candidate gate list per mutant (via
`--filter`), then stamped with exactly the gates that fired — not tuned, not
assumed:

| id | targets | result |
|---|---|---|
| `peephole-walk-drops-else-arm` | `optimizeStackIR`'s N-264 bottom-up collection: disables `if (op.else) lists.push(op.else)`, so an if-statement's else arm is never itself optimized | caught by `differential-witness`, `real-crypto-branch-merged-locals`, `stack-frame-mutation-pins` |
| `peephole-withoptimizedarms-swap-then-else` | `withOptimizedArms` swaps the rebuilt `then`/`else` arms | caught by `differential-witness`, `branch-merged-locals-vm`, `real-crypto-branch-merged-locals`, `stack-frame-mutation-pins` |
| `peephole-f392-roll0-opcode-form-matches-pick` | F-392's opcode-string-form matching: the `PUSH 0, Roll{0}` rule's `isOpcode(…, 'OP_ROLL')` disjunct is changed to `'OP_PICK'`, so it wrongly intercepts a `PUSH 0, OP_PICK` window that should become `dup` and erases both ops instead | **formerly a documented survivor, now closed by `peephole-exhaustive`** — see below |
| `sideeffect-unioninto-and-instead-of-or` | `unionInto` flips one effect-propagation `||=` to `&&=`, so a private helper's `mutatesState` effect is silently dropped from its public caller's summary | caught **only** by the new `real-crypto-private-helper-outputs` gate (added by this item) — no other existing gate detects it |
| `sideeffect-ifstmt-skip-else-branch` | `collectStmt`'s `if_statement` case: disables the `stmt.else` walk, so a private helper's side effect hidden only inside an else-branch never surfaces | **formerly a documented survivor, now closed by `side-effect-summary-unit`** — see below |

`real-crypto-private-helper-outputs` (new gate, added alongside these
mutants) replays `conformance/witnesses/real-crypto/private-helper-outputs.json`
through `witnesses/real-crypto-execution.test.ts -t private-helper-outputs` —
the existing regression fixture for side-effect-summary.ts's call-graph walk
(see that file's own module docstring), not previously wired into this
harness's gate table.

## Formerly a documented survivor, now closed

`constantfold-add-to-sub` flips `evalBinOp('+')` in the ANF constant-fold pass.
It **used to survive** both `differential-witness` and `fold-equivalence`,
because no witnessed conformance fixture executed an all-constant subexpression
through the fold pass. `conformance/witnesses/fold-execution.test.ts` closed the
hole (its accept/reject verdict depends on a folded `2n + 3n`); the mutant's
`expectCaughtBy` is `["fold-execution"]` and its `finding` records the
before/after. Kept as an example of the corpus's own discipline: a real hole
was measured, named, and closed with new execution — not by relabelling.

`peephole-f392-roll0-opcode-form-matches-pick` (N-287's documented survivor
for F-392's opcode-string-form matching) **used to survive** every gate
probed, because `peephole-rules.ts`'s declarative mirror only encoded the
TYPED form of the Roll/Pick windows, never the opcode-string form the same
matchers also accept. Five new cases in
`packages/runar-compiler/src/__tests__/peephole-exhaustive.test.ts` ("F-392:
opcode-string-form Roll/Pick windows match the SAME rule as their typed
form") run `optimizeStackIR` for real on the opcode-string form of each of
Roll{0,1,2}/Pick{0,1} and assert its output matches the typed form's
documented replacement. The mutant's `expectCaughtBy` is now
`["peephole-exhaustive"]`.

`sideeffect-ifstmt-skip-else-branch` (N-287's documented survivor for
`collectStmt`'s `else`-branch walk) **used to survive** every gate probed,
because every fixture in the corpus — `private-helper-outputs` included —
put a private helper's effect at the top level or in a `then` arm, never
exclusively inside an `else` branch. A new ANF/ABI parameter-propagation test
in `packages/runar-compiler/src/__tests__/side-effect-summary.test.ts`
("N-298: side-effect-summary walks a private helper's else branch") pins a
private helper whose only mutation is reachable solely through an else arm,
wired into this harness as the new `side-effect-summary-unit` gate; a
sibling interpreter-execution test in the same describe block pins that the
else-only mutation still runs under `TestContract`'s business-logic model,
but does not itself detect this mutation. The mutant's `expectCaughtBy` is
now `["side-effect-summary-unit"]`.

## Phase E1 additions — Palmer-class corpus (TS-GAP-007, 2026-08)

Two fund-safety miscompilations (PALMER-1: branch-merged locals; PALMER-2:
state-section MINIMALDATA framing — see `docs/audit/2026-08-testing-gap-remediation-plan.md`
§0, fixed in `23ef2d2b`) shipped with a fully green suite because the mutation
corpus had no mutant of either shape. These 6 mutants close that specific gap
by **inverting the fix commit's hunks** — each is a literal reproduction of
the historical bug, not a synthetic one:

| id | file | inverts | verified caught by |
|---|---|---|---|
| `anflower-merge-locals-single-only` | `04-anf-lower.ts` | the canonical branch-merge list, truncated to its first entry (**re-derived 2026-08-06** — see below) | `branch-merged-locals-vm`, `real-crypto-branch-merged-locals` |
| `stacklower-merge-locals-property-only` | `05-stack-lower.ts` | the `_properties`-only restriction on adopting the declared results by name (**re-derived 2026-08-06**) | `branch-merged-locals-vm`, `branch-result-depth-invariant`, `real-crypto-branch-merged-locals` |
| `sdkstate-encode-minimaldata-opn` | `packages/runar-sdk/src/state.ts` | restoring the #110 MINIMALDATA short-circuit in `encodePushDataState` | `state-push-framing-vm`, `c28-state-strict` |
| `sdkstate-decode-opn-as-length` | `packages/runar-sdk/src/state.ts` | restoring the OP_N decode branch in `decodePushData` | `state-push-framing-vm`, `c28-state-strict` — see finding below |
| `sdksplice-constructor-slot-wrong-length` | `packages/runar-sdk/src/contract.ts` | new Phase C3 family: 1 stray byte per constructor-slot substitution | `sdk-vertical-constructor-slots` |
| `sdksplice-codeseparator-off-by-one` | `packages/runar-sdk/src/contract.ts` | new Phase C4 family: off-by-one on the baked `codeSepIndexSlots` value | `sdk-vertical-codeseparator` |

### Measured finding: both PALMER-1 mutants went STALE, and the baseline said otherwise (2026-08-06)

`4b0f688f` ("multi-result branch node") moved where branch merging is decided.
Both PALMER-1 mutants kept applying — their `find` strings still occurred
exactly once — but to lines that no longer gate the merged-local path:

- `anflower-merge-locals-single-only` targeted `if (mergedLocals.length >= 2)`
  inside `branchOutputRejectionReason`, which only runs when an `if` arm emits
  an **output**. No branch-merged-locals fixture does.
- `stacklower-merge-locals-property-only` targeted the `_properties` check in
  `elseMatchesThenNResultLayout`, which after `4b0f688f` is reachable only when
  `nDeclared === 0`. Every merged-local shape now takes the declared-results
  path instead.

Both therefore **SURVIVED**, while `baseline.json` recorded both as `caught`.
The corpus overstated its own detection power for the flagship regression
family, and the only check that would have said so is the baseline-regression
step in `.github/workflows/fuzzer-nightly.yml` — nightly-only, and it had not
run since the refactor landed.

Both were re-derived against the current source and re-measured **per gate**
(each gate run separately against the applied patch, not inferred):

| mutant | `branch-merged-locals-vm` | `branch-result-depth-invariant` | `real-crypto-branch-merged-locals` |
|---|---|---|---|
| `anflower-merge-locals-single-only` | **FIRES** — 5/9 shapes (S3, S6, S7, S8, S9) | **silent** — 18/18 still pass | **FIRES** — 1/3 spends (the `toFirst==0` accept) |
| `stacklower-merge-locals-property-only` | **FIRES** — 8/9 shapes (all but S2, if-without-else) | **FIRES** — 12/18 | **FIRES** — 3/3 spends |

The silent cell is the point, and it is recorded rather than papered over:
truncating the merge list is **depth-preserving and name-corrupting**, and
Layer C only compares depths, so the invariant added in `7b888035` to make "the
next one LOUD instead of silent" does not see that half of the family at all.
`expectCaughtBy` lists only the gates that were observed to fire.

### Guard against this recurring: stale ≠ survivor

A mutant whose patch no longer applies is now reported as **STALE** — not as a
survivor — by `run-mutation.ts` (no gate is run for it, and the run exits
non-zero), and `__tests__/mutant-staleness.test.ts` re-checks every mutant's
anchor in **milliseconds**, with no gates and no mutation, so a refactor that
moves the code fails on its own PR instead of decaying into a mystery survivor
weeks later. That test runs in the ordinary suite and in the `conformance` CI
job. A survivor means "the net has a hole"; a stale mutant means "the corpus no
longer describes the code" — opposite fixes, so they are reported separately.

`restoreAfterMutation` also un-applies the patch against whatever the file holds
at the end of the gate run rather than blind-writing the pre-mutation snapshot:
this repo is worked in several checkouts at once, and a blind restore silently
throws away anything saved during the seconds a mutated compiler source is in
place.

### Measured finding: `sdkstate-decode-opn-as-length` (execution-verified, not tuned away) — FIXED by N-299

This mutant restores ONLY the decode-side OP_N branch (the encoder stays
correct). Run against `state-push-framing-vm` alone it used to **survive**:
every test in that file constructed its state blob through the (correct)
encoder, so an OP_N-framed byte sequence never reached the decoder — the added
leniency was dead code for every case that file exercised. `caughtBy` for this
mutant was `["c28-state-strict"]` while `expectCaughtBy` listed both gates;
the scorer's own `missedExpectedGates` reporting printed
`⚠ expected gate(s) did NOT fire: state-push-framing-vm` for exactly this
reason — the mutant was caught overall (`c28-state-strict.test.ts` has a direct
`expect(() => deserializeState(fields, '55')).toThrow(/is not a push opcode/)`
pin), but the gate this corpus's own Phase E1 table proposed for it did
**not**, on its own, provide that coverage. This was verified by running the
mutant, not asserted — it was NOT tuned to pass; the honest result was
recorded as-is, with a fix candidate: give `state-push-framing-vm.test.ts` a
direct malformed-input decode case, per P3 ("round-trip alone is never
sufficient for a listed wire primitive").

**N-299 implemented that fix candidate.** `state-push-framing-vm.test.ts`
gained a direct unit test — `deserializeState(fields, opHex)` called with
hand-written OP_1..OP_16 (0x51-0x60) and OP_1NEGATE (0x4f) bytes, never routed
through `serializeState` — asserting each one throws `/is not a push
opcode/`. Re-measured by execution (apply the mutant, run the gate, observe):
`state-push-framing-vm` now fires too. `caughtBy` for this mutant is now
`["state-push-framing-vm", "c28-state-strict"]`, both nominated gates fire,
and the scorer no longer reports this mutant as partially caught.

### `stateful-bytestring-op-n-state` sdk-output golden: NOT wired (documented, not invented)

The Phase E1 table in the remediation plan also names the
`conformance/sdk-output` `stateful-bytestring-op-n-state` golden as an
intended gate for the two `sdkstate-*` mutants. It was **not** added:
`conformance/sdk-output/runner/sdk-runner.ts`'s coverage audit currently fails
before running any fixture (4 compiler-conformance fixtures added by a
parallel work stream — `loop-carried-locals`, `merge-locals-prop-updates`,
`merge-locals-shapes`, `state-bigint-edges` — are not yet registered in
`sdk-output` or `coverage-allowlist.json`). A gate whose unmutated baseline
already fails would "catch" every mutant for a reason that has nothing to do
with the mutation, which is worse than not having the gate. `c28-state-strict`
was substituted as an execution-verified alternative that exercises the same
underlying regression. Re-add `stateful-bytestring-op-n-state` once the
`sdk-output` coverage audit is green again.

### `constructorSlots` / `codeSeparatorIndex`: wired to `conformance/sdk-vertical`

`conformance/sdk-vertical` (Phase C3/C4) existed by the time this work started
and is used directly — see the `sdk-vertical-*` gates above and their caveats
about the in-progress case set.

## Running

```bash
cd conformance && npx tsx mutation/run-mutation.ts     # or: npm run mutation:score
cd conformance && npx tsx mutation/run-mutation.ts --filter merge-locals   # one family
```

Prints a scorecard (`caught N/M`, survivors listed with class + stage) and exits
**non-zero if any mutant with a non-empty `expectCaughtBy` survives** (the net
weakened) **or if any mutant is stale** (the corpus no longer describes the
code). `baseline.json` is the stamped reference; the nightly CI job
(`.github/workflows/fuzzer-nightly.yml`) fails if a previously-caught mutant
becomes a survivor. `baseline.json` covers only the 22 mutants that existed
when it was last written — the six 2026-08-17 frame-offset additions (see
Corpus shape above) have no baseline entry; F-251 makes a surviving one of
those six still fail the run. Stamp from the last `--write-baseline`:
**22/22 caught, 0 survivors, 0 stale** (39s wall, 2026-08-06) — the same
22/22 the previous baseline claimed,
except that two of those 22 were not actually being detected when it was
stamped.

`--filter <substr>` scores only the matching mutant ids. It cannot be combined
with `--write-baseline` (a partial baseline is a lie), and it exists to keep the
window in which a real compiler source sits mutated as short as possible.

The scorer **always reverts** every mutant (try/finally), so the working tree is
left clean; a mutated compiler source is never committed.

## Future extension

The corpus is TS-only. Go / Rust / other-tier mutants (mutating
`compilers/go/**`, etc. and scoring against that tier's suites) are a documented
future extension — they would require a native build per mutant and are out of
scope for this first increment.
