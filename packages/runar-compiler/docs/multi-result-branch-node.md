# Should the ANF `if` node yield multiple results?

**Status: IMPLEMENTED 2026-08-06 in all seven tiers. §1-§8 below are the
assessment that preceded it and are kept as written; §9 records the containment
attempt that came first; §10 records what actually landed and where this note's
predictions were wrong.**

This note sits beside the passes it concerns (`src/passes/04-anf-lower.ts`,
`src/passes/05-stack-lower.ts`) rather than under `docs/`, because it is a
compiler-internal design question, not user documentation.

---

## 1. The recurring bug

Six confirmed miscompiles in one week share one root cause: **one stack carrier
is asked to hold N live values.** `lowerIf` registers exactly ONE `stackMap`
name for whatever the arms leave behind. When the arms leave more than one
physical slot, every later operand resolves N−1 slots off — and because the
`stackMap` is the compiler's only model of the stack, nothing notices.

| # | Shape | Symptom | Closed by |
|---|---|---|---|
| P1 | `if` merging K≥2 locals | wrong-but-accepted continuation | `mergedLocals >= 2` normalisation (`appendMergedLocalResults`) + `countMergedLocalResults` trim + `elseMatchesThenNResultLayout` |
| P2 | K=1 local both arms rebind in place | compile error `Value '<if>' not found on stack` | `branchInPlaceRebindDepth` |
| P3 | loop-carried local rebound then read again | `wacc = step*N` instead of `step*N*(N+1)/2` | `collectLoopCarriedRebinds` |
| P4 | same, one loop deeper | `wacc = 24` instead of `30` | `flattenNestedLoopBodies` |
| P5 | constant-fold blanking an untaken arm | silent at K=2, loud at K=1 | fold both arms unconditionally |
| P6 | K≥2 merged locals **dead after the `if`** | `wacc = 3` instead of `9` | merged-local protection in `lowerIf` (2026-08-06) |
| **P7** | **arm writes a property AND rebinds a merged local** | **UNSPENDABLE script** | **OPEN** — see §6 |

Six patches around one gap, and the seventh instance is open and fund-critical.

## 2. The proposal

Give the `if` node an explicit result list: one slot for the branch's
serialised output bytes, plus N for merged locals **and property writes**.
`lowerIf` then registers N+1 `stackMap` names instead of 1, and
`drainBranchPrivateResidue` stops inferring liveness by name.

## 3. What it would touch

Root `CLAUDE.md`'s "Adding a New ANF Value Kind" checklist is the real blast
radius. This is not a new kind — it is a **shape change to an existing kind**,
which is strictly worse, because the existing kind is already serialised into
checked-in goldens and read by other tiers.

**Per tier (×7):** ANF IR type, ANF lowering, stack lowering, the ANF JSON
loader's known-kinds/field dispatch. Plus TS-only: `constant-fold.ts`,
`packages/runar-ir-schema/src/anf-ir.ts` (kept in sync by hand with
`src/ir/anf-ir.ts`), and the seven SDK ANF interpreters
(`packages/runar-{sdk,go,rs,py,zig,rb,java}`, 1169–2477 lines each).

The two functions that carry the logic are large everywhere:

| tier | stack lowering | ANF lowering |
|---|---|---|
| TypeScript | 5540 | 2662 |
| Go | 5549 | 2837 |
| Rust | 6873 | 3948 |
| Python | 4793 | 2670 |
| Zig | 6370 | 3898 |
| Ruby | 4245 | 2850 |
| Java | 4072 | 2489 |

**The part that is easy to miss: the ANF `if` node is a cross-tier wire
format.** `conformance/tests/*/expected-ir.json` is the **ANF** IR, not the
Stack IR, and `conformance/runner/index.ts --ir-parity` feeds the TypeScript
tier's checked-in ANF JSON to all six non-TS tiers and requires byte-identical
hex out. So a shape change means:

- all **70** `expected-ir.json` goldens are rewritten, each needing a
  content-pinned `golden-provenance-allowlist.json` entry or a co-changed
  witness (the gate in `conformance/scripts/check-golden-provenance.mjs`);
- the ANF loader in all six non-TS tiers must accept the new shape **in the
  same commit**, or `--ir-parity` cannot pass at any intermediate point;
- four fixtures have `__merge$` blocks baked into their goldens
  (`branch-merged-locals`, `merge-locals-shapes`, `merge-locals-prop-updates`,
  `loop-if-merged-locals`) and those blocks disappear entirely.

There is no incremental path through this: it is one atomic 7-tier commit or a
broken parity gate.

## 4. Byte neutrality

**No.** Concretely, what moves:

- **ANF goldens: all 70** if the result list is an unconditional field on the
  node (`"results": []` serialises everywhere). Keeping it optional/omitted
  when empty would confine ANF movement to the ~4 merge fixtures — worth doing,
  and it is the difference between 70 provenance entries and 4.
- **Script hex: the merge fixtures.** `appendMergedLocalResults`' two-pass
  copy-then-rebind block is *exactly* what produces today's PICK/ROLL sequence
  for K≥2. Delete the block and the arms' opcode sequences change. Affected:
  `branch-merged-locals`, `merge-locals-shapes`, `merge-locals-prop-updates`,
  `loop-if-merged-locals`, plus the `BranchMergedLocals` example in 9 formats.
  Expect the merge arms to get *smaller* (the `__merge$` temps exist only to
  work around single-result), so `script-size-baseline.json` moves down for
  those fixtures.
- **Everything else: unchanged**, provided the new path is taken only where an
  `if` actually has >1 result. That is the same discipline that made all six
  patches byte-neutral, and it is checkable the same way (repo-wide sweep ×
  both fold modes).

Rough size: 4 of 70 fixtures move hex, ~4–70 move ANF depending on the optional
-field decision. That is a reviewable diff, but every moved golden is a
self-produced artifact that needs independent justification — which is real
work, not a rubber stamp.

## 5. Does it subsume the six patches?

Honestly: **three yes, one partly, two no.**

- **P1 — subsumed, and deleted.** The whole `__merge$` convention exists only
  because the node carries one value. `appendMergedLocalResults`,
  `countMergedLocalResults`, `mergedLocalResultNames`, the trim loop and
  `elseMatchesThenNResultLayout` all go away. This is the single biggest
  simplification on offer.
- **P2 — subsumed.** `branchInPlaceRebindDepth` exists because at K=1 the arms'
  net depth change is zero and nothing gets registered. With a declared result
  list there is a name to register regardless of depth arithmetic.
- **P6 — subsumed.** My 2026-08-06 fix makes `appendMergedLocalResults`' stated
  premise true by protecting the merged locals. If the node declares its
  results, lowering must materialise them, so the premise is structural rather
  than assumed.
- **P5 — partly.** Blanking an arm would become a *loud* structural violation
  (the node says N results, the arm produces 0) instead of a silent
  miscompile. But the second half of P5 — propagating a taken arm's constants
  into the enclosing env while the `if` survives — is unrelated and still needs
  its own fix.
- **P3, P4 — NOT subsumed at all.** These are loop-carried liveness, not branch
  results: `acc = acc + step` at a loop body's top level involves no `if`.
  `collectLoopCarriedRebinds` and `flattenNestedLoopBodies` stay exactly as they
  are. Two of the seven defects — and the two that were hardest to find — are
  outside this proposal's reach.

That is the honest scorecard: the proposal fixes the **branch** half of the
family and leaves the **loop** half untouched. The loop half would need its own
analogous change (a loop node that declares its carried values), which nobody
has proposed and which this note does not assess.

## 6. P7 — the open defect this assessment turned up

While assessing, I added a temporary `stackMap`-vs-physical-depth invariant to
`lowerIf` and ran the whole suite under it. It held for **4614 tests** and fired
on exactly one shape, the fuzzer's `prop-write-in-arm`. Reproduced end to end:

```ts
let na = 1n;
if (flag > 0n) { this.p = x + 100n; na = x + 1n; } else { na = x + 2n; }
this.addOutput(1000n, this.p, na, this.b);
```

The then-arm produces **an UNSPENDABLE script** — `@bsv/sdk`'s `Spend` runs to
the end and rejects on a falsy top of stack. Pre-existing at `32b9cb2a`, and
TS and Go emit byte-identical wrong hex, so it is a seven-tier defect. Both
arities (K=1 and K=2) fail; both fold modes fail; the else-arm is fine. Pinned
in `packages/runar-testing/src/__tests__/branch-prop-write-with-merged-local-vm.test.ts`.

No shipped artifact reaches it — a structural sweep of every `.runar.*` in the
repo found zero methods with a property write and a local rebind in the same
arm. `cond-write-multi-field` writes only properties in its arm;
`merge-locals-prop-updates` writes its properties *after* the `if`. The
combination is unfixtured, which is why it survived.

**It is not patchable the way its six siblings were.** The merged-local
normalisation covers LOCALS; a property written in an arm is a second result
kind it does not model, so the arms end at different depths *with different
layouts*:

```
then: [ ..., p(new), na(new) ]   +2
else: [ ..., na(new) ]           +1
```

`lowerIf`'s phase-3 padding assumes the missing slots are the **topmost** ones
and pads on top. Here the missing slot is `p`, which sits *beneath* `na`. The
bug is in the padding loop's slot **selection**, not in a liveness predicate —
there is no "protect this name" patch that fixes it. Fixing it properly means
an arm's result set must include property writes, which is exactly this
proposal.

**P7 is therefore the strongest argument in favour of the proposal, and the
clearest evidence that the patch-a-predicate strategy has reached its limit.**

## 7. Cheaper intermediates

**(a) A `stackMap`-vs-physical-depth invariant on `lowerIf` — do this first.**
This is the highest-value/lowest-cost item in the whole analysis. It emits no
opcodes, so it is byte-neutral by construction, and it is ~10 lines per tier.
Measured: it holds across 4614 existing tests with the P6 fix in place, and it
catches P1, P2, P6 and P7 at **compile time, loudly**, instead of on-chain.
It is the same genre as the existing "Layer B" branch-balance guard, which was
added for exactly this reason after issue #99. Note the naive form
(`this.stackMap.depth === thenCtx.stackMap.depth`) is wrong — the post-`ENDIF`
reconcile legitimately drops stale slots — so it must be stated as
`this.stackMap.depth + physicalDropsEmittedAfterEndif === armDepth`.

**(b) A result COUNT on the stackMap, keeping the single-result node.** Much of
this already exists as `nResults` plus the N≥2 adopt path; the gap was never the
count, it was the *precondition* that both arms actually leave N equally-named
slots. Adding a count without fixing arm layout does not close P7. Low value.

**(c) Extend `mergedLocals` to include arm-written properties, keeping the
`__merge$` block.** This would close P7 within today's architecture, at the cost
of moving hex for `cond-write-multi-field` and friends. It is a smaller change
than the full node migration, but it doubles down on the convention the
migration exists to delete — the classic "one more patch" that makes the
eventual migration harder.

## 8. Recommendation

**Do it — but not next. Order: (a), then P7 via (c) or the migration, then the
migration.**

Justification from the evidence:

1. **The invariant (a) is unambiguously right and nearly free.** Six of seven
   defects in this family were silent; the invariant makes four of them loud for
   ~70 lines total across 7 tiers, byte-neutral, no goldens touched. There is no
   argument against doing it immediately, and it protects the migration itself —
   a 7-tier IR migration without a stack-shape invariant is exactly the change
   most likely to add defect #8.
2. **The migration is right in the medium term.** P1 is pure workaround
   scaffolding, P7 proves the workaround does not generalise to a second result
   kind, and the trend line is one new instance per few days of looking. The
   proposal deletes the scaffolding rather than extending it.
3. **But it is not right *now*, for three concrete reasons.** It cannot be
   staged: the ANF `if` node is a cross-tier wire format with a hard parity gate,
   so it is one atomic 7-tier commit. It moves goldens that each need
   independent provenance justification. And it closes only 3.5 of the 7 known
   defects — the two loop-carried ones are untouched — so it is not the "one
   change that ends the family" it looks like.
4. **A half-done migration is the worst outcome available.** Between "seven
   tiers on the old shape" and "seven tiers on the new shape" there is no green
   state: `--ir-parity` fails for every intermediate commit. It needs a
   dedicated change with all seven tiers moving together, not a slice of a
   remediation pass.

The concrete next action is (a): add the depth invariant to `lowerIf` in all
seven tiers, verify byte-neutrality by the usual sweep, and let it turn P7 —
and any future member of this family — into a compile error instead of a locked
UTXO.

---

## 9. Outcome of acting on §7(a) — 2026-08-06

§7(a) (the `stackMap`-vs-physical-depth invariant) **landed in all seven
tiers**. §2 (the multi-result node) **did not**. What the attempt measured:

**The invariant needs TWO halves, not one.** The depth form this note proposed
catches P7 only at K=1. At K>=2 the depths stay *consistent* — the merged-local
trim quietly drops the arm's property write on its "everything beneath the K
results is dead" premise, which is false for a property (properties get no
`__merge$` normalisation). So the trim's premise is now checked directly,
beside the depth comparison. Both are pure asserts; neither emits an opcode.

**P7 has a third sub-shape, and it is still open.** When the written property is
READ AGAIN after the `if`, the arm's slots are *reordered* rather than
*miscounted*: the arm leaves `[ ..., p(new), local(new) ]` while the parent
models `[ ..., local, <if> ]`. Depths agree exactly; only the LAYOUT is wrong.
Neither half of the invariant can see it, and it still compiles to an
unspendable script. Pinned as case `E` in
`packages/runar-testing/src/__tests__/branch-prop-write-with-merged-local-vm.test.ts`.

**A layout invariant does catch it, and cannot be landed as-is.** "The parent
stack model must equal the arms' model minus the result slots" was prototyped
and measured against the full suite: **37 failures across 18 files**, all
legitimate. The K=1 alias rebind deliberately moves the local's slot to the top
and repairs the naming *afterwards*, so parent and arm layouts differ by design
there. Separating the two means re-deriving what the reconcile intended — which
is §2 itself. That is a second, independent argument for §2, on top of P7.

**§3's blast radius re-measured and confirmed:** 70 `expected-ir.json` + 70
`expected-script.hex` goldens; exactly 4 fixtures carry `__merge$` blocks
(`branch-merged-locals`, `merge-locals-prop-updates`, `merge-locals-shapes`,
`loop-if-merged-locals`); exactly 2 carry an `update_prop` inside an `if` arm
(`cond-write-multi-field`, `branched-readonly-len`); the seven SDK ANF
interpreters run 1038–3421 lines each.

**Byte neutrality of (a), measured not assumed:** conformance **630/630 in both
fold modes**, full TS suite **8750 passed / 194 skipped / 0 failed**, and every
tier's own suite green. The seven diffs are pure insertions apart from two
semantically-identical restructures (Ruby's `while` modifier becomes a block;
Java's `rebalanceDuplicate` returns its drop count).

**Containment, not a fix.** The two caught sub-shapes are now *refused* at
compile time. The source is legal Rúnar; a correct compiler accepts it. The
workaround is the one `merge-locals-prop-updates` already uses — write the
property AFTER the `if`.


---

## 10. What landed — 2026-08-06

The node shipped in all seven tiers. `If` gained an optional ordered
`results: string[]` (deepest slot first); 04-anf-lower computes it as
**merged locals (canonical merge order) ++ arm-written properties (contract
declaration order)** and appends a copy-then-rebind block to BOTH arms that
materialises exactly that list in exactly that order; 05-stack-lower trims each
arm to `results.length`, **asserts** the arms' top-N names equal `results`, and
adopts them by the declared order. `countMergedLocalResults`,
`mergedLocalResultNames` and `branchInPlaceRebindDepth` are deleted in every
tier — the count, the layout and the K=1 in-place special case were all
inference, and the node replaces all three with a declaration.

**When the node engages.** `results` is emitted, and the arms normalised, when
the `if` has no branch outputs, is not a `liftBranchUpdateProps` chain, and
either merges >=2 locals (the pre-existing trigger, kept exactly so the four
`__merge$` goldens keep their bytes) or has a **non-empty else arm** and at
least one result. An `if` without an else keeps `lowerIf`'s
preserve-the-old-value path, which already produces the declared results by
construction — deliberately left intact, and measured correct across the whole
arm-shape sweep.

**What this note got wrong.**

- **The defect set was much larger than §6 and §9 described.** A 25-cell K=1
  arm-shape sweep (5 then-arm styles x 5 else-arm styles x both spender
  branches x both fold modes) found **20 interpreter-vs-VM divergences at
  HEAD**, every one a *guard bypass* (`interpreter=false vm=true`). All of them
  are one shape: one arm rebinds its local IN PLACE (net depth 0) while the
  other pushes a fresh slot (net +1), so phase 3 padded the shorter arm with an
  EMPTY push and the parent registered that as the merged value. Defect #8 is
  one cell of that grid, not a singular finding. A parallel stateful sweep found
  six more broken shapes the note never named: two arms writing the same
  properties in a DIFFERENT order, two arms writing DIFFERENT property sets, an
  empty THEN arm with a non-empty else, and a local rebound in one arm beside a
  property written in the other.
- **§5's scorecard on P2 was too cautious.** `branchInPlaceRebindDepth` is fully
  subsumed and deleted; so are `countMergedLocalResults` /
  `mergedLocalResultNames` and the whole "recognise the trailing `__merge$`
  block" convention as an *inference* (the block itself survives as the
  materialisation mechanism, which is what keeps the ANF interpreters unchanged).
- **§4's byte-movement estimate was pessimistic in one direction and blind in
  another.** Only **2** script goldens move (`if-else` 14 -> 20,
  `branched-readonly-len` 1086 -> 1096) and **6** ANF goldens (the four
  `__merge$` fixtures gain the `results` field and nothing else). But §4 never
  considered `liftBranchUpdateProps`: appending the normalisation block breaks
  that pass's recogniser (it needs the arm's last binding to be the
  `update_prop`, with everything before it side-effect free), which silently
  disabled the C20 lift for TicTacToe's position dispatch and produced an
  **unspendable `move` script**. The fix is to exclude liftable `if`s from
  declaring results — they are rewritten into flat single-valued `if`s anyway —
  and it is also why `selector` (985 bytes) and TicTacToe (9494 bytes) do NOT
  move.
- **§3's "the seven SDK ANF interpreters must change" is wrong.** They need no
  change at all: the normalisation block is ordinary bindings (a read then a
  write of a value the arm already holds), so every interpreter executes it
  correctly without knowing `results` exists. What DOES need touching per tier,
  beyond the four files in the CLAUDE.md checklist, is the **constant folder**
  (every tier rebuilds the `if` node and must carry `results` through — four
  tiers silently dropped it and diverged fold-ON until fixed) and, for two
  tiers, the ANF **JSON codec**: Ruby's `--emit-ir` has an explicit field list
  and Python's from-dict loader has explicit field handling, so both omitted
  `results` and broke `--ir-parity` until listed.

**What it still does not fix.** §5's P3/P4 verdict stands: `collectLoopCarriedRebinds`
and `flattenNestedLoopBodies` are loop-carried liveness, not branch results, and
are untouched. And an `if` whose arm emits outputs still refuses every
combination that would need a second result (`branchOutputRejectionReason`) —
lifting that is a separate change, because the output-bytes slot would have to
join the result list and `drainBranchPrivateResidue` interacts with it.

---

## 11. Adversarial review of §10 — 2026-08-06

An independent review of the landed node found two P0s and three P1s, all in
the BOUNDARY the change drew around itself rather than in its mechanism. What
the remediation measured:

**The exclusion was wider than the rewrite it deferred to — twice.** §10 says
liftable `if`s are excluded "because they are rewritten into flat single-valued
`if`s anyway". That was true of the ones the lift REWRITES and false of the ones
its collector merely RECOGNISES, and the gap had two halves:

- `collectUpdateBranches` returns a **ONE-element** list on the
  `isAssertFalseElse` path, but `liftBranchUpdateProps` only rewrites at **>= 2**.
  So `if (n > 0n) { this.count = ... } else { assert(false) }` — the idiomatic
  guard — was recognised, excluded, and then not rewritten. It declared no
  results, the arm's `update_prop` kept the property's stale slot, and
  `lowerGetStateScript`'s `findDepth` resolved the property to the TOPMOST slot,
  so the continuation committed the PRE-call value: a permanently unspendable
  UTXO. Deleting the `else` made it correct.
- `liftBranchUpdateProps` walks `method.body` and does not recurse, while
  `declaresResults` is evaluated at every nesting depth. The same chain one
  `for` deeper, or inside another arm, was recognised everywhere and rewritten
  nowhere.

Both are fixed by making the exclusion mean what it says: `!ctx.nested && lifted
!== null && lifted.length >= 2`. That needs one more piece, because a chain's
DEEPEST `if` is nested by definition and therefore now declares results and
carries a `__merge$` block — which the lift's recogniser reads as a second
`update_prop` and rejects, silently disabling the C20 lift for the whole chain.
Measured, not assumed: the naive `length < 2` fix alone moved TicTacToe by +464
bytes (the unspendable-`move` regression §10 warned about) and `selector` by
-10. `collectUpdateBranches` therefore strips a declared block before matching
(`stripDeclaredResults`), after which the chain is recognised and lifted exactly
as before and the lift discards the inner node, block and all.

**Cost: ONE golden, and it is temp numbering only.** A 338-entry sweep (every
conformance fixture and every `.runar.ts` in the repo, both fold modes) shows
ZERO script-hex movement. `conformance/tests/selector/expected-ir.json` shifts
every `tN` by one, because the chain tail's block emits its `update_prop` under
a fresh temp and `liftBranchUpdateProps` starts its own naming one higher. All
seven tiers produce the identical new ANF.

**§9's layout invariant is still NOT landable, and its prediction was wrong.**
§9 recorded 37 failures across 18 files and attributed all of them to the K=1
alias rebind, which §10 deleted **for declaring `if`s only**. Re-run at HEAD:
the "parent model == arms' model minus the result slots" invariant fails **41
test files** (37 `branch layout mismatch` occurrences in the run log). The alias
path at `04-anf-lower.ts`'s `if (!declaresResults)` is still live for every
non-declaring `if` — which is every `if` without an else, and every lifted
chain — so it still moves slots by design. An arms-vs-arms variant narrows the
fixture corpus to three contracts, but one of them is TicTacToe, which is proven
spendable on a regtest node, so that form is over-strict too.

**The shape §9 called "P1-1" was real, and it is now CLOSED (R-133).** This
paragraph used to open "is real, and it is OPEN", and it stayed that way for
three weeks after the fix landed — long enough for an independent review to
raise a CRITICAL finding off it that then had to be withdrawn. A stale "OPEN"
misdirects remediation exactly as badly as a stale "RESOLVED" hides a defect,
so the retraction is recorded here rather than by deleting the paragraph.

The shape: reduced to `if (c1) { if (c2) { a = 5n } else { a = 6n } }` with a
live sibling local, the inner `if` declares its one result and its adopt loop
physically ROLL+DROPs the stale slot out of the region the arm INHERITED from
the enclosing arm. The enclosing `lowerIf` reconciles by name set and by depth,
and neither sees a middle slot removed and a same-named slot appearing on top.
The two arms of the OUTER `if` then left the same DEPTH with different LAYOUTS,
and the else-path compiled to an unspendable script. Confirmed pre-existing at
`4b0f688f` (identical failure with the fix reverted).

**The fix is `9cfd953f`** — "fix(stack-lower): restore inherited slot order
after adopting declared results", `05-stack-lower.ts:2543-2568`, which turned
the twelve pinned failures green. The reduction is checked in and LIVE at
`packages/runar-testing/src/__tests__/nested-declared-results-arm-layout-vm.test.ts`
(6 cases, no skips; its post-state values are derived from the source by hand
rather than read back from compiler output, so a regression goes red there
immediately). `r133-p11-doc-not-stale.test.ts` pins this paragraph and that
suite to each other so they cannot drift apart again.

**Two containment gaps closed, both byte-neutral.** The ANF wire format has no
version field, so a pre-`4b0f688f` ANF (a legitimate `--ir` / `--ir-parity`
input) loaded cleanly with `results` absent and the result count silently fell
back to counting the arm's untrimmed block residue; all seven tiers now refuse a
`__merge$` block without `results`. And `results` could contain the SAME NAME
TWICE — a `let count` beside `this.count` yields `['count','count']`, both
emitted as `load_prop`/`update_prop`, so the local's value was silently replaced
by the property's while the layout assertion passed on coincidentally-equal
names. Verified accepted end-to-end before fixing. All seven tiers now refuse
the source shape, and the stack lowerer additionally refuses a duplicated
declared list arriving as `--ir` data.
