# Stack scheduler — current behaviour, measured inefficiencies, and a design

**Status:** design, pre-implementation. Companion to
[`script-size-optimization-baseline.md`](script-size-optimization-baseline.md).
**Scope:** the generic ANF → Stack lowering in
`packages/runar-compiler/src/passes/05-stack-lower.ts`. Crypto macro modules
(`ec-codegen.ts`, `p256-p384-codegen.ts`, `sha256-codegen.ts`, `slh-dsa-codegen.ts`, …)
emit Stack IR directly through their own `ECTracker`-family trackers and are **out of
scope for this document** — they are addressed separately by constant pooling.

---

## 1. What the current lowering does

### 1.1 The symbolic stack

`class StackMap` (`05-stack-lower.ts:166`) is an array of `(string | null)`, index 0 =
bottom. `null` marks an anonymous slot (e.g. the discard half of an `OP_SPLIT`).

```ts
findDepth(name): number     // :192 — searches TOP-DOWN, returns depth-from-top
removeAtDepth(d)            // :207 — the ROLL effect
peekAtDepth(d)              // :217 — the PICK effect
clone()                     // :226 — used to fork a branch arm
```

`findDepth` resolves to the *shallowest* match, so rebinding a name pushes a new slot with
the same name and the old one becomes dead-but-resident. `LoweringContext` (`:547`) owns one
`StackMap`, the emitted `ops`, `maxDepth`, and `outerProtectedRefs`. The constructor (`:578`)
seeds the map with parameter names, first param at the bottom.

### 1.2 Liveness

The entire liveness analysis is `computeLastUses(bindings)` (`:276`): one forward scan
mapping each referenced name → the highest binding index that references it. Array-literal
indirection is patched through (`:284`) so element temps stay live to the array's consumer.

Consumption is decided by two predicates:

```ts
isLastUse(ref, i, lastUses)          // :1304  last <= i
operandConsume(ref, operands, i, …)  // :1328  isLastUse AND appears once in this operand list
```

`operandConsume` needs the occurrence check because `t := x + x` must PICK at both positions.

Outer-scope values are pinned by *forcing* their last use past the end:
`lastUses.set(ref, bindings.length)` (`:1154`, and `:2196` for branch arms). That is the only
pinning mechanism.

### 1.3 Materialization — `bringToTop(name, consume)` (`:1038`)

Every operand goes through this one function:

| depth | consume (last use) | !consume (still live) |
|---:|---|---|
| 0 | nothing | `OP_DUP` |
| 1 | `OP_SWAP` | `OP_OVER` |
| 2 | `OP_ROT` | `push 2; OP_PICK` |
| d | `push d; OP_ROLL` | `push d; OP_PICK` |

The depth 0/1/2 peepholes are inlined here, which is why the peephole rules `roll1-to-swap`,
`roll2-to-rot`, `pick0-to-dup`, `pick1-to-over` almost never fire on the main path.

### 1.4 What is *not* done

- **No operand reordering.** `lowerBinOp` (`:1507`) always materializes left then right,
  even for commutative operators, and `lowerCall` (`:1839`) always walks args in order.
- **No proactive dead-value removal.** `computeLastUses` knows exactly when a temp dies;
  nothing acts on it. Dead slots linger until `cleanupExcessStack()` (`:621`) NIPs the method
  tail, or until a branch's `drainBranchPrivateResidue` (`:1112`) sweeps them.
- **No alt stack.** The generic lowerer emits `OP_TOALTSTACK` in exactly three places
  (`:3013`, `:3105` state serialization, and the `divmod` intrinsic at `:4517`). Never for
  scheduling. `docs/compiler-architecture.md` claims otherwise — that paragraph is
  aspirational and should be corrected.
- **No cost model.** Choices are structural, never compared by emitted bytes.

### 1.5 Branches and loops, in one line each

`lowerIf` (`:2092`) forks a cloned `StackMap` per arm, pins every parent value that outlives
the `if`, reconciles asymmetric consumption, trims to the declared `results` layout, pads the
shallower arm with 1-byte empty pushes (`:2400`, `:2405`), and asserts equal arm depth at
`OP_ENDIF`. `lowerLoop` (`:2665`) fully unrolls, recomputing `lastUses` per iteration and
pinning loop-carried refs on every non-final iteration.

Any scheduler change must leave these invariants intact — they are enforced by hard throws
(`branch result layout mismatch` at `:2346`, the Layer B/C depth assertions at `:2417`,
`:2640`), not by tests alone.

---

## 2. Measured inefficiencies

All figures from the 72 checked-in goldens via
`pnpm --filter runar-conformance run script-metrics`.

### 2.1 Stack traffic is 23 % of the corpus — and 35–68 % of ordinary contracts

| fixture | bytes | stack-shuffle share |
|---|---:|---:|
| `arithmetic` | 28 | **67.9 %** |
| `bounded-loop` | 42 | 57.1 % |
| `multisig` | 17 | 58.8 % |
| `if-without-else-multi-temp` | 226 | 55.3 % |
| `stateful-counter` | 1,875 | 35.9 % |
| `token-ft` | 3,154 | 36.1 % |
| `math-demo` | 17,348 | 35.7 % |

### 2.2 The dead-slot hypothesis is **refuted**

The obvious theory — dead values sink under live ones, so later accesses pay a deeper
`push(depth)`, and crossing depth 16 turns a 1-byte depth push into 2 — does not survive
measurement. Across all 387,749 `OP_PICK`/`OP_ROLL` sites in the corpus:

```
depth ≤ 16 : 387,092   (1-byte depth push)
depth > 16 :     657   (2-byte depth push)
deepest anywhere: 75
```

Typical depths are 2–5. On `p256-wallet` every one of the 21,926 depth pushes is a single
byte. **Eager dead-slot retirement would cost 1–3 bytes per drop to save essentially nothing,
and is dropped from the design.** This is the main correction to the original plan.

### 2.3 Where the shuffle bytes actually are

`p256-wallet`: 173,967 shuffle bytes, of which only 43,852 are `PICK`/`ROLL` (op + depth
push). The remaining ~130 kB is bare one-byte shuffles — `OP_ROT`×30,406, `OP_SWAP`×27,342,
`OP_OVER`×23,417, `OP_DROP`×22,558, `OP_2DUP`×20,453 — and ~100 kB of that is the fixed
five-shuffle tail inside `cFieldMod`, i.e. crypto-macro output, not this scheduler.

For the ordinary contracts the picture inverts: `arithmetic` spends 16 of 28 bytes on stack
access, split 8 bytes of depth pushes and 8 bytes of `PICK`/`ROLL`/`ROT`/`SWAP`.

### 2.4 A measured headroom number

`conformance/tests/arithmetic` is the only fixture whose bytes are produced *entirely* by
this pass. Source:

```ts
const sum = a + b; const diff = a - b; const prod = a * b; const quot = a / b;
assert(sum + diff + prod + quot === this.target);
```

Emitted today (28 bytes, `00` = constructor placeholder):

```
OP_2DUP OP_ADD                          sum          [a,b,sum]
OP_2 OP_PICK OP_2 OP_PICK OP_SUB        diff         [a,b,sum,diff]
OP_3 OP_PICK OP_3 OP_PICK OP_MUL        prod         [a,b,sum,diff,prod]
OP_4 OP_ROLL OP_4 OP_ROLL OP_DIV        quot         [sum,diff,prod,quot]
OP_3 OP_ROLL OP_3 OP_ROLL OP_ADD OP_ROT OP_ADD OP_SWAP OP_ADD
<target> OP_NUMEQUAL
```

`a` and `b` are each materialized four times, and every materialization is deeper than the
last because each result is pushed on top of them.

Hand-scheduled alternative (18 bytes) — operands stay in the top two slots, finished results
are parked on the alt stack:

```
OP_2DUP OP_ADD OP_TOALTSTACK            sum   -> alt
OP_2DUP OP_SUB OP_TOALTSTACK            diff  -> alt
OP_2DUP OP_MUL OP_TOALTSTACK            prod  -> alt
OP_DIV                                  quot  (consumes a, b)
OP_FROMALTSTACK OP_ADD                  + prod
OP_FROMALTSTACK OP_ADD                  + diff
OP_FROMALTSTACK OP_ADD                  + sum
<target> OP_NUMEQUAL
```

**28 → 18 bytes, −36 %, and every byte saved is stack traffic.** Both scripts are executed
against the real `@bsv/sdk` interpreter over 14 (a, b) pairs including negatives, zero, and
the 16/17 script-number boundary, in
`packages/runar-testing/src/__tests__/scheduler-headroom.test.ts`; they accept and reject
identically. The number is measured, not estimated.

The three effects that produced it, in order of contribution:

1. **Result spilling to the alt stack.** Keeps the hot operands at depth 0/1, so every
   subsequent access is `OP_2DUP` (1 byte) instead of `push d; OP_PICK; push d; OP_PICK`
   (4 bytes). Worth 3 of the 4 materializations here.
2. **Adjacent-pair fusion.** `(a, b)` at depths 1 and 0 is `OP_2DUP`, not two picks. The
   peephole has an `over,over → OP_2DUP` rule, but the lowerer emits `push;pick;push;pick`,
   which no window can fuse.
3. **Consumption ordering.** Scheduling the one operator that *consumes* `a` and `b`
   (`OP_DIV`) last removes the final pair of `OP_4 OP_ROLL`s entirely.

---

## 3. Design

### 3.1 Representation

Extend the existing analysis rather than replacing it. `computeLastUses` already gives last
use; add, over the same scan:

```ts
interface LivenessInfo {
  lastUse: Map<string, number>;     // existing
  useCount: Map<string, number>;    // total references (excluding array indirection)
  nextUse: Map<string, number[]>;   // sorted binding indices that reference the name
}
```

`nextUse` is what makes "will this value be touched again soon, or not for a while?" a
question the scheduler can answer, and it is the input to the spill decision. It costs one
extra pass over the same bindings.

### 3.2 Scheduling unit: the branch-free run

The prototype operates only on a **maximal run of consecutive bindings containing no `if`
and no `loop`**. A run ends at any control-flow binding, and the stack is restored to a
canonical layout (everything on the main stack, alt stack empty) before that binding is
lowered.

This is deliberate. `lowerIf`'s arm reconciliation, result-layout assertion and depth
balancing (§1.5) are the most delicate code in the backend, and every one of them reasons
about main-stack depth only. Confining spills to branch-free runs means **no arm ever begins
or ends with a non-empty alt stack**, so none of those invariants can be perturbed. It also
means the prototype cannot help inside a loop body — accepted for now; loops are unrolled, so
the runs *between* control flow are still scheduled.

### 3.3 Byte-cost function

`estimateScriptBytes` / `sizeOfStackOp` from `packages/runar-compiler/src/metrics/cost-model.ts`
— already implemented and asserted byte-exact against `06-emit.ts` over the whole corpus
(`__tests__/cost-model.test.ts`). The scheduler's local decisions use these derived costs:

```
accessCost(depth, consume)      = 1                        depth 0 (consume) — free
                                = 1                        depth 0/1/2 via DUP/SWAP/OVER/ROT
                                = sizeOfPushValue(depth)+1 otherwise
pairAccessCost(d0, d1)          = 1                        (a,b) at depths 1,0 -> OP_2DUP
                                = accessCost(d0)+accessCost(d1) otherwise
spillCost                       = 2                        TOALTSTACK + FROMALTSTACK
rematerializeCost(constant)     = sizeOfPushValue(v)
```

### 3.4 Heuristic

Greedy, single forward pass over a run. Not globally optimal, and deliberately so — the
brief asks for a simple greedy implementation first.

For each binding `t := op(x, y)`:

1. **Order the operands.** If `op` is commutative (`+ * === !== && || & | ^`, `min`, `max`),
   order so the operand already nearer the top is materialized second. Ties keep source
   order, so the default mode is unchanged.
2. **Fuse the pair.** If `(x, y)` sit at depths 1 and 0 and neither is consumed, emit
   `OP_2DUP` instead of two accesses. Generalize to `OP_2OVER` for depths 3,2.
3. **Rematerialize instead of accessing.** If `x` is a `load_const` whose push encoding costs
   ≤ `accessCost(depth(x), consume)`, re-push it and leave the resident copy alone.
4. **Spill the result.** After emitting the operation, if the result's `nextUse` is more than
   `SPILL_HORIZON` bindings away *and* at least one still-live value sits below it, park it
   with `OP_TOALTSTACK`. Restore in reverse spill order at the point of use. Spill only when
   `spillCost < projected access savings`, computed from `nextUse` and the current depths.
5. **Restore before a run boundary.** Every spilled value is popped back before any `if`,
   `loop`, or the end of the method.

**As built, step 4 is stricter than this design anticipated.** Spilling is refused outright in
any scope that still has control flow ahead of it, because restoring immediately before an
`if` miscompiled a fixture — see §6. And step 1 is scored by running the candidate op
sequences through the real peephole rather than a byte formula, because the cheapest-looking
local choice is often one the peephole would have erased anyway (§6 again).

The per-site heuristics are backed by a **method-level guard**: both schedules are lowered and
the cheaper one, measured after peephole with `estimateScriptBytes`, is kept. "The scheduler
never grows a method" is therefore a structural property, not a hope — which matters, because
the greedy heuristic cannot tell whether removing one slot actually moves an access across a
cost boundary (depths 0-2 are all one byte).

### 3.5 Gating

`schedulerMode: 'current' | 'liveness'` on `LoweringContext`, plumbed from
`CompileOptions.schedulerMode` (`packages/runar-compiler/src/index.ts:109`) and a CLI
`--stack-scheduler=<mode>` (`packages/runar-cli/src/bin.ts:39`,
`commands/compile.ts:14/84/177/252` — the `--disable-constant-folding` path is the template).

Default is `'current'`, and every new behaviour is a no-op in that mode. This keeps the
72 goldens, `conformance/script-size-baseline.json`, the cross-tier hex parity gate and the
golden-provenance gate untouched while the experiment runs.

---

## 4. Correctness invariants

The scheduler may reorder *materialization*, never *evaluation*. Concretely:

1. **Side-effect order is fixed.** Bindings are lowered in ANF order. Only the stack
   operations that arrange operands may move. `hasSideEffect` (`optimizer/dce.ts:133`) names
   the kinds that must never be reordered relative to each other.
2. **Operand order is preserved for non-commutative operators.** `-`, `/`, `%`, `<<`, `>>`,
   `<`, `>`, `<=`, `>=`, `OP_SPLIT`, `OP_CAT` and every intrinsic keep source order.
   Commutativity is asserted per-operator against the interpreter, not assumed: `OP_ADD` and
   `OP_MUL` are commutative on script numbers; `OP_CAT` is not; `OP_BOOLAND`/`OP_BOOLOR` are
   commutative but **not** short-circuit at this level, so reordering them cannot change
   which side is evaluated (both already are).
3. **Alt stack is empty at every control-flow boundary** and at method exit. Asserted in the
   lowerer, not just tested — a `LoweringContext` invariant check before each `if`/`loop` and
   in `lowerMethod`.
4. **Main-stack depth at `OP_ENDIF` is unchanged.** The Layer B/C assertions (`:2417`,
   `:2640`) stay in force; the prototype must not touch arm reconciliation at all.
5. **`maxStackDepth` may not exceed `MAX_STACK_DEPTH = 800`** (`:63`). Spilling *reduces*
   main-stack depth, but the alt stack shares the interpreter's 1,000-element budget, so the
   sum is what gets checked.
6. **No assertion is weakened.** The scheduler never removes an `assert` binding, never
   changes which value an `OP_VERIFY` consumes, and never elides a normalization
   (`OP_BIN2NUM`, `OP_NUM2BIN`, sign fixups) that a later consumer observes.

---

## 5. Benchmark plan

**Metric:** serialized locking-script bytes, from `estimateScriptBytes` (exact) and confirmed
against the emitted hex.

**Command:**

```bash
pnpm --filter runar-conformance run script-metrics -- --compare current,liveness
```

**Report, per fixture:** script bytes, `OP_PICK` / `OP_ROLL` / `OP_DUP` / `OP_SWAP` /
`OP_2DUP` / `OP_TOALTSTACK` counts, `maxStackDepth` delta.

**Acceptance (from the brief, restated as pass/fail):**

1. Semantically identical Script — proven, not assumed. `scheduler-equivalence.test.ts`
   (modelled on `packages/runar-testing/src/oracle/fold-equivalence.ts`) compiles each source
   under both modes and asserts identical accept/reject through `ScriptVM` plus agreement
   with the mode-independent AST interpreter, over every witness in
   `conformance/witnesses/`. Plus `conformance/fuzzer/index.ts --execute` with the toggle.
2. All existing VM / interpreter tests pass under both modes.
3. No material growth on ordinary fixtures. Fail the experiment if any fixture grows > 1 %.
4. A measurable win on at least one arithmetic-heavy fixture. **Target: > 10 %.**

**Prior expectations, so the result could disappoint honestly:**

| fixture class | expected | **measured** |
|---|---|---|
| `arithmetic` | −20 % to −36 % | **−35.7 %** (28 → 18 B) |
| `bounded-loop`, `boolean-logic` | −20 % to −36 % | −11.9 % (42 → 37 B) / 0 % |
| `math-demo`, `token-ft`, `function-patterns` | −3 % to −10 % | **−0.1 %** |
| stateful fixtures | −1 % to −4 % | −0.1 % to −0.2 % |
| EC / P-256 / P-384 | 0 % | 0 % |
| SLH-DSA / SHA-256 / BLAKE3 | 0 % | 0 % |

`arithmetic` reached 18 bytes — the hand-derived optimum in §2.4 — which the scheduler found
on its own. The mid-size prediction was wrong by an order of magnitude: those contracts do have
a 35 % stack-shuffle share, but almost all of it is sighash and state-serialization macro
output, not ANF chains the scheduler can reach. Their ANF is mostly bindings consumed by the
very next binding, where there is nothing to spill.

So the honest conclusion is the one the plan named as the disappointing case: **the generic
scheduler is worth having for small arithmetic contracts and little else**, and the remaining
shuffle budget belongs to the macro emitters. Corpus-wide it moves 34 of 72 fixtures and
−0.0 % of total bytes. It is kept as a gated mode, not proposed for a 7-tier port.

---

## 6. What went wrong, and what caught it

### A miscompile, caught by the witness corpus

The first working scheduler **miscompiled `if-without-else-multi-temp`**: the script ran to
completion, left a truthy top-of-stack, and **accepted a witness the shipping compiler
rejects**. Byte counts, the goldens for every other fixture, and 4,099 compiler unit tests all
passed while that was true.

`conformance/witnesses/` replayed through `runDifferentialExecution` caught it — deployed
script versus the ANF interpreter, on witnesses the repo had already committed to, with at
least one accept and one reject per fixture. Two of 86 cases failed.

Cause: restoring spilled values immediately before an `if` leaves the parent stack in a shape
`lowerIf`'s arm reconciliation, declared-result trim and Layer B/C depth invariants were not
written for. The fix is the precondition in §3.4 — refuse to spill in a scope with control
flow ahead of it — rather than an attempt to make the two agree.

### Two things worth remembering

**A passing bisect can be vacuous.** Turning off commutative reordering made the failure
disappear, which looked like an acquittal for spilling. It was not: with reordering off, the
method-level cost guard simply preferred the baseline schedule, so no spilling happened at
all. Only after confirming the variant still changed the emitted bytes did the second bisect
mean anything.

**The cost model had to be peephole-aware.** Two consumed operands at depths 1 and 0 emit
`OP_SWAP OP_SWAP`, which the `swap-swap` rule deletes outright — free — while the
"cheaper-looking" reversed order emits one real `OP_SWAP` and costs a byte. Scoring candidate
op sequences through `optimizeStackIR` before comparing them took `arithmetic` from 24 bytes
to 18.
