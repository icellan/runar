# Phase 3w-c Gap Analysis: Lean Pipeline vs TS Reference

**Status as of 2026-04-26**: 0 / 46 byte-exact matches (0 / 31 SimpleANF subset).

This document identifies the concrete gaps between the verified Lean
pipeline (`Lower → Peephole → Emit`) and the TypeScript reference
(`packages/runar-compiler/src/passes/05-stack-lower.ts` and
`packages/runar-compiler/src/optimizer/peephole.ts`). The goal is a
prioritized punch list — not patches.

## Method

A temporary debug runner (since deleted) was used to dump
Lean's `compileHex` against `expected-script.hex` for 8 simple-looking
SimpleANF fixtures: `basic-p2pkh`, `arithmetic`, `boolean-logic`,
`bitwise-ops`, `if-else`, `if-without-else`, `shift-ops`, `math-demo`.
Across all eight:
- Lean's emitted hex was either `7676527976` (5B) — the trivial constructor
  body — or some short variant unrelated to the expected output.
- Expected hex sizes ranged from 5B (basic-p2pkh) up through 96B
  (bitwise-ops) and 4322B (math-demo).

The dominant root cause is structural, not micro-optimization: Lean lowers
the *first* method, which in conformance fixtures is always the
auto-generated `constructor`. The TS reference filters constructors out
entirely before emit. Until that single bug is fixed, byte-exact matching
on the SimpleANF subset is unreachable; once fixed, ~14 of the 31 simple
fixtures should approach byte-exact and the remaining gaps are
liveness/peephole driven.

## Punch List (top 5 by impact)

### Gap 1 — Lean lowers the constructor instead of public methods (BLOCKER)

**Problem.** `RunarVerification/Stack/Lower.lean:299-301` lowers every
method in `p.methods.map lowerMethod`. `RunarVerification/Script/Emit.lean:200-203`
then emits *only the head* of that list. In every conformance IR the head
method is `constructor` (which TS strips entirely). Result: every fixture
emits the constructor's prologue — typically `7676527976` —
instead of the public method body.

**TS reference.** `packages/runar-compiler/src/passes/05-stack-lower.ts:4863-4875`
filters `method.name !== 'constructor' && !method.isPublic` before
`lowerMethod` is called. `06-emit.ts:558` re-asserts the same filter
(`m.name !== 'constructor'`).

**Fix.** Filter constructors and private methods out in
`Stack.Lower.lower` before mapping over `p.methods`. For multi-method
contracts also implement the dispatch chain in
`Script.Emit.emit` (`06-emit.ts:605-637`: `OP_DUP <i> OP_NUMEQUAL OP_IF
OP_DROP <body> OP_ELSE … OP_NUMEQUALVERIFY <last> OP_ENDIF*`). Without
dispatch, multi-method fixtures (`arithmetic` is single-method but
`bitwise-ops`, `multi-method`, `auction`, `escrow`, `shift-ops` are
multi-method) still mismatch.

**Effort.** S for the filter (one-line change in `lower`); M for the
multi-method dispatch chain.

**Expected impact.** Single largest unlock. Without it, 0 / 31 SimpleANF
match. With it, optimistically 6-10 simple single-method fixtures
(basic-p2pkh, escrow, oracle-price, ec-unit, sphincs-wallet,
post-quantum-wots, etc., once their other gaps are also closed) become
reachable; multi-method fixtures unlock once the dispatch chain lands.

---

### Gap 2 — No liveness analysis; loads always copy (PICK/OVER/DUP) instead of consuming (ROLL/SWAP)

**Problem.** `Stack.Lower.lean:153-158` (`loadRef`) emits
`dup` / `over` / `pick d` based purely on stack depth. The TS reference
at `05-stack-lower.ts:797-847` (`bringToTop`) selects between
`pick`/`roll` (and `over`/`swap`/`rot`) using a per-binding `consume`
flag, derived from `computeLastUses` (`05-stack-lower.ts:247-258`).
The `lowerLoadParam` / `lowerBinOp` / `lowerLoadConst` callers all pass
`isLastUse(...)`. When a value is consumed at its last use, ROLL frees
the stack slot — so subsequent depths shrink. Lean copies indefinitely,
emitting different (deeper) PICK/OVER patterns and inflating output.

**TS reference.** `05-stack-lower.ts:973-976` (`isLastUse`),
`05-stack-lower.ts:982-1002` (`lowerLoadParam` consumes its source on
last use), `05-stack-lower.ts:1088-1106` (`lowerBinOp` `leftIsLast` /
`rightIsLast`), `05-stack-lower.ts:1032-1070` (`lowerLoadConst` with
@ref aliases is liveness-aware too — `localBindings` discrimination at
line 1046 is critical for IF-branch ref handling).

**Fix.** Add a `LastUses` map (Lean: `RBMap String Nat`), a
`collectRefs : ANFValue → List String`, and a `computeLastUses` over
`List ANFBinding`. Thread the binding index through `lowerBindings` and
`lowerValue`. Replace `loadRef sm name` with `loadRef sm name consume`
where `consume = isLastUse name idx lastUses ∧ name ∈ localBindings`.
Emit `swap` (depth=1, consume) / `rot` (depth=2, consume) / `roll d`
(general consume) on the consume path.

**Effort.** L. Touches all of `lowerValue` cases that consume named
refs; introduces a new state component to thread; updates the simulation
proof in `Stack/Sim.lean`. The TS code is ~150 lines; the Lean
equivalent is comparable plus proofs.

**Expected impact.** Necessary precondition for byte-exactness on
*every* fixture that has more than one consumer of a parameter or temp
(virtually all of them). Combined with Gap 1, plausibly closes
~5-8 simple fixtures (e.g., basic-p2pkh, escrow, oracle-price).

---

### Gap 3 — Missing peephole rules: `OP_3DUP`, `OP_2DUP`/widening, fold-chains

**Problem.** Lean's peephole (`Stack/Peephole.lean`) implements
exactly six rules: `[push, drop]→∅`, `[dup, drop]→∅`, `[swap, swap]→∅`,
`[OP_EQUAL,OP_VERIFY]→OP_EQUALVERIFY`, `[OP_CHECKSIG,OP_VERIFY]→
OP_CHECKSIGVERIFY`, `[OP_NUMEQUAL,OP_VERIFY]→OP_NUMEQUALVERIFY`, plus
double-NOT (`Peephole.lean:394-399`). The TS optimizer
(`optimizer/peephole.ts:49-433`) runs **22 rules to fixed point** plus
recurses into `if`-branches (`peephole.ts:467-479`). Concrete missing
rules whose absence is visible in the goldens:
- `[push 1, OP_ADD]→[OP_1ADD]` (`peephole.ts:92-100`) and `[push 1, OP_SUB]→[OP_1SUB]` (`peephole.ts:105-113`)
- `[push 0, OP_ADD]→[]`, `[push 0, OP_SUB]→[]` (additive identity)
- `[push 0, OP_NUMEQUAL]→[OP_NOT]` (`peephole.ts:336-343`)
- `[OP_DROP, OP_DROP]→[OP_2DROP]` (`peephole.ts:253-261`)
- `[OP_OVER, OP_OVER]→[OP_2DUP]` (`peephole.ts:240-248`)
- `[push 0, roll{0}]→[]`, `[push 1, roll{1}]→swap`, `[push 2, roll{2}]→rot`,
  `[push 0, pick{0}]→dup`, `[push 1, pick{1}]→over` (`peephole.ts:274-317`)
  — **these are already partially anticipated by Lean's `loadRef`**
  emitting `.dup`/`.over` directly, but become essential once Gap 2 is
  closed and `roll d` / `pick d` reappear after the depth-1/2 fast path
- 3-op constant folding `[push a, push b, OP_ADD]→[push (a+b)]` and
  `OP_SUB`, `OP_MUL` variants (`peephole.ts:354-396`)
- 4-op chain folds `[push a, ADD, push b, ADD]→[push (a+b), ADD]`
  (`peephole.ts:402-432`)
- `OP_3DUP` (0x6e) — emerges from `[OP_2DUP, OP_OVER]` or similar; the
  TS encoder also emits `OP_3DUP` directly when three params are loaded
  with all-non-last uses. The arithmetic golden opens with `6e`
  (`OP_3DUP`) and Lean has no rule that ever produces it.
- `if`-branch recursion (`peephole.ts:467-479`) — Lean's `peepholePass`
  is flat; nested `ifOp` ops never get optimized.

**TS reference.** `optimizer/peephole.ts:49-433` (all rules);
`peephole.ts:448-462` (fixed-point driver).

**Fix.** Port the missing rules into Lean as additional `apply*`
passes, compose them in `peepholePass`, and drive to fixed point
(currently Lean's `peepholePass` is a single sweep). Recurse into
`StackOp.ifOp then else?` branches.

**Effort.** M for the rules themselves (each is ~5-10 lines + a
soundness theorem on `runOps`); S for the fixed-point driver; M for
the if-branch recursion + soundness over arbitrary nested IFs.

**Expected impact.** Once Gaps 1+2 land, Gap 3 is the long tail. Not
a binary unlock — it shaves 1-3 bytes per arithmetic operation and is
required for every fixture that uses 1, 2, or 0 as immediate operands
or that has chained adds/subs (arithmetic, boolean-logic, shift-ops,
escrow). Plausibly the difference between "close" and "byte-exact" on
~10 SimpleANF fixtures.

---

### Gap 4 — `loadConst @ref:` aliases do not consume; @this synthesizes a `push 0` placeholder

**Problem.** `Stack.Lower.lean:234-239` treats `.loadConst (.refAlias
n)` as equivalent to `loadRef sm n` (always non-consuming) and
`.loadConst .thisRef` as a no-op stack-name push. The TS reference at
`05-stack-lower.ts:1038-1056` is more nuanced:
  1. `@ref:` aliases consume (ROLL) iff `localBindings.has(refName) ∧
     isLastUse(refName, …)` — so an alias emitted in an IF-branch but
     defined in the outer scope must PICK; an alias to a same-scope
     temp consumes.
  2. `@this` materializes as `push 0n` (`05-stack-lower.ts:1062`), not
     as a stack-map alias to nothing — so the binding sits on top of
     the stack and downstream `loadRef bindingName` finds it at depth 0.

Lean's `.loadConst .thisRef => ([], sm)` instead returns no ops *and*
no push, so the binding name is registered as a synthetic in `sm.push`
inside `lowerValue` — wait, it's `(sm)` not `(sm.push bindingName)`,
which means downstream loads of `bindingName` resolve to
`OP_RUNAR_UNRESOLVED_…`.

**TS reference.** `05-stack-lower.ts:1032-1070` (`lowerLoadConst`),
`856-866` (`localBindings` binding registration in `lowerBindings`).

**Fix.** Mirror the TS branches exactly:
- `.loadConst (.refAlias n)`: `loadRef`-with-consume threaded through
  the same liveness map introduced in Gap 2; `localBindings`
  discrimination requires tracking the current scope's bindings (Lean
  doesn't currently model this — `lowerBindings` doesn't pass scope
  info to `lowerValue`).
- `.loadConst .thisRef`: emit `push 0n` and `sm.push bindingName`.

**Effort.** S (mostly mechanical) but **strictly downstream of Gap 2**
because consume-aware `loadRef` is a prerequisite.

**Expected impact.** Required for every SimpleANF fixture that uses
`@ref:` aliases — that's all of `arithmetic`, `boolean-logic`,
`if-else`, `if-without-else`, `bitwise-ops`, `shift-ops` (since
constructors-stripped public bodies invariably alias temps via `sum =
@ref:t2` etc.). Without this, even fixed Gap 1+2+3 won't byte-match.

---

### Gap 5 — `lowerBindings` does not handle terminal-assert + dispatches `assert` like a regular binding

**Problem.** `Stack.Lower.lean:281-287` always runs `lowerValue` on
each binding. TS `lowerBindings` (`05-stack-lower.ts:856-902`) takes a
`terminalAssert` flag (true for public methods) and finds the *last*
`assert` (or last `if` containing a terminal assert), then lowers that
binding with `terminalAssert=true` so the final assert leaves its
truthy value on top of stack instead of running `OP_VERIFY`. Bitcoin
Script requires the top of stack to be truthy on script termination,
so the trailing `OP_VERIFY` *must* be elided on the very last assert.
The Lean lowering currently always emits `OP_VERIFY`
(`Lower.lean:260-261`), which would leave the public method script
unsatisfiable even after Gap 1.

**TS reference.** `05-stack-lower.ts:856-902` (`terminalAssert`
threading); `05-stack-lower.ts:lowerAssert` honors the flag at the
emission site; the same flag also propagates through
`lowerIf`-of-asserts.

**Fix.** Add `terminalAssert : Bool` parameter to
`lowerBindings`/`lowerValue`. Find the terminal assert / terminal
`ifVal`-of-asserts. Emit `loadRef ref` (no `OP_VERIFY`) for the
terminal one. Update `lower` to pass `m.isPublic` as the terminal
flag.

**Effort.** S-M. Single new flag, one pre-scan over the bindings list,
one branch in `.assert` lowering. Soundness theorem requires
strengthening the `Sim.lean` invariant from "stack empty after assert"
to "stack has truthy top after public method".

**Expected impact.** Without it, *no* public-method fixture is
byte-exact (the trailing `OP_VERIFY` is wrong). With it, plus Gaps
1-4, the simplest single-public-method fixtures (basic-p2pkh,
escrow, oracle-price, ec-unit) should hit byte-exact.

---

## Recommended Implementation Order

1. **Gap 1** (filter constructor + multi-method dispatch). One-line +
   ~30-line dispatch chain. **Without this, none of the others are
   visible.**
2. **Gap 5** (terminalAssert) — small, makes outputs end correctly,
   cheap shape-preservation proof.
3. **Gap 2** (liveness + ROLL/SWAP/ROT) — the deepest, biggest, but
   the byte-exactness foundation for any non-trivial fixture.
4. **Gap 4** (`@ref:` consume + `@this` push 0). Trivially follows
   from Gap 2.
5. **Gap 3** (peephole rule pack + fixed-point + if-recursion). The
   long-tail polish.

After (1)+(5)+(2)+(4) land, an estimated **6-10 of the 31 SimpleANF
fixtures** should byte-match. After (3), an estimated **20-25 of 31**.
The remaining ~6 SimpleANF gaps are likely encoding edge cases
(`OP_PUSHDATA2` for ≥256-byte literals — `Emit.lean:100-104` handles
it but the constants paths in `loadConst` may not exercise it
correctly) and exotic patterns in `bitwise-ops` / `shift-ops` that
need fixture-by-fixture review.

## Appendix: Verified facts

```
$ lake build                               # success
$ lake env lean --run tests/PipelineGolden.lean
running pipeline-golden over: …/conformance/tests
found 46 test fixtures
=== Phase 3a Pipeline Golden Report ===
  total fixtures      : 46
  ANF parse OK        : 46
  WF.ANF OK           : 46
  SimpleANF subset    : 31
  pipeline ran        : 46
  byte-exact hex match: 0
phase 3a pipeline golden: PASS
```

The 31 SimpleANF fixtures are: `arithmetic`, `babybear`,
`babybear-ext4`, `basic-p2pkh`, `bitwise-ops`, `blake3`,
`boolean-logic`, `bounded-loop`, `convergence-proof`,
`cross-covenant`, `ec-demo`, `ec-primitives`, `ec-unit`, `escrow`,
`go-dsl-bytestring-literal`, `if-else`, `if-without-else`,
`merkle-proof`, `oracle-price`, `p256-primitives`, `p256-wallet`,
`p384-primitives`, `p384-wallet`, `post-quantum-slhdsa`,
`post-quantum-wallet`, `post-quantum-wots`, `schnorr-zkp`,
`sha256-compress`, `sha256-finalize`, `shift-ops`, `sphincs-wallet`.
