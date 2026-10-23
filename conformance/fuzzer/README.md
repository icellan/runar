# Rúnar fuzzers — what each mode actually proves

Every mode is driven from one CLI:

```bash
cd conformance
node_modules/.bin/tsx fuzzer/index.ts --help
```

Read this table before citing a fuzzer as evidence for anything. **The modes do
not all prove the same kind of thing**, and the difference is exactly the gap
that let two fund-safety bugs ship through a green suite in 2026-08
(`docs/audit/2026-08-testing-gap-remediation-plan.md`, reviewer point #6 /
design principle P8).

| Mode | Oracle | Kind | Proves |
|---|---|---|---|
| `--anf` | tier vs tier | **horizontal (parity only)** | All 7 tiers emit byte-identical hex for the same ANF; a finding is delta-debugged (`reduce.ts`) into `program-reduced.json`, which fails with the same reason string as the original `program.json` |
| `--ir` | tier vs tier | **horizontal (parity only)** | All 7 tiers agree at contract level, incl. native frontends |
| `--canonical` | tier vs tier | **horizontal (parity only)** | All 7 SDKs' `canonicalJson` agree byte-for-byte (no module banner: `canonical-json-differential.ts` carries a literal NUL byte in its JCS vectors, so git treats it as binary and any edit becomes unreviewable — this table is its scope note) |
| `--execute` | ANF interpreter vs `ScriptVM` | absolute, **stateless fragments** | Compiled script and source semantics agree on accept/reject |
| `--tri-modal` | interpreter vs `ScriptVM` vs `Spend.validate()` | absolute, **stateless fragments** | Same, plus consensus wrappers, with shrinking |
| `--spend-oracle` | real `@bsv/sdk` `Spend` over a real deploy→call, **plus an independent state model** | absolute, **full tx context + state VALUE** | The spend is really spendable **and** commits the right state |
| `--replay` | checked-in reproducers | regression | A divergence already found cannot come back |
| `metamorphic-fuzz.ts` (standalone driver, `pnpm fuzz:metamorphic` — not a `fuzzer/index.ts` mode) | `ScriptVM` verdict on the original vs on its `metamorphic.ts` transform | absolute, verdict-only, EMI-style | A semantics-preserving rewrite (renamed locals, swapped pure commutative operands) must not change the compiled script's accept/reject verdict |

## Mode inventory: what each mode cannot generate

The table above says what each oracle PROVES. This section says what each
generator cannot REACH, so "the fuzzers are green" is never read as covering
the whole language. Every claim is re-derived from the code at the time of
writing (F-370); `__tests__/f370-fuzz-mode-inventory-doc.test.ts` re-derives the
mode list, the CI steps and the `--anf` kind lists from the live sources and
fails when this section drifts from them. File references are
`conformance/fuzzer/` unless prefixed; "IR generator" is
`packages/runar-testing/src/fuzzer/generator.ts`.

Constructs NO generator in this directory draws (so none of the modes below
covers them; the conformance fixtures and the per-feature tests do): `ternary`
expressions (the contract IR has the node, `contract-ir.ts`, but no generator
emits it), private/helper methods (every generated method is `public`),
`ByteString`-typed properties in the cross-tier modes, any crypto builtin
(`checkSig`, hashes, EC, SLH-DSA, WOTS, BN254, ...), `FixedArray`, property
initialisers, `addRawOutput` / `addDataOutput`, `UnsafeSmartContract` / `asm`
(`raw_script`), and `method_call` ANF nodes. Hand-written conformance fixtures
carry all of those; they are not fuzzed.

### `--anf`

Compares: 7 tiers, final hex, from a generated ANF program. Default is fold-OFF
through each tier's `--ir --hex` (skips every frontend); `--fold-on` instead
renders the same ANF program to `.runar.ts` (`renderAnfProgramToTypeScript`,
`anf-differential.ts`) and compiles it from SOURCE in every tier with constant
folding ON (N-003; `--ir` cannot fold, every tier forces folding off on IR
input). So fold-ON exercises the frontends and the folder on a derived
corpus; fold-OFF exercises the loader, stack lowering and emitter only.

**Generates ANF kinds:** `load_param`, `load_prop`, `load_const`, `bin_op`, `unary_op`, `call`, `array_literal`, `assert`, `update_prop`

**Never generates ANF kinds:** `method_call`, `if`, `loop`, `get_state_script`, `check_preimage`, `deserialize_state`, `add_output`, `add_raw_output`, `add_data_output`, `raw_script`

**Cannot generate:** every program is straight-line. Besides the ten kinds above
(the header comment in `anf-differential.ts` lists only the `if`/`loop` and
stateful-only kinds; `method_call` and `raw_script` are also absent), the only
`call` is `abs`; types are `bigint` and `boolean` only (no `ByteString`, so no
byte ops, no `cat`/`substr`/`len`, no hashes); properties are all `bigint`. A
program that draws `update_prop` is handed to every tier as a
`StatefulSmartContract` (N-395), and the stateful scaffolding the frontend adds
around it (`check_preimage`, `deserialize_state`, `get_state_script`, the
change-output `if`) is exercised INDIRECTLY, but the generator never emits those
nodes itself. `if` / `loop` / `add_output` are reached by `--ir`
(contract-level), not by this mode; `add_raw_output`, `add_data_output`,
`method_call` and `raw_script` are reached by no fuzzer. Oracle: horizontal
(tier agreement) only.

### `--ir`

Compares: 7 tiers on a generated CONTRACT (IR generator), rendered either to one
TS source (`--render ts`, default) or to each tier's native surface
(`--render native`, so each frontend is exercised). Compares final hex with
`--hex`, ANF IR without it. `--stateful` mixes in `StatefulSmartContract`s.
**Fold mode: always OFF.** Every tier is invoked with `--disable-constant-folding`
(and the TS tier with `disableConstantFolding: true`), so no contract-level
cross-tier comparison here ever runs the folder. The legacy default mode is
fold-OFF the same way. Cross-tier fold-ON parity is fuzzed only by
`--anf --fold-on`, on straight-line ANF programs.

`sourceLoc` is stripped ONLY in the ANF-depth compare (no `--hex`):
`sortKeysDeep` in `ir-differential.ts` skips the key, because under
`--render native` every tier compiles a different file. With `--hex` there is
no `sourceLoc` in the compared bytes at all. Source-map fidelity is therefore
NOT compared by any fuzz mode. The legacy default mode (below) strips it the
same way.

**Cannot generate:** only `bigint` and `boolean` properties and parameters
(stateful methods: `bigint` parameters only); expressions are `+ - * / %`
(divisor a non-zero literal), comparisons, `&& || !`, `abs`/`min`/`max`,
`pow` with a literal exponent, `<< >>` with a small literal count, `& | ^`.
No ternary, no `ByteString`, no crypto builtin, no private methods, no
`addRawOutput` / `addDataOutput`; `addOutput` takes satoshis from
`{0, 1000, 1}` and the mutable properties only. Branches are the fixed
`BRANCH_SHAPES` families (`STATEFUL_BRANCH_SHAPES` adds the conditional
property write). Loops are the fixed `IR_LOOP_SHAPES` families (single carrier,
two-carrier cross-read, nested cross-read), at most ONE loop per method, with a
literal bound. `--render native` additionally cannot express countdown
(`step: -1`, `>` / `>=`) or closed-bound (`<=`) loops, so the native strategy
draws ascending unit-step half-open loops only (F-300); only `--render ts`
(`const wide = strategy === 'ts'`) draws the wide loop forms, and no
generator draws `|step| >= 2`. A native-render run's Zig/Rust/Go/Python/Ruby
surfaces for those wide forms are therefore never compared.

### `--execute`

Compares: the AST-walking interpreter against the compiled fold-ON script on
`ScriptVM` (`@bsv/sdk` `Spend`), accept/reject only. **One tier**: the in-process
TypeScript compiler. `execute-differential.ts` imports no `child_process` and
invokes no other tier's compiler, so it says nothing about the six native
compilers (the earlier brief called this out as "TS-only"; it is, by design:
the cross-tier half is `--anf` / `--ir`).

**Cannot generate:** it samples `arbGeneratedContract`, so the same stateless
`bigint`/`boolean` space as `--ir` minus stateful contracts, minus the wide loop
forms, minus `ByteString`, crypto and `addOutput`. Verdict-only: a miscompile
that keeps the script acceptable while committing the wrong state is invisible.
Input values are bigints up to magnitude 70000.

### `--tri-modal`

Compares: interpreter vs `ScriptVM` vs strict `Spend.validate()`, in fast-check
PROPERTY mode with shrinking. One tier (in-process TS compiler), verdict-only.

**Cannot generate:** the dedicated `arbExecCase` corpus: stateless contracts
only, `bigint` / `ByteString` properties and `bigint` / `boolean` /
`ByteString` parameters; loops with `step` of exactly `+1` or
`-1` (`LoopBounds.step: 1 | -1`; no `|step| >= 2`), `substr` / `cat` / `len` /
`reverseBytes` over `ByteString`, post-loop parameter reads and
`EXEC_BRANCH_SHAPES`. No stateful contract, no crypto builtin, no `addOutput`,
no ternary. Cases are constructed to be in-range, so out-of-range arguments to
the byte builtins are never probed.

### `--spend-oracle` (with `--metamorphic`)

Compares: a real deploy then call through the SDK, replayed through real
`Spend.validate()`, with the post-state decoded from the broadcast bytes and
compared with the generator's independent model. One tier (in-process TS
compiler, fold-ON); `spend-oracle.ts` spawns no process.

**Cannot generate:** the fixed `FAMILIES` list in `spend-shapes.ts`
(`REQUIRED_CASE_COUNT` cases, one per family): branch merges k=1..4, ByteString /
negative-bigint / boolean / PubKey state values, multi-slot constructor args,
and loop-carried locals fed to `addOutput`. Loops are `for (i = 0n; i < N; i++)`
with a literal `N` and a unit step only, with an additive body (`l0 = l0 + p0`,
`l1 = l1 + l0`); no countdown, no `|step| >= 2`, no loop body beyond those
forms. The templates are fixed source shapes, not a grammar: no crypto
builtin, no ternary, no private method. `--metamorphic` adds exactly
two rewrites: renamed locals and swapped pure `if/else` arms.

### `--canonical`

Compares: `canonicalJson` (RFC 8785) across the 7 SDKs, byte-identical or an
identical typed rejection, each non-TS tier through its `--canonicalise` shim.

**Cannot generate:** anything but JSON values. No contracts, no compiler is
invoked, and `signEnvelope` / `verifyEnvelope` are not fuzzed (the envelope
fixtures in `conformance/sdk-envelope/` cover those). The PR gate runs six
tiers (Java forks a JVM per case); Java is covered on PRs by
`canonical-java-gate.ts`, below.

### `canonical-java-gate.ts`

Compares: the same fixed-seed `--canonical` corpus (`--num 256`), pushed through
the Java shim's batch entry in one JVM and byte-compared with the TS reference.

**Cannot generate:** its own cases; it regenerates the `--canonical` corpus, so
it inherits that mode's JSON-only scope. Java is the only tier it compares.

### `--replay`

Compares: every checked-in reproducer under `conformance/fuzz-regressions/entries/`
through the `--execute` oracle's differential-execution function.

**Cannot generate:** anything new; it replays pinned verdicts, so it detects a
return of a bug already found and nothing else. CI runs it as
`fuzz-regressions/replay.ts` (the same `runReplayAndReport` the `--replay`
flag calls), not as `fuzzer/index.ts --replay`.

### `metamorphic-fuzz.ts`

Compares: `ScriptVM` verdict of a generated stateless contract against the
verdict of each `metamorphic.ts` transform (identifier rename, commutative
operand reorder, let-introduction, dead-code insertion). One tier, source-text
transforms.

**Cannot generate:** it samples the legacy string generators
(`arbArithmeticContract`, `arbStatelessContract`), so arithmetic and boolean
expressions over `bigint` / `boolean`, `if` statements, no loops, no
stateful contract. A
transform that does not apply cleanly is skipped and counted, not failed.

### `(no mode flag)`

`fuzzer/index.ts` with none of the mode flags runs `differential.ts`, the
original string-based harness (`--property` adds fast-check shrinking). It
compares ANF IR (or hex with `--hex`) across the tiers, `sourceLoc` stripped.
It is NOT run in CI: no workflow step invokes it (`pnpm fuzz` /
`pnpm --dir conformance fuzz:property` only).

**Cannot generate:** one public method `verify`, `bigint` properties, literal
arithmetic and comparisons; no `if`, no loops, no parameters of other types, no
stateful contract. Java is skipped by this harness (it has no structured AST to
re-render as Java; `--ir` does render Java).

### `--property`

The legacy mode above with fast-check property shrinking instead of
`fc.sample`. Not run in CI.

**Cannot generate:** the same space as `(no mode flag)`: it is the same
generator.

### Common flags

`--seed <n>` makes a run reproducible (the effective seed is printed when
omitted); `--verbose` prints each program; `--findings-dir <path>` and
`--output <path>` redirect failing cases and the results JSON; `--inputs <n>`
sets input vectors per method for `--execute`; `--time-budget-ms <n>` early-stops
the budgeted modes (an early-stopped run that did not finish its corpus fails,
it does not report a partial pass); `--replay-filter <s>` narrows `--replay`;
`--help` prints the same list. `--num`, `--compilers`, `--hex`, `--render`,
`--stateful`, `--fold-on`, `--require-tiers` and `--metamorphic` are described
in the sections above.

## Where each mode runs in CI

`PR only` = `if: github.event_name == 'pull_request'`; `non-PR` = the
`schedule` / `push` to main / `workflow_dispatch` triggers (the larger
rotating-seed runs); `every trigger` = no `if` guard. All steps below are in
`.github/workflows/fuzzer-nightly.yml` unless the job is `ts-compiler`
(`.github/workflows/ci.yml`). A seed is "fixed" (424242 or 20020602) on PRs and
`run_id`-derived on non-PR runs. Tiers: all seven unless the row says
otherwise. Step names are matched verbatim by the doc test.

| Step | Job | Placement | Mode | Scope |
|---|---|---|---|---|
| Fuzz (PR gate — fold-OFF, fixed seed) | `fuzz` | PR only | `--anf` | 40 programs, 7 tiers, `--ir --hex` fold-OFF |
| Fuzz (PR gate — fold-ON, fixed seed) | `fuzz` | PR only | `--anf --fold-on` | 40 programs, rendered `.runar.ts`, fold-ON, fails if folding changed no program |
| Fuzz (PR gate — execution oracle, fixed seed) | `fuzz` | PR only | `--execute` | 60 contracts, TS tier only |
| Fuzz (PR gate — tri-modal execution oracle, fixed seed) | `fuzz` | PR only | `--tri-modal` | 200 property runs, TS tier only |
| Fuzz (PR gate — contract-level IR -> hex, fixed seed) | `fuzz` | PR only | `--ir --hex --render native` | 40 stateless contracts, 7 tiers |
| Fuzz (PR gate — stateful contract-level IR -> hex, fixed seed) | `fuzz` | PR only | `--ir --hex --stateful --render native` | 40 contracts, 7 tiers |
| Fuzz (ANF differential, all 7 tiers) | `fuzz` | non-PR | `--anf` | rotating seed, fold-OFF only (no nightly `--fold-on`) |
| Fuzz (execution oracle, rotating seed) | `fuzz` | non-PR | `--execute` | 500 contracts, TS tier only |
| Fuzz (tri-modal execution oracle, rotating seed) | `fuzz` | non-PR | `--tri-modal` | 1000 property runs, TS tier only |
| Fuzz (contract-level IR -> hex, rotating seed) | `fuzz` | non-PR | `--ir --hex --render native` | 200 contracts, 7 tiers |
| Fuzz (stateful contract-level IR -> hex, rotating seed) | `fuzz` | non-PR | `--ir --hex --stateful --render native` | 200 contracts, 7 tiers |
| Fuzz (contract-level ANF-depth compare, rotating seed) | `fuzz` | non-PR | `--ir --render native` | 200 contracts; the only run that compares ANF (`sourceLoc` stripped) |
| Canonical fuzz (PR gate — fixed seed, 6 fast tiers) | `fuzz-canonical` | PR only | `--canonical` | 64 cases, all tiers except Java |
| Canonical Java gate (PR gate — deterministic, one-JVM batch) | `fuzz-canonical` | PR only | `canonical-java-gate.ts` | 256 cases, Java vs TS reference |
| Canonical fuzz (all 7 SDK tiers) | `fuzz-canonical` | non-PR | `--canonical` | rotating seed, all 7 |
| Metamorphic fuzz (fixed seed, hard-fail on divergence) | `fuzz-metamorphic` | every trigger | `metamorphic-fuzz.ts` | 200 cases, fixed seed 424242, TS tier only |
| Spend-oracle (PR gate — fixed seed, metamorphic) | `spend-oracle` | PR only | `--spend-oracle --metamorphic` | 35 cases (one per family), TS tier only |
| Spend-oracle (rotating seed, budgeted) | `spend-oracle` | non-PR | `--spend-oracle --metamorphic` | 400 cases, wall-clock budget, TS tier only |
| Fuzz harness unit guards (conformance/fuzzer/__tests__) | `spend-oracle` | every trigger | vitest | generator reachability and gate-pin tests, incl. this inventory |
| Fuzzer regression corpus replay | `ts-compiler` | every trigger | `--replay` equivalent | all checked-in reproducers, deterministic (`ci.yml`) |
| Fuzzer regression corpus — entries are never deleted (rule 3) | `ts-compiler` | every trigger | replay guard | fails on a deleted entry vs the merge-base (`ci.yml`) |

What the table implies: cross-tier fold-ON parity runs only for the `--anf
--fold-on` corpus (straight-line programs; the contract-level `--ir` runs are
fold-OFF), while the oracles that do compile fold-ON (`--execute`,
`--tri-modal`, `--spend-oracle`, `metamorphic-fuzz.ts`) are TS-tier only, so
fold-ON on a contract with branches or loops is never compared across tiers by
any fuzz mode. The cross-tier ANF-depth compare and every rotating-seed run happen
only after merge; those four oracles never run a native tier, so a divergence confined to one
native compiler is only visible to the horizontal `--anf` / `--ir` modes and the
conformance suite.

## A skipped tier is a failure, not a smaller run (`--canonical`)

Every non-TS tier in `--canonical` is discovered by probing for its toolchain or
shim binary. A tier that is not found used to be marked `skip`, dropped from the
comparison, and neither warned about nor counted — so a run that never touched
Zig still printed `Mismatches: 0` and exited **0**:

```
Tiers: ts=ok go=ok rust=ok python=ok zig=skip ruby=ok java=ok     # exit 0
```

A gate meant to establish SEVEN-tier parity reporting success having established
six. `canonicalJson` is a **wire** primitive — one divergent byte breaks every
cross-tier signature — so "we did not check that tier" must never read as "that
tier agrees".

`--require-tiers` closes it. It defaults to **every tier in `--compilers`** (all
7 for a bare run), and a required tier that was not compared — shim missing, or
not requested — fails the run before any case executes:

```
Tiers:    ts=ok go=ok rust=ok python=ok zig=SKIP ruby=ok java=ok
Required: ts,go,rust,python,zig,ruby,java
INCOMPLETE RUN: required tier(s) zig were NOT compared …          # exit 1
```

The Zig shim is the one that needs an explicit build; the other five are built
lazily on first invocation:

```bash
cd packages/runar-zig && zig build canonicalise
```

`--require-tiers none` opts out for local exploration. Never use it in CI: both
`--canonical` steps in `.github/workflows/fuzzer-nightly.yml` name their tiers
explicitly, so narrowing the set is a visible diff rather than a silent skip.

## Horizontal parity fuzz is NOT fund-safety-complete on its own

`anf-differential.ts`, `ir-differential.ts`, `canonical-json-differential.ts`
and `tri-modal-differential.ts`'s cross-tier half compare **tier against tier**.
Seven compilers (or seven SDKs) that share one bug agree with each other
perfectly and every one of those fuzzers stays green.

That is not hypothetical. Both bugs fixed in `23ef2d2b` were of exactly that
shape:

- **branch-merged locals** — miscompiled identically by all 7 compilers;
- **state-section MINIMALDATA framing** — changed identically in all 7 SDKs
  (`#110`), encoder *and* decoder, so every round-trip test stayed green too.

Keep these modes. They catch real divergences and they are cheap. Just do not
report "the fuzzers are green" as evidence that generated contracts are
**spendable** or that their post-spend state is **correct** — no horizontal mode
makes either claim, and neither does a round-trip.

## What closes the gap

`--execute` / `--tri-modal` add an **absolute** oracle (the real engine), but
they are scoped to **stateless** fragments run against a synthetic transaction
context, and they compare **verdicts only**. A miscompile that leaves the script
acceptable while committing the WRONG continuation state is invisible to a
verdict-only comparison.

`--spend-oracle` (`spend-oracle.ts` + `spend-shapes.ts`) is the mode that covers
the rest:

1. **Construct-biased generation** (Phase E2, `spend-shapes.ts`) — multi-local
   branch merges (k=1/2/3+, both-arms, asymmetric, if-without-else, nested-if);
   1-byte OP_N-range / `0x00` / empty / out-of-range / multi-byte `ByteString`
   state; **negative** `bigint` state; multi-slot constructor args including a
   slot whose encoded length differs from its 1-byte template placeholder so
   later slot offsets shift.
2. **A real transaction** — compile fold-ON, deploy and call through the SDK
   with a real `LocalSigner`; `MockProvider` replays every broadcast through
   real `Spend` (default-on since Phase A1) and the harness re-validates the
   contract input itself.
3. **A value pin that the pipeline cannot poison** — the post-state is compared
   in BYTES, taken from the broadcast call transaction, against the
   **generator's own model** of what the contract should do, encoded by a
   **second, independent implementation** of the state-section wire format.

Point 3 is the whole reason the job exists, so it is worth being explicit about
what would have made it worthless:

> The SDK computes the next state by running the artifact's ANF
> (`anf-interpreter.ts`), and the covenant that validates the spend was compiled
> from the **same** ANF. An ANF-level miscompile corrupts both sides
> identically — the SDK writes the stale value, the on-chain `hash256(outputs)`
> check is satisfied by it, `Spend` accepts, and `contract.state` reports it
> back. Any expectation read out of `contract.state`, out of
> `extractStateFromScript`'s round trip, or out of a second run of the pipeline
> is **derived from the bug and confirms it**.

So the expectation is decided by the generator *before* any compilation, and the
comparison never touches `runar-sdk`'s `serializeState`. Where a shape cannot be
modelled independently it is simply not modelled (`expectedState: null`); no
self-confirming check is emitted.

### Failure kinds

| Kind | Meaning |
|---|---|
| `reject-when-accept-intended` | Real `Spend` rejected a spend the generator intended to accept — unspendable contract from idiomatic source |
| `accept-when-reject-intended` | Real `Spend` accepted a spend the generator intended to reject |
| `interpreter-vs-spend` | The ANF interpreter and the real engine disagree |
| `deploy-state-mismatch` | The DEPLOYED state section differs from the independently encoded bytes (the PALMER-2 framing class) |
| `expected-state-mismatch` | The spend was **accepted** but the continuation commits a state the generator never asked for (the quiet-corruption class) |
| `metamorphic-divergence` | A semantics-preserving rewrite (renamed locals, swapped pure `if/else` arms) changed the verdict or the state (Phase E4, `--metamorphic`) |
| `vacuous-validation` | The pass/failure never actually reached the script guard |
| `compile-error` / `harness-error` | The compiler or the harness threw |

### Running it

```bash
cd conformance
# PR gate: fixed seed, deterministic, ~3s. `--num` must be at least
# `REQUIRED_CASE_COUNT` (spend-shapes.ts): families are drawn round-robin, so a
# smaller run never reaches the tail families.
node_modules/.bin/tsx fuzzer/index.ts --spend-oracle --metamorphic --seed 424242 --num 35

# Longer sweep
node_modules/.bin/tsx fuzzer/index.ts --spend-oracle --seed 1 --num 500 --time-budget-ms 240000
```

Findings land in `conformance/fuzz-findings-spend/<seed>-<index>-<kind>/`
(rendered source + `finding.json` with the args, the expected and actual state
bytes, and the engine error). Every failure prints the exact replay command.
Promote a reduced repro to `conformance/fuzz-regressions/` the same way as any
other fuzz finding — see `conformance/fuzz-regressions/README.md`.

### CI

- **PR** — fixed seed `424242`, 35 cases (== `REQUIRED_CASE_COUNT`, one per
  construct family), `--metamorphic`. Deterministic, no
  native toolchains needed (in-process TS compiler + `@bsv/sdk`).
  The workflow carries that count as a literal, so
  `__tests__/spend-oracle-num-gate.test.ts` pins every `--spend-oracle` step's
  `--num` — and this README's — at or above `REQUIRED_CASE_COUNT`. Adding a
  family reddens that test until both places are updated.
- **Nightly / push** — rotating `run_id`-derived seed, 400 cases, with a
  wall-clock budget. An early-stopped run that did not finish its corpus FAILS
  (same C5 rule as the other budgeted modes) rather than reporting a partial
  pass, and a run in which nothing reached the engine fails as vacuous.

Both live in `.github/workflows/fuzzer-nightly.yml`, job `spend-oracle`.

## Known gap in the corpus (honest residual)

Under a deliberate re-introduction of the branch-merged-locals ANF bug, this
corpus reports the **loud** faces (compile error, script rejection,
interpreter-vs-Spend disagreement) on hundreds of cases but has not yet produced
the **quiet** face (accepted spend + stale state) for that specific mutation —
the stack misalignment the same bug causes rejects the script first. The
`expected-state-mismatch` pin is not dead code: an ANF miscompile that keeps the
stack shape intact (a merged-local result *ordering* error) does trigger it. If
you are extending the corpus, shapes where a stale value has the same encoded
width as the fresh one are the ones most likely to reach the quiet face.
