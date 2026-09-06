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
| `--anf` | tier vs tier | **horizontal (parity only)** | All 7 tiers emit byte-identical hex for the same ANF |
| `--ir` | tier vs tier | **horizontal (parity only)** | All 7 tiers agree at contract level, incl. native frontends |
| `--canonical` | tier vs tier | **horizontal (parity only)** | All 7 SDKs' `canonicalJson` agree byte-for-byte (no module banner: `canonical-json-differential.ts` carries a literal NUL byte in its JCS vectors, so git treats it as binary and any edit becomes unreviewable — this table is its scope note) |
| `--execute` | ANF interpreter vs `ScriptVM` | absolute, **stateless fragments** | Compiled script and source semantics agree on accept/reject |
| `--tri-modal` | interpreter vs `ScriptVM` vs `Spend.validate()` | absolute, **stateless fragments** | Same, plus consensus wrappers, with shrinking |
| `--spend-oracle` | real `@bsv/sdk` `Spend` over a real deploy→call, **plus an independent state model** | absolute, **full tx context + state VALUE** | The spend is really spendable **and** commits the right state |
| `--replay` | checked-in reproducers | regression | A divergence already found cannot come back |

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
node_modules/.bin/tsx fuzzer/index.ts --spend-oracle --metamorphic --seed 424242 --num 32

# Longer sweep
node_modules/.bin/tsx fuzzer/index.ts --spend-oracle --seed 1 --num 500 --time-budget-ms 240000
```

Findings land in `conformance/fuzz-findings-spend/<seed>-<index>-<kind>/`
(rendered source + `finding.json` with the args, the expected and actual state
bytes, and the engine error). Every failure prints the exact replay command.
Promote a reduced repro to `conformance/fuzz-regressions/` the same way as any
other fuzz finding — see `conformance/fuzz-regressions/README.md`.

### CI

- **PR** — fixed seed `424242`, 32 cases (== `REQUIRED_CASE_COUNT`, one per
  construct family), `--metamorphic`. Deterministic, no
  native toolchains needed (in-process TS compiler + `@bsv/sdk`).
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
