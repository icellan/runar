# Testing Guide

This guide covers how to test Rúnar smart contracts at every level, from unit tests of individual contracts to property-based fuzzing and cross-compiler conformance testing.

Read [Layers of assurance](#layers-of-assurance) first. It is the part of this
guide that says which of the tools below actually prove a contract is
spendable, and which only prove that seven implementations made the same
choice. Getting that distinction wrong is how the two 2026-08 fund-safety bugs
shipped through a green CI net.

---

## Layers of assurance

Rúnar's test suite has three structurally different kinds of gate. They are
**not** interchangeable, and a claim of the form "this is covered" is only
meaningful once you say *which layer* covers it.

| Layer | The question it answers | Examples in this repo |
|---|---|---|
| **Horizontal** | Do the independent implementations of the same thing agree with *each other*? | `conformance/tests/**` (7 compilers, byte-identical IR + hex), `conformance/sdk-output/**` (7 SDKs, byte-identical locking script), `conformance/fuzzer` `--ir` / `anf-differential` (tier vs tier) |
| **Vertical** | Does one component agree with the *other side of the same boundary*? | `conformance/sdk-vertical/**` (compiler artifact ↔ SDK splice / codesep), `conformance/sdk-output/tests/stateful-bytestring-op-n-state` (compiler state framing ↔ SDK `serializeState`), `conformance/sdk-bip143` (TS reference preimage ↔ six consumers) |
| **Absolute execution** | Would the Bitcoin network accept these exact bytes, and what state do they leave behind? | `conformance/witnesses/real-crypto/*.json` (real `@bsv/sdk` `Spend` + real secp256k1 + `expectedState`), `MockProvider`'s default broadcast validation, `conformance/script_execution_test.go`, `integration/**` on regtest, `conformance/fuzzer --spend-oracle` |

### Horizontal agreement proves agreement, not correctness

All seven tiers can be identically wrong, and the suite will be entirely
green while they are. This is not a hypothetical risk; it is the observed
failure mode of both 2026-08 fund-safety bugs.

**PALMER-1 — branch-merged locals.** An `if` statement carries exactly one
value, so when a method merged **two or more** locals across a branch, ANF
lowering kept post-branch references pointing at the dead pre-branch binding
and stack lowering registered one `stackMap` slot for N physical results. All
seven compilers produced byte-identical output, so every horizontal gate was
green. Worse, the bug has two faces:

- *Face A* — the script is unspendable. Any accept/reject oracle catches this
  once a fixture of that shape exists. None did.
- *Face B* — the script **validates**, and silently commits the wrong
  continuation state. Accept/reject agreement cannot see this at all: the
  interpreter and the compiled script both "accept" the same wrong answer.

**PALMER-2 — state-section framing.** Issue #110 taught all seven SDKs the
MINIMALDATA rule for the state section (`0x05` written as `OP_5`) and none of
the seven compilers (which read `<len><data>`). Every round-trip test stayed
green, because `deserialize(serialize(x)) === x` holds for *any*
self-consistent framing including a wrong one. Cross-SDK conformance stayed
green, because all seven SDKs moved together. **Zero goldens moved.** Any
contract carrying a 1-byte `0x01`–`0x10` ByteString state value became
permanently unspendable.

### Which gate catches each one now

| Bug | Gate that now catches it | Where |
|---|---|---|
| PALMER-1 Face A (unspendable) | Conformance fixtures of that shape + the source-vs-script differential oracle | `conformance/tests/merge-locals-shapes`, `merge-locals-prop-updates`, `branch-merged-locals`; `witnesses/differential.test.ts` |
| PALMER-1 Face B (wrong state, still accepted) | Real-crypto witness with a hand-authored `expectedState`, machine-required for every stateful accept | `conformance/witnesses/real-crypto/branch-merged-locals.json`; enforced by `witnesses/coverage-claims.test.ts` + `real-crypto-execution.test.ts` |
| PALMER-1 (as a *class*, not a fixture) | Construct ledger row + mutation mutants + Spend-oracle fuzz | `conformance/construct-ledger.json` (`merge-locals-*`), mutants `anflower-merge-locals-single-only` / `stacklower-merge-locals-property-only`, `conformance/fuzzer --spend-oracle` |
| PALMER-2 (framing) | Compiler↔SDK vertical pin + a 1-byte OP_N-range state fixture + wire-primitive register | `conformance/sdk-output/tests/stateful-bytestring-op-n-state`, `conformance/sdk-vertical/**`, `conformance/wire-primitives.json` (`state-section-framing`) |
| PALMER-2 (the *process* hole: zero goldens moved) | Must-move-a-golden gate | `conformance/scripts/wire-format-pr-audit.ts`, `wire-format-must-move-golden` CI job |
| Both (as regressions) | Mutation corpus with `expectCaughtBy` gates | `conformance/mutation/mutants.json` (`sdkstate-encode-minimaldata-opn`, `sdkstate-decode-opn-as-length`, …) |

The rule that falls out of this, and which the rest of the guide applies:

> **New parity work that only extends a horizontal matrix, without a vertical
> pin or an absolute execution pin for the same family, is incomplete for
> fund-safety.**
> (`docs/audit/2026-08-testing-gap-remediation-plan.md` §2 P7.)

---

## Broadcast validation is on by default

`MockProvider` (`packages/runar-sdk/src/providers/mock.ts`) **validates every
transaction you broadcast through it**, by default, with no flag. It:

1. replays each input whose UTXO it knows about through `@bsv/sdk`'s
   production `Spend` interpreter (real secp256k1, real BIP-143 sighash);
2. **fails closed** if a tx has inputs but *none* of them could be validated —
   an entirely-unregistered-input broadcast is not "passing validation", it
   never ran a script (register funding UTXOs with `addUtxo()` /
   `addContractUtxo()` / `addTransaction()`);
3. when every input is known, rejects an output with `satoshis === undefined`,
   and requires the tx to pay at least the SDK's own fee model,
   `ceil(txSize * feeRate / 1000)`.

`broadcast()` **throws** on failure instead of returning a fake txid. So an SDK
test that "successfully deploys and calls" is now, by default, an assertion
that the script really runs.

`getValidationStats()` returns `{ validated, skipped }` — cumulative input
counts across every validated broadcast. Use it to prove a test was not
validated *vacuously*: `validated === 0` means no script actually ran.

### Opting out (and the allowlist policy)

There are two independent switches. They are deliberately separate:

| Switch | What it turns off | How |
|---|---|---|
| **Broadcast validation** | Everything above — no `Spend`, no conservation, no fee check | `new MockProvider('testnet', { validateBroadcasts: false })`, `disableBroadcastValidation()`, `enableBroadcastValidation(false)`, or `newAlwaysAckMockProvider()` |
| **Fee floor only** | Only the `ceil(txSize * feeRate / 1000)` requirement; `Spend` and the outputs-≤-inputs check still run | `new MockProvider('testnet', { enforceFeeFloor: false })` or `disableFeeFloor()` |

If your test intentionally underpays a fee (e.g. an exact-cover UTXO case),
use **`disableFeeFloor()`**. It is not an always-ack escape hatch and does not
need an allowlist entry.

`newAlwaysAckMockProvider()` is **not** exported from `runar-sdk`'s public
barrels (`src/index.ts`, `src/providers/index.ts`) — only from the non-public
`providers/mock.js` module — so a downstream package cannot reach the
never-validate factory at all. `p1-3-always-ack-not-public.test.ts` asserts
that absence.

**Every use of an always-ack escape hatch inside `packages/runar-sdk` must be
allowlisted.** `always-ack-allowlist.test.ts` scans **every `.ts` file under
`src/`** — not just `*.test.ts`, so a non-test-named helper that quietly
disables validation cannot hide — excluding only the audit file itself and
`providers/mock.ts` (the escape hatches' own declaration site). It matches
`disableBroadcastValidation` / `newAlwaysAckMockProvider` /
`validateBroadcasts: false` / `validateBroadcasts = false` /
`enableBroadcastValidation(false)` and fails on any unlisted hit — and on any
**stale** entry, so the list can only shrink.

To add an entry to `packages/runar-sdk/src/__tests__/always-ack-allowlist.json`:

```jsonc
{
  "file": "src/__tests__/my-test.test.ts",
  "reason": "Which test(s) in the file opt out, and why the rest use the default validating provider.",
  "category": "structure-only",   // | negative-api | fixture-shape | pending-a3
  // REQUIRED if the file matches /\.deploy\(|\.call\(|finalizeCall\(/ :
  "fundPathJustification": "why this does not launder an unverified fund-moving tx"
}
```

Three constraints, all machine-checked:

- The entry count is **ratcheted** against a committed ceiling
  (`MAX_ALLOWLIST_ENTRIES`, currently **9**). Lower it when an entry goes
  away; raising it to admit a new file is the wrong move — fix the test.
- A file that calls `.deploy(` / `.call(` / `finalizeCall(` is a **fund-path**
  file and needs a `fundPathJustification`. The bar is high: every current
  one either re-proves rejection itself through the *same* `Spend` interpreter
  on the *same* input, or is pointed at a synthetic `OP_TRUE` artifact that
  can never be script-valid for any call, so there is no real covenant to
  protect.
- **Scope caveat, stated in the allowlist's own `$comment`:** this gate
  governs `MockProvider` only. A test can still hand-roll an inline `Provider`
  object whose `broadcast()` acks anything, and that surface is invisible to
  the gate. Passing it means "no unlisted `MockProvider` always-ack usage",
  not "every broadcast in this package is validated".

### `dryRun` vs provider validation — two different questions

`CallOptions.dryRun` (`RunarContract.call` / `finalizeCall`) is a **separate**
gate from provider broadcast validation, and neither substitutes for the other.

|  | `{ dryRun: true }` | `MockProvider` broadcast validation |
|---|---|---|
| **Question** | "Does *this contract's* unlocking script satisfy *this* locking script?" | "Would this *whole transaction* be accepted?" |
| **Scope** | The primary contract input (index 0) only | Every input whose UTXO the provider knows |
| **Value semantics** | None — no conservation, no fee check | Outputs ≤ known inputs, plus the fee floor |
| **When it runs** | Inside `finalizeCall`, *before* broadcast | Inside `provider.broadcast()` |
| **Default** | **OFF (opt-in)**, in production and in tests | **ON** |
| **Failure message** | `RunarContract.finalizeCall: local pre-broadcast dry-run rejected the primary contract input (deep-review C8)…` | `MockProvider: refusing to broadcast invalid transaction (C8)…` |

**The production default stays opt-in, deliberately.** The local dry-run
harness still produces at least one documented **false rejection** (it rejects
an `Auction.bid()` that the independent real-crypto oracle accepts, plus
clean-stack failures on synthetic stub artifacts). For a fail-closed
pre-broadcast gate a false rejection is worse than the hole it closes — it
would strand funds. The polarity flips only once `dryRunContractInput` agrees
with `runStatefulSpend` on every `witnesses/real-crypto/*.json` accept case.
The full evidence is in the `CallOptions.dryRun` docstring in
`packages/runar-sdk/src/contract.ts`.

> **`dryRun: false` does not mean "unvalidated".** With the provider default
> on, the broadcast is still replayed through the real `Spend` engine. `dryRun`
> buys you a *narrower, earlier, value-free* check, not the only check.

**Do not infer one from the other's error string.** The
`MockProvider: refusing to broadcast invalid transaction (C8)` prefix covers
three structurally different causes:

1. `input i: script evaluated to false` — a genuine engine rejection;
2. `input i: <exception>` — the `Spend` **constructor** threw; the engine
   never evaluated anything;
3. `underfunded: …` / `fee too low: …` — **not engine results at all**, and
   reachable only *after* every known input's script already validated
   **true**.

A "this spend is rejected" test that keys on that prefix can therefore pass
having never exercised the contract's guard. The real-crypto oracle
(`packages/runar-testing/src/oracle/real-crypto-execution.ts`) hit exactly
that: its near-miss reject helper was switched to drive `{ dryRun: true }` and
key on `dryRunContractInput`'s **unique** message, which checks the primary
contract input only and has no fee semantics to be confused with a rejection.
If you write a rejection assertion, make it name the input and the mechanism.

---

## When `TestContract` is enough, and when a real `Spend` is mandatory

`TestContract` is an **AST interpreter with mocked ECDSA**. It walks the parsed
contract (`RunarInterpreter.executeMethod` over the `ContractNode`), not the
compiled Bitcoin Script, and `checkSig` / `checkMultiSig` / `checkPreimage` /
`verifyRabinSig` always return `true`.

> **`TestContract` proves business logic. It never proves spendability.**

That is not a criticism of the tool — it is what makes it usable for
state-transition tests without managing keys and sighashes. It just means a
green `TestContract` suite is silent about whether the contract can be spent
on-chain at all.

| Use `TestContract` for | Use real `Spend` for |
|---|---|
| State transitions, arithmetic, assertion logic | "Is this locking script spendable?" |
| Which branch a condition takes | Post-spend **state values** on a covenant continuation |
| Output count / values registered via `addOutput` | Anything about signatures, preimages, or sighash |
| Fast iteration while writing a contract | Any claim used as coverage evidence for a fund-critical construct |

Real-`Spend` paths, in rising order of cost:

1. **`ScriptVM`** (TS / Go / Rust / Python) — executes compiled script bytes
   against a synthetic single-input tx context. Real `OP_CHECKSIG`. Not
   available in Zig / Ruby / Java (documented platform limits — see CLAUDE.md
   ⇒ "Off-chain Script VM").
2. **Real-crypto witnesses** (`conformance/witnesses/real-crypto/*.json`) —
   deploy→call driven through the SDK, re-validated on `Spend`, with a
   hand-authored `expectedState` pin. This is the canonical path for a
   stateful contract.
3. **`MockProvider` deploy/call** (default-validating) — an end-to-end SDK
   path in a plain vitest, e.g.
   `examples/ts/fixed-array-nested/Grid2x2.test.ts`.
4. **Regtest integration** (`integration/{ts,go,rust,python,ruby,zig,java}`) —
   a real node. The canonical real-crypto path for Zig, Ruby and Java.

### The example policy for `examples/ts/`

Every **stateful** example under `examples/ts/` that ships a vitest must
either:

- **(a)** have a spendability test — a real `Spend`, `ScriptVM`, or a
  default-validating `MockProvider` deploy/call — or
- **(b)** carry a banner comment at the top of the test file:

  ```ts
  // INTERPRETER-ONLY: spendability covered by conformance/witnesses/real-crypto/<fixture>.json
  ```

  naming a path that **actually covers this contract**. Verify it. A banner
  pointed at a witness for a different contract is worse than no banner: it
  converts a visible hole into a false claim.

`examples/ts/example-spendability-policy.test.ts` enforces this and fails on a
stateful example test with neither. Examples with genuinely no covering path
use a third, ratcheted form that is an honest hole, not a pass:

```ts
// INTERPRETER-ONLY: UNCOVERED — <what was checked, when, and what would close it>
```

The count of `UNCOVERED` banners is asserted against a committed ceiling in
that test, so it can shrink and never grow.

Two scope notes, both deliberate:

- **A stateful example with no vitest at all is out of scope.** No test means
  no claim, so there is no false confidence to correct. Their coverage is
  tracked per-construct in `conformance/construct-ledger.json` and per-fixture
  in `conformance/witnesses/coverage-ledger.json`, not here. The lint prints
  that set on every run so it stays visible.
- **The lint verifies the banner, not just its presence.** For a
  `conformance/witnesses/real-crypto/<fixture>.json` banner it resolves
  `conformance/tests/<fixture>/source.json` and requires the `.runar.ts`
  source to land *inside this example's directory* — a hard identity check.
  For any other path (a Go script-execution test, a regtest suite) it requires
  the file to mention this example or one of its stateful contract classes.

At the time of writing, one example is `UNCOVERED`: `companion-verifier`, a
two-input cross-contract covenant that neither `runStatefulSpend` nor the
sdk-output driver protocol can compose. Its banner carries the close plan.

---

## Construct coverage: the construct ledger

`conformance/construct-ledger.json` + `construct-ledger.test.ts` count
coverage in **fund-critical constructs** — language shapes and wire value
classes — instead of fixtures. Every other gate answers "is this *fixture*
exercised?"; this one answers "is this *shape* exercised?". Both 2026-08 bugs
were **empty cells** in this matrix while the fixture-counted suite was green.

**How to add a row** (the full contract is in
`conformance/README.md` ⇒ "Construct ledger"):

1. Pick a stable `id` and, if the construct is fund-critical, add it to
   `REQUIRED_CONSTRUCTS` in `construct-ledger.test.ts`. That array is
   hard-coded **in the test**, not derived from the ledger — deriving it would
   make the gate vacuous, because deleting a row would delete its own
   requirement.
2. Add the row with `category`, `severity` and a human `description`.
3. Fill the cell with `coveredBy` **XOR** (`status: "UNCOVERED"` + `issue`).
   Never both, never neither.

**What counts as evidence.** `kind` is one of `conformance-fixture`,
`real-crypto-witness`, `sdk-output`, `vertical-pin`, `negative-compile`,
`vm-unit`. Every `path` is repo-relative and must exist on disk — deleting a
witness turns its construct **red** rather than letting the claim decay
silently. Round-trip-only tests are denylisted (`ROUND_TRIP_ONLY_PATHS`) and
can never be a row's evidence.

**Empty cells are the deliverable.** An honest `UNCOVERED` row with a dated
close plan is the signal this file exists to produce. A cell pointed at a weak
or unrelated file is strictly worse than an empty one.

---

## Wire primitives: never round-trip alone

For anything whose **bytes cross a boundary** — SDK ↔ compiler, SDK ↔ peer SDK,
unlocking script vs state section — the gate is:

```text
bytes_from_A(value) === bytes_from_B(value)
```

or

```text
spend(A_bytes) accepts and yields expectedState
```

**never only**

```text
deserialize(serialize(x)) === x
```

`conformance/wire-primitives.json` is the register of every fund-critical wire
primitive and the **absolute** pin that proves it. Rows carry `producedBy`
(encode side), `consumedBy` (decode side or the independent other-side
implementation), `absolutePins` (machine-checked, non-empty, path must exist,
must not be a known round-trip test), and optional `roundTripSmokeTests` —
allowed, informative, and never sufficient alone. `wire-primitives.test.ts`
fails a row whose only evidence is a round-trip file. The current rows:
`state-section-framing`, `unlocking-encodeArg-minimaldata`,
`constructor-slot-splicing`, `codeseparator-index`, `bip143-preimage-layout`,
`signed-envelope-bytes`, `canonicalJson`.

Round-trip tests you keep should say so in a comment:

```ts
// round-trip only — absolute pin: conformance/sdk-vertical/cases/bytes-op-n-mid/expected-vertical.json
```

### Must move a golden

A change to a wire-format implementation path that moves **zero** pinned bytes
is **untested by definition** and fails CI — it does not reassure anyone. That
is the `wire-format-must-move-golden` job
(`conformance/scripts/wire-format-pr-audit.ts`); the authoritative path list is
`WIRE_FORMAT_RULES` in that script, and the checklist for satisfying it is in
`conformance/README.md` ⇒ "Encoding-change checklist". Reproducing #110's
"change all seven SDK serializers, move zero goldens" now fails.

---

## Adding a vertical pin or a real-crypto witness

### Vertical pins (state / `constructorSlots` / codeSeparator)

`conformance/sdk-vertical/` holds the compiler↔SDK pins for constructor-arg
splicing (**C3**) and codeSeparator offsets (**C4**); state-section framing
(**C2**) is pinned by
`conformance/sdk-output/tests/stateful-bytestring-op-n-state`. The expected
bytes come from an independent re-implementation in
`conformance/sdk-vertical/reference/`, which **imports nothing from
`packages/**`** — that restriction is the whole point of the directory and is
worth defending on review, because deriving the expectation from the SDK under
test would prove only that the SDK agrees with itself.

To add a row:

1. Append to `MATRIX` in `conformance/sdk-vertical/matrix.ts` with a
   `valueClass` that says what the row is *for*. New contract shapes go under
   `contracts/`.
2. `cd conformance && npx tsx sdk-vertical/generate.ts`.
3. Review the golden diff — the derived goldens **are** the reviewable
   artifact.
4. `npx tsx sdk-vertical/runner/vertical-runner.ts --update-golden` to pin
   `expected-locking.hex`, then re-run without the flag.
5. Add a provenance allowlist entry for each new/changed golden (see
   [Provenance discipline](#provenance-discipline) below).

Tier divergences this gate has found and that are not yet fixed live in
`known-divergences.json`. An entry makes a divergence **tracked, not
acceptable**: the runner also fails in the *other* direction if an entry stops
reproducing, so a fixed bug must delete its entry in the same commit.

### Real-crypto witnesses with `expectedState`

`conformance/witnesses/real-crypto/<fixture>.json` declares concrete spends
executed through `@bsv/sdk`'s `Spend` with real secp256k1 — real DER
signatures over the real BIP-143 sighash and, for stateful contracts, a real
state-continuation preimage synthesised by the deploy→call SDK path.

Two spec kinds: `stateless-signed` (a `SmartContract`; `$sig` args are filled
with real signatures, and the accept path is cross-checked against the
reference AST interpreter) and `stateful` (a `StatefulSmartContract` driven deploy→call and
re-validated on `Spend`).

**Every `stateful` spend with `expect: "accept"` must pin `expectedState`** —
a hand-authored, property → scalar map of the continuation state, compared
against the state decoded from the call transaction's bytes. This is
machine-required by `witnesses/coverage-claims.test.ts` and enforced at run
time by `real-crypto-execution.test.ts`. Accept alone does not prove a correct
state transition (PALMER-1 Face B).

```jsonc
{
  "fixture": "stateful-counter",
  "kind": "stateful",
  "signerKey": "alice",
  "constructorArgs": ["5n"],
  "spends": [
    { "method": "increment", "args": [], "expect": "accept",
      "expectedState": { "count": "6n" } },
    { "method": "increment", "args": [], "tamperOutput": true,
      "cryptoNearMiss": true, "expect": "reject",
      "note": "tampered continuation output" }
  ]
}
```

Each fixture carries **≥1 accept and ≥1 reject/near-miss**. The only escape
from the `expectedState` requirement is `noStateCheck: true`, which additionally
requires a non-empty `note` **and** a non-empty `issue`, and is **ratcheted at
zero occurrences** — adding one means editing that assertion in the open. (The
remediation plan sketched a `terminal` / `expectedState: null` pair for this;
the implementation reused the repo's pre-existing `noStateCheck` convention
instead. `noStateCheck` is the mechanism that exists.)

---

## Horizontal fuzz vs Spend-oracle fuzz

Both live in `conformance/fuzzer/`, and they answer different questions.

| Mode | Oracle | Layer | Catches |
|---|---|---|---|
| `--ir` / `anf-differential` / `ir-differential` | The other six tiers | **Horizontal** | One tier drifting from the other six |
| `--execute` | Reference AST interpreter vs `ScriptVM` on generated scripts | Absolute, but **stateless fragments** and **verdict-only** | Codegen bugs that flip accept/reject |
| `--spend-oracle` | Post-state decoded from the **broadcast transaction's bytes** vs the generator's own model | Absolute, **full tx context + state value** | Reject-when-accept-intended, accept-when-reject-intended, interpreter↔`Spend` disagreement, and `expectedState` mismatch |

```bash
cd conformance
npx tsx fuzzer/index.ts --ir --hex --num 100 --seed 1   # horizontal (parity only)
npx tsx fuzzer/index.ts --execute --num 200             # absolute, stateless, verdict-only
npx tsx fuzzer/index.ts --spend-oracle --num 50 --seed 1 # absolute, stateful, state-pinned
```

Tier-vs-tier differential fuzzing is **necessary but not sufficient** for
fund-safety: agreement can be universally wrong, which is precisely what
PALMER-1 was. `--spend-oracle` is construct-biased — it generates the
asymmetric multi-local branch merge, 1-byte OP_N-range / `0x00` / empty /
negative state values, and multi-slot constructor args with shifting offsets —
and it compares against the **generator's own model**, never against the SDK's
next-state computation, which runs through the same ANF the covenant does and
is therefore poisoned by the very bug class it is hunting.

---

## Provenance discipline

Goldens are **self-produced** by the implementation under test. Changing one
requires an independent justification — `conformance/README.md` ⇒
"Golden-regeneration integrity gate" is the authoritative description, and
"Provenance discipline (plan §F3)" in the same file states the rule for
regenerating them. In short: `verified-against` plus a witness/oracle
co-change whenever execution for that fixture exists, and **no golden-only PRs
for control-flow or wire fixtures**.

---

## TypeScript Unit Testing with Vitest

TypeScript contract tests use vitest. Contract tests compile a `.runar.ts` file to an artifact, then execute methods against the built-in Script VM.

### Basic Test Structure

```typescript
import { describe, it, expect } from 'vitest';
import {
  TestContract,
} from 'runar-testing';
import { readFileSync } from 'fs';

const source = readFileSync('contracts/P2PKH.runar.ts', 'utf8');

describe('P2PKH', () => {
  const pubKeyHash = '89abcdef01234567890abcdef01234567890abcd';
  const contract = TestContract.fromSource(source, { pubKeyHash });

  it('succeeds with valid signature and matching pubkey', () => {
    const sig = '3044022...'; // valid DER signature hex
    const pubKey = '02abc...'; // matching compressed pubkey hex

    const result = contract.call('unlock', { sig, pubKey });
    expect(result.success).toBe(true);
  });

  it('fails with wrong pubkey', () => {
    const sig = '3044022...';
    const wrongPubKey = '03def...'; // different pubkey

    const result = contract.call('unlock', { sig, pubKey: wrongPubKey });
    expect(result.success).toBe(false);
  });
});
```

### Running Tests

```bash
# Run all tests
pnpm test

# Run tests for a specific file
pnpm test -- P2PKH.test.ts

# Run in watch mode
pnpm test -- --watch
```

---

## Native-Language Unit Testing

Each of the six native frontends ships its own example tree that uses the host language's test runner. The native `runar` package/crate/gem/jar provides type aliases, mock crypto, real hash functions, and a `CompileCheck` / `compile_check` entry point that re-runs the contract through the frontend (parse → validate → typecheck).

The quick-reference commands per CLAUDE.md ⇒ "Build & Test":

- **Go** — `cd examples/go && go test ./...`
- **Rust** — `cd examples/rust && cargo test`
- **Python** — `cd examples/python && PYTHONPATH=../../packages/runar-py python3 -m pytest`
- **Zig** — `cd examples/zig && zig build test`
- **Ruby** — `cd examples/ruby && bundle exec rspec` (the compiler itself is exercised via `cd compilers/ruby && rake test`)
- **Java** — `cd examples/java && ./gradlew test`

The Zig example suite is backed by `packages/runar-zig`, which provides the `runar` module, compile-check helpers, fixtures, and the native helper/runtime surface used by `examples/zig/*/*_test.zig`. Some Zig examples now execute the real contract module directly; others still rely on mirror coverage where the current Zig execution model is not yet natural enough.

The Java example suite uses JUnit 5 via the committed Gradle wrapper. `runar.lang.sdk.CompileCheck` invokes the real compiler frontend (composite-built from `compilers/java`), and `runar.lang.runtime.ContractSimulator` lets Java tests run the compiled artifact against real hashes + real secp256k1 with mocked sig-verify — a Java-only off-chain capability covered in detail under [Cryptographic verification in tests](#cryptographic-verification-in-tests).

The full per-tier tooling for Go, Rust, Python, Zig, Ruby, and Java is documented in [Testing Go Contracts](#testing-go-contracts) and [Testing Rust Contracts](#testing-rust-contracts) below, plus the comparison table under [Cross-Language Testing Comparison](#cross-language-testing-comparison).

---

## Using TestContract (Interpreter-Based Testing)

`TestContract` is the primary test helper. It compiles a contract from source, uses the **interpreter** (not the Script VM) to execute methods, and tracks state changes.

> **Important:** `TestContract` uses mocked ECDSA cryptographic operations — `checkSig`, `checkMultiSig`, and `checkPreimage` always return `true`. This is intentional: it lets you test business logic (state transitions, assertions, arithmetic) without managing real keys or signatures. The post-quantum (`verifyWOTS`, `verifySLHDSA_SHA2_*`) and Schnorr / EC-arithmetic builtins are **not** mocked — they execute the real algorithm in the interpreter. See [Cryptographic verification in tests](#cryptographic-verification-in-tests) below for the full mocked-vs-real list and the escape hatches for exercising real ECDSA / preimage rejection.

> **`TestContract` proves business logic, never spendability.** It is an AST
> interpreter — it never runs the compiled Bitcoin Script. See
> [When `TestContract` is enough, and when a real `Spend` is mandatory](#when-testcontract-is-enough-and-when-a-real-spend-is-mandatory).

### Creating an Instance

```typescript
import { TestContract } from 'runar-testing';

// From source code with initial state
const contract = TestContract.fromSource(source, { count: 0n });

// Multi-format: pass fileName to select the parser
const solContract = TestContract.fromSource(solSource, { count: 0n }, 'Counter.runar.sol');

// From a file path
const contract = TestContract.fromFile('contracts/Counter.runar.ts', { count: 0n });
```

The `initialState` is a `Record<string, unknown>` mapping property names to their initial values.

### Calling Methods

```typescript
const result = contract.call('methodName', { arg1: value1, arg2: value2 });
```

Arguments are passed as a `Record<string, unknown>` with named keys matching the method parameter names:

| Rúnar Type | Argument Format |
|----------|----------------|
| `bigint` | `bigint` value (e.g., `42n`) |
| `boolean` | `true` or `false` |
| `PubKey`, `Sig`, `ByteString`, etc. | Hex-encoded string |

The return value is a `TestCallResult` object:

```typescript
interface TestCallResult {
  success: boolean;          // true if all assertions passed
  error?: string;            // error message if a method assertion failed
  outputs: OutputSnapshot[]; // outputs registered via addOutput (stateful contracts)
}
```

### Reading State

After calling a method, read the updated state:

```typescript
const counter = TestContract.fromSource(source, { count: 0n });
counter.call('increment');
expect(counter.state.count).toBe(1n);
```

### Configuring Mock Preimage

For stateful contracts that inspect transaction preimage fields (e.g., time locks, input amounts), use `setMockPreimage()` to override the default mock values:

```typescript
const contract = TestContract.fromSource(source, { deadline: 1000n });

// Override the locktime preimage field for this test
contract.setMockPreimage({ locktime: 2000n });

const result = contract.call('spend', { sig, pubKey });
expect(result.success).toBe(true);
```

`setMockPreimage` accepts a partial `MockPreimage` object with the following optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `locktime` | `bigint` | Mock nLocktime value |
| `amount` | `bigint` | Mock input amount (satoshis) |
| `version` | `bigint` | Mock transaction version |
| `sequence` | `bigint` | Mock input nSequence |

---

## Cryptographic verification in tests

`TestContract` runs contracts through the reference **AST** interpreter (`RunarInterpreter`, which walks the parsed `ContractNode`), not a Bitcoin Script VM. The interpreter mocks the ECDSA / preimage builtins so you can write business-logic tests without managing real keys, signatures, or transaction sighashes. The trade-off: a `TestContract` test that "rejects a bad signature" by passing a malformed `sig` value **does not actually exercise ECDSA verification** — `checkSig` returned `true` either way. The rejection in such a test, if there is one, comes from some *other* assertion in the method (a hash mismatch, a state check, etc.), not from the signature being invalid.

This applies to every native-tier package — `runar` (Go), `runar::prelude` (Rust), `runar` (Python), `runar` (Zig), `runar` (Ruby), `runar.lang` (Java) — but the crypto is **not** a blanket mock, and the helper names are not uniform. What is actually true today:

| | Signature-verify | `mock_sig` / `mock_pub_key` helpers |
|---|---|---|
| Go | **real** ECDSA over the fixed test message (`CheckSig`, `CheckMultiSig`) | **absent** — use `runar.Alice.PubKey` and `runar.SignTestMessage(runar.Alice.PrivKey)`; `MockPreimage()` is the only `Mock*` function |
| Rust | **real** (`check_sig`) | `mock_sig()`, `mock_pub_key()`, `mock_preimage()` |
| Python | **real** (`check_sig`) | `mock_sig()`, `mock_pub_key()` |
| Zig | **real** (`checkSig`, via bsvz) | `mockPreimage()` only |
| Ruby | **real** (`check_sig`) | `mock_sig`, `mock_pub_key` |
| Java | mocked — `MockCrypto.checkSig` is a null check | absent |

`checkPreimage` is stubbed to `true` in every tier: real preimage verification needs a full transaction context, which an off-chain unit test does not have. Native-tier tests run the contract as plain code in the host language — they verify business logic, not on-chain acceptance.

### What is mocked vs. real in the interpreter

| Builtin | Behavior in interpreter | Notes |
|---------|------------------------|-------|
| `checkSig` | **Mocked → always `true`** | Real ECDSA verification requires a transaction sighash that the interpreter does not synthesize. |
| `checkMultiSig` | **Mocked → always `true`** | Same reason as `checkSig`. |
| `checkPreimage` | **Mocked → always `true`** | The interpreter does not synthesize a BIP-143 preimage; use `setMockPreimage` to control the *fields* the contract reads. |
| `verifyRabinSig` | **Mocked → always `true`** | Rabin verification is not implemented in the interpreter. |
| `verifyWOTS` | **Real** | Runs the actual WOTS+ verification (hash-chain replay). A bad WOTS+ signature *does* fail this check. |
| `verifySLHDSA_SHA2_*` | **Real** (all 6 parameter sets) | Runs the actual FIPS 205 verifier. |
| `sha256`, `hash160`, `hash256`, `ripemd160` | **Real** | Standard hash functions. |
| `sha256Compress`, `sha256Finalize` | **Real** | Partial-block SHA-256 primitives. |
| `ecAdd`, `ecMul`, `ecMulGen`, `ecNegate`, `ecOnCurve`, `ecModReduce`, `ecEncodeCompressed`, `ecMakePoint`, `ecPointX`, `ecPointY` | **Real** | secp256k1 field/group arithmetic. Schnorr-ZKP and other EC-arithmetic contracts therefore *do* fail the interpreter when the math is wrong. |
| All math / bitwise / preimage-extractor builtins | **Real** (or fixed test values for preimage extractors) | See the `TestContract` mock-preimage table for the configurable subset. |

The pattern: **mocked = anything whose real implementation needs an ECDSA / Bitcoin sighash context the interpreter does not own**; **real = anything that's a pure function of its inputs** (hashes, EC arithmetic, hash-based PQ signatures, modular arithmetic). PQ and Schnorr-ZKP contracts are exempt from BUG-005's caveats for exactly this reason.

### Escape hatches for real-crypto rejection

If you genuinely need to assert that *the on-chain signature check would reject this input*, `TestContract` is not the right tool. Pick one of:

1. **`ScriptVM` (TypeScript, Go, Rust, Python).** Each of these tiers wraps an upstream BSV SDK's Bitcoin Script interpreter (see CLAUDE.md ⇒ "Off-chain Script VM (`ScriptVM`)" for the exact wrapper and per-tier capabilities). `ScriptVM` executes the *compiled* locking + unlocking scripts and runs real `OP_CHECKSIG` / `OP_CHECKSIGVERIFY` against the supplied signature, pubkey, and sighash. This is the only off-chain path that exercises real ECDSA verification. **Zig, Ruby, and Java have no `ScriptVM`** — by documented project policy, no canonical upstream BSV SDK script interpreter is usable for those tiers (Ruby/Java have no `bsv-blockchain` SDK; the Zig `bsvz` engine does not compile on the repo's Zig 0.16 toolchain).
2. **Regtest integration tests (all 7 tiers).** `integration/{ts,go,rust,python,ruby,zig,java}` ship end-to-end harnesses that deploy the compiled contract to a local BSV regtest node and spend it for real. Real keys, real ECDSA, real preimage. This is the canonical real-crypto rejection path for Zig, Ruby, and Java.
3. **Conformance byte-parity (all 7 tiers).** The conformance suite verifies all 7 compilers produce byte-identical canonical ANF IR + script hex for every fixture (subject to the per-fixture `compilers` allowlist). Stack IR is not compared (R-096). If the TS compiler's compiled hex passes a real-crypto ScriptVM test, and the Zig/Ruby/Java compilers produce the same bytes, the on-chain behavior is the same — but byte-parity is *semantic* assurance, not a VM-level rejection test in those tiers.

### Concrete example: this test does NOT prove signature rejection

```typescript
import { TestContract } from 'runar-testing';

const contract = TestContract.fromSource(p2pkhSource, { pubKeyHash });

it('rejects a bad signature', () => {
  // This test fails for the WRONG reason. `checkSig` is mocked to return true,
  // so the rejection (if any) comes from the assert(hash160(pubKey) === this.pubKeyHash)
  // line, not from the signature being malformed.
  const result = contract.call('unlock', {
    sig: '00'.repeat(70),       // intentionally garbage
    pubKey: validCompressedPk,  // hash160 still matches pubKeyHash
  });
  expect(result.success).toBe(false); // FAILS — the interpreter accepts this.
});
```

To actually exercise ECDSA rejection, use `ScriptVM` (TS/Go/Rust/Python) or a regtest integration test (all 7 tiers):

```typescript
import { ScriptVM, hexToBytes } from 'runar-testing';
import { compile } from 'runar-compiler';

const vm = new ScriptVM();
const artifact = compile(p2pkhSource, { fileName: 'P2PKH.runar.ts' });

it('on-chain script rejects a bad signature', () => {
  const lockingScript = hexToBytes(artifact.script);
  // Build an unlocking script that pushes a garbage signature + a valid pubkey.
  const unlockingScript = buildUnlockingScript({
    sig: '00'.repeat(70),
    pubKey: validCompressedPk,
  });
  const result = vm.execute(unlockingScript, lockingScript, sighashCtx);
  expect(result.success).toBe(false); // PASSES — OP_CHECKSIG genuinely rejects.
});
```

For Zig, Ruby, and Java contracts, drop the `ScriptVM` step and write the equivalent rejection test in `integration/{zig,ruby,java}` against regtest. The Java SDK additionally exposes `runar.lang.runtime.ContractSimulator`, which runs compiled artifacts against real hashes and real secp256k1 with mocked signature-verify — useful for shape/round-trip assertions on the compiled artifact, but **not** a substitute for real-ECDSA rejection (it still mocks the sig check).

---

## Script VM Testing (Compiled Script Execution)

The `ScriptVM` class can be used directly for lower-level testing without the `TestSmartContract` wrapper. Unlike `TestContract` (which interprets the parsed Rúnar AST with mocked crypto), `ScriptVM` executes actual compiled Bitcoin Script opcodes.

```typescript
import { ScriptVM, hexToBytes, bytesToHex, disassemble } from 'runar-testing';

const vm = new ScriptVM();

// Execute raw scripts
const unlockingScript = hexToBytes('0151'); // OP_TRUE
const lockingScript = hexToBytes('69');     // OP_VERIFY
const result = vm.execute(unlockingScript, lockingScript);

console.log(result.success);    // true
console.log(result.opsExecuted); // 2

// Disassemble a script for debugging
const asm = disassemble(lockingScript);
console.log(asm); // "OP_VERIFY"
```

### VM Utilities

```typescript
import {
  encodeScriptNumber,
  decodeScriptNumber,
  isTruthy,
  hexToBytes,
  bytesToHex,
} from 'runar-testing';

// Encode/decode Script numbers
const encoded = encodeScriptNumber(42n);  // Uint8Array
const decoded = decodeScriptNumber(encoded); // 42n

// Check if a stack element is truthy
isTruthy(new Uint8Array([0x01])); // true
isTruthy(new Uint8Array([]));     // false (OP_FALSE)
```

### Interactive step-through debugger: `runar debug`

`runar debug <artifact>` opens an interactive REPL that runs the compiled Bitcoin Script one opcode at a time, with breakpoints, stack inspection, and source-map mapping back to the original Rúnar source line. It is the step-mode counterpart to `ScriptVM` — built on the same per-tier upstream BSV script interpreter wrapper.

**Available in: TypeScript, Go, Rust, Python.** **Not available in: Zig, Ruby, Java.**

The reason mirrors the [Off-chain Script VM (`ScriptVM`)](../CLAUDE.md) policy: `runar debug` needs the same underlying script interpreter that `ScriptVM` wraps, and no canonical upstream BSV SDK script interpreter is currently usable for the Zig, Ruby, or Java tiers (no `bsv-blockchain` SDK exists for Ruby or Java; the Zig `bsvz` script engine does not compile on the repo's Zig 0.16 toolchain). Per project policy, those three tiers do **not** ship a hand-written Script VM, and therefore do not ship a `runar debug` CLI. See CLAUDE.md ⇒ "Off-chain Script VM (`ScriptVM`)" for the authoritative explanation — this guide does not duplicate it.

**Recommended workflow for Zig, Ruby, Java users who need step-level inspection:**

1. **ANF interpreter** — write the test against the `runar-testing`-style harness in your tier (the native `runar` package's `CompileCheck` + the contract-as-native-code pattern shown earlier in this guide). The interpreter does not single-step opcodes, but it does evaluate the same ANF IR the compiler emits, so you can pinpoint the *line* of contract logic that fails — just not the *opcode* it lowered to.
2. **Regtest** — deploy the compiled artifact to a local BSV regtest node via `integration/{zig,ruby,java}`. You can rebuild the locking + unlocking scripts by hand, run them through `bitcoin-cli`'s script-decoding tools, and step the failing path that way. Slower than `runar debug`, but it's the canonical real-VM path for these tiers.
3. **Cross-tier `runar debug`** — for any contract written in a format the TS / Go / Rust / Python frontends accept (every format does — frontend parity is a hard project invariant), you can compile the contract with the Java/Ruby/Zig frontend, then re-compile the same source with `runar` (TS) and run `runar debug` on the TS-tier artifact. Because all 7 compilers produce byte-identical script hex for non-allowlisted fixtures, stepping the TS artifact tells you what the Java/Ruby/Zig artifact does on-chain.

---

## Reference Interpreter for Oracle Testing

The reference interpreter (`RunarInterpreter`) evaluates the **Rúnar AST** (`ContractNode`) directly, without compiling to Bitcoin Script. It does *not* consume ANF IR: `04-anf-lower.ts` sits downstream of its input, which is exactly why it can disagree with — and catch — a miscompile in ANF lowering. (The per-SDK `AnfInterpreter`s and `conformance/anf-interpreter/` are a different thing, and those genuinely do consume ANF IR.) It serves as an oracle: if the compiled script and the interpreter produce different results for the same inputs, there is a bug.

```typescript
import { RunarInterpreter } from 'runar-testing';
import type { RunarValue } from 'runar-testing';
import { compile } from 'runar-compiler';

// Compile the contract to get the AST (ContractNode)
const result = compile(source, { fileName: 'P2PKH.runar.ts' });
const contractNode = result.contract!; // ContractNode (from CompileResult, not artifact)

// Create interpreter with property values (constructor args).
// Unlike TestContract (which accepts plain JS values), RunarInterpreter
// requires RunarValue wrappers for all values:
//   { kind: 'bigint', value: 42n }
//   { kind: 'boolean', value: true }
//   { kind: 'bytes', value: hexToBytes('abcd') }
const interpreter = new RunarInterpreter({
  pubKeyHash: { kind: 'bytes', value: hexToBytes('89abcdef...') },
});

// Optionally set the contract node for reuse across multiple calls
interpreter.setContract(contractNode);

// Execute a method with RunarValue-wrapped arguments
const interpResult = interpreter.executeMethod(contractNode, 'unlock', {
  sig: { kind: 'bytes', value: hexToBytes('3044022...') },
  pubKey: { kind: 'bytes', value: hexToBytes('02abc...') },
});

// interpResult.success: boolean
// interpResult.error?: string (if an assertion failed)
// interpResult.returnValue?: RunarValue (for private methods)
```

### Comparing Interpreter and VM Results

```typescript
it('compiler and interpreter agree', () => {
  const vmResult = contract.call('unlock', { sig, pubKey });
  const interpResult = interpreter.executeMethod(contractNode, 'unlock', {
    sig: { kind: 'bytes', value: hexToBytes(sig) },
    pubKey: { kind: 'bytes', value: hexToBytes(pubKey) },
  });

  // Both should agree on success/failure
  expect(vmResult.success).toBe(interpResult.success);
});
```

This pattern is the foundation of differential testing. If they ever disagree, you have found a compiler bug.

> **It compares verdicts only.** The two engines share just
> parse/validate/typecheck — the interpreter reads the parsed AST directly and
> `04-anf-lower.ts` sits downstream of that input, so the oracle *can* catch a
> miscompile in ANF lowering / stack-lower / emit — but **only when the bug
> flips accept/reject**. A miscompile that leaves the script acceptable while
> committing the wrong continuation state (PALMER-1 Face B) reports
> `agrees: true` while the state is wrong. Catching that needs an independent,
> hand-authored pin that is not derived from this pipeline: `expectedState` in
> `conformance/witnesses/real-crypto/*.json`, or an external KAT. The full
> statement is in the header of
> `packages/runar-testing/src/oracle/differential-execution.ts`.

---

## Property-Based Fuzzing

Rúnar includes property-based testing generators built on fast-check. These generate random valid Rúnar contracts and verify compiler correctness.

### Built-in Generators

```typescript
import {
  arbContract,
  arbStatelessContract,
  arbArithmeticContract,
  arbCryptoContract,
} from 'runar-testing';
```

| Generator | Produces |
|-----------|----------|
| `arbContract` | Random valid Rúnar contract source |
| `arbStatelessContract` | Random contract with only `readonly` properties |
| `arbArithmeticContract` | Contract focusing on arithmetic operations |
| `arbCryptoContract` | Contract using cryptographic built-ins |

### Using with fast-check

```typescript
import { describe, it } from 'vitest';
import * as fc from 'fast-check';
import { arbStatelessContract } from 'runar-testing';
import { compile } from 'runar-compiler';

describe('compiler fuzzing', () => {
  it('never crashes on valid input', () => {
    fc.assert(
      fc.property(arbStatelessContract, (source) => {
        // The compiler should never throw on valid Rúnar
        const artifact = compile(source);
        expect(artifact).toBeDefined();
        expect(artifact.script).toBeTruthy();
      }),
      { numRuns: 1000 },
    );
  });
});
```

### Differential Fuzzing

The conformance fuzzer in `conformance/fuzzer/` generates random ANF programs and checks that all seven compiler tiers produce **byte-identical** Bitcoin Script hex for each program (a cross-tier *parity* oracle). It does **not** execute the generated scripts or compare against the interpreter — that source-vs-script execution oracle is provided separately by `packages/runar-testing/src/oracle/differential-execution.ts` and the `--execute` fuzzer mode (see "Differential execution").

> This mode is **horizontal**: it proves the seven tiers agree, not that they
> are right. For an absolute oracle over a full transaction context *and* the
> post-spend state value, use `--spend-oracle` — see
> [Horizontal fuzz vs Spend-oracle fuzz](#horizontal-fuzz-vs-spend-oracle-fuzz).

```bash
# Run the differential fuzzer
pnpm run fuzz -- --num 10000

# Run with a specific seed for reproducibility
pnpm run fuzz -- --seed 42 --num 5000

# Run the source-vs-script execution oracle (accept/reject only, stateless fragments)
pnpm run fuzz -- --execute --num 200

# Run the Spend-oracle fuzzer (absolute: full tx context + expectedState)
cd conformance && npx tsx fuzzer/index.ts --spend-oracle --num 50 --seed 1
```

The fuzzer follows this pipeline:

```
Generate random .runar.ts --> Compile to ANF IR --> Compile to Script
                         |                    |
                         v                    v
                 Interpret the AST       Execute in VM
                         |                    |
                         v                    v
                    Compare results: must match
```

If the results disagree, the failing program is saved for reproduction. This is inspired by CSmith (Yang et al., PLDI 2011) and is the primary mechanism for finding compiler bugs.

---

## Testing Go Contracts

Go contracts are tested as native Go code using Go's standard `testing` package. The `runar` mock package (`packages/runar-go`) provides type aliases, mock crypto functions, and real hash functions so contracts execute as plain Go.

### Project Setup

Go examples live in `examples/go/`, with one directory per contract. The module resolution relies on a `go.work` file at the project root:

```
go.work
├── compilers/go         # Go compiler
├── examples/go          # Go contract examples + tests
├── packages/runar-go     # Mock types, crypto, CompileCheck()
└── conformance          # Cross-compiler tests
```

This workspace allows `import runar "github.com/icellan/runar/packages/runar-go"` to resolve to the mock package everywhere. Within the monorepo, the `go.work` file provides local replacement; external consumers use the published module path directly.

### Basic Test Structure

```go
package contract

import (
	"testing"
	runar "github.com/icellan/runar/packages/runar-go"
)

func TestP2PKH_Unlock(t *testing.T) {
	pk := runar.Alice.PubKey
	c := &P2PKH{PubKeyHash: runar.Hash160(pk)}
	c.Unlock(runar.SignTestMessage(runar.Alice.PrivKey), pk)
}

func TestP2PKH_Unlock_WrongKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong public key")
		}
	}()
	pk := runar.Alice.PubKey
	c := &P2PKH{PubKeyHash: runar.Hash160(pk)}
	c.Unlock(runar.SignTestMessage(runar.Bob.PrivKey), runar.Bob.PubKey)
}

func TestP2PKH_Compile(t *testing.T) {
	if err := runar.CompileCheck("P2PKH.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
```

Contracts call `runar.Assert()` which panics on failure. Tests that expect a failure use `defer/recover` to catch the panic.

### Testing Stateful Contracts

Stateful contracts mutate struct fields directly. After calling a method, inspect the fields:

```go
func TestCounter_Increment(t *testing.T) {
	c := &Counter{Count: 0}
	c.Increment()
	if c.Count != 1 {
		t.Errorf("expected Count=1, got %d", c.Count)
	}
}

func TestCounter_DecrementAtZero_Fails(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := &Counter{Count: 0}
	c.Decrement()
}
```

### Multi-Output Contracts

Contracts that call `AddOutput()` track outputs via the embedded `StatefulSmartContract` base. Use `Outputs()` to inspect them:

```go
func TestFungibleToken_Transfer(t *testing.T) {
	c := newToken(alice, 100)
	c.Transfer(runar.SignTestMessage(runar.Alice.PrivKey), bob, 30, 1000)
	out := c.Outputs()
	if len(out) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(out))
	}
	if out[0].Values[0] != bob {
		t.Error("output[0] owner should be bob")
	}
	if out[0].Values[1] != runar.Bigint(30) {
		t.Errorf("output[0] balance: expected 30, got %v", out[0].Values[1])
	}
}
```

The `OutputSnapshot` struct holds `Satoshis int64` and `Values []any` (mutable properties in declaration order).

### Mock Types and Functions

The `runar` package provides:

| Category | Functions |
|----------|-----------|
| **Types** | `Int`, `Bigint` (`int64`), `Bool` (`bool`), `PubKey`, `Sig`, `ByteString`, `Sha256`, `Addr` (all `string`-backed) |
| **Crypto** | `CheckSig`, `CheckMultiSig` — **real** ECDSA over the fixed test message; `VerifyRabinSig`, `VerifyWOTS`, `VerifySLHDSA_*` — **real** verification; `CheckPreimage` — stubbed to `true` (needs a transaction context) |
| **Real hashes** | `Hash160`, `Hash256`, `Sha256Hash`, `Ripemd160Func` — compute real values |
| **Math** | `Abs`, `Min`, `Max`, `Within`, `Safediv`, `Safemod`, `Clamp`, `Sign`, `Pow`, `MulDiv`, `PercentOf`, `Sqrt`, `Gcd`, `Log2`, `ToBool` |
| **Test helpers** | `MockPreimage()`, `SignTestMessage(privKeyHex)`, and the `Alice` / `Bob` / `Charlie` key pairs (`.PubKey`, `.PrivKey`). There is no `MockSig()` or `MockPubKey()` in this package — a real signature over a real key pair is what `CheckSig` needs |
| **Preimage extractors** | `ExtractLocktime`, `ExtractOutputHash`, `ExtractAmount`, etc. — return fixed test values |

Byte-backed types use `string` (not `[]byte`) so that `==` comparison works naturally in Go.

### CompileCheck

`runar.CompileCheck(filename)` runs the contract source through the Go compiler frontend (parse → validate → typecheck) and returns an error if anything fails. Always include a compile check test alongside your business logic tests:

```go
func TestMyContract_Compile(t *testing.T) {
	if err := runar.CompileCheck("MyContract.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
```

### Running Go Tests

```bash
cd examples/go
go test ./...                    # Run all Go contract tests
go test ./p2pkh/...              # Run a specific contract
go test -v ./stateful-counter/   # Verbose output
```

---

## Testing Rust Contracts

Rust contracts are tested as native Rust code using `#[test]` attributes. The `runar` mock crate (`packages/runar-rs`) provides a prelude with type aliases, mock crypto, and real hash functions.

### Project Setup

Rust examples live in `examples/rust/`, with one directory per contract. A single `Cargo.toml` defines the workspace with `[[test]]` entries for each contract:

```toml
[package]
name = "runar-example-tests"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
runar = { package = "runar-lang", version = "0.1.0" }

[[test]]
name = "p2pkh"
path = "p2pkh/P2PKH_test.rs"

[[test]]
name = "counter"
path = "stateful-counter/Counter_test.rs"

# ... one entry per contract
```

### Basic Test Structure

```rust
#[path = "P2PKH.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

#[test]
fn test_unlock() {
    let pk = mock_pub_key();
    let c = P2PKH { pub_key_hash: hash160(&pk) };
    c.unlock(&mock_sig(), &pk);
}

#[test]
#[should_panic]
fn test_unlock_wrong_key() {
    let pk = mock_pub_key();
    let wrong_pk = vec![0x03; 33];
    let c = P2PKH { pub_key_hash: hash160(&pk) };
    c.unlock(&mock_sig(), &wrong_pk);
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("P2PKH.runar.rs"),
        "P2PKH.runar.rs",
    ).unwrap();
}
```

Key patterns:
- **`#[path = "Contract.runar.rs"] mod contract;`** imports the contract source as a Rust module.
- **`use runar::prelude::*;`** brings all mock types and functions into scope.
- **`#[should_panic]`** cleanly asserts that a contract method panics (no need for `catch_unwind`).
- **`include_str!()`** embeds the contract source for `compile_check()`.

### Testing Stateful Contracts

Stateful contracts take `&mut self` and mutate fields directly:

```rust
#[test]
fn test_increment() {
    let mut c = Counter { count: 0 };
    c.increment();
    assert_eq!(c.count, 1);
}

#[test]
fn test_multiple_operations() {
    let mut c = Counter { count: 0 };
    c.increment();
    c.increment();
    c.increment();
    c.decrement();
    assert_eq!(c.count, 2);
}

#[test]
#[should_panic]
fn test_decrement_at_zero_fails() {
    Counter { count: 0 }.decrement();
}
```

### Multi-Output Contracts

Rust's borrow checker requires `.clone()` when passing owned fields to `add_output()`. Test files typically define a local output struct:

```rust
#[derive(Clone)]
struct FtOutput { satoshis: Bigint, owner: PubKey, balance: Bigint }

struct FungibleToken {
    owner: PubKey,
    balance: Bigint,
    token_id: ByteString,
    outputs: Vec<FtOutput>,
}

impl FungibleToken {
    fn add_output(&mut self, satoshis: Bigint, owner: PubKey, balance: Bigint) {
        self.outputs.push(FtOutput { satoshis, owner, balance });
    }
}

#[test]
fn test_transfer() {
    let mut c = new_token(alice(), 100);
    c.transfer(&mock_sig(), bob(), 30, 1000);
    assert_eq!(c.outputs.len(), 2);
    assert_eq!(c.outputs[0].owner, bob());
    assert_eq!(c.outputs[0].balance, 30);
}
```

Note: The `.runar.rs` contract file itself needs `.clone()` on owned values passed to `add_output()`. This is a no-op for Bitcoin Script compilation but satisfies the Rust borrow checker.

### Mock Types and Functions

The `runar::prelude` provides:

| Category | Functions |
|----------|-----------|
| **Types** | `Int`, `Bigint` (`i64`), `PubKey`, `Sig`, `ByteString`, `Sha256`, `Addr` (all `Vec<u8>`) |
| **Mock crypto** | `check_sig`, `check_multi_sig`, `check_preimage`, `verify_rabin_sig`, `verify_wots` — always return `true` |
| **Real hashes** | `hash160`, `hash256`, `sha256`, `ripemd160` — compute real values |
| **Math** | `safediv`, `safemod`, `clamp`, `sign`, `pow`, `mul_div`, `percent_of`, `sqrt`, `gcd`, `log2`, `bool_cast` |
| **Byte ops** | `num2bin`, `len`, `cat`, `substr` |
| **Test helpers** | `mock_sig()`, `mock_pub_key()`, `mock_preimage()` |
| **Preimage extractors** | `extract_locktime`, `extract_output_hash`, etc. — return fixed test values |

Byte-backed types use `Vec<u8>`, so equality comparisons with `==` work via `PartialEq`.

### compile_check

`runar::compile_check(source, filename)` runs the contract through the Rust compiler frontend (parse → validate → typecheck) and returns `Result<(), String>`:

```rust
#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("Counter.runar.rs"),
        "Counter.runar.rs",
    ).unwrap();
}
```

Always include a compile check test. This catches Rúnar language errors (invalid types, unknown functions, recursion, etc.) that the Rust compiler itself would not flag.

### Running Rust Tests

```bash
cd examples/rust
cargo test                           # Run all Rust contract tests
cargo test --test p2pkh              # Run a specific contract
cargo test --test counter -- --nocapture  # Verbose output
```

---

## Cross-Language Testing Comparison

All seven tiers run native unit tests with their language's standard test runner, plus a `CompileCheck` / `compile_check` entry point that re-runs the contract through the frontend.

| Aspect | TypeScript | Go | Rust | Python | Zig | Ruby | Java |
|--------|-----------|----|------|--------|-----|------|------|
| **Test framework** | vitest | `testing.T` | `#[test]` | pytest | `zig build test` | rspec | JUnit 5 |
| **Failure assertion** | `expectScriptFailure(result)` (see note below) | `defer/recover` | `#[should_panic]` | `pytest.raises(AssertionError)` | `testing.expectError` | `expect { ... }.to raise_error` | `assertThrows(...)` |
| **Contract loading** | `TestContract.fromSource(source, state)` | Struct literal in same package | `#[path = "..."] mod contract;` | `load_contract("File.runar.py")` (conftest helper) | `@import("./contract.zig")` + struct literal | `require_relative` + class instantiation | Class instantiation in same package |
| **Type imports** | `import { ... } from 'runar-testing'` | `import runar "github.com/icellan/runar/packages/runar-go"` | `use runar::prelude::*;` | `from runar import ...` | `const runar = @import("runar");` | `require "runar"` | `import runar.lang.*;` |
| **Byte types** | Hex strings / `Uint8Array` | `string` (for `==`) | `Vec<u8>` (for `==` via `PartialEq`) | `bytes` | `[]const u8` | `String` (binary-encoded) | `byte[]` / `ByteString` wrapper |
| **Scalar types** | `bigint` | `int64` aliases | `i64` aliases | `int` (arbitrary precision) | `i64` aliases | `Integer` | `long` / `BigInteger` |
| **Output tracking** | `contract.state` after `call()` | `c.Outputs()` method | Manual `Vec<Output>` field | `c.outputs` list | `c.outputs` slice | `c.outputs` array | `c.outputs()` accessor |
| **Compile check** | Built into `fromArtifact` / `fromSource` | `runar.CompileCheck("file.runar.go")` | `runar::compile_check(include_str!("file"), "file")` | `runar.compile_check("file.runar.py")` | `runar.compileCheck("file.runar.zig")` | `Runar.compile_check("file.runar.rb")` | `CompileCheck.run(Path.of("File.runar.java"))` |
| **Borrow workarounds** | N/A | None needed | `.clone()` for owned fields in `add_output` | None needed | Explicit slice/allocator handling | None needed | None needed |
| **Off-chain real-crypto harness** | `ScriptVM` | `ScriptVM` | `ScriptVM` (execute-only) | `ScriptVM` (optional `bsv-sdk` dep) | None (regtest only) | None (regtest only) | `ContractSimulator` (real hashes + real secp256k1 + mocked sig-verify) |
| **Run command** | `npx vitest run` | `go test ./...` | `cargo test` | `python3 -m pytest` | `zig build test` | `bundle exec rspec` | `./gradlew test` |

Identifier-casing note: Python and Ruby contracts use snake_case in source; the parser converts to camelCase in the AST (`pub_key_hash` → `pubKeyHash`, `check_sig` → `checkSig`). Native tests in those tiers reference the snake_case names that the host language uses.

> **`expectScriptFailure`**: A convenience assertion exported from `runar-testing`. It takes a `VMResult` from `TestSmartContract.call()` or `ScriptVM.execute()` and throws if the script execution succeeded (i.e., it asserts that the script failed). Its counterpart is `expectScriptSuccess`. Both are imported from `runar-testing`:
>
> ```typescript
> import { expectScriptFailure, expectScriptSuccess } from 'runar-testing';
> ```

---

## Post-Quantum Signature Testing (Experimental)

Post-quantum signature verification (WOTS+ and SLH-DSA) has dedicated testing at three levels:

### Reference Implementation Tests

Pure TypeScript implementations in `packages/runar-testing/src/crypto/`:

- `wots.ts` — WOTS+ keygen, sign, verify (18 unit tests)
- `slh-dsa.ts` — SLH-DSA for all 6 SHA-256 parameter sets (9 unit tests)

```bash
npx vitest run packages/runar-testing/src/crypto/__tests__/
```

### Interpreter Tests

The interpreter performs real PQ verification (not mocked). Test contracts call `verifyWOTS` or `verifySLHDSA_SHA2_*` and the interpreter executes the actual algorithm:

```typescript
import { wotsKeygen, wotsSign } from '../crypto/wots.js';
const { sk, pk } = wotsKeygen(seed);
const sig = wotsSign(msg, sk);
const contract = TestContract.fromSource(source, { pubkey: toHex(pk) });
expect(contract.call('spend', { msg: toHex(msg), sig: toHex(sig) }).success).toBe(true);
```

### Dual-Oracle Tests

These validate that the compiled Bitcoin Script produces the same result as the interpreter:

- `post-quantum-dual-oracle.test.ts` — WOTS+ (10 KB script)
- `post-quantum-slh-dual-oracle.test.ts` — SLH-DSA-128s (203 KB script)

Both paths must agree on valid signatures (accept) and invalid signatures (reject).

### Conformance Golden Files

`conformance/tests/post-quantum-wots/` and `conformance/tests/post-quantum-slhdsa/` contain golden `expected-script.hex` files. WOTS+ and SLH-DSA codegen ship in **all 7 maintained compilers** (TS, Go, Rust, Python, Zig, Ruby, Java), and all 7 target byte-identical output against these goldens.

---

## Elliptic Curve Contract Testing

EC-based contracts (using `ecAdd`, `ecMul`, `ecMulGen`, etc.) are tested like any other Rúnar contract via `TestContract`, but require generating valid EC test vectors in the test harness.

### Generating EC Test Vectors

Since EC operations manipulate secp256k1 points, tests need to compute valid points and scalars. The test file typically includes JS helper functions for EC arithmetic:

```typescript
import { TestContract } from 'runar-testing';

// secp256k1 constants
const EC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const EC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

// JS helpers for test vector generation
function mod(a: bigint, m: bigint): bigint { return ((a % m) + m) % m; }
function modInv(a: bigint, m: bigint): bigint { /* extended Euclidean */ }
function pointAdd(x1: bigint, y1: bigint, x2: bigint, y2: bigint): [bigint, bigint] { /* ... */ }
function scalarMul(bx: bigint, by: bigint, k: bigint): [bigint, bigint] { /* ... */ }

// Encode a point as a 128-char hex string (64 bytes: x[32] || y[32])
function makePointHex(x: bigint, y: bigint): string {
  return x.toString(16).padStart(64, '0').toUpperCase()
       + y.toString(16).padStart(64, '0').toUpperCase();
}
```

### Example: Testing a Schnorr ZKP Contract

```typescript
describe('SchnorrZKP contract', () => {
  it('verifies a valid Schnorr ZKP proof', () => {
    const privKey = 42n;
    const [pubX, pubY] = scalarMul(GX, GY, privKey);
    const pubKeyHex = makePointHex(pubX, pubY);

    const r = 12345n;
    const [rX, rY] = scalarMul(GX, GY, r);
    const rHex = makePointHex(rX, rY);

    const e = 7n;
    const s = mod(r + e * privKey, EC_N);

    const c = TestContract.fromSource(source, { pubKey: pubKeyHex });
    const result = c.call('verify', { rPoint: rHex, s, e });
    expect(result.success).toBe(true);
  });

  it('rejects a proof with wrong s value', () => {
    // ... same setup but pass s + 1n ...
    const result = c.call('verify', { rPoint: rHex, s: s + 1n, e });
    expect(result.success).toBe(false);
  });
});
```

### Key Testing Considerations for EC Contracts

- **Point format**: Points are 64 bytes (128 hex chars), big-endian unsigned, no prefix. Use `makePointHex()` or equivalent to construct valid test points.
- **Modular arithmetic**: All scalar computations in tests must use `mod(value, EC_N)` to stay within the group order, matching what the on-chain contract does.
- **Interpreter-based**: `TestContract` uses the interpreter, which performs real EC arithmetic (not mocked). This means test results accurately reflect the contract's mathematical behavior.
- **Script size**: EC contracts generate very large scripts — **~429 KB** per `ecMul`/`ecMulGen` call, ~460 KB per `p256Mul`, ~927 KB per `p384Mul`, ~974 KB for one `verifyECDSA_P256` and ~1.99 MB for one `verifyECDSA_P384`. Full Script VM execution is feasible but slow (seconds per call). These sizes also matter beyond test runtime: most of them exceed the BSV default `maxscriptsizepolicy` of 500,000 B **per script**, so a contract that passes every test here may still be rejected as non-standard by a node on stock policy — see the script-size and relay-policy table in [`docs/language-reference.md`](language-reference.md#script-size-and-relay-policy). `integration/regtest.sh` runs with `maxscriptsizepolicy=0`, so the regtest suite cannot catch it.

---

## Conformance Testing Across Compilers

The conformance suite in `conformance/` ensures the maintained Rúnar compilers produce identical output for the shared test corpus.

### Golden-File Tests

Each test case is a directory containing:

```
conformance/tests/basic-p2pkh/
  basic-p2pkh.runar.ts      # Source contract
  P2PKH.runar.zig           # Optional alternate-source frontend fixture
  expected-ir.json          # Expected ANF IR (canonical JSON)
  expected-script.hex       # Expected compiled script (hex)
```

### Running Conformance Tests

```bash
# Test the TypeScript reference compiler
pnpm run conformance:ts

# Test the Go compiler
pnpm run conformance:go

# Test the Rust compiler
pnpm run conformance:rust

# Test the Python compiler
pnpm run conformance:python

# Test the Zig compiler
pnpm run conformance:zig

# Test the Ruby compiler
pnpm run conformance:ruby

# Test the Java compiler
pnpm run conformance:java

# Run every conformance suite end-to-end (all 7 compilers + cross-tier + SDK + ANF parity)
pnpm run conformance:all
```

The runner compiles each source file, serializes the ANF IR using canonical JSON (RFC 8785), and compares the SHA-256 hash against the expected output. Byte-identical output is required.

### Adding a New Conformance Test

1. Create a directory under `conformance/tests/` with a descriptive name.
2. Write the source contract (`.runar.ts`).
3. Generate the expected IR using the reference compiler:

```bash
runar compile conformance/tests/my-test/my-test.runar.ts --ir --canonical
```

4. Copy the canonical ANF IR to `expected-ir.json`.
5. Optionally generate and save the expected script hex.
6. Run `pnpm run conformance:ts` to verify.

### Updating Golden Files

When the spec or compiler changes in a way that affects output:

```bash
cd conformance && pnpm run update-golden
```

Review the diffs carefully. An unexpected change in a golden file indicates either a compiler bug or an unintended spec change.

---

## Testing Strategy Summary

Rúnar employs a layered testing strategy. The **Assurance** column is the one
that matters when you are deciding whether a claim of "covered" is load-bearing
— see [Layers of assurance](#layers-of-assurance).

| Layer | What It Tests | Assurance | Tool |
|-------|--------------|-----------|------|
| **Unit tests per pass** | Each compiler pass in isolation | tier-local | vitest |
| **End-to-end compilation** | Full pipeline: source to script | tier-local | vitest + conformance golden files |
| **VM execution** | Compiled script with specific inputs | absolute (verdict) | `TestSmartContract` / `ScriptVM` (execute compiled Bitcoin Script) |
| **Interpreter oracle** | AST evaluation matches compiled-script execution | absolute (**verdict only**) | `RunarInterpreter` vs `ScriptVM` |
| **Real-crypto witnesses** | Real `Spend` accept/reject **plus** post-spend `expectedState` | absolute (verdict **+ value**) | `conformance/witnesses/real-crypto/*.json` |
| **Provider broadcast validation** | Whole-tx acceptance on the SDK path (default ON) | absolute | `MockProvider` + `@bsv/sdk` `Spend` |
| **Property-based fuzzing** | Random valid programs compile correctly | tier-local | fast-check generators |
| **Differential fuzzing (parity)** | All 7 tiers emit byte-identical hex | **horizontal** | `conformance/fuzzer` |
| **Differential execution (semantics)** | Interpreter and BSV engine agree on accept/reject | absolute (**verdict only**) | `packages/runar-testing/src/oracle`, `conformance/fuzzer --execute` |
| **Spend-oracle fuzzing** | Generated stateful contracts deploy→call→`Spend` with a state pin | absolute (verdict **+ value**) | `conformance/fuzzer --spend-oracle` |
| **Cross-compiler conformance** | All compilers produce identical output | **horizontal** | Golden-file SHA-256 comparison |
| **Cross-SDK conformance** | All 7 SDKs emit identical locking scripts | **horizontal** | `conformance/sdk-output` |
| **Compiler↔SDK vertical pins** | SDK behaviour matches the compiler's declaration | **vertical** | `conformance/sdk-vertical`, `stateful-bytestring-op-n-state` |
| **Construct ledger** | Which fund-critical *shapes* are exercised at all | coverage meta-gate | `conformance/construct-ledger.json` |
| **Post-quantum dual-oracle** | Compiled PQ script matches interpreter | absolute (verdict) | `TestContract` vs `ScriptExecutionContract` |

The layers build on each other. Unit tests catch obvious regressions. VM tests verify that the compiled script actually works. The interpreter oracle catches subtle semantic bugs. Fuzzing searches for edge cases that hand-written tests miss. Conformance testing ensures the multi-compiler strategy holds together.

What conformance testing does **not** do is prove any of them right: seven
tiers agreeing byte-for-byte on a wrong answer is a green horizontal suite. The
vertical pins, the real-crypto `expectedState` pins, and the Spend-oracle
fuzzer are the layers that can disagree with a consensus.

### Per-Pass Test Structure

Each compiler pass has its own test file. Tests provide specific input IR, run the pass, and assert properties of the output:

```
Pass 1 tests: source string      --> Rúnar AST assertions
Pass 2 tests: Rúnar AST           --> validation error/success
Pass 3 tests: Validated AST      --> type error/success assertions
Pass 4 tests: Validated AST      --> ANF IR structural assertions
Pass 5 tests: ANF IR             --> Stack IR depth assertions
Pass 6 tests: Stack IR           --> hex script assertions
```

This granularity makes it straightforward to isolate where a bug was introduced when a higher-level test fails.
