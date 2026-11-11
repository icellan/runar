# `conformance/sdk-vertical` — compiler ↔ SDK vertical pins

Phase **C3** (`constructorSlots` / constructor-arg splicing) and **C4**
(codeSeparator offsets) of
[`docs/audit/2026-08-testing-gap-remediation-plan.md`](../../docs/audit/2026-08-testing-gap-remediation-plan.md).

## What a vertical pin is, and why horizontal parity is not one

The repo has two strong **horizontal** invariants: seven compilers agree with
each other, and seven SDKs agree with each other. Neither one asks whether the
agreed-upon answer is *correct*.

Plan **§2 P7** states the rule this directory implements:

> 7-way compiler agreement and 7-way SDK agreement do **not** substitute for a
> compiler↔SDK pin. New parity work that only extends horizontal matrices
> without a vertical pin for the same family is incomplete for fund-safety.

That is not a hypothetical. **PALMER-2** (2026-08) changed the state-section
framing in *all seven* SDKs at once. Every round-trip test stayed green,
`conformance/sdk-output` stayed green — because it only compares SDKs to each
other — and zero goldens moved. Contracts carrying a 1-byte `0x01`–`0x10`
ByteString became permanently unspendable.

A **vertical** pin crosses the boundary: it compares what an SDK *does* with an
artifact against what the compiler that produced that artifact *declared*. Two
tiers can only pass it by both being right.

## What was missing before this directory

`constructorSlots` and `codeSeparatorIndex` / `codeSeparatorIndices` are bare
integers in the artifact JSON. Surveying the existing suite:

| Existing test | What it actually pins |
|---|---|
| `packages/runar-sdk/src/__tests__/constructor-slots.test.ts` | Hand-authored artifacts and hardcoded expected hex. The compiler is never invoked, so no compiler-emitted `byteOffset` is validated. |
| `.../ctor-bytestring-minimaldata-roundtrip.test.ts` | **Round-trip only** — `extractConstructorArgs(encodeArg(x)) === x` over exactly the six OP_N-range classes. The SDK grading itself with its own inverse; the intermediate bytes are never asserted. This is the PALMER-2 shape. |
| `.../codesep-offsets.test.ts` | `findCodesepOffsets` against hand-written literal scripts. Never pointed at a compiled artifact. |
| `.../codeseparator-signing.test.ts` | Real deploy/call execution (good), but only asserts the codesep fields are `toBeDefined()`, plus `expect(artifact.script).toContain('ab')` — which a `0xab` byte inside push data satisfies. |
| `.../slot-layout.test.ts` | The strongest existing file; derives an oracle by byte-diffing two bakes. But the oracle reads offsets out of the **SDK-spliced** output, so a wrong compiler-emitted `byteOffset` shifts oracle and bake together and cancels out. |

Nothing in the repo walked a compiled script and compared the result to
`codeSeparatorIndices`. `conformance/construct-ledger.json` says so itself:

> `RESIDUAL: this pins the SCRIPT bytes, not the index array itself; no test
> asserts findCodesepOffsets(compiledScript) equals
> artifact.codeSeparatorIndices for a stateful contract. That vertical pin is
> plan Phase C4.`

Likewise, every existing check of a slot offset asks only *"is the byte at this
offset `0x00`?"* — which an off-by-one onto a neighbouring `OP_0` also satisfies.

## Where the reference bytes come from (and why that is not circular)

Deriving the expected spliced hex by calling the SDK function under test would
prove only that the SDK agrees with itself. The gate therefore has **four**
sides, three of which need no SDK at all:

1. **The compiler's declaration.** `artifact.script` (the template bytes),
   `constructorSlots[]` (`byteOffset`, `valueEncoding`, `fixedValueByteLength`,
   `fixedPushHeaderBytes`), `codeSepIndexSlots[]`, `codeSeparatorIndex(-ices)`.
   The artifact does not just carry offsets — it carries a *specification* of
   the splice. Most of that specification was previously unchecked against
   anything.

2. **An independent re-implementation** in [`reference/`](reference/), written
   from the Bitcoin push-data rules and the `ConstructorSlot` contract.
   `reference/**` imports nothing from `packages/**` — that restriction is the
   whole point and is worth preserving on review. It provides:
   - `script.ts` — an opcode walker. This is what turns a bare integer into a
     checkable claim: it can say *"offset 878 is a real opcode boundary holding
     a 1-byte OP_0"*, and *"the `0xab` at byte 1200 is push data, not an
     OP_CODESEPARATOR"*.
   - `encode.ts` — the deploy-time encoding spec (**SPEC layer**).
   - `derive.ts` — the splice, plus a disassembly of the finished script that
     asks what each slot *actually pushes* (**SEMANTIC layer**).

   The two layers fail differently on purpose. The SPEC layer catches a byte
   that is merely *different*; the SEMANTIC layer catches a byte that is
   *wrong* — `OP_0` and `01 00` are both legal pushes, but they put different
   values on the stack, and that difference is exactly PALMER-2. The semantic
   layer would still fire if the project deliberately changed encodings.

3. **Checked-in absolute goldens**, per case:
   `expected-code-part.hex`, `expected-vertical.json`, `expected-locking.hex`,
   `expected-readback.json`.
   Because they are committed, a change to the harness alone cannot silently
   move the target — it shows up as a reviewable golden diff (and feeds the
   must-move-golden gate, plan Phase F). `expected-code-part.hex` and
   `expected-vertical.json` and `expected-readback.json` are written from the
   **independent derivation**,
   never from an SDK; `generate.ts` refuses to write a golden for a case whose
   artifact fails its own template claims.

4. **The seven SDKs**, via the drivers `conformance/sdk-output/tools/` already
   ships (the case `input.json` uses that suite's exact shape so they run
   unchanged).

## Layout

```
sdk-vertical/
  contracts/        SlotMatrix / SlotBool / CodeSepMatrix .runar.ts fixtures
  artifacts/        their compiled artifacts (regenerated by generate.ts)
  matrix.ts         the value-class matrix — one row per deployment
  generate.ts       recompile + rewrite inputs and the derived goldens
                    (--check: recompile + diff against the goldens, write nothing)
  known-divergences.json  tier divergences found and not yet fixed (see below)
  reference/        the independent implementation (imports nothing from packages/**)
    script.ts       opcode walker / disassembler / codesep finder
    encode.ts       deploy-time constructor-arg encoding spec
    derive.ts       splice + template-claim checks + deployed-script checks
    readback.ts     honest locking script + tampered scripts, and what
                    matchesArtifact / extractConstructorArgs must say about each
  runner/           the seven-tier CLI gate
  cases/<row>/
    input.json               {artifact, constructorArgs}
    expected-code-part.hex   INDEPENDENTLY DERIVED
    expected-vertical.json   INDEPENDENTLY DERIVED (slot layout + codesep offsets)
    expected-locking.hex     the full deployed script all tiers agree on
    expected-readback.json   INDEPENDENTLY DERIVED (honest script + tampers, readback verdicts)
  vertical-pins.test.ts      compiler-side pins + the red-proofs (vitest)
```

## Running

```bash
# Compiler-side pins + red-proofs (no toolchains needed; part of `npx vitest run`)
npx vitest run conformance/sdk-vertical/vertical-pins.test.ts

# Full gate, all seven SDKs (needs go / cargo / zig / gradle + the sdk-output drivers)
cd conformance && npm run sdk-vertical
# equivalently: npx tsx sdk-vertical/runner/vertical-runner.ts

# Useful flags
  --no-sdk              compiler-side pins only
  --tiers typescript,go restrict tiers (unrecognized names throw)
  --filter codesep      restrict cases (a filter matching nothing throws)
  --update-golden       rewrite expected-locking.hex (never the derived goldens)

# Regenerate everything after changing contracts/ or matrix.ts
cd conformance && npm run sdk-vertical:generate
# equivalently: npx tsx sdk-vertical/generate.ts

# Recompile contracts/*.runar.ts and diff the result against the checked-in
# goldens WITHOUT writing anything (plan P0-3). Every other check in this
# suite only ever inspects the committed artifact blob; this is the one check
# that re-invokes the compiler, so it is the one that can catch a compiler
# regression a stale golden would otherwise launder silently. A failure names
# the exact differing byte.
cd conformance && npm run sdk-vertical:check
# equivalently: npx tsx sdk-vertical/generate.ts --check
```

CI runs the gate in the `sdk-output` job, reusing the drivers built there.

## What each case checks

| # | Check | Needs an SDK? |
|---|---|---|
| T2/T3 | every `constructorSlots[].byteOffset` and `codeSepIndexSlots[].byteOffset` is a genuine **opcode boundary** holding a 1-byte `OP_0` | no |
| T4 | no two slots claim the same byte | no |
| T5 | `codeSeparatorIndices` equals the real `OP_CODESEPARATOR` positions from an opcode walk | no |
| T6 | `codeSeparatorIndex` is the **last** real separator (`06-emit.ts` overwrites it as it emits) | no |
| T7 | every `codeSepIndexSlots[].codeSepIndex` targets a real separator | no |
| T8 | slot `name` / `paramIndex` agree with the ABI | no |
| D2 | each slot, in the **deployed** script, pushes exactly the deploy-time value (semantic layer) and fills its slot | no |
| D3 | `fixedPushHeaderBytes` / `fixedValueByteLength` match the real deployed bytes | no |
| D4 | deployed separator offsets equal the artifact's indices shifted by the actual constructor-arg expansion | no |
| D5 | the codesep index each SDK **bakes into the script** equals the byte offset where `OP_CODESEPARATOR` actually lands | no (pinned), yes (per tier) |
| — | every tier's deployed locking script carries the derived code part as its prefix, tiers agree, and all match `expected-locking.hex` | yes |
| R1 | every tier's `matchesArtifact` accepts the honest locking script (which must equal `expected-locking.hex`) and `extractConstructorArgs` reads back exactly the case's constructor args | yes (all seven) |
| R2 | every tier's `matchesArtifact` rejects every tampered script in `expected-readback.json`, and `extractConstructorArgs` raises exactly where pinned (see "Readback" below) | yes (all seven) |
| X1 (TS only) | `RunarContract.getSubscriptForSigning()` trims the deployed script at the SAME offset the independent derivation computes, for every method of every codesep case | yes (typescript) |
| X2 (TS only) | a real deploy → call continuation spend of `CodeSepMatrix.reseal` (the shifted, multi-byte codesep bake) validates on `@bsv/sdk`'s `Spend` | yes (typescript) |

D5 pins the baked INDEX (a number written into the script) against an
independent disassembly of that same script — it does not itself prove that
number is where a tier's BIP-143 signer actually trims the scriptCode; see
"Scope boundaries" below for what does and does not close that gap.

## Value classes covered

`bigint`: `0`, `1`, `-1`, `16`, `17`, `127`, `128`, `-128`, `-16`, `-17`,
`-129`, large (>2^63), large negative (<-2^63).
`bool`: `true`, `false`.
`ByteString`: `""`, `0x00`, `0x01`, `0x05`, `0x10`, `0x81`, `0x11`, `0xff`,
`0xab`, `0x0011`, `0xdeadbeef`, 75 bytes (direct-push ceiling), 76 bytes
(OP_PUSHDATA1), 255 bytes (OP_PUSHDATA1 ceiling), 256 bytes and 300 bytes
(OP_PUSHDATA2, the latter with both length bytes non-zero).
Multi-slot: `SlotMatrix` carries five slots over three params (`tag` and
`owner` each appear twice), plus two explicit mixed rows.
C4: `CodeSepMatrix` has three public methods (`bump`, `reseal`, `close`), each
auto-injecting its own `OP_CODESEPARATOR`. `bump`'s own `codeSepIndexSlot`
always targets template offset 6 — before every ctor slot — so it always
bakes the constant `6`; `reseal`'s targets its own separator, which sits
AFTER the `tag` ctor slot, so its baked value shifts with `tag`'s encoded
length. Six rows shift it by 0/0/+1/+4/+3/+77.

The `0xab` rows exist so that a naive `script.indexOf('ab')` separator scan
false-positives and the opcode walk does not.

## Readback (`expected-readback.json`)

The checks above pin what an SDK *writes*. R1/R2 pin what it *reads back*:
`matchesArtifact(artifact, script)` and `extractConstructorArgs(artifact,
script)`, run by each tier's driver in readback mode (input `{artifact,
scriptHex}`, output `{matches, args, error}`; the mode is selected by the
presence of `scriptHex`, so the drivers' locking-script output is unchanged).

`reference/readback.ts` derives, per case:

- **honest**: the spliced code part plus, for a stateful artifact, the
  `OP_RETURN` state tail. `matches: true`, and `args` positional by
  `paramIndex` as `{type, value}` in `input.json`'s conventions (decimal,
  `'true'`/`'false'`, lowercase hex; `type` is the artifact's ABI type), `null`
  for a param with no constructor slot (a mutable state field).
- **tampers**, from the contract's own slot layout. Each is built by
  re-splicing the template with one slot overridden, so the codeSepIndex
  slots and codePartLen fields stay consistent with the tampered widths and
  the defect under test is the only one:

  | class | applies when | `extractRaises` |
  |---|---|---|
  | `non-push-at-slot` | always: `OP_NOP` at the first constructor slot; also at the second reference of any param referenced twice | yes |
  | `repeat-ref-differs` | a param has two references (SlotMatrix `tag`, `owner`): a different valid push of the same width class at the second | no |
  | `wrong-fixed-width` | a slot declares `fixedValueByteLength` (every `owner`): a push one byte short, at every reference | no |
  | `missing-state` | the artifact is stateful (CodeSepMatrix): the honest code part with no `OP_RETURN` after it | no |

  Every tamper must give `matches: false`. When extraction is not pinned to
  raise, the args it reports are not compared: the script is not a deployment
  of the artifact, so there is no honest answer.

Java's `ContractScript.extractConstructorArgs` is package-private; the Java
driver reaches it through `runar.lang.sdk.DriverReadbackAccess`, a class in the
driver's own source tree under the SDK's package name, and maps the `0`
placeholder Java returns for a slotless param to `null`.

## Adding a matrix row

1. Append to `MATRIX` in [`matrix.ts`](matrix.ts) with a `valueClass` that says
   what the row is *for*. If it needs a new contract shape, add it under
   `contracts/`.
2. `cd conformance && npx tsx sdk-vertical/generate.ts`.
3. Review the golden diff — the derived goldens are the reviewable artifact.
4. `npx tsx sdk-vertical/runner/vertical-runner.ts --update-golden` to pin
   `expected-locking.hex`, then re-run without the flag.

## `known-divergences.json`

A tier divergence this gate has found and that is not yet fixed. An entry makes
the divergence **tracked**, not acceptable: listed `(tier, case)` pairs report
as `KNOWN` instead of failing, and the runner then fails in the other
direction if an entry **stops** reproducing — a fixed bug must delete its entry
in the same commit. Any divergence *not* listed fails outright.

Every listed case needs an `expectedFirstDiff` record — `{ byte, golden, tier }`
— naming the EXACT byte the divergence must reproduce (`golden` = what the
independent derivation says belongs there, `tier` = what the divergent tier
actually produces). A `(tier, case)` pair only classifies as `KNOWN` when its
divergence reproduces that exact byte; the loader throws if an entry omits
one. Without this, listing `(tier, case)` alone made ANY divergence on that
pair report as `KNOWN` — a truncated script, an empty result exiting 0 — not
just the one that was actually found and assessed (plan P1-3).

Current entries are fund-safety findings with byte-level evidence; read
[`known-divergences.json`](known-divergences.json) before adding another.

## Scope boundaries

- **State-section framing** is the C2 vertical family, pinned by
  `conformance/sdk-output/tests/stateful-bytestring-op-n-state`. This gate owns
  the **code part** and only asserts that a stateful tail begins with `OP_RETURN`.
- **Signing subscripts** are pinned indirectly through D5 (the baked index) for
  all seven tiers, and directly for TypeScript only: X1 asserts
  `RunarContract.getSubscriptForSigning()` trims at the exact offset the
  independent derivation computes, for every codesep case and every method
  index, and X2 runs a real deploy → call continuation spend of
  `CodeSepMatrix.reseal` — the shifted, multi-byte codesep bake — through
  `@bsv/sdk`'s `Spend`. The other six tiers still only get the D5 indirect
  pin. A per-tier driver that emits each tier's actual `getSubscriptForSigning`
  output would pin it directly for all seven; the sdk-output driver protocol
  prints only the locking script, so that would need six new
  `--emit-subscript <methodIndex>` driver modes (those drivers live in
  `conformance/sdk-output/tools/**`, outside this directory). Recorded as a
  follow-up, not claimed here.
