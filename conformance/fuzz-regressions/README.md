# Fuzzer regression corpus

A permanent, checked-in corpus of **minimised reproducers of divergences the
Rúnar differential fuzzers actually found**, replayed on **every CI run**.

## Why this exists

The nightly fuzzers (`conformance/fuzzer/index.ts`, driven by
`.github/workflows/fuzzer-nightly.yml`) are loud when they find something: the
workflow runs under `set -euo pipefail` with zero `continue-on-error`, so a
divergence hard-fails the job.

What they do **not** do is *persist* the finding. Each fuzz mode writes its
reproducer into `conformance/fuzz-findings-<oracle>/`, and the workflow uploads
that tree as a CI artifact with `retention-days: 30`. Thirty days later the
reproducer is gone, and nothing ever replays it. A bug found once is only ever
covered again **by chance** — the fuzzer has to rediscover it.

This corpus closes that loop. Every entry here is a bug the fuzzer found, that a
human minimised, that is now replayed deterministically forever.

## The contract

Five rules. They are what make the corpus worth having.

1. **Every entry is a real finding.** An entry is a minimised reproducer of a
   divergence the fuzzer (or an audit of the same oracle) actually found. Not a
   hypothetical, not a unit test that happens to touch the same code. If it
   never diverged in practice, it belongs in the ordinary test suite instead.
2. **Every entry passes today.** The corpus is a *regression guard*, not an
   xfail list. An entry is only added once the underlying bug is fixed, and it
   pins the post-fix verdicts. `--promote` refuses to create an entry whose
   oracle still diverges.
3. **Entries are never deleted.** A fixed bug stays covered forever. If an entry
   becomes hard to keep passing, that is a signal about the change under review,
   not a reason to drop the entry. Removing one requires an explicit rationale in
   the PR description.
4. **Replay runs on every CI run.** Not nightly. The gate is deterministic and
   costs well under a second for the whole corpus, so it runs on every PR (see
   *CI wiring* below).
5. **Deterministic, no network.** No RNG, no seeds, no clock, no I/O beyond
   reading the entry. Same inputs, same bytes, same verdicts, every run. An entry
   that cannot be made deterministic is not added.

## Layout

```
conformance/fuzz-regressions/
  README.md                        <- this file
  replay.ts                        <- the replay runner (and --promote)
  entries/
    <YYYY-MM-DD>-<slug>/
      entry.json                   <- manifest: inputs + pinned verdicts + guards
      contract.runar.ts            <- the minimised contract
```

### `entry.json`

| field | meaning |
| --- | --- |
| `id` | must equal the directory name |
| `title` | one line describing the divergence |
| `discovered` | ISO date the divergence was found |
| `oracle` | which oracle the entry replays against — `execute` or `tri-modal` (see Scope) |
| `sourceFile` | contract file, relative to the entry directory |
| `fileName` | name handed to the compiler; selects the frontend parser |
| `method` | public method spent through |
| `constructorArgs` | encoded constructor args (see below) |
| `args` | encoded method args, in declaration order |
| `expect.interpreterAccepted` | pinned ANF-interpreter verdict |
| `expect.vmAccepted` | pinned ScriptVM verdict |
| `requiredOpcodes` | opcodes the compiled script MUST still contain |
| `provenance` | original finding dir, fixing commits, issue, reconstruction notes |
| `rationale` | why these exact verdicts are the correct ones |

Argument encoding is **identical to the encoding saved findings already use**
(`jsonifyArg` in `conformance/fuzzer/execute-differential.ts`), which is what
makes promotion a near-copy rather than a translation:

- bigint → `"255n"`
- boolean → `true` / `false`
- ByteString → `"0xdeadbeef"`

### Why verdicts are pinned, not just "they agree"

Asserting only `interpreterAccepted === vmAccepted` is too weak: a change that
breaks **both** engines the same way keeps `agrees` true and the entry stays
green. Each entry therefore pins the exact expected verdict of *each* engine, so
a regression is caught whether it desynchronises the engines or corrupts both.

### Why `requiredOpcodes` exists

A regression entry that no longer reaches the code path it was written for is
worthless — it keeps passing green while covering nothing. Each entry names the
Script opcodes its compiled locking script must still contain. If a future
optimiser folds the interesting operation away, the entry fails loudly with
`no longer exercises OP_LSHIFT` instead of silently degrading to a no-op.
`loadCorpus` rejects an entry with an empty `requiredOpcodes` list.

## Running it

```bash
cd conformance

npm run fuzz:replay                                  # replay the whole corpus
npx tsx fuzz-regressions/replay.ts --verbose         # ... printing every entry
npx tsx fuzz-regressions/replay.ts --filter shift    # ... only matching ids
npx tsx fuzz-regressions/replay.ts --list            # list the corpus
npx tsx fuzzer/index.ts --replay                     # same gate via the fuzzer CLI
```

Exit code is non-zero if any entry fails, and the failing entry ids are printed.

## Adding a new entry

### The short version

```bash
cd conformance

# 1. Fix the bug the fuzzer found. Do NOT skip this — see rule 2.

# 2. Promote the findings directory into a corpus entry.
npx tsx fuzz-regressions/replay.ts \
  --promote fuzz-findings-execute/2026-08-01T12-00-00-000Z-Foo-bar \
  --id 2026-08-01-foo-op-and-length \
  --title "OP_AND aborts on a length mismatch the interpreter accepted" \
  --fixed-by abc1234,def5678 \
  --issue "#142"

# 3. Read the generated entry.json. Fill in `rationale` — a reviewer must be
#    able to tell from the entry alone WHY these verdicts are correct.

# 4. Confirm it passes, then commit the entry directory.
npm run fuzz:replay
```

`--promote` does the following, and refuses in the failure cases:

- reads `finding.json` + `contract.runar.ts` from the findings directory;
- **re-runs the oracle at current HEAD** to capture the *post-fix* verdicts —
  the verdicts stored in `finding.json` are the divergent ones from when the bug
  was live and must never be pinned;
- **refuses if the oracle still diverges**, telling you to fix the bug first;
- auto-populates `requiredOpcodes` by intersecting the compiled script with the
  `SEMANTIC_OPCODES` table in `replay.ts` (the byte-array bitwise/shift ops,
  the non-trivial arithmetic ops, the splice ops, and the crypto ops);
- **refuses if that intersection is empty**, because the entry would have no
  anti-triviality guard. Either add the opcode to `SEMANTIC_OPCODES` or write
  the entry by hand;
- **refuses to overwrite an existing entry** (rule 3).

### Writing an entry by hand

Promotion covers the `--execute` oracle, whose findings carry a rendered TS
contract. For a finding from another oracle, or one you have minimised by hand,
create the directory yourself with the two files above. Keep it minimal: strip
every property, parameter, and statement that is not needed to reproduce the
divergence. A 5-line contract that fails for one reason is worth more than the
80-line generated one it came from.

## CI wiring

The replay is a step in the **TypeScript Compiler** job of
`.github/workflows/ci.yml` (named *Fuzzer regression corpus replay*). That job
already runs `pnpm install` + `pnpm run build`, which is everything the replay
needs — the TS compiler and `runar-testing`'s `@bsv/sdk`-backed `ScriptVM`. No
native compiler toolchain, no new job, no extra checkout.

The nightly fuzzer workflow is unchanged. Randomised discovery stays nightly;
replay of what discovery already found runs on every PR.

## Scope

Entries replay through `runDifferentialExecution`
(`packages/runar-testing/src/oracle/differential-execution.ts`) — the **same**
differential path `conformance/fuzzer/index.ts --execute` uses: the compiler's
fold-ON deployed bytes on the `@bsv/sdk`-backed `ScriptVM` versus the ANF
interpreter, asserting accept/reject.

That oracle is in-process and TS-only, so it cannot run contracts needing a real
transaction context or real crypto.

An entry declares which oracle it replays against, and `replay.ts` supports two:

- `execute` — the bare `ScriptVM` accept/reject verdict. `ScriptVM.success` is
  "no evaluation error and truthy top of stack"; it does NOT apply the consensus
  wrappers, so it does not enforce minimal encoding, clean stack, or push-only
  unlocking.
- `tri-modal` — the CONSENSUS verdict (`Spend.validate()`). Required for any
  divergence only a real node sees. `1 >> 1` leaves a non-minimal `[0x00]`: a
  node aborts when a numeric op consumes it, while the bare VM accepts. Pinning
  such an entry against `execute` would record the weaker engine's verdict as
  if it were the chain's.

R-253: this section used to say findings from anything but `--execute` "are not
replayable here yet; add a second `oracle` kind to `replay.ts` when the first
such finding needs pinning". That kind landed, and
`2026-08-17-shift-nonminimal-zero-numeric-consume` uses it. A reader following
the old text would have concluded a consensus-only regression could not be
pinned here, and not pinned one.

Findings from the cross-tier parity oracles (`--anf`, `--ir`, `--canonical`) are
still not replayable through this corpus.

## Current entries

| id | guards |
| --- | --- |
| `2026-07-12-shift-truncation` | `<<` is OP_LSHIFT over script-number bytes (length-preserving), not a native bigint shift |
| `2026-07-12-invert-byte-semantics` | `~` is OP_INVERT over script-number bytes, not numeric two's-complement |
| `2026-07-14-chained-shift-and-length-mismatch` | **funds loss** — chained `(x << 8) & 0` aborts on-chain; the interpreter called the spend valid |
| `2026-07-14-chained-shift-or-nonminimal` | chained `(x << 8) \| 5` succeeds on-chain; the interpreter aborted (opposite direction of the same bug) |
| `2026-08-06-branch-k1-empty-pad-guard-bypass` | **funds risk** — a K=1 branch merge padded the shorter arm with an EMPTY push and registered it as the merged value, so the script accepted a spend the source rejects |
| `2026-08-17-shift-nonminimal-zero-numeric-consume` | **funds locking** — `1 >> 1` leaves a non-minimal `[0x00]`; a numeric consumer aborts on chain while the interpreter accepted. Pinned against the `tri-modal` (consensus) oracle, not `execute` |

The first four come from the shift/bitwise semantics bug fixed in PR #141
(commits `61796893`, `88bb6903`, `694c891b`). The original
`fuzz-findings-execute/` directories had already passed their 30-day artifact
retention by the time this corpus was created — which is precisely the gap this
directory exists to close — so the reproducers were reconstructed from the
divergences documented verbatim in those commit messages and re-verified against
the current oracle. Each entry's `provenance.note` records that.
