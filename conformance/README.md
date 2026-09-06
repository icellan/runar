# Rúnar Conformance Tests

**Cross-compiler conformance test suite ensuring all Rúnar compilers produce identical output.**

The conformance suite is the enforcement mechanism for Rúnar's multi-compiler strategy. It contains golden-file test cases (source + expected IR + expected script), a test runner, and a differential fuzzer. Every Rúnar compiler -- TypeScript, Go, Rust, Python, Zig, Ruby, and Java -- must pass the full suite *for the tiers each fixture lists in its `compilers` allowlist*.

Most fixtures run on every tier. A small number opt out of one or more tiers — see [Per-fixture compiler allowlist](#per-fixture-compiler-allowlist) below.

---

## Purpose

Rúnar defines a **canonical IR conformance boundary** at the ANF level. For any given source program, all conforming compilers must produce byte-identical ANF IR (serialized via RFC 8785). The conformance suite verifies this property.

Additionally, the compiled Bitcoin Script output must be identical across compilers. The script is the final artifact deployed on-chain, so even a single-byte difference could mean a different locking script hash and a non-functional contract.

---

## Test Structure

Each test case is a directory containing:

```
tests/
+-- basic-p2pkh/
|   +-- basic-p2pkh.runar.ts      # Source contract (TypeScript)
|   +-- basic-p2pkh.runar.sol     # Source contract (Solidity-like)
|   +-- basic-p2pkh.runar.move    # Source contract (Move-style)
|   +-- basic-p2pkh.runar.go      # Source contract (Go)
|   +-- basic-p2pkh.runar.rs      # Source contract (Rust)
|   +-- basic-p2pkh.runar.py      # Source contract (Python)
|   +-- basic-p2pkh.runar.zig     # Source contract (Zig)
|   +-- basic-p2pkh.runar.rb      # Source contract (Ruby)
|   +-- basic-p2pkh.runar.json    # Reference artifact (JSON AST, not tested by runner)
|   +-- expected-ir.json          # Expected ANF IR (canonical JSON)
|   +-- expected-script.hex       # Expected compiled script (hex string)
|
+-- arithmetic/
|   +-- arithmetic.runar.ts
|   +-- arithmetic.runar.sol      # (+ .move, .go, .rs, .py variants; .json is a reference artifact)
|   +-- expected-ir.json
|   +-- expected-script.hex
|
+-- boolean-logic/
|   +-- boolean-logic.runar.ts    # (+ multi-format variants)
|   +-- expected-ir.json
|   +-- expected-script.hex
|
+-- if-else/
|   +-- if-else.runar.ts          # (+ multi-format variants)
|   +-- expected-ir.json
|   +-- expected-script.hex
|
+-- bounded-loop/
|   +-- bounded-loop.runar.ts     # (+ multi-format variants)
|   +-- expected-ir.json
|   +-- expected-script.hex
|
+-- multi-method/
|   +-- multi-method.runar.ts     # (+ .sol, .move, .go, .rs, .py variants)
|   +-- expected-ir.json
|   +-- expected-script.hex
|
+-- stateful/
|   +-- stateful.runar.ts         # (+ multi-format variants)
|   +-- expected-ir.json
|   +-- expected-script.hex
|
+-- post-quantum-wots/
|   +-- post-quantum-wots.runar.ts
|   +-- expected-ir.json
|   +-- expected-script.hex
|
+-- post-quantum-slhdsa/
|   +-- post-quantum-slhdsa.runar.ts
|   +-- expected-ir.json
|   +-- expected-script.hex
|
+-- ec-primitives/
|   +-- ec-primitives.runar.ts
|   +-- expected-ir.json
|   +-- expected-script.hex
|
+-- auction/                       # (+ 15 more test directories)
+-- convergence-proof/
+-- covenant-vault/
+-- ec-demo/
+-- escrow/
+-- function-patterns/
+-- math-demo/
+-- oracle-price/
+-- post-quantum-wallet/
+-- property-initializers/
+-- schnorr-zkp/
+-- sphincs-wallet/
+-- stateful-counter/
+-- token-ft/
+-- token-nft/
```

> **Note:** Most test directories also contain multi-format source variants (`.runar.sol`, `.runar.move`, `.runar.go`, `.runar.rs`, `.runar.py`, `.runar.zig`, `.runar.rb`, `.runar.java`). All format variants must produce the same ANF IR and script output for every compiler tier the fixture targets. Sources live under `examples/<format>/<case>/` and `source.json` references them by relative path. Several test directories also include `.runar.json` (JSON AST) files; these are reference artifacts for tooling and are **not** tested by the conformance runner.

### Per-fixture compiler allowlist

`source.json` may carry an optional `"compilers"` field that restricts which compilers run against that fixture. **When the field is absent, the contract is implicit: every tier (TypeScript, Go, Rust, Python, Zig, Ruby, Java) must produce byte-identical IR + script output.** When present, only the listed tiers are exercised — both the IR-stage and hex-stage golden checks honour the allowlist (see `runner/runner.ts`).

Allowlists are reserved for fixtures whose underlying Stack-IR primitives are intentionally not yet implemented in every tier. They are not a place to hide ordinary cross-compiler bugs — the lone supported reasons are documented below.

Every `source.json` carrying a `compilers` allowlist must ALSO carry a non-empty `compilersJustification` string explaining WHY the listed tiers are scoped (e.g. `"Codegen for {primitive} is Go-only by project policy — see CLAUDE.md"` or `"Java Stack-IR pass for {feature} is deferred — see HANDOFF"`). The `allowlist-audit.test.ts` test fails if any allowlist is missing its rationale.

The parser layer is tier-agnostic: the conformance runner's `discoverFormats()` asserts that every fixture ships all nine `*.runar.{ts,sol,move,go,rs,py,zig,rb,java}` source files (referenced from `source.json`'s `sources` map) regardless of the `compilers` allowlist. A fixture may opt OUT of a single format at the parser layer by listing it in `source.json`'s `parserSkip` array along with a non-empty `parserSkipReason` string — that escape hatch exists for genuinely blocked ports (e.g. a Move-syntax limitation for a complex contract). Lazy multi-format opt-outs are not allowed; if you find yourself reaching for `parserSkip` for more than one format, port the contract instead.

#### Per-tier universal parser coverage

The runner's `--parser-only` mode (CI step "Run all-tier parser-only coverage") **runs every available compiler's `--parse-only` entry point against every fixture × every declared format**, ignoring the per-fixture `compilers` allowlist. The allowlist scopes Stack-IR / hex parity ONLY — the parser layer is universal, so all 7 tiers (TypeScript, Go, Rust, Python, Zig, Ruby, Java) MUST accept all 9 formats for every fixture. Each compiler exposes `--parse-only` (Java additionally accepts `parseOnly: true` in its JSON-RPC daemon) which runs Pass 1 (parse) + Pass 2 (validate) and exits zero with `parser ok` on success or non-zero with diagnostics on failure. A non-zero exit fails the CI job.

Run locally:

```bash
cd conformance && npx tsx runner/index.ts --parser-only
```

#### Cross-tier IR → hex parity (`--ir-parity`) — the single source of truth

The runner's `--ir-parity` mode (CI step "Run IR -> hex cross-tier parity") compiles every fixture's checked-in `expected-ir.json` with all six **non-TS** tiers and requires byte-identical script hex plus equality with `expected-script.hex`. It gates each tier's `--ir` loader + Stack-IR + emit path, complementing the source-driven `--multi-format` mode (which is where the TypeScript tier is covered).

Unlike `--parser-only`, this gate **is** scoped by the per-fixture `compilers` allowlist — hex parity is exactly what the allowlist governs. A fixture whose allowlist has no overlap with the six non-TS tiers is skipped. The mode always runs fold-OFF (`--disable-constant-folding`), regardless of `RUNAR_DISABLE_CONSTANT_FOLDING`, because the goldens were stamped fold-OFF; fold-ON parity is `--multi-format`'s job.

This replaces ~180 lines of inline bash/jq that `.github/workflows/ci.yml` used to carry, which held its **own** copy of the allowlist rule and could drift from the runner's. The workflow step is now a thin caller. `runar-verification/scripts/cross-compiler-diff.sh` remains a separate implementation — it is the Tier-6.1 verification gate and additionally drives the Lean reference tier, which this runner does not know about. **If you change parity or allowlist semantics, change `runner/runner.ts` first and mirror it there.**

Run locally:

```bash
cd conformance && npx tsx runner/index.ts --ir-parity
```

#### Audited allowlists

The complete set of fixtures with a `compilers` allowlist is enumerated and pinned by `runner/__tests__/allowlist-audit.test.ts`. That test fails if a new allowlist appears (or an existing one drifts) without being approved here, so the set cannot silently expand. Adding a new allowlisted fixture requires **both**:

1. Adding the fixture's expected allowlist to `APPROVED_ALLOWLISTS` in `runner/__tests__/allowlist-audit.test.ts`.
2. Adding a row to the table below with a one-line rationale (and the matching `compilersJustification` string in the fixture's `source.json`).

##### Go-only crypto family

These fixtures exercise the Baby Bear / KoalaBear / Poseidon2 / BN254-witness / FRI / Merkle / FiatShamir-KB Stack-IR codegen modules, which currently ship in the Go compiler only (Mode-3 STARK / FRI verification flows). See CLAUDE.md ("Go-only crypto codegen modules").

| Fixture | Allowlist | Rationale |
|---|---|---|
| `babybear` | `["go"]` | BabyBear prime-field arithmetic; Stack-IR codegen ships in Go only. |
| `babybear-ext4` | `["go"]` | BabyBear Ext4 extension-field operations; Stack-IR codegen ships in Go only. |
| `merkle-proof` | `["go"]` | SHA-256 Merkle-root verification using the Go-only Merkle codegen helpers. |

##### EVM/STARK proof-system primitives (Go-only by project policy)

Hybrid contracts whose method bodies call EVM/STARK primitives also fall under the Go-only scope above (see CLAUDE.md "EVM/STARK proof-system primitives are Go-only by project policy"). Their parsers are still exercised by every tier via the all-tier `--parser-only` matrix, but the IR + hex golden checks run only against the Go codegen.

| Fixture | Allowlist | Rationale |
|---|---|---|
| `state-covenant` | `["go"]` | Uses `bbFieldMul` (BabyBear field) and `merkleRootSha256` (4-deep Merkle proof). Both are EVM/STARK primitives — Go is the canonical reference; partial ports in TS/Rust/Python/Zig/Ruby exist for historical reasons but are not conformance targets, and Java is not exempt due to a deferred port — it is exempt because the entire family is Go-only. |

(The former `schnorr-zkp` oversize-bigint exemption is gone: every tier now carries the 256-bit secp256k1 group order through parse → ANF → codegen as a decimal-string-backed `BigIntLiteral`, so `schnorr-zkp` runs across all 7 tiers with no allowlist.)

### Fold-ON allowlist (`conformance/fold-on-allowlist.json`)

CI runs the multi-format conformance suite **twice**: once with `--disable-constant-folding` passed to every compiler (matching the byte-stable goldens checked into each fixture) and once with `RUNAR_DISABLE_CONSTANT_FOLDING=0` so every compiler runs its end-user default (folding ON). The second run enforces cross-tier hex + ANF parity across all 7 tiers but skips the golden-file comparison (because the goldens were stamped fold-OFF).

A fixture (or a specific format variant of a fixture) that is known to fail the fold-ON cross-tier check must be listed in `conformance/fold-on-allowlist.json` with a per-entry `reason` (and ideally a `tracking` ref). The runner refuses to load entries that lack a non-empty `reason` — there is no "bare list" mode. The fold-OFF run is unaffected, so allowlisting only relaxes the dual-mode parity check, not the canonical golden coverage.

The allowlist is currently **empty** (`"skip": []`): there are no fold-ON exemptions, so every fixture is enforced across all 7 tiers under both fold modes. If a fold-ON-only divergence is ever introduced, add an entry here (with a `reason`) and to `conformance/fold-on-allowlist.json` in the same commit.

### File Roles

| File | Purpose |
|---|---|
| `*.runar.ts` | The source contract. Input to the compiler. |
| `expected-ir.json` | The expected ANF IR output. Canonical JSON (RFC 8785, no whitespace, sorted keys). The SHA-256 of this file is the conformance check. |
| `expected-script.hex` | The expected compiled Bitcoin Script as a hex string. If present, the compiler's script output must match exactly. |

---

## How the Test Runner Works

The runner (in `runner/`) performs these steps for each test case:

```
For each test directory:
  1. Read the .runar.ts source file.
  2. Invoke the compiler under test to produce ANF IR.
  3. Serialize the compiler's ANF IR using canonical JSON (RFC 8785).
  4. Compare SHA-256(compiler_output) with SHA-256(expected-ir.json).
  5. If expected-script.hex exists:
     a. Invoke the compiler to produce the final script.
     b. Compare the script hex with expected-script.hex.
  6. Report pass/fail.
```

### Running the Conformance Suite

```bash
# Run all conformance tests (TypeScript compiler)
pnpm test

# Output as JSON or Markdown
pnpm run test:json
pnpm run test:markdown

# Filter to a specific test
pnpm run test:filter -- arithmetic

# Test all input format variants (.ts, .sol, .move, .go, .rs, .py, .zig, .rb, .java)
pnpm test -- --multi-format

# Run cross-SDK locking-script conformance (all 7 SDK tools)
pnpm run sdk-output
```

The runner compiles each test case with the TypeScript reference compiler and compares the output against the golden files.

### Harness failures vs conformance failures (NEW-003)

The runner separates *"the compilers disagree"* from *"the runner never got an
answer out of a compiler"*, and gives them different exit codes:

| Exit | Meaning |
| ---- | ------- |
| `0`  | All fixtures passed and every compiler subprocess produced usable output. |
| `1`  | **Conformance failure** — tiers diverged, or a golden did not match. |
| `2`  | **Harness failure** — a compiler subprocess timed out, was killed by a signal, blew the output-capture cap, or failed to spawn. |

Exit `2` takes precedence over exit `1`: a run whose subprocesses died did not
measure parity, so its board is not a verdict in *either* direction. Harness
faults are listed under a `HARNESS FAILURE` banner and each one also emits a
`::error::conformance harness:` line for CI annotation. Per-fixture error lines
from a dead subprocess are prefixed `HARNESS:` so the board never shows a
killed tier as though it had an opinion about the script.

This exists because it silently failed the other way. `runCmd` used to fold a
signal death (`code === null`) into exit status `0`, so a SIGKILLed compiler
looked like a successful compile and its half-drained stdout became that tier's
"script". Two flake shapes came out of that one line:

* pipe empty at kill time → `reported success but produced empty hex: [zig, ruby]`
* pipe drained mid-write → `majority [6 tiers] vs [x] identical up to length`

Both blamed six innocent tiers for a resource problem. The invariant now pinned
in `runner/__tests__/subprocess-integrity.test.ts`: **a child that did not exit
under its own control has no output worth reading**, and neither `--hex` stdout
nor a `tolerateHexFailure` fallback may be taken from one.

Tuning knobs when a loaded host trips this:

* `RUNAR_CONFORMANCE_COMPILE_TIMEOUT_MS` (default `180000`) — per-invocation
  budget for a native compiler. It is a **hang detector, not a performance
  budget**: killing a slow-but-healthy child destroys its output mid-pipe,
  which is the whole failure mode above, so keep it generous. Worst observed
  single invocation on an 8-core host is ~5.6s at the default concurrency and
  ~33s at 10x oversubscription.
* `RUNAR_CONFORMANCE_CONCURRENCY` (default `max(2, min(8, cpus/4))`) — outer
  fixture parallelism. Each fixture fans out to up to 7 compiler processes, so
  the default already runs ~14 children on an 8-core host.

---

## How to Add New Test Cases

1. Create a new directory under `tests/` with a descriptive name:

```bash
mkdir conformance/tests/my-new-test
```

2. Write the source contract:

```bash
# conformance/tests/my-new-test/my-new-test.runar.ts
```

3. Generate the expected IR using the reference compiler:

```bash
runar compile conformance/tests/my-new-test/my-new-test.runar.ts --ir
# Canonical JSON serialization (RFC 8785) is applied automatically.
# Copy the ANF IR output to expected-ir.json
```

4. Optionally generate the expected script:

```bash
runar compile conformance/tests/my-new-test/my-new-test.runar.ts
# Copy the script hex to expected-script.hex
```

5. Run the conformance suite to verify the new test passes:

```bash
pnpm test
```

---

## Differential Fuzzing

The fuzzer (in `fuzzer/`) generates random valid Rúnar programs and tests compiler correctness by comparing against the reference interpreter.

### How It Works

```
  +----------+      +-----------+      +----------+
  |  Fuzzer   | --> | Compiler  | --> | Script VM |
  | generates |     | compiles  |     | executes  |
  | random    |     | to script |     |           |
  | .runar.ts  |     |           |     |           |
  +----------+      +-----------+      +----------+
       |                  |                  |
       |                  v                  v
       |           +-------------+    +-----------+
       +---------> | Interpreter | -->| Compare   |
                   | evaluates   |    | results   |
                   | ANF IR      |    |           |
                   +-------------+    +-----------+
                                           |
                                      pass / MISMATCH
```

If the compiler + VM produce a different result than the interpreter, a bug has been found. The fuzzer saves the failing program for reproduction.

### Running the Fuzzer

```bash
# Run 100 random programs (default)
pnpm run fuzz

# Run 10 programs with verbose output
pnpm run fuzz:quick

# Run with a specific count and seed (for reproducibility)
pnpm run fuzz -- --num 5000 --seed 42

# Use fast-check property-based mode (with shrinking)
pnpm run fuzz:property
```

### IR-based Fuzzing (Richer Grammar, All 7 Compilers)

The legacy fuzzer (above) emits a single `.runar.ts` source and feeds it to every compiler. A newer IR-based generator produces a language-neutral contract description (`GeneratedContract`) and can render it either as shared TypeScript or as each compiler's native source (`.runar.go`, `.runar.rs`, `.runar.py`, `.runar.zig`, `.runar.rb`, `.runar.java`). The IR generator covers multiple property types (`bigint`, `boolean`, `ByteString`, `PubKey`, `Sig`), stateful contracts, multiple methods, built-in calls (`hash160`, `sha256`, `abs`, `min`, `max`, etc.), and `if/else` bodies.

```bash
# Run the IR generator, compare compiled hex across all 7 compilers
pnpm run fuzz:ir -- --num 100 --seed 1

# Render each compiler's native source format (stresses the frontends too)
pnpm run fuzz:ir:native

# Mix stateful contracts into the sample
pnpm run fuzz:ir:stateful
```

Failing cases are written to `conformance/fuzz-findings-ir/<timestamp>/` with one `source-<compiler>.txt` and one `output-<compiler>.txt` per compiler plus a `finding.json` describing the mismatch.

### Script-Level Static Analysis

Compiled scripts can be checked independently of the compiler via `runar analyze`:

```bash
# Hex string
runar analyze 76a90088ac

# .hex file
runar analyze conformance/tests/basic-p2pkh/expected-script.hex

# Artifact JSON (reads the "script" field)
runar analyze artifacts/Counter.json

# Stdin
cat script.hex | runar analyze -

# JSON output / filter by severity
runar analyze 76a90088ac --json
runar analyze 76a90088ac --severity warning
```

The analyzer enumerates spending paths, runs symbolic stack analysis along each, and reports findings: stack underflow, unreachable code after `OP_RETURN`, unbalanced `OP_IF/OP_ENDIF`, branches that leave inconsistent stack depths, paths with no signature check or no verification at all (would allow anyone to spend), dropped `OP_CHECKSIG` results, `OP_CODESEPARATOR` presence, inefficient `OP_PUSHDATA` encodings, and oversized scripts.

---

## Golden File Management

Golden files (`expected-ir.json`, `expected-script.hex`) are checked into version control. When the spec changes in a way that affects IR output:

1. Update the spec documents in `spec/`.
2. Update the reference compiler.
3. Regenerate all golden files:

```bash
pnpm run update-golden
```

4. Review the diffs to verify the changes are expected.
5. Commit the updated golden files alongside the compiler changes.

Golden file updates should always be reviewed carefully. An unexpected change in a golden file indicates either a compiler bug or an unintended spec change.

### Golden-regeneration integrity gate (issue #122)

Goldens are **self-produced** by the very implementation under test — `pnpm run update-golden` writes whatever the compilers currently emit. That is a structural hazard: a PR can silently regenerate a golden to match a *buggy* new output, and the suite then validates the corrupt bytes against itself and ships green ("corrupt scripts validated by self-consistent tests"). The gate closes that hole. It does **not** replace the golden comparison — it adds an admission check so that *changing* a golden requires an **independent** cross-check, not just the compiler's own say-so.

**What it guards.** Any file in the PR's changed set (three-dot diff against the merge-base) matching one of the self-produced golden/vector families:

- `conformance/tests/**/expected-script.hex`
- `conformance/tests/**/expected-ir.json`
- `conformance/runtime-vectors/*.json` (official-KAT hash vectors)
- `conformance/sdk-output/tests/**/expected-*.hex`
- `conformance/sdk-vertical/cases/*/expected-*.{hex,json}` (the compiler↔SDK vertical pins — `expected-code-part.hex`, `expected-vertical.json`, `expected-locking.hex`)
- `conformance/sdk-vertical/artifacts/*.json` (the compiled artifacts those cases splice; `constructorSlots[].byteOffset` and `codeSeparatorIndices` live here)
- `conformance/analyzer/**/expected-analyzer-report.json`
- `conformance/source-map/**/expected-source-map.json`
- `conformance/script-size-baseline.json`
- `packages/decompiler/coverage-baseline.json`

(The authoritative matcher list lives in `GOLDEN_MATCHERS` in `conformance/scripts/check-golden-provenance.mjs` — extend it there when a new golden family is added.) Pure **deletions** are ignored (removing a golden is not a regeneration risk); non-golden changes are a no-op.

> The sdk-vertical goldens are guarded **even though** `expected-code-part.hex` and `expected-vertical.json` are written from an independent re-implementation (`sdk-vertical/reference/`, which imports nothing from `packages/**`). "Derived from an independent oracle" is a reason to *trust* a regeneration, not a reason to skip *reviewing* one: that reference lives in this repo and can be changed by the same PR that moves the bytes. `sdk-vertical/cases/*/input.json` is deliberately **not** guarded — it is a verbatim copy of the guarded `artifacts/*.json` plus literal constructor args, written by the same `generate.ts` run, and a lone hand-edit turns the vertical runner red against derived goldens it cannot also move.

**How a golden change is justified.** For **each** changed golden, the gate requires **one** of:

- **(A) Scoped cross-check co-change** — for a fixture golden `conformance/tests/<fixture>/expected-{script.hex,ir.json}`, the same PR also modifies that fixture's independent execution oracle `conformance/witnesses/<fixture>.json`. The differential-execution oracle (`witnesses/differential.test.ts`) re-runs the declared spends through a *second* engine (ANF interpreter + `@bsv/sdk` ScriptVM), so the fixture's new bytes get an accept/reject check that does not come from the compiler that produced them. This is the ergonomic happy-path for a legitimate codegen change.
- **(B) Provenance allowlist entry** — an entry in `conformance/golden-provenance-allowlist.json` (works for **any** golden, including runtime-vectors, sdk-output, analyzer, source-map, and coverage-ledger fixtures with no witness):

  ```json
  {
    "path": "conformance/tests/arithmetic/expected-script.hex",
    "sha256": "<sha256 of the NEW file bytes>",
    "verified-against": "official-KAT | second-implementation | differential-oracle | intentional-spec-change",
    "reason": "why the new bytes are correct + which independent oracle confirmed them",
    "reviewer": "gh:your-handle",
    "review-status": "reviewed"
  }
  ```

  The entry is **content-pinned**: `sha256` must equal the current bytes of the golden. Because the pin is content-addressed, an entry can only ever justify the *one* value it was reviewed for — a later, *different* regeneration of the same file fails the gate again and forces a fresh, re-reviewed entry. This is what prevents a stale exemption from silently authorizing future silent regenerations. `verified-against` records the class of independent oracle; `reason` and `reviewer` make the sign-off explicit and reviewable in the allowlist diff. Exactly **one** entry per path — a duplicate `path` is rejected, because the shadowed entry is the one a reviewer would read.

  **`reviewer` must be true, not conventional — and the gate now enforces it.** A provenance record whose sign-off is fabricated is worse than no record, because it launders exactly the self-regeneration the gate exists to catch. The 2026-08 audit found the earlier version of this rule being satisfied on paper and defeated in practice: 27 entries carried `"reviewer": "unreviewed:generated-by-agent"` **and** `"review-status": "unreviewed"` — a machine-written string that literally records that nobody checked the golden — and the gate accepted every one of them, because it only ever tested that `reviewer` was a non-empty string and never read `review-status` at all.

  The gate therefore now **rejects** any entry whose `reviewer` matches `/^unreviewed:/` or whose `review-status` is anything other than the omitted-legacy case or `"reviewed"` (so `unreviewed`, `pending`, `todo` and typos all fail). A rejected entry justifies nothing: the golden it names is treated as if the entry were absent, and the gate exits non-zero. Both directions are covered by `--self-test` (`b1-unreviewed-reviewer`, `b1-unreviewed-status`, `b1-status-typo`, `b1-reviewed`).

  The practical consequence: **there is no way to park an unreviewed golden in the allowlist.** If you regenerated a golden and cannot yet name the independent oracle that confirms it, do not write a placeholder entry — leave the golden unjustified and let the gate stay red until someone reviews it. `reason` should name the oracle you actually ran and what it reported, and should describe the delta the `sha256` **pin authorizes** (cumulative vs the merge base), not the delta of whichever single commit you happened to be writing up.

**Running it.**

```bash
# Auto-detect the changed set vs the merge-base (CI mode); base defaults to
# origin/main, override with --base <ref> or $GOLDEN_GATE_BASE.
node conformance/scripts/check-golden-provenance.mjs --base origin/main

# Print the sha256 of every changed golden (to fill in an allowlist entry).
node conformance/scripts/check-golden-provenance.mjs --print-hashes --base origin/main

# Prove both directions still work (reject-without-justification / pass-with).
node conformance/scripts/check-golden-provenance.mjs --self-test
```

**CI wiring.** The `golden-provenance-gate` job in `.github/workflows/ci.yml` runs on `pull_request` (no `continue-on-error`), checks out with `fetch-depth: 0`, and passes the PR base commit SHA via `$GOLDEN_GATE_BASE` (through `env:`, never interpolated into a shell command). It runs the checker in auto-detect mode and then `--self-test` so the gate cannot rot into a silent no-op. The script is dependency-light (Node built-ins + `git`; no `pnpm install`).

### Provenance discipline — the rule for regenerating a golden (plan §F3)

The gate above is the *mechanism*. This is the **rule** it enforces, written down so it can be cited in review (testing-gap remediation plan §F3).

> **Regenerating a golden requires `verified-against` PLUS a witness/oracle co-change whenever execution exists for that fixture. There are no silent golden-only PRs for control-flow or wire fixtures.**

Read as three obligations:

1. **Name the independent oracle.** Every allowlist entry carries `verified-against`, drawn from a closed set — `official-KAT`, `second-implementation`, `differential-oracle`, `intentional-spec-change` — plus a `reason` naming *which* oracle confirmed the new bytes and a `reviewer` sign-off. "The compiler emits this now" is not a `reason`; it is the thing being questioned.

2. **Co-change the execution evidence when execution exists.** If the fixture has a witness (`conformance/witnesses/<fixture>.json`), a real-crypto spec (`conformance/witnesses/real-crypto/<fixture>.json`), a Go script-execution case, or an integration spend, the PR that moves the golden must move that evidence too — and, for a fixture golden, pin the new sha256 in the witness's `goldenHashes`. A bare witness touch does **not** satisfy path (A): the differential-execution oracle compiles fresh from source (fold-ON) and never reads the fold-OFF golden, so it cannot validate the regenerated bytes. Only a deliberate, self-invalidating content pin can.

3. **Golden-only is the failure mode, not the happy path.** A PR whose entire diff is regenerated goldens has, by construction, no independent check in it. That is acceptable for a genuinely-external re-derivation (`official-KAT`) and essentially never for a **control-flow** fixture (branch merges, loops, `if`-without-`else` — the PALMER-1 surface) or a **wire** fixture (state framing, push encoding, constructor slots, codeSeparator — the PALMER-2 surface). For those two families the reviewer should expect to see, in the same diff, either a moved witness/`expectedState` or a moved vertical pin. If neither moved, the bytes changed and nothing re-derived them.

This is the mirror image of the [must-move-a-golden](#encoding-change-checklist-must-move-a-golden) rule below. Together: *changing a wire encoder without moving a golden is untested*, and *moving a golden without moving an oracle is unjustified*. Both are cheap to satisfy honestly and both are exactly what #110 and the branch-merged-locals miscompile lacked.

#### Introducing a NEW golden family

A brand-new family of self-produced goldens is a two-step obligation, and step 2 is the one that gets forgotten — the comment above `GOLDEN_MATCHERS` has asked for step 1 since issue #122, and the `sdk-vertical` family still arrived without it.

1. **Register the family.** Add a matcher to `GOLDEN_MATCHERS` in `conformance/scripts/check-golden-provenance.mjs`, add the glob to the guarded list in this README, and state in the matcher's comment why any *near*-golden in the same directory is deliberately excluded (the way `sdk-vertical/cases/*/input.json` is). An unregistered family is not "provisionally trusted"; it is ungated.

2. **Stamp every file in it.** Additions count as changes (`--diff-filter=ACMRT`), so the introducing PR must justify each new golden exactly like a regeneration. There is no grandfather clause, and that is deliberate: the first version of a golden is the one nobody has ever compared against anything.

```bash
# List every changed/added golden with its sha256, ready to paste into
# conformance/golden-provenance-allowlist.json.
node conformance/scripts/check-golden-provenance.mjs --print-hashes --base origin/main
```

Write a **real** `reason` per entry — which independent oracle produced or confirmed those bytes, and what value class the file covers. A batch of identical boilerplate reasons across N files is not provenance; it is a signature on something nobody read. If a family is large enough that per-file review is impractical, that is a signal the family needs a *generator* whose output is itself checked (like `sdk-bip143`'s `--check` mode), not a longer allowlist.

---

## Weak coverage kinds (plan §F4)

Some `coveredBy.kind` values in this directory's ledgers are genuinely weaker than others, and the difference is load-bearing. Written down so it is not re-litigated per PR (testing-gap remediation plan §F4 / TG-014):

> **`go-family-exec` and deploy-only integration are NOT substitutes for fixture-byte execution.**

- **`go-family-exec`** claims that *some contract in the same primitive family* executed on the Go engine. It does not claim that *this fixture's compiled bytes* ever ran. A composed contract can be wrong in the composition while every primitive in the family is right.
- **Deploy-only integration** proves a locking script was accepted into a transaction output. Nothing has spent it. Deploy is not a script execution of the covenant — the covenant runs at *spend* time, which is where every fund-safety bug in this repo has lived.
- **`go-script-exec`** and **`real-crypto-witness`** are the strong kinds: this fixture's compiled bytes, on a real engine, with an accept and a near-miss reject (and, for stateful accepts, a pinned `expectedState`).

**Policy.** No new weak `coveredBy.kind` may be introduced without a written **why-not-fixture-exec** — a specific statement of what blocks the strong gate, in the ledger entry itself, in the style of the existing `add-raw-output` entry ("the SDK deploy→call path funds a single continuation output; it cannot compose the separate 1000-sat raw output, so a real Spend rejects a valid spend"). "Structurally redundant with X" is a claim about two contracts being similar, which is not evidence about bytes.

### Known residual: cross-tier agreement standing in for an absolute pin

One live entry does not meet the bar above and is recorded here rather than quietly relabelled (plan §P6 — honest residuals).

`conformance/sdk-output/coverage-allowlist.json` justifies omitting the `add-raw-output` byte golden on the grounds that a method-call output mismatch is:

> "caught by the dedicated ANF parity fixture `conformance/anf-interpreter/inputs/add-raw-output-publish.json` (lenient + strict goldens), which fans out across all 7 SDK driver outputs and asserts byte-equal `{state, dataOutputs, rawOutputs}` envelopes."

That is **seven-way agreement between the seven SDKs' own ANF interpreters** offered as the sole reason to skip an absolute byte pin — the §2 P7 anti-pattern this plan exists to name. Seven interpreters can be identically wrong; that is the entire lesson of PALMER-2, where all seven SDKs moved together and every cross-SDK comparison stayed green.

Mitigating facts, so the residual is sized honestly rather than dramatised:

- The **deploy-time locking script** for `add-raw-output` is not unpinned. It is byte-pinned by `conformance/tests/add-raw-output/expected-script.hex` across the compiler tiers; the allowlist only omits the *SDK-layer* mirror of a locking script the entry argues is identical to a stateless wrapper's.
- The **method-time raw-output behaviour** does have a strong gate today: `conformance/script_execution_test.go`'s `TestRawOutput_ScriptExecution_Accept` / `_Reject_RawOutputAbsent` hand-build the exact `[rawOutput, continuation, change]` transaction and execute the compiled bytes on the go-sdk engine. `conformance/witnesses/coverage-ledger.json` already records this as **superseding** the ANF-parity claim.

So the residual is narrow: the *allowlist entry's stated rationale* is a cross-tier-agreement argument, and it has not been rewritten to cite the strong gate that now exists. **Close plan:** rewrite that entry's rationale to point at `script_execution_test.go` (the argument the coverage ledger already makes), which costs nothing and removes the last place in this directory where horizontal agreement is written down as sufficient. Not done here because that file is outside this change's scope.

---

## Encoding-change checklist (must move a golden)

The golden-provenance gate above asks *"you changed a golden — prove the new bytes are right."* This section is its complement: **"you changed a wire encoder and no golden moved — then nothing checked the bytes at all."**

**Why.** In 2026-08 a change altered the state-section wire framing in **all seven SDK serializers** and moved **zero** pinned bytes. Every suite was green and cross-SDK conformance was 46/46 — because the encoder and the decoder were co-changed and every test was a round-trip. `deserialize(serialize(x)) === x` holds for **any** self-consistent framing, including a wrong one. The result was a state section the compiler no longer agreed with. So: **a wire-format change that moves no pinned bytes is untested by definition**, and it blocks CI instead of reassuring anyone.

**The rule (enforced, not advisory).**

```text
changed ∩ wire-format paths ≠ ∅   ∧   changed ∩ STRONG pin paths = ∅   ⇒   CI fails
```

**Why "strong" (2026-08-06).** The rule used to accept *any* pin, weak ones included, and only print a `⚠` when every pin was weak. Replaying the literal changed set of `bd7ec284` — the incident commit this whole section exists for — through the gate exited **0**: that commit co-added `packages/runar-sdk/src/__tests__/encode-push-data-minimaldata.test.ts`, whose name matches the `*minimaldata*` tier-local pin glob, and one weak pin was enough. A round-trip-class test added in the *same* commit as the encoder it exercises is not independent evidence of anything — it is the encoder graded against its own inverse, and it asserted the wrong framing as correct. The weak-pin allowance had been granted because `conformance/sdk-vertical/**` did not exist yet; it does now (39 cases × 7 tiers of absolute compiler↔SDK pins), so a strong pin is available to every wire-format change. `conformance/scripts/__tests__/wire-format-pr-audit.test.ts` carries the replay as a named regression (`bd7ec284 (the incident this gate exists for)`).

**Before you push a change to any wire-format path, do one of these:**

1. **Move a pinned byte artifact** (preferred) — `conformance/tests/<fixture>/expected-script.hex`, `conformance/sdk-output/tests/*/expected-*.hex`, `conformance/sdk-vertical/cases/*/expected-*`, `conformance/anf-interpreter/expected*/*.json`, `conformance/sdk-bip143/fixtures.json`, or a `conformance/witnesses/real-crypto/*.json` witness. If no existing fixture exercises the value class you changed, **add one**. "No fixture covers it" is the hole, not the excuse — that is precisely why the 1-byte OP_N-range ByteString state bug shipped.
2. **Add a cross-component pin** for the primitive you touched — a byte comparison against the **other** implementation of the format (compiler ↔ SDK, or SDK ↔ peer SDK). Never `deserialize(serialize(x)) === x` alone; see the plan's design principle P3. A tier-local unit test is recorded as a **weak pin** and named in the report, but it does **not** satisfy the gate on its own — write it *and* move a strong pin.
3. **Record an explicit, dated `UNCOVERED`** — strongly discouraged for wire format. Add an entry to `conformance/wire-format-exceptions.json`:

   ```json
   {
     "path": "packages/runar-sdk/src/state.ts",
     "reason": "why no pinned bytes can move",
     "date": "2026-08-05",
     "expires": "2026-09-05",
     "sha256": "<sha256 of that file's reviewed content>",
     "reviewer": "gh:your-handle"
   }
   ```

   Entries are **per exact path** (no globs) and every field is required. `expires` is capped at **180 days** after `date` and is a **hard failure** once passed — a wire waiver is always temporary. `sha256` **content-pins** the exact reviewed version of the file (same mechanism as `golden-provenance-allowlist.json`), so an exception granted for a comment-only touch cannot silently cover the *next* change to the same file; a stale pin is printed as `NOT applied` and the gate fails. Every applied exception is **printed on every run**, and the *entry count is asserted to be zero* by the gate's own test suite — adding one means editing that assertion in the same PR, in the open.

**Which paths count as wire format.** The authoritative list is `WIRE_FORMAT_RULES` in [`scripts/wire-format-pr-audit.ts`](scripts/wire-format-pr-audit.ts) — it is **not duplicated here**, so it cannot drift out of sync. Nine families:

| Family | What it frames |
|---|---|
| `sdk-state-serialization` | State-section framing written into the deployed locking script, + `STATE_FIELD_WIDTHS` (the one width/encoding table the compiler *and* the SDK read) |
| `push-data-encoding` | Push-data / MINIMALDATA opcode selection (`encodeArg`, `encodePushData`) |
| `constructor-slot-splicing` | Constructor-arg splicing at `constructorSlots` offsets |
| `codeseparator-emit-and-artifact` | `OP_CODESEPARATOR` emission + the artifact fields (and JSON schema) SDKs read |
| `sighash-scriptcode` | BIP-143 scriptCode built from the codeSeparator offsets |
| `bip143-sighash-preimage` | Hand-rolled BIP-143 signing-preimage serialization (Rust/Python/Ruby/Java) |
| `state-framing-stack-lower` | `OP_RETURN` / P2PKH output framing + `addOutput` ordering — emitted by **anf-lower** as well as stack-lower |
| `sdk-anf-interpreter` | Off-chain ANF interpreters: post-state values + the output order `hash256(outputs)` binds |
| `sdk-transaction-assembly` | `codePart ‖ OP_RETURN ‖ state` and multi-contract unlocking-script assembly done outside the per-tier contract module |

The pin list lives beside it: `BYTE_ARTIFACT_PIN_GLOBS` (content **is** the bytes), `WEAK_PIN_GLOBS` + the two-part `TIER_LOCAL_PIN_*` match (evidence *about* bytes), and `CONTENT_SENSITIVE_PIN_GLOBS`. Three properties are load-bearing:

- **Liveness.** Every glob in both lists is liveness-checked by `scripts/__tests__/wire-format-pr-audit.test.ts`: a glob that matches no file is a **hard test failure**, because a gate whose globs match nothing reports green forever.
- **Anchors.** Liveness proves a *path* exists, not that the encoding logic still lives in it. `WIRE_FORMAT_ANCHORS` pins byte tokens (`1976a914`, `88ac`, `STATE_FIELD_WIDTHS`, …) to the files that must still contain them, so extracting an encoder into a new file turns the gate's own test red until the new file is globbed.
- **Pin ≠ any file under `conformance/`.** A *strong* pin means the file's content **is** the wire bytes. Inputs (`input.json`), runners, generators, contracts and prose are **not** pins, and a witness diff that touches only free-text `note`/`description` fields does **not** count — the gate reads the merge-base blob and compares the note-stripped evidence.
- **Weak ≠ sufficient.** Tier-local framing tests and `construct-ledger.json` stay *classified* as pins (they are listed in the report, and a doc merely *named* `*codesep*` is still not a pin at all), but a changed set whose pins are all weak now **fails**. See "Why 'strong'" above.

**Known limitation.** Comment/doc-only diff detection is **not** implemented for *implementation* files. Classifying a hunk as "comments only" across seven grammars (line comments, block comments, docstrings, strings containing comment markers) fails **open** when it gets it wrong — a real byte change misread as a comment would pass silently, which is the one failure mode this gate must not have. Use an exceptions entry for the rare comment-only touch of a wire file. (Free-text detection *is* implemented for the JSON witness pins, where the format is known and the failure direction is safe: an unparseable or non-JSON diff is always treated as material.)

**Running it.**

```bash
# Auto-detect the changed set vs the merge-base (CI mode); base defaults to
# origin/main, override with --base <ref> or $WIRE_FORMAT_GATE_BASE.
# Always pass a REF (origin/main), never a pinned SHA.
pnpm run wire-format-audit -- --base origin/main

# Feed an explicit newline-delimited changed set.
pnpm run wire-format-audit -- --changed-file /tmp/changed.txt

# Report the failure but exit 0 (the plan's optional one-PR warn phase).
pnpm run wire-format-audit -- --warn-only

# The gate's own tests, including glob liveness and the #110 regression.
pnpm run wire-format-audit:self-test
```

**CI wiring.** The `wire-format-must-move-golden` job in `.github/workflows/ci.yml` runs two steps.

- The **self-test** (`pnpm run wire-format-audit:self-test`) runs on **every** event, so a rename on `main` that turns a glob into a permanent no-op is caught the moment it lands.
- The **audit** step runs in **fail** mode on `pull_request`, on `merge_group`, **and on `push` to `main` / `release/*`**. The push path is not optional: the 2026-08 state-framing commit this gate exists for was pushed straight to `main`'s first-parent chain and was never a PR, so a `pull_request`-only gate would have watched it go past. Base resolution per event: `origin/<pull_request.base.ref>` → `merge_group.base_sha` → `github.event.before` → `HEAD^`. It is deliberately a **ref**, not `pull_request.base.sha`: that SHA is the base tip as of the PR's last sync, while the checkout is `refs/pull/N/merge` against the *current* base, so diffing from it sweeps in every golden other PRs merged in between — and one of those would satisfy this gate for free. The script resolves `git merge-base <ref> HEAD` at run time. Only base refs/SHAs from `github.event.*` are consumed, passed via `env:` and never interpolated into a shell command.

> **Branch protection is not configurable from the repository.** For this job to actually block, `Lint — wire-format must-move-a-golden gate` must be added to the **required status checks** for `main` and `release/*` in the repository settings (and to the merge queue's required checks). Nothing in this repo can assert that; until an admin does it, the job reports but does not gate.

---

## Construct ledger

`construct-ledger.json` + `construct-ledger.test.ts` count coverage in **fund-critical constructs** — language shapes and wire value classes — instead of fixtures. Every other gate in this directory answers "is this fixture exercised?". This one answers "is this *shape* exercised?", which is a different question and the one both 2026-08 fund-safety bugs failed:

- **branch-merged locals with ≥2 merged locals** — an `if` carries ONE value, so post-branch references kept naming the dead pre-branch binding and stack lowering registered one `stackMap` slot for N physical results. All seven compilers agreed, byte for byte, on a permanently unspendable script generated from idiomatic source.
- **a 1-byte ByteString state value in the OP_N range** — #110 taught the seven SDKs MINIMALDATA and none of the seven compilers, so the state section was written `OP_5` and read `<len><data>`.

Neither was a missing fixture. Both were **empty cells** in this matrix while the fixture-counted suite was green.

### How to add a row

1. **Pick an `id`** (stable slug) and add it to `REQUIRED_CONSTRUCTS` in `construct-ledger.test.ts` if the construct is fund-critical. That array is hard-coded **in the test file, not derived from the ledger** — deriving it would make the gate vacuous, since deleting a row would delete its own requirement. CI stays red until the row exists.

   The two directions are both checked, so the requirement cannot be edited red-to-green. `REQUIRED_CONSTRUCTS` and the ledger's row ids must be **the same set**: an id with no row fails (the original direction), and a row with no id also fails — otherwise a construct is silently demoted by deleting one line in the test file while its row stays put. This file has no CODEOWNERS, so a PR that trips the gate could otherwise just delete the id it trips on; `MIN_REQUIRED_CONSTRUCTS` is a committed floor on the set's size that may be raised freely and lowered only as its own reviewed, argued diff.

2. **Add the row** to `construct-ledger.json` under `constructs`, with `category` (`language` | `control-flow` | `wire` | `artifact`), `severity` (`fund-critical` | `correctness`), and a human-readable `description`. The enums are closed so a typo cannot invent an unreviewed coverage axis.

3. **Fill the cell — honestly.** A row carries `coveredBy` **XOR** (`status: "UNCOVERED"` + `issue`). Never both, never neither.

   ```jsonc
   {
     "id": "merge-locals-k2-asymmetric",
     "category": "control-flow",
     "severity": "fund-critical",
     "description": "Two locals merged across an `if` whose arms reassign DIFFERENT ones.",
     "coveredBy": [
       { "kind": "real-crypto-witness",
         "path": "conformance/witnesses/real-crypto/branch-merged-locals.json",
         "note": "Both arms accept with expectedState pinned; tamperOutput rejects." }
     ]
   }
   ```

   Every `path` is **repo-relative**, must exist on disk, and must be **non-empty** — a zero-byte file and an empty directory both fail, because bare `existsSync` waved them through and "the path exists" is not "the evidence exists". Deleting or renaming a witness turns its construct **red** rather than letting the claim silently decay — that detection is the point of the file, so do not "fix" such a failure by deleting the row.

   `kind` is one of `conformance-fixture`, `real-crypto-witness`, `sdk-output`, `vertical-pin`, `negative-compile`, `vm-unit`; the vocabulary is documented in the ledger's own `_doc` block and enforced in the test.

   **`kind` must also match the SHAPE of the `path` it claims.** Enum membership alone let `{"kind": "real-crypto-witness", "path": "conformance/README.md"}` pass every gate while the schema doc calls that the strongest kind in the file. `KIND_SHAPE` in the test makes each `kind` a checkable claim about *what the evidence is*:

   | `kind` | accepted shape |
   |---|---|
   | `real-crypto-witness` | `conformance/witnesses/real-crypto/<fixture>.json` — the only files `real-crypto-execution.test.ts` executes |
   | `conformance-fixture` | `conformance/tests/<fixture>/` containing `source.json`, or its `conformance/witnesses/<fixture>.json` spend spec |
   | `sdk-output` | `conformance/sdk-output/tests/<name>/` containing `expected-locking.hex` |
   | `vertical-pin` | a compiler↔SDK test **file**, or `conformance/sdk-vertical/cases/<name>/` containing `expected-locking.hex` |
   | `vm-unit`, `negative-compile` | a test **file**, never a directory |

4. **If there is genuinely no evidence, say so.** An honest empty cell is the entire deliverable; a cell pointed at a weak or unrelated file is worse than nothing, because it converts a visible hole into a false claim.

   ```jsonc
   {
     "id": "loop-carried-locals-k2",
     "category": "control-flow",
     "severity": "fund-critical",
     "description": "A bounded loop carrying >=2 locals across iterations, then addOutput.",
     "status": "UNCOVERED",
     "issue": "Plan Phase D1. Verified empty 2026-08-05: every loop in the repo carries exactly one local. CLOSE PLAN: add a k=2 loop-carried contract to branch-merged-locals-vm.test.ts, then a sibling fixture."
   }
   ```

   `issue` must be a tracking ref **or a dated close plan sentence** — enough that the next reader knows what was checked, when, and what would close it.

5. **Round-trip evidence is rejected.** `ROUND_TRIP_ONLY_PATHS` in the test file denylists tests that only assert `deserialize(serialize(x)) === x`. A self-inverse cannot detect a change that moves encode and decode together, which is exactly how the OP_N framing bug survived seven SDKs. Cite an absolute byte pin, a cross-implementation golden, or a real-crypto witness with `expectedState` instead.

   **The denylist itself is checked live.** Every `ROUND_TRIP_ONLY_PATHS` entry must still name a real file. Nothing used to assert that, so renaming or deleting a denylisted test silently turned its entry into a no-op — the file could then be cited as coverage with no gate firing, the same decay mode the sibling wire-format gate defends against. Re-point a stale entry at the file's new path, or delete it deliberately with a note saying why.

```bash
# Run the gate
pnpm run conformance:construct-ledger
```

**CI wiring.** The `conformance` job in `.github/workflows/ci.yml` runs it as the **Construct ledger gate** step, immediately after the per-fixture differential execution step.

**Relationship to `witnesses/coverage-ledger.json`.** That ledger is per-**fixture** ("the plain differential oracle does not execute this fixture — what covers it instead?"). This one is per-**construct** ("which fund-critical shape is exercised, by what?"). One fixture supplies evidence to several constructs, and several constructs have no fixture at all. Same machine-checked style, different axis — see [Why the other ledgers stay separate](witnesses/README.md#why-the-other-ledgers-stay-separate).

---

## Current Test Cases

The suite currently contains **64 fixtures** under `tests/` — that directory is the authoritative list (`find tests -name source.json | wc -l`). The table below describes the most commonly referenced ones. Tier scoping (which compilers run a fixture) is governed solely by the [Per-fixture compiler allowlist](#per-fixture-compiler-allowlist) above — do not infer it from this table.

| Test | Exercises | Has Script Golden |
|---|---|---|
| `add-data-output` | `this.addDataOutput(satoshis, bytes)` intrinsic | Yes |
| `add-raw-output` | `this.addRawOutput(satoshis, scriptBytes)` intrinsic | Yes |
| `arithmetic` | Binary arithmetic operations (+, -, *, /, %) | Yes |
| `auction` | Stateful auction with bidding and closing | Yes |
| `babybear` | BabyBear prime-field arithmetic | Yes |
| `babybear-ext4` | BabyBear Ext4 extension-field operations | Yes |
| `basic-p2pkh` | Property loading, hash160, checkSig, assert | Yes |
| `bitwise-ops` | Bitwise operators (&, \|, ^, ~, <<, >>) on bigint + ByteString | Yes |
| `blake3` | BLAKE3 compression + full-hash builtins | Yes |
| `boolean-logic` | Logical operators (&&, \|\|, !), short-circuit lowering | Yes |
| `bounded-loop` | Loop unrolling in ANF IR | Yes |
| `convergence-proof` | Convergence proof patterns | Yes |
| `covenant-vault` | Covenant spending constraints | Yes |
| `cross-covenant` | Cross-contract covenant validation | Yes |
| `ec-demo` | EC point operation demos | Yes |
| `ec-primitives` | EC point operations (ecAdd, ecMul, ecMulGen, etc.) | Yes |
| `ec-unit` | Fine-grained EC unit tests | Yes |
| `escrow` | Multi-party escrow with multiple spending paths | Yes |
| `function-patterns` | Private helper methods and function call patterns | Yes |
| `go-dsl-bytestring-literal` | `.runar.go` DSL `ByteString` literal grammar | Yes |
| `if-else` | Conditional branches in ANF IR | Yes |
| `if-without-else` | if-only conditionals | Yes |
| `math-demo` | Built-in math functions (abs, min, max, sqrt, pow, etc.) | Yes |
| `merkle-proof` | Merkle-root verification | Yes |
| `multi-method` | Method dispatch table generation | Yes |
| `oracle-price` | Rabin signature oracle price feed | Yes |
| `p256-primitives` | NIST P-256 EC primitives | Yes |
| `p256-wallet` | P-256 wallet contract | Yes |
| `p384-primitives` | NIST P-384 EC primitives | Yes |
| `p384-wallet` | P-384 wallet contract | Yes |
| `post-quantum-slhdsa` | SLH-DSA (SPHINCS+) signature verification | Yes |
| `post-quantum-wallet` | WOTS+ wallet contract | Yes |
| `post-quantum-wots` | WOTS+ hash chain signature verification | Yes |
| `property-initializers` | Default values on contract properties | Yes |
| `schnorr-zkp` | Schnorr zero-knowledge proof (EC ops) | Yes |
| `sphincs-wallet` | SLH-DSA wallet contract | Yes |
| `state-covenant` | Stateful covenant constraints | Yes |
| `stateful` | State updates, checkPreimage, getStateScript | Yes |
| `stateful-bytestring` | Stateful ByteString mutations | Yes |
| `stateful-counter` | Stateful counter with increment | Yes |
| `token-ft` | Fungible token with split/merge | Yes |
| `token-nft` | NFT with transfer/burn | Yes |

### Script execution oracle

`script_execution_test.go` compiles a curated set of contract families to their
**fold-ON deployed bytes** (the compiler default), builds a valid spend witness,
and executes the unlocking+locking scripts through the go-sdk Bitcoin Script
interpreter. Every contract family also ships adversarial **near-miss** witnesses
(wrong key, wrong state, tampered signature, off-curve point) that MUST fail.
Gated in CI by the `Script Execution Oracle` job. It is a curated family list
(not a completeness gate over every fixture); the TS `witnesses/differential.test.ts`
ScriptVM also executes fold-ON bytes against a script engine.

### SDK-output conformance (46 fixtures, 7 SDKs)

`sdk-output/tests/` contains 46 fixtures (one `input.json` + one
`expected-locking.hex` per directory). The runner in `sdk-output/runner/sdk-runner.ts`
compiles each fixture through all seven SDK tools in `sdk-output/tools/` (TypeScript,
Go, Python, Ruby, Rust, Zig, Java) and asserts byte-identical locking-script hex
across every SDK. Invoke with `pnpm run sdk-output`.

Coverage gate: `sdk-runner.ts` runs `--audit` before each suite execution
(and exposes the same audit standalone via `npx tsx conformance/sdk-output/runner/sdk-runner.ts --audit`).
The audit fails CI on any compiler-conformance fixture (`conformance/tests/`)
that is absent from `sdk-output/tests/` AND not listed in
`conformance/sdk-output/coverage-allowlist.json`. The allowlist is the only
approved way to opt a fixture out of SDK-output coverage; every entry carries
a one-line rationale and is checked for staleness on each audit run.

### Cross-tier BIP-143 sighash interop (GAP-003)

`sdk-bip143/` is the cross-tier gate for **BIP-143 transaction sighash
preimage construction** — proving the seven SDKs build the *same* preimage
bytes for the same spend, independent of any node. (Before this, BIP-143
deploy/call sighash was only tested per-tier against a regtest node; two tiers
could diverge on a consensus-irrelevant byte, or skip a scenario, and still
ship green.)

- `sdk-bip143/generate-fixtures.ts` — TypeScript reference generator. TS owns
  the de-facto golden BIP-143 path (`@bsv/sdk` `TransactionSignature.format`,
  the exact code `runar-sdk`'s LocalSigner / oppushtx use). It hand-builds an
  unsigned raw tx per scenario, computes the full preimage, and signs
  `sha256d(preimage)` with a fixed test key (priv=1, RFC-6979 + low-S — same
  convention as `sdk-envelope/` signing vectors, so the DER signature is
  byte-reproducible). Run `npx tsx sdk-bip143/generate-fixtures.ts` to
  regenerate; `--check` re-derives and fails on drift without rewriting (the
  CI drift guard).
- `sdk-bip143/fixtures.json` — frozen fixture. Two scenarios:
  `p2pkh_spend` (stateless, SIGHASH_ALL|FORKID) and `counter_call` (the
  stateful OP_PUSH_TX path, using the compiled `Counter` contract as the
  subscript + a stateful-continuation + OP_RETURN output shape). Each scenario
  carries everything a consumer needs to recompute the preimage:
  `{ unsignedTxHex, inputIndex, prevScriptHex, prevValueSats, sighashFlags }`
  plus expected `{ preimageHex, digestHex, sigHex, pubkeyHex }`.
- Per-tier replay tests load the fixture, **independently recompute** the
  BIP-143 preimage from the tx + prevout, assert byte-equality with
  `preimageHex` (the core node-free check), assert `sha256d(preimage)` equals
  `digestHex`, and verify the TS-produced `sigHex` against `pubkeyHex` over
  their own digest. They live beside each tier's `envelope_interop` peer:
  Go `packages/runar-go/sdk_bip143_interop_test.go`,
  Rust `packages/runar-rs/tests/bip143_interop.rs`,
  Python `packages/runar-py/tests/test_bip143_interop.py`,
  Ruby `packages/runar-rb/spec/runar/sdk/bip143_interop_spec.rb`,
  Zig `packages/runar-zig/src/sdk_bip143_interop_test.zig`,
  Java `packages/runar-java/src/test/java/runar/lang/sdk/Bip143InteropTest.java`.
  All seven tiers (TS reference + six consumers) are green and byte-identical.
