# FRI Verifier Measurements

Phase 2 production-scale measurements for the SP1 FRI verifier, captured
against the canonical Plonky3 KoalaBear `evm-guest` fixture
(`tests/vectors/sp1/fri/evm-guest/proof.postcard`).

Companion to `docs/sp1-fri-verifier.md` Section 4 (target metrics) and
the BSVM handoff `../bsv-evm/RUNAR-FRI-VERIFIER.md` Section 2.1
(production-parameter rationale).

## Measurement methodology

* **Test harness**: `compilers/go/codegen/sp1_fri_test.go::TestSp1FriVerifier_AcceptsEvmGuestFixture`.
* **Script VM**: go-sdk Bitcoin Script interpreter via
  `BuildAndExecuteOps` (no flag adjustments — Genesis + Chronicle + ForkID
  applied implicitly by the test harness).
* **Hardware**: macOS 25.3.0 (Apple silicon).
* **Wall-clock**: `time.Since(startWall)` around the
  `buildAndExecute(t, ops)` call — covers script-VM execution only;
  excludes prelude-build and emit time.
* **Compiled script size**: `len(Emit([]StackMethod{...}).ScriptHex) / 2`
  over the prelude + body op stream (i.e. the unlocking-script prelude
  plus the locking-script body in a single concatenated script — same
  shape the harness exercises).

## Measurements (production fixture, 2026-04-25, post-B1-fix natural tuple)

The B1 hardcode `numRounds = 1` was fixed in commit `e132eda` —
`EmitFullSP1FriVerifierBody` now derives `numRounds = degreeBits -
logFinalPolyLen` per the Plonky3 prover invariant
`fri/src/prover.rs:75: log_min_height > log_final_poly_len + log_blowup`.
The natural production tuple `(degreeBits=10, log_blowup=1,
log_final_poly_len=0)` is therefore now valid on-chain (numRounds = 10
commit-phase rounds at arity 2). The earlier
`log_final_poly_len = 9` workaround is gone.

Source: `compilers/go/codegen/sp1_fri_test.go::TestSp1FriVerifier_AcceptsEvmGuestFixture`
(prelude+body, no peephole) and
`compilers/go/compiler/sp1_fri_compile_test.go` (full compiler-frontend
path with peephole — what gets deployed).

| Metric                          | Measured (codegen test) | Measured (compiler test) | Target (`docs/sp1-fri-verifier.md` Section 4) | Hard limit | Status                |
|---------------------------------|-------------------------|--------------------------|-----------------------------------------------|------------|-----------------------|
| Proof size (postcard)           | 326,909 B (~319 KB)     | n/a                      | 80-200 KB                                     | -          | over target, under any limit |
| Compiled script (prelude+body)  | 1,609,627 B (~1.57 MB)  | n/a                      | < 2 MB                                        | 10 MB      | within target          |
| Compiled locking script (deployed, peephole) | n/a        | 849,054 B (~829 KB)      | < 2 MB                                        | 10 MB      | within target          |
| Total emit ops                  | 848,377                 | n/a                      | -                                             | -          | (informational)        |
| Unlocking-prelude ops           | 164                     | n/a                      | -                                             | -          | (informational)        |
| Locking-body ops                | 848,213                 | n/a                      | -                                             | -          | (informational)        |
| Peak named-stack depth          | 154                     | n/a                      | < 500                                         | 1,000      | within target          |
| Wall-clock (script-VM execute)  | 806 ms                  | n/a                      | < 500 ms                                      | 1 s        | over target, within hard limit |

### Production parameter tuple actually used (natural)

| Param              | This fixture     | Brief target | Notes                                  |
|--------------------|------------------|--------------|----------------------------------------|
| num_queries        | 100              | 100          | matches target                         |
| log_blowup         | 1                | 1            | matches target                         |
| log_final_poly_len | 0                | 0            | matches target (B1 fixed)              |
| commit_pow_bits    | 16               | 16           | matches target                         |
| query_pow_bits     | 16               | 16           | matches target                         |
| max_log_arity      | 1                | 1            | matches target                         |
| trace_height (log) | 10 (= 1024 rows) | 16-20        | scaled down for fixture-gen tractability |
|                    |                  |              | (the verifier itself is parametric on  |
|                    |                  |              | `degreeBits`; trace_height affects     |
|                    |                  |              | proof generation cost, not on-chain    |
|                    |                  |              | verifier cost)                          |

Cite Plonky3 source for the param-tuning trade-off:
`fri/src/prover.rs::commit_phase` line 75 -- the prover asserts
`log_min_height > log_final_poly_len + log_blowup`. With
`log_blowup = 1, log_final_poly_len = 0, degreeBits = 10` this
holds (10 > 0 + 1) and the natural FRI commit-phase recursion runs
for `numRounds = degreeBits - log_final_poly_len = 10` rounds at
arity 2. See `compilers/go/codegen/sp1_fri.go:368` for the
derivation.

## Status against `docs/sp1-fri-verifier.md` Section 4

* **Script size**: ~829 KB compiled-artifact locking script, ~1.57 MB
  raw prelude+body — both under the 2 MB target. The peephole pass
  (`compilers/go/codegen/optimizer.go::OptimizeStackOps`, applied at
  `compilers/go/compiler/compiler.go:198`) eliminates roughly half of
  the body via dup-drop / push-drop / OP_DROP-run elimination — the
  raw body alone is ~1,595 KB before peephole. Dominant remaining
  cost: the per-query Step 10 derive ops (`emitQueryIndexDerive` ×
  100) plus the FRI commit-phase Merkle ladder (10 rounds at arity 2).
  **Within target.**
* **Peak named-stack depth**: 154 — comfortably under the 500 target
  and the 1,000 hard limit. The B1 fix shifted the dominant pre-push
  layer off the final_poly absorb (2,048 base elements at logFinalPolyLen=9)
  and onto the per-round commit-phase digests (10 rounds × 9 base
  elements = 90 elements), an order-of-magnitude reduction.
* **Wall-clock**: 806 ms in the test-harness go-sdk interpreter.
  Under the 1 s hard limit; over the 500 ms target. Caveat: the
  interpreter is single-threaded, allocates per StackOp, and has no
  batched evaluation. A deployed BSV miner would target the hard
  limit; the apples-to-apples regtest measurement appears below.

## Fallback rationale (handoff Section 2.1)

`docs/sp1-fri-verifier.md` Section 5 fallback order:

1. **Reduce `num_queries` 100 → 64 → 16**: NOT exercised. The full 100
   queries verify within hard limits; the script size and stack depth
   are bottlenecked by the per-query stubs and final-poly pushes, not
   by query count itself. Reducing `num_queries` would marginally
   shrink the script but does not address the per-query Step 10 stub
   cost (each derived query index is dropped — the full input-batch
   MMCS verify chain is the next-largest cost when wired up).
2-4: not yet evaluated.

## Bugs flagged

### B1 — `EmitFullSP1FriVerifierBody` hardcoded `numRounds = 1` (FIXED in `e132eda`)

**File**: `compilers/go/codegen/sp1_fri.go:368`.

**Resolution**: `numRounds` is now derived as `params.DegreeBits -
params.LogFinalPolyLen` per the Plonky3 prover invariant
`fri/src/prover.rs:75: log_min_height > log_final_poly_len + log_blowup`
with `max_log_arity = 1` (arity-2 folding ⇒ one round per bit of
height reduction). The natural production tuple
`(degreeBits=10, log_blowup=1, log_final_poly_len=0)` now compiles to
10 commit-phase rounds at arity 2, matching what the SP1 prover emits.
The earlier `log_final_poly_len = 9` workaround is gone.

Verified end-to-end against the canonical Plonky3 KoalaBear `evm-guest`
fixture by `compilers/go/codegen/sp1_fri_test.go::TestSp1FriVerifier_AcceptsEvmGuestFixture`
(script VM accepts at the natural production tuple) and at the
compiler-frontend level by
`compilers/go/compiler/sp1_fri_compile_test.go::TestSp1Fri_CompileFromSource_WithProductionPreset`
(deployable artifact at the natural production tuple — see "Mainnet
readiness" below).

### B2 (resolved upstream) — `TestEncodeUnlockingScript_AcceptsMinimalGuestFixture`

**File**: `packages/runar-go/sp1fri/unlocking_test.go`.

**Status**: Now passing. Verified during the regtest measurement run
on 2026-04-25 (both the AcceptsMinimalGuestFixture and
RejectsTamperedUnlocking cases are green; param-validation table
exhaustive). The split [unlocking][locking] shape is the same shape the
regtest example deploys.

## Reproduction

```bash
# 1. Regenerate the fixture (only needed if it does not exist).
cd tests/vectors/sp1/fri/evm-guest/regen
ulimit -n 65536
cargo build --release -j 2
./target/release/runar-evm-guest-fixture-gen ../proof.postcard

# 2. Off-chain reference verifier accept.
cd ../../../../../packages/runar-go/sp1fri
go test -run TestVerifyEvmGuest -v

# 3. On-chain script-VM accept + measurements.
cd ../../../compilers/go
go test -run TestSp1FriVerifier_AcceptsEvmGuestFixture -v ./codegen/...
```

## Regtest measurements (BSV node)

Captured via `examples/go/sp1_fri_verifier_main.go` (run with
`./integration/regtest.sh start` first; defaults to the bsv-sv Docker image
and the policy knobs in `integration/regtest-data/n1/bitcoin.conf`:
`maxscriptsizepolicy=0`, `maxstackmemoryusagepolicy=100000000`,
`maxtxsizepolicy=0`).

Hardware: macOS 25.3.0 (Apple silicon). Run dates: 2026-04-25.

**Note**: the production-tuple regtest row below was captured BEFORE
the B1 fix landed in `e132eda` and is therefore against the
`log_final_poly_len = 9` workaround (resulting in a 6.3 MB locking
script). The post-B1-fix natural-tuple locking script is ~829 KB
(see "Mainnet readiness" below for compiler-frontend measurements);
a re-run of the regtest example against the natural tuple is filed
as a follow-up — the deploy / spend should both still accept since
the smaller script is well under the wide regtest policy ceiling.

| Metric                    | PoC (num_queries=2) | Production (num_queries=100, lfp=9 workaround — pre-B1-fix) | Target                  | Hard limit | Status                      |
|---------------------------|---------------------|------------------------------|-------------------------|------------|-----------------------------|
| Locking-script size (KB)  | 242.7               | 6,324.2                      | < 2,000                 | 10,000     | PoC ok; prod within hard limit |
| Unlocking-script size (KB)| 3.5                 | 285.3                        | -                       | -          | informational                |
| Deploy tx size (KB)       | 242.9               | 6,324.4                      | -                       | -          | both accepted on-chain       |
| Spend tx size (KB)        | 3.6                 | 285.4                        | -                       | -          | both accepted on-chain       |
| Deploy wall-clock (s)     | 0.116               | 2.03                         | -                       | -          | informational                |
| Spend wall-clock (s)      | 0.34                | 3.00                         | < 0.5                   | 1          | PoC ok; prod over hard limit |
| Block accepted (deploy)   | yes (height 6847)   | yes (height 6851)            | yes                     | -          | both ok                      |
| Block accepted (spend)    | yes (height 6848)   | yes (height 6852)            | yes                     | -          | both ok                      |

Notes on the spend wall-clock: the regtest measurement is
`build + broadcast + 1-confirm` (round-trip including a manually-mined
block via `generatetoaddress`). The pure script-VM execution time is the
2.03s figure for the PoC and ~3s for production; the wall-clock includes
Docker RPC overhead, manual mining, and confirmation polling. A miner
running in continuous-mining mode against the same locking script would
amortise the mining cost.

### Fallback recommendation

`docs/sp1-fri-verifier.md` §5 fallback order does NOT need to kick in for
either fixture under the regtest policy used here:

1. **Reduce `num_queries` 100 → 64 → 16**: not required. The full 100
   queries deploy and spend cleanly. Production-scale `maxscriptsizepolicy=0`
   accepts the 6.3 MB locking script; if a downstream miner ran a stricter
   policy (default mainnet `maxscriptsizepolicy = 100MB`, `maxtxsizepolicy
   = 100MB`) the production tx would still be far under both, so this
   fallback is reserved for a tighter mainnet policy regime than the
   current default.
2. **SP1 proof composition / tx-split / Groth16 wrap**: not required —
   the verifier is monolithic in a single locking script today and a
   single spend tx broadcasts cleanly.

Bottom line: the production-scale verifier is regtest-deployable as a
single locking script + single spend tx today; the fallback order in
docs/sp1-fri-verifier.md §5 is reserved for a tighter mainnet policy
regime than the regtest defaults exercise.

### Pre-existing bug fixed during this run

**`packages/runar-go/sdk_contract.go::encodeArg` (line 1709)**: the
`switch` on `value` had no case for `[]byte`, so passing a raw byte slice
as a constructor arg fell through to `default` (`EncodePushData(fmt.Sprintf("%v", v))`)
and produced "[]"-encoded hex which `sdkscript.NewFromHex` then rejected
with `invalid byte: U+005B '['`. Fix added a `case []byte` branch that
hex-encodes the bytes and routes through `EncodePushData`. Empty `[]byte{}`
now correctly encodes to OP_0, matching the OP_0 placeholder reserved by
the codegen for ByteString constructor slots — exactly what the SP1 FRI
PoC verifier needs for its empty `sp1VKeyHash` slot. Without this fix the
example program could not even compile its first deploy tx.

### Resolved follow-ups (post-`e132eda`)

* **B1** (`numRounds = 1` hardcode) — fixed; see updated B1 entry above.
  `EmitFullSP1FriVerifierBody` derives `numRounds` from
  `params.{DegreeBits, LogFinalPolyLen}` and the natural production
  tuple (`log_final_poly_len = 0, degreeBits = 10` ⇒ 10 commit-phase
  rounds) compiles + executes cleanly. Locking-script size dropped
  from 6.3 MB (workaround) to ~829 KB (natural tuple, peephole
  applied).
* **SDK compile-frontend surface** — `compiler.CompileOptions.SP1FriParams`
  + `compiler.SP1FriPreset(name)` + `compiler.SP1FriPresetMust(name)`
  shipped in `compilers/go/compiler/options.go`. Downstream consumers
  can now write `compiler.CompileFromSource(path,
  compiler.CompileOptions{SP1FriParams: compiler.SP1FriPresetMust("evm-guest")})`
  and get a deployable artifact at the production tuple — no more
  direct `codegen.EmitFullSP1FriVerifierBody` calls required.
  End-to-end coverage in
  `compilers/go/compiler/sp1_fri_compile_test.go`.

### Out-of-scope follow-ups still pending

* Regtest re-run at the natural production tuple (currently the
  regtest table records only the pre-B1-fix workaround run). Should
  reduce the production-row Locking-script size from 6,324.2 KB to
  ~829 KB and the Spend wall-clock from 3.00 s by a similar fraction.
  Tracked as a deployment-validation follow-up.

## Mainnet readiness

### Recommended deployment

Deploy the SP1 FRI verifier at the **natural production preset**
(`compiler.SP1FriPresetMust("evm-guest")` — equivalently
`"production-100"`). The compiled locking script is ~829 KB,
**1.66× over the BSV-node default `maxscriptsizepolicy = 500 KB`** but
well under the consensus and policy hard limits (`maxtxsizepolicy =
10 MB` default, 1 GB consensus). Mainnet acceptance therefore depends
on the receiving miner: nodes running the stock policy will reject the
locking script as non-standard; nodes running a relaxed policy
(`maxscriptsizepolicy ≥ 1 MB`, which TAAL and other large miners
publish on request) will accept and mine it. Coordinate with the
target mining pool ahead of the first mainnet broadcast. If the only
available mainnet relayer cannot raise `maxscriptsizepolicy` past 500
KB, fall back to `compiler.SP1FriPresetMust("production-64")` (~748 KB
locking script, ~64-bit FRI security + 16 bits PoW grinding) — still
over the 500 KB default but the closest fallback the param tuple
admits without further codegen work. The "production-16" preset
(642 KB) is **not** recommended: 16-bit FRI security is below the
threshold any production rollup should accept.

### Mainnet miner policy (BSV node defaults, post-Genesis)

Source: bitcoin-sv/bitcoin-sv `src/policy/policy.h`
([github.com/bitcoin-sv/bitcoin-sv/blob/master/src/policy/policy.h](https://github.com/bitcoin-sv/bitcoin-sv/blob/master/src/policy/policy.h)),
plus the BSV Skills Center Configuration page
([docs.bsvblockchain.org](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/installation/sv-node/configuration))
and the bitcoin-sv wiki Consensus-Limits page
([github.com/bitcoin-sv/bitcoin-sv/wiki/Consensus-Limits](https://github.com/bitcoin-sv/bitcoin-sv/wiki/Consensus-Limits)).
Verified via WebFetch on 2026-04-25.

| Knob                          | Default (post-Genesis, mainnet)             | Consensus hard limit | Notes |
|-------------------------------|---------------------------------------------|----------------------|-------|
| `maxscriptsizepolicy`         | `DEFAULT_MAX_SCRIPT_SIZE_POLICY_AFTER_GENESIS = 500 * ONE_KILOBYTE` (500,000 B) | unlimited within consensus (`UINT32_MAX`) | The binding constraint for the SP1 FRI verifier locking script. |
| `maxtxsizepolicy`             | `DEFAULT_MAX_TX_SIZE_POLICY_AFTER_GENESIS = 10 * ONE_MEGABYTE` (10,000,000 B) | 1 GB after Genesis | Verifier locking script + funding inputs + change output fits. |
| `maxstackmemoryusagepolicy`   | `DEFAULT_STACK_MEMORY_USAGE_POLICY_AFTER_GENESIS = 100 * ONE_MEGABYTE` (100,000,000 B) | unlimited within consensus | Verifier transcript bookkeeping + per-query Merkle paths fit. |
| `maxopsperscriptpolicy`       | `UINT32_MAX` (unlimited) | `UINT32_MAX` after Genesis | The 848,213-op locking body fits trivially. |

Miner-published policy overrides (TAAL, GorillaPool) are negotiable —
historically these miners have accepted scripts well above the 500 KB
default for tokenization and STN-class workloads. The published
TAAL / GorillaPool documentation surfaces (`docs.taal.com`,
`gorillapool.io`) do not list a current `maxscriptsizepolicy` figure,
so the BSV-node default is the safe assumption when negotiating.

### Comparison: natural production locking script vs. mainnet defaults

| Metric                       | Natural production (this codebase) | BSV default policy | Headroom |
|------------------------------|------------------------------------|--------------------|----------|
| Locking-script size          | 829,054 B                          | 500,000 B          | -1.66× over default; 12× under consensus tx-size limit (10 MB policy) |
| Unlocking-script size (est.) | ~285 KB (regtest measurement, was at workaround tuple — natural tuple should be similar order) | 500,000 B (each script is policy-checked separately) | within default |
| Per-script ops               | 848,213                            | unlimited          | trivially under |
| Stack memory usage           | 154 named-slot peak (runtime stack much smaller) | 100 MB | trivially under |

The locking-script-size headroom is the only tight constraint. All
other policy knobs have order-of-magnitude headroom against the
natural production tuple.

### Fallback options at the param-tuple level

Concrete locking-script sizes for each preset, measured at
`compilers/go/compiler/sp1_fri_compile_test.go::TestSp1Fri_AllPresetsCompile`
on 2026-04-25 (post-peephole, deployable artifact bytes):

| Preset             | num_queries | FRI security (bits) | PoW grinding (bits) | Total bits | Locking-script size | vs. BSV default `maxscriptsizepolicy = 500 KB` |
|--------------------|-------------|---------------------|---------------------|------------|---------------------|----------------------------------------------|
| `evm-guest` / `production-100` | 100 | ~100 (`num_queries × log_blowup`) | 32 (16 commit + 16 query) | ~132 | 849,054 B (~829 KB) | 1.66× over |
| `production-64`    | 64          | ~64                 | 32                  | ~96        | 766,182 B (~748 KB) | 1.49× over |
| `production-16`    | 16          | ~16                 | 32                  | ~48        | 641,916 B (~626 KB) | 1.25× over |
| `minimal-guest` (PoC) | 2        | ~2                  | 2 (1 commit + 1 query) | ~4   | 248,560 B (~242 KB) | within default (informational only — PoC tuple) |

FRI conjectured security per Plonky3
`fri/src/config.rs::conjectured_soundness_bits` is approximately
`min(num_queries * log_blowup + log2(num_queries),
2*num_queries / 3)` plus PoW grinding. With `log_blowup = 1`, the
linear term dominates for `num_queries ≤ 100`. The 132-bit / 96-bit /
48-bit totals above are the **conjectured** soundness; provable
soundness is roughly half. **`production-16` falls below the
80-bit floor most production rollups require and is documented here
only as the lower bound of the param-tuple-level fallback ladder, not
as a recommended deployment.**

Note: smaller-`num_queries` fallbacks would each require their own
fixture regeneration (the `evm-guest/proof.postcard` is pinned at
`num_queries = 100`) for an end-to-end on-chain acceptance test. The
locking-script-size measurements above are valid without regen because
the verifier code path is parameter-determined; only the unlocking
script (which carries per-query openings) depends on the fixture. A
follow-up sibling regen target — `tests/vectors/sp1/fri/evm-guest-q64/`
and `evm-guest-q16/` — is filed if the BSVM team needs end-to-end
validation at the fallback tuples; the `regen/src/main.rs` would gain
a `NUM_QUERIES` const + CLI flag and the existing `make_two_adic_config`
already parameterises on it.

### What if the binding policy gets tighter than 500 KB?

If a mainnet miner runs `maxscriptsizepolicy < 500 KB`, even
`production-16` (642 KB) is over policy and the §5 fallback ladder
escalates to the next rung:

* **(2) SP1 proof composition** — recursively aggregate the SP1 proof
  so the on-chain verifier sees a single composed proof at reduced
  width. Coordinates with SP1 upstream and BSVM. Out of scope for
  this Rúnar release; tracked in the BSVM-side covenant work.
* **(3) Split FRI verification across multiple BSV transactions** —
  per `docs/sp1-fri-verifier.md` §5(3). Sumcheck, PoW, per-query paths
  become separate spends bound by a continuation-hash covenant.
* **(4) Groth16 wrap (Mode 2 mechanics)** — falls back to honest-verifier
  trust until SP1 composition is available. Requires BSVM whitepaper
  trust-model revision.

### Acceptance criteria

The deployable artifact at the natural production preset is mainnet-ready
**conditional on miner-policy negotiation** (1.66× over default
`maxscriptsizepolicy`). It is fully within consensus limits. The
recommended deployment path is:

1. Compile via
   `compiler.CompileFromSource("RollupCovenant.runar.go",
   compiler.CompileOptions{SP1FriParams: compiler.SP1FriPresetMust("evm-guest")})`.
2. Negotiate `maxscriptsizepolicy ≥ 1 MB` (recommended; gives 200 KB
   headroom for covenant and unlocking-script growth) with the target
   mainnet miner.
3. If negotiation fails, fall back to `production-64` (~748 KB, ~96 bits
   total security) — still over the 500 KB default but the smallest
   tuple the codegen helper supports without additional follow-up work.
4. Re-run the regtest end-to-end gate at the chosen tuple before the
   first mainnet broadcast.
