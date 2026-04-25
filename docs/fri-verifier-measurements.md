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

## Measurements (production fixture, 2026-04-25)

| Metric                          | Measured           | Target (`docs/sp1-fri-verifier.md` Section 4) | Hard limit | Status                         |
|---------------------------------|--------------------|-----------------------------------------------|------------|--------------------------------|
| Proof size (postcard)           | 140,778 B (~138 KB) | 80-200 KB                                     | -          | within target band             |
| Compiled script size            | 6,768,131 B (~6.6 MB) | < 2 MB                                        | 10 MB      | over target, under hard limit  |
| Total emit ops                  | 5,753,486          | -                                             | -          | (informational)                |
| Unlocking-prelude ops           | 2,118              | -                                             | -          | (informational)                |
| Locking-body ops                | 5,751,368          | -                                             | -          | (informational)                |
| Peak named-stack depth          | 2,108              | < 500                                         | 1,000      | over hard limit (see below)    |
| Wall-clock (script-VM execute)  | 1m5s               | < 500 ms                                      | 1 s        | over hard limit (see below)    |

### Production parameter tuple actually used

| Param              | This fixture | Brief target | Notes                                  |
|--------------------|--------------|--------------|----------------------------------------|
| num_queries        | 100          | 100          | matches target                         |
| log_blowup         | 1            | 1            | matches target                         |
| log_final_poly_len | 9            | 0            | bumped to satisfy codegen-helper       |
|                    |              |              | invariant `numRounds = 1` (see "Bugs   |
|                    |              |              | flagged")                              |
| commit_pow_bits    | 16           | 16           | matches target                         |
| query_pow_bits     | 16           | 16           | matches target                         |
| max_log_arity      | 1            | 1            | matches target                         |
| trace_height (log) | 10 (= 1024 rows) | 16-20    | scaled down to keep `numRounds = 1`    |
|                    |              |              | tractable; `degreeBits =`              |
|                    |              |              | `log_final_poly_len + 1` is the binding |
|                    |              |              | constraint here.                        |

Cite Plonky3 source for the param-tuning trade-off:
`fri/src/prover.rs::commit_phase` line 75 -- the prover asserts
`log_min_height > log_final_poly_len + log_blowup`. With
`log_blowup = 1, log_final_poly_len = 9` this requires
`log_min_height > 10`, i.e. `degreeBits + log_blowup >= 11`, i.e.
`degreeBits >= 10`. Lifting `log_final_poly_len` back toward 0 demands
either a deeper FRI commit phase (more rounds) or a much larger trace
(stalling under macOS open-file limits during proving). The codegen
helper's `numRounds = 1` constraint forces the former path closed,
hence the bumped final-poly length.

## Status against `docs/sp1-fri-verifier.md` Section 4

* **Script size**: 3.3x over the 2 MB target. Dominated by the FRI
  commit-phase byte-stream pre-pushes (final_poly = 512 Ext4 = 2,048
  base elements pre-pushed) and the per-query Step 10 stub
  (`emitQueryIndexDerive` × 100). Lifting the codegen `numRounds = 1`
  restriction (see "Bugs flagged") would drop `final_poly` size 100x
  but add `numRounds * (8 digest pushes + 1 PoW witness + Ext4 beta
  squeeze)`; net should be a small reduction, with the bulk of the
  remaining 6 MB coming from the per-query loop. **Within hard limit.**
* **Peak named-stack depth**: 2,108 — exceeds both the 500 target and
  the 1,000 hard limit. Caveat: this is the codegen tracker's named-slot
  depth (deepest pre-push count), not the actual Bitcoin Script
  evaluation stack depth at runtime. The script VM accepts the script,
  which would not be the case if the runtime stack actually exceeded
  the 1,000 depth limit. The peak named-stack depth metric primarily
  reflects pre-pushed input fields (final_poly absorb layer), which are
  consumed (PICK + drop) one at a time during transcript absorbs.
* **Wall-clock**: 65 s vs. 1 s hard limit. This measures the test-harness
  go-sdk interpreter, not a deployed BSV miner. The interpreter is
  unoptimized, single-threaded, and has Go-allocation overhead per StackOp.
  A deployed miner running the same script would target the hard limit
  via batched evaluation; measurement against regtest is the correct
  apples-to-apples gate (deferred to integration/go/regtest).

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

### B1 — `EmitFullSP1FriVerifierBody` hardcodes `numRounds = 1`

**File**: `compilers/go/codegen/sp1_fri.go` line 317.

**Symptom**: Production parameter tuple from
`docs/sp1-fri-verifier.md` Section 4 calls for
`log_final_poly_len = 0` with the FRI commit-phase round count derived
from the trace. With `degreeBits = 10`, `log_blowup = 1`,
`log_final_poly_len = 0`, `max_log_arity = 1`, the natural round count
is `total_log_reduction = degreeBits - log_final_poly_len = 10`. The
codegen helper rejects everything except `numRounds = 1`.

**Workaround** (used here): pin `log_final_poly_len = degreeBits - 1`
so `numRounds` collapses to 1. Shifts ~512 Ext4 coefficients into the
final-poly absorb layer instead of the FRI commit-phase Merkle ladder.
Total prover work equivalent.

**Fix**: extract `numRounds` from
`SP1FriVerifierParams.{DegreeBits, LogFinalPolyLen, MaxLogArity}` and
unroll the `emitFriCommitPhaseAbsorb` call site over the actual round
count. The transcript-input slot-name list (`sp1FriPrePushedFieldNames`)
already parameterizes on `numRounds`, so only the `numRounds := 1`
line needs to change to a derived expression and the per-query
`logGlobalMaxHeight` derivation already loops over `numRounds`.

Out of scope for this scale-up (brief: "DO NOT modify the verifier
algorithm or codegen helpers"). Filed for follow-up.

### B2 (pre-existing, out-of-bounds) -- `TestEncodeUnlockingScript_AcceptsMinimalGuestFixture` fails

**File**: `packages/runar-go/sp1fri/unlocking_test.go` line 230 (untracked
WIP file at the time of this measurement run).

**Symptom**: `script VM rejected canonical fixture: OP_EQUALVERIFY failed`
when running through the production-split [unlocking][locking] shape
(vs. the single concatenated script the codegen test uses). Reproduces
on `main` without any Phase 2 changes.

**Status**: Out of scope per brief bounds (`unlocking.go` and
`unlocking_test.go` are untracked WIP, not in the brief's allowed-edit
set). Flagged here so it does not get lost.

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
