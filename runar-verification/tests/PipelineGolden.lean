import RunarVerification.Pipeline
import RunarVerification.ANF.Json
open RunarVerification ANF Pipeline

/--
Phase 3 baseline: fixtures that compile byte-exact through the verified Lean
pipeline. Any of these fixtures regressing (dropping out of byte-exact match)
MUST fail CI. New fixtures becoming byte-exact bumps the count past the
threshold but does not fail.

`expectedByteExact` locks the count of fixtures the Lean pipeline produces
byte-identical hex for; ratchet it upward (and append the new fixture name to
`baselineMatches`) when progress lands. The remaining fixtures are tracked in
the categorized buckets below for triage; they don't gate CI but document why
each is still pending.

Step-6 triage (this commit) also surfaced two fixtures (`sha256-compress`,
`sha256-finalize`) that the Phase 3 final summary listed as "out of scope"
yet which now compile byte-exact through the verified pipeline. They have
been promoted into `baselineMatches` and the count bumped from 25 → 27.

Step-6 follow-up (Item 3): the `math-demo` fixture became byte-exact after
adding `pow`/`sqrt`/`gcd`/`log2`/`sign` arms to `Stack/Lower.lean` (mirroring
the existing TS / Go / etc. reference lowerings — no new opaque axioms).
The count moved from 27 → 28 and `mathBuiltinsPending` is now empty.

Step-6 follow-up (Item 4): the `blake3` fixture became byte-exact after
porting `blake3-codegen.ts` to `RunarVerification/Stack/Blake3.lean` and
adding `blake3Compress` / `blake3Hash` dispatch arms to `Stack/Lower.lean`.
The count moved from 28 → 29.

Step-6 follow-up (Item 5): the `post-quantum-wots` and `post-quantum-wallet`
fixtures became byte-exact after porting `lowerVerifyWOTS` / `emitWOTSOneChain`
(TS `05-stack-lower.ts:3951-4175`) to `RunarVerification/Stack/Wots.lean`
and adding a `verifyWOTS` dispatch arm to `Stack/Lower.lean`. The count
moved from 29 → 31.
-/
def expectedByteExact : Nat := 33

def baselineMatches : List String := [
  "add-raw-output",
  "auction",
  "bitwise-ops",
  "cross-covenant",
  "stateful-bytestring",
  "state-ripemd160",
  "bounded-loop",
  "oracle-price",
  "property-initializers",
  "shift-ops",
  "multi-method",
  "covenant-vault",
  "stateful",
  "go-dsl-bytestring-literal",
  "add-data-output",
  "token-nft",
  "basic-p2pkh",
  "function-patterns",
  "if-without-else",
  "stateful-counter",
  "token-ft",
  "arithmetic",
  "escrow",
  "boolean-logic",
  "if-else",
  -- Promoted in Step 6 (Phase 3z follow-up): these fixtures compile through
  -- the existing `sha256Compress` / `sha256Finalize` Stack.Lower paths
  -- without needing any new Lean codegen module. The HANDOFF "Phase 3
  -- final" section originally bucketed them with the Phase-4 crypto ports;
  -- the actual pipeline already produces the correct ~46 KB / ~139 KB hex.
  "sha256-compress",
  "sha256-finalize",
  -- Promoted in Step-6 follow-up Item 3: `math-demo` exercises every
  -- math builtin (safediv, percentOf, clamp, mulDiv, pow, sqrt, gcd,
  -- log2, sign). The first four already had `Stack/Lower.lean` arms;
  -- this commit added the remaining five mirroring `lowerPow`,
  -- `lowerSqrt`, `lowerGcd`, `lowerLog2`, `lowerSign` from
  -- `05-stack-lower.ts` (and their Go peers in `compilers/go/codegen/stack.go`).
  "math-demo",
  -- Promoted in Step-6 follow-up Item 4: `blake3` exercises both
  -- `blake3Compress` and `blake3Hash`. The Lean port lives in
  -- `RunarVerification/Stack/Blake3.lean` and mirrors the TS reference
  -- in `packages/runar-compiler/src/passes/blake3-codegen.ts`. The
  -- dispatch arms in `Stack/Lower.lean` follow the same pattern as the
  -- existing `sha256Compress` / `sha256Finalize` arms.
  "blake3",
  -- Promoted in Step-6 follow-up Item 5: `post-quantum-wots` and
  -- `post-quantum-wallet` both exercise `verifyWOTS` (Winternitz one-time
  -- signature; w=16, n=32, len=67 chains). The Lean port lives in
  -- `RunarVerification/Stack/Wots.lean` and mirrors the TS reference
  -- `lowerVerifyWOTS` / `emitWOTSOneChain` at
  -- `packages/runar-compiler/src/passes/05-stack-lower.ts:3951-4175`.
  -- The `verifyWOTS` dispatch arm in `Stack/Lower.lean` follows the same
  -- pattern as the existing `blake3Compress` / `blake3Hash` arms.
  "post-quantum-wots",
  "post-quantum-wallet",
  -- Promoted in Phase 4: two new fixtures added in commit 3fed3295
  -- ("close cross-compiler test gaps + fixes") that compile through the
  -- existing Stack.Lower path. `private-helper-outputs` exercises
  -- recursive private-helper inlining + paramAliasStack across all 7
  -- compilers; `conditional-data-output-stateful` covers the canonical
  -- computeStateOutput path when only an if-branch contains
  -- addDataOutput. Promotion was unblocked by the Phase 4 fix to
  -- `removeConsumedAtDepths` (depth-2 cleanup uses `OP_ROT OP_DROP`
  -- instead of `[push 2, OP_ROLL, OP_DROP]`, saving 1 byte) and the
  -- empty-bytes else shadow-rebind detection in `lowerIf`.
  "private-helper-outputs",
  "conditional-data-output-stateful"
]

/--
Fixtures that are intentionally **Go-only by project policy** (see
`project_go_only_crypto_modules` memory and `CLAUDE.md`'s "Go-first
development approach"). The Rúnar codegen modules they depend on
(BabyBear, KoalaBear, Poseidon2*, BN254, FiatShamirKb, Merkle) ship only
in the Go reference compiler; the other six tiers (TS/Rust/Python/Zig/
Ruby/Java) — and therefore the Lean verified port — are explicitly
exempt from porting them. These fixtures are tracked here so future
contributors don't re-investigate; they will not become byte-exact
in the Lean pipeline and must not be added to `baselineMatches`.

Count: 4. Combined with `baselineMatches` (27) and the pending buckets
below, the total is 46 — matching `conformance/tests/`.
-/
def goOnlyFixtures : List String := [
  "babybear",          -- bbField{Add,Sub,Mul,Inv}
  "babybear-ext4",     -- bbField* + bbExt4* (ext4 multiplications)
  "merkle-proof",      -- merkleRootSha256, merkleRootHash256
  "state-covenant"     -- bbFieldMul + merkleRootSha256 (composite)
]

/--
Fixtures whose codegen IS shipped across all 7 reference tiers (TS, Go,
Rust, Python, Zig, Ruby, Java) but whose Lean Stack.Lower path is not
yet extended to the relevant primitive AND whose end-to-end correctness
will require discharging per-primitive crypto axioms (analogous to the
`agrees`/`lower_observational_correct` blocker). Each of these is a
multi-week proof effort and explicitly Phase-4 work — they are tracked
here for triage, not gated.

Per primitive:
  * EC (secp256k1):       ec-demo, ec-primitives, ec-unit, schnorr-zkp,
                          convergence-proof
  * NIST P-256:           p256-primitives, p256-wallet
  * NIST P-384:           p384-primitives, p384-wallet
  * SLH-DSA (FIPS 205):   post-quantum-slhdsa, sphincs-wallet

Count: 11. (`blake3` was promoted out of this bucket once
`RunarVerification/Stack/Blake3.lean` landed; see Step-6 Item 4.
`post-quantum-wots` and `post-quantum-wallet` were promoted out
once `RunarVerification/Stack/Wots.lean` landed; see Step-6 Item 5.)
-/
def cryptoAxiomPending : List String := [
  "convergence-proof",
  "ec-demo",
  "ec-primitives",
  "ec-unit",
  "p256-primitives",
  "p256-wallet",
  "p384-primitives",
  "p384-wallet",
  "post-quantum-slhdsa",
  "schnorr-zkp",
  "sphincs-wallet"
]

/--
Fixtures blocked on math-builtin codegen extension in the Lean Stack.Lower
pass. Unlike the crypto buckets these don't touch any cryptographic
primitive — they exercise pure arithmetic intrinsics (`pow`, `sqrt`,
`gcd`, `log2`, `sign`, `abs`, `min`, `max`, `within`, `safemod`,
`divmod`, `bool`) that the TS/Go/Rust/etc. reference compilers all
implement but that the Lean Stack.Lower pass does not yet cover.
This is a smaller engineering task than the crypto axioms — no new
opaque crypto axioms required, just additional `func = "..."` arms in
`Stack/Lower.lean` mirroring `05-stack-lower.ts`.

Count: 0 (math-demo promoted; bucket retained for future math-builtin
fixtures that may not be byte-exact on first compile).
-/
def mathBuiltinsPending : List String := []

/--
Fixtures introduced after the Phase 3 lock (e.g. in commit 3fed3295)
whose contracts compile but produce a non-byte-exact hex due to
small-but-real Stack.Lower divergences from the TS reference. These
are tracked here so the sanity-check sum matches `conformance/tests/`
without forcing a `baselineMatches` promotion before the divergence
is closed.

Count: 1.

* `if-without-else-multi-temp` — uses an if-without-else where the
  THEN branch produces a multi-temp value (not a simple shadow rebind);
  Lean's `lowerIf` empty-else synthesis path handles only the
  single-shadow case, so the multi-temp variant produces a divergent
  PICK/ROLL sequence. Closing this requires extending the empty-else
  detection to the multi-temp shape (mirrors TS `lowerIf` at
  `05-stack-lower.ts:1782-1800`).
-/
def lowerDivergencePending : List String := [
  "if-without-else-multi-temp"
]

/--
Sanity check: 33 baseline + 4 Go-only + 11 crypto-pending + 0 math-pending
+ 1 lower-divergence = 49, matching `conformance/tests/` after commit
3fed3295 added 3 fixtures (`conditional-data-output-stateful`,
`if-without-else-multi-temp`, `private-helper-outputs`).
-/
example : baselineMatches.length + goOnlyFixtures.length
        + cryptoAxiomPending.length + mathBuiltinsPending.length
        + lowerDivergencePending.length = 49 := by rfl

def main : IO Unit := do
  -- Resolve relative to the repo root. CI runs us from `runar-verification/`
  -- via `lake env`, so the conformance tree sits one level up. Local macOS
  -- runs via `lake env lean --run tests/PipelineGolden.lean` set the same cwd.
  let dir := "../conformance/tests"
  let entries ← System.FilePath.readDir dir
  -- Determine full vs default mode once up front so the cryptoAxiomPending
  -- bucket gating + per-fixture timing both observe the same flag.
  let full ← match (← IO.getEnv "RUNAR_VERIFICATION_FULL") with
    | some _ => pure true
    | none   => pure false
  let mut total := 0
  let mut matched := 0
  let mut matchedNames : List String := []
  -- 3c: Per-fixture timing telemetry for the cryptoAxiomPending bucket.
  -- Each entry: (fixture name, milliseconds elapsed, byteExact?).
  let mut fullTimings : List (String × Nat × Bool) := []
  for e in entries do
    let path := e.path
    let ir := path / "expected-ir.json"
    let hex := path / "expected-script.hex"
    if (← System.FilePath.pathExists ir) && (← System.FilePath.pathExists hex) then
      try
        let irJson ← IO.FS.readFile ir.toString
        let expected := (← IO.FS.readFile hex.toString).trim
        match ANFProgram.fromString irJson with
        | .ok p =>
            total := total + 1
            -- Phase 5: the EC / P-256 / P-384 / SLH-DSA fixtures in
            -- `cryptoAxiomPending` are skipped by default — even the
            -- compiled native exe takes >1 hour to evaluate the
            -- multi-MB scripts (`compileHex` is ~10⁵+ ops × pure
            -- function calls in Lean's runtime). Set
            -- `RUNAR_VERIFICATION_FULL=1` to include them; users
            -- doing local crypto-codegen verification opt in.
            -- Future closure: rewrite `compileHex` (or just
            -- `Script.Emit.emit`) with `@[implemented_by]` to a C
            -- helper, OR pre-compute expected hex offline and gate
            -- via stored constants. See HANDOFF §25 (Phase 5 entry).
            if !full && cryptoAxiomPending.contains e.fileName then
              pure ()
            else
              -- 3c: Time each fixture's compile. In full mode, log
              -- per-fixture progress so users see what's happening
              -- during multi-hour runs.
              let t0 ← IO.monoMsNow
              let actual := compileHex p
              let isMatch := expected == actual
              let t1 ← IO.monoMsNow
              let elapsedMs := t1 - t0
              if full && cryptoAxiomPending.contains e.fileName then
                fullTimings := (e.fileName, elapsedMs, isMatch) :: fullTimings
                IO.eprintln s!"  [full] {e.fileName} compiled in {elapsedMs}ms (byte-exact={isMatch})"
                (← IO.getStderr).flush
              if isMatch then
                matched := matched + 1
                matchedNames := e.fileName :: matchedNames
        | _ => pure ()
      catch _ => pure ()
  IO.println s!"PIPELINE GOLDEN: {matched}/{total} byte-exact"
  -- 3c: Surface per-fixture timing for the cryptoAxiomPending bucket
  -- when full mode ran. Helps identify which fixtures are tractable
  -- for opt-in CI vs which need the (i) @[implemented_by] or (ii)
  -- pre-computed-constant escape hatches.
  if full && !fullTimings.isEmpty then
    IO.println ""
    IO.println "FULL-MODE TIMING (cryptoAxiomPending bucket):"
    let sorted := fullTimings.reverse  -- preserve discovery order
    for (n, ms, m) in sorted do
      let mark := if m then "✓" else "✗"
      IO.println s!"  {mark} {n}: {ms}ms"
  -- Phase 4 diagnostic: surface ANY matched fixture not in baselineMatches.
  -- Both pending-bucket fixtures AND brand-new fixtures (e.g., the 3 added
  -- in commit 3fed3295) become visible without needing per-bucket entries.
  let mut promoCandidates : List String := []
  for n in matchedNames do
    if !baselineMatches.contains n then
      promoCandidates := n :: promoCandidates
  if !promoCandidates.isEmpty then
    IO.eprintln "NOTICE: byte-exact fixtures NOT in baselineMatches:"
    for n in promoCandidates do
      IO.eprintln s!"  - {n}"

  -- Gate 1: total byte-exact count must not regress below the Phase 3 baseline.
  if matched < expectedByteExact then
    IO.eprintln s!"FAIL: byte-exact match regressed: {matched} < {expectedByteExact}"
    IO.Process.exit 1

  -- Gate 2: every fixture from the Phase 3 baseline must still match. This
  -- guards against a swap (e.g. a new fixture becomes byte-exact while one
  -- of the original baseline silently breaks, leaving the count unchanged).
  let mut regressions : List String := []
  for name in baselineMatches do
    if !(matchedNames.contains name) then
      regressions := name :: regressions
  if !regressions.isEmpty then
    IO.eprintln "FAIL: previously byte-exact fixtures regressed:"
    for n in regressions.reverse do
      IO.eprintln s!"  - {n}"
    IO.Process.exit 1

  -- Gate 3: any fixture in the pending-triage buckets that has *flipped* to
  -- byte-exact should be promoted into `baselineMatches` (and the count
  -- bumped). We surface this as a non-fatal notice so progress is visible.
  let mut newlyMatched : List String := []
  for name in goOnlyFixtures ++ cryptoAxiomPending ++ mathBuiltinsPending do
    if matchedNames.contains name then
      newlyMatched := name :: newlyMatched
  if !newlyMatched.isEmpty then
    IO.eprintln "NOTICE: fixtures in the pending-triage buckets are now byte-exact:"
    for n in newlyMatched.reverse do
      IO.eprintln s!"  - {n}"
    IO.eprintln "Promote them into `baselineMatches` and bump `expectedByteExact`."

  IO.println s!"OK: {expectedByteExact} baseline fixtures still byte-exact"
