# Runar Verification Handoff

This is the active implementation roadmap. Historical exploration,
gap-analysis, and audit Markdown files were removed after their live
findings were folded into `README.md`, `TRUST_MANIFEST.md`, and this
handoff.

The unimported `RunarVerification/Pipeline/SimpleSoundness.lean` proof
sketch was also removed. It no longer built as a standalone module; the
remaining active proof obligations live in `Pipeline.lean`,
`Stack/Agrees.lean`, and `TRUST_MANIFEST.md`.

## Current Baseline

* Lean toolchain: `leanprover/lean4:v4.29.1`.
* No `sorry`, no `admit`, and no `partial def` under
  `RunarVerification/`.
* `scripts/lean-verify.sh` builds every tracked Lean module, not only
  the default import closure.
* `goldenLoad` and `roundtrip` cover 49/49 conformance fixtures.
* Default `pipelineGolden` is honest: 34/49 live byte-exact fixtures.
* The remaining 15 fixtures are the crypto-heavy pending-assumption
  bucket. They need full-mode live verification or stored Lean-produced
  constants before they can count in default CI.
* `Pipeline.compileSafe` is the proof-facing compiler entrypoint and
  rejects sentinel or unknown opcodes before byte emission.

## Finish Order

1. **Proof-facing execution model**
   * Replace authentication and hash executable defaults with explicit
     oracle parameters or real implementations.
   * Complete Script-number and byte semantics for all Rúnar-emitted
     opcodes.
   * Model tx context, sighash coverage, and `OP_CODESEPARATOR` well
     enough for stateful contracts.

2. **Lowering simulation**
   * Finish the bridge from binding-level `Stack.Agrees` results to
     method-level `Lower.lower`.
   * Prove lowering simulation for all supported ANF constructors.
   * Keep unsupported constructs routed through `compileSafe` errors,
     never through emitted sentinel bytes.

3. **Peephole and emit composition**
   * Prove soundness for exactly the pass chain used by
     `Pipeline.peepholeProgram`.
   * Prove emit/parse round-trip for the emitted subset.
   * Connect parsed bytes to `Stack.Eval.runOps`.

4. **Fixture gates**
   * Populate `cryptoAxiomPendingExpected` only with Lean-produced hex
     from regen/full mode.
   * Keep default CI at 34/49 until those constants exist or full mode is
     fast enough to gate.
   * Add scheduled/manual full verification for all 49 fixtures.

5. **Differential assurance**
   * Run the Lean parser/VM against an external BSV reference.
   * Store differential reports as artifacts or temp files, not tracked
     test fixtures.
   * Treat differential agreement as assurance alongside formal proofs,
     not as a substitute for theorem obligations.

## Acceptance Criteria

The implementation is finished when:

* the public theorem for `compileSafe` no longer relies on hypotheses
  that restate its conclusion;
* every remaining assumption is listed in `TRUST_MANIFEST.md` and counted
  by `check-tcb-drift.sh`;
* default CI, full/manual CI, and README status numbers agree exactly;
* no active code path silently emits empty bytes for unknown opcodes; and
* obsolete analysis documents and references to them are absent.
