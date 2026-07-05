import { describe, it, expect } from 'vitest';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runExecuteDifferential } from '../execute-differential.js';

// Smoke test for the randomized source-vs-script execution oracle
// (TS-GAP-001 randomized half / TS-GAP-005). On a fixed seed the generated
// corpus, the synthesized inputs, and the verdicts are all deterministic, so
// this is a stable gate: the ANF interpreter and the compiled fold-ON script
// (executed on ScriptVM) MUST agree on accept/reject for every generated spend.
describe('runExecuteDifferential (source-vs-script execution oracle)', () => {
  it('agrees on accept/reject for a fixed-seed generated corpus (0 divergences)', async () => {
    const report = await runExecuteDifferential({
      numContracts: 15,
      seed: 424242,
      inputsPerMethod: 4,
      findingsDir: join(tmpdir(), 'runar-exec-fuzz-smoke'),
    });

    // The harness actually executed spends.
    expect(report.casesRun).toBeGreaterThan(0);
    // Every spend was classified as accept or reject (no dropped cases).
    expect(report.acceptCount + report.rejectCount).toBe(report.casesRun);
    // Both engines are independent implementations of the same source
    // semantics — any disagreement is a real shared-design compiler bug.
    expect(report.divergenceCount).toBe(0);
    // No compile/interpreter/VM throws on the generated corpus.
    expect(report.errorCount).toBe(0);
    // Fixed seed → deterministic replay.
    expect(report.effectiveSeed).toBe(424242);
  });

  it('exercises BOTH the accept and reject paths (oracle is not vacuous)', async () => {
    const report = await runExecuteDifferential({
      numContracts: 40,
      seed: 424242,
      inputsPerMethod: 6,
      findingsDir: join(tmpdir(), 'runar-exec-fuzz-smoke'),
    });
    expect(report.divergenceCount).toBe(0);
    expect(report.errorCount).toBe(0);
    expect(report.acceptCount).toBeGreaterThan(0);
    expect(report.rejectCount).toBeGreaterThan(0);
  });
});
