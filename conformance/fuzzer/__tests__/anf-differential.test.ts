import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  classifyTierResults,
  classifyUnavailableTier,
  runAnfDifferential,
  ALL_TIERS,
  type CompilerName,
} from '../anf-differential.js';

describe('classifyUnavailableTier (finding #18 — requested tier silently dropped)', () => {
  it('DEFAULT: a requested tier with no binary FAILS (not silently skipped)', () => {
    // skipMissingTiers unset — the CI gates never pass it, so the old default
    // silently skipped a missing tier, hiding cross-tier divergences.
    expect(classifyUnavailableTier(false, undefined)).toBe('failed');
    expect(classifyUnavailableTier(false, false)).toBe('failed');
  });
  it('only an EXPLICIT skipMissingTiers:true downgrades a missing tier to a skip', () => {
    expect(classifyUnavailableTier(false, true)).toBe('skipped');
  });
  it('an AVAILABLE tier that produced null = ran-and-rejected = failure', () => {
    expect(classifyUnavailableTier(true, undefined)).toBe('failed');
    expect(classifyUnavailableTier(true, true)).toBe('failed');
    expect(classifyUnavailableTier(undefined, true)).toBe('failed');
  });
});

// Finding #16 — the ANF differential harness's own docstring (anf-differential.ts
// header) promises it "fails the job on ... any compiler crash that doesn't
// reproduce on every other tier." `classifyTierResults` is the pure decision
// function pulled out of `runAnfDifferential`'s per-program loop; these tests
// drive it directly with synthetic tier outputs instead of the full
// generate-and-compile pipeline.
describe('classifyTierResults (finding #16 — silent single-tier crash)', () => {
  it('is a mismatch when >=2 tiers agree but a requested tier crashed/rejected', () => {
    // Six tiers agree on identical hex; `java` has an installed binary that
    // rejected the (valid) program. Before the fix this was NEVER checked
    // once >=2 outputs existed, so the crash was silently dropped.
    const outputs = {
      ts: 'aabbcc',
      go: 'aabbcc',
      rust: 'aabbcc',
      python: 'aabbcc',
      zig: 'aabbcc',
      ruby: 'aabbcc',
    };
    const result = classifyTierResults(outputs, ['java']);
    expect(result.status).toBe('mismatch');
    if (result.status === 'mismatch') {
      expect(result.reason).toContain('java');
    }
  });

  it('is ok when all producing tiers agree and nothing failed', () => {
    const outputs = { ts: 'aabbcc', go: 'aabbcc', rust: 'aabbcc' };
    const result = classifyTierResults(outputs, []);
    expect(result.status).toBe('ok');
  });

  it('is still a mismatch on plain hex divergence (existing behavior preserved)', () => {
    const outputs = { ts: 'aabbcc', go: 'ddeeff' };
    const result = classifyTierResults(outputs, []);
    expect(result.status).toBe('mismatch');
    if (result.status === 'mismatch') {
      expect(result.reason).toContain('hex divergence');
    }
  });

  it('reports BOTH hex divergence and a tier crash when both occur together', () => {
    const outputs = { ts: 'aabbcc', go: 'ddeeff' };
    const result = classifyTierResults(outputs, ['java']);
    expect(result.status).toBe('mismatch');
    if (result.status === 'mismatch') {
      expect(result.reason).toContain('hex divergence');
      expect(result.reason).toContain('java');
    }
  });

  it('is a mismatch when fewer than 2 tiers produced output and one failed (pre-existing behavior)', () => {
    const outputs = { ts: 'aabbcc' };
    const result = classifyTierResults(outputs, ['go']);
    expect(result.status).toBe('mismatch');
    if (result.status === 'mismatch') {
      expect(result.reason).toContain('go');
    }
  });

  it('is insufficient (skip, not mismatch) when fewer than 2 tiers ran and none failed', () => {
    const outputs = { ts: 'aabbcc' };
    const result = classifyTierResults(outputs, []);
    expect(result.status).toBe('insufficient');
  });
});

// F-173 — `reduceAnfProgram` (reduce.ts) was dead code: no harness called it,
// so every ANF finding landed at full generated size. These tests drive the
// REAL `runAnfDifferential` loop (real generator, real canonicaliser, real
// `classifyTierResults`) with an injected per-tier compiler in which `go`
// diverges whenever the program contains a `%` bin_op, and every other tier
// emits a digest of the canonical IR bytes.
//
// PROVES: on a mismatch the harness shrinks the finding before writing it,
// keeps the original `program.json`, writes a strictly smaller
// `program-reduced.json`, and the reduced program — re-run through the SAME
// fake tiers and the SAME `classifyTierResults` oracle — still fails with the
// byte-identical reason string the original did.
// DOES NOT PROVE: anything about real tier binaries (none run here), that the
// reduction is globally minimal (ddmin-lite is only locally minimal), or the
// wall-clock cost of shrinking a real 7-tier divergence.
describe('runAnfDifferential shrinks findings with reduceAnfProgram (F-173)', () => {
  const hasModOp = (program: any): boolean =>
    program.methods.some((m: any) =>
      m.body.some((b: any) => b.value.kind === 'bin_op' && b.value.op === '%'),
    );
  const fakeTier = (tier: CompilerName, program: unknown, irFile: string): string | null => {
    const digest = createHash('sha256').update(readFileSync(irFile)).digest('hex');
    return tier === 'go' && hasModOp(program) ? digest + 'ff' : digest;
  };
  const countBindings = (program: any): number =>
    program.methods.reduce((n: number, m: any) => n + m.body.length, 0);

  it('writes a smaller program-reduced.json that still fails the same oracle check', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'anf-reduce-'));
    try {
      // Fixed seed + corpus; keep only programs carrying the trigger so the
      // test does not depend on which index the generator happens to put it at.
      const report = await runAnfDifferential({
        numPrograms: 40,
        seed: 173,
        findingsDir: dir,
        compileTier: fakeTier,
        genOpts: { maxMethods: 3, maxBindingsPerMethod: 15 },
      });
      expect(report.mismatchCount).toBeGreaterThan(0);
      expect(report.findings.length).toBe(report.mismatchCount);

      for (const findingDir of report.findings) {
        const finding = JSON.parse(readFileSync(join(findingDir, 'finding.json'), 'utf-8'));
        const original = JSON.parse(readFileSync(join(findingDir, 'program.json'), 'utf-8'));
        const reducedPath = join(findingDir, 'program-reduced.json');
        expect(existsSync(reducedPath), `${findingDir} has no program-reduced.json`).toBe(true);
        const reducedBytes = readFileSync(reducedPath, 'utf-8');
        const reduced = JSON.parse(reducedBytes);

        expect(hasModOp(original)).toBe(true);
        expect(hasModOp(reduced)).toBe(true);
        expect(countBindings(reduced)).toBeLessThan(countBindings(original));
        expect(finding.reducedReason).toBe(finding.reason);

        // Independent re-check: replay the reduced canonical bytes through
        // the same tiers + the same classifier, outside the harness.
        const irFile = join(dir, 'replay.json');
        writeFileSync(irFile, reducedBytes, 'utf-8');
        const outputs: Partial<Record<CompilerName, string>> = {};
        for (const tier of ALL_TIERS) outputs[tier] = fakeTier(tier, reduced, irFile)!;
        const recheck = classifyTierResults(outputs, []);
        expect(recheck).toEqual({ status: 'mismatch', reason: finding.reason });
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);
});
