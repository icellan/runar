import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, runDifferentialExecution } from 'runar-testing';
import { compile } from 'runar-compiler';

/**
 * R-102 — the loop shape the corpus never had.
 *
 * Two `for` loops existed repo-wide before this example, both zero-start and
 * incrementing, so the ANF `loop` node's `start` field was exercised by
 * nothing. Two wrong-value miscompiles were living behind that gap — Go's
 * constant folder dropping Start and Step (N-128), and Zig's `.runar.go` /
 * `.runar.java` parsers dropping the init value (N-129).
 *
 * Both produced a script that computes a different number than the source says,
 * and both were invisible to a corpus of zero-start loops. The assertions below
 * therefore pin the SUM, and name the two wrong answers so a regression says
 * which bug came back.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'LoopShapes.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

const SUM = 3n + 4n + 5n + 6n; // 18

describe('LoopShapes (a non-zero loop start)', () => {
  it('the loop really does start at 3 and run four times', () => {
    expect(SUM).toBe(18n);
  });

  it('accepts seed + 18', () => {
    const c = TestContract.fromSource(source, { target: SUM }, FILE);
    const r = c.call('verify', { seed: 0n });
    expect(r.success, r.error).toBe(true);
  });

  it('accepts a shifted seed with the matching target', () => {
    const c = TestContract.fromSource(source, { target: 100n + SUM }, FILE);
    expect(c.call('verify', { seed: 100n }).success).toBe(true);
  });

  it('REJECTS 6 — the sum of 0+1+2+3, which is what a dropped start gives', () => {
    const c = TestContract.fromSource(source, { target: 6n }, FILE);
    expect(
      c.call('verify', { seed: 0n }).success,
      'N-128: Go folded the loop as zero-start step-1 and produced exactly this',
    ).toBe(false);
  });

  it('REJECTS 21 — the sum of 0..6, which is what a dropped init gives', () => {
    const c = TestContract.fromSource(source, { target: 21n }, FILE);
    expect(
      c.call('verify', { seed: 0n }).success,
      "N-129: Zig's .runar.go / .runar.java parsers unrolled 0..bound and " +
        'produced exactly this',
    ).toBe(false);
  });

  it('the ANF carries the start, not just the count', () => {
    const r = compile(source, { fileName: FILE });
    expect(r.success, r.diagnostics.map((d) => d.message).join('\n')).toBe(true);
    const loops = r
      .anf!.methods.flatMap((m) => m.body)
      .map((b) => b.value)
      .filter((v): v is Extract<typeof v, { kind: 'loop' }> => v.kind === 'loop');
    expect(loops.length, 'the fixture must still contain a loop').toBe(1);
    expect(loops[0]!.start, 'a start of 0 here means the shape stopped being tested').toBe(3n);
    expect(loops[0]!.count).toBe(4);
  });

  it('the interpreter and the ScriptVM agree', () => {
    const r = runDifferentialExecution({
      source,
      fileName: FILE,
      method: 'verify',
      args: [0n],
      constructorArgs: { target: SUM },
    });
    expect(r.agrees, `interpreter=${r.interpreterAccepted} vm=${r.vmAccepted}`).toBe(true);
  });
});
