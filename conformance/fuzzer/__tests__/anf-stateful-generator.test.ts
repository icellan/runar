/**
 * N-395 — the `--anf` fold-OFF gate went red when N-087 made every tier's
 * `--ir` path refuse a mutable property in a SmartContract: the ANF generator
 * declared every property `readonly: false`, drew `update_prop`, and set no
 * `parentClass`, so every program with a property was refused by all seven
 * tiers ("Property 'prop0' in SmartContract must be readonly"). The shrinker
 * then reduced each such finding to a near-empty program, because a refusal's
 * reason named only the refusing tiers and not what they said, so any
 * refusal "reproduced" it.
 *
 * PROVES:
 *   - every program the harness actually feeds a tier (captured through the
 *     `compileTier` seam, at the CI seed) that declares a mutable property or
 *     carries an `update_prop` is labelled StatefulSmartContract, every other
 *     one SmartContract with only readonly properties, and every one of them
 *     passes the real TS `--ir` validator (`compileFromANF`, which runs the
 *     N-087 parent-class rules and the N-101 scaffolding check) and compiles;
 *   - the corpus is not vacuous: some fed programs are stateful and some are
 *     not;
 *   - a refusal finding keeps the refusing tier's message, and the shrinker
 *     only accepts candidates refused with that same message, so the reduced
 *     program still carries what triggered the refusal.
 * DOES NOT PROVE: that the six native tiers accept these programs or agree on
 * their bytes (no native binary runs here — that is what the gate itself
 * checks), that the stateful scripts are spendable, or that the shrinker's
 * result is minimal.
 */
import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compileFromANF } from '../../../packages/runar-compiler/src/index.js';
import { runAnfDifferential, type CompilerName } from '../anf-differential.js';

type AnyProgram = {
  parentClass?: string;
  properties: Array<{ name: string; readonly: boolean }>;
  methods: Array<{ body: Array<{ value: { kind: string; op?: string } }> }>;
};

const hasUpdateProp = (p: AnyProgram): boolean =>
  p.methods.some((m) => m.body.some((b) => b.value.kind === 'update_prop'));

describe('N-395: the ANF generator feeds every tier a program its --ir path accepts', () => {
  it('labels mutable-state programs StatefulSmartContract and the TS --ir validator accepts every fed program', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'anf-n395-'));
    const fed: AnyProgram[] = [];
    try {
      await runAnfDifferential({
        numPrograms: 60,
        seed: 424242,
        findingsDir: dir,
        compileTier: (tier, program) => {
          if (tier === 'ts') fed.push(program as unknown as AnyProgram);
          return 'aa';
        },
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    expect(fed.length).toBe(60);

    const isMutable = (p: AnyProgram) => p.properties.some((q) => !q.readonly) || hasUpdateProp(p);
    const stateful = fed.filter(isMutable);
    const stateless = fed.filter((p) => !isMutable(p));
    expect(stateful.length).toBeGreaterThan(0);
    expect(stateless.length).toBeGreaterThan(0);
    // Mutable-state programs first: they are what N-087 made every tier refuse.
    for (const program of [...stateful, ...stateless]) {
      const r = compileFromANF(program as never, { disableConstantFolding: true });
      expect(r.scriptHex).toMatch(/^[0-9a-f]+$/);
      expect(program.parentClass).toBe(isMutable(program) ? 'StatefulSmartContract' : 'SmartContract');
    }
  }, 60_000);
});

describe('N-395: a refusal finding keeps the refusing tier\'s message through the shrink', () => {
  const hasModOp = (program: AnyProgram): boolean =>
    program.methods.some((m) => m.body.some((b) => b.value.kind === 'bin_op' && b.value.op === '%'));

  it('records the message and reduces only to programs refused with that same message', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'anf-n395-shrink-'));
    // `go` refuses EVERY program, but for two different reasons. Before the
    // fix the two were indistinguishable, so a `%` finding shrank to a program
    // with no `%` (any refusal reproduced it).
    const fakeTier = (tier: CompilerName, program: unknown) => {
      if (tier !== 'go') return 'aa';
      return { rejected: hasModOp(program as AnyProgram) ? 'go: modulo refused' : 'go: other refusal' };
    };
    try {
      const report = await runAnfDifferential({
        numPrograms: 30,
        seed: 173,
        findingsDir: dir,
        compileTier: fakeTier as never,
        genOpts: { maxMethods: 3, maxBindingsPerMethod: 15 },
      });
      expect(report.mismatchCount).toBe(30);
      let modFindings = 0;
      for (const findingDir of report.findings) {
        const finding = JSON.parse(readFileSync(join(findingDir, 'finding.json'), 'utf-8'));
        const original = JSON.parse(readFileSync(join(findingDir, 'program.json'), 'utf-8'));
        const message = hasModOp(original) ? 'go: modulo refused' : 'go: other refusal';
        expect(finding.reason).toContain(message);
        const reducedPath = join(findingDir, 'program-reduced.json');
        expect(existsSync(reducedPath), `${findingDir} has no program-reduced.json`).toBe(true);
        expect(finding.reducedReason).toBe(finding.reason);
        const reduced = JSON.parse(readFileSync(reducedPath, 'utf-8'));
        if (hasModOp(original)) {
          modFindings += 1;
          expect(hasModOp(reduced)).toBe(true);
        }
      }
      expect(modFindings).toBeGreaterThan(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);
});
