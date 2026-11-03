// N-166: a missing ANF parity driver must fail CI and must never be a silent
// local pass.
//
// Proves: the gate shared by the three cross-interpreter suites throws for a
// missing driver whenever CI is set to any non-false value (not only the
// literal `CI=true` GitHub sets) or RUNAR_ANF_DRIVERS_STRICT=1, and that
// outside CI it names every missing driver and its setup hint on the warn
// channel instead of only bumping vitest's anonymous "skipped" count. It also
// proves all three suites route through this gate (no private copy).
// Does not prove: that the drivers produce correct output (the suites do
// that), or that the CI workflow builds them (ci.yml conformance-anf-parity
// job). The env is injected; process.env is never mutated.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { enforceDriverGate, isCiEnv, type GateDriver } from './driver-gate.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const ZIG: GateDriver = { name: 'zig', setupHint: 'zig build inside drivers/zig/' };

function run(env: Record<string, string | undefined>, missing: GateDriver[] = [ZIG]) {
  const lines: string[] = [];
  let error: unknown;
  try {
    enforceDriverGate('ANF parity', missing, env, (l) => lines.push(l));
  } catch (e) {
    error = e;
  }
  return { lines, error };
}

describe('ANF driver gate (N-166)', () => {
  for (const ci of ['true', '1', 'yes', 'TRUE']) {
    it(`CI=${ci} with a missing driver fails, not skips`, () => {
      const { error } = run({ CI: ci });
      expect(error).toBeInstanceOf(Error);
      expect(String(error)).toContain('zig');
    });
  }

  it('GITHUB_ACTIONS=true with a missing driver fails', () => {
    expect(run({ GITHUB_ACTIONS: 'true' }).error).toBeInstanceOf(Error);
  });

  it('RUNAR_ANF_DRIVERS_STRICT=1 with a missing driver fails locally', () => {
    expect(run({ RUNAR_ANF_DRIVERS_STRICT: '1' }).error).toBeInstanceOf(Error);
  });

  for (const ci of [undefined, '', '0', 'false', 'FALSE']) {
    it(`CI=${JSON.stringify(ci)} is not CI: missing driver warns by name with its setup hint`, () => {
      expect(isCiEnv({ CI: ci })).toBe(false);
      const { lines, error } = run({ CI: ci });
      expect(error).toBeUndefined();
      expect(lines).toHaveLength(1);
      expect(lines[0]).toContain('zig');
      expect(lines[0]).toContain(ZIG.setupHint);
    });
  }

  it('no missing driver: no throw, no warning, even under CI', () => {
    expect(run({ CI: '1' }, [])).toEqual({ lines: [], error: undefined });
    expect(run({}, [])).toEqual({ lines: [], error: undefined });
  });

  for (const suite of [
    'cross-interpreter.test.ts',
    'cross-interpreter-strict.test.ts',
    'cross-interpreter-real-crypto.test.ts',
  ]) {
    it(`${suite} uses the shared gate`, () => {
      const src = readFileSync(join(__dirname, suite), 'utf8');
      expect(src).toContain("from './driver-gate.js'");
      expect(src).toMatch(/enforceDriverGate\('[^']+', missingDrivers, process\.env\);/);
      expect(src).not.toMatch(/process\.env\.CI\b/);
    });
  }
});
