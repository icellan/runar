import { describe, it, expect, vi } from 'vitest';
import { decideMissingCompilerAction, emptyFixtureSetError } from '../runner.js';
import { printReportToConsole, type ConformanceReport } from '../report.js';

// R-103: "running the conformance suite with one compiler binary deleted must
// exit non-zero locally, not just in CI."
//
// The runner gates its hard failure on `CI === 'true'` and silently continues
// otherwise, which is a deliberate choice (local devs rarely have all seven
// toolchains). The choice is only defensible if a local run that dropped a
// tier CANNOT be mistaken for full coverage, and if a local run CAN be made
// to exit non-zero on demand. Both halves are pinned here.

const compiler = (name: string, available: boolean) => ({
  name,
  available,
  testsRun: available ? 3 : 0,
  testsSucceeded: available ? 3 : 0,
  averageDurationMs: 1,
});

const report = (avail: Record<string, boolean>): ConformanceReport => ({
  timestamp: '2026-09-13T00:00:00.000Z',
  totalTests: 1,
  passed: 1,
  failed: 0,
  skipped: 0,
  results: [
    { testName: 'demo', status: 'pass', irMatch: true, scriptMatch: true, errors: [], timings: {} },
  ],
  compilers: Object.entries(avail).map(([n, a]) => compiler(n, a)),
});

const capture = (r: ConformanceReport): string => {
  const lines: string[] = [];
  const spy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    lines.push(args.map(String).join(' '));
  });
  try {
    printReportToConsole(r);
  } finally {
    spy.mockRestore();
  }
  // Strip ANSI so assertions are about content, not colour.
  return lines.join('\n').replace(/\x1b\[[0-9;]*m/g, '');
};

describe('R-103 missing-tier visibility', () => {
  describe('decideMissingCompilerAction', () => {
    it('is ok when nothing is missing, whatever the environment', () => {
      expect(decideMissingCompilerAction([], {})).toBe('ok');
      expect(decideMissingCompilerAction([], { CI: 'true' })).toBe('ok');
      expect(decideMissingCompilerAction([], { RUNAR_CONFORMANCE_STRICT: '1' })).toBe('ok');
    });

    it('hard-fails in CI (existing behaviour, unchanged)', () => {
      expect(decideMissingCompilerAction(['zig'], { CI: 'true' })).toBe('fail');
    });

    it('hard-fails locally when strict mode is requested — R-103', () => {
      expect(decideMissingCompilerAction(['zig'], { RUNAR_CONFORMANCE_STRICT: '1' })).toBe('fail');
      expect(decideMissingCompilerAction(['zig'], { RUNAR_CONFORMANCE_STRICT: 'true' })).toBe('fail');
    });

    it('warns — never silently passes — on a permissive local run', () => {
      expect(decideMissingCompilerAction(['zig'], {})).toBe('warn');
      expect(decideMissingCompilerAction(['zig', 'ruby'], { CI: 'false' })).toBe('warn');
      // An unset/empty strict flag is not strict.
      expect(decideMissingCompilerAction(['zig'], { RUNAR_CONFORMANCE_STRICT: '0' })).toBe('warn');
      expect(decideMissingCompilerAction(['zig'], { RUNAR_CONFORMANCE_STRICT: '' })).toBe('warn');
    });
  });

  describe('printReportToConsole', () => {
    it('brands a run that dropped a tier as INCOMPLETE COVERAGE and names the tier', () => {
      const out = capture(report({ TypeScript: true, Go: true, Zig: false, Ruby: false }));
      expect(out).toContain('INCOMPLETE COVERAGE');
      expect(out).toMatch(/Zig/);
      expect(out).toMatch(/Ruby/);
      // and tells the reader how to turn it into a non-zero exit
      expect(out).toContain('RUNAR_CONFORMANCE_STRICT');
    });

    it('says nothing of the sort when every tier ran', () => {
      const out = capture(report({ TypeScript: true, Go: true, Zig: true, Ruby: true }));
      expect(out).not.toContain('INCOMPLETE COVERAGE');
      expect(out).not.toContain('RUNAR_CONFORMANCE_STRICT');
    });
  });

  // R-103, second half: "No entry point asserts the fixture set is non-empty
  // either, so a path-resolution mistake yields '0 fixtures, 0 failures, PASS'."
  describe('emptyFixtureSetError', () => {
    it('is silent when at least one fixture ran', () => {
      expect(emptyFixtureSetError(1, { mode: 'golden', testsDir: '/repo/conformance/tests' })).toBeNull();
      expect(emptyFixtureSetError(700, { mode: 'multi-format', testsDir: '/x' })).toBeNull();
    });

    it('reports a zero-fixture run, naming the mode and the directory it searched', () => {
      const msg = emptyFixtureSetError(0, { mode: 'ir-parity', testsDir: '/repo/conformance/tests' });
      expect(msg).not.toBeNull();
      expect(msg).toContain('ir-parity');
      expect(msg).toContain('/repo/conformance/tests');
      expect(msg).toMatch(/0 fixtures/);
    });

    it('blames the filter when one was given, so a typo is not read as a pass', () => {
      const msg = emptyFixtureSetError(0, { mode: 'golden', testsDir: '/x', filter: 'stafeul' });
      expect(msg).not.toBeNull();
      expect(msg).toContain('stafeul');
      const noFilter = emptyFixtureSetError(0, { mode: 'golden', testsDir: '/x' });
      expect(noFilter).not.toContain('--filter');
    });
  });
});
