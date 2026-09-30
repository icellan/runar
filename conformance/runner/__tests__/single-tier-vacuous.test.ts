import { describe, it, expect, afterAll, afterEach, vi } from 'vitest';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

import {
  runConformanceTest,
  runConformanceTestForFormat,
  shutdownJavaDaemon,
  type ConformanceResult,
} from '../runner.js';
import { generateReport, printReportToConsole } from '../report.js';

// F-049 (CL-BUG-088): a single-tier fixture compared NOTHING in the fold-ON
// conformance step and was still reported 'pass'.
//
// Two short-circuits stacked: compareIR/compareScript return a trivial match
// when the `compilers` allowlist names one tier, and the golden comparison is
// skipped under fold-ON (the goldens are stamped fold-OFF). The row's only
// surviving check was "the compiler exited 0", yet it was counted in
// "N passed" exactly like a 7-tier cross-validated row.
//
// The fix labels such a row 'vacuous': counted separately in the Summary,
// never in "passed". The same label applies whenever fewer than two tiers were
// compared and no golden was checked (e.g. the only allowlisted tier's binary
// is unavailable), in either fold mode.
//
// What this proves: for the real state-covenant fixture (allowlist ["go"]),
// the fold-ON row is not reported as a pass in either runner mode, while the
// fold-OFF row (which IS checked against the golden) still passes; and the
// Summary line keeps the prefix scripts/release.sh parses.
// What it does not prove: anything about the correctness of the Go-only
// goldens themselves (they were stamped by the tier they grade), nor that the
// fold-ON Go output is correct — only that the report no longer claims it was
// checked.

const __dirname = dirname(fileURLToPath(import.meta.url));
const TESTS_DIR = join(__dirname, '../../tests');
const FIXTURE = join(TESTS_DIR, 'state-covenant');

function tsFormat(): { ext: string; sourceFile: string } {
  const src = JSON.parse(readFileSync(join(FIXTURE, 'source.json'), 'utf-8')) as {
    sources: Record<string, string>;
  };
  return { ext: '.runar.ts', sourceFile: resolve(FIXTURE, src.sources['.runar.ts']!) };
}

const prevFold = process.env.RUNAR_DISABLE_CONSTANT_FOLDING;
afterEach(() => {
  if (prevFold === undefined) delete process.env.RUNAR_DISABLE_CONSTANT_FOLDING;
  else process.env.RUNAR_DISABLE_CONSTANT_FOLDING = prevFold;
});
afterAll(async () => {
  await shutdownJavaDaemon();
});

describe('F-049: single-tier fixture under fold-ON is not a pass', () => {
  it('multi-format fold-ON row is vacuous, not passed', async () => {
    process.env.RUNAR_DISABLE_CONSTANT_FOLDING = '0';
    const r = await runConformanceTestForFormat(FIXTURE, tsFormat());
    expect(r.errors).toEqual([]);
    // The one allowlisted tier really ran and succeeded — vacuity here comes
    // from the single-tier allowlist, not from a missing binary.
    expect(r.goCompiler?.success).toBe(true);
    const report = generateReport([r]);
    expect(report.results[0]!.status).toBe('vacuous');
    expect(report.passed).toBe(0);
    expect(report.vacuous).toBe(1);
    expect(report.failed).toBe(0);
  }, 180_000);

  it('golden-mode fold-ON row is vacuous, not passed', async () => {
    process.env.RUNAR_DISABLE_CONSTANT_FOLDING = '0';
    const r = await runConformanceTest(FIXTURE);
    expect(r.errors).toEqual([]);
    expect(r.goCompiler?.success).toBe(true);
    const report = generateReport([r]);
    expect(report.results[0]!.status).toBe('vacuous');
    expect(report.passed).toBe(0);
  }, 180_000);

  it('control: fold-OFF row is checked against the golden and still passes', async () => {
    process.env.RUNAR_DISABLE_CONSTANT_FOLDING = '1';
    const r = await runConformanceTestForFormat(FIXTURE, tsFormat());
    const report = generateReport([r]);
    expect(report.results[0]!.status, r.errors.join('\n')).toBe('pass');
    expect(report.vacuous).toBe(0);
  }, 180_000);
});

describe('F-049: vacuous accounting in the report', () => {
  const out = (success: boolean) => ({
    irJson: '', scriptHex: '', scriptAsm: '', success, durationMs: 1,
  });
  const row = (over: Partial<ConformanceResult>): ConformanceResult => ({
    testName: 'demo',
    tsCompiler: out(true),
    irMatch: true,
    scriptMatch: true,
    errors: [],
    ...over,
  });

  it('an error on a vacuous row is still a failure', () => {
    const report = generateReport([row({ vacuous: 'nothing compared', errors: ['Go compiler failed'] })]);
    expect(report.results[0]!.status).toBe('fail');
    expect(report.failed).toBe(1);
    expect(report.vacuous).toBe(0);
  });

  it('Summary names the vacuous count and keeps the prefix release.sh parses', () => {
    const report = generateReport([
      row({ goCompiler: out(true) }),
      row({ testName: 'single', vacuous: 'only [go] ran; no golden under fold-ON' }),
    ]);
    const lines: string[] = [];
    const spy = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => {
      lines.push(a.map(String).join(' '));
    });
    try {
      printReportToConsole(report);
    } finally {
      spy.mockRestore();
    }
    const text = lines.join('\n').replace(/\x1b\[[0-9;]*m/g, '');
    const summary = text.split('\n').find((l) => l.startsWith('Summary:'))!;
    expect(summary).toBe('Summary: 1 passed, 0 failed, 0 skipped, 1 vacuous (2 total)');
    expect(summary).toMatch(/^Summary: [0-9]+ passed, [0-9]+ failed/);
    expect(text).toContain('VACUOUS single');
  });
});
