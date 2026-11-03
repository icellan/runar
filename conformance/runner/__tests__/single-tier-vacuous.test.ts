import { describe, it, expect, afterAll, afterEach, vi } from 'vitest';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';

import {
  readFixtureFoldOnMatchesGolden,
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
// N-473 (user decision R190): the 5 Go-only fixtures were still 45 VACUOUS
// rows in every fold-ON multi-format run. Measured at 2f2b78f5b, the Go
// tier's fold-ON IR and hex equal the fold-OFF golden byte-for-byte in all 9
// formats, so those fixtures now opt in with `"foldOnMatchesGolden": true` in
// source.json and the runner compares their fold-ON output against the
// existing (provenance-gated) golden. The vacuity detector is unchanged: a
// flagged row is non-vacuous only because a golden comparison really ran.
//
// What this proves:
//  - control: an UNflagged single-tier fixture (temp copy of state-covenant
//    without the flag) is still vacuous under fold-ON in both runner modes;
//  - positive: the flagged state-covenant fold-ON row passes, in both modes,
//    i.e. a golden comparison ran (a single-tier row with no golden check is
//    vacuous by construction, so 'pass' implies irGoldenChecked and
//    scriptGoldenChecked > 0);
//  - negative: a flagged temp copy whose golden is tampered FAILS the fold-ON
//    row (script and IR separately), so the comparison is real;
//  - hardening: the flag is refused on a fixture with no `compilers`
//    allowlist and refused unless it is literally `true`;
//  - the fold-OFF row still passes against the golden.
// What it does not prove: that the Go-only goldens are correct (they were
// stamped by the only tier they grade), nor anything about fold-ON parity of
// multi-tier fixtures (those are cross-validated tier-against-tier).

const __dirname = dirname(fileURLToPath(import.meta.url));
const TESTS_DIR = join(__dirname, '../../tests');
const FIXTURE = join(TESTS_DIR, 'state-covenant');

interface SourceJson {
  compilers?: string[];
  foldOnMatchesGolden?: unknown;
  sources: Record<string, string>;
  [k: string]: unknown;
}

function readSource(): SourceJson {
  return JSON.parse(readFileSync(join(FIXTURE, 'source.json'), 'utf-8')) as SourceJson;
}

function tsFormat(dir = FIXTURE): { ext: string; sourceFile: string } {
  const src = JSON.parse(readFileSync(join(dir, 'source.json'), 'utf-8')) as SourceJson;
  return { ext: '.runar.ts', sourceFile: resolve(dir, src.sources['.runar.ts']!) };
}

const tempDirs: string[] = [];

/**
 * Temp copy of state-covenant: source.json with ABSOLUTE source paths (the
 * real ones are relative to the fixture dir), edited by `edit`, plus the
 * fixture's goldens. Named 'state-covenant' so per-fixture lookups match.
 */
function tempFixture(edit: (cfg: SourceJson) => void): string {
  const parent = mkdtempSync(join(tmpdir(), 'n473-'));
  tempDirs.push(parent);
  const dir = join(parent, 'state-covenant');
  const cfg = readSource();
  for (const k of Object.keys(cfg.sources)) cfg.sources[k] = resolve(FIXTURE, cfg.sources[k]!);
  edit(cfg);
  mkdirSync(dir);
  writeFileSync(join(dir, 'source.json'), JSON.stringify(cfg, null, 2));
  copyFileSync(join(FIXTURE, 'expected-ir.json'), join(dir, 'expected-ir.json'));
  copyFileSync(join(FIXTURE, 'expected-script.hex'), join(dir, 'expected-script.hex'));
  return dir;
}

const prevFold = process.env.RUNAR_DISABLE_CONSTANT_FOLDING;
afterEach(() => {
  if (prevFold === undefined) delete process.env.RUNAR_DISABLE_CONSTANT_FOLDING;
  else process.env.RUNAR_DISABLE_CONSTANT_FOLDING = prevFold;
});
afterAll(async () => {
  for (const d of tempDirs) rmSync(d, { recursive: true, force: true });
  await shutdownJavaDaemon();
});

describe('F-049: unflagged single-tier fixture under fold-ON is not a pass (control)', () => {
  it('multi-format fold-ON row is vacuous, not passed', async () => {
    process.env.RUNAR_DISABLE_CONSTANT_FOLDING = '0';
    const dir = tempFixture((c) => { delete c.foldOnMatchesGolden; });
    const r = await runConformanceTestForFormat(dir, tsFormat(dir));
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
    const dir = tempFixture((c) => { delete c.foldOnMatchesGolden; });
    const r = await runConformanceTest(dir);
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

describe('N-473: foldOnMatchesGolden makes a single-tier fold-ON row assert something', () => {
  it('state-covenant declares the opt-in', () => {
    expect(readSource().foldOnMatchesGolden).toBe(true);
    expect(readFixtureFoldOnMatchesGolden(FIXTURE)).toBe(true);
  });

  it('positive: flagged multi-format fold-ON row passes against the golden', async () => {
    process.env.RUNAR_DISABLE_CONSTANT_FOLDING = '0';
    const r = await runConformanceTestForFormat(FIXTURE, tsFormat());
    expect(r.goCompiler?.success).toBe(true);
    expect(r.vacuous).toBeUndefined();
    const report = generateReport([r]);
    expect(report.results[0]!.status, r.errors.join('\n')).toBe('pass');
    expect(report.vacuous).toBe(0);
  }, 180_000);

  it('positive: flagged golden-mode fold-ON row passes against the golden', async () => {
    process.env.RUNAR_DISABLE_CONSTANT_FOLDING = '0';
    const r = await runConformanceTest(FIXTURE);
    expect(r.vacuous).toBeUndefined();
    const report = generateReport([r]);
    expect(report.results[0]!.status, r.errors.join('\n')).toBe('pass');
  }, 180_000);

  it('negative: a tampered script golden fails the flagged fold-ON row', async () => {
    process.env.RUNAR_DISABLE_CONSTANT_FOLDING = '0';
    const dir = tempFixture((c) => { c.foldOnMatchesGolden = true; });
    const hex = readFileSync(join(dir, 'expected-script.hex'), 'utf-8').trim();
    // Flip the last nibble: one-byte-different golden.
    const last = hex.slice(-1) === '0' ? '1' : '0';
    writeFileSync(join(dir, 'expected-script.hex'), hex.slice(0, -1) + last + '\n');
    const r = await runConformanceTestForFormat(dir, tsFormat(dir));
    expect(r.errors.join('\n')).toMatch(/Script does not match golden file/);
    expect(generateReport([r]).results[0]!.status).toBe('fail');

    const g = await runConformanceTest(dir);
    expect(g.errors.join('\n')).toMatch(/Go compiler script does not match golden file/);
  }, 180_000);

  it('negative: a tampered IR golden fails the flagged fold-ON row', async () => {
    process.env.RUNAR_DISABLE_CONSTANT_FOLDING = '0';
    const dir = tempFixture((c) => { c.foldOnMatchesGolden = true; });
    const ir = JSON.parse(readFileSync(join(dir, 'expected-ir.json'), 'utf-8')) as { contractName: string };
    ir.contractName = `${ir.contractName}Tampered`;
    writeFileSync(join(dir, 'expected-ir.json'), JSON.stringify(ir));
    const r = await runConformanceTestForFormat(dir, tsFormat(dir));
    expect(r.errors.join('\n')).toMatch(/IR does not match golden file/);
    expect(generateReport([r]).results[0]!.status).toBe('fail');
  }, 180_000);

  it('hardening: the flag is refused without a compilers allowlist', () => {
    const dir = tempFixture((c) => { c.foldOnMatchesGolden = true; delete c.compilers; });
    expect(() => readFixtureFoldOnMatchesGolden(dir)).toThrow(/foldOnMatchesGolden.*compilers/);
  });

  it('hardening: the flag must be literally true', () => {
    const dir = tempFixture((c) => { c.foldOnMatchesGolden = 'yes'; });
    expect(() => readFixtureFoldOnMatchesGolden(dir)).toThrow(/foldOnMatchesGolden/);
  });
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
