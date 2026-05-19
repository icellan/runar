import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  BASELINE_PATH,
  TESTS_DIR,
  classify,
  discoverFixtures,
  hexFileByteLength,
  loadBaseline,
  rewriteBaseline,
  runComparison,
  type Baseline,
} from '../script-size-check.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE_ROOT = resolve(__dirname, '../..');

// ---------------------------------------------------------------------------
// Helpers — build a throwaway fixture tree under /tmp so we can exercise the
// pure verification logic with whatever sizes we need. The real
// conformance/tests tree must not be touched.
// ---------------------------------------------------------------------------

function makeHexOfBytes(n: number): string {
  // Each byte = 2 hex chars. Use "ab" repeated so the hex regex is happy.
  return 'ab'.repeat(n) + '\n';
}

interface SandboxedTree {
  root: string;
  testsDir: string;
  baselinePath: string;
  cleanup: () => void;
}

function makeSandbox(): SandboxedTree {
  const root = mkdtempSync(join(tmpdir(), 'runar-script-size-'));
  const testsDir = join(root, 'tests');
  mkdirSync(testsDir, { recursive: true });
  const baselinePath = join(root, 'script-size-baseline.json');
  return {
    root,
    testsDir,
    baselinePath,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

function writeFixture(testsDir: string, name: string, bytes: number) {
  const dir = join(testsDir, name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'expected-script.hex'), makeHexOfBytes(bytes), 'utf8');
}

function writeBaseline(path: string, fixtures: Record<string, number>) {
  const data: Baseline = {
    _tolerance_growth_percent: 10,
    _tolerance_shrink_percent: 50,
    fixtures,
  };
  writeFileSync(path, JSON.stringify(data, null, 2) + '\n', 'utf8');
}

// ---------------------------------------------------------------------------
// Repo-baseline structural tests
// ---------------------------------------------------------------------------

describe('checked-in script-size-baseline.json', () => {
  const baseline = loadBaseline(BASELINE_PATH);
  const fixtures = discoverFixtures(TESTS_DIR);

  it('is valid JSON with a fixtures map', () => {
    expect(baseline.fixtures).toBeTypeOf('object');
    expect(Object.keys(baseline.fixtures).length).toBeGreaterThan(0);
  });

  it('records a positive integer byte count for every entry', () => {
    for (const [name, bytes] of Object.entries(baseline.fixtures)) {
      expect(Number.isInteger(bytes), `${name} bytes must be an integer`).toBe(true);
      expect(bytes, `${name} bytes must be > 0`).toBeGreaterThan(0);
    }
  });

  it('every baseline key maps to a real fixture in conformance/tests/', () => {
    for (const name of Object.keys(baseline.fixtures)) {
      expect(
        fixtures.has(name),
        `baseline lists ${name} but conformance/tests/${name}/expected-script.hex is missing`,
      ).toBe(true);
    }
  });

  it('every conformance fixture appears in the baseline (no silent additions)', () => {
    for (const name of fixtures.keys()) {
      expect(
        Object.prototype.hasOwnProperty.call(baseline.fixtures, name),
        `fixture ${name} has expected-script.hex but no baseline entry`,
      ).toBe(true);
    }
  });
});

describe('checked-in fixtures match the baseline exactly (0 % drift today)', () => {
  it('runComparison passes against the real conformance/tests tree', () => {
    const baseline = loadBaseline(BASELINE_PATH);
    const report = runComparison(baseline, TESTS_DIR);
    if (report.failed) {
      // Print actionable diff before failing.
      const offenders = report.results
        .filter((r) => r.status === 'fail' || r.status === 'missing-baseline' || r.status === 'missing-current')
        .map((r) => `  - ${r.message}`)
        .join('\n');
      throw new Error(
        `Script-size regression check failed:\n${offenders}\n` +
          `Run \`pnpm script-size-check -- --update\` to re-stamp the baseline ` +
          `(only on intentional size-change PRs; justify in the PR description).`,
      );
    }
    expect(report.failed).toBe(false);
    expect(report.fail).toBe(0);
    expect(report.missing).toBe(0);
    // Today the tree is exactly at baseline — warn count should be 0 too.
    expect(report.warn).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Pure classification logic — exercise +15 %, -60 %, +5 %, unchanged.
// ---------------------------------------------------------------------------

describe('classify()', () => {
  it('flags +15 % growth as fail', () => {
    const result = classify('foo', 1000, 1150);
    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/threshold \+10%/);
    expect(result.message).toMatch(/\+15\.00%/);
  });

  it('flags -60 % shrinkage as fail (suspicious)', () => {
    const result = classify('foo', 1000, 400);
    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/suspicious shrinkage past -50%/);
  });

  it('accepts +5 % growth as warn (within tolerance)', () => {
    const result = classify('foo', 1000, 1050);
    expect(result.status).toBe('warn');
    expect(result.message).toMatch(/within \+10% tolerance/);
  });

  it('accepts unchanged sizes as ok', () => {
    const result = classify('foo', 1000, 1000);
    expect(result.status).toBe('ok');
    expect(result.delta).toBe(0);
  });

  it('accepts modest shrinkage as ok', () => {
    const result = classify('foo', 1000, 900);
    expect(result.status).toBe('ok');
  });

  it('reports missing-baseline when fixture is new', () => {
    const result = classify('foo', null, 500);
    expect(result.status).toBe('missing-baseline');
  });

  it('reports missing-current when fixture is deleted', () => {
    const result = classify('foo', 500, null);
    expect(result.status).toBe('missing-current');
  });

  it('respects custom tolerances passed in from baseline metadata', () => {
    // tighter window: +1 % growth, -10 % shrink
    expect(classify('foo', 1000, 1015, 1, 10).status).toBe('fail');
    expect(classify('foo', 1000, 850, 1, 10).status).toBe('fail');
    expect(classify('foo', 1000, 1005, 1, 10).status).toBe('warn');
  });
});

// ---------------------------------------------------------------------------
// hexFileByteLength — handles trailing whitespace, rejects odd / non-hex.
// ---------------------------------------------------------------------------

describe('hexFileByteLength()', () => {
  let sandbox: SandboxedTree;
  beforeEach(() => {
    sandbox = makeSandbox();
  });
  afterEach(() => sandbox.cleanup());

  it('strips trailing newline and computes byte count', () => {
    const p = join(sandbox.root, 'a.hex');
    writeFileSync(p, 'abcdef\n', 'utf8');
    expect(hexFileByteLength(p)).toBe(3);
  });

  it('throws on odd hex length', () => {
    const p = join(sandbox.root, 'b.hex');
    writeFileSync(p, 'abc', 'utf8');
    expect(() => hexFileByteLength(p)).toThrow(/Odd hex length/);
  });

  it('throws on non-hex characters', () => {
    const p = join(sandbox.root, 'c.hex');
    writeFileSync(p, 'abzz', 'utf8');
    expect(() => hexFileByteLength(p)).toThrow(/Non-hex/);
  });
});

// ---------------------------------------------------------------------------
// End-to-end against a synthetic tree (sandbox /tmp dir) — covers +15 %,
// -60 %, +5 %, and unchanged in a single runComparison call.
// ---------------------------------------------------------------------------

describe('runComparison() against a synthetic fixture tree', () => {
  let sandbox: SandboxedTree;
  beforeEach(() => {
    sandbox = makeSandbox();
  });
  afterEach(() => sandbox.cleanup());

  it('classifies +15 % growth as fail, +5 % as warn, unchanged as ok, -60 % as fail', () => {
    writeBaseline(sandbox.baselinePath, {
      grew_a_lot: 1000,
      grew_a_bit: 1000,
      flat: 1000,
      shrunk_a_lot: 1000,
    });
    writeFixture(sandbox.testsDir, 'grew_a_lot', 1150);   // +15%
    writeFixture(sandbox.testsDir, 'grew_a_bit', 1050);   // +5%
    writeFixture(sandbox.testsDir, 'flat', 1000);          // 0
    writeFixture(sandbox.testsDir, 'shrunk_a_lot', 400);   // -60%

    const baseline = loadBaseline(sandbox.baselinePath);
    const report = runComparison(baseline, sandbox.testsDir);

    const byName = Object.fromEntries(report.results.map((r) => [r.fixture, r]));
    expect(byName.grew_a_lot.status).toBe('fail');
    expect(byName.grew_a_bit.status).toBe('warn');
    expect(byName.flat.status).toBe('ok');
    expect(byName.shrunk_a_lot.status).toBe('fail');
    expect(report.failed).toBe(true);
    expect(report.fail).toBe(2);
    expect(report.warn).toBe(1);
    expect(report.ok).toBe(1);
  });

  it('fails on missing fixture (baseline entry without a hex file)', () => {
    writeBaseline(sandbox.baselinePath, { gone: 500 });
    // no fixture written
    const report = runComparison(loadBaseline(sandbox.baselinePath), sandbox.testsDir);
    expect(report.failed).toBe(true);
    expect(report.missing).toBe(1);
    expect(report.results[0].status).toBe('missing-current');
  });

  it('fails on undeclared fixture (hex file without a baseline entry)', () => {
    writeBaseline(sandbox.baselinePath, {});
    writeFixture(sandbox.testsDir, 'surprise', 500);
    const report = runComparison(loadBaseline(sandbox.baselinePath), sandbox.testsDir);
    expect(report.failed).toBe(true);
    expect(report.missing).toBe(1);
    expect(report.results[0].status).toBe('missing-baseline');
  });
});

// ---------------------------------------------------------------------------
// rewriteBaseline (the --update flag) — restamps cleanly.
// ---------------------------------------------------------------------------

describe('rewriteBaseline() (--update flag)', () => {
  let sandbox: SandboxedTree;
  beforeEach(() => {
    sandbox = makeSandbox();
  });
  afterEach(() => sandbox.cleanup());

  it('writes one entry per fixture, sorted, with current byte counts', () => {
    writeBaseline(sandbox.baselinePath, { gamma: 999 });
    writeFixture(sandbox.testsDir, 'alpha', 100);
    writeFixture(sandbox.testsDir, 'beta', 200);
    writeFixture(sandbox.testsDir, 'gamma', 50); // pre-existing baseline was wrong

    const result = rewriteBaseline(sandbox.testsDir, sandbox.baselinePath);
    expect(result.written).toBe(3);

    const written = JSON.parse(readFileSync(sandbox.baselinePath, 'utf8')) as Baseline;
    expect(written.fixtures).toEqual({ alpha: 100, beta: 200, gamma: 50 });
    expect(written._tolerance_growth_percent).toBe(10);
    expect(written._tolerance_shrink_percent).toBe(50);

    // Round-trip: a subsequent runComparison should pass at 0 % drift.
    const next = runComparison(written, sandbox.testsDir);
    expect(next.failed).toBe(false);
    expect(next.fail).toBe(0);
    expect(next.warn).toBe(0);
    expect(next.missing).toBe(0);
    expect(next.ok).toBe(3);
  });
});
