import { describe, it, expect } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  parseArgs,
  formatTable,
  formatComparison,
  formatDetail,
  measureGolden,
  tsSourcePath,
  VARIANTS,
  type FixtureMetrics,
} from '../script-metrics.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fakeMetrics(fixture: string, scriptBytes: number): FixtureMetrics {
  return {
    fixture,
    source: 'compiled',
    scriptBytes,
    opcodeCount: scriptBytes,
    pushCount: 0,
    categories: {
      'const-push': scriptBytes, 'small-int-push': 0, 'stack-shuffle': 0,
      arithmetic: 0, bytes: 0, crypto: 0, control: 0, other: 0,
    },
    opcodes: { PUSH: 1 },
    constants: [],
  };
}

// ---------------------------------------------------------------------------

describe('parseArgs', () => {
  it('defaults to reading goldens with a summary table', () => {
    const a = parseArgs([]);
    expect(a.compileMode).toBe(false);
    expect(a.detail).toBe(false);
    expect(a.compare).toEqual([]);
  });

  it('--compare implies --compile', () => {
    const a = parseArgs(['--compare', 'current,current']);
    expect(a.compare).toEqual(['current', 'current']);
    expect(a.compileMode).toBe(true);
  });

  it('rejects an unknown argument instead of ignoring it', () => {
    // A silently-ignored flag in a benchmark harness reads as "I measured
    // that" when nothing was measured.
    expect(() => parseArgs(['--nope'])).toThrow(/unknown argument/);
  });
});

describe('variants', () => {
  it('always offers the shipping default as the comparison base', () => {
    expect(VARIANTS.current).toBeDefined();
    expect(VARIANTS.current).toEqual({});
  });
});

describe('tsSourcePath', () => {
  it('resolves a fixture that ships a TypeScript source', () => {
    const p = tsSourcePath('p2pkh') ?? tsSourcePath('basic-p2pkh');
    expect(p).toMatch(/\.runar\.ts$/);
  });

  it('returns null for a fixture that declares no .runar.ts rather than throwing', () => {
    // A size report must skip such a fixture visibly, not crash on it.
    const dir = mkdtempSync(join(tmpdir(), 'runar-metrics-'));
    try {
      mkdirSync(join(dir, 'go-only'));
      writeFileSync(
        join(dir, 'go-only', 'source.json'),
        JSON.stringify({ sources: { '.runar.go': './X.runar.go' }, compilers: ['go'] }),
      );
      expect(tsSourcePath('go-only', dir)).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('returns null when the fixture has no source.json at all', () => {
    const dir = mkdtempSync(join(tmpdir(), 'runar-metrics-'));
    try {
      mkdirSync(join(dir, 'bare'));
      expect(tsSourcePath('bare', dir)).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('throws when source.json points at a file that is not on disk', () => {
    const dir = mkdtempSync(join(tmpdir(), 'runar-metrics-'));
    try {
      mkdirSync(join(dir, 'ghost'));
      writeFileSync(
        join(dir, 'ghost', 'source.json'),
        JSON.stringify({ sources: { '.runar.ts': './nope.runar.ts' } }),
      );
      expect(() => tsSourcePath('ghost', dir)).toThrow(/missing file/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('measureGolden', () => {
  it('reports the byte length and category split of a golden', () => {
    const dir = mkdtempSync(join(tmpdir(), 'runar-metrics-'));
    try {
      const hexPath = join(dir, 'expected-script.hex');
      // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
      writeFileSync(hexPath, `76a914${'ab'.repeat(20)}88ac\n`);
      const m = measureGolden('p2pkh-ish', hexPath);
      expect(m.scriptBytes).toBe(25);
      expect(m.source).toBe('golden');
      expect(m.categories['const-push']).toBe(21);
      expect(m.opcodes['OP_CHECKSIG']).toBe(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('formatting', () => {
  it('orders the summary table largest-first', () => {
    const table = formatTable([fakeMetrics('small', 10), fakeMetrics('big', 100)]);
    expect(table.indexOf('| big |')).toBeLessThan(table.indexOf('| small |'));
  });

  it('reports the delta of the last variant against the first', () => {
    const byVariant = new Map([
      ['current', new Map([['fx', fakeMetrics('fx', 1000)]])],
      ['tuned', new Map([['fx', fakeMetrics('fx', 250)]])],
    ]);
    const out = formatComparison(['current', 'tuned'], byVariant);
    expect(out).toContain('-75.0%');
  });

  it('renders a dash for a variant that produced no result', () => {
    const byVariant = new Map([
      ['current', new Map([['fx', fakeMetrics('fx', 1000)]])],
      ['tuned', new Map<string, FixtureMetrics>()],
    ]);
    expect(formatComparison(['current', 'tuned'], byVariant)).toContain('| — |');
  });

  it('lists dominant constants in the detail view', () => {
    const m = fakeMetrics('fx', 340);
    m.constants = [{ hex: 'ff'.repeat(33), count: 10, bytes: 340 }];
    const out = formatDetail(m);
    expect(out).toContain('33 B');
    expect(out).toContain('100.0%');
  });
});
