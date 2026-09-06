/**
 * TDD proof for the independent source-anchor oracle (audit finding #22).
 *
 * `checkSourceAnchors` (independent-oracle.ts) derives correctness from the
 * REAL `.runar.*` source text on disk, never from `expected-source-map.json`
 * or from any Rúnar compiler pass. This file proves that property has teeth:
 *
 *   - RED: a deliberately-wrong mapping (mutated in memory from a real,
 *     currently-correct golden) is caught, even though byte-identity against
 *     "itself as the golden" trivially holds — demonstrating the oracle
 *     cannot be fooled by regenerating the golden to match a bug.
 *   - GREEN: the real TS and Python goldens (confirmed clean by direct
 *     inspection) pass with zero violations.
 *   - Inventory / regression gate: every committed `expected-source-map.json`
 *     across all 5 fixtures × 7 tiers is evaluated against
 *     `anchor-known-issues.json`. Pairs with no entry must be fully clean;
 *     pairs with an entry must match its exact recorded signature. This is
 *     what makes the independent oracle "run in CI alongside the golden
 *     compare" as a real gate — any new drift (a previously-clean tier
 *     regressing, or an already-broken tier's violation count changing)
 *     fails this test until the allowlist is deliberately updated.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync, readdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import {
  checkSourceAnchors,
  evaluateAgainstKnownIssues,
  loadKnownIssues,
  type SourceMap,
  type AnchorReport,
} from './independent-oracle.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');
const SOURCE_MAP_DIR = __dirname;

function loadGolden(fixture: string, tier: string): SourceMap {
  const p = join(SOURCE_MAP_DIR, fixture, tier, 'expected-source-map.json');
  return JSON.parse(readFileSync(p, 'utf-8')) as SourceMap;
}

describe('checkSourceAnchors — RED: catches a wrong mapping the golden compare cannot', () => {
  it('flags a mapping shifted one character into a token (the exact bug pattern found in go/rs/rb)', () => {
    const golden = loadGolden('arithmetic', 'ts');
    // arithmetic/ts opcodeIndex 1 maps to L12C4 — the 'c' of `const sum: bigint = a + b;`.
    // Mutate the mapping to be off-by-one: pointing at 'o' inside the "const" token.
    const mutated: SourceMap = {
      mappings: golden.mappings.map((m) => (m.opcodeIndex === 1 ? { ...m, column: m.column + 1 } : m)),
    };

    // Byte-identity vs "itself as the golden" trivially holds — this is the
    // exact failure mode the audit is about: a self-produced golden can
    // never disagree with the generator that produced it.
    expect(JSON.stringify(mutated)).toBe(JSON.stringify(mutated));

    // The independent oracle does NOT consult the golden at all — it reads
    // the real source file — so it still catches the wrong mapping.
    const report = checkSourceAnchors(mutated, REPO_ROOT);
    expect(report.ok).toBe(false);
    expect(report.violations).toContainEqual(
      expect.objectContaining({ opcodeIndex: 1, kind: 'splits-token' }),
    );
  });

  it('flags a mapping moved onto a blank/whitespace-only position', () => {
    const golden = loadGolden('basic-p2pkh', 'ts');
    // opcodeIndex 0 maps to L43C4 ("assert(hash160..."). Move it one line up
    // to the fixture's blank separator line (whichever line it is), by
    // shifting to column 0 of the line above a statement — use a line known
    // to be blank in every Rúnar contract: line 2 (blank line after the
    // import). Column 0 of a blank line is whitespace/out-of-bounds.
    const mutated: SourceMap = {
      mappings: golden.mappings.map((m) => (m.opcodeIndex === 0 ? { ...m, line: 2, column: 0 } : m)),
    };
    const report = checkSourceAnchors(mutated, REPO_ROOT);
    expect(report.ok).toBe(false);
    expect(report.violations.some((v) => v.opcodeIndex === 0)).toBe(true);
  });

  it('flags a mapping pointing past the end of the file', () => {
    const golden = loadGolden('if-else', 'ts');
    const mutated: SourceMap = {
      mappings: golden.mappings.map((m) => (m.opcodeIndex === 0 ? { ...m, line: 9999, column: 0 } : m)),
    };
    const report = checkSourceAnchors(mutated, REPO_ROOT);
    expect(report.ok).toBe(false);
    expect(report.violations).toContainEqual(
      expect.objectContaining({ opcodeIndex: 0, kind: 'line-out-of-bounds' }),
    );
  });

  it('flags a source map where every mapping is untracked (the Java "all line=0" case)', () => {
    const degenerate: SourceMap = {
      mappings: [
        { opcodeIndex: 0, sourceFile: 'examples/ts/arithmetic/Arithmetic.runar.ts', line: 0, column: 0 },
        { opcodeIndex: 1, sourceFile: 'examples/ts/arithmetic/Arithmetic.runar.ts', line: 0, column: 0 },
      ],
    };
    const report = checkSourceAnchors(degenerate, REPO_ROOT);
    expect(report.ok).toBe(false);
    expect(report.trackedCount).toBe(0);
    expect(report.violations).toEqual([]); // no per-mapping violation — the deficit is trackedCount itself
  });
});

describe('checkSourceAnchors — GREEN: real, currently-correct goldens pass cleanly', () => {
  const CLEAN_FIXTURES = ['basic-p2pkh', 'stateful-counter', 'escrow', 'arithmetic', 'if-else'];

  for (const tier of ['ts', 'py'] as const) {
    for (const fixture of CLEAN_FIXTURES) {
      it(`${fixture}/${tier} has zero anchor violations and full position coverage`, () => {
        const sm = loadGolden(fixture, tier);
        const report = checkSourceAnchors(sm, REPO_ROOT);
        expect(report.violations).toEqual([]);
        expect(report.trackedCount).toBeGreaterThan(0);
        expect(report.ok).toBe(true);
      });
    }
  }
});

describe('evaluateAgainstKnownIssues', () => {
  const okReport: AnchorReport = { ok: true, violations: [], trackedCount: 3, untrackedCount: 0, totalCount: 3 };

  it('passes a clean report with no allowlist entry', () => {
    const result = evaluateAgainstKnownIssues('fx', 'ts', okReport, []);
    expect(result.ok).toBe(true);
  });

  it('fails a violating report with no allowlist entry', () => {
    const bad: AnchorReport = {
      ok: false,
      violations: [{ opcodeIndex: 0, kind: 'splits-token', detail: 'x' }],
      trackedCount: 3,
      untrackedCount: 0,
      totalCount: 3,
    };
    const result = evaluateAgainstKnownIssues('fx', 'go', bad, []);
    expect(result.ok).toBe(false);
  });

  it('passes when the report signature exactly matches an allowlist entry', () => {
    const bad: AnchorReport = {
      ok: false,
      violations: [{ opcodeIndex: 0, kind: 'splits-token', detail: 'x' }],
      trackedCount: 4,
      untrackedCount: 0,
      totalCount: 4,
    };
    const result = evaluateAgainstKnownIssues('fx', 'go', bad, [
      { fixture: 'fx', tier: 'go', violationCount: 1, trackedCount: 4, totalCount: 4, reason: 'known bug' },
    ]);
    expect(result.ok).toBe(true);
  });

  it('fails when a previously-broken pair improves without updating the allowlist (drift)', () => {
    // Simulates a generator fix landing without a matching allowlist update
    // — the improvement must be surfaced (and the entry removed), not
    // silently absorbed as still "ok".
    const fixed: AnchorReport = { ok: true, violations: [], trackedCount: 4, untrackedCount: 0, totalCount: 4 };
    const result = evaluateAgainstKnownIssues('fx', 'go', fixed, [
      { fixture: 'fx', tier: 'go', violationCount: 1, trackedCount: 4, totalCount: 4, reason: 'known bug' },
    ]);
    expect(result.ok).toBe(false);
  });

  it('fails when trackedCount regresses even though violationCount alone is unchanged (Java-style collapse)', () => {
    // violationCount stays 0 in both the recorded entry and the new report,
    // but trackedCount collapses from partially-tracked to fully-untracked.
    // A violationCount-only comparison would miss this; pinning all three
    // fields does not.
    const collapsed: AnchorReport = { ok: false, violations: [], trackedCount: 0, untrackedCount: 4, totalCount: 4 };
    const result = evaluateAgainstKnownIssues('fx', 'java', collapsed, [
      { fixture: 'fx', tier: 'java', violationCount: 0, trackedCount: 2, totalCount: 4, reason: 'partially tracked' },
    ]);
    expect(result.ok).toBe(false);
  });

  it('rejects an allowlist entry with an empty reason', () => {
    expect(() =>
      loadKnownIssuesFromObject({ knownIssues: [{ fixture: 'fx', tier: 'go', violationCount: 1, trackedCount: 1, totalCount: 1, reason: '' }] }),
    ).toThrow(/reason/);
  });
});

// loadKnownIssues reads from a file path; wrap an in-memory object through a
// temp file so the "empty reason" contract test doesn't need a fixture file.
function loadKnownIssuesFromObject(obj: unknown): ReturnType<typeof loadKnownIssues> {
  const dir = mkdtempSync(join(tmpdir(), 'anchor-known-issues-'));
  const p = join(dir, 'known-issues.json');
  writeFileSync(p, JSON.stringify(obj));
  return loadKnownIssues(p);
}

describe('independent anchor oracle vs anchor-known-issues.json — regression gate', () => {
  const KNOWN_ISSUES_PATH = join(SOURCE_MAP_DIR, 'anchor-known-issues.json');
  const knownIssues = loadKnownIssues(KNOWN_ISSUES_PATH).knownIssues;

  const FIXTURES = readdirSync(SOURCE_MAP_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory() && !d.name.startsWith('.'))
    .map((d) => d.name);
  const TIERS = ['ts', 'go', 'rs', 'py', 'zig', 'rb', 'java'];

  // A missing golden used to `continue`, which emits no `it()` at all — so
  // deleting a golden deleted its own test and nothing went red. Every
  // (fixture, tier) pair must ship one.
  const missingGoldens = FIXTURES.flatMap((fixture) =>
    TIERS.filter(
      (tier) => !existsSync(join(SOURCE_MAP_DIR, fixture, tier, 'expected-source-map.json')),
    ).map((tier) => `${fixture}/${tier}`),
  );

  it('every fixture ships a source-map golden for all 7 tiers', () => {
    expect(FIXTURES.length).toBeGreaterThan(0);
    expect(missingGoldens, `missing source-map goldens: ${missingGoldens.join(', ')}`).toEqual([]);
  });

  for (const fixture of FIXTURES) {
    for (const tier of TIERS) {
      const goldenPath = join(SOURCE_MAP_DIR, fixture, tier, 'expected-source-map.json');
      if (!existsSync(goldenPath)) continue;

      it(`${fixture}/${tier} anchor signature matches anchor-known-issues.json (or is clean)`, () => {
        const sm = JSON.parse(readFileSync(goldenPath, 'utf-8')) as SourceMap;
        const report = checkSourceAnchors(sm, REPO_ROOT);
        const evaluation = evaluateAgainstKnownIssues(fixture, tier, report, knownIssues);
        expect(evaluation.ok, evaluation.reason).toBe(true);
      });
    }
  }
});
