import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decideExitCode, decideGoldenWrite, decideLiveShape } from './run.js';
import { loadKnownIssues, type SourceMap } from './independent-oracle.js';

// N-088 (companion to the conformance/runner/index.ts --update-golden fix):
// `conformance/source-map/run.ts --update` had two instances of the same
// fail-open class.
//
//   (a) `writeFileSync(goldenPath, emitted)` under `--update` ran
//       unconditionally — a compile that produced a structurally invalid
//       source map, or one whose mappings failed the independent
//       source-anchor oracle, still got STAMPED as the new golden.
//   (b) the final exit check was `if (failed > 0 && !update) process.exit(1)`
//       — any failure found while regenerating (including the one (a) just
//       wrote to disk) was masked by the mere fact of running `--update`.
//
// `decideGoldenWrite` and `decideExitCode` are the two decisions this file's
// `main()` now delegates to. Importing `run.ts` does NOT run its CLI (the
// entry-point guard at the bottom only calls `main()` when this file is the
// process entry point), so these pure functions can be unit-tested without
// spawning any of the seven compilers.
//
// What this proves: given the inputs that correspond to a fixture whose
// structural or anchor check failed, the golden is not written under
// --update, and the overall run reports a non-zero exit code regardless of
// --update.
// What it does not prove: anything about the structural/anchor checks
// themselves, or about any real fixture's source map.

describe('N-088: source-map run.ts --update does not mask a failing fixture', () => {
  it('writes the golden under --update only when both checks pass', () => {
    expect(decideGoldenWrite(true, true)).toBe(true);
    expect(decideGoldenWrite(false, true)).toBe(false);
    expect(decideGoldenWrite(true, false)).toBe(false);
    expect(decideGoldenWrite(false, false)).toBe(false);
  });

  it('a nonzero failure count is a nonzero exit code, with or without --update', () => {
    expect(decideExitCode(1, true)).not.toBe(0);
    expect(decideExitCode(1, false)).not.toBe(0);
    expect(decideExitCode(0, true)).toBe(0);
    expect(decideExitCode(0, false)).toBe(0);
  });
});

// N-370: run.ts compiles every (fixture, tier) live but used to apply only the
// per-mapping anchor rule, never the F-293 whole-map shape rule against the
// TS reference (that ran over the committed goldens only). `decideLiveShape`
// is the decision main() now delegates to for each live compile.
//
// What this proves: a LIVE map that duplicates one valid mapping onto opcodes
// the live TS reference leaves unmapped (extraMappings) or collapses the
// reference's anchors into one (mergedAnchors) is rejected unless pinned
// exactly; a clean live map and a live map matching its pinned signature
// pass; a missing live reference fails closed for a non-TS tier.
// What it does not prove: that the real compilers emit such maps today (the
// live runner over all tiers does), or that any anchor is the correct one.
describe('N-370: source-map run.ts applies the whole-map shape rule to live maps', () => {
  const dir = dirname(fileURLToPath(import.meta.url));
  const knownIssues = loadKnownIssues(join(dir, 'anchor-known-issues.json')).knownIssues;
  const golden = (fixture: string, tier: string): SourceMap =>
    JSON.parse(readFileSync(join(dir, fixture, tier, 'expected-source-map.json'), 'utf-8')) as SourceMap;

  it('passes a live map identical to the reference (clean pair)', () => {
    const ref = golden('arithmetic', 'ts');
    expect(decideLiveShape('arithmetic', 'go', ref, ref, knownIssues).ok).toBe(true);
  });

  it('rejects a live map that maps opcodes the live reference leaves unmapped', () => {
    const ref = golden('arithmetic', 'ts');
    const first = ref.mappings[0]!;
    const maxOp = Math.max(...ref.mappings.map((m) => m.opcodeIndex));
    const dup: SourceMap = {
      mappings: [...ref.mappings, ...[1, 2, 3].map((i) => ({ ...first, opcodeIndex: maxOp + i }))],
    };
    const r = decideLiveShape('arithmetic', 'go', dup, ref, knownIssues);
    expect(r.ok).toBe(false);
    expect(r.reason).toContain('extraMappings:3');
  });

  it('rejects a live map that merges the reference anchors into one', () => {
    const ref = golden('arithmetic', 'ts');
    const first = ref.mappings[0]!;
    const merged: SourceMap = { mappings: ref.mappings.map((m) => ({ ...m, line: first.line, column: first.column })) };
    expect(decideLiveShape('arithmetic', 'rs', merged, ref, knownIssues).ok).toBe(false);
  });

  it('accepts a live map whose signature equals its pin (if-else/rs)', () => {
    expect(decideLiveShape('if-else', 'rs', golden('if-else', 'rs'), golden('if-else', 'ts'), knownIssues).ok).toBe(true);
  });

  it('fails closed when no live reference is available for a non-ts tier', () => {
    const r = decideLiveShape('arithmetic', 'go', golden('arithmetic', 'go'), null, knownIssues);
    expect(r.ok).toBe(false);
    expect(r.reason).toContain('reference');
  });
});
