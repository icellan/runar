/**
 * R-097 — `docs/compiler-architecture.md` described a FIVE-tier project.
 *
 * Four codegen families (SLH-DSA, EC, SHA-256, BLAKE3) each listed "all five
 * maintained compilers" and named TypeScript, Go, Rust, Python and Zig. Ruby
 * and Java ship the same four families and were absent from every list — and
 * the closing summary said each compiler "supports a different slice of the
 * source-format matrix", which the universal nine-format parser layer has not
 * been true of for a long time.
 *
 * A stale architecture guide is not cosmetic here: these four families are
 * exactly the ones CLAUDE.md says MUST ship in all seven tiers (as opposed to
 * the Go-only EVM/STARK primitives), so a reader checking whether a tier owes
 * an implementation gets the wrong answer from the document that exists to
 * answer it.
 *
 * This test keeps the lists honest in both directions: every family must name a
 * path for every one of the seven tiers, and every path it names must exist on
 * disk. A tier added later fails here until the guide learns about it; a file
 * moved later fails here until the guide is updated.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';

const REPO = resolve(__dirname, '../../..');
const DOC = 'docs/compiler-architecture.md';

const TIERS = ['TypeScript', 'Go', 'Rust', 'Python', 'Zig', 'Ruby', 'Java'] as const;

/** The four codegen families the guide enumerates per tier. */
const FAMILIES = [
  'The SLH-DSA codegen is replicated across all seven maintained compilers:',
  'The EC codegen is replicated across all seven maintained compilers:',
  'The SHA-256 codegen is replicated across all seven maintained compilers:',
  'The BLAKE3 codegen is replicated across all seven maintained compilers:',
];

const text = readFileSync(join(REPO, DOC), 'utf-8');

/** The bullet block that follows a family heading, up to the first blank line. */
function blockAfter(heading: string): string[] | null {
  const at = text.indexOf(heading);
  if (at < 0) return null;
  const rest = text.slice(at + heading.length).split('\n');
  const out: string[] = [];
  for (const line of rest) {
    if (line.trim() === '') {
      if (out.length > 0) break;
      continue;
    }
    if (!line.startsWith('-')) break;
    out.push(line);
  }
  return out;
}

describe('R-097: the architecture guide describes seven tiers', () => {
  it('the document exists and is non-trivial', () => {
    expect(existsSync(join(REPO, DOC))).toBe(true);
    expect(text.length).toBeGreaterThan(1000);
  });

  it('no "five maintained compilers" claim survives', () => {
    const hits = text
      .split('\n')
      .map((line, i) => ({ line, n: i + 1 }))
      .filter(({ line }) => /\b(all )?five (maintained )?compilers\b|\bAll five produce\b/i.test(line))
      .map((h) => `${DOC}:${h.n}`);
    expect(hits, `the project has seven compilers, not five`).toEqual([]);
  });

  for (const heading of FAMILIES) {
    const family = heading.split(' codegen')[0]!.replace('The ', '');

    it(`${family}: every one of the seven tiers is listed, with a path that exists`, () => {
      const block = blockAfter(heading);
      expect(block, `heading not found verbatim in ${DOC}: "${heading}"`).not.toBeNull();

      const missingTiers = TIERS.filter(
        (t) => !block!.some((line) => line.includes(`${t}:`)),
      );
      expect(missingTiers, `${family} codegen list omits: ${missingTiers.join(', ')}`).toEqual([]);

      const badPaths: string[] = [];
      for (const line of block!) {
        const m = line.match(/`([^`]+)`/);
        if (!m) {
          badPaths.push(`no backticked path in: ${line.trim()}`);
          continue;
        }
        if (!existsSync(join(REPO, m[1]!))) badPaths.push(`does not exist: ${m[1]}`);
      }
      expect(badPaths, `${family} codegen list has stale entries`).toEqual([]);
    });
  }
});
