/**
 * R-195 (CL-GAP-044 + GK-GAP-004): two example directories exist only under
 * `examples/ts/`, and nothing said why.
 *
 * The finding's wording for companion-verifier — "the single-tier status looks
 * deliberate, but undocumented" — is the whole problem: a reader could not tell
 * a deliberate exception from a forgotten port. This test does not decide which
 * examples may be TS-only; it requires that each one is NAMED in
 * examples/README.md, so the decision is written down where it is made.
 */

import { describe, it, expect } from 'vitest';
import { readdirSync, statSync, readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const EXAMPLES = join(ROOT, 'examples');

/** Peer trees that carry the same contract catalogue in their own surface. */
const PEER_TREES = ['go', 'rust', 'python', 'zig', 'ruby', 'sol', 'move'];
const JAVA_TREE = join(EXAMPLES, 'java', 'src', 'main', 'java', 'runar', 'examples');

function dirsIn(path: string): string[] {
  try {
    return readdirSync(path).filter((d) => {
      try { return statSync(join(path, d)).isDirectory(); } catch { return false; }
    });
  } catch {
    return [];
  }
}

function tsOnlyExamples(): string[] {
  const peers = new Map(PEER_TREES.map((t) => [t, new Set(dirsIn(join(EXAMPLES, t)))]));
  const java = new Set(dirsIn(JAVA_TREE));
  return dirsIn(join(EXAMPLES, 'ts'))
    .filter((d) => ![...peers.values()].some((s) => s.has(d)) && !java.has(d))
    .sort();
}

describe('R-195: every TypeScript-only example is documented as one', () => {
  it('is exactly the set examples/README.md accounts for', () => {
    const readme = readFileSync(join(EXAMPLES, 'README.md'), 'utf8');
    const undocumented = tsOnlyExamples().filter((d) => !readme.includes(`\`${d}/\``));

    expect(
      undocumented,
      'these examples exist only under examples/ts/ and are not explained in ' +
        'examples/README.md. Either port them to the peer trees, or add a row ' +
        'saying why they stay TS-only',
    ).toEqual([]);
  });

  it('still finds the known ones, so the detector is not vacuous', () => {
    // If this ever goes empty because the scan broke, the test above would
    // pass for the wrong reason.
    //
    // `compiler-directives` joined the set in R-209: `@embedAlways` and
    // `@sighash` are read on the `.runar.ts` surface only — the other eight
    // parsers reject a source carrying either — so unlike the other two its
    // TS-only status is permanent rather than pending a translation.
    expect(tsOnlyExamples()).toEqual([
      'companion-verifier',
      'compiler-directives',
      'nested-if-multi-reassign',
    ]);
  });
});
