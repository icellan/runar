import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { resolve, join } from 'node:path';

/**
 * R-199 / CL-DOC-020 — examples/README.md was severely stale.
 *
 * It claimed "a 21-contract set" and "a 16-contract sol/move subset", and left
 * `ruby/` and `java/` out of the format list and the testing sections
 * entirely. Measured: 78–80 contract directories per tree, sol and move
 * included, and 76 `.runar.java` sources under the Gradle layout.
 *
 * A count in prose goes stale the week after it is written, so this test pins
 * the two things that matter and can be checked mechanically: the README must
 * not assert a small fixed catalogue size, and every example tree must have a
 * documented way to run it. The exact numbers in the table are allowed to age;
 * a claim that contradicts the directory by an order of magnitude is not.
 */

const REPO = resolve(__dirname, '..');
const README = resolve(REPO, 'examples/README.md');

function contractDirs(tree: string): number {
  const base = resolve(REPO, 'examples', tree);
  if (!existsSync(base)) return 0;
  return readdirSync(base).filter((e) => {
    const p = join(base, e);
    return statSync(p).isDirectory() && readdirSync(p).some((f) => /\.runar\./.test(f));
  }).length;
}

describe('R-199 examples/README reflects the catalogue', () => {
  it('the trees are big (an empty sweep would pass vacuously)', () => {
    expect(contractDirs('ts')).toBeGreaterThan(50);
    expect(contractDirs('sol')).toBeGreaterThan(50);
    expect(contractDirs('move')).toBeGreaterThan(50);
  });

  it('does not claim a 21-contract catalogue or a 16-contract sol/move subset', () => {
    const text = readFileSync(README, 'utf-8');
    const claims = text
      .split('\n')
      .map((line, n) => ({ line, n: n + 1 }))
      .filter(({ line }) => /\b21[- ]contract\b|\b16[- ]contract\b/.test(line))
      // The corrected text names the old claims to say they were wrong.
      .filter(({ line }) => !/R-199|previously claimed|NOT a 16-contract/.test(line));
    expect(
      claims.map((c) => `examples/README.md:${c.n}`),
      'examples/README.md still states a fixed small catalogue size; the trees hold ' +
        `${contractDirs('ts')} (ts) and ${contractDirs('sol')} (sol) contract directories.`,
    ).toEqual([]);
  });

  for (const [tree, marker] of [
    ['ruby', /###\s+Ruby/],
    ['java', /###\s+Java/],
    ['python', /###\s+Python/],
    ['zig', /###\s+Zig/],
    ['go', /###\s+Go/],
    ['rust', /###\s+Rust/],
  ] as const) {
    it(`documents how to run the ${tree} examples`, () => {
      expect(contractDirs(tree) > 0 || existsSync(resolve(REPO, 'examples', tree)), `examples/${tree} is gone`).toBe(true);
      const text = readFileSync(README, 'utf-8');
      expect(
        marker.test(text),
        `examples/${tree}/ exists but examples/README.md has no section telling anyone how to run it`,
      ).toBe(true);
    });
  }
});
