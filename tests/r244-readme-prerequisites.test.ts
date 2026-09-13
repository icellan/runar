/**
 * R-244 (GK-DOC-004): the README's Development prerequisites listed Node, pnpm,
 * Go, Rust, Ruby and Python — and not Zig or Java.
 *
 * Both ship a compiler under compilers/ and an example tree, both are part of
 * the seven-tier claim the README makes higher up, and neither was mentioned in
 * the list of things you need installed. Someone following the README cannot
 * run `pnpm test` to completion.
 *
 * This test derives the expected set from the repository rather than from a
 * second hand-written list: every directory under compilers/ is a tier, and
 * every tier must be named in the prerequisites.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** How each compilers/<dir> is spelled in prose. */
const TIER_WORDS: Record<string, string> = {
  go: 'Go',
  rust: 'Rust',
  python: 'Python',
  zig: 'Zig',
  ruby: 'Ruby',
  java: 'Java',
};

describe('R-244: the README prerequisites cover every tier', () => {
  it('names each compilers/<tier> toolchain', () => {
    const tiers = readdirSync(join(ROOT, 'compilers')).filter((d) =>
      statSync(join(ROOT, 'compilers', d)).isDirectory(),
    );
    expect(tiers.length, 'no compiler directories found — the scan broke').toBeGreaterThan(4);

    const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');
    const start = readme.indexOf('### Prerequisites');
    expect(start, 'the Prerequisites heading has moved').toBeGreaterThan(0);
    const section = readme.slice(start, readme.indexOf('###', start + 3));

    const missing = tiers
      .map((t) => TIER_WORDS[t] ?? t)
      .filter((word) => !section.includes(`**${word}**`));

    expect(
      missing,
      'these tiers ship a compiler but are not listed as a prerequisite; ' +
        'someone following the README cannot run the full suite',
    ).toEqual([]);
  });
});
