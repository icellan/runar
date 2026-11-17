/**
 * GK-GAP-011: three cross-compiler describes (mutable Rabin state, terminal
 * read with a var-length sibling, mixed add/sub chain) looped over the six
 * peer tiers with `if (tier.skip) continue` inside a single `it`. A missing
 * tier was silently dropped: the `it` still reported PASSED after comparing
 * TS with itself, and nothing reached the skip count. Measured locally with
 * Rust/Zig/Ruby/Java absent: "4 passed | 468 skipped" for the Rabin describe,
 * with the four absent tiers invisible.
 *
 * Proves: no per-tier comparison in cross-compiler.test.ts is hidden behind a
 * `continue`; each is its own skip-aware case, so an absent tier shows
 * up as SKIPPED. Does not prove: that the tiers agree (the cases do that).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const SRC = readFileSync(join(__dirname, 'cross-compiler.test.ts'), 'utf8');

describe('GK-GAP-011: cross-compiler tier skips are visible', () => {
  it('no comparison loop silently continues past a missing tier', () => {
    const hits = SRC.split('\n')
      .map((l, i) => ({ l, n: i + 1 }))
      .filter(({ l }) => /if \(tier\.skip\) continue/.test(l))
      .map(({ n }) => `cross-compiler.test.ts:${n}`);
    expect(hits).toEqual([]);
  });

  it('the three tier tables each drive one skip-aware case per tier', () => {
    for (const table of ['RABIN_STATE_TIERS', 'STALE_STATE_TIERS', 'REASSOC_TIERS']) {
      expect(SRC, table).toMatch(new RegExp(`for \\(const tier of ${table}\\)[\\s\\S]{0,200}?it\\.skipIf\\(tier\\.skip\\)`));
    }
  });
});
