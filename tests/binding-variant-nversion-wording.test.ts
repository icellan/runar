/**
 * `@bindingVariant all` is spendable only when the spending transaction's
 * nVersion is greater than 1: that is the condition under which `@bsv/sdk`'s
 * `Spend` (and the node's post-Chronicle policy) relaxes LOW_S and the
 * minimal-number rules. nVersion is a signed 32-bit field, so "!= 1" also
 * admits 0 and negative versions, which are NOT relaxed. Comments across all
 * seven tiers said "!= 1"; this guard keeps the wrong condition from coming
 * back.
 */

import { describe, it, expect } from 'vitest';
import { execSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

describe('@bindingVariant all: nVersion condition wording', () => {
  it('no tracked source says "nVersion != 1"', () => {
    const out = execSync(
      `git grep -n -E 'nVersion ?!= ?1' -- ':!runar-verification' ':!tests/binding-variant-nversion-wording.test.ts' || true`,
      { cwd: ROOT, encoding: 'utf-8' },
    );
    expect(out.trim().split('\n').filter(Boolean), 'the condition is nVersion > 1').toEqual([]);
  });
});
