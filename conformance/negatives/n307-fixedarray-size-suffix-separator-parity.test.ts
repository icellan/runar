import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { REPO, buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-307 — a `FixedArray<T, N>` size written with a bigint suffix (`2n`) or a
 * numeric separator (`1_0`) is refused by every tier, with the TS reference's
 * diagnostic. Sibling of n120-fixedarray-size-radix-parity.test.ts.
 *
 * Before: `2n` was accepted as size 2 by TS, Python, Zig, Ruby and Java and
 * refused (with other wording) by Go and Rust; `1_0` was read as 1 by TS
 * (parseInt stops at '_') and as 10 by the other tiers, so one source meant
 * two different array lengths. Rule (user decision R115): refuse both.
 *
 * What this proves:
 *   - every tier refuses `FixedArray<bigint, N>` for N in 2n, 1_0 (gate
 *     fixtures N280/N281) and 10n, 1_000 (temp files), and its diagnostic
 *     contains `FixedArray size must be a positive integer literal, got
 *     '<N as written>'`;
 *   - every tier still ACCEPTS the same contracts with decimal `2` / `10`,
 *     so the refusal is the spelling and not FixedArray properties in general;
 *   - every tier is present (a missing toolchain fails, it is not skipped).
 * What it does NOT prove:
 *   - diagnostic locations (they differ per tier);
 *   - other size spellings (`2.0`, `1e1`, leading zeros), which are not part
 *     of this rule;
 *   - FixedArray sizes on any surface other than `.runar.ts`.
 */

const TIERS = buildSourceTiers();
const DIR = join(REPO, 'conformance/negatives');

const message = (size: string): string =>
  `FixedArray size must be a positive integer literal, got '${size}'`;

const two = (size: string): string => `import { SmartContract, assert, FixedArray } from 'runar-lang';

class FixedArraySizeSuffix extends SmartContract {
  readonly a: FixedArray<bigint, ${size}> = [1n, 2n];

  constructor() {
    super();
  }

  public unlock(x: bigint) {
    assert(x === this.a[0] + this.a[1]);
  }
}
`;

const ten = (size: string): string => `import { SmartContract, assert, FixedArray } from 'runar-lang';

class FixedArraySizeSeparator extends SmartContract {
  readonly a: FixedArray<bigint, ${size}> = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n];

  constructor() {
    super();
  }

  public unlock(x: bigint) {
    assert(x === this.a[0] + this.a[9]);
  }
}
`;

const tmp = mkdtempSync(join(tmpdir(), 'n307-'));
function tempContract(size: string, body: (s: string) => string): string {
  const path = join(tmp, `Size_${size}.runar.ts`);
  writeFileSync(path, body(size));
  return path;
}

/** [path, size as written]. */
const REFUSED: Array<[string, string]> = [
  [join(DIR, 'N280-ts-fixedarray-size-bigint-suffix.runar.ts'), '2n'],
  [join(DIR, 'N281-ts-fixedarray-size-separator.runar.ts'), '1_0'],
  [tempContract('10n', ten), '10n'],
  [tempContract('1_000', two), '1_000'],
];

const escape = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

describe('N-307: every tier refuses a bigint-suffixed or separator FixedArray size with one diagnostic', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  it('the gate fixtures spell the size they are checked against', () => {
    for (const [path, size] of REFUSED) {
      expect(readFileSync(path, 'utf8')).toContain(`FixedArray<bigint, ${size}>`);
    }
  });

  for (const [path, size] of REFUSED) {
    it(`FixedArray<bigint, ${size}> -> ${message(size)}`, () => {
      const re = new RegExp(escape(message(size)));
      const got: Record<string, string> = {};
      for (const tier of TIERS) {
        const r = judge(tier, path);
        got[tier.id] =
          r.verdict === 'rejected' && re.test(r.diag)
            ? 'shared diagnostic'
            : `${r.verdict}: ${r.diag.trim().slice(0, 200)}`;
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'shared diagnostic'])));
    }, 900_000);
  }

  for (const [size, body] of [['2', two], ['10', ten]] as const) {
    it(`the same contract with decimal size ${size} compiles in every tier`, () => {
      const src = tempContract(size, body);
      const got: Record<string, string> = {};
      for (const tier of TIERS) {
        const r = judge(tier, src);
        got[tier.id] = r.verdict === 'accepted' ? 'accepted' : `rejected: ${r.diag.trim().slice(0, 200)}`;
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'accepted'])));
    }, 900_000);
  }
});
