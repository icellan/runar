import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { REPO, buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-120 — a `FixedArray<T, N>` size written with a radix prefix is refused by
 * every tier, with the TS reference's diagnostic.
 *
 * The reference (01-parse.ts) reads the size with `parseInt(text, 10)`, which
 * stops at the `x` / `o` / `b` of a `0x` / `0o` / `0b` prefix and yields 0, so
 * it refuses with `FixedArray size must be a positive integer literal, got
 * '<text>'`. Go refused too, in other words; Rust, Python, Zig, Ruby and Java
 * read `0x2` / `0b10` / `0o2` as the integer 2 and compiled the contract.
 *
 * What this proves:
 *   - every tier refuses `FixedArray<bigint, N>` for N in 0x2, 0X2, 0b10, 0o2
 *     (two as gate fixtures N272/N273, two written to a temp dir), and its
 *     diagnostic contains the reference message with the size as written;
 *   - every tier still ACCEPTS the same contract with a decimal `2`, so the
 *     refusal is the radix prefix and not FixedArray properties in general;
 *   - every tier is present (a missing toolchain fails, it is not skipped).
 * What it does NOT prove:
 *   - the location of the diagnostic: Go reports this parse error with no
 *     file:line:col, and the others with differing prefixes;
 *   - any other size spelling. `2n` and `1_0` still diverge across tiers
 *     (reported separately, not this item's rule);
 *   - FixedArray sizes on any surface other than `.runar.ts`.
 */

const TIERS = buildSourceTiers();
const DIR = join(REPO, 'conformance/negatives');

const message = (size: string): string =>
  `FixedArray size must be a positive integer literal, got '${size}'`;

const contract = (size: string): string => `import { SmartContract, assert, FixedArray } from 'runar-lang';

class FixedArraySizeRadix extends SmartContract {
  readonly a: FixedArray<bigint, ${size}> = [1n, 2n];

  constructor() {
    super();
  }

  public unlock(x: bigint) {
    assert(x === this.a[0] + this.a[1]);
  }
}
`;

const tmp = mkdtempSync(join(tmpdir(), 'n120-'));
function tempContract(size: string): string {
  const path = join(tmp, `Size_${size}.runar.ts`);
  writeFileSync(path, contract(size));
  return path;
}

/** [path, size as written]. */
const REFUSED: Array<[string, string]> = [
  [join(DIR, 'N272-ts-fixedarray-size-hex.runar.ts'), '0x2'],
  [join(DIR, 'N273-ts-fixedarray-size-binary.runar.ts'), '0b10'],
  [tempContract('0X2'), '0X2'],
  [tempContract('0o2'), '0o2'],
];

const escape = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

describe('N-120: every tier refuses a radix-prefixed FixedArray size with one diagnostic', () => {
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

  it('the same contract with a decimal size compiles in every tier', () => {
    const src = tempContract('2');
    const got: Record<string, string> = {};
    for (const tier of TIERS) {
      const r = judge(tier, src);
      got[tier.id] = r.verdict === 'accepted' ? 'accepted' : `rejected: ${r.diag.trim().slice(0, 200)}`;
    }
    expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'accepted'])));
  }, 900_000);
});
