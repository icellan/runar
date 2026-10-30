import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { REPO, buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-300 — a `//runar:sighash` directive above a package-level `func init()`
 * or `func main()` in `.runar.go`. N-018 made a free init/main a dropped
 * package-level function in all seven tiers, so the directive attaches to no
 * spending entry point and every tier refuses it. Before this item Go and
 * Rust reported it as "lost" (`@sighash directive is not attached to any
 * method ...`) while TypeScript and Java reported it as sitting on a
 * "non-public method"; the three other tiers differed again.
 *
 * Decision: TypeScript is the reference. Its wording (`@sighash directive on
 * non-public method 'init' has no effect — only public methods are spending
 * entry points`) is also the more useful one here: the "lost" text tells the
 * author to move the comment "directly above the method it annotates", which
 * the author already did.
 *
 * What this proves:
 *   - for a directive above a free init, a free main and a private contract
 *     method, every tier rejects with the TS non-public diagnostic naming the
 *     func, so the diagnostic is the same in all seven tiers;
 *   - the same directive above a public method is accepted by every tier
 *     (the control, so the refusal is the directive rule and not the fixture);
 *   - every tier is present (a missing toolchain fails, it is not skipped).
 * What it does NOT prove:
 *   - anything about the other eight surfaces, or the position/column of the
 *     diagnostic (the CLIs expose only the verdict and message text);
 *   - that a free helper func (neither init nor main) is handled the same way:
 *     that path was already agreed (it is kept as a private method).
 */

const TIERS = buildSourceTiers();
const DIR = join(REPO, 'conformance/negatives');

const nonPublic = (name: string): string =>
  `@sighash directive on non-public method '${name}' has no effect — only public methods are spending entry points`;

const REJECTED: ReadonlyArray<readonly [string, string]> = [
  ['N300-go-sighash-free-init.runar.go', 'init'],
  ['N300-go-sighash-free-main.runar.go', 'main'],
  ['N300-go-sighash-private-method.runar.go', 'helper'],
];

describe('N-300: every tier gives one diagnostic for a //runar:sighash that is not on a public method', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const [fixture, func] of REJECTED) {
    it(`${fixture} -> ${nonPublic(func).slice(0, 70)}...`, () => {
      const got: Record<string, string> = {};
      for (const tier of TIERS) {
        const r = judge(tier, join(DIR, fixture));
        got[tier.id] =
          r.verdict === 'rejected' && r.diag.includes(nonPublic(func))
            ? 'shared diagnostic'
            : `${r.verdict}: ${r.diag.trim().slice(0, 300)}`;
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'shared diagnostic'])));
    }, 900_000);
  }

  it('N300-go-sighash-public-method.runar.go (the control) is accepted by every tier', () => {
    const got: Record<string, string> = {};
    for (const tier of TIERS) {
      const r = judge(tier, join(DIR, 'N300-go-sighash-public-method.runar.go'));
      got[tier.id] = r.verdict === 'accepted' ? 'accepted' : `rejected: ${r.diag.trim().slice(0, 300)}`;
    }
    expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'accepted'])));
  }, 900_000);
});
