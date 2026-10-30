import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { ALL_TIER_IDS, Tier, buildSourceTiers, verdict } from './tier-harness.js';

/**
 * N-415 — one definition of `--parse-only` across the seven tiers.
 *
 * The documented contract (conformance/README.md "all-tier parser-only
 * coverage", runner.ts `runAllParserOnlyChecks`, Go `ParseAndValidateOnly`) is
 * that `--parse-only` runs Pass 1 (parse) AND Pass 2 (validate). The six native
 * CLIs did; the TS CLI stopped after Pass 1, so it ACCEPTED
 * N227-rb-rabin-pubkey-param and N93-rb-index-assign-bytestring-prop — both are
 * refused by the validator, not the parser — while the other six refused them.
 *
 * Proves: for these two validator-refused fixtures, every available tier's
 * `--parse-only` entry point refuses, and each tier ACCEPTS a valid contract
 * under the same flag (so a refusal is not a mis-driven CLI).
 * Does not prove: that `--parse-only` agrees on every negative (typecheck-stage
 * refusals are deliberately invisible to it), nor that the diagnostics match.
 */

/** Same CLIs as the source->hex matrix, re-pointed at `--parse-only`. */
const TIERS: Tier[] = buildSourceTiers().map((t) => ({
  ...t,
  argsFor: (s: string) => (t.id === 'ts' ? [s, '--parse-only'] : ['--source', s, '--parse-only']),
}));
const available = TIERS.filter((t) => t.cmd !== null);

const DIR = __dirname;
const FIXTURES = [
  'N227-rb-rabin-pubkey-param.runar.rb',
  'N93-rb-index-assign-bytestring-prop.runar.rb',
];
const POSITIVE_CONTROL = join(DIR, 'positive-control.runar.ts');

describe('N-415: --parse-only agrees across tiers on validator-refused programs', () => {
  it('the matrix names all seven tiers', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...ALL_TIER_IDS]);
  });

  for (const tier of available) {
    it(`${tier.id} --parse-only accepts the positive control`, () => {
      expect(verdict(tier, POSITIVE_CONTROL)).toBe('accepted');
    });
    for (const fixture of FIXTURES) {
      it(`${tier.id} --parse-only rejects ${fixture}`, () => {
        expect(
          verdict(tier, join(DIR, fixture)),
          `${tier.id} --parse-only ACCEPTED ${fixture}; the validator (Pass 2) must run under --parse-only`,
        ).toBe('rejected');
      });
    }
  }
});
