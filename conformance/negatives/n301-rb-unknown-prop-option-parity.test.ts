import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { REPO, buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-301 — an unknown keyword option on a `.runar.rb` `prop` declaration is
 * refused by every tier with one shared diagnostic.
 *
 * Before the fix all seven Ruby-surface parsers read the options after the
 * type in a loop that recognised `readonly:`, `embed_always:` and `default:`
 * and silently dropped everything else, so `prop :x, ByteString,
 * embed_alwyas: true` compiled WITHOUT the embed-always behaviour the author
 * asked for.
 *
 * What this proves:
 *   - for the typo and for an unknown option after a valid one (gate fixtures
 *     N282/N283), every tier rejects and its diagnostic contains
 *     `unknown prop option '<name>'`;
 *   - the same contract with the correct spelling `embed_always: true`
 *     (and with `readonly: true` / `default:`) is still ACCEPTED by every
 *     tier, so the refusal is the unknown key and not prop options in general;
 *   - every tier is present (a missing toolchain fails, it is not skipped).
 * What it does NOT prove:
 *   - anything about malformed VALUES of a known option (`readonly: maybe`),
 *     which is a separate defect;
 *   - the diagnostic's location, which differs per tier;
 *   - other surfaces' property syntax.
 */

const TIERS = buildSourceTiers();
const DIR = join(REPO, 'conformance/negatives');

const contract = (opts: string): string => `require 'runar'

class PropOpt < Runar::SmartContract
  prop :pub_key_hash, Addr
  prop :tag, ByteString${opts}

  def initialize(pub_key_hash, tag)
    super(pub_key_hash, tag)
    @pub_key_hash = pub_key_hash
    @tag = tag
  end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end
end
`;

const tmp = mkdtempSync(join(tmpdir(), 'n301-'));
function tempContract(name: string, opts: string): string {
  const path = join(tmp, `${name}.runar.rb`);
  writeFileSync(path, contract(opts));
  return path;
}

/** [path, option name as written]. */
const REFUSED: Array<[string, string]> = [
  [join(DIR, 'N282-rb-unknown-prop-option-typo.runar.rb'), 'embed_alwyas'],
  [join(DIR, 'N283-rb-unknown-prop-option-after-valid.runar.rb'), 'colour'],
  [tempContract('Bare', ', bogus: true'), 'bogus'],
];

const ACCEPTED: Array<[string, string]> = [
  ['embed_always', ', embed_always: true'],
  ['readonly', ', readonly: true'],
  ['embed_always-and-readonly', ', readonly: true, embed_always: true'],
];

describe('N-301: every tier refuses an unknown .runar.rb prop option with one diagnostic', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const [path, name] of REFUSED) {
    it(`prop option '${name}' -> unknown prop option`, () => {
      const needle = `unknown prop option '${name}'`;
      const got: Record<string, string> = {};
      for (const tier of TIERS) {
        const r = judge(tier, path);
        got[tier.id] =
          r.verdict === 'rejected' && r.diag.includes(needle)
            ? 'shared diagnostic'
            : `${r.verdict}: ${r.diag.trim().slice(0, 200)}`;
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'shared diagnostic'])));
    }, 900_000);
  }

  for (const [label, opts] of ACCEPTED) {
    it(`known options (${label}) still compile in every tier`, () => {
      const src = tempContract(`Ok_${label}`, opts);
      const got: Record<string, string> = {};
      for (const tier of TIERS) {
        const r = judge(tier, src);
        got[tier.id] = r.verdict === 'accepted' ? 'accepted' : `rejected: ${r.diag.trim().slice(0, 200)}`;
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'accepted'])));
    }, 900_000);
  }
});
