import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { REPO, buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-319 — a `.runar.rb` class with no closing `end` is refused by every tier
 * with one shared diagnostic.
 *
 * Before the fix all seven Ruby-surface parsers ended the class body with a
 * silent optional match on `end`, so a file truncated after the last method
 * parsed with zero diagnostics.
 *
 * What this proves:
 *   - for the gate fixture N284 and for a class whose last METHOD lacks its
 *     `end` (so the method swallows the class `end`), every tier
 *     rejects and its diagnostic contains `missing closing 'end'`;
 *   - the same contract with its `end` restored is still ACCEPTED by every
 *     tier, so the refusal is the missing `end` and not the contract;
 *   - every tier is present (a missing toolchain fails, it is not skipped).
 * What it does NOT prove:
 *   - the diagnostic's location, which differs per tier;
 *   - other surfaces' unterminated-block handling.
 */

const TIERS = buildSourceTiers();
const DIR = join(REPO, 'conformance/negatives');

const contract = (tail: string): string => `require 'runar'

class P2PKH < Runar::SmartContract
  prop :pub_key_hash, Addr

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
${tail}`;

const tmp = mkdtempSync(join(tmpdir(), 'n319-'));
function tempContract(name: string, tail: string): string {
  const path = join(tmp, `${name}.runar.rb`);
  writeFileSync(path, contract(tail));
  return path;
}

const NEEDLE = "missing closing 'end'";
const REFUSED: Array<[string, string]> = [
  ['N284 fixture', join(DIR, 'N284-rb-unterminated-class.runar.rb')],
  ['method end swallows class end', tempContract('SwallowedEnd', 'end\n')],
  ['neither end', tempContract('NoEnds', '')],
];

describe("N-319: every tier refuses a .runar.rb class missing its closing 'end'", () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const [label, path] of REFUSED) {
    it(`${label} -> missing closing 'end'`, () => {
      const got: Record<string, string> = {};
      for (const tier of TIERS) {
        const r = judge(tier, path);
        got[tier.id] =
          r.verdict === 'rejected' && r.diag.includes(NEEDLE)
            ? 'shared diagnostic'
            : `${r.verdict}: ${r.diag.trim().slice(0, 200)}`;
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'shared diagnostic'])));
    }, 900_000);
  }

  it('the terminated contract still compiles in every tier', () => {
    const src = tempContract('Ok', '  end\nend\n');
    const got: Record<string, string> = {};
    for (const tier of TIERS) {
      const r = judge(tier, src);
      got[tier.id] = r.verdict === 'accepted' ? 'accepted' : `rejected: ${r.diag.trim().slice(0, 200)}`;
    }
    expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'accepted'])));
  }, 900_000);
});
