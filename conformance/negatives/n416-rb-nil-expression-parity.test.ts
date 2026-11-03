import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex, judge } from './tier-harness.js';

/**
 * N-416 — `nil` as an expression in a `.runar.rb` method body is refused by
 * every tier with one shared diagnostic.
 *
 * Before the fix every tier's Ruby expression parser mapped the `nil` token to
 * the bigint literal 0, so `x = nil`, `assert x == nil` and `nil` as a call
 * argument compiled silently as 0. `nil` is not a Rúnar value (CLAUDE.md:
 * BigInt, Bool and ByteString literals only; docs/formats/ruby.md never
 * mentions it; N-414 already refuses it in `default:`).
 *
 * What this proves:
 *   - for each REFUSED body, every tier rejects and its diagnostic contains
 *     the shared needle `'nil' is not a Rúnar value`;
 *   - the well-formed control (same shape, `0` in place of `nil`) still
 *     compiles, with byte-identical hex in all seven tiers;
 *   - every tier is present (a missing toolchain fails, it is not skipped).
 * What it does NOT prove:
 *   - the diagnostic's line:col, which each tier formats its own way;
 *   - `nil` inside prop `default:` (N-414's gate) or Ruby `.nil?` calls;
 *   - other surfaces' (non-.rb) null-like literals.
 */

const TIERS = buildSourceTiers();

const contract = (body: string): string => `require 'runar'

class NilUse < Runar::SmartContract
  prop :pub_key_hash, Addr

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
${body}
  end
end
`;

const tmp = mkdtempSync(join(tmpdir(), 'n416-'));
let seq = 0;
function tempContract(body: string): string {
  const path = join(tmp, `C${seq++}.runar.rb`);
  writeFileSync(path, contract(body));
  return path;
}

const NEEDLE = "'nil' is not a Rúnar value";

const REFUSED: Array<[string, string]> = [
  ['assignment', '    x = nil\n    assert x == 0'],
  ['comparison', '    assert len(pub_key) != nil'],
  ['call argument', '    assert max(len(pub_key), nil) == 33'],
  ['arithmetic', '    assert len(pub_key) + nil == 33'],
];

const ACCEPTED: Array<[string, string]> = [
  ['assignment', '    x = 0\n    assert x == 0'],
  ['comparison', '    assert len(pub_key) != 0'],
  ['call argument', '    assert max(len(pub_key), 0) == 33'],
];

describe('N-416: every tier refuses `nil` as a .runar.rb expression with one diagnostic', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const [name, body] of REFUSED) {
    it(`nil as ${name} -> refused`, () => {
      const src = tempContract(body);
      const got: Record<string, string> = {};
      for (const tier of TIERS) {
        const r = judge(tier, src);
        got[tier.id] =
          r.verdict === 'rejected' && r.diag.includes(NEEDLE)
            ? 'shared diagnostic'
            : `${r.verdict}: ${r.diag.trim().slice(0, 200)}`;
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'shared diagnostic'])));
    }, 900_000);
  }

  for (const [name, body] of ACCEPTED) {
    it(`well-formed control (${name}) compiles to identical hex in every tier`, () => {
      const src = tempContract(body);
      const hex: Record<string, string> = {};
      for (const tier of TIERS) hex[tier.id] = compileHex(tier, src);
      const ref = hex['ts'];
      expect(Object.fromEntries(TIERS.map((t) => [t.id, hex[t.id] === ref]))).toEqual(
        Object.fromEntries(TIERS.map((t) => [t.id, true])),
      );
    }, 900_000);
  }
});
