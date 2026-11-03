import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex, judge } from './tier-harness.js';

/**
 * N-413 — a token left over after a `.runar.rb` `prop` type or option value
 * is refused by every tier with one shared diagnostic.
 *
 * Before the fix all seven Ruby-surface parsers read `default:` as ONE unary
 * expression and then skipped the rest of the line, so `default: 1 + 2`
 * silently became 1 and `default: '00' * 33` (a PubKey) silently became the
 * one byte `'00'`. The same skip swallowed anything after a valid boolean
 * option (`readonly: true false`), after an option missing its comma, or
 * directly after the type (`prop :n, Bigint junk`).
 * Property initializers are literal-only (CLAUDE.md "Property
 * initializers"), so the fix refuses the leftover token rather than
 * evaluating an expression.
 *
 * What this proves:
 *   - for each REFUSED declaration, every tier rejects and its diagnostic
 *     contains `unexpected '<tok>' in prop declaration (expected ',' or end
 *     of line)` naming the first leftover token;
 *   - the well-formed controls (a literal default alone, with readonly:,
 *     in either order, a negative default, a 33-byte ByteString literal)
 *     still compile, and all seven tiers emit byte-identical hex for each;
 *   - every tier is present (a missing toolchain fails, it is not skipped).
 * What it does NOT prove:
 *   - the diagnostic's line:col, which each tier formats its own way (the
 *     leftover token's position is what every tier reports, checked by hand);
 *   - that a literal `default:` has the right TYPE for its property (the
 *     typechecker's job, N-414);
 *   - other surfaces' property syntax.
 */

const TIERS = buildSourceTiers();

// Each property is read against a method argument so its initializer value
// reaches the emitted script (and cannot be folded away): a hex match then
// compares the default's bytes, not just the P2PKH skeleton.
function useOf(propLine: string): string {
  if (propLine.includes(':pk,')) return 'assert @pk != pub_key';
  if (propLine.includes(':arr,')) return 'assert @arr[0] + @arr[1] != len(pub_key)';
  return 'assert @n != len(pub_key)';
}

const contract = (propLine: string): string => `require 'runar'

class PropTail < Runar::SmartContract
  prop :pub_key_hash, Addr
  ${propLine}

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
    ${useOf(propLine)}
  end
end
`;

const tmp = mkdtempSync(join(tmpdir(), 'n413-'));
let seq = 0;
function tempContract(propLine: string): string {
  const path = join(tmp, `C${seq++}.runar.rb`);
  writeFileSync(path, contract(propLine));
  return path;
}

const PK33 = '00'.repeat(33);

// [prop declaration, first leftover token as every tier quotes it]
const REFUSED: Array<[string, string]> = [
  ['prop :n, Bigint, default: 1 + 2', '+'],
  ["prop :pk, PubKey, default: '00' * 33", '*'],
  ['prop :n, Bigint, readonly: true false', 'false'],
  ['prop :n, Bigint, embed_always: false true, default: 3', 'true'],
  ['prop :n, Bigint, default: 3 readonly: true', 'readonly'],
  ['prop :n, Bigint, default: -3 4', '4'],
  ['prop :n, Bigint junk', 'junk'],
];

const ACCEPTED: string[] = [
  'prop :n, Bigint, default: 3',
  'prop :n, Bigint, default: -3',
  'prop :n, Bigint, readonly: true, default: 3',
  'prop :n, Bigint, default: 3, readonly: true',
  `prop :pk, PubKey, default: '${PK33}'`,
  'prop :n, Bigint, embed_always: false, default: 3',
  'prop :n, Bigint, default: 3 # trailing comment',
  'prop :arr, FixedArray[Bigint, 2], default: [1, 2]',
];

describe('N-413: every tier refuses tokens left over after a .runar.rb prop option value', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const [decl, tok] of REFUSED) {
    it(`${decl} -> unexpected '${tok}'`, () => {
      const src = tempContract(decl);
      const needle = `unexpected '${tok}' in prop declaration (expected ',' or end of line)`;
      const got: Record<string, string> = {};
      for (const tier of TIERS) {
        const r = judge(tier, src);
        got[tier.id] =
          r.verdict === 'rejected' && r.diag.includes(needle)
            ? 'shared diagnostic'
            : `${r.verdict}: ${r.diag.trim().slice(0, 200)}`;
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'shared diagnostic'])));
    }, 900_000);
  }

  for (const decl of ACCEPTED) {
    it(`well-formed (${decl}) compiles to identical hex in every tier`, () => {
      const src = tempContract(decl);
      const hex: Record<string, string> = {};
      for (const tier of TIERS) hex[tier.id] = compileHex(tier, src);
      const ref = hex['ts'];
      expect(ref.length).toBeGreaterThan('76a90088ac'.length);
      expect(Object.fromEntries(TIERS.map((t) => [t.id, hex[t.id] === ref]))).toEqual(
        Object.fromEntries(TIERS.map((t) => [t.id, true])),
      );
    }, 900_000);
  }
});
