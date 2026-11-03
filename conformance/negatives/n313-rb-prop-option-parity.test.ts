import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex, judge } from './tier-harness.js';

/**
 * N-313 — a malformed VALUE of a known `.runar.rb` `prop` option is refused by
 * every tier with one shared diagnostic.
 *
 * Before the fix all seven Ruby-surface parsers read `readonly:` and
 * `embed_always:` with "if the next token is true/false take it, otherwise do
 * nothing", so `prop :x, Bigint, readonly: maybe` and `embed_always: 1`
 * compiled as if the option had never been written (N-301 closed the same
 * hole for unknown option NAMES).
 *
 * What this proves:
 *   - for each of `readonly:` and `embed_always:` with the values `maybe`,
 *     `1` and `0`, plus a value missing at end of line, every tier rejects and
 *     its diagnostic contains
 *     `invalid value '<v>' for prop option '<opt>' (expected true or false)`;
 *   - well-formed `true` / `false` values still compile, and all seven tiers
 *     emit byte-identical hex for each of them (so the refusal is the value,
 *     not the options in general);
 *   - every tier is present (a missing toolchain fails, it is not skipped).
 * What it does NOT prove:
 *   - the diagnostic's line:col, which each tier formats its own way (the
 *     value's position is what every tier reports, checked by hand);
 *   - `default:` values: a non-literal `default:` (an identifier, a call, an
 *     array for a scalar) is already refused downstream by the shared
 *     property-initializer rule, so no parse-time check was added; tokens
 *     after a literal `default:` value are still skipped (a separate defect);
 *   - other surfaces' property syntax.
 */

const TIERS = buildSourceTiers();

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

const tmp = mkdtempSync(join(tmpdir(), 'n313-'));
let seq = 0;
function tempContract(opts: string): string {
  const path = join(tmp, `C${seq++}.runar.rb`);
  writeFileSync(path, contract(opts));
  return path;
}

// [option, value as written, value as every tier quotes it]
const REFUSED: Array<[string, string, string]> = [];
for (const opt of ['readonly', 'embed_always']) {
  for (const v of ['maybe', '1', '0']) REFUSED.push([opt, v, v]);
  REFUSED.push([opt, '', '<end of line>']);
}

const ACCEPTED: string[] = [
  ', readonly: true',
  ', readonly: false',
  ', embed_always: true',
  ', embed_always: false',
  ', readonly: true, embed_always: true',
  ', readonly: false, embed_always: false',
];

describe('N-313: every tier refuses a malformed .runar.rb prop option value with one diagnostic', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const [opt, written, quoted] of REFUSED) {
    it(`${opt}: ${written || '<nothing>'} -> invalid value`, () => {
      const src = tempContract(`, ${opt}:${written === '' ? '' : ' ' + written}`);
      const needle = `invalid value '${quoted}' for prop option '${opt}' (expected true or false)`;
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

  for (const opts of ACCEPTED) {
    it(`well-formed (${opts.slice(2)}) compiles to identical hex in every tier`, () => {
      const src = tempContract(opts);
      const hex: Record<string, string> = {};
      for (const tier of TIERS) hex[tier.id] = compileHex(tier, src);
      const ref = hex['ts'];
      expect(Object.fromEntries(TIERS.map((t) => [t.id, hex[t.id] === ref]))).toEqual(
        Object.fromEntries(TIERS.map((t) => [t.id, true])),
      );
    }, 900_000);
  }
});
