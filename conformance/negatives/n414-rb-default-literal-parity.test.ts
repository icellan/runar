import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex, judge } from './tier-harness.js';

/**
 * N-414 — a `.runar.rb` `prop ... default:` value that is not a well-formed
 * Rúnar literal is refused by every tier with one shared diagnostic.
 *
 * Before the fix:
 *   - `default: nil` was accepted by all seven tiers and compiled as the
 *     bigint 0 (the Ruby expression parser maps `nil` to a bigint literal),
 *     although CLAUDE.md "Property initializers" limits initializers to
 *     BigIntLiteral, BoolLiteral and ByteStringLiteral and docs/formats/ruby.md
 *     never mentions `nil`;
 *   - an odd-length hex ByteString default (`default: 'abc'`, `default: "x"`)
 *     was refused by TypeScript and Rust but accepted by Go, Python, Zig, Ruby
 *     and Java (spec/grammar.md: a ByteString literal is an even number of hex
 *     digits).
 *
 * What this proves:
 *   - for each REFUSED declaration, every tier rejects and its diagnostic
 *     contains the shared needle (`prop default 'nil' is not a literal ...`
 *     or `ByteString literal '<v>' has odd length (<n>)`);
 *   - the well-formed controls (numbers, booleans, even-length hex in both
 *     quote styles) still compile, and all seven tiers emit byte-identical
 *     hex for each of them;
 *   - every tier is present (a missing toolchain fails, it is not skipped).
 * What it does NOT prove:
 *   - the diagnostic's line:col, which each tier formats its own way;
 *   - `nil` in a METHOD BODY (still read as 0 by the expression parser) or
 *     non-hex even-length ByteString text; both are left as they are;
 *   - other surfaces' (non-.rb) literal checks.
 */

const TIERS = buildSourceTiers();

// The property is read against a method argument so its initializer value
// reaches the emitted script: a hex match compares the default's bytes.
function useOf(propLine: string): string {
  if (propLine.includes(':flag,')) return 'assert @flag != (len(pub_key) == 33)';
  if (propLine.includes(':tag,')) return 'assert @tag != pub_key';
  return 'assert @n != len(pub_key)';
}

const contract = (propLine: string): string => `require 'runar'

class PropDefault < Runar::SmartContract
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

const tmp = mkdtempSync(join(tmpdir(), 'n414-'));
let seq = 0;
function tempContract(propLine: string): string {
  const path = join(tmp, `C${seq++}.runar.rb`);
  writeFileSync(path, contract(propLine));
  return path;
}

const NIL = "prop default 'nil' is not a literal";

// [prop declaration, needle every tier's diagnostic must contain]
const REFUSED: Array<[string, string]> = [
  ['prop :n, Bigint, default: nil', NIL],
  ['prop :tag, ByteString, default: nil', NIL],
  ['prop :flag, Boolean, default: nil', NIL],
  ["prop :tag, ByteString, default: 'abc'", "ByteString literal 'abc' has odd length (3)"],
  ['prop :tag, ByteString, default: "abc"', "ByteString literal 'abc' has odd length (3)"],
  ['prop :tag, ByteString, default: "x"', "ByteString literal 'x' has odd length (1)"],
  ["prop :tag, ByteString, default: 'a'", "ByteString literal 'a' has odd length (1)"],
];

const ACCEPTED: string[] = [
  'prop :n, Bigint, default: 0',
  'prop :n, Bigint, default: 5',
  'prop :n, Bigint, default: -3',
  'prop :flag, Boolean, default: true',
  'prop :flag, Boolean, default: false',
  "prop :tag, ByteString, default: 'ab'",
  "prop :tag, ByteString, default: 'abcd'",
  'prop :tag, ByteString, default: "abcd"',
];

describe('N-414: every tier refuses a malformed .runar.rb prop default with one diagnostic', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const [decl, needle] of REFUSED) {
    it(`${decl} -> refused`, () => {
      const src = tempContract(decl);
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
      expect(Object.fromEntries(TIERS.map((t) => [t.id, hex[t.id] === ref]))).toEqual(
        Object.fromEntries(TIERS.map((t) => [t.id, true])),
      );
    }, 900_000);
  }
});
