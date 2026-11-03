import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex, judge } from './tier-harness.js';

/**
 * N-437: inside `runar.ByteString(...)` on the `.runar.go` surface, every tier
 * reads the argument with Go's string-literal rules
 * (https://go.dev/ref/spec#String_literals), because per user decision R169
 * the conversion is Go's `[]byte(s)`:
 *
 *   - an interpreted literal decodes `\a \b \f \n \r \t \v \\ \"`, `\xNN`,
 *     octal `\NNN` (at most 255), `\uNNNN` and `\UNNNNNNNN` (UTF-8 encoded);
 *   - an escape Go refuses (`\q`, `\'`, `\8`, `\400`, a short `\x`/`\u`, a
 *     surrogate or out-of-range `\u`/`\U`, `\0` without three digits) is a
 *     compile error, in every tier;
 *   - a backtick raw literal is its text verbatim as UTF-8, backslashes
 *     included, with carriage returns discarded.
 *
 * Before the fix `"\351"` pushed e9 in go but 333531 in ts/zig/ruby and
 * 5c333531 in python/rust/java; `"é"` pushed c3a9 in go and the text
 * "u00e9" or a raw backslash-u elsewhere; a backtick literal compiled in
 * go/rust and was refused by the other five; an invalid escape was refused
 * only by go.
 *
 * What this proves: for each literal below every available tier's `--hex` CLI
 * pushes exactly the bytes Go's own compiler gives the literal, all tiers emit
 * identical scripts, and each invalid escape is refused by every tier (the
 * non-Go tiers with the shared "invalid escape sequence" diagnostic). What it
 * does NOT prove: execution on a node (the pushed bytes are checked
 * structurally); a bare quoted literal outside `ByteString(...)` (those are
 * hex, N-429); a bare backtick literal outside `ByteString(...)`; ill-formed
 * UTF-8 in the source file itself.
 */

const contract = (name: string, lit: string) => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type ${name} struct {
	runar.SmartContract
	Expected runar.ByteString \`runar:"readonly"\`
}

func (c *${name}) Check() {
	runar.Assert(runar.ByteString(${lit}) == c.Expected)
}
`;

// `lit` is the Go source text of the argument; `bytes` the Go value's bytes, hex.
const ACCEPTED: Array<{ name: string; lit: string; bytes: string }> = [
  { name: 'Octal', lit: '"\\351"', bytes: 'e9' },
  { name: 'OctalPair', lit: '"\\101\\102"', bytes: '4142' },
  { name: 'OctalNul', lit: '"\\000\\377"', bytes: '00ff' },
  { name: 'UnicodeShort', lit: '"\\u00e9"', bytes: 'c3a9' },
  { name: 'UnicodeLong', lit: '"\\U0001F600"', bytes: 'f09f9880' },
  { name: 'SimpleEscapes', lit: '"\\a\\b\\f\\r\\v\\n\\t\\\\\\""', bytes: '07080c0d0b0a095c22' },
  { name: 'HexAndOctal', lit: '"\\x41\\102\\u0043"', bytes: '414243' },
  { name: 'RawBacktick', lit: '`a\\nb`', bytes: '615c6e62' }, // backslash stays
  { name: 'RawBacktickUtf8', lit: '`é😀`', bytes: 'c3a9f09f9880' },
  { name: 'RawBacktickNewline', lit: '`a\nb`', bytes: '610a62' },
  { name: 'RawBacktickCr', lit: '`a\r\nb`', bytes: '610a62' }, // \r discarded
];

const REJECTED: Array<{ name: string; lit: string; esc: string }> = [
  { name: 'UnknownLetter', lit: '"\\q"', esc: '\\q' },
  { name: 'EscapedSingleQuote', lit: '"\\\'"', esc: "\\'" },
  { name: 'EightIsNotOctal', lit: '"\\8"', esc: '\\8' },
  { name: 'OctalAbove255', lit: '"\\400"', esc: '\\400' },
  { name: 'OctalAbove255Max', lit: '"\\777"', esc: '\\777' },
  { name: 'OctalTooShort', lit: '"\\0"', esc: '\\0' },
  { name: 'ShortHex', lit: '"\\x4"', esc: '\\x' },
  { name: 'ShortUnicode', lit: '"\\u12"', esc: '\\u' },
  { name: 'Surrogate', lit: '"\\ud800"', esc: '\\u' },
  { name: 'UnicodeOutOfRange', lit: '"\\U00110000"', esc: '\\U' },
];

const DIR = mkdtempSync(join(tmpdir(), 'n437-go-string-literal-'));
const tiers = buildSourceTiers().filter((t) => t.cmd !== null);

describe('N-437: .runar.go ByteString(...) literals follow Go string-literal rules in every tier', () => {
  it('the TS reference tier and at least one peer are available (else the comparison is vacuous)', () => {
    expect(tiers.find((t) => t.id === 'ts')).toBeDefined();
    expect(tiers.length).toBeGreaterThanOrEqual(2);
  });

  for (const { name, lit, bytes } of ACCEPTED) {
    const file = join(DIR, `${name}.runar.go`);
    writeFileSync(file, contract(name, lit), 'utf-8');
    const push = (bytes.length / 2).toString(16).padStart(2, '0') + bytes;
    for (const tier of tiers) {
      it(`${tier.id} pushes ${bytes} for ${name}`, () => {
        expect(compileHex(tier, file)).toContain(push);
      }, tier.timeoutMs);
    }
    it(`all tiers compile ${name} to byte-identical scripts`, () => {
      const hexes = tiers.map((t) => compileHex(t, file));
      for (const h of hexes) expect(h).toBe(hexes[0]);
    }, 600_000);
  }

  for (const { name, lit, esc } of REJECTED) {
    const file = join(DIR, `${name}.runar.go`);
    writeFileSync(file, contract(name, lit), 'utf-8');
    for (const tier of tiers) {
      it(`${tier.id} refuses ${name} (${lit})`, () => {
        const { verdict, diag } = judge(tier, file);
        expect(verdict).toBe('rejected');
        // Go's own compiler words it differently; every other tier shares one text.
        if (tier.id !== 'go') expect(diag).toContain(`invalid escape sequence '${esc}'`);
      }, tier.timeoutMs);
    }
  }
});
