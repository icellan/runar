import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex, judge } from './tier-harness.js';

/**
 * N-439: a BARE string literal on the `.runar.go` surface (one that is not the
 * sole argument of `runar.ByteString(...)`, which N-437 settled) is a
 * ByteString HEX literal (N-429). Every tier first decodes it with Go's
 * string-literal rules (https://go.dev/ref/spec#String_literals) -- the Go tier
 * is `strconv.Unquote` -- and only then checks and uses the decoded text as hex:
 *
 *   - `"\x34\x31"`, `"41"`, `"\064\061"` decode to the text `41`
 *     and push the single byte 0x41;
 *   - a backtick raw literal is its text verbatim, so
 *     `4142` pushes 0x41 0x42, and `\x34\x31` stays a backslash text that is
 *     not hex and is refused;
 *   - `"\x41"` decodes to `A`, which is not hex (odd length) and is refused.
 *
 * Before the fix Zig and Ruby kept the raw escape text, so they refused the
 * three escaped forms the other five tiers accept, and TS, Python, Java, Zig
 * and Ruby refused a bare backtick literal that Go and Rust accept.
 *
 * What this proves: for each literal every available tier's `--hex` CLI pushes
 * exactly the bytes the Go tier gives it, all tiers emit identical scripts, and
 * each non-hex result is refused by every tier. What it does NOT prove:
 * execution on a node; a lone carriage return inside a bare backtick literal
 * (Go discards it, the Python tier's source reader has already turned it into a
 * line feed -- a source-reading matter shared by every Python format); ByteString(...) arguments (n437); the wording of the
 * non-hex diagnostic, which still quotes the raw or decoded text per tier
 * (N-436); a bare literal in a property initializer or struct-tag position.
 */

const contract = (name: string, lit: string) => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type ${name} struct {
	runar.SmartContract
	Expected runar.ByteString \`runar:"readonly"\`
}

func (c *${name}) Check() {
	x := ${lit}
	runar.Assert(x == c.Expected)
}
`;

// `lit` is the Go source text of the literal; `bytes` the bytes the Go tier pushes.
const ACCEPTED: Array<{ name: string; lit: string; bytes: string }> = [
  { name: 'PlainHex', lit: '"4142"', bytes: '4142' },
  { name: 'HexEscapes', lit: '"\\x34\\x31"', bytes: '41' },
  { name: 'UnicodeEscapes', lit: '"\\u0034\\u0031"', bytes: '41' },
  { name: 'OctalEscapes', lit: '"\\064\\061"', bytes: '41' },
  { name: 'MixedEscapes', lit: '"\\x34\\061\\u0032\\x32"', bytes: '4122' },
  { name: 'RawBacktickHex', lit: '`4142`', bytes: '4142' },
];

const REJECTED: Array<{ name: string; lit: string }> = [
  { name: 'DecodesToOddText', lit: '"\\x41"' }, // decodes to "A"
  { name: 'RawBacktickKeepsBackslash', lit: '`\\x34\\x31`' }, // text stays \x34\x31
  { name: 'InvalidEscape', lit: '"\\q"' },
];

const DIR = mkdtempSync(join(tmpdir(), 'n439-go-bare-literal-'));
const tiers = buildSourceTiers().filter((t) => t.cmd !== null);

describe('N-439: bare .runar.go string literals are Go-decoded, then hex, in every tier', () => {
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

  for (const { name, lit } of REJECTED) {
    const file = join(DIR, `${name}.runar.go`);
    writeFileSync(file, contract(name, lit), 'utf-8');
    for (const tier of tiers) {
      it(`${tier.id} refuses ${name} (${lit})`, () => {
        expect(judge(tier, file).verdict).toBe('rejected');
      }, tier.timeoutMs);
    }
  }
});
