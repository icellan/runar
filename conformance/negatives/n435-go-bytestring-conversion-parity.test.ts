import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex } from './tier-harness.js';

/**
 * N-435: `runar.ByteString("...")` on the `.runar.go` surface is a
 * string-to-bytes conversion, exactly like Go's `[]byte(s)`: the pushed bytes
 * are the UTF-8 bytes of the string, with a `\xNN` escape contributing the one
 * raw byte NN. It is NOT a hex literal (`"ab"` pushes 6162, not ab).
 *
 * Before the fix, go/rust/zig/ruby pushed the UTF-8 bytes of a literal `é`
 * (c3a9) while ts/python/java pushed one byte per UTF-16 code unit / Latin-1
 * character (e9), so the same `.runar.go` source compiled to different
 * scripts. The converged rule is the one native Go execution of the same
 * contract has (and the one four tiers, plus the compiler tests pinning
 * `"\x00\x6a"` -> 006a, already implemented).
 *
 * What this proves: every available tier's `--hex` CLI compiles a contract
 * that compares a property against `runar.ByteString(<literal>)` to a script
 * that (a) is byte-identical across tiers and (b) pushes exactly the Go bytes
 * of the literal. What it does NOT prove: execution of the script on a node
 * (the pushed bytes are checked structurally), non-literal arguments
 * (`runar.ByteString(variable)` is a no-op unwrap and untouched), or the other
 * eight surfaces (their quoted literals are hex and are covered by N-429).
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
const CASES: Array<{ name: string; lit: string; bytes: string }> = [
  { name: 'Ascii', lit: '"ab"', bytes: '6162' }, // looks like hex, is text
  { name: 'NonHexAscii', lit: '"zz"', bytes: '7a7a' },
  { name: 'Accented', lit: '"é"', bytes: 'c3a9' }, // the N-435 divergence
  { name: 'Emoji', lit: '"😀"', bytes: 'f09f9880' }, // astral: UTF-16 pair vs 4 UTF-8 bytes
  { name: 'EscapedByte', lit: '"\\xe9"', bytes: 'e9' }, // escape = one raw byte, not UTF-8
  { name: 'MixedEscape', lit: '"a\\xe9é"', bytes: '61e9c3a9' }, // raw byte then UTF-8
  { name: 'EscapedPair', lit: '"\\x00\\x6a"', bytes: '006a' },
];

const DIR = mkdtempSync(join(tmpdir(), 'n435-go-bytestring-'));
const tiers = buildSourceTiers().filter((t) => t.cmd !== null);

describe('N-435: .runar.go runar.ByteString("literal") pushes the Go string bytes in every tier', () => {
  it('the TS reference tier and at least one peer are available (else the comparison is vacuous)', () => {
    expect(tiers.find((t) => t.id === 'ts')).toBeDefined();
    expect(tiers.length).toBeGreaterThanOrEqual(2);
  });

  for (const { name, lit, bytes } of CASES) {
    const file = join(DIR, `${name}.runar.go`);
    writeFileSync(file, contract(name, lit), 'utf-8');
    const push = (bytes.length / 2).toString(16).padStart(2, '0') + bytes;
    for (const tier of tiers) {
      it(`${tier.id} pushes ${bytes} for ${lit}`, () => {
        const hex = compileHex(tier, file);
        expect(hex).toContain(push);
      }, tier.timeoutMs);
    }
    it(`all tiers compile ${lit} to byte-identical scripts`, () => {
      const hexes = tiers.map((t) => compileHex(t, file));
      for (const h of hexes) expect(h).toBe(hexes[0]);
    }, 600_000);
  }
});
