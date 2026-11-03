import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex, judge } from './tier-harness.js';

/**
 * N-448 (user decisions R174, R176-R178): on the `.runar.go` and `.runar.zig`
 * surfaces a bare, non-empty string literal used as a ByteString value (or any
 * ByteString subtype: PubKey, Sig, Addr, ...) is REFUSED by every tier. Native
 * Go and Zig read `"006a"` as four ASCII bytes while the compiler read it as
 * hex, so one source meant two different programs. The hex form is spelled
 * with the format's explicit helper:
 *
 *   - Go:  `runar.HexToBytes("006a")`  (runar-go decodes it natively)
 *   - Zig: `runar.hexToBytes("006a")`  (already existed)
 *
 * Every tier prints the SAME diagnostic, `<file>:<line>:<0-based col>: <msg>`,
 * with the position of the literal's opening quote (computed here from the
 * fixture's source text, never copied from a compiler's output).
 *
 * Still accepted (checked below): the empty string `""` (R178: zero bytes under
 * both readings), `runar.ByteString("text")` on the Go surface (an explicit
 * ASCII conversion, N-437), and the first argument of `runar.Asm(...)` /
 * `runar.asm(...)` (an opcode body, not a ByteString value).
 *
 * What this proves: every available tier refuses each bare form with the one
 * message at the right position, accepts the helper spelling, and all tiers
 * emit byte-identical scripts for it that carry the decoded hex bytes.
 * What it does NOT prove: execution on a node; that the native Go / Zig
 * packages decode the helper (their own unit tests do); every other literal
 * position (an array literal element, a struct-literal field).
 */

const TIERS = buildSourceTiers();
const DIR = mkdtempSync(join(tmpdir(), 'n448-bare-literal-'));

const goMsg = (lit: string): string =>
  `bare string literal "${lit}" is ambiguous in .runar.go source: natively it is ASCII text but the compiler reads it as hex — write runar.HexToBytes("${lit}") for hex bytes or runar.ByteString("${lit}") for the text`;
const zigMsg = (lit: string): string =>
  `bare string literal "${lit}" is ambiguous in .runar.zig source: natively it is ASCII text but the compiler reads it as hex — write runar.hexToBytes("${lit}") for hex bytes`;

const goLocal = (name: string, expr: string): string => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type ${name} struct {
	runar.SmartContract
	Expected runar.ByteString \`runar:"readonly"\`
}

func (c *${name}) Check() {
	x := ${expr}
	runar.Assert(x == c.Expected)
}
`;

const goPubKeyInit = (name: string, expr: string): string => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type ${name} struct {
	runar.SmartContract
	Owner runar.PubKey \`runar:"readonly"\`
	Tag   runar.ByteString \`runar:"readonly"\`
}

func (c *${name}) init() {
	c.Owner = ${expr}
}

func (c *${name}) Check(k runar.ByteString) {
	runar.Assert(k == c.Tag)
}
`;

const goAsm = (name: string): string => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type ${name} struct {
	runar.UnsafeSmartContract
}

func (c *${name}) Unlock() {
	runar.Asm("51", 0, 1)
}
`;

const zigCheck = (name: string, expr: string): string => `const runar = @import("runar");

pub const ${name} = struct {
    pub const Contract = runar.SmartContract;

    expected: runar.ByteString,

    pub fn init(expected: runar.ByteString) ${name} {
        return .{ .expected = expected };
    }

    pub fn check(self: *const ${name}) void {
        runar.assert(runar.bytesEq(${expr}, self.expected));
    }
};
`;

const zigPubKeyInit = (name: string, expr: string): string => `const runar = @import("runar");

pub const ${name} = struct {
    pub const Contract = runar.SmartContract;

    owner: runar.PubKey = ${expr},
    tag: runar.ByteString,

    pub fn init(tag: runar.ByteString) ${name} {
        return .{ .tag = tag };
    }

    pub fn check(self: *const ${name}, k: runar.ByteString) void {
        runar.assert(runar.bytesEq(k, self.tag));
    }
};
`;

const zigAsm = (name: string): string => `const runar = @import("runar");

pub const ${name} = struct {
    pub const Contract = runar.UnsafeSmartContract;

    pub fn init() ${name} {
        return .{};
    }

    pub fn unlock(self: *const ${name}) void {
        _ = self;
        runar.asm("51", 0, 1);
    }
};
`;

const PK = '0'.repeat(66);

interface Refused { name: string; ext: 'go' | 'zig'; src: string; lit: string; msg: string }
const REFUSED: Refused[] = [
  { name: 'GoLocal', ext: 'go', src: goLocal('GoLocal', '"006a"'), lit: '006a', msg: goMsg('006a') },
  { name: 'GoPubKeyInit', ext: 'go', src: goPubKeyInit('GoPubKeyInit', `"${PK}"`), lit: PK, msg: goMsg(PK) },
  { name: 'ZigCheck', ext: 'zig', src: zigCheck('ZigCheck', '"006a"'), lit: '006a', msg: zigMsg('006a') },
  { name: 'ZigPubKeyInit', ext: 'zig', src: zigPubKeyInit('ZigPubKeyInit', `"${PK}"`), lit: PK, msg: zigMsg(PK) },
];

/** `<line>:<0-based column>` of the literal's opening quote in `text`. */
function expectedPosition(text: string, lit: string): string {
  const anchor = `"${lit}"`;
  const lines = text.split('\n');
  const idx = lines.findIndex((l) => l.includes(anchor));
  if (idx < 0) throw new Error(`anchor ${anchor} not in source`);
  return `${idx + 1}:${lines[idx]!.indexOf(anchor)}`;
}

describe('N-448: bare ByteString string literals are refused on .runar.go / .runar.zig', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const { name, ext, src, lit, msg } of REFUSED) {
    const fileName = `${name}.runar.${ext}`;
    const file = join(DIR, fileName);
    writeFileSync(file, src);
    const want = `${fileName}:${expectedPosition(src, lit)}: ${msg}`;
    for (const tier of TIERS) {
      it(`${tier.id} refuses ${fileName} with the one diagnostic`, () => {
        const r = judge(tier, file);
        expect(r.verdict).toBe('rejected');
        expect(r.diag).toContain(want);
      }, tier.timeoutMs);
    }
  }

  // The hex spelling: accepted everywhere, byte-identical, carrying 0x00 0x6a.
  const HELPER: Array<{ name: string; ext: 'go' | 'zig'; src: string }> = [
    { name: 'GoHelperLocal', ext: 'go', src: goLocal('GoHelperLocal', 'runar.HexToBytes("006a")') },
    { name: 'GoHelperPubKeyInit', ext: 'go', src: goPubKeyInit('GoHelperPubKeyInit', `runar.HexToBytes("${PK}")`) },
    { name: 'ZigHelperCheck', ext: 'zig', src: zigCheck('ZigHelperCheck', 'runar.hexToBytes("006a")') },
    { name: 'ZigHelperPubKeyInit', ext: 'zig', src: zigPubKeyInit('ZigHelperPubKeyInit', `runar.hexToBytes("${PK}")`) },
  ];
  for (const { name, ext, src } of HELPER) {
    const file = join(DIR, `${name}.runar.${ext}`);
    writeFileSync(file, src);
    it(`all tiers compile ${name}.runar.${ext} to identical scripts`, () => {
      const hexes = TIERS.map((t) => compileHex(t, file));
      for (const h of hexes) expect(h).toBe(hexes[0]);
    }, 900_000);
  }
  it('the helper pushes the decoded bytes (0x00 0x6a), not ASCII', () => {
    const hex = compileHex(TIERS.find((t) => t.id === 'ts')!, join(DIR, 'GoHelperLocal.runar.go'));
    expect(hex).toContain('02006a');
    expect(hex).not.toContain('3030366');
  }, 300_000);

  // Exemptions: these must keep compiling in every tier.
  const KEPT: Array<{ name: string; ext: 'go' | 'zig'; src: string }> = [
    { name: 'GoEmpty', ext: 'go', src: goLocal('GoEmpty', '""') },
    { name: 'GoAsciiConversion', ext: 'go', src: goLocal('GoAsciiConversion', 'runar.ByteString("hi")') },
    { name: 'GoAsmBody', ext: 'go', src: goAsm('GoAsmBody') },
    { name: 'ZigEmpty', ext: 'zig', src: zigCheck('ZigEmpty', '""') },
    { name: 'ZigAsmBody', ext: 'zig', src: zigAsm('ZigAsmBody') },
  ];
  for (const { name, ext, src } of KEPT) {
    const file = join(DIR, `${name}.runar.${ext}`);
    writeFileSync(file, src);
    for (const tier of TIERS) {
      it(`${tier.id} still accepts ${name}.runar.${ext}`, () => {
        expect(judge(tier, file).verdict).toBe('accepted');
      }, tier.timeoutMs);
    }
  }
});
