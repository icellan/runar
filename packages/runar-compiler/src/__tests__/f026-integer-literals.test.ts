import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile } from '../index.js';
import { parse } from '../passes/01-parse.js';
import {
  invalidIntegerLiteral,
  parseIntLiteral,
  type LiteralSurface,
} from '../passes/int-literal.js';
import { PY_STATEMENT_LINE_BREAK, ZIG_LIST_COMMA } from '../errors.js';

/**
 * F-026 (CL-BUG-198) — an integer literal means what its host language says it
 * means, on every surface, or it is refused.
 *
 * The .runar.zig and .runar.py tokenizers scanned decimal digits only, so
 * `0b1010` lexed as `0` followed by the identifier `b1010`. When an identifier
 * of that name was in scope, the stray token was absorbed: .zig call arguments
 * did not need commas and .py accepted two statements on one line. The guard
 * `runar.assert(amount > 0b1010)` then compiled to `amount > 0`, and @bsv/sdk
 * Spend.validate accepted amount = 5. The .ts surface ignored TypeScript's
 * own syntax errors, so `0b102` compiled as 2 and `0o19` as 1.
 *
 * The rule (user decision R15), defined here and ported to all seven tiers:
 *   - a number token runs over every glued [0-9A-Za-z_] character, and the
 *     whole token must be an integer literal of the surface's host language
 *     (`conformance/negatives/int-literal-cases.json`, generated from the host
 *     toolchains). It gets the host's value. Anything else is refused with
 *     `invalid <Language> integer literal '<text>'`;
 *   - .zig call and array-literal lists require commas;
 *   - .py refuses a second statement on the same line;
 *   - .ts reports TypeScript's syntactic diagnostics.
 *
 * What this proves: the reference validator reproduces every row of the host
 * table, every reference tokenizer (eight hand-written, plus ts-morph) is wired
 * to it, and the attempt-1 exploit shapes (a shadowing identifier plus a
 * radix literal) now compile to the literal's value or are refused. It also
 * proves the absorbing paths are closed with their shared diagnostics.
 * What it does NOT prove: anything about the other six tiers (their own suites,
 * conformance/negatives/int-literal-parity.test.ts and the N68+ negatives cover
 * them). It also does not prove the Solidity and Move rows, which come from
 * documentation because no host toolchain for them is available.
 */

const CASES_FILE = resolve(__dirname, '../../../../conformance/negatives/int-literal-cases.json');
const CASES = JSON.parse(readFileSync(CASES_FILE, 'utf8')).cases as Record<LiteralSurface, [string, string | null][]>;
const SURFACES: LiteralSurface[] = ['ts', 'sol', 'move', 'go', 'rs', 'py', 'zig', 'rb', 'java'];

/** One-literal contract per surface: the literal is the right operand of `a >`. */
const TEMPLATE: Record<LiteralSurface, (lit: string) => string> = {
  ts: (l) => `import { SmartContract, assert } from 'runar-lang';\n\nclass T extends SmartContract {\n  readonly target: bigint;\n\n  constructor(target: bigint) {\n    super(target);\n    this.target = target;\n  }\n\n  public verify(a: bigint): void {\n    assert(a > ${l});\n  }\n}\n`,
  sol: (l) => `pragma runar ^0.1.0;\n\ncontract T is SmartContract {\n    int immutable target;\n\n    constructor(int _target) {\n        target = _target;\n    }\n\n    function verify(int a) public {\n        require(a > ${l});\n    }\n}\n`,
  move: (l) => `module T {\n    use runar::types::{Int};\n\n    struct T {\n        target: Int,\n    }\n\n    public fun verify(contract: &T, a: Int) {\n        assert!(a > ${l});\n    }\n}\n`,
  go: (l) => `package contract\n\nimport runar "github.com/icellan/runar/packages/runar-go"\n\ntype T struct {\n\trunar.SmartContract\n\tTarget runar.Int \`runar:"readonly"\`\n}\n\nfunc (c *T) Verify(a runar.Int) {\n\trunar.Assert(a > ${l})\n}\n`,
  rs: (l) => `use runar::prelude::*;\n\n#[runar::contract]\nstruct T {\n    #[readonly]\n    target: Int,\n}\n\nimpl T {\n    pub fn verify(&self, a: Int) {\n        assert!(a > ${l});\n    }\n}\n`,
  py: (l) => `from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n        self.target = target\n\n    @public\n    def verify(self, a: Bigint):\n        assert_(a > ${l})\n`,
  zig: (l) => `const runar = @import("runar");\n\npub const T = struct {\n    pub const Contract = runar.SmartContract;\n\n    target: i64,\n\n    pub fn init(target: i64) T {\n        return .{ .target = target };\n    }\n\n    pub fn verify(self: *const T, a: i64) void {\n        _ = self;\n        runar.assert(a > ${l});\n    }\n};\n`,
  rb: (l) => `require 'runar'\n\nclass T < Runar::SmartContract\n  prop :target, Bigint\n\n  def initialize(target)\n    super(target)\n    @target = target\n  end\n\n  runar_public a: Bigint\n  def verify(a)\n    assert a > ${l}\n  end\nend\n`,
  java: (l) => `package t;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\nimport runar.lang.annotations.Readonly;\nimport runar.lang.types.Bigint;\n\nimport static runar.lang.Builtins.assertThat;\n\nclass T extends SmartContract {\n\n    @Readonly Bigint target;\n\n    T(Bigint target) {\n        super(target);\n        this.target = target;\n    }\n\n    @Public\n    void verify(Bigint a) {\n        assertThat(a.gt(Bigint.of(${l})));\n    }\n}\n`,
};

const FILE: Record<LiteralSurface, string> = {
  ts: 'T.runar.ts', sol: 'T.runar.sol', move: 'T.runar.move', go: 'T.runar.go', rs: 'T.runar.rs',
  py: 'T.runar.py', zig: 'T.runar.zig', rb: 'T.runar.rb', java: 'T.runar.java',
};

/** Every bigint literal in the public method's body, in source order. */
function literalsOf(source: string, file: string): { values: bigint[]; errors: string[] } {
  const r = parse(source, file);
  const errors = r.errors.filter((e) => e.severity === 'error').map((e) => e.message);
  const values: bigint[] = [];
  const walk = (n: unknown): void => {
    if (Array.isArray(n)) { n.forEach(walk); return; }
    if (n && typeof n === 'object') {
      const o = n as Record<string, unknown>;
      if (o.kind === 'bigint_literal') values.push(o.value as bigint);
      for (const [k, v] of Object.entries(o)) if (k !== 'sourceLocation') walk(v);
    }
  };
  const m = r.contract?.methods.find((x) => x.name === 'verify');
  if (m) walk(m.body);
  return { values, errors };
}

function hexOf(source: string, fileName: string): string {
  const r = compile(source, { fileName, disableConstantFolding: true });
  const errs = r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
  expect(errs, fileName).toEqual([]);
  return r.scriptHex!;
}

function compileErrors(source: string, fileName: string): string[] {
  const r = compile(source, { fileName, disableConstantFolding: true });
  return r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
}

describe('F-026 the reference validator reproduces the host-language table', () => {
  it('the table covers all nine surfaces', () => {
    expect(Object.keys(CASES).sort()).toEqual([...SURFACES].sort());
    for (const s of SURFACES) expect(CASES[s].length).toBeGreaterThan(40);
  });

  for (const s of SURFACES) {
    it(`${s}: every row`, () => {
      const bad: string[] = [];
      for (const [lit, want] of CASES[s]) {
        const r = parseIntLiteral(s, lit);
        const got = r && !r.negOnly ? r.value.toString() : null;
        if (got !== want) bad.push(`${lit}: want ${want}, got ${got}`);
      }
      expect(bad).toEqual([]);
    });
  }

  it('the shared diagnostic names the language and quotes the literal', () => {
    expect(invalidIntegerLiteral('zig', '0B1010')).toBe("invalid Zig integer literal '0B1010'");
    expect(invalidIntegerLiteral('ts', '0b102')).toBe("invalid TypeScript integer literal '0b102'");
  });
});

describe('F-026 every reference tokenizer applies the table', () => {
  for (const s of SURFACES) {
    it(`${s}: accepted forms carry the host value, refused forms the shared diagnostic`, () => {
      const bad: string[] = [];
      for (const [lit, want] of CASES[s]) {
        const { values, errors } = literalsOf(TEMPLATE[s](lit), FILE[s]);
        if (want === null) {
          if (!errors.includes(invalidIntegerLiteral(s, lit))) bad.push(`${lit}: not refused (${JSON.stringify(errors)} ${values})`);
        } else if (errors.length > 0 || values.length !== 1 || values[0] !== BigInt(want)) {
          bad.push(`${lit}: want [${want}], got [${values}] ${JSON.stringify(errors)}`);
        }
      }
      expect(bad).toEqual([]);
    });
  }
});

describe('F-026 unary-minus-only literals (Java int/long minimum, Rust signed-suffix minimum)', () => {
  it('java: -2147483648 and -9223372036854775808L are accepted, bare or parenthesised they are not', () => {
    expect(literalsOf(TEMPLATE.java('-2147483648'), FILE.java)).toEqual({ values: [2147483648n], errors: [] });
    expect(literalsOf(TEMPLATE.java('- 9223372036854775808L'), FILE.java)).toEqual({ values: [9223372036854775808n], errors: [] });
    for (const lit of ['-(2147483648)', '1 - 2147483648', '2147483648', '9223372036854775808L', '-9223372036854775808']) {
      const bad = lit.replace(/^.*?(\d\w*)\)?$/, '$1');
      expect(literalsOf(TEMPLATE.java(lit), FILE.java).errors, lit).toContain(invalidIntegerLiteral('java', bad));
    }
  });

  it('rs: -128i8 and -(128i8) are accepted, bare 128i8 is not', () => {
    expect(literalsOf(TEMPLATE.rs('-128i8'), FILE.rs)).toEqual({ values: [128n], errors: [] });
    expect(literalsOf(TEMPLATE.rs('-(128i8)'), FILE.rs)).toEqual({ values: [128n], errors: [] });
    expect(literalsOf(TEMPLATE.rs('-9223372036854775808i64'), FILE.rs)).toEqual({ values: [9223372036854775808n], errors: [] });
    expect(literalsOf(TEMPLATE.rs('128i8'), FILE.rs).errors).toContain(invalidIntegerLiteral('rs', '128i8'));
    expect(literalsOf(TEMPLATE.rs('1 - 128i8'), FILE.rs).errors).toContain(invalidIntegerLiteral('rs', '128i8'));
    expect(literalsOf(TEMPLATE.rs('-129i8'), FILE.rs).errors).toContain(invalidIntegerLiteral('rs', '129i8'));
  });
});

// ---------------------------------------------------------------------------
// The attempt-1 exploit shapes: a radix literal next to an identifier of the
// same spelling as its tail. Pre-fix, the reference tier compiled each one to
// `> 0` (or refused it only by accident).
// ---------------------------------------------------------------------------

const zigWith = (params: string, body: string): string =>
  `const runar = @import("runar");\n\npub const T = struct {\n    pub const Contract = runar.SmartContract;\n\n    target: i64,\n\n    pub fn init(target: i64) T {\n        return .{ .target = target };\n    }\n\n    pub fn verify(self: *const T, amount: i64${params}) void {\n        _ = self;\n${body}\n    }\n};\n`;

const pyWith = (params: string, body: string): string =>
  `from runar import SmartContract, Bigint, ByteString, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n        self.target = target\n\n    @public\n    def verify(self, amount: Bigint${params}):\n${body}\n`;

describe('F-026 attempt-1 exploit shapes compile to the literal value', () => {
  it('zig: `amount > 0b1010` with a ByteString `b1010` in scope is `amount > 10`', () => {
    const exploit = zigWith(', b1010: runar.ByteString', '        runar.assert(amount > 0b1010);');
    const control = zigWith(', b1010: runar.ByteString', '        runar.assert(amount > 10);');
    expect(hexOf(exploit, 'T.runar.zig')).toBe(hexOf(control, 'T.runar.zig'));
  });

  it('zig: a field default `target: i64 = 0b1010` is 10', () => {
    const src = (lit: string) => `const runar = @import("runar");\n\npub const T = struct {\n    pub const Contract = runar.SmartContract;\n\n    target: i64 = ${lit},\n\n    pub fn verify(self: *const T, amount: i64) void {\n        runar.assert(amount > self.target);\n    }\n};\n`;
    expect(hexOf(src('0b1010'), 'T.runar.zig')).toBe(hexOf(src('10'), 'T.runar.zig'));
    expect(hexOf(src('0o12'), 'T.runar.zig')).toBe(hexOf(src('10'), 'T.runar.zig'));
    expect(hexOf(src('0xa'), 'T.runar.zig')).toBe(hexOf(src('10'), 'T.runar.zig'));
  });

  it('zig: an upper-case prefix next to a same-named identifier is refused, never absorbed', () => {
    const src = zigWith(', B1010: i64', '        runar.assert(amount > 0B1010);\n        runar.assert(B1010 == B1010);');
    expect(compileErrors(src, 'T.runar.zig')).toContain(invalidIntegerLiteral('zig', '0B1010'));
  });

  it('py: `lim = 0b1010` with `b1010` in scope is 10', () => {
    const exploit = pyWith(', b1010: Bigint', '        lim = 0b1010\n        assert_(amount > lim)');
    const control = pyWith(', b1010: Bigint', '        lim = 10\n        assert_(amount > lim)');
    expect(hexOf(exploit, 'T.runar.py')).toBe(hexOf(control, 'T.runar.py'));
  });

  it('py: a class-level default `target: Bigint = 0o12` is 10', () => {
    const src = (lit: string) => `from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n    limit: Bigint = ${lit}\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n        self.target = target\n\n    @public\n    def verify(self, amount: Bigint):\n        assert_(amount > self.limit)\n`;
    expect(hexOf(src('0o12'), 'T.runar.py')).toBe(hexOf(src('10'), 'T.runar.py'));
    expect(hexOf(src('0b1010'), 'T.runar.py')).toBe(hexOf(src('10'), 'T.runar.py'));
  });

  it('ts: `0b102` and `0o19` are refused, not read as 2 and 1', () => {
    expect(compileErrors(TEMPLATE.ts('0b102'), 'T.runar.ts')).toContain(invalidIntegerLiteral('ts', '0b102'));
    expect(compileErrors(TEMPLATE.ts('0o19'), 'T.runar.ts')).toContain(invalidIntegerLiteral('ts', '0o19'));
  });
});

describe('F-026 absorbing paths', () => {
  it('zig: a call argument list without a comma is refused', () => {
    const src = zigWith(', b: i64', '        runar.assert(runar.within(amount b, 20));');
    expect(compileErrors(src, 'T.runar.zig')).toContain(ZIG_LIST_COMMA);
    const ok = zigWith(', b: i64', '        runar.assert(runar.within(amount, b, 20,));');
    expect(compileErrors(ok, 'T.runar.zig')).not.toContain(ZIG_LIST_COMMA);
  });

  it('zig: an array literal without a comma is refused', () => {
    const src = zigWith('', '        const xs = [_]i64{ 1 2, 3 };\n        runar.assert(amount > xs[0]);');
    expect(compileErrors(src, 'T.runar.zig')).toContain(ZIG_LIST_COMMA);
    const src2 = zigWith('', '        const xs: [3]i64 = .{ 1, 2 3 };\n        runar.assert(amount > xs[0]);');
    expect(compileErrors(src2, 'T.runar.zig')).toContain(ZIG_LIST_COMMA);
  });

  it('py: two statements on one line are refused, in a method and at class level', () => {
    const src = pyWith(', b: Bigint', '        lim = 10 b\n        assert_(amount > lim)');
    expect(compileErrors(src, 'T.runar.py')).toContain(PY_STATEMENT_LINE_BREAK);
    const src2 = pyWith(', b: Bigint', '        assert_(amount > 1) assert_(amount > 2)');
    expect(compileErrors(src2, 'T.runar.py')).toContain(PY_STATEMENT_LINE_BREAK);
    const cls = `from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint = 10 extra\n\n    @public\n    def verify(self, amount: Bigint):\n        assert_(amount > self.target)\n`;
    expect(compileErrors(cls, 'T.runar.py')).toContain(PY_STATEMENT_LINE_BREAK);
  });

  it('ts: a TypeScript syntax error is reported, not ignored', () => {
    const src = TEMPLATE.ts('10').replace('assert(a > 10);', 'assert(a > 10;');
    const errs = compileErrors(src, 'T.runar.ts');
    expect(errs.some((e) => e.startsWith('TypeScript syntax error: '))).toBe(true);
  });
});
