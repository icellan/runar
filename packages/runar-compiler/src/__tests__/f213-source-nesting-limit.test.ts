import { describe, it, expect } from 'vitest';
import { compile, parseSolSource } from '../index.js';
import { InputLimits } from 'runar-ir-schema';

/**
 * F-213 — a deeply nested source must be REFUSED with one shared diagnostic,
 * never crash the compiler.
 *
 * Before this item no tier bounded nesting. Measured on the CLIs: the Rust tier
 * SIGABRTs (stack overflow) on ~2000 nested parens (a 4 KB file, three orders of
 * magnitude under MAX_SOURCE_BYTES); Zig SIGABRTs on a 5000-term `a + a + …`
 * chain; this TS tier answered `Maximum call stack size exceeded` on 2000 parens
 * — a refusal, but a RangeError surfacing by accident, not a limit.
 *
 * The limit, `InputLimits.MAX_SOURCE_NESTING`, is enforced on two measures, both
 * defined in input-limits.ts and implemented identically in all seven tiers:
 *   (A) parse nesting — statements + expression-parse entries (paren groups,
 *       call args, …) + prefix-unary operands;
 *   (B) AST nesting — statement level + expression-tree depth.
 * The canonical shapes below sit exactly on either side of the limit for one of
 * the two measures, on all nine surfaces.
 *
 * Proves: on every surface the TS tier accepts each shape at the limit and
 * refuses it one past the limit with the shared diagnostic; a 20 000-deep
 * shape and a 500 000-term chain are refused the same way, with no thrown
 * exception; the per-format export `parseSolSource` enforces it too.
 * Does not prove: the other six tiers (conformance/negatives/
 * f213-nesting-limit-parity.test.ts drives all seven CLIs), or that the limit is
 * the right size — that is the corpus measurement recorded in input-limits.ts.
 */

const L = InputLimits.MAX_SOURCE_NESTING;
const DIAG = `source nesting depth exceeds MAX_SOURCE_NESTING (limit=${L})`;

type Surface = 'ts' | 'sol' | 'move' | 'go' | 'rs' | 'py' | 'zig' | 'rb' | 'java';
type Shape = 'parens' | 'if' | 'unary' | 'chain';

interface Tpl {
  head: string;
  assign: (e: string) => string;
  ifWrap: (n: number, inner: string) => string;
}

const braceIf = (open: string, close: string) => (n: number, inner: string) =>
  open.repeat(n) + inner + '\n' + close.repeat(n);

const TPL: Record<Surface, Tpl> = {
  ts: {
    head: "import { SmartContract, assert } from 'runar-lang';\n\nclass P extends SmartContract {\n  readonly limit: bigint;\n  constructor(limit: bigint) { super(limit); this.limit = limit; }\n  public check(value: bigint, mode: boolean): void {\n    let result: bigint = 0n;\n{BODY}\n    assert(result > 0n);\n  }\n}\n",
    assign: (e) => `    result = ${e};`,
    ifWrap: braceIf('if (mode) {\n', '}\n'),
  },
  sol: {
    head: 'pragma runar ^0.1.0;\n\ncontract P is SmartContract {\n    int immutable limit;\n    constructor(int _limit) { limit = _limit; }\n    function check(int value, bool mode) public {\n        int result = 0;\n{BODY}\n        require(result > 0);\n    }\n}\n',
    assign: (e) => `        result = ${e};`,
    ifWrap: braceIf('if (mode) {\n', '}\n'),
  },
  move: {
    head: 'module P {\n    use runar::types::{Int};\n    struct P { limit: Int, }\n    public fun check(contract: &P, value: Int, mode: bool) {\n        let result: Int = 0;\n{BODY}\n        assert!(result > 0, 0);\n    }\n}\n',
    assign: (e) => `        result = ${e};`,
    ifWrap: braceIf('if (mode) {\n', '};\n'),
  },
  go: {
    head: 'package contract\n\nimport runar "github.com/icellan/runar/packages/runar-go"\n\ntype P struct {\n\trunar.SmartContract\n\tLimit runar.Int `runar:"readonly"`\n}\n\nfunc (c *P) Check(value runar.Int, mode runar.Bool) {\n\tresult := runar.Int(0)\n{BODY}\n\trunar.Assert(result > 0)\n}\n',
    assign: (e) => `\tresult = ${e}`,
    ifWrap: braceIf('if mode {\n', '}\n'),
  },
  rs: {
    head: 'use runar::prelude::*;\n\n#[runar::contract]\nstruct P {\n    #[readonly]\n    limit: Int,\n}\n\nimpl P {\n    pub fn check(&self, value: Int, mode: bool) {\n        let mut result: Int = 0;\n{BODY}\n        assert!(result > 0);\n    }\n}\n',
    assign: (e) => `        result = ${e};`,
    ifWrap: braceIf('if mode {\n', '}\n'),
  },
  py: {
    head: 'from runar import SmartContract, Bigint, public, assert_\n\nclass P(SmartContract):\n    limit: Bigint\n\n    def __init__(self, limit: Bigint):\n        super().__init__(limit)\n        self.limit = limit\n\n    @public\n    def check(self, value: Bigint, mode: bool):\n        result: Bigint = 0\n{BODY}\n        assert_(result > 0)\n',
    assign: (e) => `        result = ${e}`,
    // One extra space of indentation per level keeps a 127-deep nest small.
    ifWrap: (n, inner) => {
      const lines: string[] = [];
      for (let i = 0; i < n; i++) lines.push('        ' + ' '.repeat(i) + 'if mode:');
      lines.push('        ' + ' '.repeat(n) + inner.trim());
      return lines.join('\n');
    },
  },
  zig: {
    head: 'const runar = @import("runar");\n\npub const P = struct {\n    pub const Contract = runar.SmartContract;\n    limit: i64,\n    pub fn init(limit: i64) P { return .{ .limit = limit }; }\n    pub fn check(self: *const P, value: i64, mode: bool) void {\n        var result: i64 = 0;\n{BODY}\n        runar.assert(result > 0);\n    }\n};\n',
    assign: (e) => `        result = ${e};`,
    ifWrap: braceIf('if (mode) {\n', '}\n'),
  },
  rb: {
    head: "require 'runar'\n\nclass P < Runar::SmartContract\n  prop :limit, Bigint\n\n  def initialize(limit)\n    super(limit)\n    @limit = limit\n  end\n\n  runar_public value: Bigint, mode: Boolean\n  def check(value, mode)\n    result = 0\n{BODY}\n    assert result > 0\n  end\nend\n",
    assign: (e) => `    result = ${e}`,
    ifWrap: braceIf('if mode\n', 'end\n'),
  },
  java: {
    head: 'package p;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\nimport runar.lang.annotations.Readonly;\nimport runar.lang.types.Bigint;\n\nimport static runar.lang.Builtins.assertThat;\n\nclass P extends SmartContract {\n    @Readonly Bigint limit;\n    P(Bigint limit) { super(limit); this.limit = limit; }\n    @Public\n    void check(Bigint value, boolean mode) {\n        Bigint result = Bigint.ZERO;\n{BODY}\n        assertThat(result.gt(Bigint.ZERO));\n    }\n}\n',
    assign: (e) => `        result = ${e};`,
    ifWrap: braceIf('if (mode) {\n', '}\n'),
  },
};

const SURFACES = Object.keys(TPL) as Surface[];

/** The source for `shape` at size `n` on `surface`. */
function source(surface: Surface, shape: Shape, n: number): string {
  const t = TPL[surface];
  let body: string;
  switch (shape) {
    case 'parens': body = t.assign('('.repeat(n) + 'value' + ')'.repeat(n)); break;
    case 'unary': body = t.assign('-('.repeat(n) + 'value' + ')'.repeat(n)); break;
    case 'chain': body = t.assign(Array(n).fill('value').join(' + ')); break;
    case 'if': body = t.ifWrap(n, t.assign('value').trim()); break;
  }
  return t.head.replace('{BODY}', body);
}

/**
 * Largest accepted / smallest refused size per shape (spec in input-limits.ts):
 *   parens  (A) = n + 2      if  (A) = (B) = n + 2
 *   unary   (A) = 2n + 2     chain (B) = k + 1
 */
const BOUNDARY: Record<Shape, { accept: number; refuse: number }> = {
  parens: { accept: L - 2, refuse: L - 1 },
  if: { accept: L - 2, refuse: L - 1 },
  unary: { accept: (L - 2) / 2, refuse: (L - 2) / 2 + 1 },
  chain: { accept: L - 1, refuse: L },
};

function run(surface: Surface, shape: Shape, n: number) {
  return compile(source(surface, shape, n), { fileName: `P.runar.${surface}` });
}

describe('F-213: MAX_SOURCE_NESTING is a shared, enforced limit', () => {
  it('is 128, well above the deepest checked-in contract (combined depth 14)', () => {
    expect(L).toBe(128);
  });

  for (const surface of SURFACES) {
    describe(`.runar.${surface}`, () => {
      for (const shape of Object.keys(BOUNDARY) as Shape[]) {
        const { accept, refuse } = BOUNDARY[shape];

        it(`${shape}: accepts n=${accept} (at the limit)`, () => {
          const r = run(surface, shape, accept);
          const errs = r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
          expect(errs).toEqual([]);
          expect(r.success).toBe(true);
          expect(r.scriptHex).toMatch(/^[0-9a-f]+$/);
        });

        it(`${shape}: refuses n=${refuse} (one past) with the shared diagnostic`, () => {
          const r = run(surface, shape, refuse);
          expect(r.success).toBe(false);
          expect(r.diagnostics.map((d) => d.message)).toContain(DIAG);
        });

        // Python's nested `if` costs one indentation column per level, so 20 000
        // levels would blow MAX_SOURCE_BYTES first; 2 500 levels is ~3.1 MB.
        const deep = surface === 'py' && shape === 'if' ? 2500 : 20000;
        it(`${shape}: refuses n=${deep} with the shared diagnostic, no RangeError`, () => {
          const r = run(surface, shape, deep);
          expect(r.success).toBe(false);
          const msgs = r.diagnostics.map((d) => d.message);
          expect(msgs).toContain(DIAG);
          expect(msgs.join('\n')).not.toMatch(/call stack/i);
        });
      }

      it('chain: refuses a 500 000-term chain (just under MAX_SOURCE_BYTES)', () => {
        const src = source(surface, 'chain', 500_000);
        expect(Buffer.byteLength(src)).toBeLessThan(InputLimits.MAX_SOURCE_BYTES);
        const r = compile(src, { fileName: `P.runar.${surface}` });
        expect(r.success).toBe(false);
        expect(r.diagnostics.map((d) => d.message)).toContain(DIAG);
      });
    });
  }

  it('the per-format export parseSolSource enforces the limit too', () => {
    const r = parseSolSource(source('sol', 'parens', BOUNDARY.parens.refuse), 'P.runar.sol');
    expect(r.contract).toBeNull();
    expect(r.errors.map((d) => d.message)).toContain(DIAG);
  });
});
