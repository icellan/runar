import { describe, it, expect, beforeAll } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers, compileHex, judge } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * F-213 — seven-tier gate for the shared source-nesting limit.
 *
 * Before F-213 no tier bounded nesting, and the tiers failed differently on the
 * same input (measured on the CLIs, n = nesting levels):
 *
 *   rust  SIGABRT (stack overflow) — 2000 parens on .ts/.py, 5000 on all nine
 *         surfaces, and a 500 000-term `a + a + …` chain even under --parse-only
 *   zig   SIGABRT on a 5000-term chain, all nine surfaces
 *   ts    `Maximum call stack size exceeded` from 512-2000 levels
 *   python `maximum recursion depth exceeded` already at 128 parens / 128 ifs
 *   ruby  SystemStackError, java StackOverflowError (exit 1 / 65)
 *   go    accepted everything (growable stacks) — no limit at all
 *
 * The limit is InputLimits.MAX_SOURCE_NESTING (128), defined with both of its
 * measures in packages/runar-ir-schema/src/input-limits.ts. Every tier must
 * refuse past it with the ONE diagnostic below and accept, byte-identically,
 * right at it.
 *
 * Proves, for every available tier on all nine surfaces: each canonical shape
 * at the limit compiles to the TS reference's bytes (both fold modes); one past
 * the limit it is refused — a real verdict (no signal, no usage/launcher error)
 * naming the shared diagnostic; and 20 000 nested parens and a 500 000-term
 * chain (just under MAX_SOURCE_BYTES) are refused the same way — no abort.
 * Does not prove: shapes other than these four (nested calls, ternary chains,
 * nested types are bounded by the same counters but not pinned here), nor that
 * 128 is the right number — see the corpus measurement in input-limits.ts.
 */

const L = 128;
/** Each case spawns every tier (14 for the at-limit cases); tsx alone pays ~1 s per spawn. */
const CASE_TIMEOUT_MS = 600_000;
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

/** Largest accepted / smallest refused size per shape (measures in input-limits.ts). */
const BOUNDARY: Record<Shape, { accept: number; refuse: number }> = {
  parens: { accept: L - 2, refuse: L - 1 },
  if: { accept: L - 2, refuse: L - 1 },
  unary: { accept: (L - 2) / 2, refuse: (L - 2) / 2 + 1 },
  chain: { accept: L - 1, refuse: L },
};

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF_TIERS: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'f213-nesting-'));
});

let seq = 0;
function write(surface: Surface, text: string): string {
  const sub = join(dir, String(seq++));
  mkdirSync(sub, { recursive: true });
  const p = join(sub, `P.runar.${surface}`);
  writeFileSync(p, text);
  return p;
}

describe('F-213 seven-tier source-nesting limit', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const surface of SURFACES) {
    describe(`.runar.${surface}`, () => {
      for (const shape of Object.keys(BOUNDARY) as Shape[]) {
        const { accept, refuse } = BOUNDARY[shape];

        for (const [mode, tiers] of [
          ['fold-on', TIERS],
          ['fold-off', FOLD_OFF_TIERS],
        ] as const) {
          it(`${shape} n=${accept} (at the limit, ${mode}): every tier emits the TS bytes`, () => {
            const file = write(surface, source(surface, shape, accept));
            const ts = tiers.find((t) => t.id === 'ts');
            expect(ts, 'the TS reference tier is required').toBeDefined();
            const want = compileHex(ts!, file);
            for (const tier of tiers) {
              expect(compileHex(tier, file), `${tier.id} on ${shape} n=${accept}`).toBe(want);
            }
          }, CASE_TIMEOUT_MS);
        }

        it(`${shape} n=${refuse} (one past): every tier refuses with the shared diagnostic`, () => {
          const file = write(surface, source(surface, shape, refuse));
          for (const tier of TIERS) {
            const { verdict, diag } = judge(tier, file);
            expect(verdict, `${tier.id} accepted ${shape} n=${refuse}`).toBe('rejected');
            expect(diag, `${tier.id} refused ${shape} n=${refuse} for another reason`).toContain(DIAG);
          }
        }, CASE_TIMEOUT_MS);
      }

      const deep: Array<[Shape, number]> = [['parens', 20000], ['chain', 500000]];
      for (const [shape, n] of deep) {
        it(`${shape} n=${n}: every tier refuses with the shared diagnostic, none aborts`, () => {
          const file = write(surface, source(surface, shape, n));
          for (const tier of TIERS) {
            const { verdict, diag } = judge(tier, file);
            expect(verdict, `${tier.id} accepted ${shape} n=${n}`).toBe('rejected');
            expect(diag, `${tier.id} refused ${shape} n=${n} for another reason`).toContain(DIAG);
          }
        }, CASE_TIMEOUT_MS);
      }
    });
  }
});
