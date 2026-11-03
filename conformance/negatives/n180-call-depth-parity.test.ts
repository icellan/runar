import { describe, it, expect, beforeAll } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers, compileHex, judge } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-180 — seven-tier gate for the shared call-depth limit.
 *
 * A chain of private helpers `verify -> m0 -> m1 -> ... -> mN` is flat source
 * (MAX_SOURCE_NESTING never fires) but N+1 nested inlinings. Before N-180 the
 * tiers failed differently on it (measured on the CLIs):
 *
 *   rust   SIGABRT (stack overflow) at N=8000
 *   zig    segfault (stack overflow in stack_lower's inlining) at N=4000
 *   ruby   uncaught SystemStackError from the recursion check at N=2000
 *   java   uncaught StackOverflowError at N=8000; >115 s CPU at N=2000
 *   go     >156 s CPU at N=20000 (quadratic recursion check)
 *   python `maximum recursion depth exceeded`; ts `Maximum call stack size exceeded`
 *
 * The limit is InputLimits.MAX_CALL_DEPTH (128), defined with its measure in
 * packages/runar-ir-schema/src/input-limits.ts: `verify` in the chain below has
 * call depth N+1. Every tier must refuse past it with the ONE diagnostic below
 * (naming the first method in declaration order past the bound) and accept,
 * byte-identically, right at it.
 *
 * Proves, for every available tier on all nine surfaces: the chain at the limit
 * (N=127) compiles to the TS reference's bytes (both fold modes); one past
 * (N=128) is refused naming `verify` — a real verdict (no signal, no
 * usage/launcher error); N=20000 (~1 MB) is refused naming `m0`, no abort,
 * within the harness timeout.
 * Does not prove: call graphs other than a chain (a DAG is measured by the same
 * longest-path rule but not pinned here), the --ir path (an externally supplied
 * ANF program never meets the source validator), nor that 128 is the right
 * number — see the measurement in input-limits.ts.
 */

const L = 128;
/** Each case spawns every tier (14 for the at-limit cases); tsx alone pays ~1 s per spawn. */
const CASE_TIMEOUT_MS = 600_000;
const DIAG = (m: string) => `call depth of method '${m}' exceeds MAX_CALL_DEPTH (limit=${L})`;

type Surface = 'ts' | 'sol' | 'move' | 'go' | 'rs' | 'py' | 'zig' | 'rb' | 'java';

/** The chain m0 -> ... -> mN on `surface` (remediation-logs/F-213/refute/chaingen.py). */
function chain(surface: Surface, n: number): string {
  const range = (f: (i: number) => string) => Array.from({ length: n }, (_, i) => f(i)).join('');
  switch (surface) {
    case 'ts':
      return "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n"
        + range((i) => ` private m${i}(x: bigint): bigint { return this.m${i + 1}(x); }\n`)
        + ` private m${n}(x: bigint): bigint { return x; }\n public verify(a: bigint) { assert(this.m0(a) == this.t); }\n}\n`;
    case 'sol':
      return 'pragma runar ^0.1.0;\ncontract P is SmartContract {\n int immutable t;\n constructor(int _t) { t = _t; }\n'
        + range((i) => ` function m${i}(int x) private returns (int) { return m${i + 1}(x); }\n`)
        + ` function m${n}(int x) private returns (int) { return x; }\n function verify(int a) public { require(m0(a) == t); }\n}\n`;
    case 'go':
      return 'package contract\n\nimport runar "github.com/icellan/runar/packages/runar-go"\n\ntype P struct {\n\trunar.SmartContract\n\tT runar.Int `runar:"readonly"`\n}\n\n'
        + range((i) => `func (c *P) m${i}(x runar.Int) runar.Int { return c.m${i + 1}(x) }\n`)
        + `func (c *P) m${n}(x runar.Int) runar.Int { return x }\nfunc (c *P) Verify(a runar.Int) { runar.Assert(c.m0(a) == c.T) }\n`;
    case 'py':
      return 'from runar import SmartContract, Bigint, public, assert_\n\nclass P(SmartContract):\n    t: Bigint\n\n    def __init__(self, t: Bigint):\n        super().__init__(t)\n        self.t = t\n\n'
        + range((i) => `    def m${i}(self, x: Bigint) -> Bigint:\n        return self.m${i + 1}(x)\n\n`)
        + `    def m${n}(self, x: Bigint) -> Bigint:\n        return x\n\n    @public\n    def verify(self, a: Bigint):\n        assert_(self.m0(a) == self.t)\n`;
    case 'rb':
      return "require 'runar'\n\nclass P < Runar::SmartContract\n  prop :t, Bigint\n\n  def initialize(t)\n    super(t)\n    @t = t\n  end\n\n"
        + range((i) => `  params x: Bigint\n  def m${i}(x)\n    m${i + 1}(x)\n  end\n`)
        + `  params x: Bigint\n  def m${n}(x)\n    x\n  end\n\n  runar_public a: Bigint\n  def verify(a)\n    assert m0(a) == @t\n  end\nend\n`;
    case 'java':
      return 'package p;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\nimport runar.lang.annotations.Readonly;\nimport runar.lang.types.Bigint;\nimport static runar.lang.Builtins.assertThat;\n\nclass P extends SmartContract {\n    @Readonly Bigint t;\n    P(Bigint t) { super(t); this.t = t; }\n'
        + range((i) => `    private Bigint m${i}(Bigint x) { return m${i + 1}(x); }\n`)
        + `    private Bigint m${n}(Bigint x) { return x; }\n    @Public\n    void verify(Bigint a) { assertThat(m0(a).eq(this.t)); }\n}\n`;
    case 'rs':
      return 'use runar::prelude::*;\n\n#[runar::contract]\nstruct P {\n #[readonly]\n t: Int,\n}\n\nimpl P {\n'
        + range((i) => ` fn m${i}(&self, x: Int) -> Int { self.m${i + 1}(x) }\n`)
        + ` fn m${n}(&self, x: Int) -> Int { x }\n pub fn verify(&self, a: Int) { assert!(self.m0(a) == self.t); }\n}\n`;
    case 'zig':
      return 'const runar = @import("runar");\n\npub const P = struct {\n    pub const Contract = runar.SmartContract;\n    t: i64,\n    pub fn init(t: i64) P { return .{ .t = t }; }\n'
        + range((i) => `    fn m${i}(self: *const P, x: i64) i64 { return self.m${i + 1}(x); }\n`)
        + `    fn m${n}(self: *const P, x: i64) i64 { return x; }\n    pub fn verify(self: *const P, a: i64) void { runar.assert(self.m0(a) == self.t); }\n};\n`;
    case 'move':
      return 'module P {\n use runar::types::{Int};\n struct P { t: Int, }\n'
        + range((i) => ` fun m${i}(contract: &P, x: Int): Int { m${i + 1}(contract, x) }\n`)
        + ` fun m${n}(contract: &P, x: Int): Int { x }\n public fun verify(contract: &P, a: Int) { assert_eq!(m0(contract, a), contract.t); }\n}\n`;
  }
}

const SURFACES: Surface[] = ['ts', 'sol', 'move', 'go', 'rs', 'py', 'zig', 'rb', 'java'];

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF_TIERS: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n180-call-depth-'));
});

let seq = 0;
function write(surface: Surface, text: string): string {
  const sub = join(dir, String(seq++));
  mkdirSync(sub, { recursive: true });
  const p = join(sub, `P.runar.${surface}`);
  writeFileSync(p, text);
  return p;
}

describe('N-180 seven-tier call-depth limit', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const surface of SURFACES) {
    describe(`.runar.${surface}`, () => {
      for (const [mode, tiers] of [
        ['fold-on', TIERS],
        ['fold-off', FOLD_OFF_TIERS],
      ] as const) {
        it(`N=${L - 1} (at the limit, ${mode}): every tier emits the TS bytes`, () => {
          const file = write(surface, chain(surface, L - 1));
          const ts = tiers.find((t) => t.id === 'ts');
          expect(ts, 'the TS reference tier is required').toBeDefined();
          const want = compileHex(ts!, file);
          for (const tier of tiers) {
            expect(compileHex(tier, file), `${tier.id} on N=${L - 1}`).toBe(want);
          }
        }, CASE_TIMEOUT_MS);
      }

      for (const [n, offender] of [[L, 'verify'], [20000, 'm0']] as const) {
        it(`N=${n}: every tier refuses with the shared diagnostic, none aborts`, () => {
          const file = write(surface, chain(surface, n));
          for (const tier of TIERS) {
            const { verdict, diag } = judge(tier, file);
            expect(verdict, `${tier.id} accepted N=${n}`).toBe('rejected');
            expect(diag, `${tier.id} refused N=${n} for another reason`).toContain(DIAG(offender));
          }
        }, CASE_TIMEOUT_MS);
      }
    });
  }
});
