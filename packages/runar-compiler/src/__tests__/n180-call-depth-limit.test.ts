import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { InputLimits } from 'runar-ir-schema';

/**
 * N-180 — a long chain of private helpers (verify -> m0 -> m1 -> ... -> mN) must
 * be REFUSED with one shared diagnostic, never crash the compiler.
 *
 * The source is flat (every method body is one statement), so F-213's
 * MAX_SOURCE_NESTING never fires; the depth lives in the call graph. Private
 * methods are inlined at every call site, so a chain of N helpers is N nested
 * inlinings. Before N-180, measured on the CLIs: Rust SIGABRT (stack overflow)
 * at N=8000, Zig segfault at N=4000, Ruby SystemStackError at N=2000, Java
 * StackOverflowError at N=8000 (and >115 s CPU at N=2000), Go >156 s CPU at
 * N=20000, Python/TS a stray RecursionError/RangeError. The recursion check
 * itself restarted its DFS from every method (quadratic) and recursed once
 * per link.
 *
 * The limit, `InputLimits.MAX_CALL_DEPTH`, bounds the longest chain of
 * contract-method calls starting at any method (a method that calls none has
 * depth 0). The canonical shape below — `verify` calls m0, mi calls mi+1, mN
 * calls none — gives `verify` depth N+1, so N = L-1 sits exactly at the limit.
 *
 * Proves: on every surface the TS tier accepts the chain at the limit, refuses it
 * one past with the shared diagnostic naming `verify`, and refuses a
 * 20 000-link chain the same way within the test timeout, with no RangeError.
 * Also: a recursive helper is still reported as recursion (not as depth), with
 * the same per-method diagnostics as before.
 * Does not prove: the other six tiers (conformance/negatives/
 * n180-call-depth-parity.test.ts drives all seven CLIs); the --ir path (an
 * externally supplied ANF program never meets this source validator).
 */

const L = InputLimits.MAX_CALL_DEPTH;
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

function run(surface: Surface, n: number) {
  return compile(chain(surface, n), { fileName: `P.runar.${surface}` });
}

describe('N-180: MAX_CALL_DEPTH is a shared, enforced limit', () => {
  it('is 128', () => {
    expect(L).toBe(128);
  });

  for (const surface of SURFACES) {
    describe(`.runar.${surface}`, () => {
      it(`accepts a chain of N=${L - 1} helpers (verify at depth ${L})`, () => {
        const r = run(surface, L - 1);
        const errs = r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
        expect(errs).toEqual([]);
        expect(r.success).toBe(true);
        expect(r.scriptHex).toMatch(/^[0-9a-f]+$/);
      });

      it(`refuses N=${L} (one past) with the shared diagnostic`, () => {
        const r = run(surface, L);
        expect(r.success).toBe(false);
        const errs = r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
        expect(errs).toEqual([DIAG('verify')]);
      });

      it('refuses N=20000 with the shared diagnostic, no RangeError', () => {
        const r = run(surface, 20000);
        expect(r.success).toBe(false);
        const msgs = r.diagnostics.map((d) => d.message);
        expect(msgs).toContain(DIAG('m0'));
        expect(msgs.join('\n')).not.toMatch(/call stack/i);
      });
    });
  }

  it('a cycle is reported as recursion, once per method that reaches it, not as depth', () => {
    const src = "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n"
      + ' private a(x: bigint): bigint { return this.b(x); }\n'
      + ' private b(x: bigint): bigint { return this.c(x); }\n'
      + ' private c(x: bigint): bigint { return this.b(x); }\n'
      + ' private d(x: bigint): bigint { return x; }\n'
      + ' public verify(v: bigint) { assert(this.a(v) + this.d(v) == this.t); }\n}\n';
    const r = compile(src, { fileName: 'P.runar.ts' });
    const errs = r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
    const rec = (m: string) => `Recursion detected: method '${m}' calls itself directly or indirectly. Recursion is not allowed in Rúnar contracts.`;
    expect(errs).toEqual([rec('a'), rec('b'), rec('c'), rec('verify')]);
  });
});
