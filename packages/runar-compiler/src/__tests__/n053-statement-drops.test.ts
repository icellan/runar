import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { parseZigSource } from '../passes/01-parse-zig.js';

/**
 * N-053 — silent statement drops in the .runar.zig / .runar.rb / .runar.py
 * statement dispatchers (reference tier).
 *
 * 1. `.runar.zig` `_ = expr;` parsed `expr` and returned no statement. A
 *    private helper called only for its asserts (`_ = self.check(x);`) lost
 *    its guard: Disc compiled to 5177 (OP_1 OP_NIP) and any x unlocked it.
 *    Zig's discard still evaluates the expression, so it now lowers to the
 *    expression statement `expr`. A bare name (`_ = self;`, the unused-binding
 *    idiom the examples use) is still dropped: reading a name has no effect.
 * 2. `.runar.rb` / `.runar.py`: any statement whose first token was not one
 *    the dispatcher knew was skipped ONE TOKEN AT A TIME. A Ruby private
 *    helper ending in `!(x == @t)` returned `x == @t` (the `!` and the
 *    parentheses were skipped), inverting the guard of every caller; `false`,
 *    `42`, `-x` vanished, and `@x + 1` returned `@x` (the ivar statement
 *    stopped after `@x`'s postfix chain). A token that can begin an expression now begins an
 *    expression statement; any other token is refused with the shared
 *    diagnostic "Unsupported statement starting with '<token>'".
 *
 * What this proves: in the reference tier, each shape compiles to the bytes
 * of its .runar.ts twin (so the guard is in the script), and the listed
 * non-expression starts are refused with the shared text.
 * What it does NOT prove: on-chain behaviour (the Spend-engine proof and the
 * seven-tier byte parity live in
 * conformance/negatives/n053-statement-drop-parity.test.ts); class-body token
 * skipping (N-004 / N-033, separate items).
 */

const errorsOf = (src: string, fileName: string): string[] =>
  compile(src, { fileName, disableConstantFolding: true }).diagnostics
    .filter((d) => d.severity === 'error')
    .map((d) => d.message);

function hexOf(src: string, fileName: string): string {
  const r = compile(src, { fileName, disableConstantFolding: true });
  expect(r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message)).toEqual([]);
  expect(r.success).toBe(true);
  return r.artifact!.script.toLowerCase();
}

const tsTwin = (unlockBody: string, helper: string): string => `import { SmartContract, assert } from 'runar-lang';

class Disc extends SmartContract {
  readonly t: bigint;

  constructor(t: bigint) {
    super(t);
    this.t = t;
  }

  public unlock(x: bigint) {
    ${unlockBody}
  }

  ${helper}
}
`;

const TS_CHECK = 'private check(x: bigint): bigint {\n    assert(x === this.t);\n    return x;\n  }';

// ---------------------------------------------------------------------------
// .runar.zig `_ = expr;`
// ---------------------------------------------------------------------------

const zig = (stmt: string): string => `const runar = @import("runar");

pub const Disc = struct {
    pub const Contract = runar.SmartContract;

    t: i64,

    pub fn init(t: i64) Disc {
        return .{ .t = t };
    }

    fn check(self: *const Disc, x: i64) i64 {
        runar.assert(x == self.t);
        return x;
    }

    pub fn unlock(self: *const Disc, x: i64) void {
        ${stmt}
        runar.assert(true);
    }
};
`;

describe('N-053 .runar.zig `_ = expr;` keeps the expression', () => {
  it('parses `_ = self.check(x);` to the expression statement self.check(x)', () => {
    const r = parseZigSource(zig('_ = self.check(x);'), 'Disc.runar.zig');
    expect(r.errors.filter((e) => e.severity === 'error')).toEqual([]);
    const unlock = r.contract!.methods.find((m) => m.name === 'unlock')!;
    expect(unlock.body[0]!.kind).toBe('expression_statement');
    const stmt = unlock.body[0] as { expression: { kind: string; callee: { kind: string; property?: string } } };
    expect(stmt.expression.kind).toBe('call_expr');
    expect(stmt.expression.callee.property).toBe('check');
  });

  it('the discarded helper call keeps its assert: same bytes as `this.check(x);`', () => {
    const want = hexOf(tsTwin('this.check(x);\n    assert(true);', TS_CHECK), 'Disc.runar.ts');
    expect(want).toBe('76009d5177');
    expect(hexOf(zig('_ = self.check(x);'), 'Disc.runar.zig')).toBe(want);
  });

  it('`_ = x;` lowers like the expression statement `x;`', () => {
    const want = hexOf(tsTwin('x;\n    assert(true);', TS_CHECK), 'Disc.runar.ts');
    expect(hexOf(zig('_ = x;'), 'Disc.runar.zig')).toBe(want);
  });
});

// ---------------------------------------------------------------------------
// .runar.rb statement dispatcher
// ---------------------------------------------------------------------------

const rb = (unlockBody: string, helperBody: string): string => `require 'runar'

class Disc < Runar::SmartContract
  prop :t, Bigint

  def initialize(t)
    super(t)
    @t = t
  end

  runar_public x: Bigint
  def unlock(x)
    ${unlockBody}
  end

  private

  params x: Bigint
  def _check(x)
    ${helperBody}
  end
end
`;

describe('N-053 .runar.rb statements are lowered or refused, never skipped', () => {
  it('a helper ending in `!(x == @t)` returns the negation (the guard is not inverted)', () => {
    const want = hexOf(
      tsTwin('assert(!this.check(x));', 'private check(x: bigint): boolean {\n    return !(x === this.t);\n  }'),
      'Disc.runar.ts',
    );
    expect(hexOf(rb('assert !_check(x)', '!(x == @t)'), 'Disc.runar.rb')).toBe(want);
  });

  it('a helper ending in a literal returns it (implicit return of `false`)', () => {
    const want = hexOf(
      tsTwin('assert(!this.check(x));', 'private check(x: bigint): boolean {\n    assert(x === this.t);\n    return false;\n  }'),
      'Disc.runar.ts',
    );
    expect(hexOf(rb('assert !_check(x)', 'assert x == @t\n    false'), 'Disc.runar.rb')).toBe(want);
  });

  it('a helper ending in `@t + 1` returns the sum (the `+ 1` is not dropped)', () => {
    const want = hexOf(
      tsTwin('assert(x === this.check(x));', 'private check(x: bigint): bigint {\n    return this.t + 1n;\n  }'),
      'Disc.runar.ts',
    );
    expect(hexOf(rb('assert x == _check(x)', '@t + 1'), 'Disc.runar.rb')).toBe(want);
  });

  const rbHelper = 'assert x == @t\n    x';
  const rbTwins: Array<[string, string]> = [
    ['(_check(x))', '(this.check(x));'],
    ['!_check(x)', '!this.check(x);'],
    ['-x', '-x;'],
    ['42', '42n;'],
    ['true', 'true;'],
  ];
  for (const [stmt, twin] of rbTwins) {
    it(`\`${stmt}\` is an expression statement (same bytes as \`${twin}\`)`, () => {
      const want = hexOf(tsTwin(`${twin}\n    assert(true);`, TS_CHECK), 'Disc.runar.ts');
      expect(hexOf(rb(`${stmt}\n    assert true`, rbHelper), 'Disc.runar.rb')).toBe(want);
    });
  }

  for (const tok of ['do', 'in', 'class', 'def']) {
    it(`a statement starting with \`${tok}\` is refused with the shared diagnostic`, () => {
      const src = rb(`${tok} assert x == @t\n    assert true`, rbHelper);
      expect(errorsOf(src, 'Disc.runar.rb')).toContain(`Unsupported statement starting with '${tok}'`);
    });
  }

  it('a statement starting with a symbol is refused', () => {
    expect(compile(rb(':foo\n    assert true', rbHelper), { fileName: 'Disc.runar.rb' }).success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// .runar.py statement dispatcher
// ---------------------------------------------------------------------------

const py = (stmt: string): string => `from runar import SmartContract, Bigint, public, assert_

class Disc(SmartContract):
    t: Bigint

    def __init__(self, t: Bigint):
        super().__init__(t)
        self.t = t

    @public
    def unlock(self, x: Bigint):
        ${stmt}
        assert_(True)

    def _check(self, x: Bigint) -> Bigint:
        assert_(x == self.t)
        return x
`;

describe('N-053 .runar.py statements are lowered or refused, never skipped', () => {
  const pyTwins: Array<[string, string]> = [
    ['(self._check(x))', '(this.check(x));'],
    ['not self._check(x) == x', '!(this.check(x) === x);'],
    ['-x', '-x;'],
    ['42', '42n;'],
    ['True', 'true;'],
  ];
  for (const [stmt, twin] of pyTwins) {
    it(`\`${stmt}\` is an expression statement (same bytes as \`${twin}\`)`, () => {
      const want = hexOf(tsTwin(`${twin}\n    assert(true);`, TS_CHECK), 'Disc.runar.ts');
      expect(hexOf(py(stmt), 'Disc.runar.py')).toBe(want);
    });
  }

  for (const tok of ['in', 'from', 'import', '@', 'elif', 'else']) {
    it(`a statement starting with \`${tok}\` is refused with the shared diagnostic`, () => {
      const stmt = tok === '@' ? '@public' : tok === 'elif' || tok === 'else' ? `${tok} x == self.t:\n            pass` : `${tok} x`;
      expect(errorsOf(py(stmt), 'Disc.runar.py')).toContain(`Unsupported statement starting with '${tok}'`);
    });
  }

  it('an unexpected indent is refused (the indented assert is not lifted out)', () => {
    const src = py('y = x\n            assert_(x == self.t)');
    expect(compile(src, { fileName: 'Disc.runar.py' }).success).toBe(false);
  });

  it('`pass` is still a no-op', () => {
    const want = hexOf(tsTwin('assert(true);', TS_CHECK), 'Disc.runar.ts');
    expect(hexOf(py('pass'), 'Disc.runar.py')).toBe(want);
  });
});
