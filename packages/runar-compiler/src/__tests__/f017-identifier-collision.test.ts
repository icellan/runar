import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { parse } from '../passes/01-parse.js';
import { identifierCollisionMessage } from '../passes/snake-to-camel.js';

/**
 * F-017 — two distinct source identifiers that the surface's name conversion
 * maps to ONE Rúnar name are refused.
 *
 * Five surfaces rename identifiers on the way into the AST: `.runar.py`,
 * `.runar.rs`, `.runar.rb`, `.runar.move` (snake_case -> camelCase, plus the
 * Python/Ruby underscore-strip conventions) and `.runar.go` (PascalCase ->
 * camelCase). None of those mappings is injective, and before this rule the
 * compiler bound both spellings to the same variable. So
 *
 *     tmp = n + 1
 *     tmp_ = n + 2
 *     assert_(tmp == tmp_)      # always false under Python semantics
 *
 * compiled to `... OP_DUP OP_DUP OP_NUMEQUAL ...`: the second binding compared
 * with a copy of itself, an always-TRUE guard. The execution proof (real
 * `@bsv/sdk` Spend) lives in
 * packages/runar-testing/src/__tests__/f017-identifier-collision-spend.test.ts.
 *
 * What this proves: the reference tier refuses, with the one shared
 * diagnostic text, every collision shape below on all five renaming surfaces
 * (local/local, param/local, property/local, property/param, method/method,
 * loop variable/local); it still accepts the non-colliding controls,
 * including `sum_` on its own (the keyword-avoidance convention) and one
 * spelling reused across methods.
 * What it does NOT prove: anything about the other six tiers (their own
 * suites + conformance/negatives/N46-N50 cover that), or anything about a
 * local that SHADOWS a property under the SAME spelling — that is not a
 * naming collision and is outside this rule.
 */

const msg = (a: string, b: string, name: string) =>
  `identifier collision: '${a}' and '${b}' both convert to '${name}'; rename one of them`;

function errorsOf(source: string, fileName: string): string[] {
  const r = compile(source, { fileName });
  return r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
}

function expectRefused(source: string, fileName: string, expected: string): void {
  const r = compile(source, { fileName });
  expect(r.success, `${fileName} compiled; it must be refused`).toBe(false);
  const errors = r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
  expect(errors).toContain(expected);
  // The frontend itself refuses (CompileCheck-style callers see it too).
  expect(parse(source, fileName).errors.map((e) => e.message)).toContain(expected);
}

function expectAccepted(source: string, fileName: string): void {
  expect(errorsOf(source, fileName)).toEqual([]);
}

// ---------------------------------------------------------------------------
// The rule itself
// ---------------------------------------------------------------------------

describe('F-017 identifierCollisionMessage (the shared rule)', () => {
  it('is null when every Rúnar name has exactly one source spelling', () => {
    expect(identifierCollisionMessage([['tmp', 'tmp'], ['tmp', 'tmp'], ['sum_', 'sum'], ['a_b', 'aB']])).toBeNull();
  });

  it('reports a collision between two distinct spellings', () => {
    expect(identifierCollisionMessage([['tmp', 'tmp'], ['tmp_', 'tmp']])).toBe(msg('tmp', 'tmp_', 'tmp'));
  });

  it('is independent of declaration order: smallest name, then its two smallest spellings', () => {
    const decls: Array<[string, string]> = [
      ['z_', 'z'], ['z', 'z'],
      ['b__c', 'bC'], ['b_c', 'bC'], ['bC', 'bC'],
    ];
    const expected = msg('bC', 'b__c', 'bC');
    expect(identifierCollisionMessage(decls)).toBe(expected);
    expect(identifierCollisionMessage([...decls].reverse())).toBe(expected);
  });
});

// ---------------------------------------------------------------------------
// .runar.py
// ---------------------------------------------------------------------------

const PY = (body: string, extra = '') => `from runar import SmartContract, Bigint, public, assert_


class Trail(SmartContract):
    k: Bigint
${extra}
    def __init__(self, k: Bigint):
        super().__init__(k)
        self.k = k

    @public
    def unlock(self, n: Bigint):
${body}
`;

describe('F-017 .runar.py', () => {
  const F = 'Trail.runar.py';

  it('refuses tmp / tmp_ (the always-false guard)', () => {
    expectRefused(PY('        tmp = n + 1\n        tmp_ = n + 2\n        assert_(tmp == tmp_)'), F, msg('tmp', 'tmp_', 'tmp'));
  });
  it('refuses a_b / aB, _tmp / tmp, a__b / a_b, tmp / tmp__', () => {
    expectRefused(PY('        a_b = n + 1\n        aB = n + 2\n        assert_(a_b == aB)'), F, msg('aB', 'a_b', 'aB'));
    expectRefused(PY('        _tmp = n + 1\n        tmp = n + 2\n        assert_(_tmp == tmp)'), F, msg('_tmp', 'tmp', 'tmp'));
    expectRefused(PY('        a__b = n + 1\n        a_b = n + 2\n        assert_(a__b == a_b)'), F, msg('a__b', 'a_b', 'aB'));
    expectRefused(PY('        tmp = n + 1\n        tmp__ = n + 2\n        assert_(tmp == tmp__)'), F, msg('tmp', 'tmp__', 'tmp'));
  });
  it('refuses a local that collides with a parameter', () => {
    expectRefused(PY('        n_ = n + 1\n        assert_(n_ == n)'), F, msg('n', 'n_', 'n'));
  });
  it('refuses a local that collides with a property', () => {
    expectRefused(PY('        k_ = n + 1\n        assert_(k_ == self.k)'), F, msg('k', 'k_', 'k'));
  });
  it('refuses a loop variable that collides with a local', () => {
    expectRefused(PY('        acc = n\n        for i_ in range(3):\n            acc = acc + 1\n        i = acc\n        assert_(i == n + 3)'), F, msg('i', 'i_', 'i'));
  });
  it('refuses two method names that collide', () => {
    const src = PY('        assert_(self.helper(n) == self._helper(n))',
      '\n    def helper(self, v: Bigint) -> Bigint:\n        return v + 1\n\n    def _helper(self, v: Bigint) -> Bigint:\n        return v + 2\n');
    expectRefused(src, F, msg('_helper', 'helper', 'helper'));
  });
  it('accepts distinct names, sum_ on its own, and one spelling reused', () => {
    expectAccepted(PY('        x = n + 1\n        y = n + 2\n        assert_(x != y)'), F);
    expectAccepted(PY('        sum_ = n + 1\n        sum_ = sum_ + 1\n        assert_(sum_ == n + 2)'), F);
    const ast = parse(PY('        sum_ = n + 1\n        assert_(sum_ == n + 1)'), F).contract!;
    const unlock = ast.methods.find((m) => m.name === 'unlock')!;
    expect(unlock.body[0]).toMatchObject({ kind: 'variable_decl', name: 'sum' });
  });
});

// ---------------------------------------------------------------------------
// .runar.rs
// ---------------------------------------------------------------------------

const RS = (body: string, fields = '    #[readonly]\n    k: Int,\n', extraFns = '') => `use runar::prelude::*;

#[runar::contract]
struct Trail {
${fields}}

impl Trail {
${extraFns}    pub fn unlock(&self, n: Int) {
${body}
    }
}
`;

describe('F-017 .runar.rs', () => {
  const F = 'Trail.runar.rs';

  it('refuses tmp / tmp_ and a__b / a_b', () => {
    expectRefused(RS('        let tmp = n + 1;\n        let tmp_ = n + 2;\n        assert!(tmp == tmp_);'), F, msg('tmp', 'tmp_', 'tmp'));
    expectRefused(RS('        let a__b = n + 1;\n        let a_b = n + 2;\n        assert!(a__b == a_b);'), F, msg('a__b', 'a_b', 'aB'));
  });
  it('refuses a local that collides with a field', () => {
    expectRefused(RS('        let p_q = n + 1;\n        assert!(p_q == self.pQ);', '    #[readonly]\n    pQ: Int,\n'), F, msg('pQ', 'p_q', 'pQ'));
  });
  it('refuses two method names that collide', () => {
    expectRefused(
      RS('        assert!(self.do_it(n) == self.doIt(n));', undefined,
        '    fn do_it(&self, v: Int) -> Int {\n        v + 1\n    }\n\n    fn doIt(&self, v: Int) -> Int {\n        v + 2\n    }\n\n'),
      F, msg('doIt', 'do_it', 'doIt'));
  });
  it('accepts distinct names and Rust shadowing under one spelling', () => {
    expectAccepted(RS('        let x = n + 1;\n        let y = n + 2;\n        assert!(x != y);'), F);
    expectAccepted(RS('        let x = n + 1;\n        let x = x + 1;\n        assert!(x == n + 2);'), F);
  });
});

// ---------------------------------------------------------------------------
// .runar.rb
// ---------------------------------------------------------------------------

const RB = (body: string) => `require 'runar'

class Trail < Runar::SmartContract
  prop :k, Bigint

  def initialize(k)
    super(k)
    @k = k
  end

  runar_public n: Bigint
  def unlock(n)
${body}
  end
end
`;

describe('F-017 .runar.rb', () => {
  const F = 'Trail.runar.rb';

  it('refuses tmp / tmp_ and _tmp / tmp', () => {
    expectRefused(RB('    tmp = n + 1\n    tmp_ = n + 2\n    assert tmp == tmp_'), F, msg('tmp', 'tmp_', 'tmp'));
    expectRefused(RB('    _tmp = n + 1\n    tmp = n + 2\n    assert _tmp == tmp'), F, msg('_tmp', 'tmp', 'tmp'));
  });
  it('accepts distinct names', () => {
    expectAccepted(RB('    x = n + 1\n    y = n + 2\n    assert x != y'), F);
  });
});

// ---------------------------------------------------------------------------
// .runar.move
// ---------------------------------------------------------------------------

const MOVE = (body: string) => `module Trail {
    use runar::types::{Int};

    struct Trail {
        k: Int,
    }

    public fun unlock(contract: &Trail, n: Int) {
${body}
    }
}
`;

describe('F-017 .runar.move', () => {
  const F = 'Trail.runar.move';

  it('refuses tmp / tmp_', () => {
    expectRefused(MOVE('        let tmp = n + 1;\n        let tmp_ = n + 2;\n        assert!(tmp == tmp_, 0);'), F, msg('tmp', 'tmp_', 'tmp'));
  });
  it('accepts distinct names', () => {
    expectAccepted(MOVE('        let x = n + 1;\n        let y = n + 2;\n        assert!(x != y, 0);'), F);
  });
});

// ---------------------------------------------------------------------------
// .runar.go (PascalCase -> camelCase)
// ---------------------------------------------------------------------------

const GO = (body: string, extra = '') => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Trail struct {
	runar.SmartContract
	K runar.Int \`runar:"readonly"\`
}
${extra}
func (c *Trail) Unlock(n runar.Int) {
${body}
}
`;

describe('F-017 .runar.go', () => {
  const F = 'Trail.runar.go';

  it('refuses Tmp / tmp', () => {
    expectRefused(GO('\tTmp := n + 1\n\ttmp := n + 2\n\trunar.Assert(Tmp == tmp)'), F, msg('Tmp', 'tmp', 'tmp'));
  });
  it('refuses a local that collides with a field (K / k)', () => {
    expectRefused(GO('\tk := n + 1\n\trunar.Assert(k == c.K)'), F, msg('K', 'k', 'k'));
  });
  it('refuses two method names that collide (Unlock / unlock)', () => {
    expectRefused(GO('\trunar.Assert(c.unlock(n) == n)', '\nfunc (c *Trail) unlock(v runar.Int) runar.Int {\n\treturn v + 1\n}\n'), F, msg('Unlock', 'unlock', 'unlock'));
  });
  it('accepts distinct names', () => {
    expectAccepted(GO('\tx := n + 1\n\ty := n + 2\n\trunar.Assert(x != y)'), F);
  });
});
