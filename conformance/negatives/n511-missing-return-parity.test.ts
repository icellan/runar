import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-511 — a private method that declares a non-void return type must return a
 * value on every path. Every tier refuses one that does not, with one shared
 * diagnostic:
 *
 *   Method '<name>' declares return type '<type>' but does not return a value
 *   on every path
 *
 * Before the fix: an empty body or a bare `return;` was refused by all seven
 * tiers only by an internal stack-lowering error ("value 't2' not found on
 * stack"), and a conditional return (`if (c) { return x; }` with nothing on
 * the fall-through path) was ACCEPTED by all seven, the missing path
 * evaluating to OP_0.
 *
 * The rule (identical in every tier's type checker):
 *   - it applies to private methods whose declared return type is present and
 *     not void (Ruby spells no return type; Python `-> None` is void);
 *   - a statement list returns when one of its statements returns;
 *   - `return <value>` returns; an `if` returns only when it has an else and
 *     both arms return; a loop never counts;
 *   - a bare `return;` anywhere in such a method is itself a refusal;
 *   - tail value: an expression statement counts as a return when it is the
 *     last statement of an arm of an if/else that is itself last in its list,
 *     recursively up to the method body. This is the .runar.rs / .runar.move
 *     tail if-expression (`if c { x } else { 0 }`), which compiles to the same
 *     bytes as `if c { return x; } else { return 0; }` in every tier. A
 *     top-level trailing expression is NOT credited (the Rust and Move parsers
 *     turn it into a return themselves). The same AST spelled on another
 *     surface (`if (c) { x; } else { y; }` last in a TS helper) is therefore
 *     also accepted, as it is today.
 *
 * What this proves:
 *   - on the eight surfaces that spell a return type, every tier refuses the
 *     empty-body, bare-return and conditional-return helpers with the shared
 *     wording, naming the method (and, on .runar.ts, the conditional-return
 *     helper when no method calls it: the check is on the declaration, not on
 *     the inlined call — such a contract compiled before);
 *   - the same helper with a plain return, an if/else that returns in both
 *     arms, an early return followed by a trailing return, and an else-if
 *     chain ending in else is ACCEPTED by every tier (and on .runar.rs /
 *     .runar.move the implicit tail expression and tail if-expression too,
 *     and on .runar.rs a nested and a mixed return/tail if-expression).
 * What it does NOT prove:
 *   - that every legal helper in the checked-in corpus is still accepted: the
 *     all-format over-rejection sweep covers that;
 *   - the bytes of accepted programs (the conformance goldens cover that);
 *   - `.runar.rb` (no return-type syntax).
 */

const TIERS = buildSourceTiers();
const TMP = mkdtempSync(join(tmpdir(), 'n511-'));
const WORDING = /Method '_?helper' declares return type '[^']+' but does not return a value on every path/i;

type Bad = 'empty' | 'bare' | 'cond' | 'uncalled';
type Good = 'plain' | 'ifelse' | 'early' | 'elseif' | 'tail' | 'tailif' | 'tailnested' | 'tailmixed';
const BAD: Bad[] = ['empty', 'bare', 'cond', 'uncalled'];

interface Surface {
  ext: string;
  /** Helper bodies; a missing entry means the surface cannot spell it. */
  body: Partial<Record<Bad | Good, string>>;
  /** `called` false: the public method does not call the helper. */
  src: (body: string, called: boolean) => string;
}

const SURFACES: Surface[] = [
  {
    ext: 'ts',
    body: {
      empty: '',
      bare: 'return;',
      cond: 'if (x > 0n) { return x; }',
      uncalled: 'if (x > 0n) { return x; }',
      plain: 'return x;',
      ifelse: 'if (x > 0n) { return x; } else { return 0n; }',
      early: 'if (x > 0n) { return x; } return 0n;',
      elseif: 'if (x > 0n) { return x; } else if (x < 0n) { return 0n; } else { return 1n; }',
    },
    src: (b, called) => `import { SmartContract, assert } from 'runar-lang';
class Probe extends SmartContract {
  readonly target: bigint;
  constructor(target: bigint) { super(target); this.target = target; }
  private helper(x: bigint): bigint { ${b} }
  public verify(a: bigint): void {
    assert(${called ? 'this.helper(a)' : 'a'} === this.target);
  }
}
`,
  },
  {
    ext: 'sol',
    body: {
      empty: '',
      bare: 'return;',
      cond: 'if (x > 0) { return x; }',
      plain: 'return x;',
      ifelse: 'if (x > 0) { return x; } else { return 0; }',
      early: 'if (x > 0) { return x; } return 0;',
      // `else if` is spelled `else { if ... }`: the TS tier's .sol parser
      // refuses `else if` (pre-existing, unrelated to N-511).
      elseif: 'if (x > 0) { return x; } else { if (x < 0) { return 0; } else { return 1; } }',
    },
    src: (b) => `pragma runar ^0.1.0;
contract Probe is SmartContract {
    int immutable target;
    constructor(int _target) { target = _target; }
    function helper(int x) private returns (int) { ${b} }
    function verify(int a) public {
        require(this.helper(a) == target);
    }
}
`,
  },
  {
    ext: 'move',
    body: {
      empty: '',
      bare: 'return;',
      cond: 'if (x > 0) { return x; };',
      plain: 'return x;',
      ifelse: 'if (x > 0) { return x; } else { return 0; };',
      early: 'if (x > 0) { return x; }; return 0;',
      // `else { if ... }`: the TS and Ruby tiers' .move parsers refuse
      // `else if` (pre-existing, unrelated to N-511).
      elseif: 'if (x > 0) { return x; } else { if (x < 0) { return 0; } else { return 1; } };',
      tail: 'x',
      tailif: 'if (x > 0) { x } else { 0 }',
    },
    src: (b) => `module Probe {
    use runar::types::{Int};
    struct Probe { target: Int, }
    fun helper(x: Int): Int { ${b} }
    public fun verify(contract: &Probe, a: Int) {
        assert_eq!(helper(a), contract.target);
    }
}
`,
  },
  {
    ext: 'go',
    body: {
      empty: '',
      bare: 'return',
      cond: 'if x > 0 {\n\t\treturn x\n\t}',
      plain: 'return x',
      ifelse: 'if x > 0 {\n\t\treturn x\n\t} else {\n\t\treturn 0\n\t}',
      early: 'if x > 0 {\n\t\treturn x\n\t}\n\treturn 0',
      elseif: 'if x > 0 {\n\t\treturn x\n\t} else if x < 0 {\n\t\treturn 0\n\t} else {\n\t\treturn 1\n\t}',
    },
    src: (b) => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Probe struct {
	runar.SmartContract
	Target runar.Int \`runar:"readonly"\`
}

func (c *Probe) helper(x runar.Int) runar.Int {
	${b}
}

func (c *Probe) Verify(a runar.Int) {
	runar.Assert(c.helper(a) == c.Target)
}
`,
  },
  {
    ext: 'rs',
    body: {
      empty: '',
      bare: 'return;',
      cond: 'if x > 0 { return x; }',
      plain: 'return x;',
      ifelse: 'if x > 0 { return x; } else { return 0; }',
      early: 'if x > 0 { return x; } return 0;',
      // `else { if ... }`: the Go tier's .rs parser refuses `else if`
      // (pre-existing, unrelated to N-511).
      elseif: 'if x > 0 { return x; } else { if x < 0 { return 0; } else { return 1; } }',
      tail: 'x',
      tailif: 'if x > 0 { x } else { 0 }',
      tailnested: 'if x > 0 { x } else { if x < 0 { 0 } else { 1 } }',
      tailmixed: 'if x > 0 { return x; } else { 0 }',
    },
    src: (b) => `use runar::prelude::*;

#[runar::contract]
struct Probe {
    #[readonly]
    target: Int,
}

impl Probe {
    fn helper(&self, x: Int) -> Int {
        ${b}
    }

    pub fn verify(&self, a: Int) {
        assert!(self.helper(a) == self.target);
    }
}
`,
  },
  {
    ext: 'py',
    body: {
      empty: 'pass',
      bare: 'return',
      cond: 'if x > 0:\n            return x',
      plain: 'return x',
      ifelse: 'if x > 0:\n            return x\n        else:\n            return 0',
      early: 'if x > 0:\n            return x\n        return 0',
      elseif: 'if x > 0:\n            return x\n        elif x < 0:\n            return 0\n        else:\n            return 1',
    },
    src: (b) => `from runar import SmartContract, Bigint, public, assert_

class Probe(SmartContract):
    target: Bigint

    def __init__(self, target: Bigint):
        super().__init__(target)
        self.target = target

    def _helper(self, x: Bigint) -> Bigint:
        ${b}

    @public
    def verify(self, a: Bigint):
        assert_(self._helper(a) == self.target)
`,
  },
  {
    ext: 'zig',
    body: {
      empty: '',
      bare: 'return;',
      cond: 'if (x > 0) {\n            return x;\n        }',
      plain: 'return x;',
      ifelse: 'if (x > 0) {\n            return x;\n        } else {\n            return 0;\n        }',
      early: 'if (x > 0) {\n            return x;\n        }\n        return 0;',
      elseif: 'if (x > 0) {\n            return x;\n        } else if (x < 0) {\n            return 0;\n        } else {\n            return 1;\n        }',
    },
    src: (b) => `const runar = @import("runar");

pub const Probe = struct {
    pub const Contract = runar.SmartContract;

    target: i64,

    pub fn init(target: i64) Probe {
        return .{ .target = target };
    }

    fn helper(x: i64) i64 {
        ${b}
    }

    pub fn verify(self: *const Probe, a: i64) void {
        runar.assert(helper(a) == self.target);
    }
};
`,
  },
  {
    ext: 'java',
    body: {
      empty: '',
      bare: 'return;',
      cond: 'if (x.gt(Bigint.ZERO)) { return x; }',
      plain: 'return x;',
      ifelse: 'if (x.gt(Bigint.ZERO)) { return x; } else { return Bigint.ZERO; }',
      early: 'if (x.gt(Bigint.ZERO)) { return x; } return Bigint.ZERO;',
      elseif: 'if (x.gt(Bigint.ZERO)) { return x; } else if (x.lt(Bigint.ZERO)) { return Bigint.ZERO; } else { return Bigint.ONE; }',
    },
    src: (b) => `package runar.examples.probe;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

class Probe extends SmartContract {

    @Readonly Bigint target;

    Probe(Bigint target) {
        super(target);
        this.target = target;
    }

    private Bigint helper(Bigint x) {
        ${b}
    }

    @Public
    void verify(Bigint a) {
        assertThat(this.helper(a).eq(this.target));
    }
}
`,
  },
];

function write(s: Surface, variant: string): string {
  const dir = mkdtempSync(join(TMP, `${variant}-${s.ext}-`));
  const path = join(dir, `Probe.runar.${s.ext}`);
  writeFileSync(path, s.src(s.body[variant as Bad | Good]!, variant !== 'uncalled'));
  return path;
}

describe('N-511: every tier refuses a declared non-void private helper that does not return on every path', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const s of SURFACES) {
    it(`.runar.${s.ext}: empty / bare-return / conditional-return refused with the shared wording; returning helpers accepted`, () => {
      const got: Record<string, Record<string, string>> = {};
      const want: Record<string, Record<string, string>> = {};
      for (const variant of Object.keys(s.body)) {
        const path = write(s, variant);
        const bad = (BAD as string[]).includes(variant);
        got[variant] = {};
        want[variant] = {};
        for (const tier of TIERS) {
          const r = judge(tier, path);
          want[variant][tier.id] = bad ? 'refused (shared wording)' : 'accepted';
          if (bad) {
            got[variant][tier.id] =
              r.verdict === 'rejected' && WORDING.test(r.diag)
                ? 'refused (shared wording)'
                : `${r.verdict}: ${r.diag.trim().slice(0, 200)}`;
          } else {
            got[variant][tier.id] = r.verdict === 'accepted' ? 'accepted' : `${r.verdict}: ${r.diag.trim().slice(0, 200)}`;
          }
        }
      }
      expect(got).toEqual(want);
    }, 1_800_000);
  }
});
