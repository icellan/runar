import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-026 — a for-loop bound that is not an integer literal is refused by every
 * tier on every one of the nine surfaces, and every tier names the refusal
 * with the REFERENCE (TypeScript) tier's sentence for that bound shape:
 *
 *   - `this.<prop>` bound, or a bound that is an expression (`3 + 1`)
 *       -> "For loop bound must be a compile-time constant (literal or const variable)"
 *   - identifier bound (a parameter or a local, `const` or not)
 *       -> "Cannot determine loop bound at compile time. For-loop bounds must be integer literals."
 *
 * The reference splits the two because its validator trusts a bare identifier
 * ("could be a const") and ANF lowering is what finally refuses it. Before the
 * fix Go, Python, Ruby and Java used a lowercase variant of the first sentence
 * for every shape, and Rust used the first sentence for identifiers too. No
 * tier ever accepted an unsafe shape; only the wording differed.
 *
 * What this proves:
 *   - per (surface, shape, tier): the tier refuses, the diagnostic carries the
 *     reference sentence for that shape and NOT the other shape's sentence;
 *   - a literal bound (control) is accepted by every tier on every surface, so
 *     the refusals are about the bound and not the contract shape.
 * What it does NOT prove:
 *   - bound shapes outside this matrix (e.g. `N > i` with reversed operands);
 *   - the position/prefix wrapped around the sentence by each CLI;
 *   - any other non-`for` loop spelling (only Move `loop {}` is covered, below).
 */

const TIERS = buildSourceTiers();
const TMP = mkdtempSync(join(tmpdir(), 'n026-'));

const RUNTIME = 'For loop bound must be a compile-time constant (literal or const variable)';
const IDENT = 'Cannot determine loop bound at compile time. For-loop bounds must be integer literals.';

type Shape = 'rt' | 'param' | 'local' | 'expr' | 'lit';
const SHAPES: Shape[] = ['rt', 'param', 'local', 'expr', 'lit'];
const EXPECT: Record<Exclude<Shape, 'lit'>, [string, string]> = {
  rt: [RUNTIME, IDENT],
  expr: [RUNTIME, IDENT],
  param: [IDENT, RUNTIME],
  local: [IDENT, RUNTIME],
};

interface Surface {
  ext: string;
  template: string;
  header: Record<Shape, string>;
  local: string;
}

const SURFACES: Surface[] = [
  {
    ext: 'ts',
    template: `import { SmartContract, assert } from 'runar-lang';

class Probe extends SmartContract {
  readonly n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }

  public verify(x: bigint, k: bigint): void {
    let sum: bigint = 0n;
@LOCAL@    @HEADER@ {
      sum = sum + i + 10n;
    }
    assert(sum === x);
  }
}
`,
    header: {
      rt: 'for (let i: bigint = 0n; i < this.n; i++)',
      param: 'for (let i: bigint = 0n; i < k; i++)',
      local: 'for (let i: bigint = 0n; i < lim; i++)',
      expr: 'for (let i: bigint = 0n; i < 3n + 1n; i++)',
      lit: 'for (let i: bigint = 0n; i < 3n; i++)',
    },
    local: '    const lim: bigint = 3n;\n',
  },
  {
    ext: 'sol',
    template: `pragma runar ^0.1.0;

contract Probe is SmartContract {
    int immutable n;

    constructor(int _n) {
        n = _n;
    }

    function verify(int x, int k) public {
        int sum = 0;
@LOCAL@        @HEADER@ {
            sum = sum + i + 10;
        }
        require(sum == x);
    }
}
`,
    header: {
      rt: 'for (int i = 0; i < n; i++)',
      param: 'for (int i = 0; i < k; i++)',
      local: 'for (int i = 0; i < lim; i++)',
      expr: 'for (int i = 0; i < 3 + 1; i++)',
      lit: 'for (int i = 0; i < 3; i++)',
    },
    local: '        int lim = 3;\n',
  },
  {
    ext: 'move',
    template: `module Probe {
    use runar::types::{Int};

    struct Probe {
        n: Int,
    }

    public fun verify(contract: &Probe, x: Int, k: Int) {
        let sum: Int = 0;
@LOCAL@        @HEADER@ {
            sum = sum + i + 10;
            i = i + 1;
        };
        assert_eq!(sum, x);
    }
}
`,
    header: {
      rt: 'let i: Int = 0;\n        while (i < contract.n)',
      param: 'let i: Int = 0;\n        while (i < k)',
      local: 'let i: Int = 0;\n        while (i < lim)',
      expr: 'let i: Int = 0;\n        while (i < 3 + 1)',
      lit: 'let i: Int = 0;\n        while (i < 3)',
    },
    local: '        let lim: Int = 3;\n',
  },
  {
    ext: 'go',
    template: `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Probe struct {
    runar.SmartContract
    N runar.Int \`runar:"readonly"\`
}

func (c *Probe) Verify(x runar.Int, k runar.Int) {
    sum := runar.Int(0)
@LOCAL@    @HEADER@ {
        sum = sum + i + 10
    }
    runar.Assert(sum == x)
}
`,
    header: {
      rt: 'for i := runar.Int(0); i < c.N; i++',
      param: 'for i := runar.Int(0); i < k; i++',
      local: 'for i := runar.Int(0); i < lim; i++',
      expr: 'for i := runar.Int(0); i < 3 + 1; i++',
      lit: 'for i := runar.Int(0); i < 3; i++',
    },
    local: '    lim := runar.Int(3)\n',
  },
  {
    ext: 'rs',
    template: `use runar::prelude::*;

#[runar::contract]
struct Probe {
    #[readonly]
    n: Int,
}

impl Probe {
    pub fn verify(&self, x: Int, k: Int) {
        let mut sum: Int = 0;
@LOCAL@        @HEADER@ {
            sum = sum + i + 10;
        }
        assert!(sum == x);
    }
}
`,
    header: {
      rt: 'for i in 0..self.n',
      param: 'for i in 0..k',
      local: 'for i in 0..lim',
      expr: 'for i in 0..3 + 1',
      lit: 'for i in 0..3',
    },
    local: '        let lim: Int = 3;\n',
  },
  {
    ext: 'py',
    template: `from runar import SmartContract, Bigint, public, assert_

class Probe(SmartContract):
    n: Bigint

    def __init__(self, n: Bigint):
        super().__init__(n)
        self.n = n

    @public
    def verify(self, x: Bigint, k: Bigint):
        sum_: Bigint = 0
@LOCAL@        @HEADER@:
            sum_ = sum_ + i + 10
        assert_(sum_ == x)
`,
    header: {
      rt: 'for i in range(self.n)',
      param: 'for i in range(k)',
      local: 'for i in range(lim)',
      expr: 'for i in range(3 + 1)',
      lit: 'for i in range(3)',
    },
    local: '        lim: Bigint = 3\n',
  },
  {
    ext: 'zig',
    template: `const runar = @import("runar");

pub const Probe = struct {
    pub const Contract = runar.SmartContract;

    n: i64,

    pub fn init(n: i64) Probe {
        return .{ .n = n };
    }

    pub fn verify(self: *const Probe, x: i64, k: i64) void {
        var sum: i64 = 0;
@LOCAL@        @HEADER@ {
            sum = sum + i + 10;
        }
        runar.assert(sum == x);
    }
};
`,
    header: {
      rt: 'var i: i64 = 0;\n        while (i < self.n) : (i += 1)',
      param: 'var i: i64 = 0;\n        while (i < k) : (i += 1)',
      local: 'var i: i64 = 0;\n        while (i < lim) : (i += 1)',
      expr: 'var i: i64 = 0;\n        while (i < 3 + 1) : (i += 1)',
      lit: 'var i: i64 = 0;\n        while (i < 3) : (i += 1)',
    },
    local: '        const lim: i64 = 3;\n',
  },
  {
    ext: 'rb',
    template: `require 'runar'

class Probe < Runar::SmartContract
  prop :n, Bigint

  def initialize(n)
    super(n)
    @n = n
  end

  runar_public x: Bigint, k: Bigint
  def verify(x, k)
    sum = 0
@LOCAL@    @HEADER@
      sum = sum + i + 10
    end
    assert sum == x
  end
end
`,
    header: {
      rt: 'for i in 0...@n',
      param: 'for i in 0...k',
      local: 'for i in 0...lim',
      expr: 'for i in 0...3 + 1',
      lit: 'for i in 0...3',
    },
    local: '    lim = 3\n',
  },
  {
    ext: 'java',
    template: `package runar.examples.probe;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

class Probe extends SmartContract {

    @Readonly Bigint n;

    Probe(Bigint n) {
        super(n);
        this.n = n;
    }

    @Public
    void verify(Bigint x, Bigint k) {
        Bigint sum = Bigint.ZERO;
@LOCAL@        @HEADER@ {
            sum = sum.plus(i).plus(Bigint.of(10));
        }
        assertThat(sum.eq(x));
    }
}
`,
    header: {
      rt: 'for (Bigint i = Bigint.ZERO; i.lt(this.n); i = i.plus(Bigint.ONE))',
      param: 'for (Bigint i = Bigint.ZERO; i.lt(k); i = i.plus(Bigint.ONE))',
      local: 'for (Bigint i = Bigint.ZERO; i.lt(lim); i = i.plus(Bigint.ONE))',
      expr: 'for (Bigint i = Bigint.ZERO; i.lt(Bigint.of(3).plus(Bigint.ONE)); i = i.plus(Bigint.ONE))',
      lit: 'for (Bigint i = Bigint.ZERO; i.lt(Bigint.of(3)); i = i.plus(Bigint.ONE))',
    },
    local: '        Bigint lim = Bigint.of(3);\n',
  },
];

let n = 0;
function write(s: Surface, shape: Shape): string {
  const text = s.template
    .replace('@LOCAL@', shape === 'local' ? s.local : '')
    .replace('@HEADER@', s.header[shape]);
  const dir = mkdtempSync(join(TMP, `c${n++}-`));
  const path = join(dir, `Probe.runar.${s.ext}`);
  writeFileSync(path, text);
  return path;
}

describe('N-026: non-constant for-loop bound diagnostics match the reference on every tier', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const s of SURFACES) {
    for (const shape of SHAPES) {
      if (shape === 'lit') {
        it(`.runar.${s.ext} literal bound (control): accepted by every tier`, () => {
          const path = write(s, shape);
          const got: Record<string, string> = {};
          for (const tier of TIERS) {
            const r = judge(tier, path);
            got[tier.id] = r.verdict === 'accepted' ? 'accepted' : `rejected: ${r.diag.slice(0, 160)}`;
          }
          expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'accepted'])));
        }, 900_000);
        continue;
      }
      const [want, other] = EXPECT[shape];
      it(`.runar.${s.ext} ${shape} bound: every tier refuses with the reference sentence`, () => {
        const path = write(s, shape);
        const got: Record<string, string> = {};
        for (const tier of TIERS) {
          const r = judge(tier, path);
          got[tier.id] =
            r.verdict === 'rejected' && r.diag.includes(want) && !r.diag.includes(other)
              ? 'ok'
              : `${r.verdict}: ${r.diag.slice(0, 200)}`;
        }
        expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'ok'])));
      }, 900_000);
    }
  }

  // Move `loop { }` has no bound at all. The reference lowers it to a `for`
  // whose condition is the literal `true` and refuses it because the condition
  // does not test the iterator; Rust used to die in the parser on the `loop`
  // keyword and Zig used to answer with the bound sentence instead.
  it('.runar.move loop {}: every tier refuses with the reference sentence', () => {
    const text = `module Probe {
    use runar::types::{Int};

    struct Probe {
        n: Int,
    }

    public fun verify(contract: &Probe, x: Int, k: Int) {
        let sum: Int = 0;
        loop {
            sum = sum + 10;
        };
        assert_eq!(sum, x);
    }
}
`;
    const dir = mkdtempSync(join(TMP, `c${n++}-`));
    const path = join(dir, 'Probe.runar.move');
    writeFileSync(path, text);
    const want = "For loop condition must compare the loop variable '_l' to a compile-time constant";
    const got: Record<string, string> = {};
    for (const tier of TIERS) {
      const r = judge(tier, path);
      got[tier.id] =
        r.verdict === 'rejected' && r.diag.includes(want) ? 'ok' : `${r.verdict}: ${r.diag.slice(0, 200)}`;
    }
    expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'ok'])));
  }, 900_000);
});
