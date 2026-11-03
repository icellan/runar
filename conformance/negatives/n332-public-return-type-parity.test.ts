import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-332 — a PUBLIC method that declares a return type is refused by every
 * tier, on every surface that spells a return type. Public (spending) methods
 * return nothing in Rúnar (spec/grammar.md:161, docs/formats/go.md "Public
 * methods must not return a value"); private methods keep their return types.
 *
 * Before the fix the verdict depended on the tier: the `-> bool` (.runar.rs)
 * contract was accepted by go/rust/zig and refused by ts/python/ruby/java for
 * incidental reasons (a trailing-expression body, or a `return` statement),
 * never for the declared type. Here the body ends in its `assert`, has no
 * `return`, and the only defect is the declared return type, so a tier that
 * refuses does so because of the declaration.
 *
 * What this proves:
 *   - for each of the eight surfaces that spell a return type, every tier
 *     refuses a public method declaring a non-void return type, and its
 *     diagnostic names the method (`verify`, any case: the TS and Ruby Go-surface
 *     parsers quote the Go spelling `Verify`) and says "return type";
 *   - the same contract with the return type removed (or spelled void where
 *     the surface has no way to omit it) is ACCEPTED by every tier, so the
 *     refusal is the declaration;
 *   - the same contract with the return type moved to a PRIVATE helper is
 *     ACCEPTED by every tier (private methods keep their return types).
 * What it does NOT prove:
 *   - the diagnostic wording beyond the method name and "return type";
 *   - that every legal public-method spelling is still accepted: the
 *     checked-in examples and conformance fixtures cover that (over-rejection
 *     sweep over all non-negative sources);
 *   - `.runar.rb` (no return-type syntax);
 *   - return STATEMENTS in public methods (NEW-012, already gated elsewhere).
 */

const TIERS = buildSourceTiers();
const TMP = mkdtempSync(join(tmpdir(), 'n332-'));

type Variant = 'pubRet' | 'none' | 'privRet';

interface Surface { ext: string; src: (v: Variant) => string }
const SURFACES: Surface[] = [
  { ext: 'ts', src: (v) => `import { SmartContract, assert } from 'runar-lang';
class Arithmetic extends SmartContract {
  readonly target: bigint;
  constructor(target: bigint) { super(target); this.target = target; }
${v === 'privRet' ? `  private helper(x: bigint): bigint { return x; }\n` : ''}  public verify(a: bigint)${v === 'pubRet' ? ': boolean' : ': void'} {
    assert(a === this.target);
  }
}
` },
  { ext: 'sol', src: (v) => `pragma runar ^0.1.0;
contract Arithmetic is SmartContract {
    int immutable target;
    constructor(int _target) { target = _target; }
${v === 'privRet' ? `    function helper(int x) private returns (int) { return x; }\n` : ''}    function verify(int a) public${v === 'pubRet' ? ' returns (bool)' : ''} {
        require(a == target);
    }
}
` },
  { ext: 'move', src: (v) => `module Arithmetic {
    use runar::types::{Int};
    struct Arithmetic { target: Int, }
${v === 'privRet' ? `    fun helper(x: Int): Int { x }\n` : ''}    public fun verify(contract: &Arithmetic, a: Int)${v === 'pubRet' ? ': Bool' : ''} {
        assert_eq!(a, contract.target);
    }
}
` },
  { ext: 'go', src: (v) => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Arithmetic struct {
	runar.SmartContract
	Target runar.Int \`runar:"readonly"\`
}
${v === 'privRet' ? `
func (c *Arithmetic) helper(x runar.Int) runar.Int {
	return x
}
` : ''}
func (c *Arithmetic) Verify(a runar.Int)${v === 'pubRet' ? ' runar.Bool' : ''} {
	runar.Assert(a == c.Target)
}
` },
  { ext: 'rs', src: (v) => `use runar::prelude::*;

#[runar::contract]
struct Arithmetic {
    #[readonly]
    target: Int,
}

impl Arithmetic {
${v === 'privRet' ? `    fn helper(&self, x: Int) -> Int {\n        x\n    }\n\n` : ''}    pub fn verify(&self, a: Int)${v === 'pubRet' ? ' -> bool' : ''} {
        assert!(a == self.target);
    }
}
` },
  { ext: 'py', src: (v) => `from runar import SmartContract, Bigint, public, assert_

class Arithmetic(SmartContract):
    target: Bigint

    def __init__(self, target: Bigint):
        super().__init__(target)
        self.target = target
${v === 'privRet' ? `
    def _helper(self, x: Bigint) -> Bigint:
        return x
` : ''}
    @public
    def verify(self, a: Bigint)${v === 'pubRet' ? ' -> bool' : ''}:
        assert_(a == self.target)
` },
  { ext: 'zig', src: (v) => `const runar = @import("runar");

pub const Arithmetic = struct {
    pub const Contract = runar.SmartContract;

    target: i64,

    pub fn init(target: i64) Arithmetic {
        return .{ .target = target };
    }
${v === 'privRet' ? `
    fn helper(x: i64) i64 {
        return x;
    }
` : ''}
    pub fn verify(self: *const Arithmetic, a: i64) ${v === 'pubRet' ? 'bool' : 'void'} {
        runar.assert(a == self.target);
    }
};
` },
  { ext: 'java', src: (v) => `package runar.examples.arithmetic;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

class Arithmetic extends SmartContract {

    @Readonly Bigint target;

    Arithmetic(Bigint target) {
        super(target);
        this.target = target;
    }
${v === 'privRet' ? `
    Bigint helper(Bigint x) {
        return x;
    }
` : ''}
    @Public
    ${v === 'pubRet' ? 'boolean' : 'void'} verify(Bigint a) {
        assertThat(a.eq(this.target));
    }
}
` },
];

function write(s: Surface, v: Variant): string {
  const dir = mkdtempSync(join(TMP, `${v}-${s.ext}-`));
  const path = join(dir, `Arithmetic.runar.${s.ext}`);
  writeFileSync(path, s.src(v));
  return path;
}

const fmt = (r: { verdict: string; diag: string }): string => `${r.verdict}: ${r.diag.trim().slice(0, 160)}`;

describe('N-332: every tier refuses a public method that declares a return type', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  // `.runar.rb` spells no return type, so it has no row.
  for (const s of SURFACES) {
    it(`.runar.${s.ext} public-method return type: refused by every tier; no return type and a private return type accepted`, () => {
      const bad = write(s, 'pubRet');
      const none = write(s, 'none');
      const priv = write(s, 'privRet');
      const got: Record<string, string> = {};
      const controlNone: Record<string, string> = {};
      const controlPriv: Record<string, string> = {};
      for (const tier of TIERS) {
        const r = judge(tier, bad);
        got[tier.id] =
          r.verdict === 'rejected' && /verify/i.test(r.diag) && /return type/i.test(r.diag)
            ? 'refused naming verify and the return type'
            : fmt(r);
        const c1 = judge(tier, none);
        controlNone[tier.id] = c1.verdict === 'accepted' ? 'accepted' : fmt(c1);
        const c2 = judge(tier, priv);
        controlPriv[tier.id] = c2.verdict === 'accepted' ? 'accepted' : fmt(c2);
      }
      const all = (v: string): Record<string, string> => Object.fromEntries(TIERS.map((t) => [t.id, v]));
      expect({ got, controlNone, controlPriv }).toEqual({
        got: all('refused naming verify and the return type'),
        controlNone: all('accepted'),
        controlPriv: all('accepted'),
      });
    }, 900_000);
  }
});
