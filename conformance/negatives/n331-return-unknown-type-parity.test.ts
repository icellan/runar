import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-331 — an unknown type name in a private-method RETURN-type position is
 * refused by every tier, on every surface that spells a return type.
 * Continues N-325 (parameter positions), which left the return slot open
 * because no tier keeps the return annotation in its AST.
 *
 * Before the fix all seven tiers accepted `helper(...): TTT` on every surface
 * (TS reference included). The helper is never called, so a call-site type
 * mismatch cannot refuse it incidentally; its parameters and everything else
 * are valid, so the only defect in the contract is the return type.
 *
 * What this proves:
 *   - for each of the eight surfaces that spell a return type, every tier
 *     refuses the contract and its diagnostic names `TTT`;
 *   - the same contract with the surface's own spelling of bigint as the return
 *     type is ACCEPTED by every tier, so the refusal is the unknown name.
 * What it does NOT prove:
 *   - public-method return types (N-332, a separate item);
 *   - the diagnostic wording (only that it quotes the unknown name);
 *   - that every legal return type is still accepted: the checked-in examples
 *     and conformance fixtures cover that (all-corpus over-rejection sweep);
 *   - `.runar.rb` (no return-type syntax).
 */

const TIERS = buildSourceTiers();
const TMP = mkdtempSync(join(tmpdir(), 'n331-'));

type Slot = 'pub' | 'priv' | 'ctor' | 'ret';

interface Surface { ext: string; good: string; src: (t: Record<Slot, string>) => string }
const SURFACES: Surface[] = [
  { ext: 'ts', good: 'bigint', src: (t) => `import { SmartContract, assert } from 'runar-lang';
class Arithmetic extends SmartContract {
  readonly target: bigint;
  constructor(target: ${t.ctor}) { super(target); this.target = target; }
  private helper(x: ${t.priv}): ${t.ret} { return 1n; }
  public verify(a: bigint, c: ${t.pub}): void {
    assert(a === this.target);
  }
}
` },
  { ext: 'sol', good: 'int', src: (t) => `pragma runar ^0.1.0;
contract Arithmetic is SmartContract {
    int immutable target;
    constructor(${t.ctor} _target) { target = _target; }
    function helper(${t.priv} x) private returns (${t.ret}) { return 1; }
    function verify(int a, ${t.pub} c) public {
        require(a == target);
    }
}
` },
  { ext: 'move', good: 'Int', src: (t) => `module Arithmetic {
    use runar::types::{Int};
    struct Arithmetic { target: Int, }
    fun helper(x: ${t.priv}): ${t.ret} { 1 }
    public fun verify(contract: &Arithmetic, a: Int, c: ${t.pub}) {
        assert_eq!(a, contract.target);
    }
}
` },
  { ext: 'go', good: 'Int', src: (t) => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Arithmetic struct {
	runar.SmartContract
	Target runar.Int \`runar:"readonly"\`
}

func (c *Arithmetic) helper(x runar.${t.priv}) runar.${t.ret} {
	return 1
}

func (c *Arithmetic) Verify(a runar.Int, d runar.${t.pub}) {
	runar.Assert(a == c.Target)
}
` },
  { ext: 'rs', good: 'Int', src: (t) => `use runar::prelude::*;

#[runar::contract]
struct Arithmetic {
    #[readonly]
    target: Int,
}

impl Arithmetic {
    fn helper(&self, x: ${t.priv}) -> ${t.ret} {
        1
    }

    pub fn verify(&self, a: Int, c: ${t.pub}) {
        assert!(a == self.target);
    }
}
` },
  { ext: 'py', good: 'Bigint', src: (t) => `from runar import SmartContract, Bigint, public, assert_

class Arithmetic(SmartContract):
    target: Bigint

    def __init__(self, target: ${t.ctor}):
        super().__init__(target)
        self.target = target

    def _helper(self, x: ${t.priv}) -> ${t.ret}:
        return 1

    @public
    def verify(self, a: Bigint, c: ${t.pub}):
        assert_(a == self.target)
` },
  { ext: 'zig', good: 'i64', src: (t) => `const runar = @import("runar");

pub const Arithmetic = struct {
    pub const Contract = runar.SmartContract;

    target: i64,

    pub fn init(target: ${t.ctor}) Arithmetic {
        return .{ .target = target };
    }

    fn helper(x: ${t.priv}) ${t.ret} {
        return 1;
    }

    pub fn verify(self: *const Arithmetic, a: i64, c: ${t.pub}) void {
        runar.assert(a == self.target);
    }
};
` },
  { ext: 'rb', good: 'Bigint', src: (t) => `require 'runar'

class Arithmetic < Runar::SmartContract
  prop :target, Bigint

  def initialize(target)
    super(target)
    @target = target
  end

  params x: ${t.priv}
  def helper(x)
    return 1
  end

  runar_public a: Bigint, c: ${t.pub}
  def verify(a, c)
    assert a == @target
  end
end
` },
  { ext: 'java', good: 'Bigint', src: (t) => `package runar.examples.arithmetic;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

class Arithmetic extends SmartContract {

    @Readonly Bigint target;

    Arithmetic(${t.ctor} target) {
        super(target);
        this.target = target;
    }

    ${t.ret} helper(${t.priv} x) {
        return Bigint.of(1);
    }

    @Public
    void verify(Bigint a, ${t.pub} c) {
        assertThat(a.eq(this.target));
    }
}
` },
];

function write(s: Surface, bad: Slot | null, tag: string): string {
  const t = { pub: s.good, priv: s.good, ctor: s.good, ret: s.good } as Record<Slot, string>;
  if (bad) t[bad] = 'TTT';
  const dir = mkdtempSync(join(TMP, `${tag}-${s.ext}-`));
  const path = join(dir, `Arithmetic.runar.${s.ext}`);
  writeFileSync(path, s.src(t));
  return path;
}

describe('N-331: every tier refuses an unknown type name in a method return-type position', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  // `.runar.rb` spells no return type, so it has no row.
  for (const s of SURFACES.filter((x) => x.ext !== 'rb')) {
    {
      it(`.runar.${s.ext} private-method return type: unknown type refused by every tier, valid type accepted`, () => {
        const bad = write(s, 'ret', 'bad-ret');
        const good = write(s, null, 'good-ret');
        const got: Record<string, string> = {};
        const control: Record<string, string> = {};
        for (const tier of TIERS) {
          const r = judge(tier, bad);
          got[tier.id] =
            r.verdict === 'rejected' && r.diag.includes('TTT')
              ? 'refused naming TTT'
              : `${r.verdict}: ${r.diag.trim().slice(0, 160)}`;
          const c = judge(tier, good);
          control[tier.id] = c.verdict === 'accepted' ? 'accepted' : `${c.verdict}: ${c.diag.trim().slice(0, 160)}`;
        }
        expect({ got, control }).toEqual({
          got: Object.fromEntries(TIERS.map((t) => [t.id, 'refused naming TTT'])),
          control: Object.fromEntries(TIERS.map((t) => [t.id, 'accepted'])),
        });
      }, 900_000);
    }
  }
});
