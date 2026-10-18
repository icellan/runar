import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-325 — an unknown type name in a parameter position is refused by every
 * tier, on every surface whose method/constructor syntax takes a type.
 *
 * Before the fix all seven tiers accepted `b: TTT` on a public method, on a
 * private method and on the constructor, on every surface. The parameter is
 * declared but UNUSED on purpose: a private helper called with a bigint is
 * refused by most tiers for the call-site mismatch, which is not the check
 * under test. The Go-surface `var q runar.TTT` (no initializer) was accepted
 * by the Zig tier alone: N-323 only checked the initializer branch.
 * (`.runar.rb` has no local annotation syntax, so it is only in the
 * parameter matrix.)
 *
 * What this proves:
 *   - for each of the nine surfaces and each of {public param, private param,
 *     constructor param}, every tier refuses the contract and its diagnostic
 *     names `TTT`;
 *   - the same contract with the surface's own spelling of bigint is ACCEPTED
 *     by every tier, so the refusal is the unknown name and not the contract;
 *   - `.runar.go` `var q runar.TTT`: every tier refuses, and every tier that
 *     accepts the same shape with `runar.Int` names `TTT`.
 * What it does NOT prove:
 *   - unknown names in a RETURN-type position: no tier keeps the annotation
 *     (the AST has no field for it), so that position is a separate item;
 *   - the diagnostic wording (only that it quotes the unknown name);
 *   - that every legal parameter type is still accepted: the checked-in
 *     examples and conformance fixtures cover that.
 */

const TIERS = buildSourceTiers();
const TMP = mkdtempSync(join(tmpdir(), 'n325-'));

type Slot = 'pub' | 'priv' | 'ctor';
const SLOTS: Slot[] = ['pub', 'priv', 'ctor'];

interface Surface { ext: string; good: string; src: (t: Record<Slot, string>) => string }
const SURFACES: Surface[] = [
  { ext: 'ts', good: 'bigint', src: (t) => `import { SmartContract, assert } from 'runar-lang';
class Arithmetic extends SmartContract {
  readonly target: bigint;
  constructor(target: ${t.ctor}) { super(target); this.target = target; }
  private helper(x: ${t.priv}): bigint { return 1n; }
  public verify(a: bigint, c: ${t.pub}): void {
    assert(a === this.target);
  }
}
` },
  { ext: 'sol', good: 'int', src: (t) => `pragma runar ^0.1.0;
contract Arithmetic is SmartContract {
    int immutable target;
    constructor(${t.ctor} _target) { target = _target; }
    function helper(${t.priv} x) private returns (int) { return 1; }
    function verify(int a, ${t.pub} c) public {
        require(a == target);
    }
}
` },
  { ext: 'move', good: 'Int', src: (t) => `module Arithmetic {
    use runar::types::{Int};
    struct Arithmetic { target: Int, }
    fun helper(x: ${t.priv}): Int { 1 }
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

func (c *Arithmetic) helper(x runar.${t.priv}) runar.Int {
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
    fn helper(&self, x: ${t.priv}) -> Int {
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

    def _helper(self, x: ${t.priv}) -> Bigint:
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

    fn helper(x: ${t.priv}) i64 {
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

    Bigint helper(${t.priv} x) {
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
  const t = { pub: s.good, priv: s.good, ctor: s.good } as Record<Slot, string>;
  if (bad) t[bad] = 'TTT';
  const dir = mkdtempSync(join(TMP, `${tag}-${s.ext}-`));
  const path = join(dir, `Arithmetic.runar.${s.ext}`);
  writeFileSync(path, s.src(t));
  return path;
}

// Surfaces whose constructor parameters are not separately typed in the source:
// Move, Go and Rust derive the constructor from the struct, and Ruby from `prop`.
// The `ctor` slot has nothing to substitute there, so it is skipped.
const NO_CTOR_PARAM = new Set(['move', 'go', 'rs', 'rb']);

describe('N-325: every tier refuses an unknown type name in a parameter position', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const s of SURFACES) {
    for (const slot of SLOTS) {
      if (slot === 'ctor' && NO_CTOR_PARAM.has(s.ext)) continue;
      it(`.runar.${s.ext} ${slot} param: unknown type refused by every tier, valid type accepted`, () => {
        const bad = write(s, slot, `bad-${slot}`);
        const good = write(s, null, `good-${slot}`);
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

  it('.runar.go `var q runar.TTT` (no initializer): refused by every tier', () => {
    const src = (ty: string) => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Arithmetic struct {
	runar.SmartContract
	Target runar.Int \`runar:"readonly"\`
}

func (c *Arithmetic) Verify(a runar.Int) {
	var q runar.${ty}
	q = a
	runar.Assert(q == c.Target)
}
`;
    const mk = (ty: string, tag: string) => {
      const dir = mkdtempSync(join(TMP, `${tag}-noinit-`));
      const p = join(dir, 'Arithmetic.runar.go');
      writeFileSync(p, src(ty));
      return p;
    };
    const bad = mk('TTT', 'bad');
    const good = mk('Int', 'good');
    const got: Record<string, string> = {};
    for (const tier of TIERS) {
      const r = judge(tier, bad);
      // A tier that rejects the valid shape too (`var` without initializer is
      // unsupported Go there) refuses for that reason; only a tier that
      // accepts the valid shape must name the unknown type.
      const c = judge(tier, good);
      if (r.verdict !== 'rejected') got[tier.id] = `accepted TTT`;
      else if (c.verdict === 'accepted' && !r.diag.includes('TTT')) got[tier.id] = `refused without naming TTT: ${r.diag.trim().slice(0, 160)}`;
      else got[tier.id] = 'refused';
    }
    expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'refused'])));
  }, 900_000);
});
