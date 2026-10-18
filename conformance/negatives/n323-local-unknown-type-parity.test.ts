import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-323 — a local variable annotated with an unknown type name is refused by
 * every tier, on every surface whose local-declaration syntax takes a type.
 *
 * Before the fix the Zig tier accepted `let q: TTT = a;` on all eight such
 * surfaces: each of its parsers lowers an unrecognised name to the `unknown`
 * type, and the type checker treats `unknown` as compatible with everything.
 * (`.runar.rb` has no local annotation syntax, so it is not in the matrix.)
 *
 * What this proves:
 *   - for each of ts / sol / move / go / rs / py / zig / java, every tier
 *     refuses the contract and its diagnostic names `TTT`;
 *   - the same contract with `bigint` (the surface's own spelling) as the
 *     annotation is ACCEPTED by every tier, so the refusal is the unknown
 *     name and not the surrounding contract.
 * What it does NOT prove:
 *   - the diagnostic wording (only that it quotes the unknown name);
 *   - unknown names in other positions (parameters, properties, return types);
 *   - that every legal annotation is still accepted: the checked-in examples
 *     and conformance fixtures cover that.
 */

const TIERS = buildSourceTiers();
const TMP = mkdtempSync(join(tmpdir(), 'n323-'));

interface Surface { ext: string; src: (ty: string) => string }
const SURFACES: Surface[] = [
  { ext: 'ts', src: (ty) => `import { SmartContract, assert } from 'runar-lang';
class Arithmetic extends SmartContract {
  readonly target: bigint;
  constructor(target: bigint) { super(target); this.target = target; }
  public verify(a: bigint, b: bigint): void {
    let q: ${ty} = a;
    assert(q === this.target);
  }
}
` },
  { ext: 'sol', src: (ty) => `pragma runar ^0.1.0;
contract Arithmetic is SmartContract {
    int immutable target;
    constructor(int _target) { target = _target; }
    function verify(int a, int b) public {
        ${ty} q = a;
        require(q == target);
    }
}
` },
  { ext: 'move', src: (ty) => `module Arithmetic {
    use runar::types::{Int};
    struct Arithmetic { target: Int, }
    public fun verify(contract: &Arithmetic, a: Int, b: Int) {
        let q: ${ty} = a;
        assert_eq!(q, contract.target);
    }
}
` },
  { ext: 'go', src: (ty) => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Arithmetic struct {
	runar.SmartContract
	Target runar.Int \`runar:"readonly"\`
}

func (c *Arithmetic) Verify(a runar.Int, b runar.Int) {
	var q runar.${ty} = a
	runar.Assert(q == c.Target)
}
` },
  { ext: 'rs', src: (ty) => `use runar::prelude::*;

#[runar::contract]
struct Arithmetic {
    #[readonly]
    target: Int,
}

impl Arithmetic {
    pub fn verify(&self, a: Int, b: Int) {
        let q: ${ty} = a;
        assert!(q == self.target);
    }
}
` },
  { ext: 'py', src: (ty) => `from runar import SmartContract, Bigint, public, assert_

class Arithmetic(SmartContract):
    target: Bigint

    def __init__(self, target: Bigint):
        super().__init__(target)
        self.target = target

    @public
    def verify(self, a: Bigint, b: Bigint):
        q: ${ty} = a
        assert_(q == self.target)
` },
  { ext: 'zig', src: (ty) => `const runar = @import("runar");

pub const Arithmetic = struct {
    pub const Contract = runar.SmartContract;

    target: i64,

    pub fn init(target: i64) Arithmetic {
        return .{ .target = target };
    }

    pub fn verify(self: *const Arithmetic, a: i64, b: i64) void {
        const q: ${ty} = a;
        runar.assert(q == self.target);
    }
};
` },
  { ext: 'java', src: (ty) => `package runar.examples.arithmetic;

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

    @Public
    void verify(Bigint a, Bigint b) {
        ${ty} q = a;
        assertThat(q.eq(this.target));
    }
}
` },
];

/** The surface's own spelling of a valid annotation. */
const GOOD: Record<string, string> = {
  ts: 'bigint', sol: 'int', move: 'Int', go: 'Int', rs: 'Int', py: 'Bigint', zig: 'i64', java: 'Bigint',
};

function write(ext: string, ty: string, tag: string): string {
  const s = SURFACES.find((x) => x.ext === ext)!;
  const dir = mkdtempSync(join(TMP, `${tag}-${ext}-`));
  const path = join(dir, `Arithmetic.runar.${ext}`);
  writeFileSync(path, s.src(ty));
  return path;
}

describe('N-323: every tier refuses a local annotated with an unknown type name', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const { ext } of SURFACES) {
    it(`.runar.${ext}: unknown type refused by every tier, valid type accepted`, () => {
      const bad = write(ext, 'TTT', 'bad');
      const good = write(ext, GOOD[ext]!, 'good');
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
});
