import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex } from './tier-harness.js';

/**
 * N-054 — `var` is a mutable `let`, on every tier.
 *
 * The TypeScript surface's `var` used to split the seven tiers: TS and Rust
 * accepted it as a mutable local, Go/Python/Ruby/Zig/Java refused it (Python,
 * Zig, Ruby and Java with a misleading "LabeledStatement"/for-loop diagnostic),
 * and spec/grammar.md §9 listed only `const | let`. Decision (R85): `var`
 * is accepted everywhere `let` is, with `let`'s semantics. The spec now says so.
 *
 * What this proves, per tier and across tiers:
 *   - a `.runar.ts` statement `var s = ...; s = s + x;` is accepted and
 *     compiles to the SAME hex as the identical program written with `let`;
 *   - a for-initializer `for (var i ...)` likewise matches `for (let i ...)`;
 *   - the native `var` spellings that already existed (`.runar.go` `var x T = v`,
 *     `.runar.zig` `var x: T = v`) still match their non-`var` twin (controls).
 * What it does NOT prove:
 *   - `var` hoisting / function-scope semantics: the subset treats `var` as
 *     block-scoped `let`, nothing here exercises a use-before-declaration;
 *   - Java's `var s = ...` (Java 10 local type inference): that is a different
 *     feature, not a mutable-let keyword; every tier refuses it today and it
 *     is out of scope for this item;
 *   - surfaces with no `var` keyword (sol, move, rs, py, rb).
 */

const TIERS = buildSourceTiers();
const TMP = mkdtempSync(join(tmpdir(), 'n054-'));
let n = 0;

function write(ext: string, text: string): string {
  const dir = mkdtempSync(join(TMP, `c${n++}-`));
  const path = join(dir, `Probe.runar.${ext}`);
  writeFileSync(path, text);
  return path;
}

const TS_STMT = (kw: string) => `import { SmartContract, assert } from 'runar-lang';

class Probe extends SmartContract {
  readonly n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }

  public verify(x: bigint): void {
    ${kw} s: bigint = 1n;
    s = s + x;
    assert(s === this.n);
  }
}
`;

const TS_FOR = (kw: string) => `import { SmartContract, assert } from 'runar-lang';

class Probe extends SmartContract {
  readonly n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }

  public verify(x: bigint): void {
    let s: bigint = 0n;
    for (${kw} i: bigint = 0n; i < 3n; i++) {
      s = s + i;
    }
    assert(s === x + this.n);
  }
}
`;

const GO = (decl: string) => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Probe struct {
    runar.SmartContract
    N runar.Int \`runar:"readonly"\`
}

func (c *Probe) Verify(x runar.Int) {
    ${decl}
    sum = sum + x
    runar.Assert(sum == c.N)
}
`;

const ZIG = (decl: string) => `const runar = @import("runar");

pub const Probe = struct {
    pub const Contract = runar.SmartContract;

    n: i64,

    pub fn init(n: i64) Probe {
        return .{ .n = n };
    }

    pub fn verify(self: *const Probe, x: i64) void {
        ${decl}
        s = s + x;
        runar.assert(s == self.n);
    }
};
`;

interface Case {
  name: string;
  ext: string;
  withVar: string;
  withLet: string;
}

const CASES: Case[] = [
  { name: '.runar.ts statement', ext: 'ts', withVar: TS_STMT('var'), withLet: TS_STMT('let') },
  { name: '.runar.ts for-initializer', ext: 'ts', withVar: TS_FOR('var'), withLet: TS_FOR('let') },
  {
    name: '.runar.go native var (control)',
    ext: 'go',
    withVar: GO('var sum runar.Int = 1'),
    withLet: GO('sum := runar.Int(1)'),
  },
  {
    name: '.runar.zig native var (control)',
    ext: 'zig',
    withVar: ZIG('var s: i64 = 1;'),
    withLet: ZIG('var s: i64 = 1;'),
  },
];

describe('N-054: `var` is a mutable `let` on every tier', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const c of CASES) {
    it(`${c.name}: every tier compiles the var program to the let program's hex`, () => {
      const varPath = write(c.ext, c.withVar);
      const letPath = write(c.ext, c.withLet);
      const got: Record<string, string> = {};
      const letHexes: Record<string, string> = {};
      for (const tier of TIERS) {
        let letHex: string;
        try {
          letHex = compileHex(tier, letPath);
        } catch (e) {
          throw new Error(`control (let) program failed on ${tier.id}: ${(e as Error).message}`);
        }
        letHexes[tier.id] = letHex;
        try {
          const varHex = compileHex(tier, varPath);
          got[tier.id] = varHex === letHex ? 'ok' : `var hex ${varHex} != let hex ${letHex}`;
        } catch (e) {
          got[tier.id] = `refused: ${(e as Error).message.slice(0, 200)}`;
        }
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'ok'])));
      // And the tiers agree with each other (non-vacuous: hexes are non-empty).
      const distinct = new Set(Object.values(letHexes));
      expect([...distinct].every((h) => h.length > 0)).toBe(true);
      expect(distinct.size).toBe(1);
    }, 900_000);
  }
});
