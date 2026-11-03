import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-402 — an unknown base class on `.runar.ts`, `.runar.py`, `.runar.rb` and
 * `.runar.java` is refused by all seven tiers with the diagnostic N-014
 * already unified for `.sol`/`.zig`.
 *
 * Before the fix every tier already refused these sources, but the wording
 * differed per tier and surface ("Unknown parent class: X", "unknown parent
 * class: X", Java "contract class must extend ..., got X").
 *
 * What this proves:
 *   - for a read-only and a mutable-property contract on each of the four
 *     surfaces, every available tier rejects the unknown base and its
 *     diagnostic contains the shared N-014 text;
 *   - the .ts surface keeps its (already uniform, N-011) "No class extending"
 *     text; see TS_NO_CLASS_DIAG;
 *   - the three real bases still compile (read-only control) to the same hex
 *     on every tier, so the wording change did not alter acceptance.
 * What it does NOT prove:
 *   - the position prefix of the diagnostic (differs per tier);
 *   - the Go, Rust-DSL and Move surfaces (no `extends <Base>` form checked
 *     here; .sol/.zig/.go are pinned by n014-unknown-base-class-parity).
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TMP = mkdtempSync(join(tmpdir(), 'n402-'));

const SHARED_PARENT_DIAG =
  "unknown parent class: 'TotallyMadeUp', expected SmartContract, StatefulSmartContract, or UnsafeSmartContract";
// .ts is the one surface where an unknown base is NOT reported as such, by
// design (N-011): the parser keeps only a class whose `extends` names a real
// base and ignores the rest, so the diagnostic is the shared "no contract
// class" text in all seven tiers. Pinned here so it stays uniform.
const TS_NO_CLASS_DIAG =
  'No class extending SmartContract, StatefulSmartContract, or UnsafeSmartContract found';
const REAL_BASES = ['SmartContract', 'StatefulSmartContract', 'UnsafeSmartContract'];

const tsRO = (base: string) => `import { ${base}, assert } from 'runar-lang';
import type { Sig } from 'runar-lang';

class BogusRO extends ${base} {
  readonly target: bigint;

  constructor(target: bigint) {
    super(target);
    this.target = target;
  }

  public unlock(x: bigint) {
    assert(x === this.target);
  }
}
`;

const tsMut = (base: string) => `import { ${base}, assert } from 'runar-lang';

class Bogus extends ${base} {
  total: bigint;

  constructor(total: bigint) {
    super(total);
    this.total = total;
  }

  public bump() {
    this.total = this.total + 1n;
  }
}
`;

const pyRO = (base: string) => `from runar import ${base}, public, assert_

class BogusRO(${base}):
    target: int

    def __init__(self, target: int):
        super().__init__(target)
        self.target = target

    @public
    def unlock(self, x: int):
        assert_(x == self.target)
`;

const pyMut = (base: string) => `from runar import ${base}, public, assert_

class Bogus(${base}):
    total: int

    def __init__(self, total: int):
        super().__init__(total)
        self.total = total

    @public
    def bump(self):
        self.total = self.total + 1
`;

const rbRO = (base: string) => `require 'runar'

class BogusRO < Runar::${base}
  prop :target, Bigint

  def initialize(target)
    super(target)
    @target = target
  end

  runar_public x: Bigint
  def unlock(x)
    assert x == @target
  end
end
`;

const rbMut = (base: string) => `require 'runar'

class Bogus < Runar::${base}
  prop :total, Bigint

  def initialize(total)
    super(total)
    @total = total
  end

  runar_public
  def bump
    @total = @total + 1
  end
end
`;

const javaRO = (base: string) => `package runar.examples.bogus;

import runar.lang.${base};
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

class BogusRO extends ${base} {
    @Readonly Bigint target;

    BogusRO(Bigint target) {
        super(target);
        this.target = target;
    }

    @Public
    void unlock(Bigint x) {
        assertThat(x.eq(target));
    }
}
`;

const javaMut = (base: string) => `package runar.examples.bogus;

import runar.lang.${base};
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;

class Bogus extends ${base} {
    Bigint total;

    Bogus(Bigint total) {
        super(total);
        this.total = total;
    }

    @Public
    void bump() {
        this.total = this.total.plus(Bigint.of(1));
    }
}
`;

let n = 0;
function write(file: string, text: string): string {
  const dir = join(TMP, String(n++));
  mkdirSync(dir, { recursive: true });
  const p = join(dir, file);
  writeFileSync(p, text);
  return p;
}

const REJECT: Array<[string, string, string, string]> = [
  ['.ts read-only', 'BogusRO.runar.ts', tsRO('TotallyMadeUp'), TS_NO_CLASS_DIAG],
  ['.ts mutable', 'Bogus.runar.ts', tsMut('TotallyMadeUp'), TS_NO_CLASS_DIAG],
  ['.py read-only', 'BogusRO.runar.py', pyRO('TotallyMadeUp'), SHARED_PARENT_DIAG],
  ['.py mutable', 'Bogus.runar.py', pyMut('TotallyMadeUp'), SHARED_PARENT_DIAG],
  ['.rb read-only', 'BogusRO.runar.rb', rbRO('TotallyMadeUp'), SHARED_PARENT_DIAG],
  ['.rb mutable', 'Bogus.runar.rb', rbMut('TotallyMadeUp'), SHARED_PARENT_DIAG],
  ['.java read-only', 'BogusRO.runar.java', javaRO('TotallyMadeUp'), SHARED_PARENT_DIAG],
  ['.java mutable', 'Bogus.runar.java', javaMut('TotallyMadeUp'), SHARED_PARENT_DIAG],
];

const ACCEPT: Array<[string, string, (b: string) => string]> = [
  ['.ts read-only', 'BogusRO.runar.ts', tsRO],
  ['.py read-only', 'BogusRO.runar.py', pyRO],
  ['.rb read-only', 'BogusRO.runar.rb', rbRO],
  ['.java read-only', 'BogusRO.runar.java', javaRO],
];

describe('N-402 unknown base class wording — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [name, file, text, diag] of REJECT) {
    const path = write(file, text);
    for (const tier of TIERS) {
      it(`${tier.id} refuses an unknown base on ${name} with the shared diagnostic`, () => {
        const j = judge(tier, path);
        expect(j.verdict).toBe('rejected');
        expect(j.diag).toContain(diag);
      });
    }
  }

  for (const [name, file, mk] of ACCEPT) {
    for (const base of REAL_BASES) {
      const path = write(file, mk(base));
      it(`every tier compiles ${name} under ${base} to the same hex`, () => {
        const hexes = TIERS.map((t) => compileHex(t, path));
        for (const h of hexes) expect(h).toBe(hexes[0]);
      });
    }
  }
});
