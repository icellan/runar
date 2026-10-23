import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-014 — an unknown base class on `.runar.sol` and `.runar.zig` is refused at
 * parse by all seven tiers, with one shared diagnostic.
 *
 * Before the fix the TS reference and the Rust tier folded an unknown name
 * after `contract X is ...` (.sol) to SmartContract, and six tiers (every
 * tier but Zig) folded an unknown `pub const Contract = runar.<Name>;`
 * (.zig) the same way. A read-only contract therefore compiled under a base
 * class the author never wrote (`is StatefulSmartContrct` compiled as a
 * stateless contract), while Go/Python/Zig/Ruby/Java refused the same .sol
 * source. A mutable-property contract was only caught later by the readonly
 * validator rule, with a different message per tier.
 *
 * What this proves:
 *   - for a read-only and a mutable-property contract on each of .sol and
 *     .zig, every available tier rejects the unknown base and its diagnostic
 *     carries the shared text below;
 *   - a read-only .runar.go contract embedding an unknown `runar.<Name>` is
 *     refused by every tier with the shared Go-surface text (already uniform
 *     before this item; pinned so it stays that way);
 *   - the three real bases still compile, to the same hex on every tier.
 * What it does NOT prove:
 *   - the .ts/.py/.rb/.java surfaces (they already refuse in every tier; their
 *     wording is not unified here), nor the Move and Rust-DSL surfaces, which
 *     have no `is <Base>` form;
 *   - the exact position prefix of the diagnostic, which differs per tier.
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TMP = mkdtempSync(join(tmpdir(), 'n014-'));

const SHARED_PARENT_DIAG =
  "unknown parent class: 'TotallyMadeUp', expected SmartContract, StatefulSmartContract, or UnsafeSmartContract";
const GO_DIAG = 'no Rúnar contract struct found in Go source';
const REAL_BASES = ['SmartContract', 'StatefulSmartContract', 'UnsafeSmartContract'];

const solRO = (base: string) => `pragma runar ^0.1.0;

contract BogusRO is ${base} {
    bigint immutable target;

    constructor(bigint _target) {
        target = _target;
    }

    function unlock(bigint x) public {
        require(x == this.target);
    }
}
`;

const solMut = (base: string) => `pragma runar ^0.1.0;

contract Bogus is ${base} {
    bigint total;

    constructor(bigint _total) {
        total = _total;
    }

    function bump() public {
        this.total = this.total + 1;
    }
}
`;

const zigRO = (base: string) => `const runar = @import("runar");

pub const BogusRO = struct {
    pub const Contract = runar.${base};

    target: i64,

    pub fn init(target: i64) BogusRO {
        return .{ .target = target };
    }

    pub fn unlock(self: *const BogusRO, x: i64) void {
        runar.assert(x == self.target);
    }
};
`;

const zigMut = (base: string) => `const runar = @import("runar");

pub const Bogus = struct {
    pub const Contract = runar.${base};

    total: i64 = 0,

    pub fn init(total: i64) Bogus {
        return .{ .total = total };
    }

    pub fn bump(self: *Bogus) void {
        self.total = self.total + 1;
    }
};
`;

const goRO = (base: string) => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type BogusRO struct {
	runar.${base}
	Target runar.Int \`runar:"readonly"\`
}

func (c *BogusRO) Unlock(x runar.Int) {
	runar.Assert(x == c.Target)
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
  ['.sol read-only', 'BogusRO.runar.sol', solRO('TotallyMadeUp'), SHARED_PARENT_DIAG],
  ['.sol mutable', 'Bogus.runar.sol', solMut('TotallyMadeUp'), SHARED_PARENT_DIAG],
  ['.zig read-only', 'BogusRO.runar.zig', zigRO('TotallyMadeUp'), SHARED_PARENT_DIAG],
  ['.zig mutable', 'Bogus.runar.zig', zigMut('TotallyMadeUp'), SHARED_PARENT_DIAG],
  ['.go read-only', 'BogusRO.runar.go', goRO('TotallyMadeUp'), GO_DIAG],
];

const ACCEPT: Array<[string, string, (b: string) => string]> = [
  ['.sol read-only', 'BogusRO.runar.sol', solRO],
  ['.zig read-only', 'BogusRO.runar.zig', zigRO],
];

describe('N-014 unknown base class — seven-tier parity', () => {
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
