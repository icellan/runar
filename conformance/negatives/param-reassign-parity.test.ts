import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers } from './tier-harness.js';

/**
 * N-129 — seven-tier positive parity for a public method that REASSIGNS ONE
 * OF ITS OWN PARAMETERS.
 *
 * Zig's anf_lower `.assign` arm treated a bare target as either a declared
 * local or a property, and a parameter is neither. A parameter sharing a
 * property's name (`count = count + 1`) became `update_prop count`, a state
 * write the source never made; any other parameter (`x = x + 2`) had its new
 * value discarded, so later reads saw the caller's argument. The other six
 * tiers rebind the parameter, as the TS reference does. Before the fix the
 * PR contract compiled to 1436 hex in Zig and 1420 in the other six on every
 * brace surface, and the N-023 ShadowParam probe to 1402 vs 1404.
 *
 * Why here and not packages/runar-compiler/src/__tests__/cross-compiler.test.ts:
 * every suite there feeds the TS-produced ANF to the other tiers' `--ir` mode,
 * which never runs their own source frontend or ANF lowering, where this bug
 * lived. Why not a conformance fixture: the item forbids one (a fixture also
 * needs a provenance-gated golden).
 *
 * What this proves: every available tier's CLI (fold-ON default) compiles the
 * PR contract in each of the seven brace surfaces, the stateless SL contract,
 * and the N-023 ShadowParam .runar.java probe to the same bytes, and those
 * bytes are pinned (sha256 / literal) so all seven drifting together still
 * fails.
 * What it does NOT prove: on-chain spend behaviour of those bytes, fold-OFF
 * output (compilers/zig/src/tests/param_reassignment.zig pins Zig's fold-OFF
 * bytes, which are the same), or the .runar.py / .runar.rb surfaces, whose
 * parsers lower a first assignment as a declaration and never reached the
 * defective arm.
 */

const PR_SHA256 = '342abda71c4eed6f75a655b86db86e98cd2357eec9861ae69df6b2aab2fa507d';
const SHADOW_PARAM_SHA256 = 'efbe11c00856b75de6e6ca9e0e54812a17c7633c594c1065c64e0ecf098ee2e4';
const SL_HEX = '788b7852937c9d0000a07777';

const PR_SOURCES: Record<string, string> = {
  'PR.runar.ts': `import { StatefulSmartContract, assert } from 'runar-lang';
class PR extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment(count: bigint, x: bigint) {
    count = count + 1n;
    x = x + 2n;
    assert(x > 0n);
    this.count = count;
  }
}
`,
  'PR.runar.sol': `pragma runar ^0.1.0;
contract PR is StatefulSmartContract {
    int count;
    constructor(int _count) { count = _count; }
    function increment(int count, int x) public {
        count = count + 1;
        x = x + 2;
        require(x > 0);
        this.count = count;
    }
}
`,
  'PR.runar.move': `module PR {
    use runar::StatefulSmartContract;
    resource struct PR {
        count: &mut Int,
    }
    public fun increment(contract: &mut PR, count: Int, x: Int) {
        count = count + 1;
        x = x + 2;
        assert!(x > 0, 0);
        contract.count = count;
    }
}
`,
  'PR.runar.go': `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type PR struct {
	runar.StatefulSmartContract
	Count runar.Int
}

func (c *PR) Increment(Count runar.Int, x runar.Int) {
	Count = Count + 1
	x = x + 2
	runar.Assert(x > 0)
	c.Count = Count
}
`,
  'PR.runar.rs': `use runar::prelude::*;

#[runar::contract]
struct PR {
    count: Int,
}

impl PR {
    pub fn increment(&mut self, count: Int, x: Int) {
        count = count + 1;
        x = x + 2;
        assert!(x > 0);
        self.count = count;
    }
}
`,
  'PR.runar.zig': `const runar = @import("runar");

pub const PR = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,

    pub fn init(count: i64) PR {
        return .{ .count = count };
    }

    pub fn increment(self: *PR, count: i64, x: i64) void {
        count = count + 1;
        x = x + 2;
        runar.assert(x > 0);
        self.count = count;
    }
};
`,
  'PR.runar.java': `package runar.examples.pr;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

class PR extends StatefulSmartContract {

    Bigint count;

    PR(Bigint count) {
        super(count);
        this.count = count;
    }

    @Public
    void increment(Bigint count, Bigint x) {
        count = count.plus(Bigint.ONE);
        x = x.plus(Bigint.TWO);
        assertThat(x.gt(Bigint.ZERO));
        this.count = count;
    }
}
`,
};

/** remediation-logs/N-023/probe/ShadowParam.runar.java, the item's repro. */
const SHADOW_PARAM_JAVA = `package runar.examples.barecounter;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;

class BareCounter extends StatefulSmartContract {

    Bigint count;

    BareCounter(Bigint count) {
        super(count);
        this.count = count;
    }

    @Public
    void increment(Bigint count) {
        count = count.plus(Bigint.ONE); this.count = count;
    }
}
`;

const SL_TS = `import { SmartContract, assert } from 'runar-lang';
class SL extends SmartContract {
  readonly count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public spend(count: bigint, x: bigint) {
    count = count + 1n;
    x = x + 2n;
    assert(x == count);
    assert(this.count > 0n);
  }
}
`;

function compileHex(tier: Tier, file: string): string {
  const r = spawnSync(tier.cmd!, [...tier.prefix, ...tier.argsFor(file)], {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.error) throw new Error(`${tier.id} could not run: ${r.error.message}`);
  const stdout = r.stdout ?? '';
  const hexLines = stdout.split(/\r?\n/).map((l) => l.trim()).filter((l) => /^[0-9a-f]+$/i.test(l));
  if (r.status !== 0 || hexLines.length === 0) {
    throw new Error(`${tier.id} ${file}: exit ${r.status}\n${`${stdout}\n${r.stderr ?? ''}`.slice(0, 800)}`);
  }
  return hexLines[hexLines.length - 1]!.toLowerCase();
}

const sha256 = (s: string): string => createHash('sha256').update(s).digest('hex');

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
let dir = '';

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n129-param-reassign-'));
});

function write(name: string, src: string): string {
  const p = join(dir, name);
  writeFileSync(p, src);
  return p;
}

describe('N-129 parameter reassignment — seven-tier positive parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (process.env.CI === 'true') expect(TIERS.length).toBe(7);
  });

  for (const [name, src] of Object.entries(PR_SOURCES)) {
    for (const tier of TIERS) {
      it(`${tier.id} compiles ${name} to the TS reference bytes`, () => {
        expect(sha256(compileHex(tier, write(name, src)))).toBe(PR_SHA256);
      });
    }
  }

  for (const tier of TIERS) {
    it(`${tier.id} compiles the N-023 ShadowParam.runar.java probe to the TS reference bytes`, () => {
      expect(sha256(compileHex(tier, write('ShadowParam.runar.java', SHADOW_PARAM_JAVA)))).toBe(
        SHADOW_PARAM_SHA256,
      );
    });

    it(`${tier.id} keeps a stateless parameter rebind (neither dropped nor a readonly write)`, () => {
      expect(compileHex(tier, write('SL.runar.ts', SL_TS))).toBe(SL_HEX);
    });
  }
});
