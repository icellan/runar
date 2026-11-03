import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import {
  CONSENSUS_SPEND_CONTEXT,
  newConsensusSpend,
} from '../../packages/runar-testing/src/consensus-spend.js';
import { compile } from '../../packages/runar-compiler/src/index.js';
import { Tier, buildSourceTiers, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-053 — silent statement drops, seven-tier parity and on-chain proof.
 *
 * Before N-053, in all seven tiers:
 *   - `.runar.zig` `_ = self.check(x);` parsed the call and returned NO
 *     statement, so the private helper's assert vanished: Disc compiled to
 *     5177 (OP_1 OP_NIP) and any x unlocked it;
 *   - the `.runar.rb` statement dispatcher skipped any token it did not know,
 *     one token at a time, so a helper ending in `!(x == @t)` returned
 *     `x == @t` — the caller's guard `assert !_check(x)` was INVERTED and
 *     every wrong x unlocked it (009c91), while the right x was refused; a
 *     helper ending in `@t + 1` returned `@t` (the ivar statement stopped
 *     after `@t`, and `+` and `1` were skipped);
 *   - the `.runar.py` dispatchers disagreed: some tiers skipped `42`, `True`,
 *     `in`, `from`, others lowered or refused them;
 *   - `.runar.java` `;` (an empty statement) was a no-op in TS/Go/Rust and
 *     refused by Python/Zig/Ruby/Java.
 * Now every tier lowers `_ = expr;` as the expression statement `expr` (a bare
 * name `_ = self;` stays a no-op), lowers a .rb/.py statement that starts
 * with an expression token as an expression statement, refuses any other
 * start with "Unsupported statement starting with '<token>'", and accepts
 * `;` as a no-op on .runar.java, as the TS reference does.
 *
 * What this proves:
 *   - every available tier compiles each shape to the same bytes, in both fold
 *     modes, and those bytes are pinned to the TS reference;
 *   - the pinned Disc (.zig) and Neg (.rb) scripts, with t = 7 baked in,
 *     REJECT x = 8 and ACCEPT x = 7 under @bsv/sdk Spend.validate (consensus
 *     rules, version-1 tx), and the pre-fix bytes ACCEPT x = 8 — so the
 *     oracle can see the attack;
 *   - every tier refuses each non-expression statement start with the shared
 *     diagnostic.
 * What it does NOT prove: class-body token skipping (N-004 / N-033); the
 * tokenizers' handling of unknown characters (N-019 / N-020); any surface
 * other than .zig / .rb / .py / .java.
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF_TIERS: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));

const SHARED = (tok: string): string => `Unsupported statement starting with '${tok}'`;

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

const zig = (stmt: string): string => `const runar = @import("runar");

pub const Disc = struct {
    pub const Contract = runar.SmartContract;

    t: i64,

    pub fn init(t: i64) Disc {
        return .{ .t = t };
    }

    fn check(self: *const Disc, x: i64) i64 {
        runar.assert(x == self.t);
        return x;
    }

    pub fn unlock(self: *const Disc, x: i64) void {
        ${stmt}
        runar.assert(true);
    }
};
`;

const rb = (unlockBody: string, helperBody: string): string => `require 'runar'

class Disc < Runar::SmartContract
  prop :t, Bigint

  def initialize(t)
    super(t)
    @t = t
  end

  runar_public x: Bigint
  def unlock(x)
    ${unlockBody}
  end

  private

  params x: Bigint
  def _check(x)
    ${helperBody}
  end
end
`;

const RB_HELPER = 'assert x == @t\n    x';

const py = (stmt: string): string => `from runar import SmartContract, Bigint, public, assert_

class Disc(SmartContract):
    t: Bigint

    def __init__(self, t: Bigint):
        super().__init__(t)
        self.t = t

    @public
    def unlock(self, x: Bigint):
        ${stmt}
        assert_(True)

    def _check(self, x: Bigint) -> Bigint:
        assert_(x == self.t)
        return x
`;

const java = (stmt: string): string => `package p;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

class Disc extends SmartContract {
    @Readonly Bigint t;

    Disc(Bigint t) {
        super(t);
        this.t = t;
    }

    @Public
    void unlock(Bigint x) {
        ${stmt}
        assertThat(true);
    }

    Bigint check(Bigint x) {
        assertThat(x.eq(this.t));
        return x;
    }
}
`;

const ZIG_DISC = zig('_ = self.check(x);');
const RB_NEG = rb('assert !_check(x)', '!(x == @t)');

/** [case name, file name, source, pinned hex (fold OFF and ON agree for these)]. */
const POSITIVE: Array<[string, string, string, string]> = [
  ['zig `_ = self.check(x);`', 'Disc.runar.zig', ZIG_DISC, '76009d5177'],
  ['zig `_ = self; _ = x;`', 'Disc.runar.zig', zig('_ = self;\n        _ = x;'), '5177'],
  ['zig `_ = self.t + x;`', 'Disc.runar.zig', zig('_ = self.t + x;'), '007c935177'],
  ['rb helper `!(x == @t)`', 'Disc.runar.rb', RB_NEG, '009c'],
  ['rb helper ending in `false`', 'Disc.runar.rb', rb('assert !_check(x)', 'assert x == @t\n    false'), '009d0091'],
  ['rb helper ending in `@t + 1`', 'Disc.runar.rb', rb('assert x == _check(x)', '@t + 1'), '767c008b7b7c9c77'],
  ['rb `(_check(x))`', 'Disc.runar.rb', rb('(_check(x))\n    assert true', RB_HELPER), '76009d5177'],
  ['rb `!_check(x)`', 'Disc.runar.rb', rb('!_check(x)\n    assert true', RB_HELPER), '76009d915177'],
  ['rb `-x`', 'Disc.runar.rb', rb('-x\n    assert true', RB_HELPER), '8f5177'],
  ['rb `42`', 'Disc.runar.rb', rb('42\n    assert true', RB_HELPER), '012a517777'],
  ['rb `true`', 'Disc.runar.rb', rb('true\n    assert true', RB_HELPER), '51517777'],
  ['py `(self._check(x))`', 'Disc.runar.py', py('(self._check(x))'), '76009d5177'],
  ['py `not self._check(x) == x`', 'Disc.runar.py', py('not self._check(x) == x'), '7676009d7c9c915177'],
  ['py `-x`', 'Disc.runar.py', py('-x'), '8f5177'],
  ['py `42`', 'Disc.runar.py', py('42'), '012a517777'],
  ['py `True`', 'Disc.runar.py', py('True'), '51517777'],
  ['java `;`', 'Disc.runar.java', java(';'), '5177'],
  ['java `check(x);;`', 'Disc.runar.java', java('check(x);;'), '76009d5177'],
  ['java `if (...) { ; }`', 'Disc.runar.java', java('if (x.gt(Bigint.ZERO)) { ; }\n        check(x);'), '7600a0636876009d5177'],
];

/** [case name, file name, source, refused token]. */
const REFUSED: Array<[string, string, string, string]> = [
  ...['do', 'in', 'class', 'def'].map(
    (tok): [string, string, string, string] => [
      `rb \`${tok} ...\``,
      'Disc.runar.rb',
      rb(`${tok} assert x == @t\n    assert true`, RB_HELPER),
      tok,
    ],
  ),
  ...[
    ['in', 'in x'],
    ['from', 'from x'],
    ['import', 'import x'],
    ['@', '@public'],
    ['elif', 'elif x == self.t:\n            pass'],
    ['else', 'else:\n            pass'],
  ].map(([tok, stmt]): [string, string, string, string] => [`py \`${stmt!.split('\n')[0]}\``, 'Disc.runar.py', py(stmt!), tok!]),
];

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n053-statement-drops-'));
});

let seq = 0;
function write(name: string, src: string): string {
  const sub = join(dir, String(seq++));
  mkdirSync(sub, { recursive: true });
  const p = join(sub, name);
  writeFileSync(p, src);
  return p;
}

/** Run a tier and return its refusal diagnostic; fail if it compiled. */
function refusal(tier: Tier, file: string): string {
  const r = spawnSync(tier.cmd!, [...tier.prefix, ...tier.argsFor(file)], {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.error) throw new Error(`${tier.id} could not run: ${r.error.message}`);
  if (r.status === 0) throw new Error(`${tier.id} ${file}: compiled, expected a refusal`);
  return `${r.stderr ?? ''}\n${r.stdout ?? ''}`;
}

// ---------------------------------------------------------------------------
// On-chain oracle
// ---------------------------------------------------------------------------

/** Push of a small script number 1..16 (OP_1..OP_16). */
const smallInt = (n: number): string => (0x50 + n).toString(16);

function spends(lockingHex: string, x: number): boolean {
  try {
    return newConsensusSpend({
      ...CONSENSUS_SPEND_CONTEXT,
      lockingScript: LockingScript.fromHex(lockingHex),
      unlockingScript: UnlockingScript.fromHex(smallInt(x)),
      otherInputs: [],
      outputs: [],
    }).validate();
  } catch {
    return false; // a thrown validation error is a failed spend
  }
}

function baked(src: string, fileName: string): string {
  const r = compile(src, { fileName, constructorArgs: { t: 7n } });
  expect(r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message)).toEqual([]);
  return r.artifact!.script.toLowerCase();
}

describe('N-053 statement drops — on-chain proof (@bsv/sdk Spend, t = 7)', () => {
  it('zig `_ = self.check(x);`: the guard is enforced', () => {
    const lock = baked(ZIG_DISC, 'Disc.runar.zig');
    expect(spends(lock, 7)).toBe(true);
    expect(spends(lock, 8)).toBe(false);
  });

  it('control: the pre-fix zig bytes (5177) accept the wrong x', () => {
    expect(spends('5177', 8)).toBe(true);
  });

  it('rb helper `!(x == @t)`: the guard is enforced, not inverted', () => {
    const lock = baked(RB_NEG, 'Disc.runar.rb');
    expect(spends(lock, 7)).toBe(true);
    expect(spends(lock, 8)).toBe(false);
  });

  it('control: the pre-fix rb bytes (t, OP_NUMEQUAL, OP_NOT) accept the wrong x and refuse the right one', () => {
    const inverted = `${smallInt(7)}9c91`;
    expect(spends(inverted, 8)).toBe(true);
    expect(spends(inverted, 7)).toBe(false);
  });
});

describe('N-053 statement drops — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [mode, tiers] of [
    ['fold-on', TIERS],
    ['fold-off', FOLD_OFF_TIERS],
  ] as const) {
    for (const [name, file, src, pin] of POSITIVE) {
      for (const tier of tiers) {
        it(`${tier.id} (${mode}) compiles ${name} to the pinned bytes`, () => {
          expect(compileHex(tier, write(file, src))).toBe(pin);
        });
      }
    }
  }

  for (const [name, file, src, tok] of REFUSED) {
    for (const tier of TIERS) {
      it(`${tier.id} refuses ${name} with the shared diagnostic`, () => {
        expect(refusal(tier, write(file, src))).toContain(SHARED(tok));
      });
    }
  }
});
