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
import { Tier, buildSourceTiers, compileHex } from './tier-harness.js';
import { isCiEnv } from '../anf-interpreter/driver-gate.js';

/**
 * N-153 — statement-shape parity on the .sol / .move / .go / .rs surfaces.
 *
 * N-053 aligned the .zig / .rb / .py / .java statement dispatchers. Probing
 * the remaining four surfaces found seven more shapes on which the tiers
 * disagreed. The TS reference decides each one:
 *
 *   - .rs bare block `{ ... }`: TS refuses. The Ruby tier alone accepted it,
 *     and a GUARD DROP: its expression parser turned `{` into the literal 0
 *     without a diagnostic, the block's `}` closed the METHOD, and every
 *     statement after the block was skipped as impl-level junk. So
 *     `{ assert!(true); } assert!(x == self.t);` compiled to 00517777, which
 *     any x unlocks;
 *   - .rs `;` (an empty statement): TS refuses; Zig and Ruby accepted;
 *   - .sol `;`: TS refuses; Zig accepted;
 *   - .move `abort 0;`: TS refuses (`abort` is not part of the Move surface);
 *     Zig accepted it as assert(false);
 *   - .move `;`: TS accepts it as a no-op; Rust refused;
 *   - .go `;` as an empty statement: TS refuses; Rust, Python and Java
 *     accepted. (A `;` that SEPARATES two statements on one line is a
 *     different shape and is not settled here — see the report for N-153.)
 *   - .go `_ = y` with y a local: Zig dropped the assignment, the others bind
 *     `_` like the TS reference does;
 *   - .go `{ ... }` at statement start: TS, Rust, Python, Ruby and Java read it
 *     as a brace composite literal (accepting `{ x, c.check(x) }`, which is
 *     not Go); Go and Zig refused. Decision: refuse it in every tier.
 *
 * What this proves:
 *   - every available tier compiles each accepted shape to the same bytes as
 *     the TS reference, in both fold modes;
 *   - every available tier refuses each refused shape, and the TS reference
 *     plus every tier this item changed say so with the TS diagnostic;
 *   - under @bsv/sdk Spend (consensus rules, version-1 tx) the Ruby tier's
 *     pre-fix .rs bytes accept a wrong x, while the TS bytes of the same
 *     guard, with the block removed, refuse it — so the dropped statement was
 *     the only guard.
 *   - every tier refuses a .go `{` at statement start (bare block or not-Go
 *     brace literal), the TS reference and the tiers changed here with the
 *     TS diagnostic, while composite literals in expression position still
 *     compile (positive pins below).
 * What it does NOT prove: the .go same-line `;` separator (N-154), and any
 *   surface other than .sol / .move / .go / .rs.
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF_TIERS: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));

const UNEXPECTED = (tok: string): string => `Unexpected token in expression: '${tok}'`;
const UNDEFINED = (name: string): string => `Undefined variable '${name}'`;

// ---------------------------------------------------------------------------
// Sources (one contract per surface; `@@` is the probed statement)
// ---------------------------------------------------------------------------

const sol = (stmt: string): string => `pragma runar ^0.1.0;

contract Disc is SmartContract {
    bigint immutable t;

    constructor(bigint _t) {
        t = _t;
    }

    function unlock(bigint x) public {
        ${stmt}
        require(true);
    }

    function check(bigint x) private returns (bigint) {
        require(x == t);
        return x;
    }
}
`;

const move = (stmt: string): string => `module Disc {
    use runar::SmartContract;
    use runar::types::{Int};

    struct Disc {
        t: Int,
    }

    public fun unlock(contract: &Disc, x: Int) {
        ${stmt}
        assert!(true, 0);
    }

    fun check(x: Int): Int {
        assert!(x == self.t, 0);
        return x;
    }
}
`;

const go = (stmt: string): string => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Disc struct {
\trunar.SmartContract
\tT runar.Bigint \`runar:"readonly"\`
}

func (c *Disc) Unlock(x runar.Bigint) {
\t${stmt}
\trunar.Assert(true)
}

func (c *Disc) check(x runar.Bigint) runar.Bigint {
\trunar.Assert(x == c.T)
\treturn x
}
`;

/** .rs Disc whose unlock body is exactly `body`. */
const rsBody = (body: string): string => `use runar::prelude::*;

#[runar::contract]
pub struct Disc {
    #[readonly]
    pub t: Bigint,
}

impl Disc {
    pub fn unlock(&self, x: Bigint) {
        ${body}
    }

    fn check(&self, x: Bigint) -> Bigint {
        assert!(x == self.t);
        x
    }
}
`;
const rs = (stmt: string): string => rsBody(`${stmt}\n        assert!(true);`);

/** The Ruby guard drop: the only guard sits after a bare block. */
const RS_GUARD_AFTER_BLOCK = rsBody('{ assert!(true); }\n        assert!(x == self.t);');

/** Statement-position `{` shapes: [case name, statement]. */
const GO_BLOCKS: Array<[string, string]> = [
  ['`{ runar.Assert(...) }`', '{ runar.Assert(x == c.T) }'],
  ['`{ x, c.check(x) }` (not Go)', '{ x, c.check(x) }'],
  ['`{ c.check(x) }`', '{ c.check(x) }'],
  ['`{ }`', '{ }'],
  ['`{ y := x ... }` (a real Go block)', '{\n\t\ty := x\n\t\trunar.Assert(y == c.T)\n\t}'],
  ['`{ if ... }` (a real Go block)', '{\n\t\tif x == c.T {\n\t\t\trunar.Assert(true)\n\t\t}\n\t}'],
  ['nested in an if arm', 'if x == c.T {\n\t\t{ runar.Assert(true) }\n\t}'],
];

/** [case name, file name, source, pinned TS hex (fold OFF and ON agree)]. */
const POSITIVE: Array<[string, string, string, string]> = [
  ['move `;`', 'Disc.runar.move', move(';'), '5177'],
  ['move `;;`', 'Disc.runar.move', move(';;'), '5177'],
  ['move `self.check(x);;`', 'Disc.runar.move', move('self.check(x);;'), '76009d5177'],
  ['move `if (...) { ; };`', 'Disc.runar.move', move('if (x == self.t) { ; };'), '009c636851'],
  ['go `y := c.check(x); _ = y`', 'Disc.runar.go', go('y := c.check(x)\n\t_ = y'), '76009d76517777'],
  ['go `y := x + 1; _ = y; _ = y`', 'Disc.runar.go', go('y := x + 1\n\t_ = y\n\t_ = y'), '8b767c517777'],
  ['go `_ = x`', 'Disc.runar.go', go('_ = x'), '5177'],
  ['go `_ = c.T`', 'Disc.runar.go', go('_ = c.T'), '00517777'],
  ['go `_ = c.check(x)`', 'Disc.runar.go', go('_ = c.check(x)'), '76009d5177'],
];

/**
 * [case name, file name, source, TS diagnostic, tiers that must print it].
 * Every tier must refuse; the TS reference and the tiers this item changed
 * must say so with the TS diagnostic (the others keep their own wording —
 * cross-tier refusal parity is wording-independent, see rejection-parity).
 */
const REFUSED: Array<[string, string, string, string, string[]]> = [
  ['rs `{ ... }` then the guard', 'Disc.runar.rs', RS_GUARD_AFTER_BLOCK, UNEXPECTED('{'), ['ts', 'ruby']],
  ['rs `{ assert!(...); }`', 'Disc.runar.rs', rs('{ assert!(x == self.t); }'), UNEXPECTED('{'), ['ts', 'ruby']],
  ['rs `;`', 'Disc.runar.rs', rs(';'), UNEXPECTED(';'), ['ts', 'zig', 'ruby']],
  ['rs `assert!(...);;`', 'Disc.runar.rs', rs('assert!(x == self.t);;'), UNEXPECTED(';'), ['ts', 'zig', 'ruby']],
  ['sol `;`', 'Disc.runar.sol', sol(';'), UNEXPECTED(';'), ['ts', 'zig']],
  ['sol `require(...);;`', 'Disc.runar.sol', sol('require(x == t);;'), UNEXPECTED(';'), ['ts', 'zig']],
  ['move `abort 0;`', 'Disc.runar.move', move('abort 0;'), UNDEFINED('abort'), ['ts', 'zig']],
  ['move `if (...) { abort 0; };`', 'Disc.runar.move', move('if (x != self.t) { abort 0; };'), UNDEFINED('abort'), ['ts', 'zig']],
  ['go `;`', 'Disc.runar.go', go(';'), UNEXPECTED(';'), ['ts', 'rust', 'python', 'java']],
  ['go `;` on the line after a statement', 'Disc.runar.go', go('runar.Assert(x == c.T)\n\t;'), UNEXPECTED(';'), ['ts', 'rust', 'python', 'java']],
  ['go `stmt; ;`', 'Disc.runar.go', go('runar.Assert(x == c.T); ;'), UNEXPECTED(';'), ['ts', 'rust', 'python', 'java']],
  ['go `if ... { ; }`', 'Disc.runar.go', go('if x == c.T { ; }'), UNEXPECTED(';'), ['ts', 'rust', 'python', 'java']],
  // A `{` at statement start is refused (user decision on the N-153
  // escalation). TS used to read it as a brace composite literal: it accepted
  // `{ x, c.check(x) }` (not Go) and refused real Go blocks for unrelated
  // reasons. Composite literals in expression position are unaffected.
  ...GO_BLOCKS.map(([name, stmt]): [string, string, string, string, string[]] => [
    `go ${name}`, 'Disc.runar.go', go(stmt), UNEXPECTED('{'), ['ts', 'rust', 'python', 'ruby', 'java'],
  ]),
];

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n153-statement-shapes-'));
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
  if (r.status === 0) throw new Error(`${tier.id} ${file}: compiled (${r.stdout.trim().slice(-40)}), expected a refusal`);
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

describe('N-153 .rs bare block — the dropped statement was the only guard (@bsv/sdk Spend, t = 7)', () => {
  it('the TS bytes of the guard without the block (5169, t, 9c) refuse x = 8 and accept x = 7', () => {
    // `assert!(true); assert!(x == self.t);` — TS emits 5169 009c, t baked as OP_7.
    const guarded = `5169${smallInt(7)}9c`;
    expect(spends(guarded, 8)).toBe(false);
    expect(spends(guarded, 7)).toBe(true);
  });

  it('control: the pre-fix Ruby bytes (00517777) accept the wrong x', () => {
    expect(spends('00517777', 8)).toBe(true);
  });
});

describe('N-153 statement shapes — seven-tier parity', () => {
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
        it(`${tier.id} (${mode}) compiles ${name} to the TS bytes`, () => {
          expect(compileHex(tier, write(file, src))).toBe(pin);
        });
      }
    }
  }

  for (const [name, file, src, diag, sayIt] of REFUSED) {
    for (const tier of TIERS) {
      it(`${tier.id} refuses ${name}`, () => {
        const out = refusal(tier, write(file, src));
        if (sayIt.includes(tier.id)) expect(out).toContain(diag);
      });
    }
  }
});
