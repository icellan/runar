import { describe, it, expect, beforeAll } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers, compileHex } from './tier-harness.js';
import { isCiEnv } from '../anf-interpreter/driver-gate.js';

/**
 * N-115 — a reversed loop comparison (`5n > i`) is the canonical one (`i < 5n`).
 *
 * The Zig tier's `.runar.zig` `while` parser accepted `while (5 > i)` and
 * `while (4 >= i)` and lowered them as `i < 5` / `i <= 4`. Every other tier,
 * and every other surface in the Zig tier, refused the same comparison because
 * the loop-condition rule (W4, `validateForConditionTestsIterator`) reads the
 * iterator off the LEFT-hand side only. User decision R87: accept the reversed
 * form everywhere. Each tier now rewrites `N op i` to `i op' N` (operands
 * swapped, comparison mirrored) at parse time, before validation, so the rest
 * of the pipeline only ever sees the canonical spelling.
 *
 * Proves: on every surface whose loop header carries a comparison (`.runar.ts`,
 * `.sol`, `.move` while-fold, `.go`, `.zig` while, `.java`), for all four
 * mirrored operators (count-up `>`/`>=`, count-down `<`/`<=`), every available
 * tier compiles the reversed spelling to exactly the bytes the TS reference
 * emits for the canonical `.runar.ts` spelling, in both fold modes.
 * Does not prove: anything about conditions the rewrite leaves alone — a
 * computed left-hand side (N40), a stray variable (N41) and a direction
 * mismatch (N42) keep their own seven-tier refusal gates. `.runar.py`/`.rs`/
 * `.rb` loops are range-based and have no comparison to reverse.
 */

type Shape = { start: number; up: boolean; op: '<' | '<=' | '>' | '>='; n: number };

/** The canonical comparison and the iteration it drives. The reversed form
 *  of each is `n MIRROR[op] i`. */
const SHAPES: Shape[] = [
  { start: 0, up: true, op: '<', n: 5 },
  { start: 0, up: true, op: '<=', n: 4 },
  { start: 5, up: false, op: '>', n: 0 },
  { start: 5, up: false, op: '>=', n: 1 },
];
const MIRROR = { '<': '>', '<=': '>=', '>': '<', '>=': '<=' } as const;
const JAVA_OP = { '<': 'lt', '<=': 'le', '>': 'gt', '>=': 'ge' } as const;

const tsSource = (s: Shape, cond: string): string => `import { SmartContract, assert } from 'runar-lang';

class L extends SmartContract {
  readonly expectedSum: bigint;
  constructor(expectedSum: bigint) {
    super(expectedSum);
    this.expectedSum = expectedSum;
  }
  public verify(start: bigint): void {
    let sum: bigint = 0n;
    for (let i: bigint = ${s.start}n; ${cond}; i${s.up ? '++' : '--'}) {
      sum = sum + start + i;
    }
    assert(sum === this.expectedSum);
  }
}
`;

/** [extension, source for a reversed condition]. */
const SURFACES: Array<[string, (s: Shape) => string]> = [
  ['ts', (s) => tsSource(s, `${s.n}n ${MIRROR[s.op]} i`)],
  ['sol', (s) => `pragma runar ^0.1.0;

contract L is SmartContract {
    int immutable expectedSum;
    constructor(int _expectedSum) { expectedSum = _expectedSum; }
    function verify(int start) public {
        int sum = 0;
        for (int i = ${s.start}; ${s.n} ${MIRROR[s.op]} i; i${s.up ? '++' : '--'}) {
            sum = sum + start + i;
        }
        require(sum == expectedSum);
    }
}
`],
  ['move', (s) => `module L {
    use runar::types::{Int};
    struct L { expected_sum: Int, }
    public fun verify(contract: &L, start: Int) {
        let sum: Int = 0;
        let i: Int = ${s.start};
        while (${s.n} ${MIRROR[s.op]} i) {
            sum = sum + start + i;
            i = i ${s.up ? '+' : '-'} 1;
        };
        assert_eq!(sum, contract.expected_sum);
    }
}
`],
  ['go', (s) => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type L struct {
	runar.SmartContract
	ExpectedSum runar.Int \`runar:"readonly"\`
}

func (c *L) Verify(start runar.Int) {
	sum := runar.Int(0)
	for i := runar.Int(${s.start}); ${s.n} ${MIRROR[s.op]} i; i${s.up ? '++' : '--'} {
		sum = sum + start + i
	}
	runar.Assert(sum == c.ExpectedSum)
}
`],
  ['zig', (s) => `const runar = @import("runar");

pub const L = struct {
    pub const Contract = runar.SmartContract;
    expectedSum: i64,
    pub fn init(expectedSum: i64) L {
        return .{ .expectedSum = expectedSum };
    }
    pub fn verify(self: *const L, start: i64) void {
        var sum: i64 = 0;
        var i: i64 = ${s.start};
        while (${s.n} ${MIRROR[s.op]} i) : (i ${s.up ? '+=' : '-='} 1) {
            sum = sum + start + i;
        }
        runar.assert(sum == self.expectedSum);
    }
};
`],
  ['java', (s) => `package p;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

class L extends SmartContract {
    @Readonly Bigint expectedSum;
    L(Bigint expectedSum) { super(expectedSum); this.expectedSum = expectedSum; }
    @Public
    void verify(Bigint start) {
        Bigint sum = Bigint.ZERO;
        for (Bigint i = Bigint.of(${s.start}); Bigint.of(${s.n}).${JAVA_OP[MIRROR[s.op]]}(i); i = i.${s.up ? 'plus' : 'minus'}(Bigint.ONE)) {
            sum = sum.plus(start).plus(i);
        }
        assertThat(sum.eq(this.expectedSum));
    }
}
`],
];

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF_TIERS: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n115-reversed-loop-'));
});

let seq = 0;
function write(ext: string, src: string): string {
  const sub = join(dir, String(seq++));
  mkdirSync(sub, { recursive: true });
  const p = join(sub, `L.runar.${ext}`);
  writeFileSync(p, src);
  return p;
}

/** Hex, or the tier's refusal text — collected per tier so a failure shows the
 *  whole matrix instead of stopping at the first tier that disagrees. This is
 *  not a rejection assertion: every entry is compared against the reference
 *  hex, so a refusal (or a broken tier) can only ever fail the test. */
function outcome(tier: Tier, file: string): string {
  try {
    return compileHex(tier, file);
  } catch (e) {
    return `NO HEX: ${(e as Error).message.replace(/\s+/g, ' ').slice(0, 200)}`;
  }
}

describe('N-115 reversed loop comparison: seven-tier byte parity with the canonical form', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [mode, tiers] of [
    ['fold-on', TIERS],
    ['fold-off', FOLD_OFF_TIERS],
  ] as const) {
    for (const shape of SHAPES) {
      const canonical = `i ${shape.op} ${shape.n}n`;
      const reversed = `${shape.n} ${MIRROR[shape.op]} i`;
      it(`\`${reversed}\` (${mode}): every surface, every tier emits the TS bytes of \`${canonical}\``, () => {
        const ts = tiers.find((t) => t.id === 'ts');
        expect(ts, 'the TS reference tier is required').toBeDefined();
        const want = compileHex(ts!, write('ts', tsSource(shape, canonical)));

        const got: Record<string, string> = {};
        const expected: Record<string, string> = {};
        for (const [ext, source] of SURFACES) {
          const file = write(ext, source(shape));
          for (const tier of tiers) {
            got[`${ext}/${tier.id}`] = outcome(tier, file);
            expected[`${ext}/${tier.id}`] = want;
          }
        }
        expect(got).toEqual(expected);
      }, 1_800_000);
    }
  }
});
