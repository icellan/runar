import { describe, it, expect } from 'vitest';
import { runStatelessSigned } from '../oracle/real-crypto-execution.js';

/**
 * NEW-010 / NEW-011 — `TestContract`'s AST interpreter accepted two byte-op
 * edges the chain ABORTS on, so a contract whose off-chain tests were green
 * deployed to a permanently unspendable UTXO.
 *
 * NEW-010 — the OP_SPLIT family (`substr` / `left` / `right` / `split`)
 * ---------------------------------------------------------------------
 * The interpreter forwarded the caller's bounds straight to
 * `Uint8Array.slice`, which CLAMPS an out-of-range range and reads a NEGATIVE
 * start from the END of the array. `OP_SPLIT` does neither — it aborts:
 *
 *   OP_SPLIT requires the first stack item to be a non-negative number less
 *   than or equal to the size of the second-from-top stack item.
 *
 * Three directions failed open: `start > len`, `start + len > len`, and a
 * negative bound. `substr` is `<data> <start> OP_SPLIT OP_NIP <length>
 * OP_SPLIT OP_DROP` (`lowerSubstr`, 05-stack-lower.ts), so BOTH splits are
 * bounds-checked, the second against the REMAINDER `len - start`. `left` is
 * `OP_SPLIT OP_DROP`, `split` is a bare `OP_SPLIT`, and `right` is
 * `OP_SWAP OP_SIZE OP_ROT OP_SUB OP_SPLIT OP_NIP` — its split index is
 * `size - n`, which is what makes `right(b, n > len(b))` a NEGATIVE index.
 *
 * NEW-011 — `num2bin` / `int2str` undersized
 * ------------------------------------------
 * The interpreter silently TRUNCATED to the requested width. `OP_NUM2BIN`
 * aborts:
 *
 *   OP_NUM2BIN requires that the size expressed in the top stack item is
 *   large enough to hold the value expressed in the second-from-top stack
 *   item.
 *
 * This one is worse than a wrong accept/reject bit: `num2bin(70000n, 1n)`
 * returned the bytes of 112 with no error, so every downstream comparison in
 * the test ran against a value the chain will never produce.
 *
 * WHY BOTH DIRECTIONS ARE PINNED
 * ------------------------------
 * A test that only pins the aborts is satisfied by an interpreter that
 * rejects everything. Every out-of-range case below is paired with its
 * IN-RANGE neighbour — `substr` at 0 and at `len`, `left`/`right`/`split` at
 * 0 and at `len`, `num2bin` at exact width, at a padded width and at width 0
 * — and those neighbours are verified to agree on every engine today, so a
 * fix that turns one of them red is wrong.
 *
 * The two `num2bin` VALUE pins (`701101`, `70110100`, `0180`) exist because
 * accept/reject alone cannot catch the truncation half of NEW-011: the
 * padding path (including moving a negative number's sign bit to the new MSB)
 * has to keep producing the same bytes the engine produces.
 *
 * TWO INDEPENDENT PATHS
 * ---------------------
 * `runStatelessSigned` returns BOTH verdicts for one compiled artifact:
 * `vmAccepted` from `@bsv/sdk`'s real `Spend.validate()` over the deployed
 * bytes, and `interpreterAccepted` from `TestContract` over the source AST.
 * The engine verdict is the authority; the interpreter is required to match
 * it. `reachedEngine` is asserted so a harness error before `Spend` ran can
 * never be scored as a script rejection.
 */

const FILE = 'Edge.runar.ts';

/**
 * A minimal stateless contract. `n` is a constructor-baked property, so the
 * compiled bytes are runnable without the SDK's constructor-slot splice.
 */
function edge(imports: string, params: string, body: string): string {
  return `import { SmartContract, assert, ${imports} } from 'runar-lang';
import type { ByteString } from 'runar-lang';

export class Edge extends SmartContract {
  readonly n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public m(${params}): void {
${body}
    assert(this.n > 0n);
  }
}
`;
}

/** 4 bytes, so `len(b) === 4n` is the boundary every split case straddles. */
const B4 = new Uint8Array([1, 2, 3, 4]);

/** `assert(len(<expr>) >= 0n)` — always true, so the ONLY way to fail is the
 *  OP_SPLIT abort itself. */
const splitCase = (imports: string, expr: string): string =>
  edge(`${imports}, len`, 'b: ByteString', `    assert(len(${expr}) >= 0n);`);

const numCase = (imports: string, body: string): string =>
  edge(imports, 'p: bigint', body);

interface Case {
  readonly label: string;
  readonly source: string;
  readonly args: (bigint | Uint8Array)[];
  /** The real engine's verdict — and therefore the interpreter's. */
  readonly accepts: boolean;
}

const SPLIT_CASES: Case[] = [
  // --- substr: in-range neighbours (must keep working) --------------------
  { label: 'substr(b, 0, 4) — split at offset 0', source: splitCase('substr', 'substr(b, 0n, 4n)'), args: [B4], accepts: true },
  { label: 'substr(b, 4, 0) — split at offset len', source: splitCase('substr', 'substr(b, 4n, 0n)'), args: [B4], accepts: true },
  { label: 'substr(b, 2, 2) — interior', source: splitCase('substr', 'substr(b, 2n, 2n)'), args: [B4], accepts: true },
  // --- substr: out of range (NEW-010) -------------------------------------
  { label: 'substr(b, 5, 0) — start > len', source: splitCase('substr', 'substr(b, 5n, 0n)'), args: [B4], accepts: false },
  { label: 'substr(b, 0, 9) — start + len > len', source: splitCase('substr', 'substr(b, 0n, 9n)'), args: [B4], accepts: false },
  { label: 'substr(b, 3, 2) — start + len > len, start in range', source: splitCase('substr', 'substr(b, 3n, 2n)'), args: [B4], accepts: false },
  { label: 'substr(b, -1, 1) — negative start', source: splitCase('substr', 'substr(b, -1n, 1n)'), args: [B4], accepts: false },
  { label: 'substr(b, 0, -1) — negative length', source: splitCase('substr', 'substr(b, 0n, -1n)'), args: [B4], accepts: false },

  // --- left ---------------------------------------------------------------
  { label: 'left(b, 0) — in range', source: splitCase('left', 'left(b, 0n)'), args: [B4], accepts: true },
  { label: 'left(b, 4) — in range, at len', source: splitCase('left', 'left(b, 4n)'), args: [B4], accepts: true },
  { label: 'left(b, 5) — > len', source: splitCase('left', 'left(b, 5n)'), args: [B4], accepts: false },
  { label: 'left(b, -1) — negative', source: splitCase('left', 'left(b, -1n)'), args: [B4], accepts: false },

  // --- right (split index is `size - n`) ----------------------------------
  { label: 'right(b, 0) — in range', source: splitCase('right', 'right(b, 0n)'), args: [B4], accepts: true },
  { label: 'right(b, 4) — in range, at len', source: splitCase('right', 'right(b, 4n)'), args: [B4], accepts: true },
  { label: 'right(b, 5) — > len', source: splitCase('right', 'right(b, 5n)'), args: [B4], accepts: false },
  { label: 'right(b, -1) — negative', source: splitCase('right', 'right(b, -1n)'), args: [B4], accepts: false },

  // --- split --------------------------------------------------------------
  { label: 'split(b, 0) — in range', source: splitCase('split', 'split(b, 0n)'), args: [B4], accepts: true },
  { label: 'split(b, 4) — in range, at len', source: splitCase('split', 'split(b, 4n)'), args: [B4], accepts: true },
  { label: 'split(b, 5) — > len', source: splitCase('split', 'split(b, 5n)'), args: [B4], accepts: false },
  { label: 'split(b, -1) — negative', source: splitCase('split', 'split(b, -1n)'), args: [B4], accepts: false },
];

/**
 * 70000 = 0x011170; its minimal script-number encoding is the 3 bytes
 * `701101` (little-endian, high bit of the MSB clear so no sign byte).
 * -1 encodes minimally as the 1 byte `81`; widened to 2 bytes the engine
 * moves the sign bit to the NEW most-significant byte, giving `0180`.
 */
const NUM_CASES: Case[] = [
  // --- in-range neighbours, pinned BY VALUE -------------------------------
  {
    label: 'num2bin(70000, 3) — exact minimal width',
    source: numCase('num2bin, toByteString', `    assert(num2bin(p, 3n) === toByteString('701101'));`),
    args: [70000n],
    accepts: true,
  },
  {
    label: 'num2bin(70000, 4) — padded one byte',
    source: numCase('num2bin, toByteString', `    assert(num2bin(p, 4n) === toByteString('70110100'));`),
    args: [70000n],
    accepts: true,
  },
  {
    label: 'num2bin(-1, 2) — padded, sign bit moves to the new MSB',
    source: numCase('num2bin, toByteString', `    assert(num2bin(p, 2n) === toByteString('0180'));`),
    args: [-1n],
    accepts: true,
  },
  {
    label: 'num2bin(0, 0) — zero value, zero width',
    source: numCase('num2bin, len', `    assert(len(num2bin(p, 0n)) === 0n);`),
    args: [0n],
    accepts: true,
  },
  {
    label: 'num2bin(0, 4) — zero value, padded',
    source: numCase('num2bin, toByteString', `    assert(num2bin(p, 4n) === toByteString('00000000'));`),
    args: [0n],
    accepts: true,
  },
  {
    label: 'int2str(70000, 3) — exact minimal width',
    source: numCase('int2str, toByteString', `    assert(int2str(p, 3n) === toByteString('701101'));`),
    args: [70000n],
    accepts: true,
  },

  // --- undersized (NEW-011) ------------------------------------------------
  {
    label: 'num2bin(70000, 1) — undersized by 2',
    source: numCase('num2bin, len', `    assert(len(num2bin(p, 1n)) >= 0n);`),
    args: [70000n],
    accepts: false,
  },
  {
    label: 'num2bin(70000, 2) — undersized by 1',
    source: numCase('num2bin, len', `    assert(len(num2bin(p, 2n)) >= 0n);`),
    args: [70000n],
    accepts: false,
  },
  {
    label: 'num2bin(-1, 0) — undersized, negative value',
    source: numCase('num2bin, len', `    assert(len(num2bin(p, 0n)) >= 0n);`),
    args: [-1n],
    accepts: false,
  },
  {
    label: 'int2str(70000, 1) — undersized by 2 (the num2bin alias)',
    source: numCase('int2str, len', `    assert(len(int2str(p, 1n)) >= 0n);`),
    args: [70000n],
    accepts: false,
  },
];

function run(c: Case) {
  return runStatelessSigned({
    source: c.source,
    fileName: FILE,
    method: 'm',
    args: c.args,
    constructorArgs: { n: 1n },
  });
}

describe('NEW-010 — the OP_SPLIT family is bounds-checked', () => {
  for (const c of SPLIT_CASES) {
    it(`${c.label} => ${c.accepts ? 'ACCEPT' : 'REJECT'} on both engines`, () => {
      const r = run(c);
      // Attribute the verdict to the script guard, not to a harness error.
      expect(r.reachedEngine, `never reached Spend: ${r.vmError ?? ''}`).toBe(true);
      expect(r.vmAccepted, `Spend disagreed with the fixture: ${r.vmError ?? ''}`).toBe(c.accepts);
      expect(
        r.interpreterAccepted,
        `TestContract disagreed with the real engine: ${r.interpreterError ?? '(accepted)'}`,
      ).toBe(c.accepts);
      if (!c.accepts) {
        expect(r.vmError ?? '').toContain('OP_SPLIT requires the first stack item');
        expect(r.interpreterError ?? '').toContain('OP_SPLIT requires the first stack item');
      }
    });
  }
});

describe('NEW-011 — num2bin rejects a width too small for the value', () => {
  for (const c of NUM_CASES) {
    it(`${c.label} => ${c.accepts ? 'ACCEPT' : 'REJECT'} on both engines`, () => {
      const r = run(c);
      expect(r.reachedEngine, `never reached Spend: ${r.vmError ?? ''}`).toBe(true);
      expect(r.vmAccepted, `Spend disagreed with the fixture: ${r.vmError ?? ''}`).toBe(c.accepts);
      expect(
        r.interpreterAccepted,
        `TestContract disagreed with the real engine: ${r.interpreterError ?? '(accepted)'}`,
      ).toBe(c.accepts);
      if (!c.accepts) {
        expect(r.vmError ?? '').toContain('OP_NUM2BIN requires that the size');
        expect(r.interpreterError ?? '').toContain('OP_NUM2BIN requires that the size');
      }
    });
  }
});
