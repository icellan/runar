import { describe, it, expect } from 'vitest';
import { runStatelessSigned } from '../oracle/real-crypto-execution.js';

/**
 * NEW-014 — `&&` / `||` short-circuited in the AST interpreter but NOT in the
 * compiled script, so the ordinary defensive guard idiom deployed to a
 * permanently unspendable UTXO.
 *
 *     assert(d === 0n || (100n / d) > 1n);   // "guard the division"
 *     assert(len(b) < 4n || substr(b, 4n, 1n) === tail);   // "check first"
 *
 * Both read as safe. Both passed `TestContract`. Both were unspendable for
 * exactly the input the guard exists to protect.
 *
 * WHY IT HAPPENED
 * ---------------
 * `&&` / `||` lowered to `OP_BOOLAND` / `OP_BOOLOR`, which are binary stack
 * ops: both operands must already be ON the stack, so both are evaluated
 * unconditionally. `spec/semantics.md` §3.7 licensed that with
 *
 *   "This is safe in Rúnar because all expressions are pure (no side effects
 *    beyond `assert`)."
 *
 * Purity is not totality. The same document's §10 and §11.3 list division by
 * zero as a runtime failure, and `OP_SPLIT` / `OP_NUM2BIN` abort out of range
 * (NEW-010 / NEW-011). An operand that ABORTS is not "free to evaluate", so
 * the premise never held and the guard idiom was unwritable.
 *
 * The fix makes `&&` / `||` real control flow — the same `OP_IF` / `OP_ELSE`
 * lowering the ternary has always used, `a && b` = `a ? b : false` and
 * `a || b` = `a ? true : b`. §3.9 already specifies the ternary's untaken arm
 * as unevaluated, so laziness was already in the language; `&&` / `||` were
 * the sole eager outlier, and the interpreter never implemented the eager rule
 * anyway.
 *
 * WHAT THIS TEST PINS
 * -------------------
 * `runStatelessSigned` yields both verdicts from ONE compiled artifact:
 * `vmAccepted` from `@bsv/sdk`'s real `Spend.validate()` over the deployed
 * bytes, and `interpreterAccepted` from `TestContract` over the source AST.
 * They must agree, and they must agree with short-circuit source semantics.
 * `reachedEngine` is asserted so a harness error before `Spend` ran can never
 * be scored as a script rejection.
 *
 * BOTH DIRECTIONS ARE PINNED. A test that only pins "the guarded call is
 * accepted" is satisfied by a compiler that drops the right operand entirely,
 * so every short-circuiting case is paired with the input that must REACH the
 * right operand and with the input that must REJECT through it.
 */

const FILE = 'Sc.runar.ts';

function sc(imports: string, params: string, body: string): string {
  return `import { SmartContract, assert${imports ? `, ${imports}` : ''} } from 'runar-lang';
import type { ByteString } from 'runar-lang';

export class Sc extends SmartContract {
  readonly n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public m(${params}): void {
${body}
    assert(this.n > 0n);
  }
}
`;
}

/** 4 bytes, so `len(b) === 4n` is the boundary the guarded `substr` straddles. */
const B4 = new Uint8Array([1, 2, 3, 4]);

/** `d === 0n || (100n / d) > 1n` — the textbook divide-by-zero guard. */
const OR_DIV = sc('', 'd: bigint', '    assert(d === 0n || (100n / d) > 1n);');

/** `d !== 0n && (100n / d) > 1n` — the same guard written with `&&`. */
const AND_DIV = sc('', 'd: bigint', '    assert(d !== 0n && (100n / d) > 1n);');

/** `||` short-circuits away an OP_SPLIT that would abort out of range. */
const OR_SUBSTR = sc(
  'len, substr',
  'b: ByteString',
  '    assert(len(b) === 4n || len(substr(b, 9n, 1n)) === 1n);',
);

/** `&&` short-circuits away the same aborting OP_SPLIT. */
const AND_SUBSTR = sc(
  'len, substr',
  'b: ByteString',
  '    assert(len(b) !== 4n && len(substr(b, 9n, 1n)) === 1n);',
);

/** `||` short-circuits away an OP_NUM2BIN that would abort undersized. */
const OR_NUM2BIN = sc(
  'len, num2bin',
  'b: ByteString',
  '    assert(len(b) === 4n || len(num2bin(70000n, 1n)) === 1n);',
);

/** Chained `||`: the FIRST true operand must stop evaluation. */
const OR_CHAIN = sc(
  '',
  'd: bigint',
  '    assert(d === 0n || d === 1n || (100n / d) > 1n);',
);

/** Chained `&&`: the FIRST false operand must stop evaluation. */
const AND_CHAIN = sc(
  '',
  'd: bigint',
  '    assert(d !== 0n && d !== 1n && (100n / d) > 1n);',
);

/** Mixed precedence — `&&` binds tighter, so this is `(a && b) || c`. */
const MIXED = sc(
  '',
  'd: bigint',
  '    assert(d === 0n && d === 0n || (100n / d) > 1n);',
);

interface Case {
  readonly label: string;
  readonly source: string;
  readonly args: (bigint | Uint8Array)[];
  /** What the SOURCE says, and therefore what both engines must say. */
  readonly accepts: boolean;
}

const CASES: Case[] = [
  // --- `||` guards a division by zero -------------------------------------
  // No byte op involved: OP_DIV has always aborted on a zero divisor, so this
  // half of NEW-014 predates every byte-op change.
  { label: '|| guards OP_DIV, d=0 — right operand must NOT run', source: OR_DIV, args: [0n], accepts: true },
  { label: '|| guards OP_DIV, d=5 — right operand runs and holds', source: OR_DIV, args: [5n], accepts: true },
  { label: '|| guards OP_DIV, d=200 — right operand runs and fails', source: OR_DIV, args: [200n], accepts: false },

  // --- `&&` guards a division by zero -------------------------------------
  { label: '&& guards OP_DIV, d=0 — right operand must NOT run', source: AND_DIV, args: [0n], accepts: false },
  { label: '&& guards OP_DIV, d=5 — right operand runs and holds', source: AND_DIV, args: [5n], accepts: true },
  { label: '&& guards OP_DIV, d=200 — right operand runs and fails', source: AND_DIV, args: [200n], accepts: false },

  // --- `||` / `&&` guard an out-of-range OP_SPLIT (NEW-010's abort) -------
  { label: '|| guards OP_SPLIT, len=4 — right operand must NOT run', source: OR_SUBSTR, args: [B4], accepts: true },
  { label: '&& guards OP_SPLIT, len=4 — right operand must NOT run', source: AND_SUBSTR, args: [B4], accepts: false },

  // --- `||` guards an undersized OP_NUM2BIN (NEW-011's abort) ------------
  { label: '|| guards OP_NUM2BIN, len=4 — right operand must NOT run', source: OR_NUM2BIN, args: [B4], accepts: true },

  // --- chains: laziness has to survive nesting ---------------------------
  { label: '|| chain, d=0 — stops at the first operand', source: OR_CHAIN, args: [0n], accepts: true },
  { label: '|| chain, d=1 — stops at the second operand', source: OR_CHAIN, args: [1n], accepts: true },
  { label: '|| chain, d=5 — reaches the third operand and holds', source: OR_CHAIN, args: [5n], accepts: true },
  { label: '|| chain, d=200 — reaches the third operand and fails', source: OR_CHAIN, args: [200n], accepts: false },
  { label: '&& chain, d=0 — stops at the first operand', source: AND_CHAIN, args: [0n], accepts: false },
  { label: '&& chain, d=1 — stops at the second operand', source: AND_CHAIN, args: [1n], accepts: false },
  { label: '&& chain, d=5 — reaches the third operand and holds', source: AND_CHAIN, args: [5n], accepts: true },

  // --- mixed precedence ---------------------------------------------------
  { label: '(a && b) || c, d=0 — the `&&` is true so `c` must NOT run', source: MIXED, args: [0n], accepts: true },
  { label: '(a && b) || c, d=5 — the `&&` is false so `c` runs and holds', source: MIXED, args: [5n], accepts: true },
  { label: '(a && b) || c, d=200 — the `&&` is false so `c` runs and fails', source: MIXED, args: [200n], accepts: false },

  // --- controls: these agreed BEFORE the fix and must keep agreeing -------
  // Same aborting operand, NOT short-circuited: both engines reject.
  {
    label: 'CONTROL bare OP_SPLIT out of range — both reject',
    source: sc('len, substr', 'b: ByteString', '    assert(len(substr(b, 9n, 1n)) === 1n);'),
    args: [B4],
    accepts: false,
  },
  // Short-circuit position, PURE operand: nothing to abort either way.
  {
    label: 'CONTROL || with a pure right operand, left true',
    source: sc('len, substr', 'b: ByteString', '    assert(len(b) === 4n || len(substr(b, 1n, 1n)) === 9n);'),
    args: [B4],
    accepts: true,
  },
  {
    label: 'CONTROL || with a pure right operand, left false',
    source: sc('len', 'b: ByteString', '    assert(len(b) === 9n || len(b) === 4n);'),
    args: [B4],
    accepts: true,
  },
  {
    label: 'CONTROL && with a pure right operand, both true',
    source: sc('len', 'b: ByteString', '    assert(len(b) === 4n && len(b) > 0n);'),
    args: [B4],
    accepts: true,
  },
  {
    label: 'CONTROL && with a pure right operand, right false',
    source: sc('len', 'b: ByteString', '    assert(len(b) === 4n && len(b) > 9n);'),
    args: [B4],
    accepts: false,
  },
];

describe('NEW-014 — `&&` / `||` short-circuit on-chain, not just in the interpreter', () => {
  for (const c of CASES) {
    it(`${c.label} => ${c.accepts ? 'ACCEPT' : 'REJECT'} on both engines`, () => {
      const r = runStatelessSigned({
        source: c.source,
        fileName: FILE,
        method: 'm',
        args: c.args,
        constructorArgs: { n: 1n },
      });
      // Attribute the verdict to the script, not to a harness error.
      expect(r.reachedEngine, `never reached Spend: ${r.vmError ?? ''}`).toBe(true);
      expect(
        r.vmAccepted,
        `the real engine disagreed with short-circuit source semantics: ${r.vmError ?? '(accepted)'}`,
      ).toBe(c.accepts);
      expect(
        r.interpreterAccepted,
        `TestContract disagreed with the real engine: ${r.interpreterError ?? '(accepted)'}`,
      ).toBe(c.accepts);
    });
  }
});
