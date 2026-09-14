/**
 * N-051 — a private-helper call inside a BRANCH ARM must inline the callee.
 *
 * `spec/semantics.md` §6.3 defines a private method as source-level
 * substitution at every call site, and its canonical example is a helper call
 * in EXPRESSION position:
 *
 *     private square(x: bigint): bigint { return x * x; }
 *     public verify(n: bigint): void { assert(this.square(n) < 100n); }
 *     // After inlining:
 *     public verify(n: bigint): void { assert(n * n < 100n); }
 *
 * `spec/ir-format.md` §4.7 keeps `method_call` in the canonical ANF ("Inlining
 * happens in a later compiler phase"), so the substitution is stack lowering's
 * job — and stack lowering lowers an `if`'s arms in a FRESH context.
 *
 * The defect: Go, Rust and Python built that arm context without copying the
 * private-method map. Inside an arm the callee was therefore unknown, and each
 * tier improvised a different answer for the same source:
 *
 *     const v: bigint = p > 0n ? this.bump(p) : 0n;   // bump(x) = x + 1n
 *
 *     ts / zig / ruby / java   7600a0638b6700776800a2         (correct)
 *     go                       7600a063006700776800a2         (silently wrong)
 *     python                   7600a063007c00776700776800a2   (silently wrong)
 *     rust                     rejected: "unknown function 'bump'"
 *
 * Two tiers ACCEPTED and emitted a script that never evaluates the helper —
 * `OP_0` where the source says `OP_1ADD`. That is the fund-safety half: the
 * covenant deploys, and the arm computes a value the contract never asked for.
 *
 * The tier-independent proof that Go and Python were wrong, and the second
 * test below: changing the callee body from `x + 1n` to `x + 2n` changed
 * NOTHING in their output. A compiler that emits identical bytes for two
 * different programs is not merely disagreeing with its peers.
 *
 * This is the branch-lowering arm contract (NEW-014 / NEW-018) again: an arm
 * context is constructed fresh, so every field it needs has to be re-plumbed by
 * hand. `scriptLevelCodeSeparator` was re-plumbed by R-010 and `renamedParams`
 * by issue #130 — both with a comment at the copy site. `privateMethods` was
 * missed. TS, Ruby and Java already copied it, which is exactly why those tiers
 * were correct.
 *
 * The hexes below are the SEVEN-TIER agreed output. Every tier pins the same
 * strings (each tier's own `n051_branch_arm_private_helper` test), which is
 * what makes this a parity gate: a tier that lowers the fix differently fails
 * its own test.
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

const PRELUDE = `import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  readonly s: bigint;

  constructor(s: bigint) { super(s); this.s = s; }
`;

function contract(body: string): string {
  return `${PRELUDE}${body}}\n`;
}

/** Helper called from a ternary arm. */
const TERNARY_ARM_PLUS_1 = contract(`  private bump(x: bigint): bigint { return x + 1n; }

  public m(p: bigint): void {
    const v: bigint = p > 0n ? this.bump(p) : 0n;
    assert(v >= this.s);
  }
`);

/** Same shape, different callee body — the body-independence probe. */
const TERNARY_ARM_PLUS_2 = contract(`  private bump(x: bigint): bigint { return x + 2n; }

  public m(p: bigint): void {
    const v: bigint = p > 0n ? this.bump(p) : 0n;
    assert(v >= this.s);
  }
`);

/** Control: the same program with the helper inlined by hand. */
const TERNARY_ARM_MANUAL_INLINE = contract(`  public m(p: bigint): void {
    const v: bigint = p > 0n ? p + 1n : 0n;
    assert(v >= this.s);
  }
`);

/** Helper called from an `if` STATEMENT arm. */
const IF_STATEMENT_ARM = contract(`  private bump(x: bigint): bigint { return x + 1n; }

  public m(p: bigint): void {
    let v: bigint = 0n;
    if (p > 0n) {
      v = this.bump(p);
    } else {
      v = 0n;
    }
    assert(v >= this.s);
  }
`);

/** Control: the same `if` with no helper call in either arm. */
const IF_STATEMENT_ARM_NO_HELPER = contract(`  public m(p: bigint): void {
    let v: bigint = 0n;
    if (p > 0n) {
      v = p + 1n;
    } else {
      v = 0n;
    }
    assert(v >= this.s);
  }
`);

/** Control: a helper call in ordinary statement position, outside any arm. */
const STATEMENT_POSITION = contract(`  private bump(x: bigint): bigint { return x + 1n; }

  public m(p: bigint): void {
    const v: bigint = this.bump(p);
    assert(v >= this.s);
  }
`);

const SEVEN_TIER_HEX: Record<string, string> = {
  'ternary-arm/+1': '7600a0638b6700776800a2',
  'ternary-arm/+2': '7600a06352936700776800a2',
  'ternary-arm-manual-inline': '7600a0638b6700776800a2',
  'if-statement-arm': '007800a0637c8b767676537a757777670076537a7577687c7500a2',
  'if-statement-arm-no-helper': '007800a0637c8b7677670076537a7577687c7500a2',
  'statement-position': '8b00a2',
};

function compileScriptHex(source: string, disableConstantFolding: boolean): string {
  const r = compile(source, { fileName: 'C.runar.ts', disableConstantFolding });
  expect(r.success, r.diagnostics.map((d) => d.message).join('; ')).toBe(true);
  return r.artifact!.script;
}

describe('N-051: a private-helper call inside a branch arm inlines the callee', () => {
  const cases: [string, string][] = [
    ['ternary-arm/+1', TERNARY_ARM_PLUS_1],
    ['ternary-arm/+2', TERNARY_ARM_PLUS_2],
    ['ternary-arm-manual-inline', TERNARY_ARM_MANUAL_INLINE],
    ['if-statement-arm', IF_STATEMENT_ARM],
    ['if-statement-arm-no-helper', IF_STATEMENT_ARM_NO_HELPER],
    ['statement-position', STATEMENT_POSITION],
  ];

  for (const [key, source] of cases) {
    for (const disable of [true, false]) {
      it(`${key} (fold-${disable ? 'off' : 'on'}) matches the seven-tier hex`, () => {
        expect(compileScriptHex(source, disable)).toBe(SEVEN_TIER_HEX[key]);
      });
    }
  }

  // spec/semantics.md §6.3: inlining IS substitution, so a helper call in a
  // ternary arm and the hand-substituted program are the same program.
  it('a helper call in a ternary arm compiles exactly like the hand-inlined source', () => {
    for (const disable of [true, false]) {
      expect(compileScriptHex(TERNARY_ARM_PLUS_1, disable))
        .toBe(compileScriptHex(TERNARY_ARM_MANUAL_INLINE, disable));
    }
  });

  // The tier-independent oracle. No reference tier is consulted: a compiler
  // that emits the same bytes for `x + 1n` and `x + 2n` has dropped the callee
  // body, whatever its peers do.
  it('the callee body reaches the arm — a different helper body changes the script', () => {
    for (const disable of [true, false]) {
      expect(compileScriptHex(TERNARY_ARM_PLUS_1, disable))
        .not.toBe(compileScriptHex(TERNARY_ARM_PLUS_2, disable));
    }
  });
});
