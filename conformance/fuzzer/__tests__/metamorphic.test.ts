import { describe, it, expect } from 'vitest';
import {
  renameLocals,
  reorderCommutative,
  introduceLet,
  insertDeadCode,
} from '../metamorphic.js';
import { runDifferentialExecution, type WitnessArg } from 'runar-testing';

// A tiny stateless-arithmetic contract with a local `const`, two params, one
// property, and a commutative (`===`) top-level assert condition — enough
// surface for every transform to have something to rewrite.
const SRC = `
import { SmartContract, assert } from 'runar-lang';
export class R extends SmartContract {
  readonly t: bigint;
  constructor(t: bigint) { super(t); this.t = t; }
  public verify(a: bigint, b: bigint): void { const s = a + b; assert(s === this.t); }
}
`;

// Witnesses spanning both accept and reject verdicts for target t = 10.
const WITNESSES: ReadonlyArray<readonly [bigint, bigint, boolean]> = [
  [3n, 7n, true],
  [3n, 8n, false],
  [10n, 0n, true],
  [1n, 1n, false],
];

/**
 * Metamorphic assertion: `transform(SRC)` must (a) actually change the source
 * (proving it applied) and (b) produce a contract whose EXECUTED accept/reject
 * verdict matches the original's on every witness. We compare `vmAccepted`
 * (compiled-script behaviour on the BSV engine), never bytes — a
 * semantics-preserving edit legitimately shifts byte offsets.
 */
function expectBehaviorPreserved(transform: (s: string) => string): void {
  const transformed = transform(SRC);
  expect(transformed, 'transform must change the source').not.toBe(SRC);
  for (const [a, b, expectAccept] of WITNESSES) {
    const args: WitnessArg[] = [a, b];
    const orig = runDifferentialExecution({
      source: SRC,
      fileName: 'R.runar.ts',
      method: 'verify',
      args,
      constructorArgs: { t: 10n },
    });
    const mut = runDifferentialExecution({
      source: transformed,
      fileName: 'R.runar.ts',
      method: 'verify',
      args,
      constructorArgs: { t: 10n },
    });
    expect(orig.vmAccepted, `original verdict for (${a},${b})`).toBe(expectAccept);
    expect(
      mut.vmAccepted,
      `transformed verdict diverged for (${a},${b}): orig=${orig.vmAccepted} mut=${mut.vmAccepted}`,
    ).toBe(orig.vmAccepted);
  }
}

describe('metamorphic transforms preserve compiled behavior', () => {
  it('renameLocals: identifier rename', () => {
    expectBehaviorPreserved(renameLocals);
  });

  it('reorderCommutative: swap commutative operands', () => {
    // Sanity: the transform swaps `s === this.t` to `this.t === s`.
    expect(reorderCommutative(SRC)).toContain('this.t === s');
    expectBehaviorPreserved(reorderCommutative);
  });

  it('introduceLet: bind a subexpression to a fresh const', () => {
    expect(introduceLet(SRC)).toMatch(/const __mm_let0/);
    expectBehaviorPreserved(introduceLet);
  });

  it('insertDeadCode: inject never-executed code', () => {
    expect(insertDeadCode(SRC)).toMatch(/if \(false\)/);
    expectBehaviorPreserved(insertDeadCode);
  });
});
