import { describe, it, expect } from 'vitest';
import { renameLocals } from '../metamorphic.js';
import { runDifferentialExecution } from 'runar-testing';

// A tiny stateless-arithmetic contract with a local `const` and two params.
// Metamorphic property: a semantics-preserving source transform must not
// change the compiled contract's accept/reject verdict on any witness.
const SRC = `
import { SmartContract, assert } from 'runar-lang';
export class R extends SmartContract {
  readonly t: bigint;
  constructor(t: bigint) { super(t); this.t = t; }
  public verify(a: bigint, b: bigint): void { const s = a + b; assert(s === this.t); }
}
`;

describe('metamorphic: identifier rename preserves behavior', () => {
  it('renamed source accepts/rejects identically on the same witnesses', () => {
    const renamed = renameLocals(SRC);
    // Sanity: the transform actually changed the source (renamed at least one local).
    expect(renamed).not.toBe(SRC);
    for (const [a, b, expectAccept] of [
      [3n, 7n, true],
      [3n, 8n, false],
    ] as const) {
      const orig = runDifferentialExecution({
        source: SRC,
        fileName: 'R.runar.ts',
        method: 'verify',
        args: [a, b],
        constructorArgs: { t: 10n },
      });
      const mut = runDifferentialExecution({
        source: renamed,
        fileName: 'R.runar.ts',
        method: 'verify',
        args: [a, b],
        constructorArgs: { t: 10n },
      });
      expect(mut.vmAccepted).toBe(orig.vmAccepted);
      expect(mut.vmAccepted).toBe(expectAccept);
    }
  });
});
