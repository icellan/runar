import { describe, it, expect } from 'vitest';
import { runFoldEquivalence } from '../oracle/index.js';

// Contract with an all-constant subexpression that constant folding collapses
// (2n * 3n + 4n → 10n). Fold-OFF keeps the arithmetic ops; fold-ON emits a
// single push. The two deployments must still accept/reject identically.
const SRC = `
import { SmartContract, assert } from 'runar-lang';

export class Folds extends SmartContract {
  readonly base: bigint;
  constructor(base: bigint) { super(base); this.base = base; }
  public verify(x: bigint): void {
    // (2 * 3 + 4) folds to 10; equivalence must hold across fold modes.
    assert(x === this.base + (2n * 3n + 4n));
  }
}
`;

describe('runFoldEquivalence', () => {
  it('fold-OFF and fold-ON accept/reject identically across witnesses', () => {
    const r = runFoldEquivalence({
      source: SRC,
      fileName: 'Folds.runar.ts',
      method: 'verify',
      constructorArgs: { base: 5n },
      // base(5) + 10 === 15 → only x=15 accepts; the rest are near-misses.
      witnesses: [[15n], [16n], [0n], [-1n]],
    });
    expect(r.equivalent, JSON.stringify(r.divergences)).toBe(true);
    // Folding actually changed the deployed bytes (the constant subexpr collapsed).
    expect(r.bytesDiffer).toBe(true);
  });

  it('reports the accept witness and near-misses as equivalent (no divergence)', () => {
    const r = runFoldEquivalence({
      source: SRC,
      fileName: 'Folds.runar.ts',
      method: 'verify',
      constructorArgs: { base: 5n },
      witnesses: [[15n], [14n], [100n]],
    });
    expect(r.divergences).toEqual([]);
    expect(r.equivalent).toBe(true);
    expect(r.foldOffHex.length).toBeGreaterThan(0);
    expect(r.foldOnHex.length).toBeGreaterThan(0);
  });
});
