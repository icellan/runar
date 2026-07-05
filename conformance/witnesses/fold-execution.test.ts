/**
 * Constant-fold execution coverage (closes the TS-GAP-006 mutation survivor).
 *
 * The ANF constant-fold pass collapses all-constant subexpressions at compile
 * time (`evalBinOp` in `optimizer/constant-fold.ts`). The mutation-scoring
 * harness surfaced a measured hole: NO witnessed fixture executed a folded
 * constant in a way that changed the accept/reject verdict, so a fold
 * arithmetic bug (e.g. the `constantfold-add-to-sub` mutant, `+` -> `-`)
 * survived both the differential-witness and fold-equivalence gates.
 *
 * This suite pins a contract whose verdict DEPENDS on a folded constant and
 * runs it through BOTH oracles:
 *   - runDifferentialExecution: interpreter (correct source semantics) vs the
 *     compiled fold-ON script. A mis-folded constant changes the compiled
 *     script's accepted input, diverging from the interpreter.
 *   - runFoldEquivalence: fold-OFF (constant evaluated at runtime) vs fold-ON
 *     (constant collapsed at compile time). A fold bug makes the two diverge.
 * Either oracle now catches the mutant.
 */

import { describe, it, expect } from 'vitest';
import { runDifferentialExecution, runFoldEquivalence } from 'runar-testing';

// `(2n + 3n)` is an all-constant subexpression the fold pass collapses to 5n.
// `this.base` is a constructor arg (NOT constant), so `this.base + 5n` stays a
// runtime OP_ADD — only the inner `2n + 3n` routes through evalBinOp('+').
// base = 10 => verify accepts x === 15, rejects otherwise.
const SRC = `
import { SmartContract, assert } from 'runar-lang';

export class FoldExec extends SmartContract {
  readonly base: bigint;
  constructor(base: bigint) { super(base); this.base = base; }
  public verify(x: bigint): void {
    assert(x === this.base + (2n + 3n));
  }
}
`;
const FILE = 'FoldExec.runar.ts';
const CTOR = { base: 10n };

describe('constant-fold execution coverage (TS-GAP-006)', () => {
  it('source and script agree on a folded-constant accept/reject (fold-ON)', () => {
    const accept = runDifferentialExecution({
      source: SRC,
      fileName: FILE,
      method: 'verify',
      args: [15n],
      constructorArgs: CTOR,
    });
    expect(
      accept.agrees,
      `interp=${accept.interpreterAccepted} vm=${accept.vmAccepted} vmErr=${accept.vmError}`,
    ).toBe(true);
    expect(accept.vmAccepted).toBe(true);

    const reject = runDifferentialExecution({
      source: SRC,
      fileName: FILE,
      method: 'verify',
      args: [16n],
      constructorArgs: CTOR,
    });
    expect(reject.agrees).toBe(true);
    expect(reject.vmAccepted).toBe(false);
  });

  it('fold-OFF ≡ fold-ON on the folded-constant path (and folding changes the bytes)', () => {
    const r = runFoldEquivalence({
      source: SRC,
      fileName: FILE,
      method: 'verify',
      constructorArgs: CTOR,
      witnesses: [[15n], [16n]],
    });
    expect(r.equivalent, JSON.stringify(r.divergences)).toBe(true);
    // Folding actually collapsed `2n + 3n` -> `5n`, so the two compilations differ.
    expect(r.bytesDiffer).toBe(true);
  });
});
