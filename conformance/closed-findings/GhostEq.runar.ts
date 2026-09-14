// GK-BUG-009 — an identifier that resolves to nothing, compared with `===`.
//
// R-085's pin (Undeclared.runar.java) exercises `>`, which lands in the
// bigint-family check and errors in every tier for the WRONG reason: the
// operand typed `<unknown>` and `<unknown>` is not in the bigint family.
// `===` takes the isSubtype path instead, and the lattice deliberately makes
// `<unknown>` compatible with everything (R-092), so the comparison itself
// raises nothing. Nothing in the six non-TS tiers ever said the name was not
// declared.
//
// The file is named "Ghost" rather than "Undeclared" on purpose: several tiers
// echo the source path into the diagnostic, so a fixture whose NAME contains
// the word the pin greps for can satisfy the pin without the compiler ever
// having said it.
//
// MUST NOT COMPILE, and the diagnostic must be the resolution failure — not a
// downstream stack-lowering complaint that calls the name a "method parameter".
import { SmartContract, assert } from 'runar-lang';

export class GhostEq extends SmartContract {
  readonly target: bigint;
  constructor(target: bigint) { super(target); this.target = target; }
  public verify(seed: bigint) {
    assert(notDeclaredAnywhere === 1n);
  }
}
