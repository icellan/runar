import { SmartContract, assert } from 'runar-lang';

/**
 * N-446 — constant folding orphaned an operand binding INSIDE an `if` arm.
 *
 * `-5n` lowers to `t0 = 5; t1 = -t0`. The folder rewrites `t1` to the constant
 * `-5` and the N-138 prune removes the now-unreferenced `t0` — but that prune
 * walked only the method's top-level bindings, so inside the else arm `t0`
 * survived, stack lowering pushed it, and the else arm ended one slot deeper
 * than the then arm. Go refused the contract ("conditional needs 1 placeholder
 * push(es) to balance a NON-EMPTY then arm"); the six other tiers padded the
 * then arm with OP_0. Fold-OFF, every tier accepted it.
 *
 * Spendable with p in {8, 10, …} (then arm) and p in {-4 … 0} (else arm);
 * rejected for p in {1 … 7}, p <= -5 and p = 9.
 */
export class FoldArmOrphan extends SmartContract {
  constructor() {
    super();
  }

  public unlock(p: bigint): void {
    if (p > 0n) {
      assert(p > 7n);
    } else {
      assert(p > -5n);
    }
    assert(p !== 9n);
  }
}
