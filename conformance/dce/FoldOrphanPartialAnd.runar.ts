import { SmartContract, assert } from 'runar-lang';

/**
 * Fuzzer finding (seed 1351961626, FuzzContract94.method2) — fold-ON DCE
 * deleted a PARTIAL binding.
 *
 * `41n & p` aborts on-chain unless `p` encodes to exactly one byte
 * (OP_AND requires equal-length operands). Folding `m === 5n` to `true`
 * orphans the first `m`, and the N-138 prune then deleted `41n & p` as
 * "pure" — so the fold-ON script accepted every `p`, while the source and the
 * fold-OFF script reject a multi-byte or zero `p`.
 *
 * Spendable only with a one-byte `p` (e.g. 1, -1 encodes as 0x81 too).
 */
export class FoldOrphanPartialAnd extends SmartContract {
  constructor() {
    super();
  }

  public unlock(p: bigint): void {
    let m: bigint = 41n & p;
    m = 5n;
    assert(m === 5n);
  }
}
