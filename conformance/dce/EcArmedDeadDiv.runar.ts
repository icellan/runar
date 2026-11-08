import { SmartContract, assert, ByteString, ecMulGen } from 'runar-lang';

/**
 * Same defect via the EC-optimizer's unrestricted DCE sweep: the foldable
 * `ecMulGen(1n)` arms `optimizeEC`'s `eliminateDeadBindings` over the whole
 * program — in BOTH fold modes — and it deleted the never-read `100n / p`.
 * The source aborts when `p === 0n` (spec/semantics.md §10), so `p = 0` must
 * not spend.
 */
export class EcArmedDeadDiv extends SmartContract {
  readonly tag: ByteString;

  constructor(tag: ByteString) {
    super(tag);
    this.tag = tag;
  }

  public unlock(p: bigint): void {
    const q: bigint = 100n / p;
    const g: ByteString = ecMulGen(1n);
    assert(g !== this.tag);
  }
}
