// R-083 — TypeScript for-loop updates were not validated, so a non-unit step
// (`i += 2n`) was silently coerced to a unit step and the unrolled loop
// computed a different number. MUST NOT COMPILE.
import { SmartContract, assert } from 'runar-lang';

export class BadUpdate extends SmartContract {
  readonly target: bigint;
  constructor(target: bigint) { super(target); this.target = target; }
  public verify(seed: bigint) {
    let acc: bigint = seed;
    for (let i = 0n; i < 6n; i += 2n) { acc = acc + i; }
    assert(acc === this.target);
  }
}
