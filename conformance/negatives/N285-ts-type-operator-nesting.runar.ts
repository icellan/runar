// N-311: a type annotation nesting `&` 200 levels deep, past MAX_SOURCE_NESTING
// (128). Measure (A) counts +1 per operand of an intersection / union type, so
// the TS, Go and Rust tiers refuse it with the shared diagnostic
//   source nesting depth exceeds MAX_SOURCE_NESTING (limit=128)
// (n311-type-operator-nesting-parity.test.ts pins that). The other four tiers'
// .runar.ts type grammar has no `&` and refuses it at the first `(`.
import { SmartContract, assert } from 'runar-lang';

class TypeOperatorNesting extends SmartContract {
  readonly t: bigint;

  constructor(t: bigint) {
    super(t);
    this.t = t;
  }

  public verify(a: bigint) {
    let q: (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & (bigint & bigint)))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) = a;
    assert(q === this.t);
  }
}
