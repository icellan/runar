// N-234: a scalar property initializer of the wrong literal family compiled
// without complaint.
//
// Found by the F-356 agent: `readonly x: bigint = toByteString('ab')` (and
// the equivalent bare-hex-literal form `readonly x: bigint = 'ab'`) passed
// every tier's frontend and emitted `01ab519c` — a locking script that
// pushes a 1-byte BYTE STRING where the contract's own arithmetic
// (`this.x === 1n`) expects a script NUMBER. A different program from the
// one the author wrote, deployed without a word of complaint, and all seven
// tiers agreed on it.
//
// 02-validate (and its six peers) only checked that a property initializer
// IS a literal of one of the three families (bigint, boolean, ByteString);
// none of them checked that the literal's family matches the PROPERTY'S
// DECLARED TYPE. The method-body assignment path (`y = toByteString('ab')`
// for a `let y: bigint`) was already refused everywhere by the pre-existing
// `assignment` statement type check — this gap was specific to property
// initializers.
//
// The shape stays invalid under any future typing rule: ByteString is not a
// member of the bigint family on any surface.
import { SmartContract, assert } from 'runar-lang';

export class ScalarInitTypeMismatch extends SmartContract {
  readonly x: bigint = 'ab';

  constructor() {
    super();
  }

  public check(): void {
    assert(this.x === 1n);
  }
}
