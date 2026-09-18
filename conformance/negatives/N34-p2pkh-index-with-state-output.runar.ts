// R-300 (CL-GAP-096): `requireOutputP2PKH`'s byte offsets assume every output
// in the serialised set is exactly 34 bytes.
//
// The intrinsic lowers to a fixed-offset read:
//
//     substr(_serialisedOutputs, outputIndex * 34, 34) === <expected P2PKH>
//
// which is only sound when every output before `outputIndex` really is 34
// bytes (8-byte LE amount ‖ 0x19 ‖ 25-byte P2PKH script).
//
// Two neighbouring cases were already refused. Mixing the intrinsic with
// `this.addDataOutput()` is rejected as Crit-3, because an OP_RETURN output is
// variable-length. `requireOutputP2PKH(0, ...)` in a state-mutating method with
// NO explicit output is rejected, because the implicit single-output
// continuation puts the contract's own large codePart at index 0.
//
// This shape fell between them and compiled. `this.addOutput(...)` puts the
// contract's continuation — codePart plus serialised state, hundreds of bytes —
// at output 0, so the offset for index 1 is 34 and lands INSIDE that script.
// The assertion then compares 34 bytes taken from the middle of the contract's
// own locking script against the expected P2PKH serialisation, which no honest
// spend can satisfy: the UTXO is permanently unspendable, and the compiler said
// nothing. Measured before the fix — `ts success= true`, `go exit=0`.
//
// The same reasoning covers `addRawOutput`, whose script length is a runtime
// value the compiler cannot bound, so it cannot prove the offsets either.

import { StatefulSmartContract, assert, requireOutputP2PKH } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class P2PKHIndexWithStateOutput extends StatefulSmartContract {
  count: bigint;
  readonly payee: ByteString;

  constructor(count: bigint, payee: ByteString) {
    super(count, payee);
    this.count = count;
    this.payee = payee;
  }

  public go(amount: bigint) {
    this.count = this.count + 1n;
    this.addOutput(1000n, this.count);
    requireOutputP2PKH(1n, this.payee, amount);
    assert(true);
  }
}
