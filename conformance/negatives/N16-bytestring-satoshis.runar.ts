// N-098: a ByteString in the SATOSHIS position of `this.addOutput(...)`.
//
// Not a diagnostic gap. The TypeScript reference refuses this source
// ("addOutput() first argument (satoshis) must be bigint, got 'ByteString'");
// the other six tiers accepted it and lowered the ByteString into the satoshis
// slot WITH NO CONVERSION. The emitted script was byte-identical to the same
// contract with `blob: bigint` — measured, not read: both compiled through the
// Go tier to the same 1358-hexchar script.
//
// `lowerAddOutput` prepends the satoshis operand as `OP_8 OP_NUM2BIN`, so the
// covenant's committed output amount becomes whatever those bytes decode to as
// a script number. Executed on the real @bsv/sdk `Spend` engine, with
// `blob = 0x2a`:
//
//   - a continuation paying 42 satoshis  (= NUM2BIN(0x2a, 8) read little-endian)
//     VALIDATES;
//   - the 1000-satoshi continuation the author funded is REJECTED.
//
// Longer blobs do not fail safe either, they fail shut: 0xcafebabefeed0001
// demands 7.2e16 satoshis (more than the entire money supply) and a 20-byte
// hash aborts the script at OP_NUM2BIN, so in both cases the UTXO can never be
// spent. A type error in a covenant's amount slot is a fund-loss bug, which is
// why this is a gate and not a lint.
//
// `addRawOutput` and `addDataOutput` carry the same first-argument contract and
// had the same hole in the same six tiers. Every tier routes all three through
// ONE check, so this single source gates the family here; the per-intrinsic
// probes live in each tier's own N-098 test.
//
// The shape stays invalid regardless of how inference evolves: `ByteString` is
// not a member of the bigint family under any tier's `isBigintFamily`.
import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

export class ByteStringSatoshis extends StatefulSmartContract {
  count: bigint;
  readonly blob: ByteString;

  constructor(count: bigint, blob: ByteString) {
    super(count, blob);
    this.count = count;
    this.blob = blob;
  }

  public bump(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(this.blob, this.count);
  }
}
