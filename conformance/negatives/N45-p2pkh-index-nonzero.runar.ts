// W2 (OutputInception): `requireOutputP2PKH(i, ...)` for a literal `i` other
// than 0 is refused in v1, in all seven tiers.
//
// The intrinsic lowers to a fixed-offset read:
//
//     substr(_serialisedOutputs, outputIndex * 34, 34) === <expected P2PKH>
//
// `outputIndex * 34` is the START of output `outputIndex` only if every earlier
// output is exactly 34 bytes. Nothing in a transaction makes that true. An
// output is `value[8] ‖ CompactSize(len) ‖ script[len]`, and the spender picks
// output 0's length freely.
//
// So for `i = 1` an attacker builds output 0 as a 78-byte OP_RETURN whose
// payload carries the promised 34-byte P2PKH serialisation starting at global
// offset 34, and puts their own P2PKH at the transaction's real output 1. The
// `_serialisedOutputs` witness still hashes to the preimage's `hashOutputs` —
// it IS the real output set — the substring at offset 34 matches byte for byte,
// and the bond is paid to the attacker. Measured on @bsv/sdk's `Spend` before
// the fix: `validate() === true`, with the honest two-34-byte-output control
// also true, so the engine could not tell them apart.
//
// Index 0 stays legal: offset 0 is a genuine output boundary, so matching 34
// bytes there forces output 0 to BE the promised P2PKH. Indexes above 0 need a
// CompactSize walk from byte 0, which the v1 codegen does not emit.
//
// This is NOT the R-300 shape (N34). R-300 refuses MIXING the intrinsic with
// `addDataOutput` / `addOutput` / `addRawOutput`, i.e. a contract that emits
// its own variable-length outputs and is therefore unspendable. The contract
// below emits no outputs at all and compiled cleanly under R-300 — a source-
// level ban on the contract's own outputs is not a constraint on the
// transaction an attacker builds.

import { StatefulSmartContract, requireOutputP2PKH } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class P2PKHIndexNonZero extends StatefulSmartContract {
  readonly bondPKH: ByteString;
  readonly bondAmount: bigint;
  count: bigint;

  constructor(bondPKH: ByteString, bondAmount: bigint, count: bigint) {
    super(bondPKH, bondAmount, count);
    this.bondPKH = bondPKH;
    this.bondAmount = bondAmount;
    this.count = count;
  }

  public settle() {
    requireOutputP2PKH(1n, this.bondPKH, this.bondAmount);
  }
}
