import { StatefulSmartContract, ByteString, requireOutputP2PKH } from 'runar-lang';

/**
 * IntentOutputP2PKH exercises the `requireOutputP2PKH` intent intrinsic.
 *
 * The contract asserts that output 0 of the spending transaction is a
 * standard P2PKH output paying exactly `bondAmount` satoshis to
 * `bondPKH` (the 20-byte HASH160 of the bond-return pubkey).
 *
 * The auto-injected method parameter `_serialisedOutputs` carries the
 * full serialised output set; the intrinsic asserts hash256 of those
 * bytes matches the preimage's hashOutputs field, then substrings at
 * offset 0 (= outputIndex * 34) to compare against the expected P2PKH
 * bytes.
 */
class IntentOutputP2PKH extends StatefulSmartContract {
  readonly bondPKH: ByteString;
  readonly bondAmount: bigint;
  count: bigint;

  constructor(bondPKH: ByteString, bondAmount: bigint, count: bigint) {
    super(bondPKH, bondAmount, count);
    this.bondPKH = bondPKH;
    this.bondAmount = bondAmount;
    this.count = count;
  }

  public payBond() {
    requireOutputP2PKH(0n, this.bondPKH, this.bondAmount);
    this.count = this.count + 1n;
  }
}
