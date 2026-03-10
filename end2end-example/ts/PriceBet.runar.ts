import { SmartContract, assert, PubKey, Sig, ByteString, RabinSig, RabinPubKey, checkSig, verifyRabinSig, num2bin } from 'runar-lang';

/**
 * PriceBet -- a two-party price wager settled by a Rabin oracle.
 *
 * Oracle replay note: The oracle signs only `num2bin(price, 8)` -- raw price
 * bytes with no domain separation. Any valid oracle signature for a given
 * price can be reused across all PriceBet contracts that share the same
 * oraclePubKey. This is acceptable when oracle attestations represent
 * reusable global facts (e.g., "BTC price at block N"). For production
 * contracts requiring per-instance isolation, include domain fields such as
 * a contract ID, UTXO outpoint, or expiry timestamp in the signed message.
 */
class PriceBet extends SmartContract {
  readonly alicePubKey: PubKey;
  readonly bobPubKey: PubKey;
  readonly oraclePubKey: RabinPubKey;
  readonly strikePrice: bigint;

  constructor(alicePubKey: PubKey, bobPubKey: PubKey, oraclePubKey: RabinPubKey, strikePrice: bigint) {
    super(alicePubKey, bobPubKey, oraclePubKey, strikePrice);
    this.alicePubKey = alicePubKey;
    this.bobPubKey = bobPubKey;
    this.oraclePubKey = oraclePubKey;
    this.strikePrice = strikePrice;
  }

  public settle(price: bigint, rabinSig: RabinSig, padding: ByteString, aliceSig: Sig, bobSig: Sig) {
    const msg = num2bin(price, 8n);
    assert(verifyRabinSig(msg, rabinSig, padding, this.oraclePubKey));

    assert(price > 0n);

    if (price > this.strikePrice) {
      // bobSig is present in the unlocking script for stack alignment but is
      // intentionally not checked in this branch — only alice (the winner) signs.
      assert(checkSig(aliceSig, this.alicePubKey));
    } else {
      // aliceSig is present in the unlocking script for stack alignment but is
      // intentionally not checked in this branch — only bob (the winner) signs.
      assert(checkSig(bobSig, this.bobPubKey));
    }
  }

  public cancel(aliceSig: Sig, bobSig: Sig) {
    assert(checkSig(aliceSig, this.alicePubKey));
    assert(checkSig(bobSig, this.bobPubKey));
  }
}
