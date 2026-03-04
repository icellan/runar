import { SmartContract, assert, PubKey, Sig, ByteString, RabinSig, RabinPubKey, checkSig, verifyRabinSig, num2bin } from 'runar-lang';

class BlackjackBet extends SmartContract {
  readonly playerPubKey: PubKey;
  readonly housePubKey: PubKey;
  readonly oraclePubKey: RabinPubKey;
  readonly roundId: bigint;

  constructor(playerPubKey: PubKey, housePubKey: PubKey, oraclePubKey: RabinPubKey, roundId: bigint) {
    super(playerPubKey, housePubKey, oraclePubKey, roundId);
    this.playerPubKey = playerPubKey;
    this.housePubKey = housePubKey;
    this.oraclePubKey = oraclePubKey;
    this.roundId = roundId;
  }

  public settle(outcome: bigint, rabinSig: RabinSig, padding: ByteString, playerSig: Sig, houseSig: Sig) {
    const msg = num2bin(outcome, 8n);
    assert(verifyRabinSig(msg, rabinSig, padding, this.oraclePubKey));
    assert(outcome > 0n);
    if (outcome > this.roundId) {
      assert(checkSig(playerSig, this.playerPubKey));
    } else {
      assert(checkSig(houseSig, this.housePubKey));
    }
  }

  public cancel(playerSig: Sig, houseSig: Sig) {
    assert(checkSig(playerSig, this.playerPubKey));
    assert(checkSig(houseSig, this.housePubKey));
  }
}
