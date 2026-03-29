import { SmartContract, assert, PubKey, Sig, Addr, ByteString, SigHashPreimage, checkSig, checkPreimage, extractOutputHash, hash256, num2bin, cat } from 'runar-lang';

class CovenantVault extends SmartContract {
  readonly owner: PubKey;
  readonly recipient: Addr;
  readonly minAmount: bigint;

  constructor(owner: PubKey, recipient: Addr, minAmount: bigint) {
    super(owner, recipient, minAmount);
    this.owner = owner;
    this.recipient = recipient;
    this.minAmount = minAmount;
  }

  public spend(sig: Sig, txPreimage: SigHashPreimage) {
    assert(checkSig(sig, this.owner));
    assert(checkPreimage(txPreimage));
    const p2pkhScript = cat(cat('1976a914', this.recipient), '88ac');
    const expectedOutput = cat(num2bin(this.minAmount, 8n), p2pkhScript);
    assert(hash256(expectedOutput) === extractOutputHash(txPreimage));
  }
}
