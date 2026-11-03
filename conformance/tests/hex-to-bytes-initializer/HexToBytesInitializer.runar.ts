import { SmartContract, assert, PubKey, Sig, Addr, ByteString, hash160, checkSig, cat } from 'runar-lang';

/**
 * HexToBytesInitializer — N-090 conformance fixture.
 *
 * Two readonly ByteString properties carry hex-literal initializers. The Zig
 * surface writes them as `runar.hexToBytes("...")`, which every tier must
 * lower to the same ByteString literal as the other surfaces' byte literals.
 * The spend must present the P2PKH output script built from those bytes, so a
 * tier that read the initializer as text, or dropped it, fails the spend.
 */
class HexToBytesInitializer extends SmartContract {
  readonly p2pkhPrefix: ByteString = '1976a914' as ByteString;
  readonly p2pkhSuffix: ByteString = '88ac' as ByteString;
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey, script: ByteString) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(cat(cat(this.p2pkhPrefix, this.pubKeyHash), this.p2pkhSuffix) === script);
    assert(checkSig(sig, pubKey));
  }
}
