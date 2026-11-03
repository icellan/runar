import { SmartContract, assert, checkSig, hash160 } from 'runar-lang';
import type { Addr, FixedArray, PubKey, Sig } from 'runar-lang';

/**
 * EmbedTags — `@embedAlways` on a `FixedArray` property (F-098, decision R35).
 *
 * A `FixedArray<T, N>` property is expanded by the compiler into N scalar
 * slots (`tags__0`, `tags__1`, `tags__2`). The directive applies to EVERY
 * slot: each one is kept in the locking script even though `unlock` reads only
 * `tags[1]`. Without the directive, `tags__0` and `tags__2` are dead and are
 * eliminated, exactly as an unread scalar would be.
 *
 * Before F-098 every compiler tier rebuilt the slots without the directive, so
 * it was silently ignored on a FixedArray. This contract is the conformance
 * fixture `embed-always-fixed-array`, which pins the bytes in all seven tiers
 * and on eight surfaces: the ports beside it spell the directive natively
 * (N-093). There is no `.runar.java` port because FixedArray cannot be spelled
 * on the Java surface (see docs/formats/java.md).
 */
class EmbedTags extends SmartContract {
  readonly pubKeyHash: Addr;

  /** @embedAlways */
  readonly tags: FixedArray<bigint, 3> = [7n, 9n, 11n];

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey, amount: bigint) {
    assert(amount >= this.tags[1]);
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
