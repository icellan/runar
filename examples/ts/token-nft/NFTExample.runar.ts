import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

/**
 * SimpleNFT -- A non-fungible token (NFT) represented as a single UTXO.
 *
 * Unlike fungible tokens, an NFT is indivisible -- the token IS the UTXO. This contract
 * demonstrates ownership transfer and burn (permanent destruction) of a unique digital asset,
 * enforced entirely by Bitcoin Script.
 *
 * **UTXO as NFT:**
 * Each NFT is a single UTXO carrying:
 * - `owner` (mutable): current owner's public key, updated on transfer
 * - `tokenId` (readonly): unique identifier baked into the locking script
 * - `metadata` (readonly): content hash or URI, also baked in and immutable
 *
 * **Operations:**
 * - `transfer` -- Changes ownership. Creates one continuation UTXO via `addOutput` with a new owner.
 * - `burn`     -- Destroys the token permanently. No `addOutput` = no continuation UTXO = token ceases to exist.
 *
 * **The burn pattern:**
 * When a stateful contract method doesn't call `addOutput` and doesn't mutate state, the
 * compiler generates no state continuation. The UTXO is simply spent with no successor --
 * the token is destroyed.
 *
 * **Authorization:** Both operations require the current owner's ECDSA signature via `checkSig`.
 */
class SimpleNFT extends StatefulSmartContract {
  /** Current owner's public key. Mutable -- updated when the NFT is transferred. */
  owner: PubKey;
  /** Unique token identifier. Readonly -- baked into the locking script at deploy time. */
  readonly tokenId: ByteString;
  /** Token metadata (content hash or URI). Readonly -- immutable for the token's lifetime. */
  readonly metadata: ByteString;

  constructor(owner: PubKey, tokenId: ByteString, metadata: ByteString) {
    super(owner, tokenId, metadata);
    this.owner = owner;
    this.tokenId = tokenId;
    this.metadata = metadata;
  }

  /**
   * Transfer ownership of the NFT to a new owner.
   *
   * Creates one continuation UTXO via `addOutput` with the new owner. The tokenId and
   * metadata remain unchanged (readonly properties are baked into the locking script).
   * `addOutput(satoshis, owner)` takes the single mutable property positionally.
   *
   * @param sig            - Current owner's signature (authorization)
   * @param newOwner       - New owner's public key
   * @param outputSatoshis - Satoshis to fund the continuation UTXO
   */
  public transfer(sig: Sig, newOwner: PubKey, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);
    this.addOutput(outputSatoshis, newOwner);
  }

  /**
   * Burn (permanently destroy) the NFT.
   *
   * The owner signs to authorize destruction. Because this method does not call `addOutput`
   * and does not mutate state, the compiler generates no state continuation. The UTXO is
   * simply spent with no successor -- the token ceases to exist on-chain.
   *
   * @param sig - Current owner's signature (authorization)
   */
  public burn(sig: Sig) {
    assert(checkSig(sig, this.owner));
    // No addOutput and no state mutation = token destroyed
  }
}
