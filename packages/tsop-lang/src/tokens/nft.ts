// ---------------------------------------------------------------------------
// tsop-lang/tokens/nft.ts — NonFungibleToken abstract base class
// ---------------------------------------------------------------------------
// Provides the canonical on-chain logic for non-fungible tokens (NFTs) on
// Bitcoin SV.  Each UTXO represents a unique token identified by `tokenId`.
//
// Design:
//   - No decorators.
//   - The compiler recognises classes extending NonFungibleToken and emits
//     the appropriate locking/unlocking script structure.
// ---------------------------------------------------------------------------

import { SmartContract } from '../index.js';
import type { ByteString, PubKey, Sig, Addr } from '../types.js';

/**
 * Abstract base class for non-fungible tokens.
 *
 * ```ts
 * class MyNFT extends NonFungibleToken {
 *   // custom properties / logic
 * }
 * ```
 */
export abstract class NonFungibleToken extends SmartContract {
  /** Current owner's compressed public key. */
  public readonly owner: PubKey;

  /**
   * Unique token identifier.
   * Typically the genesis outpoint (txid + vout) hex, but can be any
   * arbitrary byte string the minting contract chooses.
   */
  public readonly tokenId: ByteString;

  constructor(owner: PubKey, tokenId: ByteString) {
    super(owner, tokenId);
    this.owner = owner;
    this.tokenId = tokenId;
  }

  // -----------------------------------------------------------------------
  // Public spending methods (compiled to script spending paths)
  // -----------------------------------------------------------------------

  /**
   * Transfer ownership to a new address.
   *
   * The compiler emits a spending path that:
   * 1. Verifies `sig` against `this.owner`.
   * 2. Creates a new output locked to `to` carrying the same `tokenId`.
   *
   * @param sig - Signature from the current owner.
   * @param to  - Destination address (Hash160 of the new owner's pubkey).
   */
  public transfer(_sig: Sig, _to: Addr): void {
    throw new Error(
      'NonFungibleToken.transfer() cannot be called at runtime — compile this contract.',
    );
  }

  /**
   * Burn (destroy) the token permanently.
   *
   * The spending transaction must have no outputs carrying this token.
   * The compiler enforces that the token UTXO is consumed without creating
   * a successor.
   *
   * @param sig - Signature from the current owner.
   */
  public burn(_sig: Sig): void {
    throw new Error(
      'NonFungibleToken.burn() cannot be called at runtime — compile this contract.',
    );
  }
}
