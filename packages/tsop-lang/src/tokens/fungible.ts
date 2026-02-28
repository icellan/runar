// ---------------------------------------------------------------------------
// tsop-lang/tokens/fungible.ts — FungibleToken abstract base class
// ---------------------------------------------------------------------------
// Provides the canonical on-chain logic for fungible tokens on Bitcoin SV.
// Contract authors extend this class and optionally override hooks.
//
// Design:
//   - No decorators. Public methods that should be callable from spending
//     transactions are simply `public`.
//   - The compiler recognises classes extending FungibleToken and emits the
//     appropriate locking/unlocking script structure.
//   - `validateGenesis` performs a back-to-genesis (B2G) check so that only
//     tokens minted via the original genesis transaction are accepted.
// ---------------------------------------------------------------------------

import { SmartContract } from '../index.js';
import type { ByteString, PubKey, Sig, Addr } from '../types.js';

/**
 * Abstract base class for fungible tokens.
 *
 * Subclasses must implement any custom validation logic.  The three public
 * entry-points (`transfer`, `merge`, `split`) are recognised by the compiler
 * as spending paths.
 *
 * ```ts
 * class MyToken extends FungibleToken {
 *   // optionally override hooks
 * }
 * ```
 */
export abstract class FungibleToken extends SmartContract {
  /** Total supply held in this UTXO (in the token's smallest unit). */
  public readonly supply: bigint;

  /** Current holder's compressed public key. */
  public readonly holder: PubKey;

  constructor(supply: bigint, holder: PubKey) {
    super(supply, holder);
    this.supply = supply;
    this.holder = holder;
  }

  // -----------------------------------------------------------------------
  // Public spending methods (compiled to script spending paths)
  // -----------------------------------------------------------------------

  /**
   * Transfer the entire balance to a new address.
   *
   * The compiler emits a spending path that:
   * 1. Verifies `sig` against `this.holder`.
   * 2. Validates genesis lineage via `validateGenesis`.
   * 3. Creates a new output locked to `to` with the same `supply`.
   *
   * @param sig  - Signature from the current holder.
   * @param to   - Destination address (Hash160 of new holder's pubkey).
   */
  public transfer(_sig: Sig, _to: Addr): void {
    throw new Error(
      'FungibleToken.transfer() cannot be called at runtime — compile this contract.',
    );
  }

  /**
   * Merge two token UTXOs into one.
   *
   * The spending transaction must have two inputs (both carrying this token)
   * and one output whose `supply` equals the sum of the two inputs.
   *
   * @param sig          - Signature from the current holder.
   * @param otherSupply  - Supply of the other UTXO being merged.
   * @param otherHolder  - Holder pubkey of the other UTXO.
   */
  public merge(_sig: Sig, _otherSupply: bigint, _otherHolder: PubKey): void {
    throw new Error(
      'FungibleToken.merge() cannot be called at runtime — compile this contract.',
    );
  }

  /**
   * Split a token UTXO into two outputs.
   *
   * @param sig       - Signature from the current holder.
   * @param amount1   - Supply assigned to the first output.
   * @param to1       - Address for the first output.
   * @param to2       - Address for the second output (receives `supply - amount1`).
   */
  public split(_sig: Sig, _amount1: bigint, _to1: Addr, _to2: Addr): void {
    throw new Error(
      'FungibleToken.split() cannot be called at runtime — compile this contract.',
    );
  }

  // -----------------------------------------------------------------------
  // Genesis validation
  // -----------------------------------------------------------------------

  /**
   * Back-to-genesis (B2G) validation.
   *
   * Walks the chain of transaction inputs back to the original minting
   * transaction to ensure this token UTXO descends from a legitimate
   * genesis.  The compiler emits an inlined verification loop.
   *
   * @param genesisOutpoint - The outpoint (txid + vout) of the genesis tx.
   * @returns `true` if the lineage is valid.
   */
  protected validateGenesis(_genesisOutpoint: ByteString): boolean {
    throw new Error(
      'FungibleToken.validateGenesis() cannot be called at runtime — compile this contract.',
    );
  }
}
