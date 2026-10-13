// ---------------------------------------------------------------------------
// runar-sdk/tokens.ts — Token UTXO management
// ---------------------------------------------------------------------------

import type { RunarArtifact } from 'runar-ir-schema';
import type { Provider } from './providers/provider.js';
import type { Signer } from './signers/signer.js';
import type { UTXO } from './types.js';
import { RunarContract } from './contract.js';
import { buildP2PKHScript } from './script-utils.js';

// N-239 (user decision R92): `merge` and `transfer` drive an ABI that cannot
// be made sound, so they are deprecated rather than redesigned or removed.
// Each warns once per process on first use.
const MERGE_DEPRECATION =
  'runar-sdk: warning: TokenWallet.merge is deprecated and unsafe. Its ' +
  'merge(sig, otherSupply, otherHolder) ABI cannot authenticate the companion ' +
  'input, so a holder can call merge on ONE input with a made-up otherSupply ' +
  '(supply inflation). Use the token-ft example (FungibleTokenExample, ' +
  'examples/*/token-ft/) instead (N-239).';
const TRANSFER_DEPRECATION =
  'runar-sdk: warning: TokenWallet.transfer is deprecated and unsafe. Its ' +
  'transfer(sig, to: Addr) ABI cannot re-key the PubKey holder from an Addr, ' +
  'so the token stays with the current holder instead of moving to the ' +
  'recipient. Use the token-ft example (FungibleTokenExample, ' +
  'examples/*/token-ft/) instead (N-239).';
let mergeDeprecationWarned = false;
let transferDeprecationWarned = false;

/**
 * Manages token UTXOs for a fungible token contract.
 *
 * Assumes the artifact describes a token contract with:
 * - A `transfer` public method.
 * - A state field named `balance` or `amount` of type int/bigint.
 *
 * This is a higher-level convenience wrapper around RunarContract for the
 * common token use-case.
 */
export class TokenWallet {
  constructor(
    private readonly artifact: RunarArtifact,
    private readonly provider: Provider,
    private readonly signer: Signer,
  ) {}

  /**
   * Get the total token balance across all UTXOs belonging to this wallet.
   */
  async getBalance(): Promise<bigint> {
    const utxos = await this.getUtxos();
    let total = 0n;

    for (const utxo of utxos) {
      const contract = await RunarContract.fromTxId(
        this.artifact,
        utxo.txid,
        utxo.outputIndex,
        this.provider,
      );
      const state = contract.state;
      // Look for a supply/balance/amount field in the state
      const balanceField = state['supply'] ?? state['balance'] ?? state['amount'] ?? 0;
      total += BigInt(balanceField as number | bigint);
    }

    return total;
  }

  /**
   * Transfer the entire balance of a token UTXO to a new address.
   *
   * The FungibleToken.transfer(sig, to) method transfers the full supply
   * held in the UTXO to the given address.  The signature is produced by
   * this wallet's signer and passed as the first argument.
   *
   * @param recipientAddr - The BSV address (Addr) of the recipient.
   * @param amount - Minimum token balance required in the source UTXO.
   * @returns The txid of the transfer transaction.
   * @deprecated Unsafe (N-239): the `transfer(sig, to: Addr)` ABI cannot
   * re-key a PubKey holder, so the token does not move to `recipientAddr`.
   * Use the token-ft example (FungibleTokenExample) instead.
   */
  async transfer(recipientAddr: string, amount: bigint): Promise<string> {
    if (!transferDeprecationWarned) {
      transferDeprecationWarned = true;
      console.warn(TRANSFER_DEPRECATION);
    }
    const utxos = await this.getUtxos();
    if (utxos.length === 0) {
      throw new Error('TokenWallet.transfer: no token UTXOs found');
    }

    // Use the first UTXO that has sufficient balance
    for (const utxo of utxos) {
      const contract = await RunarContract.fromTxId(
        this.artifact,
        utxo.txid,
        utxo.outputIndex,
        this.provider,
      );
      const state = contract.state;
      const balance = BigInt((state['balance'] ?? state['supply'] ?? state['amount'] ?? 0) as number | bigint);

      if (balance >= amount) {
        // FungibleToken.transfer(sig: Sig, to: Addr)
        // F-045: pass `null` for the Sig so contract.call auto-signs the
        // transaction it actually builds and broadcasts. Signing a locally
        // built preliminary tx and passing that signature in covers a
        // different tx (coin selection, unlock size, change, subscript) and
        // is rejected on-chain.
        // An Addr is a 20-byte hash160: accept a Base58 address (as
        // documented), a raw hash160, or a public key.
        const toPKH = buildP2PKHScript(recipientAddr).slice(6, 46);
        const changeAddress = await this.signer.getAddress();
        const result = await contract.call(
          'transfer',
          [null, toPKH],
          this.provider,
          this.signer,
          { changeAddress },
        );
        return result.txid;
      }
    }

    throw new Error(
      `TokenWallet.transfer: insufficient token balance for transfer of ${amount}`,
    );
  }

  /**
   * Merge two token UTXOs into a single UTXO.
   *
   * FungibleToken.merge(sig, otherSupply, otherHolder) combines the supply
   * from two UTXOs.  The second UTXO's supply and holder are read from its
   * on-chain state and passed as arguments.
   *
   * @returns The txid of the merge transaction.
   * @deprecated Unsafe (N-239): the `merge(sig, otherSupply, otherHolder)` ABI
   * cannot authenticate its companion input, so a holder can inflate supply.
   * Use the token-ft example (FungibleTokenExample) instead.
   */
  async merge(): Promise<string> {
    if (!mergeDeprecationWarned) {
      mergeDeprecationWarned = true;
      console.warn(MERGE_DEPRECATION);
    }
    const utxos = await this.getUtxos();
    if (utxos.length < 2) {
      throw new Error('TokenWallet.merge: need at least 2 UTXOs to merge');
    }

    // Merge the first two UTXOs by calling the merge method on the first.
    const firstUtxo = utxos[0]!;
    const contract = await RunarContract.fromTxId(
      this.artifact,
      firstUtxo.txid,
      firstUtxo.outputIndex,
      this.provider,
    );

    // Read the second UTXO's state to extract its supply and holder.
    const secondUtxo = utxos[1]!;
    const secondContract = await RunarContract.fromTxId(
      this.artifact,
      secondUtxo.txid,
      secondUtxo.outputIndex,
      this.provider,
    );
    const secondState = secondContract.state;
    const otherSupply = BigInt((secondState['supply'] ?? secondState['balance'] ?? secondState['amount'] ?? 0) as number | bigint);
    const otherHolder = (secondState['holder'] ?? '') as string;

    // FungibleToken.merge(sig: Sig, otherSupply: bigint, otherHolder: PubKey)
    // F-045: spend BOTH token UTXOs in one tx. Each input's unlock carries the
    // OTHER input's supply/holder, and every Sig is `null` so contract.call
    // signs each input over the transaction it actually broadcasts.
    const firstState = contract.state;
    const firstSupply = BigInt((firstState['supply'] ?? firstState['balance'] ?? firstState['amount'] ?? 0) as number | bigint);
    const firstHolder = (firstState['holder'] ?? '') as string;

    const changeAddress = await this.signer.getAddress();
    const result = await contract.call(
      'merge',
      [null, otherSupply, otherHolder],
      this.provider,
      this.signer,
      {
        changeAddress,
        additionalContractInputs: [secondUtxo],
        additionalContractInputArgs: [[null, firstSupply, firstHolder]],
      },
    );

    return result.txid;
  }

  /**
   * Get all token UTXOs associated with this wallet's signer address.
   */
  async getUtxos(): Promise<UTXO[]> {
    const address = await this.signer.getAddress();
    const allUtxos = await this.provider.getUtxos(address);

    // Filter to UTXOs whose script begins like this token contract's.
    //
    // R-274: this used to compare against `this.artifact.script` whole. That
    // is the TEMPLATE — each constructor slot holds a one-byte OP_0 that
    // deployment replaces with the encoded argument — so for any contract with
    // a constructorSlot inside its code part, no deployed instance starts with
    // it and this returned EMPTY. Silently: getBalance() answered 0n for a
    // wallet holding tokens, and transfer() reported "no token UTXOs found".
    //
    // The comparison cannot run past the first slot: the substituted argument
    // is variable-length, so every byte after it sits at a shifted offset.
    // Matching the template up to the first slot is what every deployed
    // instance of this contract genuinely shares. It is a FILTER, not proof of
    // identity — callers that need certainty read the artifact's slot layout.
    const firstSlotByteOffset = (this.artifact.constructorSlots ?? [])
      .map((slot) => slot.byteOffset)
      .reduce((lowest, offset) => Math.min(lowest, offset), Number.POSITIVE_INFINITY);
    const scriptPrefix = Number.isFinite(firstSlotByteOffset)
      ? this.artifact.script.slice(0, firstSlotByteOffset * 2)
      : this.artifact.script;

    return allUtxos.filter((utxo) => {
      // With no script to compare, or a template that is all slot from byte 0,
      // include everything and let the caller filter further.
      if (utxo.script && scriptPrefix) {
        return utxo.script.startsWith(scriptPrefix);
      }
      return true;
    });
  }
}

