// ---------------------------------------------------------------------------
// runar-sdk/tokens.ts — Token UTXO management
// ---------------------------------------------------------------------------

import type { RunarArtifact } from 'runar-ir-schema';
import type { Provider } from './providers/provider.js';
import type { Signer } from './signers/signer.js';
import type { UTXO } from './types.js';
import { RunarContract } from './contract.js';

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
      // Look for a balance/amount field in the state
      const balanceField = state['balance'] ?? state['amount'] ?? 0;
      total += BigInt(balanceField as number | bigint);
    }

    return total;
  }

  /**
   * Transfer tokens to a recipient address.
   *
   * @param recipientAddr - The BSV address of the recipient.
   * @param amount - The amount of tokens to transfer.
   * @returns The txid of the transfer transaction.
   */
  async transfer(recipientAddr: string, amount: bigint): Promise<string> {
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
      const balance = BigInt((state['balance'] ?? state['amount'] ?? 0) as number | bigint);

      if (balance >= amount) {
        const result = await contract.call(
          'transfer',
          [recipientAddr, amount],
          this.provider,
          this.signer,
          { changeAddress: await this.signer.getAddress() },
        );
        return result.txid;
      }
    }

    throw new Error(
      `TokenWallet.transfer: insufficient token balance for transfer of ${amount}`,
    );
  }

  /**
   * Merge multiple token UTXOs into a single UTXO.
   *
   * @returns The txid of the merge transaction.
   */
  async merge(): Promise<string> {
    const utxos = await this.getUtxos();
    if (utxos.length < 2) {
      throw new Error('TokenWallet.merge: need at least 2 UTXOs to merge');
    }

    // Merge the first two UTXOs by calling a merge method
    // This assumes the contract has a 'merge' public method.
    const firstUtxo = utxos[0]!;
    const contract = await RunarContract.fromTxId(
      this.artifact,
      firstUtxo.txid,
      firstUtxo.outputIndex,
      this.provider,
    );

    const secondUtxo = utxos[1]!;
    const result = await contract.call(
      'merge',
      [secondUtxo.txid, BigInt(secondUtxo.outputIndex)],
      this.provider,
      this.signer,
      { changeAddress: await this.signer.getAddress() },
    );

    return result.txid;
  }

  /**
   * Get all token UTXOs associated with this wallet's signer address.
   */
  async getUtxos(): Promise<UTXO[]> {
    const address = await this.signer.getAddress();
    const allUtxos = await this.provider.getUtxos(address);

    // Filter to only UTXOs whose script matches the token contract's
    // locking script prefix (the code portion, before state).
    const scriptPrefix = this.artifact.script;

    return allUtxos.filter((utxo) => {
      // If we have the script, check it starts with the contract code.
      // Otherwise, include all UTXOs (caller can filter further).
      if (utxo.script && scriptPrefix) {
        return utxo.script.startsWith(scriptPrefix);
      }
      return true;
    });
  }
}
