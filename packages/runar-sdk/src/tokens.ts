// ---------------------------------------------------------------------------
// runar-sdk/tokens.ts — Token UTXO management
// ---------------------------------------------------------------------------

import type { RunarArtifact } from 'runar-ir-schema';
import type { Provider } from './providers/provider.js';
import type { Signer } from './signers/signer.js';
import type { UTXO } from './types.js';
import { RunarContract } from './contract.js';
import { buildCallTransaction } from './calling.js';
import { Utils } from '@bsv/sdk';

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
      const balance = BigInt((state['balance'] ?? state['supply'] ?? state['amount'] ?? 0) as number | bigint);

      if (balance >= amount) {
        // FungibleToken.transfer(sig: Sig, to: Addr)
        // Build a preliminary unlocking script with a placeholder sig so we
        // can construct the transaction, then BIP-143 sign input 0.
        const placeholderSig = '00'.repeat(72); // DER sig placeholder
        const prelimUnlock = contract.buildUnlockingScript('transfer', [placeholderSig, recipientAddr]);

        // Build the preliminary transaction to obtain a signable tx hex
        const changeAddress = await this.signer.getAddress();
        const feeRate = await this.provider.getFeeRate();
        const additionalUtxos = await this.provider.getUtxos(changeAddress);
        const changeScript = buildP2PKHScriptFromAddress(changeAddress);

        const { txHex: prelimTxHex } = buildCallTransaction(
          utxo,
          prelimUnlock,
          undefined, // FungibleToken is stateless (SmartContract base)
          undefined,
          changeAddress,
          changeScript,
          additionalUtxos.length > 0 ? additionalUtxos : undefined,
          feeRate,
        );

        // Sign input 0 against the contract UTXO's locking script
        const sig = await this.signer.sign(prelimTxHex, 0, utxo.script, utxo.satoshis);

        const result = await contract.call(
          'transfer',
          [sig, recipientAddr],
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
   */
  async merge(): Promise<string> {
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
    // Build a preliminary transaction with a placeholder sig for BIP-143 signing.
    const placeholderSig = '00'.repeat(72);
    const prelimUnlock = contract.buildUnlockingScript('merge', [placeholderSig, otherSupply, otherHolder]);

    const changeAddress = await this.signer.getAddress();
    const feeRate = await this.provider.getFeeRate();
    const additionalUtxos = await this.provider.getUtxos(changeAddress);
    const changeScript = buildP2PKHScriptFromAddress(changeAddress);

    const { txHex: prelimTxHex } = buildCallTransaction(
      firstUtxo,
      prelimUnlock,
      undefined,
      undefined,
      changeAddress,
      changeScript,
      additionalUtxos.length > 0 ? additionalUtxos : undefined,
      feeRate,
    );

    // Sign input 0 against the first contract UTXO's locking script
    const sig = await this.signer.sign(prelimTxHex, 0, firstUtxo.script, firstUtxo.satoshis);

    const result = await contract.call(
      'merge',
      [sig, otherSupply, otherHolder],
      this.provider,
      this.signer,
      { changeAddress },
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a P2PKH locking script from an address string.
 */
function buildP2PKHScriptFromAddress(address: string): string {
  let pubKeyHash: string;

  if (/^[0-9a-fA-F]{40}$/.test(address)) {
    pubKeyHash = address;
  } else {
    const decoded = Utils.fromBase58Check(address);
    pubKeyHash = typeof decoded.data === 'string'
      ? decoded.data
      : Utils.toHex(decoded.data);
  }

  return '76a914' + pubKeyHash + '88ac';
}
