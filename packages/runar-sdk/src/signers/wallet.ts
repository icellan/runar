// ---------------------------------------------------------------------------
// runar-sdk/signers/wallet.ts — BRC-100 wallet signer
// ---------------------------------------------------------------------------
//
// Delegates signing to a BRC-100 compatible wallet via @bsv/sdk's WalletClient.
// Computes BIP-143 sighash locally, then sends the pre-hashed digest to the
// wallet for ECDSA signing via `hashToDirectlySign`.
// ---------------------------------------------------------------------------

import type { Signer } from './signer.js';
import {
  WalletClient,
  Signature,
  TransactionSignature,
  Transaction,
  Script,
  Hash,
  Utils,
  type SecurityLevel,
} from '@bsv/sdk';

const SIGHASH_ALL_FORKID = 0x41;

export interface WalletSignerOptions {
  /** BRC-100 protocol ID tuple, e.g. [2, 'my app'] */
  protocolID: [SecurityLevel, string];
  /** Key derivation ID, e.g. '1' */
  keyID: string;
  /** Optional pre-existing WalletClient instance. If not provided, a new one is created. */
  wallet?: WalletClient;
}

export class WalletSigner implements Signer {
  private readonly wallet: WalletClient;
  private readonly protocolID: [SecurityLevel, string];
  private readonly keyID: string;
  private cachedPubKey: string | null = null;

  constructor(options: WalletSignerOptions) {
    this.wallet = options.wallet ?? new WalletClient();
    this.protocolID = options.protocolID;
    this.keyID = options.keyID;
  }

  async getPublicKey(): Promise<string> {
    if (this.cachedPubKey) return this.cachedPubKey;
    const { publicKey } = await this.wallet.getPublicKey({
      protocolID: this.protocolID,
      keyID: this.keyID,
    });
    this.cachedPubKey = publicKey;
    return publicKey;
  }

  async getAddress(): Promise<string> {
    const pubKeyHex = await this.getPublicKey();
    const pubKeyBytes = Utils.toArray(pubKeyHex, 'hex');
    const hash160 = Hash.hash160(pubKeyBytes);
    return Utils.toHex(hash160);
  }

  async sign(
    txHex: string,
    inputIndex: number,
    subscript: string,
    satoshis: number,
    sigHashType: number = SIGHASH_ALL_FORKID,
  ): Promise<string> {
    // 1. Compute BIP-143 sighash from the transaction context
    const tx = Transaction.fromHex(txHex);
    const input = tx.inputs[inputIndex]!;
    const otherInputs = tx.inputs
      .filter((_, i) => i !== inputIndex)
      .map((inp) => ({
        sourceTXID: inp.sourceTXID!,
        sourceOutputIndex: inp.sourceOutputIndex,
        sequence: inp.sequence!,
      }));

    const preimage = TransactionSignature.format({
      sourceTXID: input.sourceTXID!,
      sourceOutputIndex: input.sourceOutputIndex,
      sourceSatoshis: satoshis,
      transactionVersion: tx.version,
      otherInputs,
      outputs: tx.outputs,
      inputIndex,
      subscript: Script.fromHex(subscript),
      inputSequence: input.sequence ?? 0xffffffff,
      lockTime: tx.lockTime,
      scope: sigHashType,
    });

    // 2. Double SHA256 = BIP-143 sighash
    const sighash = Hash.hash256(preimage);

    // 3. Send to wallet for signing (wallet signs directly, no additional hashing)
    const { signature } = await this.wallet.createSignature({
      hashToDirectlySign: sighash,
      protocolID: this.protocolID,
      keyID: this.keyID,
      counterparty: 'self',
    });

    // 4. Convert to checksig format (DER + sighash flag byte)
    const rawSig = Signature.fromDER(signature);
    const txSig = new TransactionSignature(rawSig.r, rawSig.s, sigHashType);
    return Utils.toHex(txSig.toChecksigFormat());
  }

  /**
   * Sign a raw sighash directly, without computing BIP-143 from a
   * transaction context. Useful for multi-signer flows where the
   * sighash has already been computed by `prepareCall()`.
   *
   * @param sighash - Pre-computed sighash as hex string or byte array.
   * @returns DER-encoded signature hex (without sighash flag byte).
   */
  async signHash(sighash: string | number[]): Promise<string> {
    const hashBytes: number[] = typeof sighash === 'string'
      ? Utils.toArray(sighash, 'hex')
      : sighash;

    const { signature } = await this.wallet.createSignature({
      hashToDirectlySign: hashBytes,
      protocolID: this.protocolID,
      keyID: this.keyID,
      counterparty: 'self',
    });

    const rawSig = Signature.fromDER(signature);
    return Utils.toHex(rawSig.toDER() as number[]);
  }
}
