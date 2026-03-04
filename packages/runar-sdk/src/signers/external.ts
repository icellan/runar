// ---------------------------------------------------------------------------
// runar-sdk/signers/external.ts — External / callback-based signer
// ---------------------------------------------------------------------------

import type { Signer } from './signer.js';

/**
 * Callback type for external signing.
 *
 * The external system receives the raw transaction hex, input index, the
 * locking script being spent, the satoshi value, and sighash flags — all the
 * information needed to compute a BIP-143 sighash and return a DER-encoded
 * signature with the sighash byte appended.
 */
export type SignCallback = (
  txHex: string,
  inputIndex: number,
  subscript: string,
  satoshis: number,
  sigHashType?: number,
) => Promise<string>;

/**
 * External signer that delegates signing to a caller-provided callback.
 *
 * Useful for hardware wallets, browser extension wallets, or any signing
 * system where the private key is not directly accessible.
 *
 * ```ts
 * const signer = new ExternalSigner(
 *   myPubKeyHex,
 *   myAddress,
 *   async (txHex, inputIndex, subscript, satoshis, sigHashType) => {
 *     return await myHardwareWallet.sign(txHex, inputIndex, subscript, satoshis, sigHashType);
 *   },
 * );
 * ```
 */
export class ExternalSigner implements Signer {
  constructor(
    private readonly pubKeyHex: string,
    private readonly addressStr: string,
    private readonly signFn: SignCallback,
  ) {}

  async getPublicKey(): Promise<string> {
    return this.pubKeyHex;
  }

  async getAddress(): Promise<string> {
    return this.addressStr;
  }

  async sign(
    txHex: string,
    inputIndex: number,
    subscript: string,
    satoshis: number,
    sigHashType?: number,
  ): Promise<string> {
    return this.signFn(txHex, inputIndex, subscript, satoshis, sigHashType);
  }
}
