// ---------------------------------------------------------------------------
// tsop-sdk/signers/external.ts — External / callback-based signer
// ---------------------------------------------------------------------------

import type { Signer } from './signer.js';

/**
 * Callback type for external signing.
 *
 * The external system receives the raw transaction hex and the input index,
 * and is responsible for computing the sighash and returning a DER-encoded
 * signature with the sighash byte appended.
 */
export type SignCallback = (
  txHex: string,
  inputIndex: number,
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
 *   async (txHex, inputIndex) => {
 *     return await myHardwareWallet.sign(txHex, inputIndex);
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
    _subscript: string,
    _satoshis: number,
    _sigHashType?: number,
  ): Promise<string> {
    return this.signFn(txHex, inputIndex);
  }
}
