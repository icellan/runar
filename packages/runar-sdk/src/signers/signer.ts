// ---------------------------------------------------------------------------
// runar-sdk/signers/signer.ts — Signer interface
// ---------------------------------------------------------------------------

export interface Signer {
  /** Get the hex-encoded compressed public key (33 bytes = 66 hex chars). */
  getPublicKey(): Promise<string>;

  /** Get the BSV address (Base58Check-encoded). */
  getAddress(): Promise<string>;

  /**
   * Sign a transaction input.
   *
   * @param txHex       - The full raw transaction hex being signed.
   * @param inputIndex  - Index of the input being signed.
   * @param subscript   - The locking script of the UTXO being spent (hex).
   * @param satoshis    - The satoshi value of the UTXO being spent.
   * @param sigHashType - Sighash flags (defaults to ALL | FORKID = 0x41).
   * @returns The DER-encoded signature with sighash byte appended, hex-encoded.
   */
  sign(
    txHex: string,
    inputIndex: number,
    subscript: string,
    satoshis: number,
    sigHashType?: number,
  ): Promise<string>;
}
