// ---------------------------------------------------------------------------
// runar-sdk/signers/local.ts — Local signer (private key in memory)
// ---------------------------------------------------------------------------
//
// Uses @bsv/sdk for real secp256k1 key derivation, address generation,
// and ECDSA signing with BIP-143 sighash preimage computation.
// ---------------------------------------------------------------------------

import type { Signer } from './signer.js';
import { PrivateKey, TransactionSignature, Hash, Transaction, Script } from '@bsv/sdk';

/** SIGHASH_ALL | SIGHASH_FORKID — the default BSV sighash type. */
const SIGHASH_ALL_FORKID = 0x41;

/**
 * Local (in-process) signer that holds a private key in memory.
 *
 * Suitable for CLI tooling and testing. Not recommended for production
 * wallets — use ExternalSigner with hardware wallet callbacks instead.
 */
export class LocalSigner implements Signer {
  private readonly bsvPrivKey: PrivateKey;
  private readonly privateKeyHex: string;

  /**
   * Create a LocalSigner from a private key.
   *
   * @param keyInput - Either a 64-char hex string (raw 32-byte key) or a
   *                   WIF-encoded private key (Base58Check, starts with 5/K/L).
   */
  constructor(keyInput: string) {
    if (/^[0-9a-fA-F]{64}$/.test(keyInput)) {
      // Raw hex private key
      this.bsvPrivKey = PrivateKey.fromHex(keyInput);
      this.privateKeyHex = keyInput;
    } else if (/^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$/.test(keyInput)) {
      // WIF-encoded private key
      this.bsvPrivKey = PrivateKey.fromWif(keyInput);
      this.privateKeyHex = this.bsvPrivKey.toHex();
    } else {
      throw new Error(
        'LocalSigner: expected a 64-char hex private key or a WIF-encoded key (starts with 5, K, or L)',
      );
    }
  }

  async getPublicKey(): Promise<string> {
    // Derive compressed public key via secp256k1 point multiplication.
    const pubKey = this.bsvPrivKey.toPublicKey();
    return pubKey.toDER('hex') as string;
  }

  async getAddress(): Promise<string> {
    // Bitcoin address = Base58Check( 0x00 + HASH160(pubkey) )
    return this.bsvPrivKey.toAddress();
  }

  /** Get the raw private key hex (for integration with @bsv/sdk). */
  getPrivateKeyHex(): string {
    return this.privateKeyHex;
  }

  async sign(
    txHex: string,
    inputIndex: number,
    subscript: string,
    satoshis: number,
    sigHashType: number = SIGHASH_ALL_FORKID,
  ): Promise<string> {
    const scope = sigHashType;

    // Parse the raw transaction using @bsv/sdk's built-in parser.
    const tx = Transaction.fromHex(txHex);
    const input = tx.inputs[inputIndex]!;

    const otherInputs = tx.inputs
      .filter((_inp, i) => i !== inputIndex)
      .map((inp) => ({
        sourceTXID: inp.sourceTXID!,
        sourceOutputIndex: inp.sourceOutputIndex,
        sequence: inp.sequence!,
      }));

    const outputs = tx.outputs.map((out) => ({
      satoshis: out.satoshis!,
      lockingScript: out.lockingScript,
    }));

    const preimage = TransactionSignature.format({
      sourceTXID: input.sourceTXID!,
      sourceOutputIndex: input.sourceOutputIndex,
      sourceSatoshis: satoshis,
      transactionVersion: tx.version,
      otherInputs: otherInputs as Parameters<typeof TransactionSignature.format>[0]['otherInputs'],
      outputs: outputs as unknown as Parameters<typeof TransactionSignature.format>[0]['outputs'],
      inputIndex,
      subscript: Script.fromHex(subscript) as unknown as Parameters<typeof TransactionSignature.format>[0]['subscript'],
      inputSequence: input.sequence!,
      lockTime: tx.lockTime,
      scope,
    });

    // PrivateKey.sign() internally SHA-256 hashes its input before signing.
    // We pass SHA256(preimage) so the total is SHA256(SHA256(preimage)) =
    // hash256(preimage), which is the correct BIP-143 sighash digest.
    const sighash = Hash.sha256(preimage);
    const signature = this.bsvPrivKey.sign(sighash);

    // Return DER-encoded signature with sighash byte appended
    const derHex = signature.toDER('hex') as string;
    return derHex + scope.toString(16).padStart(2, '0');
  }
}
