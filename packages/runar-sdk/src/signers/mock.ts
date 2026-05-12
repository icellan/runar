// ---------------------------------------------------------------------------
// runar-sdk/signers/mock.ts — Deterministic mock signer for testing
// ---------------------------------------------------------------------------

import type { Signer } from './signer.js';

/** Default 33-byte compressed pubkey: 0x02 || 32 zero bytes. */
const DEFAULT_MOCK_PUBKEY = '02' + '00'.repeat(32);
/** Default mock address: 20 zero bytes hex-encoded. */
const DEFAULT_MOCK_ADDRESS = '00'.repeat(20);
/** SIGHASH_ALL | SIGHASH_FORKID — the BSV default sighash byte. */
const SIGHASH_ALL_FORKID = 0x41;

/**
 * Deterministic in-memory signer for testing.
 *
 * Returns a fixed pubkey, fixed address, and a fixed 72-byte DER-shaped
 * signature on every call. Performs no real cryptography. The signature
 * format is `0x30` (DER SEQUENCE tag) || 70 zero bytes || sighash byte
 * (default `0x41`), matching the Go / Rust / Python / Zig / Ruby / Java
 * `MockSigner` byte layout so cross-tier integration tests stay byte-exact.
 */
export class MockSigner implements Signer {
  private readonly pubKey: string;
  private readonly address: string;

  constructor(pubKeyHex?: string, address?: string) {
    this.pubKey = pubKeyHex && pubKeyHex.length > 0 ? pubKeyHex : DEFAULT_MOCK_PUBKEY;
    this.address = address && address.length > 0 ? address : DEFAULT_MOCK_ADDRESS;
  }

  async getPublicKey(): Promise<string> {
    return this.pubKey;
  }

  async getAddress(): Promise<string> {
    return this.address;
  }

  async sign(
    _txHex: string,
    _inputIndex: number,
    _subscript: string,
    _satoshis: number,
    sigHashType: number = SIGHASH_ALL_FORKID,
  ): Promise<string> {
    // 0x30 (DER SEQUENCE tag) + 70 zero bytes + sighash byte.
    const sighashByte = (sigHashType & 0xff).toString(16).padStart(2, '0');
    return '30' + '00'.repeat(70) + sighashByte;
  }
}
