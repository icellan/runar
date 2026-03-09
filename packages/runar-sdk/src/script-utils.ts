// ---------------------------------------------------------------------------
// runar-sdk/script-utils.ts — P2PKH script construction utility
// ---------------------------------------------------------------------------

import { Hash, Utils } from '@bsv/sdk';

/**
 * Build a standard P2PKH locking script hex from an address, pubkey hash,
 * or public key.
 *
 *   OP_DUP OP_HASH160 OP_PUSH20 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
 *   76      a9         14        <20 bytes>    88              ac
 *
 * Accepted input formats:
 * - 40-char hex: treated as raw 20-byte pubkey hash (hash160)
 * - 66-char hex: compressed public key (auto-hashed via hash160)
 * - 130-char hex: uncompressed public key (auto-hashed via hash160)
 * - Other: decoded as Base58Check BSV address
 */
export function buildP2PKHScript(addressOrPubKey: string): string {
  let pubKeyHash: string;

  if (/^[0-9a-fA-F]{40}$/.test(addressOrPubKey)) {
    // Already a raw 20-byte pubkey hash in hex
    pubKeyHash = addressOrPubKey;
  } else if (/^[0-9a-fA-F]{66}$/.test(addressOrPubKey) || /^[0-9a-fA-F]{130}$/.test(addressOrPubKey)) {
    // Compressed (33 bytes) or uncompressed (65 bytes) public key — hash it
    const pubKeyBytes = Utils.toArray(addressOrPubKey, 'hex');
    const hash160Bytes = Hash.hash160(pubKeyBytes);
    pubKeyHash = Utils.toHex(hash160Bytes);
  } else {
    // Decode Base58Check address to extract the 20-byte pubkey hash
    const decoded = Utils.fromBase58Check(addressOrPubKey);
    pubKeyHash = typeof decoded.data === 'string'
      ? decoded.data
      : Utils.toHex(decoded.data);
  }

  return '76a914' + pubKeyHash + '88ac';
}
