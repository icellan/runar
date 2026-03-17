/**
 * Real ECDSA signing and verification for contract testing.
 *
 * Instead of mocking checkSig to always return true, we use a fixed
 * test message hash so that signature verification is real ECDSA.
 *
 * TEST_MESSAGE is the UTF-8 encoding of "runar-test-message-v1".
 * The @bsv/sdk internally SHA-256 hashes this before signing/verifying,
 * so the actual ECDSA digest is SHA256(TEST_MESSAGE).
 *
 * For Go/Rust/Python (which use raw-digest ECDSA APIs), the equivalent
 * digest is: SHA256("runar-test-message-v1") =
 *   ee5e6c74a298854942a9eadd789f2812b38936691230134ad50b884cc1f119fa
 */

import { PrivateKey, PublicKey, Signature } from '@bsv/sdk';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** The raw test message bytes (UTF-8 encoding of "runar-test-message-v1"). */
export const TEST_MESSAGE = Array.from(
  new TextEncoder().encode('runar-test-message-v1'),
);

/**
 * SHA256(TEST_MESSAGE) — the actual ECDSA digest that gets signed/verified.
 * Exported for cross-language reference. Go/Rust/Python use this directly
 * with their raw-digest ECDSA APIs.
 */
export const TEST_MESSAGE_DIGEST =
  'ee5e6c74a298854942a9eadd789f2812b38936691230134ad50b884cc1f119fa';

// ---------------------------------------------------------------------------
// Signing helpers
// ---------------------------------------------------------------------------

/**
 * Sign the fixed test message with a private key.
 * Returns a DER-encoded ECDSA signature as a hex string.
 *
 * @param privKeyHex - 64-char hex private key
 */
export function signTestMessage(privKeyHex: string): string {
  const pk = PrivateKey.fromHex(privKeyHex);
  const sig = pk.sign(TEST_MESSAGE);
  return sig.toDER('hex') as string;
}

/**
 * Derive the compressed public key from a private key.
 * Returns a 33-byte compressed public key as a hex string.
 *
 * @param privKeyHex - 64-char hex private key
 */
export function pubKeyFromPrivKey(privKeyHex: string): string {
  const pk = PrivateKey.fromHex(privKeyHex);
  return pk.toPublicKey().toDER('hex') as string;
}

// ---------------------------------------------------------------------------
// Verification (used by interpreter and runtime builtins)
// ---------------------------------------------------------------------------

/**
 * Verify an ECDSA signature against a public key over TEST_MESSAGE.
 *
 * The signature can be either:
 *   - Raw DER bytes
 *   - DER + sighash byte (the last byte is stripped before parsing)
 *
 * @param sigBytes - DER-encoded signature bytes (with optional trailing sighash byte)
 * @param pubKeyBytes - Compressed or uncompressed public key bytes
 * @returns true if the signature is valid
 */
export function verifyTestMessageSig(
  sigBytes: Uint8Array,
  pubKeyBytes: Uint8Array,
): boolean {
  try {
    const pubKey = ecPublicKeyFromBytes(pubKeyBytes);
    const sig = parseDERSignature(sigBytes);
    if (!sig) return false;
    return pubKey.verify(TEST_MESSAGE, sig);
  } catch {
    return false;
  }
}

/**
 * Verify an ECDSA signature given hex-encoded sig and pubkey.
 * Convenience wrapper for interpreter and runtime builtins.
 */
export function verifyTestMessageSigHex(
  sigHex: string,
  pubKeyHex: string,
): boolean {
  return verifyTestMessageSig(hexToBytes(sigHex), hexToBytes(pubKeyHex));
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function ecPublicKeyFromBytes(bytes: Uint8Array): InstanceType<typeof PublicKey> {
  // @bsv/sdk PublicKey.fromDER takes number[]
  return PublicKey.fromDER(Array.from(bytes));
}

/**
 * Parse a DER signature, stripping a trailing sighash byte if present.
 *
 * DER format: 0x30 [totalLen] 0x02 [rLen] [r] 0x02 [sLen] [s]
 * Bitcoin adds a sighash byte after the DER envelope.
 * We detect this by comparing the declared DER length with actual length.
 */
function parseDERSignature(bytes: Uint8Array): InstanceType<typeof Signature> | null {
  if (bytes.length < 8) return null;

  // DER envelope: bytes[0] = 0x30, bytes[1] = declared length
  // If actual length = declared + 2, it's pure DER (0x30 + len byte + content)
  // If actual length = declared + 3, there's a trailing sighash byte
  const declaredLen = bytes[1]!;
  const expectedPureDER = declaredLen + 2;

  let derBytes: number[];
  if (bytes.length === expectedPureDER) {
    derBytes = Array.from(bytes);
  } else if (bytes.length === expectedPureDER + 1) {
    // Strip trailing sighash byte
    derBytes = Array.from(bytes.slice(0, expectedPureDER));
  } else {
    // Try as-is
    derBytes = Array.from(bytes);
  }

  return Signature.fromDER(derBytes);
}
