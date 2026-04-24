// ---------------------------------------------------------------------------
// Tests for WIF decoding in runar-cli/commands/deploy.ts
//
// These exercise the exported `decodeWIF` helper to verify Base58Check
// checksum validation.
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
import { decodeWIF } from '../commands/deploy.js';

// A known valid mainnet WIF (compressed). Constructed from the private key
// 0x01 (all zeros except final byte) with the compressed flag set. Verified
// against standard BSV/BTC WIF encoders.
// Payload bytes (hex):  80 + 000000..01 + 01  =>
//   80000000000000000000000000000000000000000000000000000000000000000101
// SHA256(SHA256(payload))[0..4] is appended to produce the Base58Check.
const VALID_WIF_COMPRESSED =
  'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn';

describe('decodeWIF', () => {
  it('decodes a known-valid mainnet compressed WIF to 32-byte hex', () => {
    const hex = decodeWIF(VALID_WIF_COMPRESSED);
    expect(hex).toHaveLength(64);
    // Private key bytes for this test vector are 31 zero bytes + 0x01.
    expect(hex).toBe(
      '0000000000000000000000000000000000000000000000000000000000000001',
    );
  });

  it('throws on a WIF with a corrupted checksum byte', () => {
    // Flip the last character: this corrupts the final byte of the
    // checksum. The decoder must detect the mismatch.
    const lastChar = VALID_WIF_COMPRESSED.slice(-1);
    // Pick a different alphabet character to avoid an accidental no-op.
    const flipped = lastChar === 'n' ? 'm' : 'n';
    const corruptWif = VALID_WIF_COMPRESSED.slice(0, -1) + flipped;
    expect(corruptWif).not.toBe(VALID_WIF_COMPRESSED);

    expect(() => decodeWIF(corruptWif)).toThrow(/checksum/i);
  });
});
