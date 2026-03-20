import { SmartContract, assert, sha256Finalize } from 'runar-lang';
import type { ByteString } from 'runar-lang';

/**
 * Sha256FinalizeTest — verifies SHA-256 finalize correctness on-chain.
 *
 * The sha256Finalize intrinsic handles FIPS 180-4 padding internally: it
 * appends the 0x80 byte, zero-pads, and appends the 8-byte big-endian bit
 * length, then compresses one or two blocks depending on the remaining length.
 *
 * - remaining <= 55 bytes: single-block path (one compression)
 * - 56-119 bytes: two-block path (two compressions)
 *
 * The msgBitLen parameter is the TOTAL message bit length (across all prior
 * compress calls), used in the final padding suffix.
 */
class Sha256FinalizeTest extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(state: ByteString, remaining: ByteString, msgBitLen: bigint) {
    const result = sha256Finalize(state, remaining, msgBitLen);
    assert(result === this.expected);
  }
}
