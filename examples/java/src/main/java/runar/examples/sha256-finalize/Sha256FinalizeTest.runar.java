package runar.examples.sha256finalize;

import java.math.BigInteger;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.sha256Finalize;

/**
 * Sha256FinalizeTest -- verifies SHA-256 finalize correctness on-chain.
 *
 * <p>The {@code sha256Finalize} intrinsic handles FIPS 180-4 padding
 * internally: it appends the 0x80 byte, zero-pads, and appends the 8-byte
 * big-endian bit length, then compresses one or two blocks depending on
 * the remaining length:
 * <ul>
 *   <li>remaining ≤ 55 bytes: single-block path (one compression, ~74 KB script)</li>
 *   <li>56-119 bytes: two-block path (two compressions, ~148 KB script)</li>
 * </ul>
 *
 * <p>The {@code msgBitLen} parameter is the TOTAL message bit length
 * across all prior {@code sha256Compress} calls plus the remaining bytes.
 * This value is used in the 64-bit length suffix of the SHA-256 padding.
 *
 * <p>For standalone hashing, pass the SHA-256 IV as state and the full
 * message as remaining. For multi-block hashing, use
 * {@code sha256Compress} for the first N full blocks and
 * {@code sha256Finalize} for the trailing bytes.
 */
class Sha256FinalizeTest extends SmartContract {

    ByteString expected;

    Sha256FinalizeTest(ByteString expected) {
        super(expected);
        this.expected = expected;
    }

    /** Verify {@code sha256Finalize(state, remaining, msgBitLen)} matches {@code expected}. */
    @Public
    void verify(ByteString state, ByteString remaining, BigInteger msgBitLen) {
        ByteString result = sha256Finalize(state, remaining, msgBitLen);
        assertThat(result.equals(this.expected));
    }
}
