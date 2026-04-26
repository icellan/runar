package runar.examples.sha256compress;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.sha256Compress;

/**
 * Sha256CompressTest -- verifies SHA-256 compression correctness on-chain.
 *
 * <p>The {@code sha256Compress} intrinsic performs one round of SHA-256
 * block compression (FIPS 180-4 Section 6.2.2): takes a 32-byte state and
 * a 64-byte block, producing a new 32-byte state. The compiled script is
 * ~74 KB (64 rounds of bit manipulation using OP_LSHIFT, OP_RSHIFT,
 * OP_AND, OP_XOR).
 *
 * <p>For a single-block message (≤55 bytes), the caller pads per FIPS
 * 180-4 Section 5.1.1 (append 0x80, zero-pad to 56 bytes, append 8-byte
 * big-endian bit length) and passes the SHA-256 IV as the initial state.
 * The result matches the OP_SHA256 opcode.
 *
 * <p>For multi-block messages, chain multiple {@code sha256Compress}
 * calls -- each producing an intermediate state for the next block.
 */
class Sha256CompressTest extends SmartContract {

    @Readonly ByteString expected;

    Sha256CompressTest(ByteString expected) {
        super(expected);
        this.expected = expected;
    }

    /** Verify {@code sha256Compress(state, block)} matches {@code expected}. */
    @Public
    void verify(ByteString state, ByteString block) {
        ByteString result = sha256Compress(state, block);
        assertThat(result.equals(this.expected));
    }
}
