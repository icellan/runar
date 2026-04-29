package runar.examples.blake3;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.blake3Compress;
import static runar.lang.Builtins.blake3Hash;

/**
 * Blake3Test -- exercises the built-in BLAKE3 hash primitives.
 *
 * <p>BLAKE3 is a modern (2020) cryptographic hash function based on the Bao
 * tree hashing mode. It produces a 32-byte digest using a 64-byte
 * compression function with a 7-round mixing schedule. The compiled
 * Bitcoin Script for the BLAKE3 compression is roughly 10,000 opcodes
 * (~11 KB) and is practical for on-chain hash verification.
 *
 * <p>This is a stateless {@link SmartContract}. The expected 32-byte
 * digest is baked into the locking script at deploy time; each spending
 * method computes a BLAKE3 hash from unlocking arguments and asserts it
 * matches.
 *
 * <h2>Constructor</h2>
 * <ul>
 *   <li>{@code expected} ({@link ByteString}, readonly) -- the 32-byte
 *       BLAKE3 digest the caller's input must hash to.</li>
 * </ul>
 *
 * <h2>Spending methods</h2>
 * <ul>
 *   <li>{@link #verifyCompress} -- raw compression primitive over a 32-byte
 *       chaining value and a 64-byte block. Use when you need full control
 *       (e.g. verifying intermediate nodes in a BLAKE3 Merkle tree).</li>
 *   <li>{@link #verifyHash} -- single-block convenience hash for messages up
 *       to 64 bytes. Hardcodes {@code blockLen = 64}, {@code counter = 0},
 *       and {@code flags = 11} (CHUNK_START | CHUNK_END | ROOT).</li>
 * </ul>
 *
 * <p>Ports {@code examples/go/blake3/Blake3Test.runar.go}; peer
 * implementations exist for TS, Rust, Python, Zig, and Ruby.
 */
class Blake3Test extends SmartContract {

    @Readonly ByteString expected;

    Blake3Test(ByteString expected) {
        super(expected);
        this.expected = expected;
    }

    @Public
    void verifyCompress(ByteString chainingValue, ByteString block) {
        ByteString result = blake3Compress(chainingValue, block);
        assertThat(result.equals(expected));
    }

    @Public
    void verifyHash(ByteString message) {
        ByteString result = blake3Hash(message);
        assertThat(result.equals(expected));
    }
}
