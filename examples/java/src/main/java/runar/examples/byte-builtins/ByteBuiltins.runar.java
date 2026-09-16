package runar.examples.bytebuiltins;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import java.math.BigInteger;
import runar.lang.types.ByteString;
import runar.lang.types.Ripemd160;
import runar.lang.types.Sha256;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.int2str;
import static runar.lang.Builtins.reverseBytes;
import static runar.lang.Builtins.ripemd160;
import static runar.lang.Builtins.sha256;
import static runar.lang.Builtins.split;

/**
 * ByteBuiltins -- Java port. Executed coverage for five byte-level builtins
 * that no conformance fixture called: {@code split}, {@code int2str},
 * {@code reverseBytes}, {@code sha256} and {@code ripemd160}.
 *
 * <p>See the {@code .runar.ts} port for the full rationale.
 *
 * <p>This file is a Rúnar frontend input, not a Java compilation unit, and
 * {@code examples/java/build.gradle.kts} excludes it from javac — the Go port
 * states the same thing with {@code //go:build ignore}. One signature is why:
 * Rúnar's {@code split} returns the RIGHT half as a single {@code ByteString},
 * because no surface parser accepts array destructuring and the left half is
 * unnameable, while {@code runar.lang.Builtins.split} models it as a
 * {@code ByteString[]} pair. Everything else here is valid Java. The Rúnar side
 * is fully covered: {@code conformance/tests/byte-builtins} reads this file for
 * the {@code .runar.java} surface, and the compiled bytes are spent in
 * {@code conformance/byte_builtins_execution_test.go}.
 */
class ByteBuiltins extends SmartContract {

    @Readonly Sha256 expectedDigest;
    @Readonly Ripemd160 expectedRipemd;

    ByteBuiltins(Sha256 expectedDigest, Ripemd160 expectedRipemd) {
        super(expectedDigest, expectedRipemd);
        this.expectedDigest = expectedDigest;
        this.expectedRipemd = expectedRipemd;
    }

    /** OP_SPLIT. Binds the right half of {@code data} at {@code idx}. */
    @Public
    void checkSplit(ByteString data, BigInteger idx, ByteString expectedTail) {
        ByteString tail = split(data, idx);
        assertThat(tail.equals(expectedTail));
    }

    /** OP_NUM2BIN. Fixed-width little-endian sign-magnitude encoding. */
    @Public
    void checkInt2Str(BigInteger value, BigInteger width, ByteString expected) {
        ByteString s = int2str(value, width);
        assertThat(s.equals(expected));
    }

    /** 520 unrolled OP_SPLIT / OP_CAT iterations -- one per possible byte. */
    @Public
    void checkReverse(ByteString data, ByteString expected) {
        ByteString r = reverseBytes(data);
        assertThat(r.equals(expected));
    }

    /** OP_SHA256, against the digest baked into the locking script. */
    @Public
    void checkSha256(ByteString preimage) {
        ByteString h = sha256(preimage);
        assertThat(h.equals(this.expectedDigest));
    }

    /** OP_RIPEMD160, against the digest baked into the locking script. */
    @Public
    void checkRipemd(ByteString preimage) {
        ByteString h = ripemd160(preimage);
        assertThat(h.equals(this.expectedRipemd));
    }
}
