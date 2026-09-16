package runar.examples.bytebuiltins;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.Sha256;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.int2str;
import static runar.lang.Builtins.reverseBytes;
import static runar.lang.Builtins.sha256;
import static runar.lang.Builtins.split;

/**
 * ByteBuiltins -- Java port. Executed coverage for four byte-level builtins
 * that no conformance fixture called: {@code split}, {@code int2str},
 * {@code reverseBytes} and {@code sha256}.
 *
 * <p>See the {@code .runar.ts} port for the full rationale, and for why
 * {@code ripemd160} is absent.
 */
class ByteBuiltins extends SmartContract {

    @Readonly Sha256 expectedDigest;

    ByteBuiltins(Sha256 expectedDigest) {
        super(expectedDigest);
        this.expectedDigest = expectedDigest;
    }

    /** OP_SPLIT. Binds the right half of {@code data} at {@code idx}. */
    @Public
    void checkSplit(ByteString data, Bigint idx, ByteString expectedTail) {
        ByteString tail = split(data, idx);
        assertThat(tail.equals(expectedTail));
    }

    /** OP_NUM2BIN. Fixed-width little-endian sign-magnitude encoding. */
    @Public
    void checkInt2Str(Bigint value, Bigint width, ByteString expected) {
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
        Sha256 h = sha256(preimage);
        assertThat(h.equals(this.expectedDigest));
    }
}
