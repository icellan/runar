package runar.examples.p256encodenegate;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.ByteString;
import runar.lang.types.P256Point;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.p256EncodeCompressed;
import static runar.lang.Builtins.p256Negate;

/**
 * P256EncodeNegate -- Java port. Executed coverage for {@code p256Negate} and
 * {@code p256EncodeCompressed}, neither of which appeared in any fixture.
 *
 * <p>See the {@code .runar.ts} port for the full rationale.
 */
class P256EncodeNegate extends SmartContract {

    @Readonly ByteString expectedCompressed;

    P256EncodeNegate(ByteString expectedCompressed) {
        super(expectedCompressed);
        this.expectedCompressed = expectedCompressed;
    }

    /** (x, y) -&gt; (x, p - y). Guards canonicity AND the 64-byte width. */
    @Public
    void checkNegate(P256Point p, P256Point expected) {
        P256Point n = p256Negate(p);
        assertThat(n.equals(expected));
    }

    /** Point -&gt; 33-byte 02/03||x, parity read at a fixed offset. */
    @Public
    void checkEncode(P256Point p, ByteString expected) {
        ByteString e = p256EncodeCompressed(p);
        assertThat(e.equals(expected));
    }

    /** Composed: compressing the negation must flip the prefix only. */
    @Public
    void checkNegateThenEncode(P256Point p) {
        P256Point n = p256Negate(p);
        ByteString e = p256EncodeCompressed(n);
        assertThat(e.equals(this.expectedCompressed));
    }
}
