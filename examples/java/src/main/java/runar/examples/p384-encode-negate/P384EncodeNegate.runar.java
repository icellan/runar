package runar.examples.p384encodenegate;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.ByteString;
import runar.lang.types.P384Point;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.p384EncodeCompressed;
import static runar.lang.Builtins.p384Negate;

/**
 * P384EncodeNegate -- Java port. Executed coverage for {@code p384Negate} and
 * {@code p384EncodeCompressed}, neither of which appeared in any fixture.
 *
 * <p>See the {@code .runar.ts} port for the full rationale.
 */
class P384EncodeNegate extends SmartContract {

    @Readonly ByteString expectedCompressed;

    P384EncodeNegate(ByteString expectedCompressed) {
        super(expectedCompressed);
        this.expectedCompressed = expectedCompressed;
    }

    /** (x, y) -&gt; (x, p - y). Guards canonicity AND the 96-byte width. */
    @Public
    void checkNegate(P384Point p, P384Point expected) {
        P384Point n = p384Negate(p);
        assertThat(n.equals(expected));
    }

    /** Point -&gt; 49-byte 02/03||x, parity read at a fixed offset. */
    @Public
    void checkEncode(P384Point p, ByteString expected) {
        ByteString e = p384EncodeCompressed(p);
        assertThat(e.equals(expected));
    }

    /** Composed: compressing the negation must flip the prefix only. */
    @Public
    void checkNegateThenEncode(P384Point p) {
        P384Point n = p384Negate(p);
        ByteString e = p384EncodeCompressed(n);
        assertThat(e.equals(this.expectedCompressed));
    }
}
