package runar.examples.ternaryexpression;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;

/**
 * TernaryExpression -- see TernaryExpression.runar.ts.
 */
class TernaryExpression extends SmartContract {

    @Readonly Bigint threshold;
    @Readonly ByteString highTag;
    @Readonly ByteString lowTag;

    TernaryExpression(Bigint threshold, ByteString highTag, ByteString lowTag) {
        super(threshold, highTag, lowTag);
        this.threshold = threshold;
        this.highTag = highTag;
        this.lowTag = lowTag;
    }

    @Public
    void check(Bigint x, Bigint distance, ByteString tag, Bigint band) {
        Bigint d = x.gt(this.threshold) ? x.minus(this.threshold) : this.threshold.minus(x);
        assertThat(d.eq(distance));

        ByteString t = x.gt(this.threshold) ? this.highTag : this.lowTag;
        assertThat(t.equals(tag));

        Bigint b = x.gt(this.threshold) ? Bigint.TWO : (x.eq(this.threshold) ? Bigint.ONE : Bigint.ZERO);
        assertThat(b.eq(band));
    }
}
