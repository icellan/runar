package runar.examples.propertyinitializers;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

/**
 * PropertyInitializers -- conformance fixture for property initializers.
 * Properties with literal defaults ({@code count = 0n},
 * {@code active = true}) are excluded from the auto-generated
 * constructor; only {@code maxCount} must be supplied at deploy time.
 */
class PropertyInitializers extends StatefulSmartContract {

    Bigint count = Bigint.ZERO;
    @Readonly Bigint maxCount;
    @Readonly boolean active = true;

    PropertyInitializers(Bigint maxCount) {
        super(maxCount);
        this.maxCount = maxCount;
    }

    @Public
    void increment(Bigint amount) {
        assertThat(this.active);
        this.count = this.count.plus(amount);
        assertThat(this.count.le(this.maxCount));
    }

    @Public
    void reset() {
        this.count = Bigint.ZERO;
    }
}
