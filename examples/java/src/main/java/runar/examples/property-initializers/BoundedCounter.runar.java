package runar.examples.propertyinitializers;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

/**
 * BoundedCounter -- demonstrates property initializers in the Java
 * contract format.
 *
 * <p>Fields with a literal default ({@code count = Bigint.ZERO},
 * {@code active = true}) are initialised inline and excluded from the
 * auto-generated constructor. Only {@code maxCount} must be supplied at
 * deploy time. The constructor passes the full argument list to
 * {@code super(...)} so the base class captures the actual deployment
 * args for the off-chain simulator.
 *
 * <p>The contract enforces {@code count <= maxCount} after every
 * {@code increment} call and rejects all bumps once {@code active} is
 * flipped to {@code false} (future work: add a deactivate path).
 */
class BoundedCounter extends StatefulSmartContract {

    Bigint count = Bigint.ZERO;           // mutable, initialised to 0
    @Readonly Bigint maxCount;            // immutable upper bound, supplied in constructor
    @Readonly boolean active = true;      // readonly with default

    BoundedCounter(Bigint maxCount) {
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
