package runar.examples.stateful;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

/**
 * Stateful -- minimal stateful conformance fixture that mixes a mutable
 * {@code count} with an immutable {@code maxCount} ceiling. Demonstrates
 * the two-property state-continuation lowering.
 *
 * <p>Because this class extends {@link StatefulSmartContract}, the compiler
 * auto-injects {@code checkPreimage} at each public method entry and a
 * state-continuation output at each public method exit -- only the
 * mutable property ({@code count}) flows through the continuation; the
 * {@code @Readonly} {@code maxCount} is baked into the locking script at
 * deploy time.
 *
 * <h2>Constructor</h2>
 * <ul>
 *   <li>{@code count} ({@link Bigint}, mutable) -- current counter value
 *       (the contract's persistent state).</li>
 *   <li>{@code maxCount} ({@link Bigint}, readonly) -- upper bound that
 *       {@code count} may never exceed.</li>
 * </ul>
 *
 * <h2>Spending methods</h2>
 * <ul>
 *   <li>{@link #increment} -- add {@code amount}; asserts the new count
 *       does not exceed {@code maxCount}.</li>
 *   <li>{@link #reset} -- reset {@code count} to zero.</li>
 * </ul>
 *
 * <p>Used as a conformance fixture across all 7 compiler tiers.
 */
class Stateful extends StatefulSmartContract {

    Bigint count;
    @Readonly Bigint maxCount;

    Stateful(Bigint count, Bigint maxCount) {
        super(count, maxCount);
        this.count = count;
        this.maxCount = maxCount;
    }

    @Public
    void increment(Bigint amount) {
        this.count = this.count.plus(amount);
        assertThat(this.count.le(this.maxCount));
    }

    @Public
    void reset() {
        this.count = Bigint.ZERO;
    }
}
