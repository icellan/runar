package runar.examples.statefulcounter;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

/**
 * Counter -- the simplest possible stateful smart contract.
 *
 * <p>Demonstrates Rúnar's state management: a counter that persists its
 * value across spending transactions on the Bitcoin SV blockchain.
 *
 * <p>Because this class extends {@link StatefulSmartContract} (not
 * {@code SmartContract}), the compiler auto-injects {@code checkPreimage}
 * at each public method entry and state-continuation output emission at
 * each public method exit. The mutable {@code count} field becomes the
 * contract's serialized state, encoded as push data after OP_RETURN.
 *
 * <p>Written using the {@link Bigint} wrapper so the body reads like the
 * TypeScript source ({@code this.count = this.count + 1n}). The Rúnar
 * Java parser recognises {@code a.plus(b)}, {@code a.minus(b)},
 * {@code a.gt(b)}, ... and lowers them to the canonical arithmetic AST.
 *
 * <p>No authorization checks. This contract is intentionally minimal for
 * educational purposes -- anyone can call {@code increment} or
 * {@code decrement}.
 */
class Counter extends StatefulSmartContract {

    Bigint count; // no @Readonly -> mutable state (persists across transactions)

    Counter(Bigint count) {
        super(count);
        this.count = count;
    }

    /** Increment {@code count} by 1. Anyone can call this method. */
    @Public
    void increment() {
        this.count = this.count.plus(Bigint.ONE);
    }

    /**
     * Decrement {@code count} by 1. Asserts count > 0 to prevent
     * underflow. Anyone can call this method.
     */
    @Public
    void decrement() {
        assertThat(this.count.gt(Bigint.ZERO));
        this.count = this.count.minus(Bigint.ONE);
    }
}
