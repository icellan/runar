package runar.examples.functionpatterns;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.clamp;
import static runar.lang.Builtins.mulDiv;
import static runar.lang.Builtins.percentOf;
import static runar.lang.Builtins.safemod;

/**
 * FunctionPatterns -- demonstrates every way functions and methods can
 * be used inside a Rúnar Java contract.
 *
 * <p>Rúnar contracts support three categories of callable code:
 * <ol>
 *   <li>Public methods -- annotated with {@code @Public}. Spending
 *       entry points that appear in the compiled Bitcoin Script.</li>
 *   <li>Private methods -- package-private (no annotation). Can access
 *       contract state via {@code this} and are inlined by the compiler
 *       at call sites. Private methods may return a value.</li>
 *   <li>Built-in functions -- imported from {@link runar.lang.Builtins}
 *       (e.g. {@code assertThat}, {@code checkSig}, {@code percentOf},
 *       {@code clamp}). These map directly to Bitcoin Script opcodes.</li>
 * </ol>
 *
 * <p>Note: like Python contracts, Java contracts cannot define
 * standalone functions outside the class. All helper logic must be
 * private methods on the class.
 */
class FunctionPatterns extends StatefulSmartContract {

    @Readonly PubKey owner;   // immutable: contract creator
    Bigint balance;           // stateful: current balance

    FunctionPatterns(PubKey owner, Bigint balance) {
        super(owner, balance);
        this.owner = owner;
        this.balance = balance;
    }

    // -------------------------------------------------------------------
    // 1. Public methods -- spending entry points
    // -------------------------------------------------------------------

    /** Deposit adds funds. Calls a private method and a built-in. */
    @Public
    void deposit(Sig sig, Bigint amount) {
        // Private method: shared signature check
        requireOwner(sig);

        // Built-in: assertion
        assertThat(amount.gt(Bigint.ZERO));

        // Update state
        this.balance = this.balance.plus(amount);
    }

    /**
     * Withdraw removes funds after applying a fee.
     *
     * <p>Demonstrates chaining a private method that returns a value.
     */
    @Public
    void withdraw(Sig sig, Bigint amount, Bigint feeBps) {
        requireOwner(sig);
        assertThat(amount.gt(Bigint.ZERO));

        // Private method with return value
        Bigint fee = computeFee(amount, feeBps);
        Bigint total = amount.plus(fee);

        assertThat(total.le(this.balance));
        this.balance = this.balance.minus(total);
    }

    /**
     * Scale multiplies the balance by a rational number.
     *
     * <p>Demonstrates calling a private method that wraps a built-in.
     */
    @Public
    void scale(Sig sig, Bigint numerator, Bigint denominator) {
        requireOwner(sig);
        this.balance = scaleValue(this.balance, numerator, denominator);
    }

    /**
     * Normalize clamps the balance to a range and rounds down.
     *
     * <p>Demonstrates composing multiple private helper methods.
     */
    @Public
    void normalize(Sig sig, Bigint lo, Bigint hi, Bigint step) {
        requireOwner(sig);
        Bigint clamped = clampValue(this.balance, lo, hi);
        this.balance = roundDown(clamped, step);
    }

    // -------------------------------------------------------------------
    // 2. Private methods -- inlined helpers
    // -------------------------------------------------------------------

    /** Verify the caller is the contract owner. Shared by all public methods. */
    void requireOwner(Sig sig) {
        assertThat(checkSig(sig, this.owner));
    }

    /** Compute a fee in basis points. Returns the fee amount. */
    Bigint computeFee(Bigint amount, Bigint feeBps) {
        return Bigint.of(percentOf(amount.value(), feeBps.value()));
    }

    /** Multiply a value by a fraction using mulDiv for precision. */
    Bigint scaleValue(Bigint value, Bigint numerator, Bigint denominator) {
        return Bigint.of(mulDiv(value.value(), numerator.value(), denominator.value()));
    }

    /** Clamp a value to {@code [lo, hi]}. */
    Bigint clampValue(Bigint value, Bigint lo, Bigint hi) {
        return Bigint.of(clamp(value.value(), lo.value(), hi.value()));
    }

    /** Round down to the nearest multiple of step. */
    Bigint roundDown(Bigint value, Bigint step) {
        Bigint remainder = Bigint.of(safemod(value.value(), step.value()));
        return value.minus(remainder);
    }
}
