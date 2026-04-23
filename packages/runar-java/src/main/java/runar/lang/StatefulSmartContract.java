package runar.lang;

/**
 * Base class for stateful Rúnar contracts. The compiler auto-injects
 * {@code checkPreimage} at method entry and state continuation at exit;
 * mutable fields become the contract's serialized state.
 *
 * <p>Wrap readonly fields in {@code @Readonly} (from
 * {@code runar.lang.annotations}); all unannotated fields are treated
 * as mutable state.
 */
public abstract class StatefulSmartContract extends SmartContract {

    protected StatefulSmartContract(Object... constructorArgs) {
        super(constructorArgs);
    }
}
