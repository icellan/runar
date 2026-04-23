package runar.lang;

import java.math.BigInteger;

/**
 * Base class for stateless Rúnar contracts. All fields of a subclass
 * are implicitly readonly; the compiler rejects mutation in method
 * bodies.
 *
 * <p>Phase 1 stub: methods throw at runtime. The off-chain simulator
 * (milestone 11) provides real implementations for unit testing, and
 * the compiler consumes these classes as AST-extraction targets rather
 * than executing them.
 */
public abstract class SmartContract {

    protected SmartContract(Object... constructorArgs) {
        // The compiler replaces super(...) with a no-op AST binding;
        // at Java runtime this is a harmless constructor hook for any
        // future off-chain simulator.
    }

    /**
     * Add an output to the current spending transaction. Positional
     * values must match the mutable properties of the contract in
     * declaration order (stateful) or be absent (stateless).
     */
    protected final void addOutput(BigInteger satoshis, Object... values) {
        throw new UnsupportedOperationException(
            "addOutput is a compile-time intrinsic; invoke via the off-chain simulator (milestone 11)"
        );
    }

    /**
     * Add a raw output with caller-specified script bytes instead of
     * the contract's own codePart.
     */
    protected final void addRawOutput(BigInteger satoshis, Object scriptBytes) {
        throw new UnsupportedOperationException(
            "addRawOutput is a compile-time intrinsic; invoke via the off-chain simulator (milestone 11)"
        );
    }
}
