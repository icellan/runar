package runar.lang;

import runar.lang.types.ByteString;

/**
 * Base class for stateless Rúnar contracts that need the raw-script
 * escape hatch ({@code asm}). Like {@link SmartContract}, all fields of a
 * subclass are implicitly readonly — UnsafeSmartContract trades the
 * type-checked subset only for the bytes inside {@code asm} calls, not
 * for mutable state. Use {@link StatefulSmartContract} for mutable
 * state.
 *
 * <p>The {@code asm} compiler intrinsic is provided as
 * {@link #asm(AsmArgs)}; it panics at runtime, since the call is
 * intercepted at compile time and lowered to a {@code raw_script} ANF
 * node.
 */
public abstract class UnsafeSmartContract {

    protected UnsafeSmartContract(Object... constructorArgs) {
        // The compiler replaces super(...) with a no-op AST binding.
        // Kept as a harmless constructor hook for test-time simulation.
    }

    /**
     * Structured argument for the {@code asm} compiler intrinsic. The
     * Rúnar Java frontend intercepts {@code asm(args)} calls at parse
     * time and lowers them to a {@code raw_script} ANF node; this record
     * only exists so native {@code javac} compilation of contract source
     * succeeds.
     *
     * @param body     even-length hex string of the raw Bitcoin Script
     *                 opcode bytes to embed verbatim
     * @param inArity  number of stack items consumed on entry (defaults to 0)
     * @param outArity number of stack items left on exit (defaults to 1)
     */
    public record AsmArgs(String body, int inArity, int outArity) {
        public AsmArgs {
            if (body == null) body = "";
        }

        public AsmArgs(String body) {
            this(body, 0, 1);
        }

        public AsmArgs(String body, int inArity) {
            this(body, inArity, 1);
        }

        public AsmArgs(ByteString body, int inArity, int outArity) {
            this(body == null ? "" : body.toHex(), inArity, outArity);
        }
    }

    /**
     * Embed a raw Bitcoin Script byte sequence in a contract method.
     * Only callable from inside a contract that extends
     * {@link UnsafeSmartContract} — the compiler enforces this.
     *
     * <p>This runtime stub panics: {@code asm} is a compile-time
     * intrinsic and cannot be executed off-chain.
     */
    protected static void asm(AsmArgs args) {
        throw new UnsupportedOperationException(
            "asm() cannot be called at runtime — compile this contract with the Rúnar compiler"
        );
    }

    /**
     * Positional {@code asm} overload — {@code asm(body, inArity, outArity)}.
     * Mirrors the Go {@code runar.Asm("51", 0, 1)} surface so Rúnar Java
     * contracts can spell the intrinsic inline without constructing an
     * {@link AsmArgs}. The compiler intercepts the call at parse time; this
     * stub panics if reached at runtime.
     *
     * @param body     even-length hex string of the raw opcode bytes
     * @param inArity  stack items consumed on entry
     * @param outArity stack items left on exit
     */
    protected static void asm(String body, int inArity, int outArity) {
        throw new UnsupportedOperationException(
            "asm() cannot be called at runtime — compile this contract with the Rúnar compiler"
        );
    }
}
