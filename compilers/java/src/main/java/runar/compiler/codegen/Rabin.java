package runar.compiler.codegen;

import java.util.Set;
import java.util.function.Consumer;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.StackOp;

/**
 * Rabin signature verification codegen for the Rúnar Java stack lowerer.
 *
 * <p>Direct port of the {@code _lower_verify_rabin_sig} routine in
 * {@code compilers/python/runar_compiler/codegen/stack.py} and the
 * {@code lower_verify_rabin_sig} routine in
 * {@code compilers/rust/src/codegen/stack.rs}.
 *
 * <p>The Rabin verification is a fixed 10-opcode sequence that takes
 * {@code [msg, sig, padding, pubkey]} on the stack (with {@code pubkey}
 * on top) and produces a single boolean result. All four arguments are
 * consumed by the emitter; the caller is responsible for bringing them
 * to the top in argument order before invoking
 * {@link #emitVerifyRabinSig(Consumer)}.
 *
 * <p>The opcode sequence is:
 * <pre>
 *   OP_SWAP OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL
 * </pre>
 *
 * <p>It computes {@code (sig*sig + padding) mod pubkey == sha256(msg)},
 * which is the standard Rabin signature check.
 */
public final class Rabin {

    private Rabin() {}

    /** Set of builtin names that route to {@link #emitVerifyRabinSig}. */
    private static final Set<String> NAMES = Set.of("verifyRabinSig");

    public static boolean isRabinBuiltin(String name) {
        return NAMES.contains(name);
    }

    /**
     * Emit the Rabin signature verification opcode sequence.
     *
     * <p>Stack on entry: {@code [..., msg, sig, padding, pubkey]} (pubkey on top).
     * Stack on exit:  {@code [..., bool]} where 1 = signature valid, 0 = invalid.
     */
    public static void emitVerifyRabinSig(Consumer<StackOp> emit) {
        emit.accept(new OpcodeOp("OP_SWAP"));
        emit.accept(new OpcodeOp("OP_ROT"));
        emit.accept(new OpcodeOp("OP_DUP"));
        emit.accept(new OpcodeOp("OP_MUL"));
        emit.accept(new OpcodeOp("OP_ADD"));
        emit.accept(new OpcodeOp("OP_SWAP"));
        emit.accept(new OpcodeOp("OP_MOD"));
        emit.accept(new OpcodeOp("OP_SWAP"));
        emit.accept(new OpcodeOp("OP_SHA256"));
        emit.accept(new OpcodeOp("OP_EQUAL"));
    }

    /**
     * Dispatch entry point for {@code StackLower}. Currently only
     * {@code verifyRabinSig} is supported; included for symmetry with
     * the other crypto codegen modules.
     */
    public static void dispatch(String funcName, Consumer<StackOp> emit) {
        if ("verifyRabinSig".equals(funcName)) {
            emitVerifyRabinSig(emit);
            return;
        }
        throw new RuntimeException("unknown Rabin builtin: " + funcName);
    }
}
