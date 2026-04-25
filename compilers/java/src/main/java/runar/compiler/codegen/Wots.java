package runar.compiler.codegen;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import runar.compiler.ir.stack.DropOp;
import runar.compiler.ir.stack.IfOp;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.PushOp;
import runar.compiler.ir.stack.PushValue;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.SwapOp;

/**
 * WOTS+ (Winternitz One-Time Signature, post-quantum) Bitcoin Script
 * codegen for the Rúnar Java stack lowerer.
 *
 * <p>Direct port of the {@code _lower_verify_wots} / {@code _emit_wots_one_chain}
 * routines in {@code compilers/python/runar_compiler/codegen/stack.py} and
 * the corresponding routines in {@code compilers/rust/src/codegen/stack.rs}
 * and {@code compilers/go/codegen/stack.go}. All emitted ops are
 * byte-identical to those reference implementations for the same input.
 *
 * <p>Entry point: {@link #emitVerifyWots(Consumer)} emits the full
 * verification script. Stack on entry: {@code [..., msg, sig, pubkey]}
 * (pubkey on top). Stack on exit: {@code [..., bool]}.
 *
 * <p>The script:
 * <ol>
 *   <li>Splits the 64-byte pubkey into pubSeed(32) and pkRoot(32).</li>
 *   <li>SHA-256 hashes the message into a 32-byte digest.</li>
 *   <li>Processes the 32 message bytes into 64 message-chain digits
 *       (one nibble per chain), running each through a WOTS+ chain.</li>
 *   <li>Computes 3 checksum digits and runs them through chains 64, 65, 66.</li>
 *   <li>SHA-256 hashes the concatenated 67 chain endpoints.</li>
 *   <li>Compares the resulting hash to pkRoot.</li>
 * </ol>
 */
public final class Wots {

    private Wots() {}

    /** Set of builtin names that route to {@link #emitVerifyWots}. */
    private static final Set<String> NAMES = Set.of("verifyWOTS");

    public static boolean isWotsBuiltin(String name) {
        return NAMES.contains(name);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static PushOp pushInt(long v) {
        return new PushOp(PushValue.of(BigInteger.valueOf(v)));
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    private static PushOp pushBytes(byte[] v) {
        return new PushOp(PushValue.ofHex(hex(v)));
    }

    // ------------------------------------------------------------------
    // One WOTS+ chain
    // ------------------------------------------------------------------

    /**
     * Emit one WOTS+ chain verification.
     *
     * <p>Direct port of {@code _emit_wots_one_chain} from
     * {@code compilers/python/runar_compiler/codegen/stack.py}.
     */
    private static void emitWotsOneChain(Consumer<StackOp> emit, int chainIndex) {
        // Save steps_copy = 15 - digit to alt
        emit.accept(new OpcodeOp("OP_DUP"));
        emit.accept(pushInt(15));
        emit.accept(new SwapOp());
        emit.accept(new OpcodeOp("OP_SUB"));
        emit.accept(new OpcodeOp("OP_TOALTSTACK"));

        // Save endpt, csum to alt
        emit.accept(new SwapOp());
        emit.accept(new OpcodeOp("OP_TOALTSTACK"));
        emit.accept(new SwapOp());
        emit.accept(new OpcodeOp("OP_TOALTSTACK"));

        // Split 32B sig element
        emit.accept(new SwapOp());
        emit.accept(pushInt(32));
        emit.accept(new OpcodeOp("OP_SPLIT"));
        emit.accept(new OpcodeOp("OP_TOALTSTACK"));
        emit.accept(new SwapOp());

        // Hash loop: 15 unrolled iterations.
        for (int j = 0; j < 15; j++) {
            byte[] adrsBytes = new byte[]{(byte) (chainIndex & 0xff), (byte) (j & 0xff)};

            emit.accept(new OpcodeOp("OP_DUP"));
            emit.accept(new OpcodeOp("OP_0NOTEQUAL"));

            List<StackOp> thenOps = new ArrayList<>();
            thenOps.add(new OpcodeOp("OP_1SUB"));

            List<StackOp> elseOps = new ArrayList<>();
            elseOps.add(new SwapOp());
            elseOps.add(pushInt(2));
            elseOps.add(new OpcodeOp("OP_PICK"));
            elseOps.add(pushBytes(adrsBytes));
            elseOps.add(new OpcodeOp("OP_CAT"));
            elseOps.add(new SwapOp());
            elseOps.add(new OpcodeOp("OP_CAT"));
            elseOps.add(new OpcodeOp("OP_SHA256"));
            elseOps.add(new SwapOp());

            emit.accept(new IfOp(thenOps, elseOps));
        }
        emit.accept(new DropOp());

        // Restore from altstack
        emit.accept(new OpcodeOp("OP_FROMALTSTACK"));
        emit.accept(new OpcodeOp("OP_FROMALTSTACK"));
        emit.accept(new OpcodeOp("OP_FROMALTSTACK"));
        emit.accept(new OpcodeOp("OP_FROMALTSTACK"));

        // csum += steps_copy
        emit.accept(new OpcodeOp("OP_ROT"));
        emit.accept(new OpcodeOp("OP_ADD"));

        // Concat endpoint to endpt_acc
        emit.accept(new SwapOp());
        emit.accept(pushInt(3));
        emit.accept(new OpcodeOp("OP_ROLL"));
        emit.accept(new OpcodeOp("OP_CAT"));
    }

    // ------------------------------------------------------------------
    // Full WOTS+ verifier
    // ------------------------------------------------------------------

    /**
     * Emit the full WOTS+ signature verification script.
     *
     * <p>Stack on entry: {@code [..., msg, sig, pubkey]} (pubkey on top).
     * Stack on exit:  {@code [..., bool]} where 1 = valid, 0 = invalid.
     *
     * <p>Direct port of {@code _lower_verify_wots} from
     * {@code compilers/python/runar_compiler/codegen/stack.py}.
     */
    public static void emitVerifyWots(Consumer<StackOp> emit) {
        // Split 64-byte pubkey into pubSeed(32) and pkRoot(32)
        emit.accept(pushInt(32));
        emit.accept(new OpcodeOp("OP_SPLIT"));
        emit.accept(new OpcodeOp("OP_TOALTSTACK"));

        // Rearrange: put pubSeed at bottom, hash msg
        emit.accept(new OpcodeOp("OP_ROT"));
        emit.accept(new OpcodeOp("OP_ROT"));
        emit.accept(new SwapOp());
        emit.accept(new OpcodeOp("OP_SHA256"));

        // Canonical layout
        emit.accept(new SwapOp());
        emit.accept(pushInt(0));
        emit.accept(new OpcodeOp("OP_0"));
        emit.accept(pushInt(3));
        emit.accept(new OpcodeOp("OP_ROLL"));

        // Process 32 bytes -> 64 message chains
        for (int byteIdx = 0; byteIdx < 32; byteIdx++) {
            if (byteIdx < 31) {
                emit.accept(pushInt(1));
                emit.accept(new OpcodeOp("OP_SPLIT"));
                emit.accept(new SwapOp());
            }
            // Unsigned byte conversion
            emit.accept(pushInt(0));
            emit.accept(pushInt(1));
            emit.accept(new OpcodeOp("OP_NUM2BIN"));
            emit.accept(new OpcodeOp("OP_CAT"));
            emit.accept(new OpcodeOp("OP_BIN2NUM"));
            // Extract nibbles
            emit.accept(new OpcodeOp("OP_DUP"));
            emit.accept(pushInt(16));
            emit.accept(new OpcodeOp("OP_DIV"));
            emit.accept(new SwapOp());
            emit.accept(pushInt(16));
            emit.accept(new OpcodeOp("OP_MOD"));

            if (byteIdx < 31) {
                emit.accept(new OpcodeOp("OP_TOALTSTACK"));
                emit.accept(new SwapOp());
                emit.accept(new OpcodeOp("OP_TOALTSTACK"));
            } else {
                emit.accept(new OpcodeOp("OP_TOALTSTACK"));
            }

            emitWotsOneChain(emit, byteIdx * 2);  // high nibble chain

            if (byteIdx < 31) {
                emit.accept(new OpcodeOp("OP_FROMALTSTACK"));
                emit.accept(new OpcodeOp("OP_FROMALTSTACK"));
                emit.accept(new SwapOp());
                emit.accept(new OpcodeOp("OP_TOALTSTACK"));
            } else {
                emit.accept(new OpcodeOp("OP_FROMALTSTACK"));
            }

            emitWotsOneChain(emit, byteIdx * 2 + 1);  // low nibble chain

            if (byteIdx < 31) {
                emit.accept(new OpcodeOp("OP_FROMALTSTACK"));
            }
        }

        // Checksum digits
        emit.accept(new SwapOp());
        // d66
        emit.accept(new OpcodeOp("OP_DUP"));
        emit.accept(pushInt(16));
        emit.accept(new OpcodeOp("OP_MOD"));
        emit.accept(new OpcodeOp("OP_TOALTSTACK"));
        // d65
        emit.accept(new OpcodeOp("OP_DUP"));
        emit.accept(pushInt(16));
        emit.accept(new OpcodeOp("OP_DIV"));
        emit.accept(pushInt(16));
        emit.accept(new OpcodeOp("OP_MOD"));
        emit.accept(new OpcodeOp("OP_TOALTSTACK"));
        // d64
        emit.accept(pushInt(256));
        emit.accept(new OpcodeOp("OP_DIV"));
        emit.accept(pushInt(16));
        emit.accept(new OpcodeOp("OP_MOD"));
        emit.accept(new OpcodeOp("OP_TOALTSTACK"));

        // 3 checksum chains (indices 64, 65, 66)
        for (int ci = 0; ci < 3; ci++) {
            emit.accept(new OpcodeOp("OP_TOALTSTACK"));
            emit.accept(pushInt(0));
            emit.accept(new OpcodeOp("OP_FROMALTSTACK"));
            emit.accept(new OpcodeOp("OP_FROMALTSTACK"));
            emitWotsOneChain(emit, 64 + ci);
            emit.accept(new SwapOp());
            emit.accept(new DropOp());
        }

        // Final comparison
        emit.accept(new SwapOp());
        emit.accept(new DropOp());
        emit.accept(new OpcodeOp("OP_SHA256"));
        emit.accept(new OpcodeOp("OP_FROMALTSTACK"));
        emit.accept(new OpcodeOp("OP_EQUAL"));
        // Clean up pubSeed
        emit.accept(new SwapOp());
        emit.accept(new DropOp());
    }

    /**
     * Dispatch entry point for {@code StackLower}. Currently only
     * {@code verifyWOTS} is supported; included for symmetry with the
     * other crypto codegen modules.
     */
    public static void dispatch(String funcName, Consumer<StackOp> emit) {
        if ("verifyWOTS".equals(funcName)) {
            emitVerifyWots(emit);
            return;
        }
        throw new RuntimeException("unknown WOTS+ builtin: " + funcName);
    }
}
