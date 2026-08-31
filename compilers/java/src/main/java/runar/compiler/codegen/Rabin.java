package runar.compiler.codegen;

import java.math.BigInteger;
import java.util.Set;
import java.util.function.Consumer;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.PushOp;
import runar.compiler.ir.stack.PushValue;
import runar.compiler.ir.stack.StackOp;

/**
 * Rabin signature verification codegen for the Rúnar Java stack lowerer.
 *
 * <p>Direct port of the {@code _lower_verify_rabin_sig} routine in
 * {@code compilers/python/runar_compiler/codegen/stack.py} and the
 * {@code lower_verify_rabin_sig} routine in
 * {@code compilers/rust/src/codegen/stack.rs}.
 *
 * <p>The Rabin verification is a fixed 15-opcode sequence that takes
 * {@code [msg, sig, padding, pubkey]} on the stack (with {@code pubkey}
 * on top) and produces a single boolean result. All four arguments are
 * consumed by the emitter; the caller is responsible for bringing them
 * to the top in argument order before invoking
 * {@link #emitVerifyRabinSig(Consumer)}.
 *
 * <p>The opcode sequence (post BUG-010) is:
 * <pre>
 *   OP_SWAP
 *   OP_DUP OP_0 &lt;push 65536&gt; OP_WITHIN OP_VERIFY   // 0 &lt;= padding &lt; 65536 (BUG-010)
 *   OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD
 *   OP_SWAP OP_SHA256 &lt;push 0x00&gt; OP_CAT OP_BIN2NUM OP_NUMEQUAL
 * </pre>
 *
 * <p>It computes {@code (sig*sig + padding) mod pubkey == sha256(msg)},
 * which is the standard Rabin signature check, and additionally enforces
 * the {@code 0 &lt;= padding &lt; 65536} range bound on-chain.
 * See {@code _review/BUG-010-rfc.md}.
 */
public final class Rabin {

    private Rabin() {}

    /**
     * Exclusive upper bound on the Rabin {@code padding} parameter, enforced
     * on-chain. The legitimate signer
     * ({@code packages/runar-go/rabin.go::RabinSign}) produces
     * {@code padding < 1000}; the on-chain bound is 65536 (16-bit) for slack.
     */
    public static final long RABIN_PADDING_LIMIT = 65_536L;

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
        // BUG-010 padding range check: assert 0 <= padding < 65536.
        emit.accept(new OpcodeOp("OP_DUP"));
        emit.accept(new OpcodeOp("OP_0"));
        emit.accept(new PushOp(PushValue.of(BigInteger.valueOf(RABIN_PADDING_LIMIT))));
        emit.accept(new OpcodeOp("OP_WITHIN"));
        emit.accept(new OpcodeOp("OP_VERIFY"));
        emit.accept(new OpcodeOp("OP_ROT"));
        emit.accept(new OpcodeOp("OP_DUP"));
        emit.accept(new OpcodeOp("OP_MUL"));
        emit.accept(new OpcodeOp("OP_ADD"));
        emit.accept(new OpcodeOp("OP_SWAP"));
        emit.accept(new OpcodeOp("OP_MOD"));
        emit.accept(new OpcodeOp("OP_SWAP"));
        emit.accept(new OpcodeOp("OP_SHA256"));
        // BUG-011 digest-encoding normalization: OP_MOD leaves a MINIMAL Script
        // number, which carries a trailing 0x00 sign byte whenever the digest's
        // most-significant byte has its high bit set (~50% of messages), while
        // OP_SHA256 pushes exactly 32 raw bytes. A bare OP_EQUAL is a BYTE
        // compare and refused about half of all honest signatures on a real
        // consensus VM. Give the digest an explicit 0x00 sign byte, collapse to
        // minimal form, and compare NUMERICALLY. OP_NUMEQUAL never aborts, so
        // the any-of-N pattern still yields false rather than killing the script.
        emit.accept(new PushOp(PushValue.ofHex("00")));
        emit.accept(new OpcodeOp("OP_CAT"));
        emit.accept(new OpcodeOp("OP_BIN2NUM"));
        emit.accept(new OpcodeOp("OP_NUMEQUAL"));
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
