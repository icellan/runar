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
 * <p>The Rabin verification is a fixed 34-op sequence that takes
 * {@code [msg, sig, padding, pubkey]} on the stack (with {@code pubkey}
 * on top) and produces a single boolean result. All four arguments are
 * consumed by the emitter; the caller is responsible for bringing them
 * to the top in argument order before invoking
 * {@link #emitVerifyRabinSig(Consumer)}.
 *
 * <p>The opcode sequence (post BUG-010, BUG-011, F-047, F-144, F-368) is a
 * fixed 34 ops:
 * <pre>
 *   &lt;push 0x00&gt; OP_CAT OP_BIN2NUM                   // pubkey as unsigned (F-144)
 *   OP_SWAP
 *   &lt;push 0x00&gt; OP_CAT OP_BIN2NUM                   // padding as unsigned (F-144)
 *   OP_DUP OP_0 &lt;push 65536&gt; OP_WITHIN OP_VERIFY   // 0 &lt;= padding &lt; 65536 (BUG-010)
 *   OP_ROT
 *   &lt;push 0x00&gt; OP_CAT OP_BIN2NUM                   // sig as unsigned (F-144)
 *   OP_DUP OP_3 OP_PICK OP_LESSTHAN OP_VERIFY      // sig &lt; pubkey (F-368)
 *   OP_DUP OP_MUL OP_ADD OP_OVER OP_MOD
 *   OP_ROT OP_SHA256 &lt;push 0x00&gt; OP_CAT OP_BIN2NUM
 *   OP_ROT OP_MOD OP_NUMEQUAL                       // digest mod pubkey (F-047)
 * </pre>
 *
 * <p>It computes {@code (sig*sig + padding) mod pubkey == sha256(msg)},
 * which is the standard Rabin signature check, and additionally enforces
 * the {@code 0 &lt;= padding &lt; 65536} range bound on-chain.
 * See {@code _review/BUG-010-rfc.md}. F-368 adds {@code sig &lt; pubkey}
 * ({@code sig &gt;= 0} already holds after F-144), so the
 * {@code sig + k*pubkey} re-encodings of one signature are refused.
 *
 * <p>OPERAND SIGN (F-144): off-chain verifiers read padding (and the native
 * Go/Rust/Python/Ruby/Zig layers also sig and pubkey) as UNSIGNED
 * little-endian bytes; OP_WITHIN / OP_MUL / OP_MOD read a Script number,
 * whose last byte's high bit is the sign. Each operand gets an explicit
 * 0x00 sign byte and OP_BIN2NUM, so a raw unsigned push keeps its unsigned
 * value and a non-negative Script number is unchanged.
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
        emit.accept(new PushOp(PushValue.ofHex("00"))); // F-144: pubkey as unsigned
        emit.accept(new OpcodeOp("OP_CAT"));
        emit.accept(new OpcodeOp("OP_BIN2NUM"));
        emit.accept(new OpcodeOp("OP_SWAP"));
        emit.accept(new PushOp(PushValue.ofHex("00"))); // F-144: padding as unsigned
        emit.accept(new OpcodeOp("OP_CAT"));
        emit.accept(new OpcodeOp("OP_BIN2NUM"));
        // BUG-010 padding range check: assert 0 <= padding < 65536.
        emit.accept(new OpcodeOp("OP_DUP"));
        emit.accept(new OpcodeOp("OP_0"));
        emit.accept(new PushOp(PushValue.of(BigInteger.valueOf(RABIN_PADDING_LIMIT))));
        emit.accept(new OpcodeOp("OP_WITHIN"));
        emit.accept(new OpcodeOp("OP_VERIFY"));
        emit.accept(new OpcodeOp("OP_ROT"));
        emit.accept(new PushOp(PushValue.ofHex("00"))); // F-144: sig as unsigned
        emit.accept(new OpcodeOp("OP_CAT"));
        emit.accept(new OpcodeOp("OP_BIN2NUM"));
        // F-368: assert sig < pubkey (sig >= 0 already holds after F-144).
        emit.accept(new OpcodeOp("OP_DUP"));
        emit.accept(new PushOp(PushValue.of(BigInteger.valueOf(3))));
        emit.accept(new OpcodeOp("OP_PICK"));
        emit.accept(new OpcodeOp("OP_LESSTHAN"));
        emit.accept(new OpcodeOp("OP_VERIFY"));
        emit.accept(new OpcodeOp("OP_DUP"));
        emit.accept(new OpcodeOp("OP_MUL"));
        emit.accept(new OpcodeOp("OP_ADD"));
        emit.accept(new OpcodeOp("OP_OVER")); // F-047: keep pubkey for the digest reduction
        emit.accept(new OpcodeOp("OP_MOD"));
        emit.accept(new OpcodeOp("OP_ROT"));
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
        // F-047: reduce the digest mod pubkey, matching every off-chain verifier.
        emit.accept(new OpcodeOp("OP_ROT"));
        emit.accept(new OpcodeOp("OP_MOD"));
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
