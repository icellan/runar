package runar.compiler.codegen;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.stack.IfOp;
import runar.compiler.ir.stack.StackMethod;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.StackProgram;
import runar.compiler.passes.Emit;

/**
 * Byte-identical parity tests for {@link P256P384} against the Go reference
 * codegen.
 *
 * <p>Goldens (op count, hex byte length, SHA-256 of hex) were produced by
 * running {@code compilers/go/codegen/p256_p384.go}'s {@code EmitP*} entry
 * points through {@code codegen.EmitMethod} on the same commit as this port.
 * Any divergence means the Java emitter has drifted from the reference and
 * will produce non-conforming Bitcoin Script.
 */
class P256P384Test {

    // --------------------------------------------------------------
    // P-256
    // --------------------------------------------------------------

    /**
     * +21 ops / +21 bytes over the pre-P==-Q-fix shape — the same delta
     * {@code ecAdd} and {@code p384Add} take, since all three share the affine-add
     * structure: a second OP_NUMEQUAL on y, the OP_BOOLAND folding it into
     * {@code cond}, OP_SUB/OP_NOT for {@code notinf}, two OP_MULs masking rx/ry,
     * plus the picks/rolls feeding them. Every one of those is a 1-byte op, so the
     * op count and the byte count move by the same amount.
     *
     * <p>CL-BUG-096 adds a further +50 / +50 on top, shared by all three curves:
     * {@link Ec#emitAffineInfinitySelect} replaces the four toTop/drop cleanups
     * and the two {@code notinf} OP_MULs with the pinf/qinf/usep/useq/user
     * select. All 1-byte ops again.
     */
    @Test
    void p256AddParity() {
        assertParity("p256Add",
            P256P384::emitP256Add,
            6737, 20114,
            "3c210d17ca365ce2b1b504f2210a8cc2452bf0513d1cb1620923539ea0a8b0bf");
    }

    @Test
    void p256MulParity() {
        assertParity("p256Mul",
            P256P384::emitP256Mul,
            140047, 459824,
            "7cdb7e5512d7f60a0ab9e77284b42a2a4fb580116e557883978d77d5feef875d");
    }

    @Test
    void p256MulGenParity() {
        assertParity("p256MulGen",
            P256P384::emitP256MulGen,
            140049, 459890,
            "5165984eee9eb6ec51e1e75d54aed2c2a1c5db6cd9a348e574ab6239012f317f");
    }

    @Test
    void p256NegateParity() {
        assertParity("p256Negate",
            P256P384::emitP256Negate,
            956, 1096,
            "835560d4837be0c382d789e70fc289dbc432c55d40224d2da5d6083d382744cd");
    }

    @Test
    void p256OnCurveParity() {
        assertParity("p256OnCurve",
            P256P384::emitP256OnCurve,
            574, 940,
            "218e2c15582b847eb8479d7d5c9787a60b9fa97f6ab50bdc277be6201a50e8e8");
    }

    @Test
    void p256EncodeCompressedParity() {
        assertParity("p256EncodeCompressed",
            P256P384::emitP256EncodeCompressed,
            16, 21,
            "6fabc7557f72bcbe35f7fa63715afa3d5f30d54924e8ef48ef879caa1c011ab0");
    }

    /**
     * +85 ops / +151 bytes for the {@code _dk_valid} pubkey-validity gate, which
     * decomposes exactly:
     *
     * <ul>
     *   <li><b>52 curve-independent ops</b> (1 byte each) — 21 for the affine-add
     *       P == -Q mask (see {@link #p256AddParity()}), the rest for the residue +
     *       canonicity check in {@code cDecompressPubKey}, its altstack stash, and
     *       the closing OP_BOOLAND in {@code cEmitVerifyECDSA}. P-384 pays the same
     *       52, which is what makes it curve-independent.</li>
     *   <li><b>+1 op / +1 byte per set bit of the sqrt exponent</b> — 33 here, 287 on
     *       P-384. {@code _dk_y2_keep} now sits under {@code _dk_y2} for the whole of
     *       {@code cFieldPow}, so the loop's {@code copyToTop(base)} moves from depth
     *       1 (OP_OVER) to depth 2 (OP_2 + OP_PICK). {@code (p+1)/4} has 34 set bits
     *       on P-256 and 288 on P-384; the MSB is the loop's seed, not a step.</li>
     *   <li><b>+66 bytes</b> beyond the op count — the two full-width pushes of p the
     *       check adds (one inside {@code cFieldSqr}'s reduce, one for the
     *       OP_LESSTHAN). p is 32 bytes, so each push is 34 bytes on the wire against
     *       the 1 byte the op count sees: 33 extra x2. On P-384 p is 48 bytes, so it
     *       is 49 extra x2 = 98.</li>
     * </ul>
     *
     * 52 + 33 = 85 ops, 85 + 66 = 151 bytes. Both match the TypeScript reference.
     *
     * <p>A further <b>+58 ops / +225 bytes</b> for the argument-validation gates —
     * the two length clamps on {@code _sig} / {@code _pk}, the
     * {@code 1 <= r, s <= n-1} range gate, the SEC1 prefix check inside
     * {@code cDecompressPubKey}, and the OP_BOOLANDs folding all of them into
     * {@code _input_ok}. Unlike the {@code _dk_valid} delta above, the OP count is
     * curve-INDEPENDENT (P-384 pays the same 58) because nothing here loops over the
     * exponent; only the widths of the pushed constants differ. The 58 breaks down as
     * 18 for the two length-gate blocks + 1 roll to reach {@code _sig}, 15 for the
     * range gate, 8 for the prefix check, and 16 for the folds, rolls and picks that
     * wire them together (7 of the 58 are OP_BOOLAND).
     *
     * <p>The +167 bytes beyond the op count are entirely wide pushes:
     * <ul>
     *   <li><b>3 x 34</b> — the 33-byte zero pad the {@code _pk} clamp concatenates,
     *       and the two pushes of n the range gate compares against (n needs a
     *       leading sign byte, so it is a 33-byte script number too). 102 bytes
     *       against 3 the op count sees: +99.</li>
     *   <li><b>1 x 65</b> — the 64-byte zero pad for the {@code _sig} clamp; 64 &lt;=
     *       75, so it is a direct push, 1 length byte + 64: +64.</li>
     *   <li><b>4 x 2</b> — the four small pushes of the target width (33, 33, 64, 64),
     *       all above OP_16 so none collapses to an OP_N: +4.</li>
     * </ul>
     *
     * 99 + 64 + 4 = 167, and 58 + 167 = 225.
     */
    @Test
    void verifyEcdsaP256Parity() {
        assertParity("verifyECDSA_P256",
            P256P384::emitVerifyECDSA_P256,
            297393, 974090,
            "c94bb4a39d339b75b7cfd5403d443c0f2154b380a49a1c3c33b47fefab06b1e9");
    }

    // --------------------------------------------------------------
    // P-384
    // --------------------------------------------------------------

    /** Same +21 op / +21 byte affine-add delta as {@code p256Add} — see there. */
    @Test
    void p384AddParity() {
        assertParity("p384Add",
            P256P384::emitP384Add,
            11543, 46982,
            "477c845892660ecd52d7892894130db422f6a1eae60c37c298cbfa2c65cee443");
    }

    @Test
    void p384MulParity() {
        assertParity("p384Mul",
            P256P384::emitP384Mul,
            211189, 927460,
            "82c1e9e057d192d672ca3b2e8ca5f9e01fe65e267cc18975b93a0136443d2c75");
    }

    @Test
    void p384MulGenParity() {
        assertParity("p384MulGen",
            P256P384::emitP384MulGen,
            211191, 927559,
            "7834b69797d1bef722f6711ee4ddfdd42a8d80a2ae74350eb58bedabf1249211");
    }

    @Test
    void p384NegateParity() {
        assertParity("p384Negate",
            P256P384::emitP384Negate,
            1404, 1608,
            "cae64040e199c863851f06675c2e1b1f04fe2da0a6b6daf60a52e82f1101bbb8");
    }

    @Test
    void p384OnCurveParity() {
        assertParity("p384OnCurve",
            P256P384::emitP384OnCurve,
            798, 1342,
            "94a8fdd5522fc28ec1e497bc94cb734d98bf778cd82d362a5977aebf28708a07");
    }

    @Test
    void p384EncodeCompressedParity() {
        assertParity("p384EncodeCompressed",
            P256P384::emitP384EncodeCompressed,
            16, 21,
            "0445ab05c849a3528caa951da2d8202ebba4c29a11237b8695b73773cb01c508");
    }

    /**
     * +339 ops / +437 bytes for the same {@code _dk_valid} gate as
     * {@link #verifyEcdsaP256Parity()}: 52 + 287 = 339 ops, 339 + 2*49 = 437 bytes.
     * The 254-op gap to P-256 is exactly the gap in set-bit counts of {@code (p+1)/4}
     * (287 vs 33) — see there for the full decomposition.
     *
     * <p>Plus the same argument-validation gates as
     * {@link #verifyEcdsaP256Parity()}: <b>+58 ops</b> — identical, the gates do not
     * loop — and <b>+306 bytes</b>, the extra 81 over P-256 being nothing but wider
     * constants: 3 x 50 for the 49-byte {@code _pk} pad and the two 49-byte pushes of
     * n (+147), 1 x 98 for the 96-byte {@code _sig} pad (+97 — 96 &gt; 75, so this one
     * needs an OP_PUSHDATA1 length prefix where P-256's 64-byte pad did not, which is
     * the odd byte in 306 - 225 = 81), and 4 x 2 for the width pushes (+4).
     * 147 + 97 + 4 = 248, and 58 + 248 = 306.
     */
    @Test
    void verifyEcdsaP384Parity() {
        assertParity("verifyECDSA_P384",
            P256P384::emitVerifyECDSA_P384,
            453369, 1987460,
            "08dfb06168c1ed75f18e4943a6151d5d65bac852c4ec42d631738fe7a27c5a20");
    }

    // --------------------------------------------------------------
    // Curve constants sanity
    // --------------------------------------------------------------

    @Test
    void p256ConstantsAreCorrect() {
        // p (NIST P-256) = 2^256 - 2^224 + 2^192 + 2^96 - 1
        BigInteger expectedP = BigInteger.TWO.pow(256)
            .subtract(BigInteger.TWO.pow(224))
            .add(BigInteger.TWO.pow(192))
            .add(BigInteger.TWO.pow(96))
            .subtract(BigInteger.ONE);
        assertEquals(expectedP, P256P384.P256_P);
        assertEquals(P256P384.P256_P.subtract(BigInteger.TWO), P256P384.P256_P_MINUS_2);
        assertEquals(P256P384.P256_N.subtract(BigInteger.TWO), P256P384.P256_N_MINUS_2);
    }

    @Test
    void p384ConstantsAreCorrect() {
        // p (NIST P-384) = 2^384 - 2^128 - 2^96 + 2^32 - 1
        BigInteger expectedP = BigInteger.TWO.pow(384)
            .subtract(BigInteger.TWO.pow(128))
            .subtract(BigInteger.TWO.pow(96))
            .add(BigInteger.TWO.pow(32))
            .subtract(BigInteger.ONE);
        assertEquals(expectedP, P256P384.P384_P);
        assertEquals(P256P384.P384_P.subtract(BigInteger.TWO), P256P384.P384_P_MINUS_2);
        assertEquals(P256P384.P384_N.subtract(BigInteger.TWO), P256P384.P384_N_MINUS_2);
    }

    // --------------------------------------------------------------
    // Dispatch
    // --------------------------------------------------------------

    @Test
    void dispatchRecognisesAllNistBuiltins() {
        String[] names = {
            "p256Add", "p256Mul", "p256MulGen", "p256Negate", "p256OnCurve",
            "p256EncodeCompressed",
            "p384Add", "p384Mul", "p384MulGen", "p384Negate", "p384OnCurve",
            "p384EncodeCompressed"
        };
        for (String n : names) {
            assertTrue(P256P384.isNistEcBuiltin(n), n + " should be a NIST EC builtin");
        }
        assertFalse(P256P384.isNistEcBuiltin("ecAdd"));
        assertFalse(P256P384.isNistEcBuiltin("p999Add"));
    }

    @Test
    void verifyDispatchRecognisesEcdsa() {
        assertTrue(P256P384.isVerifyEcdsaBuiltin("verifyECDSA_P256"));
        assertTrue(P256P384.isVerifyEcdsaBuiltin("verifyECDSA_P384"));
        assertFalse(P256P384.isVerifyEcdsaBuiltin("verifyECDSA"));
        assertFalse(P256P384.isVerifyEcdsaBuiltin("checkSig"));
    }

    @Test
    void dispatchThrowsOnUnknown() {
        assertThrows(RuntimeException.class,
            () -> P256P384.dispatch("p256Banana", op -> {}));
    }

    // --------------------------------------------------------------
    // Helpers
    // --------------------------------------------------------------

    /**
     * Total number of {@link StackOp}s in {@code ops}, INCLUDING the bodies of
     * {@code if} ops.
     *
     * <p>A flat {@code ops.size()} cannot see inside a branch, so any emitter
     * whose work sits in an {@code if} body — the scalar ladders emit 257 / 385
     * conditional additions, WOTS+ and SLH-DSA are almost entirely conditional —
     * reports a count that barely moves no matter what the branch contains.
     * Adding +1.3 KB of script inside the ladder's last step left the
     * {@code p256Mul} / {@code p384Mul} goldens byte-identical. Recursing is what
     * makes the golden a gate.
     */
    private static int countOpTree(List<StackOp> ops) {
        int total = 0;
        for (StackOp op : ops) {
            total++;
            if (op instanceof IfOp ifOp) {
                if (ifOp.thenBranch() != null) total += countOpTree(ifOp.thenBranch());
                if (ifOp.elseBranch() != null) total += countOpTree(ifOp.elseBranch());
            }
        }
        return total;
    }

    private static void assertParity(String label, Consumer<Consumer<StackOp>> emitter,
                                     int expectedOpCount, int expectedHexBytes,
                                     String expectedHexSha256) {
        List<StackOp> ops = new ArrayList<>();
        emitter.accept(ops::add);
        assertEquals(expectedOpCount, countOpTree(ops), label + " op count drift");

        String hex = emitHex(ops);
        assertEquals(expectedHexBytes, hex.length() / 2, label + " hex byte count drift");
        assertEquals(expectedHexSha256, sha256Hex(hex), label + " hex bytes drift");
    }

    private static String emitHex(List<StackOp> ops) {
        StackProgram prog = new StackProgram("Test",
            List.of(new StackMethod("run", ops, 0L)));
        return Emit.run(prog);
    }

    private static String sha256Hex(String hex) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(hex.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
