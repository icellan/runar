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

    @Test
    void p256AddParity() {
        assertParity("p256Add",
            P256P384::emitP256Add,
            6505, 19418,
            "be53099ae1518f0b03ab41933e3dc0b2ea409183e5e42b7683c117ad47e2fb03");
    }

    @Test
    void p256MulParity() {
        assertParity("p256Mul",
            P256P384::emitP256Mul,
            73306, 458398,
            "20ada33f4f91dad21a9b167b3a3bd021564f643b24edd5c8dfcd04990b645105");
    }

    @Test
    void p256MulGenParity() {
        assertParity("p256MulGen",
            P256P384::emitP256MulGen,
            73308, 458464,
            "98029254800f28cab0a1a2cf78f9c3c4d97bd79bde5a4f731816521b1eeaa454");
    }

    @Test
    void p256NegateParity() {
        assertParity("p256Negate",
            P256P384::emitP256Negate,
            945, 1018,
            "92527f4c693de2e9ad7207842fc80cae1735abcef68bf26ce32b14a70dec6c2f");
    }

    @Test
    void p256OnCurveParity() {
        assertParity("p256OnCurve",
            P256P384::emitP256OnCurve,
            546, 779,
            "d0a7c849eaf9173a6db524645642f532583ff108c96ff0c7e6ffac026eb9c93f");
    }

    @Test
    void p256EncodeCompressedParity() {
        assertParity("p256EncodeCompressed",
            P256P384::emitP256EncodeCompressed,
            14, 19,
            "a4481881396c90da361f987c4adc581125b09103bfb6bd11f3d5acc5be1635d1");
    }

    @Test
    void verifyEcdsaP256Parity() {
        assertParity("verifyECDSA_P256",
            P256P384::emitVerifyECDSA_P256,
            163589, 970485,
            "717c96a9796da7951e0363cbb1eefa41404a0e473808a1dc067fa01eeac7c1b2");
    }

    // --------------------------------------------------------------
    // P-384
    // --------------------------------------------------------------

    @Test
    void p384AddParity() {
        assertParity("p384Add",
            P256P384::emitP384Add,
            11311, 46062,
            "780140fafac0b41f8560714b864eb444c1730e7828624afb048f325a4f2abef2");
    }

    @Test
    void p384MulParity() {
        assertParity("p384Mul",
            P256P384::emitP384Mul,
            111424, 925554,
            "190e6bb1a4573823f4903561a177ce243cd4a42e3aae4b24514935d36d340072");
    }

    @Test
    void p384MulGenParity() {
        assertParity("p384MulGen",
            P256P384::emitP384MulGen,
            111426, 925653,
            "18bdecfb8bd9d971232e4c9db815d6d3e98dce142ef845fd572ad543ac29de39");
    }

    @Test
    void p384NegateParity() {
        assertParity("p384Negate",
            P256P384::emitP384Negate,
            1393, 1498,
            "147e2c655c23973481673628c1d0151034a5945462fb26828a6c8c1748b15cdc");
    }

    @Test
    void p384OnCurveParity() {
        assertParity("p384OnCurve",
            P256P384::emitP384OnCurve,
            770, 1116,
            "7494c921c04ce9b762ab0ead9047b7d6cb6d6b8c244e1c3e242704997407e7b9");
    }

    @Test
    void p384EncodeCompressedParity() {
        assertParity("p384EncodeCompressed",
            P256P384::emitP384EncodeCompressed,
            14, 19,
            "e32d98f40a17d26f70ce433663a01e3c476073419ab6109964d00cfbb57d6eae");
    }

    @Test
    void verifyEcdsaP384Parity() {
        assertParity("verifyECDSA_P384",
            P256P384::emitVerifyECDSA_P384,
            253263, 1982432,
            "22fa3fa7e97fdcbe3e239635daae9871746bcb7ddc69534b694bf458da5e63fc");
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

    private static void assertParity(String label, Consumer<Consumer<StackOp>> emitter,
                                     int expectedOpCount, int expectedHexBytes,
                                     String expectedHexSha256) {
        List<StackOp> ops = new ArrayList<>();
        emitter.accept(ops::add);
        assertEquals(expectedOpCount, ops.size(), label + " op count drift");

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
