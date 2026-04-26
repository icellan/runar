package runar.examples.ecunit;

import java.math.BigInteger;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.runtime.MockCrypto.Point;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.ecAdd;
import static runar.lang.Builtins.ecEncodeCompressed;
import static runar.lang.Builtins.ecMakePoint;
import static runar.lang.Builtins.ecMul;
import static runar.lang.Builtins.ecMulGen;
import static runar.lang.Builtins.ecNegate;
import static runar.lang.Builtins.ecOnCurve;
import static runar.lang.Builtins.ecPointX;
import static runar.lang.Builtins.ecPointY;
import static runar.lang.Builtins.len;

/**
 * ECUnit -- unit-style exercises for the secp256k1 EC built-ins.
 *
 * <p>Stores a {@code pubKey} byte string but the actual contract logic
 * builds points off the generator and checks invariants of every EC
 * primitive in a single method. Useful as a smoke test for Bitcoin
 * Script EC opcodes.
 */
class ECUnit extends SmartContract {

    @Readonly ByteString pubKey;

    ECUnit(ByteString pubKey) {
        super(pubKey);
        this.pubKey = pubKey;
    }

    /**
     * Exercise {@code ecMulGen}, {@code ecOnCurve}, {@code ecNegate},
     * {@code ecMul}, {@code ecAdd}, {@code ecPointX}, {@code ecPointY},
     * {@code ecMakePoint}, and {@code ecEncodeCompressed}.
     */
    @Public
    void testOps() {
        Point g = ecMulGen(BigInteger.ONE);
        assertThat(ecOnCurve(g));
        Point neg = ecNegate(g);
        assertThat(ecOnCurve(neg));
        Point doubled = ecMul(g, BigInteger.TWO);
        assertThat(ecOnCurve(doubled));
        Point sum = ecAdd(g, g);
        assertThat(ecOnCurve(sum));
        BigInteger x = ecPointX(g);
        BigInteger y = ecPointY(g);
        Point rebuilt = ecMakePoint(x, y);
        assertThat(ecOnCurve(rebuilt));
        ByteString compressed = ecEncodeCompressed(g);
        assertThat(len(compressed).equals(BigInteger.valueOf(33)));
        assertThat(true);
    }
}
