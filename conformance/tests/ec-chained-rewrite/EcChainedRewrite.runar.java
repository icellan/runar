package runar.conformance.ecchainedrewrite;

import java.math.BigInteger;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.runtime.MockCrypto.Point;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.ecAdd;
import static runar.lang.Builtins.ecMulGen;

/**
 * EcChainedRewrite -- two EC optimizer rules firing on one binding (F-115):
 * {@code ecAdd(ecMulGen(n - 7), ecMulGen(7)) -> ecMulGen(0)} -> the point at
 * infinity. n - 7 is 256 bits, so it is spelled {@code new BigInteger("...")},
 * which the Rúnar Java parser folds to a bigint literal.
 */
class EcChainedRewrite extends SmartContract {

    EcChainedRewrite() {
        super();
    }

    @Public
    void unlock(Point p) {
        Point r = ecAdd(
            ecMulGen(new BigInteger("115792089237316195423570985008687907852837564279074904382605163141518161494330")),
            ecMulGen(BigInteger.valueOf(7)));
        assertThat(r.equals(p));
    }
}
