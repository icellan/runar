package runar.examples.schnorrzkp;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.MockCrypto;
import runar.lang.runtime.MockCrypto.Point;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Surface + simulator tests for SchnorrZKP. Builds a complete
 * non-interactive Schnorr proof off-chain (using {@link MockCrypto})
 * and exercises the on-chain verifier through the simulator.
 */
class SchnorrZKPTest {

    private static BigInteger deriveChallenge(Point rPoint, Point pubKey) {
        ByteString rBytes = new ByteString(rPoint.toRaw64());
        ByteString pBytes = new ByteString(pubKey.toRaw64());
        byte[] cat = new byte[rBytes.length() + pBytes.length()];
        System.arraycopy(rBytes.toByteArray(), 0, cat, 0, rBytes.length());
        System.arraycopy(pBytes.toByteArray(), 0, cat, rBytes.length(), pBytes.length());
        byte[] h = MockCrypto.hash256(cat);
        return MockCrypto.bin2num(new ByteString(h));
    }

    @Test
    void contractInstantiates() {
        Point pub = MockCrypto.ecMulGen(BigInteger.valueOf(12345));
        SchnorrZKP c = new SchnorrZKP(pub);
        assertNotNull(c);
    }

    @Test
    void verifyValidProof() {
        BigInteger k = BigInteger.valueOf(12345);
        Point pubKey = MockCrypto.ecMulGen(k);

        // Prover picks random r, computes R = r*G.
        BigInteger r = BigInteger.valueOf(67890);
        Point rPoint = MockCrypto.ecMulGen(r);

        // Derive Fiat-Shamir challenge.
        BigInteger e = deriveChallenge(rPoint, pubKey);

        // Response s = r + e*k (mod n).
        BigInteger s = r.add(e.multiply(k)).mod(MockCrypto.EC_N);

        SchnorrZKP c = new SchnorrZKP(pubKey);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("verify", rPoint, s);
    }

    @Test
    void verifyRejectsTamperedS() {
        BigInteger k = BigInteger.valueOf(12345);
        Point pubKey = MockCrypto.ecMulGen(k);
        BigInteger r = BigInteger.valueOf(67890);
        Point rPoint = MockCrypto.ecMulGen(r);
        BigInteger e = deriveChallenge(rPoint, pubKey);
        BigInteger s = r.add(e.multiply(k)).mod(MockCrypto.EC_N);

        SchnorrZKP c = new SchnorrZKP(pubKey);
        ContractSimulator sim = ContractSimulator.stateless(c);
        // Any wrong s should make ec_mul_gen(s) != R + e*P.
        assertThrows(
            Throwable.class,
            () -> sim.call("verify", rPoint, s.add(BigInteger.ONE))
        );
    }
}
