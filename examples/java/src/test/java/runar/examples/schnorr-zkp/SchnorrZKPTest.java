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

    // BUG-001 adversarial tests — see examples/ts/schnorr-zkp/SchnorrZKP.test.ts
    // for the canonical commentary; this is the .runar.java mirror.

    @Test
    void rejectsSAtN() {
        // s = secp256k1 group order is rejected (within(s, 1, n) half-open).
        BigInteger k = BigInteger.valueOf(12345);
        Point pubKey = MockCrypto.ecMulGen(k);
        Point rPoint = MockCrypto.ecMulGen(BigInteger.valueOf(67890));
        SchnorrZKP c = new SchnorrZKP(pubKey);
        ContractSimulator sim = ContractSimulator.stateless(c);
        assertThrows(
            Throwable.class,
            () -> sim.call("verify", rPoint, MockCrypto.EC_N)
        );
    }

    @Test
    void rejectsSZero() {
        // s = 0 is rejected (within(s, 1, n) requires s >= 1).
        BigInteger k = BigInteger.valueOf(12345);
        Point pubKey = MockCrypto.ecMulGen(k);
        Point rPoint = MockCrypto.ecMulGen(BigInteger.valueOf(67890));
        SchnorrZKP c = new SchnorrZKP(pubKey);
        ContractSimulator sim = ContractSimulator.stateless(c);
        assertThrows(
            Throwable.class,
            () -> sim.call("verify", rPoint, BigInteger.ZERO)
        );
    }

    @Test
    void nonceReuseRecoversKey() {
        // Reusing r across two proofs leaks k = (e1-e2)^{-1} * (s1-s2).
        BigInteger k = BigInteger.valueOf(0xC0FFEEL);
        Point pubKey = MockCrypto.ecMulGen(k);
        BigInteger r = BigInteger.valueOf(12345);
        Point rPoint = MockCrypto.ecMulGen(r);
        BigInteger e1 = deriveChallenge(rPoint, pubKey);
        BigInteger s1 = r.add(e1.multiply(k)).mod(MockCrypto.EC_N);
        BigInteger e2 = e1.add(BigInteger.ONE).mod(MockCrypto.EC_N);
        BigInteger s2 = r.add(e2.multiply(k)).mod(MockCrypto.EC_N);
        BigInteger eDiff = e1.subtract(e2).mod(MockCrypto.EC_N);
        BigInteger recovered = s1.subtract(s2)
            .multiply(eDiff.modInverse(MockCrypto.EC_N))
            .mod(MockCrypto.EC_N);
        org.junit.jupiter.api.Assertions.assertEquals(k, recovered);
        // Each proof verifies individually — on-chain gate cannot detect r reuse.
        SchnorrZKP c = new SchnorrZKP(pubKey);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("verify", rPoint, s1);
    }
}
