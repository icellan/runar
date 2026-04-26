package runar.examples.schnorrzkp;

import java.math.BigInteger;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.runtime.MockCrypto.Point;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.bin2num;
import static runar.lang.Builtins.cat;
import static runar.lang.Builtins.ecAdd;
import static runar.lang.Builtins.ecMul;
import static runar.lang.Builtins.ecMulGen;
import static runar.lang.Builtins.ecOnCurve;
import static runar.lang.Builtins.ecPointX;
import static runar.lang.Builtins.ecPointY;
import static runar.lang.Builtins.hash256;

/**
 * Schnorr Zero-Knowledge Proof verifier (non-interactive, Fiat-Shamir).
 *
 * <p>Proves knowledge of a private key {@code k} such that
 * {@code P = k*G} without revealing {@code k}. Uses the Schnorr
 * identification protocol with the Fiat-Shamir heuristic to derive
 * the challenge on-chain:
 *
 * <pre>
 *   Prover:    picks random r, computes R = r*G
 *   Challenge: e = bin2num(hash256(R || P))   (derived on-chain)
 *   Prover:    sends s = r + e*k (mod n)
 *   Verifier:  checks s*G === R + e*P
 * </pre>
 *
 * <p>The challenge is derived deterministically from the commitment
 * and public key, preventing the prover from choosing a convenient
 * {@code e}.
 */
class SchnorrZKP extends SmartContract {

    @Readonly Point pubKey;

    SchnorrZKP(Point pubKey) {
        super(pubKey);
        this.pubKey = pubKey;
    }

    /**
     * Verify a Schnorr ZKP proof.
     *
     * @param rPoint the commitment R = r*G (prover's nonce point)
     * @param s the response s = r + e*k (mod n)
     */
    @Public
    void verify(Point rPoint, BigInteger s) {
        // Verify R is on the curve.
        assertThat(ecOnCurve(rPoint));

        // Derive challenge via Fiat-Shamir: e = bin2num(hash256(R || P)).
        // Rúnar Point is structurally a 64-byte ByteString (x[32] || y[32]);
        // the canonical TS source passes Points directly to cat, and the
        // Java {@link runar.lang.Builtins#cat(MockCrypto.Point,MockCrypto.Point)}
        // overload coerces them to their raw 64-byte form so the IR produced
        // by every frontend matches.
        BigInteger e = bin2num(hash256(cat(rPoint, this.pubKey)));

        // Left side: s*G
        Point sG = ecMulGen(s);

        // Right side: R + e*P
        Point eP = ecMul(this.pubKey, e);
        Point rhs = ecAdd(rPoint, eP);

        // Verify equality
        assertThat(ecPointX(sG).equals(ecPointX(rhs)));
        assertThat(ecPointY(sG).equals(ecPointY(rhs)));
    }
}
