package runar.examples.schnorrzkp;

import java.math.BigInteger;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.runtime.MockCrypto.Point;
import runar.lang.types.ByteString;

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

    Point pubKey;

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

        // The Rúnar parser sees a Point passed where a ByteString is
        // expected and treats the receiver as the underlying 64-byte
        // encoding. Off-chain we hand the point's raw 64-byte form to
        // cat(...) so the simulator's hash256 sees the same input.
        ByteString rBytes = rPoint.toByteString();
        ByteString pBytes = this.pubKey.toByteString();

        // Derive challenge via Fiat-Shamir: e = bin2num(hash256(R || P))
        BigInteger e = bin2num(hash256(cat(rBytes, pBytes)));

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
