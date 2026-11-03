package runar.conformance.bn254pairing;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.runtime.MockCrypto.Point;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.bn254MultiPairing4;

/**
 * Bn254Pairing -- N-314: four-pair BN254 pairing-product check (Go-only codegen).
 */
class Bn254Pairing extends SmartContract {

    Bn254Pairing() {
        super();
    }

    @Public
    void verify(
        Point p1, Bigint q1x0, Bigint q1x1, Bigint q1y0, Bigint q1y1,
        Point p2, Bigint q2x0, Bigint q2x1, Bigint q2y0, Bigint q2y1,
        Point p3, Bigint q3x0, Bigint q3x1, Bigint q3y0, Bigint q3y1,
        Point p4, Bigint q4x0, Bigint q4x1, Bigint q4y0, Bigint q4y1
    ) {
        assertThat(bn254MultiPairing4(
            p1, q1x0, q1x1, q1y0, q1y1,
            p2, q2x0, q2x1, q2y0, q2y1,
            p3, q3x0, q3x1, q3y0, q3y1,
            p4, q4x0, q4x1, q4y0, q4y1
        ));
    }
}
