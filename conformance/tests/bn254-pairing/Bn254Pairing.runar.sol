pragma runar ^0.1.0;

/// @title Bn254Pairing
/// @notice N-314: four-pair BN254 pairing-product check (Go-only codegen).
contract Bn254Pairing is SmartContract {
    constructor() {
    }

    function verify(
        Point p1, bigint q1x0, bigint q1x1, bigint q1y0, bigint q1y1,
        Point p2, bigint q2x0, bigint q2x1, bigint q2y0, bigint q2y1,
        Point p3, bigint q3x0, bigint q3x1, bigint q3y0, bigint q3y1,
        Point p4, bigint q4x0, bigint q4x1, bigint q4y0, bigint q4y1
    ) public {
        require(bn254MultiPairing4(
            p1, q1x0, q1x1, q1y0, q1y1,
            p2, q2x0, q2x1, q2y0, q2y1,
            p3, q3x0, q3x1, q3y0, q3y1,
            p4, q4x0, q4x1, q4y0, q4y1
        ));
    }
}
