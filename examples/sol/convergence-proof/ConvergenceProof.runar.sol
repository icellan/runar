pragma runar ^0.1.0;

contract ConvergenceProof is SmartContract {
    Point immutable rA;
    Point immutable rB;

    constructor(Point _rA, Point _rB) {
        rA = _rA;
        rB = _rB;
    }

    function proveConvergence(bigint deltaO) public {
        // Verify both committed points are on the curve
        require(ecOnCurve(this.rA));
        require(ecOnCurve(this.rB));

        // R_A - R_B (point subtraction = addition with negated second operand)
        Point diff = ecAdd(this.rA, ecNegate(this.rB));

        // delta_o * G (scalar multiplication of generator)
        Point expected = ecMulGen(deltaO);

        // Assert point equality via coordinate comparison
        require(ecPointX(diff) == ecPointX(expected));
        require(ecPointY(diff) == ecPointY(expected));
    }
}
