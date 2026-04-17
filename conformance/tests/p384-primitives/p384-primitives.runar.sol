pragma runar ^0.1.0;

contract P384Primitives is SmartContract {
    P384Point immutable expectedPoint;

    constructor(P384Point _expectedPoint) {
        expectedPoint = _expectedPoint;
    }

    function verify(bigint k, P384Point basePoint) public {
        P384Point result = p384Mul(basePoint, k);
        require(p384OnCurve(result));
        require(result == this.expectedPoint);
    }

    function verifyAdd(P384Point a, P384Point b) public {
        P384Point result = p384Add(a, b);
        require(p384OnCurve(result));
        require(result == this.expectedPoint);
    }

    function verifyMulGen(bigint k) public {
        P384Point result = p384MulGen(k);
        require(p384OnCurve(result));
        require(result == this.expectedPoint);
    }
}
