pragma runar ^0.1.0;

contract P256Primitives is SmartContract {
    P256Point immutable expectedPoint;

    constructor(P256Point _expectedPoint) {
        expectedPoint = _expectedPoint;
    }

    function verify(bigint k, P256Point basePoint) public {
        P256Point result = p256Mul(basePoint, k);
        require(p256OnCurve(result));
        require(result == this.expectedPoint);
    }

    function verifyAdd(P256Point a, P256Point b) public {
        P256Point result = p256Add(a, b);
        require(p256OnCurve(result));
        require(result == this.expectedPoint);
    }

    function verifyMulGen(bigint k) public {
        P256Point result = p256MulGen(k);
        require(p256OnCurve(result));
        require(result == this.expectedPoint);
    }
}
