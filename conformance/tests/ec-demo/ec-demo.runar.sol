pragma runar ^0.1.0;

contract ECDemo is SmartContract {
    Point immutable pt;

    constructor(Point _pt) {
        pt = _pt;
    }

    function checkX(bigint expectedX) public {
        require(ecPointX(this.pt) == expectedX);
    }

    function checkY(bigint expectedY) public {
        require(ecPointY(this.pt) == expectedY);
    }

    function checkMakePoint(bigint x, bigint y, bigint expectedX, bigint expectedY) public {
        Point p = ecMakePoint(x, y);
        require(ecPointX(p) == expectedX);
        require(ecPointY(p) == expectedY);
    }

    function checkOnCurve() public {
        require(ecOnCurve(this.pt));
    }

    function checkAdd(Point other, bigint expectedX, bigint expectedY) public {
        Point result = ecAdd(this.pt, other);
        require(ecPointX(result) == expectedX);
        require(ecPointY(result) == expectedY);
    }

    function checkMul(bigint scalar, bigint expectedX, bigint expectedY) public {
        Point result = ecMul(this.pt, scalar);
        require(ecPointX(result) == expectedX);
        require(ecPointY(result) == expectedY);
    }

    function checkMulGen(bigint scalar, bigint expectedX, bigint expectedY) public {
        Point result = ecMulGen(scalar);
        require(ecPointX(result) == expectedX);
        require(ecPointY(result) == expectedY);
    }

    function checkNegate(bigint expectedNegY) public {
        Point neg = ecNegate(this.pt);
        require(ecPointY(neg) == expectedNegY);
    }

    function checkNegateRoundtrip() public {
        Point neg1 = ecNegate(this.pt);
        Point neg2 = ecNegate(neg1);
        require(ecPointX(neg2) == ecPointX(this.pt));
        require(ecPointY(neg2) == ecPointY(this.pt));
    }

    function checkModReduce(bigint value, bigint modulus, bigint expected) public {
        require(ecModReduce(value, modulus) == expected);
    }

    function checkEncodeCompressed(ByteString expected) public {
        ByteString compressed = ecEncodeCompressed(this.pt);
        require(compressed == expected);
    }

    function checkMulIdentity() public {
        Point result = ecMul(this.pt, 1);
        require(ecPointX(result) == ecPointX(this.pt));
        require(ecPointY(result) == ecPointY(this.pt));
    }

    function checkAddOnCurve(Point other) public {
        Point result = ecAdd(this.pt, other);
        require(ecOnCurve(result));
    }

    function checkMulGenOnCurve(bigint scalar) public {
        Point result = ecMulGen(scalar);
        require(ecOnCurve(result));
    }
}
