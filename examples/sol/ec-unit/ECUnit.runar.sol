pragma runar ^0.1.0;

/// @title ECUnit
/// @notice Unit-style exercises for the secp256k1 EC built-ins.
contract ECUnit is SmartContract {
    ByteString immutable pubKey;

    constructor(ByteString _pubKey) {
        pubKey = _pubKey;
    }

    /// @notice Exercise ecMulGen, ecOnCurve, ecNegate, ecMul, ecAdd,
    /// ecPointX, ecPointY, ecMakePoint, and ecEncodeCompressed.
    function testOps() public {
        Point g = ecMulGen(1);
        require(ecOnCurve(g));
        Point neg = ecNegate(g);
        require(ecOnCurve(neg));
        Point doubled = ecMul(g, 2);
        require(ecOnCurve(doubled));
        Point sum = ecAdd(g, g);
        require(ecOnCurve(sum));
        bigint x = ecPointX(g);
        bigint y = ecPointY(g);
        Point rebuilt = ecMakePoint(x, y);
        require(ecOnCurve(rebuilt));
        ByteString compressed = ecEncodeCompressed(g);
        require(len(compressed) == 33);
        require(true);
    }
}
