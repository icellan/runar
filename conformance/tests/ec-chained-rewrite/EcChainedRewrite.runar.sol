pragma runar ^0.1.0;

/// @title EcChainedRewrite
/// @notice Two EC optimizer rules firing on one binding (F-115):
/// ecAdd(ecMulGen(n - 7), ecMulGen(7)) -> ecMulGen(0) -> the point at infinity.
contract EcChainedRewrite is SmartContract {
    constructor() {}

    function unlock(Point p) public {
        Point r = ecAdd(ecMulGen(115792089237316195423570985008687907852837564279074904382605163141518161494330), ecMulGen(7));
        require(r == p);
    }
}
