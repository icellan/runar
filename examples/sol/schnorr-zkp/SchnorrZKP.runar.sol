pragma runar ^0.1.0;

contract SchnorrZKP is SmartContract {
    Point immutable pubKey;

    constructor(Point _pubKey) {
        pubKey = _pubKey;
    }

    function verify(Point rPoint, bigint s) public {
        // Bound s to the canonical range [1, n) where n is the secp256k1
        // group order (malleability gate). Inlined as a decimal literal so
        // every frontend lowers it to the same bigint_literal ANF node
        // (sol/move/go/rust/zig all lex 0x... as a ByteString literal).
        // Value: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        require(within(s, 1, 115792089237316195423570985008687907852837564279074904382605163141518161494337));
        require(ecOnCurve(rPoint));
        bigint e = bin2num(hash256(cat(rPoint, this.pubKey)));
        Point sG = ecMulGen(s);
        Point eP = ecMul(this.pubKey, e);
        Point rhs = ecAdd(rPoint, eP);
        require(ecPointX(sG) == ecPointX(rhs));
        require(ecPointY(sG) == ecPointY(rhs));
    }
}
