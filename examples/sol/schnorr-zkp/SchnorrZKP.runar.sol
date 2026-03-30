pragma runar ^0.1.0;

contract SchnorrZKP is SmartContract {
    Point immutable pubKey;

    constructor(Point _pubKey) {
        pubKey = _pubKey;
    }

    function verify(Point rPoint, bigint s) public {
        require(ecOnCurve(rPoint));
        bigint e = bin2num(hash256(cat(rPoint, this.pubKey)));
        Point sG = ecMulGen(s);
        Point eP = ecMul(this.pubKey, e);
        Point rhs = ecAdd(rPoint, eP);
        require(ecPointX(sG) == ecPointX(rhs));
        require(ecPointY(sG) == ecPointY(rhs));
    }
}
