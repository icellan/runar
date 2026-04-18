// ECUnit — Unit-style exercises for the secp256k1 EC built-ins.
module ECUnit {
    use runar::types::{Point, ByteString};
    use runar::crypto::{ecAdd, ecMul, ecMulGen, ecNegate, ecOnCurve, ecEncodeCompressed, ecMakePoint, ecPointX, ecPointY};
    use runar::builtins::{len};

    struct ECUnit {
        pubKey: ByteString,
    }

    // Exercise ecMulGen, ecOnCurve, ecNegate, ecMul, ecAdd, ecPointX,
    // ecPointY, ecMakePoint, and ecEncodeCompressed.
    public fun test_ops(contract: &ECUnit) {
        let g: Point = ecMulGen(1);
        assert!(ecOnCurve(g), 0);
        let neg: Point = ecNegate(g);
        assert!(ecOnCurve(neg), 0);
        let doubled: Point = ecMul(g, 2);
        assert!(ecOnCurve(doubled), 0);
        let sum: Point = ecAdd(g, g);
        assert!(ecOnCurve(sum), 0);
        let x: bigint = ecPointX(g);
        let y: bigint = ecPointY(g);
        let rebuilt: Point = ecMakePoint(x, y);
        assert!(ecOnCurve(rebuilt), 0);
        let compressed: ByteString = ecEncodeCompressed(g);
        assert!(len(compressed) == 33, 0);
        assert!(true, 0);
    }
}
