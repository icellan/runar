use runar::prelude::*;

/// ECUnit -- Unit-style exercises for the secp256k1 EC built-ins.
#[runar::contract]
pub struct ECUnit {
    #[readonly]
    pub pub_key: ByteString,
}

#[runar::methods(ECUnit)]
impl ECUnit {
    /// Exercise ecMulGen, ecOnCurve, ecNegate, ecMul, ecAdd, ecPointX,
    /// ecPointY, ecMakePoint, and ecEncodeCompressed.
    #[public]
    pub fn test_ops(&self) {
        let g = ec_mul_gen(1);
        assert!(ec_on_curve(g));
        let neg = ec_negate(g);
        assert!(ec_on_curve(neg));
        let doubled = ec_mul(g, 2);
        assert!(ec_on_curve(doubled));
        let sum = ec_add(g, g);
        assert!(ec_on_curve(sum));
        let x = ec_point_x(g);
        let y = ec_point_y(g);
        let rebuilt = ec_make_point(x, y);
        assert!(ec_on_curve(rebuilt));
        let compressed = ec_encode_compressed(g);
        assert!(len(compressed) == 33);
        assert!(true);
    }
}
