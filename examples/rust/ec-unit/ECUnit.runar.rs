use runar::prelude::*;

/// ECUnit -- Unit-style exercises for the secp256k1 EC built-ins.
#[runar::contract]
pub struct ECUnit {
    #[readonly]
    pub pub_key: ByteString,
}

impl ECUnit {
    /// Exercise ecMulGen, ecOnCurve, ecNegate, ecMul, ecAdd, ecPointX,
    /// ecPointY, ecMakePoint, and ecEncodeCompressed.
    pub fn test_ops(&self) {
        let g = ec_mul_gen(1);
        assert!(ec_on_curve(&g));
        let neg = ec_negate(&g);
        assert!(ec_on_curve(&neg));
        let doubled = ec_mul(&g, 2);
        assert!(ec_on_curve(&doubled));
        let sum = ec_add(&g, &g);
        assert!(ec_on_curve(&sum));
        // P + (-P) is the point at infinity: ec_add returns the all-zero blob
        // from a SUCCESSFUL script, and ec_on_curve must reject it.
        let inf_pt = ec_add(&g, &neg);
        assert!(!ec_on_curve(&inf_pt));
        let x = ec_point_x(&g);
        let y = ec_point_y(&g);
        let rebuilt = ec_make_point(x, y);
        assert!(ec_on_curve(&rebuilt));
        let compressed = ec_encode_compressed(&g);
        assert!(len(&compressed) == 33);
        assert!(true);
    }
}
