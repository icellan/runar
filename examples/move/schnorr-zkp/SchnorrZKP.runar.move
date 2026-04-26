module SchnorrZKP {
    use runar::types::{Point};
    use runar::crypto::{ecOnCurve, ecMulGen, ecMul, ecAdd, ecPointX, ecPointY, hash256, cat, bin2num};

    struct SchnorrZKP {
        pub_key: Point,
    }

    public fun verify(contract: &SchnorrZKP, r_point: Point, s: bigint) {
        assert!(ecOnCurve(r_point), 0);
        let e: bigint = bin2num(hash256(cat(r_point, contract.pub_key)));
        let s_g: Point = ecMulGen(s);
        let e_p: Point = ecMul(contract.pub_key, e);
        let rhs: Point = ecAdd(r_point, e_p);
        assert!(ecPointX(s_g) == ecPointX(rhs), 0);
        assert!(ecPointY(s_g) == ecPointY(rhs), 0);
    }
}
