module SchnorrZKP {
    use runar::types::{Point};
    use runar::crypto::{ecOnCurve, ecMulGen, ecMul, ecAdd, ecPointX, ecPointY, hash256, cat, bin2num, within};

    struct SchnorrZKP {
        pub_key: Point,
    }

    public fun verify(contract: &SchnorrZKP, r_point: Point, s: bigint) {
        // Bound s to the canonical range [1, n) where n is the secp256k1
        // group order (malleability gate). Inlined as a decimal literal so
        // every frontend lowers it to the same bigint_literal ANF node
        // (sol/move/go/rust/zig all lex 0x... as a ByteString literal).
        // Value: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        assert!(within(s, 1, 115792089237316195423570985008687907852837564279074904382605163141518161494337), 0);
        assert!(ecOnCurve(r_point), 0);
        let e: bigint = bin2num(hash256(cat(r_point, contract.pub_key)));
        let s_g: Point = ecMulGen(s);
        let e_p: Point = ecMul(contract.pub_key, e);
        let rhs: Point = ecAdd(r_point, e_p);
        assert!(ecPointX(s_g) == ecPointX(rhs), 0);
        assert!(ecPointY(s_g) == ecPointY(rhs), 0);
    }
}
