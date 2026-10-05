// EcChainedRewrite -- two EC optimizer rules firing on one binding (F-115):
// ecAdd(ecMulGen(n - 7), ecMulGen(7)) -> ecMulGen(0) -> the point at infinity.
module EcChainedRewrite {
    use runar::types::{Point};
    use runar::crypto::{ecAdd, ecMulGen};

    struct EcChainedRewrite {
    }

    public fun unlock(contract: &EcChainedRewrite, p: Point) {
        let r: Point = ecAdd(ecMulGen(115792089237316195423570985008687907852837564279074904382605163141518161494330), ecMulGen(7));
        assert!(r == p, 0);
    }
}
