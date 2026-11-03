use runar::prelude::*;

/// EcChainedRewrite -- two EC optimizer rules firing on one binding (F-115):
/// ecAdd(ecMulGen(n - 7), ecMulGen(7)) -> ecMulGen(0) -> the point at infinity.
#[runar::contract]
pub struct EcChainedRewrite {}

impl EcChainedRewrite {
    pub fn unlock(&self, p: Point) {
        let r = ec_add(&ec_mul_gen(115792089237316195423570985008687907852837564279074904382605163141518161494330), &ec_mul_gen(7));
        assert!(r == p);
    }
}
