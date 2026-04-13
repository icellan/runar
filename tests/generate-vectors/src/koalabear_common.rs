//! Shared Koala Bear field and extension field helpers for test vector generators.

pub use p3_koala_bear::KoalaBear;
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
use rand::rngs::StdRng;
use rand::Rng;

pub const P: u64 = 2130706433; // Koala Bear prime: 2^31 - 2^24 + 1

pub type EF4 = BinomialExtensionField<KoalaBear, 4>;

pub fn kb(val: u64) -> KoalaBear {
    KoalaBear::new(val as u32)
}

pub fn to_u64(f: KoalaBear) -> u64 {
    f.as_canonical_u32() as u64
}

pub fn ef4(a0: u64, a1: u64, a2: u64, a3: u64) -> EF4 {
    EF4::new([kb(a0), kb(a1), kb(a2), kb(a3)])
}

pub fn ef4_to_array(f: EF4) -> [u64; 4] {
    let coeffs = f.as_basis_coefficients_slice();
    [
        to_u64(coeffs[0]),
        to_u64(coeffs[1]),
        to_u64(coeffs[2]),
        to_u64(coeffs[3]),
    ]
}

pub fn random_ef4(rng: &mut StdRng) -> EF4 {
    ef4(
        rng.gen_range(0..P),
        rng.gen_range(0..P),
        rng.gen_range(0..P),
        rng.gen_range(0..P),
    )
}

pub fn random_nonzero_base(rng: &mut StdRng) -> KoalaBear {
    kb(rng.gen_range(1..P))
}

/// Embed a base field element into ext4: (val, 0, 0, 0)
pub fn embed_base(val: KoalaBear) -> EF4 {
    EF4::new([val, KoalaBear::ZERO, KoalaBear::ZERO, KoalaBear::ZERO])
}
