// EVM-guest fixture generator (Phase 2 / production-scale).
//
// Same Plonky3 KoalaBear FibAir setup as the minimal-guest fixture
// (`tests/vectors/sp1/fri/minimal-guest/regen/src/main.rs`), tuned for the
// production parameter tuple from `docs/sp1-fri-verifier.md` Section 4 and
// the BSVM handoff Section 2.1:
//
//   log_blowup            = 1   (PoC: 2)   - tighter blowup, more queries needed
//   num_queries           = 100 (PoC: 2)   - ~100-bit FRI security
//   commit_pow_bits       = 16  (PoC: 1)   - proof-of-work grinding
//   query_pow_bits        = 16  (PoC: 1)   - proof-of-work grinding
//   max_log_arity         = 1   (unchanged) - binary folding
//   trace_height (degreeBits) = 10 (PoC: 3) - 1024-row Fibonacci trace
//   log_final_poly_len    = 0   (PoC: 2)   - natural production tuple from
//                                            the BSVM handoff §2.1. Now
//                                            tractable on-chain because the
//                                            codegen helper derives numRounds
//                                            from `degreeBits -
//                                            log_final_poly_len` per Plonky3
//                                            fri/src/prover.rs:75 (the previous
//                                            B1 hardcode `numRounds = 1` is
//                                            fixed in
//                                            compilers/go/codegen/sp1_fri.go).
//                                            With (degree_bits=10,
//                                            log_blowup=1, log_final_poly_len=0,
//                                            max_log_arity=1) this gives
//                                            numRounds = 10 commit-phase
//                                            rounds (1 final-poly Ext4
//                                            coefficient instead of 512).
//
// AIR is unchanged: 2-column Fibonacci with public inputs `[a, b, fib(n-1)]`.
// PIs for this fixture are `[0, 1, fib(1023) mod p]`.

use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove, verify};

const NUM_FIBONACCI_COLS: usize = 2;
const LOG_TRACE_HEIGHT: usize = 10;
// LOG_FINAL_POLY_LEN = 0: natural production tuple. Now valid because
// `EmitFullSP1FriVerifierBody` derives numRounds = degreeBits -
// log_final_poly_len from params (B1 fixed). For (degree_bits=10,
// log_blowup=1, log_final_poly_len=0) the on-chain script unrolls
// numRounds = 10 commit-phase rounds at arity 2.
const LOG_FINAL_POLY_LEN: usize = 0;

#[derive(Default)]
pub struct FibonacciAir {}

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize { NUM_FIBONACCI_COLS }
    fn num_public_values(&self) -> usize { 3 }
    fn max_constraint_degree(&self) -> Option<usize> { Some(2) }
}

impl<AB: AirBuilder> Air<AB> for FibonacciAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let pis = builder.public_values();
        let a = pis[0]; let b = pis[1]; let x = pis[2];
        let local: &FibonacciRow<AB::Var> = main.current_slice().borrow();
        let next: &FibonacciRow<AB::Var> = main.next_slice().borrow();
        let mut wf = builder.when_first_row();
        wf.assert_eq(local.left, a);
        wf.assert_eq(local.right, b);
        let mut wt = builder.when_transition();
        wt.assert_eq(local.right, next.left);
        wt.assert_eq(local.left + local.right, next.right);
        builder.when_last_row().assert_eq(local.right, x);
    }
}

pub struct FibonacciRow<F> { pub left: F, pub right: F }
impl<F> FibonacciRow<F> { const fn new(left: F, right: F) -> Self { Self { left, right } } }
impl<F> Borrow<FibonacciRow<F>> for [F] {
    fn borrow(&self) -> &FibonacciRow<F> {
        let (p, s, sf) = unsafe { self.align_to::<FibonacciRow<F>>() };
        debug_assert!(p.is_empty()); debug_assert!(sf.is_empty()); debug_assert_eq!(s.len(), 1);
        &s[0]
    }
}

pub fn generate_trace_rows<F: PrimeField64>(a: u64, b: u64, n: usize) -> RowMajorMatrix<F> {
    assert!(n.is_power_of_two());
    let mut t = RowMajorMatrix::new(F::zero_vec(n * NUM_FIBONACCI_COLS), NUM_FIBONACCI_COLS);
    let (p, rows, sf) = unsafe { t.values.align_to_mut::<FibonacciRow<F>>() };
    assert!(p.is_empty()); assert!(sf.is_empty()); assert_eq!(rows.len(), n);
    rows[0] = FibonacciRow::new(F::from_u64(a), F::from_u64(b));
    for i in 1..n { rows[i].left = rows[i - 1].right; rows[i].right = rows[i - 1].left + rows[i - 1].right; }
    t
}

type Val = KoalaBear;
type Perm = Poseidon2KoalaBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs = MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;
type Challenge = BinomialExtensionField<Val, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

fn make_two_adic_config(log_final_poly_len: usize) -> MyConfig {
    let perm = default_koalabear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters {
        log_blowup: 1,
        log_final_poly_len,
        max_log_arity: 1,
        num_queries: 100,
        commit_proof_of_work_bits: 16,
        query_proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    MyConfig::new(pcs, challenger)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: runar-evm-guest-fixture-gen <output-path>");
        std::process::exit(1);
    }
    let out_path = &args[1];

    let n = 1usize << LOG_TRACE_HEIGHT;
    let trace = generate_trace_rows::<Val>(0, 1, n);

    // Compute fib(n-1) mod p ahead of time so we can supply matching public
    // input `x`.
    let mut a: u64 = 0;
    let mut b: u64 = 1;
    let p: u64 = Val::ORDER_U64;
    for _ in 1..n {
        let next = (a + b) % p;
        a = b;
        b = next;
    }
    let x_pub = b;

    let config = make_two_adic_config(LOG_FINAL_POLY_LEN);
    let pis = vec![Val::ZERO, Val::ONE, Val::from_u64(x_pub)];
    let proof = prove(&config, &FibonacciAir::default(), trace, &pis);
    verify(&config, &FibonacciAir::default(), &proof, &pis).expect("self-verify");
    let bytes = postcard::to_allocvec(&proof)?;
    if let Some(p) = std::path::Path::new(out_path).parent() { std::fs::create_dir_all(p)?; }
    std::fs::write(out_path, &bytes)?;
    println!(
        "path: {} size: {} bytes  (degree_bits={}, log_final_poly_len={}, num_queries=100, log_blowup=1, pow_bits=16, x_pub={})",
        out_path, bytes.len(), LOG_TRACE_HEIGHT, LOG_FINAL_POLY_LEN, x_pub
    );
    Ok(())
}
