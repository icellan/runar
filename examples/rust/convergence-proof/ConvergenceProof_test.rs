#[path = "ConvergenceProof.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;

#[test]
fn test_valid_delta() {
    let token: Bigint = 42;
    let o_a: Bigint = 100;
    let o_b: Bigint = 37;

    let r_a = ec_mul_gen(token + o_a);
    let r_b = ec_mul_gen(token + o_b);
    let delta_o = o_a - o_b;

    let c = ConvergenceProof { r_a, r_b };
    c.prove_convergence(delta_o); // should not panic
}

#[test]
#[should_panic]
fn test_wrong_delta() {
    let token: Bigint = 42;
    let o_a: Bigint = 100;
    let o_b: Bigint = 37;

    let r_a = ec_mul_gen(token + o_a);
    let r_b = ec_mul_gen(token + o_b);
    let wrong_delta = o_a - o_b + 1;

    let c = ConvergenceProof { r_a, r_b };
    c.prove_convergence(wrong_delta);
}

#[test]
#[should_panic]
fn test_different_tokens() {
    let token_a: Bigint = 42;
    let token_b: Bigint = 99;
    let o_a: Bigint = 100;
    let o_b: Bigint = 37;

    let r_a = ec_mul_gen(token_a + o_a);
    let r_b = ec_mul_gen(token_b + o_b);
    let delta_o = o_a - o_b;

    let c = ConvergenceProof { r_a, r_b };
    c.prove_convergence(delta_o);
}

#[test]
fn test_larger_scalars() {
    let token: Bigint = 1_234_567_890;
    let o_a: Bigint = 987_654_321;
    let o_b: Bigint = 111_111_111;

    let r_a = ec_mul_gen(token + o_a);
    let r_b = ec_mul_gen(token + o_b);
    let delta_o = o_a - o_b;

    let c = ConvergenceProof { r_a, r_b };
    c.prove_convergence(delta_o);
}

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("ConvergenceProof.runar.rs"),
        "ConvergenceProof.runar.rs",
    )
    .unwrap();
}
