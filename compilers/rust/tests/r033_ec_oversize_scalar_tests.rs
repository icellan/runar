//! R-033 (CL-BUG-022): the Rust EC composition rules must fire for
//! constant scalars that do not fit a JS-safe JSON number.
//!
//! `frontend/anf_lower.rs::bigint_to_json` encodes any `load_const` bigint
//! whose magnitude exceeds `Number.MAX_SAFE_INTEGER` as a JS-style decimal
//! BigInt STRING (`"115792089...n"`) rather than a JSON number — that is the
//! cross-tier wire encoding every tier shares. The EC optimizer's constness
//! helpers used to inspect only `Value::as_i64()` / `as_f64()`, both of
//! which return `None` on a `Value::String`, so every scalar-fusing rule
//! silently declined to fire on a real secp256k1-sized scalar.
//!
//! The other tiers all carry the scalar in an arbitrary-precision type and
//! fold it mod n:
//!   - TS     `packages/runar-compiler/src/optimizer/anf-ec.ts`  (`bigint`)
//!   - Go     `compilers/go/frontend/ec_rules_engine.go`         (`*big.Int`)
//!   - Python `compilers/python/runar_compiler/frontend/anf_optimize.py` (`int`)
//!   - Ruby   `compilers/ruby/lib/runar_compiler/frontend/anf_optimize.rb` (`Integer`)
//!   - Java   `compilers/java/.../passes/AnfOptimize.java`       (`BigInteger`)
//!
//! so a Rust-compiled contract diverged in hex from all of them. These tests
//! pin the oversize path AND keep a small-scalar control so a regression can
//! be told apart from "the rules stopped working entirely".

use num_bigint::BigInt;
use num_traits::Num;
use runar_compiler_rust::ir::{ANFProgram, ANFValue};

/// secp256k1 group order — the modulus every tier reduces a folded scalar by.
fn curve_n() -> BigInt {
    BigInt::from_str_radix(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap()
}

/// Inline spelling on purpose: binding an operand to a `const` first makes ANF
/// lowering insert an `@ref:` alias between the `ecAdd` and the `ecMulGen`
/// calls, and no tier's matcher resolves through those — the rule could not
/// fire either way and the test would prove nothing. (Same reasoning as
/// `packages/runar-compiler/src/__tests__/ec-mulgen-linear-parity.test.ts`.)
fn mulgen_linear_source(k1: &str, k2: &str) -> String {
    format!(
        r#"
import {{ SmartContract, assert, ecAdd, ecMulGen, ecOnCurve }} from 'runar-lang';

class ECLinear extends SmartContract {{
    constructor() {{
        super();
    }}

    public spend(a: bigint, b: bigint) {{
        assert(ecOnCurve(ecAdd(ecMulGen({k1}), ecMulGen({k2}))));
    }}
}}
"#
    )
}

/// `ecMul(ecMul(p, k1), k2)` — rule 9, the multiplicative fusing rule.
fn mul_associative_source(k1: &str, k2: &str) -> String {
    format!(
        r#"
import {{ SmartContract, assert, ecMul, ecOnCurve, Point }} from 'runar-lang';

class ECAssoc extends SmartContract {{
    constructor() {{
        super();
    }}

    public spend(p: Point) {{
        assert(ecOnCurve(ecMul(ecMul(p, {k1}), {k2})));
    }}
}}
"#
    )
}

fn lower_to_anf(source: &str) -> ANFProgram {
    runar_compiler_rust::compile_source_str_to_ir(source, Some("Probe.runar.ts"))
        .unwrap_or_else(|e| panic!("Rust frontend failed to lower probe: {e}"))
}

fn spend_calls(program: &ANFProgram) -> Vec<String> {
    let spend = program
        .methods
        .iter()
        .find(|m| m.name == "spend")
        .expect("spend method missing from lowered ANF");
    spend
        .body
        .iter()
        .filter_map(|b| match &b.value {
            ANFValue::Call { func, .. } => Some(func.clone()),
            _ => None,
        })
        .collect()
}

/// Every `load_const` in `spend`, decoded through the shared wire-format
/// parser, so a bare JSON number and a `"...n"` decimal string compare equal.
fn spend_const_ints(program: &ANFProgram) -> Vec<BigInt> {
    let spend = program
        .methods
        .iter()
        .find(|m| m.name == "spend")
        .expect("spend method missing from lowered ANF");
    spend
        .body
        .iter()
        .filter_map(|b| match &b.value {
            ANFValue::LoadConst { value } => match runar_compiler_rust::ir::parse_const_value(value)
            {
                Some(runar_compiler_rust::ir::ConstValue::Int(i)) => Some(i),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

fn count(calls: &[String], func: &str) -> usize {
    calls.iter().filter(|f| f.as_str() == func).count()
}

/// True when `spend` contains an `ecMul` whose point operand is the method
/// parameter itself (not another `ecMul`) and whose scalar operand is the
/// constant `expected` — i.e. rule 9 rewired the outer multiply straight onto
/// `p` with the fused scalar.
///
/// The now-dead inner `ecMul` binding is intentionally still present: the ANF
/// dead-binding pass treats `call` bindings as potentially effectful and does
/// not drop them, in every tier. Counting `ecMul` bindings therefore proves
/// nothing; the rewired operands do.
fn has_fused_ec_mul(program: &ANFProgram, expected: &BigInt) -> bool {
    let spend = program
        .methods
        .iter()
        .find(|m| m.name == "spend")
        .expect("spend method missing from lowered ANF");
    let value_of = |name: &str| spend.body.iter().find(|b| b.name == name).map(|b| &b.value);

    spend.body.iter().any(|b| match &b.value {
        ANFValue::Call { func, args } if func == "ecMul" && args.len() == 2 => {
            let point_is_param = matches!(value_of(&args[0]), Some(ANFValue::LoadParam { .. }));
            let scalar_matches = match value_of(&args[1]) {
                Some(ANFValue::LoadConst { value }) => {
                    matches!(runar_compiler_rust::ir::parse_const_value(value),
                        Some(runar_compiler_rust::ir::ConstValue::Int(i)) if i == *expected)
                }
                _ => false,
            };
            point_is_param && scalar_matches
        }
        _ => false,
    })
}

// ---------------------------------------------------------------------------
// Control: small constant scalars. This path already worked before the fix —
// it distinguishes "oversize handling is broken" from "the rules never fire".
// ---------------------------------------------------------------------------

#[test]
fn control_small_constant_scalars_fold_ec_mulgen_linear() {
    let anf = lower_to_anf(&mulgen_linear_source("5n", "7n"));
    let calls = spend_calls(&anf);

    assert_eq!(
        count(&calls, "ecAdd"),
        0,
        "control: ecAdd should have been folded away, calls = {calls:?}"
    );
    assert!(
        spend_const_ints(&anf).contains(&BigInt::from(12)),
        "control: folded scalar 5 + 7 = 12 not found among {:?}",
        spend_const_ints(&anf)
    );
}

#[test]
fn control_small_constant_scalars_fold_ec_mul_associative() {
    let anf = lower_to_anf(&mul_associative_source("5n", "7n"));
    let calls = spend_calls(&anf);

    assert!(
        has_fused_ec_mul(&anf, &BigInt::from(35)),
        "control: ecMul(ecMul(p, 5), 7) should have been rewired to ecMul(p, 35); \
         calls = {calls:?}, consts = {:?}",
        spend_const_ints(&anf)
    );
}

// ---------------------------------------------------------------------------
// The bug: real secp256k1-sized constant scalars.
// ---------------------------------------------------------------------------

/// Two 256-bit scalars whose sum wraps past the curve order, so the test also
/// pins the mod-n reduction the other six tiers perform.
const BIG_K1: &str = "115792089237316195423570985008687907852837564279074904382605163141518161494330";
const BIG_K2: &str = "115792089237316195423570985008687907852837564279074904382605163141518161494331";

#[test]
fn oversize_constant_scalars_fold_ec_mulgen_linear() {
    let anf = lower_to_anf(&mulgen_linear_source(
        &format!("{BIG_K1}n"),
        &format!("{BIG_K2}n"),
    ));
    let calls = spend_calls(&anf);

    assert_eq!(
        count(&calls, "ecAdd"),
        0,
        "ecAdd(ecMulGen(k1), ecMulGen(k2)) must fuse for 256-bit constant scalars \
         (TS/Go/Python/Ruby/Java all fold it); calls = {calls:?}"
    );
    let k1: BigInt = BIG_K1.parse().unwrap();
    let k2: BigInt = BIG_K2.parse().unwrap();
    let expected = (k1 + k2) % curve_n();
    assert!(
        spend_const_ints(&anf).contains(&expected),
        "folded scalar (k1 + k2) mod n = {expected} not found among {:?}",
        spend_const_ints(&anf)
    );
}

#[test]
fn oversize_constant_scalars_fold_ec_mul_associative() {
    let anf = lower_to_anf(&mul_associative_source(
        &format!("{BIG_K1}n"),
        &format!("{BIG_K2}n"),
    ));
    let calls = spend_calls(&anf);

    let k1: BigInt = BIG_K1.parse().unwrap();
    let k2: BigInt = BIG_K2.parse().unwrap();
    let expected = (k1 * k2) % curve_n();
    assert!(
        has_fused_ec_mul(&anf, &expected),
        "ecMul(ecMul(p, k1), k2) must fuse for 256-bit constant scalars into \
         ecMul(p, (k1 * k2) mod n = {expected}); calls = {calls:?}, consts = {:?}",
        spend_const_ints(&anf)
    );
}

/// Both operands are JS-safe JSON numbers, so the OLD constness check
/// accepted them — but the product overflows `i64`, and the rewritten
/// constant used to be re-encoded with `n as i64`, which wraps. Distinct
/// failure class from the string-decoding one, same helper.
#[test]
fn js_safe_operands_whose_product_overflows_i64_fold_without_wrapping() {
    // 2^52 and 2^52: both < Number.MAX_SAFE_INTEGER, product = 2^104.
    let k1: BigInt = BigInt::from(1u64 << 52);
    let k2: BigInt = BigInt::from(1u64 << 52);
    let anf = lower_to_anf(&mul_associative_source(
        &format!("{k1}n"),
        &format!("{k2}n"),
    ));
    let calls = spend_calls(&anf);

    let expected = (k1 * k2) % curve_n();
    let consts = spend_const_ints(&anf);
    assert!(
        has_fused_ec_mul(&anf, &expected),
        "the two ecMul calls should fuse into ecMul(p, 2^104 = {expected}); \
         calls = {calls:?}, consts = {consts:?} \
         (a wrapped i64 would show up as a small or negative value)"
    );
}
