//! Cross-tier parity for the EXPERIMENTAL EC size flags.
//!
//! The flags default off, so the ordinary conformance suite — which compiles
//! with defaults — cannot see them at all. Seven tiers could each ship a
//! DIFFERENT `--ec-constant-pool` and the suite would stay green.
//!
//! That matters because the flags are not cosmetic: they change which reduction
//! form is emitted and which addition formula each ladder round uses. A tier
//! that ports the constant pool but not the sign lattice's `Reduced`
//! precondition produces a script that is smaller, passes its own tests, and is
//! wrong on `ecAdd((0,1), (2^256-1,1))`. Byte-identical output against a single
//! reference is the only cheap check that catches that.
//!
//! `conformance/ec-flag-parity/expected.json` is derived from the TypeScript
//! reference compiler and re-derived by its own vitest, so it cannot go stale.

use std::collections::BTreeMap;
use std::path::PathBuf;

use runar_compiler_rust::codegen::ec::{
    emit_ec_add, emit_ec_encode_compressed, emit_ec_make_point, emit_ec_mod_reduce, emit_ec_mul,
    emit_ec_mul_gen, emit_ec_negate, emit_ec_on_curve, emit_ec_point_x, emit_ec_point_y,
    EcCodegenOptions,
};
use runar_compiler_rust::codegen::emit::emit_method;
use runar_compiler_rust::codegen::p256_p384::{
    emit_p256_add, emit_p256_encode_compressed, emit_p256_mul, emit_p256_mul_gen,
    emit_p256_negate, emit_p256_on_curve, emit_p384_add, emit_p384_encode_compressed,
    emit_p384_mul, emit_p384_mul_gen, emit_p384_negate, emit_p384_on_curve,
    emit_verify_ecdsa_p256, emit_verify_ecdsa_p384,
};
use runar_compiler_rust::codegen::stack::{StackMethod, StackOp};
use sha2::{Digest, Sha256};

type Emitter = fn(&mut dyn FnMut(StackOp), Option<&EcCodegenOptions>);

/// Adapt an emitter the flags cannot reach to the options-taking shape.
///
/// These are deliberately included: a tier that accidentally made
/// `ecModReduce` or `ecPointX` flag-sensitive would be diverging just as badly
/// as one that ignored a flag.
macro_rules! ignore_opts {
    ($f:path) => {
        (|e: &mut dyn FnMut(StackOp), _: Option<&EcCodegenOptions>| $f(e)) as Emitter
    };
}

fn emitters() -> BTreeMap<&'static str, Emitter> {
    let mut m: BTreeMap<&'static str, Emitter> = BTreeMap::new();
    m.insert("EcAdd", emit_ec_add as Emitter);
    m.insert("EcMul", emit_ec_mul as Emitter);
    m.insert("EcMulGen", emit_ec_mul_gen as Emitter);
    m.insert("EcNegate", emit_ec_negate as Emitter);
    m.insert("EcOnCurve", emit_ec_on_curve as Emitter);
    m.insert("EcModReduce", ignore_opts!(emit_ec_mod_reduce));
    m.insert("EcEncodeCompressed", ignore_opts!(emit_ec_encode_compressed));
    m.insert("EcMakePoint", ignore_opts!(emit_ec_make_point));
    m.insert("EcPointX", ignore_opts!(emit_ec_point_x));
    m.insert("EcPointY", ignore_opts!(emit_ec_point_y));

    m.insert("P256Add", emit_p256_add as Emitter);
    m.insert("P256Mul", emit_p256_mul as Emitter);
    m.insert("P256MulGen", emit_p256_mul_gen as Emitter);
    m.insert("P256Negate", emit_p256_negate as Emitter);
    m.insert("P256OnCurve", emit_p256_on_curve as Emitter);
    m.insert("P256EncodeCompressed", ignore_opts!(emit_p256_encode_compressed));
    m.insert("VerifyECDSA_P256", emit_verify_ecdsa_p256 as Emitter);

    m.insert("P384Add", emit_p384_add as Emitter);
    m.insert("P384Mul", emit_p384_mul as Emitter);
    m.insert("P384MulGen", emit_p384_mul_gen as Emitter);
    m.insert("P384Negate", emit_p384_negate as Emitter);
    m.insert("P384OnCurve", emit_p384_on_curve as Emitter);
    m.insert("P384EncodeCompressed", ignore_opts!(emit_p384_encode_compressed));
    m.insert("VerifyECDSA_P384", emit_verify_ecdsa_p384 as Emitter);
    m
}

fn fixture() -> serde_json::Value {
    // tests -> compilers/rust -> compilers -> repo root
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/ec-flag-parity/expected.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    serde_json::from_str(&raw).expect("parse ec-flag-parity/expected.json")
}

fn emit_and_hash(f: Emitter, opts: Option<&EcCodegenOptions>) -> (usize, String) {
    let mut ops: Vec<StackOp> = Vec::new();
    f(&mut |op| ops.push(op), opts);
    let method = StackMethod {
        name: "t".to_string(),
        ops,
        max_stack_depth: 0,
        uses_code_part: false,
        source_locs: Vec::new(),
    };
    let res = emit_method(&method).expect("emit_method");
    let raw = hex::decode(&res.script_hex).expect("valid hex");
    let mut h = Sha256::new();
    h.update(&raw);
    (raw.len(), hex::encode(h.finalize()))
}

#[test]
fn ec_flag_parity_against_typescript_reference() {
    let f = fixture();
    let variants = f["variants"].as_object().expect("variants object");

    for (name, emitter) in emitters() {
        let want = f["emitters"][name]
            .as_object()
            .unwrap_or_else(|| panic!("{}: no entry in the parity fixture", name));
        for (variant, spec) in variants {
            let expect = want
                .get(variant)
                .unwrap_or_else(|| panic!("{}/{}: no entry in the parity fixture", name, variant));
            let opts = EcCodegenOptions {
                constant_pool: spec["constantPool"].as_bool().unwrap_or(false),
                reduction_sinking: spec["reductionSinking"].as_bool().unwrap_or(false),
                fixed_base_comb: spec["fixedBaseComb"].as_bool().unwrap_or(false),
            };
            let (bytes, hash) = emit_and_hash(emitter, Some(&opts));
            let want_bytes = expect["bytes"].as_u64().unwrap() as usize;
            let want_hash = expect["sha256"].as_str().unwrap();
            assert_eq!(
                (bytes, hash.as_str()),
                (want_bytes, want_hash),
                "{} under {}: Rust and the TypeScript reference disagree",
                name,
                variant
            );
        }
    }
}

/// `None` options must be byte-identical to the shipping output. This is what
/// keeps the existing goldens, the size baseline and every cross-tier hex
/// comparison from moving while the flags are experimental.
#[test]
fn ec_flags_default_off_is_byte_identical() {
    let f = fixture();
    for (name, emitter) in emitters() {
        let (_, none_hash) = emit_and_hash(emitter, None);
        let (_, off_hash) = emit_and_hash(emitter, Some(&EcCodegenOptions::default()));
        assert_eq!(none_hash, off_hash, "{}: None and all-false disagree", name);
        assert_eq!(
            none_hash,
            f["emitters"][name]["off"]["sha256"].as_str().unwrap(),
            "{}: default output moved",
            name
        );
    }
}
