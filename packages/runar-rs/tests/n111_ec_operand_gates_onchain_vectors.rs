//! N-111: the Rust native EC builtins (`runar::prelude`, what a `.runar.rs`
//! contract calls under `cargo test`) must apply the compiled script's operand
//! gates — `ec_add` / `ec_negate`: 64 bytes and x, y < p (R-117); `ec_mul`:
//! on-curve or the all-zero identity O (R-157); `ec_point_x` / `ec_point_y` /
//! `ec_encode_compressed`: width only — and accept exactly what the script
//! accepts (off-curve operands of `ec_add` / `ec_negate` included).
//!
//! Oracle: `packages/runar-zig/src/fixtures/n111-ec-operand-gates-onchain.json`,
//! every row executed on @bsv/sdk Spend.validate by
//! `packages/runar-testing/src/__tests__/n111-ec-operand-gates-onchain.test.ts`.
//!
//! Proves: for every row, each builtin returns the on-chain value, or panics
//! where the script aborts (never a value).
//! Does not prove: inputs outside the file, or the script itself.

use std::panic;

use runar_lang::prelude::{
    ec_add, ec_encode_compressed, ec_mul, ec_mul_gen, ec_negate, ec_point_x, ec_point_y,
};

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex digit"))
        .collect()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn run(c: &serde_json::Value) -> String {
    let p = c["p"].as_str().map(from_hex);
    let q = c["q"].as_str().map(from_hex);
    let k = c["k"].as_str().map(|s| s.parse::<i64>().expect("k fits i64"));
    match c["fn"].as_str().expect("fn") {
        "ecAdd" => to_hex(&ec_add(p.as_ref().unwrap(), q.as_ref().unwrap())),
        "ecMul" => to_hex(&ec_mul(p.as_ref().unwrap(), k.unwrap())),
        "ecMulGen" => to_hex(&ec_mul_gen(k.unwrap())),
        "ecNegate" => to_hex(&ec_negate(p.as_ref().unwrap())),
        "ecPointX" => ec_point_x(p.as_ref().unwrap()).to_string(),
        "ecPointY" => ec_point_y(p.as_ref().unwrap()).to_string(),
        "ecEncodeCompressed" => to_hex(&ec_encode_compressed(p.as_ref().unwrap())),
        other => panic!("unknown fn {other}"),
    }
}

#[test]
fn n111_ec_builtins_match_onchain_operand_gates() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../runar-zig/src/fixtures/n111-ec-operand-gates-onchain.json"
    );
    let text = std::fs::read_to_string(path).expect("shared EC gate vectors");
    let doc: serde_json::Value = serde_json::from_str(&text).expect("vectors JSON");
    let cases = doc["cases"].as_array().expect("cases");
    assert!(!cases.is_empty());

    let prev_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let mut failures = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        let want = c["expect"].as_str().expect("expect");
        let got = panic::catch_unwind(|| run(c)).ok();
        let ok = match (want, &got) {
            ("abort", None) => true,
            ("abort", Some(_)) => false,
            (w, Some(g)) => g == w,
            (_, None) => false,
        };
        if !ok {
            failures.push(format!(
                "row {i} {} [{}]: want {want}, got {}",
                c["fn"], c["why"], got.as_deref().unwrap_or("panic")
            ));
        }
    }
    panic::set_hook(prev_hook);
    assert!(failures.is_empty(), "{} rows diverge:\n{}", failures.len(), failures.join("\n"));
}
