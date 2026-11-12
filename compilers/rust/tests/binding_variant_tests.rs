//! Ports #170 (original design: brendan-elas, #167): the C=1 Any-S binding and
//! the `@bindingVariant` directive in the Rust tier. The two blobs are pinned
//! here as literals so a Rust-only drift fails this file; execution of the
//! same bytes through @bsv/sdk Spend lives in
//! packages/runar-testing/src/__tests__/binding-variant.test.ts.

use runar_compiler_rust::{
    compile_from_ir_str, compile_from_source_str_with_options, compile_source_str_to_ir_with_options,
    CompileOptions,
};

/// 422 bytes: s = lowS((z+1) mod n), C=1 key 038ff83d...
const LOWS_HEX: &str = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad";
/// 376 bytes: s = z+1, no mod-n, no low-S (nVersion > 1 only).
const ALL_HEX: &str = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8b82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad";

fn opts() -> CompileOptions {
    CompileOptions { disable_constant_folding: true, ..CompileOptions::default() }
}

fn counter(directive: &str) -> String {
    format!(
        "class C extends StatefulSmartContract {{\n  count: bigint;\n  constructor(count: bigint) {{ super(count); this.count = count; }}\n  {}\n  public bump() {{ this.count++; }}\n}}\n",
        directive
    )
}

fn script(src: &str, file: &str) -> String {
    compile_from_source_str_with_options(src, Some(file), &opts())
        .unwrap_or_else(|e| panic!("{file} failed to compile: {e}"))
        .script
}

fn compile_err(src: &str, file: &str) -> String {
    match compile_from_source_str_with_options(src, Some(file), &opts()) {
        Ok(_) => panic!("{file} compiled, expected an error"),
        Err(e) => e,
    }
}

#[test]
fn pinned_sizes() {
    assert_eq!(LOWS_HEX.len() / 2, 422);
    assert_eq!(ALL_HEX.len() / 2, 376);
}

#[test]
fn default_and_explicit_lows_emit_the_c1_blob() {
    for d in ["", "/** @bindingVariant lowS */"] {
        let s = script(&counter(d), "C.runar.ts");
        assert_eq!(s.matches(LOWS_HEX).count(), 1, "{d:?}");
        assert!(!s.contains("02b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0"), "{d:?}");
    }
}

#[test]
fn all_emits_the_compact_blob() {
    let s = script(&counter("/** @bindingVariant all */"), "C.runar.ts");
    assert_eq!(s.matches(ALL_HEX).count(), 1);
    assert!(!s.contains(LOWS_HEX));
}

#[test]
fn nested_arm_inherits_the_variant() {
    let src = "class G extends SmartContract {\n  constructor() { super(); }\n  /** @bindingVariant all */\n  public unlock(a: SigHashPreimage, b: SigHashPreimage, c: boolean) {\n    if (c) { assert(checkPreimage(a)); } else { assert(checkPreimage(b)); }\n  }\n}\n";
    let s = script(src, "G.runar.ts");
    assert_eq!(s.matches(ALL_HEX).count(), 2);
    assert!(!s.contains(LOWS_HEX));
}

#[test]
fn directive_errors() {
    for (d, want) in [
        ("/** @bindingVariant: all */", "@bindingVariant: malformed directive; expected `@bindingVariant lowS` or `@bindingVariant all`"),
        ("/** @bindingVariant high */", "@bindingVariant: unknown variant \"high\" (valid: lowS, all)"),
        (
            "/** @bindingVariant all */\n  // @bindingVariant lowS",
            "@bindingVariant: more than one @bindingVariant directive on this method; declare exactly one",
        ),
    ] {
        let e = compile_err(&counter(d), "C.runar.ts");
        assert!(e.contains(want), "{d:?}: {e}");
    }
    let private = counter("/** @bindingVariant all */").replace("public bump", "private bump");
    let e = compile_err(&private, "C.runar.ts");
    assert!(e.contains("@bindingVariant directive on non-public method 'bump' has no effect"), "{e}");
}

#[test]
fn non_ts_surfaces_refuse() {
    for (file, name) in [
        ("C.runar.sol", "Solidity"),
        ("C.runar.move", "Move"),
        ("C.runar.py", "Python"),
        ("C.runar.go", "Go DSL"),
        ("C.runar.rs", "Rust"),
        ("C.runar.rb", "Ruby"),
        ("C.runar.zig", "Zig"),
        ("C.runar.java", "Java"),
    ] {
        let e = compile_err("// @bindingVariant all\n", file);
        let want = format!("@bindingVariant directive is not supported by the {name} surface parser; write the contract in TypeScript (.runar.ts), where @bindingVariant is honoured");
        assert!(e.contains(&want), "{file}: {e}");
    }
}

#[test]
fn ir_loader_refuses_an_unknown_variant() {
    let program = compile_source_str_to_ir_with_options(&counter("/** @bindingVariant all */"), Some("C.runar.ts"), &opts())
        .expect("lower to IR");
    let json = serde_json::to_string(&program).expect("serialize");
    assert!(json.contains("\"bindingVariant\":\"all\""), "{json}");
    compile_from_ir_str(&json).expect("valid all IR must load");
    let bad = json.replacen("\"bindingVariant\":\"all\"", "\"bindingVariant\":\"high\"", 1);
    let e = compile_from_ir_str(&bad).err().expect("invalid bindingVariant must be refused");
    assert!(e.contains("bindingVariant must be \"lowS\" or \"all\""), "{e}");
}
