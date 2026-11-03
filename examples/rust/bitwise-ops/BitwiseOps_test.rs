// BitwiseOps.runar.rs uses `~` as a unary bitwise-not operator, which is
// valid Rúnar (via its own parser) but NOT valid Rust syntax — Rust spells
// it `!`. Attempting `#[path] mod contract;` therefore fails to compile.
// We exercise the Rúnar frontend directly via compile_check, which is the
// cross-compiler conformance boundary we care about.
//
// That also means this tier cannot run F-167's wrong-value cases natively
// (the contract now checks caller-supplied shift / AND / OR / XOR results).
// The rejection is covered for the compiled bytes by
// conformance/witnesses/real-crypto/bitwise-ops.json on @bsv/sdk's Spend, and
// natively by the Go, Python, Ruby, Zig and Java example tests.

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("BitwiseOps.runar.rs"),
        "BitwiseOps.runar.rs",
    )
    .unwrap();
}
