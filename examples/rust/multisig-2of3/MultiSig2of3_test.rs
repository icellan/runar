// R-107 — `multisig-2of3` is the canonical checkMultiSig + array-literal
// example and was tested in four of the nine formats (ts, sol, move, zig).
// This is the Rust half.
//
// `check_multi_sig([sig1, sig2], [self.pk1, self.pk2, self.pk3])` lowers to two
// `array_literal` ANF nodes — the canonical site where that node kind is
// emitted at all.
//
// The contract's `check_multi_sig` is a Rúnar intrinsic the compiler
// materialises into Script; it is not a method on the macro-generated struct,
// so `#[path] mod contract;` would not build. The frontend is the boundary the
// cross-compiler conformance cares about, and `compile_check` is how the peer
// suites exercise it.

#[test]
fn test_compile() {
    runar::compile_check(
        include_str!("MultiSig2of3.runar.rs"),
        "MultiSig2of3.runar.rs",
    )
    .unwrap();
}
