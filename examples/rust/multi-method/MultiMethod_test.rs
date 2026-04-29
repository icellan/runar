// MultiMethod.runar.rs is parser-only friendly: the contract source uses
// `check_sig(sig, self.owner)` (by-value, no references) which mirrors the
// Rúnar surface but does not type-check as native Rust against
// `runar::prelude::check_sig`. So we cover the Rúnar frontend (parse →
// validate → typecheck) only.

#[test]
fn test_compile() {
    runar::compile_check(include_str!("MultiMethod.runar.rs"), "MultiMethod.runar.rs").unwrap();
}
