use runar::prelude::*;

/// Mirrors examples/go/go-dsl-bytestring-literal/GoDslBytestringLiteral.runar.go.
///
/// The Go-DSL fixture exercises Go-only surface features (`runar.BigintBig`
/// property type, `runar.ByteString("\x00\x6a")` literal). In the Rust DSL
/// the equivalent surface is plain `Bigint` / `ByteString` plus a `0x006a`
/// hex literal. Both lower to the same primitives in the AST.
#[runar::contract]
pub struct GoDslBytestringLiteral {
    #[readonly]
    pub target: Bigint,
    #[readonly]
    pub expected: ByteString,
}

impl GoDslBytestringLiteral {
    pub fn check(&self, a: Bigint, b: Bigint) {
        assert!(a + b == self.target);
        assert!(0x006a == self.expected);
    }
}
