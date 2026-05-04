// Mirrors examples/go/go-dsl-bytestring-literal/GoDslBytestringLiteral.runar.go.
//
// The Go-DSL fixture exercises Go-only surface features (`runar.BigintBig`
// property type, `runar.ByteString("\x00\x6a")` literal). In Move the
// equivalent surface is plain `Int` / `ByteString` plus a `0x006a` hex
// literal. Both lower to the same primitives in the AST.
module GoDslBytestringLiteral {
    use runar::types::{Int, ByteString};

    struct GoDslBytestringLiteral {
        target: Int,
        expected: ByteString,
    }

    public fun check(contract: &GoDslBytestringLiteral, a: Int, b: Int) {
        assert!(a + b == contract.target, 0);
        assert!(0x006a == contract.expected, 0);
    }
}
