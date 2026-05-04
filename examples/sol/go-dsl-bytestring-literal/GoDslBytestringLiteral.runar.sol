// Mirrors examples/go/go-dsl-bytestring-literal/GoDslBytestringLiteral.runar.go.
//
// The Go-DSL fixture exercises Go-only surface features (`runar.BigintBig`
// property type, `runar.ByteString("\x00\x6a")` literal). In Solidity the
// equivalent surface is plain `bigint` / `ByteString` plus a `0x006a` hex
// literal. Both lower to the same primitives in the AST.

pragma runar ^0.1.0;

contract GoDslBytestringLiteral is SmartContract {
    bigint immutable target;
    ByteString immutable expected;

    constructor(bigint _target, ByteString _expected) {
        target = _target;
        expected = _expected;
    }

    function check(bigint a, bigint b) public {
        require(a + b == target);
        require(0x006a == expected);
    }
}
