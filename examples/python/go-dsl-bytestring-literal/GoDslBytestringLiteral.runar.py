"""Mirrors examples/go/go-dsl-bytestring-literal/GoDslBytestringLiteral.runar.go.

The Go-DSL fixture exercises Go-only surface features (`runar.BigintBig`
property type, `runar.ByteString("\\x00\\x6a")` literal). In Python the
equivalent surface is plain `Bigint` / `ByteString` plus a `b"\\x00\\x6a"`
byte-string literal. Both lower to the same primitives in the AST.
"""

from runar import SmartContract, Bigint, ByteString, public, assert_


class GoDslBytestringLiteral(SmartContract):
    target: Bigint
    expected: ByteString

    def __init__(self, target: Bigint, expected: ByteString):
        super().__init__(target, expected)
        self.target = target
        self.expected = expected

    @public
    def check(self, a: Bigint, b: Bigint):
        assert_(a + b == self.target)
        assert_(b"\x00\x6a" == self.expected)
