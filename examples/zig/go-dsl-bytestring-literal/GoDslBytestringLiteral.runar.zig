// Mirrors examples/go/go-dsl-bytestring-literal/GoDslBytestringLiteral.runar.go.
//
// The Go-DSL fixture exercises Go-only surface features (`runar.BigintBig`
// property type, `runar.ByteString("\x00\x6a")` literal). In Zig the
// equivalent surface is plain `Bigint` / `ByteString` plus a bare string
// literal `"006a"` (the Zig parser maps string literals directly to
// ByteStringLiteral). Both lower to the same primitives in the AST.
const runar = @import("runar");

pub const GoDslBytestringLiteral = struct {
    pub const Contract = runar.SmartContract;

    target: runar.Bigint,
    expected: runar.ByteString,

    pub fn init(target: runar.Bigint, expected: runar.ByteString) GoDslBytestringLiteral {
        return .{ .target = target, .expected = expected };
    }

    pub fn check(self: *const GoDslBytestringLiteral, a: runar.Bigint, b: runar.Bigint) void {
        runar.assert(a + b == self.target);
        runar.assert(runar.bytesEq("006a", self.expected));
    }
};
