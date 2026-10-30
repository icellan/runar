const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const P384EncodeNegate = @import("P384EncodeNegate.runar.zig").P384EncodeNegate;
const v = @import("vectors.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "p384-encode-negate/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check P384EncodeNegate.runar.zig" {
    try runCompileChecks("P384EncodeNegate.runar.zig");
}

// Proves: p384Negate maps G to (x, p - y) and p384EncodeCompressed maps G to 02/03 || x with the parity of y, against known-answer vectors from Go's crypto/elliptic (not derived from the runar Zig package). checkNegate / checkEncode accept the right answer, and the abort probes show a wrong expected point (G itself instead of -G) and a flipped parity prefix abort with the Runar assertion; checkNegateThenEncode shows compressing -G flips the prefix and nothing else.
// Does not prove: the compiled script's behaviour on non-canonical or off-curve points (the codegen guards those; conformance/p256_p384_encode_negate_execution_test.go runs it on a consensus interpreter), and nothing here checks that the point is on the curve (neither does the builtin).

test "P384EncodeNegate checkNegate accepts -G for G" {
    const c = P384EncodeNegate.init(v.neg_g_compressed);
    c.checkNegate(v.g, v.neg_g);
}

test "P384EncodeNegate checkEncode accepts the compressed encoding of G" {
    const c = P384EncodeNegate.init(v.neg_g_compressed);
    c.checkEncode(v.g, v.g_compressed);
}

test "P384EncodeNegate checkNegateThenEncode matches the compressed -G" {
    const c = P384EncodeNegate.init(v.neg_g_compressed);
    c.checkNegateThenEncode(v.g);
}

test "P384EncodeNegate checkNegate aborts for the wrong negation" {
    try root.expectAssertFailure("p384-encode-negate-wrong-negation");
}

test "P384EncodeNegate checkEncode aborts for the wrong parity prefix" {
    try root.expectAssertFailure("p384-encode-negate-wrong-prefix");
}

test "P384EncodeNegate checkNegateThenEncode aborts when the expected encoding is the un-negated one" {
    try root.expectAssertFailure("p384-encode-negate-negate-then-encode-wrong");
}
