const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const ByteBuiltins = @import("ByteBuiltins.runar.zig").ByteBuiltins;

// FIPS 180-4 B.1 SHA-256("abc") and the published RIPEMD-160("abc") vector.
const sha256_abc = runar.hexToBytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
const ripemd160_abc = runar.hexToBytes("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "byte-builtins/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check ByteBuiltins.runar.zig" {
    try runCompileChecks("ByteBuiltins.runar.zig");
}

// Proves: each of the five checks accepts the correct answer and aborts with the Runar assertion for a wrong one: split binds the tail at the index, int2str is the fixed-width little-endian sign-magnitude encoding (258 in 4 bytes, -1 in 2 bytes is 01 80), reverseBytes reverses, and sha256 / ripemd160 match published known-answer digests (not values the runar package computed).
// Does not prove: the out-of-range behaviour (split past the end, a width too small, more than 520 bytes to reverse) which is a builtin panic rather than a contract assertion and is pinned in packages/runar-zig/src/builtins_n375_native_gaps_test.zig; nor the compiled script (conformance/go_sdk_byte_builtins_execution_test.go).

test "ByteBuiltins accepts the correct split, int2str, reverse, sha256 and ripemd160" {
    const c = ByteBuiltins.init(sha256_abc, ripemd160_abc);
    c.checkSplit("abcdef", 2, "cdef");
    c.checkSplit("abcdef", 6, "");
    c.checkInt2Str(258, 4, &[_]u8{ 0x02, 0x01, 0x00, 0x00 });
    c.checkInt2Str(-1, 2, &[_]u8{ 0x01, 0x80 });
    c.checkReverse("abc", "cba");
    c.checkSha256("abc");
    c.checkRipemd("abc");
}

test "ByteBuiltins checkSplit aborts for a wrong tail" {
    try root.expectAssertFailure("byte-builtins-split-wrong");
}

test "ByteBuiltins checkInt2Str aborts for a wrong encoding" {
    try root.expectAssertFailure("byte-builtins-int2str-wrong");
}

test "ByteBuiltins checkReverse aborts for a wrong reversal" {
    try root.expectAssertFailure("byte-builtins-reverse-wrong");
}

test "ByteBuiltins checkSha256 aborts for a different preimage" {
    try root.expectAssertFailure("byte-builtins-sha256-wrong");
}

test "ByteBuiltins checkRipemd aborts for a different preimage" {
    try root.expectAssertFailure("byte-builtins-ripemd-wrong");
}
