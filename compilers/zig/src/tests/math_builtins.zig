//! Per-builtin codegen op-shape tests for the 16 Rúnar math builtins (GAP-m8).
//!
//! Before this file, the Zig tier exercised the math builtins only through
//! the cross-tier conformance suite — there was no per-tier unit anchor, so a
//! wrong-opcode regression in an individual `lowerX` routine would surface
//! only as a conformance hex divergence (and only if Zig diverged from the
//! other 6 tiers, not if all 7 regressed in lock-step).
//!
//! Each test compiles a minimal stateless contract that calls one builtin on
//! method parameters (so the constant folder cannot fold the call away) and
//! asserts the compiled hex contains the builtin's load-bearing opcode(s).
//!
//! Builtin -> representative opcode(s):
//!   abs       -> OP_ABS      (0x90)
//!   min       -> OP_MIN      (0xa3)
//!   max       -> OP_MAX      (0xa4)
//!   within    -> OP_WITHIN   (0xa5)
//!   safediv   -> OP_DIV      (0x96)
//!   safemod   -> OP_MOD      (0x97)
//!   clamp     -> OP_MAX+OP_MIN (clamp = min(max(x,lo),hi))
//!   sign      -> OP_ABS      (0x90)  (DUP IF DUP ABS SWAP DIV ENDIF)
//!   pow       -> OP_MUL      (0x95)
//!   mulDiv    -> OP_MUL+OP_DIV
//!   percentOf -> OP_MUL+OP_DIV
//!   sqrt      -> OP_DIV      (0x96)
//!   gcd       -> OP_MOD      (0x97)
//!   divmod    -> OP_MOD+OP_DIV
//!   log2      -> OP_DIV      (0x96)  + OP_1ADD (0x8b)
//!   bool      -> OP_0NOTEQUAL (0x92)

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

/// Check that `hex` contains `opcode` (a 2-char hex byte) at a byte-aligned
/// boundary. Mirrors compiler_api.hexContainsOpcode (which is file-private).
fn hexHasOpcode(hex: []const u8, opcode: []const u8) bool {
    std.debug.assert(opcode.len == 2);
    var i: usize = 0;
    while (i + 1 < hex.len) : (i += 2) {
        if (hex[i] == opcode[0] and hex[i + 1] == opcode[1]) return true;
    }
    return false;
}

/// Compile a stateless contract whose `check` method body is `body_src` and
/// return the locking-script hex. The contract has three i64 params
/// (`a`, `b`, `c`) and one i64 property (`threshold`) so any builtin can be
/// exercised on non-constant operands.
fn compileBuiltinCheck(comptime body_src: []const u8) ![]const u8 {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const MathProbe = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    threshold: i64,
        \\
        \\    pub fn init(threshold: i64) MathProbe {
        \\        return .{ .threshold = threshold };
        \\    }
        \\
        \\    pub fn check(self: *const MathProbe, a: i64, b: i64, c: i64) void {
    ++ body_src ++
        \\
        \\    }
        \\};
    ;
    return compiler_api.compileSourceToHex(std.testing.allocator, source, "MathProbe.runar.zig");
}

fn expectOpcode(hex: []const u8, opcode: []const u8) !void {
    try std.testing.expect(hexHasOpcode(hex, opcode));
}

// E1 — abs
test "math builtin abs lowers to OP_ABS" {
    const hex = try compileBuiltinCheck("        runar.assert(runar.abs(a) == self.threshold);");
    defer std.testing.allocator.free(hex);
    try expectOpcode(hex, "90");
}

// E2 — min
test "math builtin min lowers to OP_MIN" {
    const hex = try compileBuiltinCheck("        runar.assert(runar.min(a, b) == self.threshold);");
    defer std.testing.allocator.free(hex);
    try expectOpcode(hex, "a3");
}

// E3 — max
test "math builtin max lowers to OP_MAX" {
    const hex = try compileBuiltinCheck("        runar.assert(runar.max(a, b) == self.threshold);");
    defer std.testing.allocator.free(hex);
    try expectOpcode(hex, "a4");
}

// E4 — within
test "math builtin within lowers to OP_WITHIN" {
    const hex = try compileBuiltinCheck("        runar.assert(runar.within(a, b, c));");
    defer std.testing.allocator.free(hex);
    try expectOpcode(hex, "a5");
}

// E5 — safediv
test "math builtin safediv lowers to OP_DIV" {
    const hex = try compileBuiltinCheck("        runar.assert(runar.safediv(a, b) == self.threshold);");
    defer std.testing.allocator.free(hex);
    try expectOpcode(hex, "96");
}

// E6 — safemod
test "math builtin safemod lowers to OP_MOD" {
    const hex = try compileBuiltinCheck("        runar.assert(runar.safemod(a, b) == self.threshold);");
    defer std.testing.allocator.free(hex);
    try expectOpcode(hex, "97");
}

// E7 — clamp
test "math builtin clamp lowers to OP_MAX and OP_MIN" {
    const hex = try compileBuiltinCheck("        runar.assert(runar.clamp(a, b, c) == self.threshold);");
    defer std.testing.allocator.free(hex);
    try expectOpcode(hex, "a4"); // OP_MAX
    try expectOpcode(hex, "a3"); // OP_MIN
}

// E8 — sign
test "math builtin sign lowers to OP_ABS" {
    const hex = try compileBuiltinCheck("        runar.assert(runar.sign(a) == self.threshold);");
    defer std.testing.allocator.free(hex);
    try expectOpcode(hex, "90");
}

// E9 — pow
test "math builtin pow lowers to OP_MUL" {
    const hex = try compileBuiltinCheck("        runar.assert(runar.pow(a, b) == self.threshold);");
    defer std.testing.allocator.free(hex);
    try expectOpcode(hex, "95");
}

// E10 — mulDiv
test "math builtin mulDiv lowers to OP_MUL and OP_DIV" {
    const hex = try compileBuiltinCheck("        runar.assert(runar.mulDiv(a, b, c) == self.threshold);");
    defer std.testing.allocator.free(hex);
    try expectOpcode(hex, "95"); // OP_MUL
    try expectOpcode(hex, "96"); // OP_DIV
}

// E11 — percentOf
test "math builtin percentOf lowers to OP_MUL and OP_DIV" {
    const hex = try compileBuiltinCheck("        runar.assert(runar.percentOf(a, b) == self.threshold);");
    defer std.testing.allocator.free(hex);
    try expectOpcode(hex, "95"); // OP_MUL
    try expectOpcode(hex, "96"); // OP_DIV
}

// E12 — sqrt
test "math builtin sqrt lowers to OP_DIV" {
    const hex = try compileBuiltinCheck("        runar.assert(runar.sqrt(a) == self.threshold);");
    defer std.testing.allocator.free(hex);
    try expectOpcode(hex, "96");
}

// E13 — gcd
test "math builtin gcd lowers to OP_MOD" {
    const hex = try compileBuiltinCheck("        runar.assert(runar.gcd(a, b) == self.threshold);");
    defer std.testing.allocator.free(hex);
    try expectOpcode(hex, "97");
}

// E14 — divmod
test "math builtin divmod lowers to OP_MOD and OP_DIV" {
    const hex = try compileBuiltinCheck("        runar.assert(runar.divmod(a, b) == self.threshold);");
    defer std.testing.allocator.free(hex);
    try expectOpcode(hex, "97"); // OP_MOD
    try expectOpcode(hex, "96"); // OP_DIV
}

// E15 — log2
test "math builtin log2 lowers to OP_DIV and OP_1ADD" {
    const hex = try compileBuiltinCheck("        runar.assert(runar.log2(a) == self.threshold);");
    defer std.testing.allocator.free(hex);
    try expectOpcode(hex, "96"); // OP_DIV
    try expectOpcode(hex, "8b"); // OP_1ADD
}

// E16 — bool() cast. The Zig surface parser treats a bare `bool` as a type
// keyword, so the `bool` builtin is exercised through a `.runar.ts` source
// compiled by the Zig compiler (which parses all 9 surface formats).
test "math builtin bool lowers to OP_0NOTEQUAL" {
    const source =
        \\import { SmartContract, assert, bool } from 'runar-lang';
        \\
        \\class BoolProbe extends SmartContract {
        \\  readonly threshold: bigint;
        \\
        \\  constructor(threshold: bigint) {
        \\    super(threshold);
        \\    this.threshold = threshold;
        \\  }
        \\
        \\  public check(a: bigint): void {
        \\    assert(bool(a));
        \\  }
        \\}
    ;
    const hex = try compiler_api.compileSourceToHex(std.testing.allocator, source, "BoolProbe.runar.ts");
    defer std.testing.allocator.free(hex);
    try expectOpcode(hex, "92"); // OP_0NOTEQUAL
}
