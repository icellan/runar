//! Codegen op-shape tests for the language-construct rows the Zig tier
//! previously exercised only through the cross-tier conformance suite
//! (GAP-m9 / audit section 4 follow-up).
//!
//! The pipeline passes (validate / typecheck / ANF / constant-fold /
//! expand-fixed-arrays) and the type-system rows (bigint / bool /
//! ByteString / Point / fixed arrays / assert / if-else / for-loops)
//! already carry assertion-grade inline `test` blocks in their respective
//! `passes/*.zig` source files. The genuine remaining gaps were the
//! *codegen* rows with no dedicated per-tier probe:
//!
//!   C3  addOutput            — multi-output state continuation
//!   C4  addRawOutput         — caller-specified script bytes output
//!   D8  if-without-else      — control-flow merge
//!   D10 bitwise on bigint    — & | ^ ~
//!   D11 bitwise on ByteString
//!   D12 shift << >>
//!
//! Each test compiles a minimal contract exercising the construct and
//! asserts the compiled hex contains the construct's load-bearing opcodes.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

fn hexHasOpcode(hex: []const u8, opcode: []const u8) bool {
    std.debug.assert(opcode.len == 2);
    var i: usize = 0;
    while (i + 1 < hex.len) : (i += 2) {
        if (hex[i] == opcode[0] and hex[i + 1] == opcode[1]) return true;
    }
    return false;
}

fn compile(comptime source: []const u8, file_name: []const u8) ![]const u8 {
    return compiler_api.compileSourceToHex(std.testing.allocator, source, file_name);
}

// C3 — addOutput (multi-output state continuation).
test "addOutput emits the BIP-143 output serialization opcodes" {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const OutputProbe = struct {
        \\    pub const Contract = runar.StatefulSmartContract;
        \\
        \\    count: i64 = 0,
        \\
        \\    pub fn init(count: i64) OutputProbe {
        \\        return .{ .count = count };
        \\    }
        \\
        \\    pub fn bump(self: *OutputProbe) void {
        \\        self.count = self.count + 1;
        \\        self.addOutput(1000, self.count);
        \\    }
        \\};
    ;
    const hex = try compile(source, "OutputProbe.runar.zig");
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hexHasOpcode(hex, "82")); // OP_SIZE — script-len prefix
    try std.testing.expect(hexHasOpcode(hex, "7e")); // OP_CAT — output assembly
    try std.testing.expect(hexHasOpcode(hex, "80")); // OP_NUM2BIN — 8-byte LE satoshis
}

// C4 — addRawOutput (caller-specified script bytes).
test "addRawOutput emits the BIP-143 output serialization opcodes" {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const RawProbe = struct {
        \\    pub const Contract = runar.StatefulSmartContract;
        \\
        \\    count: i64 = 0,
        \\
        \\    pub fn init(count: i64) RawProbe {
        \\        return .{ .count = count };
        \\    }
        \\
        \\    pub fn sendToScript(self: *RawProbe, scriptBytes: runar.ByteString) void {
        \\        self.addRawOutput(1000, scriptBytes);
        \\        self.count = self.count + 1;
        \\        self.addOutput(0, self.count);
        \\    }
        \\};
    ;
    const hex = try compile(source, "RawProbe.runar.zig");
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hexHasOpcode(hex, "82")); // OP_SIZE
    try std.testing.expect(hexHasOpcode(hex, "7e")); // OP_CAT
    try std.testing.expect(hexHasOpcode(hex, "80")); // OP_NUM2BIN
}

// D8 — if without else (control-flow merge).
test "if without else emits OP_IF / OP_ENDIF" {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const IfProbe = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    threshold: i64,
        \\
        \\    pub fn init(threshold: i64) IfProbe {
        \\        return .{ .threshold = threshold };
        \\    }
        \\
        \\    pub fn check(self: *const IfProbe, a: i64) void {
        \\        var x: i64 = a;
        \\        if (a > self.threshold) {
        \\            x = a - self.threshold;
        \\        }
        \\        runar.assert(x >= 0 or x < 0);
        \\    }
        \\};
    ;
    const hex = try compile(source, "IfProbe.runar.zig");
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hexHasOpcode(hex, "63")); // OP_IF
    try std.testing.expect(hexHasOpcode(hex, "68")); // OP_ENDIF
}

// D10 — bitwise & | ^ ~ on bigint.
test "bitwise operators on bigint emit OP_AND / OP_OR / OP_XOR / OP_INVERT" {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const BitProbe = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    a: i64,
        \\    b: i64,
        \\
        \\    pub fn init(a: i64, b: i64) BitProbe {
        \\        return .{ .a = a, .b = b };
        \\    }
        \\
        \\    pub fn check(self: *const BitProbe) void {
        \\        const andResult = self.a & self.b;
        \\        const orResult = self.a | self.b;
        \\        const xorResult = self.a ^ self.b;
        \\        const notResult = ~self.a;
        \\        runar.assert(andResult >= 0 or andResult < 0);
        \\        runar.assert(orResult >= 0 or orResult < 0);
        \\        runar.assert(xorResult >= 0 or xorResult < 0);
        \\        runar.assert(notResult >= 0 or notResult < 0);
        \\    }
        \\};
    ;
    const hex = try compile(source, "BitProbe.runar.zig");
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hexHasOpcode(hex, "84")); // OP_AND
    try std.testing.expect(hexHasOpcode(hex, "85")); // OP_OR
    try std.testing.expect(hexHasOpcode(hex, "86")); // OP_XOR
    try std.testing.expect(hexHasOpcode(hex, "83")); // OP_INVERT
}

// D11 — bitwise on ByteString.
test "bitwise operators on ByteString emit OP_AND" {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const ByteBitProbe = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    mask: runar.ByteString,
        \\
        \\    pub fn init(mask: runar.ByteString) ByteBitProbe {
        \\        return .{ .mask = mask };
        \\    }
        \\
        \\    pub fn check(self: *const ByteBitProbe, data: runar.ByteString) void {
        \\        const masked = data & self.mask;
        \\        runar.assert(masked == self.mask);
        \\    }
        \\};
    ;
    const hex = try compile(source, "ByteBitProbe.runar.zig");
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hexHasOpcode(hex, "84")); // OP_AND
}

// D12 — shift << >>.
test "shift operators emit OP_LSHIFT / OP_RSHIFT" {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const ShiftProbe = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    a: i64,
        \\
        \\    pub fn init(a: i64) ShiftProbe {
        \\        return .{ .a = a };
        \\    }
        \\
        \\    pub fn check(self: *const ShiftProbe) void {
        \\        const left = self.a << 3;
        \\        const right = self.a >> 2;
        \\        runar.assert(left >= 0 or left < 0);
        \\        runar.assert(right >= 0 or right < 0);
        \\    }
        \\};
    ;
    const hex = try compile(source, "ShiftProbe.runar.zig");
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hexHasOpcode(hex, "98")); // OP_LSHIFT
    try std.testing.expect(hexHasOpcode(hex, "99")); // OP_RSHIFT
}
