//! Per-builtin codegen op-shape tests for the simple hash + signature
//! builtins (GAP-m9): sha256, hash160, hash256, ripemd160, checkSig,
//! checkMultiSig.
//!
//! The structured crypto codegen families (EC core, NIST P-256/P-384,
//! SHA-256 compress/finalize, BLAKE3, WOTS+, SLH-DSA, Rabin) already carry
//! assertion-grade inline tests in their dedicated `*_emitters.zig` helper
//! modules. The remaining gap was the *simple* one-to-one builtins that map
//! straight to a single opcode in `BUILTIN_OPCODES` and had no dedicated
//! per-builtin probe. This file closes that gap.
//!
//! Each test compiles a minimal contract that calls one builtin on a method
//! parameter and asserts the compiled hex contains the builtin's opcode.
//!
//! Builtin -> opcode:
//!   sha256        -> OP_SHA256        (0xa8)
//!   hash160       -> OP_HASH160       (0xa9)
//!   hash256       -> OP_HASH256       (0xaa)
//!   ripemd160     -> OP_RIPEMD160     (0xa6)
//!   checkSig      -> OP_CHECKSIG      (0xac)
//!   checkMultiSig -> OP_CHECKMULTISIG (0xae)

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

/// Compile a stateless contract whose `check` method body is `body_src`.
/// The contract has a `ByteString` property and the method takes a
/// `ByteString` param so hashing builtins operate on a non-constant value.
fn compileHashCheck(comptime body_src: []const u8) ![]const u8 {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const HashProbe = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    expected: runar.ByteString,
        \\
        \\    pub fn init(expected: runar.ByteString) HashProbe {
        \\        return .{ .expected = expected };
        \\    }
        \\
        \\    pub fn check(self: *const HashProbe, data: runar.ByteString) void {
    ++ body_src ++
        \\
        \\    }
        \\};
    ;
    return compiler_api.compileSourceToHex(std.testing.allocator, source, "HashProbe.runar.zig");
}

// F5 — sha256
test "hash builtin sha256 lowers to OP_SHA256" {
    const hex = try compileHashCheck("        runar.assert(runar.sha256(data) == self.expected);");
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hexHasOpcode(hex, "a8"));
}

// F6 — hash160
test "hash builtin hash160 lowers to OP_HASH160" {
    const hex = try compileHashCheck("        runar.assert(runar.hash160(data) == self.expected);");
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hexHasOpcode(hex, "a9"));
}

// F7 — hash256
test "hash builtin hash256 lowers to OP_HASH256" {
    const hex = try compileHashCheck("        runar.assert(runar.hash256(data) == self.expected);");
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hexHasOpcode(hex, "aa"));
}

// F15 — ripemd160
test "hash builtin ripemd160 lowers to OP_RIPEMD160" {
    const hex = try compileHashCheck("        runar.assert(runar.ripemd160(data) == self.expected);");
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hexHasOpcode(hex, "a6"));
}

// F10 — checkSig
test "sig builtin checkSig lowers to OP_CHECKSIG" {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const SigProbe = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    owner: runar.PubKey,
        \\
        \\    pub fn init(owner: runar.PubKey) SigProbe {
        \\        return .{ .owner = owner };
        \\    }
        \\
        \\    pub fn unlock(self: *const SigProbe, sig: runar.Sig) void {
        \\        runar.assert(runar.checkSig(sig, self.owner));
        \\    }
        \\};
    ;
    const hex = try compiler_api.compileSourceToHex(std.testing.allocator, source, "SigProbe.runar.zig");
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hexHasOpcode(hex, "ac"));
}

// F11 — checkMultiSig
test "sig builtin checkMultiSig lowers to OP_CHECKMULTISIG" {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const MultiSigProbe = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    keyA: runar.PubKey,
        \\    keyB: runar.PubKey,
        \\
        \\    pub fn init(keyA: runar.PubKey, keyB: runar.PubKey) MultiSigProbe {
        \\        return .{ .keyA = keyA, .keyB = keyB };
        \\    }
        \\
        \\    pub fn unlock(self: *const MultiSigProbe, sigA: runar.Sig, sigB: runar.Sig) void {
        \\        const sigs = [_]runar.Sig{ sigA, sigB };
        \\        const keys = [_]runar.PubKey{ self.keyA, self.keyB };
        \\        runar.assert(runar.checkMultiSig(sigs, keys));
        \\    }
        \\};
    ;
    const hex = try compiler_api.compileSourceToHex(std.testing.allocator, source, "MultiSigProbe.runar.zig");
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hexHasOpcode(hex, "ae"));
}
