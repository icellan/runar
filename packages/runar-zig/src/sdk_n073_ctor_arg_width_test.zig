//! N-073: a fixed-width ByteString-family constructor arg must have its
//! declared width (Addr/Ripemd160 20, Sha256 32, PubKey 33, Point/P256Point 64,
//! P384Point 96), refused with `error.InvalidConstructorArg` (this tier's
//! error tag for the N-045 width rule). `fromUtxo`'s restore path is
//! unaffected.
//!
//! Proves: a 33-byte Sha256 and a 19-byte Addr (scalar and FixedArray leaf)
//! are refused; correct widths are accepted; ByteString takes any length;
//! `fromUtxo` restores.
//! Does NOT prove: method-call or state value widths (N-045), on-chain
//! spendability, or that the restore bypass is unreachable by user input.

const std = @import("std");
const types = @import("sdk_types.zig");
const contract_mod = @import("sdk_contract.zig");

fn artifactJson(comptime param_type: []const u8) []const u8 {
    return "{\"contractName\":\"N073\",\"abi\":{\"constructor\":{\"params\":[{\"name\":\"owner\",\"type\":\"" ++
        param_type ++ "\"}]},\"methods\":[]},\"script\":\"00\",\"stateFields\":[]," ++
        "\"constructorSlots\":[{\"paramIndex\":0,\"byteOffset\":0}]}";
}

fn initWith(comptime param_type: []const u8, arg: types.StateValue) !void {
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, artifactJson(param_type));
    defer artifact.deinit();
    const args = [_]types.StateValue{arg};
    var contract = try contract_mod.RunarContract.init(allocator, &artifact, &args);
    defer contract.deinit();
}

fn hex(comptime n: usize) []const u8 {
    return "ab" ** n;
}

test "N-073: a wrong-width Sha256 / Addr constructor arg is refused" {
    try std.testing.expectError(error.InvalidConstructorArg, initWith("Sha256", .{ .bytes = hex(33) }));
    try std.testing.expectError(error.InvalidConstructorArg, initWith("Addr", .{ .bytes = hex(19) }));
}

test "N-073: a wrong-width FixedArray<Addr, 2> leaf is refused" {
    const leaves = [_]types.StateValue{ .{ .bytes = hex(20) }, .{ .bytes = hex(19) } };
    try std.testing.expectError(
        error.InvalidConstructorArg,
        initWith("FixedArray<Addr, 2>", .{ .array_value = &leaves }),
    );
}

test "N-073: correct widths are accepted, one byte less is refused, ByteString is free" {
    try initWith("Addr", .{ .bytes = hex(20) });
    try initWith("Ripemd160", .{ .bytes = hex(20) });
    try initWith("Sha256", .{ .bytes = hex(32) });
    try initWith("PubKey", .{ .bytes = hex(33) });
    try initWith("Point", .{ .bytes = hex(64) });
    try initWith("P256Point", .{ .bytes = hex(64) });
    try initWith("P384Point", .{ .bytes = hex(96) });
    try std.testing.expectError(error.InvalidConstructorArg, initWith("Addr", .{ .bytes = hex(19) }));
    try std.testing.expectError(error.InvalidConstructorArg, initWith("Ripemd160", .{ .bytes = hex(19) }));
    try std.testing.expectError(error.InvalidConstructorArg, initWith("PubKey", .{ .bytes = hex(32) }));
    try std.testing.expectError(error.InvalidConstructorArg, initWith("Point", .{ .bytes = hex(63) }));
    try std.testing.expectError(error.InvalidConstructorArg, initWith("P256Point", .{ .bytes = hex(63) }));
    try std.testing.expectError(error.InvalidConstructorArg, initWith("P384Point", .{ .bytes = hex(95) }));
    try initWith("ByteString", .{ .bytes = hex(3) });
}
