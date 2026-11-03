//! N-330: a ByteString-family constructor arg whose `StateValue` is not
//! `.bytes` must be refused with `error.InvalidConstructorArg`. `StateValue`
//! has no raw-bytes variant (`.bytes` already carries hex), so there is
//! nothing to convert in this tier. Before, `encodeArg` encoded `.int` /
//! `.big_int` / `.boolean` as a script number / OP_1 / OP_0 for a ByteString
//! param, silently producing a different script from the hex the developer
//! meant.
//!
//! Proves: `RunarContract.init` returns `error.InvalidConstructorArg` for
//! `.int`, `.big_int`, `.boolean`, `.empty_sig`, and an `.array_value` for a
//! non-FixedArray param, and for an `.int` leaf inside an `.array_value` for a
//! `FixedArray<Addr, 2>`.
//! Does NOT prove: width checks, method-call args or on-chain spendability.

const std = @import("std");
const types = @import("sdk_types.zig");
const contract_mod = @import("sdk_contract.zig");

fn artifactJson(comptime param_type: []const u8) []const u8 {
    return "{\"contractName\":\"N330\",\"abi\":{\"constructor\":{\"params\":[{\"name\":\"owner\",\"type\":\"" ++
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

test "N-330: a non-bytes ByteString-family constructor arg is refused" {
    const leaves = [_]types.StateValue{.{ .bytes = "aabb" }};
    try std.testing.expectError(error.InvalidConstructorArg, initWith("ByteString", .{ .int = 5 }));
    try std.testing.expectError(error.InvalidConstructorArg, initWith("ByteString", .{ .big_int = "5" }));
    try std.testing.expectError(error.InvalidConstructorArg, initWith("ByteString", .{ .boolean = true }));
    try std.testing.expectError(error.InvalidConstructorArg, initWith("PubKey", .empty_sig));
    try std.testing.expectError(error.InvalidConstructorArg, initWith("ByteString", .{ .array_value = &leaves }));
}

test "N-330: a non-bytes FixedArray<Addr, 2> leaf is refused" {
    const leaves = [_]types.StateValue{ .{ .bytes = "aabb" }, .{ .int = 7 } };
    try std.testing.expectError(
        error.InvalidConstructorArg,
        initWith("FixedArray<Addr, 2>", .{ .array_value = &leaves }),
    );
}
