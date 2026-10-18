//! N-329: a ByteString-family constructor arg that is not an even-length hex
//! string must be refused at construction with a typed error, not spliced into
//! the locking script as raw text (a push header sized for the raw bytes
//! followed by non-hex characters, with no error).
//!
//! Proves: `RunarContract.init` returns `error.InvalidConstructorArg` for raw
//! non-hex Addr bytes, odd-length hex and a non-hex leaf inside an
//! `array_value` for a `FixedArray<Addr, 2>` param; valid hex (either case,
//! empty) is accepted and `getLockingScript()` is hex-only.
//! Does NOT prove: width checks (a 3-byte Addr is accepted here) or on-chain
//! spendability.

const std = @import("std");
const types = @import("sdk_types.zig");
const script_utils = @import("sdk_script_utils.zig");
const contract_mod = @import("sdk_contract.zig");

fn artifactJson(comptime param_type: []const u8) []const u8 {
    return "{\"contractName\":\"N329\",\"abi\":{\"constructor\":{\"params\":[{\"name\":\"owner\",\"type\":\"" ++
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
    const script = try contract.getLockingScript();
    defer allocator.free(script);
    try std.testing.expect(script_utils.isHexBytes(script));
}

test "N-329: a non-hex ByteString-family constructor arg is refused" {
    const raw_addr = "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93";
    try std.testing.expectError(error.InvalidConstructorArg, initWith("Addr", .{ .bytes = raw_addr }));
    try std.testing.expectError(error.InvalidConstructorArg, initWith("ByteString", .{ .bytes = "abc" }));
    try std.testing.expectError(error.InvalidConstructorArg, initWith("PubKey", .{ .bytes = "zz" }));
}

test "N-329: a non-hex FixedArray<Addr, 2> leaf is refused" {
    const leaves = [_]types.StateValue{ .{ .bytes = "aabb" }, .{ .bytes = "not-hex!" } };
    try std.testing.expectError(
        error.InvalidConstructorArg,
        initWith("FixedArray<Addr, 2>", .{ .array_value = &leaves }),
    );
}

test "N-329: hex ByteString constructor args are accepted" {
    try initWith("ByteString", .{ .bytes = "9a1c78a5" });
    try initWith("ByteString", .{ .bytes = "9A1C78A5" });
    try initWith("ByteString", .{ .bytes = "" });
}
