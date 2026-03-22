const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const SchnorrZKP = @import("SchnorrZKP.runar.zig").SchnorrZKP;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "schnorr-zkp/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check SchnorrZKP.runar.zig" {
    try runCompileChecks("SchnorrZKP.runar.zig");
}

test "SchnorrZKP init stores pubKey" {
    const pub_key = runar.ecMulGen(11);
    const contract = SchnorrZKP.init(pub_key);
    try std.testing.expectEqualSlices(u8, runar.ecEncodeCompressed(pub_key), runar.ecEncodeCompressed(contract.pubKey));
}

test "SchnorrZKP rejects invalid points" {
    try root.expectAssertFailure("schnorr-zkp-invalid-r-point");
}

test "SchnorrZKP verifies a valid Fiat-Shamir proof with wide bigint response" {
    const pub_key_hex =
        "fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af" ++
        "07b158f244cd0de2134ac7c1d371cffbfae4db40801a2572e531c573cda9b5b4";
    const r_point_hex =
        "f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f" ++
        "0eba29d0f0c5408ed681984dc525982abefccd9f7ff01dd26da4999cf3f6a295";
    const s_le_hex =
        "eddbfe2cedf6f857ae5530a2dc2ee18f3f9562076f6269e09da736fee207ec5f";

    const pub_key = try runar.hex.decodeAlloc(std.testing.allocator, pub_key_hex);
    defer std.testing.allocator.free(pub_key);

    const r_point = try runar.hex.decodeAlloc(std.testing.allocator, r_point_hex);
    defer std.testing.allocator.free(r_point);

    const s_bytes = try runar.hex.decodeAlloc(std.testing.allocator, s_le_hex);
    defer std.testing.allocator.free(s_bytes);

    const contract = SchnorrZKP.init(pub_key);
    const s = runar.bin2num(s_bytes);

    contract.verify(r_point, s);
}
