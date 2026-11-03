//! N-051 (TaffyTail), SDK side — deploy-time `SIZE(_codePart)` pins.
//!
//! A stateful contract that bakes a variable-width readonly constructor arg
//! into its code cannot know its deployed code-part length at compile time.
//! The compiler now always emits an EQUALITY pin and records the pin's 4-byte
//! little-endian value field in the artifact's `codePartLenSlots`; the SDK
//! writes the real deployed code-part length (inscription envelope included)
//! into that field when it builds the code script.
//!
//! Fixtures: the TypeScript-compiled TaffyTailVault artifact (fold OFF) and
//! the bytes the TypeScript SDK produces from it. Every tier must reproduce
//! them byte-for-byte.

const std = @import("std");
const types = @import("sdk_types.zig");
const contract_mod = @import("sdk_contract.zig");
const script_utils = @import("sdk_script_utils.zig");
const ordinals = @import("sdk_ordinals.zig");

const RunarContract = contract_mod.RunarContract;

const ARTIFACT_JSON = @embedFile("fixtures/n051-taffytail-artifact.json");
const EXPECTED_JSON = @embedFile("fixtures/n051-taffytail-expected.json");

const Expected = struct {
    parsed: std.json.Parsed(std.json.Value),

    fn load(allocator: std.mem.Allocator) !Expected {
        return .{ .parsed = try std.json.parseFromSlice(std.json.Value, allocator, EXPECTED_JSON, .{}) };
    }
    fn deinit(self: *Expected) void {
        self.parsed.deinit();
    }
    fn str(self: *const Expected, key: []const u8) []const u8 {
        return self.parsed.value.object.get(key).?.string;
    }
    fn int(self: *const Expected, key: []const u8) usize {
        return @intCast(self.parsed.value.object.get(key).?.integer);
    }
    fn ctorArg(self: *const Expected, i: usize) []const u8 {
        return self.parsed.value.object.get("constructorArgs").?.array.items[i].string;
    }
    fn inscription(self: *const Expected) ordinals.Inscription {
        const o = self.parsed.value.object.get("inscription").?.object;
        return .{ .content_type = o.get("contentType").?.string, .data = o.get("data").?.string };
    }
};

fn ctorArgs(e: *const Expected) [3]types.StateValue {
    return .{ .{ .bytes = e.ctorArg(0) }, .{ .bytes = e.ctorArg(1) }, .{ .bytes = e.ctorArg(2) } };
}

test "N-051: the artifact's codePartLenSlots are parsed" {
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, ARTIFACT_JSON);
    defer artifact.deinit();
    try std.testing.expectEqual(@as(usize, 1), artifact.code_part_len_slots.len);
    try std.testing.expectEqual(@as(i32, 959), artifact.code_part_len_slots[0].byte_offset);
}

test "N-051: the built code part and locking script carry the deployed code-part length" {
    const allocator = std.testing.allocator;
    var e = try Expected.load(allocator);
    defer e.deinit();
    var artifact = try types.RunarArtifact.fromJson(allocator, ARTIFACT_JSON);
    defer artifact.deinit();

    const args = ctorArgs(&e);
    var contract = try RunarContract.init(allocator, &artifact, &args);
    defer contract.deinit();

    const code = try contract.getCodePartHex();
    defer allocator.free(code);
    try std.testing.expectEqual(e.int("codePartLen"), code.len / 2);
    try std.testing.expectEqualStrings(e.str("codePartHex"), code);

    const locking = try contract.getLockingScript();
    defer allocator.free(locking);
    try std.testing.expectEqualStrings(e.str("lockingScriptHex"), locking);
}

test "N-051: withInscription is accepted and the pin is patched to the inscribed length" {
    const allocator = std.testing.allocator;
    var e = try Expected.load(allocator);
    defer e.deinit();
    var artifact = try types.RunarArtifact.fromJson(allocator, ARTIFACT_JSON);
    defer artifact.deinit();

    const args = ctorArgs(&e);
    var contract = try RunarContract.init(allocator, &artifact, &args);
    defer contract.deinit();

    try contract.withInscription(e.inscription());

    const code = try contract.getCodePartHex();
    defer allocator.free(code);
    try std.testing.expectEqual(e.int("inscribedCodePartLen"), code.len / 2);
    try std.testing.expectEqualStrings(e.str("inscribedCodePartHex"), code);
}

test "N-051: a codePartLenSlots entry that does not point at a pin field is refused" {
    const allocator = std.testing.allocator;
    var e = try Expected.load(allocator);
    defer e.deinit();
    var artifact = try types.RunarArtifact.fromJson(allocator, ARTIFACT_JSON);
    defer artifact.deinit();
    try std.testing.expectEqual(@as(usize, 1), artifact.code_part_len_slots.len);

    const args = ctorArgs(&e);
    for ([_]i32{ 958, 960, 0 }) |bad| {
        artifact.code_part_len_slots[0].byte_offset = bad;
        var contract = try RunarContract.init(allocator, &artifact, &args);
        defer contract.deinit();
        try std.testing.expectError(error.CodePartLenSlotMismatch, contract.getLockingScript());
        try std.testing.expectError(error.CodePartLenSlotMismatch, contract.getCodePartHex());
    }
}

test "N-051: matchesArtifact compares the pin field against the candidate's own code-part length" {
    const allocator = std.testing.allocator;
    var e = try Expected.load(allocator);
    defer e.deinit();
    var artifact = try types.RunarArtifact.fromJson(allocator, ARTIFACT_JSON);
    defer artifact.deinit();

    const locking = e.str("lockingScriptHex");
    try std.testing.expect(try script_utils.matchesArtifact(&artifact, locking));

    // Tamper with the deployed length field: no longer the code part's length.
    const code_len = e.int("codePartLen");
    try std.testing.expectEqual(@as(usize, 1608), code_len);
    const needle = "0448060000819c69"; // LE32(1608) = 48 06 00 00
    const at = std.mem.indexOf(u8, locking, needle) orelse return error.PinNotFound;
    const tampered = try allocator.dupe(u8, locking);
    defer allocator.free(tampered);
    @memcpy(tampered[at + 2 .. at + 4], "49");
    try std.testing.expect(!try script_utils.matchesArtifact(&artifact, tampered));
}
