//! `matchesArtifact` must check what sits at each constructor slot, not only
//! the template bytes between slots: a push or small-integer opcode, the same
//! bytes at every reference of one param, and exactly `fixedValueByteLength`
//! bytes where the slot declares it. A stateful artifact's script must carry
//! an OP_RETURN after its code part.
//!
//! Replays the shared cross-tier vector
//! `conformance/sdk-matches-artifact/slot-values.json` (also replayed by the
//! TS, Go, Rust, Python, Ruby and Java SDKs), plus the TS unit cases for hex
//! case, `extractConstructorArgs` refusing a non-push opcode, and
//! `extractConstructorArgs` after a codeSepIndex slot wider than one byte.
//!
//! Proves: honest deployments match; the forgeries in the vector do not;
//! `extractConstructorArgs` returns error.MalformedScript on a non-push opcode
//! at any reference of a param and reads an arg after a wide codeSep slot
//! from its deployed position.
//! Does NOT prove: that a slot push is minimally encoded, nor anything about
//! the length of the state after the OP_RETURN.

const std = @import("std");
const types = @import("sdk_types.zig");
const script_utils = @import("sdk_script_utils.zig");

const FIXTURE_PATH = "../../conformance/sdk-matches-artifact/slot-values.json";
const G = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const G_UPPER = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";

const Fixture = struct {
    raw: []u8,
    parsed: std.json.Parsed(std.json.Value),

    fn load(allocator: std.mem.Allocator) !Fixture {
        const raw = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, FIXTURE_PATH, allocator, .limited(4 * 1024 * 1024));
        errdefer allocator.free(raw);
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
        return .{ .raw = raw, .parsed = parsed };
    }

    fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        self.parsed.deinit();
        allocator.free(self.raw);
    }

    fn cases(self: *const Fixture) []std.json.Value {
        return self.parsed.value.object.get("cases").?.array.items;
    }

    fn artifact(self: *const Fixture, allocator: std.mem.Allocator, key: []const u8) !types.RunarArtifact {
        const v = self.parsed.value.object.get("artifacts").?.object.get(key).?;
        const json = try std.json.Stringify.valueAlloc(allocator, v, .{});
        defer allocator.free(json);
        return types.RunarArtifact.fromJson(allocator, json);
    }
};

fn freeArgs(allocator: std.mem.Allocator, result: *std.StringHashMap(types.StateValue)) void {
    var it = result.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
        entry.value_ptr.deinit(allocator);
    }
    result.deinit();
}

test "slot-values: matchesArtifact replays conformance/sdk-matches-artifact/slot-values.json" {
    const allocator = std.testing.allocator;
    var fx = try Fixture.load(allocator);
    defer fx.deinit(allocator);
    const cases = fx.cases();
    try std.testing.expect(cases.len > 0);
    var wrong: usize = 0;
    for (cases) |c| {
        const o = c.object;
        var artifact = try fx.artifact(allocator, o.get("artifact").?.string);
        defer artifact.deinit();
        const got = try script_utils.matchesArtifact(&artifact, o.get("script_hex").?.string);
        if (got != o.get("expected").?.bool) {
            std.debug.print("slot-values case wrong: {s} (got {})\n", .{ o.get("name").?.string, got });
            wrong += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), wrong);
}

test "slot-values: slot values compare without regard to hex case" {
    const allocator = std.testing.allocator;
    var fx = try Fixture.load(allocator);
    defer fx.deinit(allocator);
    var owner2 = try fx.artifact(allocator, "owner2");
    defer owner2.deinit();
    try std.testing.expect(try script_utils.matchesArtifact(&owner2, "21" ++ G ++ "ad21" ++ G_UPPER ++ "ac"));
}

test "slot-values: extractConstructorArgs refuses a non-push opcode at a constructor slot" {
    const allocator = std.testing.allocator;
    var fx = try Fixture.load(allocator);
    defer fx.deinit(allocator);
    const cases = [_]struct { key: []const u8, script: []const u8 }{
        .{ .key = "owner2", .script = "acad21" ++ G ++ "ac" },
        .{ .key = "owner2", .script = "21" ++ G ++ "adacac" },
        .{ .key = "slotMatrix", .script = "ac7b880111" ++ "7c9dac" ++ "21" ++ G ++ "879169" ++ "21" ++ G ++ "ac" },
    };
    var wrong: usize = 0;
    for (cases) |c| {
        var artifact = try fx.artifact(allocator, c.key);
        defer artifact.deinit();
        if (script_utils.extractConstructorArgs(&artifact, c.script, allocator)) |res| {
            var r = res;
            freeArgs(allocator, &r);
            std.debug.print("slot-values: extract accepted non-push: {s}\n", .{c.script[0..12]});
            wrong += 1;
        } else |err| {
            try std.testing.expectEqual(error.MalformedScript, err);
        }
    }
    try std.testing.expectEqual(@as(usize, 0), wrong);
}

test "slot-values: honest deployments still extract" {
    const allocator = std.testing.allocator;
    var fx = try Fixture.load(allocator);
    defer fx.deinit(allocator);
    var slot_matrix = try fx.artifact(allocator, "slotMatrix");
    defer slot_matrix.deinit();
    var owner2 = try fx.artifact(allocator, "owner2");
    defer owner2.deinit();
    for (fx.cases()) |c| {
        const o = c.object;
        const name = o.get("name").?.string;
        if (o.get("expected").?.bool and std.mem.eql(u8, o.get("artifact").?.string, "slotMatrix")) {
            var res = try script_utils.extractConstructorArgs(&slot_matrix, o.get("script_hex").?.string, allocator);
            defer freeArgs(allocator, &res);
            try std.testing.expectEqual(@as(i64, 17), res.get("count").?.int);
            try std.testing.expectEqualStrings(G, res.get("owner").?.bytes);
        }
        if (std.mem.eql(u8, name, "owner2-honest")) {
            var res = try script_utils.extractConstructorArgs(&owner2, o.get("script_hex").?.string, allocator);
            defer freeArgs(allocator, &res);
            try std.testing.expectEqual(@as(u32, 1), res.count());
            try std.testing.expectEqualStrings(G, res.get("owner").?.bytes);
        }
    }
}

test "slot-values: extractConstructorArgs after a codeSepIndex slot wider than one byte" {
    // Hand-built: a codeSepIndex slot at byte 1 with codeSepIndex 140, baked as
    // 143 (`02 8f00`), then a constructor slot at byte 3. Script pinned by the
    // TS SDK's RunarContract.getLockingScript().
    const allocator = std.testing.allocator;
    const json =
        \\{"version":"runar-v1.0.0-rc.1","compilerVersion":"1.0.0-rc.1","contractName":"CodeSepBeforeSlot",
        \\"abi":{"constructor":{"params":[{"name":"x","type":"ByteString"}]},"methods":[]},
        \\"script":"5100520053","constructorSlots":[{"paramIndex":0,"byteOffset":3}],
        \\"codeSepIndexSlots":[{"byteOffset":1,"codeSepIndex":140}]}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();
    const script = "51028f005203aabbcc53";
    try std.testing.expect(try script_utils.matchesArtifact(&artifact, script));
    var res = try script_utils.extractConstructorArgs(&artifact, script, allocator);
    defer freeArgs(allocator, &res);
    try std.testing.expectEqual(@as(u32, 1), res.count());
    try std.testing.expectEqualStrings("aabbcc", res.get("x").?.bytes);
}
