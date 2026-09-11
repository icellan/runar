//! `Sig` / `SigHashPreimage` state fields are push-data-framed variable-length
//! state, exactly like `ByteString`, on BOTH the write and the read side.
//!
//! The Zig tier got the WRITE side right from the start — both serialize sites
//! in `passes/stack_lower.zig` (`:3550`, `:5687`) already went through
//! `isVariableLengthStateType`. The READ side did not:
//! `methodReadsVarLenStateRec` matched `prop.type_info == .byte_string` alone,
//! so for a TERMINAL method reading a mutable `Sig` field `usesCodePart` stayed
//! false, `lowerDeserializeState` took its "no `_codePart`" shortcut and pushed
//! no mutable property at all, and every `load_prop` fell through to the
//! DEPLOY-TIME constructor placeholder. The script kept authorising against the
//! value baked in at deploy — a rotating key or signature field could be
//! updated on-chain for ever without the script noticing.
//!
//! The deploy-time writer settles which list is right: every SDK's
//! `encodeStateValue` enumerates the fixed-size types (PubKey, Addr, Ripemd160,
//! Sha256, Point, P256Point, P384Point) and push-data-frames everything else.
//!
//! The lock: a `Sig` / `SigHashPreimage` field must compile BYTE-IDENTICALLY to
//! the same contract with a `ByteString` field — the path that was already
//! correct. `RabinSig` (a bigint alias, a bare 8-byte NUM2BIN word) and `PubKey`
//! (33 raw bytes) are the negative controls and must stay DIFFERENT.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

/// Mutating method — drives the state-continuation WRITE path.
fn writeSrc(allocator: std.mem.Allocator, prop_type: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\class VarLenStateWrite extends StatefulSmartContract {{
        \\  tag: {s};
        \\
        \\  constructor(tag: {s}) {{
        \\    super(tag);
        \\    this.tag = tag;
        \\  }}
        \\
        \\  public update(next: {s}) {{
        \\    this.tag = next;
        \\  }}
        \\}}
    , .{ prop_type, prop_type, prop_type });
}

/// Terminal read of the field — drives `methodReadsVarLenState`.
fn readSrc(allocator: std.mem.Allocator, prop_type: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\class VarLenStateRead extends StatefulSmartContract {{
        \\  tag: {s};
        \\
        \\  constructor(tag: {s}) {{
        \\    super(tag);
        \\    this.tag = tag;
        \\  }}
        \\
        \\  public check(expected: bigint) {{
        \\    assert(len(this.tag) == expected);
        \\  }}
        \\}}
    , .{ prop_type, prop_type });
}

fn artifactScriptHex(json: []const u8) ![]const u8 {
    const marker = "\"script\":\"";
    const idx = std.mem.indexOf(u8, json, marker) orelse return error.MissingHex;
    const after = idx + marker.len;
    const end = std.mem.indexOfPos(u8, json, after, "\"") orelse return error.MissingHex;
    return json[after..end];
}

/// Compile `src` and return an owned copy of its locking-script hex.
fn scriptHexOf(allocator: std.mem.Allocator, src: []const u8, file_name: []const u8) ![]u8 {
    const result = try compiler_api.compileSource(allocator, src, file_name);
    defer result.deinit(allocator);
    const json = result.artifact_json orelse return error.MissingArtifact;
    return allocator.dupe(u8, try artifactScriptHex(json));
}

fn usesCodePart(allocator: std.mem.Allocator, src: []const u8, file_name: []const u8) !bool {
    const result = try compiler_api.compileSource(allocator, src, file_name);
    defer result.deinit(allocator);
    const json = result.artifact_json orelse return error.MissingArtifact;
    return std.mem.indexOf(u8, json, "\"usesCodePart\":true") != null;
}

const VAR_LEN_TYPES = [_][]const u8{ "Sig", "SigHashPreimage" };

test "a mutating method on a Sig/SigHashPreimage field frames like ByteString" {
    const allocator = std.testing.allocator;

    const control_src = try writeSrc(allocator, "ByteString");
    defer allocator.free(control_src);
    const control = try scriptHexOf(allocator, control_src, "VarLenStateWrite.runar.ts");
    defer allocator.free(control);

    for (VAR_LEN_TYPES) |prop_type| {
        const src = try writeSrc(allocator, prop_type);
        defer allocator.free(src);
        const got = try scriptHexOf(allocator, src, "VarLenStateWrite.runar.ts");
        defer allocator.free(got);
        try std.testing.expectEqualStrings(control, got);
    }
}

test "a terminal read of a Sig/SigHashPreimage field matches the ByteString control" {
    const allocator = std.testing.allocator;

    const control_src = try readSrc(allocator, "ByteString");
    defer allocator.free(control_src);
    const control = try scriptHexOf(allocator, control_src, "VarLenStateRead.runar.ts");
    defer allocator.free(control);

    for (VAR_LEN_TYPES) |prop_type| {
        const src = try readSrc(allocator, prop_type);
        defer allocator.free(src);
        const got = try scriptHexOf(allocator, src, "VarLenStateRead.runar.ts");
        defer allocator.free(got);
        try std.testing.expectEqualStrings(control, got);
    }
}

test "a terminal read of a Sig/SigHashPreimage field advertises usesCodePart" {
    // The ABI shape, not just the byte count: the SDK reads this flag to decide
    // whether to push `_codePart` into the unlocking script.
    const allocator = std.testing.allocator;
    const types = VAR_LEN_TYPES ++ [_][]const u8{"ByteString"};
    for (types) |prop_type| {
        const src = try readSrc(allocator, prop_type);
        defer allocator.free(src);
        try std.testing.expect(try usesCodePart(allocator, src, "VarLenStateRead.runar.ts"));
    }
}

test "fixed-width state types are NOT push-data framed" {
    // Without this the tests above would still pass if every state type
    // collapsed onto the same lowering.
    const allocator = std.testing.allocator;

    const control_src = try writeSrc(allocator, "ByteString");
    defer allocator.free(control_src);
    const control = try scriptHexOf(allocator, control_src, "VarLenStateWrite.runar.ts");
    defer allocator.free(control);

    for ([_][]const u8{ "RabinSig", "RabinPubKey", "PubKey" }) |prop_type| {
        const src = try writeSrc(allocator, prop_type);
        defer allocator.free(src);
        const got = try scriptHexOf(allocator, src, "VarLenStateWrite.runar.ts");
        defer allocator.free(got);
        try std.testing.expect(!std.mem.eql(u8, control, got));
    }
}
